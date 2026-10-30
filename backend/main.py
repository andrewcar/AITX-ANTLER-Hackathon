"""
VulnSwarm backend.

    extension  --login-->  token  --/scan-->  backend  --finding-->  extension
    dashboard  --login-->  token  --/scan/stream-->  backend  --SSE-->  dashboard

POST /scan runs the swarm and returns the finished report. POST /scan/stream runs
the same swarm and pushes phase, agent, and finding events as they happen.
Both refuse any target that is not on ALLOWLIST before the orchestrator starts.

SCOPE SAFETY: a host not on ALLOWLIST is rejected with HTTP 403. The streaming
path uses the same check and re-checks inside the worker so a stream cannot
reach the orchestrator by skipping the handler.

GUARDRAILS: a kill switch (one scan, or every in-flight scan), a concurrency
cap, per-request pacing, and an append-only audit log. See control.py and audit.py.

GET /preview only describes how the dashboard should draw a target. Off-list
hosts are not fetched. It does not start a scan and it does not follow redirects.
"""
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

import socket

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

import audit
import control
import streaming

log = logging.getLogger("vulnswarm")

# --- config -----------------------------------------------------------------
TOKEN_TTL = 60 * 60 * 8  # 8 hours


def _session_secret() -> bytes:
    """HMAC key for demo bearer tokens. Prefer env; else a random per-process value."""
    env = (
        os.environ.get("VULNSWARM_SESSION_SECRET")
        or os.environ.get("VULNSWARM_SECRET")  # legacy alias
    )
    if env:
        return env.encode()
    generated = secrets.token_hex(32)
    log.warning(
        "VULNSWARM_SESSION_SECRET is unset; using a random per-process secret. "
        "Set VULNSWARM_SESSION_SECRET for any shared or production use."
    )
    return generated.encode()


SECRET = _session_secret()

# Demo users for local hackathon demos. Real version: proper user store + hashed pw.
# password here is "demo" for both — fine for localhost only, not prod.
USERS = {
    "erwin@local": "demo",
    "andrew@local": "demo",
}

# The ONLY hosts the swarm is allowed to touch. Everything we own, nothing else.
# Fill with your tower's hosted sites. A target not in here is rejected at /scan.
ALLOWLIST = {
    "localhost",
    "127.0.0.1",
    # No LAN IPs: on shared/venue WiFi a LAN address can belong to someone else.
    # Add a LAN host only on a private network you control.
}

# The hosted lab targets shown on the dashboard (the multi-site "main page").
LAB_TARGETS = [
    {"name": "DVWA", "stack": "PHP / LAMP", "url": "http://localhost:8081"},
    {"name": "Juice Shop", "stack": "Node / SPA", "url": "http://localhost:3001"},
]

# Default CORS: local dashboard (nginx :8090 / file:// → Origin null) and common lab hosts.
# Override with VULNSWARM_CORS_ORIGINS (comma-separated).
_DEFAULT_CORS_ORIGINS = [
    "http://localhost:8090",
    "http://127.0.0.1:8090",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "null",  # dashboard opened as a local file
]


def _cors_origins() -> list[str]:
    raw = os.environ.get("VULNSWARM_CORS_ORIGINS", "").strip()
    if not raw:
        return list(_DEFAULT_CORS_ORIGINS)
    return [o.strip() for o in raw.split(",") if o.strip()]


app = FastAPI(title="Swarmageddon — consent-first vulnerability swarm")

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_methods=["*"],
    allow_headers=["*"],
)

bearer = HTTPBearer(auto_error=True)


# --- tiny signed-token helpers (no external dep, good enough for the slice) ---
def _sign(payload: str) -> str:
    sig = hmac.new(SECRET, payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def make_token(email: str) -> str:
    payload = json.dumps({"sub": email, "exp": int(time.time()) + TOKEN_TTL})
    # base64-ish without padding noise: hex-encode the payload so it survives transport
    payload_hex = payload.encode().hex()
    return _sign(payload_hex)


def verify_token(creds: HTTPAuthorizationCredentials = Depends(bearer)) -> str:
    token = creds.credentials
    try:
        payload_hex, sig = token.rsplit(".", 1)
    except ValueError:
        raise HTTPException(401, "malformed token")
    expected = hmac.new(SECRET, payload_hex.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        raise HTTPException(401, "bad signature")
    data = json.loads(bytes.fromhex(payload_hex))
    if data["exp"] < time.time():
        raise HTTPException(401, "token expired")
    return data["sub"]


# --- models ------------------------------------------------------------------
class LoginIn(BaseModel):
    email: str
    password: str


class ScanIn(BaseModel):
    url: str


class StopIn(BaseModel):
    run_id: str | None = None
    all: bool = False


# --- routes ------------------------------------------------------------------
@app.post("/auth/login")
def login(body: LoginIn):
    if USERS.get(body.email) != body.password:
        raise HTTPException(401, "invalid credentials")
    return {"token": make_token(body.email), "email": body.email}


@app.get("/me")
def me(user: str = Depends(verify_token)):
    return {"email": user}


@app.get("/targets")
def targets(user: str = Depends(verify_token)):
    """The hosted sites the dashboard lists."""
    return {"targets": LAB_TARGETS}


class ScopeError(Exception):
    """Raised when a target host is not on ALLOWLIST. Never starts a scan."""

    def __init__(self, host: str, url: str):
        self.host = host
        self.url = url
        super().__init__(
            f"target '{host or url}' is not on the allowlist — refusing to scan"
        )


def allowlisted_host(url: str) -> str:
    """Return the target hostname, or raise ScopeError. Does not touch the network."""
    host = urlparse(url).hostname or ""
    if host not in ALLOWLIST:
        raise ScopeError(host, url)
    return host


def _refuse_scope(url: str, user: str) -> str:
    """Allowlist gate. A refusal is audited and never takes a scan slot."""
    try:
        return allowlisted_host(url)
    except ScopeError as e:
        audit.record("scan", actor=user, target=url, status="rejected", detail="allowlist")
        raise HTTPException(403, str(e))


def _lease_or_429(url: str, user: str) -> control.ScanLease:
    try:
        return control.acquire(target=url, actor=user)
    except control.BusyError as e:
        audit.record("scan", actor=user, target=url, status="rejected", detail="rate_limit")
        raise HTTPException(429, str(e), headers={"Retry-After": "2"})


def _audit_outcome(lease: control.ScanLease, result: dict | None, error: str | None = None) -> None:
    if error:
        audit.record(
            "scan", run_id=lease.run_id, actor=lease.actor, target=lease.target,
            status="error", detail=error,
        )
        return
    status = (result or {}).get("status") or "complete"
    audit.record(
        "scan", run_id=lease.run_id, actor=lease.actor, target=lease.target, status=status,
    )


def _rev_dns(ip_or_host: str) -> str:
    """Best-effort machine name for an IP or host. Returns '' if it can't resolve."""
    if not ip_or_host:
        return ""
    try:
        # if given a hostname, resolve to IP first, then reverse-lookup its name
        ip = socket.gethostbyname(ip_or_host)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def machine_provenance(client_ip: str, host: str, server_banner: str) -> dict:
    """Who asked, who scanned, what was scanned."""
    return {
        "requested_from": {
            "ip": client_ip,
            "name": _rev_dns(client_ip) or "unknown",
        },
        "scanner": {
            "name": os.environ.get("SCANNER_NAME") or socket.gethostname(),
        },
        "target": {
            "url_host": host,
            "server_banner": server_banner or "unknown",
            "name": _rev_dns(host) or "unknown",
        },
    }


@app.post("/scan")
def scan(body: ScanIn, request: Request, user: str = Depends(verify_token)):
    """Validate scope, run the swarm, return the finished report."""
    import orchestrator

    host = _refuse_scope(body.url, user)
    lease = _lease_or_429(body.url, user)
    try:
        with control.scope(lease):
            audit.record(
                "scan", run_id=lease.run_id, actor=user, target=body.url, status="started",
            )
            try:
                result = orchestrator.run_scan(
                    body.url, should_stop=lease.stopped, run_id=lease.run_id,
                )
            except Exception as e:
                _audit_outcome(lease, None, error=type(e).__name__)
                raise HTTPException(502, f"scan failed: {type(e).__name__}: {e}")
            _audit_outcome(lease, result)
    finally:
        control.release(lease.run_id)

    if result.get("status") == "cancelled":
        raise HTTPException(409, "scan stopped")

    client_ip = request.client.host if request.client else ""
    return {
        "target": body.url,
        "requested_by": user,
        "status": "complete",
        "machines": machine_provenance(client_ip, host, result["recon"]["server"]),
        **result,  # recon, specialists_run, model, ai_available, findings, summary
    }


@app.post("/scan/stream")
def scan_stream(body: ScanIn, request: Request, user: str = Depends(verify_token)):
    """Same swarm as /scan, pushed as Server-Sent Events while it runs.

    Refuses with HTTP 403 before the response starts when the host is not on
    ALLOWLIST, and with HTTP 429 when the concurrency cap is full. The worker
    checks the allowlist again before calling the orchestrator.

    Events (JSON, one per message, `type` field):
      scan_started, phase, agent, finding, verdict, scan_complete, error

    Disconnect, POST /scan/stop, and POST /scan/stop with all=true set the
    lease event. Recon checks that event on every outbound request.
    """
    import orchestrator

    host = _refuse_scope(body.url, user)
    lease = _lease_or_429(body.url, user)
    client_ip = request.client.host if request.client else ""
    target_url = body.url

    def produce(on_event, stop):
        try:
            # Backstop: never call the orchestrator for a host the allowlist rejects,
            # even if a future caller starts the thread without the handler check.
            try:
                allowlisted_host(target_url)
            except ScopeError as e:
                audit.record(
                    "scan", run_id=lease.run_id, actor=user, target=target_url,
                    status="rejected", detail="allowlist",
                )
                on_event({"type": "error", "message": str(e)})
                return

            def wrapped(ev: dict):
                if ev.get("type") in ("scan_started", "scan_complete"):
                    ev["requested_by"] = user
                if ev.get("type") == "scan_complete":
                    recon = ev.get("recon") if isinstance(ev.get("recon"), dict) else {}
                    ev["machines"] = machine_provenance(
                        client_ip, host, recon.get("server") or ""
                    )
                on_event(ev)

            with control.scope(lease):
                audit.record(
                    "scan", run_id=lease.run_id, actor=user, target=target_url, status="started",
                )
                try:
                    result = orchestrator.run_scan(
                        target_url, on_event=wrapped, should_stop=stop.is_set, run_id=lease.run_id,
                    )
                except Exception as e:
                    _audit_outcome(lease, None, error=type(e).__name__)
                    raise
                _audit_outcome(lease, result)
        finally:
            control.release(lease.run_id)

    events, stop = streaming.start_scan_thread(produce, lease.event)
    return StreamingResponse(
        streaming.sse_frames(events, stop),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/scan/stop")
def scan_stop(body: StopIn | None = None, user: str = Depends(verify_token)):
    """Stop one scan, or every in-flight scan when `all` is true or run_id is omitted."""
    body = body or StopIn()
    if body.all or not body.run_id:
        stopped = control.stop_all()
    else:
        stopped = [body.run_id] if control.stop(body.run_id) else []
    audit.record(
        "scan", actor=user, status="stop_requested",
        run_id=body.run_id or "", detail="all" if (body.all or not body.run_id) else "one",
        target="",
    )
    return {"stopped": stopped, "active": control.active_ids()}


class _PreviewNoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect would send the next request wherever Location says. Don't."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_preview_opener = urllib.request.build_opener(_PreviewNoRedirect)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def _header_map(headers) -> dict:
    if headers is None:
        return {}
    try:
        pairs = headers.items()
    except Exception:
        return {}
    return {str(k).lower(): v for k, v in pairs}


def _html_title(body: bytes) -> str:
    match = _TITLE_RE.search(body.decode("utf-8", "replace"))
    if not match:
        return ""
    text = re.sub(r"\s+", " ", match.group(1)).strip()
    return text[:120]


def _frameable(headers: dict) -> bool:
    """True when the dashboard's origin is allowed to embed this response.

    sameorigin and frame-ancestors 'self' still block us: the dashboard is a
    different origin from the lab target. Only an explicit wildcard (or no
    framing policy at all) counts as embeddable.
    """
    xfo = (headers.get("x-frame-options") or "").split(",")[0].strip().lower()
    if xfo in {"deny", "sameorigin"}:
        return False
    match = re.search(r"frame-ancestors\s+([^;]+)", headers.get("content-security-policy") or "", re.I)
    if not match:
        return True
    return match.group(1).split() == ["*"]


def _preview_pack(status: int, headers, body: bytes) -> dict:
    mapped = _header_map(headers)
    frameable = 200 <= status < 300 and _frameable(mapped)
    return {
        "mode": "iframe" if frameable else "placeholder",
        "frameable": frameable,
        "status": int(status),
        "title": _html_title(body or b""),
        "server": mapped.get("server") or "",
    }


def fetch_preview(url: str) -> dict:
    """GET one allowlisted URL for the dashboard thumbnail. No redirects.

    A failure becomes a placeholder. The caller has already checked the allowlist,
    so this never runs for an off-list host.
    """
    req = urllib.request.Request(url, headers={"User-Agent": "VulnSwarm/0.1"}, method="GET")
    try:
        resp = _preview_opener.open(req, timeout=1.5)
        try:
            return _preview_pack(getattr(resp, "status", 200), resp.headers, resp.read(4000))
        finally:
            resp.close()
    except urllib.error.HTTPError as e:
        try:
            body = e.read(2000)
        except Exception:
            body = b""
        return _preview_pack(e.code, e.headers, body)
    except Exception:
        return {
            "mode": "placeholder",
            "frameable": False,
            "status": 0,
            "title": "",
            "server": "",
        }


@app.get("/preview")
def preview(url: str, user: str = Depends(verify_token)):
    """How to draw this target. Off-list hosts are not contacted."""
    try:
        host = allowlisted_host(url)
    except ScopeError:
        return {
            "allowlisted": False,
            "mode": "placeholder",
            "frameable": False,
            "url": url,
            "host": urlparse(url).hostname or "",
            "title": urlparse(url).hostname or url,
            "status": 0,
            "server": "",
        }
    info = fetch_preview(url)
    info["allowlisted"] = True
    info["url"] = url
    info["host"] = host
    if not info.get("title"):
        info["title"] = host
    return info


@app.get("/audit")
def audit_recent(limit: int = 40, user: str = Depends(verify_token)):
    """Newest audit records first, plus the live caps so the dashboard can show them."""
    return {
        "records": audit.recent(limit),
        "limits": {
            "max_concurrent": control.max_concurrent(),
            "request_interval_ms": int(control.request_interval_s() * 1000),
            "global_request_interval_ms": int(control.global_interval_s() * 1000),
            "active": len(control.active_ids()),
        },
    }


@app.get("/health")
def health():
    return {"ok": True}
