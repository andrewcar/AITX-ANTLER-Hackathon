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
"""
import hashlib
import hmac
import json
import os
import time
from urllib.parse import urlparse

import socket

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

import streaming

# --- config -----------------------------------------------------------------
# Demo secret. In real use this comes from env / a secrets store, never hardcoded.
SECRET = os.environ.get("VULNSWARM_SECRET", "dev-secret-change-me").encode()
TOKEN_TTL = 60 * 60 * 8  # 8 hours

# Demo users for the pipeline proof. Real version: proper user store + hashed pw.
# password here is "demo" for both — fine for a localhost pipeline test, not prod.
USERS = {
    "erwin@local": "demo",
    "andrew@local": "demo",
}

# The ONLY hosts the swarm is allowed to touch. Everything we own, nothing else.
# Fill with your tower's hosted sites. A target not in here is rejected at /scan.
ALLOWLIST = {
    "localhost",
    "127.0.0.1",
    "10.0.0.32",          # the tower's LAN IP — the targets are published here
    # add Andrew's server IP here when we bring it in
}

# The hosted lab targets shown on the dashboard (the multi-site "main page").
LAB_TARGETS = [
    {"name": "DVWA", "stack": "PHP / LAMP", "url": "http://10.0.0.32:8081"},
    {"name": "Juice Shop", "stack": "Node / SPA", "url": "http://10.0.0.32:3001"},
]

app = FastAPI(title="VulnSwarm backend (pipeline proof)")

# The extension and dashboard call us from a different origin, so allow CORS.
# Tighten to the real extension id + dashboard origin before any shared use.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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

    try:
        host = allowlisted_host(body.url)
    except ScopeError as e:
        raise HTTPException(403, str(e))

    # run the swarm: auth -> map -> plan -> swarm -> verify -> report
    try:
        result = orchestrator.run_scan(body.url)
    except Exception as e:
        raise HTTPException(502, f"scan failed: {type(e).__name__}: {e}")

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
    ALLOWLIST. The worker checks again before calling the orchestrator.

    Events (JSON, one per message, `type` field):
      scan_started, phase, agent, finding, verdict, scan_complete, error

    A disconnected client sets a per-request stop flag checked between phases.
    There is no global kill switch, no rate limit, and no audit log on this path.
    """
    import orchestrator

    try:
        host = allowlisted_host(body.url)
    except ScopeError as e:
        raise HTTPException(403, str(e))

    client_ip = request.client.host if request.client else ""
    target_url = body.url

    def produce(on_event, stop):
        # Backstop: never call the orchestrator for a host the allowlist rejects,
        # even if a future caller starts the thread without the handler check.
        try:
            allowlisted_host(target_url)
        except ScopeError as e:
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

        orchestrator.run_scan(
            target_url, on_event=wrapped, should_stop=stop.is_set
        )

    events, stop = streaming.start_scan_thread(produce)
    return StreamingResponse(
        streaming.sse_frames(events, stop),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/health")
def health():
    return {"ok": True}
