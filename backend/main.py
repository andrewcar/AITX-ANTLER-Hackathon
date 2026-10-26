"""
VulnSwarm backend — pipeline-proof slice.

Purpose of THIS file (not the final product): prove the pipeline works end to end:
    extension  --login-->  token  --/scan-->  backend  --finding-->  extension

The real swarm (orchestrator + specialist agents + verifier + reporter) plugs in
later behind the /scan endpoint. For now /scan returns a single stub finding so we
can confirm auth + transport + UI all round-trip before committing to the design.

SCOPE SAFETY: /scan refuses any target not on ALLOWLIST. This stays in the final
product — the tool must physically refuse to touch anything we don't own.
"""
import hashlib
import hmac
import json
import os
import time

import socket

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

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
    """The hosted sites the dashboard lists. For now, the allowlist itself."""
    return {"targets": sorted(ALLOWLIST)}


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


@app.post("/scan")
def scan(body: ScanIn, request: Request, user: str = Depends(verify_token)):
    """
    Pipeline proof: validate scope, then return ONE stub finding.
    Later this hands the target to the orchestrator and streams real findings.
    """
    from urllib.parse import urlparse

    import llm
    import recon

    host = urlparse(body.url).hostname or ""
    if host not in ALLOWLIST:
        raise HTTPException(
            403,
            f"target '{host or body.url}' is not on the allowlist — refusing to scan",
        )

    # 1. REAL recon — collect factual evidence from the target
    try:
        data = recon.scan(body.url)
    except Exception as e:
        raise HTTPException(502, f"could not reach target: {type(e).__name__}: {e}")

    # 2. AI triage — the LLM explains the evidence into findings
    findings, ai_status = [], "ok"
    if llm.available():
        try:
            findings = llm.analyze(data)
        except Exception as e:
            ai_status = f"ai_error: {type(e).__name__}: {str(e)[:120]}"
    else:
        ai_status = "ai_disabled: FEATHERLESS_API_KEY not set"

    # 3. Fallback — if the AI gave nothing, surface the hard recon facts directly
    #    so the scan is still useful (missing headers are a deterministic finding).
    if not findings:
        for h in data["missing_security_headers"]:
            findings.append({
                "id": f"RECON-{h}",
                "layer": "config",
                "severity": "low",
                "title": f"Missing security header: {h}",
                "evidence": f"HTTP {data['status']} from {body.url} had no '{h}' header",
                "verified": True,  # deterministic: we directly observed its absence
                "fix": f"Set the '{h}' response header.",
            })

    # --- machine identities (provenance): who asked, who scanned, what was scanned ---
    client_ip = request.client.host if request.client else ""
    machines = {
        "requested_from": {                         # the laptop running the extension
            "ip": client_ip,
            "name": _rev_dns(client_ip) or "unknown",
        },
        "scanner": {                                # the machine running this backend
            # inside docker the hostname is just the container id, so prefer an
            # explicit SCANNER_NAME from env (each host sets its own in .env)
            "name": os.environ.get("SCANNER_NAME") or socket.gethostname(),
        },
        "target": {                                 # the machine hosting the scanned site
            "url_host": host,
            "server_banner": data["server"] or "unknown",
            "name": _rev_dns(host) or "unknown",
        },
    }

    return {
        "target": body.url,
        "requested_by": user,
        "status": "complete",
        "ai": ai_status,
        "model": llm.MODEL,
        "machines": machines,
        "recon": {
            "status": data["status"],
            "server": data["server"],
            "scanned_internal": data["scanned_internal"],
        },
        "findings": findings,
    }


@app.get("/health")
def health():
    return {"ok": True}
