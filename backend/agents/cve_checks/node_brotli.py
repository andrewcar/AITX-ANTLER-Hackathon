"""Node2Shell Brotli (CVE-2026-111497) — one valid compressed JSON body.

Fingerprint Node, Express, or Bun from headers the scan already has. If the
crawler already recorded a JSON endpoint, send one small valid Brotli JSON
POST (Content-Encoding: br). Acceptance means the runtime should be checked;
this is not a version claim and not an exploit.
"""
import re
from urllib.parse import urlparse

import recon

from .client import same_target
from .spec import CveCheck, base_finding


TITLE = (
    "Node + Brotli request bodies accepted; verify runtime >= 22.23.4 / "
    "24.22.1 / 26.12.1, Bun > 1.4.3"
)
_SKIP = (
    "logout", "delete", "remove", "upload", "password", "passwd",
    "reset", "drop", "wipe", "clear", "payment", "checkout", "erase", "purge",
)


def runtime_hint(ctx) -> str:
    root = getattr(ctx, "recon_root", None) or {}
    headers = root.get("raw_headers") or {}
    fingerprint = getattr(ctx, "fingerprint", None) or {}
    parts = [
        str(root.get("server") or ""),
        str(headers.get("server") or ""),
        str(headers.get("x-powered-by") or ""),
        str(headers.get("x-runtime") or ""),
        str(fingerprint.get("lang") or ""),
        str(fingerprint.get("stack") or ""),
        str(fingerprint.get("server") or ""),
    ]
    blob = " ".join(parts).lower()
    if re.search(r"\bbun\b", blob):
        return "bun"
    if re.search(r"\b(node(?:\.js)?|express)\b", blob):
        return "node"
    if fingerprint.get("lang") == "node" or fingerprint.get("stack") == "node":
        return "node"
    return ""


def _skippable(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(part in path for part in _SKIP)


def pick_endpoint(ctx) -> str | None:
    surface = getattr(ctx, "surface", None) or {}
    endpoints = surface.get("json_endpoints") or []
    usable = []
    for item in endpoints:
        url = (item or {}).get("url") or ""
        if not same_target(ctx, url) or _skippable(url):
            continue
        if urlparse(url).scheme not in ("http", "https"):
            continue
        usable.append(url)
    for url in usable:
        if "/api/" in urlparse(url).path.lower() or "/rest/" in urlparse(url).path.lower():
            return url
    return usable[0] if usable else None


def _accepted(resp: dict) -> bool:
    status = resp.get("status") or 0
    if status == 204:
        return True
    if status < 200 or status >= 300:
        return False
    ctype = (resp.get("content_type") or "").lower()
    if "html" in ctype:
        return False
    if "json" in ctype:
        return True
    body = (resp.get("body") or "").lstrip()
    return body.startswith("{") or body.startswith("[")


def run(section, ctx) -> list[dict]:
    hint = runtime_hint(ctx)
    endpoint = pick_endpoint(ctx) if hint else None
    if not hint or not endpoint:
        return []
    resp = recon.post_brotli_json(endpoint, session=getattr(ctx, "session", None))
    if not _accepted(resp):
        return []
    path = urlparse(endpoint).path or "/"
    return [base_finding(
        CHECK,
        severity="high",
        title=TITLE,
        evidence=(
            f"{hint} was fingerprinted from response headers, and one valid "
            f"Brotli-encoded JSON body (Content-Encoding: br) to {path} was "
            f"accepted (HTTP {resp.get('status')}). {TITLE}. "
            f"Advisory: {CHECK.cve}. The body was not malformed or oversized, "
            "and this request is not repeated during verification."
        ),
        fix=(
            "Verify the runtime is Node.js >= 22.23.4, >= 24.22.1, or >= 26.12.1, "
            "or Bun > 1.4.3. Until then, do not accept Brotli request bodies. "
            f"See {CHECK.cve}."
        ),
        match=f"brotli:{path}",
        once=True,
    )]


CHECK = CveCheck(
    id="node-brotli",
    cve="CVE-2026-111497",
    agent="misconfig",
    fixed="Node.js 22.23.4 / 24.22.1 / 26.12.1, Bun > 1.4.3",
    summary=(
        "Fingerprint Node, Express, or Bun from headers already collected. If the "
        "crawler found a JSON endpoint, send one small valid Brotli JSON body. "
        "When that body is accepted, flag it so an operator can verify the runtime."
    ),
    sends=(
        "One POST with Content-Encoding: br and a small valid Brotli JSON body, "
        "and only to a JSON URL the crawler already recorded (not a logout, delete, "
        "upload, password, or reset path)."
    ),
    does_not_send="No malformed stream, no oversized stream, no second compressed body, no exploit payload.",
    run=run,
)
