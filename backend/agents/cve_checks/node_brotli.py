"""Node2Shell Brotli (CVE-2026-111497) — one valid compressed JSON body.

Fingerprint Node, Express, or Bun from headers the scan already has. The one
Brotli JSON POST goes only to a URL the crawler already saw answer a plain GET
with 2xx JSON during this scan. Form actions, POST-only routes, and
state-changing paths are not targets. If nothing qualifies, the POST is not
sent and the finding is Info.
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
SKIPPED_TITLE = "Node/Express/Bun fingerprinted; Brotli check skipped"
# Substrings of a path that look state-changing. The POST never goes there.
_SKIP = (
    "logout", "login", "register", "signup", "delete", "remove",
    "upload", "password", "passwd", "reset", "drop", "wipe", "clear",
    "payment", "checkout", "order", "pay", "admin", "erase", "purge",
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


def _get_verified(item: dict) -> bool:
    """True only for a crawl GET that already returned 2xx JSON.

    Form actions and POST-only routes do not qualify, even if a caller dropped
    them into the endpoint list. A missing method or status does not qualify.
    """
    if not isinstance(item, dict):
        return False
    if str(item.get("method") or "").lower() != "get":
        return False
    if str(item.get("source") or "crawl").lower() in {"form", "post"}:
        return False
    try:
        status = int(item.get("status"))
    except (TypeError, ValueError):
        return False
    return 200 <= status < 300


def pick_endpoint(ctx) -> str | None:
    """One same-target URL the crawler GET already saw answer 2xx.

    Form actions and POST-only routes are not candidates: they never pass
    ``_get_verified``. A URL that is also a form action is still eligible when
    this scan already recorded a plain GET 2xx for it. State-changing paths
    are dropped even then.
    """
    surface = getattr(ctx, "surface", None) or {}
    verified = []
    for item in surface.get("json_endpoints") or []:
        if not _get_verified(item):
            continue
        url = (item.get("url") or "").split("#")[0]
        if not same_target(ctx, url) or _skippable(url):
            continue
        if urlparse(url).scheme not in ("http", "https"):
            continue
        verified.append(url)
    for url in verified:
        path = urlparse(url).path.lower()
        if "/api/" in path or "/rest/" in path:
            return url
    return verified[0] if verified else None


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


def _skipped(hint: str) -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=SKIPPED_TITLE,
        evidence=(
            f"{hint} was fingerprinted, but this scan had no JSON endpoint that "
            "answered a plain GET with 2xx. The Brotli check was skipped and no "
            "POST was sent. Form actions, POST-only routes, and state-changing "
            "paths are not targets."
        ),
        fix=(
            "Confirm the runtime is Node.js >= 22.23.4, >= 24.22.1, or >= 26.12.1, "
            f"or Bun > 1.4.3, if a public JSON GET is added later. See {CHECK.cve}."
        ),
        match="brotli:skipped",
    )


def run(section, ctx) -> list[dict]:
    hint = runtime_hint(ctx)
    if not hint:
        return []
    endpoint = pick_endpoint(ctx)
    if not endpoint:
        return [_skipped(hint)]
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
        "Fingerprint Node, Express, or Bun from headers already collected. Send one "
        "small valid Brotli JSON body only to a URL the crawler already saw answer "
        "a plain GET with 2xx JSON. If none exists, skip the POST and report Info."
    ),
    sends=(
        "One POST with Content-Encoding: br and a small valid Brotli JSON body, "
        "and only to a same-target URL that returned 2xx JSON to a crawl GET. "
        "Paths that look state-changing (login, register, signup, reset, delete, "
        "checkout, order, pay, upload, admin, and similar) are skipped."
    ),
    does_not_send=(
        "No POST to form actions, POST-only routes, or state-changing paths. "
        "No malformed stream, no oversized stream, no second compressed body, no exploit payload."
    ),
    run=run,
)
