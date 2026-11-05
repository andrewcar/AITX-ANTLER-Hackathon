"""Unauthenticated Node-RED editor (CVE-2026-58115).

One GET /settings. If that response is not Node-RED, one fallback GET /flows.
A 200 Node-RED document with no auth challenge is Critical. /flows is never POSTed.
"""
import json

from .client import fetch_path
from .spec import CveCheck, base_finding


_NODE_TYPES = {
    "tab", "subflow", "function", "inject", "debug", "comment", "switch", "change",
}


def _load(body: str):
    try:
        return json.loads(body or "")
    except (json.JSONDecodeError, TypeError):
        return None


def is_settings(body: str) -> bool:
    obj = _load(body)
    if not isinstance(obj, dict):
        return False
    if "httpNodeRoot" in obj:
        return True
    if "editorTheme" in obj and any(key in obj for key in ("version", "codeEditor", "context")):
        return True
    return False


def is_flows(body: str) -> bool:
    obj = _load(body)
    if not isinstance(obj, list) or not obj:
        return False
    return any(isinstance(node, dict) and node.get("type") in _NODE_TYPES for node in obj[:30])


def challenged(resp: dict) -> bool:
    if resp.get("status") in (401, 403):
        return True
    headers = {str(k).lower(): v for k, v in (resp.get("headers") or {}).items()}
    return bool(headers.get("www-authenticate"))


def _critical(path: str) -> dict:
    return base_finding(
        CHECK,
        severity="critical",
        title="Unauthenticated Node-RED editor (adminAuth not set) = RCE",
        evidence=(
            f"GET {path} returned HTTP 200 Node-RED JSON and no authentication "
            f"challenge. Unauthenticated Node-RED editor (adminAuth not set) = RCE. "
            f"Advisory: {CHECK.cve}. Only a GET was sent; /flows was not POSTed."
        ),
        fix=(
            "Set adminAuth in Node-RED's settings file and do not expose the editor "
            f"on an untrusted network. See {CHECK.cve}."
        ),
        match=f"nodered:{path}",
        layer="auth",
    )


def _denial_is_nodered(resp: dict) -> bool:
    if resp.get("status") not in (401, 403) and not challenged(resp):
        return False
    blob = (resp.get("body") or "").lower()
    return "node-red" in blob or "nodered" in blob or "adminauth" in blob


def run(section, ctx) -> list[dict]:
    settings = fetch_path(ctx, "/settings", max_bytes=65536)
    if settings.get("status") == 200 and is_settings(settings.get("body") or "") and not challenged(settings):
        return [_critical("/settings")]
    if _denial_is_nodered(settings):
        return []
    flows = fetch_path(ctx, "/flows", max_bytes=65536)
    if flows.get("status") == 200 and is_flows(flows.get("body") or "") and not challenged(flows):
        return [_critical("/flows")]
    return []


CHECK = CveCheck(
    id="nodered-admin",
    cve="CVE-2026-58115",
    agent="auth",
    fixed="adminAuth configured (this is not a version check)",
    summary=(
        "GET /settings once, falling back to GET /flows only when /settings is not "
        "a Node-RED answer. Critical when a 200 Node-RED document comes back with "
        "no auth challenge."
    ),
    sends="One GET /settings, plus GET /flows only as that fallback.",
    does_not_send="Never POST /flows. No flow deploy, no exploit payload.",
    run=run,
)
