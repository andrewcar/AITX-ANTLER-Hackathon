"""Langflow (CVE-2026-93680 / CVE-2026-110186) — version, then two read-only notes.

GET the version endpoint. Below 1.13.0 is Critical. When the body is Langflow,
also GET the MCP endpoint and the auto-login endpoint and note whether tools
are listed without a login and whether auto-login answers. A token in that
answer is never stored, never sent, and never copied into the finding.
"""
import json
import re

from .client import fetch_path
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, pad3, parse_dotted


VERSION = "/api/v1/version"
MCP = "/api/v1/mcp"
AUTO = "/api/v1/auto_login"
_FIXED = (1, 13, 0)
_TOKEN_KEY = re.compile(
    r'"(?:access_token|refresh_token|id_token|token)"\s*:',
    re.I,
)


def parse_version_body(body: str) -> tuple[bool, tuple[int, ...] | None]:
    """Return (is_langflow, version or None). The raw body is not returned."""
    if "langflow" not in (body or "").lower():
        return False, None
    version = None
    try:
        obj = json.loads(body)
    except json.JSONDecodeError:
        obj = None
    if isinstance(obj, dict):
        version = parse_dotted(str(obj.get("version") or "").lstrip("vV"))
    if version is None:
        match = re.search(r"langflow[^0-9]{0,12}(\d+\.\d+\.\d+)", body, re.I)
        if match:
            version = parse_dotted(match.group(1))
    return True, version


def below_fix(version: tuple[int, ...]) -> bool:
    return cmp_ver(pad3(version), _FIXED) < 0


def lists_tools(body: str, status: int) -> bool:
    if status != 200:
        return False
    try:
        obj = json.loads(body or "")
    except json.JSONDecodeError:
        return False
    return isinstance(obj, dict) and isinstance(obj.get("tools"), list)


def token_present(body: str) -> bool:
    """True when a token field name is present. The value is never returned."""
    return bool(_TOKEN_KEY.search(body or ""))


def run(section, ctx) -> list[dict]:
    resp = fetch_path(ctx, VERSION, max_bytes=32768)
    if resp.get("status") != 200:
        return []
    present, version = parse_version_body(resp.get("body") or "")
    if not present:
        return []
    findings = []
    if version is None:
        findings.append(base_finding(
            CHECK,
            severity="info",
            title=f"Langflow detected; version not exposed ({CHECK.cve})",
            evidence=(
                f"GET {VERSION} identified Langflow but no version number. "
                f"{CHECK.cve} was not compared."
            ),
            fix=f"Upgrade Langflow to 1.13.0 or later. See {CHECK.cve}.",
            match="langflow:unknown",
            layer="config",
        ))
    elif below_fix(version):
        label = fmt(pad3(version))
        findings.append(base_finding(
            CHECK,
            severity="critical",
            title=f"{UNCONFIRMED}: Langflow {label} ({CHECK.cve})",
            evidence=(
                f"Observed Langflow {label} via GET {VERSION}. {UNCONFIRMED}. "
                f"{label} is below 1.13.0. Advisories: {CHECK.cve}. "
                "No flow was run and no token was used."
            ),
            fix=f"Upgrade Langflow to 1.13.0 or later. See {CHECK.cve}.",
            match=f"langflow:{label}",
            layer="config",
        ))
    mcp = fetch_path(ctx, MCP, max_bytes=65536)
    tools = lists_tools(mcp.get("body") or "", mcp.get("status") or 0)
    tool_state = (
        "lists tools without login"
        if tools else "does not list tools without login"
    )
    findings.append(base_finding(
        CHECK,
        severity="info",
        title=f"Langflow MCP endpoint {tool_state}",
        evidence=(
            f"GET {MCP} -> HTTP {mcp.get('status')}; it {tool_state}. "
            "No login was attempted and no tool was invoked."
        ),
        fix="Require authentication before the MCP endpoint lists or runs tools.",
        match=f"langflow-mcp:{'open' if tools else 'closed'}",
        layer="auth",
    ))
    auto = fetch_path(ctx, AUTO, max_bytes=32768)
    status = auto.get("status") or 0
    # Last request on purpose: nothing in this check runs after a token could appear.
    answered = status == 200
    leaked = answered and token_present(auto.get("body") or "")
    if answered and leaked:
        note = "answers and returned a token; the token was not stored or sent"
    elif answered:
        note = "answers without login"
    else:
        note = "does not answer without login"
    findings.append(base_finding(
        CHECK,
        severity="info",
        title=f"Langflow auto-login {note}",
        evidence=(
            f"GET {AUTO} -> HTTP {status}; auto-login {note}. "
            "The response body was not copied into this finding and was not reused."
        ),
        fix="Disable auto-login on any Langflow instance that is not a private demo.",
        match=f"langflow-autologin:{'token' if leaked else ('open' if answered else 'closed')}",
        layer="auth",
    ))
    return findings


CHECK = CveCheck(
    id="langflow",
    cve="CVE-2026-93680 / CVE-2026-110186",
    agent="auth",
    fixed="1.13.0",
    summary=(
        "Read the version from Langflow's version endpoint and flag Critical below "
        "1.13.0. Note whether the MCP endpoint lists tools without login and whether "
        "auto-login answers. Read-only."
    ),
    sends="GET /api/v1/version, then GET /api/v1/mcp and GET /api/v1/auto_login only when that body is Langflow.",
    does_not_send="Never uses a returned token, never runs a flow, no POST.",
    run=run,
)
