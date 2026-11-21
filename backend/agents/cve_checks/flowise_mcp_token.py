"""Flowise (CVE-2026-130796) — version fingerprint only.

One GET of Flowise's version document. High when the version is 3.1.3 or 3.1.4
(the range VulnCheck lists; no fixed release exists, the project is archived).
The public-chatflow route and the MCP route are never requested: the leak
needs a chatflow id, and the MCP route would use a leaked bearer token.
"""
import json

from .client import fetch_path
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, pad3, parse_dotted


VERSION = "/api/v1/version"
_LOW = (3, 1, 3)
_HIGH = (3, 1, 4)


def parse_version_body(body: str) -> tuple[int, ...] | None:
    """Version from a small ``{"version": "x.y.z"}`` document, else None."""
    try:
        obj = json.loads(body or "")
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict) or "version" not in obj or len(obj) > 3:
        return None
    return parse_dotted(str(obj.get("version") or "").strip().lstrip("vV"))


def affected(version: tuple[int, ...]) -> bool:
    v = pad3(version)
    return cmp_ver(v, _LOW) >= 0 and cmp_ver(v, _HIGH) <= 0


def run(section, ctx) -> list[dict]:
    resp = fetch_path(ctx, VERSION, max_bytes=4096)
    if resp.get("status") != 200:
        return []
    version = parse_version_body(resp.get("body") or "")
    if version is None or not affected(version):
        return []
    label = fmt(pad3(version))
    return [base_finding(
        CHECK,
        severity="high",
        title=f"{UNCONFIRMED}: Flowise {label} ({CHECK.cve})",
        evidence=(
            f"Observed version {label} via GET {VERSION}, inside the affected "
            f"range 3.1.3 to 3.1.4. {UNCONFIRMED}. The version document alone "
            "does not identify Flowise, and exposure also needs a public "
            "chatflow with its MCP server enabled; neither was tested. "
            f"{CHECK.cve} (CVSS 8.8, VulnCheck). No fixed version is listed. "
            "No chatflow or MCP route was requested."
        ),
        fix=(
            "Turn off the public flag on every chatflow with MCP enabled (or "
            "disable the MCP server), rotate MCP bearer tokens, and plan a "
            "move off Flowise: the project is archived and no patch is coming."
        ),
        match=f"flowise-mcp-token:{label}",
    )]


CHECK = CveCheck(
    id="flowise-mcp-token",
    cve="CVE-2026-130796",
    agent="secrets",
    fixed="none listed (Flowise archived 2026-08-10)",
    summary=(
        "Read the version from Flowise's version document. High when it is "
        "3.1.3 or 3.1.4, which leak MCP bearer tokens through public chatflows."
    ),
    sends="One GET /api/v1/version.",
    does_not_send=(
        "Never requests /api/v1/public-chatflows or /api/v1/mcp. No POST, no "
        "token, no exploit payload."
    ),
    run=run,
)
