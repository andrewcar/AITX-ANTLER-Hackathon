"""Confluence Data Center (CVE-2026-90436) — passive Axis/Remote-API version read.

Apache Axis 1.x (through 1.4, EOL, no upstream fix) has an unsafe-reflection
unauthenticated RCE (CWE-470, CVSS 9.8, disclosed 6 November 2026). Confluence
Data Center 1.x–9.x bundles Axis and is exploitable only when
"Remote API (XML-RPC & SOAP)" is enabled (off by default for new installs since
3.0). Fixed in 9.2.28; 10.x removed the feature; Atlassian Cloud is unaffected.
Rapid7 MDR observed exploitation in the wild on 13 November 2026.

Detection is passive only: fingerprint Confluence from the already-fetched
root/login HTML (``ajs-version-number`` / other ``ajs-`` meta tags, or the
"Powered by Atlassian Confluence" footer). When Confluence is present without a
version, at most one GET of ``/login.action``. Versions below 9.2.28 on major
<=9 are flagged unconfirmed — exploitability depends on the Remote API setting.
``*.atlassian.net`` hosts and 10.x+ are not flagged.

Never requests ``/rpc/``, ``/rpc/soap-axis/*``, ``/rpc/xmlrpc``, any ``?wsdl``,
or other Axis/SOAP paths; never sends XML or SOAP bodies; never POSTs.
"""
import re
from urllib.parse import urlparse

from .client import base_url, fetch_path, root_observation
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, pad3, parse_dotted


LOGIN = "/login.action"
_FIXED = (9, 2, 28)

_SOURCES = (
    "https://www.rapid7.com/blog/post/etr-rapid7-detected-exploitation-of-"
    "cve-2026-90436-against-atlassian-confluence-data-center-n-able-n-central-"
    "also-exploited/",
    "https://confluence.atlassian.com/security/cve-2026-90436-remote-code-"
    "execution-in-confluence-data-center-1874560038.html",
)

_AJS_VERSION = re.compile(
    r"""<meta[^>]+name\s*=\s*['"]ajs-version-number['"][^>]+"""
    r"""content\s*=\s*['"]([^'"]+)['"]""",
    re.I,
)
_AJS_VERSION_REV = re.compile(
    r"""<meta[^>]+content\s*=\s*['"]([^'"]+)['"][^>]+"""
    r"""name\s*=\s*['"]ajs-version-number['"]""",
    re.I,
)
_AJS_META = re.compile(
    r"""<meta[^>]+name\s*=\s*['"]ajs-[^'"]+['"]""",
    re.I,
)
_POWERED = re.compile(
    r"Powered by Atlassian Confluence",
    re.I,
)


def _fix() -> str:
    return (
        "Upgrade Confluence Data Center to 9.2.28 or a current 10.x release, or "
        "disable Remote API (XML-RPC & SOAP) under General Configuration → "
        "Further Configuration (takes effect without restart). Atlassian Cloud "
        f"is unaffected. See {CHECK.cve}. Sources: " + "; ".join(_SOURCES) + "."
    )


def _sources_note() -> str:
    return "Sources: " + "; ".join(_SOURCES) + "."


def atlassian_cloud(ctx) -> bool:
    """True for Atlassian Cloud hosts (unaffected; skip entirely)."""
    host = (urlparse(base_url(ctx)).hostname or "").lower()
    return host == "atlassian.net" or host.endswith(".atlassian.net")


def version_in(text: str) -> tuple[int, ...] | None:
    """First ajs-version-number dotted version in HTML, or None."""
    raw = text or ""
    for pattern in (_AJS_VERSION, _AJS_VERSION_REV):
        match = pattern.search(raw)
        if match:
            return parse_dotted(match.group(1))
    return None


def is_confluence(headers: dict, body: str) -> bool:
    """True when the already-fetched response fingerprints Confluence."""
    text = body or ""
    if version_in(text) is not None:
        return True
    if _AJS_META.search(text):
        return True
    if _POWERED.search(text):
        return True
    # Confluence often emits this timing header on HTML responses.
    if (headers or {}).get("x-confluence-request-time"):
        return True
    return False


def affected(version: tuple[int, ...]) -> bool:
    """True for major <=9 below 9.2.28. 10.x+ are not affected."""
    current = pad3(version)
    if current[0] >= 10:
        return False
    return cmp_ver(current, _FIXED) < 0


def _critical(version: tuple[int, ...], where: str) -> dict:
    label = fmt(pad3(version))
    return base_finding(
        CHECK,
        severity="critical",
        title=f"{UNCONFIRMED}: Confluence Data Center {label} ({CHECK.cve})",
        evidence=(
            f"Observed Confluence Data Center {label} via {where}. "
            f"{UNCONFIRMED}. Affected: Confluence Data Center 1.x–9.x below "
            f"9.2.28 when Remote API (XML-RPC & SOAP) is enabled (off by "
            f"default for new installs since 3.0). Fixed in 9.2.28; 10.x "
            f"removed the feature; Atlassian Cloud is unaffected. {CHECK.cve}: "
            "Apache Axis 1.x (<=1.4, EOL) unsafe-reflection unauthenticated "
            "RCE (CWE-470, CVSS 9.8). Exploitability depends on the Remote API "
            "setting, which this check does not confirm. Rapid7 MDR observed "
            "exploitation in the wild (13 November 2026). Only a passive "
            f"fingerprint and at most one GET of {LOGIN} were used; no /rpc/, "
            "Axis/SOAP, ?wsdl, XML, or SOAP body was sent. "
            f"{_sources_note()}"
        ),
        fix=_fix(),
        match=f"confluence-axis:{label}",
    )


def _info(where: str) -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=(
            f"Confluence Data Center detected; version not visible; confirm "
            f">= 9.2.28 or 10.x / Remote API off ({CHECK.cve}, exploited)"
        ),
        evidence=(
            f"Confluence Data Center was fingerprinted via {where} "
            f"(ajs- meta tags or Powered by Atlassian Confluence), but no "
            f"comparable ajs-version-number was readable from the root "
            f"response or GET {LOGIN}. {CHECK.cve} cannot be compared "
            "(affected 1.x–9.x below 9.2.28 when Remote API is enabled; fixed "
            "9.2.28 / 10.x). Confirm the install is patched or Remote API is "
            "disabled. No /rpc/, Axis/SOAP, ?wsdl, XML, or SOAP body was "
            f"sent. {_sources_note()}"
        ),
        fix=_fix(),
        match="confluence-axis:unknown",
    )


def run(section, ctx) -> list[dict]:
    if atlassian_cloud(ctx):
        return []

    headers, body = root_observation(ctx)
    if not is_confluence(headers, body):
        return []

    version = version_in(body)
    where = "root response"
    if version is None:
        resp = fetch_path(ctx, LOGIN, max_bytes=65536)
        text = resp.get("body") or ""
        version = version_in(text)
        if version is not None:
            where = f"GET {LOGIN}"
        elif is_confluence(resp.get("headers") or {}, text):
            where = f"GET {LOGIN}"

    if version is not None:
        if affected(version):
            return [_critical(version, where)]
        return []
    return [_info(where)]


CHECK = CveCheck(
    id="confluence-axis",
    cve="CVE-2026-90436",
    agent="misconfig",
    fixed="9.2.28+ or 10.x (affected: Confluence Data Center 1.x–9.x <9.2.28 when Remote API enabled)",
    summary=(
        "Fingerprint Confluence from the root response (ajs-version-number / "
        "other ajs- meta tags, or Powered by Atlassian Confluence), then read "
        "the version from that page or one GET of /login.action. Critical, "
        "version unconfirmed / Remote-API-dependent, when major <=9 and below "
        "9.2.28. Info when Confluence is present but the version is hidden. "
        "*.atlassian.net and 10.x+ are skipped. Non-Confluence targets are "
        "skipped."
    ),
    sends=(
        "Nothing when Confluence is not fingerprinted on the already-fetched "
        "homepage, or when the host is *.atlassian.net. Otherwise at most one "
        "GET /login.action when the version is not already on the root "
        "response."
    ),
    does_not_send=(
        "Never requests /rpc/, /rpc/soap-axis/*, /rpc/xmlrpc, any ?wsdl, or "
        "other Axis/SOAP paths. No XML or SOAP bodies, no POST/PUT, no login "
        "attempts, no uploads, no writes, and no malformed input."
    ),
    run=run,
)
