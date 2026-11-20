"""NGINX nginx2root (CVE-2026-123007) — passive Server-header fingerprint.

Primary advisory CVE-2026-123007: HTTP/2 flow-control heap overflow (CVSS
8.1–9.2) when HTTP/2 is enabled on a listener. Sibling nginx2root flaws
(CVE-2026-123633 HTTP/2 proxy UAF, CVE-2026-121810 HTTP/3 UAF,
CVE-2026-123634 resolver UAF, CVE-2026-113425 mail auth_http UAF) share the
same fixed releases. Affected Open Source builds: 1.9.5 through 1.31.8.
Fixed in NGINX Open Source 1.30.7 (stable) and 1.31.9 (mainline); NGINX Plus
R37 37.0.8.1 / 37.3.0.1. Public PoC exists (Rapid7, against 1.31.8). Not in
CISA KEV and no confirmed in-the-wild exploitation as of 2026-11-20.
Exploitability depends on config (HTTP/2 enablement), so version alone does
not prove exposure — findings are marked unconfirmed.

Detection is passive only: read the ``Server`` header already collected on
the root response (e.g. ``nginx/1.31.8``). No extra request. No HTTP/2 or
HTTP/3/QUIC connections, no flow-control / WINDOW_UPDATE frames, no SETTINGS
or malformed frames, no connection floods, no mail-proxy connections, no
raw sockets, no exploit payload. Bare ``nginx`` (server_tokens off),
OpenResty/Tengine, and non-nginx banners yield no finding.
"""
import re

from .client import root_observation
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, parse_dotted


_AFFECTED_FROM = (1, 9, 5)
_FIXED_STABLE = (1, 30, 7)
_FIXED_MAINLINE = (1, 31, 9)

# Strict ``nginx/x.y[.z]`` only — never map OpenResty/Tengine version lines.
_NGINX = re.compile(r"(?<![-\w])nginx/(\d+\.\d+(?:\.\d+){0,2})\b", re.I)
# ALPN / negotiated-protocol tokens the recon layer may already have stored.
_H2_PROTOCOL = re.compile(r"(?:^|[\s/,;])(h2c?|http/2(?:\.0)?)(?:$|[\s/,;])", re.I)

_SOURCES = (
    "https://www.cert.europa.eu/publications/security-advisories/2026-022",
    "https://www.bleepingcomputer.com/news/security/"
    "critical-nginx-nginx2root-bugs-let-attackers-hijack-servers/",
    "https://blog.qualys.com/product-tech/patch-management/2026/11/18/"
    "nginx2root-five-nginx-flaws-led-by-cve-2026-123007-how-to-find-mitigate"
    "-and-patch-now",
    "https://blog.cloudflare.com/nginx2root/",
    "https://nginx.org/en/security_advisories.html",
)


def nginx_version(server: str) -> tuple[int, ...] | None:
    """Parse ``nginx/x.y[.z]`` from a Server header. Bare ``nginx`` is None."""
    match = _NGINX.search(server or "")
    if not match:
        return None
    return parse_dotted(match.group(1))


def affected(version: tuple[int, ...]) -> bool:
    """True when the Open Source version is in the nginx2root advisory range.

    ``1.9.5 <= v`` and not fixed: ``1.30.x`` fixed at 1.30.7; ``1.31.x`` (and
    later mainline) fixed at 1.31.9; any other branch below 1.30 (EOL) is
    vulnerable. ``< 1.9.5`` and patched floors yield False.
    """
    current = (tuple(version) + (0, 0, 0))[:3]
    if cmp_ver(current, _AFFECTED_FROM) < 0:
        return False
    if current[:2] == (1, 30):
        return cmp_ver(current, _FIXED_STABLE) < 0
    if cmp_ver(current, (1, 31, 0)) >= 0:
        return cmp_ver(current, _FIXED_MAINLINE) < 0
    # Branches below 1.30 that are still >= 1.9.5 (all EOL).
    return cmp_ver(current, (1, 30, 0)) < 0


def http2_seen(headers: dict, root: dict | None = None) -> bool:
    """True when the already-fetched response shows HTTP/2 (h2/h2c).

    Looks only at stored headers and recon fields — never opens a socket or
    speaks HTTP/2 frames.
    """
    upgrade = str((headers or {}).get("upgrade") or "")
    if _H2_PROTOCOL.search(upgrade):
        return True
    alt_svc = str((headers or {}).get("alt-svc") or "").lower()
    if re.search(r"(?:^|[\s,])h2c?=", alt_svc):
        return True
    root = root or {}
    for key in (
        "http_version",
        "protocol",
        "alpn",
        "negotiated_protocol",
        "negotiated_alpn",
    ):
        value = str(root.get(key) or "")
        if _H2_PROTOCOL.search(value):
            return True
    return False


def _server_value(headers: dict, root: dict) -> str:
    return str(
        (headers or {}).get("server")
        or (root or {}).get("server")
        or ""
    )


def run(section, ctx) -> list[dict]:
    headers, _body = root_observation(ctx)
    root = getattr(ctx, "recon_root", None) or {}
    server = _server_value(headers, root)
    version = nginx_version(server)
    if version is None or not affected(version):
        return []
    label = fmt(version)
    saw_h2 = http2_seen(headers, root)
    h2_note = (
        "HTTP/2 (h2/h2c) was already visible on the stored response "
        "(negotiated protocol, Upgrade, or Alt-Svc); HTTP/2 enablement is "
        "still not fully verified for every listener."
        if saw_h2
        else (
            "No HTTP/2 signal was present on the stored response; the version "
            "is still in the advisory range, but reachability requires HTTP/2 "
            "enabled on a listener (Florian Roth / CERT-EU: config-dependent)."
        )
    )
    return [base_finding(
        CHECK,
        severity="high",
        title=f"{UNCONFIRMED}: nginx/{label} ({CHECK.cve})",
        evidence=(
            f"Observed Server header nginx/{label}. {UNCONFIRMED}. {h2_note} "
            f"{CHECK.cve}: HTTP/2 flow-control heap overflow (CVSS 8.1–9.2) "
            "when HTTP/2 is enabled. Sibling nginx2root advisories: "
            "CVE-2026-123633 (HTTP/2 proxy UAF), CVE-2026-121810 (HTTP/3 UAF), "
            "CVE-2026-123634 (resolver UAF), CVE-2026-113425 (mail auth_http "
            "UAF). Affected Open Source 1.9.5–1.31.8; fixed in 1.30.7 "
            "(stable) / 1.31.9 (mainline) and NGINX Plus 37.0.8.1 / 37.3.0.1. "
            "Public PoC (Rapid7, against 1.31.8). Not listed in CISA KEV and "
            "no confirmed in-the-wild exploitation as of 2026-11-20. Version "
            "alone does not prove exposure. No extra request was sent; no "
            "HTTP/2 or HTTP/3/QUIC connection, WINDOW_UPDATE / SETTINGS / "
            "malformed frames, connection flood, or mail-proxy probe was "
            f"sent. Sources: {', '.join(_SOURCES)}."
        ),
        fix=(
            "Upgrade NGINX Open Source to 1.30.7 (stable) or 1.31.9 "
            "(mainline), or NGINX Plus to 37.0.8.1 / 37.3.0.1, then restart. "
            "Interim mitigation: disable HTTP/2 on listeners until patched. "
            "See https://nginx.org/en/security_advisories.html and CERT-EU "
            "2026-022."
        ),
        match=f"nginx2root:{label}",
    )]


CHECK = CveCheck(
    id="nginx2root",
    cve="CVE-2026-123007",
    agent="misconfig",
    fixed="1.30.7 (stable) / 1.31.9 (mainline); NGINX Plus 37.0.8.1 / 37.3.0.1",
    summary=(
        "Read nginx/x.y.z from the Server header already on the root response. "
        "High (unconfirmed) for Open Source 1.9.5–1.31.8 not yet on 1.30.7 / "
        "1.31.9: HTTP/2 enablement is not verified. Bare nginx, OpenResty, "
        "and non-nginx banners yield no finding."
    ),
    sends=(
        "No extra request. Uses the Server header (and any HTTP/2 signal "
        "already on the root response) the scan fetched."
    ),
    does_not_send=(
        "No HEAD/GET beyond the existing root response. No HTTP/2 or "
        "HTTP/3/QUIC connections, no WINDOW_UPDATE / SETTINGS / malformed "
        "frames, no flow-control abuse, no connection floods, no mail-proxy "
        "connections, no raw sockets, no POST, no auth bypass, no exploit "
        "payload."
    ),
    run=run,
)
