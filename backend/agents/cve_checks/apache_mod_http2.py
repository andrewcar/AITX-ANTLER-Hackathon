"""Apache HTTP Server mod_http2 (CVE-2026-119618) — passive version fingerprint.

Race condition in ``assign_headers()`` can cause heap corruption when
``mod_http2`` is loaded and ``Protocols`` includes ``h2`` or ``h2c``. Affected
httpd 2.4.55–2.4.70 (standalone ``mod_h2`` 2.0.8–2.0.42). Fixed in 2.4.71
(released 2026-11-11). Public crash-reproduction research exists; not listed in
CISA KEV. This check does not attempt to trigger the race.

Detection is passive only: read the ``Server`` header (and any HTTP/2 signal)
already collected on the root response. No extra request. No raw sockets, no
custom HTTP/2 frames, no concurrent streams, no malformed input.
"""
import re

from .client import root_observation
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt


_AFFECTED_FROM = (2, 4, 55)
_AFFECTED_THROUGH = (2, 4, 70)
_FIXED = (2, 4, 71)

_APACHE = re.compile(r"\bApache/(\d+)\.(\d+)\.(\d+)\b", re.I)
# ALPN / negotiated-protocol tokens the recon layer may already have stored.
_H2_PROTOCOL = re.compile(r"(?:^|[\s/,;])(h2c?|http/2(?:\.0)?)(?:$|[\s/,;])", re.I)


def apache_version(server: str) -> tuple[int, int, int] | None:
    """Parse ``Apache/2.4.x`` from a Server header value. Bare ``Apache`` is None."""
    match = _APACHE.search(server or "")
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def affected(version: tuple[int, ...]) -> bool:
    """True for httpd 2.4.55 through 2.4.70 inclusive."""
    current = (tuple(version) + (0, 0, 0))[:3]
    if current[:2] != (2, 4):
        return False
    return (
        cmp_ver(current, _AFFECTED_FROM) >= 0
        and cmp_ver(current, _AFFECTED_THROUGH) <= 0
    )


def http2_seen(headers: dict, root: dict | None = None) -> bool:
    """True when the already-fetched response shows HTTP/2 (h2/h2c).

    Looks only at stored headers and recon fields — never opens a socket or
    speaks HTTP/2 frames.
    """
    upgrade = str((headers or {}).get("upgrade") or "")
    if _H2_PROTOCOL.search(upgrade):
        return True
    alt_svc = str((headers or {}).get("alt-svc") or "").lower()
    # Alt-Svc lists like: h2=":443"; ma=3600, h2c=":80"
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
    version = apache_version(server)
    if version is None or not affected(version):
        return []
    label = fmt(version)
    saw_h2 = http2_seen(headers, root)
    severity = "high" if saw_h2 else "medium"
    h2_note = (
        "HTTP/2 (h2/h2c) was already visible on the stored response "
        "(negotiated protocol, Upgrade, or Alt-Svc)."
        if saw_h2
        else (
            "No HTTP/2 signal was present on the stored response; the version "
            "is still in the advisory range, but reachability requires "
            "mod_http2 with Protocols including h2 or h2c."
        )
    )
    match = f"apache-mod-http2:{label}:{'h2' if saw_h2 else 'no-h2'}"
    return [base_finding(
        CHECK,
        severity=severity,
        title=f"{UNCONFIRMED}: Apache/{label} ({CHECK.cve})",
        evidence=(
            f"Observed Server header Apache/{label}. {UNCONFIRMED}. {h2_note} "
            f"{CHECK.cve}: race in mod_http2 assign_headers() (heap corruption; "
            "potentially unauthenticated RCE when HTTP/2 is enabled). Affected "
            f"httpd 2.4.55–2.4.70; fixed in {fmt(_FIXED)} (released 2026-11-11). "
            "Not listed in CISA KEV. Distro packages often backport fixes without "
            "changing the version string, so this is a version-based signal to "
            "verify against the vendor advisory — not a confirmed vulnerable "
            "build. No extra request was sent; no HTTP/2 frames, concurrent "
            "streams, race trigger, or malformed input was sent."
        ),
        fix=(
            f"Upgrade Apache HTTP Server to {fmt(_FIXED)} or later, or apply "
            "your distribution's backported security update for "
            f"{CHECK.cve}. Confirm mod_http2 / Protocols settings if HTTP/2 "
            "must stay enabled. See "
            "https://httpd.apache.org/security/vulnerabilities_24.html."
        ),
        match=match,
    )]


CHECK = CveCheck(
    id="apache-mod-http2",
    cve="CVE-2026-119618",
    agent="misconfig",
    fixed="2.4.71 (httpd); standalone mod_h2 after 2.0.42",
    summary=(
        "Read Apache/2.4.x from the Server header already on the root response. "
        "Likely vulnerable for 2.4.55–2.4.70: high when HTTP/2 was already "
        "visible (negotiated protocol, Upgrade: h2c, or Alt-Svc), medium "
        "otherwise. Notes distro backport ambiguity."
    ),
    sends=(
        "No extra request. Uses the Server header and any HTTP/2 signal already "
        "on the root response the scan fetched."
    ),
    does_not_send=(
        "No HEAD/GET beyond the existing root response. No raw sockets, no "
        "custom HTTP/2 frame logic, no concurrent or parallel HTTP/2 streams, "
        "no race trigger, no malformed frames, no POST, no auth bypass, no "
        "exploit payload."
    ),
    run=run,
)
