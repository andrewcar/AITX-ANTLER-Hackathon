"""mljar Mercury unauthenticated terminal API (CVE-2026-111057 / GHSA-f8c7-rwf9-fmgm).

Mercury (pip ``mercury``) turns Jupyter notebooks into web apps. Versions
3.0.0–3.2.3 start Jupyter with anonymous access and a URL blocklist whose
missing comma left ``/api/terminals`` unblocked, so an unauthenticated caller
could reach Jupyter's terminal API (CVSS 10.0). Fixed in 3.2.4 (21 August
2026). Sibling CVE-2026-111058 (CVSS 9.8): through 3.2.5 anonymous users can
start a kernel via ``/api/kernels`` and run Python; fixed in 3.2.6. Sibling
CVE-2026-111059 (CVSS 6.1): stored XSS in ``mr.Markdown``; fixed in 3.2.11.
Recommended floor: 3.2.11. Exploitation in the wild is not established (not
in CISA KEV).

Detection is passive and gated: fingerprint Mercury from already-crawled root
HTML (verified markers from ``mljar/mercury`` templates), optionally compare a
passively visible version, then at most one read-only GET of ``/api/terminals``
(Jupyter's list-terminals endpoint). Critical for an open terminal list;
version floors map to critical / high / medium for the three CVEs.

Never POSTs ``/api/terminals`` (that spawns a shell), never opens a WebSocket
(``/terminals/websocket/*``, ``/api/kernels/*/channels``), never touches
``/api/kernels``, ``/api/sessions``, ``/api/contents``, ``/files``, ``/lab``,
or ``/api/shutdown``, and never sends tokens, auth, code, or payloads.
"""
import json
import re

from .client import fetch_path, root_observation
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, pad3, parse_dotted


TERMINALS = "/api/terminals"
_TERMINAL_FIXED = (3, 2, 4)
_KERNEL_FIXED = (3, 2, 6)
_XSS_FIXED = (3, 2, 11)
_FLOOR = (3, 2, 11)

_SOURCES = (
    "https://github.com/mljar/mercury/security/advisories/GHSA-f8c7-rwf9-fmgm",
    "https://osv.dev/vulnerability/GHSA-f8c7-rwf9-fmgm",
    "https://advisories.gitlab.com/pypi/mercury/CVE-2026-111057/",
    "https://safeguard.sh/resources/blog/mercury-cve-2026-111057-cve-2026-111058-"
    "missing-comma-blocklist-rce",
)

# Markers verified from mljar/mercury mercury_app/templates/{root,app,page,login}.html.
_CSS_VAR = re.compile(r"--mercury-(?:content-background|topbar-background|font-family|text-color)\b")
_CLASS = re.compile(
    r"\b(?:mercury-starting-loader|mercury-page-header|mercury-page-brand|"
    r"mercury-left-panel|mercury-runall-btn|hideMercuryLoader)\b"
)
_FOOTER = re.compile(r"MLJAR\s*-\s*next generation of AI tools", re.I)
_WELCOME = re.compile(r"Welcome to Mercury\.", re.I)
_NOSCRIPT = re.compile(r"Mercury requires JavaScript\.", re.I)
_LOADER_ID = re.compile(r"""id=["']mercury-loader["']""", re.I)
_TITLE = re.compile(r"<title[^>]*>\s*Mercury\s*</title>", re.I)

# Passively visible version near a Mercury product token (not a generic word alone).
_VERSION_NEAR = re.compile(
    r"(?:@mljar/mercury(?:-meta|-extension|-app)?|mercury(?:-framework)?)"
    r"[^0-9]{0,48}v?(\d+\.\d+\.\d+)",
    re.I,
)
_VERSION_AT = re.compile(r"\bmercury@(\d+\.\d+\.\d+)\b", re.I)
_VERSION_LABEL = re.compile(
    r"\bMercury(?:\s+Framework)?(?:\s+v(?:ersion)?|\s+)(\d+\.\d+\.\d+)\b",
    re.I,
)


def _sources_note() -> str:
    return "Sources: " + "; ".join(_SOURCES) + "."


def _fix() -> str:
    return (
        "Upgrade Mercury (pip package mercury) to 3.2.11 or later. "
        "3.2.4 blocks /api/terminals (CVE-2026-111057); 3.2.6 closes the "
        "anonymous /api/kernels path (CVE-2026-111058); 3.2.11 fixes stored "
        "XSS in mr.Markdown (CVE-2026-111059). Do not expose Mercury on an "
        "untrusted network without an authenticating reverse proxy. "
        f"See {CHECK.cve}. {_sources_note()}"
    )


def is_mercury(body: str) -> bool:
    """True when crawled HTML matches verified Mercury template markers."""
    text = body or ""
    if _CSS_VAR.search(text):
        return True
    if _CLASS.search(text):
        return True
    if _FOOTER.search(text):
        return True
    if _WELCOME.search(text):
        return True
    if _NOSCRIPT.search(text):
        return True
    if _LOADER_ID.search(text):
        return True
    # Title alone is weak; require another Mercury CSS/class token nearby.
    if _TITLE.search(text) and (
        "--mercury-" in text or "mercury-page-" in text or "mercury-starting-" in text
    ):
        return True
    return False


def version_in(text: str) -> tuple[int, ...] | None:
    """First comparable Mercury version passively visible in HTML/assets."""
    raw = text or ""
    for pattern in (_VERSION_AT, _VERSION_NEAR, _VERSION_LABEL):
        match = pattern.search(raw)
        if match:
            found = parse_dotted(match.group(1))
            if found:
                return found
    return None


def terminals_list_open(resp: dict) -> bool:
    """True when GET /api/terminals returns a Jupyter terminals JSON list."""
    if (resp.get("status") or 0) != 200:
        return False
    headers = {
        str(key).lower(): str(value)
        for key, value in (resp.get("headers") or {}).items()
    }
    ctype = (resp.get("content_type") or headers.get("content-type") or "").lower()
    if "json" not in ctype:
        return False
    try:
        obj = json.loads(resp.get("body") or "")
    except (json.JSONDecodeError, TypeError):
        return False
    if not isinstance(obj, list):
        return False
    for item in obj:
        if not isinstance(item, dict) or "name" not in item:
            return False
    return True


def version_severity(version: tuple[int, ...]) -> str | None:
    """Severity for a visible Mercury version, or None when at/above 3.2.11."""
    current = pad3(version)
    if cmp_ver(current, _TERMINAL_FIXED) < 0:
        return "critical"
    if cmp_ver(current, _KERNEL_FIXED) < 0:
        return "high"
    if cmp_ver(current, _XSS_FIXED) < 0:
        return "medium"
    return None


def _version_finding(version: tuple[int, ...], severity: str) -> dict:
    label = fmt(pad3(version))
    if severity == "critical":
        advisory = (
            f"{CHECK.cve} / GHSA-f8c7-rwf9-fmgm (CVSS 10.0): missing-comma "
            "blocklist left /api/terminals reachable for anonymous OS shell "
            "access. Affected 3.0.0–3.2.3; fixed in 3.2.4. Sibling "
            "CVE-2026-111058 (anonymous /api/kernels RCE, fixed 3.2.6) and "
            "CVE-2026-111059 (mr.Markdown stored XSS, fixed 3.2.11) also apply "
            "below the 3.2.11 floor."
        )
        match = f"mercury:{label}:terminals-cve"
    elif severity == "high":
        advisory = (
            f"CVE-2026-111058 (CVSS 9.8): anonymous users can start a kernel "
            "via /api/kernels and run Python. Affected through 3.2.5; fixed "
            f"in 3.2.6. Primary {CHECK.cve} (/api/terminals) is fixed in "
            "3.2.4+; sibling CVE-2026-111059 (stored XSS) still applies below "
            "3.2.11."
        )
        match = f"mercury:{label}:kernels-cve"
    else:
        advisory = (
            "CVE-2026-111059 (CVSS 6.1): stored XSS in mr.Markdown. Fixed in "
            f"3.2.11. Primary {CHECK.cve} and CVE-2026-111058 are fixed in "
            "3.2.4+ / 3.2.6+."
        )
        match = f"mercury:{label}:xss-cve"
    return base_finding(
        CHECK,
        severity=severity,
        title=f"{UNCONFIRMED}: Mercury {label} ({CHECK.cve})",
        evidence=(
            f"Observed Mercury {label} in already-crawled HTML/assets. "
            f"{UNCONFIRMED}. {advisory} Recommended floor: 3.2.11. "
            "Exploitation in the wild is not established (not in CISA KEV). "
            f"Only a Mercury fingerprint and at most one GET of {TERMINALS} "
            "were used; no POST /api/terminals, WebSocket, /api/kernels, "
            f"/api/sessions, /api/contents, or /api/shutdown was sent. "
            f"{_sources_note()}"
        ),
        fix=_fix(),
        match=match,
    )


def _terminal_finding(version: tuple[int, ...] | None) -> dict:
    if version is not None:
        label = fmt(pad3(version))
        version_note = (
            f" Passively observed Mercury {label}; recommended floor is "
            f"{fmt(_FLOOR)} ({UNCONFIRMED} for version-gated siblings)."
        )
        match = f"mercury:{label}:terminals-open"
    else:
        version_note = (
            " Mercury was fingerprinted but no comparable version was visible."
        )
        match = "mercury:unknown:terminals-open"
    return base_finding(
        CHECK,
        severity="critical",
        title="Unauthenticated Jupyter terminal API reachable (Mercury)",
        evidence=(
            f"GET {TERMINALS} returned HTTP 200 JSON that parses as a Jupyter "
            "terminals list (each item has a name field, including an empty "
            "list). Unauthenticated Jupyter terminal API reachable — on "
            f"Mercury 3.0.0–3.2.3 this maps to {CHECK.cve} / GHSA-f8c7-rwf9-fmgm "
            "(CVSS 10.0, missing-comma blocklist). Exploitation in the wild "
            "is not established (not in CISA KEV)."
            f"{version_note} "
            "Only a read-only GET was sent; no POST /api/terminals (shell "
            "spawn), WebSocket, /api/kernels, /api/sessions, /api/contents, "
            f"or /api/shutdown was used. {_sources_note()}"
        ),
        fix=_fix(),
        match=match,
    )


def run(section, ctx) -> list[dict]:
    _headers, body = root_observation(ctx)
    if not is_mercury(body):
        return []

    version = version_in(body)
    findings: list[dict] = []

    resp = fetch_path(ctx, TERMINALS, max_bytes=65536)
    if terminals_list_open(resp):
        findings.append(_terminal_finding(version))
        return findings

    if version is None:
        # Fingerprinted, terminals blocked/opaque, no version — emit nothing.
        return []

    severity = version_severity(version)
    if severity is None:
        return []
    findings.append(_version_finding(version, severity))
    return findings


CHECK = CveCheck(
    id="mercury",
    cve="CVE-2026-111057",
    agent="misconfig",
    fixed="3.2.11 (3.2.4 terminals / 3.2.6 kernels / 3.2.11 XSS)",
    summary=(
        "Fingerprint Mercury from crawled HTML (template CSS vars / classes / "
        "MLJAR footer / Welcome to Mercury), compare a visible version against "
        "3.2.4 / 3.2.6 / 3.2.11 floors, then at most one GET /api/terminals. "
        "Critical when that list answers as JSON; otherwise critical/high/"
        "medium from the version floors. Not in CISA KEV."
    ),
    sends=(
        "Nothing when Mercury is not fingerprinted on already-crawled HTML. "
        "Otherwise one GET /api/terminals."
    ),
    does_not_send=(
        "Never POST /api/terminals. Never WebSocket /terminals/websocket/*, "
        "/api/kernels/*/channels. Never GET/POST /api/kernels, /api/sessions, "
        "/api/contents, /files, /lab, or /api/shutdown. No tokens, auth, "
        "code execution, payloads, or malformed input."
    ),
    run=run,
)
