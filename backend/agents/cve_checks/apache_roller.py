"""Apache Roller XML-RPC deserialization RCE (CVE-2026-129448).

Same bug as CVE-2026-82384. Roller 4.0.0 through 6.1.5 deserialize XML-RPC
vendor extension types before authenticating at ``/roller-services/xmlrpc``
(or ``/roller/roller-services/xmlrpc``). Fixed in 6.1.6. CVSS 9.8. Apache
reports active exploitation (ASF / oss-security 2026-11-17); CISA added it
to KEV on 2026-11-20. Disabling XML-RPC in the admin UI is not enough on
older versions; mitigation is ``enabledForExtensions=false`` in
``WEB-INF/web.xml`` or removing the servlet mapping.

Detection is passive only: fingerprint Roller from already-crawled HTML using
markers verified in ``apache/roller`` (``/roller-ui/`` UI assets from
``WEB-INF/jsps/tiles/head.jsp`` and themes, ``/themes/<name>/`` via
``URLModel.themeResource``, ``Powered by Apache Roller`` /
``footer.productName`` version string, feed ``<generator>Apache Roller``).
When a comparable version is visible (generator / powered-by Version /
asset ``?ver=``), versions ``4.0.0 <= v < 6.1.6`` are Critical. Hidden
version yields an Info note. No fingerprint → no finding and no request.

Never requests ``/roller-services/xmlrpc``, ``/roller/roller-services/xmlrpc``,
``/roller-ui/login*``, ``/roller-ui/admin*``, or ``/roller-services/rest*``.
No XML-RPC body, no auth, no payloads, no malformed input, no POST/PUT/DELETE.
"""
import re

from .client import root_observation
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, pad3, parse_dotted


_AFFECTED_FROM = (4, 0, 0)
_FIXED = (6, 1, 6)

_SOURCES = (
    "https://www.openwall.com/lists/oss-security/2026/11/17/5",
    "https://thehackernews.com/2026/11/critical-apache-roller-rce-flaw-under.html",
    "https://www.bleepingcomputer.com/news/security/apache-warns-of-roller-rce-"
    "vulnerability-exploited-in-attacks/",
    "https://www.cisa.gov/news-events/alerts/2026/11/20/"
    "cisa-adds-four-known-exploited-vulnerabilities-catalog",
)

# Theme directory names under app/src/main/webapp/themes/ (apache/roller).
_THEME_NAMES = (
    "basic",
    "basicmobile",
    "fauxcoly",
    "frontpage",
    "gaurav",
    "hyde",
    "papermod",
    "terminal",
)
_THEME_PATH = re.compile(
    r"/themes/(?:" + "|".join(_THEME_NAMES) + r")/",
    re.I,
)
_ROLLER_UI = re.compile(r"/roller-ui/", re.I)
_OPENSEARCH = re.compile(r"/roller-services/opensearch\b", re.I)
# ApplicationResources: generic.poweredBy / footer.productName (may wrap a link).
_POWERED = re.compile(
    r"Powered by(?:\s|<[^>]+>)*Apache\s+Roller\b",
    re.I,
)
_GENERATOR_META = re.compile(
    r"""<meta[^>]+name\s*=\s*['"]generator['"][^>]+"""
    r"""content\s*=\s*['"]([^'"]*Apache\s+Roller[^'"]*)['"]""",
    re.I,
)
_GENERATOR_META_REV = re.compile(
    r"""<meta[^>]+content\s*=\s*['"]([^'"]*Apache\s+Roller[^'"]*)['"]"""
    r"""[^>]+name\s*=\s*['"]generator['"]""",
    re.I,
)
_FEED_GENERATOR = re.compile(
    r"<generator\b[^>]*>\s*Apache\s+Roller\b",
    re.I,
)

# Version next to the verified footer / powered-by product string.
_VERSION_FOOTER = re.compile(
    r"Apache\s+Roller(?:\s+Weblogger)?(?:</a>)?\s+Version\s+"
    r"(\d+\.\d+(?:\.\d+){0,2})\b",
    re.I,
)
_VERSION_POWERED = re.compile(
    r"Powered by\s+(?:<[^>]+>\s*)*Apache\s+Roller(?:\s+Weblogger)?"
    r"(?:\s*</a>)?\s+v?(?:ersion\s+)?(\d+\.\d+(?:\.\d+){0,2})\b",
    re.I,
)
_VERSION_META = re.compile(
    r"Apache\s+Roller(?:\s+Weblogger)?\s+v?(\d+\.\d+(?:\.\d+){0,2})\b",
    re.I,
)
_FEED_VERSION_ATTR = re.compile(
    r"""<generator\b[^>]*\bversion\s*=\s*['"](\d+\.\d+(?:\.\d+){0,2})\b""",
    re.I,
)
_FEED_VERSION_BODY = re.compile(
    r"<generator\b[^>]*>\s*Apache\s+Roller(?:\s+Weblogger)?\s+"
    r"(\d+\.\d+(?:\.\d+){0,2})\b",
    re.I,
)
_ASSET_VER = re.compile(
    r"(?:/roller-ui/|/themes/(?:" + "|".join(_THEME_NAMES) + r")/)"
    r"""[^\"'\s>]*[?&](?:ver|v)=(\d+\.\d+(?:\.\d+){0,2})\b""",
    re.I,
)


def _sources_note() -> str:
    return "Sources: " + "; ".join(_SOURCES) + "."


def _fix() -> str:
    return (
        "Upgrade Apache Roller to 6.1.6 or later. On older releases, disabling "
        "XML-RPC in the admin UI is not enough: set "
        "enabledForExtensions=false for the XML-RPC servlet in WEB-INF/web.xml "
        "or remove the /roller-services/xmlrpc servlet mapping, then restart. "
        f"See {CHECK.cve} (same bug as CVE-2026-82384). {_sources_note()}"
    )


def is_roller(body: str) -> bool:
    """True when crawled HTML matches verified Apache Roller markers."""
    text = body or ""
    if _ROLLER_UI.search(text):
        return True
    if _THEME_PATH.search(text):
        return True
    if _POWERED.search(text):
        return True
    if _GENERATOR_META.search(text) or _GENERATOR_META_REV.search(text):
        return True
    if _FEED_GENERATOR.search(text):
        return True
    if _OPENSEARCH.search(text):
        return True
    return False


def version_in(text: str) -> tuple[tuple[int, ...] | None, str]:
    """Return ``(version, where)`` from passively visible HTML, or ``(None, "")``."""
    raw = (text or "").replace("&amp;", "&")
    for pattern, where in (
        (_GENERATOR_META, "generator meta"),
        (_GENERATOR_META_REV, "generator meta"),
    ):
        match = pattern.search(raw)
        if match:
            blob = match.group(1)
            ver_match = _VERSION_META.search(blob)
            found = parse_dotted(ver_match.group(1) if ver_match else blob)
            if found:
                return found, where
    for pattern, where in (
        (_VERSION_FOOTER, "powered-by footer"),
        (_VERSION_POWERED, "powered-by footer"),
        (_FEED_VERSION_ATTR, "feed generator"),
        (_FEED_VERSION_BODY, "feed generator"),
        (_ASSET_VER, "theme/UI asset query"),
    ):
        match = pattern.search(raw)
        if match:
            found = parse_dotted(match.group(1))
            if found:
                return found, where
    return None, ""


def affected(version: tuple[int, ...]) -> bool:
    """True for 4.0.0 <= version < 6.1.6."""
    current = pad3(version)
    if cmp_ver(current, _AFFECTED_FROM) < 0:
        return False
    return cmp_ver(current, _FIXED) < 0


def _critical(version: tuple[int, ...], where: str) -> dict:
    label = fmt(pad3(version))
    return base_finding(
        CHECK,
        severity="critical",
        title=f"{UNCONFIRMED}: Apache Roller {label} ({CHECK.cve})",
        evidence=(
            f"Observed Apache Roller {label} via {where}. {UNCONFIRMED}. "
            f"{CHECK.cve} (same bug as CVE-2026-82384, CVSS 9.8): unauthenticated "
            "XML-RPC vendor-extension deserialization at /roller-services/xmlrpc "
            "before authentication. Affected 4.0.0 through 6.1.5; fixed in 6.1.6. "
            "Exploited per Apache (ASF / oss-security); added to CISA KEV on "
            "2026-11-20. Only already-crawled HTML was read; no request was "
            "sent to /roller-services/xmlrpc, /roller/roller-services/xmlrpc, "
            "/roller-ui/login*, /roller-ui/admin*, or /roller-services/rest*; no "
            f"XML-RPC body, auth, or payload was sent. {_sources_note()}"
        ),
        fix=_fix(),
        match=f"apache-roller:{label}",
    )


def _info() -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=(
            f"Roller detected, version hidden; confirm >= 6.1.6 or apply the "
            f"web.xml mitigation ({CHECK.cve})"
        ),
        evidence=(
            "Apache Roller was fingerprinted from already-crawled HTML "
            "(/roller-ui/, /themes/<shared-theme>/, Powered by Apache Roller, "
            "generator, or /roller-services/opensearch), but no comparable "
            f"version was visible. {CHECK.cve} (same bug as CVE-2026-82384) "
            "affects 4.0.0–6.1.5; fixed in 6.1.6. Confirm the install is "
            ">= 6.1.6 or set enabledForExtensions=false / remove the XML-RPC "
            "servlet mapping in WEB-INF/web.xml. Exploited per Apache; added to "
            "CISA KEV on 2026-11-20. No request was sent to the XML-RPC "
            f"endpoint or admin/login paths. {_sources_note()}"
        ),
        fix=_fix(),
        match="apache-roller:unknown",
    )


def run(section, ctx) -> list[dict]:
    _headers, body = root_observation(ctx)
    if not is_roller(body):
        return []
    version, where = version_in(body)
    if version is not None:
        if affected(version):
            return [_critical(version, where)]
        return []
    return [_info()]


CHECK = CveCheck(
    id="apache-roller",
    cve="CVE-2026-129448",
    agent="misconfig",
    fixed="6.1.6; affected: 4.0.0–6.1.5 (same bug as CVE-2026-82384)",
    summary=(
        "Fingerprint Apache Roller from already-crawled HTML (/roller-ui/, "
        "shared /themes/<name>/, Powered by Apache Roller, generator, "
        "opensearch link). Critical, version unconfirmed, when 4.0.0 <= v < "
        "6.1.6. Info when Roller is present but the version is hidden. No "
        "extra request. Non-Roller targets are skipped."
    ),
    sends=(
        "No extra request. Uses already-crawled HTML from the root response "
        "the scan fetched."
    ),
    does_not_send=(
        "Never requests /roller-services/xmlrpc, /roller/roller-services/xmlrpc, "
        "/roller-ui/login*, /roller-ui/admin*, or /roller-services/rest*. No "
        "XML-RPC body, no POST/PUT/DELETE, no auth, no payloads, no malformed "
        "input, no uploads, no writes."
    ),
    run=run,
)
