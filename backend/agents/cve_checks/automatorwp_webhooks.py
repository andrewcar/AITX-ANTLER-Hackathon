"""AutomatorWP Pro Webhooks (CVE-2026-126173) — passive add-on version read.

AutomatorWP Pro Webhooks (slug ``automatorwp-webhooks``) through 1.4.4 has a
missing-authorization flaw (CWE-862): an unauthenticated caller can reset any
WordPress user's password and take over the account, but only when an admin
configured a Receive Webhook trigger with an ``Is the user ID`` field paired
with an Update User action whose User ID is blank and whose Password is mapped
to the webhook password tag (a documented, supported configuration). Fixed in
1.4.5. CVSS 9.8. Patchstack labels known-exploited (published 13 November
2026; Patchstack telemetry, not CISA KEV). Brandefense says exploitation is
not confirmed.

Detection is passive only: confirm WordPress from the already-fetched root
response, accept ``?ver=`` on ``/wp-content/plugins/automatorwp-webhooks/``
assets already in crawled HTML, otherwise at most two read-only GETs of
plugin ``readme.txt`` under the documented slug folder
``automatorwp-webhooks``, and when that path is uncertain the marketing-name
alternate ``automatorwp-pro-webhooks``. Affected versions yield a medium
finding marked UNCONFIRMED/config-dependent — the exploitable automation
cannot be seen from outside. Present but unknown version is Info. Fixed
versions yield none.

Never requests AutomatorWP webhook endpoints (``/wp-json/automatorwp/...`` or
any webhook URL), password, user-ID, or webhook parameters, POSTs, login or
password-reset requests, writes, malformed input, or anything under
``/wp-admin``.
"""
import re

import recon

from .client import fetch_path, root_observation
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, parse_dotted


PRIMARY = "/wp-content/plugins/automatorwp-webhooks/readme.txt"
ALTERNATE = "/wp-content/plugins/automatorwp-pro-webhooks/readme.txt"
_AFFECTED_THROUGH = (1, 4, 4)
_FIXED = (1, 4, 5)

_SOURCES = (
    "https://patchstack.com/database/wordpress/plugin/automatorwp-webhooks/"
    "vulnerability/wordpress-automatorwp-pro-webhooks-addon-plugin-1-4-4-"
    "missing-authorization-to-unauthenticated-arbitrary-user-password-reset-"
    "account-takeover-via-webhook-with-is-the-user-id-field-vulnerability",
    "https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/"
    "automatorwp-webhooks",
    "https://www.rapid7.com/db/vulnerabilities/cve-2026-126173/",
    "https://brandefense.io/knowledge-hub/vulnerabilities/cve-2026-126173/",
)

_STABLE = re.compile(r"(?im)^[ \t]*stable tag:[ \t]*(\d+(?:\.\d+){0,3})[ \t]*$")
_HEADER = re.compile(r"(?im)^===\s*(.+?)\s*===\s*$")
_CHANGELOG_HEAD = re.compile(r"(?im)^==[ \t]*changelog[ \t]*==[ \t]*$")
_CHANGELOG_VER = re.compile(r"(?im)^=[ \t]*(\d+(?:\.\d+){0,3})[ \t]*=[ \t]*$")
_README_FIELDS = ("stable tag:", "contributors:", "requires at least:")
_NAME_MARKERS = (
    "automatorwp-webhooks",
    "automatorwp - webhooks",
    "automatorwp webhooks",
    "automatorwp pro webhooks",
)
_ASSET = re.compile(
    r"/wp-content/plugins/automatorwp-(?:pro-)?webhooks/[^\"'\s>]*",
    re.I,
)
_VER = re.compile(r"[?&]ver=(\d+(?:\.\d+){0,3})", re.I)
_WP_GENERATOR = re.compile(
    r"<meta[^>]*\bcontent\s*=\s*['\"]WordPress\b",
    re.I,
)
_WP_PATH = re.compile(
    r"/wp-(?:content|includes|admin|json|login\.php|cron\.php)\b",
    re.I,
)
_WP_LINK = re.compile(r"""rel=["']https://api\.w\.org/["']""", re.I)
_WP_MARKERS = (
    "wordpress",
    "/wp-content/",
    "/wp-includes/",
    "wp-json",
    "wp-emoji",
    "wp-block-",
)


def _fix() -> str:
    return (
        "Update AutomatorWP Pro Webhooks to 1.4.5 or later through the vendor "
        "licensed update channel. Review Receive Webhook → Update User "
        "automations (especially any with an 'Is the user ID' field, a blank "
        "User ID on Update User, and Password mapped to the webhook password "
        "tag). Audit recent administrator password changes and rotate "
        f"credentials if compromise is suspected. See {CHECK.cve}. "
        f"Sources: {'; '.join(_SOURCES)}"
    )


def looks_like_wordpress(headers: dict, body: str) -> bool:
    """True when the already-fetched root response shows WordPress markers."""
    text = body or ""
    if _WP_GENERATOR.search(text):
        return True
    if _WP_PATH.search(text) or _WP_LINK.search(text):
        return True
    low = text.lower()
    if any(marker in low for marker in _WP_MARKERS):
        return True
    link = (headers or {}).get("link") or ""
    if "api.w.org" in link.lower():
        return True
    pingback = (headers or {}).get("x-pingback") or ""
    if "xmlrpc.php" in pingback.lower():
        return True
    return False


def stable_tag(body: str) -> tuple[int, ...] | None:
    match = _STABLE.search(body or "")
    return parse_dotted(match.group(1)) if match else None


def changelog_version(body: str) -> tuple[int, ...] | None:
    """First dotted version heading under ``== Changelog ==``, if present."""
    text = body or ""
    head = _CHANGELOG_HEAD.search(text)
    if not head:
        return None
    match = _CHANGELOG_VER.search(text, head.end())
    return parse_dotted(match.group(1)) if match else None


def plugin_version(body: str) -> tuple[tuple[int, ...] | None, str]:
    """Prefer Stable tag; fall back to the latest changelog heading version."""
    version = stable_tag(body)
    if version is not None:
        return version, "Stable tag"
    version = changelog_version(body)
    if version is not None:
        return version, "changelog version"
    return None, ""


def is_plugin_readme(body: str) -> bool:
    """True when the body looks like AutomatorWP Webhooks readme, not HTML."""
    text = body or ""
    if recon.looks_like_app_html(text[:400]):
        return False
    low = text.lower()
    if not any(field in low for field in _README_FIELDS):
        return False
    if not any(marker in low for marker in _NAME_MARKERS):
        return False
    match = _HEADER.search(text)
    if match:
        name = match.group(1).lower()
        if "automatorwp" in name and "webhook" in name:
            return True
    return "automatorwp" in low and "webhook" in low


def affected(version: tuple[int, ...]) -> bool:
    """True for versions through 1.4.4 inclusive. 1.4.5+ is patched."""
    return cmp_ver(version, _AFFECTED_THROUGH) <= 0


def version_from_assets(body: str) -> tuple[tuple[int, ...] | None, bool]:
    """Plugin-file ``?ver=`` on an AutomatorWP Webhooks asset, and whether seen."""
    seen = False
    found = None
    for match in _ASSET.finditer(body or ""):
        seen = True
        if found is not None:
            continue
        ver_match = _VER.search(match.group(0).replace("&amp;", "&"))
        if ver_match:
            found = parse_dotted(ver_match.group(1))
    return found, seen


def observe_html(body: str) -> tuple[tuple[int, ...] | None, str, bool]:
    """Return ``(version, where, seen)`` from already-crawled HTML only."""
    version, seen = version_from_assets(body)
    if version is not None:
        return version, "plugin asset ?ver=", True
    if seen:
        return None, "plugin asset", True
    return None, "", False


def _config_note() -> str:
    return (
        "Config-dependent: only matters when a Receive Webhook trigger with "
        "an 'Is the user ID' field is paired with an Update User action whose "
        "User ID is blank and Password is mapped to the webhook password tag. "
        "The exploitable automation cannot be seen from outside. "
    )


def _passive_note() -> str:
    return (
        "Only read-only GETs of public plugin readme.txt paths were sent when "
        "needed; no AutomatorWP webhook endpoint (/wp-json/automatorwp/...), "
        "webhook URL, password, user-ID or webhook parameter, POST, login, "
        "password-reset request, write, malformed input, or /wp-admin request "
        "was sent."
    )


def _vulnerable(version: tuple[int, ...], where: str) -> dict:
    label = fmt(version)
    return base_finding(
        CHECK,
        severity="medium",
        title=f"{UNCONFIRMED}: AutomatorWP Pro Webhooks {label} ({CHECK.cve})",
        evidence=(
            f"Observed AutomatorWP Pro Webhooks {label} via {where}. "
            f"{UNCONFIRMED}. Config-dependent. "
            f"Affected: AutomatorWP Pro Webhooks through 1.4.4. Fixed in "
            f"{fmt(_FIXED)}. {CHECK.cve}: missing authorization (CWE-862) "
            "lets an unauthenticated attacker reset any user's password and "
            "take over the account when the documented Receive Webhook → "
            "Update User automation is configured (CVSS 9.8). Patchstack "
            "labels this known-exploited (published 13 November 2026; "
            "Patchstack telemetry, not CISA KEV). Brandefense says "
            f"exploitation is not confirmed. {_config_note()}{_passive_note()} "
            f"Sources: {'; '.join(_SOURCES)}"
        ),
        fix=_fix(),
        match=f"automatorwp-webhooks:{label}",
    )


def _info(where: str) -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=(
            f"AutomatorWP Pro Webhooks detected; version not exposed "
            f"({CHECK.cve})"
        ),
        evidence=(
            f"AutomatorWP Pro Webhooks was detected via {where}, but no "
            f"readable version was exposed. {CHECK.cve} cannot be compared "
            f"(affected through 1.4.4; fixed in {fmt(_FIXED)}). "
            f"{_config_note()}{_passive_note()} "
            f"Sources: {'; '.join(_SOURCES)}"
        ),
        fix=_fix(),
        match="automatorwp-webhooks:unknown",
    )


def _assess(body: str, path: str) -> list[dict]:
    version, where = plugin_version(body)
    source = f"GET {path} {where}".strip() if where else f"GET {path}"
    if version is not None:
        if affected(version):
            return [_vulnerable(version, source)]
        return []
    return [_info(source)]


def _probe(ctx, path: str) -> tuple[str, list[dict] | None]:
    """Return ``(certainty, findings_or_None)``.

    ``certain`` means the path answered with a confirmed Webhooks readme
    (so no alternate probe is needed). ``uncertain`` means try the alternate.
    Findings is None when there is no finding yet.
    """
    resp = fetch_path(ctx, path, max_bytes=65536)
    status = int(resp.get("status") or 0)
    body = resp.get("body") or ""
    if status != 200:
        return "uncertain", None
    if is_plugin_readme(body):
        return "certain", _assess(body, path)
    return "uncertain", None


def run(section, ctx) -> list[dict]:
    headers, body = root_observation(ctx)
    if not looks_like_wordpress(headers, body):
        return []

    version, where, seen = observe_html(body)
    if version is not None:
        if affected(version):
            return [_vulnerable(version, where)]
        return []

    # No usable ?ver=: at most two readme GETs (documented slug, then alternate).
    certainty, findings = _probe(ctx, PRIMARY)
    if certainty == "certain":
        return findings or []

    certainty, findings = _probe(ctx, ALTERNATE)
    if certainty == "certain":
        return findings or []

    if seen:
        return [_info(where or "plugin asset")]
    return []


CHECK = CveCheck(
    id="automatorwp-webhooks",
    cve="CVE-2026-126173",
    # Auth slot: unauthenticated password reset / account takeover when a
    # specific automation is configured (same family as latepoint).
    agent="auth",
    fixed="1.4.5+ (affected: AutomatorWP Pro Webhooks through 1.4.4)",
    summary=(
        "Confirm WordPress from the already-fetched root response, then read "
        "the AutomatorWP Pro Webhooks version from a plugin asset ?ver= "
        "already in the page, or when that is absent at most two GETs of "
        "plugin readme.txt under /wp-content/plugins/automatorwp-webhooks/ "
        "and, when uncertain, /wp-content/plugins/automatorwp-pro-webhooks/. "
        "Medium, version unconfirmed / config-dependent, for versions through "
        "1.4.4 (fixed in 1.4.5). Info when the add-on is present but the "
        "version is hidden. Non-WordPress targets yield no request."
    ),
    sends=(
        "No request when the root response does not look like WordPress, or "
        "when crawled HTML already shows an automatorwp-webhooks asset ?ver=. "
        "Otherwise one GET of /wp-content/plugins/automatorwp-webhooks/"
        "readme.txt; when that path is uncertain, one GET of "
        "/wp-content/plugins/automatorwp-pro-webhooks/readme.txt (max two)."
    ),
    does_not_send=(
        "Never requests AutomatorWP webhook endpoints "
        "(/wp-json/automatorwp/... or any webhook URL). Never sends password, "
        "user-ID, or webhook parameters. No POSTs, login or password-reset "
        "requests, writes, malformed input, or anything to /wp-admin."
    ),
    run=run,
)
