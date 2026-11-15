"""wpForo Forum (CVE-2026-119155) — passive plugin version read.

wpForo Forum (WordPress.org slug ``wpforo``) through 3.2.2 has an unauthenticated
time-based SQL injection via the ``href[locale]`` parameter:
``Boards::build_sql_select()`` put ``esc_like()`` output into SQL without
``prepare()``. The nonce is public in the ``wpforo.nonces`` JS object. Fixed in
3.2.3 (current line includes 3.2.4). Patchstack marks known-exploited
(Patchstack telemetry, not CISA KEV). CVSS 9.3 (Patchstack) / 7.5 (Wordfence).

Detection is passive only: confirm WordPress from the already-fetched root
response, parse crawled HTML for ``/wp-content/plugins/wpforo/`` asset URLs with
``?ver=``, and when the plugin path is present without a version, at most one
GET of the plugin ``readme.txt`` Stable tag.

Never reads or uses the ``wpforo.nonces`` value. Never calls any wpForo AJAX
action. Never sends ``href`` or ``locale`` parameters. No POSTs, form
submissions, SQL or time-based payloads, uploads, writes, or /wp-admin.
"""
import re

import recon

from .client import fetch_path, root_observation
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, parse_dotted


README = "/wp-content/plugins/wpforo/readme.txt"
_AFFECTED_THROUGH = (3, 2, 2)
_FIXED = (3, 2, 3)

_SOURCES = (
    "https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/"
    "wpforo/wpforo-forum-322-unauthenticated-sql-injection-via-hreflocale-parameter",
    "https://wpdeeply.com/wpforo-sql-injection-cve-2026-119155/",
    "https://euvd.enisa.europa.eu/vulnerability/EUVD-2026-119033",
)

_STABLE = re.compile(r"(?im)^[ \t]*stable tag:[ \t]*(\d+(?:\.\d+){0,3})[ \t]*$")
_HEADER = re.compile(r"(?im)^===\s*.*\bwpforo\b.*===\s*$")
_README_FIELDS = ("stable tag:", "contributors:", "requires at least:")
_ASSET = re.compile(
    r"/wp-content/plugins/wpforo/[^\"'\s>]*",
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


def _fix() -> str:
    return (
        "Update wpForo Forum to 3.2.3 or later (current line includes 3.2.4). "
        "Purge page, object, and CDN caches after updating. Review logs for "
        "delayed requests to wpForo endpoints. Rotate database credentials and "
        f"WordPress salts if compromise is suspected. See {CHECK.cve}. "
        f"Sources: {'; '.join(_SOURCES)}"
    )


def looks_like_wordpress(headers: dict, body: str) -> bool:
    """True when the already-fetched root response shows WordPress markers."""
    text = body or ""
    if _WP_GENERATOR.search(text):
        return True
    if _WP_PATH.search(text) or _WP_LINK.search(text):
        return True
    if "wordpress" in text.lower() and (
        "wp-content" in text.lower() or "wp-includes" in text.lower()
    ):
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


def is_plugin_readme(body: str) -> bool:
    """True when the body is a wpForo plugin readme, not an HTML page."""
    text = body or ""
    if recon.looks_like_app_html(text[:400]):
        return False
    if not _HEADER.search(text) and "wpforo" not in text.lower():
        return False
    low = text.lower()
    if "wpforo" not in low:
        return False
    return any(field in low for field in _README_FIELDS)


def affected(version: tuple[int, ...]) -> bool:
    """True for versions through 3.2.2 inclusive. 3.2.3+ is patched."""
    return cmp_ver(version, _AFFECTED_THROUGH) <= 0


def version_from_assets(body: str) -> tuple[tuple[int, ...] | None, bool]:
    """Plugin-file ``?ver=`` on a wpForo asset, and whether any asset was seen."""
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


def _passive_note() -> str:
    return (
        "Only a read-only GET of the public plugin readme.txt was sent when "
        "needed; no wpforo.nonces value was read or used, no wpForo AJAX "
        "action was called, and no href, locale, href[locale], POST, form "
        "submission, SQL/timing payload, upload, write, or /wp-admin request "
        "was sent."
    )


def _vulnerable(version: tuple[int, ...], where: str) -> dict:
    label = fmt(version)
    return base_finding(
        CHECK,
        severity="critical",
        title=f"{UNCONFIRMED}: wpForo Forum {label} ({CHECK.cve})",
        evidence=(
            f"Observed wpForo Forum {label} via {where}. {UNCONFIRMED}. "
            f"Affected: wpForo Forum through 3.2.2. Fixed in 3.2.3 "
            "(current line includes 3.2.4). "
            f"{CHECK.cve}: unauthenticated time-based SQL injection via the "
            "href[locale] parameter (Boards::build_sql_select() put esc_like() "
            "output into SQL without prepare(); the nonce is public in the "
            "wpforo.nonces JS object). Patchstack CVSS 9.3 / Wordfence CVSS "
            "7.5. Patchstack marks this as known-exploited (Patchstack "
            f"telemetry, not CISA KEV). {_passive_note()} "
            f"Sources: {'; '.join(_SOURCES)}"
        ),
        fix=_fix(),
        match=f"wpforo:{label}",
    )


def _info(where: str) -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=f"wpForo Forum detected; version not exposed ({CHECK.cve})",
        evidence=(
            f"wpForo Forum was detected via {where}, but no readable version "
            f"was exposed. {CHECK.cve} cannot be compared (affected through "
            "3.2.2; fixed in 3.2.3). "
            f"{_passive_note()} Sources: {'; '.join(_SOURCES)}"
        ),
        fix=_fix(),
        match="wpforo:unknown",
    )


def _readme_version(ctx) -> tuple[tuple[int, ...] | None, str, bool]:
    """At most one GET of the plugin readme. Returns ``(version, where, is_plugin)``."""
    readme = fetch_path(ctx, README, max_bytes=65536)
    if readme.get("status") != 200:
        return None, "", False
    body = readme.get("body") or ""
    if not is_plugin_readme(body):
        return None, "", False
    version = stable_tag(body)
    if version is not None:
        return version, f"GET {README} Stable tag", True
    return None, f"GET {README}", True


def run(section, ctx) -> list[dict]:
    headers, body = root_observation(ctx)
    if not looks_like_wordpress(headers, body):
        return []

    version, where, seen = observe_html(body)

    # Only fetch the readme when the plugin path is already present without
    # a version. Plugin absent from crawled HTML: no requests, no finding.
    if version is None and seen:
        readme_version, readme_where, is_plugin = _readme_version(ctx)
        if is_plugin:
            where = readme_where
            version = readme_version

    if version is not None:
        if affected(version):
            return [_vulnerable(version, where)]
        return []

    if seen:
        return [_info(where)]
    return []


CHECK = CveCheck(
    id="wpforo",
    cve="CVE-2026-119155",
    # Closest registry agent: InjectionAgent is the active probe specialist and
    # is not one of CveCheck.AGENTS (misconfig/recon/auth/secrets). This check is
    # a passive WordPress plugin fingerprint for an unauthenticated SQLi advisory,
    # same family as amelia-pro / slicewp.
    agent="misconfig",
    fixed="3.2.3+ (affected: wpForo Forum through 3.2.2; current includes 3.2.4)",
    summary=(
        "Confirm WordPress from the already-fetched root response, then read "
        "the wpForo version from a plugin asset ?ver= already in the page, or "
        "when the plugin path is present without a version, one GET of "
        "/wp-content/plugins/wpforo/readme.txt Stable tag. Critical for "
        "versions through 3.2.2 (fixed in 3.2.3; current includes 3.2.4). Info "
        "when the plugin is present but the version is hidden. Non-WordPress "
        "targets and pages without a wpforo asset yield no request."
    ),
    sends=(
        "No request when the root response does not look like WordPress, or "
        "when crawled HTML already shows a wpforo asset ?ver=. When WordPress "
        "is indicated and the plugin path is present without a version, one "
        "GET of /wp-content/plugins/wpforo/readme.txt. No request when the "
        "plugin is absent from crawled HTML."
    ),
    does_not_send=(
        "Never reads or uses the wpforo.nonces value. Never calls any wpForo "
        "AJAX action. Never sends href or locale parameters (including "
        "href[locale]). No POSTs or form submissions, no SQL or time-based "
        "payloads, no uploads, no writes, nothing to /wp-admin, and never "
        "more than the single readme GET."
    ),
    run=run,
)
