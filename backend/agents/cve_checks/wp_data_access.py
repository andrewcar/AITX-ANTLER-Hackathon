"""WP Data Access (CVE-2026-118267) — passive plugin readme version read.

WordPress plugin WP Data Access (slug ``wp-data-access``) through 5.5.89 has
incorrect authorization on App Builder write endpoints
(``wpda/app/update``, ``delete``, ``insert``): they ignore the row filter and
column allow-list, enabling admin takeover. Fixed in 5.5.90. Patchstack lists
this as known-exploited (Patchstack telemetry, not CISA KEV). Unauthenticated
when a published Data App allows anonymous writes; otherwise needs Subscriber.

Detection is passive only: confirm WordPress from the already-fetched root
response, then one GET of ``/wp-content/plugins/wp-data-access/readme.txt``.
Parse Stable tag (or latest changelog version). High when <= 5.5.89. Info when
the plugin readme is present but the version is unreadable.

Never requests ``wpda/app`` REST endpoints, key/value params, logins,
registrations, POSTs, form submissions, uploads, writes, or malformed input.
"""
import re

import recon

from .client import fetch_path, root_observation
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, parse_dotted


README = "/wp-content/plugins/wp-data-access/readme.txt"
_AFFECTED_THROUGH = (5, 5, 89)
_FIXED = (5, 5, 90)

_STABLE = re.compile(r"(?im)^[ \t]*stable tag:[ \t]*(\d+(?:\.\d+){0,3})[ \t]*$")
_HEADER = re.compile(
    r"(?im)^===\s*.*\bwp\s*data\s*access\b.*===\s*$"
)
_README_FIELDS = ("stable tag:", "contributors:", "requires at least:")
_CHANGELOG_HEAD = re.compile(r"(?im)^==[ \t]*changelog[ \t]*==[ \t]*$")
_CHANGELOG_VER = re.compile(r"(?im)^=[ \t]*(\d+(?:\.\d+){0,3})[ \t]*=[ \t]*$")
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
        "Update WP Data Access to 5.5.90 or later (Plugins screen or "
        "`wp plugin update wp-data-access`). Purge page, object, and CDN "
        "caches after updating. Review published Data Apps and disable "
        "anonymous write access unless required. Review WordPress "
        f"administrator accounts for unexpected changes. See {CHECK.cve}."
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
    """True when the body is a WP Data Access plugin readme, not an HTML page."""
    text = body or ""
    if recon.looks_like_app_html(text[:400]):
        return False
    low = text.lower()
    if not _HEADER.search(text) and "wp data access" not in low and "wp-data-access" not in low:
        return False
    if "wp data access" not in low and "wp-data-access" not in low and "wpda" not in low:
        return False
    return any(field in low for field in _README_FIELDS)


def affected(version: tuple[int, ...]) -> bool:
    """True for versions through 5.5.89 inclusive. 5.5.90+ is patched."""
    return cmp_ver(version, _AFFECTED_THROUGH) <= 0


def _vulnerable(version: tuple[int, ...], where: str) -> dict:
    label = fmt(version)
    return base_finding(
        CHECK,
        severity="high",
        title=f"{UNCONFIRMED}: WP Data Access {label} ({CHECK.cve})",
        evidence=(
            f"GET {README} {where} is {label}. {UNCONFIRMED}. "
            f"Affected: WP Data Access through 5.5.89. Fixed in 5.5.90. "
            f"{CHECK.cve}: incorrect authorization on App Builder write "
            "endpoints (wpda/app/update, delete, insert) that ignore the row "
            "filter and column allow-list, allowing admin takeover. Patchstack "
            "marks this as known-exploited (Patchstack telemetry, not CISA KEV). "
            "Unauthenticated exposure depends on Data App configuration "
            "(anonymous writes on a published Data App); otherwise Subscriber "
            "is required — this check does not confirm that exposure. Only a "
            "read-only GET of the plugin readme was sent; no wpda/app REST "
            "endpoint, key/value parameter, login, registration, POST, form "
            "submission, upload, write, or malformed input was sent."
        ),
        fix=_fix(),
        match=f"wp-data-access:{label}",
    )


def _info(where: str) -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=(
            f"WP Data Access present, version unknown "
            f"(low confidence) ({CHECK.cve})"
        ),
        evidence=(
            f"WP Data Access was detected via {where}, but no readable "
            f"version was exposed. {CHECK.cve} cannot be compared (affected "
            "through 5.5.89; fixed in 5.5.90). Unauthenticated exposure "
            "depends on Data App configuration, which this check does not "
            "confirm. Only a read-only GET of the plugin readme was sent; "
            "no wpda/app REST endpoint, key/value parameter, login, "
            "registration, POST, form submission, upload, write, or "
            "malformed input was sent."
        ),
        fix=_fix(),
        match="wp-data-access:unknown",
    )


def run(section, ctx) -> list[dict]:
    headers, body = root_observation(ctx)
    if not looks_like_wordpress(headers, body):
        return []
    readme = fetch_path(ctx, README, max_bytes=65536)
    if readme.get("status") != 200:
        return []
    text = readme.get("body") or ""
    if not is_plugin_readme(text):
        return []
    version, where = plugin_version(text)
    if version is not None:
        if affected(version):
            return [_vulnerable(version, where)]
        return []
    return [_info(f"GET {README}")]


CHECK = CveCheck(
    id="wp-data-access",
    cve="CVE-2026-118267",
    agent="misconfig",
    fixed="5.5.90 (affected: WP Data Access through 5.5.89)",
    summary=(
        "Confirm WordPress from the already-fetched root response, then one "
        "GET of the WP Data Access plugin readme Stable tag (or latest "
        "changelog version). High for versions through 5.5.89 (fixed in "
        "5.5.90). Info (present, version unknown, low confidence) when the "
        "plugin readme is present but the version is unparseable. Non-WordPress "
        "targets are skipped with no request."
    ),
    sends=(
        "No request when the root response does not look like WordPress. "
        "Otherwise one GET of /wp-content/plugins/wp-data-access/readme.txt."
    ),
    does_not_send=(
        "Never requests wpda/app REST endpoints (update, delete, insert) or "
        "any key/value parameters. No login, registration, POST, form "
        "submission, upload, write, or malformed input."
    ),
    run=run,
)
