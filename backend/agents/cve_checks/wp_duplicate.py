"""WP Duplicate / LocalSync (CVE-2026-123751) — passive plugin readme check.

WordPress.org slug and WPScan/Patchstack advisories all use ``local-sync``
(product renamed from LocalSync to WP Duplicate; folder slug unchanged).
No second install slug is confirmed, so this check issues exactly one GET of
``/wp-content/plugins/local-sync/readme.txt``.

Affected: Stable tag <= 1.1.11. No fixed release; remediation is deactivate and
remove the plugin. Same versions are also tracked under CVE-2026-39755
(subscriber-level upload, Patchstack, no patch) — this check only cites
CVE-2026-123751.

Never requests upload/sync endpoints, admin-ajax, POST, auth values, file
writes, or crafted parameters — readme fingerprint only.
"""
import re

import recon

from .client import fetch_path
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, parse_dotted


# Confirmed WordPress.org / WPScan / Patchstack slug. Contributor username
# ``localsync`` is not a plugin folder; do not GET a guessed alternate path.
README = "/wp-content/plugins/local-sync/readme.txt"
_STABLE = re.compile(r"(?im)^[ \t]*stable tag:[ \t]*(\d+(?:\.\d+){0,3})[ \t]*$")
_THRESHOLD = (1, 1, 11)
_README_FIELDS = ("stable tag:", "contributors:", "requires at least:")
_NAME_MARKERS = ("wp duplicate", "localsync", "local-sync", "local sync")

FIX = (
    "Deactivate and remove the WP Duplicate (formerly LocalSync) plugin. "
    "No fixed version is available for CVE-2026-123751. "
    "Review uploads and the plugin directory for unexpected files, then "
    "rotate credentials if compromise is suspected."
)


def stable_tag(body: str) -> tuple[int, ...] | None:
    match = _STABLE.search(body or "")
    if not match:
        return None
    return parse_dotted(match.group(1))


def is_plugin_readme(body: str) -> bool:
    """True when the body looks like the WP Duplicate / LocalSync readme."""
    text = body or ""
    low = text.lower()
    if not any(field in low for field in _README_FIELDS):
        return False
    if not any(marker in low for marker in _NAME_MARKERS):
        return False
    # Soft 404 / theme HTML wrappers are not the plugin readme.
    if recon.looks_like_app_html(text[:400]) and "stable tag:" not in low[:2000]:
        return False
    return True


def vulnerable(version: tuple[int, ...]) -> bool:
    """True for Stable tag <= 1.1.11 (inclusive). No patched release exists."""
    return cmp_ver(version, _THRESHOLD) <= 0


def _critical(version: tuple[int, ...]) -> dict:
    label = fmt(version)
    return base_finding(
        CHECK,
        severity="critical",
        title=(
            f"{UNCONFIRMED}: WP Duplicate {label} "
            f"(CVE-2026-123751 unauthenticated file upload)"
        ),
        evidence=(
            f"GET {README} Stable tag is {label}. {UNCONFIRMED}. "
            "WP Duplicate <=1.1.11, CVE-2026-123751 unauthenticated file upload, "
            "exploited, no fix: remove the plugin. "
            "Affected range: Stable tag 1.1.11 and lower. "
            "WPScan reports active exploitation; there is no known fixed release. "
            "Same versions are also tracked as CVE-2026-39755 (subscriber-level "
            "upload, no patch). No upload, sync, admin-ajax, POST, auth value, "
            "or crafted parameter was sent."
        ),
        fix=FIX,
        match=f"wp-duplicate:{label}",
    )


def _high_unknown() -> dict:
    return base_finding(
        CHECK,
        severity="high",
        title=(
            "WP Duplicate / LocalSync detected; version not readable "
            f"({CHECK.cve})"
        ),
        evidence=(
            f"GET {README} returned the WP Duplicate (formerly LocalSync) "
            "plugin readme, but the Stable tag could not be parsed. "
            f"{CHECK.cve} affects versions through 1.1.11 with no known fix. "
            "Recommend removing the plugin or confirming the installed version "
            "out of band. No upload, sync, admin-ajax, POST, auth value, or "
            "crafted parameter was sent."
        ),
        fix=FIX,
        match="wp-duplicate:unknown",
    )


def _review(version: tuple[int, ...]) -> dict:
    label = fmt(version)
    return base_finding(
        CHECK,
        severity="info",
        title=(
            f"WP Duplicate {label} present; review removal "
            f"({CHECK.cve})"
        ),
        evidence=(
            f"GET {README} Stable tag is {label}. That tag is above 1.1.11, so "
            f"it is not flagged Critical for {CHECK.cve}, but the plugin still "
            "warrants review: advisories list no fixed release, and the product "
            "was closed on WordPress.org pending review. Prefer removing the "
            "plugin unless a verified patched build is confirmed. No upload, "
            "sync, admin-ajax, POST, auth value, or crafted parameter was sent."
        ),
        fix=FIX,
        match=f"wp-duplicate:review:{label}",
    )


def run(section, ctx) -> list[dict]:
    readme = fetch_path(ctx, README, max_bytes=65536)
    if readme.get("status") != 200:
        return []
    body = readme.get("body") or ""
    if not is_plugin_readme(body):
        return []
    version = stable_tag(body)
    if version is None:
        return [_high_unknown()]
    if vulnerable(version):
        return [_critical(version)]
    return [_review(version)]


CHECK = CveCheck(
    id="wp-duplicate",
    cve="CVE-2026-123751",
    agent="misconfig",
    fixed="none (affected: <= 1.1.11; deactivate and remove the plugin)",
    summary=(
        "One GET of /wp-content/plugins/local-sync/readme.txt (confirmed "
        "WordPress.org / WPScan slug). Critical when Stable tag is 1.1.11 or "
        "lower (unauthenticated file upload / RCE, exploited, no fix: remove "
        "the plugin). High when the plugin readme is present but the version "
        "is unreadable. Info when a higher Stable tag is observed, for review."
    ),
    sends="Exactly one GET of /wp-content/plugins/local-sync/readme.txt.",
    does_not_send=(
        "Never requests upload or sync endpoints, admin-ajax actions, or "
        "alternate guessed slugs. No POST, no file upload, no auth value, "
        "no crafted parameters, no malformed input, no exploit payload."
    ),
    run=run,
)
