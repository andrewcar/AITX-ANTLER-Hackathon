"""LatePoint (CVE-2026-118066) — passive plugin readme version read.

One read-only GET of ``/wp-content/plugins/latepoint/readme.txt``. Critical when
the Stable tag (or latest changelog version) is 5.7.6 or lower. Fixed in 5.7.7
(changelog dated 2 November 2026). Patchstack CVSS 9.8 and marks known-exploited
(Patchstack telemetry, not CISA KEV). Wordfence CVSS 9.1.

Never requests admin-ajax.php or LatePoint AJAX routes, password-reset tokens,
order-intent keys, sentinel strings, POSTs, logins, or writes.
"""
import re

import recon

from .client import fetch_path
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, parse_dotted


README = "/wp-content/plugins/latepoint/readme.txt"
_AFFECTED_THROUGH = (5, 7, 6)
_FIXED = (5, 7, 7)

_STABLE = re.compile(r"(?im)^[ \t]*stable tag:[ \t]*(\d+(?:\.\d+){0,3})[ \t]*$")
_HEADER = re.compile(r"(?im)^===\s*.*\blatepoint\b.*===\s*$")
_README_FIELDS = ("stable tag:", "contributors:", "requires at least:")
_CHANGELOG_HEAD = re.compile(r"(?im)^==[ \t]*changelog[ \t]*==[ \t]*$")
_CHANGELOG_VER = re.compile(r"(?im)^=[ \t]*(\d+(?:\.\d+){0,3})[ \t]*=[ \t]*$")


def _fix() -> str:
    return (
        "Update LatePoint to 5.7.7 or later (Plugins screen or "
        "`wp plugin update latepoint`). Purge page, object, and CDN caches after "
        "updating. Review LatePoint customer accounts for unexpected password "
        f"changes. See {CHECK.cve}."
    )


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
    """True when the body is a LatePoint plugin readme, not an HTML page."""
    text = body or ""
    if recon.looks_like_app_html(text[:400]):
        return False
    if not _HEADER.search(text) and "latepoint" not in text.lower():
        return False
    low = text.lower()
    if "latepoint" not in low:
        return False
    return any(field in low for field in _README_FIELDS)


def affected(version: tuple[int, ...]) -> bool:
    """True for versions through 5.7.6 inclusive. 5.7.7+ is patched."""
    return cmp_ver(version, _AFFECTED_THROUGH) <= 0


def _vulnerable(version: tuple[int, ...], where: str) -> dict:
    label = fmt(version)
    return base_finding(
        CHECK,
        severity="critical",
        title=f"{UNCONFIRMED}: LatePoint {label} ({CHECK.cve})",
        evidence=(
            f"GET {README} {where} is {label}. {UNCONFIRMED}. "
            f"Affected: LatePoint through 5.7.6. Fixed in 5.7.7 "
            "(changelog dated 2 November 2026). "
            f"{CHECK.cve}: unauthenticated customer account takeover via the "
            "password-reset token path (Patchstack CVSS 9.8, Wordfence CVSS 9.1). "
            "Patchstack marks this as known-exploited (Patchstack telemetry, "
            "not CISA KEV). Only a read-only GET of the plugin readme was sent; "
            "no admin-ajax.php, LatePoint AJAX route, password-reset request, "
            "POST, login, or write was sent."
        ),
        fix=_fix(),
        match=f"latepoint:{label}",
    )


def _info(where: str) -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=f"LatePoint detected; version not exposed ({CHECK.cve})",
        evidence=(
            f"LatePoint was detected via {where}, but no readable version was "
            f"exposed. {CHECK.cve} cannot be compared (affected through 5.7.6; "
            "fixed in 5.7.7). Only a read-only GET of the plugin readme was sent; "
            "no admin-ajax.php, LatePoint AJAX route, password-reset request, "
            "POST, login, or write was sent."
        ),
        fix=_fix(),
        match="latepoint:unknown",
    )


def run(section, ctx) -> list[dict]:
    readme = fetch_path(ctx, README, max_bytes=65536)
    if readme.get("status") != 200:
        return []
    body = readme.get("body") or ""
    if not is_plugin_readme(body):
        return []
    version, where = plugin_version(body)
    if version is not None:
        if affected(version):
            return [_vulnerable(version, where)]
        return []
    return [_info(f"GET {README}")]


CHECK = CveCheck(
    id="latepoint",
    cve="CVE-2026-118066",
    # Auth slot: unauthenticated customer account takeover via password-reset
    # token (same family as nodered-admin / langflow auth checks).
    agent="auth",
    fixed="5.7.7 (affected: LatePoint through 5.7.6)",
    summary=(
        "One GET of the LatePoint plugin readme Stable tag (or latest changelog "
        "version). Critical for versions through 5.7.6 (fixed in 5.7.7). Info "
        "when the plugin readme is present but the version is unparseable."
    ),
    sends="One GET of /wp-content/plugins/latepoint/readme.txt.",
    does_not_send=(
        "Never requests admin-ajax.php or LatePoint AJAX routes "
        "(customer_cabinet__change_password, steps__start_from_order_intent). "
        "No params[password_reset_token], params[order_intent_key], IS NULL / "
        "IS NOT NULL strings, password-reset requests, POSTs, logins, or writes."
    ),
    run=run,
)
