"""ACF Extended PRO (CVE-2026-120534) — passive plugin readme version read.

Advanced Custom Fields: Extended PRO (Wordfence / vendor slug
``acf-extended-pro``) through 0.9.2.6 has an unauthenticated RCE via the
Dynamic Render field flow: front-end form config is merged into field settings
and a PHP callback is invoked. Prerequisites (not confirmed by this check):
non-default ``shortcode_preview`` on an affected form, or no OpenSSL on the
server (ACF decrypt falls back to unverified base64). First fix 0.9.2.7;
0.9.2.8 recommended. Patchstack marks known-exploited (recently-exploited list
3 November 2026; Patchstack telemetry, not CISA KEV). Wordfence CVSS 9.8.

Detection is passive only: confirm WordPress from already-crawled HTML, then at
most two read-only GETs of plugin ``readme.txt`` under the vendor PRO folder
``acf-extended-pro``, and when that path is uncertain the documented free-folder
alternative ``acf-extended``. The free WordPress.org plugin is a different
product and is never flagged without a confirmed PRO marker. Present but
version unknown is low-confidence info only.

Never submits ACF/ACFE forms, never calls admin-ajax or REST API, and never
sends render/callback parameters, POSTs, uploads, writes, or malformed input.
"""
import re

import recon

from .client import fetch_path, root_observation
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, parse_dotted


PRIMARY = "/wp-content/plugins/acf-extended-pro/readme.txt"
ALTERNATE = "/wp-content/plugins/acf-extended/readme.txt"
_AFFECTED_THROUGH = (0, 9, 2, 6)
_FIXED = "0.9.2.7"
_RECOMMENDED = "0.9.2.8"

_STABLE = re.compile(r"(?im)^[ \t]*stable tag:[ \t]*(\d+(?:\.\d+){0,3})[ \t]*$")
_HEADER = re.compile(r"(?im)^===\s*(.+?)\s*===\s*$")
_CHANGELOG_HEAD = re.compile(r"(?im)^==[ \t]*changelog[ \t]*==[ \t]*$")
_CHANGELOG_VER = re.compile(r"(?im)^=[ \t]*(\d+(?:\.\d+){0,3})[ \t]*=[ \t]*$")
_README_FIELDS = ("stable tag:", "contributors:", "requires at least:")
_NAME_MARKERS = (
    "acf-extended",
    "acf extended",
    "advanced custom fields: extended",
)
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
        "Update Advanced Custom Fields: Extended PRO to 0.9.2.8 or later "
        "(first fix 0.9.2.7; 0.9.2.8 recommended for additional form/callback "
        "hardening) through the vendor licensed update channel. Purge page, "
        "object, and CDN caches after updating. Review front-end ACFE forms "
        "that use Dynamic Render or shortcode preview, confirm PHP OpenSSL is "
        "available as defense in depth, and rotate credentials if compromise "
        f"is suspected. See {CHECK.cve}."
    )


def looks_like_wordpress(body: str) -> bool:
    """True when already-crawled HTML already indicates WordPress."""
    low = (body or "").lower()
    return any(marker in low for marker in _WP_MARKERS)


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


def is_acf_extended_readme(body: str) -> bool:
    """True when the body looks like an ACF Extended plugin readme, not HTML."""
    text = body or ""
    if recon.looks_like_app_html(text[:400]):
        return False
    low = text.lower()
    if not any(field in low for field in _README_FIELDS):
        return False
    if not any(marker in low for marker in _NAME_MARKERS):
        return False
    return True


def is_pro_readme(body: str, *, from_pro_path: bool) -> bool:
    """True only when the PRO product is confirmed.

    The vendor PRO install folder ``acf-extended-pro`` is definitive. The free
    WordPress.org folder ``acf-extended`` is accepted only when the plugin
    header names the PRO product — free readmes that merely advertise Pro
    features or list Pro changelog lines must not count.
    """
    if not is_acf_extended_readme(body):
        return False
    if from_pro_path:
        return True
    match = _HEADER.search(body or "")
    if not match:
        return False
    name = match.group(1).lower()
    if "pro" not in name:
        return False
    return "acf" in name or "extended" in name


def affected(version: tuple[int, ...]) -> bool:
    """True for versions through 0.9.2.6 inclusive. 0.9.2.7+ is patched."""
    return cmp_ver(version, _AFFECTED_THROUGH) <= 0


def _prereq_note() -> str:
    return (
        "Exposure prerequisites (not confirmed by this check): non-default "
        "shortcode_preview on an affected form, or a server without OpenSSL "
        "where ACF decrypt falls back to unverified base64. "
    )


def _passive_note() -> str:
    return (
        "Only read-only GETs of public plugin readme.txt paths were sent; no "
        "ACF/ACFE form submission, admin-ajax, REST API, render/callback "
        "parameter, POST, upload, write, or malformed input was sent."
    )


def _vulnerable(version: tuple[int, ...], where: str) -> dict:
    label = fmt(version)
    return base_finding(
        CHECK,
        severity="critical",
        title=f"{UNCONFIRMED}: ACF Extended PRO {label} ({CHECK.cve})",
        evidence=(
            f"{where} is {label}. {UNCONFIRMED}. "
            f"Affected: ACF Extended PRO through 0.9.2.6. First fix {_FIXED}; "
            f"{_RECOMMENDED} recommended. "
            f"{CHECK.cve}: unauthenticated RCE via the Dynamic Render field "
            "flow (front-end form config merged into field settings and a PHP "
            "callback invoked; Wordfence CVSS 9.8). Patchstack marks this as "
            "known-exploited (recently-exploited list 3 November 2026; "
            "Patchstack telemetry, not CISA KEV). "
            f"{_prereq_note()}{_passive_note()}"
        ),
        fix=_fix(),
        match=f"acf-extended-pro:{label}",
    )


def _unknown(where: str) -> dict:
    finding = base_finding(
        CHECK,
        severity="info",
        title=(
            f"ACF Extended PRO detected; version not exposed "
            f"({CHECK.cve}, low confidence)"
        ),
        evidence=(
            f"ACF Extended PRO was detected via {where}, but no readable "
            f"version was exposed (low confidence). {CHECK.cve} cannot be "
            "compared (affected through 0.9.2.6; first fix 0.9.2.7; 0.9.2.8 "
            f"recommended). {_prereq_note()}{_passive_note()}"
        ),
        fix=_fix(),
        match="acf-extended-pro:unknown",
    )
    finding["confidence"] = "low"
    return finding


def _assess(body: str, path: str) -> list[dict]:
    version, where = plugin_version(body)
    source = f"GET {path} {where}".strip() if where else f"GET {path}"
    if version is not None:
        if affected(version):
            return [_vulnerable(version, source)]
        return []
    return [_unknown(source)]


def _probe(ctx, path: str, *, from_pro_path: bool) -> tuple[str, list[dict] | None]:
    """Return ``(certainty, findings_or_None)``.

    ``certain`` means the path answered with a confirmed PRO or free readme
    (so no alternate probe is needed). ``uncertain`` means try the alternate.
    Findings is None when there is no finding yet.
    """
    resp = fetch_path(ctx, path, max_bytes=65536)
    status = int(resp.get("status") or 0)
    body = resp.get("body") or ""
    if status != 200:
        return "uncertain", None
    if is_pro_readme(body, from_pro_path=from_pro_path):
        return "certain", _assess(body, path)
    if is_acf_extended_readme(body):
        # Confirmed free (or non-PRO) readme — do not flag, do not keep probing.
        return "certain", []
    return "uncertain", None


def run(section, ctx) -> list[dict]:
    _headers, body = root_observation(ctx)
    if not looks_like_wordpress(body):
        return []

    certainty, findings = _probe(ctx, PRIMARY, from_pro_path=True)
    if certainty == "certain":
        return findings or []

    # Primary path missing or not a clear plugin readme: one alternate GET only.
    _certainty, findings = _probe(ctx, ALTERNATE, from_pro_path=False)
    return findings or []


CHECK = CveCheck(
    id="acf-extended-pro",
    cve="CVE-2026-120534",
    # Misconfig/Enumeration: WordPress plugin fingerprint only.
    agent="misconfig",
    fixed=(
        "0.9.2.7+ (first fix; 0.9.2.8 recommended; affected: ACF Extended PRO "
        "through 0.9.2.6; free acf-extended is out of scope)"
    ),
    summary=(
        "Confirm WordPress from already-crawled HTML, then at most two GETs of "
        "plugin readme.txt under /wp-content/plugins/acf-extended-pro/ (vendor "
        "PRO folder) and, when uncertain, /wp-content/plugins/acf-extended/. "
        "Critical for PRO through 0.9.2.6 (first fix 0.9.2.7; 0.9.2.8 "
        "recommended). Info/low confidence when PRO is present but the version "
        "is hidden. Free acf-extended alone is never flagged."
    ),
    sends=(
        "After WordPress is already visible in crawled HTML: one GET of "
        "/wp-content/plugins/acf-extended-pro/readme.txt; when that path is "
        "uncertain, one GET of /wp-content/plugins/acf-extended/readme.txt "
        "(max two GETs). No request when WordPress is not indicated."
    ),
    does_not_send=(
        "Never submits ACF/ACFE forms. Never requests admin-ajax.php or REST "
        "API routes. Never sends render/callback parameters, shortcode_preview "
        "probes, Dynamic Render payloads, POSTs, uploads, writes, logins, or "
        "malformed input."
    ),
    run=run,
)
