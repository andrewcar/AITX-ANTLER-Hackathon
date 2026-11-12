"""SliceWP (CVE-2026-120043) — passive plugin version read.

Affiliate Program Suite – SliceWP Affiliates (WordPress.org slug ``slicewp``)
through 1.2.14 has an unauthenticated SQL injection via insufficient escaping
of the ``email`` parameter on the ``user_register`` hook after WooCommerce My
Account registration (registration nonce available to guests). Fixed in 1.2.15
(WordPress.org changelog: ``Misc: Variable escaping.``). Patchstack priority
9.3 and marks known-exploited (Patchstack telemetry, not CISA KEV). Wordfence
CVSS 7.5.

Detection is passive only: read already-crawled HTML for
``/wp-content/plugins/slicewp/`` asset URLs with ``?ver=``, and when the plugin
path is present without a version, at most one GET of the plugin
``readme.txt`` Stable tag.

Never requests ``/my-account/`` or any registration endpoint. No POSTs or form
submissions, no account creation, no ``email`` or other parameters, no
SQL/quote/timing payloads, no nonce fetching, no malformed input, no uploads,
no writes, no brute force, and never more than the single readme GET.
"""
import re

import recon

from .client import fetch_path, root_observation
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, parse_dotted


README = "/wp-content/plugins/slicewp/readme.txt"
_AFFECTED_THROUGH = (1, 2, 14)

_STABLE = re.compile(r"(?im)^[ \t]*stable tag:[ \t]*(\d+(?:\.\d+){0,3})[ \t]*$")
_HEADER = re.compile(r"(?im)^===\s*.*\bslicewp\b.*===\s*$")
_README_FIELDS = ("stable tag:", "contributors:", "requires at least:")
_ASSET = re.compile(
    r"/wp-content/plugins/slicewp/[^\"'\s>]*",
    re.I,
)
_VER = re.compile(r"[?&]ver=(\d+(?:\.\d+){0,3})", re.I)


def _fix() -> str:
    return (
        "Update SliceWP to 1.2.15 or later. Purge page, object, and CDN caches "
        "after updating. If the update cannot be applied yet, temporarily "
        "disable public WooCommerce My Account registration or deactivate "
        f"SliceWP. See {CHECK.cve}."
    )


def stable_tag(body: str) -> tuple[int, ...] | None:
    match = _STABLE.search(body or "")
    return parse_dotted(match.group(1)) if match else None


def is_plugin_readme(body: str) -> bool:
    """True when the body is a SliceWP plugin readme, not an HTML page."""
    text = body or ""
    if recon.looks_like_app_html(text[:400]):
        return False
    if not _HEADER.search(text) and "slicewp" not in text.lower():
        return False
    low = text.lower()
    if "slicewp" not in low:
        return False
    return any(field in low for field in _README_FIELDS)


def affected(version: tuple[int, ...]) -> bool:
    """True for versions through 1.2.14 inclusive. 1.2.15+ is patched."""
    return cmp_ver(version, _AFFECTED_THROUGH) <= 0


def version_from_assets(body: str) -> tuple[tuple[int, ...] | None, bool]:
    """Plugin-file ``?ver=`` on a SliceWP asset, and whether any asset was seen."""
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


def _vulnerable(version: tuple[int, ...], where: str) -> dict:
    label = fmt(version)
    return base_finding(
        CHECK,
        severity="critical",
        title=f"{UNCONFIRMED}: SliceWP {label} ({CHECK.cve})",
        evidence=(
            f"Observed SliceWP {label} via {where}. {UNCONFIRMED}. "
            f"Affected: SliceWP through 1.2.14. Fixed in 1.2.15 "
            "(WordPress.org changelog: additional variable escaping). "
            f"{CHECK.cve}: unauthenticated SQL injection via the email "
            "parameter on the user_register hook after WooCommerce My Account "
            "registration (Patchstack priority 9.3, Wordfence CVSS 7.5). "
            "Patchstack marks this as known-exploited (Patchstack telemetry, "
            "not CISA KEV). Exposure requires public WooCommerce My Account "
            "registration, which this check does not confirm. No /my-account/ "
            "or registration request, POST, form submission, account creation, "
            "email parameter, SQL/quote/timing payload, nonce fetch, malformed "
            "input, upload, write, or brute force was sent."
        ),
        fix=_fix(),
        match=f"slicewp:{label}",
    )


def _info(where: str) -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=f"SliceWP detected; version not exposed ({CHECK.cve})",
        evidence=(
            f"SliceWP was detected via {where}, but no readable version was "
            f"exposed. {CHECK.cve} cannot be compared (affected through 1.2.14; "
            "fixed in 1.2.15). Exposure requires public WooCommerce My Account "
            "registration, which this check does not confirm. No /my-account/ "
            "or registration request, POST, form submission, account creation, "
            "email parameter, SQL/quote/timing payload, nonce fetch, malformed "
            "input, upload, write, or brute force was sent."
        ),
        fix=_fix(),
        match="slicewp:unknown",
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
    _headers, body = root_observation(ctx)
    version, where, seen = observe_html(body)

    # Only fetch readme when the plugin path is already present without a version.
    # Plugin absent from crawled HTML: no requests, no finding.
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
    id="slicewp",
    cve="CVE-2026-120043",
    agent="misconfig",
    fixed="1.2.15+ (affected: SliceWP through 1.2.14)",
    summary=(
        "Read the SliceWP version from a plugin asset ?ver= already in the "
        "page, or when the plugin path is present without a version, one GET "
        "of the plugin readme Stable tag. Critical for versions through "
        "1.2.14 (fixed in 1.2.15). Info when the plugin is present but the "
        "version is hidden. Plugin absent from crawled HTML yields no request."
    ),
    sends=(
        "No request when crawled HTML already shows a slicewp asset ?ver=. "
        "When the plugin path is present without a version, one GET of "
        "/wp-content/plugins/slicewp/readme.txt. No request when the plugin "
        "is absent from crawled HTML."
    ),
    does_not_send=(
        "Never requests /my-account/ or any registration endpoint. No POSTs "
        "or form submissions, no account creation, no email or other "
        "parameters, no SQL/quote/timing payloads, no nonce fetching, no "
        "malformed input, no uploads, no writes, no brute force, and never "
        "more than the single readme GET."
    ),
    run=run,
)
