"""Estatik (CVE-2026-125795) — passive plugin version read.

Estatik real-estate plugin (WordPress.org slug ``estatik``) through 4.3.6 has
an unauthenticated local file inclusion (CWE-98, CVSS 9.8) via its logged-out
listing-search template parameter. Fixed in 4.3.7 (12 November 2026).
Patchstack labels known-exploited (Patchstack telemetry, not CISA KEV).
GHSA-3cfv-f88w-c563.

Detection is passive only: confirm WordPress from the already-fetched root
response, parse crawled HTML for ``/wp-content/plugins/estatik/`` asset URLs
with ``?ver=``, and when the plugin path is present without a version, at most
one GET of the plugin ``readme.txt`` Stable tag (validated so a soft-404 HTML
page does not match).

Never calls listing-search or admin-ajax endpoints, never sends template or
path parameters or traversal strings, and never POSTs, uploads, or touches
``/wp-admin``.
"""
import re

import recon

from .client import fetch_path, root_observation
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, parse_dotted


README = "/wp-content/plugins/estatik/readme.txt"
_AFFECTED_THROUGH = (4, 3, 6)
_FIXED = (4, 3, 7)

_SOURCES = (
    "https://patchstack.com/database/wordpress/plugin/estatik/"
    "vulnerability/wordpress-estatik-plugin-4-3-6-local-file-inclusion-"
    "vulnerability",
    "https://laskyr.com/cve/CVE-2026-125795",
    "https://www.openadvisories.org/vuln/CVE-2026-125795",
)

_STABLE = re.compile(r"(?im)^[ \t]*stable tag:[ \t]*(\d+(?:\.\d+){0,3})[ \t]*$")
_HEADER = re.compile(r"(?im)^===\s*.*\bestatik\b.*===\s*$")
_README_FIELDS = ("stable tag:", "contributors:", "requires at least:")
_NAME_MARKERS = (
    "estatik",
    "estatik real estate",
    "real estate plugin",
)
_ASSET = re.compile(
    r"/wp-content/plugins/estatik/[^\"'\s>]*",
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
        "Update Estatik to 4.3.7 or later (Plugins screen or "
        "`wp plugin update estatik`). Purge page, object, and CDN caches after "
        f"updating. See {CHECK.cve}."
    )


def _sources_note() -> str:
    return "Sources: " + "; ".join(_SOURCES) + "."


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
    """True when the body is an Estatik plugin readme, not an HTML soft-404."""
    text = body or ""
    if recon.looks_like_app_html(text[:400]):
        return False
    low = text.lower()
    if not _HEADER.search(text) and not any(marker in low for marker in _NAME_MARKERS):
        return False
    if not any(marker in low for marker in _NAME_MARKERS):
        return False
    return any(field in low for field in _README_FIELDS)


def affected(version: tuple[int, ...]) -> bool:
    """True for versions through 4.3.6 inclusive. 4.3.7+ is patched."""
    return cmp_ver(version, _AFFECTED_THROUGH) <= 0


def version_from_assets(body: str) -> tuple[tuple[int, ...] | None, bool]:
    """Plugin-file ``?ver=`` on an Estatik asset, and whether any was seen."""
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
        "needed; no listing-search or admin-ajax call, template or path "
        "parameter, traversal string, POST, form submission, upload, write, or "
        "/wp-admin request was sent."
    )


def _vulnerable(version: tuple[int, ...], where: str) -> dict:
    label = fmt(version)
    return base_finding(
        CHECK,
        severity="critical",
        title=f"{UNCONFIRMED}: Estatik {label} ({CHECK.cve})",
        evidence=(
            f"Observed Estatik {label} via {where}. {UNCONFIRMED}. "
            f"Affected: Estatik through 4.3.6. Fixed in 4.3.7. {CHECK.cve}: "
            "unauthenticated local file inclusion via the logged-out "
            "listing-search template parameter (CWE-98, CVSS 9.8). Patchstack "
            "labels known-exploited (Patchstack telemetry, not CISA KEV). "
            f"GHSA-3cfv-f88w-c563. {_passive_note()} {_sources_note()}"
        ),
        fix=_fix(),
        match=f"estatik:{label}",
    )


def _info(where: str) -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=f"Estatik detected; version not exposed ({CHECK.cve})",
        evidence=(
            f"Estatik was detected via {where}, but no readable version was "
            f"exposed. {CHECK.cve} cannot be compared (affected through 4.3.6; "
            f"fixed in 4.3.7). {_passive_note()} {_sources_note()}"
        ),
        fix=_fix(),
        match="estatik:unknown",
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

    # Only fetch the readme when the plugin path is already present without a
    # version. Plugin absent from crawled HTML: no requests, no finding.
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
    id="estatik",
    cve="CVE-2026-125795",
    # Closest registry agent: InjectionAgent owns LFI / file-read probes and is
    # not one of CveCheck.AGENTS (misconfig/recon/auth/secrets). Same pattern as
    # Ninja Forms File Uploads and Amelia Pro (InjectionAgent family → misconfig
    # fingerprint).
    agent="misconfig",
    fixed="4.3.7+ (affected: Estatik through 4.3.6)",
    summary=(
        "Confirm WordPress from the already-fetched root response, then read "
        "the Estatik version from a plugin asset ?ver= already in the page, "
        "or when the plugin path is present without a version, one GET of "
        "/wp-content/plugins/estatik/readme.txt Stable tag. Critical for "
        "versions through 4.3.6 (fixed in 4.3.7; CVSS 9.8). Info when the "
        "plugin is present but the version is hidden. Non-WordPress targets "
        "and pages without an estatik asset yield no request."
    ),
    sends=(
        "No request when the root response does not look like WordPress, or "
        "when crawled HTML already shows an estatik asset ?ver=. When "
        "WordPress is indicated and the plugin path is present without a "
        "version, one GET of /wp-content/plugins/estatik/readme.txt. No "
        "request when the plugin is absent from crawled HTML."
    ),
    does_not_send=(
        "Never calls listing-search or admin-ajax endpoints. Never sends "
        "template or path parameters or traversal strings. No POSTs or form "
        "submissions, no uploads, no writes, and nothing to /wp-admin. Never "
        "more than the single readme GET."
    ),
    run=run,
)
