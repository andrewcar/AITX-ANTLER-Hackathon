"""Gravity Forms (CVE-2026-103039) — passive plugin version read.

Gravity Forms (premium slug ``gravityforms``) through 3.1.2 has an
unauthenticated PHP object injection via a List-type Post Custom Field:
``GFFormsModel::create_post()`` passed the submitted value to WordPress'
unrestricted ``maybe_unserialize()`` instead of the plugin's hardened
``GFCommon::maybe_unserialize()``. Code execution is possible when a gadget
chain exists (CVSS 9.8). Fixed in 3.1.3 (released 1 October 2026; current
line includes 3.2.1). Patchstack marks known-exploited (Patchstack telemetry,
not CISA KEV). Wordfence CVSS 9.8.

Detection is passive only: confirm WordPress from the already-fetched root
response, parse crawled HTML for ``/wp-content/plugins/gravityforms/`` asset
URLs with ``?ver=``, and when the plugin path is present without a version,
at most one GET of the packaged ``change_log.txt`` (premium plugin; usually
no public readme).

Never requests admin-ajax, REST form submission, or any form endpoint. No
POSTs, form submissions, serialized PHP strings, ``O:``-style payloads, file
uploads, writes, or anything to /wp-admin.
"""
import re

import recon

from .client import fetch_path, root_observation
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, parse_dotted


CHANGELOG = "/wp-content/plugins/gravityforms/change_log.txt"
_AFFECTED_THROUGH = (3, 1, 2)
_FIXED = (3, 1, 3)

_ASSET = re.compile(
    r"/wp-content/plugins/gravityforms/[^\"'\s>]*",
    re.I,
)
_VER = re.compile(r"[?&]ver=(\d+(?:\.\d+){0,3})", re.I)
_CHANGELOG_HEAD = re.compile(
    r"(?im)^[ \t]*###[ \t]+(\d+(?:\.\d+){0,3})[ \t]*(?:\|[^\n]*)?$",
)
_NAME_MARKERS = (
    "gravity forms",
    "gravityforms",
    "gform_",
    "gfcommon",
)
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
        "Update Gravity Forms to 3.1.3 or later through the vendor licensed "
        "update channel (current line includes 3.2.1). Purge page, object, and "
        "CDN caches after updating. Review front-end forms that create posts "
        "with List-type Post Custom Fields, and rotate credentials if "
        f"compromise is suspected. See {CHECK.cve}."
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


def affected(version: tuple[int, ...]) -> bool:
    """True for versions through 3.1.2 inclusive. 3.1.3+ is patched."""
    return cmp_ver(version, _AFFECTED_THROUGH) <= 0


def version_from_assets(body: str) -> tuple[tuple[int, ...] | None, bool]:
    """Plugin-file ``?ver=`` on a Gravity Forms asset, and whether any was seen."""
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


def changelog_version(body: str) -> tuple[int, ...] | None:
    """Newest dotted version from a ``### X.Y.Z | date`` changelog heading."""
    match = _CHANGELOG_HEAD.search(body or "")
    return parse_dotted(match.group(1)) if match else None


def is_plugin_changelog(body: str) -> bool:
    """True when the body looks like Gravity Forms change_log.txt, not HTML."""
    text = body or ""
    if recon.looks_like_app_html(text[:400]):
        return False
    if not _CHANGELOG_HEAD.search(text):
        return False
    low = text.lower()
    return any(marker in low for marker in _NAME_MARKERS)


def _passive_note() -> str:
    return (
        "Only a read-only GET of the public plugin change_log.txt was sent when "
        "needed; no admin-ajax.php, REST form submission, form endpoint, POST, "
        "form submission, serialized PHP string, O:-style payload, file upload, "
        "write, or /wp-admin request was sent."
    )


def _vulnerable(version: tuple[int, ...], where: str) -> dict:
    label = fmt(version)
    return base_finding(
        CHECK,
        severity="critical",
        title=f"{UNCONFIRMED}: Gravity Forms {label} ({CHECK.cve})",
        evidence=(
            f"Observed Gravity Forms {label} via {where}. {UNCONFIRMED}. "
            f"Affected: Gravity Forms through 3.1.2. Fixed in 3.1.3 "
            "(released 1 October 2026; current line includes 3.2.1). "
            f"{CHECK.cve}: unauthenticated PHP object injection via a "
            "List-type Post Custom Field (Patchstack CVSS 9.8, Wordfence "
            "CVSS 9.8). Patchstack marks this as known-exploited (Patchstack "
            "telemetry, not CISA KEV). Code execution requires a gadget chain "
            "outside the plugin, which this check does not confirm. "
            f"{_passive_note()}"
        ),
        fix=_fix(),
        match=f"gravityforms:{label}",
    )


def _info(where: str) -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=f"Gravity Forms detected; version not exposed ({CHECK.cve})",
        evidence=(
            f"Gravity Forms was detected via {where}, but no readable version "
            f"was exposed. {CHECK.cve} cannot be compared (affected through "
            "3.1.2; fixed in 3.1.3). Code execution requires a gadget chain "
            f"outside the plugin, which this check does not confirm. "
            f"{_passive_note()}"
        ),
        fix=_fix(),
        match="gravityforms:unknown",
    )


def _changelog_version(ctx) -> tuple[tuple[int, ...] | None, str, bool]:
    """At most one GET of change_log.txt. Returns ``(version, where, is_plugin)``."""
    resp = fetch_path(ctx, CHANGELOG, max_bytes=65536)
    if resp.get("status") != 200:
        return None, "", False
    body = resp.get("body") or ""
    if not is_plugin_changelog(body):
        return None, "", False
    version = changelog_version(body)
    if version is not None:
        return version, f"GET {CHANGELOG} version heading", True
    return None, f"GET {CHANGELOG}", True


def run(section, ctx) -> list[dict]:
    headers, body = root_observation(ctx)
    if not looks_like_wordpress(headers, body):
        return []

    version, where, seen = observe_html(body)

    # Only fetch the changelog when the plugin path is already present without
    # a version. Plugin absent from crawled HTML: no requests, no finding.
    if version is None and seen:
        log_version, log_where, is_plugin = _changelog_version(ctx)
        if is_plugin:
            where = log_where
            version = log_version

    if version is not None:
        if affected(version):
            return [_vulnerable(version, where)]
        return []

    if seen:
        return [_info(where)]
    return []


CHECK = CveCheck(
    id="gravityforms",
    cve="CVE-2026-103039",
    agent="misconfig",
    fixed="3.1.3+ (affected: Gravity Forms through 3.1.2)",
    summary=(
        "Confirm WordPress from the already-fetched root response, then read "
        "the Gravity Forms version from a plugin asset ?ver= already in the "
        "page, or when the plugin path is present without a version, one GET "
        "of /wp-content/plugins/gravityforms/change_log.txt. Critical for "
        "versions through 3.1.2 (fixed in 3.1.3). Info when the plugin is "
        "present but the version is hidden. Non-WordPress targets and pages "
        "without a gravityforms asset yield no request."
    ),
    sends=(
        "No request when the root response does not look like WordPress, or "
        "when crawled HTML already shows a gravityforms asset ?ver=. When "
        "WordPress is indicated and the plugin path is present without a "
        "version, one GET of /wp-content/plugins/gravityforms/change_log.txt. "
        "No request when the plugin is absent from crawled HTML."
    ),
    does_not_send=(
        "Never requests admin-ajax.php, REST form submission, or any form "
        "endpoint. No POSTs or form submissions, no serialized PHP strings, "
        "no O:-style payloads, no file uploads, no writes, and nothing to "
        "/wp-admin. Never more than the single change_log.txt GET."
    ),
    run=run,
)
