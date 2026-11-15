"""Ninja Forms File Uploads (CVE-2026-126537) — passive plugin version read.

Ninja Forms — File Uploads (premium slug ``ninja-forms-uploads``) through
3.3.36 has unauthenticated arbitrary file deletion plus file read via
cloud-storage exfiltration: when ``extra.saveProgress`` is set,
``NF_FU_Fields_Upload::process()`` leaves client-supplied ``files[].data``
intact, and omitting ``upload_id`` lets ``data.file_path`` reach the
background upload queue (unlink / S3 SourceFile) with no upload-directory
containment check. Deleting ``wp-config.php`` can force the WordPress
installer and enable takeover (Rapid7 CVSS 9.1). Fixed in 3.3.37 (released
2 November 2026). VulnCheck observed exploitation before CISA listing.

Detection is passive only: confirm WordPress from the already-fetched root
response, parse crawled HTML for ``/wp-content/plugins/ninja-forms-uploads/``
asset URLs with ``?ver=``, and when the plugin path is present without a
version, at most one GET of the packaged ``changelog.txt``.

Why ``changelog.txt`` (not ``readme.txt``): this is a license-gated premium
add-on, not a WordPress.org free plugin with a reliable public readme Stable
tag. The vendor publishes a markdown changelog (``#### X.Y.Z (date)``), and
packaged ``changelog.txt`` is the usual premium companion — same rationale as
Gravity Forms' ``change_log.txt``.

Never submits Ninja Forms forms, never sends ``saveProgress`` or
``file_path`` fields, never touches ``nf_ajax_submit``. No POSTs, admin-ajax,
REST form calls, uploads, deletions, path traversal, or anything to /wp-admin.
"""
import re

import recon

from .client import fetch_path, root_observation
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, parse_dotted


CHANGELOG = "/wp-content/plugins/ninja-forms-uploads/changelog.txt"
_AFFECTED_THROUGH = (3, 3, 36)
_FIXED = (3, 3, 37)

_ASSET = re.compile(
    r"/wp-content/plugins/ninja-forms-uploads/[^\"'\s>]*",
    re.I,
)
_VER = re.compile(r"[?&]ver=(\d+(?:\.\d+){0,3})", re.I)
# Vendor / packaged changelog: "#### 3.3.37 (2 November 2026)" or "### 3.3.37".
_CHANGELOG_HEAD = re.compile(
    r"(?im)^[ \t]*#{1,4}[ \t]+(\d+(?:\.\d+){0,3})[ \t]*(?:\([^)]*\)|[|][^\n]*)?[ \t]*$",
)
_NAME_MARKERS = (
    "ninja forms",
    "ninja-forms-uploads",
    "file uploads",
    "nf_fu_",
    "nf-fu-",
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
        "Update Ninja Forms File Uploads to 3.3.37 or later and confirm the "
        "license-gated update actually landed (Plugins screen / vendor channel). "
        "Confirm wp-config.php is intact and the WordPress installer screen is "
        "not showing. Check for unknown administrator accounts. Review connected "
        "S3, Dropbox, and Google Drive folders for stray or unexpected files. "
        "Purge page, object, and CDN caches after updating. See "
        f"{CHECK.cve}; "
        "https://www.rapid7.com/db/vulnerabilities/cve-2026-126537/ ; "
        "https://ninjaforms.com/extensions/file-uploads/?changelog=1 ; "
        "https://vexday.io/en/boletim/2026-11-11 ."
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
    """True for versions through 3.3.36 inclusive. 3.3.37+ is patched."""
    return cmp_ver(version, _AFFECTED_THROUGH) <= 0


def version_from_assets(body: str) -> tuple[tuple[int, ...] | None, bool]:
    """Plugin-file ``?ver=`` on a File Uploads asset, and whether any was seen."""
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
    """Newest dotted version from a ``#### X.Y.Z (date)`` changelog heading."""
    match = _CHANGELOG_HEAD.search(body or "")
    return parse_dotted(match.group(1)) if match else None


def is_plugin_changelog(body: str) -> bool:
    """True when the body looks like ninja-forms-uploads changelog.txt, not HTML."""
    text = body or ""
    if recon.looks_like_app_html(text[:400]):
        return False
    if not _CHANGELOG_HEAD.search(text):
        return False
    low = text.lower()
    return any(marker in low for marker in _NAME_MARKERS)


def _passive_note() -> str:
    return (
        "Only a read-only GET of the public plugin changelog.txt was sent when "
        "needed; no Ninja Forms form submission, saveProgress or file_path "
        "field, nf_ajax_submit, admin-ajax.php, REST form call, POST, upload, "
        "file deletion, path traversal, or /wp-admin request was sent."
    )


def _vulnerable(version: tuple[int, ...], where: str) -> dict:
    label = fmt(version)
    return base_finding(
        CHECK,
        severity="critical",
        title=f"{UNCONFIRMED}: Ninja Forms File Uploads {label} ({CHECK.cve})",
        evidence=(
            f"Observed Ninja Forms File Uploads {label} via {where}. "
            f"{UNCONFIRMED}. Affected: Ninja Forms File Uploads through 3.3.36. "
            "Fixed in 3.3.37 (released 2 November 2026). "
            f"{CHECK.cve}: unauthenticated arbitrary file deletion plus file "
            "read via cloud-storage exfiltration through files[].data.file_path "
            "when extra.saveProgress is set (Rapid7 CVSS 9.1). VulnCheck "
            "observed exploitation before CISA. Deleting wp-config.php can "
            "force the WordPress installer; this check does not confirm that "
            f"outcome. {_passive_note()} Sources: "
            "https://www.rapid7.com/db/vulnerabilities/cve-2026-126537/ ; "
            "https://ninjaforms.com/extensions/file-uploads/?changelog=1 ; "
            "https://vexday.io/en/boletim/2026-11-11 ."
        ),
        fix=_fix(),
        match=f"ninja-forms-uploads:{label}",
    )


def _info(where: str) -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=(
            f"Ninja Forms File Uploads detected; version not exposed "
            f"({CHECK.cve})"
        ),
        evidence=(
            f"Ninja Forms File Uploads was detected via {where}, but no "
            f"readable version was exposed. {CHECK.cve} cannot be compared "
            "(affected through 3.3.36; fixed in 3.3.37). "
            f"{_passive_note()}"
        ),
        fix=_fix(),
        match="ninja-forms-uploads:unknown",
    )


def _changelog_version(ctx) -> tuple[tuple[int, ...] | None, str, bool]:
    """At most one GET of changelog.txt. Returns ``(version, where, is_plugin)``."""
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
    id="ninja-forms-uploads",
    cve="CVE-2026-126537",
    agent="misconfig",
    fixed="3.3.37+ (affected: Ninja Forms File Uploads through 3.3.36)",
    summary=(
        "Confirm WordPress from the already-fetched root response, then read "
        "the Ninja Forms File Uploads version from a plugin asset ?ver= already "
        "in the page, or when the plugin path is present without a version, one "
        "GET of /wp-content/plugins/ninja-forms-uploads/changelog.txt. Critical "
        "for versions through 3.3.36 (fixed in 3.3.37). Info when the plugin is "
        "present but the version is hidden. Non-WordPress targets and pages "
        "without a ninja-forms-uploads asset yield no request."
    ),
    sends=(
        "No request when the root response does not look like WordPress, or "
        "when crawled HTML already shows a ninja-forms-uploads asset ?ver=. "
        "When WordPress is indicated and the plugin path is present without a "
        "version, one GET of "
        "/wp-content/plugins/ninja-forms-uploads/changelog.txt. No request "
        "when the plugin is absent from crawled HTML."
    ),
    does_not_send=(
        "Never submits Ninja Forms forms. Never sends saveProgress or "
        "file_path fields. Never touches nf_ajax_submit. No POSTs, "
        "admin-ajax.php, REST form calls, uploads, file deletions, path "
        "traversal, or anything to /wp-admin. Never more than the single "
        "changelog.txt GET."
    ),
    run=run,
)
