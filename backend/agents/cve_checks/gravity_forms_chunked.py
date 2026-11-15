"""Gravity Forms chunked upload (CVE-2026-119529) — passive plugin version read.

Gravity Forms before 3.2.2 does not properly restrict file types that
unauthenticated users can upload through its chunked file upload feature.
On servers that parse Server-Side Includes (SSI), that can become local file
inclusion exposing environment variables and web-root file contents
(CVSS 5.9). Fixed in 3.2.2 (validates extensions before writing chunks).
VulnCheck observed exploitation before CISA; a public PoC exists.

Reuses Gravity Forms helpers from ``gravity_forms`` (CVE-2026-103039): the
same asset ``?ver=`` parse and at most one shared GET of
``/wp-content/plugins/gravityforms/change_log.txt`` per scan. Never calls
upload endpoints (``gf_upload`` / ``GFAsyncUpload``) and never sends file
chunks.
"""
from . import gravity_forms as gf
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt


_AFFECTED_THROUGH = (3, 2, 1)
_FIXED = (3, 2, 2)


def _fix() -> str:
    return (
        "Update Gravity Forms to 3.2.2 or later through the vendor licensed "
        "update channel. Purge page, object, and CDN caches after updating. "
        "Review multi-file upload fields and disable SSI / Server-Side "
        "Includes for upload directories if enabled. Rotate any secrets that "
        f"may have been exposed via environment or web-root reads. See "
        f"{CHECK.cve}."
    )


def affected(version: tuple[int, ...]) -> bool:
    """True for versions through 3.2.1 inclusive. 3.2.2+ is patched."""
    return cmp_ver(version, _AFFECTED_THROUGH) <= 0


def _passive_note() -> str:
    return (
        "Only a read-only GET of the public plugin change_log.txt was sent when "
        "needed (shared with the sibling object-injection check); no "
        "admin-ajax.php, REST form submission, form endpoint, POST, form "
        "submission, gf_upload, GFAsyncUpload, file chunk, file upload, write, "
        "or /wp-admin request was sent."
    )


def _vulnerable(version: tuple[int, ...], where: str) -> dict:
    label = fmt(version)
    return base_finding(
        CHECK,
        severity="medium",
        title=f"{UNCONFIRMED}: Gravity Forms {label} ({CHECK.cve})",
        evidence=(
            f"Observed Gravity Forms {label} via {where}. {UNCONFIRMED}. "
            f"Affected: Gravity Forms before 3.2.2 (through 3.2.1). Fixed in "
            f"{fmt(_FIXED)}. {CHECK.cve}: unauthenticated users can upload "
            "unsupported file types through chunked upload; on servers with "
            "SSI enabled this can become LFI exposing environment variables "
            "and web-root files (OpenAdvisories / WPScan CVSS 5.9). VulnCheck "
            "observed exploitation before CISA; a public PoC exists. This "
            "check does not confirm SSI is enabled or that uploads are "
            f"reachable. {_passive_note()} Sources: "
            "https://www.openadvisories.org/vuln/CVE-2026-119529 , "
            "https://www.gravityforms.com/blog/gravity-forms-3-2-2/ , "
            "https://vexday.io/en/boletim/2026-11-11 ."
        ),
        fix=_fix(),
        match=f"gravityforms-chunked:{label}",
    )


def _info(where: str) -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=f"Gravity Forms detected; version not exposed ({CHECK.cve})",
        evidence=(
            f"Gravity Forms was detected via {where}, but no readable version "
            f"was exposed. {CHECK.cve} cannot be compared (affected before "
            f"3.2.2; fixed in {fmt(_FIXED)}). This check does not confirm SSI "
            f"is enabled. {_passive_note()}"
        ),
        fix=_fix(),
        match="gravityforms-chunked:unknown",
    )


def run(section, ctx) -> list[dict]:
    version, where, seen = gf.resolve_plugin_version(ctx)

    if version is not None:
        if affected(version):
            return [_vulnerable(version, where)]
        return []

    if seen:
        return [_info(where)]
    return []


CHECK = CveCheck(
    id="gravityforms-chunked",
    cve="CVE-2026-119529",
    agent="misconfig",
    fixed="3.2.2+ (affected: Gravity Forms before 3.2.2 / through 3.2.1)",
    summary=(
        "Confirm WordPress from the already-fetched root response, then read "
        "the Gravity Forms version from a plugin asset ?ver= already in the "
        "page, or when the plugin path is present without a version, one GET "
        "of /wp-content/plugins/gravityforms/change_log.txt shared with the "
        "sibling CVE-2026-103039 check. Medium for versions through 3.2.1 "
        "(fixed in 3.2.2). Info when the plugin is present but the version is "
        "hidden. Non-WordPress targets and pages without a gravityforms asset "
        "yield no request."
    ),
    sends=(
        "No request when the root response does not look like WordPress, or "
        "when crawled HTML already shows a gravityforms asset ?ver=. When "
        "WordPress is indicated and the plugin path is present without a "
        "version, one GET of /wp-content/plugins/gravityforms/change_log.txt "
        "(at most once per scan, shared with gravityforms). No request when "
        "the plugin is absent from crawled HTML."
    ),
    does_not_send=(
        "Never requests gf_upload, GFAsyncUpload, admin-ajax.php, REST form "
        "submission, or any form/upload endpoint. No POSTs or form "
        "submissions, no file chunks, no file uploads, no writes, and nothing "
        "to /wp-admin. Never more than the single shared change_log.txt GET."
    ),
    run=run,
)
