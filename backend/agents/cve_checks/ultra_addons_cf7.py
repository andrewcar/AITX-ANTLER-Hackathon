"""Ultra Addons for Contact Form 7 (CVE-2026-100386 / CVE-2026-102435).

WordPress plugin Ultra Addons for Contact Form 7 (slug
``ultimate-addons-for-contact-form-7``) through 3.5.54 has two unauthenticated
issues when the PDF Generator add-on is active and a form is configured for
PDF generation:

* CVE-2026-100386 — arbitrary file read via path traversal in
  ``uacf7_wpcf7_mail_components``, rendered into the generated PDF (CVSS 7.5).
* CVE-2026-102435 — arbitrary file deletion via a POP chain in mPDF
  ``_getObjAttr`` (RCE possible after ``wp-config.php`` deletion).

Fixed in 3.5.55 (current line includes 3.5.57). Patchstack marks both as
known-exploited (Patchstack telemetry, not CISA KEV).

Detection is passive only: confirm WordPress from the already-fetched root
response, parse crawled HTML for
``/wp-content/plugins/ultimate-addons-for-contact-form-7/`` asset URLs with
``?ver=``, and when the plugin path is present without a version, at most one
GET of the plugin ``readme.txt`` Stable tag (header validated against soft-404
HTML).

Never submits Contact Form 7 forms, never calls ``/wp-json/contact-form-7/`` or
``admin-ajax``, never requests generated PDFs, and never sends path strings,
POSTs, uploads, writes, or anything to ``/wp-admin``.
"""
import re

import recon

from .client import fetch_path, root_observation
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, parse_dotted


README = "/wp-content/plugins/ultimate-addons-for-contact-form-7/readme.txt"
_AFFECTED_THROUGH = (3, 5, 54)
_FIXED = (3, 5, 55)

_SOURCES = (
    "https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/"
    "ultimate-addons-for-contact-form-7/"
    "ultra-addons-for-contact-form-7-3554-unauthenticated-arbitrary-file-read-"
    "via-cf7-field-value-in-mpdf-writehtml-svg-parser",
    "https://laskyr.com/plugins/ultimate-addons-for-contact-form-7",
    "https://nvd.nist.gov/vuln/detail/cve-2026-100386",
)

_STABLE = re.compile(r"(?im)^[ \t]*stable tag:[ \t]*(\d+(?:\.\d+){0,3})[ \t]*$")
_HEADER = re.compile(
    r"(?im)^===\s*.*\b(?:ultra|ultimate)\s*addons?\s*(?:for\s*)?"
    r"(?:contact\s*form\s*7|cf7)\b.*===\s*$"
)
_README_FIELDS = ("stable tag:", "contributors:", "requires at least:")
_NAME_MARKERS = (
    "ultra addons",
    "ultimate addons",
    "ultimate-addons-for-contact-form-7",
    "uacf7",
    "contact form 7",
)
_ASSET = re.compile(
    r"/wp-content/plugins/ultimate-addons-for-contact-form-7/[^\"'\s>]*",
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
        "Update Ultra Addons for Contact Form 7 to 3.5.55 or later "
        "(ideally 3.5.57; Plugins screen or "
        "`wp plugin update ultimate-addons-for-contact-form-7`). "
        "If the PDF Generator add-on was enabled, rotate the database "
        "password and WordPress salts (AUTH_KEY / SECURE_AUTH_KEY / "
        "LOGGED_IN_KEY / NONCE_KEY and their salts in wp-config.php), "
        "confirm wp-config.php is intact, and review for unexpected "
        f"administrator accounts. See {CHECK.cve}."
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
    """True when the body is an Ultra Addons CF7 plugin readme, not HTML."""
    text = body or ""
    if recon.looks_like_app_html(text[:400]):
        return False
    # Require the === ... === header so a soft-404 that only mentions the
    # product name and a Stable tag line cannot pass as the plugin readme.
    if not _HEADER.search(text):
        return False
    low = text.lower()
    if not any(marker in low for marker in _NAME_MARKERS):
        return False
    return any(field in low for field in _README_FIELDS)


def affected(version: tuple[int, ...]) -> bool:
    """True for versions through 3.5.54 inclusive. 3.5.55+ is patched."""
    return cmp_ver(version, _AFFECTED_THROUGH) <= 0


def version_from_assets(body: str) -> tuple[tuple[int, ...] | None, bool]:
    """Plugin-file ``?ver=`` on an Ultra Addons asset, and whether any was seen."""
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
        "needed; no Contact Form 7 form submission, /wp-json/contact-form-7/ "
        "or admin-ajax call, generated PDF request, path string, POST, "
        "upload, write, or /wp-admin request was sent."
    )


def _vulnerable(version: tuple[int, ...], where: str) -> dict:
    label = fmt(version)
    return base_finding(
        CHECK,
        severity="high",
        title=f"{UNCONFIRMED}: Ultra Addons for CF7 {label} ({CHECK.cve})",
        evidence=(
            f"Observed Ultra Addons for Contact Form 7 {label} via {where}. "
            f"{UNCONFIRMED}. Affected: ultimate-addons-for-contact-form-7 "
            f"through 3.5.54. Fixed in 3.5.55 (current includes 3.5.57). "
            f"CVE-2026-100386: unauthenticated arbitrary file read via path "
            "traversal in uacf7_wpcf7_mail_components rendered into the "
            "generated PDF (CVSS 7.5). CVE-2026-102435: unauthenticated "
            "arbitrary file deletion via a POP chain in mPDF _getObjAttr "
            "(RCE possible after wp-config.php deletion). Both require the "
            "PDF Generator add-on active and a form configured for PDF "
            "generation, which this check does not confirm. Patchstack "
            "marks both as known-exploited (Patchstack telemetry, not CISA "
            f"KEV). {_passive_note()} {_sources_note()}"
        ),
        fix=_fix(),
        match=f"ultra-addons-cf7:{label}",
    )


def _info(where: str) -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=(
            f"Ultra Addons for CF7 detected; version not exposed ({CHECK.cve})"
        ),
        evidence=(
            f"Ultra Addons for Contact Form 7 was detected via {where}, but "
            f"no readable version was exposed. {CHECK.cve} cannot be compared "
            "(affected through 3.5.54; fixed in 3.5.55). Exposure depends on "
            "the PDF Generator add-on, which this check does not confirm. "
            f"{_passive_note()} {_sources_note()}"
        ),
        fix=_fix(),
        match="ultra-addons-cf7:unknown",
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
    id="ultra-addons-cf7",
    cve="CVE-2026-100386 / CVE-2026-102435",
    # File-read / misconfig specialist (path traversal into PDF + mPDF POP
    # deletion). Closest registry agent is misconfig — same family as
    # ninja-forms-uploads / vite_dev_server file-read fingerprints.
    agent="misconfig",
    fixed="3.5.55+ (ideally 3.5.57; affected: Ultra Addons for CF7 through 3.5.54)",
    summary=(
        "Confirm WordPress from the already-fetched root response, then read "
        "the Ultra Addons for Contact Form 7 version from a plugin asset "
        "?ver= already in the page, or when the plugin path is present "
        "without a version, one GET of "
        "/wp-content/plugins/ultimate-addons-for-contact-form-7/readme.txt "
        "Stable tag. High for versions through 3.5.54 (fixed in 3.5.55; "
        "CVE-2026-100386 / CVE-2026-102435; depends on PDF Generator). Info "
        "when the plugin is present but the version is hidden. Non-WordPress "
        "targets and pages without an ultimate-addons-for-contact-form-7 "
        "asset yield no request."
    ),
    sends=(
        "No request when the root response does not look like WordPress, or "
        "when crawled HTML already shows an "
        "ultimate-addons-for-contact-form-7 asset ?ver=. When WordPress is "
        "indicated and the plugin path is present without a version, one GET "
        "of /wp-content/plugins/ultimate-addons-for-contact-form-7/readme.txt. "
        "No request when the plugin is absent from crawled HTML."
    ),
    does_not_send=(
        "Never submits Contact Form 7 forms. Never calls "
        "/wp-json/contact-form-7/ or admin-ajax. Never requests generated "
        "PDFs. Never sends path strings or traversal payloads. No POSTs or "
        "form submissions, no uploads, no writes, and nothing to /wp-admin. "
        "Never more than the single readme GET."
    ),
    run=run,
)
