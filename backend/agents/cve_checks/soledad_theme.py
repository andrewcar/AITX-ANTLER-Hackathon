"""Soledad theme (CVE-2026-121684) — one style.css Version header read.

Soledad (ThemeForest, by PenciDesign) through 8.7.7 has an unauthenticated
local file inclusion that can lead to remote code execution through the
public load-more-posts handler. Fixed in 8.7.8, released 30 October 2026.
Wordfence, WPScan, and Patchstack agree: affected through 8.7.7 (WPScan
writes this as < 8.7.8), patched in 8.7.8, CVSS 8.1, CWE-74, unauthenticated.

The exploited label comes from Patchstack ("Known to be exploited"). The CVE
is not in the CISA Known Exploited Vulnerabilities catalog (catalog CSV
checked 23 November 2026; no Soledad row and no CVE-2026-121684).

PenciDesign changelog for 8.7.8 (30 October 2026): "Addressed identified
security issues across the theme and bundled plugins." The ThemeForest
changelog for the same release says "Addressed all identified security
issues."

Detection is one read-only GET of the public theme stylesheet and a parse of
its header ``Version:`` line. Likely vulnerable only when that header is the
Soledad theme and the version is through 8.7.7. A missing file, a non-Soledad
stylesheet, or an unparseable version is not a guess.

Never calls admin-ajax.php or the load-more-posts handler. No POST, no
payload, no SQL, no serialized string, no upload, no auth attempt, and no
write.

Sources:
- https://patchstack.com/database/wordpress/theme/soledad/vulnerability/wordpress-soledad-theme-8-7-7-unauthenticated-remote-code-execution-vulnerability
- https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-themes/soledad/soledad-multi-concept-blogmagazine-wordpress-theme-877-unauthenticated-remote-code-execution-via-penci-more-post-ajax-shortcode-allowlist-bypass-and-featured-sliders-local-file-inclusion
- https://wpscan.com/theme/soledad/
- https://www.pencidesign.net/changelog
- https://themeforest.net/item/soledad-multiconcept-blogmagazine-wp-theme/12945398
- https://musthaveplugins.com/blog/wordpress-vulnerability-report-2026-week-47/
- https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv
"""
import re

import recon

from .client import fetch_path
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, parse_dotted


STYLE = "/wp-content/themes/soledad/style.css"
_AFFECTED_THROUGH = (8, 7, 7)
_FIXED = (8, 7, 8)

_THEME_NAME = re.compile(r"(?im)^[ \t]*theme name:[ \t]*soledad[ \t]*$")
_AUTHOR = re.compile(r"(?im)^[ \t]*author:[ \t]*penci\s*design[ \t]*$")
_TEXT_DOMAIN = re.compile(r"(?im)^[ \t]*text domain:[ \t]*soledad[ \t]*$")
_VERSION = re.compile(
    r"(?im)^[ \t]*version:[ \t]*(\d+\.\d+(?:\.\d+)?)[ \t]*$"
)

_SOURCES = (
    "https://patchstack.com/database/wordpress/theme/soledad/vulnerability/"
    "wordpress-soledad-theme-8-7-7-unauthenticated-remote-code-execution-"
    "vulnerability",
    "https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-themes/"
    "soledad",
    "https://wpscan.com/theme/soledad/",
    "https://www.pencidesign.net/changelog",
    "https://themeforest.net/item/soledad-multiconcept-blogmagazine-wp-theme/"
    "12945398",
    "https://musthaveplugins.com/blog/wordpress-vulnerability-report-2026-week-47/",
    "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv",
)


def _fix() -> str:
    return (
        "Update the Soledad theme to 8.7.8 or later through the Envato licence "
        "or the Penci dashboard (it is not distributed on WordPress.org). "
        "Purge page, object, and CDN caches after updating. If the site ran "
        "8.7.7 or older, review administrator accounts and unexpected PHP "
        f"files in upload directories. See {CHECK.cve}."
    )


def _sources_note() -> str:
    return "Sources: " + "; ".join(_SOURCES) + "."


def header_block(body: str) -> str:
    """Theme header comment, or empty when the body is not a stylesheet header."""
    text = (body or "").lstrip("\ufeff").replace("\r\n", "\n").replace("\r", "\n")
    if recon.looks_like_app_html(text[:400]):
        return ""
    start = text.find("/*")
    if start < 0 or start > 64:
        return ""
    end = text.find("*/", start + 2)
    if end < 0:
        return ""
    return text[start:end]


def is_soledad_header(block: str) -> bool:
    """True when the header names the PenciDesign Soledad theme."""
    text = block or ""
    if not _THEME_NAME.search(text):
        return False
    return bool(_AUTHOR.search(text) or _TEXT_DOMAIN.search(text))


def style_version(block: str) -> tuple[int, ...] | None:
    """Exact ``Version:`` header, or None when it is missing or not dotted."""
    match = _VERSION.search(block or "")
    if not match:
        return None
    return parse_dotted(match.group(1))


def affected(version: tuple[int, ...]) -> bool:
    """True through 8.7.7 inclusive. 8.7.8 and later are patched."""
    return cmp_ver(version, _AFFECTED_THROUGH) <= 0


def _passive_note() -> str:
    return (
        f"Only a read-only GET of {STYLE} was sent, with no request body. "
        "admin-ajax.php and the load-more-posts handler were not called. "
        "No POST, payload, SQL, serialized string, upload, auth attempt, "
        "or write was sent."
    )


def _vulnerable(version: tuple[int, ...]) -> dict:
    label = fmt(version)
    return base_finding(
        CHECK,
        severity="high",
        title=(
            f"{UNCONFIRMED}: Soledad {label} <= {fmt(_AFFECTED_THROUGH)}, "
            f"likely vulnerable to {CHECK.cve}"
        ),
        evidence=(
            f"Observed Soledad {label} via GET {STYLE} Version header. "
            f"{UNCONFIRMED}. {label} is through {fmt(_AFFECTED_THROUGH)} and "
            f"is likely vulnerable to {CHECK.cve}: unauthenticated local file "
            "inclusion leading to remote code execution through the public "
            f"load-more-posts handler (CWE-74, CVSS 8.1). Fixed in {fmt(_FIXED)} "
            "(30 October 2026). The exploited label comes from Patchstack "
            "(Patchstack telemetry, not CISA KEV). This check does not confirm "
            f"that the handler is reachable. {_passive_note()} {_sources_note()}"
        ),
        fix=_fix(),
        match=f"soledad-theme:{label}",
    )


def _unknown() -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=f"Soledad theme detected; version unknown ({CHECK.cve})",
        evidence=(
            f"GET {STYLE} is a Soledad theme header, but it has no parseable "
            f"Version line. {CHECK.cve} was not compared (affected through "
            f"{fmt(_AFFECTED_THROUGH)}; fixed in {fmt(_FIXED)}). "
            f"{_passive_note()} {_sources_note()}"
        ),
        fix=_fix(),
        match="soledad-theme:unknown",
    )


def run(section, ctx) -> list[dict]:
    stylesheet = fetch_path(ctx, STYLE, max_bytes=16384)
    if stylesheet.get("status") != 200:
        return []
    block = header_block(stylesheet.get("body") or "")
    if not is_soledad_header(block):
        return []
    version = style_version(block)
    if version is None:
        return [_unknown()]
    if affected(version):
        return [_vulnerable(version)]
    return []


CHECK = CveCheck(
    id="soledad-theme",
    cve="CVE-2026-121684",
    agent="misconfig",
    fixed="8.7.8 (affected: Soledad through 8.7.7)",
    summary=(
        "One GET of /wp-content/themes/soledad/style.css. High, version "
        "unconfirmed / likely vulnerable, when the stylesheet header is "
        "Soledad and Version is through 8.7.7 (fixed in 8.7.8, 30 October "
        "2026; CWE-74, CVSS 8.1). Patchstack known-exploited (Patchstack "
        "telemetry, not CISA KEV). Info when the Soledad header is present "
        "but Version cannot be parsed. 8.7.8 and later, a missing file, and "
        "a body that is not the Soledad stylesheet are not detected."
    ),
    sends=f"One GET of {STYLE}. No request body.",
    does_not_send=(
        "Never calls admin-ajax.php or the load-more-posts handler. No POST, "
        "no exploit payload, no SQL, no serialized string, no file upload, "
        "no auth attempt, no write, and no malformed input. Exactly one GET "
        "of the static stylesheet."
    ),
    run=run,
)
