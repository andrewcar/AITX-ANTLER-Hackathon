"""Dokan (CVE-2026-119220) — one readme Stable tag or changelog read.

Dokan: AI Powered WooCommerce Multivendor Marketplace Solution (WordPress.org
slug ``dokan-lite``) 5.0.15 through 5.3.3 lets an unauthenticated visitor read
paid-download links and other private product fields through the WooCommerce
product API. A check meant for Dokan's AI integration matched its marker too
broadly, so the product API answered as if the caller could edit products.
No AI or MCP setting has to be enabled. Fixed in 5.3.4 (5 November 2026).
5.3.5 (19 November 2026) is the recommended update: it also fixes
CVE-2026-131784 (broken access control, vendor) and CVE-2026-131792 (XSS).

Wordfence and Patchstack publish the range as <= 5.3.3, patched in 5.3.4
(CVSS 7.5, unauthenticated, CWE broken access control). The integration that
contains the over-broad marker was added in 5.0.15 (changelog 19 August 2026:
WooCommerce Abilities / MCP support). This check flags only 5.0.15–5.3.3.
Releases before 5.0.15 are not flagged. Patchstack labels CVE-2026-119220
known-exploited (Patchstack telemetry). It is not in the CISA Known Exploited
Vulnerabilities catalog (checked the CISA KEV JSON feed and CSV on
23 November 2026; no CVE-2026-119220 entry).

Sources:
- https://patchstack.com/database/wordpress/plugin/dokan-lite/vulnerability/wordpress-dokan-ai-powered-woocommerce-multivendor-marketplace-solution-build-your-own-amazon-ebay-etsy-plugin-5-3-3-authorization-bypass-vulnerability
- https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/dokan-lite/dokan-ai-powered-woocommerce-multivendor-marketplace-solution-533-authorization-bypass-via-dokanmcp-marker-in-request-uri
- https://musthaveplugins.com/blog/wordpress-vulnerability-report-2026-week-47/
- https://wordpress.org/plugins/dokan-lite/ (Stable tag 5.3.5; changelog)
- https://plugins.trac.wordpress.org/browser/dokan-lite/trunk/readme.txt
- https://patchstack.com/database/wordpress/plugin/dokan-lite/vulnerability/wordpress-dokan-plugin-5-3-4-broken-access-control-vulnerability
  (CVE-2026-131784, fixed in 5.3.5)
- https://patchstack.com/database/wordpress/plugin/dokan-lite/vulnerability/wordpress-dokan-plugin-5-3-4-cross-site-scripting-xss-vulnerability
  (CVE-2026-131792, fixed in 5.3.5)
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  (CVE-2026-119220 absent)
- GHSA-fr8v-22hh-89vj

Detection is one read-only GET of
``/wp-content/plugins/dokan-lite/readme.txt``. The Stable tag is preferred;
the newest changelog heading is used only when that tag is missing. A version
hit is a fingerprint only.

Never requests WooCommerce product API routes, never sends a marker, query
string, POST, login, upload, or write.
"""
import re

import recon

from .client import fetch_path
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, parse_dotted


README = "/wp-content/plugins/dokan-lite/readme.txt"
_INTRODUCED = (5, 0, 15)
_AFFECTED_THROUGH = (5, 3, 3)
_FIXED = (5, 3, 4)
_RECOMMENDED = (5, 3, 5)

_SOURCES = (
    "https://patchstack.com/database/wordpress/plugin/dokan-lite/vulnerability/"
    "wordpress-dokan-ai-powered-woocommerce-multivendor-marketplace-solution-"
    "build-your-own-amazon-ebay-etsy-plugin-5-3-3-authorization-bypass-"
    "vulnerability",
    "https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/"
    "dokan-lite/dokan-ai-powered-woocommerce-multivendor-marketplace-solution-"
    "533-authorization-bypass-via-dokanmcp-marker-in-request-uri",
    "https://musthaveplugins.com/blog/wordpress-vulnerability-report-2026-week-47/",
    "https://wordpress.org/plugins/dokan-lite/",
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
)

_STABLE = re.compile(r"(?im)^[ \t]*stable tag:[ \t]*(\d+(?:\.\d+){0,3})[ \t]*$")
_HEADER = re.compile(r"(?im)^===\s*.*\bdokan\b.*===\s*$")
_README_FIELDS = ("stable tag:", "contributors:", "requires at least:")
_CHANGELOG_HEAD = re.compile(r"(?im)^==[ \t]*changelog[ \t]*==[ \t]*$")
# WordPress.org readme headings look like "= v5.3.5 ( Nov 19, 2026 ) =".
_CHANGELOG_VER = re.compile(
    r"(?im)^=[ \t]*v?(\d+(?:\.\d+){1,3})\b[^\n]*=[ \t]*$"
)


def _fix() -> str:
    return (
        "Update Dokan (dokan-lite) to 5.3.5 or later (Plugins screen or "
        "`wp plugin update dokan-lite`). 5.3.4 fixes CVE-2026-119220; 5.3.5 "
        "(19 November 2026) is recommended because it also fixes "
        "CVE-2026-131784 and CVE-2026-131792. Purge page, object, and CDN "
        "caches after updating. Treat paid download links that may have been "
        f"read as public and replace the ones that matter. See {CHECK.cve}."
    )


def _sources_note() -> str:
    return "Sources: " + "; ".join(_SOURCES) + "."


def _passive_note() -> str:
    return (
        "Only a read-only GET of the public plugin readme.txt was sent. "
        "No WooCommerce product API request, marker, query string, POST, "
        "login, upload, or write was sent."
    )


def stable_tag(body: str) -> tuple[int, ...] | None:
    match = _STABLE.search(body or "")
    return parse_dotted(match.group(1)) if match else None


def changelog_version(body: str) -> tuple[int, ...] | None:
    """Newest dotted version heading under ``== Changelog ==``, if present."""
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
    """True when the body is a Dokan plugin readme, not an HTML soft-404."""
    text = body or ""
    if recon.looks_like_app_html(text[:400]):
        return False
    if not _HEADER.search(text):
        return False
    low = text.lower()
    if "dokan" not in low:
        return False
    if any(field in low for field in _README_FIELDS):
        return True
    return _CHANGELOG_HEAD.search(text) is not None


def affected(version: tuple[int, ...]) -> bool:
    """True for 5.0.15 through 5.3.3 inclusive. 5.3.4+ is patched."""
    return (
        cmp_ver(version, _INTRODUCED) >= 0
        and cmp_ver(version, _AFFECTED_THROUGH) <= 0
    )


def _vulnerable(version: tuple[int, ...], where: str) -> dict:
    label = fmt(version)
    return base_finding(
        CHECK,
        severity="high",
        title=f"{UNCONFIRMED}: Dokan {label} ({CHECK.cve})",
        evidence=(
            f"GET {README} {where} is {label}. {UNCONFIRMED}. "
            "Affected: Dokan (dokan-lite) 5.0.15 through 5.3.3. Fixed in "
            f"{fmt(_FIXED)} (5 November 2026). {fmt(_RECOMMENDED)} "
            "(19 November 2026) is recommended because it also fixes "
            "CVE-2026-131784 and CVE-2026-131792. "
            f"{CHECK.cve}: unauthenticated read of paid download links and "
            "other private product fields through the WooCommerce product "
            "API, because an AI-integration marker match was over-broad "
            "(CVSS 7.5). The integration arrived in 5.0.15; no AI setting "
            "has to be enabled. Patchstack marks this known-exploited "
            "(Patchstack telemetry, not CISA KEV). "
            f"{_passive_note()} {_sources_note()}"
        ),
        fix=_fix(),
        match=f"dokan:{label}",
    )


def _unknown() -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=f"Dokan detected; version unknown ({CHECK.cve})",
        evidence=(
            f"GET {README} is a Dokan readme, but neither the Stable tag nor "
            f"a changelog version could be parsed. {CHECK.cve} cannot be "
            "compared (affected 5.0.15 through 5.3.3; fixed in 5.3.4; 5.3.5 "
            "recommended). This is not a vulnerability guess. "
            f"{_passive_note()} {_sources_note()}"
        ),
        fix=_fix(),
        match="dokan:unknown",
    )


def run(section, ctx) -> list[dict]:
    readme = fetch_path(ctx, README, max_bytes=65536)
    if readme.get("status") != 200:
        return []
    body = readme.get("body") or ""
    if not is_plugin_readme(body):
        return []
    version, where = plugin_version(body)
    if version is None:
        return [_unknown()]
    if affected(version):
        return [_vulnerable(version, where)]
    return []


CHECK = CveCheck(
    id="dokan",
    cve="CVE-2026-119220",
    # Auth slot: unauthenticated broken access control on product reads.
    agent="auth",
    fixed=(
        "5.3.4 fixes CVE-2026-119220; 5.3.5 recommended "
        "(affected: Dokan 5.0.15 through 5.3.3)"
    ),
    summary=(
        "One GET of the Dokan (dokan-lite) readme. High, version unconfirmed, "
        "when the Stable tag or, if that tag is missing, the newest changelog "
        "heading is 5.0.15 through 5.3.3 (fixed in 5.3.4; 5.3.5 recommended). "
        "Info (version unknown) when the readme is Dokan but no version can "
        "be parsed. A missing readme, a non-plugin body, or a version outside "
        "5.0.15–5.3.3 yields no finding."
    ),
    sends=f"One GET of {README}.",
    does_not_send=(
        "Never requests WooCommerce product API routes under /wp-json/wc/ "
        "(including /wc/v1, /wc/v2, /wc/v3, and /wc-analytics). No query "
        "string, no AI-integration marker, no POST, no login or auth "
        "attempt, no upload, no write, no SQL, no serialized string, and "
        "no malformed input. Never more than the single readme GET."
    ),
    run=run,
)
