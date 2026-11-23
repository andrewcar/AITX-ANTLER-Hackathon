"""Simple Shopping Cart (CVE-2026-131782) — one readme Stable tag read.

WordPress.org slug ``wordpress-simple-paypal-shopping-cart`` (product name
Simple Shopping Cart; also marketed as WordPress Simple PayPal Shopping
Cart). Through 5.3.3 the plugin has an unauthenticated PHP object injection
(CWE-502, Patchstack CVSS 9.8) in saved cart data that is unserialized
without a class allow-list. Fixed in 5.3.4 (20 November 2026). The 5.3.4
changelog says saved cart data can no longer be changed to load other PHP
classes, and credits Patchstack. Code execution still needs a gadget chain
outside this plugin, which this check does not confirm.

The affected range is Patchstack and the CVE CNA text: "from n/a through
5.3.3", patched in 5.3.4. WPSec WPSEC-2026-3628 describes the same ceiling
("all versions up to, and including, 5.3.3") and also lists a lower bound of
5.0.3; this check follows the CNA range and does not apply that floor.
Patchstack's page labels the issue "Known to be exploited". That label is
Patchstack's, not CISA's. CVE-2026-131782 is not in the CISA Known Exploited
Vulnerabilities catalog (the catalog CSV on cisa.gov was checked on
23 November 2026 and does not contain this CVE). No Wordfence or WPScan
entry for CVE-2026-131782 was found on that date.

Detection is passive only: one GET of the plugin ``readme.txt``. A parsed
Stable tag at or below 5.3.3 is reported as a version fingerprint
("version appears vulnerable (unconfirmed)"). Anything else — missing file,
non-readme body, or no parseable Stable tag — is not-detected or unknown.
No version is inferred.

Sources:
- Patchstack (CNA): https://patchstack.com/database/wordpress/plugin/wordpress-simple-paypal-shopping-cart/vulnerability/wordpress-simple-shopping-cart-plugin-5-3-3-php-object-injection-vulnerability
- Plugin changelog 5.3.4: https://wordpress.org/plugins/wordpress-simple-paypal-shopping-cart/
  and https://plugins.svn.wordpress.org/wordpress-simple-paypal-shopping-cart/trunk/readme.txt
- musthaveplugins week 47: https://musthaveplugins.com/blog/wordpress-vulnerability-report-2026-week-47/
- WPSec: https://wpsec.com/vuln/WPSEC-2026-3628/
- CISA KEV CSV (absence): https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv

Never adds to the cart, sets a cart cookie, or sends serialized data. No
POST, SQL, upload, auth attempt, write, or malformed input.
"""
import re

import recon

from .client import fetch_path
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, parse_dotted


README = "/wp-content/plugins/wordpress-simple-paypal-shopping-cart/readme.txt"
_AFFECTED_THROUGH = (5, 3, 3)
_FIXED = (5, 3, 4)

_STABLE = re.compile(r"(?im)^[ \t]*stable tag:[ \t]*(\d+(?:\.\d+){0,3})[ \t]*$")
_HEADER = re.compile(r"(?im)^===\s*simple shopping cart\s*===\s*$")
_README_FIELDS = ("stable tag:", "contributors:", "requires at least:")


def _fix() -> str:
    return (
        "Update Simple Shopping Cart (wordpress-simple-paypal-shopping-cart) "
        "to 5.3.4 or later (Plugins screen or "
        "`wp plugin update wordpress-simple-paypal-shopping-cart`). Purge "
        "page, object, and CDN caches after updating. Review the site for "
        f"unexpected files or accounts if compromise is suspected. See {CHECK.cve}."
    )


def stable_tag(body: str) -> tuple[int, ...] | None:
    match = _STABLE.search(body or "")
    if not match:
        return None
    return parse_dotted(match.group(1))


def is_plugin_readme(body: str) -> bool:
    """True when the body is this plugin's readme, not an HTML page."""
    text = body or ""
    if recon.looks_like_app_html(text[:400]):
        return False
    if not _HEADER.search(text):
        return False
    low = text.lower()
    return any(field in low for field in _README_FIELDS)


def affected(version: tuple[int, ...]) -> bool:
    """True through 5.3.3 inclusive. 5.3.4 and later are patched."""
    return cmp_ver(version, _AFFECTED_THROUGH) <= 0 and cmp_ver(version, _FIXED) < 0


def _passive_note() -> str:
    return (
        "Only a read-only GET of the public plugin readme was sent. Nothing "
        "was added to a cart, no cart cookie was set, and no serialized data "
        "was sent."
    )


def _critical(version: tuple[int, ...]) -> dict:
    label = fmt(version)
    return base_finding(
        CHECK,
        severity="critical",
        title=f"{UNCONFIRMED}: Simple Shopping Cart {label} ({CHECK.cve})",
        evidence=(
            f"GET {README} Stable tag is {label}. {UNCONFIRMED}. "
            f"Affected: Simple Shopping Cart through 5.3.3. Fixed in 5.3.4 "
            "(20 November 2026). "
            f"{CHECK.cve}: unauthenticated PHP object injection through saved "
            "cart data (Patchstack CVSS 9.8, CWE-502). Patchstack marks this "
            "known-exploited (Patchstack telemetry, not CISA KEV). Code "
            "execution requires a gadget chain outside the plugin, which this "
            f"check does not confirm. {_passive_note()}"
        ),
        fix=_fix(),
        match=f"simple-shopping-cart:{label}",
    )


def _info() -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=(
            "Simple Shopping Cart detected; version not exposed "
            f"({CHECK.cve})"
        ),
        evidence=(
            f"GET {README} is a Simple Shopping Cart readme, but it has no "
            f"parseable Stable tag. {CHECK.cve} cannot be compared (affected "
            f"through 5.3.3; fixed in 5.3.4). The version is unknown. {_passive_note()}"
        ),
        fix=_fix(),
        match="simple-shopping-cart:unknown",
    )


def run(section, ctx) -> list[dict]:
    readme = fetch_path(ctx, README, max_bytes=65536)
    if readme.get("status") != 200:
        return []
    body = readme.get("body") or ""
    if not is_plugin_readme(body):
        return []
    version = stable_tag(body)
    if version is None:
        return [_info()]
    if affected(version):
        return [_critical(version)]
    return []


CHECK = CveCheck(
    id="simple-shopping-cart",
    cve="CVE-2026-131782",
    # Closest registry agent: Injection/Deserialization is not one of
    # CveCheck.AGENTS. Same mapping as Gravity Forms and Estatik
    # (InjectionAgent family → misconfig fingerprint). Passive version only.
    agent="misconfig",
    fixed="5.3.4 (affected: through 5.3.3)",
    summary=(
        "One GET of the Simple Shopping Cart readme. Critical, version "
        "unconfirmed, when that file is the plugin readme and the Stable tag "
        "is 5.3.3 or lower (fixed in 5.3.4). Info when the readme is the "
        "plugin but the Stable tag cannot be parsed. A missing or non-plugin "
        "body is not detected. No version is guessed."
    ),
    sends=f"One GET of {README}.",
    does_not_send=(
        "Never adds to the cart, sets a cart cookie, or sends serialized "
        "data. No POST, SQL, file upload, auth attempt, write, or malformed "
        "input. No request other than the single readme.txt GET."
    ),
    run=run,
)
