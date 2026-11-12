"""Registration Form for WooCommerce (CVE-2026-119075) — one readme version read.

GET the public plugin readme. Critical when that file is the ThemeGrill
Registration Form for WooCommerce readme and the observed version (Stable tag,
or else the top Changelog heading) is 1.1.4 or lower. Fixed in 1.1.5. A missing
or unparseable readme is not detected and is never treated as vulnerable. A
version hit is a fingerprint only; the published readme can lag installed code.
"""
import re

import recon

from .client import fetch_path
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, parse_dotted


README = "/wp-content/plugins/registration-form-for-woocommerce/readme.txt"
_STABLE = re.compile(r"(?im)^[ \t]*stable tag:[ \t]*(\d+(?:\.\d+){0,3})[ \t]*$")
_HEADER = re.compile(
    r"(?im)^===\s*.*\bregistration form for woocommerce\b.*===\s*$"
)
_CHANGELOG_HEAD = re.compile(
    r"(?im)^=\s*(\d+(?:\.\d+){0,3})\s*(?:-\s*[^=]*)?=$"
)
_README_FIELDS = ("stable tag:", "contributors:", "requires at least:")
_AFFECTED_THROUGH = (1, 1, 4)

FIX = (
    "Upgrade Registration Form for WooCommerce "
    "(registration-form-for-woocommerce) to 1.1.5 or later. "
    "Review WordPress administrator accounts created around the time this "
    "plugin was exposed and remove any unexpected admins. See CVE-2026-119075."
)


def stable_tag(body: str) -> tuple[int, ...] | None:
    match = _STABLE.search(body or "")
    if not match:
        return None
    return parse_dotted(match.group(1))


def changelog_version(body: str) -> tuple[int, ...] | None:
    """First dotted version heading under ``== Changelog ==``, if present."""
    text = body or ""
    low = text.lower()
    marker = low.find("== changelog ==")
    if marker < 0:
        return None
    section = text[marker:]
    match = _CHANGELOG_HEAD.search(section)
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


def observed_version(body: str) -> tuple[tuple[int, ...] | None, str]:
    """Prefer Stable tag; fall back to the top Changelog heading."""
    stable = stable_tag(body)
    if stable is not None:
        return stable, "Stable tag"
    changelog = changelog_version(body)
    if changelog is not None:
        return changelog, "Changelog"
    return None, ""


def vulnerable(version: tuple[int, ...]) -> bool:
    return cmp_ver(version, _AFFECTED_THROUGH) <= 0


def _critical(version: tuple[int, ...], where: str) -> dict:
    label = fmt(version)
    return base_finding(
        CHECK,
        severity="critical",
        title=f"{UNCONFIRMED}: Registration Form for WooCommerce {label} ({CHECK.cve})",
        evidence=(
            f"GET {README} {where} is {label}. {UNCONFIRMED}. "
            f"Advisory: {CHECK.cve} (CVSS 9.8). Versions 1.1.4 and lower are "
            "in range; 1.1.5 is fixed. The public readme can lag the code "
            "installed on disk. No exploit payload was sent."
        ),
        fix=FIX,
        match=f"registration-form-woocommerce:{label}",
    )


def run(section, ctx) -> list[dict]:
    readme = fetch_path(ctx, README, max_bytes=65536)
    if readme.get("status") != 200:
        return []
    body = readme.get("body") or ""
    if not is_plugin_readme(body):
        return []
    version, where = observed_version(body)
    if version is None or not vulnerable(version):
        return []
    return [_critical(version, where)]


CHECK = CveCheck(
    id="registration-form-woocommerce",
    cve="CVE-2026-119075",
    agent="recon",
    fixed="1.1.5 (affected: through 1.1.4)",
    summary=(
        "GET the Registration Form for WooCommerce readme and flag Critical "
        "when the Stable tag (or else the top Changelog version) is 1.1.4 or "
        "lower. Missing or unparseable readmes are not detected. A version "
        "match is unconfirmed; the readme can lag installed code."
    ),
    sends=f"One GET of {README}.",
    does_not_send=(
        "No checkout or registration POST, no user_roles or "
        "tgwcfb/user-roles parameters, no account creation, no form "
        "submission, no write, no upload, no malformed input, and no "
        "exploit payload."
    ),
    run=run,
)
