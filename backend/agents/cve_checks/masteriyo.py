"""Masteriyo LMS (CVE-2026-73996) — one readme Stable tag read.

GET the public plugin readme. Critical when that file is the Masteriyo LMS
readme and the Stable tag is 2.3.2 or lower. Info when the readme is the
plugin but the tag cannot be parsed. A version hit is a fingerprint only.
"""
import re

import recon

from .client import fetch_path
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, parse_dotted


README = "/wp-content/plugins/learning-management-system/readme.txt"
_STABLE = re.compile(r"(?im)^[ \t]*stable tag:[ \t]*(\d+(?:\.\d+){0,3})[ \t]*$")
_HEADER = re.compile(r"(?im)^===\s*.*\bmasteriyo\b.*===\s*$")
_AFFECTED_THROUGH = (2, 3, 2)
_README_FIELDS = ("stable tag:", "contributors:", "requires at least:")


def stable_tag(body: str) -> tuple[int, ...] | None:
    match = _STABLE.search(body or "")
    if not match:
        return None
    return parse_dotted(match.group(1))


def is_plugin_readme(body: str) -> bool:
    """True when the body is a Masteriyo LMS readme, not an HTML page."""
    text = body or ""
    if recon.looks_like_app_html(text[:400]):
        return False
    if not _HEADER.search(text):
        return False
    low = text.lower()
    return any(field in low for field in _README_FIELDS)


def vulnerable(version: tuple[int, ...]) -> bool:
    return cmp_ver(version, _AFFECTED_THROUGH) <= 0


def _critical(version: tuple[int, ...]) -> dict:
    label = fmt(version)
    return base_finding(
        CHECK,
        severity="critical",
        title=f"{UNCONFIRMED}: Masteriyo LMS {label} ({CHECK.cve})",
        evidence=(
            f"GET {README} Stable tag is {label}. {UNCONFIRMED}. "
            f"Advisory: {CHECK.cve}. Tags 2.3.2 and lower are in range. "
            "Fixed in 2.3.3. No exploit payload was sent."
        ),
        fix=(
            "Upgrade the Masteriyo LMS plugin (learning-management-system) "
            f"to 2.3.3 or later. See {CHECK.cve}."
        ),
        match=f"masteriyo:{label}",
    )


def _info() -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=f"Masteriyo LMS detected; version not exposed ({CHECK.cve})",
        evidence=(
            f"GET {README} is a Masteriyo LMS readme, but it has no parseable "
            f"Stable tag. {CHECK.cve} cannot be compared. No exploit payload was sent."
        ),
        fix=(
            "Upgrade the Masteriyo LMS plugin to 2.3.3 or later when the "
            f"installed release is 2.3.2 or older. See {CHECK.cve}."
        ),
        match="masteriyo:unknown",
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
    if vulnerable(version):
        return [_critical(version)]
    return []


CHECK = CveCheck(
    id="masteriyo-lms",
    cve="CVE-2026-73996",
    agent="recon",
    fixed="2.3.3 (affected: through 2.3.2)",
    summary=(
        "GET the Masteriyo LMS readme and flag Critical when the Stable tag is "
        "2.3.2 or lower. Info when that readme is present but the Stable tag "
        "cannot be parsed. A version match is unconfirmed."
    ),
    sends=f"One GET of {README}.",
    does_not_send=(
        "No upload, no POST, PUT, or DELETE, no login, no PHP body, "
        "no path traversal, and no request to a plugin upload route."
    ),
    run=run,
)
