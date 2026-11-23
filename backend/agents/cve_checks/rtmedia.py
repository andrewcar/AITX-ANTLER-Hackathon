"""rtMedia (CVE-2026-128102) — one readme Stable tag read.

rtMedia for WordPress, BuddyPress and bbPress (WordPress.org slug
``buddypress-media``) through 4.7.17 has an unauthenticated SQL injection
through the ``custom_fields`` parameter. Fixed in 4.7.18 (changelog
16 November 2026: "Hardened the query filter that renames the meta_id column
for the media meta table"). 4.7.19 (19 November 2026) is current and also
includes that fix. Patchstack marks known-exploited (Patchstack telemetry,
not CISA KEV). Checked the CISA Known Exploited Vulnerabilities catalog on
23 November 2026; CVE-2026-128102 is not listed.

Sources:
- Patchstack (CVSS 9.3, <= 4.7.17, patched 4.7.18, published 19 Nov 2026,
  "Known to be exploited"):
  https://patchstack.com/database/wordpress/plugin/buddypress-media/vulnerability/wordpress-rtmedia-for-wordpress-buddypress-and-bbpress-plugin-4-7-17-unauthenticated-sql-injection-vulnerability
- Wordfence (CVE-2026-128102, CVSS 7.5, <= 4.7.17, patched 4.7.18,
  ``custom_fields`` parameter):
  https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/buddypress-media/rtmedia-for-wordpress-buddypress-and-bbpress-4717-unauthenticated-sql-injection-via-custom-fields-parameter
- WPScan (< 4.7.18, fixed in 4.7.18, CVSS 7.5, published 19 Nov 2026):
  https://wpscan.com/plugin/buddypress-media/
- Plugin changelog, Stable tag 4.7.19:
  https://plugins.svn.wordpress.org/buddypress-media/trunk/readme.txt
  https://github.com/rtCamp/rtMedia
- Week 47 report (Patchstack exploited label; fixed 4.7.18, current 4.7.19):
  https://musthaveplugins.com/blog/wordpress-vulnerability-report-2026-week-47/
- CISA KEV catalog (CVE-2026-128102 absent):
  https://www.cisa.gov/known-exploited-vulnerabilities-catalog

Detection is one read-only GET of the public plugin readme. Critical when
that file is the rtMedia readme and the Stable tag is 4.7.17 or lower. Info
when the readme is the plugin but the tag cannot be parsed. Anything else
(missing file, HTML soft-404, another plugin) is not detected. A version hit
is a fingerprint only.

Never sends the ``custom_fields`` parameter or any SQL. No POST, upload,
auth attempt, write, or malformed input.
"""
import re

import recon

from .client import fetch_path
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, parse_dotted


README = "/wp-content/plugins/buddypress-media/readme.txt"
_AFFECTED_THROUGH = (4, 7, 17)

_STABLE = re.compile(r"(?im)^[ \t]*stable tag:[ \t]*(\d+(?:\.\d+){0,3})[ \t]*$")
_HEADER = re.compile(r"(?im)^===\s*.*\brtmedia\b.*===\s*$")
_README_FIELDS = ("stable tag:", "contributors:", "requires at least:")


def _fix() -> str:
    return (
        "Update rtMedia for WordPress, BuddyPress and bbPress "
        "(buddypress-media) to 4.7.18 or later. 4.7.19 is current. "
        "Plugins screen or `wp plugin update buddypress-media`. "
        f"See {CHECK.cve}."
    )


def stable_tag(body: str) -> tuple[int, ...] | None:
    match = _STABLE.search(body or "")
    if not match:
        return None
    return parse_dotted(match.group(1))


def is_plugin_readme(body: str) -> bool:
    """True when the body is an rtMedia readme, not an HTML page."""
    text = body or ""
    if recon.looks_like_app_html(text[:400]):
        return False
    if not _HEADER.search(text):
        return False
    low = text.lower()
    return any(field in low for field in _README_FIELDS)


def affected(version: tuple[int, ...]) -> bool:
    """True for versions through 4.7.17 inclusive. 4.7.18+ is patched."""
    return cmp_ver(version, _AFFECTED_THROUGH) <= 0


def _passive_note() -> str:
    return (
        "Only a read-only GET of the public plugin readme.txt was sent. "
        "The custom_fields parameter was not sent, and no SQL, POST, upload, "
        "auth attempt, write, or malformed input was sent."
    )


def _critical(version: tuple[int, ...]) -> dict:
    label = fmt(version)
    return base_finding(
        CHECK,
        severity="critical",
        title=f"{UNCONFIRMED}: rtMedia {label} ({CHECK.cve})",
        evidence=(
            f"GET {README} Stable tag is {label}. {UNCONFIRMED}. "
            f"Affected: rtMedia through 4.7.17. Fixed in 4.7.18 "
            "(changelog 16 November 2026). 4.7.19 is current. "
            f"{CHECK.cve}: unauthenticated SQL injection through the "
            "custom_fields parameter. Patchstack CVSS 9.3 and known-exploited "
            "(Patchstack telemetry, not CISA KEV). Wordfence and WPScan "
            f"CVSS 7.5. {_passive_note()}"
        ),
        fix=_fix(),
        match=f"rtmedia:{label}",
    )


def _info() -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=f"rtMedia detected; version not exposed ({CHECK.cve})",
        evidence=(
            f"GET {README} is an rtMedia readme, but it has no parseable "
            f"Stable tag. {CHECK.cve} cannot be compared (affected through "
            f"4.7.17; fixed in 4.7.18). {_passive_note()}"
        ),
        fix=_fix(),
        match="rtmedia:unknown",
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
    id="rtmedia",
    cve="CVE-2026-128102",
    # Closest registry agent: InjectionAgent owns active SQL probes and is
    # not one of CveCheck.AGENTS (misconfig/recon/auth/secrets). This check is
    # a passive version fingerprint only, same pattern as wpForo and Estatik.
    agent="misconfig",
    fixed="4.7.18+ (affected: rtMedia through 4.7.17; current 4.7.19)",
    summary=(
        "One GET of the rtMedia (buddypress-media) readme. Critical when that "
        "file is the rtMedia readme and the Stable tag is 4.7.17 or lower "
        "(fixed in 4.7.18; 4.7.19 is current). Info when the readme is rtMedia "
        "but the Stable tag cannot be parsed. Missing or non-plugin bodies "
        "are not detected. A version match is unconfirmed."
    ),
    sends=f"One GET of {README}.",
    does_not_send=(
        "Never sends the custom_fields parameter or any SQL. No POST, no "
        "upload endpoint, no file upload, no auth attempt, no write, and no "
        "malformed input. Exactly one read-only GET of the plugin readme."
    ),
    run=run,
)
