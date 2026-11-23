"""Tribulant Newsletters (CVE-2026-111402) — one readme Stable tag read.

WordPress.org slug ``newsletters-lite`` (plugin header ``=== Newsletters ===``,
contributor ``contrid``, Tribulant Software). Confirmed on the public readme
(Stable tag 4.18.3) and on the Patchstack / Wordfence entries below.

CVE-2026-111402 is an unauthenticated SQL injection in every release through
4.18.1, patched in 4.18.2 (CWE-89). Patchstack scores it 9.3 and marks it
"Known to be exploited". That exploited label is Patchstack's, not CISA KEV:
CVE-2026-111402 is absent from the CISA Known Exploited Vulnerabilities catalog
CSV (https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv,
read 23 November 2026). Wordfence records the same range and the same 4.18.2
fix (Wordfence CVSS 7.5). The 4.18.2 changelog (21 October 2026) records the
unauthenticated subscriber-profile SQL injection fix. Patchstack and Wordfence
credit Noverdi Anugrah Ramadhan; the changelog credits zickzick2 (Sejong
University) for that subscriber-profile fix. Both descriptions are closed by
4.18.2.

4.18.2 is not the version to stop on. Two later unauthenticated issues, both
published by Patchstack on 18 November 2026, affect every release through
4.18.2 and are patched in 4.18.3 (released 10 November 2026):

* CVE-2026-129039 — unauthenticated PHP object injection, CVSS 9.8 (CWE-502).
  Patchstack, the NVD / GitHub advisory (PR:N), and WPSec. The 4.18.3
  changelog describes the Date-field object-injection fix as authenticated and
  does not print this CVE id.
* CVE-2026-129043 — unauthenticated SQL injection, CVSS 9.3 (CWE-89).
  Patchstack, NVD (PR:N), and WPSec. The 4.18.3 changelog does not print this
  CVE id; it records a separate authenticated ``instance[lists]`` SQL injection
  as CVE-2026-119064 and an authenticated profile-email SQL injection as
  CVE-2026-122063.

Neither follow-on carried Patchstack's exploited marker on 23 November 2026,
and neither is on CISA KEV. A parsed 4.18.2 is reported as "update to 4.18.3".
Versions through 4.18.1 are "likely vulnerable" to CVE-2026-111402 and are
told to update to 4.18.3 rather than stop at 4.18.2. 4.18.3 and later are
not flagged. A missing or unparseable version is unknown, never a guess.

Detection is one read-only GET of
``/wp-content/plugins/newsletters-lite/readme.txt`` with no query string.
``fetch_path`` is the only request, so the domain allowlist, global rate
limit, kill switch, and audit log still apply.

Sources:
https://patchstack.com/database/wordpress/plugin/newsletters-lite/vulnerability/wordpress-newsletters-plugin-4-18-1-sql-injection-vulnerability
https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/newsletters-lite/newsletters-4181-unauthenticated-sql-injection
https://tribulant.com/docs/wordpress-mailing-list-plugin/77983/newsletters-4-18-2-release-notes/
https://plugins.svn.wordpress.org/newsletters-lite/trunk/readme.txt
https://wordpress.org/plugins/newsletters-lite/
https://patchstack.com/database/wordpress/plugin/newsletters-lite/vulnerability/wordpress-newsletters-plugin-4-18-2-php-object-injection-vulnerability-2
https://nvd.nist.gov/vuln/detail/CVE-2026-129039
https://patchstack.com/database/wordpress/plugin/newsletters-lite/vulnerability/wordpress-newsletters-plugin-4-18-2-sql-injection-vulnerability
https://nvd.nist.gov/vuln/detail/CVE-2026-129043
https://tribulant.com/docs/wordpress-mailing-list-plugin/78125/newsletters-4-18-3-release-notes/
https://wpserverguard.com/blog/exploited-wordpress-plugins-november-2026/
https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv
"""
import re

import recon

from .client import fetch_path
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, parse_dotted


README = "/wp-content/plugins/newsletters-lite/readme.txt"
_SQLI_THROUGH = (4, 18, 1)
_FOLLOWON_THROUGH = (4, 18, 2)
_FIXED = (4, 18, 3)

_SOURCES = (
    "https://patchstack.com/database/wordpress/plugin/newsletters-lite/"
    "vulnerability/wordpress-newsletters-plugin-4-18-1-sql-injection-"
    "vulnerability",
    "https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/"
    "newsletters-lite/newsletters-4181-unauthenticated-sql-injection",
    "https://tribulant.com/docs/wordpress-mailing-list-plugin/77983/"
    "newsletters-4-18-2-release-notes/",
    "https://plugins.svn.wordpress.org/newsletters-lite/trunk/readme.txt",
    "https://patchstack.com/database/wordpress/plugin/newsletters-lite/"
    "vulnerability/wordpress-newsletters-plugin-4-18-2-php-object-injection-"
    "vulnerability-2",
    "https://patchstack.com/database/wordpress/plugin/newsletters-lite/"
    "vulnerability/wordpress-newsletters-plugin-4-18-2-sql-injection-"
    "vulnerability",
    "https://tribulant.com/docs/wordpress-mailing-list-plugin/78125/"
    "newsletters-4-18-3-release-notes/",
    "https://wpserverguard.com/blog/exploited-wordpress-plugins-november-2026/",
)

_STABLE = re.compile(r"(?im)^[ \t]*stable tag:[ \t]*(\d+(?:\.\d+){0,3})[ \t]*$")
_HEADER = re.compile(r"(?im)^===\s*.*\bnewsletters\b.*===\s*$")
_README_FIELDS = ("stable tag:", "contributors:", "requires at least:")
_NAME_MARKERS = ("tribulant", "contrid", "newsletters-lite")


def _fix() -> str:
    return (
        "Update Tribulant Newsletters (newsletters-lite) to 4.18.3 or later "
        "(Plugins screen or `wp plugin update newsletters-lite`). 4.18.2 "
        "fixes CVE-2026-111402 and is not enough: update to 4.18.3. "
        f"See {CHECK.cve}, CVE-2026-129039, and CVE-2026-129043."
    )


def _sources_note() -> str:
    return "Sources: " + "; ".join(_SOURCES) + "."


def _passive_note() -> str:
    return (
        "Only one read-only GET of the public plugin readme.txt was sent, "
        "with no query string and no request body. No plugin endpoint, POST, "
        "upload, authentication attempt, or write was sent."
    )


def stable_tag(body: str) -> tuple[int, ...] | None:
    match = _STABLE.search(body or "")
    return parse_dotted(match.group(1)) if match else None


def is_plugin_readme(body: str) -> bool:
    """True when the body is the Tribulant Newsletters readme, not an HTML page."""
    text = body or ""
    if recon.looks_like_app_html(text[:400]):
        return False
    if not _HEADER.search(text):
        return False
    low = text.lower()
    if not any(marker in low for marker in _NAME_MARKERS):
        return False
    return any(field in low for field in _README_FIELDS)


def sqli_affected(version: tuple[int, ...]) -> bool:
    """True through 4.18.1 inclusive (CVE-2026-111402)."""
    return cmp_ver(version, _SQLI_THROUGH) <= 0


def followon_affected(version: tuple[int, ...]) -> bool:
    """True for 4.18.2, which is past CVE-2026-111402 and still inside the later ranges."""
    return (
        cmp_ver(version, _SQLI_THROUGH) > 0
        and cmp_ver(version, _FOLLOWON_THROUGH) <= 0
    )


def _vulnerable(version: tuple[int, ...]) -> dict:
    label = fmt(version)
    return base_finding(
        CHECK,
        severity="critical",
        title=(
            f"{UNCONFIRMED}: Newsletters {label} likely vulnerable "
            f"({CHECK.cve}); update to 4.18.3"
        ),
        evidence=(
            f"GET {README} Stable tag is {label}. {UNCONFIRMED}. "
            f"Likely vulnerable: Newsletters (newsletters-lite) through 4.18.1. "
            f"{CHECK.cve}: unauthenticated SQL injection (CWE-89, Patchstack "
            "CVSS 9.3, Wordfence CVSS 7.5). Patched in 4.18.2, which is not "
            "the recommended release. Update to 4.18.3, because 4.18.2 is "
            "still inside CVE-2026-129039 (unauthenticated PHP object "
            "injection, CVSS 9.8) and CVE-2026-129043 (unauthenticated SQL "
            "injection, CVSS 9.3). Patchstack marks CVE-2026-111402 known "
            "exploited (Patchstack telemetry, not CISA KEV). "
            f"{_passive_note()} {_sources_note()}"
        ),
        fix=_fix(),
        match=f"newsletters:{label}",
    )


def _update_4183(version: tuple[int, ...]) -> dict:
    label = fmt(version)
    return base_finding(
        CHECK,
        severity="critical",
        title=(
            f"{UNCONFIRMED}: Newsletters {label} likely vulnerable "
            "(CVE-2026-129039, CVE-2026-129043); update to 4.18.3"
        ),
        evidence=(
            f"GET {README} Stable tag is {label}. {UNCONFIRMED}. "
            f"{label} is the patched release for {CHECK.cve} and is not "
            "likely vulnerable to that SQL injection. It is still inside "
            "the Patchstack ranges for CVE-2026-129039 (unauthenticated PHP "
            "object injection, CVSS 9.8) and CVE-2026-129043 (unauthenticated "
            "SQL injection, CVSS 9.3), both through 4.18.2 and patched in "
            "4.18.3. Update to 4.18.3. Those two follow-ons are not marked "
            "exploited by Patchstack. CVE-2026-111402's exploited label is "
            "Patchstack telemetry, not CISA KEV, and does not apply to this "
            f"version. {_passive_note()} {_sources_note()}"
        ),
        fix=_fix(),
        match=f"newsletters:{label}",
    )


def _unknown() -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=f"Newsletters detected; version unknown ({CHECK.cve})",
        evidence=(
            f"GET {README} is a Tribulant Newsletters readme, but it has no "
            f"parseable Stable tag. Unknown: {CHECK.cve} (through 4.18.1, "
            "patched in 4.18.2) and CVE-2026-129039 / CVE-2026-129043 "
            "(through 4.18.2, patched in 4.18.3) were not compared. "
            f"Not a guess. {_passive_note()} {_sources_note()}"
        ),
        fix=_fix(),
        match="newsletters:unknown",
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
        return [_unknown()]
    if sqli_affected(version):
        return [_vulnerable(version)]
    if followon_affected(version):
        return [_update_4183(version)]
    return []


CHECK = CveCheck(
    id="newsletters",
    cve="CVE-2026-111402",
    # Closest registry agent: Injection owns SQL-injection probes and is not
    # one of CveCheck.AGENTS. This check is a passive version fingerprint, the
    # same mapping as Estatik and wpForo (Injection family → misconfig).
    agent="misconfig",
    fixed=(
        "4.18.3 (CVE-2026-111402 affected through 4.18.1, patched in 4.18.2; "
        "4.18.2 must update to 4.18.3 for CVE-2026-129039 and CVE-2026-129043)"
    ),
    summary=(
        "One GET of the Tribulant Newsletters (newsletters-lite) readme. "
        "Critical, version unconfirmed, when the Stable tag is 4.18.1 or "
        "lower (CVE-2026-111402, unauthenticated SQL injection; Patchstack "
        "known-exploited, not CISA KEV). 4.18.2 is reported as update to "
        "4.18.3 (CVE-2026-129039 and CVE-2026-129043). 4.18.3 and later are "
        "not flagged. Info when the readme is the plugin but the Stable tag "
        "cannot be parsed."
    ),
    sends=f"One GET of {README}. No query string.",
    does_not_send=(
        "No query string on the plugin readme or on any plugin endpoint. "
        "No POST, PUT, or DELETE. No request body. No SQL, no serialized "
        "string, no file upload, no authentication attempt, no write, and "
        "nothing to /wp-admin. Never more than the single readme GET."
    ),
    run=run,
)
