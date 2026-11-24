"""Ninja Forms (CVE-2026-109997 / CVE-2026-110899) — one readme Stable tag read.

One bug, two CVE records. Ninja Forms (WordPress.org slug ``ninja-forms``)
through 3.15.5 has an unauthenticated stored cross-site scripting issue via
``formData.extra`` (CWE-79, Injection). Fixed in 3.15.6 (changelog
15 October 2026: "protect stored submission data against cross-site
scripting"). Wordfence, CNA for CVE-2026-109997, scores CVSS 7.2 HIGH and
names 3.15.6 as the patched release. Patchstack, CNA for CVE-2026-110899,
scores CVSS 7.1 HIGH, affected from n/a through 3.15.5, unaffected at 3.15.6.

Patchstack's database page calls this a medium-priority issue and notes a
possible CVE collision: CVE-2026-109997, published by another numbering
authority, describes the same vulnerability as CVE-2026-110899, and patching
the affected version resolves both. The CVE-2026-110899 record carries
Patchstack's ``x_known-exploited-vulnerability`` tag (record updated
23 November 2026). That exploited label is Patchstack's, not CISA's.

Neither ID is in the CISA Known Exploited Vulnerabilities catalog. The
catalog CSV on cisa.gov was fetched on 24 November 2026 (entries through
23 November 2026, including CVE-2026-133968) and contains neither
CVE-2026-109997 nor CVE-2026-110899. CISA ADP SSVC lists Exploitation
"none" on both records.

This check is separate from ``ninja_forms_uploads`` (CVE-2026-126537), which
covers the File Uploads add-on. It never submits a form.

Detection is one read-only GET of
``/wp-content/plugins/ninja-forms/readme.txt``. A parsed Stable tag at or
below 3.15.5 is reported likely vulnerable (medium-high, version
unconfirmed). A Ninja Forms readme whose Stable tag is missing or
unparseable is unknown. A 404, a non-readme body, or 3.15.6 and later is
not detected. No version is guessed. ``fetch_path`` is the only request, so
the domain allowlist, global rate limit, kill switch, and audit log still
apply.

Sources:
- Patchstack (CVE-2026-110899, medium priority, possible CVE collision):
  https://patchstack.com/database/wordpress/plugin/ninja-forms/vulnerability/wordpress-ninja-forms-plugin-3-15-5-cross-site-scripting-xss-vulnerability
- CVE-2026-110899 record (Patchstack CNA; tag x_known-exploited-vulnerability;
  unaffected at 3.15.6):
  https://cveawg.mitre.org/api/cve/CVE-2026-110899
- Wordfence / CVE-2026-109997 (stored XSS via formData.extra, <= 3.15.5,
  patched 3.15.6, CVSS 7.2):
  https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/ninja-forms/ninja-forms-3155-unauthenticated-stored-cross-site-scripting-via-extra-parameter-via-metadata-key-normalization
  https://cveawg.mitre.org/api/cve/CVE-2026-109997
- NVD:
  https://nvd.nist.gov/vuln/detail/CVE-2026-109997
  https://nvd.nist.gov/vuln/detail/CVE-2026-110899
- Duggan, 23 November 2026 (one bug, two CVEs; Patchstack exploited label;
  not CISA KEV):
  https://www.dugganusa.com/post/wordpress-plugins-flagged-exploited-ninja-forms-givewp-rtmedia-jetformbuilder
- Plugin readme (Stable tag and the 3.15.6 changelog entry):
  https://plugins.svn.wordpress.org/ninja-forms/trunk/readme.txt
- CISA KEV CSV (both IDs absent on 24 November 2026):
  https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv

Never submits a form. No POST, no formData body, no upload, no write, no
forged header, and no malformed input. Exactly one read-only GET.
"""
import re

import recon

from .client import fetch_path
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, parse_dotted


README = "/wp-content/plugins/ninja-forms/readme.txt"
_AFFECTED_THROUGH = (3, 15, 5)
_FIXED = (3, 15, 6)

_SOURCES = (
    "https://patchstack.com/database/wordpress/plugin/ninja-forms/vulnerability/"
    "wordpress-ninja-forms-plugin-3-15-5-cross-site-scripting-xss-vulnerability",
    "https://cveawg.mitre.org/api/cve/CVE-2026-110899",
    "https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/"
    "ninja-forms/ninja-forms-3155-unauthenticated-stored-cross-site-scripting-"
    "via-extra-parameter-via-metadata-key-normalization",
    "https://cveawg.mitre.org/api/cve/CVE-2026-109997",
    "https://nvd.nist.gov/vuln/detail/CVE-2026-109997",
    "https://nvd.nist.gov/vuln/detail/CVE-2026-110899",
    "https://www.dugganusa.com/post/"
    "wordpress-plugins-flagged-exploited-ninja-forms-givewp-rtmedia-jetformbuilder",
    "https://plugins.svn.wordpress.org/ninja-forms/trunk/readme.txt",
    "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv",
)

_STABLE = re.compile(r"(?im)^[ \t]*stable tag:[ \t]*(\d+(?:\.\d+){0,3})[ \t]*$")
_HEADER = re.compile(r"(?im)^===\s*ninja forms\b.*===\s*$")
_README_FIELDS = ("stable tag:", "contributors:", "requires at least:")


def _fix() -> str:
    return (
        "Update Ninja Forms (ninja-forms) to 3.15.6 or later "
        "(Plugins screen or `wp plugin update ninja-forms`). "
        "3.15.6 (15 October 2026) closes both CVE-2026-109997 and "
        "CVE-2026-110899. Review stored submissions if an administrator "
        f"may have opened entries on an affected release. See {CHECK.cve}."
    )


def _sources_note() -> str:
    return "Sources: " + "; ".join(_SOURCES) + "."


def _passive_note() -> str:
    return (
        "Only a read-only GET of the public plugin readme.txt was sent. "
        "No form was submitted. No POST, formData body, upload, write, "
        "forged header, or malformed input was sent."
    )


def stable_tag(body: str) -> tuple[int, ...] | None:
    match = _STABLE.search(body or "")
    if not match:
        return None
    return parse_dotted(match.group(1))


def is_plugin_readme(body: str) -> bool:
    """True when the body is a Ninja Forms readme, not an HTML page."""
    text = body or ""
    if recon.looks_like_app_html(text[:400]):
        return False
    if not _HEADER.search(text):
        return False
    if re.search(r"(?im)^===\s*ninja forms\b[^\n]*file uploads\b", text):
        return False
    low = text.lower()
    return any(field in low for field in _README_FIELDS)


def affected(version: tuple[int, ...]) -> bool:
    """True through 3.15.5 inclusive. 3.15.6 and later are patched."""
    return cmp_ver(version, _AFFECTED_THROUGH) <= 0 and cmp_ver(version, _FIXED) < 0


def _vulnerable(version: tuple[int, ...]) -> dict:
    label = fmt(version)
    return base_finding(
        CHECK,
        severity="high",
        title=(
            f"{UNCONFIRMED}: Ninja Forms {label} likely vulnerable "
            f"(medium-high) ({CHECK.cve})"
        ),
        evidence=(
            f"GET {README} Stable tag is {label}. {UNCONFIRMED}. "
            f"Likely vulnerable, medium-high: Ninja Forms through 3.15.5. "
            f"Fixed in {fmt(_FIXED)} (15 October 2026). "
            "CVE-2026-109997 and CVE-2026-110899 are one bug: unauthenticated "
            "stored cross-site scripting via formData.extra (CWE-79). "
            "Wordfence CVSS 7.2 HIGH; Patchstack CVSS 7.1 HIGH and medium "
            "priority. Patchstack notes a possible CVE collision: "
            "CVE-2026-109997 describes the same issue as CVE-2026-110899, "
            "and 3.15.6 resolves both. Patchstack marks it known-exploited "
            "(Patchstack label, not CISA KEV). "
            f"{_passive_note()} {_sources_note()}"
        ),
        fix=_fix(),
        match=f"ninja-forms:{label}",
    )


def _unknown() -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=f"Ninja Forms detected; version unknown ({CHECK.cve})",
        evidence=(
            f"GET {README} is a Ninja Forms readme, but it has no parseable "
            f"Stable tag. Unknown: CVE-2026-109997 / CVE-2026-110899 "
            f"(through 3.15.5; fixed in {fmt(_FIXED)}) was not compared. "
            f"Not a guess. {_passive_note()}"
        ),
        fix=_fix(),
        match="ninja-forms:unknown",
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
    if affected(version):
        return [_vulnerable(version)]
    return []


CHECK = CveCheck(
    id="ninja-forms",
    cve="CVE-2026-109997 / CVE-2026-110899",
    # Closest registry agent: Injection owns active probes and is not one of
    # CveCheck.AGENTS. This check is a passive version fingerprint, the same
    # mapping as ninja_forms_uploads and rtmedia (Injection family → misconfig).
    agent="misconfig",
    fixed="3.15.6+ (affected: Ninja Forms through 3.15.5)",
    summary=(
        "One GET of the Ninja Forms (ninja-forms) readme. High, medium-high, "
        "version unconfirmed / likely vulnerable, when that file is the "
        "Ninja Forms readme and the Stable tag is 3.15.5 or lower (fixed in "
        "3.15.6). CVE-2026-109997 and CVE-2026-110899 are one stored-XSS bug; "
        "Patchstack notes a possible CVE collision and marks it "
        "known-exploited (Patchstack label, not CISA KEV). Info when the "
        "readme is Ninja Forms but the Stable tag cannot be parsed. A missing "
        "file or a non-plugin body is not detected. Separate from "
        "ninja-forms-uploads. No version is guessed."
    ),
    sends=f"One GET of {README}.",
    does_not_send=(
        "Never submits a Ninja Forms form. Never sends a formData body. "
        "No POST, no upload, no write, no forged header, and no malformed "
        "input. Exactly one read-only GET of the core plugin readme. "
        "Does not request the File Uploads add-on."
    ),
    run=run,
)
