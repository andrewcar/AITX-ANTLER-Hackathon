"""GiveWP (CVE-2026-104405 / CVE-2026-82675) — one readme Stable tag read.

GiveWP – Donation Plugin and Fundraising Platform, WordPress.org slug
``give``. Two unauthenticated issues share the same affected range and the
same fixed release, so this one check cites both.

CVE-2026-104405 is unauthenticated privilege escalation (CWE-266, incorrect
privilege assignment) in every release through 4.17.0, fixed in 4.18.0.
Patchstack and NVD score it CVSS 8.1 (HIGH). Wordfence scores the same range
CVSS 7.3 and names the slug ``give``. NVD's affected entry is package
``give``, from n/a through 4.17.0, unaffected at 4.18.0. Patchstack's page
says "Known to be exploited". That exploited label is Patchstack's, not
CISA's. The CVE record also carries Patchstack's
``x_known-exploited-vulnerability`` tag (record updated 23 November 2026).
Duggan's 23–24 November 2026 note lists folder ``give``, exposed at 4.17.0
and earlier, fix 4.18.0, and says the exploitation flag is the Patchstack
page (also picked up by VulnCheck), not CISA KEV.

CVE-2026-82675 is a separate unauthenticated donor account takeover
(CWE-287). Wordfence and NVD both score it CVSS 8.1 and both say every
release through 4.17.0. Wordfence's remediation is 4.18.0, the same fixed
version, slug ``give``. NVD's affected entry is lessThanOrEqual 4.17.0 with
default status unaffected. This check does not describe how that takeover
works. Wordfence does not mark CVE-2026-82675 known-exploited; only
CVE-2026-104405 carries Patchstack's exploited label.

Neither CVE is in the CISA Known Exploited Vulnerabilities catalog. The
catalog CSV on cisa.gov was checked on 24 November 2026 (1,793 entries) and
contains neither CVE-2026-104405 nor CVE-2026-82675.

Slug confirmed on the public readme. Trunk, the 4.17.0 tag, and the 4.18.0
tag all use the header ``=== GiveWP - Donation Plugin and Fundraising
Platform ===`` and contributor ``givewp``. Older tags such as 2.5.0 use
``=== Give - Donation Plugin and Fundraising Platform ===`` with the same
``givewp`` contributor. Trunk's Stable tag was 4.19.2.2 on 24 November 2026.
The 4.17.0 tag's Stable tag is 4.17.0. The 4.18.0 tag's Stable tag is 4.18.0
(changelog 1 October 2026). 4.18.0.1 and later are not flagged.

Detection is one read-only GET of
``/wp-content/plugins/give/readme.txt`` through ``fetch_path``, so the
allowlist, global rate limit, kill switch, and audit log still apply. A
parsed Stable tag at or below 4.17.0 is high and "likely vulnerable". A
GiveWP readme with a missing or unparseable Stable tag is unknown, not a
guess. A missing file, a non-200 response, a non-plugin body, or a parsed
version above 4.17.0 (including 4.18.0 and later) is not detected.

Sources:
- Patchstack (CVE-2026-104405, <= 4.17.0, patched 4.18.0, CVSS 8.1,
  "Known to be exploited"):
  https://patchstack.com/database/wordpress/plugin/give/vulnerability/wordpress-givewp-plugin-4-17-0-privilege-escalation-vulnerability
- NVD CVE-2026-104405 (package give, through 4.17.0, unaffected at 4.18.0):
  https://nvd.nist.gov/vuln/detail/CVE-2026-104405
- Wordfence CVE-2026-104405 (slug give, <= 4.17.0, patched 4.18.0, CVSS 7.3):
  https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/give/givewp-donation-plugin-and-fundraising-platform-4170-unauthenticated-privilege-escalation
- Wordfence CVE-2026-82675 (slug give, <= 4.17.0, patched 4.18.0, CVSS 8.1):
  https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/give/givewp-donation-plugin-and-fundraising-platform-4170-unauthenticated-donor-account-takeover
- NVD CVE-2026-82675 (through 4.17.0, CWE-287, CVSS 8.1):
  https://nvd.nist.gov/vuln/detail/CVE-2026-82675
- Duggan, GiveWP row (folder give, exposed through 4.17.0, fix 4.18.0;
  Patchstack exploited label, not CISA KEV):
  https://www.dugganusa.com/post/wordpress-plugins-flagged-exploited-ninja-forms-givewp-rtmedia-jetformbuilder
- Plugin readme (slug give):
  https://plugins.svn.wordpress.org/give/trunk/readme.txt
  https://wordpress.org/plugins/give/
- CISA KEV catalog (both CVEs absent on 24 November 2026):
  https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv

Never requests a donor, registration, or login endpoint. No POST, no
request body, no exploit payload, no forged header, no malformed input,
no upload, and no write.
"""
import re

import recon

from .client import fetch_path
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, parse_dotted


README = "/wp-content/plugins/give/readme.txt"
_AFFECTED_THROUGH = (4, 17, 0)

_STABLE = re.compile(r"(?im)^[ \t]*stable tag:[ \t]*(\d+(?:\.\d+){0,3})[ \t]*$")
# Current header is "GiveWP - Donation Plugin ...". Tags as old as 2.5.0
# say "Give - Donation Plugin ..." and still list the givewp contributor.
_HEADER = re.compile(
    r"(?im)^===\s*give(?:wp)?\s*-\s*donation plugin\b.*===\s*$"
)
_GIVEWP_HEADER = re.compile(r"(?i)\bgivewp\b")
_CONTRIBUTOR = re.compile(r"(?im)^[ \t]*contributors:[^\n]*\bgivewp\b")
_README_FIELDS = ("stable tag:", "contributors:", "requires at least:")


def _fix() -> str:
    return (
        "Update GiveWP (give) to 4.18.0 or later. 4.18.0 fixes both "
        "CVE-2026-104405 and CVE-2026-82675. 4.19.2.2 was the WordPress.org "
        "Stable tag on 24 November 2026. Plugins screen or "
        f"`wp plugin update give`. See {CHECK.cve}."
    )


def _passive_note() -> str:
    return (
        "Only a read-only GET of the public plugin readme was sent. "
        "No donor, registration, or login endpoint was requested. No POST, "
        "request body, exploit payload, forged header, malformed input, "
        "upload, or write was sent."
    )


def stable_tag(body: str) -> tuple[int, ...] | None:
    match = _STABLE.search(body or "")
    if not match:
        return None
    return parse_dotted(match.group(1))


def is_plugin_readme(body: str) -> bool:
    """True when the body is a GiveWP readme, not an HTML page or another plugin."""
    text = body or ""
    if recon.looks_like_app_html(text[:400]):
        return False
    header = _HEADER.search(text)
    if header is None:
        return False
    low = text.lower()
    if not any(field in low for field in _README_FIELDS):
        return False
    if _GIVEWP_HEADER.search(header.group(0)):
        return True
    return _CONTRIBUTOR.search(text) is not None


def affected(version: tuple[int, ...]) -> bool:
    """True through 4.17.0 inclusive. 4.18.0 and later are patched."""
    return cmp_ver(version, _AFFECTED_THROUGH) <= 0


def _high(version: tuple[int, ...]) -> dict:
    label = fmt(version)
    return base_finding(
        CHECK,
        severity="high",
        title=(
            f"{UNCONFIRMED}: GiveWP {label} likely vulnerable ({CHECK.cve})"
        ),
        evidence=(
            f"GET {README} Stable tag is {label}. {UNCONFIRMED}. "
            f"Likely vulnerable: GiveWP (give) through 4.17.0. Fixed in "
            "4.18.0. CVE-2026-104405: unauthenticated privilege escalation "
            "(CWE-266). Patchstack and NVD CVSS 8.1; Wordfence CVSS 7.3. "
            "Patchstack marks CVE-2026-104405 known-exploited (Patchstack "
            "label, not CISA KEV). CVE-2026-82675: unauthenticated donor "
            "account takeover (CWE-287, Wordfence and NVD CVSS 8.1), same "
            "affected range and the same 4.18.0 fix. CVE-2026-82675 is not "
            f"marked known-exploited. Neither CVE is on CISA KEV. "
            f"{_passive_note()}"
        ),
        fix=_fix(),
        match=f"givewp:{label}",
    )


def _unknown() -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=f"GiveWP detected; version unknown ({CHECK.cve})",
        evidence=(
            f"GET {README} is a GiveWP readme, but it has no parseable "
            "Stable tag. Unknown: CVE-2026-104405 and CVE-2026-82675 were "
            "not compared (affected through 4.17.0; fixed in 4.18.0). "
            f"Not a guess. {_passive_note()}"
        ),
        fix=_fix(),
        match="givewp:unknown",
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
        return [_high(version)]
    return []


CHECK = CveCheck(
    id="givewp",
    cve="CVE-2026-104405 / CVE-2026-82675",
    # Privilege escalation and account takeover. Same auth slot as
    # miniOrange OTP: a passive version fingerprint, not a login attempt.
    agent="auth",
    fixed="4.18.0 (affected: GiveWP through 4.17.0; both CVEs)",
    summary=(
        "One GET of the GiveWP (give) readme. High, version unconfirmed, "
        "when that file is the GiveWP readme and the Stable tag is 4.17.0 "
        "or lower (fixed in 4.18.0). CVE-2026-104405 is unauthenticated "
        "privilege escalation; Patchstack marks it known-exploited (not "
        "CISA KEV). CVE-2026-82675 is unauthenticated donor account takeover "
        "with the same range and the same 4.18.0 fix. Info when the readme "
        "is GiveWP but the Stable tag cannot be parsed. A missing file, a "
        "non-plugin body, or a parsed version above 4.17.0 is not detected."
    ),
    sends=f"One GET of {README}. No query string.",
    does_not_send=(
        "Never requests a donor, registration, or login endpoint. No POST, "
        "no request body, no exploit payload, no forged header, no malformed "
        "input, no upload, and no write. Exactly one read-only GET of the "
        "plugin readme."
    ),
    run=run,
)
