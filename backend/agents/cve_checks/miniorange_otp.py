"""miniOrange OTP Verification (CVE-2026-129073) — one readme Stable tag read.

WordPress.org slug ``miniorange-otp-verification`` (plugin name: miniOrange
OTP Login, Verification and SMS Notifications). Unauthenticated broken
authentication (CWE-288, CVSS 9.8): an attacker can log in without the OTP.

Confirmed range. Patchstack (CNA), published 18 November 2026, reported by
AndrewN on 11 November 2026: affected through 5.6.1, patched in 5.6.2.
CVE record: from n/a through 5.6.1. GHSA-cfvw-x827-j287.
https://patchstack.com/database/wordpress/plugin/miniorange-otp-verification/vulnerability/wordpress-miniorange-otp-verification-plugin-5-6-1-broken-authentication-vulnerability
https://cve.circl.lu/vuln/cve-2026-129073

Plugin changelog (trunk ``readme.txt``, Stable tag 5.6.3):
https://plugins.svn.wordpress.org/miniorange-otp-verification/trunk/readme.txt
https://wordpress.org/plugins/miniorange-otp-verification/
Tag 5.6.2 (16 November 2026) is "Minor security fix". 5.6.3, current as of
23 November 2026, is a further login fix: OTP login state is kept in one
server-chosen store and bound to the user it was started for, and the
WordPress login no longer discards errors from other login security checks
(captcha, login lockout).

Version wording, reconciled. The two operator reports agree on the
vulnerable ceiling and disagree only on where to stop:

- WP Server Guard, week to 23 November 2026: affected ≤ 5.6.1, fixed in
  5.6.2, current 5.6.3 which "adds a further login fix".
  https://wpserverguard.com/blog/exploited-wordpress-plugins-november-2026/
- Must Have Plugins week 47: "5.6.1 and older", "Fixed in 5.6.2 on
  November 16; 5.6.3 is current", and the action is update to 5.6.3
  (table: "5.6.2 go to 5.6.3").
  https://musthaveplugins.com/blog/wordpress-vulnerability-report-2026-week-47/

That matches the changelog: 5.6.2 is the patched release for this CVE, and
5.6.3 is a later login fix. This check reports a parsed version through
5.6.1 as likely vulnerable, reports 5.6.2 (and any parsed version above
5.6.1 and below 5.6.3) as info ("update to 5.6.3"), and reports 5.6.3 and
later as not detected. WPSec WPSEC-2026-3301 gives a narrower introduced-in
of 5.4.7. The CNA range, and both reports above, are through 5.6.1 with no
higher floor, so this check follows that range.
https://wpsec.com/vuln/WPSEC-2026-3301/

The "exploited" / "Known to be exploited (KEV)" label is Patchstack's.
CVE-2026-129073 is not in the CISA Known Exploited Vulnerabilities catalog.
The CSV at
https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv
was checked on 23 November 2026: no CVE-2026-129073 and no miniOrange
entry. That feed does include CVE-2026-129448, added 20 November 2026, so
it is current past this CVE's publication. CISA's SSVC decision on the CVE
record is Exploitation: none. WP Server Guard notes an earlier exploited
flaw in this same plugin in its 26 October 2026 briefing. This check covers
CVE-2026-129073 only. Wordfence's plugin record (last updated 7 November
2026) does not yet list CVE-2026-129073:
https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/miniorange-otp-verification/

Detection is one read-only GET of the public plugin readme. A version hit
is a fingerprint only. Never requests wp-login.php or any OTP endpoint.
"""
import re

import recon

from .client import fetch_path
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, parse_dotted


README = "/wp-content/plugins/miniorange-otp-verification/readme.txt"
_AFFECTED_THROUGH = (5, 6, 1)
_CURRENT = (5, 6, 3)

_STABLE = re.compile(r"(?im)^[ \t]*stable tag:[ \t]*(\d+(?:\.\d+){0,3})[ \t]*$")
_HEADER = re.compile(
    r"(?im)^===\s*.*\bminiorange\b.*\botp\b.*===\s*$",
)
_README_FIELDS = ("stable tag:", "contributors:", "requires at least:")

_PATCHSTACK = (
    "https://patchstack.com/database/wordpress/plugin/"
    "miniorange-otp-verification/vulnerability/"
    "wordpress-miniorange-otp-verification-plugin-5-6-1-broken-authentication-"
    "vulnerability"
)
_CHANGELOG = (
    "https://plugins.svn.wordpress.org/miniorange-otp-verification/trunk/readme.txt"
)
_WPSERVERGUARD = (
    "https://wpserverguard.com/blog/exploited-wordpress-plugins-november-2026/"
)
_MUSTHAVE = (
    "https://musthaveplugins.com/blog/wordpress-vulnerability-report-2026-week-47/"
)


def _fix() -> str:
    return (
        "Update miniOrange OTP Verification (miniorange-otp-verification) to "
        "5.6.3 or later (Plugins screen or "
        "`wp plugin update miniorange-otp-verification`). 5.6.2 fixes "
        f"{CHECK.cve}; 5.6.3 is current and carries a further login fix. "
        "Review administrator accounts and recent logins. "
        f"See {CHECK.cve}."
    )


def _passive_note() -> str:
    return (
        "Only a read-only GET of the public plugin readme was sent, with no "
        "request body. No wp-login.php request, OTP endpoint, login, POST, "
        "upload, or write was sent."
    )


def stable_tag(body: str) -> tuple[int, ...] | None:
    match = _STABLE.search(body or "")
    return parse_dotted(match.group(1)) if match else None


def is_plugin_readme(body: str) -> bool:
    """True when the body is this plugin's readme, not an HTML soft-404."""
    text = body or ""
    if recon.looks_like_app_html(text[:400]):
        return False
    if not _HEADER.search(text):
        return False
    low = text.lower()
    if "miniorange" not in low or "otp" not in low:
        return False
    return any(field in low for field in _README_FIELDS)


def affected(version: tuple[int, ...]) -> bool:
    """True for versions through 5.6.1 inclusive. 5.6.2+ is patched."""
    return cmp_ver(version, _AFFECTED_THROUGH) <= 0


def recommend_current(version: tuple[int, ...]) -> bool:
    """True for the patched 5.6.2 line that is still short of 5.6.3."""
    return cmp_ver(version, _AFFECTED_THROUGH) > 0 and cmp_ver(version, _CURRENT) < 0


def _vulnerable(version: tuple[int, ...]) -> dict:
    label = fmt(version)
    return base_finding(
        CHECK,
        severity="critical",
        title=f"{UNCONFIRMED}: miniOrange OTP Verification {label} ({CHECK.cve})",
        evidence=(
            f"GET {README} Stable tag is {label}. {UNCONFIRMED}. "
            "Affected: miniOrange OTP Verification through 5.6.1. Fixed in "
            "5.6.2 (16 November 2026, changelog: Minor security fix). "
            "5.6.3 is current and carries a further login fix; update to "
            "5.6.3. "
            f"{CHECK.cve}: unauthenticated authentication bypass that lets an "
            "attacker log in without the OTP (CWE-288, CVSS 9.8). Patchstack "
            "marks this known-exploited (Patchstack label, not CISA KEV). "
            f"{_passive_note()} "
            f"Sources: {_PATCHSTACK}; {_CHANGELOG}; {_WPSERVERGUARD}; {_MUSTHAVE}."
        ),
        fix=_fix(),
        match=f"miniorange-otp:{label}",
    )


def _update(version: tuple[int, ...]) -> dict:
    label = fmt(version)
    return base_finding(
        CHECK,
        severity="info",
        title=(
            f"miniOrange OTP Verification {label} is patched for {CHECK.cve}; "
            "update to 5.6.3"
        ),
        evidence=(
            f"GET {README} Stable tag is {label}. {label} is the patched "
            f"release for {CHECK.cve} (5.6.2, 16 November 2026, changelog: "
            "Minor security fix). Update to 5.6.3. 5.6.3 is current and "
            "carries a further login fix: OTP login state is bound to the "
            "user it was started for, and the WordPress login keeps errors "
            "from other login security checks. "
            f"{_passive_note()} "
            f"Sources: {_PATCHSTACK}; {_CHANGELOG}; {_WPSERVERGUARD}; {_MUSTHAVE}."
        ),
        fix=_fix(),
        match=f"miniorange-otp:{label}",
    )


def _unknown() -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=f"miniOrange OTP Verification detected; version not exposed ({CHECK.cve})",
        evidence=(
            f"GET {README} is a miniOrange OTP Verification readme, but it has "
            f"no parseable Stable tag. {CHECK.cve} cannot be compared "
            "(affected through 5.6.1; fixed in 5.6.2; current 5.6.3). "
            f"{_passive_note()} "
            f"Sources: {_PATCHSTACK}; {_CHANGELOG}."
        ),
        fix=_fix(),
        match="miniorange-otp:unknown",
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
    if recommend_current(version):
        return [_update(version)]
    return []


CHECK = CveCheck(
    id="miniorange-otp",
    cve="CVE-2026-129073",
    # Auth slot: unauthenticated authentication bypass on the login OTP.
    agent="auth",
    fixed=(
        "5.6.2 fixes CVE-2026-129073 (affected: through 5.6.1); "
        "update to 5.6.3 (current, further login fix)"
    ),
    summary=(
        "One GET of the miniOrange OTP Verification readme. Critical, version "
        "unconfirmed, when the Stable tag is through 5.6.1 (fixed in 5.6.2 on "
        "16 November 2026). Info for 5.6.2: update to 5.6.3. Info when that "
        "readme is present but the Stable tag cannot be parsed. 5.6.3 and "
        "later are not flagged."
    ),
    sends=f"One GET of {README}. No request body.",
    does_not_send=(
        "Never requests wp-login.php or any OTP verification, resend, or "
        "login endpoint. No POST, PUT, or DELETE, no request body, no login "
        "or authentication attempt, no OTP submission, no form submission, "
        "no upload, no write, and no malformed input. Never more than the "
        "single readme GET."
    ),
    run=run,
)
