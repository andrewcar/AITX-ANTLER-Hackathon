"""WPGuppy Lite (CVE-2026-107654) — one readme Stable tag read.

WordPress.org slug ``wpguppy-lite`` (plugin header
``=== One to one user Chat by WPGuppy ===``, contributor
``amentotechpvtltd``). Confirmed on the public readme (Stable tag 1.1.7)
and on the Patchstack, Wordfence, and NVD entries below. The installed
folder is ``/wp-content/plugins/wpguppy-lite/``.

CVE-2026-107654 is an unauthenticated SQL injection through the ``userId``
parameter in every release through 1.1.6 (CWE-89). Fixed in 1.1.7. The
1.1.7 changelog line is "Security: General security hardening and
maintenance improvements." Patchstack scores it 9.3, requires no login,
and marks the page "Known to be exploited! (KEV)". That exploited label
is Patchstack's, not CISA's. Duggan USA (23 November 2026) records a
VulnCheck KEV row for the same CVE whose cited evidence is that Patchstack
flag. CVE-2026-107654 is not in the CISA Known Exploited Vulnerabilities
catalog: the catalog CSV on cisa.gov was checked on 24 November 2026 and
does not contain this id.

NVD (published 21 November 2026, Wordfence as CNA) describes the same
range: all versions up to and including 1.1.6, unauthenticated SQL
injection via ``userId``. NVD CVSS 7.5 (High). Wordfence lists the slug
``wpguppy-lite`` and the patched version 1.1.7.

Detection is one read-only GET of
``/wp-content/plugins/wpguppy-lite/readme.txt`` with no query string.
The Stable tag is the only version source. A parsed tag at or below 1.1.6
is "likely vulnerable" (a version fingerprint, unconfirmed). A missing or
unparseable tag on a confirmed readme is unknown. A missing file, an HTML
body, or a readme that is not this plugin is not detected. No version is
guessed. ``fetch_path`` is the only request, so the domain allowlist,
global rate limit, kill switch, and audit log still apply.

Sources:
- Patchstack (CVSS 9.3, <= 1.1.6, patched 1.1.7, published 21 Nov 2026,
  "Known to be exploited"):
  https://patchstack.com/database/wordpress/plugin/wpguppy-lite/vulnerability/wordpress-one-to-one-user-chat-by-wpguppy-plugin-1-1-6-unauthenticated-sql-injection-vulnerability
- Duggan USA, 23 November 2026 (folder wpguppy-lite, exposed at 1.1.6 and
  earlier, fix 1.1.7, SQL injection via userId, CVSS 9.3; VulnCheck KEV
  evidence is the Patchstack flag; not CISA KEV):
  https://www.dugganusa.com/post/wordpress-plugins-flagged-exploited-ninja-forms-givewp-rtmedia-jetformbuilder
- NVD (CVE-2026-107654, Wordfence CNA, CVSS 7.5, CWE-89, published
  21 Nov 2026, affected through 1.1.6):
  https://nvd.nist.gov/vuln/detail/CVE-2026-107654
- Wordfence (slug wpguppy-lite, <= 1.1.6, patched 1.1.7):
  https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wpguppy-lite/one-to-one-user-chat-by-wpguppy-116-unauthenticated-sql-injection-via-userid-parameter
- Plugin readme, Stable tag 1.1.7:
  https://plugins.svn.wordpress.org/wpguppy-lite/trunk/readme.txt
  https://wordpress.org/plugins/wpguppy-lite/
- CISA KEV catalog CSV (CVE-2026-107654 absent on 24 November 2026):
  https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv
  https://www.cisa.gov/known-exploited-vulnerabilities-catalog

Never sends the ``userId`` parameter or any SQL. No query string, no POST,
no request body, no forged headers, no upload, no auth attempt, no write,
and no malformed input.
"""
import re

import recon

from .client import fetch_path
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, parse_dotted


README = "/wp-content/plugins/wpguppy-lite/readme.txt"
_AFFECTED_THROUGH = (1, 1, 6)
_FIXED = (1, 1, 7)

_SOURCES = (
    "https://patchstack.com/database/wordpress/plugin/wpguppy-lite/"
    "vulnerability/wordpress-one-to-one-user-chat-by-wpguppy-plugin-1-1-6-"
    "unauthenticated-sql-injection-vulnerability",
    "https://www.dugganusa.com/post/wordpress-plugins-flagged-exploited-"
    "ninja-forms-givewp-rtmedia-jetformbuilder",
    "https://nvd.nist.gov/vuln/detail/CVE-2026-107654",
    "https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/"
    "wpguppy-lite/one-to-one-user-chat-by-wpguppy-116-unauthenticated-sql-"
    "injection-via-userid-parameter",
    "https://plugins.svn.wordpress.org/wpguppy-lite/trunk/readme.txt",
    "https://wordpress.org/plugins/wpguppy-lite/",
    "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv",
)

_STABLE = re.compile(r"(?im)^[ \t]*stable tag:[ \t]*(\d+(?:\.\d+){0,3})[ \t]*$")
_HEADER = re.compile(r"(?im)^===\s*.*\bwpguppy\b.*===\s*$")
_README_FIELDS = ("stable tag:", "contributors:", "requires at least:")
_NAME_MARKERS = ("one to one", "amentotech", "wpguppy-lite")


def _fix() -> str:
    return (
        "Update One to one user Chat by WPGuppy (wpguppy-lite) to 1.1.7 or "
        "later (Plugins screen or `wp plugin update wpguppy-lite`). "
        f"1.1.6 and earlier are affected by {CHECK.cve}."
    )


def _sources_note() -> str:
    return "Sources: " + "; ".join(_SOURCES) + "."


def _passive_note() -> str:
    return (
        "Only one read-only GET of the public plugin readme.txt was sent, "
        "with no query string and no request body. The userId parameter was "
        "not sent, and no SQL, POST, forged header, upload, authentication "
        "attempt, write, or malformed input was sent."
    )


def stable_tag(body: str) -> tuple[int, ...] | None:
    match = _STABLE.search(body or "")
    return parse_dotted(match.group(1)) if match else None


def is_plugin_readme(body: str) -> bool:
    """True when the body is the WPGuppy Lite readme, not an HTML page."""
    text = body or ""
    if recon.looks_like_app_html(text[:400]):
        return False
    if not _HEADER.search(text):
        return False
    low = text.lower()
    if not any(marker in low for marker in _NAME_MARKERS):
        return False
    return any(field in low for field in _README_FIELDS)


def affected(version: tuple[int, ...]) -> bool:
    """True through 1.1.6 inclusive. 1.1.7 and later are patched."""
    return cmp_ver(version, _AFFECTED_THROUGH) <= 0


def _vulnerable(version: tuple[int, ...]) -> dict:
    label = fmt(version)
    return base_finding(
        CHECK,
        severity="critical",
        title=(
            f"{UNCONFIRMED}: WPGuppy Lite {label} likely vulnerable "
            f"({CHECK.cve})"
        ),
        evidence=(
            f"GET {README} Stable tag is {label}. {UNCONFIRMED}. "
            f"Likely vulnerable: One to one user Chat by WPGuppy "
            f"(wpguppy-lite) through 1.1.6. Fixed in {fmt(_FIXED)}. "
            f"{CHECK.cve}: unauthenticated SQL injection via the userId "
            "parameter (CWE-89). Patchstack CVSS 9.3 and known-exploited "
            "(Patchstack label, not CISA KEV). NVD and Wordfence CVSS 7.5. "
            f"{_passive_note()} {_sources_note()}"
        ),
        fix=_fix(),
        match=f"wpguppy-lite:{label}",
    )


def _unknown() -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=f"WPGuppy Lite detected; version unknown ({CHECK.cve})",
        evidence=(
            f"GET {README} is a WPGuppy Lite readme, but it has no parseable "
            f"Stable tag. Unknown: {CHECK.cve} (affected through 1.1.6; "
            f"fixed in {fmt(_FIXED)}) was not compared. Not a guess. "
            f"{_passive_note()} {_sources_note()}"
        ),
        fix=_fix(),
        match="wpguppy-lite:unknown",
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
    id="wpguppy-lite",
    cve="CVE-2026-107654",
    # Closest registry agent: Injection owns SQL-injection probes and is not
    # one of CveCheck.AGENTS. This check is a passive version fingerprint, the
    # same mapping as rtMedia and Newsletters (Injection family → misconfig).
    agent="misconfig",
    fixed="1.1.7 (affected: One to one user Chat by WPGuppy through 1.1.6)",
    summary=(
        "One GET of the WPGuppy Lite (wpguppy-lite) readme. Critical, version "
        "unconfirmed, when that file is the plugin readme and the Stable tag "
        "is 1.1.6 or lower (CVE-2026-107654, unauthenticated SQL injection "
        "via userId; fixed in 1.1.7). Patchstack known-exploited, not CISA "
        "KEV. Info when the readme is the plugin but the Stable tag cannot "
        "be parsed. A missing file or a non-plugin body is not detected."
    ),
    sends=f"One GET of {README}. No query string.",
    does_not_send=(
        "Never sends the userId parameter or any SQL. No query string, no "
        "POST, no request body, no forged headers, no upload, no "
        "authentication attempt, no write, and no malformed input. Exactly "
        "one read-only GET of the plugin readme."
    ),
    run=run,
)
