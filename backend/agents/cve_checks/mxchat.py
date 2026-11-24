"""MxChat (CVE-2026-110662) — one readme Stable tag read.

WordPress.org slug ``mxchat-basic`` (plugin header
``=== MxChat - AI Chatbot & Content Generation for WordPress ===``,
contributor ``mxchat``). Confirmed on the public trunk readme (Stable tag
3.2.29 on 24 November 2026) and on the WordPress.org plugin API.

CVE-2026-110662 is unauthenticated stored DOM-based cross-site scripting in
visitor rating feedback. An anonymous visitor can plant it; it runs when an
administrator views that feedback (the Transcripts screen). NVD, Wordfence,
Patchstack, and WPSec all put the affected range at every release through
3.2.25 inclusive. Fixed in 3.2.26 (changelog 17 October 2026: visitor
feedback display was hardened). 3.2.26 and later are not flagged. NVD and
Wordfence score CVSS 7.2 High. Patchstack scores CVSS 7.1 and calls the
priority medium. This check reports a parsed affected version as high on
this scanner's scale (that medium-high band).

The exploited label comes from Patchstack. DugganUSA (23 November 2026)
reports the Patchstack entry carries "Known to be exploited! (KEV)" and that
VulnCheck KEV's evidence for this CVE is that Patchstack page (evidence date
23 November 2026). It is not a CISA KEV listing. The CISA Known Exploited
Vulnerabilities JSON feed, catalogVersion 2026.11.23 (1,792 entries), was
checked on 24 November 2026 and does not contain CVE-2026-110662.

Detection is one read-only GET of
``/wp-content/plugins/mxchat-basic/readme.txt`` with no query string.
``fetch_path`` is the only request, so the domain allowlist, global rate
limit, kill switch, and audit log still apply. "Likely vulnerable" is
reported only when a Stable tag is parsed and is 3.2.25 or lower. A readme
that is this plugin but has no parseable Stable tag is unknown. A missing
file, a non-plugin body, or a tag of 3.2.26 or later is not detected. No
version is inferred from the changelog or from any other field.

Sources:
- NVD (published 2026-10-28, CVSS 3.1 7.2 HIGH, through 3.2.25):
  https://nvd.nist.gov/vuln/detail/CVE-2026-110662
- Patchstack (<= 3.2.25, patched 3.2.26, CVSS 7.1, medium priority,
  published 28 Oct 2026):
  https://patchstack.com/database/wordpress/plugin/mxchat-basic/vulnerability/wordpress-mxchat-ai-chatbot-content-generation-for-wordpress-plugin-3-2-25-unauthenticated-stored-dom-based-cross-site-scripting-vulnerability
- Wordfence (slug mxchat-basic, <= 3.2.25, patched 3.2.26, CVSS 7.2):
  https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/mxchat-basic/mxchat-3225-unauthenticated-stored-dom-based-cross-site-scripting-via-feedback-parameter-via-mxchat-save-rating
- WPSec (before 3.2.26, fix released 2026-10-17):
  https://wpsec.com/vuln/WPSEC-2026-1226/
- DugganUSA (Patchstack exploited label; not CISA KEV):
  https://www.dugganusa.com/post/wordpress-plugins-flagged-exploited-ninja-forms-givewp-rtmedia-jetformbuilder
- Plugin readme and changelog (3.2.26 hardens visitor feedback display):
  https://plugins.svn.wordpress.org/mxchat-basic/trunk/readme.txt
  https://wordpress.org/plugins/mxchat-basic/
- CISA KEV JSON (catalogVersion 2026.11.23, CVE-2026-110662 absent):
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- GHSA-jgfm-j27x-x26p:
  https://github.com/advisories/GHSA-jgfm-j27x-x26p

Never submits chatbot feedback or any script. No POST, no rating request,
no upload, no authentication attempt, no write, and no malformed input.
"""
import re

import recon

from .client import fetch_path
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, parse_dotted


README = "/wp-content/plugins/mxchat-basic/readme.txt"
_AFFECTED_THROUGH = (3, 2, 25)
_FIXED = (3, 2, 26)

_SOURCES = (
    "https://nvd.nist.gov/vuln/detail/CVE-2026-110662",
    "https://patchstack.com/database/wordpress/plugin/mxchat-basic/vulnerability/"
    "wordpress-mxchat-ai-chatbot-content-generation-for-wordpress-plugin-3-2-25-"
    "unauthenticated-stored-dom-based-cross-site-scripting-vulnerability",
    "https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/"
    "mxchat-basic/mxchat-3225-unauthenticated-stored-dom-based-cross-site-"
    "scripting-via-feedback-parameter-via-mxchat-save-rating",
    "https://wpsec.com/vuln/WPSEC-2026-1226/",
    "https://www.dugganusa.com/post/wordpress-plugins-flagged-exploited-"
    "ninja-forms-givewp-rtmedia-jetformbuilder",
    "https://plugins.svn.wordpress.org/mxchat-basic/trunk/readme.txt",
    "https://wordpress.org/plugins/mxchat-basic/",
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
)

_STABLE = re.compile(r"(?im)^[ \t]*stable tag:[ \t]*(\d+(?:\.\d+){0,3})[ \t]*$")
_HEADER = re.compile(r"(?im)^===\s*.*\bmxchat\b.*===\s*$")
_README_FIELDS = ("stable tag:", "contributors:", "requires at least:")
_NAME_MARKERS = ("contributors: mxchat", "mxchat-basic", "mxchat.ai")


def _fix() -> str:
    return (
        "Update MxChat (mxchat-basic) to 3.2.26 or later (Plugins screen or "
        "`wp plugin update mxchat-basic`). 3.2.26 is the first fixed release. "
        "Review chatbot feedback and transcripts for unexpected markup before "
        f"an administrator opens them. See {CHECK.cve}."
    )


def _sources_note() -> str:
    return "Sources: " + "; ".join(_SOURCES) + "."


def _passive_note() -> str:
    return (
        "Only one read-only GET of the public plugin readme.txt was sent, "
        "with no query string and no request body. No chatbot feedback was "
        "submitted, and no script, POST, upload, authentication attempt, or "
        "write was sent."
    )


def stable_tag(body: str) -> tuple[int, ...] | None:
    match = _STABLE.search(body or "")
    return parse_dotted(match.group(1)) if match else None


def is_plugin_readme(body: str) -> bool:
    """True when the body is the MxChat readme, not an HTML page."""
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
    """True through 3.2.25 inclusive. 3.2.26 and later are patched."""
    return cmp_ver(version, _AFFECTED_THROUGH) <= 0


def _vulnerable(version: tuple[int, ...]) -> dict:
    label = fmt(version)
    return base_finding(
        CHECK,
        severity="high",
        title=(
            f"{UNCONFIRMED}: MxChat {label} likely vulnerable ({CHECK.cve})"
        ),
        evidence=(
            f"GET {README} Stable tag is {label}. {UNCONFIRMED}. "
            f"Likely vulnerable: MxChat (mxchat-basic) through 3.2.25. "
            f"Fixed in 3.2.26. {CHECK.cve}: unauthenticated stored DOM-based "
            "cross-site scripting in visitor rating feedback, which runs when "
            "an administrator views that feedback. NVD and Wordfence CVSS 7.2 "
            "High; Patchstack CVSS 7.1, medium priority (medium-high on this "
            "scale). The exploited label is Patchstack's, not CISA KEV. "
            f"{_passive_note()} {_sources_note()}"
        ),
        fix=_fix(),
        match=f"mxchat:{label}",
    )


def _unknown() -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=f"MxChat detected; version unknown ({CHECK.cve})",
        evidence=(
            f"GET {README} is an MxChat readme, but it has no parseable "
            f"Stable tag. Unknown: {CHECK.cve} (through 3.2.25; fixed in "
            "3.2.26) was not compared. Not a guess. "
            f"{_passive_note()} {_sources_note()}"
        ),
        fix=_fix(),
        match="mxchat:unknown",
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
    id="mxchat",
    cve="CVE-2026-110662",
    # Closest registry agent: Injection owns active XSS probes and is not one
    # of CveCheck.AGENTS. This check is a passive version fingerprint, the
    # same mapping as rtMedia and Newsletters (Injection family → misconfig).
    agent="misconfig",
    fixed="3.2.26 (affected: MxChat through 3.2.25)",
    summary=(
        "One GET of the MxChat (mxchat-basic) readme. High (medium-high: "
        "Patchstack medium priority CVSS 7.1; NVD and Wordfence CVSS 7.2), "
        "version unconfirmed, when the Stable tag is 3.2.25 or lower (fixed "
        "in 3.2.26). Likely vulnerable only when that tag is parsed and in "
        "range. Info (unknown) when the readme is MxChat but the Stable tag "
        "cannot be parsed. A missing file, a non-plugin body, or 3.2.26 and "
        "later are not detected. Patchstack's exploited label; not CISA KEV."
    ),
    sends=f"One GET of {README}. No query string.",
    does_not_send=(
        "Never submits chatbot feedback or any script. No POST, no rating "
        "or transcript request, no admin-ajax action, no upload, no "
        "authentication attempt, no write, and no malformed input. Never "
        "more than the single readme GET."
    ),
    run=run,
)
