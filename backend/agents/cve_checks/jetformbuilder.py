"""JetFormBuilder (CVE-2026-4373) — one readme Stable tag read.

JetFormBuilder — Dynamic Blocks Form Builder (WordPress.org slug
``jetformbuilder``, contributors crocoblock) through 3.5.6.2 has an
unauthenticated arbitrary file read through the Media Field (CWE-36, CVSS
7.5). A form that is configured with a Media Field and a Send Email action
that attaches files can expose local files, including wp-config.php. This
check does not confirm that configuration. Fixed in 3.5.6.3. The public
plugin changelog for 3.5.6.3 records "FIX: LFI vulnerability". Trunk Stable
tag observed 24 November 2026 is 3.6.8.2, which is outside this range.

Wordfence (CNA) and the NVD CVE record: all versions up to and including
3.5.6.2. Patchstack: vulnerable <= 3.5.6.2, patched in 3.5.6.3, published
24 March 2026, CVSS 7.5. WPScan: fixed in 3.5.6.3. The ranges agree.

Patchstack's page says "Known to be exploited". That exploited label is
Patchstack's, not CISA's. CVE-2026-4373 is not in the CISA Known Exploited
Vulnerabilities catalog. The catalog CSV on cisa.gov was checked on
24 November 2026 and does not contain this CVE. Duggan USA (23 November
2026) reports the same Patchstack flag, notes VulnCheck KEV cites that
Patchstack page, and also reports the CVE absent from CISA KEV catalog
version 2026.11.23. NVD's CISA-ADP SSVC record dated 24 March 2026 lists
exploitation as "none"; that assessment is not a KEV listing.

Detection is one read-only GET of
``/wp-content/plugins/jetformbuilder/readme.txt`` through ``fetch_path``, so
the allowlist, global rate limit, kill switch, and audit log still apply.
The Stable tag is parsed as a dotted version and compared only when the
whole tag is a 2- to 4-part number. Likely vulnerable (high) only when that
version is parsed and is 3.5.6.2 or lower. 3.5.6.3 and later are not
detected. A JetFormBuilder readme with a missing or unparseable Stable tag
is unknown (info) and is not a guess. A 404, an HTML body, or a file that
is not this plugin's readme is not detected. A version mentioned only in
the changelog is ignored.

Never submits a form. Never requests the Media Field, an upload endpoint,
or wp-config.php. No POST, no request body, no exploit payload, no forged
header, and no malformed input.

Sources:
- Patchstack (known exploited, <= 3.5.6.2, patched 3.5.6.3, CVSS 7.5):
  https://patchstack.com/database/wordpress/plugin/jetformbuilder/vulnerability/wordpress-jetformbuilder-plugin-3-5-6-2-unauthenticated-arbitrary-file-read-via-media-field-vulnerability
- NVD CVE-2026-4373 (Wordfence CNA, <= 3.5.6.2, CVSS 7.5, CWE-36; record
  read from the NVD CVE 2.0 API on 24 November 2026):
  https://nvd.nist.gov/vuln/detail/CVE-2026-4373
- Wordfence (CNA, <= 3.5.6.2, patched 3.5.6.3):
  https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/jetformbuilder/jetformbuilder-3562-unauthenticated-arbitrary-file-read-via-media-field
- WPScan (fixed in 3.5.6.3):
  https://wpscan.com/vulnerability/173af602-6466-4caa-8bec-798e4a91bfe1/
- Plugin readme (Stable tag and the 3.5.6.3 changelog line):
  https://plugins.svn.wordpress.org/jetformbuilder/trunk/readme.txt
- Duggan USA (Patchstack exploited label; not CISA KEV):
  https://www.dugganusa.com/post/wordpress-plugins-flagged-exploited-ninja-forms-givewp-rtmedia-jetformbuilder
- CISA KEV catalog (CVE-2026-4373 absent on 24 November 2026):
  https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv
"""
import re

import recon

from .client import fetch_path
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt


README = "/wp-content/plugins/jetformbuilder/readme.txt"
_AFFECTED_THROUGH = (3, 5, 6, 2)
_FIXED = (3, 5, 6, 3)

_SOURCES = (
    "https://patchstack.com/database/wordpress/plugin/jetformbuilder/vulnerability/"
    "wordpress-jetformbuilder-plugin-3-5-6-2-unauthenticated-arbitrary-file-read-"
    "via-media-field-vulnerability",
    "https://nvd.nist.gov/vuln/detail/CVE-2026-4373",
    "https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/"
    "jetformbuilder/jetformbuilder-3562-unauthenticated-arbitrary-file-read-via-"
    "media-field",
    "https://wpscan.com/vulnerability/173af602-6466-4caa-8bec-798e4a91bfe1/",
    "https://plugins.svn.wordpress.org/jetformbuilder/trunk/readme.txt",
    "https://www.dugganusa.com/post/wordpress-plugins-flagged-exploited-ninja-"
    "forms-givewp-rtmedia-jetformbuilder",
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
)

# Line-anchored so a changelog heading cannot be read as the Stable tag.
# Two to four numeric parts: 3.5.6.2 must stay distinct from 3.5.6.3.
_STABLE = re.compile(r"(?im)^[ \t]*stable tag:[ \t]*(\d+(?:\.\d+){1,3})[ \t]*$")
_HEADER = re.compile(r"(?im)^===\s*.*\bjetformbuilder\b.*===\s*$")
_README_FIELDS = ("stable tag:", "contributors:", "requires at least:")


def _normalize(body: str) -> str:
    return (body or "").lstrip("\ufeff").replace("\r\n", "\n").replace("\r", "\n")


def _fix() -> str:
    return (
        "Update JetFormBuilder (jetformbuilder) to 3.5.6.3 or later "
        "(Plugins screen or `wp plugin update jetformbuilder`). Purge page, "
        "object, and CDN caches after updating. If an affected version was "
        "reachable, rotate secrets a file read could have exposed, including "
        f"the database password and salts in wp-config.php. See {CHECK.cve}."
    )


def _sources_note() -> str:
    return "Sources: " + "; ".join(_SOURCES) + "."


def _passive_note() -> str:
    return (
        "Only a read-only GET of the public plugin readme.txt was sent, with "
        "no request body. No form was submitted. The Media Field was not "
        "requested. No upload, POST, forged header, or malformed input was sent."
    )


def stable_tag(body: str) -> tuple[int, ...] | None:
    """Exact Stable tag, or None when the tag is missing or not a dotted version.

    The captured token is split directly. A shorter dotted matcher would drop
    the fourth part and could not tell 3.5.6.2 from 3.5.6.3.
    """
    match = _STABLE.search(_normalize(body))
    if not match:
        return None
    parts = tuple(int(part) for part in match.group(1).split("."))
    if len(parts) < 2 or len(parts) > 4:
        return None
    return parts


def is_plugin_readme(body: str) -> bool:
    """True when the body is a JetFormBuilder readme, not an HTML page."""
    text = _normalize(body)
    if recon.looks_like_app_html(text[:400]):
        return False
    if not _HEADER.search(text):
        return False
    low = text.lower()
    return any(field in low for field in _README_FIELDS)


def affected(version: tuple[int, ...]) -> bool:
    """True through 3.5.6.2 inclusive. 3.5.6.3 and later are patched."""
    if not version or len(version) > 4:
        return False
    return cmp_ver(version, _AFFECTED_THROUGH) <= 0


def _vulnerable(version: tuple[int, ...]) -> dict:
    label = fmt(version)
    return base_finding(
        CHECK,
        severity="high",
        title=(
            f"{UNCONFIRMED}: JetFormBuilder {label} <= {fmt(_AFFECTED_THROUGH)}, "
            f"likely vulnerable to {CHECK.cve}"
        ),
        evidence=(
            f"GET {README} Stable tag is {label}. {UNCONFIRMED}. "
            f"{label} is through {fmt(_AFFECTED_THROUGH)} and is likely "
            f"vulnerable to {CHECK.cve}: unauthenticated arbitrary file read "
            "through the Media Field (CWE-36, CVSS 7.5). Local files such as "
            "wp-config.php can be exposed when a form uses a Media Field and "
            "a Send Email action that attaches files. This check does not "
            f"confirm that configuration. Fixed in {fmt(_FIXED)}. "
            "Patchstack marks this known-exploited (Patchstack telemetry, "
            f"not CISA KEV). {_passive_note()} {_sources_note()}"
        ),
        fix=_fix(),
        match=f"jetformbuilder:{label}",
    )


def _unknown() -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=f"JetFormBuilder detected; version unknown ({CHECK.cve})",
        evidence=(
            f"GET {README} is a JetFormBuilder readme, but it has no parseable "
            f"Stable tag. Unknown: {CHECK.cve} was not compared (affected "
            f"through {fmt(_AFFECTED_THROUGH)}; fixed in {fmt(_FIXED)}). "
            f"Not a guess. {_passive_note()} {_sources_note()}"
        ),
        fix=_fix(),
        match="jetformbuilder:unknown",
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
    id="jetformbuilder",
    cve="CVE-2026-4373",
    agent="misconfig",
    fixed="3.5.6.3 (affected: JetFormBuilder through 3.5.6.2)",
    summary=(
        "One GET of the JetFormBuilder readme. High, version unconfirmed / "
        "likely vulnerable, when that file is the JetFormBuilder readme and "
        "the Stable tag is 3.5.6.2 or lower (fixed in 3.5.6.3; CWE-36, "
        "CVSS 7.5). Unauthenticated arbitrary file read through the Media "
        "Field. Patchstack known-exploited (Patchstack telemetry, not CISA "
        "KEV). Info (unknown) when the readme is JetFormBuilder but the "
        "Stable tag cannot be parsed. 3.5.6.3 and later, a missing file, "
        "and a non-plugin body are not detected. No version is guessed."
    ),
    sends=f"One GET of {README}. No request body.",
    does_not_send=(
        "Never submits a form. Never requests the Media Field, an upload "
        "endpoint, admin-ajax.php, a REST route, or wp-config.php. No POST, "
        "no request body, no exploit payload, no forged header, no upload, "
        "no auth attempt, no write, and no malformed input. Exactly one "
        "read-only GET of the plugin readme."
    ),
    run=run,
)
