"""REDCap public-survey code injection RCE (CVE-2026-90817) — passive version fingerprint.

Unauthenticated RCE via survey passthrough routing combined with Data Import
handling that accepts a crafted file-path/stream parameter. Exploitation needs
a valid public survey hash (the ``s=`` value in public survey links). Affected
from 13.3.0; fixed in 16.0.49 LTS, 17.3.10 LTS, and 17.4.4 Standard. Exploited
in the wild (Unit 42 crypto-miner campaign 7 October 2026) and listed in CISA
KEV (added 2026-11-18, due 2026-11-21).

Detection is passive only: REDCap serves assets from a versioned
``redcap_v<version>/`` directory, so already-crawled HTML/links contain that
marker. Gate on the marker, parse the version, and flag Critical (KEV) when
the build is in range. No marker yields no finding. Risk still depends on
public surveys being published, which this check does not confirm.

Never requests ``/surveys/`` (no ``s=`` hashes), DataImport*, ``/api/``,
Control Center, ``plugins/``, ``redcap_v*/`` routes, or login. No extra GET at
all; no payloads, no file paths, no malformed input.
"""
import re

import control

from .client import root_observation
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, pad3, parse_dotted


_AFFECTED_FROM = (13, 3, 0)
_FIXED_16_0 = (16, 0, 49)
_FIXED_17_3 = (17, 3, 10)
_FIXED_17_4 = (17, 4, 4)

_SOURCES = (
    "https://www.cisa.gov/news-events/alerts/2026/11/18/"
    "cisa-adds-four-known-exploited-vulnerabilities-catalog",
    "https://app.opencve.io/cve/CVE-2026-90817",
    "https://cve.socradar.com/cve/CVE-2026-90817",
    "https://www.rescana.com/post/redcap-cve-2026-90817-public-survey-rce-patch-now",
)

# Verified on live REDCap pages (e.g. redcapdemo.vumc.org / redcap.vanderbilt.edu):
# asset URLs like /redcap_v17.5.3/Resources/images/favicon.ico
_REDCAP_V = re.compile(r"redcap_v(\d+\.\d+(?:\.\d+){0,2})(?:/|\b)", re.I)


def _sources_note() -> str:
    return "Sources: " + "; ".join(_SOURCES) + "."


def _fix() -> str:
    return (
        "Upgrade REDCap to 16.0.49 LTS, 17.3.10 LTS, or 17.4.4 Standard (or "
        "later on the same line). Remove older redcap_v* directories that remain "
        "web-reachable. Review whether public surveys are published; treat "
        "internet-facing instances with public survey links as meeting the "
        f"hash precondition. See {CHECK.cve} (CISA KEV). {_sources_note()}"
    )


def version_in(text: str) -> tuple[int, ...] | None:
    """First ``redcap_vX.Y[.Z]`` version from crawled HTML/links, or None."""
    match = _REDCAP_V.search(text or "")
    if not match:
        return None
    return parse_dotted(match.group(1))


def affected(version: tuple[int, ...]) -> bool:
    """True for affected REDCap builds of CVE-2026-90817.

    Range: ``13.3.0 <= v < 16.0.49`` (including intermediate lines with no
    own-line fix); ``16.1``–``17.3.x`` when ``v < 17.3.10``; ``17.4.x`` when
    ``v < 17.4.4``. ``16.0.49+``, ``17.3.10+``, and ``>= 17.4.4`` are safe.
    Builds before ``13.3.0`` are not affected.
    """
    current = pad3(version)
    if cmp_ver(current, _AFFECTED_FROM) < 0:
        return False
    # 13.3.0 through anything below 16.0.49 (14.x, 15.x, 16.0.0–16.0.48).
    if cmp_ver(current, _FIXED_16_0) < 0:
        return True
    # 16.0.49+ on the 16.0 LTS line is fixed.
    if current[0] == 16 and current[1] == 0:
        return False
    # 16.1 through 17.3.x below 17.3.10.
    if cmp_ver(current, _FIXED_17_3) < 0:
        return True
    # 17.3.10+ on the 17.3 LTS line is fixed.
    if current[0] == 17 and current[1] == 3:
        return False
    # 17.4.x below 17.4.4; 17.5+ / 18+ are safe (>= 17.4.4).
    return cmp_ver(current, _FIXED_17_4) < 0


def _critical(version: tuple[int, ...]) -> dict:
    label = fmt(pad3(version))
    return base_finding(
        CHECK,
        severity="critical",
        title=f"{UNCONFIRMED}: REDCap {label} ({CHECK.cve})",
        evidence=(
            f"Observed REDCap {label} via redcap_v{label}/ in already-crawled "
            f"HTML/links. {UNCONFIRMED}. Affected: REDCap >= 13.3.0 below "
            f"16.0.49 LTS / 17.3.10 LTS / 17.4.4 Standard (lines between 13.3 "
            f"and 16.0 have no own-line fix). Fixed in 16.0.49, 17.3.10, and "
            f"17.4.4. {CHECK.cve}: unauthenticated RCE via survey passthrough "
            "routing and Data Import with a crafted file-path/stream param "
            "(needs a valid public survey hash). Exploited per CISA KEV "
            "(added 2026-11-18, due 2026-11-21); Unit 42 reported crypto-miner "
            "exploitation on 7 October 2026. Risk depends on public surveys "
            "being published, which this check does not confirm. Only a "
            "passive read of already-crawled HTML was used; no /surveys/, "
            "DataImport, /api/, Control Center, plugins/, redcap_v* route, "
            f"login, payload, or extra GET was sent. {_sources_note()}"
        ),
        fix=_fix(),
        match=f"redcap:{label}",
    )


def run(section, ctx) -> list[dict]:
    # Honor the scan kill switch even though this check never opens HTTP.
    if control.stopped():
        return []
    _headers, body = root_observation(ctx)
    version = version_in(body)
    if version is None:
        return []
    if affected(version):
        return [_critical(version)]
    return []


CHECK = CveCheck(
    id="redcap",
    cve="CVE-2026-90817",
    agent="recon",
    fixed="16.0.49 LTS / 17.3.10 LTS / 17.4.4 Standard (affected: >=13.3.0 below those floors)",
    summary=(
        "Parse redcap_v<version>/ from already-crawled HTML/links (REDCap "
        "serves assets from that versioned directory). Critical, version "
        "unconfirmed / KEV, when 13.3.0 <= v < 16.0.49, or 16.1–17.3.x with "
        "v < 17.3.10, or 17.4.x with v < 17.4.4. Notes that risk depends on "
        "public surveys being published. No marker yields no finding. Zero "
        "extra HTTP calls."
    ),
    sends=(
        "Nothing. Reads only already-crawled HTML for a redcap_v<version>/ "
        "marker. No extra GET."
    ),
    does_not_send=(
        "Never requests /surveys/ (no s= hashes), DataImport*, /api/, Control "
        "Center, plugins/, redcap_v*/ routes, or login. No POST/PUT/DELETE, "
        "no payloads, no file paths, no malformed input, and no extra GET."
    ),
    run=run,
)
