"""Magento / Adobe Commerce PolyShell (CVE-2026-48356) — version fingerprint only.

A version at or after 2.4.9 is the APSB26-73 fix line. No other Magento path
is requested, and nothing that would look for a backdoor.
"""
import re

from .client import fetch_path, root_observation
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, pad3, parse_dotted


_VERSION = re.compile(
    r"(?:Magento|Adobe\s+Commerce)\s*/\s*v?(\d+\.\d+\.\d+)",
    re.I,
)
_MARKERS = ("text/x-magento-init", "x-magento-", "mage.cookies", "mage/cookies")
_FIX = (2, 4, 9)


def version_in(text: str) -> tuple[int, ...] | None:
    match = _VERSION.search(text or "")
    return parse_dotted(match.group(1)) if match else None


def markers_in(headers: dict, body: str) -> bool:
    blob = " ".join([
        body or "",
        " ".join(f"{key}: {value}" for key, value in (headers or {}).items()),
    ]).lower()
    return any(marker in blob for marker in _MARKERS)


def before_fix(version: tuple[int, ...]) -> bool:
    return cmp_ver(pad3(version), _FIX) < 0


def _critical(version: tuple[int, ...], where: str) -> dict:
    label = fmt(pad3(version))
    return base_finding(
        CHECK,
        severity="critical",
        title=f"{UNCONFIRMED}: Magento/Adobe Commerce {label} ({CHECK.cve})",
        evidence=(
            f"Observed Magento/Adobe Commerce {label} via {where}. {UNCONFIRMED}. "
            f"{label} is before 2.4.9. Advisory: {CHECK.cve} (APSB26-73). "
            "No exploit payload was sent."
        ),
        fix=(
            "Upgrade Adobe Commerce / Magento to 2.4.9 or later (APSB26-73). "
            f"See {CHECK.cve}."
        ),
        match=f"magento:{label}",
    )


def run(section, ctx) -> list[dict]:
    headers, body = root_observation(ctx)
    version = version_in(body) or version_in(" ".join(headers.values()))
    where = "root response"
    hinted = markers_in(headers, body) or version is not None
    if version is None:
        resp = fetch_path(ctx, "/magento_version", max_bytes=8192)
        text = resp.get("body") or ""
        if resp.get("status") == 200:
            version = version_in(text)
            if version:
                where = "/magento_version"
            elif "magento" in text.lower():
                hinted = True
    if version is not None:
        if before_fix(version):
            return [_critical(version, where)]
        return []
    if hinted:
        return [base_finding(
            CHECK,
            severity="info",
            title=f"Magento/Adobe Commerce detected; version not exposed ({CHECK.cve})",
            evidence=(
                "Magento/Adobe Commerce markers were present but no version was read. "
                f"{CHECK.cve} (APSB26-73) was not compared. No other path was requested."
            ),
            fix="Upgrade to 2.4.9 or later once the running version is confirmed (APSB26-73).",
            match="magento:unknown",
        )]
    return []


CHECK = CveCheck(
    id="magento-polyshell",
    cve="CVE-2026-48356",
    agent="recon",
    fixed="2.4.9 (APSB26-73)",
    summary=(
        "Fingerprint the Magento/Adobe Commerce version from the root response or "
        "one GET of /magento_version. Critical for versions before 2.4.9."
    ),
    sends="No request when the root response already includes the version. Otherwise one GET /magento_version.",
    does_not_send="No backdoor-path probing, no admin crawl, no exploit payload, no POST.",
    run=run,
)
