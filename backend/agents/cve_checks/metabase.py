"""Metabase (CVE-2026-72898, CVSS 10, KEV) — public version info only.

One GET of the public properties document. Critical when the version is below
the fixed release on one of the listed branches. The password-reset route is
never requested.
"""
import json

from .client import fetch_path
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, pad3, parse_dotted


PROPERTIES = "/api/session/properties"
FIXES = {
    (0, 58): (0, 58, 24),
    (0, 59): (0, 59, 21),
    (0, 60): (0, 60, 17),
    (0, 61): (0, 61, 11),
    (0, 62): (0, 62, 9),
    (0, 63): (0, 63, 5),
}


def parse_properties(body: str) -> tuple[bool, tuple[int, ...] | None]:
    """Return (is_metabase, version or None)."""
    try:
        obj = json.loads(body or "")
    except json.JSONDecodeError:
        return False, None
    if not isinstance(obj, dict):
        return False, None
    blob = body.lower()
    if (
        "metabase" not in blob
        and "setup-token" not in obj
        and "anon-tracking-enabled" not in obj
    ):
        return False, None
    raw = obj.get("version")
    if isinstance(raw, dict):
        tag = str(raw.get("tag") or raw.get("version") or "")
    else:
        tag = str(raw or "")
    tag = tag.strip().lstrip("vV")
    return True, parse_dotted(tag)


def affected(version: tuple[int, ...]) -> bool:
    if len(version) < 2:
        return False
    branch = (version[0], version[1])
    fixed = FIXES.get(branch)
    if fixed is None:
        return False
    return cmp_ver(pad3(version), fixed) < 0


def run(section, ctx) -> list[dict]:
    resp = fetch_path(ctx, PROPERTIES, max_bytes=65536)
    if resp.get("status") != 200:
        return []
    present, version = parse_properties(resp.get("body") or "")
    if not present:
        return []
    if version is None:
        return [base_finding(
            CHECK,
            severity="info",
            title=f"Metabase detected; version not exposed ({CHECK.cve})",
            evidence=(
                f"GET {PROPERTIES} looks like Metabase but did not include a "
                f"comparable version. {CHECK.cve} was not confirmed."
            ),
            fix=f"Upgrade to a fixed release on your branch. {CHECK.fixed}.",
            match="metabase:unknown",
        )]
    if not affected(version):
        return []
    label = fmt(pad3(version))
    branch = f"{version[0]}.{version[1]}"
    fixed = fmt(FIXES[(version[0], version[1])])
    return [base_finding(
        CHECK,
        severity="critical",
        title=f"{UNCONFIRMED}: Metabase {label} ({CHECK.cve})",
        evidence=(
            f"Observed Metabase {label} via GET {PROPERTIES}. {UNCONFIRMED}. "
            f"{label} is below {fixed} on the {branch} branch. "
            f"{CHECK.cve} (CVSS 10, KEV). Fixed versions: {CHECK.fixed}. "
            "No exploit payload was sent."
        ),
        fix=(
            f"Upgrade this Metabase branch to {fixed} or later. "
            f"{CHECK.cve} is listed in KEV."
        ),
        match=f"metabase:{label}",
    )]


CHECK = CveCheck(
    id="metabase",
    cve="CVE-2026-72898",
    agent="recon",
    fixed="0.58.24, 0.59.21, 0.60.17, 0.61.11, 0.62.9, 0.63.5 on those branches",
    summary=(
        "Read the version from Metabase's public properties document. Critical "
        "when it is below 0.58.24 / 0.59.21 / 0.60.17 / 0.61.11 / 0.62.9 / 0.63.5 "
        "on that branch."
    ),
    sends="One GET /api/session/properties.",
    does_not_send="Never requests the password-reset route. No POST, no session token, no exploit payload.",
    run=run,
)
