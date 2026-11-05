"""PHP2Shell (CVE-2026-109618 / CVE-2026-109619) — passive version fingerprint.

The root response was already fetched by recon. This check only reads
X-Powered-By, the Server header, or a ``PHP/x.y.z`` token already in that
response. It does not request phpinfo or send a body.
"""
import re

from .client import root_observation
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt


FIXES = {
    (8, 5): (8, 5, 12),
    (8, 4): (8, 4, 27),
    (8, 3): (8, 3, 36),
    (8, 2): (8, 2, 35),
}
EOL_BEFORE = (8, 2)
_PHP = re.compile(r"PHP/(\d+)\.(\d+)(?:\.(\d+))?", re.I)


def _version_in(text: str) -> tuple[int, int, int] | None:
    match = _PHP.search(text or "")
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3) or 0))


def observe(headers: dict, body: str) -> tuple[tuple[int, int, int], str] | None:
    for key in ("x-powered-by", "server"):
        found = _version_in(headers.get(key) or "")
        if found:
            return found, f"{key} header"
    found = _version_in(body or "")
    if found:
        return found, "response body"
    return None


def classify(version: tuple[int, ...]) -> str | None:
    """Reason string when the version appears vulnerable, else None."""
    major, minor, patch = (tuple(version) + (0, 0, 0))[:3]
    current = (major, minor, patch)
    branch = (major, minor)
    if branch in FIXES:
        fixed = FIXES[branch]
        if cmp_ver(current, fixed) < 0:
            return f"{fmt(current)} is below {fmt(fixed)} on the {major}.{minor} branch"
        return None
    if branch < EOL_BEFORE:
        return f"{fmt(current)} is on an EOL branch with no fixed release"
    return None


def run(section, ctx) -> list[dict]:
    headers, body = root_observation(ctx)
    seen = observe(headers, body)
    if not seen:
        return []
    version, where = seen
    reason = classify(version)
    if not reason:
        return []
    label = fmt(version)
    return [base_finding(
        CHECK,
        severity="critical",
        title=f"{UNCONFIRMED}: PHP {label} ({CHECK.cve})",
        evidence=(
            f"Observed PHP {label} via {where}. {UNCONFIRMED}. {reason}. "
            f"Advisories: {CHECK.cve}. Fixed versions: {CHECK.fixed}. "
            "No exploit payload was sent."
        ),
        fix=(
            "Upgrade PHP to the fixed release on this branch "
            "(8.5.12, 8.4.27, 8.3.36, or 8.2.35). EOL branches before 8.2 have "
            "no fixed release; move to a supported branch. "
            f"See {CHECK.cve}."
        ),
        match=f"php:{label}",
    )]


CHECK = CveCheck(
    id="php2shell",
    cve="CVE-2026-109618 / CVE-2026-109619",
    agent="misconfig",
    fixed="8.5.12 (8.5), 8.4.27 (8.4), 8.3.36 (8.3), 8.2.35 (8.2); branches before 8.2 are EOL",
    summary=(
        "Read the PHP version from X-Powered-By, the Server header, or a PHP/x.y.z "
        "token already in the root response. Critical when it is below the fixed "
        "release on its branch, or the branch is EOL."
    ),
    sends="No extra request. Uses the root response the scan already fetched.",
    does_not_send="No phpinfo request, no multipart body, no upload fields, no exploit payload.",
    run=run,
)
