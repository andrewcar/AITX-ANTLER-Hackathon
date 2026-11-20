"""PHP November 2026 security release — passive version fingerprint.

Sibling of ``php2shell``: reuses that module's passive ``PHP/x.y.z`` read from
the already-fetched root response (X-Powered-By, Server, or body token). Does
not change php2shell's CVEs, floors, findings, or tests.

Advisories in the 19 November 2026 release include critical
CVE-2026-129289 (PHP-FPM request smuggling RCE, CVSS 9.2),
CVE-2026-115560 (session serializer mismatch RCE),
CVE-2026-126714 (partially overwritten session file RCE),
CVE-2026-129474 (magic-method backtrace UAF),
CVE-2026-129496 (timezone cache UAF), plus
CVE-2026-129182 / CVE-2026-129481 / CVE-2026-128090 (PHAR signature
downgrade and related shutdown/session UAFs). Fixed floors:
8.5.13 / 8.4.28 / 8.3.37 / 8.2.36; 8.6.0 (released the same day) includes
the fixes. Branches 8.1 and older are EOL (no upstream fix; third-party
backports may exist).

Critical issues need non-default / uncommon setups (PHP-FPM backend
connection reuse for 129289; session.upload_progress for 115560). No
in-the-wild exploitation reported; not in CISA KEV as of 2026-11-20.

Detection is passive only and UNCONFIRMED (config-dependent). Zero extra
HTTP calls. Never sends phpinfo, session cookies, upload-progress
multipart bodies, request-smuggling / pipelined / unread-body probes, PHAR
or FastCGI traffic, or direct FPM port connections.
"""
import control

from .client import root_observation
from .php2shell import observe
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt


FIXES = {
    (8, 6): (8, 6, 0),
    (8, 5): (8, 5, 13),
    (8, 4): (8, 4, 28),
    (8, 3): (8, 3, 37),
    (8, 2): (8, 2, 36),
}
EOL_BEFORE = (8, 2)

_CVE_LIST = (
    "CVE-2026-129289",
    "CVE-2026-115560",
    "CVE-2026-126714",
    "CVE-2026-129474",
    "CVE-2026-129496",
    "CVE-2026-129182",
    "CVE-2026-129481",
    "CVE-2026-128090",
)
_CVE_TEXT = " / ".join(_CVE_LIST)

_SOURCES = (
    "https://www.bleepingcomputer.com/news/security/php-security-updates-fix-"
    "18-flaws-including-critical-rce-bugs/",
    "https://access.redhat.com/security/vulnerabilities/RHSB-2026-020",
    "https://labs.beazley.security/advisories/BSL-A1250",
    "https://digital.nhs.uk/cyber-alerts/2026/cc-4900",
    "https://www.php.net/ChangeLog-8.php",
)


def _sources_note() -> str:
    return "Sources: " + "; ".join(_SOURCES) + "."


def classify(version: tuple[int, ...]) -> str | None:
    """Reason string when the Nov 2026 floors say outdated, else None."""
    major, minor, patch = (tuple(version) + (0, 0, 0))[:3]
    current = (major, minor, patch)
    branch = (major, minor)
    if branch in FIXES:
        fixed = FIXES[branch]
        if cmp_ver(current, fixed) < 0:
            return f"{fmt(current)} is below {fmt(fixed)} on the {major}.{minor} branch"
        return None
    if branch < EOL_BEFORE:
        return (
            f"{fmt(current)} is on an EOL branch (8.1 and older) with no "
            "upstream fixed release (third-party backports may exist)"
        )
    return None


def _fix() -> str:
    return (
        "Upgrade PHP to a fixed release on this branch (8.5.13, 8.4.28, "
        "8.3.37, 8.2.36, or 8.6.0+). EOL branches before 8.2 have no upstream "
        "fix — move to a supported branch (third-party backports may exist). "
        "Until then: set session.upload_progress.enabled=0 and disable "
        "persistent FPM backend connection reuse. "
        f"See {_CVE_TEXT}. {_sources_note()}"
    )


def run(section, ctx) -> list[dict]:
    # Honor the scan kill switch even though this check never opens HTTP.
    if control.stopped():
        return []
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
        severity="high",
        title=f"{UNCONFIRMED}: PHP {label} ({CHECK.cve})",
        evidence=(
            f"Observed PHP {label} via {where}. {UNCONFIRMED}. {reason}. "
            f"November 2026 PHP security release advisories: {_CVE_TEXT} "
            "(critical CVE-2026-129289 PHP-FPM request-smuggling RCE CVSS 9.2; "
            "CVE-2026-115560 session serializer mismatch RCE; "
            "CVE-2026-126714 partially overwritten session file RCE; "
            "CVE-2026-129474 magic-method backtrace UAF; "
            "CVE-2026-129496 timezone cache UAF; plus "
            "CVE-2026-129182 / CVE-2026-129481 / CVE-2026-128090 PHAR "
            "signature downgrade and related). Fixed versions: "
            f"{CHECK.fixed}. Released 2026-11-19. Critical issues need "
            "non-default/uncommon setups (PHP-FPM backend connection reuse "
            "for 129289; session.upload_progress for 115560), so this hit is "
            "config-dependent and unconfirmed. No in-the-wild exploitation "
            "reported; not in CISA KEV as of 2026-11-20. Only the already-"
            "fetched root response was read; no extra request, phpinfo, "
            "session cookie, upload-progress multipart, request-smuggling / "
            "pipelined / unread-body probe, PHAR or FastCGI traffic, or "
            f"direct FPM port connection was sent. {_sources_note()}"
        ),
        fix=_fix(),
        match=f"php-nov2026:{label}",
    )]


CHECK = CveCheck(
    id="php-nov2026",
    cve=_CVE_TEXT,
    agent="misconfig",
    fixed=(
        "8.5.13 (8.5), 8.4.28 (8.4), 8.3.37 (8.3), 8.2.36 (8.2), "
        "8.6.0+ (8.6 includes the fixes); branches before 8.2 are EOL"
    ),
    summary=(
        "Reuse php2shell's passive PHP/x.y.z read from the root response "
        "(X-Powered-By, Server, or body token). High, version unconfirmed / "
        "config-dependent, when below 8.5.13 / 8.4.28 / 8.3.37 / 8.2.36 on "
        "that branch, or the branch is EOL (8.1 and older). 8.6.0+ is fixed. "
        "Lists CVE-2026-129289 and sibling Nov 2026 advisories. Zero extra "
        "HTTP calls."
    ),
    sends=(
        "No extra request. Uses the root response the scan already fetched "
        "(same passive read as php2shell)."
    ),
    does_not_send=(
        "No phpinfo request, no session cookies, no upload-progress multipart, "
        "no request-smuggling / pipelined / unread-body probes, no PHAR or "
        "FastCGI traffic, no direct FPM port connection, no exploit payload."
    ),
    run=run,
)
