"""
PHP runtime specialist agent: PHP2Shell (CVE-2026-109618 / CVE-2026-109619) exposure.

PHP2Shell is a pair of unauthenticated RCE bugs in the PHP runtime itself, fixed in
PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35 on 2026-10-21 and added to CISA KEV on
2026-10-26. PHP 8.1 and earlier get no new release (source backports only).

This agent is a CONFIRMATION check, not an exploit:
  - it reads the PHP version the target already advertises (X-Powered-By on the
    root response, which recon already fetched) and, if /phpinfo.php is openly
    served, the version and the two settings the advisories name as mitigations;
  - it NEVER sends multipart bodies, PHP_SESSION_UPLOAD_PROGRESS fields, oversized
    requests or anything meant to push PHP out of memory. At most one extra GET.

A version match means "running a release PHP lists as affected", which is what the
evidence says; distro builds may carry backported fixes, and the finding says so.
"""
import re

import recon

# branch -> first fixed patch release
FIXED = {(8, 5): 12, (8, 4): 27, (8, 3): 36, (8, 2): 35}
CVES = "CVE-2026-109618 / CVE-2026-109619"
ADVISORY = "https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching"

_VER_RE = re.compile(r"php/?\s*(\d+)\.(\d+)\.(\d+)", re.I)
_INFO_VER_RE = re.compile(r"PHP Version\s*(?:</[^>]+>\s*<[^>]+>\s*)?(\d+)\.(\d+)\.(\d+)", re.I)
_UPLOAD_PROGRESS_RE = re.compile(
    r"session\.upload_progress\.enabled\s*(?:</td>\s*<td[^>]*>)?\s*(On|Off|1|0)", re.I)


def parse_version(text: str, phpinfo: bool = False):
    m = (_INFO_VER_RE if phpinfo else _VER_RE).search(text or "")
    return tuple(int(x) for x in m.groups()) if m else None


def classify(ver):
    """Return (affected, reason) for a (major, minor, patch) PHP version."""
    major, minor, patch = ver
    vs = f"{major}.{minor}.{patch}"
    if (major, minor) in FIXED:
        fixed = FIXED[(major, minor)]
        if patch < fixed:
            return True, f"PHP {vs} is older than the fixed {major}.{minor}.{fixed}"
        return False, f"PHP {vs} includes the PHP2Shell fix"
    if (major, minor) < (8, 2):
        return True, (f"PHP {vs} is end-of-life; PHP ships no fixed release for it "
                      "(source backports only)")
    return False, f"PHP {vs} is newer than the affected branches"


def upload_progress_on(phpinfo_body: str):
    m = _UPLOAD_PROGRESS_RE.search(phpinfo_body or "")
    if not m:
        return None
    return m.group(1).lower() in ("on", "1")


def _fix(ver) -> str:
    branch = (ver[0], ver[1])
    target = (f"PHP {ver[0]}.{ver[1]}.{FIXED[branch]}" if branch in FIXED
              else "a supported branch (8.2.35+, 8.3.36+, 8.4.27+ or 8.5.12+), or apply the published backport")
    return (f"Upgrade to {target} and restart every PHP worker. Until then set "
            "session.upload_progress.enabled=0 and an admin-level memory_limit per the PHP "
            "advisory, and stop advertising the version (expose_php=Off). See docs/FIX_PLAYBOOK.md.")


def run(section: dict, ctx) -> list[dict]:
    root = ctx.recon_root or {}
    base = (root.get("url", "") or "").rstrip("/")
    powered = (root.get("raw_headers", {}) or {}).get("x-powered-by", "")
    findings: list[dict] = []

    ver, where, info_body = parse_version(powered), "header", ""
    if base:
        # one GET; only counts if it is really phpinfo (catch-all apps return 200 for anything)
        r = recon.get(base + "/phpinfo.php", getattr(ctx, "session", None), max_bytes=120_000)
        if r["status"] == 200 and "PHP Version" in r.get("body", ""):
            info_body = r["body"]
            if ver is None:
                ver, where = parse_version(info_body, phpinfo=True), "phpinfo"

    if ver is None:
        return findings

    affected, reason = classify(ver)
    vs = ".".join(map(str, ver))
    evidence = (f"X-Powered-By: {powered}" if where == "header"
                else f"GET /phpinfo.php reports PHP Version {vs}")
    if affected:
        findings.append({
            "layer": "runtime",
            "severity": "high",
            "title": f"PHP2Shell-affected PHP runtime ({vs})",
            "evidence": f"{evidence}; {reason} ({CVES}, CISA KEV 2026-10-26). "
                        "Version-based: no exploit traffic was sent; distro builds may carry backports.",
            "fix": _fix(ver),
            "source": "deterministic",
            "references": [ADVISORY],
            "check": {"type": "php2shell_version", "where": where, "version": vs},
        })

    if info_body and upload_progress_on(info_body):
        findings.append({
            "layer": "runtime",
            "severity": "medium",
            "title": "PHP session.upload_progress enabled (PHP2Shell mitigation not applied)",
            "evidence": "GET /phpinfo.php shows session.upload_progress.enabled = On",
            "fix": "Set session.upload_progress.enabled=0 in php.ini or the FPM pool (not .user.ini "
                   "or ini_set) and restart workers; keep it off after patching (also covers "
                   "CVE-2026-115560). See docs/FIX_PLAYBOOK.md.",
            "source": "deterministic",
            "references": [ADVISORY],
            "check": {"type": "php_upload_progress"},
        })
    return findings
