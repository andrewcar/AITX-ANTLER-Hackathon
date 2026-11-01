"""
GitLab specialist agent: CVE-2026-97229 exposure (version fingerprint only).

CVE-2026-97229 is a CVSS 10.0 RCE in self-managed GitLab CE/EE: an integer overflow
in the Ruby/Onigmo regular-expression compiler, reached through a crafted regex in a
CI/CD configuration. GitLab fixed it in 19.2.8, 19.3.5 and 19.4.2 (critical patch
release, 2026-10-12). The advisory lists "all versions from 19.2 before 19.2.8, 19.3
before 19.3.5, and 19.4 before 19.4.2". CISA added it to KEV on 2026-10-29 (federal
due date 2026-11-01) because it is being actively exploited.

This agent is a CONFIRMATION check, not an exploit:
  - it reads only pages a GitLab server already serves to anonymous visitors:
    /users/sign_in (gon / version strings in the HTML), /-/manifest.json (product
    name), /api/v4/version (only if it answers WITHOUT a token) and /help;
  - every request is a plain GET through recon.get(), so it inherits the scope lock
    (off-allowlist redirects refused), the per-scan pace, the kill switch and the
    audit log. It also re-checks the allowlist itself before the first request;
  - it NEVER sends a regex, CI config or lint request, never creates a project,
    pipeline or account, never authenticates and never guesses credentials. At most
    four GETs.

A version match means "running a release GitLab lists as affected". It cannot see
hot-patches or a patched Ruby on a source install, and the finding says so.
"""
import json
import re

import audit
import control
import recon

CVE = "CVE-2026-97229"
# line -> first fixed patch release
FIXED = {(19, 2): 8, (19, 3): 5, (19, 4): 2}
FIRST_AFFECTED_LINE = (19, 2)
ADVISORY = "https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-4-2-released/"
KEV = "https://www.cisa.gov/news-events/alerts/2026/10/29/cisa-adds-two-known-exploited-vulnerabilities-catalog"
REFERENCES = [ADVISORY, KEV, "https://nvd.nist.gov/vuln/detail/CVE-2026-97229"]

SIGN_IN, MANIFEST, API_VERSION, HELP = "/users/sign_in", "/-/manifest.json", "/api/v4/version", "/help"
MAX_BYTES = 300_000

_SEMVER = r"v?(\d+)\.(\d+)\.(\d+)(?:-(?:ee|ce))?"
_GON_VER_RES = [
    re.compile(r"gon\.version\s*=\s*[\"']" + _SEMVER, re.I),
    re.compile(r"window\.gon\s*=\s*\{[^<]{0,20000}?[\"']version[\"']\s*:\s*[\"']" + _SEMVER, re.I),
]
_HELP_VER_RE = re.compile(
    r"GitLab\s+(?:Community|Enterprise)\s+Edition\s*(?:<[^>]+>\s*)*" + _SEMVER, re.I)
_GITLAB_HTML_MARKERS = (
    "window.gon", "gon.gitlab_url", "_gitlab_session",
    'content="gitlab"', "gitlab-logo", "data-testid=\"gitlab",
)

# confidence per evidence source: the API answer is the server's own structured claim;
# HTML strings can be stale templates or custom branding.
CONFIDENCE = {"api": "high", "help": "medium", "sign_in": "medium"}


def parse_version(text: str, where: str):
    """Pull (major, minor, patch) out of one evidence source, or None."""
    text = text or ""
    if where == "api":
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            return None
        v = data.get("version") if isinstance(data, dict) else None
        m = re.fullmatch(_SEMVER + r".*", str(v or "").strip(), re.I)
        return tuple(int(x) for x in m.groups()[:3]) if m else None
    regexes = [_HELP_VER_RE] if where == "help" else _GON_VER_RES
    for rx in regexes:
        m = rx.search(text)
        if m:
            return tuple(int(x) for x in m.groups()[:3])
    return None


def classify(ver):
    """Return (status, reason) for a GitLab version.

    status: "affected"  in a listed affected line and below its fix
            "outdated"  older than 19.2 -- outside CVE-2026-97229's listed range, but
                        unsupported and missing the 2026-10-12 security release
            "patched"   at/above the fix for its line, or a newer line
    """
    major, minor, patch = ver
    vs = f"{major}.{minor}.{patch}"
    line = (major, minor)
    if line in FIXED:
        fixed = FIXED[line]
        if patch < fixed:
            return "affected", f"GitLab {vs} is older than the fixed {major}.{minor}.{fixed}"
        return "patched", f"GitLab {vs} includes the {CVE} fix"
    if line < FIRST_AFFECTED_LINE:
        return "outdated", (f"GitLab {vs} predates the 19.2 line; GitLab's advisory lists {CVE} "
                            "from 19.2 only, but this release gets no fix for the other "
                            "2026-10-12 security issues")
    return "patched", f"GitLab {vs} is newer than the affected lines"


def looks_like_gitlab(sign_in: dict, manifest: dict) -> bool:
    """Evidence-based: GitLab's own markers in the pages it serves anonymously."""
    if manifest.get("status") == 200:
        try:
            data = json.loads(manifest.get("body") or "")
        except ValueError:
            data = None
        if isinstance(data, dict) and "gitlab" in str(data.get("name", "")).lower():
            return True
    if sign_in.get("status") == 200:
        low = (sign_in.get("body") or "").lower()
        return any(m in low for m in _GITLAB_HTML_MARKERS)
    return False


def _in_scope(base: str) -> bool:
    """Belt-and-braces scope check (the /scan gate already enforced it)."""
    import main  # lazy: main imports the orchestrator, which imports this agent
    try:
        main.allowlisted_host(base)
        return True
    except main.ScopeError:
        lease = control.current_lease()
        audit.record("request", run_id=getattr(lease, "run_id", ""),
                     target=getattr(lease, "target", ""), actor=getattr(lease, "actor", ""),
                     agent="gitlab_version", action="SCOPE_REFUSED", url=str(base)[:500],
                     status=0, detail="gitlab_version: target is off the allowlist; no request sent")
        return False


def _fix(ver) -> str:
    line = (ver[0], ver[1])
    target = (f"GitLab {ver[0]}.{ver[1]}.{FIXED[line]}" if line in FIXED
              else "a supported release (19.2.8+, 19.3.5+ or 19.4.2+)")
    return (f"Upgrade to {target} now, outside the normal patch cycle (source installs also "
            "need Ruby 3.3.13 / 3.4.12 / 4.0.9+). Until then turn off open sign-up, stop "
            "untrusted users creating or writing to public projects, restrict anonymous access, "
            "and hunt for Onigmo/CI-lint worker crashes. See docs/FIX_PLAYBOOK.md.")


def fingerprint(base: str, session=None) -> dict:
    """Read-only GitLab fingerprint. Returns {"gitlab": bool, "version", "where", "pages"}."""
    out = {"gitlab": False, "version": None, "where": None, "requests": []}

    def get(path):
        out["requests"].append(path)
        return recon.get(base + path, session, max_bytes=MAX_BYTES)

    sign_in = get(SIGN_IN)
    manifest = get(MANIFEST)
    if not looks_like_gitlab(sign_in, manifest):
        return out
    out["gitlab"] = True

    api = get(API_VERSION)  # anonymous; most instances answer 401 and that's fine
    if api.get("status") == 200:
        ver = parse_version(api.get("body"), "api")
        if ver:
            out.update(version=ver, where="api")
            return out
    if sign_in.get("status") == 200:
        ver = parse_version(sign_in.get("body"), "sign_in")
        if ver:
            out.update(version=ver, where="sign_in")
            return out
    help_page = get(HELP)
    if help_page.get("status") == 200:
        ver = parse_version(help_page.get("body"), "help")
        if ver:
            out.update(version=ver, where="help")
    return out


def run(section: dict, ctx) -> list[dict]:
    root = ctx.recon_root or {}
    base = (root.get("url", "") or getattr(ctx, "url", "") or "").rstrip("/")
    if not base or not _in_scope(base):
        return []

    fp = fingerprint(base, getattr(ctx, "session", None))
    if not fp["gitlab"]:
        return []  # not GitLab: nothing to say

    ver, where = fp["version"], fp["where"]
    if ver is None:
        return [{
            "layer": "runtime",
            "severity": "info",
            "title": "GitLab detected; version not exposed anonymously",
            "evidence": f"GitLab markers on {SIGN_IN} / {MANIFEST}, but no version string and "
                        f"{API_VERSION} needs a token. {CVE} exposure is UNKNOWN; check "
                        "Admin > Help (or `gitlab-rake gitlab:env:info`) against 19.2.8 / 19.3.5 / 19.4.2.",
            "fix": "Confirm the running version and upgrade if it is below the fix for its line. "
                   "See docs/FIX_PLAYBOOK.md.",
            "source": "deterministic",
            "references": REFERENCES,
            "check": {"type": "gitlab_detected"},
        }]

    status, reason = classify(ver)
    if status == "patched":
        return []
    vs = ".".join(map(str, ver))
    conf = CONFIDENCE[where]
    path = {"api": API_VERSION, "help": HELP, "sign_in": SIGN_IN}[where]
    evidence = (f"GET {path} reports GitLab {vs} (confidence: {conf}); {reason}. "
                "Version-based: no regex, CI config or pipeline was sent; "
                "hot-patches or a patched Ruby are invisible to this check.")
    if status == "affected":
        return [{
            "layer": "runtime",
            "severity": "critical" if conf == "high" else "high",
            "title": f"GitLab {vs} affected by {CVE} (CI regex RCE, CISA KEV)",
            "evidence": f"{evidence} CVSS 10.0; CISA KEV 2026-10-29, actively exploited.",
            "fix": _fix(ver),
            "source": "deterministic",
            "confidence": conf,
            "references": REFERENCES,
            "check": {"type": "gitlab_version", "where": where, "version": vs},
        }]
    return [{
        "layer": "runtime",
        "severity": "medium",
        "title": f"Unsupported GitLab {vs} (older than the 19.2 line)",
        "evidence": evidence,
        "fix": _fix(ver),
        "source": "deterministic",
        "confidence": conf,
        "references": REFERENCES,
        "check": {"type": "gitlab_version", "where": where, "version": vs},
    }]
