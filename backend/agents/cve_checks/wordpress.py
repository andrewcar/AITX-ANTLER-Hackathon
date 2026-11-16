"""WordPress core (CVE-2026-119977, CISA KEV) — passive version + listing read.

Detection only. Version comes from the already-fetched homepage generator meta
tag, or one GET of /feed/ (then /?feed=rss2). Each branch has its own fixed
floor; a backport such as 6.8.12 is not treated as vulnerable just because it
is below 7.1.4. One optional GET of /wp-content/upgrade/ looks for a clear
directory listing. Staged installer paths are never requested.
"""
import re

from .client import fetch_path, root_observation
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, pad3, parse_dotted


# Branch (major, minor) -> first fixed release on that branch.
# Sources: Wordfence advisory, WordPress 7.1.4 release notes / backports,
# GHSA-4w3m-c66w-69mg / NVD affected ranges (4.7.0 through 7.1.3).
FIXED = {
    (7, 1): (7, 1, 4),
    (7, 0): (7, 0, 8),
    (6, 9): (6, 9, 11),
    (6, 8): (6, 8, 12),
    (6, 7): (6, 7, 11),
    (6, 6): (6, 6, 11),
    (6, 5): (6, 5, 14),
    (6, 4): (6, 4, 14),
    (6, 3): (6, 3, 14),
    (6, 2): (6, 2, 15),
    (6, 1): (6, 1, 16),
    (6, 0): (6, 0, 18),
    (5, 9): (5, 9, 20),
    (5, 8): (5, 8, 19),
    (5, 7): (5, 7, 21),
    (5, 6): (5, 6, 23),
    (5, 5): (5, 5, 24),
    (5, 4): (5, 4, 25),
    (5, 3): (5, 3, 27),
    (5, 2): (5, 2, 30),
    (5, 1): (5, 1, 28),
    (5, 0): (5, 0, 31),
    (4, 9): (4, 9, 35),
    (4, 8): (4, 8, 34),
    (4, 7): (4, 7, 39),
}
_AFFECTED_LOW = (4, 7, 0)
_AFFECTED_HIGH = (7, 1, 3)

_GENERATOR = re.compile(
    r"<meta[^>]*\bname\s*=\s*['\"]generator['\"][^>]*\bcontent\s*=\s*['\"]WordPress\s+(\d+\.\d+(?:\.\d+)?)['\"]",
    re.I,
)
_GENERATOR_REV = re.compile(
    r"<meta[^>]*\bcontent\s*=\s*['\"]WordPress\s+(\d+\.\d+(?:\.\d+)?)['\"][^>]*\bname\s*=\s*['\"]generator['\"]",
    re.I,
)
_FEED_GENERATOR = re.compile(
    r"<generator[^>]*>[^<]*?[?&]v=(\d+\.\d+(?:\.\d+)?)[^<]*</generator>",
    re.I,
)
def is_vulnerable(version: tuple[int, ...]) -> bool:
    """True when the release is below its branch's fixed floor."""
    current = pad3(version)
    if current < _AFFECTED_LOW:
        return False
    branch = (current[0], current[1])
    fixed = FIXED.get(branch)
    if fixed is not None:
        return cmp_ver(current, fixed) < 0
    # Newer branch outside the advisory table (for example 7.2+).
    return current <= _AFFECTED_HIGH


def fixed_for(version: tuple[int, ...]) -> str:
    current = pad3(version)
    fixed = FIXED.get((current[0], current[1]))
    if fixed:
        return fmt(fixed)
    return "7.1.4 (or the fixed release for this branch)"


def version_from_html(body: str) -> tuple[tuple[int, ...] | None, str]:
    for pattern in (_GENERATOR, _GENERATOR_REV):
        match = pattern.search(body or "")
        if match:
            return parse_dotted(match.group(1)), "generator meta tag"
    return None, ""


def version_from_feed(body: str) -> tuple[int, ...] | None:
    match = _FEED_GENERATOR.search(body or "")
    return parse_dotted(match.group(1)) if match else None


def looks_like_directory_listing(status: int, body: str) -> bool:
    if status != 200:
        return False
    low = (body or "").lower()
    if any(marker in low for marker in ("index of", "directory listing for")):
        return True
    return "parent directory" in low and "<a href" in low


def _version_finding(version: tuple[int, ...], where: str) -> dict:
    label = fmt(pad3(version))
    floor = fixed_for(version)
    return base_finding(
        CHECK,
        severity="critical",
        title=f"{UNCONFIRMED}: WordPress {label} ({CHECK.cve})",
        evidence=(
            f"Observed WordPress {label} via {where}. {UNCONFIRMED}. "
            f"{CHECK.cve} (CISA KEV) is a TOCTOU race in full-package core "
            f"upgrades; this branch's fixed floor is {floor}. "
            "Detection compared the published version only. "
            "No exploit payload, upgrade request, or staged installer was sent."
        ),
        fix=(
            f"Upgrade WordPress to {floor} or later on this branch "
            f"(7.1.4 on the current line). Deny web access to "
            f"/wp-content/upgrade/ at the web server before updating. "
            f"See {CHECK.cve}."
        ),
        match=f"wordpress:{label}",
    )


def _listing_finding() -> dict:
    return base_finding(
        CHECK,
        severity="medium",
        title="WordPress upgrade staging directory may be web-listable",
        evidence=(
            "GET /wp-content/upgrade/ returned HTTP 200 with an index-of style "
            "directory listing. That path is where core upgrades stage packages; "
            "a listable staging area is a misconfiguration worth closing. "
            "Detection requested the directory index only — no recursion into "
            "staging folders and no installer PHP was requested."
        ),
        fix=(
            "Deny HTTP access to /wp-content/upgrade/ in the web server config "
            "(for example nginx `deny all` or Apache RedirectMatch 403), then "
            "upgrade WordPress to the fixed release for your branch."
        ),
        match="wordpress:upgrade-listing",
    )


def _observe_version(ctx, body: str) -> tuple[tuple[int, ...] | None, str]:
    version, where = version_from_html(body)
    if version is not None:
        return version, where
    for path in ("/feed/", "/?feed=rss2"):
        resp = fetch_path(ctx, path, max_bytes=65536)
        if resp.get("status") != 200:
            continue
        version = version_from_feed(resp.get("body") or "")
        if version is not None:
            return version, f"GET {path}"
    return None, ""


def run(section, ctx) -> list[dict]:
    _headers, body = root_observation(ctx)
    findings: list[dict] = []
    version, where = _observe_version(ctx, body)
    wordpress_seen = version is not None
    if version is not None and is_vulnerable(version):
        findings.append(_version_finding(version, where))

    # Complementary misconfig: only when WordPress was identified, one GET of
    # the upgrade directory index. Never recurse or fetch installer scripts.
    if wordpress_seen:
        listing = fetch_path(ctx, "/wp-content/upgrade/", max_bytes=65536)
        if looks_like_directory_listing(
            int(listing.get("status") or 0),
            listing.get("body") or "",
        ):
            findings.append(_listing_finding())
    return findings


CHECK = CveCheck(
    id="wordpress-core",
    cve="CVE-2026-119977",
    agent="misconfig",
    fixed=(
        "branch floors: 7.1.4, 7.0.8, 6.9.11, 6.8.12, 6.7.11, 6.6.11, 6.5.14, "
        "6.4.14, 6.3.14, 6.2.15, 6.1.16, 6.0.18, 5.9.20, 5.8.19, 5.7.21, 5.6.23, "
        "5.5.24, 5.4.25, 5.3.27, 5.2.30, 5.1.28, 5.0.31, 4.9.35, 4.8.34, 4.7.39"
    ),
    summary=(
        "Read the WordPress version from the generator meta tag on the already-"
        "fetched homepage, else one GET /feed/ or /?feed=rss2. Critical when "
        "the release is below that branch's fixed floor for CVE-2026-119977 "
        "(affected 4.7 through 7.1.3). Optional GET /wp-content/upgrade/ notes "
        "a clear directory listing as medium."
    ),
    sends=(
        "No request when the homepage generator already shows the version. "
        "Otherwise GET /feed/ or /?feed=rss2. When WordPress is identified, "
        "one GET /wp-content/upgrade/ for a directory index only."
    ),
    does_not_send=(
        "No exploit payload, no crafted upgrade or update-core request, no POST, "
        "no upload, no traversal into staged packages, no installer PHP "
        "(setup-config.php / install.php), no recursion under wp-content/upgrade/."
    ),
    run=run,
)
