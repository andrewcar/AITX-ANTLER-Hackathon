"""Bricksforge (CVE-2026-85097) — passive plugin version read.

Bricksforge (WordPress premium add-on for the Bricks builder, slug
``bricksforge``) through 3.1.8.9 has an unauthenticated arbitrary file upload
leading to remote code execution: Pro Forms trusts unvalidated
``temporaryFileUploads`` URL metadata after a MIME-checked temp upload. Affected
<=3.1.8.9. Fixed in 3.1.8.10 (also 4.0.0+); 4.0.1 recommended (related Pro Forms
upload hardening, 8 October 2026). Patchstack marks known-exploited (telemetry
since 7 October 2026; not CISA KEV). CVSS 10 (Patchstack) / 9.8 (CNA).

Detection is passive only: confirm WordPress from the already-fetched root
response, parse crawled HTML for ``/wp-content/plugins/bricksforge/`` asset URLs
with ``?ver=``, and when the version is still unknown, at most two read-only
GETs of public static version files (``readme.txt``, then ``changelog.txt``).

Never POSTs to ``/wp-json/bricksforge/v1/form_submit``, never calls admin-ajax
(``bricksforge_regenerate_nonce``, ``bricksforge_form_submit``), never sends
nonce requests, ``temporaryFileUploads`` parameters, uploads, polyglot files,
requests to ``/wp-content/uploads/bricksforge/tmp/``, writes, malformed input,
or anything to ``/wp-admin``.
"""
import re

import recon

from .client import fetch_path, root_observation
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, parse_dotted


README = "/wp-content/plugins/bricksforge/readme.txt"
CHANGELOG = "/wp-content/plugins/bricksforge/changelog.txt"
_AFFECTED_THROUGH = (3, 1, 8, 9)
_FIXED_MIN = "3.1.8.10"
_RECOMMENDED = "4.0.1"

_SOURCES = (
    "https://patchstack.com/articles/critical-unauthenticated-arbitrary-file-"
    "upload-vulnerability-exploited-in-bricksforge-plugin/",
    "https://thehackernews.com/2026/10/attackers-exploit-cvss-100-bricksforge.html",
    "https://euvd.enisa.europa.eu/vulnerability/EUVD-2026-94793",
    "https://bricksforge.io/version-changelog/",
)

_STABLE = re.compile(r"(?im)^[ \t]*stable tag:[ \t]*(\d+(?:\.\d+){0,3})[ \t]*$")
_HEADER = re.compile(r"(?im)^===\s*.*\bbricksforge\b.*===\s*$")
_CHANGELOG_SECTION = re.compile(r"(?im)^==[ \t]*changelog[ \t]*==[ \t]*$")
_CHANGELOG_EQ = re.compile(r"(?im)^=[ \t]*(\d+(?:\.\d+){0,3})[ \t]*=[ \t]*$")
_CHANGELOG_MD = re.compile(
    r"(?im)^[ \t]*#{1,4}[ \t]+(\d+(?:\.\d+){0,3})[ \t]*(?:\([^)]*\)|[|][^\n]*)?[ \t]*$",
)
_README_FIELDS = ("stable tag:", "contributors:", "requires at least:")
_NAME_MARKERS = (
    "bricksforge",
    "bricks forge",
)
_ASSET = re.compile(
    r"/wp-content/plugins/bricksforge/[^\"'\s>]*",
    re.I,
)
_VER = re.compile(r"[?&]ver=(\d+(?:\.\d+){0,3})", re.I)
_WP_GENERATOR = re.compile(
    r"<meta[^>]*\bcontent\s*=\s*['\"]WordPress\b",
    re.I,
)
_WP_PATH = re.compile(
    r"/wp-(?:content|includes|admin|json|login\.php|cron\.php)\b",
    re.I,
)
_WP_LINK = re.compile(r"""rel=["']https://api\.w\.org/["']""", re.I)


def _fix() -> str:
    return (
        f"Update Bricksforge to {_RECOMMENDED} or later (minimum {_FIXED_MIN}; "
        f"{_RECOMMENDED} recommended for related Pro Forms upload hardening). "
        "Check wp-content/uploads/bricksforge/tmp/ and other uploads directories "
        "for unexpected PHP files. Purge page, object, and CDN caches after "
        f"updating. Rotate credentials if compromise is suspected. See "
        f"{CHECK.cve}."
    )


def _sources_note() -> str:
    return "Sources: " + "; ".join(_SOURCES) + "."


def looks_like_wordpress(headers: dict, body: str) -> bool:
    """True when the already-fetched root response shows WordPress markers."""
    text = body or ""
    if _WP_GENERATOR.search(text):
        return True
    if _WP_PATH.search(text) or _WP_LINK.search(text):
        return True
    if "wordpress" in text.lower() and (
        "wp-content" in text.lower() or "wp-includes" in text.lower()
    ):
        return True
    link = (headers or {}).get("link") or ""
    if "api.w.org" in link.lower():
        return True
    pingback = (headers or {}).get("x-pingback") or ""
    if "xmlrpc.php" in pingback.lower():
        return True
    return False


def affected(version: tuple[int, ...]) -> bool:
    """True for versions through 3.1.8.9 inclusive. 3.1.8.10+ / 4.0.0+ are fixed."""
    return cmp_ver(version, _AFFECTED_THROUGH) <= 0


def stable_tag(body: str) -> tuple[int, ...] | None:
    match = _STABLE.search(body or "")
    return parse_dotted(match.group(1)) if match else None


def changelog_version(body: str) -> tuple[int, ...] | None:
    """Newest dotted version from a readme changelog section or markdown file."""
    text = body or ""
    head = _CHANGELOG_SECTION.search(text)
    if head:
        match = _CHANGELOG_EQ.search(text, head.end())
        if match:
            return parse_dotted(match.group(1))
    match = _CHANGELOG_MD.search(text)
    return parse_dotted(match.group(1)) if match else None


def plugin_version(body: str) -> tuple[tuple[int, ...] | None, str]:
    """Prefer Stable tag; fall back to a changelog heading version."""
    version = stable_tag(body)
    if version is not None:
        return version, "Stable tag"
    version = changelog_version(body)
    if version is not None:
        return version, "changelog version"
    return None, ""


def is_plugin_readme(body: str) -> bool:
    """True when the body looks like a Bricksforge plugin readme, not HTML."""
    text = body or ""
    if recon.looks_like_app_html(text[:400]):
        return False
    low = text.lower()
    if not any(marker in low for marker in _NAME_MARKERS):
        return False
    if _HEADER.search(text):
        return any(field in low for field in _README_FIELDS)
    return any(field in low for field in _README_FIELDS)


def is_plugin_changelog(body: str) -> bool:
    """True when the body looks like a Bricksforge changelog, not HTML."""
    text = body or ""
    if recon.looks_like_app_html(text[:400]):
        return False
    low = text.lower()
    if not any(marker in low for marker in _NAME_MARKERS):
        return False
    return bool(_CHANGELOG_MD.search(text) or _CHANGELOG_SECTION.search(text))


def version_from_assets(body: str) -> tuple[tuple[int, ...] | None, bool]:
    """Plugin-file ``?ver=`` on a Bricksforge asset, and whether any was seen."""
    seen = False
    found = None
    for match in _ASSET.finditer(body or ""):
        seen = True
        if found is not None:
            continue
        ver_match = _VER.search(match.group(0).replace("&amp;", "&"))
        if ver_match:
            found = parse_dotted(ver_match.group(1))
    return found, seen


def observe_html(body: str) -> tuple[tuple[int, ...] | None, str, bool]:
    """Return ``(version, where, seen)`` from already-crawled HTML only."""
    version, seen = version_from_assets(body)
    if version is not None:
        return version, "plugin asset ?ver=", True
    if seen:
        return None, "plugin asset", True
    return None, "", False


def _passive_note() -> str:
    return (
        "Only read-only GETs of public plugin readme.txt / changelog.txt were "
        "sent when needed; no POST to /wp-json/bricksforge/v1/form_submit, "
        "admin-ajax (bricksforge_regenerate_nonce, bricksforge_form_submit), "
        "nonce request, temporaryFileUploads parameter, upload, polyglot file, "
        "/wp-content/uploads/bricksforge/tmp/ request, write, malformed input, "
        "or /wp-admin request was sent."
    )


def _vulnerable(version: tuple[int, ...], where: str) -> dict:
    label = fmt(version)
    return base_finding(
        CHECK,
        severity="critical",
        title=f"{UNCONFIRMED}: Bricksforge {label} ({CHECK.cve})",
        evidence=(
            f"Observed Bricksforge {label} via {where}. {UNCONFIRMED}. "
            f"Affected: Bricksforge through 3.1.8.9. Fixed in {_FIXED_MIN} "
            f"(also 4.0.0+); {_RECOMMENDED} recommended. "
            f"{CHECK.cve}: unauthenticated arbitrary file upload leading to "
            "remote code execution through unvalidated temporaryFileUploads "
            "url metadata in Pro Forms (Patchstack CVSS 10 / CNA CVSS 9.8). "
            "Patchstack marks this as known-exploited (Patchstack telemetry "
            f"since 7 October 2026; not CISA KEV). {_passive_note()} "
            f"{_sources_note()}"
        ),
        fix=_fix(),
        match=f"bricksforge:{label}",
    )


def _info(where: str) -> dict:
    finding = base_finding(
        CHECK,
        severity="info",
        title=(
            f"Bricksforge detected; version not exposed "
            f"({CHECK.cve}, low confidence)"
        ),
        evidence=(
            f"Bricksforge was detected via {where}, but no readable version "
            f"was exposed (low confidence). {CHECK.cve} cannot be compared "
            f"(affected through 3.1.8.9; fixed in {_FIXED_MIN}; {_RECOMMENDED} "
            f"recommended). {_passive_note()} {_sources_note()}"
        ),
        fix=_fix(),
        match="bricksforge:unknown",
    )
    finding["confidence"] = "low"
    return finding


def _probe_static(
    ctx,
    path: str,
    *,
    kind: str,
) -> tuple[tuple[int, ...] | None, str, bool]:
    """One GET of a static version file. Returns ``(version, where, is_plugin)``."""
    resp = fetch_path(ctx, path, max_bytes=65536)
    if resp.get("status") != 200:
        return None, "", False
    body = resp.get("body") or ""
    if kind == "readme":
        if not is_plugin_readme(body):
            return None, "", False
    elif not is_plugin_changelog(body):
        return None, "", False
    version, label = plugin_version(body)
    if version is not None:
        return version, f"GET {path} {label}".strip(), True
    return None, f"GET {path}", True


def run(section, ctx) -> list[dict]:
    headers, body = root_observation(ctx)
    if not looks_like_wordpress(headers, body):
        return []

    version, where, seen = observe_html(body)

    # At most two read-only GETs when the HTML did not already expose a version.
    if version is None:
        readme_version, readme_where, is_readme = _probe_static(
            ctx, README, kind="readme",
        )
        if is_readme:
            seen = True
            where = readme_where
            version = readme_version
        if version is None:
            log_version, log_where, is_log = _probe_static(
                ctx, CHANGELOG, kind="changelog",
            )
            if is_log:
                seen = True
                where = log_where
                version = log_version

    if version is not None:
        if affected(version):
            return [_vulnerable(version, where)]
        return []

    if seen:
        return [_info(where)]
    return []


CHECK = CveCheck(
    id="bricksforge",
    cve="CVE-2026-85097",
    # Misconfig/Enumeration: WordPress plugin fingerprint only.
    agent="misconfig",
    fixed=(
        f"{_FIXED_MIN}+ (also 4.0.0+; {_RECOMMENDED} recommended; affected: "
        "Bricksforge through 3.1.8.9)"
    ),
    summary=(
        "Confirm WordPress from the already-fetched root response, then read "
        "the Bricksforge version from a plugin asset ?ver= already in the page, "
        "or when needed at most two GETs of /wp-content/plugins/bricksforge/"
        "readme.txt and changelog.txt. Critical for versions through 3.1.8.9 "
        f"(fixed in {_FIXED_MIN}; {_RECOMMENDED} recommended). Info/low "
        "confidence when the plugin is present but the version is hidden. "
        "Non-WordPress targets yield no request."
    ),
    sends=(
        "No request when the root response does not look like WordPress, or "
        "when crawled HTML already shows a bricksforge asset ?ver=. When "
        "WordPress is indicated and the version is still unknown, at most two "
        "GETs of /wp-content/plugins/bricksforge/readme.txt and "
        "/wp-content/plugins/bricksforge/changelog.txt."
    ),
    does_not_send=(
        "Never POSTs to /wp-json/bricksforge/v1/form_submit. Never calls "
        "admin-ajax (bricksforge_regenerate_nonce, bricksforge_form_submit). "
        "Never sends nonce requests, temporaryFileUploads parameters, uploads, "
        "polyglot files, requests to /wp-content/uploads/bricksforge/tmp/, "
        "writes, malformed input, or anything to /wp-admin. Never more than "
        "two static version-file GETs."
    ),
    run=run,
)
