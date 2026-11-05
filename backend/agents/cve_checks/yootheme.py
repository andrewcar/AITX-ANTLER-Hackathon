"""YOOtheme Pro (CVE-2026-102785) — passive version read.

Version comes from a theme asset ``?ver=`` or a generator/meta hint already in
the page HTML the crawler stored. When that HTML is missing, one GET reads the
in-scope page. Affected range is 5.0.0 through 5.0.52 (fixed in 5.0.53).
Pro 4.x and earlier are not affected. The image handler and the cache
endpoint are never requested.
"""
import re

from .client import fetch_page, page_url, root_observation
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import fmt, pad3, parse_dotted


_LOW = (5, 0, 0)
_FIXED = (5, 0, 53)
_THEME = re.compile(
    r"(?:wp-content/themes/yootheme/|templates/yootheme/)([^\"'\s>]*)",
    re.I,
)
_THEME_FILE = re.compile(
    r"(?:^|/)theme(?:\.min)?\.(?:css|js)\?([^\"'\s>]*)",
    re.I,
)
_VER = re.compile(r"(?:^|&)ver=(\d+\.\d+(?:\.\d+)?)", re.I)
_META = re.compile(r"<meta\b[^>]*>", re.I)
_NAMED = re.compile(
    r"yootheme(?:\s+pro)?\s+v?(\d+\.\d+(?:\.\d+)?)",
    re.I,
)

FIX = (
    "Update YOOtheme Pro to 5.0.53 or later. "
    "Updating does not remove an existing webshell. "
    "Check wp-content/uploads (WordPress) or images/ (Joomla) for unexpected .php files."
)


def affected(version: tuple[int, ...]) -> bool:
    """True for 5.0.0 through 5.0.52. 5.0.53+ is patched. 4.x and earlier are not."""
    current = pad3(version)
    return current[0] == 5 and _LOW <= current < _FIXED


def _query_version(query: str) -> tuple[int, ...] | None:
    match = _VER.search((query or "").replace("&amp;", "&"))
    return parse_dotted(match.group(1)) if match else None


def version_from_assets(body: str) -> tuple[tuple[int, ...] | None, bool]:
    """Theme-file ``?ver=`` on a YOOtheme asset, and whether any such asset was seen."""
    seen = False
    found = None
    for match in _THEME.finditer(body or ""):
        seen = True
        file_match = _THEME_FILE.search(match.group(1))
        if not file_match or found is not None:
            continue
        found = _query_version(file_match.group(1))
    return found, seen


def version_from_meta(body: str) -> tuple[tuple[int, ...] | None, bool]:
    """Version from a meta tag that names YOOtheme, and whether such a tag was seen."""
    seen = False
    found = None
    for tag in _META.finditer(body or ""):
        text = tag.group(0)
        if "yootheme" not in text.lower():
            continue
        seen = True
        if found is not None:
            continue
        match = _NAMED.search(text)
        if match:
            found = parse_dotted(match.group(1))
    return found, seen


def observe(body: str) -> tuple[tuple[int, ...] | None, str, bool]:
    """Return ``(version, where, seen)``. ``seen`` is true when YOOtheme is present."""
    asset_version, asset_seen = version_from_assets(body)
    meta_version, meta_seen = version_from_meta(body)
    if asset_version is not None:
        return asset_version, "theme asset ?ver=", True
    if meta_version is not None:
        return meta_version, "generator meta tag", True
    if asset_seen:
        return None, "theme asset", True
    if meta_seen:
        return None, "generator meta tag", True
    return None, "", False


def _critical(version: tuple[int, ...], where: str) -> dict:
    label = fmt(pad3(version))
    return base_finding(
        CHECK,
        severity="critical",
        title=f"{UNCONFIRMED}: YOOtheme Pro {label} ({CHECK.cve})",
        evidence=(
            f"Observed YOOtheme Pro {label} via {where}. {UNCONFIRMED}. "
            f"Affected range: 5.0.0 through 5.0.52. Fixed in 5.0.53. "
            "Pro 4.x and earlier are not affected. "
            f"Advisory: {CHECK.cve}. No exploit payload was sent."
        ),
        fix=FIX,
        match=f"yootheme:{label}",
    )


def _info(where: str) -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=f"YOOtheme detected; version not exposed ({CHECK.cve})",
        evidence=(
            f"YOOtheme was detected via {where}, but no version was exposed. "
            f"{CHECK.cve} cannot be compared. No exploit payload was sent."
        ),
        fix=FIX,
        match="yootheme:unknown",
    )


def assess(body: str) -> list[dict]:
    version, where, seen = observe(body)
    if version is not None:
        if affected(version):
            return [_critical(version, where)]
        return []
    if seen:
        return [_info(where)]
    return []


def _cache_url(ctx) -> bool:
    """True when the scan URL's path is a YOOtheme cache path. Never fetched."""
    path = page_url(ctx).lower()
    return "yootheme" in path and "/cache" in path


def run(section, ctx) -> list[dict]:
    _headers, body = root_observation(ctx)
    if not (body or "").strip() and not _cache_url(ctx):
        page = fetch_page(ctx)
        body = page.get("body") or ""
    return assess(body)


CHECK = CveCheck(
    id="yootheme-pro",
    cve="CVE-2026-102785",
    agent="misconfig",
    fixed="5.0.53 (affected: 5.0.0 through 5.0.52; 4.x and earlier are not affected)",
    summary=(
        "Read the YOOtheme Pro version from a theme asset ?ver= or a generator "
        "meta tag already in the page. Critical for 5.0.0 through 5.0.52. "
        "Info when YOOtheme is present but the version is hidden."
    ),
    sends=(
        "No request when the crawler already stored the page HTML. "
        "Otherwise one GET of the in-scope page, with no query string."
    ),
    does_not_send=(
        "Never requests the image handler or the cache endpoint. "
        "No FromFile or Save parameters, no php://input, no request body, "
        "no upload, no modified signed image URL, no path traversal, "
        "and no webshell-name guessing. No POST."
    ),
    run=run,
)
