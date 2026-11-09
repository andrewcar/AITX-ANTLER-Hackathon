"""Contact Form 7 (CVE-2026-114432) — passive version read and uploads listing check.

Version comes from a Contact Form 7 asset ``?ver=`` already in the crawled HTML,
or one GET of the public plugin readme Stable tag. Affected range is >= 6.2 and
< 6.2.4 (6.2 through 6.2.3). Fixed in 6.2.4 (6.2.4.1 also fixed). 6.1.x and
lower are not affected.

When a vulnerable version is observed, one read-only GET of
``/wp-content/uploads/`` (or a linked ``wpcf7_uploads`` folder) checks for an
Apache-style ``Index of`` autoindex. That raises severity to critical because
directory listing exposes the file-listing step on the RCE path for stock
Debian/Ubuntu Apache. No form submit, upload, or payload is ever sent.
"""
import re
from urllib.parse import urlparse

import recon

from .client import fetch_path, root_observation
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, parse_dotted


README = "/wp-content/plugins/contact-form-7/readme.txt"
UPLOADS = "/wp-content/uploads/"
_AFFECTED_FROM = (6, 2)
_FIXED = (6, 2, 4)

_STABLE = re.compile(r"(?im)^[ \t]*stable tag:[ \t]*(\d+(?:\.\d+){0,3})[ \t]*$")
_HEADER = re.compile(r"(?im)^===\s*.*\bcontact form 7\b.*===\s*$")
_README_FIELDS = ("stable tag:", "contributors:", "requires at least:")
_ASSET = re.compile(
    r"/wp-content/plugins/contact-form-7/[^\"'\s>]*",
    re.I,
)
_VER = re.compile(r"[?&]ver=(\d+(?:\.\d+){0,3})", re.I)
_WPCF7_UPLOADS = re.compile(
    r"(/wp-content/uploads/[^\"'\s>]*wpcf7_uploads/?)",
    re.I,
)
_INDEX_OF = re.compile(r"\bIndex of\b", re.I)


def _parse_version(text: str) -> tuple[int, ...] | None:
    """Dotted version with up to four parts (e.g. 6.2.4.1)."""
    parsed = parse_dotted(text)
    if parsed is not None and text.count(".") < 3:
        return parsed
    parts = []
    for piece in (text or "").split("."):
        if not piece.isdigit():
            return parsed
        parts.append(int(piece))
    if len(parts) >= 2:
        return tuple(parts)
    return parsed


def stable_tag(body: str) -> tuple[int, ...] | None:
    match = _STABLE.search(body or "")
    if not match:
        return None
    return _parse_version(match.group(1))


def is_plugin_readme(body: str) -> bool:
    """True when the body is a Contact Form 7 readme, not an HTML page."""
    text = body or ""
    if recon.looks_like_app_html(text[:400]):
        return False
    if not _HEADER.search(text):
        return False
    low = text.lower()
    return any(field in low for field in _README_FIELDS)


def affected(version: tuple[int, ...]) -> bool:
    """True for >= 6.2 and < 6.2.4. 6.1.x and 6.2.4+ are not affected."""
    return cmp_ver(version, _AFFECTED_FROM) >= 0 and cmp_ver(version, _FIXED) < 0


def version_from_assets(body: str) -> tuple[tuple[int, ...] | None, bool]:
    """Plugin-file ``?ver=`` on a Contact Form 7 asset, and whether any was seen."""
    seen = False
    found = None
    for match in _ASSET.finditer(body or ""):
        seen = True
        if found is not None:
            continue
        ver_match = _VER.search(match.group(0).replace("&amp;", "&"))
        if ver_match:
            found = _parse_version(ver_match.group(1))
    return found, seen


def uploads_path_from_html(body: str) -> str:
    """Prefer a linked wpcf7_uploads folder; otherwise the uploads directory root."""
    match = _WPCF7_UPLOADS.search(body or "")
    if not match:
        return UPLOADS
    path = match.group(1)
    candidate = urlparse(path).path or path
    if not candidate.startswith("/") or candidate.startswith("//"):
        return UPLOADS
    if "\\" in candidate or ".." in candidate:
        return UPLOADS
    if not candidate.endswith("/"):
        candidate += "/"
    return candidate


def is_autoindex(resp: dict) -> bool:
    """True when a read-only GET returned an Apache-style directory listing."""
    if (resp.get("status") or 0) != 200:
        return False
    return bool(_INDEX_OF.search(resp.get("body") or ""))


def observe_html(body: str) -> tuple[tuple[int, ...] | None, str, bool]:
    """Return ``(version, where, seen)`` from already-crawled HTML only."""
    version, seen = version_from_assets(body)
    if version is not None:
        return version, "plugin asset ?ver=", True
    if seen:
        return None, "plugin asset", True
    return None, "", False


def _fix() -> str:
    return (
        "Update Contact Form 7 to 6.2.4 or later. "
        "Disable directory listing for the uploads directory. "
        "Review uploads for unexpected files such as .phar. "
        f"See {CHECK.cve}."
    )


def _finding(
    version: tuple[int, ...],
    where: str,
    *,
    autoindex: bool,
    listing_path: str,
) -> dict:
    label = fmt(version)
    if autoindex:
        return base_finding(
            CHECK,
            severity="critical",
            title=(
                f"{UNCONFIRMED}: Contact Form 7 {label} with uploads listing "
                f"({CHECK.cve})"
            ),
            evidence=(
                f"Observed Contact Form 7 {label} via {where}. {UNCONFIRMED}. "
                f"Affected range: >= 6.2 and < 6.2.4 (6.2 through 6.2.3). "
                f"Fixed in 6.2.4+. GET {listing_path} returned an \"Index of\" "
                "autoindex listing, which exposes the file-listing step behind "
                "the RCE path on stock Debian/Ubuntu Apache. "
                f"Advisory: {CHECK.cve}. No form submission or file upload was sent."
            ),
            fix=_fix(),
            match=f"contact-form-7:{label}:autoindex",
        )
    return base_finding(
        CHECK,
        severity="high",
        title=f"{UNCONFIRMED}: Contact Form 7 {label} ({CHECK.cve})",
        evidence=(
            f"Observed Contact Form 7 {label} via {where}. {UNCONFIRMED}. "
            f"Affected range: >= 6.2 and < 6.2.4 (6.2 through 6.2.3). "
            f"Fixed in 6.2.4+. Advisory: {CHECK.cve}. "
            "No form submission or file upload was sent."
        ),
        fix=_fix(),
        match=f"contact-form-7:{label}",
    )


def _info(where: str) -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=f"Contact Form 7 detected; version not exposed ({CHECK.cve})",
        evidence=(
            f"Contact Form 7 was detected via {where}, but no readable version "
            f"was exposed. {CHECK.cve} cannot be compared. "
            "No form submission or file upload was sent."
        ),
        fix=_fix(),
        match="contact-form-7:unknown",
    )


def _readme_version(ctx) -> tuple[tuple[int, ...] | None, str, bool]:
    """One GET of the plugin readme. Returns ``(version, where, is_plugin)``."""
    readme = fetch_path(ctx, README, max_bytes=65536)
    if readme.get("status") != 200:
        return None, "", False
    body = readme.get("body") or ""
    if not is_plugin_readme(body):
        return None, "", False
    version = stable_tag(body)
    if version is not None:
        return version, f"GET {README} Stable tag", True
    return None, f"GET {README}", True


def run(section, ctx) -> list[dict]:
    _headers, body = root_observation(ctx)
    version, where, seen = observe_html(body)

    if version is None:
        readme_version, readme_where, is_plugin = _readme_version(ctx)
        if is_plugin:
            seen = True
            where = readme_where
            version = readme_version

    if version is not None:
        if not affected(version):
            return []
        listing_path = uploads_path_from_html(body)
        listing = fetch_path(ctx, listing_path, max_bytes=65536)
        return [_finding(
            version,
            where,
            autoindex=is_autoindex(listing),
            listing_path=listing_path,
        )]

    if seen:
        return [_info(where)]
    return []


CHECK = CveCheck(
    id="contact-form-7",
    cve="CVE-2026-114432",
    agent="misconfig",
    fixed="6.2.4+ (affected: >= 6.2 and < 6.2.4; 6.1.x and lower are not affected)",
    summary=(
        "Read the Contact Form 7 version from a plugin asset ?ver= already in "
        "the page, or one GET of the plugin readme Stable tag. High for "
        ">= 6.2 and < 6.2.4. Critical when a read-only uploads autoindex "
        "listing is also present. Info when the plugin is present but the "
        "version is hidden."
    ),
    sends=(
        "No request when a crawled asset ?ver= already shows the version. "
        "Otherwise one GET of the plugin readme.txt. When the version is in "
        "range, one GET of /wp-content/uploads/ (or a linked wpcf7_uploads "
        "folder) to check for an Index of listing."
    ),
    does_not_send=(
        "No POST, no form submission, no file upload, no crafted or "
        "invalid-UTF-8 filenames, no attempt to fetch or execute an uploaded "
        "file, no attack payload, and no malformed input."
    ),
    run=run,
)
