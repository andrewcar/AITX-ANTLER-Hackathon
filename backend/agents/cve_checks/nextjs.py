"""Next.js RCE advisory GHSA-2464-fhr4-w9xw — version fingerprint only.

Detection uses the root response (header or /_next/ asset URLs) and, when a
build id is present and the version is still hidden, one GET of that build's
_buildManifest.js. A hidden version is Info, not a vulnerability claim.
"""
import re

from .client import fetch_path, root_observation
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, pad3, parse_dotted


_SKIP_BUILD = {"chunks", "css", "media", "images", "image", "webpack"}
_BUILD = re.compile(r"/_next/static/([A-Za-z0-9_-]{1,64})/")
_NEXT_VER = re.compile(r"next(?:\.js)?[/ @]v?(\d+\.\d+\.\d+)", re.I)


def _header_version(headers: dict) -> tuple[int, ...] | None:
    for key in ("x-nextjs-version", "x-next-version"):
        found = parse_dotted(headers.get(key) or "")
        if found:
            return found
    powered = headers.get("x-powered-by") or ""
    match = _NEXT_VER.search(powered)
    return parse_dotted(match.group(1)) if match else None


def _detected(headers: dict, body: str) -> bool:
    powered = (headers.get("x-powered-by") or "").lower()
    if "next.js" in powered or "nextjs" in powered:
        return True
    if headers.get("x-nextjs-version") or headers.get("x-next-version"):
        return True
    return "/_next/" in (body or "")


def _build_id(body: str) -> str | None:
    for match in _BUILD.finditer(body or ""):
        token = match.group(1)
        if token not in _SKIP_BUILD:
            return token
    return None


def _version_near_next(text: str) -> tuple[int, ...] | None:
    match = _NEXT_VER.search(text or "")
    return parse_dotted(match.group(1)) if match else None


def affected(version: tuple[int, ...]) -> bool:
    """True only for 15.x below 15.5.28 and 16.x below 16.4.1."""
    current = pad3(version)
    if current[0] == 15:
        return cmp_ver(current, (15, 5, 28)) < 0
    if current[0] == 16:
        return cmp_ver(current, (16, 4, 1)) < 0
    return False


def run(section, ctx) -> list[dict]:
    headers, body = root_observation(ctx)
    if not _detected(headers, body):
        return []
    version = _header_version(headers) or _version_near_next(body)
    where = "root response"
    if version is None:
        build = _build_id(body)
        if build:
            manifest = fetch_path(
                ctx, f"/_next/static/{build}/_buildManifest.js", max_bytes=32768,
            )
            text = manifest.get("body") or ""
            if manifest.get("status") == 200 and (
                "__BUILD_MANIFEST" in text or "static/chunks" in text or "/_next/" in text
            ):
                where = "build manifest"
                version = _version_near_next(text)
    if version is None:
        return [base_finding(
            CHECK,
            severity="info",
            title=f"Next.js detected; version not exposed ({CHECK.cve})",
            evidence=(
                f"Next.js was detected via {where}, but no version was exposed. "
                f"{CHECK.cve} cannot be compared. No exploit payload was sent."
            ),
            fix=(
                "Expose the Next.js version only to operators who need it, and "
                "upgrade 15.x to 15.5.28+ or 16.x to 16.4.1+ if this app is on those lines."
            ),
            match="next:unknown",
        )]
    label = fmt(pad3(version))
    if not affected(version):
        return []
    return [base_finding(
        CHECK,
        severity="critical",
        title=f"{UNCONFIRMED}: Next.js {label} ({CHECK.cve})",
        evidence=(
            f"Observed Next.js {label} via {where}. {UNCONFIRMED}. "
            f"Advisory: {CHECK.cve}. Fixed versions: {CHECK.fixed}. "
            "No exploit payload was sent."
        ),
        fix=f"Upgrade Next.js to a fixed release. {CHECK.fixed}. Advisory {CHECK.cve}.",
        match=f"next:{label}",
    )]


CHECK = CveCheck(
    id="nextjs-rce",
    cve="GHSA-2464-fhr4-w9xw",
    agent="misconfig",
    fixed="15.5.28 on 15.x, 16.4.1 on 16.x",
    summary=(
        "Detect Next.js from a header, a /_next/ asset URL, or one build-manifest "
        "GET, and read the version when it is exposed. Critical below 15.5.28 "
        "(15.x) or 16.4.1 (16.x). Info when Next.js is detected but the version is hidden."
    ),
    sends="No request when the root response is enough. Otherwise one GET of /_next/static/<buildId>/_buildManifest.js.",
    does_not_send="No exploit payload, no RSC flight request, no POST.",
    run=run,
)
