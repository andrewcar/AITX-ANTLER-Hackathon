"""Next.js November 2026 security release (CVE-2026-119790) — version fingerprint.

Primary advisory GHSA-mfr8-8qww-v76h (cross-tenant cache disclosure via
``use cache`` + ``unstable_cache``). The same fixed floors also address
CVE-2026-119351, CVE-2026-119347, CVE-2026-119350, CVE-2026-119346,
CVE-2026-119349, and CVE-2026-119348.

Passive only: root headers/body already fetched by recon, then at most one
GET of ``/package.json`` when Next.js is present and the version is still
hidden. No build-id probing, no sourcemap crawl, no RSC or cache probes.
"""
import json
import re

from .client import fetch_path, root_observation
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, pad3, parse_dotted


FIX_15_5 = (15, 5, 29)
FIX_16 = (16, 4, 5)
SIBLING_CVES = (
    "CVE-2026-119351",
    "CVE-2026-119347",
    "CVE-2026-119350",
    "CVE-2026-119346",
    "CVE-2026-119349",
    "CVE-2026-119348",
)
_SIBLING_TEXT = ", ".join(SIBLING_CVES)
_NEXT_VER = re.compile(r"next(?:\.js)?[/ @]v?(\d+\.\d+\.\d+)", re.I)
_MARKERS = (
    "/_next/static/",
    "__NEXT_DATA__",
    "self.__next_f.push",
    "#__next",
    'id="__next"',
    "id='__next'",
)
_PKG_MAX = 65536


def outdated(version: tuple[int, ...]) -> bool:
    """True when the version is below the Nov 2026 floors for known lines.

    16.x below 16.4.5 and 15.5.x below 15.5.29 are outdated. Other 15.x lines
    need an upgrade to >=15.5.29 or >=16.4.5. Unmentioned major lines are not
    flagged (no invented floors).
    """
    current = pad3(version)
    major, minor, _patch = current
    if major == 16:
        return cmp_ver(current, FIX_16) < 0
    if major == 15:
        if minor == 5:
            return cmp_ver(current, FIX_15_5) < 0
        return True
    return False


def _detected(headers: dict, body: str) -> bool:
    powered = (headers.get("x-powered-by") or "").lower()
    if "next.js" in powered or "nextjs" in powered:
        return True
    if headers.get("x-nextjs-version") or headers.get("x-next-version"):
        return True
    text = body or ""
    return any(marker in text for marker in _MARKERS)


def _header_version(headers: dict) -> tuple[tuple[int, ...], str] | None:
    powered = headers.get("x-powered-by") or ""
    match = _NEXT_VER.search(powered)
    if match:
        found = parse_dotted(match.group(1))
        if found:
            return found, "X-Powered-By"
    for key in ("x-nextjs-version", "x-next-version"):
        found = parse_dotted(headers.get(key) or "")
        if found:
            return found, key
    return None


def _next_from_package(data: dict) -> tuple[int, ...] | None:
    if not isinstance(data, dict):
        return None
    for section in ("dependencies", "devDependencies"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        raw = block.get("next")
        if raw is None:
            continue
        found = parse_dotted(str(raw))
        if found:
            return found
    return None


def _cached_package_json(ctx) -> str | None:
    """Reuse a package.json body the scan already holds. No new request."""
    root = getattr(ctx, "recon_root", None) or {}
    for key in ("package_json", "package.json"):
        raw = root.get(key)
        if isinstance(raw, str) and raw.strip():
            return raw
        if isinstance(raw, dict):
            return json.dumps(raw)
    surface = getattr(ctx, "surface", None) or {}
    for collection in ("pages", "json_endpoints"):
        for item in surface.get(collection) or []:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url") or "")
            body = item.get("body")
            if not url.rstrip("/").endswith("package.json"):
                continue
            if isinstance(body, str) and body.strip():
                return body
            if isinstance(body, dict):
                return json.dumps(body)
    return None


def _version_from_package_json(ctx) -> tuple[tuple[int, ...], str] | None:
    cached = _cached_package_json(ctx)
    if cached is not None:
        try:
            data = json.loads(cached)
        except (json.JSONDecodeError, TypeError, ValueError):
            data = None
        found = _next_from_package(data) if data is not None else None
        if found:
            return found, "cached package.json"
    resp = fetch_path(ctx, "/package.json", max_bytes=_PKG_MAX)
    if resp.get("status") != 200:
        return None
    body = resp.get("body") or ""
    ctype = (resp.get("content_type") or "").lower()
    if "json" not in ctype and not body.lstrip().startswith("{"):
        return None
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    found = _next_from_package(data)
    if not found:
        return None
    return found, "/package.json"


def _info_finding() -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title="Next.js detected; verify Nov 2026 security release",
        evidence=(
            "Next.js markers were observed on the homepage, but no version was "
            f"exposed. {CHECK.cve} (GHSA-mfr8-8qww-v76h) and sibling advisories "
            f"({_SIBLING_TEXT}) cannot be compared. Fixed floors: {CHECK.fixed}. "
            "No exploit payload, cache probe, or RSC request was sent."
        ),
        fix=(
            "Confirm the running Next.js release and upgrade to 15.5.29+ or "
            f"16.4.5+ per the November 2026 security release. See {CHECK.cve}."
        ),
        match="nextjs-nov2026:unknown",
    )


def _version_finding(version: tuple[int, ...], where: str) -> dict:
    label = fmt(pad3(version))
    return base_finding(
        CHECK,
        severity="critical",
        title=f"{UNCONFIRMED}: Next.js {label} ({CHECK.cve})",
        evidence=(
            f"Observed Next.js {label} via {where}. {UNCONFIRMED}. "
            f"{CHECK.cve} / GHSA-mfr8-8qww-v76h (cross-tenant cache disclosure "
            "via use cache + unstable_cache). Same fixed floors also cover "
            f"{_SIBLING_TEXT}. Fixed versions: {CHECK.fixed}. "
            "No exploit payload, cache probe, or RSC request was sent."
        ),
        fix=(
            "Upgrade Next.js to 16.4.5 (16.x) or 15.5.29 (15.5.x). Other 15.x "
            "lines should move to >=15.5.29 or >=16.4.5. "
            f"See {CHECK.cve} and https://nextjs.org/blog/november-2026-security-release."
        ),
        match=f"nextjs-nov2026:{label}",
    )


def run(section, ctx) -> list[dict]:
    headers, body = root_observation(ctx)
    if not _detected(headers, body):
        return []
    seen = _header_version(headers)
    if seen is None:
        seen = _version_from_package_json(ctx)
    if seen is None:
        return [_info_finding()]
    version, where = seen
    if not outdated(version):
        return []
    return [_version_finding(version, where)]


CHECK = CveCheck(
    id="nextjs-nov2026",
    cve="CVE-2026-119790",
    agent="misconfig",
    fixed="15.5.29 on 15.5.x, 16.4.5 on 16.x; other 15.x -> >=15.5.29 or >=16.4.5",
    summary=(
        "Detect Next.js from X-Powered-By and homepage markers (/_next/static/, "
        "__NEXT_DATA__, self.__next_f.push, #__next). Compare an exposed version "
        "from X-Powered-By or one GET of /package.json against the November 2026 "
        "floors (CVE-2026-119790 / GHSA-mfr8-8qww-v76h and sibling CVEs). Info when "
        "Next.js is present but the version is hidden."
    ),
    sends=(
        "No extra request when the root response exposes a version. Otherwise one "
        "GET of /package.json when Next.js is detected and the version is still hidden."
    ),
    does_not_send=(
        "No exploit payload, no RSC flight headers, no cache-poisoning URL, no SVG "
        "bypass image, no cookie-theft probe, no build-id or sourcemap crawl, no POST."
    ),
    run=run,
)
