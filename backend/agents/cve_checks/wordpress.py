"""WordPress core (CVE-2026-119977, CISA KEV) — passive version read.

Version comes from the generator meta tag, a ?ver= on a core asset already in
the root HTML, or one GET of /readme.html. Affected range is 4.7 through 7.1.3
(fixed in 7.1.4). Upgrade and staging paths are never requested.
"""
import re

from .client import fetch_path, root_observation
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import fmt, pad3, parse_dotted


_LOW = (4, 7, 0)
_HIGH = (7, 1, 3)
_GENERATOR = re.compile(
    r"<meta[^>]*\bname\s*=\s*['\"]generator['\"][^>]*\bcontent\s*=\s*['\"]WordPress\s+(\d+\.\d+(?:\.\d+)?)['\"]",
    re.I,
)
_GENERATOR_REV = re.compile(
    r"<meta[^>]*\bcontent\s*=\s*['\"]WordPress\s+(\d+\.\d+(?:\.\d+)?)['\"][^>]*\bname\s*=\s*['\"]generator['\"]",
    re.I,
)
_ASSET = re.compile(
    r"/wp-(?:includes|admin)/[^\"'\s>]*\?ver=(\d+\.\d+(?:\.\d+)?)",
    re.I,
)
_README_VER = re.compile(r"version\s+(\d+\.\d+(?:\.\d+)?)", re.I)


def in_range(version: tuple[int, ...]) -> bool:
    current = pad3(version)
    return _LOW <= current <= _HIGH


def version_from_html(body: str) -> tuple[tuple[int, ...] | None, str]:
    for pattern in (_GENERATOR, _GENERATOR_REV):
        match = pattern.search(body or "")
        if match:
            return parse_dotted(match.group(1)), "generator meta tag"
    match = _ASSET.search(body or "")
    if match:
        return parse_dotted(match.group(1)), "core asset ?ver="
    return None, ""


def version_from_readme(body: str) -> tuple[int, ...] | None:
    text = body or ""
    low = text.lower()
    if "wordpress" not in low:
        return None
    if "readme" not in low and "semantic personal publishing" not in low:
        return None
    match = _README_VER.search(text)
    return parse_dotted(match.group(1)) if match else None


def _finding(version: tuple[int, ...], where: str) -> dict:
    label = fmt(pad3(version))
    return base_finding(
        CHECK,
        severity="critical",
        title=f"{UNCONFIRMED}: WordPress {label} actively exploited ({CHECK.cve})",
        evidence=(
            f"Observed WordPress {label} via {where}. {UNCONFIRMED}. "
            f"{CHECK.cve} is on the CISA KEV list and is actively exploited. "
            f"Affected range: 4.7 through 7.1.3. Fixed in 7.1.4. "
            "No exploit payload was sent."
        ),
        fix=(
            "Upgrade WordPress to 7.1.4 or later. "
            f"{CHECK.cve} is actively exploited (CISA KEV)."
        ),
        match=f"wordpress:{label}",
    )


def run(section, ctx) -> list[dict]:
    _headers, body = root_observation(ctx)
    version, where = version_from_html(body)
    if version is None:
        readme = fetch_path(ctx, "/readme.html", max_bytes=65536)
        if readme.get("status") == 200:
            version = version_from_readme(readme.get("body") or "")
            where = "readme.html"
    if version is None or not in_range(version):
        return []
    return [_finding(version, where)]


CHECK = CveCheck(
    id="wordpress-core",
    cve="CVE-2026-119977",
    agent="misconfig",
    fixed="7.1.4 (affected: 4.7 through 7.1.3)",
    summary=(
        "Read the WordPress version from the generator meta tag, a core asset "
        "?ver= already in the page, or GET /readme.html. Critical, and noted as "
        "actively exploited, for 4.7 through 7.1.3."
    ),
    sends="No request when the root HTML already shows the version. Otherwise one GET /readme.html.",
    does_not_send="Never requests upgrade or staging paths (update-core, wp-admin upgrade, wp-content/upgrade).",
    run=run,
)
