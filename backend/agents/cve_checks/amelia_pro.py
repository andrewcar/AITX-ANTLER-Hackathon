"""Amelia Pro (CVE-2026-116751) — passive commercial version read.

Both Amelia Lite (WordPress.org) and the commercial Amelia Pro package install
to ``/wp-content/plugins/ameliabooking/`` (vendor install docs; Pro zip is
``ameliabooking.zip``). Lite keeps its own 1.x/2.x line (WordPress.org Stable
tag verified at 2.4.14). Commercial/Pro builds enqueue
``ameliabooking`` assets with ``?ver=`` in the 4.0+ line (live vendor demos
expose 9.9.1). That commercial version line is the Pro indicator used here.

Affected: 4.0 through 9.9.1. Fixed: 9.9.2. Patchstack priority 9.3 and marks
known-exploited (Patchstack telemetry, not CISA KEV). Wordfence CVSS 7.5.

Never requests Amelia event-filter or API routes, ``tag`` parameters, SQL,
timing probes, exploit payloads, or malformed input — only already-crawled HTML
and at most one GET of the plugin ``readme.txt``.
"""
import re

from .client import fetch_path, root_observation
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import fmt, pad3, parse_dotted


README = "/wp-content/plugins/ameliabooking/readme.txt"
_PLUGIN = re.compile(
    r"/wp-content/plugins/ameliabooking/([^\"'\s>]*)",
    re.I,
)
_VER = re.compile(r"(?:^|[?&])ver=(\d+\.\d+(?:\.\d+)?)", re.I)
_STABLE = re.compile(r"(?im)^[ \t]*stable tag:[ \t]*(\d+(?:\.\d+){0,3})[ \t]*$")
_LOW = (4, 0, 0)
_HIGH = (9, 9, 1)
_FIXED = (9, 9, 2)

FIX = (
    "Update Amelia Pro to 9.9.2 or later through the vendor's licensed update "
    "channel. Purge page, object, and CDN caches after updating. Verify the "
    "running Pro version directly; do not confuse Amelia Lite on WordPress.org "
    "with the commercial plugin version."
)


def in_range(version: tuple[int, ...]) -> bool:
    """True for commercial Pro 4.0 through 9.9.1 inclusive."""
    current = pad3(version)
    return _LOW <= current <= _HIGH


def is_commercial_pro(version: tuple[int, ...]) -> bool:
    """True when the version is on the commercial/Pro line (major >= 4).

    Lite on WordPress.org uses a separate 1.x/2.x track. Commercial builds
    (advisories call the package Amelia Pro) use 4.0+.
    """
    return pad3(version)[0] >= 4


def is_lite_version(version: tuple[int, ...]) -> bool:
    """True for the WordPress.org Lite version line (major 1 or 2)."""
    return pad3(version)[0] <= 2


def version_from_assets(body: str) -> tuple[tuple[int, ...] | None, bool]:
    """``?ver=`` on an ``ameliabooking`` plugin asset, and whether any asset was seen."""
    seen = False
    found = None
    for match in _PLUGIN.finditer(body or ""):
        seen = True
        if found is not None:
            continue
        query = match.group(1)
        ver_match = _VER.search(query.replace("&amp;", "&"))
        if ver_match:
            found = parse_dotted(ver_match.group(1))
    return found, seen


def stable_tag(body: str) -> tuple[int, ...] | None:
    match = _STABLE.search(body or "")
    return parse_dotted(match.group(1)) if match else None


def is_amelia_readme(body: str) -> bool:
    text = body or ""
    low = text.lower()
    if "stable tag:" not in low:
        return False
    if "amelia" not in low and "ameliabooking" not in low and "wpamelia" not in low:
        return False
    # Soft 404 / theme HTML wrappers are not the plugin readme.
    if "<html" in low and "stable tag:" not in text[:2000].lower():
        return False
    return True


def is_lite_readme(body: str) -> bool:
    """True when the plugin readme clearly describes the WordPress.org Lite build."""
    if not is_amelia_readme(body):
        return False
    low = (body or "").lower()
    if "amelia lite" not in low:
        return False
    version = stable_tag(body)
    return version is None or is_lite_version(version)


def observe(body: str) -> tuple[tuple[int, ...] | None, str, bool, bool]:
    """Return ``(version, where, seen, lite_only)`` from already-fetched HTML."""
    asset_version, asset_seen = version_from_assets(body)
    if asset_version is not None:
        return asset_version, "ameliabooking asset ?ver=", True, is_lite_version(asset_version)
    if asset_seen:
        return None, "ameliabooking asset", True, False
    return None, "", False, False


def observe_readme(body: str) -> tuple[tuple[int, ...] | None, str, bool, bool]:
    """Return ``(version, where, seen, lite_only)`` from plugin ``readme.txt``."""
    if not is_amelia_readme(body):
        return None, "", False, False
    lite = is_lite_readme(body)
    version = stable_tag(body)
    if version is not None:
        return version, "plugin readme Stable tag", True, lite or is_lite_version(version)
    return None, "plugin readme", True, lite


def assess(
    version: tuple[int, ...] | None,
    where: str,
    seen: bool,
    lite_only: bool,
) -> list[dict]:
    if not seen:
        return []
    if lite_only:
        # Lite has its own versioning and is out of scope for this Pro advisory.
        return []
    if version is not None and is_commercial_pro(version):
        if in_range(version):
            return [_vulnerable(version, where)]
        return []
    if version is not None and not is_commercial_pro(version):
        # e.g. Pro 3.x: commercial lineage below the affected floor, or other
        # non-Pro tracks. Never emit vulnerable without a verified Pro 4.0+ build.
        return []
    return [_info(where)]


def _vulnerable(version: tuple[int, ...], where: str) -> dict:
    label = fmt(pad3(version))
    return base_finding(
        CHECK,
        severity="critical",
        title=f"{UNCONFIRMED}: Amelia Pro {label} ({CHECK.cve})",
        evidence=(
            f"Observed Amelia Pro {label} via {where}. {UNCONFIRMED}. "
            "Commercial/Pro builds use the ameliabooking plugin folder with a "
            "4.0+ version line; WordPress.org Amelia Lite uses a separate 1.x/2.x "
            "line and was not matched here. "
            f"Affected range: 4.0 through 9.9.1. Fixed in 9.9.2. "
            f"{CHECK.cve}: unauthenticated time-based SQL injection in the public "
            "event tag filter (Patchstack priority 9.3, Wordfence CVSS 7.5). "
            "Patchstack marks this as known-exploited (Patchstack data, not CISA KEV). "
            "No event-filter request, tag parameter, SQL, timing probe, or "
            "exploit payload was sent."
        ),
        fix=FIX,
        match=f"amelia-pro:{label}",
    )


def _info(where: str) -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=f"Amelia detected; verify Pro version is 9.9.2 or later ({CHECK.cve})",
        evidence=(
            f"Amelia was detected via {where}, but the commercial Pro edition "
            "and/or exact version were not confirmed from a passive fingerprint. "
            f"{CHECK.cve} affects Amelia Pro 4.0 through 9.9.1 (fixed in 9.9.2). "
            "Amelia Lite on WordPress.org uses a separate version line and must "
            "not be mistaken for Pro. No event-filter request, tag parameter, "
            "SQL, timing probe, or exploit payload was sent."
        ),
        fix=FIX,
        match="amelia-pro:unknown",
    )


def run(section, ctx) -> list[dict]:
    _headers, body = root_observation(ctx)
    version, where, seen, lite_only = observe(body)
    if seen:
        return assess(version, where, seen, lite_only)
    readme = fetch_path(ctx, README, max_bytes=65536)
    if readme.get("status") != 200:
        return []
    version, where, seen, lite_only = observe_readme(readme.get("body") or "")
    return assess(version, where, seen, lite_only)


CHECK = CveCheck(
    id="amelia-pro",
    cve="CVE-2026-116751",
    # Closest registry agent: InjectionAgent is the active probe specialist and
    # is not one of CveCheck.AGENTS (misconfig/recon/auth/secrets). This check is
    # a passive WordPress plugin fingerprint, same family as wordpress-core /
    # yootheme-pro.
    agent="misconfig",
    fixed="9.9.2 (affected: Amelia Pro 4.0 through 9.9.1; Lite is out of scope)",
    summary=(
        "Read the Amelia commercial/Pro version from an ameliabooking asset "
        "?ver= already in the page, or one GET of the plugin readme.txt. "
        "Critical for Pro 4.0 through 9.9.1 (fixed in 9.9.2). Info when Amelia "
        "is present but Pro edition/version is unclear. Lite-only fingerprints "
        "never yield a vulnerable verdict."
    ),
    sends=(
        "No request when crawled HTML already shows an ameliabooking asset. "
        "Otherwise one GET of /wp-content/plugins/ameliabooking/readme.txt."
    ),
    does_not_send=(
        "Never requests Amelia event-filter or API routes. No tag parameters, "
        "no SQL, no timing probes, no exploit payloads, no malformed input, "
        "no POST."
    ),
    run=run,
)
