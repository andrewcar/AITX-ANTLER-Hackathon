"""Craft CMS (CVE-2026-123488 / GHSA-qcvp-ggx3-97r6) — passive version fingerprint.

Unauthenticated SQL injection on the front-end element search (``craft.search``):
the ``attribute`` parameter is concatenated into SQL, and stacked queries allow
admin takeover on MySQL/MariaDB only. Affected: ``4.0.0``–``<4.18.9`` and
``5.0.0``–``<5.11.2``. Fixed: ``4.18.9`` and ``5.11.2``. Exploited in the wild
(Canadian Cyber Centre AV26-1086 Update 1; VulnCheck KEV).

Detection only. Fingerprint Craft from the already-fetched homepage/recon
response, then at most one GET of the control-panel login page (``/admin/login``)
where a public version string sometimes appears (e.g. ``Craft CMS 5.6.16``).
Stock Craft often hides the exact version; that yields Info, not Critical.

Never requests ``craft.search``, never sends ``attribute`` / ``[attribute]`` /
``%5Battribute%5D``, SQL characters, POST/PUT, login attempts, or admin actions.
"""
import re

from .client import fetch_path, root_observation
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, pad3, parse_dotted


LOGIN = "/admin/login"
_FIXED_4 = (4, 18, 9)
_FIXED_5 = (5, 11, 2)
_BRANCH_4 = (4, 0, 0)
_BRANCH_5 = (5, 0, 0)

_ADVISORY = "GHSA-qcvp-ggx3-97r6"
_ADVISORY_URL = (
    "https://github.com/craftcms/cms/security/advisories/GHSA-qcvp-ggx3-97r6"
)

_VERSION = re.compile(
    r"\bCraft\s+CMS\s+v?(\d+\.\d+(?:\.\d+){0,2})\b",
    re.I,
)
_GENERATOR = re.compile(
    r"""<meta[^>]+name\s*=\s*['"]generator['"][^>]+"""
    r"""content\s*=\s*['"]Craft\s+CMS\s+v?(\d+\.\d+(?:\.\d+){0,2})['"]""",
    re.I,
)
_GENERATOR_REV = re.compile(
    r"""<meta[^>]+content\s*=\s*['"]Craft\s+CMS\s+v?(\d+\.\d+(?:\.\d+){0,2})['"]"""
    r"""[^>]+name\s*=\s*['"]generator['"]""",
    re.I,
)
_CPRESOURCES = re.compile(r"/cpresources/", re.I)
_COOKIE_NAMES = ("craftsessionid", "craft_csrf_token")


def _fix() -> str:
    return (
        "Upgrade Craft CMS to 4.18.9+ (4.x) or 5.11.2+ (5.x). "
        f"See {CHECK.cve} / {_ADVISORY} ({_ADVISORY_URL}). "
        "Temporary mitigation: block front-end requests with "
        "`%5Battribute%5D` or `[attribute]` anywhere in the query string."
    )


def version_in(text: str) -> tuple[int, ...] | None:
    """First Craft CMS dotted version in HTML/headers, or None."""
    raw = text or ""
    for pattern in (_GENERATOR, _GENERATOR_REV, _VERSION):
        match = pattern.search(raw)
        if match:
            return parse_dotted(match.group(1))
    return None


def _cookie_blob(ctx, headers: dict) -> str:
    parts: list[str] = []
    for key, value in (headers or {}).items():
        parts.append(f"{key}: {value}")
    root = getattr(ctx, "recon_root", None) or {}
    for item in root.get("set_cookie") or []:
        parts.append(str(item))
    return "\n".join(parts)


def is_craft(ctx, headers: dict, body: str) -> bool:
    """True when the already-fetched response fingerprints Craft CMS."""
    powered = (headers or {}).get("x-powered-by") or ""
    if re.search(r"\bcraft\s*cms\b", powered, re.I):
        return True
    cookie_text = _cookie_blob(ctx, headers).lower()
    if any(name in cookie_text for name in _COOKIE_NAMES):
        return True
    text = body or ""
    if _CPRESOURCES.search(text):
        return True
    if "craftsessionid" in text.lower() or "craft_csrf_token" in text.lower():
        return True
    return False


def affected(version: tuple[int, ...]) -> bool:
    """True for 4.0.0–<4.18.9 and 5.0.0–<5.11.2. 3.x and other majors: False."""
    current = pad3(version)
    if cmp_ver(current, _BRANCH_5) >= 0:
        if current[0] != 5:
            return False
        return cmp_ver(current, _FIXED_5) < 0
    if cmp_ver(current, _BRANCH_4) >= 0 and current[0] == 4:
        return cmp_ver(current, _FIXED_4) < 0
    return False


def _critical(version: tuple[int, ...], where: str) -> dict:
    label = fmt(pad3(version))
    return base_finding(
        CHECK,
        severity="critical",
        title=f"{UNCONFIRMED}: Craft CMS {label} ({CHECK.cve})",
        evidence=(
            f"Observed Craft CMS {label} via {where}. {UNCONFIRMED}. "
            f"Affected: Craft CMS 4.0.0–<4.18.9 and 5.0.0–<5.11.2 "
            f"({_ADVISORY}). Fixed in 4.18.9 and 5.11.2. "
            f"{CHECK.cve}: unauthenticated SQL injection in craft.search "
            "`attribute` on MySQL/MariaDB (stacked queries → admin takeover). "
            "Exploited in the wild (Canadian Cyber Centre AV26-1086; VulnCheck "
            "KEV). Only a passive fingerprint and at most one GET of "
            f"{LOGIN} were used; no craft.search, attribute, SQL, POST, login, "
            "or admin-action request was sent."
        ),
        fix=_fix(),
        match=f"craft-cms:{label}",
    )


def _info() -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=(
            f"Craft CMS detected; version not visible; confirm ≥ 4.18.9 / "
            f"5.11.2 ({CHECK.cve}, exploited)"
        ),
        evidence=(
            "Craft CMS was fingerprinted from the homepage/recon response "
            f"(X-Powered-By, CraftSessionId / CRAFT_CSRF_TOKEN, or "
            f"/cpresources/), but no comparable version was readable from the "
            f"root response or GET {LOGIN}. {CHECK.cve} / {_ADVISORY} cannot "
            "be compared (affected 4.0.0–<4.18.9 and 5.0.0–<5.11.2; fixed "
            "4.18.9 / 5.11.2). Confirm the install is patched. No craft.search, "
            "attribute, SQL, POST, login, or admin-action request was sent."
        ),
        fix=_fix(),
        match="craft-cms:unknown",
    )


def run(section, ctx) -> list[dict]:
    headers, body = root_observation(ctx)
    if not is_craft(ctx, headers, body):
        return []

    version = version_in(body) or version_in(
        " ".join(f"{key}: {value}" for key, value in (headers or {}).items())
    )
    where = "root response"
    if version is None:
        resp = fetch_path(ctx, LOGIN, max_bytes=65536)
        text = resp.get("body") or ""
        version = version_in(text)
        if version is not None:
            where = f"GET {LOGIN}"

    if version is not None:
        if affected(version):
            return [_critical(version, where)]
        return []
    return [_info()]


CHECK = CveCheck(
    id="craft-cms",
    cve="CVE-2026-123488",
    agent="recon",
    fixed="4.18.9 (4.x) / 5.11.2 (5.x); affected: 4.0.0–<4.18.9 and 5.0.0–<5.11.2",
    summary=(
        "Fingerprint Craft CMS from the root response (X-Powered-By, "
        "CraftSessionId / CRAFT_CSRF_TOKEN, /cpresources/), then read the "
        "version from that page or one GET of /admin/login. Critical, "
        "version unconfirmed, when in range (4.0.0–<4.18.9 or "
        "5.0.0–<5.11.2). Info when Craft is present but the version is "
        "hidden. Non-Craft targets are skipped."
    ),
    sends=(
        "Nothing when Craft is not fingerprinted on the already-fetched "
        "homepage. Otherwise at most one GET /admin/login when the version "
        "is not already on the root response."
    ),
    does_not_send=(
        "Never requests craft.search or any URL with attribute, [attribute], "
        "or %5Battribute%5D. No SQL characters or payloads, no POST/PUT, no "
        "login attempts, no admin actions, no uploads, no writes, and no "
        "malformed input."
    ),
    run=run,
)
