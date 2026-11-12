"""GPUStack localhost auto-admin bypass (CVE-2026-102895 / GHSA-gj9m-f8ph-pmhr).

One unauthenticated GET of ``/version``. GPUStack mounts that probe without
auth in ``gpustack/routes/probes.py`` and returns
``{"version": "...", "git_commit": "..."}``. Before 2.2.0, ``get_current_user``
promotes loopback-sourced requests to the built-in admin when
``force_auth_localhost`` is False (the default). This check only reads the
public version document (or fingerprints the admin UI the crawl already
stored). It never sends ``X-GPUStack-Real-IP`` or any forwarding header, and
never touches users, api-keys, workers, or inference-backends.
"""
import json
import re

from .client import fetch_path, root_observation
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, pad3, parse_dotted


VERSION = "/version"
_FIXED = (2, 2, 0)
_ADVISORY = "https://github.com/gpustack/gpustack/security/advisories/GHSA-gj9m-f8ph-pmhr"
_TITLE = re.compile(r"<title[^>]*>[^<]*gpustack[^<]*</title>", re.I)
_NEAR = re.compile(r"gpustack[^0-9]{0,48}v?(\d+\.\d+(?:\.\d+)?)", re.I)


def version_document(body: str) -> tuple[int, ...] | None:
    """Version from a GPUStack /version JSON body, or None when it is not that document."""
    try:
        obj = json.loads(body or "")
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None
    if "git_commit" not in obj:
        return None
    raw = obj.get("version")
    if raw is None:
        return None
    return parse_dotted(str(raw).lstrip("vV"))


def is_gpustack_version_payload(body: str) -> bool:
    """True when the body is GPUStack's public /version JSON shape."""
    try:
        obj = json.loads(body or "")
    except json.JSONDecodeError:
        return False
    if not isinstance(obj, dict):
        return False
    return "version" in obj and "git_commit" in obj


def below_fix(version: tuple[int, ...]) -> bool:
    return cmp_ver(pad3(version), _FIXED) < 0


def collected_ui(ctx) -> str:
    """Title and asset URLs the crawl and the root GET already stored. No new request."""
    _headers, body = root_observation(ctx)
    parts = [body or ""]
    surface = getattr(ctx, "surface", None) or {}
    for page in surface.get("pages") or []:
        if isinstance(page, dict) and page.get("url"):
            parts.append(str(page["url"]))
    return "\n".join(parts)


def gpustack_ui(text: str) -> bool:
    blob = text or ""
    if _TITLE.search(blob):
        return True
    lowered = blob.lower()
    if "gpustack" in lowered and (
        "/static/" in lowered or "/js/" in lowered or "/css/" in lowered
    ):
        return True
    return False


def ui_version(text: str) -> tuple[int, ...] | None:
    match = _NEAR.search(text or "")
    if not match:
        return None
    return parse_dotted(match.group(1))


def _fix() -> str:
    return (
        "Upgrade GPUStack (pip package gpustack) to 2.2.0 or later. "
        "Set force_auth_localhost=true so loopback requests still require "
        "authentication. Strip client-supplied X-GPUStack-Real-IP (and other "
        f"forwarding IP headers) at the edge. See {CHECK.cve} and {_ADVISORY}."
    )


def _vulnerable_finding(version: tuple[int, ...], where: str) -> dict:
    label = fmt(pad3(version))
    return base_finding(
        CHECK,
        severity="critical",
        title=(
            f"{UNCONFIRMED}: GPUStack detected, version {label} < 2.2.0, "
            f"likely vulnerable to {CHECK.cve}"
        ),
        evidence=(
            f"Observed GPUStack {label} via {where}. {UNCONFIRMED}. "
            f"{label} is below 2.2.0 and appears affected by {CHECK.cve} "
            "(GHSA-gj9m-f8ph-pmhr, CISA KEV): unauthenticated admin when "
            "loopback is trusted or X-GPUStack-Real-IP is client-controlled. "
            "Fixed in 2.2.0. No X-GPUStack-Real-IP or forwarding header was "
            "sent, and no users, api-keys, workers, or inference-backends "
            "endpoint was requested."
        ),
        fix=_fix(),
        match=f"gpustack:{label}",
    )


def _unknown_finding() -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=(
            "GPUStack admin interface exposed; confirm version >= 2.2.0 "
            "and force_auth_localhost=true"
        ),
        evidence=(
            f"GPUStack was fingerprinted, but GET {VERSION} did not return a "
            f"comparable version and the collected UI had none. {CHECK.cve} "
            "was not compared. No X-GPUStack-Real-IP or forwarding header was "
            "sent, and no admin API was requested."
        ),
        fix=_fix(),
        match="gpustack:unknown",
    )


def run(section, ctx) -> list[dict]:
    resp = fetch_path(ctx, VERSION, max_bytes=8192)
    body = resp.get("body") or ""
    ui = collected_ui(ctx)
    payload = is_gpustack_version_payload(body)
    ui_hit = gpustack_ui(ui)
    if not payload and not ui_hit:
        return []
    version = version_document(body)
    where = f"GET {VERSION}"
    if version is None and ui_hit:
        version = ui_version(ui)
        if version is not None:
            where = "the GPUStack UI already collected by the crawl"
    if version is None:
        return [_unknown_finding()]
    if not below_fix(version):
        return []
    return [_vulnerable_finding(version, where)]


CHECK = CveCheck(
    id="gpustack",
    cve="CVE-2026-102895",
    agent="misconfig",
    fixed="2.2.0",
    summary=(
        "One GET /version on the in-scope origin. Critical when the version is "
        "below 2.2.0 (GHSA-gj9m-f8ph-pmhr / CISA KEV). Info when the admin UI "
        "is exposed but the version is hidden."
    ),
    sends="One GET /version on the in-scope origin.",
    does_not_send=(
        "No X-GPUStack-Real-IP or other spoofed forwarding header. No POST, "
        "PUT, PATCH, or DELETE. No users, api-keys, workers, "
        "inference-backends, or from-yaml request. No auth bypass probe, no "
        "upload, no malformed input, no exploit payload."
    ),
    run=run,
)
