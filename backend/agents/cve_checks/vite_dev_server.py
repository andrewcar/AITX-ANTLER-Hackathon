"""Vite development server exposure — GHSA-p4f5-76q4-ffq7.

Passive, detection-only. First inspects recon HTML already fetched for Vite
dev markers (``/@vite/client``, ``/@react-refresh``). When those are absent,
optionally one read-only GET of ``/@vite/client`` via ``fetch_path``, matching
known strings from Vite's client module. Never requests
``/@id/__vite-browser-external``, ``/@id/__vite-optional-peer-dep``, ``/@fs/``,
crafted module IDs, or anything from the advisory PoC.
"""
import re

from .client import fetch_path, root_observation
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, pad3, parse_dotted


CLIENT_PATH = "/@vite/client"
ADVISORY = "https://github.com/vitejs/vite/security/advisories/GHSA-p4f5-76q4-ffq7"
TITLE = (
    "Vite development server exposed to the internet "
    "(GHSA-p4f5-76q4-ffq7 risk)"
)

# Markers that appear in Vite/React-plugin HTML served by the development server.
_HTML_MARKERS = (
    "/@vite/client",
    "/@react-refresh",
)

# Strings verified against vite packages/vite/src/client/client.ts and the
# published client.mjs (e.g. 6.4.5 on npm): connecting log, HMR export,
# websocket protocol, and CSS HMR attribute.
_CLIENT_MARKERS = (
    "[vite] connecting...",
    "createHotContext",
    "vite-hmr",
    "data-vite-dev-id",
)

# Passively visible pin / lockfile snippets (e.g. dependency_files evidence or
# a public package-lock already present in the recon body).
_VITE_AT = re.compile(r"\bvite@(\d+\.\d+\.\d+)\b", re.I)
_VITE_JSON = re.compile(
    r'["\']vite["\']\s*:\s*["\']\^?v?(\d+\.\d+\.\d+)',
    re.I,
)
_VITE_LOCK = re.compile(
    r'node_modules/vite["\']?\s*:\s*\{[^}]{0,200}?"version"\s*:\s*"(\d+\.\d+\.\d+)"',
    re.I | re.S,
)
_VITE_PLUS_AT = re.compile(r"\bvite-plus@(\d+\.\d+\.\d+)\b", re.I)


def html_looks_like_vite_dev(body: str) -> bool:
    text = body or ""
    return any(marker in text for marker in _HTML_MARKERS)


def client_looks_like_vite(body: str) -> bool:
    """True when the body matches known Vite client.mjs / client.ts markers."""
    text = body or ""
    hits = sum(1 for marker in _CLIENT_MARKERS if marker in text)
    return hits >= 2 and "createHotContext" in text


def affected_vite(version: tuple[int, ...]) -> bool:
    """True for GHSA-p4f5-76q4-ffq7 affected Vite lines (no CVE id yet)."""
    current = pad3(version)
    major = current[0]
    if major < 4:
        return False
    if major in (4, 5):
        # No patch on 4.x / 5.x — upgrade to >= 6.4.6.
        return True
    if major == 6:
        return cmp_ver(current, (6, 4, 6)) < 0
    if major == 7:
        return cmp_ver(current, (7, 3, 8)) < 0
    if major == 8:
        if current[1] <= 1:
            return cmp_ver(current, (8, 1, 7)) < 0
        if current[1] == 2:
            return cmp_ver(current, (8, 2, 5)) < 0
        if current[1] == 3:
            return cmp_ver(current, (8, 3, 7)) < 0
        return False
    return False


def affected_vite_plus(version: tuple[int, ...]) -> bool:
    """vite-plus <= 1.5.0 is affected; fixed in 1.5.1."""
    return cmp_ver(pad3(version), (1, 5, 1)) < 0


def _parse_pkg_version(text: str) -> tuple[str, tuple[int, ...]] | None:
    if not text:
        return None
    plus = _VITE_PLUS_AT.search(text)
    if plus:
        found = parse_dotted(plus.group(1))
        if found:
            return "vite-plus", found
    for pattern in (_VITE_AT, _VITE_LOCK, _VITE_JSON):
        match = pattern.search(text)
        if match:
            found = parse_dotted(match.group(1))
            if found:
                return "vite", found
    return None


def passive_version(ctx) -> tuple[str, tuple[int, ...]] | None:
    """Best-effort Vite / vite-plus version from already-collected scan data."""
    _, body = root_observation(ctx)
    found = _parse_pkg_version(body)
    if found:
        return found
    for item in getattr(ctx, "findings", None) or []:
        if not isinstance(item, dict):
            continue
        check = item.get("check") or {}
        blob = " ".join(
            str(part)
            for part in (
                check.get("match"),
                item.get("title"),
                item.get("evidence"),
            )
            if part
        )
        found = _parse_pkg_version(blob)
        if found:
            return found
    return None


def _version_note(pkg: str, version: tuple[int, ...]) -> str:
    label = fmt(pad3(version))
    if pkg == "vite-plus":
        if affected_vite_plus(version):
            return (
                f" Passively observed {pkg} {label}, which appears below the "
                f"1.5.1 fix ({UNCONFIRMED})."
            )
        return (
            f" Passively observed {pkg} {label}, which appears at or above "
            "the 1.5.1 fix; the development server is still exposed."
        )
    if affected_vite(version):
        return (
            f" Passively observed {pkg} {label}, which appears below a "
            f"patched release ({UNCONFIRMED})."
        )
    return (
        f" Passively observed {pkg} {label}, which appears at or above a "
        "patched release; the development server is still exposed."
    )


def _finding(where: str, ctx) -> dict:
    version = passive_version(ctx)
    note = _version_note(*version) if version else ""
    evidence = (
        f"Vite development server markers were observed via {where}. "
        "Dev server exposed; any Vite below patched versions is vulnerable "
        "to GHSA-p4f5-76q4-ffq7 (RCE / file read when the server is reachable "
        "with --host / server.host). Never run the Vite development server in "
        "production or on an untrusted network."
        f"{note} "
        f"Advisory: {ADVISORY}. Only recon HTML and optionally GET "
        f"{CLIENT_PATH} were used; no /@fs/, /@id/, or advisory PoC request "
        "was sent."
    )
    return base_finding(
        CHECK,
        severity="critical",
        title=TITLE,
        evidence=evidence,
        fix=(
            "Do not expose the Vite development server to the internet. Bind "
            "it to localhost, remove --host / server.host for untrusted "
            "networks, and serve a production build instead. Upgrade Vite to "
            f"{CHECK.fixed}. 4.x/5.x have no patch — move to >= 6.4.6. "
            "For the 8.2 line prefer 8.3.7 if 8.2.5 is unavailable on npm. "
            f"See {ADVISORY}."
        ),
        match=f"vite-dev:{where}",
    )


def run(section, ctx) -> list[dict]:
    _headers, body = root_observation(ctx)
    if html_looks_like_vite_dev(body):
        return [_finding("recon HTML", ctx)]
    resp = fetch_path(ctx, CLIENT_PATH, max_bytes=65536)
    if resp.get("status") == 200 and client_looks_like_vite(resp.get("body") or ""):
        return [_finding(f"GET {CLIENT_PATH}", ctx)]
    return []


CHECK = CveCheck(
    id="vite-dev-server",
    cve="GHSA-p4f5-76q4-ffq7",
    agent="misconfig",
    fixed=(
        "6.4.6, 7.3.8, 8.1.7, 8.3.7 (prefer over 8.2.5 if missing on npm); "
        "vite-plus 1.5.1; 4.x/5.x → upgrade to >=6.4.6"
    ),
    summary=(
        "Flag a publicly reachable Vite development server from recon HTML "
        "(@vite/client / @react-refresh) or one GET of /@vite/client matching "
        "known client markers. Critical exposure risk for GHSA-p4f5-76q4-ffq7; "
        "refine wording when a Vite version is already visible."
    ),
    sends=(
        "Nothing extra when recon HTML already shows /@vite/client or "
        "/@react-refresh. Otherwise one GET /@vite/client."
    ),
    does_not_send=(
        "Never requests /@id/__vite-browser-external, "
        "/@id/__vite-optional-peer-dep, /@fs/, crafted or encoded module IDs, "
        "newline-injected URLs, advisory PoC paths, file-read attempts, "
        "writes, or malformed input."
    ),
    run=run,
)
