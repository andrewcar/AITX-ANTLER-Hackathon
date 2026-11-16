"""Xen Orchestra VSA-2026-062 — publicly reachable management UI (passive).

Empty-object authentication cookie bypass, exploited in the wild per Vates
(no CVE assigned yet). This check only fingerprints the login surface from the
recon root response, or at most one unauthenticated GET of ``/``. It never
sends an ``authenticationToken`` cookie, never touches ``/rest/v0/*`` or
``/api/*``, and never attempts login, websockets, or JSON-RPC.

Markers verified from upstream ``vatesfr/xen-orchestra``:

- ``packages/xo-server/signin.pug``: ``title Xen Orchestra``,
  ``${xo5Mount}index.css``, ``${xo5Mount}assets/logo.svg``,
  ``${xo5Mount}assets/favicon.svg``, meta author ``Vates SAS``
- ``packages/xo-server/config.toml``: mounts ``/v5`` (xo-web) and ``/v6``
  (``@xen-orchestra/web``)
- ``packages/xo-web/src/index.pug`` and ``@xen-orchestra/web/index.html``:
  ``title Xen Orchestra``

Advisory versions (cite as stated; do not overclaim on doc inconsistencies):

- Affected product line: Xen Orchestra before 6.9.2 (stable) / 6.10.1 (latest),
  plus XOA appliance
- Fixed packages: xo-server 5.211.2 (stable), 5.213.1 (latest)
"""
import re

from .client import fetch_path, root_observation
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, pad3, parse_dotted


ROOT = "/"
_ADVISORY = "VSA-2026-062"
_ADVISORY_URL = (
    "https://docs.vates.tech/security-advisories/advisories/2026/vates-sa-2026-062/"
)
_FIX_PR = "https://github.com/vatesfr/xen-orchestra/pull/10748"

# xo-server package floors from the advisory Resolution section.
_STABLE_SERVER = (5, 211, 2)
_LATEST_SERVER = (5, 213, 1)
# Product / XOA floors from the advisory Affected / Resolution sections.
_STABLE_PRODUCT = (6, 9, 2)
_LATEST_PRODUCT = (6, 10, 1)

# Upstream signin.pug / xo-web / @xen-orchestra/web title.
_TITLE = re.compile(r"<title[^>]*>\s*Xen\s+Orchestra\s*</title>", re.I)
# Mount paths from config.toml; signin.pug assets under xo5Mount (normally /v5/).
_ASSET = re.compile(
    r"(?:/v5/(?:assets/(?:logo|favicon)\.svg|index\.css)|"
    r"/v6/(?:assets/|favicon\.svg|manifest\.webmanifest)|"
    r"/v5/assets/|/v6/)",
    re.I,
)
_AUTHOR = re.compile(r'name=["\']author["\'][^>]*content=["\']Vates SAS["\']', re.I)
_SIGNIN_FORM = re.compile(r"""action=["']signin/(?:local|dispatch)["']""", re.I)
_XO_SERVER_VER = re.compile(
    r"xo-server(?:@|/|\s+|:\s*)v?(\d+\.\d+\.\d+)",
    re.I,
)
_XO_PRODUCT_VER = re.compile(
    r"(?:xen[\s-]?orchestra|xoa)(?:\s+(?:version|v)|[/:\s]+)v?(\d+\.\d+\.\d+)",
    re.I,
)


def is_xen_orchestra(headers: dict, body: str) -> bool:
    """True when the response matches verified XO login / UI markers."""
    blob = body or ""
    if _TITLE.search(blob):
        return True
    lowered = blob.lower()
    if "xen orchestra" not in lowered:
        # Title text may appear outside <title> (nuclei matches the words).
        header_blob = " ".join(
            f"{key}: {value}" for key, value in (headers or {}).items()
        ).lower()
        if "xen orchestra" not in header_blob:
            return False
    # App name plus a mount/asset or signin form / Vates author from upstream.
    return bool(
        _ASSET.search(blob)
        or _AUTHOR.search(blob)
        or _SIGNIN_FORM.search(blob)
        or "/v5/" in lowered
        or "/v6/" in lowered
    )


def parse_version(headers: dict, body: str) -> tuple[str, tuple[int, ...]] | None:
    """Return (kind, version) when a comparable version is passively present."""
    blob = " ".join(
        [
            body or "",
            " ".join(f"{key}: {value}" for key, value in (headers or {}).items()),
        ]
    )
    server = _XO_SERVER_VER.search(blob)
    if server:
        version = parse_dotted(server.group(1))
        if version:
            return "xo-server", version
    product = _XO_PRODUCT_VER.search(blob)
    if product:
        version = parse_dotted(product.group(1))
        if version:
            return "product", version
    return None


def below_fix(kind: str, version: tuple[int, ...]) -> bool:
    """True when the passively shown version is below the advisory fix floor."""
    current = pad3(version)
    if kind == "xo-server":
        # Stable channel line 5.211.x.
        if current[:2] == (5, 211):
            return cmp_ver(current, _STABLE_SERVER) < 0
        # Latest channel line 5.213.x.
        if current[:2] == (5, 213):
            return cmp_ver(current, _LATEST_SERVER) < 0
        # Older than the stable fix package entirely.
        if cmp_ver(current, _STABLE_SERVER) < 0:
            return True
        # Between channels (e.g. 5.212.x if present): still below latest fix.
        return cmp_ver(current, _LATEST_SERVER) < 0
    # Product / XOA 6.x line.
    if current[:2] == (6, 9):
        return cmp_ver(current, _STABLE_PRODUCT) < 0
    if current[:2] == (6, 10):
        return cmp_ver(current, _LATEST_PRODUCT) < 0
    if cmp_ver(current, _STABLE_PRODUCT) < 0:
        return True
    return cmp_ver(current, _LATEST_PRODUCT) < 0


def _observe(ctx) -> tuple[dict, str, str]:
    """Reuse recon root HTML, or one GET / when that body is empty."""
    headers, body = root_observation(ctx)
    if (body or "").strip():
        return headers, body, "recon root response"
    resp = fetch_path(ctx, ROOT, max_bytes=65536)
    resp_headers = {
        str(key).lower(): str(value)
        for key, value in (resp.get("headers") or {}).items()
    }
    return resp_headers, resp.get("body") or "", "GET /"


def _fix() -> str:
    return (
        "Upgrade Xen Orchestra: xo-server >= 5.211.2 (stable) or >= 5.213.1 "
        "(latest); product / XOA >= 6.9.2 (stable) or >= 6.10.1 (latest). "
        "Move the management interface behind a VPN or dedicated management "
        f"network. See {_ADVISORY} ({_ADVISORY_URL}) and fix PR {_FIX_PR}."
    )


def _exposure(where: str) -> dict:
    finding = base_finding(
        CHECK,
        severity="high",
        title=(
            "Xen Orchestra management interface publicly reachable: confirm "
            "xo-server >= 5.211.2 (stable) / >= 5.213.1 (latest) and move it "
            "behind a VPN"
        ),
        evidence=(
            f"Fingerprinted Xen Orchestra via {where} (title/app name "
            "\"Xen Orchestra\" and/or XO5/XO6 asset paths from upstream "
            "signin and mounts). No comparable xo-server or product version "
            "was passively exposed. Confidence: needs verification. "
            f"Advisory: {_ADVISORY} (empty-object authentication cookie "
            "bypass; actively exploited per Vates; no CVE yet). Fixed "
            "packages: xo-server 5.211.2 (stable), 5.213.1 (latest). "
            "Affected product line cited as before 6.9.2 (stable) / 6.10.1 "
            "(latest), plus XOA. Only a read-only root observation was used; "
            "no authenticationToken cookie, /rest/v0, /api, login, "
            "websocket, or JSON-RPC was sent."
        ),
        fix=_fix(),
        match="xen-orchestra:exposure",
        layer="config",
    )
    finding["confidence"] = "needs verification"
    return finding


def _critical(kind: str, version: tuple[int, ...], where: str) -> dict:
    label = fmt(pad3(version))
    if kind == "xo-server":
        floor = (
            fmt(_STABLE_SERVER)
            if pad3(version)[:2] == (5, 211)
            else fmt(_LATEST_SERVER)
        )
        what = f"xo-server {label}"
        floor_note = (
            f"{label} is below the xo-server fix floor "
            f"(stable {fmt(_STABLE_SERVER)} / latest {fmt(_LATEST_SERVER)}; "
            f"this build compared toward {floor})."
        )
    else:
        floor = (
            fmt(_STABLE_PRODUCT)
            if pad3(version)[:2] == (6, 9)
            else fmt(_LATEST_PRODUCT)
        )
        what = f"Xen Orchestra/XOA {label}"
        floor_note = (
            f"{label} is below the product fix floor "
            f"(stable {fmt(_STABLE_PRODUCT)} / latest {fmt(_LATEST_PRODUCT)}; "
            f"this build compared toward {floor})."
        )
    return base_finding(
        CHECK,
        severity="critical",
        title=f"{UNCONFIRMED}: {what} ({_ADVISORY})",
        evidence=(
            f"Observed {what} via {where}. {UNCONFIRMED}. {floor_note} "
            f"Advisory: {_ADVISORY}. No authenticationToken cookie, "
            "/rest/v0, /api, login, websocket, or JSON-RPC was sent."
        ),
        fix=_fix(),
        match=f"xen-orchestra:{kind}:{label}",
        layer="config",
    )


def run(section, ctx) -> list[dict]:
    headers, body, where = _observe(ctx)
    if not is_xen_orchestra(headers, body):
        return []
    parsed = parse_version(headers, body)
    if parsed is None:
        return [_exposure(where)]
    kind, version = parsed
    if not below_fix(kind, version):
        return []
    return [_critical(kind, version, where)]


CHECK = CveCheck(
    id="xen-orchestra",
    cve="VSA-2026-062",
    agent="misconfig",
    fixed="xo-server 5.211.2 (stable) / 5.213.1 (latest); XO/XOA 6.9.2 (stable) / 6.10.1 (latest)",
    summary=(
        "Fingerprint the Xen Orchestra login UI from the recon root response, "
        "or one GET / when that body is empty. High when the management "
        "interface is publicly reachable without a version (needs verification). "
        "Critical only when a passively shown xo-server or product version is "
        "below the advisory fix."
    ),
    sends=(
        "No extra request when recon already stored the root body. Otherwise "
        "one unauthenticated GET / (session=None, no redirect follow)."
    ),
    does_not_send=(
        "Never sends an authenticationToken cookie (including j:{} / j:%7B%7D). "
        "Never requests /rest/v0/* or /api/*. No login attempt, websocket, "
        "JSON-RPC, header or cookie manipulation, authenticated request, or write."
    ),
    run=run,
)
