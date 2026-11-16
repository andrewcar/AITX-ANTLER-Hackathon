"""BTCPay Server (CVE-2026-119757) — passive version read.

The product version is the footer string from BTCPayServerEnvironment.ToString:
"© BTCPay Server v{version}". That string is rendered only for an authenticated
session. Public pages still expose the layout footer and the static paths in
LayoutHead (``/main/site.css`` with ``/main/layout.css``, and checkout's
``/checkout/checkout.css``). This check reads those from HTML the crawler
already stored, or from one GET of the in-scope page. It never logs in.

Affected range, from the vendor advisory and NVD CVE-2026-119757: every
version before 2.4.2, including 2.4.2 release candidates. 2.4.2 is fixed.
NVD records this as semver ``0 <= version < 2.4.2``, which is why a 2.4.2
prerelease is affected and a later prerelease such as 2.4.3-rc1 is not.
The vendor states the stolen-funds exposure applies to deployments that use
LND. This check does not try to discover whether LND is enabled.

CISA's Known Exploited Vulnerabilities catalog did not list CVE-2026-119757
when this check was added. The finding does not claim a KEV entry.
"""
import re
from urllib.parse import unquote, urlparse

from .client import fetch_page, root_observation
from .spec import UNCONFIRMED, CveCheck, base_finding


_FIXED = (2, 4, 2)
_VERSION = re.compile(
    r"(?:\u00a9|&copy;|&#169;|&#x0*a9;)\s*BTCPay Server\s+v"
    r"(\d+(?:\.\d+){1,3})"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z.-]+)?"
    r"(?![0-9A-Za-z.])",
    re.I,
)
_FOOTER = re.compile(r"""class\s*=\s*["'][^"']*\bbtcpay-footer\b""", re.I)
_URL_ATTR = re.compile(r"""(?:href|src)\s*=\s*["']([^"']+)["']""", re.I)

ADVISORY = "https://blog.btcpayserver.org/security-advisory-btcpay-server-2-4-2/"
FIX = (
    "Update BTCPay Server to 2.4.2 or later. "
    "2.4.2 release candidates are still affected. "
    "Deployments that use LND should update promptly and treat LND credentials "
    "as potentially exposed. Follow the vendor advisory: "
    f"{ADVISORY}"
)


def classify(numeric: tuple[int, ...], prerelease: str | None) -> str:
    """Return ``affected``, ``patched``, or ``ambiguous``.

    A 2.4.2 prerelease is affected. A prerelease of an older release is also
    before 2.4.2. A prerelease of a later release (2.4.3-rc1) is after the fix.
    Four-part numbers are compared on the first three components, except
    2.4.2 with an extra component, which is ambiguous.
    """
    if len(numeric) == 3:
        core = tuple(numeric)
    elif len(numeric) == 4 and not prerelease and tuple(numeric[:3]) != _FIXED:
        core = tuple(numeric[:3])
        prerelease = None
    else:
        return "ambiguous"
    if prerelease:
        return "affected" if core <= _FIXED else "patched"
    return "affected" if core < _FIXED else "patched"


def label_of(numeric: tuple[int, ...], prerelease: str | None) -> str:
    text = ".".join(str(part) for part in numeric)
    if prerelease:
        text += f"-{prerelease}"
    return text


def versions_in(body: str) -> list[tuple[tuple[int, ...], str | None]]:
    """Footer versions that belong to BTCPay Server. Asset query numbers are ignored."""
    found = []
    for match in _VERSION.finditer(body or ""):
        numeric = tuple(int(part) for part in match.group(1).split("."))
        found.append((numeric, match.group(2) or None))
    return found


def _urls(body: str) -> str:
    return " ".join(match.group(1) for match in _URL_ATTR.finditer(body or "")).lower()


def product_seen(body: str) -> bool:
    """True for BTCPay chrome or its known static paths, not a prose mention."""
    if _FOOTER.search(body or ""):
        return True
    urls = _urls(body)
    if "/checkout/checkout.css" in urls:
        return True
    if "/main/site.css" in urls and "/main/layout.css" in urls:
        return True
    if "/main/site.css" in urls and "/main/fonts/opensans.css" in urls:
        return True
    return False


def _critical(numeric: tuple[int, ...], prerelease: str | None) -> dict:
    label = label_of(numeric, prerelease)
    prerelease_note = (
        "2.4.2 release candidates are affected. "
        if prerelease and tuple(numeric[:3]) == _FIXED
        else ""
    )
    return base_finding(
        CHECK,
        severity="critical",
        title=f"{UNCONFIRMED}: BTCPay Server {label} ({CHECK.cve})",
        evidence=(
            f"Observed BTCPay Server {label} in the product footer. {UNCONFIRMED}. "
            "Affected range: every version before 2.4.2, including 2.4.2 release "
            f"candidates. Fixed in 2.4.2. {prerelease_note}"
            "The vendor advisory says the LND credential exposure applies to "
            f"deployments that use LND. Advisory: {ADVISORY} "
            f"{CHECK.cve}. No exploit payload was sent."
        ),
        fix=FIX,
        match=f"btcpay:{label}",
    )


def _info(reason: str) -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=f"BTCPay Server detected; version not confirmed ({CHECK.cve})",
        evidence=(
            f"BTCPay Server was detected, but {reason}. "
            f"{CHECK.cve} was not classified. No exploit payload was sent."
        ),
        fix=FIX,
        match="btcpay:unknown",
    )


def assess(body: str) -> list[dict]:
    parsed = versions_in(body)
    if not product_seen(body) and not parsed:
        return []
    if not parsed:
        return [_info("no BTCPay Server version was exposed")]
    kinds = {classify(numeric, pre) for numeric, pre in parsed}
    labels = {label_of(numeric, pre) for numeric, pre in parsed}
    if kinds == {"patched"}:
        return []
    if kinds != {"affected"} or len(labels) != 1:
        return [_info("the visible BTCPay Server version is ambiguous")]
    numeric, pre = parsed[0]
    return [_critical(numeric, pre)]


def _decoded_path(ctx) -> str:
    root = getattr(ctx, "recon_root", None) or {}
    raw = (root.get("url") or getattr(ctx, "url", "") or "").strip()
    path = urlparse(raw).path or ""
    for _ in range(2):
        decoded = unquote(path)
        if decoded == path:
            break
        path = decoded
    return path.lower()


def refuses_fetch(ctx) -> bool:
    """True when the in-scope path must not be requested.

    The check never builds these paths. This only stops the single page GET
    when the scan URL itself is already one of them.
    """
    path = _decoded_path(ctx)
    if "macaroon" in path:
        return True
    if path.startswith("/api/v1") or "/api/v1/" in path:
        return True
    parts = [part for part in path.split("/") if part]
    return "lnd" in parts


def run(section, ctx) -> list[dict]:
    _headers, body = root_observation(ctx)
    if not (body or "").strip() and not refuses_fetch(ctx):
        page = fetch_page(ctx)
        body = page.get("body") or ""
    return assess(body)


CHECK = CveCheck(
    id="btcpay-server",
    cve="CVE-2026-119757",
    agent="secrets",
    fixed=(
        "2.4.2 (affected: every version before 2.4.2, including 2.4.2 "
        "release candidates)"
    ),
    summary=(
        "Read the BTCPay Server version from the product footer already in "
        "the page HTML. If that HTML was not stored, one GET of the in-scope "
        "page with no query string. Critical, version unconfirmed, before "
        "2.4.2 and for 2.4.2 release candidates. Info when BTCPay Server is "
        "present but the version is missing or ambiguous."
    ),
    sends=(
        "No request when the crawler already stored the page HTML. "
        "Otherwise one GET of the in-scope page, with no query string, "
        "and redirects are not followed."
    ),
    does_not_send=(
        "Never requests a path containing macaroon, a credential file, "
        "a Lightning or LND admin API, or a Greenfield API. "
        "No login, no POST, no request body, no exploit payload, "
        "and no redirect following."
    ),
    run=run,
)
