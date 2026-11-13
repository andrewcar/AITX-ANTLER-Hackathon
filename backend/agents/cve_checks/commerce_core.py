"""Drupal Commerce Core (CVE-2026-118539 / SA-CONTRIB-2026-254) — passive fingerprint.

Commerce Core (project ``commerce``) has a missing-authorization access bypass on
certain routes and entity fields that can allow order tampering (orders without
payment, altered prices, unauthorized adjustments). JSON:API headless sites are
affected too. Drupal confirms active exploitation (not CISA KEV).

Affected: ``<8.x-2.41`` and ``>=3.0.0 <3.3.13``. Fixed: ``3.3.13`` and
``8.x-2.41``.

Detection is passive only: confirm Drupal from the root response, detect Commerce
from markup already on that page, then at most one GET of
``/modules/contrib/commerce/commerce.info.yml`` for the ``version:`` line. When
``dependency_files`` already exposed a ``composer.lock`` with a parsed
``drupal/commerce`` version, that version is reused and the info.yml GET is
skipped.

Never adds to cart, starts checkout, sends JSON:API PATCH/POST, or changes any
order or price.
"""
import re

from .client import fetch_path, root_observation
from .pins import iter_composer
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, parse_dotted


INFO_YML = "/modules/contrib/commerce/commerce.info.yml"
_FIXED_2X = (2, 41)
_FIXED_3X = (3, 3, 13)
_BRANCH_3 = (3, 0, 0)

_X_GENERATOR = re.compile(r"\bdrupal\b", re.I)
_META_GENERATOR = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'][^"\']*\bdrupal\b',
    re.I,
)
_META_GENERATOR_REV = re.compile(
    r'<meta[^>]+content=["\'][^"\']*\bdrupal\b[^"\']*["\'][^>]+name=["\']generator["\']',
    re.I,
)
_DRUPAL_SETTINGS = re.compile(r"\bdrupalSettings\b")

_COMMERCE_CLASS = re.compile(r"""\bclass=["'][^"']*\bcommerce-[a-z0-9_-]+""", re.I)
_CART_BLOCK = re.compile(
    r"\b(?:block-commerce-cart|commerce-cart-block|commerce-cart)\b",
    re.I,
)
_CART_LINK = re.compile(r"""href=["'][^"']*/cart/?["']""", re.I)

_VERSION_LINE = re.compile(
    r"(?im)^[ \t]*version:[ \t]*['\"]?(?:(\d+)\.x-)?(\d+(?:\.\d+){0,3})['\"]?"
)
_COMPOSER_NAME_VER = re.compile(
    r'"name"\s*:\s*"drupal/commerce"\s*,\s*"version"\s*:\s*"([^"]+)"',
    re.I,
)
_COMPOSER_VER_NAME = re.compile(
    r'"version"\s*:\s*"([^"]+)"\s*,\s*"name"\s*:\s*"drupal/commerce"',
    re.I,
)
_PIN_MATCH = re.compile(
    r"drupal/commerce@([0-9A-Za-z._+-]+)",
    re.I,
)


def _fix() -> str:
    return (
        "Update Drupal Commerce Core to 3.3.13 (3.x) or 8.x-2.41 (2.x), then "
        "audit orders for inconsistencies (unpaid orders, altered prices, "
        f"unauthorized adjustments). See {CHECK.cve} / SA-CONTRIB-2026-254 "
        "(https://www.drupal.org/sa-contrib-2026-254)."
    )


def is_drupal(headers: dict, body: str) -> bool:
    """True when the root response already fingerprints Drupal."""
    gen = (headers or {}).get("x-generator") or ""
    if _X_GENERATOR.search(gen):
        return True
    text = body or ""
    if _META_GENERATOR.search(text) or _META_GENERATOR_REV.search(text):
        return True
    if _DRUPAL_SETTINGS.search(text):
        return True
    return False


def commerce_markup(body: str) -> tuple[bool, str]:
    """Commerce markers already on the fetched page: classes, cart block, /cart."""
    text = body or ""
    if _COMMERCE_CLASS.search(text):
        return True, "commerce-* CSS class"
    if _CART_BLOCK.search(text):
        return True, "commerce cart block"
    if _CART_LINK.search(text):
        return True, "/cart link"
    return False, ""


def parse_commerce_version(text: str | None) -> tuple[int, ...] | None:
    """Parse ``3.3.12``, ``8.x-2.40``, or Composer ``2.40.0`` into a tuple."""
    raw = (text or "").strip().strip("'\"")
    if not raw:
        return None
    # Drupal core-compatibility prefix: 8.x-2.40 → 2.40
    prefixed = re.match(r"^(\d+)\.x-(\d+(?:\.\d+){0,3})$", raw, re.I)
    if prefixed:
        return parse_dotted(prefixed.group(2))
    # Composer / plain dotted (ignore leading ``v``)
    plain = re.match(r"^v?(\d+(?:\.\d+){0,3})", raw, re.I)
    if plain:
        return parse_dotted(plain.group(1))
    return parse_dotted(raw)


def info_yml_version(body: str) -> tuple[int, ...] | None:
    match = _VERSION_LINE.search(body or "")
    if not match:
        return None
    if match.group(1):
        return parse_dotted(match.group(2))
    return parse_dotted(match.group(2))


def is_commerce_info_yml(body: str) -> bool:
    """True when the body looks like commerce.info.yml, not an HTML soft-404."""
    text = body or ""
    if "<html" in text[:400].lower():
        return False
    low = text.lower()
    if "project:" in low and "commerce" in low:
        return True
    if re.search(r"(?im)^[ \t]*name:[ \t]*['\"]?commerce\b", text):
        return True
    if "type: module" in low and "commerce" in low and "version:" in low:
        return True
    return False


def affected(version: tuple[int, ...]) -> bool:
    """True for ``<2.41`` or ``>=3.0.0 <3.3.13``. Fixed: 2.41 / 3.3.13+."""
    if cmp_ver(version, _BRANCH_3) >= 0:
        return cmp_ver(version, _FIXED_3X) < 0
    return cmp_ver(version, _FIXED_2X) < 0


def _fmt_label(version: tuple[int, ...]) -> str:
    """Prefer Drupal-style ``8.x-2.40`` labels for the 2.x line."""
    if cmp_ver(version, _BRANCH_3) < 0:
        return f"8.x-{fmt(version)}"
    return fmt(version)


def version_from_composer_text(text: str) -> tuple[int, ...] | None:
    """``drupal/commerce`` version from a composer.lock body or snippet."""
    raw = text or ""
    for name, ver in iter_composer(raw) or ():
        if str(name).lower() == "drupal/commerce":
            return parse_commerce_version(str(ver))
    for pattern in (_COMPOSER_NAME_VER, _COMPOSER_VER_NAME):
        match = pattern.search(raw)
        if match:
            found = parse_commerce_version(match.group(1))
            if found:
                return found
    return None


def version_from_dependency_findings(
    ctx,
) -> tuple[tuple[int, ...] | None, str, bool]:
    """Reuse a ``drupal/commerce`` version already observed via dependency_files.

    Returns ``(version, where, lock_exposed)``. When composer.lock was exposed
    but the version is not in findings evidence, ``lock_exposed`` is True so
    the caller can skip inventing a second lock fetch and fall through to
    info.yml only when Commerce markup is present.
    """
    lock_exposed = False
    for item in getattr(ctx, "findings", None) or []:
        if not isinstance(item, dict):
            continue
        check = item.get("check") or {}
        match = str(check.get("match") or "")
        if match == "exposed:/composer.lock" or match.startswith(
            "pin:"
        ) and "/composer.lock" in match:
            lock_exposed = True
        blob = " ".join(
            str(part)
            for part in (match, item.get("title"), item.get("evidence"))
            if part
        )
        pin = _PIN_MATCH.search(match) or _PIN_MATCH.search(blob)
        if pin:
            found = parse_commerce_version(pin.group(1))
            if found:
                return found, "dependency_files composer.lock", True
        found = version_from_composer_text(blob)
        if found:
            return found, "dependency_files composer.lock", True
    return None, "", lock_exposed


def _vulnerable(version: tuple[int, ...], where: str) -> dict:
    label = _fmt_label(version)
    return base_finding(
        CHECK,
        severity="critical",
        title=f"{UNCONFIRMED}: Drupal Commerce Core {label} ({CHECK.cve})",
        evidence=(
            f"Observed Drupal Commerce Core {label} via {where}. {UNCONFIRMED}. "
            "Affected: Commerce Core <8.x-2.41 and >=3.0.0 <3.3.13 "
            "(SA-CONTRIB-2026-254). Fixed in 3.3.13 and 8.x-2.41. "
            f"{CHECK.cve}: missing-authorization access bypass on certain "
            "routes and entity fields allowing order tampering (orders without "
            "payment, altered prices, unauthorized adjustments); JSON:API "
            "headless sites are affected too. Drupal confirms active "
            "exploitation (not CISA KEV). Only a passive fingerprint and at "
            "most one GET of commerce.info.yml (or a reused public "
            "composer.lock version) were used; no cart, checkout, JSON:API "
            "PATCH/POST, order, or price change was sent."
        ),
        fix=_fix(),
        match=f"commerce-core:{label}",
    )


def _info(where: str) -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=f"Drupal Commerce Core detected; version not exposed ({CHECK.cve})",
        evidence=(
            f"Drupal Commerce Core was detected via {where}, but no readable "
            f"version was exposed (low confidence). {CHECK.cve} / "
            "SA-CONTRIB-2026-254 cannot be compared (affected <8.x-2.41 and "
            ">=3.0.0 <3.3.13; fixed 3.3.13 / 8.x-2.41). Update to 3.3.13 / "
            "8.x-2.41 and audit orders. No cart, checkout, JSON:API "
            "PATCH/POST, order, or price change was sent."
        ),
        fix=_fix(),
        match="commerce-core:unknown",
    )


def _info_yml_version(ctx) -> tuple[tuple[int, ...] | None, str, bool]:
    """At most one GET of commerce.info.yml. Returns (version, where, is_module)."""
    resp = fetch_path(ctx, INFO_YML, max_bytes=65536)
    if resp.get("status") != 200:
        return None, f"GET {INFO_YML} -> {resp.get('status')}", False
    body = resp.get("body") or ""
    if not is_commerce_info_yml(body):
        return None, f"GET {INFO_YML}", False
    version = info_yml_version(body)
    if version is not None:
        return version, f"GET {INFO_YML} version:", True
    return None, f"GET {INFO_YML}", True


def run(section, ctx) -> list[dict]:
    headers, body = root_observation(ctx)
    if not is_drupal(headers, body):
        return []

    seen, markup_where = commerce_markup(body)
    version, where, _lock_exposed = version_from_dependency_findings(ctx)

    # Prefer a version already parsed from an exposed composer.lock; skip info.yml.
    if version is not None:
        if affected(version):
            return [_vulnerable(version, where)]
        return []

    # Commerce not visible on the page → do not probe info.yml.
    if not seen:
        return []

    # One GET of the static info.yml. Never cart/checkout/JSON:API writes.
    yml_version, yml_where, is_module = _info_yml_version(ctx)
    if is_module:
        if yml_version is not None:
            if affected(yml_version):
                return [_vulnerable(yml_version, yml_where)]
            return []
        return [_info(yml_where)]
    # info.yml blocked/missing but Commerce markup was on the page.
    return [_info(markup_where)]


CHECK = CveCheck(
    id="commerce-core",
    cve="CVE-2026-118539",
    agent="misconfig",
    fixed="3.3.13 (3.x) / 8.x-2.41 (2.x); affected: <8.x-2.41 and >=3.0.0 <3.3.13",
    summary=(
        "Confirm Drupal from the root response, detect Commerce from page "
        "markup, then read the version from a reused public composer.lock "
        "drupal/commerce pin or one GET of commerce.info.yml. Critical, "
        "version unconfirmed, when in range (<8.x-2.41 or >=3.0.0 <3.3.13). "
        "Info (low confidence) when Commerce is present but the version is "
        "hidden. Non-Drupal targets are skipped."
    ),
    sends=(
        "Nothing extra when a dependency_files composer.lock already provided "
        "drupal/commerce. Otherwise, when Drupal + Commerce markup are present, "
        "one GET of /modules/contrib/commerce/commerce.info.yml. No request "
        "when the target is not Drupal or Commerce is absent."
    ),
    does_not_send=(
        "Never adds to cart, starts checkout, or sends JSON:API PATCH/POST. "
        "No order or price changes, no form submissions, no registrations, "
        "no uploads, no writes, no malformed input, and no auth-bypass "
        "attempts."
    ),
    run=run,
)
