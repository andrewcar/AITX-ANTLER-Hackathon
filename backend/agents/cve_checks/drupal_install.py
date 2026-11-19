"""Drupal core installer reinstall RCE (CVE-2026-132165 / SA-CORE-2026-017).

Drupal core ships ``/core/install.php``. Under specific conditions an anonymous
attacker can use the installer to reinstall an already-installed site, leading
to site takeover or remote code execution. Partly mitigated when the web server
cannot write ``settings.php``. Released 2026-11-18. Exploitation not yet
reported; Drupal warns exploits may surface within hours or days.

Affected: ``<10.6.22``, ``>=11.0.0 <11.3.22``, ``>=11.4.0 <11.4.13``.
Fixed: ``10.6.22`` / ``11.3.22`` / ``11.4.13`` (10.5.x and 11.2.x and below
are EOL). Mitigation: block ``/core/install.php``.

Detection is passive only: confirm Drupal from the already-fetched root
response (shared fingerprint with Commerce Core), compare a core version from
``?v=`` on ``/core/`` library assets already in crawled HTML when present, then
at most one GET of ``/core/install.php`` (no query string). Critical when that
response is real installer HTML; high when the version is in range; low
hardening note when a patched version still serves the installer.

Never POSTs to ``/core/install.php``, never adds query strings
(``?langcode=``, ``?profile=``, ``?rewrite=``), never follows installer
steps, and never touches ``/update.php``, ``/core/rebuild.php``,
``/core/authorize.php``, ``/user/login``, or ``settings.php``.
"""
import re

from .client import fetch_path, root_observation
from .commerce_core import is_drupal
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, parse_dotted


INSTALL = "/core/install.php"
_FIXED_10 = (10, 6, 22)
_FIXED_11_3 = (11, 3, 22)
_FIXED_11_4 = (11, 4, 13)
_BRANCH_11 = (11, 0, 0)
_BRANCH_11_4 = (11, 4, 0)

_SOURCES = (
    "https://www.drupal.org/sa-core-2026-017",
    "https://www.bleepingcomputer.com/news/security/drupal-patches-critical-"
    "rce-flaw-warns-exploits-may-surface-quickly/",
    "https://osv.dev/vulnerability/DRUPAL-CORE-2026-017",
    "https://www.drupal.org/docs/administering-a-drupal-site/security-in-"
    "drupal/securing-the-installer-installphp",
)

# Core library assets use version: VERSION → ?v=<Drupal::VERSION> (e.g. drupal.js).
_CORE_ASSET_V = re.compile(
    r"""(?:["'(=\s]|^)/core/(?:misc|modules|themes|scripts)/[^\"'\s>]*"""
    r"""[?&]v=(\d+\.\d+\.\d+)""",
    re.I,
)

# Verified from core installer templates / AlreadyInstalledException /
# InstallerTest (Choose language, Select an installation profile, install-page.css).
_ALREADY_INSTALLED = re.compile(r"Drupal already installed", re.I)
_CHOOSE_LANGUAGE = re.compile(r"Choose language", re.I)
_SELECT_PROFILE = re.compile(r"Select an installation profile", re.I)
_INSTALLATION_TASKS = re.compile(r"Installation tasks", re.I)
_INSTALL_PAGE_CSS = re.compile(r"install-page\.css", re.I)
_INSTALL_PAGE_CLASS = re.compile(
    r"""\bclass=["'][^"']*\binstall-page\b""",
    re.I,
)
_INSTALL_FORM = re.compile(
    r"""<(?:form|input)[^>]*(?:id|name|action)=["'][^"']*install""",
    re.I,
)


def _sources_note() -> str:
    return "Sources: " + "; ".join(_SOURCES) + "."


def _fix() -> str:
    return (
        "Update Drupal core to 10.6.22, 11.3.22, or 11.4.13 (matching your "
        "branch). Block /core/install.php at the web server after install "
        "(see Drupal's securing-the-installer guidance). Confirm settings.php "
        f"is not writable by the web server. See {CHECK.cve} / SA-CORE-2026-017."
    )


def _passive_note() -> str:
    return (
        "Only a read-only GET of /core/install.php (no query string) was sent "
        "when Drupal was fingerprinted; no POST, no ?langcode=/ ?profile=/ "
        "?rewrite=, no installer follow-up pages, no /update.php, "
        "/core/rebuild.php, /core/authorize.php, /user/login, or settings.php "
        "request was sent."
    )


def _exploit_status() -> str:
    return (
        "Exploitation not yet reported as of the 2026-11-18 advisory; Drupal "
        "warns public attack code may surface within hours or days (not CISA "
        "KEV)."
    )


def core_version_from_assets(body: str) -> tuple[int, ...] | None:
    """First ``?v=x.y.z`` on a ``/core/{misc,modules,themes,scripts}/`` asset."""
    match = _CORE_ASSET_V.search(body or "")
    if not match:
        return None
    return parse_dotted(match.group(1))


def affected(version: tuple[int, ...]) -> bool:
    """True for ``<10.6.22``, ``>=11.0 <11.3.22``, or ``>=11.4 <11.4.13``."""
    if cmp_ver(version, _BRANCH_11) < 0:
        return cmp_ver(version, _FIXED_10) < 0
    if cmp_ver(version, _BRANCH_11_4) < 0:
        return cmp_ver(version, _FIXED_11_3) < 0
    return cmp_ver(version, _FIXED_11_4) < 0


def is_installer_html(body: str) -> bool:
    """True when the body shows real Drupal installer / already-installed markers."""
    text = body or ""
    if not text.strip():
        return False
    low = text[:800].lower()
    looks_html = (
        "<html" in low
        or "<!doctype" in low
        or "<body" in low
        or "<form" in low
        or "<title" in low
    )
    if not looks_html and not _ALREADY_INSTALLED.search(text):
        return False
    if _ALREADY_INSTALLED.search(text):
        return True
    if _SELECT_PROFILE.search(text):
        return True
    if _INSTALLATION_TASKS.search(text):
        return True
    if _INSTALL_PAGE_CSS.search(text) or _INSTALL_PAGE_CLASS.search(text):
        return True
    if _CHOOSE_LANGUAGE.search(text) and (
        _INSTALL_FORM.search(text) or "drupal" in text.lower()
    ):
        return True
    return False


def installer_reachable(resp: dict) -> bool:
    """True only for HTTP 200 HTML that carries real installer markers."""
    if (resp.get("status") or 0) != 200:
        return False
    headers = {
        str(key).lower(): str(value)
        for key, value in (resp.get("headers") or {}).items()
    }
    ctype = (resp.get("content_type") or headers.get("content-type") or "").lower()
    body = resp.get("body") or ""
    if ctype and "html" not in ctype and "text/" not in ctype and "<" not in body[:200]:
        return False
    return is_installer_html(body)


def _version_finding(version: tuple[int, ...]) -> dict:
    label = fmt(version)
    return base_finding(
        CHECK,
        severity="high",
        title=f"{UNCONFIRMED}: Drupal core {label} ({CHECK.cve})",
        evidence=(
            f"Observed Drupal core {label} via /core/ library asset ?v=. "
            f"{UNCONFIRMED}. Affected: <10.6.22, >=11.0.0 <11.3.22, "
            f">=11.4.0 <11.4.13 (SA-CORE-2026-017). Fixed in 10.6.22 / "
            f"11.3.22 / 11.4.13. {CHECK.cve}: under specific conditions an "
            "anonymous attacker can use /core/install.php to reinstall Drupal "
            f"(site takeover / RCE). {_exploit_status()} {_passive_note()} "
            f"{_sources_note()}"
        ),
        fix=_fix(),
        match=f"drupal-install:{label}",
    )


def _installer_critical(version: tuple[int, ...] | None) -> dict:
    if version is not None:
        label = fmt(version)
        ver_bit = f" Observed core {label} via /core/ asset ?v=."
        match = f"drupal-install:{label}:installer-open"
    else:
        label = "unknown"
        ver_bit = " Core version was not exposed on crawled assets (major-only X-Generator is not compared)."
        match = "drupal-install:unknown:installer-open"
    return base_finding(
        CHECK,
        severity="critical",
        title=f"Drupal installer reachable ({CHECK.cve})",
        evidence=(
            f"GET {INSTALL} returned HTTP 200 HTML with Drupal installer "
            f"markers (e.g. already-installed page or installer form)."
            f"{ver_bit} {CHECK.cve} / SA-CORE-2026-017: reachable installer "
            "can allow reinstall / site takeover / RCE under specific "
            f"conditions. {_exploit_status()} Block /core/install.php. "
            f"{_passive_note()} {_sources_note()}"
        ),
        fix=_fix(),
        match=match,
    )


def _installer_hardening(version: tuple[int, ...]) -> dict:
    label = fmt(version)
    finding = base_finding(
        CHECK,
        severity="low",
        title=f"Drupal installer still reachable on patched core {label}",
        evidence=(
            f"Observed Drupal core {label} (at/above fixed floors for "
            f"{CHECK.cve}), but GET {INSTALL} still returned installer HTML. "
            "Drupal recommends securing/blocking the installer after "
            "installation even on patched releases. "
            f"{_passive_note()} {_sources_note()}"
        ),
        fix=_fix(),
        match=f"drupal-install:{label}:installer-hardening",
    )
    finding["confidence"] = "low"
    return finding


def run(section, ctx) -> list[dict]:
    headers, body = root_observation(ctx)
    if not is_drupal(headers, body):
        return []

    findings: list[dict] = []
    version = core_version_from_assets(body)
    if version is not None and affected(version):
        findings.append(_version_finding(version))

    # One GET of /core/install.php. Never query string, POST, or follow-ups.
    resp = fetch_path(ctx, INSTALL, max_bytes=65536)
    if installer_reachable(resp):
        patched = version is not None and not affected(version)
        if patched:
            findings.append(_installer_hardening(version))
        else:
            findings.append(_installer_critical(version))
    return findings


CHECK = CveCheck(
    id="drupal-install",
    cve="CVE-2026-132165",
    # Misconfig agent: exposed installer surface (same specialist as commerce_core).
    agent="misconfig",
    fixed=(
        "10.6.22 / 11.3.22 / 11.4.13 (affected: <10.6.22, "
        ">=11.0.0 <11.3.22, >=11.4.0 <11.4.13)"
    ),
    summary=(
        "Confirm Drupal from the root response (X-Generator / meta generator / "
        "drupalSettings; shared with commerce-core). Compare a core version "
        "from /core/ library asset ?v= already in crawled HTML when present "
        "(high when in range). Then one GET /core/install.php with no query "
        "string: critical when real installer markers are present; low "
        "hardening note when a patched version still serves the installer. "
        "Non-Drupal targets yield no request. Exploitation not yet reported; "
        "Drupal warns public attack code may surface quickly."
    ),
    sends=(
        "No request when the root response does not fingerprint Drupal. When "
        "Drupal is indicated, one GET of /core/install.php (no query string). "
        "Version comparison uses already-crawled HTML only."
    ),
    does_not_send=(
        "Never POSTs to /core/install.php. Never adds query strings "
        "(?langcode=, ?profile=, ?rewrite=). Never follows installer pages. "
        "Never requests /update.php, /core/rebuild.php, /core/authorize.php, "
        "/user/login, or settings.php. No form submissions, uploads, writes, "
        "payloads, or authentication."
    ),
    run=run,
)
