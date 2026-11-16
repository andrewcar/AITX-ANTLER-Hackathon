"""AI Engine (CVE-2026-123478) — passive plugin version read.

Meow Apps AI Engine – MCP Server & AI Chatbot (WordPress.org slug ``ai-engine``)
through 3.9.1 has an unauthenticated stored XSS that can hijack administrator
sessions. Fixed in 3.9.2. CVSS 7.1. VulnCheck observed exploitation before
CISA listing.

Detection is passive only: confirm WordPress from the already-fetched root
response, parse crawled HTML for ``/wp-content/plugins/ai-engine/`` asset URLs
with ``?ver=``, and when the plugin path is present without a version, at most
one GET of the plugin ``readme.txt`` Stable tag.

Never sends chatbot messages, never calls ``/wp-json/mwai/`` or MCP endpoints,
never submits HTML or script content, and never POSTs, uploads, or touches
``/wp-admin``.
"""
import re

import recon

from .client import fetch_path, root_observation
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, parse_dotted


README = "/wp-content/plugins/ai-engine/readme.txt"
_AFFECTED_THROUGH = (3, 9, 1)
_FIXED = (3, 9, 2)

_SOURCES = (
    "https://wordsec.net/vulnerabilities/plugins/ai-engine/"
    "ai-engine-mcp-server-ai-chatbot-for-wordpress-with-claude-chatgpt-gemini-391-"
    "unauthenticated-stored-cross-site-scripting",
    "https://laskyr.com/cve/CVE-2026-123478",
    "https://vexday.io/en/boletim/2026-11-11",
)

_STABLE = re.compile(r"(?im)^[ \t]*stable tag:[ \t]*(\d+(?:\.\d+){0,3})[ \t]*$")
_HEADER = re.compile(
    r"(?im)^===\s*.*\bai\s*engine\b.*===\s*$"
)
_README_FIELDS = ("stable tag:", "contributors:", "requires at least:")
_NAME_MARKERS = (
    "ai engine",
    "ai-engine",
    "meow apps",
    "meow-apps",
)
_ASSET = re.compile(
    r"/wp-content/plugins/ai-engine/[^\"'\s>]*",
    re.I,
)
_VER = re.compile(r"[?&]ver=(\d+(?:\.\d+){0,3})", re.I)
_WP_GENERATOR = re.compile(
    r"<meta[^>]*\bcontent\s*=\s*['\"]WordPress\b",
    re.I,
)
_WP_PATH = re.compile(
    r"/wp-(?:content|includes|admin|json|login\.php|cron\.php)\b",
    re.I,
)
_WP_LINK = re.compile(r"""rel=["']https://api\.w\.org/["']""", re.I)


def _fix() -> str:
    return (
        "Update AI Engine to 3.9.2 or later (Plugins screen or "
        "`wp plugin update ai-engine`). Review stored chatbot, discussion, and "
        "log content for injected scripts. Reset administrator sessions if "
        f"compromise is suspected. See {CHECK.cve}."
    )


def _sources_note() -> str:
    return "Sources: " + "; ".join(_SOURCES) + "."


def looks_like_wordpress(headers: dict, body: str) -> bool:
    """True when the already-fetched root response shows WordPress markers."""
    text = body or ""
    if _WP_GENERATOR.search(text):
        return True
    if _WP_PATH.search(text) or _WP_LINK.search(text):
        return True
    if "wordpress" in text.lower() and (
        "wp-content" in text.lower() or "wp-includes" in text.lower()
    ):
        return True
    link = (headers or {}).get("link") or ""
    if "api.w.org" in link.lower():
        return True
    pingback = (headers or {}).get("x-pingback") or ""
    if "xmlrpc.php" in pingback.lower():
        return True
    return False


def stable_tag(body: str) -> tuple[int, ...] | None:
    match = _STABLE.search(body or "")
    return parse_dotted(match.group(1)) if match else None


def is_plugin_readme(body: str) -> bool:
    """True when the body is an AI Engine plugin readme, not an HTML page."""
    text = body or ""
    if recon.looks_like_app_html(text[:400]):
        return False
    low = text.lower()
    if not _HEADER.search(text) and not any(marker in low for marker in _NAME_MARKERS):
        return False
    if not any(marker in low for marker in _NAME_MARKERS):
        return False
    return any(field in low for field in _README_FIELDS)


def affected(version: tuple[int, ...]) -> bool:
    """True for versions through 3.9.1 inclusive. 3.9.2+ is patched."""
    return cmp_ver(version, _AFFECTED_THROUGH) <= 0


def version_from_assets(body: str) -> tuple[tuple[int, ...] | None, bool]:
    """Plugin-file ``?ver=`` on an AI Engine asset, and whether any was seen."""
    seen = False
    found = None
    for match in _ASSET.finditer(body or ""):
        seen = True
        if found is not None:
            continue
        ver_match = _VER.search(match.group(0).replace("&amp;", "&"))
        if ver_match:
            found = parse_dotted(ver_match.group(1))
    return found, seen


def observe_html(body: str) -> tuple[tuple[int, ...] | None, str, bool]:
    """Return ``(version, where, seen)`` from already-crawled HTML only."""
    version, seen = version_from_assets(body)
    if version is not None:
        return version, "plugin asset ?ver=", True
    if seen:
        return None, "plugin asset", True
    return None, "", False


def _passive_note() -> str:
    return (
        "Only a read-only GET of the public plugin readme.txt was sent when "
        "needed; no chatbot message, /wp-json/mwai/ or MCP endpoint call, HTML "
        "or script submission, POST, form submission, upload, write, or "
        "/wp-admin request was sent."
    )


def _vulnerable(version: tuple[int, ...], where: str) -> dict:
    label = fmt(version)
    return base_finding(
        CHECK,
        severity="high",
        title=f"{UNCONFIRMED}: AI Engine {label} ({CHECK.cve})",
        evidence=(
            f"Observed AI Engine {label} via {where}. {UNCONFIRMED}. "
            f"Affected: AI Engine (Meow Apps MCP Server & AI Chatbot) through "
            f"3.9.1. Fixed in 3.9.2. {CHECK.cve}: unauthenticated stored XSS "
            "that can hijack administrator sessions (CVSS 7.1). VulnCheck "
            "observed exploitation before CISA listing. "
            f"{_passive_note()} {_sources_note()}"
        ),
        fix=_fix(),
        match=f"ai-engine:{label}",
    )


def _info(where: str) -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=f"AI Engine detected; version not exposed ({CHECK.cve})",
        evidence=(
            f"AI Engine was detected via {where}, but no readable version was "
            f"exposed. {CHECK.cve} cannot be compared (affected through 3.9.1; "
            f"fixed in 3.9.2). {_passive_note()} {_sources_note()}"
        ),
        fix=_fix(),
        match="ai-engine:unknown",
    )


def _readme_version(ctx) -> tuple[tuple[int, ...] | None, str, bool]:
    """At most one GET of the plugin readme. Returns ``(version, where, is_plugin)``."""
    readme = fetch_path(ctx, README, max_bytes=65536)
    if readme.get("status") != 200:
        return None, "", False
    body = readme.get("body") or ""
    if not is_plugin_readme(body):
        return None, "", False
    version = stable_tag(body)
    if version is not None:
        return version, f"GET {README} Stable tag", True
    return None, f"GET {README}", True


def run(section, ctx) -> list[dict]:
    headers, body = root_observation(ctx)
    if not looks_like_wordpress(headers, body):
        return []

    version, where, seen = observe_html(body)

    # Only fetch the readme when the plugin path is already present without a
    # version. Plugin absent from crawled HTML: no requests, no finding.
    if version is None and seen:
        readme_version, readme_where, is_plugin = _readme_version(ctx)
        if is_plugin:
            where = readme_where
            version = readme_version

    if version is not None:
        if affected(version):
            return [_vulnerable(version, where)]
        return []

    if seen:
        return [_info(where)]
    return []


CHECK = CveCheck(
    id="ai-engine",
    cve="CVE-2026-123478",
    # Closest registry agent: InjectionAgent owns XSS probes and is not one of
    # CveCheck.AGENTS (misconfig/recon/auth/secrets). Same pattern as Amelia Pro
    # (SQLi / InjectionAgent family → misconfig fingerprint). Exposed AI
    # tooling surface (MCP Server & AI Chatbot), same product class as
    # langflow / gpustack — the registry has no separate AI-tooling tag field.
    agent="misconfig",
    fixed="3.9.2+ (affected: AI Engine through 3.9.1)",
    summary=(
        "Confirm WordPress from the already-fetched root response, then read "
        "the AI Engine version from a plugin asset ?ver= already in the page, "
        "or when the plugin path is present without a version, one GET of "
        "/wp-content/plugins/ai-engine/readme.txt Stable tag. High for "
        "versions through 3.9.1 (fixed in 3.9.2; CVSS 7.1). Info when the "
        "plugin is present but the version is hidden. Non-WordPress targets "
        "and pages without an ai-engine asset yield no request."
    ),
    sends=(
        "No request when the root response does not look like WordPress, or "
        "when crawled HTML already shows an ai-engine asset ?ver=. When "
        "WordPress is indicated and the plugin path is present without a "
        "version, one GET of /wp-content/plugins/ai-engine/readme.txt. No "
        "request when the plugin is absent from crawled HTML."
    ),
    does_not_send=(
        "Never sends chatbot messages. Never calls /wp-json/mwai/ or MCP "
        "endpoints. Never submits HTML or script content. No POSTs or form "
        "submissions, no uploads, no writes, and nothing to /wp-admin. Never "
        "more than the single readme GET."
    ),
    run=run,
)
