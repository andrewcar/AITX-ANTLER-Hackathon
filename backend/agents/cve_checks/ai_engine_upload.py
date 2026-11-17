"""AI Engine upload XSS (CVE-2026-125804) — passive plugin version read.

Meow Apps AI Engine (WordPress.org slug ``ai-engine``) through 3.9.3 still has
an unauthenticated stored XSS via the chatbot / AI Forms upload endpoint
``/mwai-ui/v1/files/upload``: text types such as ``.rtx`` can be served
without a Content-Type that forces download. The 3.9.2 fix for
CVE-2026-123478 was incomplete; 3.9.4 (12 November 2026) blocks
browser-renderable uploads. CVSS 7.1. Patchstack marks exploitation.

Reuses AI Engine helpers from ``ai_engine`` (CVE-2026-123478): the same asset
``?ver=`` parse and at most one shared GET of
``/wp-content/plugins/ai-engine/readme.txt`` per scan. Never sends chatbot
messages, never calls ``/wp-json/mwai/`` or ``/mwai-ui/`` endpoints, and never
uploads anything.
"""
from . import ai_engine as ae
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt


_AFFECTED_THROUGH = (3, 9, 3)
_FIXED = (3, 9, 4)

_SOURCES = (
    "https://patchstack.com/database/wordpress/plugin/ai-engine/vulnerability/"
    "wordpress-ai-engine-plugin-3-9-3-cross-site-scripting-xss-vulnerability",
    "https://wpsec.com/vuln/WPSEC-2026-3047/",
    "https://meowapps.com/products/ai-engine-pro/changelog",
    "https://laskyr.com/cve/CVE-2026-125804",
)


def _fix() -> str:
    return (
        "Upgrade AI Engine to 3.9.4 or later (Plugins screen or "
        "`wp plugin update ai-engine`). Versions 3.9.2 and 3.9.3 are not "
        "enough — the 3.9.2 fix for the earlier stored XSS left the "
        "/mwai-ui/v1/files/upload path able to store browser-renderable "
        "text uploads. Review uploaded chatbot / AI Forms files for injected "
        "scripts and reset administrator sessions if compromise is suspected. "
        f"See {CHECK.cve}."
    )


def _sources_note() -> str:
    return "Sources: " + "; ".join(_SOURCES) + "."


def affected(version: tuple[int, ...]) -> bool:
    """True for versions through 3.9.3 inclusive. 3.9.4+ is patched."""
    return cmp_ver(version, _AFFECTED_THROUGH) <= 0


def _passive_note() -> str:
    return (
        "Only a read-only GET of the public plugin readme.txt was sent when "
        "needed (shared with the sibling CVE-2026-123478 check); no chatbot "
        "message, /wp-json/mwai/, /mwai-ui/, or MCP endpoint call, HTML or "
        "script submission, POST, form submission, upload, write, or "
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
            f"Affected: AI Engine (Meow Apps) through 3.9.3. Fixed in "
            f"{fmt(_FIXED)}. {CHECK.cve}: unauthenticated stored XSS via the "
            "chatbot / AI Forms upload endpoint /mwai-ui/v1/files/upload "
            "(text types such as .rtx served without Content-Type; CVSS 7.1). "
            "The 3.9.2 fix for CVE-2026-123478 was incomplete; 3.9.2 and "
            "3.9.3 remain affected. Patchstack marks this as exploited. "
            f"{_passive_note()} {_sources_note()}"
        ),
        fix=_fix(),
        match=f"ai-engine-upload:{label}",
    )


def _info(where: str) -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=f"AI Engine detected; version not exposed ({CHECK.cve})",
        evidence=(
            f"AI Engine was detected via {where}, but no readable version "
            f"was exposed. {CHECK.cve} cannot be compared (affected through "
            f"3.9.3; fixed in {fmt(_FIXED)}; 3.9.2/3.9.3 are not enough). "
            f"{_passive_note()} {_sources_note()}"
        ),
        fix=_fix(),
        match="ai-engine-upload:unknown",
    )


def run(section, ctx) -> list[dict]:
    version, where, seen = ae.resolve_plugin_version(ctx)

    if version is not None:
        if affected(version):
            return [_vulnerable(version, where)]
        return []

    if seen:
        return [_info(where)]
    return []


CHECK = CveCheck(
    id="ai-engine-upload",
    cve="CVE-2026-125804",
    agent="misconfig",
    fixed="3.9.4+ (affected: AI Engine through 3.9.3; 3.9.2/3.9.3 not enough)",
    summary=(
        "Confirm WordPress from the already-fetched root response, then read "
        "the AI Engine version from a plugin asset ?ver= already in the "
        "page, or when the plugin path is present without a version, one GET "
        "of /wp-content/plugins/ai-engine/readme.txt shared with the sibling "
        "CVE-2026-123478 check. High for versions through 3.9.3 (fixed in "
        "3.9.4; 3.9.2/3.9.3 are not enough). Info when the plugin is present "
        "but the version is hidden. Non-WordPress targets and pages without "
        "an ai-engine asset yield no request."
    ),
    sends=(
        "No request when the root response does not look like WordPress, or "
        "when crawled HTML already shows an ai-engine asset ?ver=. When "
        "WordPress is indicated and the plugin path is present without a "
        "version, one GET of /wp-content/plugins/ai-engine/readme.txt "
        "(at most once per scan, shared with ai-engine). No request when "
        "the plugin is absent from crawled HTML."
    ),
    does_not_send=(
        "Never sends chatbot messages. Never calls /wp-json/mwai/, /mwai-ui/, "
        "or MCP endpoints. Never uploads files or submits HTML/script. No "
        "POSTs or form submissions, no writes, and nothing to /wp-admin. "
        "Never more than the single shared readme GET."
    ),
    run=run,
)
