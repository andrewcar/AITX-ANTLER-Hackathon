"""weDevs Project Manager (CVE-2026-116512) — readme Stable tag, then one REST GET.

GET the plugin readme. Critical when the Stable tag is 4.1.1 or lower.
When that readme is really the plugin, one more GET asks whether the pm/v2
route index answers without a login. No write, no authentication attempt.
"""
import re

import recon

from .client import fetch_path
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, parse_dotted


README = "/wp-content/plugins/wedevs-project-manager/readme.txt"
REST = "/wp-json/pm/v2"
_STABLE = re.compile(r"(?im)^[ \t]*stable tag:[ \t]*(\d+(?:\.\d+){0,3})[ \t]*$")
_THRESHOLD = (4, 1, 1)


def stable_tag(body: str) -> tuple[int, ...] | None:
    match = _STABLE.search(body or "")
    if not match:
        return None
    return parse_dotted(match.group(1))


def is_plugin_readme(body: str) -> bool:
    text = body or ""
    if "stable tag:" not in text.lower():
        return False
    if recon.looks_like_app_html(text[:400]) and "wedevs" not in text.lower():
        return False
    return True


def vulnerable(version: tuple[int, ...]) -> bool:
    return cmp_ver(version, _THRESHOLD) <= 0


def _challenged(resp: dict) -> bool:
    if resp.get("status") in (401, 403):
        return True
    headers = resp.get("headers") or {}
    return bool(headers.get("www-authenticate"))


def _answers(resp: dict) -> bool:
    if resp.get("status") != 200 or _challenged(resp):
        return False
    body = resp.get("body") or ""
    if recon.looks_like_app_html(body[:400]) and "pm/v2" not in body.lower():
        return False
    low = body.lower()
    return "pm/v2" in low or '"routes"' in low or '"namespace"' in low


def run(section, ctx) -> list[dict]:
    readme = fetch_path(ctx, README, max_bytes=65536)
    body = readme.get("body") or ""
    if readme.get("status") != 200 or not is_plugin_readme(body):
        return []
    findings = []
    version = stable_tag(body)
    if version and vulnerable(version):
        label = fmt(version)
        findings.append(base_finding(
            CHECK,
            severity="critical",
            title=f"{UNCONFIRMED}: weDevs Project Manager {label} ({CHECK.cve})",
            evidence=(
                f"GET {README} Stable tag is {label}. {UNCONFIRMED}. "
                f"Advisory: {CHECK.cve}. Tags 4.1.1 and lower are in range. "
                "No exploit payload was sent."
            ),
            fix=(
                "Upgrade the weDevs Project Manager plugin to a release newer than 4.1.1. "
                f"See {CHECK.cve}."
            ),
            match=f"wedevs:{label}",
        ))
    rest = fetch_path(ctx, REST, max_bytes=65536)
    open_index = _answers(rest)
    state = "answers without login" if open_index else "does not answer without login"
    findings.append(base_finding(
        CHECK,
        severity="info",
        title=f"weDevs pm/v2 REST route index {state}",
        evidence=(
            f"GET {REST} -> HTTP {rest.get('status')}; the route index {state}. "
            "No login was attempted and no write was sent."
        ),
        fix=(
            "Require authentication on the pm/v2 REST routes if they are not meant "
            "to be public, regardless of the plugin version."
        ),
        match=f"wedevs-rest:{'open' if open_index else 'closed'}",
        layer="recon",
    ))
    return findings


CHECK = CveCheck(
    id="wedevs-project-manager",
    cve="CVE-2026-116512",
    agent="recon",
    fixed="newer than 4.1.1",
    summary=(
        "GET the weDevs Project Manager readme and flag Critical when the Stable "
        "tag is 4.1.1 or lower. As Info, note whether GET /wp-json/pm/v2 returns "
        "the route index without a login."
    ),
    sends="GET of the plugin readme.txt, and, only when that readme is the plugin, one GET of /wp-json/pm/v2.",
    does_not_send="No login, no POST/PUT/DELETE, no exploit payload.",
    run=run,
)
