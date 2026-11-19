"""LiteLLM proxy custom-code guardrail sandbox escape (CVE-2026-40217).

BerriAI LiteLLM proxy ``POST /guardrails/test_custom_code`` runs user-supplied
Python inside a hand-rolled regex sandbox. Bytecode rewriting escapes that
sandbox and yields code execution in the proxy process — which runs as root in
the default Docker image (CVSS 8.8; GHSA-wxxx-gvqv-xp7p / PYSEC-2026-2601 /
X41-2026-001). Reaching the endpoint requires a proxy-admin credential in
default configs, which raises the stakes of leaked or default master keys.
Affected ``>=1.81.8``. Fixed floor used here: ``1.83.11`` (see comment on
``_FIXED``). Listed in CISA KEV (added 2026-11-18); exploited in the wild.

Detection is passive and gated: fingerprint the LiteLLM proxy from already-
crawled root HTML/headers (verified Swagger title and admin UI markers from
``BerriAI/litellm``), then at most one unauthenticated GET of
``/health/readiness``, which returns ``litellm_version`` on affected builds
(verified on ``v1.74.3-stable`` through ``v1.83.10-stable``). High when
``1.81.8 <= version < 1.83.11``. This check never probes whether
``/guardrails/test_custom_code`` is reachable.

Never requests ``/guardrails/test_custom_code``, ``/key/*``, ``/user/*``,
``/team/*``, ``/config/*``, ``/model/new``, or ``/chat/completions``. Never
sends ``Authorization`` / ``x-litellm-api-key``, master-key guesses, payloads,
or malformed input.
"""
import json
import re

from .client import fetch_path, root_observation
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, pad3, parse_dotted


READINESS = "/health/readiness"
_INTRODUCED = (1, 81, 8)
# GHSA affected range lists <1.83.10 with the v1.83.10-stable tag, but the
# advisory text, CISA/heise, and the PoC say upgrade to 1.83.11. Use 1.83.11
# as the fixed floor.
_FIXED = (1, 83, 11)

_SOURCES = (
    "https://www.cisa.gov/news-events/alerts/2026/11/18/"
    "cisa-adds-four-known-exploited-vulnerabilities-catalog",
    "https://github.com/BerriAI/litellm/security/advisories/GHSA-wxxx-gvqv-xp7p",
    "https://osv.dev/vulnerability/PYSEC-2026-2601",
    "https://www.openwall.com/lists/oss-security/2026/04/09/1",
)

# Markers verified from BerriAI/litellm proxy_server.py Swagger/UI branding and
# from projectdiscovery nuclei litellm-swagger-detect (Shodan title query).
_SWAGGER_TITLE = re.compile(
    r"<title[^>]*>[^<]*LiteLLM\s+API(?:\s*-\s*Swagger\s+UI)?[^<]*</title>",
    re.I,
)
_ADMIN_PANEL = re.compile(r"LiteLLM\s+Admin\s+Panel\s+on\s+/ui", re.I)
_PROXY_BLURB = re.compile(
    r"Proxy\s+Server\s+to\s+call\s+100\+\s+LLMs\s+in\s+the\s+OpenAI\s+format",
    re.I,
)
_UI_NEXT = re.compile(r"/ui/_next/", re.I)
_SWAGGER_ASSET = re.compile(
    r"/swagger/swagger-ui-(?:bundle\.js|css)|/swagger/favicon\.png",
    re.I,
)
_LITELLM_API = re.compile(r"\bLiteLLM\s+API\b")


def _sources_note() -> str:
    return "Sources: " + "; ".join(_SOURCES) + "."


def _fix() -> str:
    return (
        "Upgrade LiteLLM (pip package litellm) to 1.83.11 or later. "
        "If upgrading is not immediately possible, block "
        "POST /guardrails/test_custom_code at the reverse proxy or API "
        "gateway. Rotate any leaked or default master keys; the endpoint "
        "requires a proxy-admin credential in default configs. "
        f"See {CHECK.cve}. {_sources_note()}"
    )


def is_litellm(headers: dict, body: str) -> bool:
    """True when crawled root HTML/headers match verified LiteLLM proxy markers."""
    text = body or ""
    if _SWAGGER_TITLE.search(text):
        return True
    if _ADMIN_PANEL.search(text):
        return True
    if _PROXY_BLURB.search(text):
        return True
    if _UI_NEXT.search(text):
        return True
    if _SWAGGER_ASSET.search(text) and _LITELLM_API.search(text):
        return True
    blob = " ".join(
        str(value)
        for value in (headers or {}).values()
    )
    combined = f"{text}\n{blob}"
    if "litellm" in combined.lower() and (
        _LITELLM_API.search(combined) or "/ui/_next/" in combined.lower()
    ):
        return True
    return False


def version_document(body: str) -> tuple[int, ...] | None:
    """Version from a LiteLLM /health/readiness JSON body, or None."""
    try:
        obj = json.loads(body or "")
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(obj, dict):
        return None
    raw = obj.get("litellm_version")
    if raw is None:
        return None
    return parse_dotted(str(raw).lstrip("vV"))


def is_readiness_payload(body: str) -> bool:
    """True when the body looks like LiteLLM readiness JSON (not an HTML catch-all)."""
    try:
        obj = json.loads(body or "")
    except (json.JSONDecodeError, TypeError):
        return False
    if not isinstance(obj, dict):
        return False
    if "litellm_version" in obj:
        return True
    # Minimal public readiness after recon-leak hardening still returns status+db.
    return "status" in obj and "db" in obj


def affected(version: tuple[int, ...]) -> bool:
    current = pad3(version)
    if cmp_ver(current, _INTRODUCED) < 0:
        return False
    return cmp_ver(current, _FIXED) < 0


def _vulnerable_finding(version: tuple[int, ...]) -> dict:
    label = fmt(pad3(version))
    return base_finding(
        CHECK,
        severity="high",
        title=f"{UNCONFIRMED}: LiteLLM {label} ({CHECK.cve})",
        evidence=(
            f"Observed LiteLLM {label} via GET {READINESS} (litellm_version). "
            f"{UNCONFIRMED}. {label} is in the affected range "
            f">=1.81.8 and <1.83.11 for {CHECK.cve} (GHSA-wxxx-gvqv-xp7p / "
            "PYSEC-2026-2601 / X41-2026-001, CVSS 8.8): custom-code guardrail "
            "sandbox escape via bytecode rewriting on "
            "POST /guardrails/test_custom_code, yielding code execution as "
            "root in the default Docker image. Reaching that endpoint needs a "
            "proxy-admin credential in default configs (raises the stakes of "
            "leaked or default master keys). Exploited in the wild (CISA KEV, "
            "added 2026-11-18). Fixed floor used here: 1.83.11. This check did "
            "not request /guardrails/test_custom_code or any key/user/team/"
            f"config/model/chat route. {_sources_note()}"
        ),
        fix=_fix(),
        match=f"litellm:{label}",
    )


def _unknown_finding() -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=f"LiteLLM proxy detected; version not exposed ({CHECK.cve})",
        evidence=(
            f"LiteLLM was fingerprinted from already-crawled root HTML/headers, "
            f"but GET {READINESS} did not return a comparable litellm_version. "
            f"{CHECK.cve} was not compared. Confirm the proxy is >= 1.83.11. "
            "No /guardrails/test_custom_code or admin API was requested. "
            f"{_sources_note()}"
        ),
        fix=_fix(),
        match="litellm:unknown",
    )


def run(section, ctx) -> list[dict]:
    headers, body = root_observation(ctx)
    if not is_litellm(headers, body):
        return []

    resp = fetch_path(ctx, READINESS, max_bytes=8192)
    status = resp.get("status") or 0
    resp_body = resp.get("body") or ""

    if status in (401, 403, 404):
        return [_unknown_finding()]
    if status != 200:
        return [_unknown_finding()]
    if not is_readiness_payload(resp_body):
        # HTML catch-all / soft-404 — do not treat as a version document.
        return [_unknown_finding()]

    version = version_document(resp_body)
    if version is None:
        return [_unknown_finding()]
    if not affected(version):
        return []
    return [_vulnerable_finding(version)]


CHECK = CveCheck(
    id="litellm-guardrail",
    cve="CVE-2026-40217",
    agent="misconfig",
    fixed="1.83.11",
    summary=(
        "Fingerprint LiteLLM from crawled Swagger/admin UI markers, then one "
        "GET /health/readiness for litellm_version. High when "
        "1.81.8 <= version < 1.83.11 (CISA KEV). Info when fingerprinted but "
        "the version is hidden. Does not probe the guardrails endpoint."
    ),
    sends=(
        "Nothing when LiteLLM is not fingerprinted on already-crawled root "
        "HTML/headers. Otherwise one GET /health/readiness."
    ),
    does_not_send=(
        "Never GET or POST /guardrails/test_custom_code. Never requests "
        "/key/*, /user/*, /team/*, /config/*, /model/new, or /chat/completions. "
        "No Authorization or x-litellm-api-key header, no master-key guess, "
        "no POST/PUT/DELETE, no payloads, no malformed input."
    ),
    run=run,
)
