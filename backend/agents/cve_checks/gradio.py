"""Gradio run-history token exposure (CVE-2026-134825 / GHSA-4cx6-qfwr-9vfq).

Gradio 6.27.0 up to, but not including, 6.32.0 can hand the operator's saved
Hugging Face token to run-history endpoints when ``ssr_mode`` is enabled.
Fixed in 6.32.0 (12 November 2026, pull request 14050, commit ``fda8037``).
VulnCheck scores it CVSS 4.0 8.3 (High), CWE-290. The GitHub advisory is
unreviewed and has no structured package range; its description matches NVD
and OSV (introduced 6.27.0, fixed 6.32.0).

No exploitation is reported. Checked the CISA Known Exploited Vulnerabilities
catalog and CSV on 24 November 2026; CVE-2026-134825 is not listed.

Detection is one read-only GET of ``/config``. Gradio 6.27.0
``gradio/routes.py`` (``App.get_config``, still present in 6.32.0) answers
``GET /config`` and ``GET /config/`` with ``Blocks.config``. That object is
``Blocks.get_config_file`` in ``gradio/blocks.py``, whose first field is
``"version": VERSION``. ``VERSION`` is ``get_package_version()`` in
``gradio/route_utils.py``, and ``api_prefix`` is ``"/gradio_api"``. The same
document includes ``mode``, a ``components`` list, and ``"protocol":
"sse_v3"``. ``ssr_mode`` is not in that JSON, so this check never treats the
setting as confirmed.

Likely vulnerable only when that ``version`` string is an exact ``X.Y.Z``
release and ``6.27.0 <= v < 6.32.0``. A Gradio config with no comparable
version is unknown. Anything else (missing file, HTML, another JSON
document, 6.26.9 and earlier, 6.32.0 and later) is not detected.

The request goes through ``fetch_path`` (``recon.fetch``), so the allowlist,
global rate limit, kill switch, and audit log still apply.

Never sends a Host header override. Never calls a run-history or token
endpoint. No POST, no request body, no upload, no write, no forged header,
and no malformed input.

Sources:
- https://github.com/advisories/GHSA-4cx6-qfwr-9vfq
- https://nvd.nist.gov/vuln/detail/CVE-2026-134825
- https://osv.dev/vulnerability/CVE-2026-134825
- https://www.vulncheck.com/advisories/gradio-6.27.0-before-6.32.0-authentication-bypass-via-forged-host-header
- https://github.com/gradio-app/gradio/pull/14050
- https://github.com/gradio-app/gradio/commit/fda8037b83f316454e96201dfad96e50944f8547
- https://github.com/gradio-app/gradio/releases/tag/gradio%406.32.0
- https://github.com/gradio-app/gradio/blob/gradio@6.27.0/gradio/routes.py
- https://github.com/gradio-app/gradio/blob/gradio@6.27.0/gradio/blocks.py
- https://github.com/gradio-app/gradio/blob/gradio@6.27.0/gradio/route_utils.py
- https://github.com/gradio-app/gradio/blob/gradio@6.32.0/gradio/routes.py
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv
"""
import json
import re

from .client import fetch_path
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt


CONFIG = "/config"
_INTRODUCED = (6, 27, 0)
_FIXED = (6, 32, 0)
_API_PREFIX = "/gradio_api"
_PROTOCOL = "sse_v3"
_EXACT = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")

_SOURCES = (
    "https://github.com/advisories/GHSA-4cx6-qfwr-9vfq",
    "https://nvd.nist.gov/vuln/detail/CVE-2026-134825",
    "https://osv.dev/vulnerability/CVE-2026-134825",
    "https://github.com/gradio-app/gradio/releases/tag/gradio%406.32.0",
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
)


def _load(body: str):
    try:
        return json.loads(body or "")
    except (json.JSONDecodeError, TypeError):
        return None


def config_document(body: str) -> dict | None:
    """Parsed Gradio ``GET /config`` object, or None when it is not that document.

    The shape is Gradio 6.x ``Blocks.get_config_file``: ``api_prefix`` is
    ``/gradio_api``, ``protocol`` is ``sse_v3``, ``mode`` is a string, and
    ``components`` is a list. A version is not required here.
    """
    obj = _load(body)
    if not isinstance(obj, dict):
        return None
    if obj.get("api_prefix") != _API_PREFIX:
        return None
    if obj.get("protocol") != _PROTOCOL:
        return None
    mode = obj.get("mode")
    if not isinstance(mode, str) or not mode.strip():
        return None
    if not isinstance(obj.get("components"), list):
        return None
    return obj


def config_version(obj: dict) -> tuple[int, int, int] | None:
    """Exact ``version`` release, or None when the field is missing or not ``X.Y.Z``.

    Gradio writes the installed package version as a string. A suffix, a
    pre-release, a number, or a missing field is not evidence.
    """
    raw = obj.get("version") if isinstance(obj, dict) else None
    if not isinstance(raw, str):
        return None
    match = _EXACT.match(raw.strip())
    if match is None:
        return None
    major, minor, patch = (int(part) for part in match.groups())
    return (major, minor, patch)


def affected(version: tuple[int, ...]) -> bool:
    """True for an exact three-part version in ``6.27.0 <= v < 6.32.0``."""
    if len(version) != 3:
        return False
    return cmp_ver(version, _INTRODUCED) >= 0 and cmp_ver(version, _FIXED) < 0


def _fix() -> str:
    return (
        "Upgrade Gradio to 6.32.0 or later. That release stops using the "
        "operator's saved Hugging Face token for a request that only looks "
        "local, and run history uses the visitor's own token instead. Until "
        "then, do not enable ssr_mode on a host that untrusted clients can "
        f"reach, and remove any Hugging Face token saved on that host. See {CHECK.cve}."
    )


def _sources_note() -> str:
    return "Sources: " + "; ".join(_SOURCES) + "."


def _passive_note() -> str:
    return (
        f"Only a read-only GET of {CONFIG} was sent, with no request body. "
        "No Host header override was sent. No run-history or token endpoint "
        "was requested. No POST, upload, write, forged header, or malformed "
        "input was sent."
    )


def _vulnerable(version: tuple[int, int, int]) -> dict:
    label = fmt(version)
    return base_finding(
        CHECK,
        severity="high",
        title=(
            f"{UNCONFIRMED}: Gradio {label} likely vulnerable to {CHECK.cve}"
        ),
        evidence=(
            f"Observed Gradio {label} via GET {CONFIG} version field. "
            f"{UNCONFIRMED}. {label} is in 6.27.0 <= v < 6.32.0 and is "
            f"likely vulnerable to {CHECK.cve} (GHSA-4cx6-qfwr-9vfq, "
            "CVSS 4.0 8.3, CWE-290). The release is "
            "affected only if ssr_mode is enabled; the operator's HF token "
            "can be exposed. "
            "Fixed in 6.32.0. The public /config document does not include "
            "ssr_mode, so that setting was not confirmed. No exploitation "
            "reported. Not in the CISA KEV catalog (checked 24 November "
            f"2026). {_passive_note()} {_sources_note()}"
        ),
        fix=_fix(),
        match=f"gradio:{label}",
        layer="recon",
    )


def _unknown() -> dict:
    return base_finding(
        CHECK,
        severity="info",
        title=f"Gradio detected; version unknown ({CHECK.cve})",
        evidence=(
            f"GET {CONFIG} is a Gradio app config, but it has no comparable "
            f"version field. {CHECK.cve} was not compared (affected "
            "6.27.0 <= v < 6.32.0; fixed in 6.32.0). This is not a "
            f"vulnerability guess. {_passive_note()} {_sources_note()}"
        ),
        fix=_fix(),
        match="gradio:unknown",
        layer="recon",
    )


def run(section, ctx) -> list[dict]:
    resp = fetch_path(ctx, CONFIG, max_bytes=200_000)
    if resp.get("status") != 200:
        return []
    doc = config_document(resp.get("body") or "")
    if doc is None:
        return []
    version = config_version(doc)
    if version is None:
        return [_unknown()]
    if affected(version):
        return [_vulnerable(version)]
    return []


CHECK = CveCheck(
    id="gradio",
    cve="CVE-2026-134825",
    # Exposed Gradio is a reconnaissance fingerprint. ssr_mode is not in
    # /config, so the check does not confirm that misconfiguration.
    agent="recon",
    fixed="6.32.0 (affected: Gradio 6.27.0 <= v < 6.32.0)",
    summary=(
        "One GET /config on the in-scope origin (Gradio's app config JSON). "
        "High, likely vulnerable, when the version field is an exact release "
        "in 6.27.0 <= v < 6.32.0 (fixed in 6.32.0). Evidence notes the "
        "release is affected only if ssr_mode is enabled; the operator's HF "
        "token can be exposed. No exploitation reported; not CISA KEV. Info "
        "(unknown) when the body is a Gradio config but version cannot be "
        "parsed. 6.26.9 and earlier, 6.32.0 and later, a non-200 response, "
        "and non-Gradio HTML are not detected."
    ),
    sends=f"One GET of {CONFIG}. No request body.",
    does_not_send=(
        "Never sends a Host header override. Never requests run-history "
        "endpoints (/gradio_api/run-history/*, /gradio_api/runs) or any "
        "token endpoint. No POST, PUT, PATCH, or DELETE. No request body, "
        "no upload, no write, no forged header, and no malformed input. "
        "Exactly one read-only GET of /config."
    ),
    run=run,
)
