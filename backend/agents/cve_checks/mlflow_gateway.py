"""MLflow AI Gateway (CVE-2026-4035) — one read of /version.

GET /version on the scan target. MLflow's tracking server answers with the
bare version string. Below 3.11.0 the AI Gateway would resolve a secret's
api_key against the server environment. A 2xx answer with no authentication
challenge is the higher severity (default deployments have no basic-auth).
The UI title and /static-files assets already collected by recon and the
crawler can fingerprint MLflow when /version itself is only a challenge.
"""
import re

from .client import fetch_path, root_observation
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, pad3, parse_dotted


VERSION = "/version"
_FIXED = (3, 11, 0)
# The whole body is the version. MLflow returns VERSION, 200 — nothing else.
_VERSION_DOC = re.compile(
    r"^\s*v?(\d+\.\d+\.\d+)(?:[.\-+][0-9A-Za-z]+)*\s*$",
    re.I,
)
_TITLE = re.compile(r"<title[^>]*>[^<]*mlflow[^<]*</title>", re.I)
_NEAR = re.compile(r"mlflow[^0-9]{0,48}v?(\d+\.\d+\.\d+)", re.I)


def version_document(body: str) -> tuple[int, ...] | None:
    """Version from a bare /version body, or None when the body is not that document."""
    match = _VERSION_DOC.match(body or "")
    if not match:
        return None
    return parse_dotted(match.group(1))


def below_fix(version: tuple[int, ...]) -> bool:
    return cmp_ver(pad3(version), _FIXED) < 0


def _headers(resp: dict) -> dict[str, str]:
    return {
        str(key).lower(): str(value)
        for key, value in (resp.get("headers") or {}).items()
    }


def auth_challenged(resp: dict) -> bool:
    """True when /version refused the anonymous GET or advertised a challenge."""
    if resp.get("status") in (401, 403):
        return True
    return bool(_headers(resp).get("www-authenticate"))


def open_answer(resp: dict) -> bool:
    """2xx with no challenge: the endpoint answered without asking for auth."""
    status = resp.get("status") or 0
    return 200 <= status < 300 and not auth_challenged(resp)


def collected_ui(ctx) -> str:
    """Title and asset URLs the crawl and the root GET already stored. No new request."""
    _headers_root, body = root_observation(ctx)
    parts = [body or ""]
    surface = getattr(ctx, "surface", None) or {}
    for page in surface.get("pages") or []:
        if isinstance(page, dict) and page.get("url"):
            parts.append(str(page["url"]))
    return "\n".join(parts)


def mlflow_ui(text: str) -> bool:
    blob = text or ""
    if _TITLE.search(blob):
        return True
    return "/static-files/" in blob.lower()


def ui_version(text: str) -> tuple[int, ...] | None:
    match = _NEAR.search(text or "")
    if not match:
        return None
    return parse_dotted(match.group(1))


def response_is_mlflow(resp: dict) -> bool:
    body = resp.get("body") or ""
    if version_document(body) is not None:
        return True
    challenge = _headers(resp).get("www-authenticate") or ""
    return "mlflow" in f"{body} {challenge}".lower()


def _fix() -> str:
    return (
        "Upgrade MLflow to 3.11.0 or later and leave "
        "MLFLOW_GATEWAY_RESOLVE_API_KEY_FROM_ENV unset or false except on an "
        "isolated legacy gateway. Enable basic-auth or an authenticating proxy. "
        "Restrict outbound egress to known provider api_base hosts. "
        f"Replace any $VAR api_key references. See {CHECK.cve}."
    )


def _finding(version: tuple[int, ...], resp: dict, where: str) -> dict:
    label = fmt(pad3(version))
    challenged = auth_challenged(resp)
    status = resp.get("status") or 0
    if open_answer(resp):
        severity = "high"
        auth_note = (
            f"GET {VERSION} answered HTTP {status} with no authentication "
            "challenge, which suggests basic-auth is not enabled."
        )
        state = "open"
    elif challenged:
        severity = "medium"
        scheme = _headers(resp).get("www-authenticate") or ""
        basic = " Basic" if scheme.lower().startswith("basic") else ""
        auth_note = (
            f"GET {VERSION} returned HTTP {status} with an authentication "
            f"challenge{basic}, which suggests basic-auth or an authenticating "
            "proxy is enabled. A low-privilege login may still reach the gateway."
        )
        state = "auth"
    else:
        severity = "medium"
        auth_note = (
            f"GET {VERSION} returned HTTP {status} and did not show whether "
            "basic-auth is enabled."
        )
        state = "unknown"
    return base_finding(
        CHECK,
        severity=severity,
        title=f"{UNCONFIRMED}: MLflow {label} ({CHECK.cve})",
        evidence=(
            f"Observed MLflow {label} via {where}. {UNCONFIRMED}. "
            f"{label} is below 3.11.0. {auth_note} "
            f"Advisory: {CHECK.cve}. Fixed in 3.11.0. "
            "No gateway route or secret was read or written, and no completion call was sent."
        ),
        fix=_fix(),
        match=f"mlflow:{label}:{state}",
    )


def run(section, ctx) -> list[dict]:
    resp = fetch_path(ctx, VERSION, max_bytes=8192)
    body = resp.get("body") or ""
    ui = collected_ui(ctx)
    version = version_document(body)
    where = f"GET {VERSION}"
    # A catch-all can serve the UI at /version. Read a version that sits next
    # to an MLflow title or the word MLflow in that same response.
    if version is None and (response_is_mlflow(resp) or mlflow_ui(body)):
        version = ui_version(body)
    if version is None:
        version = ui_version(ui)
        if version is not None:
            where = "the MLflow UI already collected by the crawl"
    if not (response_is_mlflow(resp) or mlflow_ui(ui) or mlflow_ui(body)):
        return []
    if version is None:
        return [base_finding(
            CHECK,
            severity="info",
            title=f"MLflow detected; version not exposed ({CHECK.cve})",
            evidence=(
                f"MLflow was fingerprinted, but GET {VERSION} did not return a "
                f"comparable version and the collected UI had none. {CHECK.cve} "
                "was not compared. No gateway route was requested."
            ),
            fix=_fix(),
            match="mlflow:unknown",
        )]
    if not below_fix(version):
        return []
    return [_finding(version, resp, where)]


CHECK = CveCheck(
    id="mlflow",
    cve="CVE-2026-4035",
    agent="misconfig",
    fixed="3.11.0",
    summary=(
        "Read the version from one GET /version, or from the MLflow UI title and "
        "assets the crawl already stored. Below 3.11.0 is an unconfirmed hit. "
        "Severity is high when that GET answers with no auth challenge, and lower "
        "when basic-auth challenges."
    ),
    sends="One GET /version on the in-scope origin.",
    does_not_send=(
        "No POST, PUT, PATCH, or DELETE. No gateway route or secret create, "
        "modify, or list. No completion or invocation call. No $ENV_VAR string, "
        "credential, or external callback URL."
    ),
    run=run,
)
