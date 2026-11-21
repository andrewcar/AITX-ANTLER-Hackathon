"""MONAI Label datastore path traversal / arbitrary file write (CVE-2026-133968).

GHSA-qc22-rmgc-vg94, CVSS 9.8, CWE-22. ``PUT /datastore/image`` uses the
caller's ``image`` query parameter as the image id without validation;
``LocalDatastore.add_image()`` joins it onto the datastore directory and
``shutil.copy()``s the upload there, so ``../`` sequences write anywhere the
server user can write. ``PUT /datastore/label`` (``save_label``) has the same
flaw. Every released version is affected (through 0.8.5, the newest release,
October 2023). **No fixed release exists yet**: the fix is merged in source as
PR #1915 ("fix: confine datastore write paths", 2026-10-19) and ships in the
next release. Auth is off by default (``MONAI_LABEL_AUTH_ENABLE=False``), so
any network client can write files; with auth on, the ANNOTATOR role is
enough. Exploited in the wild: Amazon Threat Intelligence reports a
China-nexus actor whose Cairn autonomous AI agents found the bug and got root
on a university server by planting a Python startup file, then triggering
training.

Detection is read-only GETs, at most three, all verified against
``Project-MONAI/MONAILabel`` (``main`` and tag ``0.8.5``):

* ``GET /info/`` (``monailabel/endpoints/info.py``) returns
  ``MONAILabelApp.info()`` (``monailabel/interfaces/app.py``): ``name``,
  ``description``, ``version``, ``labels``, ``models``, ``trainers``,
  ``strategies``, ``scoring``, ``train_stats`` and ``datastore`` (from
  ``LocalDatastore.status()``: ``total``, ``completed``, ``label_tags``). The
  sample apps set ``name`` to ``"MONAILabel - <App> (<monailabel version>)"``
  and ``version`` to ``monailabel.__version__``; custom apps default
  ``version`` to the app's own ``"2.0"``, so ``version`` is trusted only when
  ``name`` names MONAILabel. The route sits behind ``RBAC(...)``, which only
  enforces a bearer token when auth is on: a 200 without credentials means
  auth is off.
* ``GET /auth/`` (``monailabel/endpoints/login.py``) returns ``enabled``,
  ``client_id`` and ``realm``. ``monailabel/app.py`` only mounts this router
  when ``MONAI_LABEL_AUTH_ENABLE`` is true. Requested only after ``/info/``
  answers 401/403.
* ``GET /openapi.json`` (FastAPI, ``title=settings.MONAI_LABEL_PROJECT_NAME``,
  default ``"MONAILabel"``). Fallback only when ``/info/`` is 401/403 and
  ``/auth/`` did not identify MONAI Label: title or the ``/datastore/image`` +
  ``/info/`` paths identify it; ``/auth/`` paths mean auth is on.

Never requests anything under ``/datastore``, never sends PUT/POST/DELETE, an
upload, a traversal payload, a token, or a training / inference trigger.

Sources:
https://github.com/Project-MONAI/MONAILabel/security/advisories/GHSA-qc22-rmgc-vg94
https://github.com/Project-MONAI/MONAILabel/pull/1915
https://osv.dev/vulnerability/CVE-2026-133968
https://aws.amazon.com/blogs/security/chinese-nexus-actors-cairn-ai-agents-found-a-zero-day-on-their-own/
https://thehackernews.com/2026/11/attackers-ai-agents-found-zero-day-in.html
"""
import json
import re

from .client import fetch_path
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, pad3, parse_dotted


INFO = "/info/"
AUTH = "/auth/"
OPENAPI = "/openapi.json"
_LAST_AFFECTED = (0, 8, 5)
_ADVISORY = "https://github.com/Project-MONAI/MONAILabel/security/advisories/GHSA-qc22-rmgc-vg94"
_FIX_PR = "https://github.com/Project-MONAI/MONAILabel/pull/1915"
_INFO_KEYS = ("name", "version", "labels", "models", "trainers", "strategies", "datastore")
_NAME_VERSION = re.compile(r"\(\s*v?(\d+\.\d+(?:\.\d+)?)[^)]*\)")
_OPENAPI_TITLE = re.compile(r'"title"\s*:\s*"MONAI\s*Label', re.I)
_GATED = (401, 403)


def _json(body: str):
    try:
        return json.loads(body or "")
    except json.JSONDecodeError:
        return None


def is_info_document(body: str) -> bool:
    """True for the ``MONAILabelApp.info()`` shape served at GET /info/."""
    obj = _json(body)
    if not isinstance(obj, dict):
        return False
    if any(key not in obj for key in _INFO_KEYS):
        return False
    store = obj.get("datastore")
    if not isinstance(store, dict) or "total" not in store or "completed" not in store:
        return False
    return isinstance(obj.get("models"), dict) and isinstance(obj.get("trainers"), dict)


def info_version(body: str) -> tuple[int, ...] | None:
    """MONAI Label package version from GET /info/, or None when it is not shown.

    The sample apps put ``monailabel.__version__`` in ``name`` ("MONAILabel -
    Radiology (0.8.5)") and in ``version``. A custom app's ``version`` is its
    own (default "2.0"), so it is only read when ``name`` names MONAILabel.
    """
    obj = _json(body)
    if not isinstance(obj, dict):
        return None
    name = str(obj.get("name") or "")
    if "monailabel" not in name.lower().replace(" ", ""):
        return None
    match = _NAME_VERSION.search(name)
    if match:
        return parse_dotted(match.group(1))
    return parse_dotted(str(obj.get("version") or "").strip().lstrip("vV"))


def auth_enabled_document(body: str) -> bool:
    """True for GET /auth/ ``{"enabled": true, "client_id": ..., "realm": ...}``."""
    obj = _json(body)
    if not isinstance(obj, dict):
        return False
    if not all(key in obj for key in ("enabled", "client_id", "realm")):
        return False
    return obj.get("enabled") is True


def openapi_fingerprint(body: str) -> tuple[bool, bool]:
    """(is MONAI Label, auth router mounted) from FastAPI's /openapi.json text."""
    text = body or ""
    is_monai = bool(_OPENAPI_TITLE.search(text)) or (
        '"/datastore/image"' in text and '"/info/"' in text
    )
    if not is_monai:
        return False, False
    return True, ('"/auth/"' in text or '"/auth/token"' in text)


def affected(version: tuple[int, ...]) -> bool:
    return cmp_ver(pad3(version), _LAST_AFFECTED) <= 0


def _fix() -> str:
    return (
        "No fixed MONAI Label release exists yet (all releases through 0.8.5 "
        "are affected). Until the next release ships PR #1915: set "
        "MONAI_LABEL_AUTH_ENABLE=true, grant the ANNOTATOR role only to trusted "
        "users, keep the server off untrusted networks (VPN / allowlist at the "
        "proxy, block PUT /datastore/* from outside), and run it as an "
        "unprivileged user that can only write to the datastore directory. If "
        "you run a source build, confirm it includes PR #1915. Look for "
        "unexpected Python startup files (*.pth, sitecustomize.py, "
        "usercustomize.py) in site-packages and unusual training jobs. "
        f"See {CHECK.cve}, {_ADVISORY} and {_FIX_PR}."
    )


def _sources_note() -> str:
    return (
        "Sources: GHSA-qc22-rmgc-vg94, PR #1915, OSV CVE-2026-133968, Amazon "
        "Threat Intelligence and The Hacker News (Cairn AI agents, exploited "
        "in the wild)."
    )


_NOT_SENT = (
    "Only read-only GETs were sent; nothing under /datastore was requested, "
    "and no PUT/POST, upload, traversal payload, token, or training trigger "
    "was sent."
)


def _auth_off(version: tuple[int, ...] | None) -> dict:
    if version is None:
        label = "version hidden"
        seen = (
            f"GET {INFO} returned the MONAI Label app-info document without "
            "credentials, but no MONAI Label version (custom app name)."
        )
        match = "monai-label:unknown:auth-off"
    else:
        label = fmt(pad3(version))
        seen = (
            f"GET {INFO} returned the MONAI Label app-info document without "
            f"credentials, showing MONAI Label {label} (at or below 0.8.5)."
        )
        match = f"monai-label:{label}:auth-off"
    return base_finding(
        CHECK,
        severity="critical",
        title=(
            f"{UNCONFIRMED}: MONAI Label ({label}) with auth disabled, "
            f"datastore arbitrary file write ({CHECK.cve})"
        ),
        evidence=(
            f"{seen} {UNCONFIRMED}. A 200 without a token means "
            "MONAI_LABEL_AUTH_ENABLE is off, so any network client can reach "
            f"PUT /datastore/image and PUT /datastore/label. {CHECK.cve} "
            "(GHSA-qc22-rmgc-vg94, CVSS 9.8, CWE-22): the unvalidated image id "
            "is joined onto the datastore path, giving arbitrary file write and "
            "RCE. All releases through 0.8.5 are affected and no fixed release "
            "exists yet (fix merged in source as PR #1915). Exploited in the "
            "wild (Amazon Threat Intelligence: Cairn AI agents got root on a "
            "university server). A source build after 2026-10-19 may already "
            f"include the fix. {_NOT_SENT} {_sources_note()}"
        ),
        fix=_fix(),
        match=match,
    )


def _auth_on(where: str) -> dict:
    return base_finding(
        CHECK,
        severity="high",
        title=(
            f"{UNCONFIRMED}: MONAI Label with auth enabled, datastore arbitrary "
            f"file write for any ANNOTATOR ({CHECK.cve})"
        ),
        evidence=(
            f"MONAI Label was identified via {where}; GET {INFO} needs a token, "
            f"so auth is on and the version is hidden. {UNCONFIRMED}. "
            f"{CHECK.cve} (GHSA-qc22-rmgc-vg94, CVSS 9.8, CWE-22) still lets any "
            "user with the ANNOTATOR role write arbitrary files through PUT "
            "/datastore/image or PUT /datastore/label. All releases through "
            "0.8.5 are affected and no fixed release exists yet (fix merged in "
            "source as PR #1915). Exploited in the wild. "
            f"{_NOT_SENT} {_sources_note()}"
        ),
        fix=_fix(),
        match="monai-label:unknown:auth-on",
    )


def _newer(version: tuple[int, ...]) -> dict:
    label = fmt(pad3(version))
    return base_finding(
        CHECK,
        severity="info",
        title=(
            f"MONAI Label {label} exposed without auth; confirm the build "
            f"includes PR #1915 ({CHECK.cve})"
        ),
        evidence=(
            f"GET {INFO} returned the MONAI Label app-info document without "
            f"credentials, showing MONAI Label {label}, newer than 0.8.5 (the "
            f"last release listed as affected by {CHECK.cve}). No fixed release "
            "had been published as of 2026-11-21, so this is likely a source or "
            "pre-release build: confirm it includes PR #1915 (\"fix: confine "
            "datastore write paths\"). Auth is off, so anyone on the network "
            f"can read and annotate the datastore. {_NOT_SENT}"
        ),
        fix=_fix(),
        match=f"monai-label:{label}:newer",
    )


def run(section, ctx) -> list[dict]:
    info = fetch_path(ctx, INFO, max_bytes=65536)
    status = info.get("status")
    body = info.get("body") or ""
    if status == 200:
        if not is_info_document(body):
            return []
        version = info_version(body)
        if version is not None and not affected(version):
            return [_newer(version)]
        return [_auth_off(version)]
    if status not in _GATED:
        return []
    auth = fetch_path(ctx, AUTH, max_bytes=4096)
    if auth.get("status") == 200 and auth_enabled_document(auth.get("body") or ""):
        return [_auth_on(f"GET {AUTH} (enabled: true)")]
    spec = fetch_path(ctx, OPENAPI, max_bytes=131072)
    if spec.get("status") != 200:
        return []
    is_monai, auth_paths = openapi_fingerprint(spec.get("body") or "")
    if not is_monai:
        return []
    mounted = "; /auth/ routes mounted" if auth_paths else ""
    return [_auth_on(f"GET {OPENAPI} (title / routes{mounted})")]


CHECK = CveCheck(
    id="monai-label",
    cve="CVE-2026-133968",
    agent="misconfig",
    fixed="none released (fix merged in source as PR #1915; all releases through 0.8.5 affected)",
    summary=(
        "Fingerprint MONAI Label with GET /info/ (then GET /auth/ and "
        "GET /openapi.json only when /info/ needs a token). Critical when "
        "/info/ answers without auth at version <= 0.8.5 or hidden; high when "
        "auth is on (ANNOTATOR can still exploit); info above 0.8.5. No fixed "
        "release exists yet."
    ),
    sends=(
        "GET /info/; GET /auth/ and GET /openapi.json only when /info/ answers "
        "401/403. At most three GETs."
    ),
    does_not_send=(
        "Never requests anything under /datastore. No PUT, POST, PATCH, or "
        "DELETE, no upload, no traversal payload (../), no token or login, no "
        "training, inference, or reload trigger, no exploit payload."
    ),
    run=run,
)
