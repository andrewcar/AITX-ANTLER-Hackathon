"""MONAI Label datastore path traversal (CVE-2026-133968).

Passive fingerprint only. MONAI Label's app router mounts ``GET /info/``
(``monailabel/endpoints/info.py``, prefix ``/info``, route ``/``). Official
sample apps publish the package version there: ``version=monailabel.__version__``
and the same string in the app name, for example
``MONAILabel - Radiology (0.8.5)`` (``sample-apps/radiology/main.py``).
Authentication is off by default (``MONAI_LABEL_AUTH_ENABLE=False``), so that
GET answers without a challenge on a default server.

Affected releases are <= 0.8.5. Fixed in 0.8.6. A version is compared only when
the name and the version field agree on one exact ``X.Y.Z`` string. Anything
else (hidden, suffixed, or disagreed) is possible/unknown and is not marked
vulnerable.

One unauthenticated GET of ``/info/`` through ``fetch_path``. No POST, PUT, or
DELETE. The datastore write routes are never requested.
"""
import json
import re

from .client import fetch_path, root_observation
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt


INFO = "/info/"
_AFFECTED_MAX = (0, 8, 5)
_FIXED = (0, 8, 6)

# Official apps put the package version in both fields. Require an exact
# three-part string so a suffix, a two-part number, or the base-class app
# version ("2.0") cannot be treated as the server release.
_EXACT = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
_NAME_VER = re.compile(
    r"MONAILabel\b[^\n()]{0,80}\((\d+\.\d+\.\d+)\)",
    re.I,
)
_TITLE = re.compile(r"<title[^>]*>\s*MONAI\s*Label\b", re.I)
_INFO_KEYS = (
    "name",
    "description",
    "version",
    "labels",
    "models",
    "trainers",
    "strategies",
    "scoring",
    "train_stats",
    "datastore",
)

_ADVISORY = (
    "https://github.com/Project-MONAI/MONAILabel/security/advisories/GHSA-qc22-rmgc-vg94"
)
_GHSA_DB = "https://github.com/advisories/GHSA-2f43-rwqm-6h67"
_RELEASE = "https://github.com/Project-MONAI/MONAILabel/releases/tag/0.8.6"
_FIX_PR = "https://github.com/Project-MONAI/MONAILabel/pull/1915"
_THN = "https://thehackernews.com/2026/11/attackers-ai-agents-found-zero-day-in.html"


def _load(body: str):
    try:
        return json.loads(body or "")
    except (json.JSONDecodeError, TypeError):
        return None


def info_document(body: str) -> dict | None:
    """Parsed ``GET /info/`` object, or None when the body is not that document.

    The shape is ``MONAILabelApp.info()``: the app metadata keys plus dicts for
    models, strategies, and datastore, and "MONAILabel" in the name or
    description (official sample apps set the name to ``MONAILabel - ...``).
    """
    obj = _load(body)
    if not isinstance(obj, dict):
        return None
    if any(key not in obj for key in _INFO_KEYS):
        return None
    if not isinstance(obj.get("models"), dict):
        return None
    if not isinstance(obj.get("strategies"), dict):
        return None
    if not isinstance(obj.get("datastore"), dict):
        return None
    label = f"{obj.get('name') or ''} {obj.get('description') or ''}"
    compact = re.sub(r"\s+", "", label).lower()
    if "monailabel" not in compact:
        return None
    return obj


def server_version(obj: dict) -> tuple[int, int, int] | None:
    """Package version when name and version field agree, else None.

    Fail closed: a lone version field, a suffix (``0.8.5+local``), a
    pre-release, or two fields that disagree is not evidence.
    """
    name = str(obj.get("name") or "")
    raw = obj.get("version")
    if not isinstance(raw, str) or not _EXACT.match(raw.strip()):
        return None
    raw_s = raw.strip()
    named = _NAME_VER.search(name)
    if named is None or named.group(1) != raw_s:
        return None
    major, minor, patch = (int(part) for part in raw_s.split("."))
    return (major, minor, patch)


def vulnerable(version: tuple[int, ...]) -> bool:
    """True for an exact three-part version at or below 0.8.5."""
    if len(version) != 3:
        return False
    return cmp_ver(version, _AFFECTED_MAX) <= 0


def _headers(resp: dict) -> dict[str, str]:
    return {
        str(key).lower(): str(value)
        for key, value in (resp.get("headers") or {}).items()
    }


def auth_disabled(resp: dict) -> bool:
    """True when ``/info/`` answered 2xx with no authentication challenge."""
    status = resp.get("status") or 0
    if not (200 <= status < 300):
        return False
    return not _headers(resp).get("www-authenticate")


def text_has_title(text: str) -> bool:
    return bool(_TITLE.search(text or ""))


def collected_text(ctx) -> str:
    """Root body the scan already stored, plus crawled page URLs. No new request."""
    _headers_root, body = root_observation(ctx)
    parts = [body or ""]
    surface = getattr(ctx, "surface", None) or {}
    for page in surface.get("pages") or []:
        if isinstance(page, dict) and page.get("url"):
            parts.append(str(page["url"]))
        elif isinstance(page, str):
            parts.append(page)
    return "\n".join(parts)


def _sources() -> str:
    return (
        f"CVE-2026-133968. Affected: <= 0.8.5. Fixed in 0.8.6. "
        f"GHSA-qc22-rmgc-vg94 ({_ADVISORY}). "
        f"GHSA-2f43-rwqm-6h67 ({_GHSA_DB}). "
        f"Release 0.8.6 ({_RELEASE}). "
        f"Fix pull request {_FIX_PR}. "
        f"The Hacker News, November 2026 ({_THN}): exploited since September; "
        f"attackers' AI agents reportedly found it."
    )


def _fix() -> str:
    return (
        "Upgrade MONAI Label to 0.8.6 or later. Enable authentication "
        "(MONAI_LABEL_AUTH_ENABLE) and grant roles only to trusted users. "
        "Do not expose the MONAI Label server to untrusted networks. "
        + _sources()
    )


def _auth_note(open_answer: bool) -> str:
    if open_answer:
        return (
            " authentication disabled: GET /info/ answered without an "
            "authentication challenge."
        )
    return ""


def _vulnerable_finding(version: tuple[int, int, int], open_answer: bool) -> dict:
    label = fmt(version)
    auth = _auth_note(open_answer)
    title = f"{UNCONFIRMED}: MONAI Label {label} <= 0.8.5 ({CHECK.cve})"
    if open_answer:
        title += "; authentication disabled"
    return base_finding(
        CHECK,
        severity="critical",
        title=title,
        evidence=(
            f"Observed MONAI Label {label} via GET {INFO}. {UNCONFIRMED}. "
            f"{label} is <= 0.8.5 and appears affected by {CHECK.cve} "
            "(critical path traversal in the datastore upload endpoints; "
            "arbitrary file write and remote code execution). "
            f"Fixed in 0.8.6.{auth} "
            "Only a read-only GET of /info/ was sent. "
            + _sources()
        ),
        fix=_fix(),
        match=f"monai-label:{label}",
        layer="auth",
    )


def _unknown_finding(open_answer: bool, where: str) -> dict:
    auth = _auth_note(open_answer)
    title = f"MONAI Label detected; version unknown (possible {CHECK.cve})"
    if open_answer:
        title += "; authentication disabled"
    return base_finding(
        CHECK,
        severity="info",
        title=title,
        evidence=(
            f"MONAI Label was fingerprinted via {where}, but the package version "
            f"could not be determined. Possible {CHECK.cve}; the version was not "
            f"compared and this is not marked vulnerable. Affected when confirmed: "
            f"<= 0.8.5. Fixed in 0.8.6.{auth} "
            "Only a read-only GET of /info/ was sent. "
            + _sources()
        ),
        fix=_fix(),
        match="monai-label:unknown",
        layer="auth",
    )


def run(section, ctx) -> list[dict]:
    resp = fetch_path(ctx, INFO, max_bytes=65536)
    body = resp.get("body") or ""
    doc = info_document(body)
    cached = collected_text(ctx)
    cached_doc = None if doc is not None else info_document(cached)
    present = doc is not None or cached_doc is not None or text_has_title(body) or text_has_title(cached)
    if not present:
        return []
    # A live /info/ document is the only version source once it parsed.
    # A cached copy is used only when this GET did not return that document.
    if doc is not None:
        version = server_version(doc)
    elif cached_doc is not None:
        version = server_version(cached_doc)
    else:
        version = None
    open_answer = doc is not None and auth_disabled(resp)
    if version is None:
        where = f"GET {INFO}" if (doc is not None or text_has_title(body)) else "a response the scan already fetched"
        return [_unknown_finding(open_answer, where)]
    if not vulnerable(version):
        return []
    return [_vulnerable_finding(version, open_answer)]


CHECK = CveCheck(
    id="monai-label",
    cve="CVE-2026-133968",
    agent="auth",
    fixed="0.8.6",
    summary=(
        "One GET /info/ on the in-scope origin (MONAI Label's app info route). "
        "Critical, version unconfirmed, when the name and version field agree on "
        "a release <= 0.8.5. Notes authentication disabled when that GET answers "
        "with no challenge. Info (possible/unknown) when MONAI Label is present "
        "but the version cannot be read. 0.8.6 and later are not flagged."
    ),
    sends="One GET /info/ on the in-scope origin.",
    does_not_send=(
        "No POST, PUT, PATCH, or DELETE. No datastore write. No path-traversal "
        "string, no upload, no exploit payload, no crafted header, no malformed "
        "input, no brute force."
    ),
    run=run,
)
