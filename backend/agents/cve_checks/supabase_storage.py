"""Self-hosted Supabase Storage — GHSA-fgvp-cqg6-q8h2 (and sibling GHSA-3m3f-pjv4-x2fp).

One unauthenticated GET of ``/storage/v1/version``. Upstream Storage registers
``GET /version`` in ``src/app.ts`` and returns the configured ``VERSION`` string
as plain text; Kong's self-hosted ``storage-v1`` route has no key-auth and strips
``/storage/v1``, so that same document is public at ``/storage/v1/version``.
Hosted ``*.supabase.co`` is already patched and is informational only.

Severity from the observed version alone (no JWT, no apikey, no upload):

- ``<= 1.89.8`` — critical (GHSA-fgvp-cqg6-q8h2 RLS bypass via role ``none``;
  sibling GHSA-3m3f-pjv4-x2fp also applies)
- ``1.89.9`` — high, sibling-only (GHSA-3m3f-pjv4-x2fp; primary fixed in 1.89.9)
- ``>= 1.89.10`` — clean
"""
import re
from urllib.parse import urlparse

from .client import base_url, fetch_path
from .spec import UNCONFIRMED, CveCheck, base_finding
from .versions import cmp_ver, fmt, pad3, parse_dotted


VERSION = "/storage/v1/version"
_PRIMARY_FIXED = (1, 89, 9)
_SIBLING_FIXED = (1, 89, 10)
_ADVISORY = "https://github.com/supabase/storage/security/advisories/GHSA-fgvp-cqg6-q8h2"
_SIBLING = "https://github.com/supabase/storage/security/advisories/GHSA-3m3f-pjv4-x2fp"
# Bare version document from GET /version (advisory reproduction prints e.g. 1.73.0).
_VERSION_DOC = re.compile(
    r"^\s*v?(\d+\.\d+\.\d+)(?:[.\-+][0-9A-Za-z]+)*\s*$",
    re.I,
)


def version_document(body: str) -> tuple[int, ...] | None:
    """Version from a bare Storage /version body, or None when it is not that document."""
    match = _VERSION_DOC.match(body or "")
    if not match:
        return None
    return parse_dotted(match.group(1))


def hosted_supabase(ctx) -> bool:
    """True for Supabase platform hosts (already patched; informational only)."""
    host = (urlparse(base_url(ctx)).hostname or "").lower()
    return host == "supabase.co" or host.endswith(".supabase.co")


def primary_affected(version: tuple[int, ...]) -> bool:
    """GHSA-fgvp-cqg6-q8h2: role ``none`` RLS bypass, fixed in 1.89.9."""
    return cmp_ver(pad3(version), _PRIMARY_FIXED) < 0


def sibling_affected(version: tuple[int, ...]) -> bool:
    """GHSA-3m3f-pjv4-x2fp: unsigned x-amz-copy-source on a presigned PUT, fixed in 1.89.10."""
    return cmp_ver(pad3(version), _SIBLING_FIXED) < 0


def _fix() -> str:
    return (
        "Upgrade self-hosted Supabase Storage (@supabase/storage-api) to 1.89.10 "
        f"or later. Primary advisory: {_ADVISORY}. Sibling advisory: {_SIBLING}. "
        "Hosted Supabase is already patched."
    )


def _hosted_finding(version: tuple[int, ...]) -> dict:
    label = fmt(pad3(version))
    return base_finding(
        CHECK,
        severity="info",
        title=f"Hosted Supabase Storage {label} observed ({CHECK.cve})",
        evidence=(
            f"Observed Storage {label} via GET {VERSION} on a *.supabase.co host. "
            "Hosted Supabase is already patched for GHSA-fgvp-cqg6-q8h2 and "
            "GHSA-3m3f-pjv4-x2fp; this note is informational only. "
            "Self-hosted deployments should still upgrade to 1.89.10+. "
            "No JWT, apikey, Authorization header, presigned URL, or "
            "x-amz-copy-source header was sent."
        ),
        fix=_fix(),
        match=f"supabase-storage:{label}:hosted",
    )


def _critical_finding(version: tuple[int, ...]) -> dict:
    label = fmt(pad3(version))
    return base_finding(
        CHECK,
        severity="critical",
        title=f"{UNCONFIRMED}: Supabase Storage {label} ({CHECK.cve})",
        evidence=(
            f"Observed self-hosted Supabase Storage {label} via GET {VERSION}. "
            f"{UNCONFIRMED}. {label} is <= 1.89.8 and appears affected by "
            "GHSA-fgvp-cqg6-q8h2 (CVSS 9.8): a signed JWT with role \"none\" "
            "could bypass Storage RLS. Sibling GHSA-3m3f-pjv4-x2fp (CVSS 7.1) "
            "also applies through 1.89.9. Fixed in 1.89.10+. "
            "No JWT, apikey, Authorization header, presigned URL, upload, "
            "bucket create, or x-amz-copy-source header was sent."
        ),
        fix=_fix(),
        match=f"supabase-storage:{label}:primary",
    )


def _sibling_finding(version: tuple[int, ...]) -> dict:
    label = fmt(pad3(version))
    return base_finding(
        CHECK,
        severity="high",
        title=f"{UNCONFIRMED}: Supabase Storage {label} sibling GHSA-3m3f-pjv4-x2fp",
        evidence=(
            f"Observed self-hosted Supabase Storage {label} via GET {VERSION}. "
            f"{UNCONFIRMED}. {label} is 1.89.9: GHSA-fgvp-cqg6-q8h2 is fixed, "
            "but sibling GHSA-3m3f-pjv4-x2fp (CVSS 7.1) still applies — a "
            "presigned PUT URL plus an unsigned x-amz-copy-source header could "
            "read across buckets. Upgrade to 1.89.10+. "
            "No JWT, apikey, Authorization header, presigned URL, upload, "
            "bucket create, or x-amz-copy-source header was sent."
        ),
        fix=_fix(),
        match=f"supabase-storage:{label}:sibling",
    )


def run(section, ctx) -> list[dict]:
    resp = fetch_path(ctx, VERSION, max_bytes=8192)
    if (resp.get("status") or 0) != 200:
        return []
    version = version_document(resp.get("body") or "")
    if version is None:
        return []
    if hosted_supabase(ctx):
        return [_hosted_finding(version)]
    if primary_affected(version):
        return [_critical_finding(version)]
    if sibling_affected(version):
        return [_sibling_finding(version)]
    return []


CHECK = CveCheck(
    id="supabase-storage",
    cve="GHSA-fgvp-cqg6-q8h2 / GHSA-3m3f-pjv4-x2fp",
    agent="misconfig",
    fixed="1.89.10+",
    summary=(
        "One GET /storage/v1/version on the in-scope origin. Critical when the "
        "version is <= 1.89.8 (GHSA-fgvp-cqg6-q8h2). High on 1.89.9 for sibling "
        "GHSA-3m3f-pjv4-x2fp only. *.supabase.co is informational (hosted patched)."
    ),
    sends="One GET /storage/v1/version on the in-scope origin.",
    does_not_send=(
        "No JWT (including role \"none\"), no Authorization or apikey header, "
        "no presigned URL, no x-amz-copy-source header, no upload, no bucket "
        "create, no write, no malformed input, no exploit payload."
    ),
    run=run,
)
