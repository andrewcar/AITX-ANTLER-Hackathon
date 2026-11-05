"""Public dependency manifests, then known-vulnerable pins.

A readable requirements.txt, poetry.lock, package-lock.json, or similar file
is an exposure. The file is parsed in memory against ``vulnerable_pins.json``.
The first entry is datasets<=5.1.0 (CVE-2026-57845, unpatched pickle RCE).
"""
import random
import re
import string

import recon

from .client import fetch_path
from .pins import scan_manifest
from .spec import UNCONFIRMED, CveCheck, base_finding


# path, max response bytes. Add a sibling manifest by appending a row and a
# signature in ``_looks_real`` (parsers live in pins.scan_manifest).
FILES = (
    "/requirements.txt",
    "/poetry.lock",
    "/package-lock.json",
    "/yarn.lock",
    "/pnpm-lock.yaml",
    "/Pipfile.lock",
    "/composer.lock",
    "/Gemfile.lock",
)
_READ = 262144


def _looks_real(path: str, body: str) -> bool:
    if not body or recon.looks_like_app_html(body[:500]):
        return False
    if path.endswith("requirements.txt"):
        return bool(re.search(
            r"(?m)^[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]+\])?\s*(==|>=|<=|~=|!=|<|>)",
            body,
        ))
    if path.endswith("poetry.lock"):
        return "[[package]]" in body or "[metadata]" in body
    if path.endswith("package-lock.json"):
        return '"lockfileVersion"' in body
    if path.endswith("yarn.lock"):
        return "yarn lockfile" in body.lower() or '\n  version "' in body or "__metadata:" in body
    if path.endswith("pnpm-lock.yaml"):
        return "lockfileVersion" in body
    if path.endswith("Pipfile.lock"):
        return '"_meta"' in body
    if path.endswith("composer.lock"):
        return '"content-hash"' in body or '"packages"' in body
    if path.endswith("Gemfile.lock"):
        return "GEM" in body and "specs:" in body
    return False


def _same(left: dict, right: dict) -> bool:
    return (
        left.get("status") == right.get("status")
        and left.get("length") == right.get("length")
        and (left.get("body") or "")[:120] == (right.get("body") or "")[:120]
    )


def _baseline_path() -> str:
    token = "".join(random.choices(string.ascii_lowercase, k=12))
    return f"/vulnswarm-cve-{token}"


def run(section, ctx) -> list[dict]:
    baseline = fetch_path(ctx, _baseline_path(), max_bytes=_READ)
    findings = []
    for path in FILES:
        resp = fetch_path(ctx, path, max_bytes=_READ)
        if resp.get("status") != 200:
            continue
        body = resp.get("body") or ""
        if _same(resp, baseline) or not _looks_real(path, body):
            continue
        findings.append(base_finding(
            CHECK,
            severity="medium",
            title=f"Exposed dependency file: {path}",
            evidence=(
                f"GET {path} -> 200 ({resp.get('length')} bytes) and the body "
                "matches that manifest format. The file is publicly readable."
            ),
            fix=f"Remove {path} from the web root or block it. Dependency manifests list exact packages.",
            match=f"exposed:{path}",
        ))
        for hit in scan_manifest(path, body):
            fixed = hit["fixed"] or "no fixed release is listed"
            findings.append(base_finding(
                CHECK,
                severity="critical",
                title=(
                    f"{UNCONFIRMED}: {hit['name']} {hit['version']} "
                    f"in {path} ({hit['cve']})"
                ),
                evidence=(
                    f"{hit['name']} {hit['version']} in {path} matches {hit['affected']}. "
                    f"{UNCONFIRMED}. {hit['cve']}: {hit['summary']}. "
                    "The pin was read from the public file; nothing was installed or imported."
                ),
                fix=(
                    f"Stop publishing {path}. For {hit['name']} ({hit['cve']}, {hit['summary']}) "
                    f"the listed fix is: {fixed}."
                ),
                match=f"pin:{hit['cve']}:{hit['name']}@{hit['version']}:{path}",
            ))
    return findings


CHECK = CveCheck(
    id="dependency-files",
    cve="CVE-2026-57845",
    agent="secrets",
    fixed="datasets: no patched release listed (affected <=5.1.0)",
    summary=(
        "If requirements.txt, poetry.lock, package-lock.json, or a similar manifest "
        "is publicly readable, flag the exposure, then parse it for known-vulnerable "
        "pins. The pin list starts with datasets<=5.1.0 (unpatched pickle RCE) and "
        "is data in vulnerable_pins.json."
    ),
    sends="One baseline GET of a random path, then one GET per manifest path.",
    does_not_send="No package install, no import of the dependency, no pickle load, no POST.",
    run=run,
)
