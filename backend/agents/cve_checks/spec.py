"""Shape of one exploited-CVE check.

A new advisory is a new module plus one entry in ``registry.CHECKS``. The runner
does not grow a special case. ``agent`` is the swarm specialist the planner
schedules: misconfig, recon, auth, or secrets.
"""
from dataclasses import dataclass
from typing import Callable


AGENTS = ("misconfig", "recon", "auth", "secrets")

# Version comparisons are fingerprints. They must say this, and never that we exploited.
UNCONFIRMED = "version appears vulnerable (unconfirmed)"

_LAYER = {
    "misconfig": "config",
    "recon": "recon",
    "auth": "auth",
    "secrets": "surface",
}


@dataclass(frozen=True)
class CveCheck:
    id: str
    cve: str
    agent: str
    fixed: str
    summary: str
    sends: str
    does_not_send: str
    run: Callable[[dict, object], list]

    def __post_init__(self):
        if self.agent not in AGENTS:
            raise ValueError(f"{self.id}: agent {self.agent!r} is not one of {AGENTS}")


def base_finding(
    check: CveCheck,
    *,
    severity: str,
    title: str,
    evidence: str,
    fix: str,
    match: str,
    layer: str | None = None,
    once: bool = False,
) -> dict:
    """A deterministic finding the verifier can re-run by ``match``."""
    payload = {"type": "cve", "id": check.id, "match": match}
    if once:
        # The verifier must not repeat a one-shot probe (the Brotli POST).
        payload["once"] = True
    return {
        "layer": layer or _LAYER[check.agent],
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "fix": fix,
        "source": "deterministic",
        "check": payload,
    }
