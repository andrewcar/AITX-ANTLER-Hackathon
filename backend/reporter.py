"""
Reporter — turns verified findings into one clean, ranked report.

- de-duplicates (deterministic + AI often flag the same thing); keeps the stronger copy
- assigns stable ids
- ranks: confirmed before unconfirmed, then by severity, then by source (deterministic first)
"""
SEV_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
VERDICT_ORDER = {"confirmed": 2, "unverified": 1, "rejected": 0}


def _key(f: dict) -> tuple:
    # same layer + same header/cookie, or same normalized title -> same issue
    chk = f.get("check", {})
    if chk.get("type") == "missing_header":
        return ("config", "hdr:" + chk["header"])
    if chk.get("type") == "cookie_flag":
        return ("cookie", f"cookie:{chk['cookie']}:{chk['flag']}")
    return (f.get("layer", ""), f.get("title", "").strip().lower()[:50])


def _rank(f: dict) -> tuple:
    return (
        VERDICT_ORDER.get(f.get("verdict", "unverified"), 1),
        SEV_ORDER.get(f.get("severity", "info"), 1),
        1 if f.get("source") == "deterministic" else 0,
    )


def report(findings: list[dict]) -> dict:
    # dedupe: keep the best-ranked copy of each distinct issue
    best: dict = {}
    for f in findings:
        k = _key(f)
        if k not in best or _rank(f) > _rank(best[k]):
            best[k] = f

    merged = sorted(best.values(), key=_rank, reverse=True)

    out = []
    for i, f in enumerate(merged, 1):
        out.append({
            "id": f"F-{i:03d}",
            "agent": f.get("agent", "?"),
            "layer": f.get("layer", "info"),
            "severity": f.get("severity", "info"),
            "title": f.get("title", ""),
            "evidence": f.get("evidence", ""),
            "fix": f.get("fix", ""),
            "source": f.get("source", "?"),
            "verified": f.get("verified", False),
            "verdict": f.get("verdict", "unverified"),
            "verify_note": f.get("verify_note", ""),
        })

    counts = {"confirmed": 0, "unverified": 0, "rejected": 0}
    for f in out:
        counts[f["verdict"]] = counts.get(f["verdict"], 0) + 1

    return {"findings": out, "summary": {"total": len(out), **counts}}
