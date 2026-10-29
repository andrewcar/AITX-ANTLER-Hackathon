"""
Orchestrator — the synchronized swarm.

Phases run as barriers (each completes before the next):

  AUTH   one shared session; log in if we recognize the target
  MAP    crawler discovers the site's sections
  PLAN   planner pairs sections with relevant specialists -> work units
  SWARM  specialists run the units IN PARALLEL, all writing to one shared context
  VERIFY verifier re-confirms every finding against a fresh observation
  REPORT reporter dedupes, ranks, summarizes

run_scan(url) is the blocking call behind POST /scan. Pass on_event to receive
JSON-ready snapshots as the scan moves (POST /scan/stream). Pass should_stop to
abandon the scan when the listener disconnects or the kill switch fires. The
flag is checked before every outbound request, not only between phases.
Neither argument changes the dict returned by a scan that runs to completion.

Breadth = register a specialist in SPECIALISTS and have the planner emit units for it.
Scale = replace the thread pool / in-process context with a Redis queue + worker
processes across machines; the phase logic is unchanged.
"""
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

import auth
import control
import crawler
import fingerprint
import llm
import recon
import reporter
import verifier
from agents import config_headers, exposed_paths, injection
from context import ScanContext
from planner import plan

SPECIALISTS = {
    "config_headers": config_headers.run,
    "exposed_paths": exposed_paths.run,
    "injection": injection.run,
}

MAX_WORKERS = 8  # parallel specialists in the SWARM phase

PHASES = ("AUTH", "MAP", "PLAN", "SWARM", "VERIFY", "REPORT")


def run_scan(url: str, on_event=None, should_stop=None, run_id: str | None = None) -> dict:
    """Run the barrier pipeline. See the module docstring for on_event / should_stop.

    on_event is invoked from the scan thread and from swarm worker threads. It
    must be thread-safe. Payloads are snapshots: later verification mutates the
    finding dicts in the context, not the events already emitted.
    """
    run_id = run_id or ("run_" + _new_run_suffix())
    lease = control.current_lease()
    seq = {"n": 0}
    seq_lock = threading.Lock()

    def emit(kind: str, **data):
        if on_event is None:
            return
        on_event({"type": kind, "ts": time.time(), **data})

    def phase(name: str, status: str, detail: dict | None = None):
        body = {"phase": name, "status": status}
        if detail:
            body["detail"] = detail
        emit("phase", **body)

    def next_id() -> int:
        with seq_lock:
            seq["n"] += 1
            return seq["n"]

    def stopped() -> bool:
        if lease is not None and lease.stopped():
            return True
        if control.stopped():
            return True
        return bool(should_stop and should_stop())

    def cancelled() -> dict:
        emit(
            "scan_complete",
            status="cancelled",
            run_id=run_id,
            target=url,
            summary={"total": 0, "confirmed": 0, "unverified": 0, "rejected": 0},
            findings=[],
            recon={"status": None, "server": "", "scanned_internal": False},
        )
        return {"run_id": run_id, "status": "cancelled"}

    def _pipeline() -> dict:
        emit("scan_started", url=url, run_id=run_id, agents=list(SPECIALISTS))
        if stopped():
            return cancelled()

        # AUTH — one shared session; log in if we recognize the target
        phase("AUTH", "started")
        session = recon.Session()
        with control.agent("auth"):
            auth_result = auth.maybe_login(url, session)
        phase("AUTH", "finished", {
            "authenticated": bool(auth_result.get("authenticated")),
            "scheme": auth_result.get("scheme") or "none",
            "note": auth_result.get("note") or "",
        })
        if stopped():
            return cancelled()

        # MAP — recon + crawl AS the logged-in session
        phase("MAP", "started")
        with control.agent("crawler"):
            root = recon.scan(url, session)
            ctx = ScanContext(url=url, recon_root=root, session=session, auth=auth_result, run_id=run_id)
            ctx.surface = crawler.map_site(url, session)
        ctx.fingerprint = fingerprint.detect(root, ctx.surface)
        surface_counts = {
            "pages": len(ctx.surface.get("pages", [])),
            "forms": len(ctx.surface.get("forms", [])),
            "params": len(ctx.surface.get("params", [])),
        }
        phase("MAP", "finished", {
            **surface_counts,
            "status": root.get("status"),
            "server": root.get("server") or "",
            "stack": ctx.fingerprint.get("stack") or "unknown",
            "lang": ctx.fingerprint.get("lang") or "unknown",
        })
        if stopped():
            return cancelled()

        # PLAN
        phase("PLAN", "started")
        units = plan(ctx)
        for i, unit in enumerate(units):
            unit.setdefault("id", f"u{i:03d}")
        counts = Counter(u["specialist"] for u in units)
        by_agent = {name: counts[name] for name in _agent_order(counts)}
        phase("PLAN", "finished", {"units": len(units), "by_agent": by_agent})
        if stopped():
            return cancelled()

        # SWARM — run units in parallel; each specialist appends to the shared context
        phase("SWARM", "started", {"units": len(units), "agents": list(by_agent)})

        def _run_unit(unit):
            with control.scope(lease):
                agent_name = unit["specialist"]
                with control.agent(agent_name):
                    if stopped():
                        return
                    section = unit.get("section") if isinstance(unit.get("section"), dict) else {}
                    unit_id = unit.get("id") or ""
                    label = _section_label(section)
                    brief = _section_brief(section)
                    emit(
                        "agent",
                        agent=agent_name,
                        status="started",
                        unit_id=unit_id,
                        section=brief,
                        label=label,
                    )
                    fn = SPECIALISTS.get(agent_name)
                    found: list = []
                    error = None
                    if not fn:
                        error = "unknown_specialist"
                    else:
                        try:
                            found = fn(section, ctx) or []
                            ctx.add(found, agent=agent_name, section=section)
                        except control.ScanStopped:
                            found = []
                            error = "stopped"
                        except Exception as e:
                            found = []
                            error = type(e).__name__
                        else:
                            for item in found:
                                if not isinstance(item, dict):
                                    continue
                                sid = next_id()
                                item["_stream_id"] = sid
                                emit("finding", unit_id=unit_id, **_public_finding(item, sid, label))
                    done = {
                        "agent": agent_name,
                        "status": "finished",
                        "unit_id": unit_id,
                        "section": brief,
                        "label": label,
                        "findings": len(found),
                    }
                    if error:
                        done["error"] = error
                    emit("agent", **done)

        pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)
        try:
            futures = [pool.submit(_run_unit, unit) for unit in units]
            for fut in futures:
                if stopped():
                    break
                fut.result()
        finally:
            # cancel_futures drops units that have not started. In-flight units
            # see the stop flag on their next outbound request and return.
            pool.shutdown(wait=True, cancel_futures=True)

        phase("SWARM", "finished", {"findings": len(ctx.findings)})
        if stopped():
            return cancelled()

        # VERIFY
        phase("VERIFY", "started")

        def _on_verdict(finding: dict):
            emit(
                "verdict",
                stream_id=finding.get("_stream_id"),
                verdict=finding.get("verdict") or "unverified",
                verified=bool(finding.get("verified")),
                verify_note=finding.get("verify_note") or "",
                severity=str(finding.get("severity") or "info").lower(),
                title=finding.get("title") or "",
                agent=finding.get("agent") or "",
            )

        with control.agent("verifier"):
            verified = verifier.verify_all(ctx.findings, url, session, on_verdict=_on_verdict)
        tally = {"confirmed": 0, "unverified": 0, "rejected": 0}
        for finding in verified:
            bucket = finding.get("verdict") or "unverified"
            tally[bucket] = tally.get(bucket, 0) + 1
        phase("VERIFY", "finished", tally)
        if stopped():
            return cancelled()

        # REPORT
        phase("REPORT", "started")
        rep = reporter.report(verified)
        phase("REPORT", "finished", rep["summary"])

        specialists_run = sorted({u["specialist"] for u in units})
        result = {
            "run_id": ctx.run_id,
            "auth": ctx.auth,
            "fingerprint": ctx.fingerprint,
            "surface": surface_counts,
            "units": len(units),
            "specialists_run": specialists_run,
            "recon": {
                "status": root["status"],
                "server": root["server"],
                "scanned_internal": root["scanned_internal"],
            },
            "model": llm.MODEL,
            "ai_available": llm.available(),
            **rep,
        }
        emit("scan_complete", status="complete", target=url, **result)
        return result

    try:
        return _pipeline()
    except control.ScanStopped:
        return cancelled()


def _new_run_suffix() -> str:
    import uuid
    return uuid.uuid4().hex[:10]


def _agent_order(names) -> list[str]:
    known = [name for name in SPECIALISTS if name in names]
    rest = sorted(name for name in names if name not in SPECIALISTS)
    return known + rest


def _section_brief(section: dict | None) -> dict:
    if not isinstance(section, dict):
        return {}
    brief = {}
    if section.get("kind"):
        brief["kind"] = section["kind"]
    if section.get("param"):
        brief["param"] = section["param"]
    if section.get("method"):
        brief["method"] = section["method"]
    return brief


def _section_label(section: dict | None) -> str:
    brief = _section_brief(section)
    if brief.get("param"):
        return str(brief["param"])
    return str(brief.get("kind") or "")


def _public_finding(finding: dict, stream_id: int, label: str) -> dict:
    """Fields the dashboard renders. The verifier `check` payload stays server-side."""
    return {
        "stream_id": stream_id,
        "agent": finding.get("agent") or "?",
        "layer": finding.get("layer") or "info",
        "severity": str(finding.get("severity") or "info").lower(),
        "title": finding.get("title") or "Untitled finding",
        "evidence": finding.get("evidence") or "",
        "fix": finding.get("fix") or "",
        "source": finding.get("source") or "",
        "section": label,
    }
