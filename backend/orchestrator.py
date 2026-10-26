"""
Orchestrator — the synchronized swarm.

Phases run as barriers (each completes before the next):

  MAP    crawler discovers the site's sections
  PLAN   planner pairs sections with relevant specialists -> work units
  SWARM  specialists run the units IN PARALLEL, all writing to one shared context
  VERIFY verifier re-confirms every finding against a fresh observation
  REPORT reporter dedupes, ranks, summarizes

Breadth = register a specialist in SPECIALISTS and have the planner emit units for it.
Scale = replace the thread pool / in-process context with a Redis queue + worker
processes across machines; the phase logic is unchanged.
"""
from concurrent.futures import ThreadPoolExecutor

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


def run_scan(url: str) -> dict:
    # MAP
    root = recon.scan(url)
    ctx = ScanContext(url=url, recon_root=root)
    ctx.surface = crawler.map_site(url)

    # (fingerprint informs planning / reporting)
    ctx.fingerprint = fingerprint.detect(root, ctx.surface)

    # PLAN
    units = plan(ctx)

    # SWARM — run units in parallel; each specialist appends to the shared context
    def _run_unit(unit):
        fn = SPECIALISTS.get(unit["specialist"])
        if not fn:
            return
        try:
            found = fn(unit["section"], ctx)
        except Exception:
            found = []
        ctx.add(found, agent=unit["specialist"], section=unit["section"])

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        list(pool.map(_run_unit, units))

    # VERIFY
    verified = verifier.verify_all(ctx.findings, url)

    # REPORT
    rep = reporter.report(verified)

    specialists_run = sorted({u["specialist"] for u in units})
    return {
        "run_id": ctx.run_id,
        "fingerprint": ctx.fingerprint,
        "surface": {
            "pages": len(ctx.surface.get("pages", [])),
            "forms": len(ctx.surface.get("forms", [])),
            "params": len(ctx.surface.get("params", [])),
        },
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
