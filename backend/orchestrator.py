"""
Orchestrator — the swarm brain.

For now one specialist agent (config_headers). Breadth = registering more agents in
AGENTS; the verify -> report pipeline below does not change. That's the whole point of
building the vertical slice first: adding a layer is adding one entry here.

Flow:
  1. recon once (shared observation handed to every agent)
  2. fan out: run each enabled agent, tag findings with the agent name
  3. verify: re-observe + confirm/reject/ground every finding
  4. report: dedupe, rank, summarize
"""
import llm
import recon
import reporter
import verifier
from agents import config_headers

# the swarm roster. add agents here to expand breadth; pipeline is unchanged.
AGENTS = {
    "config_headers": config_headers.run,
}


def run_scan(url: str, enabled: list[str] | None = None) -> dict:
    # 1. shared recon observation
    data = recon.scan(url)

    # 2. fan out to specialist agents
    raw: list[dict] = []
    agents_run: list[str] = []
    for name, fn in AGENTS.items():
        if enabled and name not in enabled:
            continue
        agents_run.append(name)
        for f in fn(data):
            f["agent"] = name
            raw.append(f)

    # 3. verify every finding against a fresh observation
    verified = verifier.verify_all(raw, url)

    # 4. dedupe + rank + summarize
    rep = reporter.report(verified)

    return {
        "recon": {
            "status": data["status"],
            "server": data["server"],
            "scanned_internal": data["scanned_internal"],
        },
        "agents_run": agents_run,
        "model": llm.MODEL,
        "ai_available": llm.available(),
        **rep,  # findings + summary
    }
