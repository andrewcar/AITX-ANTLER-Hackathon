# Fix playbook

One entry per check the swarm can confirm. Each entry says what the finding means,
how the swarm confirmed it (always non-destructive), and how to fix it.

## Flowise: MCP bearer token leaks through public chatflows (CVE-2026-130796)

**Finding title:** `version appears vulnerable (unconfirmed): Flowise <version> (CVE-2026-130796)` (high).
**Check id:** `flowise-mcp-token` (agent: `secrets`).

**What it is.** Flowise 3.1.3 and 3.1.4 return a chatflow's MCP server bearer token to
anyone who reads that chatflow through `GET /api/v1/public-chatflows/:id`. The token is
the only credential on `POST /api/v1/mcp/:chatflowId`, so an anonymous caller can run the
flow as an MCP tool, spend the owner's model credits and reach whatever the flow connects
to. Exposure needs two settings at once: the chatflow is public and its MCP server is on.
VulnCheck published the CVE on 2026-11-17 (CVSS 4.0 score 8.8). It is not in CISA KEV as of
2026-11-20. The Flowise project moved to a public archive on 2026-08-10, so **no fixed
version exists**.

**How the swarm confirms it (non-destructive).** One `GET /api/v1/version`. A version of
3.1.3 or 3.1.4 gives a "version appears vulnerable (unconfirmed)" finding. It never
requests the public-chatflow route or the MCP route, never sends or reads a token, and
never sends a POST. The version document alone does not name Flowise, so treat the
finding as a lead and confirm by hand on a system you own. The verifier re-reads the
same document on a fresh fetch.

**Fix.**
1. For every chatflow with its MCP server enabled, turn off the public flag, or disable the MCP server.
2. Rotate every MCP bearer token that was ever reachable, and review model-provider spend and logs for unknown callers.
3. Put Flowise behind authentication or a VPN and block `/api/v1/public-chatflows/*` and `/api/v1/mcp/*` at the proxy until you migrate.
4. Plan a move off Flowise. With no upstream patch, staying means maintaining a fork that returns a whitelisted projection from the public chatflow handler (leaving out `mcpServerConfig`).

**Sources:** [VulnCheck advisory](https://www.vulncheck.com/advisories/flowise-3.1.3-through-3.1.4-mcp-server-token-disclosure-via-public-chatflow-endpoint),
[The Injection write-up](https://theinjection.dev/items/vulncheck-flowise-mcp-token-public-chatflow/).
