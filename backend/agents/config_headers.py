"""
Config / headers specialist agent.

Produces two kinds of findings from recon data:
  - deterministic: directly observed facts (missing header, insecure cookie, version
    banner). Each carries a `check` dict so the verifier can RE-CONFIRM it exactly.
  - ai: Featherless triage of the same real data (nuance a static check misses).

The agent only observes/triages — it never decides a finding is trustworthy. That's
the verifier's job.
"""
import re

import llm

HEADER_FIX = {
    "content-security-policy": "Set a Content-Security-Policy scoped to your origins.",
    "strict-transport-security": "Set Strict-Transport-Security (HSTS) with a long max-age.",
    "x-frame-options": "Set X-Frame-Options: DENY (or a CSP frame-ancestors).",
    "x-content-type-options": "Set X-Content-Type-Options: nosniff.",
    "referrer-policy": "Set Referrer-Policy: no-referrer or strict-origin-when-cross-origin.",
    "permissions-policy": "Set a Permissions-Policy restricting unused browser features.",
}


def _cookie_name(raw: str) -> str:
    return raw.split("=", 1)[0].strip()


def run(recon_data: dict) -> list[dict]:
    findings: list[dict] = []

    # --- deterministic: missing security headers ---
    for h in recon_data.get("missing_security_headers", []):
        findings.append({
            "layer": "config",
            "severity": "low",
            "title": f"Missing security header: {h}",
            "evidence": f"HTTP {recon_data['status']} response had no '{h}' header",
            "fix": HEADER_FIX.get(h, f"Set the '{h}' response header."),
            "source": "deterministic",
            "check": {"type": "missing_header", "header": h},
        })

    # --- deterministic: insecure cookies (missing HttpOnly / Secure) ---
    for raw in recon_data.get("set_cookie", []):
        low = raw.lower()
        name = _cookie_name(raw)
        for flag in ("httponly", "secure"):
            if flag not in low:
                findings.append({
                    "layer": "cookie",
                    "severity": "medium" if flag == "httponly" else "low",
                    "title": f"Cookie '{name}' missing {flag.capitalize()} flag",
                    "evidence": f"Set-Cookie: {raw}",
                    "fix": f"Add the {flag.capitalize()} attribute to the '{name}' cookie.",
                    "source": "deterministic",
                    "check": {"type": "cookie_flag", "cookie": name, "flag": flag},
                })

    # --- deterministic: server version disclosure ---
    server = recon_data.get("server", "")
    if server and re.search(r"\d", server):
        findings.append({
            "layer": "info",
            "severity": "info",
            "title": "Server version disclosed",
            "evidence": f"Server: {server}",
            "fix": "Suppress version details in the Server header.",
            "source": "deterministic",
            "check": {"type": "server_version"},
        })

    # --- AI triage of the same real data ---
    if llm.available():
        try:
            findings.extend(llm.analyze(recon_data))
        except Exception:
            pass  # orchestrator records AI status separately; don't fail the agent

    return findings
