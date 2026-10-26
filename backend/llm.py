"""
Featherless LLM client (OpenAI-compatible).

Role of the LLM in VulnSwarm: it does NOT go find vulnerabilities on its own (LLMs
hallucinate findings). It receives REAL data a scanner collected and triages/explains
it into structured findings. Grounded in real evidence, not guesses.

Config via env (set in backend/.env, loaded by docker compose):
    FEATHERLESS_API_KEY   required
    VULNSWARM_MODEL       model id (default: small 7B for plumbing; bump to 70B later)
"""
import json
import os

from openai import OpenAI

API_KEY = os.environ.get("FEATHERLESS_API_KEY", "")
MODEL = os.environ.get("VULNSWARM_MODEL", "Qwen/Qwen2.5-7B-Instruct")
BASE_URL = os.environ.get("FEATHERLESS_BASE_URL", "https://api.featherless.ai/v1")

_client = OpenAI(base_url=BASE_URL, api_key=API_KEY) if API_KEY else None

SYSTEM = (
    "You are a web security triage assistant. You are given REAL HTTP response data "
    "collected from a target the user is authorized to test. Identify concrete security "
    "issues that are SUPPORTED BY THE DATA ONLY. Do not invent issues you cannot see in "
    "the data. For each issue return an object with keys: layer (one of "
    "'config','transport','cookie','info'), severity (one of 'info','low','medium','high'), "
    "title (short), evidence (quote the exact header/value that shows it), fix (one concrete "
    "sentence). Respond with STRICT JSON: an object {\"findings\": [ ... ]}. No prose."
)


def available() -> bool:
    return _client is not None


def analyze(recon: dict) -> list[dict]:
    """Turn recon data into findings. Returns [] on any LLM error (caller handles)."""
    if _client is None:
        raise RuntimeError("FEATHERLESS_API_KEY not set")

    user = (
        "Target: " + recon.get("url", "?") + "\n"
        "HTTP status: " + str(recon.get("status")) + "\n"
        "Response headers (JSON):\n" + json.dumps(recon.get("raw_headers", {}), indent=2) + "\n"
        "Set-Cookie values (JSON):\n" + json.dumps(recon.get("set_cookie", []), indent=2) + "\n"
        "Analyze ONLY what these show."
    )

    resp = _client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}],
        temperature=0.1,
        max_tokens=1200,
    )
    text = resp.choices[0].message.content or "{}"

    # Models sometimes wrap JSON in ```json fences — strip them.
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text[text.find("{"):] if "{" in text else text

    data = json.loads(text)
    findings = data.get("findings", []) if isinstance(data, dict) else []

    # normalize into the shape the extension renders
    out = []
    for i, f in enumerate(findings, 1):
        out.append({
            "id": f"AI-{i:03d}",
            "layer": f.get("layer", "info"),
            "severity": f.get("severity", "info"),
            "title": f.get("title", "(no title)"),
            "evidence": f.get("evidence", ""),
            "verified": False,  # AI triage is unverified until a verifier agent confirms it
            "fix": f.get("fix", ""),
        })
    return out
