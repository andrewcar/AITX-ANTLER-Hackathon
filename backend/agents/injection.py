"""
Injection specialist — dispatched onto ONE input section (a form field or query param).

Two safe, deterministic probes (lab targets we own only):
  - reflected XSS: inject a unique marker with angle brackets; if it comes back
    UNescaped in the response, the input reflects HTML -> XSS candidate.
  - error-based SQLi: inject a single quote; if the response shows a SQL error,
    the input reaches a query unsanitized -> SQLi candidate.

Both findings carry a machine-checkable `check` so the verifier can re-confirm them.
"""
import random
import string

import recon

SQL_ERRORS = [
    "you have an error in your sql syntax", "sql syntax", "mysql_fetch",
    "warning: mysqli", "warning: mysql", "pdoexception", "unclosed quotation",
    "quoted string not properly terminated", "ora-0", "sqlite", "psql:",
    "syntax error at or near",
]


def _mark() -> str:
    return "vqs" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


def _data(section: dict, param: str, value: str) -> dict:
    """Build the request body: target param gets the payload, siblings get filler."""
    d = {param: value}
    for name in section.get("inputs", []):
        d.setdefault(name, "test")
    return d


def sql_error_in(body: str) -> str | None:
    low = body.lower()
    for s in SQL_ERRORS:
        if s in low:
            return s
    return None


def run(section: dict, ctx) -> list[dict]:
    url, param = section["url"], section["param"]
    method = section.get("method", "get")
    findings = []

    # --- reflected XSS ---
    mark = _mark()
    payload = f'"><{mark}>'
    r = recon.send(url, method, _data(section, param, payload))
    if f"<{mark}>" in r.get("body", ""):
        findings.append({
            "layer": "injection", "severity": "high",
            "title": f"Reflected XSS in '{param}'",
            "evidence": f"payload '{payload}' reflected unescaped in response from {url}",
            "fix": f"Output-encode '{param}' before rendering; apply a CSP.",
            "source": "deterministic",
            "check": {"type": "xss_reflect", "url": url, "param": param,
                      "method": method, "inputs": section.get("inputs", [])},
        })

    # --- error-based SQLi ---
    r2 = recon.send(url, method, _data(section, param, "'"))
    sig = sql_error_in(r2.get("body", ""))
    if sig:
        findings.append({
            "layer": "injection", "severity": "high",
            "title": f"SQL injection (error-based) in '{param}'",
            "evidence": f"single-quote payload triggered SQL error ('{sig}') from {url}",
            "fix": f"Use parameterized queries for '{param}'; never concatenate input.",
            "source": "deterministic",
            "check": {"type": "sqli_error", "url": url, "param": param,
                      "method": method, "inputs": section.get("inputs", [])},
        })

    return findings
