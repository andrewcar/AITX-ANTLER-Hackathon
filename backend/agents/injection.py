"""
Injection specialist — dispatched onto ONE input section (form field or query param).

Safe, deterministic probes (lab targets we own only). Each finding carries a
machine-checkable `check` so the verifier can re-confirm it on a fresh request.

Classes covered:
  - reflected XSS       marker reflected unescaped in the response
  - error-based SQLi    single quote triggers a SQL error
  - boolean-blind SQLi  true vs false condition changes the response size
  - command injection    ';id' yields command output (uid=...)
  - local file inclusion traversal to /etc/passwd yields root:...:0:0
"""
import random
import re
import string

import recon

SQL_ERRORS = [
    "you have an error in your sql syntax", "sql syntax", "mysql_fetch",
    "warning: mysqli", "warning: mysql", "pdoexception", "unclosed quotation",
    "quoted string not properly terminated", "ora-0", "sqlite", "psql:",
    "syntax error at or near",
]
UID_RE = re.compile(r"uid=\d+\(")
PASSWD_RE = re.compile(r"root:.*?:0:0:")
BOOL_MIN_DIFF = 24  # min response-size delta to call boolean-blind SQLi


def _mark() -> str:
    return "vqs" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


def _data(section: dict, param: str, value: str) -> dict:
    """Target param gets the payload; sibling inputs get filler so the form submits."""
    d = {param: value}
    for name in section.get("inputs", []):
        d.setdefault(name, "1")
    return d


def sql_error_in(body: str):
    low = body.lower()
    for s in SQL_ERRORS:
        if s in low:
            return s
    return None


def _mk(sev, title, evidence, fix, check):
    return {"layer": "injection", "severity": sev, "title": title,
            "evidence": evidence, "fix": fix, "source": "deterministic", "check": check}


def run(section: dict, ctx) -> list[dict]:
    sess = getattr(ctx, "session", None)
    url, param = section["url"], section["param"]
    method = section.get("method", "get")
    inputs = section.get("inputs", [])
    base_check = {"url": url, "param": param, "method": method, "inputs": inputs}
    out = []

    # --- reflected XSS ---
    mark = _mark()
    xss = f"<{mark}>"
    r = recon.send(url, method, _data(section, param, xss), sess)
    if xss in r.get("body", ""):
        out.append(_mk("high", f"Reflected XSS in '{param}'",
                       f"payload {xss!r} reflected unescaped in response from {url}",
                       f"Output-encode '{param}' before rendering; apply a CSP.",
                       {"type": "xss_reflect", **base_check}))

    # --- error-based SQLi ---
    r = recon.send(url, method, _data(section, param, "'"), sess)
    sig = sql_error_in(r.get("body", ""))
    if sig:
        out.append(_mk("high", f"SQL injection (error-based) in '{param}'",
                       f"single-quote payload triggered SQL error ('{sig}') from {url}",
                       f"Use parameterized queries for '{param}'.",
                       {"type": "sqli_error", **base_check}))
    else:
        # --- boolean-blind SQLi (only if no visible error) ---
        t = recon.send(url, method, _data(section, param, "1' AND '1'='1"), sess).get("body", "")
        f = recon.send(url, method, _data(section, param, "1' AND '1'='2"), sess).get("body", "")
        if t and f and abs(len(t) - len(f)) >= BOOL_MIN_DIFF:
            out.append(_mk("high", f"SQL injection (boolean-blind) in '{param}'",
                           f"true/false conditions changed response size ({len(t)} vs {len(f)} bytes)",
                           f"Use parameterized queries for '{param}'.",
                           {"type": "sqli_boolean",
                            "true": "1' AND '1'='1", "false": "1' AND '1'='2", **base_check}))

    # --- command injection ---
    r = recon.send(url, method, _data(section, param, "1;id"), sess)
    if UID_RE.search(r.get("body", "")):
        out.append(_mk("high", f"Command injection in '{param}'",
                       f"payload '1;id' returned command output (uid=...) from {url}",
                       f"Never pass '{param}' to a shell; use safe APIs / strict allowlists.",
                       {"type": "cmdi", "payload": "1;id", **base_check}))

    # --- local file inclusion ---
    lfi_payload = "../../../../../../../../etc/passwd"
    r = recon.send(url, method, _data(section, param, lfi_payload), sess)
    if PASSWD_RE.search(r.get("body", "")):
        out.append(_mk("high", f"Local file inclusion in '{param}'",
                       f"traversal payload exposed /etc/passwd (root:...:0:0) via {url}",
                       f"Do not use '{param}' in file paths; use an allowlist of files.",
                       {"type": "lfi", "payload": lfi_payload, **base_check}))

    return out
