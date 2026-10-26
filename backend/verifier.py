"""
Verifier — the anti-hallucination step that makes findings trustworthy.

It takes a FRESH, independent observation of the target (a second fetch) and checks
each finding against it:

  - deterministic findings carry a `check` dict -> re-run that exact check.
      confirmed  = the condition still holds on the fresh observation
      rejected   = it does not (stale / flaky / wrong)
  - ai findings have no machine check -> GROUNDING check: is the evidence the model
    cited actually present in the real response data?
      confirmed  = the cited header/cookie genuinely exists in the fresh data
      rejected   = the cited evidence is NOT in the data (likely hallucinated)
      unverified = can't mechanically decide (a judgment-call claim) -> left for a human

Verdicts are honest: 'unverified' is a real outcome, not a failure. We never mark an
AI claim 'confirmed' unless its evidence is grounded in what we actually observed.
"""
import recon


def verify_all(findings: list[dict], url: str) -> list[dict]:
    """Re-observe the target once, then verify every finding against it."""
    try:
        fresh = recon.scan(url)
    except Exception as e:
        # can't get a fresh observation -> nothing can be confirmed
        for f in findings:
            f["verified"] = False
            f["verdict"] = "unverified"
            f["verify_note"] = f"no fresh observation ({type(e).__name__})"
        return findings

    fresh_headers = fresh.get("raw_headers", {})
    fresh_cookies = fresh.get("set_cookie", [])
    corpus = (" ".join(f"{k}: {v}" for k, v in fresh_headers.items()) + " "
              + " ".join(fresh_cookies)).lower()

    for f in findings:
        src = f.get("source")
        if src == "deterministic":
            v, verdict, note = _verify_deterministic(f, fresh, fresh_headers, fresh_cookies)
        else:
            v, verdict, note = _verify_ai(f, fresh_headers, fresh_cookies, corpus)
        f["verified"] = v
        f["verdict"] = verdict
        f["verify_note"] = note
    return findings


def _verify_deterministic(f, fresh, headers, cookies):
    chk = f.get("check", {})
    t = chk.get("type")

    if t == "missing_header":
        h = chk["header"]
        if h not in headers:
            return True, "confirmed", f"'{h}' still absent on re-fetch"
        return False, "rejected", f"'{h}' present on re-fetch: {headers[h]!r}"

    if t == "cookie_flag":
        name, flag = chk["cookie"], chk["flag"]
        matching = [c for c in cookies if c.split("=", 1)[0].strip() == name]
        if not matching:
            return False, "rejected", f"cookie '{name}' not set on re-fetch"
        if all(flag not in c.lower() for c in matching):
            return True, "confirmed", f"cookie '{name}' still lacks {flag}"
        return False, "rejected", f"cookie '{name}' now has {flag}"

    if t == "server_version":
        server = fresh.get("server", "")
        if server and any(ch.isdigit() for ch in server):
            return True, "confirmed", f"server banner still discloses version: {server!r}"
        return False, "rejected", "server banner no longer discloses a version"

    return False, "unverified", "no machine check for this finding"


def _verify_ai(f, headers, cookies, corpus):
    """Grounding: does the AI's cited evidence actually exist in the real response?"""
    ev = (f.get("evidence") or "").lower()
    if not ev:
        return False, "unverified", "AI finding had no quotable evidence"

    # 1. does the evidence reference a header that actually exists?
    referenced = [h for h in headers if h and h in ev]
    if referenced:
        return True, "confirmed", f"evidence grounded in real header(s): {', '.join(referenced)}"

    # 2. does it quote a cookie fragment that actually exists?
    for c in cookies:
        frag = c.split(";", 1)[0].strip().lower()  # name=value
        if frag and frag in corpus and frag in ev:
            return True, "confirmed", "evidence grounded in a real Set-Cookie value"

    # 3. a 'missing/absent' claim is a negative assertion we can't ground on presence;
    #    leave it for a human rather than wrongly confirming or rejecting.
    if any(w in ev for w in ("missing", "absent", "no ", "lack", "not set", "without")):
        return False, "unverified", "negative claim; not mechanically checkable here"

    # 4. evidence cites nothing we can find in the real data -> likely hallucinated
    return False, "rejected", "cited evidence not found in the actual response"
