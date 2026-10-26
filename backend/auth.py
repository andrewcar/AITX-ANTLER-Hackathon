"""
Auth — log the swarm into a target so it can reach authenticated sections.

Auto-detects DVWA (our PHP lab target) and logs in with lab creds, then sets the
security level to 'low' so the vulnerable modules are reachable. Returns a status
dict; the shared Session now holds the logged-in cookies for the whole scan.

Generic by design: add more target recipes here. Credentials come from env so they
are never hardcoded for real targets.
"""
import os
import re

import recon

DVWA_USER = os.environ.get("DVWA_USER", "admin")
DVWA_PASS = os.environ.get("DVWA_PASS", "password")

_TOKEN_RE = re.compile(r"name=['\"]user_token['\"]\s+value=['\"]([0-9a-f]+)['\"]", re.I)


def maybe_login(url: str, session: recon.Session) -> dict:
    base = url.rstrip("/")

    # detect DVWA by its login page
    login = recon.get(base + "/login.php", session)
    if login["status"] == 200 and ("dvwa" in login["body"].lower()
                                   or "damn vulnerable" in login["body"].lower()):
        return _dvwa_login(base, session)

    return {"authenticated": False, "scheme": "none",
            "note": "no known login detected; scanning as anonymous"}


def _dvwa_login(base: str, session: recon.Session) -> dict:
    page = recon.get(base + "/login.php", session)
    m = _TOKEN_RE.search(page["body"])
    token = m.group(1) if m else ""

    recon.send(base + "/login.php", "post", {
        "username": DVWA_USER, "password": DVWA_PASS,
        "user_token": token, "Login": "Login",
    }, session)

    # DVWA reads $_COOKIE['security'] — set it to reach the vulnerable modules at 'low'
    session.set_cookie("security", "low")

    check = recon.get(base + "/index.php", session)
    ok = "logout" in check["body"].lower() and "login.php" not in check["url"]
    return {
        "authenticated": ok,
        "scheme": "dvwa-form",
        "user": DVWA_USER,
        "security_level": "low",
        "note": "logged into DVWA" if ok else "DVWA login attempt did not confirm",
    }
