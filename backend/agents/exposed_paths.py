"""
Surface / exposed-paths specialist agent.

Probes sensitive paths and reports the ones genuinely reachable. All findings are
deterministic + verifiable (each carries a re-checkable `check`).

False-positive control (apps like Juice Shop return 200 for ANY path):
  1. baseline: probe a random nonsense path. If a sensitive path returns the SAME
     response as that baseline, it's the catch-all serving the app -> not a real file.
  2. expect_file paths (.env, .git, backups) must NOT come back as app HTML.
  3. if a content signature is known, require it in the body.
"""
import random
import string

import recon

# (path, severity, content-signature-or-None, expect_file)
#   expect_file=True  -> response must look like a file, not the app's HTML shell
SENSITIVE = [
    ("/.git/HEAD", "high", "ref:", True),
    ("/.git/config", "high", "[core]", True),
    ("/.env", "high", None, True),
    ("/config/config.inc.php.bak", "high", None, True),
    ("/config.inc.php.bak", "high", None, True),
    ("/phpinfo.php", "high", "PHP Version", False),
    ("/setup.php", "medium", None, False),
    ("/server-status", "medium", "Apache", False),
    ("/.htaccess", "medium", None, True),
    ("/backup.zip", "high", None, True),
    ("/robots.txt", "info", None, True),
    ("/package.json", "low", "\"name\"", True),
    ("/composer.json", "low", "require", True),
    ("/ftp", "medium", None, False),  # Juice Shop exposes this directory listing
]


def _rand_path() -> str:
    return "/vulnswarm-" + "".join(random.choices(string.ascii_lowercase, k=12))


def _same_as(a: dict, b: dict) -> bool:
    return a["length"] == b["length"] and a["snippet"][:120] == b["snippet"][:120]


def run(section: dict, ctx) -> list[dict]:
    recon_data = ctx.recon_root
    base = (recon_data.get("url", "") or "").rstrip("/")
    if not base:
        return []

    baseline = recon.probe(base + _rand_path())

    findings = []
    for path, sev, sig, expect_file in SENSITIVE:
        r = recon.probe(base + path)
        if r["status"] != 200:
            continue
        if _same_as(r, baseline):
            continue  # catch-all serving the app shell -> not a real file
        if expect_file and recon.looks_like_app_html(r["snippet"]):
            continue  # a file path served as the app page -> not a real exposure
        if sig and sig.lower() not in r["snippet"].lower():
            continue

        findings.append({
            "layer": "surface",
            "severity": sev,
            "title": f"Exposed path: {path}",
            "evidence": f"GET {path} -> 200 ({r['length']} bytes)"
                        + (f"; matched {sig!r}" if sig else ""),
            "fix": f"Remove or restrict access to {path}.",
            "source": "deterministic",
            "check": {"type": "exposed_path", "path": path, "sig": sig,
                      "expect_file": expect_file},
        })
    return findings
