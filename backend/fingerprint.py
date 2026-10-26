"""
Fingerprint the target's tech stack so the planner can pick stack-aware checks.
Evidence-based only (headers, cookies, URL extensions) — no guessing.
"""


def detect(recon_root: dict, surface: dict) -> dict:
    headers = recon_root.get("raw_headers", {})
    cookies = " ".join(recon_root.get("set_cookie", [])).lower()
    server = (recon_root.get("server") or "").lower()
    powered = (headers.get("x-powered-by") or "").lower()
    page_urls = " ".join(p["url"] for p in surface.get("pages", [])).lower()

    stack, lang, evidence = "unknown", "unknown", []

    if "php" in powered or "phpsessid" in cookies or ".php" in page_urls:
        lang = "php"
        evidence.append("PHP markers (X-Powered-By / PHPSESSID / .php urls)")
    if "apache" in server:
        stack = "lamp" if lang == "php" else "apache"
        evidence.append(f"server: {server}")
    if "express" in powered or "x-powered-by: express" in powered:
        stack, lang = "node", "node"
        evidence.append("Express marker")
    if "nginx" in server:
        evidence.append(f"server: {server}")

    return {"stack": stack, "lang": lang, "server": server or "unknown",
            "evidence": evidence}
