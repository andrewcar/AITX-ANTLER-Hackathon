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
    app = "unknown"

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
    if ("_gitlab_session" in cookies or any(h.startswith("x-gitlab-") for h in headers)
            or "/users/sign_in" in page_urls):
        app = "gitlab"
        evidence.append("GitLab markers (_gitlab_session / X-Gitlab-* / /users/sign_in)")

    return {"stack": stack, "lang": lang, "app": app, "server": server or "unknown",
            "evidence": evidence}
