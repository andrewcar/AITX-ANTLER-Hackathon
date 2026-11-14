"""Exploited-CVE checks. Recorded responses only — nothing here opens a socket."""
import json
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlparse

import pytest

import crawler
import control
import recon
import reporter
import verifier
from agents.cve_checks import CHECKS, php2shell, pins
from agents.cve_checks.dependency_files import FILES
from agents.cve_checks.magento import CHECK as MAGENTO
from agents.cve_checks.metabase import CHECK as METABASE
from agents.cve_checks.nextjs import CHECK as NEXT
from agents.cve_checks.nextjs_nov2026 import CHECK as NEXT_NOV2026
from agents.cve_checks.node_brotli import CHECK as BROTLI
from agents.cve_checks.node_brotli import TITLE as BROTLI_TITLE
from agents.cve_checks.nodered import CHECK as NODERED
from agents.cve_checks.langflow import CHECK as LANGFLOW
from agents.cve_checks.mlflow_gateway import CHECK as MLFLOW
from agents.cve_checks.spec import UNCONFIRMED
from agents.cve_checks.acf_extended_pro import CHECK as ACF_EXTENDED_PRO
from agents.cve_checks.amelia_pro import CHECK as AMELIA_PRO
from agents.cve_checks.contact_form_7 import CHECK as CONTACT_FORM_7
from agents.cve_checks.latepoint import CHECK as LATEPOINT
from agents.cve_checks.gpustack_auth import CHECK as GPUSTACK
from agents.cve_checks.registration_form_woocommerce import CHECK as TGWCFB
from agents.cve_checks.slicewp import CHECK as SLICEWP
from agents.cve_checks.gravity_forms import CHECK as GRAVITY_FORMS
from agents.cve_checks.commerce_core import CHECK as COMMERCE_CORE
from agents.cve_checks.apache_mod_http2 import CHECK as APACHE_MOD_HTTP2
from agents.cve_checks.supabase_storage import CHECK as SUPABASE_STORAGE
from agents.cve_checks.vite_dev_server import CHECK as VITE_DEV
from agents.cve_checks.vite_dev_server import CLIENT_PATH as VITE_CLIENT
from agents.cve_checks.vite_dev_server import TITLE as VITE_TITLE
from agents.cve_checks.vite_dev_server import affected_vite, affected_vite_plus
from agents.cve_checks.wedevs import CHECK as WEDEVS
from agents.cve_checks.wordpress import CHECK as WORDPRESS
from agents.cve_checks.xen_orchestra import CHECK as XEN_ORCHESTRA
from agents.cve_checks.wp_data_access import CHECK as WP_DATA_ACCESS
from agents.cve_checks.wp_duplicate import CHECK as WP_DUPLICATE
from agents.cve_checks.yootheme import CHECK as YOOTHEME
import planner
import main
import orchestrator
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
BANNED = (
    "reset_password",
    "phpinfo",
    "update-core",
    "upgrade.php",
    "/wp-admin/includes",
    "setup-config.php",
    "install.php",
    "/wp-json/amelia",
    "tag[",
    "tag%5B",
    "SLEEP(",
    "BENCHMARK(",
    "admin-ajax.php",
    "customer_cabinet__change_password",
    "steps__start_from_order_intent",
    "password_reset_token",
    "order_intent_key",
    "/@fs/",
    "/@id/",
    "__vite-browser-external",
    "__vite-optional-peer-dep",
    "/v2/users",
    "/v2/api-keys",
    "/v2/workers",
    "/v2/inference-backends",
    "from-yaml",
    "X-GPUStack-Real-IP",
    "admin-ajax",
    "/my-account",
    "woocommerce-register",
    "wpda/app",
    "wpda/app/update",
    "wpda/app/delete",
    "wpda/app/insert",
    "shortcode_preview",
    "render_field",
    "call_user_func",
    "acf-extended-pro/includes",
    "acfe_form",
)


def _ctx(headers=None, body="", server="", fingerprint=None, endpoints=None,
         forms=None, session=None):
    return SimpleNamespace(
        url="http://127.0.0.1:8081",
        recon_root={
            "url": "http://127.0.0.1:8081",
            "server": server,
            "raw_headers": headers or {},
            "body_snippet": body,
        },
        surface={
            "pages": [],
            "forms": forms or [],
            "params": [],
            "json_endpoints": endpoints or [],
        },
        session=session,
        fingerprint=fingerprint or {},
    )


def _get_json(url, status=200):
    """A crawl record: this scan already got 2xx JSON from a plain GET."""
    return {
        "url": url,
        "status": status,
        "method": "get",
        "source": "crawl",
        "content_type": "application/json",
    }


class Transport:
    def __init__(self):
        self.calls = []
        self.routes = {}
        self.post_status = 200
        self.post_body = '{"ok":true}'
        self.post_type = "application/json"

    def fetch(self, url, session=None, max_bytes=65536, follow=False):
        parsed = urlparse(url)
        path = parsed.path + (("?" + parsed.query) if parsed.query else "")
        self.calls.append(("GET", path, session, follow))
        spec = self.routes.get(path) or self.routes.get(parsed.path) or {}
        body = spec.get("body", "")
        headers = spec.get("headers") or {}
        ctype = spec.get("content_type", headers.get("content-type", "text/plain"))
        return {
            "url": url,
            "status": spec.get("status", 404),
            "content_type": ctype,
            "headers": headers,
            "body": body,
            "length": len(body.encode()),
        }

    def post(self, url, session=None):
        self.calls.append(("POST", urlparse(url).path, session, False))
        return {
            "url": url,
            "status": self.post_status,
            "content_type": self.post_type,
            "headers": {"content-type": self.post_type},
            "body": self.post_body,
            "length": len(self.post_body.encode()),
        }


def _install(monkeypatch, transport):
    monkeypatch.setattr(recon, "fetch", transport.fetch)
    monkeypatch.setattr(recon, "post_brotli_json", transport.post)

    def boom(*_a, **_k):
        raise AssertionError("CVE check used a request path other than fetch or post_brotli_json")

    monkeypatch.setattr(recon, "get", boom)
    monkeypatch.setattr(recon, "probe", boom)
    monkeypatch.setattr(recon, "send", boom)
    monkeypatch.setattr(recon, "_do", boom)


def _titles(findings):
    return [item["title"] for item in findings]


def _critical(findings):
    return [item for item in findings if item["severity"] == "critical"]


# --- registry and planner ---------------------------------------------------

def test_registry_ids_are_unique_and_each_check_is_planned_once():
    assert len({check.id for check in CHECKS}) == len(CHECKS)
    ctx = SimpleNamespace(url="http://127.0.0.1/", surface={"forms": [], "params": []})
    units = [unit for unit in planner.plan(ctx) if unit["section"].get("kind") == "cve"]
    assert [unit["section"]["check_id"] for unit in units] == [check.id for check in CHECKS]
    assert [unit["specialist"] for unit in units] == [check.agent for check in CHECKS]


def test_readme_lists_every_check_and_what_it_does_not_send():
    readme = (ROOT.parent / "README.md").read_text(encoding="utf-8")
    assert "## Exploited-CVE checks" in readme
    for check in CHECKS:
        assert f"`{check.id}`" in readme
        for token in check.cve.replace("(", " ").replace(")", " ").split("/"):
            token = token.strip()
            if token:
                assert token in readme
        assert "does not send" in readme.lower() or "What it does not send" in readme


def test_cve_modules_do_not_open_their_own_sockets():
    package = ROOT / "agents" / "cve_checks"
    for path in package.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "urlopen" not in text
        assert "http.client" not in text
        assert "requests." not in text


def test_quiet_target_is_get_only_and_avoids_exploit_paths(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    target = _ctx()
    for check in CHECKS:
        assert check.run({}, target) == []
    assert {call[0] for call in transport.calls} == {"GET"}
    assert all(call[2] is None and call[3] is False for call in transport.calls)
    paths = [call[1] for call in transport.calls]
    blob = " ".join(paths)
    for banned in BANNED:
        assert banned not in blob
    assert paths.count("/settings") == 1
    assert paths.count("/flows") == 1
    assert paths.count("/storage/v1/version") == 1
    assert paths.count("/version") == 2  # mlflow + gpustack
    assert paths.count("/wp-content/plugins/ameliabooking/readme.txt") == 1
    assert paths.count("/wp-content/plugins/contact-form-7/readme.txt") == 1
    assert paths.count("/wp-content/plugins/latepoint/readme.txt") == 1
    assert paths.count("/wp-content/plugins/local-sync/readme.txt") == 1
    # SliceWP only probes readme when the plugin path was already in crawled HTML.
    assert paths.count("/wp-content/plugins/slicewp/readme.txt") == 0
    # WP Data Access only probes readme after WordPress is confirmed from root HTML.
    assert paths.count("/wp-content/plugins/wp-data-access/readme.txt") == 0
    # ACF Extended PRO only probes after WordPress is visible in crawled HTML.
    assert paths.count("/wp-content/plugins/acf-extended-pro/readme.txt") == 0
    assert paths.count("/wp-content/plugins/acf-extended/readme.txt") == 0
    # Commerce Core only probes info.yml when Drupal + Commerce markup are present.
    assert paths.count("/modules/contrib/commerce/commerce.info.yml") == 0
    # Gravity Forms only probes change_log.txt when WordPress + plugin path are present.
    assert paths.count("/wp-content/plugins/gravityforms/change_log.txt") == 0
    assert paths.count("/wp-content/uploads/") == 0
    # yootheme fetch_page of in-scope `/` plus xen-orchestra fallback when recon body is empty
    assert paths.count("/") == 2
    assert paths.count(VITE_CLIENT) == 1
    assert "/api/v1/mcp" not in paths
    assert "/api/v1/auto_login" not in paths
    assert "/wp-json/pm/v2" not in paths
    assert "/_next/" not in blob
    assert "/rest/" not in blob
    assert "/rest/v0" not in blob
    assert "authenticationtoken" not in blob.lower()
    assert "/@fs/" not in blob
    assert "/@id/" not in blob
    assert "x-amz-copy-source" not in blob.lower()
    assert "apikey" not in blob.lower()
    assert "multipart" not in blob.lower()
    assert "wpcf7" not in blob.lower()
    assert "is null" not in blob.lower()
    assert "is not null" not in blob.lower()
    assert "x-gpustack-real-ip" not in blob.lower()
    assert "localsync" not in blob.lower()
    assert "slicewp" not in blob.lower()
    assert "wp-data-access" not in blob.lower()
    assert "wpda/app" not in blob.lower()
    assert "my-account" not in blob.lower()
    assert "commerce.info.yml" not in blob.lower()
    assert "jsonapi" not in blob.lower()
    assert all(
        path == "/wp-content/plugins/ameliabooking/readme.txt"
        or "ameliabooking" not in path
        for path in paths
    )
    assert all(
        path == "/wp-content/plugins/latepoint/readme.txt"
        or "latepoint" not in path
        for path in paths
    )
    assert all(
        path == "/wp-content/plugins/local-sync/readme.txt"
        or "local-sync" not in path
        for path in paths
    )
    assert all(
        "acf-extended" not in path
        for path in paths
    )


# --- PHP2Shell --------------------------------------------------------------

@pytest.mark.parametrize("version,vulnerable", [
    ("8.5.11", True), ("8.5.12", False),
    ("8.4.26", True), ("8.4.27", False),
    ("8.3.35", True), ("8.3.36", False),
    ("8.2.34", True), ("8.2.35", False),
    ("8.1.29", True), ("7.4.33", True), ("5.6.40", True),
    ("8.6.0", False),
])
def test_php_version_matrix(version, vulnerable):
    major, minor, patch = (int(part) for part in version.split("."))
    assert bool(php2shell.classify((major, minor, patch))) is vulnerable


def test_php_is_passive_and_unconfirmed(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    target = _ctx(headers={"x-powered-by": "PHP/8.2.34"})
    found = php2shell.run({}, target)
    assert transport.calls == []
    assert len(found) == 1
    assert found[0]["severity"] == "critical"
    assert UNCONFIRMED in found[0]["title"]
    assert UNCONFIRMED in found[0]["evidence"]
    assert "CVE-2026-109618" in found[0]["evidence"]
    assert "8.2.35" in found[0]["evidence"]
    assert php2shell.run({}, _ctx(headers={"x-powered-by": "PHP/8.2.35"})) == []
    body_hit = php2shell.run({}, _ctx(body="banner PHP/8.1.2"))
    assert body_hit and "EOL" in body_hit[0]["evidence"]


def test_verifier_confirms_php_then_rejects_a_fixed_build():
    found = php2shell.run({}, _ctx(headers={"x-powered-by": "PHP/8.3.35"}))[0]
    fresh = {
        "url": "http://127.0.0.1:8081",
        "raw_headers": {"x-powered-by": "PHP/8.3.35"},
        "body_snippet": "",
        "server": "",
    }
    ok, verdict, _note = verifier._verify_deterministic(
        found, fresh, fresh["raw_headers"], [], fresh["url"], None,
    )
    assert ok and verdict == "confirmed"
    fresh["raw_headers"] = {"x-powered-by": "PHP/8.3.36"}
    ok, verdict, _note = verifier._verify_deterministic(
        found, fresh, fresh["raw_headers"], [], fresh["url"], None,
    )
    assert not ok and verdict == "rejected"


# --- Next.js ----------------------------------------------------------------

@pytest.mark.parametrize("version,vulnerable", [
    ((15, 5, 27), True), ((15, 5, 28), False), ((15, 0, 0), True),
    ((16, 4, 0), True), ((16, 4, 1), False), ((16, 5, 0), False),
    ((14, 2, 5), False), ((17, 0, 0), False),
])
def test_next_version_matrix(version, vulnerable):
    from agents.cve_checks.nextjs import affected
    assert affected(version) is vulnerable


def test_next_hidden_version_is_info_and_manifest_is_one_get(monkeypatch):
    transport = Transport()
    transport.routes["/_next/static/abc123/_buildManifest.js"] = {
        "status": 200,
        "content_type": "application/javascript",
        "body": "self.__BUILD_MANIFEST = function(){return {}};",
    }
    _install(monkeypatch, transport)
    html = '<script src="/_next/static/abc123/pages/index.js"></script>'
    found = NEXT.run({}, _ctx(body=html))
    assert [call[1] for call in transport.calls] == ["/_next/static/abc123/_buildManifest.js"]
    assert found[0]["severity"] == "info"
    assert UNCONFIRMED not in found[0]["title"]
    assert "GHSA-2464-fhr4-w9xw" in found[0]["evidence"]


def test_next_header_version_does_not_fetch_and_flags_critical(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    found = NEXT.run({}, _ctx(headers={"x-nextjs-version": "15.5.1"}))
    assert transport.calls == []
    assert found[0]["severity"] == "critical"
    assert UNCONFIRMED in found[0]["evidence"]
    assert "15.5.28" in found[0]["evidence"]
    assert NEXT.run({}, _ctx(headers={"x-powered-by": "Next.js", "x-nextjs-version": "16.4.1"})) == []


# --- Next.js November 2026 (CVE-2026-119790) --------------------------------

@pytest.mark.parametrize("version,vulnerable", [
    ((16, 4, 1), True), ((16, 4, 5), False), ((16, 5, 0), False),
    ((15, 5, 20), True), ((15, 5, 29), False), ((15, 4, 0), True),
    ((15, 0, 0), True), ((14, 2, 5), False), ((17, 0, 0), False),
])
def test_next_nov2026_version_matrix(version, vulnerable):
    from agents.cve_checks.nextjs_nov2026 import outdated
    assert outdated(version) is vulnerable


def test_next_nov2026_powered_by_16_4_1_is_finding(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    found = NEXT_NOV2026.run({}, _ctx(headers={"x-powered-by": "Next.js 16.4.1"}))
    assert transport.calls == []
    assert len(found) == 1
    assert found[0]["severity"] == "critical"
    assert UNCONFIRMED in found[0]["title"]
    assert "CVE-2026-119790" in found[0]["evidence"]
    assert "GHSA-mfr8-8qww-v76h" in found[0]["evidence"]
    assert "16.4.5" in found[0]["evidence"]


def test_next_nov2026_powered_by_16_4_5_has_no_version_finding(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    assert NEXT_NOV2026.run({}, _ctx(headers={"x-powered-by": "Next.js 16.4.5"})) == []
    assert transport.calls == []


def test_next_nov2026_powered_by_15_5_20_is_finding(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    found = NEXT_NOV2026.run({}, _ctx(headers={"x-powered-by": "Next.js 15.5.20"}))
    assert transport.calls == []
    assert len(found) == 1
    assert UNCONFIRMED in found[0]["title"]
    assert "15.5.29" in found[0]["evidence"]
    assert "CVE-2026-119351" in found[0]["evidence"]


def test_next_nov2026_powered_by_15_5_29_has_no_version_finding(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    assert NEXT_NOV2026.run({}, _ctx(headers={"x-powered-by": "Next.js 15.5.29"})) == []
    assert transport.calls == []


def test_next_nov2026_markers_without_version_are_info_only(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    html = '<div id="__next"></div><script>self.__NEXT_DATA__={}</script>'
    found = NEXT_NOV2026.run({}, _ctx(body=html))
    assert [call[1] for call in transport.calls] == ["/package.json"]
    assert len(found) == 1
    assert found[0]["severity"] == "info"
    assert found[0]["title"] == "Next.js detected; verify Nov 2026 security release"
    assert UNCONFIRMED not in found[0]["title"]
    assert "definitely vulnerable" not in found[0]["evidence"].lower()
    assert "CVE-2026-119790" in found[0]["evidence"]


def test_next_nov2026_non_next_site_is_silent(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    assert NEXT_NOV2026.run({}, _ctx(headers={"x-powered-by": "Express"}, body="<html></html>")) == []
    assert transport.calls == []


def test_next_nov2026_package_json_version_when_header_hidden(monkeypatch):
    transport = Transport()
    transport.routes["/package.json"] = {
        "status": 200,
        "content_type": "application/json",
        "body": json.dumps({"dependencies": {"next": "16.4.1", "react": "19.0.0"}}),
    }
    _install(monkeypatch, transport)
    found = NEXT_NOV2026.run({}, _ctx(body='/_next/static/chunks/main.js'))
    assert [call[1] for call in transport.calls] == ["/package.json"]
    assert len(found) == 1
    assert "16.4.1" in found[0]["title"]
    assert UNCONFIRMED in found[0]["title"]


def test_next_nov2026_uses_cached_package_json_without_fetch(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    ctx = _ctx(body='/_next/static/chunks/main.js')
    ctx.recon_root["package_json"] = json.dumps({
        "devDependencies": {"next": "^15.5.20"},
    })
    found = NEXT_NOV2026.run({}, ctx)
    assert transport.calls == []
    assert len(found) == 1
    assert "15.5.20" in found[0]["title"]


def test_next_nov2026_does_not_request_build_manifest(monkeypatch):
    transport = Transport()
    transport.routes["/package.json"] = {"status": 404, "body": ""}
    _install(monkeypatch, transport)
    html = '<script src="/_next/static/abc123/pages/index.js"></script>'
    NEXT_NOV2026.run({}, _ctx(body=html))
    paths = [call[1] for call in transport.calls]
    assert paths == ["/package.json"]
    assert all("_buildManifest" not in path for path in paths)


# --- Node Brotli ------------------------------------------------------------

def test_brotli_probe_is_a_tiny_valid_json_stream():
    import brotli
    assert recon.BROTLI_JSON == b'{"vulnswarm":"ok"}'
    assert brotli.decompress(recon.BROTLI_JSON_BODY) == recon.BROTLI_JSON
    assert len(recon.BROTLI_JSON_BODY) < 64
    assert b"{" in recon.BROTLI_JSON_BODY


def test_brotli_probes_a_get_verified_json_endpoint(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    session = object()
    endpoints = [
        {"url": "http://evil.example/api/x", "method": "get", "status": 200, "source": "crawl"},
        _get_json("http://127.0.0.1:8081/api/delete-user"),
        _get_json("http://127.0.0.1:8081/api/items"),
    ]
    # Also a form action. The GET-verified /api/items record is what gets probed.
    forms = [{"action": "http://127.0.0.1:8081/api/items", "method": "post", "inputs": ["name"]}]
    target = _ctx(
        headers={"x-powered-by": "Express"},
        endpoints=endpoints,
        forms=forms,
        session=session,
    )
    found = BROTLI.run({}, target)
    posts = [call for call in transport.calls if call[0] == "POST"]
    assert posts == [("POST", "/api/items", session, False)]
    assert found[0]["title"] == BROTLI_TITLE
    assert found[0]["severity"] == "high"
    assert found[0]["check"]["once"] is True
    assert "CVE-2026-111497" in found[0]["evidence"]


def test_brotli_skips_post_only_and_form_action_urls(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    endpoints = [
        {"url": "http://127.0.0.1:8081/api/create", "method": "post", "status": 201, "source": "post"},
        {"url": "http://127.0.0.1:8081/api/submit", "method": "post", "status": 200, "source": "form"},
        _get_json("http://127.0.0.1:8081/api/health", status=404),
    ]
    forms = [
        {"action": "http://127.0.0.1:8081/api/submit", "method": "post", "inputs": ["name"]},
        {"action": "http://127.0.0.1:8081/api/register", "method": "post", "inputs": ["email"]},
    ]
    found = BROTLI.run({}, _ctx(headers={"x-powered-by": "Express"}, endpoints=endpoints, forms=forms))
    assert transport.calls == []
    assert found[0]["severity"] == "info"
    assert "skipped" in found[0]["title"].lower()
    assert "no POST was sent" in found[0]["evidence"]


def test_brotli_skips_state_changing_paths(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    base = "http://127.0.0.1:8081"
    endpoints = [
        _get_json(f"{base}/api/{name}")
        for name in (
            "login", "register", "signup", "reset", "delete",
            "checkout", "orders", "pay", "upload", "admin",
        )
    ]
    found = BROTLI.run({}, _ctx(headers={"x-powered-by": "Express"}, endpoints=endpoints))
    assert transport.calls == []
    assert found[0]["severity"] == "info"
    # A safe GET-verified path is still the one POST, beside those keywords.
    transport.calls.clear()
    endpoints.append(_get_json(f"{base}/api/items"))
    found = BROTLI.run({}, _ctx(headers={"x-powered-by": "Express"}, endpoints=endpoints))
    assert [call[1] for call in transport.calls] == ["/api/items"]
    assert found[0]["severity"] == "high"


def test_brotli_skips_the_post_when_no_get_verified_endpoint(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    # Runtime, but the only record was never a 2xx GET.
    found = BROTLI.run({}, _ctx(
        headers={"x-powered-by": "Express"},
        endpoints=[{"url": "http://127.0.0.1:8081/api/items"}],
    ))
    assert transport.calls == []
    assert len(found) == 1
    assert found[0]["severity"] == "info"
    assert "fingerprinted" in found[0]["title"].lower()
    assert "skipped" in found[0]["title"].lower()
    # No runtime at all: nothing to report, and still no POST.
    assert BROTLI.run({}, _ctx(server="Ubuntu", endpoints=[_get_json("http://127.0.0.1:8081/api/items")])) == []
    assert transport.calls == []


@pytest.mark.parametrize("status,ctype,body", [
    (415, "application/json", '{"error":"unsupported"}'),
    (200, "text/html", "<html>shell</html>"),
    (400, "application/json", '{"error":"bad"}'),
])
def test_brotli_rejection_is_not_a_finding(monkeypatch, status, ctype, body):
    transport = Transport()
    transport.post_status = status
    transport.post_type = ctype
    transport.post_body = body
    _install(monkeypatch, transport)
    target = _ctx(
        headers={"x-powered-by": "Express"},
        endpoints=[_get_json("http://127.0.0.1:8081/api/items")],
    )
    assert BROTLI.run({}, target) == []
    assert len(transport.calls) == 1


def test_brotli_verification_does_not_send_again(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    target = _ctx(
        fingerprint={"lang": "node"},
        endpoints=[_get_json("http://127.0.0.1:8081/api/health")],
    )
    found = BROTLI.run({}, target)[0]
    transport.calls.clear()
    ok, verdict, note = verifier._verify_deterministic(
        found, {"url": target.url, "raw_headers": {}, "body_snippet": ""},
        {}, [], target.url, None,
    )
    assert not ok and verdict == "unverified"
    assert "not repeated" in note
    assert transport.calls == []


# --- weDevs -----------------------------------------------------------------

WEDEVS_README = """=== weDevs Project Manager ===
Stable tag: 4.1.1
"""


def test_wedevs_stable_tag_and_rest_index(monkeypatch):
    transport = Transport()
    transport.routes["/wp-content/plugins/wedevs-project-manager/readme.txt"] = {
        "status": 200, "content_type": "text/plain", "body": WEDEVS_README,
    }
    transport.routes["/wp-json/pm/v2"] = {
        "status": 200,
        "content_type": "application/json",
        "body": '{"namespace":"pm/v2","routes":{"/pm/v2":{}}}',
    }
    _install(monkeypatch, transport)
    found = WEDEVS.run({}, _ctx())
    assert [call[1] for call in transport.calls] == [
        "/wp-content/plugins/wedevs-project-manager/readme.txt",
        "/wp-json/pm/v2",
    ]
    assert _critical(found)[0]["severity"] == "critical"
    assert UNCONFIRMED in _critical(found)[0]["evidence"]
    assert "4.1.1" in _critical(found)[0]["evidence"]
    assert any("answers without login" in item["title"] for item in found)
    assert all(item["severity"] == "info" or item["severity"] == "critical" for item in found)


@pytest.mark.parametrize("tag,critical", [("4.1.2", False), ("4.1.10", False), ("4.0.9", True), ("3.5.0", True)])
def test_wedevs_tag_boundary(monkeypatch, tag, critical):
    transport = Transport()
    transport.routes["/wp-content/plugins/wedevs-project-manager/readme.txt"] = {
        "status": 200, "body": f"=== weDevs Project Manager ===\nStable tag: {tag}\n",
    }
    transport.routes["/wp-json/pm/v2"] = {"status": 401, "body": "auth"}
    _install(monkeypatch, transport)
    found = WEDEVS.run({}, _ctx())
    assert bool(_critical(found)) is critical
    assert any("does not answer without login" in item["title"] for item in found)


# --- Node-RED ---------------------------------------------------------------

SETTINGS = json.dumps({
    "httpNodeRoot": "/",
    "version": "4.0.2",
    "editorTheme": {"page": {}},
    "context": {"default": "memory"},
})
FLOWS = json.dumps([{"id": "1", "type": "tab", "label": "Flow 1"}])


def test_nodered_settings_200_is_critical_and_does_not_fetch_flows(monkeypatch):
    transport = Transport()
    transport.routes["/settings"] = {
        "status": 200, "content_type": "application/json", "body": SETTINGS,
    }
    _install(monkeypatch, transport)
    found = NODERED.run({}, _ctx())
    assert [call[1] for call in transport.calls] == ["/settings"]
    assert found[0]["title"] == "Unauthenticated Node-RED editor (adminAuth not set) = RCE"
    assert found[0]["severity"] == "critical"
    assert "CVE-2026-58115" in found[0]["evidence"]
    assert "POST" not in " ".join(call[0] for call in transport.calls)


def test_nodered_falls_back_to_flows_and_stops_on_an_auth_challenge(monkeypatch):
    transport = Transport()
    transport.routes["/settings"] = {"status": 404, "body": "missing"}
    transport.routes["/flows"] = {
        "status": 200, "content_type": "application/json", "body": FLOWS,
    }
    _install(monkeypatch, transport)
    found = NODERED.run({}, _ctx())
    assert [call[1] for call in transport.calls] == ["/settings", "/flows"]
    assert found[0]["check"]["match"] == "nodered:/flows"

    transport.calls.clear()
    transport.routes["/settings"] = {
        "status": 401,
        "content_type": "application/json",
        "body": '{"error":"unauthorized","message":"node-red adminAuth"}',
    }
    assert NODERED.run({}, _ctx()) == []
    assert [call[1] for call in transport.calls] == ["/settings"]


def test_nodered_html_shell_is_not_the_editor(monkeypatch):
    transport = Transport()
    transport.routes["/settings"] = {"status": 200, "content_type": "text/html", "body": "<html>app</html>"}
    transport.routes["/flows"] = {"status": 200, "content_type": "text/html", "body": "<html>app</html>"}
    _install(monkeypatch, transport)
    assert NODERED.run({}, _ctx()) == []
    assert all(call[0] == "GET" for call in transport.calls)


# --- WordPress (CVE-2026-119977) --------------------------------------------

@pytest.mark.parametrize("version,vulnerable", [
    ("4.6.9", False),
    ("4.7", True), ("4.7.0", True), ("4.7.38", True), ("4.7.39", False),
    ("5.0", True), ("6.4.2", True), ("6.5.13", True), ("6.5.14", False),
    ("6.8.11", True), ("6.8.12", False), ("6.9.10", True), ("6.9.11", False),
    ("7.0.7", True), ("7.0.8", False),
    ("7.1.3", True), ("7.1.4", False), ("7.2.0", False), ("8.0", False),
])
def test_wordpress_branch_floors(version, vulnerable):
    from agents.cve_checks.versions import parse_dotted
    from agents.cve_checks.wordpress import is_vulnerable
    assert is_vulnerable(parse_dotted(version)) is vulnerable


def test_wordpress_generator_713_reports_cve(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    html = '<meta name="generator" content="WordPress 7.1.3" />'
    found = WORDPRESS.run({}, _ctx(body=html))
    assert [call[1] for call in transport.calls] == ["/wp-content/upgrade/"]
    assert len(found) == 1
    assert found[0]["severity"] == "critical"
    assert "CVE-2026-119977" in found[0]["title"]
    assert UNCONFIRMED in found[0]["title"]
    assert UNCONFIRMED in found[0]["evidence"]
    assert "CISA KEV" in found[0]["evidence"]
    assert "7.1.4" in found[0]["fix"]
    assert "exploit" not in found[0]["title"].lower()
    assert "No exploit payload" in found[0]["evidence"]


def test_wordpress_generator_714_is_fixed(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    html = '<meta name="generator" content="WordPress 7.1.4" />'
    found = WORDPRESS.run({}, _ctx(body=html))
    assert [call[1] for call in transport.calls] == ["/wp-content/upgrade/"]
    assert _critical(found) == []
    assert all(item.get("check", {}).get("match") != "wordpress:7.1.4" for item in found)


def test_wordpress_backport_6812_is_fixed(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    html = '<meta name="generator" content="WordPress 6.8.12" />'
    found = WORDPRESS.run({}, _ctx(body=html))
    assert _critical(found) == []
    assert all("6.8.12" not in (item.get("check") or {}).get("match", "") or
               item["severity"] != "critical" for item in found)


def test_wordpress_generator_6811_reports_cve(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    html = '<meta name="generator" content="WordPress 6.8.11" />'
    found = WORDPRESS.run({}, _ctx(body=html))
    assert len(_critical(found)) == 1
    assert found[0]["check"]["match"] == "wordpress:6.8.11"
    assert "CVE-2026-119977" in found[0]["evidence"]
    assert "6.8.12" in found[0]["fix"]


def test_wordpress_feed_fallback_without_generator(monkeypatch):
    transport = Transport()
    transport.routes["/feed/"] = {
        "status": 200,
        "content_type": "application/rss+xml",
        "body": "<rss><channel><generator>https://wordpress.org/?v=7.1.2</generator></channel></rss>",
    }
    _install(monkeypatch, transport)
    found = WORDPRESS.run({}, _ctx(body="<html><p>hello</p></html>"))
    paths = [call[1] for call in transport.calls]
    assert paths[0] == "/feed/"
    assert "/readme.html" not in paths
    assert "upgrade.php" not in " ".join(paths)
    assert "update-core" not in " ".join(paths)
    assert len(_critical(found)) == 1
    assert "7.1.2" in found[0]["title"]
    assert "CVE-2026-119977" in found[0]["evidence"]


def test_wordpress_upgrade_listing_is_medium_without_exploit_language(monkeypatch):
    transport = Transport()
    transport.routes["/wp-content/upgrade/"] = {
        "status": 200,
        "content_type": "text/html",
        "body": "<html><head><title>Index of /wp-content/upgrade/</title></head>"
                "<body><h1>Index of /wp-content/upgrade/</h1>"
                "<a href=\"/\">Parent Directory</a></body></html>",
    }
    _install(monkeypatch, transport)
    html = '<meta name="generator" content="WordPress 7.1.4" />'
    found = WORDPRESS.run({}, _ctx(body=html))
    listing = [item for item in found if item.get("check", {}).get("match") == "wordpress:upgrade-listing"]
    assert len(listing) == 1
    assert listing[0]["severity"] == "medium"
    blob = (listing[0]["title"] + " " + listing[0]["evidence"]).lower()
    for banned in ("exploit", "rce", "payload", "weaponiz"):
        assert banned not in blob
    assert "directory listing" in blob or "listable" in blob
    assert "No recursion" in listing[0]["evidence"] or "no recursion" in listing[0]["evidence"].lower()
    assert [call[1] for call in transport.calls] == ["/wp-content/upgrade/"]


# --- YOOtheme Pro ----------------------------------------------------------

_HANDLER = (
    "fromfile",
    "save=",
    "php://",
    "php%3a",
    "yootheme=cache",
    "/yootheme/cache",
    "wp-content/uploads",
)


def _assert_yootheme_passive(transport):
    assert len(transport.calls) <= 1
    for method, path, session, follow in transport.calls:
        assert method == "GET"
        assert method != "POST"
        assert session is None and follow is False
        blob = path.lower()
        for banned in _HANDLER:
            assert banned not in blob


@pytest.mark.parametrize("version,vulnerable", [
    ("5.0.0", True), ("5.0.52", True), ("5.0.53", False), ("5.0.54", False),
    ("5.1.0", False), ("4.5.28", False), ("4.0.0", False), ("3.0.16", False),
])
def test_yootheme_version_matrix(version, vulnerable):
    from agents.cve_checks.versions import parse_dotted
    from agents.cve_checks.yootheme import affected
    assert affected(parse_dotted(version)) is vulnerable


@pytest.mark.parametrize("html", [
    '<link rel="stylesheet" href="/wp-content/themes/yootheme/css/theme.css?ver=5.0.52" />'
    '<img src="/wp-content/uploads/yootheme/cache/photo.jpg" />',
    '<link href="templates/yootheme/css/theme.css?ver=5.0.52" rel="stylesheet" />',
    '<meta name="generator" content="YOOtheme Pro 5.0.52" />',
    '<meta content="YOOtheme Pro v5.0.52" name="generator" />',
])
def test_yootheme_5052_is_vulnerable_and_passive(monkeypatch, html):
    transport = Transport()
    _install(monkeypatch, transport)
    found = YOOTHEME.run({}, _ctx(body=html))
    _assert_yootheme_passive(transport)
    assert transport.calls == []
    assert len(found) == 1
    assert found[0]["severity"] == "critical"
    assert found[0]["check"]["match"] == "yootheme:5.0.52"
    assert UNCONFIRMED in found[0]["title"]
    assert UNCONFIRMED in found[0]["evidence"]
    assert "CVE-2026-102785" in found[0]["evidence"]
    assert "5.0.53" in found[0]["fix"]
    assert "wp-content/uploads" in found[0]["fix"]
    assert "images/" in found[0]["fix"]
    assert "webshell" in found[0]["fix"].lower()
    assert YOOTHEME.agent == WORDPRESS.agent == "misconfig"


def test_yootheme_5053_is_patched_and_4x_is_not_affected(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    patched = '<link rel="stylesheet" href="/wp-content/themes/yootheme/css/theme.css?ver=5.0.53" />'
    assert YOOTHEME.run({}, _ctx(body=patched)) == []
    older = '<link href="/templates/yootheme/js/theme.js?ver=4.5.28" />'
    assert YOOTHEME.run({}, _ctx(body=older)) == []
    _assert_yootheme_passive(transport)
    assert all(call[0] != "POST" for call in transport.calls)


def test_yootheme_without_version_is_info(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    html = (
        '<link rel="stylesheet" href="/wp-content/themes/yootheme/css/theme.css" />'
        '<script src="/wp-content/themes/yootheme/js/uikit.min.js?ver=3.21.6"></script>'
    )
    found = YOOTHEME.run({}, _ctx(body=html))
    _assert_yootheme_passive(transport)
    assert transport.calls == []
    assert len(found) == 1
    assert found[0]["severity"] == "info"
    assert found[0]["check"]["match"] == "yootheme:unknown"
    assert UNCONFIRMED not in found[0]["title"]
    meta = YOOTHEME.run({}, _ctx(body='<meta name="generator" content="YOOtheme Pro" />'))
    assert meta[0]["severity"] == "info"


def test_yootheme_absent_from_other_html_has_no_finding(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    html = (
        '<meta name="generator" content="WordPress 5.0.52" />'
        '<script src="/wp-includes/js/jquery.js?ver=5.0.52"></script>'
    )
    assert YOOTHEME.run({}, _ctx(body=html)) == []
    assert YOOTHEME.run({}, _ctx(body="<html><p>juice shop</p></html>")) == []
    _assert_yootheme_passive(transport)


def test_yootheme_page_get_drops_the_query_string():
    from agents.cve_checks.client import page_url
    ctx = _ctx(body="")
    ctx.url = "http://127.0.0.1:8081/index.php?ver=5.0.52"
    ctx.recon_root = {**ctx.recon_root, "url": ctx.url, "body_snippet": ""}
    assert page_url(ctx) == "http://127.0.0.1:8081/index.php"
    assert "?" not in page_url(ctx)


def test_yootheme_missing_html_is_one_page_get_and_never_the_image_handler(monkeypatch):
    transport = Transport()
    transport.routes["/"] = {
        "status": 200,
        "content_type": "text/html",
        "body": '<link rel="stylesheet" href="/wp-content/themes/yootheme/css/theme.css?ver=5.0.52" />',
    }
    transport.routes["/wp-content/uploads/yootheme/cache/photo.jpg"] = {
        "status": 200, "body": "image",
    }
    transport.routes["/index.php"] = {"status": 200, "body": "handler"}
    _install(monkeypatch, transport)
    found = YOOTHEME.run({}, _ctx(body=""))
    assert [call[0] for call in transport.calls] == ["GET"]
    assert [call[1] for call in transport.calls] == ["/"]
    _assert_yootheme_passive(transport)
    assert found[0]["severity"] == "critical"
    assert "5.0.52" in found[0]["title"]

    transport.calls.clear()
    ctx = _ctx(body="")
    ctx.url = "http://127.0.0.1:8081/wp-content/uploads/yootheme/cache/photo.jpg"
    ctx.recon_root = {**ctx.recon_root, "url": ctx.url, "body_snippet": ""}
    assert YOOTHEME.run({}, ctx) == []
    assert transport.calls == []


def test_verifier_confirms_yootheme_then_rejects_a_patched_build():
    html = '<meta name="generator" content="YOOtheme Pro 5.0.52" />'
    found = YOOTHEME.run({}, _ctx(body=html))[0]
    fresh = {
        "url": "http://127.0.0.1:8081",
        "raw_headers": {},
        "body_snippet": html,
        "server": "",
    }
    ok, verdict, _note = verifier._verify_deterministic(
        found, fresh, fresh["raw_headers"], [], fresh["url"], None,
    )
    assert ok and verdict == "confirmed"
    fresh["body_snippet"] = (
        '<link rel="stylesheet" href="/wp-content/themes/yootheme/css/theme.css?ver=5.0.53" />'
    )
    ok, verdict, _note = verifier._verify_deterministic(
        found, fresh, fresh["raw_headers"], [], fresh["url"], None,
    )
    assert not ok and verdict == "rejected"


# --- dependency pins --------------------------------------------------------

def test_pin_file_is_data_and_the_matcher_is_not_hardcoded_to_one_package():
    loaded = pins.load_pins()
    datasets = next(row for row in loaded if row["name"] == "datasets")
    assert datasets["cve"] == "CVE-2026-57845"
    assert datasets["affected"] == "<=5.1.0"
    assert datasets["ecosystem"] == "pypi"
    assert "pickle" in datasets["summary"]
    extra = [{
        "name": "left-pad", "ecosystem": "npm", "cve": "CVE-TEST",
        "affected": "<=1.2.3", "summary": "fixture", "fixed": "1.2.4",
    }]
    lock = json.dumps({"lockfileVersion": 3, "packages": {"node_modules/left-pad": {"version": "1.2.3"}}})
    hits = pins.scan_manifest("/package-lock.json", lock, pins=extra)
    assert hits and hits[0]["cve"] == "CVE-TEST"
    assert pins.scan_manifest("/package-lock.json", lock) == []


@pytest.mark.parametrize("line,hit", [
    ("datasets==5.1.0", True),
    ("datasets==5.1.1", False),
    ("datasets<=5.0", True),
    ("datasets>=6", False),
    ("datasets~=5.1.0", True),
    ("datasets~=6.0.0", False),
    ("Datasets==5.0.1", True),
    ("flask==3.0.0", False),
])
def test_requirements_pin_matrix(line, hit):
    found = pins.match_requirements(line + "\n")
    assert bool(found) is hit
    if hit:
        assert found[0]["cve"] == "CVE-2026-57845"


def test_lockfile_parsers_read_exact_versions():
    poetry = '[[package]]\nname = "datasets"\nversion = "5.1.0"\n'
    assert pins.scan_manifest("/poetry.lock", poetry)[0]["version"] == "5.1.0"
    pipfile = json.dumps({"_meta": {}, "default": {"datasets": {"version": "==5.1.0"}}})
    assert pins.scan_manifest("/Pipfile.lock", pipfile)[0]["version"] == "5.1.0"
    yarn = '# yarn lockfile v1\n\nleft-pad@^1.0.0:\n  version "1.2.3"\n'
    extra = [{"name": "left-pad", "ecosystem": "npm", "cve": "CVE-TEST",
              "affected": "==1.2.3", "summary": "fixture", "fixed": ""}]
    assert pins.scan_manifest("/yarn.lock", yarn, pins=extra)[0]["version"] == "1.2.3"
    pnpm = "lockfileVersion: '9.0'\n\n  left-pad@1.2.3:\n    resolution: x\n"
    assert pins.scan_manifest("/pnpm-lock.yaml", pnpm, pins=extra)
    composer = json.dumps({"packages": [{"name": "acme/widget", "version": "v1.0.0"}]})
    gem = "GEM\n  specs:\n    widget (1.0.0)\n"
    pack = [{"name": "acme/widget", "ecosystem": "packagist", "cve": "CVE-TEST",
             "affected": "==1.0.0", "summary": "fixture", "fixed": ""}]
    ruby = [{"name": "widget", "ecosystem": "rubygems", "cve": "CVE-TEST",
             "affected": "==1.0.0", "summary": "fixture", "fixed": ""}]
    assert pins.scan_manifest("/composer.lock", composer, pins=pack)
    assert pins.scan_manifest("/Gemfile.lock", gem, pins=ruby)


def test_exposed_manifest_and_vulnerable_pin_and_html_catch_all(monkeypatch):
    transport = Transport()
    shell = "<!doctype html><html><head></head><body>app</body></html>"
    transport.routes["/requirements.txt"] = {
        "status": 200,
        "content_type": "text/plain",
        "body": "flask==3.0.0\ndatasets==5.1.0\n",
    }
    transport.routes["/package-lock.json"] = {
        "status": 200,
        "content_type": "application/json",
        "body": shell,
    }
    _install(monkeypatch, transport)
    from agents.cve_checks.dependency_files import CHECK as DEPS
    found = DEPS.run({}, _ctx())
    paths = [call[1] for call in transport.calls]
    assert any(path.startswith("/vulnswarm-cve-") for path in paths)
    for path in FILES:
        assert path in paths
    exposed = [item for item in found if item["title"].startswith("Exposed dependency file")]
    assert [item["title"] for item in exposed] == ["Exposed dependency file: /requirements.txt"]
    pins_found = _critical(found)
    assert len(pins_found) == 1
    assert UNCONFIRMED in pins_found[0]["evidence"]
    assert "CVE-2026-57845" in pins_found[0]["evidence"]
    assert "datasets==5.1.0\n" not in pins_found[0]["evidence"]
    report = reporter.report(found)
    assert len(report["findings"]) == 2


# --- Metabase ---------------------------------------------------------------

def _meta(tag):
    return json.dumps({
        "version": {"tag": tag},
        "setup-token": None,
        "anon-tracking-enabled": False,
    })


@pytest.mark.parametrize("tag,critical", [
    ("v0.58.23", True), ("v0.58.24", False),
    ("v0.59.20", True), ("v0.59.21", False),
    ("v0.60.16", True), ("v0.60.17", False),
    ("v0.61.10", True), ("v0.61.11", False),
    ("v0.62.8", True), ("v0.62.9", False),
    ("v0.63.4", True), ("v0.63.5", False),
    ("v0.57.10", False), ("v0.64.0", False),
])
def test_metabase_branch_matrix(monkeypatch, tag, critical):
    transport = Transport()
    transport.routes["/api/session/properties"] = {
        "status": 200, "content_type": "application/json", "body": _meta(tag),
    }
    _install(monkeypatch, transport)
    found = METABASE.run({}, _ctx())
    assert [call[1] for call in transport.calls] == ["/api/session/properties"]
    assert bool(_critical(found)) is critical
    if critical:
        assert UNCONFIRMED in found[0]["evidence"]
        assert "CVE-2026-72898" in found[0]["evidence"]
        assert "KEV" in found[0]["evidence"]


def test_metabase_source_never_names_the_reset_route():
    text = (ROOT / "agents" / "cve_checks" / "metabase.py").read_text(encoding="utf-8")
    assert "reset_password" not in text


# --- Langflow ---------------------------------------------------------------

def test_langflow_version_mcp_and_autologin_redacts_the_token(monkeypatch):
    transport = Transport()
    secret = "super-secret-token-value"
    transport.routes["/api/v1/version"] = {
        "status": 200,
        "content_type": "application/json",
        "body": '{"version":"1.12.4","main_version":"1.12.4","package":"Langflow"}',
    }
    transport.routes["/api/v1/mcp"] = {
        "status": 200,
        "content_type": "application/json",
        "body": '{"tools":[{"name":"search","description":"look"}]}',
    }
    transport.routes["/api/v1/auto_login"] = {
        "status": 200,
        "content_type": "application/json",
        "body": json.dumps({"access_token": secret, "token_type": "bearer"}),
    }
    _install(monkeypatch, transport)
    found = LANGFLOW.run({}, _ctx())
    assert [call[1] for call in transport.calls] == [
        "/api/v1/version", "/api/v1/mcp", "/api/v1/auto_login",
    ]
    assert _critical(found)[0]["severity"] == "critical"
    assert UNCONFIRMED in _critical(found)[0]["evidence"]
    assert "1.13.0" in _critical(found)[0]["fix"]
    assert any("lists tools without login" in item["title"] for item in found)
    assert any("token was not stored or sent" in item["title"] for item in found)
    assert secret not in json.dumps(found)
    assert all(call[2] is None for call in transport.calls)


def test_langflow_fixed_version_still_notes_auth_and_unknown_host_stops(monkeypatch):
    transport = Transport()
    transport.routes["/api/v1/version"] = {
        "status": 200,
        "body": '{"version":"1.13.0","package":"Langflow"}',
    }
    transport.routes["/api/v1/mcp"] = {"status": 401, "body": '{"detail":"unauthorized"}'}
    transport.routes["/api/v1/auto_login"] = {"status": 404, "body": ""}
    _install(monkeypatch, transport)
    found = LANGFLOW.run({}, _ctx())
    assert not _critical(found)
    assert any("does not list tools" in item["title"] for item in found)
    assert any("does not answer" in item["title"] for item in found)

    transport.calls.clear()
    transport.routes["/api/v1/version"] = {"status": 200, "body": '{"version":"1.0.0"}'}
    assert LANGFLOW.run({}, _ctx()) == []
    assert [call[1] for call in transport.calls] == ["/api/v1/version"]


# --- MLflow AI Gateway (CVE-2026-4035) --------------------------------------

def _mlflow_page(version: str) -> str:
    return (
        "<html><head><title>MLflow</title>"
        "<script src=\"/static-files/static/js/main.js\"></script>"
        f"</head><body>MLflow {version}</body></html>"
    )


def _assert_one_get(transport):
    assert transport.calls == [("GET", "/version", None, False)]
    assert {call[0] for call in transport.calls} == {"GET"}


@pytest.mark.parametrize("version", ["3.10.0", "3.10.1", "3.10.12"])
def test_mlflow_unauthenticated_old_version_is_high(monkeypatch, version):
    transport = Transport()
    transport.routes["/version"] = {
        "status": 200,
        "content_type": "text/html; charset=utf-8",
        "body": f"{version}\n",
    }
    _install(monkeypatch, transport)
    found = MLFLOW.run({}, _ctx())
    _assert_one_get(transport)
    assert len(found) == 1
    assert found[0]["severity"] == "high"
    assert found[0]["check"]["id"] == "mlflow"
    assert UNCONFIRMED in found[0]["title"]
    assert UNCONFIRMED in found[0]["evidence"]
    assert "no authentication challenge" in found[0]["evidence"]
    assert "basic-auth" in found[0]["evidence"]
    assert "3.11.0" in found[0]["fix"]
    assert "basic-auth" in found[0]["fix"]
    assert "api_base" in found[0]["fix"]
    assert "$VAR" in found[0]["fix"]
    assert "CVE-2026-4035" in found[0]["evidence"]
    assert MLFLOW.agent == "misconfig"


def test_mlflow_basic_auth_old_version_is_lower_severity(monkeypatch):
    transport = Transport()
    transport.routes["/version"] = {
        "status": 401,
        "content_type": "text/html",
        "headers": {"WWW-Authenticate": 'Basic realm="mlflow"'},
        "body": (
            "You are not authenticated. Please see "
            "https://www.mlflow.org/docs/latest/auth/index.html "
            "on how to authenticate."
        ),
    }
    _install(monkeypatch, transport)
    found = MLFLOW.run({}, _ctx(body=_mlflow_page("3.10.4")))
    _assert_one_get(transport)
    assert len(found) == 1
    assert found[0]["severity"] == "medium"
    assert found[0]["severity"] != "high"
    assert UNCONFIRMED in found[0]["title"]
    assert UNCONFIRMED in found[0]["evidence"]
    assert "3.10.4" in found[0]["title"]
    assert "authentication challenge" in found[0]["evidence"]
    assert "basic-auth" in found[0]["evidence"]
    assert "already collected" in found[0]["evidence"]
    assert "$VAR" in found[0]["fix"]
    assert "AWS" not in json.dumps(found)


@pytest.mark.parametrize("body", ["3.11.0", "3.11.1\n", "3.12.0"])
def test_mlflow_patched_version_is_not_a_finding(monkeypatch, body):
    transport = Transport()
    transport.routes["/version"] = {"status": 200, "body": body}
    _install(monkeypatch, transport)
    assert MLFLOW.run({}, _ctx(body=_mlflow_page("3.10.1"))) == []
    _assert_one_get(transport)


def test_mlflow_non_mlflow_404_is_not_a_finding(monkeypatch):
    transport = Transport()
    transport.routes["/version"] = {"status": 404, "body": "not found"}
    _install(monkeypatch, transport)
    assert MLFLOW.run({}, _ctx(body="<html><title>Welcome</title></html>")) == []
    _assert_one_get(transport)
    transport.calls.clear()
    transport.routes["/version"] = {
        "status": 200,
        "content_type": "text/html",
        "body": "<html><title>Other</title><p>version 3.10.1</p></html>",
    }
    assert MLFLOW.run({}, _ctx()) == []
    _assert_one_get(transport)


def test_mlflow_check_never_uses_another_method(monkeypatch):
    transport = Transport()
    transport.routes["/version"] = {"status": 200, "body": "3.10.2"}
    _install(monkeypatch, transport)
    MLFLOW.run({}, _ctx())
    assert len(transport.calls) == 1
    method, path, session, follow = transport.calls[0]
    assert method == "GET"
    assert path == "/version"
    assert session is None
    assert follow is False
    text = (ROOT / "agents" / "cve_checks" / "mlflow_gateway.py").read_text(encoding="utf-8")
    assert text.count("fetch_path(") == 1
    for banned in ("/gateway", "/api/2.0/mlflow/gateway", "api/2.0/endpoints"):
        assert banned not in text


# --- Supabase Storage (GHSA-fgvp-cqg6-q8h2 / GHSA-3m3f-pjv4-x2fp) -----------

STORAGE_VERSION = "/storage/v1/version"


def _storage_ctx(url="http://127.0.0.1:8081"):
    return SimpleNamespace(
        url=url,
        recon_root={"url": url, "server": "", "raw_headers": {}, "body_snippet": ""},
        surface={"pages": [], "forms": [], "params": [], "json_endpoints": []},
        session=None,
        fingerprint={},
    )


def _assert_one_storage_get(transport):
    assert transport.calls == [("GET", STORAGE_VERSION, None, False)]
    assert {call[0] for call in transport.calls} == {"GET"}


def test_supabase_storage_1898_is_critical(monkeypatch):
    transport = Transport()
    transport.routes[STORAGE_VERSION] = {"status": 200, "body": "1.89.8\n"}
    _install(monkeypatch, transport)
    found = SUPABASE_STORAGE.run({}, _storage_ctx())
    _assert_one_storage_get(transport)
    assert len(found) == 1
    assert found[0]["severity"] == "critical"
    assert found[0]["check"]["id"] == "supabase-storage"
    assert found[0]["check"]["match"] == "supabase-storage:1.89.8:primary"
    assert UNCONFIRMED in found[0]["title"]
    assert UNCONFIRMED in found[0]["evidence"]
    assert "GHSA-fgvp-cqg6-q8h2" in found[0]["evidence"]
    assert "GHSA-3m3f-pjv4-x2fp" in found[0]["evidence"]
    assert "1.89.10" in found[0]["fix"]
    assert "role" in found[0]["evidence"]
    assert "No JWT" in found[0]["evidence"]
    assert "exploit" not in found[0]["title"].lower()
    assert SUPABASE_STORAGE.agent == "misconfig"


def test_supabase_storage_1899_is_sibling_only(monkeypatch):
    transport = Transport()
    transport.routes[STORAGE_VERSION] = {"status": 200, "body": "1.89.9"}
    _install(monkeypatch, transport)
    found = SUPABASE_STORAGE.run({}, _storage_ctx())
    _assert_one_storage_get(transport)
    assert len(found) == 1
    assert found[0]["severity"] == "high"
    assert found[0]["severity"] != "critical"
    assert found[0]["check"]["match"] == "supabase-storage:1.89.9:sibling"
    assert "sibling" in found[0]["title"].lower() or "GHSA-3m3f-pjv4-x2fp" in found[0]["title"]
    assert "GHSA-3m3f-pjv4-x2fp" in found[0]["evidence"]
    assert "GHSA-fgvp-cqg6-q8h2 is fixed" in found[0]["evidence"]
    assert "1.89.10" in found[0]["fix"]
    assert "x-amz-copy-source" in found[0]["evidence"]
    assert "No JWT" in found[0]["evidence"]


def test_supabase_storage_18910_is_clean(monkeypatch):
    transport = Transport()
    transport.routes[STORAGE_VERSION] = {"status": 200, "body": "1.89.10\n"}
    _install(monkeypatch, transport)
    assert SUPABASE_STORAGE.run({}, _storage_ctx()) == []
    _assert_one_storage_get(transport)
    transport.calls.clear()
    transport.routes[STORAGE_VERSION] = {"status": 200, "body": "1.90.0"}
    assert SUPABASE_STORAGE.run({}, _storage_ctx()) == []
    _assert_one_storage_get(transport)


def test_supabase_storage_hosted_supabase_co_is_informational(monkeypatch):
    transport = Transport()
    transport.routes[STORAGE_VERSION] = {"status": 200, "body": "1.89.8"}
    _install(monkeypatch, transport)
    found = SUPABASE_STORAGE.run(
        {}, _storage_ctx("https://abcdefgh.supabase.co")
    )
    _assert_one_storage_get(transport)
    assert len(found) == 1
    assert found[0]["severity"] == "info"
    assert found[0]["check"]["match"] == "supabase-storage:1.89.8:hosted"
    assert "hosted" in found[0]["evidence"].lower()
    assert "already patched" in found[0]["evidence"].lower()
    assert UNCONFIRMED not in found[0]["title"]


@pytest.mark.parametrize("body", [
    "",
    "not-a-version",
    "<html>1.89.8</html>",
    '{"version":"1.89.8"}',
    "Storage API",
])
def test_supabase_storage_missing_or_unparseable_version_not_detected(monkeypatch, body):
    transport = Transport()
    transport.routes[STORAGE_VERSION] = {"status": 200, "body": body}
    _install(monkeypatch, transport)
    assert SUPABASE_STORAGE.run({}, _storage_ctx()) == []
    _assert_one_storage_get(transport)


def test_supabase_storage_missing_endpoint_not_detected(monkeypatch):
    transport = Transport()
    transport.routes[STORAGE_VERSION] = {"status": 404, "body": "1.89.8"}
    _install(monkeypatch, transport)
    assert SUPABASE_STORAGE.run({}, _storage_ctx()) == []
    _assert_one_storage_get(transport)


def test_supabase_storage_non_allowlisted_host_is_refused():
    with pytest.raises(main.ScopeError) as exc:
        main.allowlisted_host("https://storage.attacker.example/storage/v1/version")
    assert "allowlist" in str(exc.value)
    with pytest.raises(main.ScopeError):
        main.allowlisted_host("https://abcdefgh.supabase.co/storage/v1/version")


def test_supabase_storage_kill_switch_stops_the_check(monkeypatch):
    def opener(_req, timeout=None):
        raise AssertionError("kill switch did not stop the request")

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(
        target="http://127.0.0.1:8081/", actor="tester", run_id="run_supabase_stop",
    )
    lease.stop()
    try:
        with control.scope(lease):
            with pytest.raises(control.ScanStopped):
                SUPABASE_STORAGE.run({}, _storage_ctx())
    finally:
        control.release(lease.run_id)


def test_supabase_storage_check_is_get_only_and_never_sends_auth_material(monkeypatch):
    transport = Transport()
    transport.routes[STORAGE_VERSION] = {"status": 200, "body": "1.89.7"}
    _install(monkeypatch, transport)
    found = SUPABASE_STORAGE.run({}, _storage_ctx())
    _assert_one_storage_get(transport)
    assert found and found[0]["severity"] == "critical"
    text = (ROOT / "agents" / "cve_checks" / "supabase_storage.py").read_text(
        encoding="utf-8"
    )
    assert text.count("fetch_path(") == 1
    assert "fetch_path(ctx, VERSION" in text
    # Probe is a bare GET through client.fetch_path — no custom headers or body.
    assert "headers=" not in text
    assert "eyJ" not in text
    assert "post_brotli" not in text
    assert "urlopen" not in text
    assert "http.client" not in text
    for banned in ("Authorization:", "apikey:", "x-amz-copy-source:"):
        assert banned not in text
    assert "exploit" not in found[0]["title"].lower()
    assert "No JWT" in found[0]["evidence"]


# --- GPUStack localhost auto-admin (CVE-2026-102895) ------------------------

GPUSTACK_VERSION = "/version"


def _gpustack_version_body(version: str, commit: str = "abc1234") -> str:
    return json.dumps({"version": version, "git_commit": commit})


def _gpustack_ui(version: str | None = None) -> str:
    ver = f" GPUStack {version}" if version else ""
    return (
        "<html><head><title>GPUStack</title>"
        "<script src=\"/js/index.js\"></script>"
        f"<link rel=\"stylesheet\" href=\"/css/index.css\"></head>"
        f"<body>Welcome to GPUStack{ver}</body></html>"
    )


def _assert_one_gpustack_get(transport):
    assert transport.calls == [("GET", GPUSTACK_VERSION, None, False)]
    assert {call[0] for call in transport.calls} == {"GET"}


def test_gpustack_211_is_critical(monkeypatch):
    transport = Transport()
    transport.routes[GPUSTACK_VERSION] = {
        "status": 200,
        "content_type": "application/json",
        "body": _gpustack_version_body("2.1.1"),
    }
    _install(monkeypatch, transport)
    found = GPUSTACK.run({}, _ctx())
    _assert_one_gpustack_get(transport)
    assert len(found) == 1
    assert found[0]["severity"] == "critical"
    assert found[0]["check"]["id"] == "gpustack"
    assert found[0]["check"]["match"] == "gpustack:2.1.1"
    assert UNCONFIRMED in found[0]["title"]
    assert "GPUStack detected, version 2.1.1 < 2.2.0" in found[0]["title"]
    assert "CVE-2026-102895" in found[0]["title"]
    assert "likely vulnerable" in found[0]["title"]
    assert UNCONFIRMED in found[0]["evidence"]
    assert "2.2.0" in found[0]["fix"]
    assert "force_auth_localhost=true" in found[0]["fix"]
    assert "X-GPUStack-Real-IP" in found[0]["fix"]
    assert "No X-GPUStack-Real-IP" in found[0]["evidence"]
    assert "exploit" not in found[0]["title"].lower()
    assert "exploit" not in found[0]["evidence"].lower()
    assert GPUSTACK.agent == "misconfig"


def test_gpustack_220_is_clean(monkeypatch):
    transport = Transport()
    transport.routes[GPUSTACK_VERSION] = {
        "status": 200,
        "content_type": "application/json",
        "body": _gpustack_version_body("2.2.0"),
    }
    _install(monkeypatch, transport)
    assert GPUSTACK.run({}, _ctx(body=_gpustack_ui("2.1.1"))) == []
    _assert_one_gpustack_get(transport)
    transport.calls.clear()
    transport.routes[GPUSTACK_VERSION] = {
        "status": 200,
        "body": _gpustack_version_body("2.3.0"),
    }
    assert GPUSTACK.run({}, _ctx()) == []
    _assert_one_gpustack_get(transport)


def test_gpustack_unknown_version_is_informational(monkeypatch):
    transport = Transport()
    transport.routes[GPUSTACK_VERSION] = {"status": 404, "body": "not found"}
    _install(monkeypatch, transport)
    found = GPUSTACK.run({}, _ctx(body=_gpustack_ui()))
    _assert_one_gpustack_get(transport)
    assert len(found) == 1
    assert found[0]["severity"] == "info"
    assert found[0]["check"]["match"] == "gpustack:unknown"
    assert "GPUStack admin interface exposed" in found[0]["title"]
    assert "confirm version >= 2.2.0" in found[0]["title"]
    assert "force_auth_localhost=true" in found[0]["title"]
    assert UNCONFIRMED not in found[0]["title"]
    assert "force_auth_localhost=true" in found[0]["fix"]


def test_gpustack_non_gpustack_page_is_not_a_finding(monkeypatch):
    transport = Transport()
    transport.routes[GPUSTACK_VERSION] = {
        "status": 200,
        "body": "2.1.1\n",
    }
    _install(monkeypatch, transport)
    assert GPUSTACK.run({}, _ctx(body="<html><title>Welcome</title></html>")) == []
    _assert_one_gpustack_get(transport)
    transport.calls.clear()
    transport.routes[GPUSTACK_VERSION] = {
        "status": 200,
        "content_type": "application/json",
        "body": '{"version":"2.1.1","package":"Other"}',
    }
    assert GPUSTACK.run({}, _ctx()) == []
    _assert_one_gpustack_get(transport)


def test_gpustack_check_is_one_get_without_spoofed_headers(monkeypatch):
    transport = Transport()
    transport.routes[GPUSTACK_VERSION] = {
        "status": 200,
        "body": _gpustack_version_body("2.1.1"),
    }
    _install(monkeypatch, transport)
    found = GPUSTACK.run({}, _ctx())
    _assert_one_gpustack_get(transport)
    assert len(transport.calls) == 1
    method, path, session, follow = transport.calls[0]
    assert method == "GET"
    assert path == GPUSTACK_VERSION
    assert session is None
    assert follow is False
    assert found and found[0]["severity"] == "critical"
    text = (ROOT / "agents" / "cve_checks" / "gpustack_auth.py").read_text(
        encoding="utf-8"
    )
    assert text.count("fetch_path(") == 1
    assert "fetch_path(ctx, VERSION" in text
    assert 'VERSION = "/version"' in text
    # Probe is a bare GET through client.fetch_path — no custom headers or body.
    assert "headers=" not in text
    assert "post_brotli" not in text
    assert "urlopen" not in text
    assert "http.client" not in text
    assert "requests." not in text
    # Never constructs a spoofed forwarding header as request material.
    for banned in (
        'X-GPUStack-Real-IP"',
        "'X-GPUStack-Real-IP'",
        "X-Forwarded-For:",
        "X-Real-IP:",
        "Forwarded:",
        '"/v2/users"',
        "'/v2/users'",
        '"/v2/api-keys"',
        "'/v2/api-keys'",
        '"/v2/workers"',
        "'/v2/workers'",
        '"/v2/inference-backends"',
        "'/v2/inference-backends'",
        '"from-yaml"',
        "'from-yaml'",
        "127.0.0.1",
    ):
        assert banned not in text
    assert "exploit" not in found[0]["title"].lower()
    assert "exploit" not in found[0]["evidence"].lower()
    assert "No X-GPUStack-Real-IP" in found[0]["evidence"]


# --- Contact Form 7 ---------------------------------------------------------

CF7_README = "/wp-content/plugins/contact-form-7/readme.txt"
CF7_UPLOADS = "/wp-content/uploads/"


def _cf7_readme(tag=None):
    lines = [
        "=== Contact Form 7 ===",
        "Contributors: takayukister",
        "Requires at least: 6.7",
    ]
    if tag is not None:
        lines.append(f"Stable tag: {tag}")
    return "\n".join(lines) + "\n"


def _cf7_asset_html(ver=None):
    if ver is None:
        return (
            '<script src="/wp-content/plugins/contact-form-7/includes/js/index.js">'
            "</script>"
        )
    return (
        f'<link rel="stylesheet" href="/wp-content/plugins/contact-form-7/'
        f'includes/css/styles.css?ver={ver}" />'
    )


@pytest.mark.parametrize("tag,vulnerable", [
    ("6.2.3", True),
    ("6.2", True),
    ("6.2.0", True),
    ("6.2.2", True),
    ("6.2.4", False),
    ("6.2.4.1", False),
    ("6.1.9", False),
    ("6.1", False),
    ("5.9.8", False),
    ("6.3.0", False),
])
def test_contact_form_7_version_matrix(tag, vulnerable):
    from agents.cve_checks.contact_form_7 import affected, _parse_version
    assert affected(_parse_version(tag)) is vulnerable


@pytest.mark.parametrize("tag,flagged", [
    ("6.2.3", True),
    ("6.2", True),
    ("6.2.4", False),
    ("6.2.4.1", False),
    ("6.1.9", False),
])
def test_contact_form_7_readme_stable_tag(monkeypatch, tag, flagged):
    transport = Transport()
    transport.routes[CF7_README] = {
        "status": 200, "content_type": "text/plain", "body": _cf7_readme(tag),
    }
    transport.routes[CF7_UPLOADS] = {"status": 403, "body": "Forbidden"}
    _install(monkeypatch, transport)
    found = CONTACT_FORM_7.run({}, _ctx())
    assert {call[0] for call in transport.calls} == {"GET"}
    assert all(call[2] is None and call[3] is False for call in transport.calls)
    if flagged:
        assert len(found) == 1
        assert found[0]["severity"] == "high"
        assert found[0]["check"]["match"] == f"contact-form-7:{tag}"
        assert UNCONFIRMED in found[0]["title"]
        assert "CVE-2026-114432" in found[0]["evidence"]
        assert "6.2.4" in found[0]["fix"]
        assert "directory listing" in found[0]["fix"].lower()
        assert ".phar" in found[0]["fix"]
        assert "exploit" not in found[0]["title"].lower()
        assert "exploit" not in found[0]["evidence"].lower()
        paths = [call[1] for call in transport.calls]
        assert paths == [CF7_README, CF7_UPLOADS]
    else:
        assert found == []
        assert [call[1] for call in transport.calls] == [CF7_README]


def test_contact_form_7_asset_ver_622_is_flagged(monkeypatch):
    transport = Transport()
    transport.routes[CF7_UPLOADS] = {"status": 403, "body": "Forbidden"}
    _install(monkeypatch, transport)
    found = CONTACT_FORM_7.run({}, _ctx(body=_cf7_asset_html("6.2.2")))
    assert found[0]["severity"] == "high"
    assert found[0]["check"]["match"] == "contact-form-7:6.2.2"
    assert [call[1] for call in transport.calls] == [CF7_UPLOADS]
    assert {call[0] for call in transport.calls} == {"GET"}


def test_contact_form_7_autoindex_uploads_raises_to_critical(monkeypatch):
    transport = Transport()
    transport.routes[CF7_README] = {
        "status": 200, "content_type": "text/plain", "body": _cf7_readme("6.2.3"),
    }
    transport.routes[CF7_UPLOADS] = {
        "status": 200,
        "content_type": "text/html",
        "body": "<html><head><title>Index of /wp-content/uploads</title></head>"
                "<body><h1>Index of /wp-content/uploads</h1></body></html>",
    }
    _install(monkeypatch, transport)
    found = CONTACT_FORM_7.run({}, _ctx())
    assert len(found) == 1
    assert found[0]["severity"] == "critical"
    assert found[0]["check"]["match"] == "contact-form-7:6.2.3:autoindex"
    assert "Index of" in found[0]["evidence"] or "autoindex" in found[0]["evidence"].lower()
    assert "file-listing" in found[0]["evidence"].lower() or "file listing" in found[0]["evidence"].lower()
    assert "RCE" in found[0]["evidence"]
    assert [call[1] for call in transport.calls] == [CF7_README, CF7_UPLOADS]
    assert {call[0] for call in transport.calls} == {"GET"}


def test_contact_form_7_uploads_403_does_not_raise(monkeypatch):
    transport = Transport()
    transport.routes[CF7_README] = {
        "status": 200, "content_type": "text/plain", "body": _cf7_readme("6.2.3"),
    }
    transport.routes[CF7_UPLOADS] = {"status": 403, "body": "Forbidden"}
    _install(monkeypatch, transport)
    found = CONTACT_FORM_7.run({}, _ctx())
    assert found[0]["severity"] == "high"
    assert found[0]["check"]["match"] == "contact-form-7:6.2.3"
    assert "autoindex" not in found[0]["check"]["match"]


def test_contact_form_7_linked_wpcf7_uploads_autoindex(monkeypatch):
    html = (
        _cf7_asset_html("6.2.1")
        + '<a href="/wp-content/uploads/wpcf7_uploads/">files</a>'
    )
    listing = "/wp-content/uploads/wpcf7_uploads/"
    transport = Transport()
    transport.routes[listing] = {
        "status": 200,
        "body": "<title>Index of /wp-content/uploads/wpcf7_uploads</title>"
                "<h1>Index of /wp-content/uploads/wpcf7_uploads</h1>",
    }
    _install(monkeypatch, transport)
    found = CONTACT_FORM_7.run({}, _ctx(body=html))
    assert found[0]["severity"] == "critical"
    assert [call[1] for call in transport.calls] == [listing]
    assert CF7_UPLOADS not in [call[1] for call in transport.calls]


def test_contact_form_7_missing_readme_with_asset_is_info(monkeypatch):
    transport = Transport()
    transport.routes[CF7_README] = {"status": 404, "body": ""}
    _install(monkeypatch, transport)
    found = CONTACT_FORM_7.run({}, _ctx(body=_cf7_asset_html(None)))
    assert len(found) == 1
    assert found[0]["severity"] == "info"
    assert found[0]["check"]["match"] == "contact-form-7:unknown"
    assert UNCONFIRMED not in found[0]["title"]
    assert [call[1] for call in transport.calls] == [CF7_README]
    assert CF7_UPLOADS not in [call[1] for call in transport.calls]


def test_contact_form_7_missing_readme_without_plugin_is_none(monkeypatch):
    transport = Transport()
    transport.routes[CF7_README] = {"status": 404, "body": ""}
    _install(monkeypatch, transport)
    assert CONTACT_FORM_7.run({}, _ctx(body="<html><p>hello</p></html>")) == []
    assert [call[1] for call in transport.calls] == [CF7_README]


def test_contact_form_7_readme_without_stable_tag_is_info(monkeypatch):
    transport = Transport()
    transport.routes[CF7_README] = {
        "status": 200, "content_type": "text/plain", "body": _cf7_readme(None),
    }
    _install(monkeypatch, transport)
    found = CONTACT_FORM_7.run({}, _ctx())
    assert found[0]["severity"] == "info"
    assert found[0]["check"]["match"] == "contact-form-7:unknown"
    assert [call[1] for call in transport.calls] == [CF7_README]


def test_contact_form_7_only_issues_get_requests(monkeypatch):
    transport = Transport()
    transport.routes[CF7_README] = {
        "status": 200, "content_type": "text/plain", "body": _cf7_readme("6.2.3"),
    }
    transport.routes[CF7_UPLOADS] = {
        "status": 200,
        "body": "<h1>Index of /wp-content/uploads</h1>",
    }
    _install(monkeypatch, transport)
    found = CONTACT_FORM_7.run({}, _ctx())
    assert found and found[0]["severity"] == "critical"
    assert {call[0] for call in transport.calls} == {"GET"}
    assert all(call[2] is None for call in transport.calls)
    text = (ROOT / "agents" / "cve_checks" / "contact_form_7.py").read_text(
        encoding="utf-8"
    )
    assert "post_brotli" not in text
    assert "recon.post" not in text
    assert "recon.send" not in text
    for banned in (
        "multipart",
        "$_POST",
        "php://",
        "<?php",
        "admin-ajax",
        "async-upload",
        "invalid-utf",
        "\udcff",
    ):
        assert banned not in text
    blob = json.dumps(found).lower()
    assert "exploit" not in blob
    assert "attack payload" not in blob


def test_contact_form_7_agent_is_misconfig():
    assert CONTACT_FORM_7.agent == "misconfig"
    assert CONTACT_FORM_7.id == "contact-form-7"
    assert CONTACT_FORM_7.cve == "CVE-2026-114432"


# --- Magento ----------------------------------------------------------------

@pytest.mark.parametrize("version,vulnerable", [
    ("2.4.8", True), ("2.4.9", False), ("2.4.10", False), ("2.3.7", True), ("1.9.4", True),
])
def test_magento_before_249(version, vulnerable):
    from agents.cve_checks.magento import before_fix
    from agents.cve_checks.versions import parse_dotted
    assert before_fix(parse_dotted(version)) is vulnerable


def test_magento_passive_version_does_not_fetch(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    found = MAGENTO.run({}, _ctx(body="Magento/2.4.6 (Community)"))
    assert transport.calls == []
    assert found[0]["severity"] == "critical"
    assert UNCONFIRMED in found[0]["evidence"]
    assert "APSB26-73" in found[0]["evidence"]
    assert "2.4.9" in found[0]["fix"]
    assert MAGENTO.run({}, _ctx(body="Magento/2.4.9-p1")) == []


def test_magento_version_file_is_the_only_request(monkeypatch):
    transport = Transport()
    transport.routes["/magento_version"] = {
        "status": 200, "content_type": "text/plain", "body": "Magento/2.4.8-p3 (Community)\n",
    }
    _install(monkeypatch, transport)
    found = MAGENTO.run({}, _ctx())
    assert [call[1] for call in transport.calls] == ["/magento_version"]
    assert "2.4.8" in found[0]["title"]
    blob = " ".join(call[1] for call in transport.calls)
    assert "shell" not in blob and "admin" not in blob


def test_magento_marker_without_version_is_info(monkeypatch):
    transport = Transport()
    transport.routes["/magento_version"] = {"status": 404, "body": "nope"}
    _install(monkeypatch, transport)
    found = MAGENTO.run({}, _ctx(body='<script type="text/x-magento-init">{}</script>'))
    assert found[0]["severity"] == "info"
    assert UNCONFIRMED not in found[0]["title"]


# --- Registration Form for WooCommerce (CVE-2026-119075) --------------------

TGWCFB_README = "/wp-content/plugins/registration-form-for-woocommerce/readme.txt"


def _tgwcfb_readme(tag=None, changelog=None):
    lines = [
        "=== Registration Form for WooCommerce ===",
        "Contributors: ThemeGrill",
        "Requires at least: 5.5",
    ]
    if tag is not None:
        lines.append(f"Stable tag: {tag}")
    lines.extend(["", "== Changelog =="])
    if changelog is not None:
        lines.append(f"= {changelog}       - 06-11-2026 =")
        lines.append("* Fix - test entry.")
    elif tag is not None:
        lines.append(f"= {tag}       - 06-11-2026 =")
        lines.append("* Fix - test entry.")
    return "\n".join(lines) + "\n"


def _assert_tgwcfb_one_get(transport):
    assert transport.calls == [("GET", TGWCFB_README, None, False)]


@pytest.mark.parametrize("tag,critical", [
    ("1.1.4", True),
    ("1.1.3", True),
    ("1.1", True),
    ("1.0.0", True),
    ("1.1.5", False),
    ("1.1.10", False),
    ("2.0.0", False),
])
def test_tgwcfb_stable_tag_range(monkeypatch, tag, critical):
    transport = Transport()
    transport.routes[TGWCFB_README] = {
        "status": 200, "content_type": "text/plain", "body": _tgwcfb_readme(tag),
    }
    _install(monkeypatch, transport)
    found = TGWCFB.run({}, _ctx())
    _assert_tgwcfb_one_get(transport)
    if critical:
        assert len(found) == 1
        assert found[0]["severity"] == "critical"
        assert found[0]["check"]["match"] == f"registration-form-woocommerce:{tag}"
        assert UNCONFIRMED in found[0]["title"]
        assert UNCONFIRMED in found[0]["evidence"]
        assert "CVE-2026-119075" in found[0]["evidence"]
        assert "lag" in found[0]["evidence"].lower()
        assert "1.1.5" in found[0]["fix"]
        assert "administrator" in found[0]["fix"].lower() or "admin" in found[0]["fix"].lower()
        assert "exploit" not in found[0]["title"].lower()
        blob = json.dumps(found).lower()
        assert "proven" not in blob
        assert "user_roles=administrator" not in blob
    else:
        assert found == []


def test_tgwcfb_114_request_budget_is_exactly_one_get(monkeypatch):
    transport = Transport()
    transport.routes[TGWCFB_README] = {
        "status": 200, "content_type": "text/plain", "body": _tgwcfb_readme("1.1.4"),
    }
    _install(monkeypatch, transport)
    found = TGWCFB.run({}, _ctx())
    _assert_tgwcfb_one_get(transport)
    assert found[0]["severity"] == "critical"
    text = (
        ROOT / "agents" / "cve_checks" / "registration_form_woocommerce.py"
    ).read_text(encoding="utf-8")
    assert text.count("fetch_path(") == 1
    assert "post_brotli" not in text
    assert "recon.post" not in text
    assert "recon.send" not in text
    for banned in (
        "woocommerce_after_checkout_validation",
        "validate_checkout_fields",
        "FormHandler",
        "$_POST",
        "multipart",
        "<?php",
        "php://",
        "../",
    ):
        assert banned not in text


def test_tgwcfb_changelog_fallback_flags_114(monkeypatch):
    transport = Transport()
    transport.routes[TGWCFB_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _tgwcfb_readme(tag=None, changelog="1.1.4"),
    }
    _install(monkeypatch, transport)
    found = TGWCFB.run({}, _ctx())
    _assert_tgwcfb_one_get(transport)
    assert len(found) == 1
    assert found[0]["severity"] == "critical"
    assert found[0]["check"]["match"] == "registration-form-woocommerce:1.1.4"
    assert "Changelog" in found[0]["evidence"]


@pytest.mark.parametrize("status,body", [
    (404, ""),
    (200, "<!doctype html><html><head><title>Registration Form</title></head>"
          "<body>Stable tag: 1.1.4</body></html>"),
    (200, "<html><body><p>Registration Form for WooCommerce Stable tag: 1.1.4</p></body></html>"),
    (200, "=== Some Other Plugin ===\nContributors: someone\nStable tag: 1.1.4\n"),
    (200, "Registration Form for WooCommerce is mentioned.\nStable tag: 1.1.4\n"),
    (200, "=== Registration Form for WooCommerce ===\nContributors: ThemeGrill\n"
          "Requires at least: 5.5\n\n== Changelog ==\n* Fix - no version heading\n"),
    (200, "not a readme at all\ngarbage\n$$$"),
])
def test_tgwcfb_missing_garbage_or_non_plugin_is_not_detected(monkeypatch, status, body):
    transport = Transport()
    transport.routes[TGWCFB_README] = {
        "status": status, "content_type": "text/html", "body": body,
    }
    _install(monkeypatch, transport)
    assert TGWCFB.run({}, _ctx()) == []
    _assert_tgwcfb_one_get(transport)


def test_tgwcfb_fixed_115_is_clean(monkeypatch):
    transport = Transport()
    transport.routes[TGWCFB_README] = {
        "status": 200, "content_type": "text/plain", "body": _tgwcfb_readme("1.1.5"),
    }
    _install(monkeypatch, transport)
    assert TGWCFB.run({}, _ctx()) == []
    _assert_tgwcfb_one_get(transport)


def test_tgwcfb_non_allowlisted_host_refused_before_any_request(monkeypatch):
    opened = []

    def opener(req, timeout=None):
        opened.append(req.full_url)
        raise AssertionError("non-allowlisted host opened a socket")

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    monkeypatch.setattr(
        orchestrator, "run_scan",
        lambda *_a, **_k: (_ for _ in ()).throw(
            AssertionError("run_scan must not run off the allowlist")
        ),
    )
    with pytest.raises(main.ScopeError):
        main.allowlisted_host("https://example.com/wp/")
    assert opened == []

    client = TestClient(main.app)
    login = client.post("/auth/login", json={"email": "erwin@local", "password": "demo"})
    assert login.status_code == 200
    token = login.json()["token"]
    denied = client.post(
        "/scan",
        json={"url": "https://example.com/"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert denied.status_code == 403
    assert "allowlist" in denied.json()["detail"]
    assert opened == []


def test_tgwcfb_kill_switch_stops_the_check(monkeypatch):
    def opener(_req, timeout=None):
        raise AssertionError("kill switch did not stop the request")

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(
        target="http://127.0.0.1:8081/", actor="tester", run_id="run_tgwcfb_stop",
    )
    lease.stop()
    try:
        with control.scope(lease):
            with pytest.raises(control.ScanStopped):
                TGWCFB.run({}, _ctx())
    finally:
        control.release(lease.run_id)


# --- crawler JSON memory ----------------------------------------------------

def test_crawler_records_json_documents_only(monkeypatch):
    pages = {
        "http://127.0.0.1/": {
            "status": 200,
            "content_type": "text/html",
            "body": (
                '<html><a href="/api/items">items</a>'
                '<a href="/api/login">login</a>'
                '<form method="post" action="/api/order"><input name="q"></form>'
                '</html>'
            ),
        },
        "http://127.0.0.1/api/items": {
            "status": 200,
            "content_type": "application/json",
            "body": '{"items":[]}',
        },
        "http://127.0.0.1/api/login": {
            "status": 401,
            "content_type": "application/json",
            "body": '{"error":"auth"}',
        },
    }

    def get(url, session=None, max_bytes=200000):
        spec = pages.get(url, {"status": 404, "content_type": "", "body": ""})
        return {"url": url, **spec}

    monkeypatch.setattr(recon, "get", get)
    surface = crawler.map_site("http://127.0.0.1/")
    assert surface["json_endpoints"] == [{
        "url": "http://127.0.0.1/api/items",
        "status": 200,
        "method": "get",
        "source": "crawl",
        "content_type": "application/json",
    }]
    actions = [form["action"] for form in surface["forms"]]
    assert "http://127.0.0.1/api/order" in actions
    assert all("/api/order" not in item["url"] for item in surface["json_endpoints"])
    assert all(item["status"] < 400 for item in surface["json_endpoints"])


# --- request path guardrails ------------------------------------------------

class _Hdrs:
    def __init__(self, items):
        self._items = list(items)

    def get(self, key, default=None):
        for name, value in self._items:
            if name.lower() == key.lower():
                return value
        return default

    def items(self):
        return list(self._items)

    def get_all(self, key):
        return [value for name, value in self._items if name.lower() == key.lower()]


class _Resp:
    def __init__(self, status=200, body=b"{}", headers=None):
        self.status = status
        self.headers = _Hdrs(headers or [("content-type", "application/json")])
        self._body = body

    def read(self, _n):
        return self._body


def test_fetch_and_brotli_post_honor_the_kill_switch(monkeypatch):
    def opener(_req, timeout=None):
        raise AssertionError("kill switch did not stop the request")

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(target="http://127.0.0.1/", actor="tester", run_id="run_cve_stop")
    lease.stop()
    try:
        with control.scope(lease):
            with pytest.raises(control.ScanStopped):
                recon.fetch("http://127.0.0.1/readme.html")
            with pytest.raises(control.ScanStopped):
                recon.post_brotli_json("http://127.0.0.1/api/items")
    finally:
        control.release(lease.run_id)


def test_brotli_post_is_one_audited_valid_body(monkeypatch):
    seen = {}

    def opener(req, timeout=None):
        seen["method"] = req.get_method()
        seen["data"] = req.data
        seen["encoding"] = req.get_header("Content-encoding")
        seen["type"] = req.get_header("Content-type")
        seen["calls"] = seen.get("calls", 0) + 1
        return _Resp(body=b'{"ok":true}')

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(target="http://127.0.0.1/", actor="tester", run_id="run_cve_post")
    try:
        with control.scope(lease), control.agent("misconfig"):
            result = recon.post_brotli_json("http://127.0.0.1/api/items")
    finally:
        control.release(lease.run_id)
    assert result["status"] == 200
    assert seen["calls"] == 1
    assert seen["method"] == "POST"
    assert seen["data"] == recon.BROTLI_JSON_BODY
    assert seen["encoding"] == "br"
    assert seen["type"] == "application/json"
    import audit
    rows = [row for row in audit.recent(20) if row["kind"] == "request"]
    assert rows[-1]["action"] == "POST"
    assert rows[-1]["agent"] == "misconfig"
    assert "body" not in rows[-1]


def test_foreign_body_and_put_never_reach_the_socket(monkeypatch):
    def opener(_req, timeout=None):
        raise AssertionError("refused method or body still opened a socket")

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    with pytest.raises(ValueError):
        recon._do("http://127.0.0.1/api", method="POST", raw_body=b'{"x":1}')
    with pytest.raises(ValueError):
        recon._do("http://127.0.0.1/api", method="PUT")
    with pytest.raises(ValueError):
        recon._do("http://127.0.0.1/api", method="DELETE")


def test_brotli_post_does_not_follow_a_redirect(monkeypatch):
    calls = []

    def opener(req, timeout=None):
        calls.append(req.full_url)
        return _Resp(status=302, body=b"", headers=[("Location", "https://example.com/land")])

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    result = recon.post_brotli_json("http://127.0.0.1/api/items")
    assert result["status"] == 302
    assert calls == ["http://127.0.0.1/api/items"]


# --- Amelia Pro (CVE-2026-116751) -------------------------------------------

AMELIA_README = "/wp-content/plugins/ameliabooking/readme.txt"
_AMELIA_EVENT_PATHS = (
    "/wp-admin/admin-ajax.php",
    "/wp-json/amelia/v1",
    "/wp-json/amelia",
)


def _amelia_asset_html(version: str) -> str:
    return (
        f'<script src="/wp-content/plugins/ameliabooking/v3/public/assets/'
        f'public.js?ver={version}"></script>'
        f'<link rel="stylesheet" href="/wp-content/plugins/ameliabooking/'
        f'v3/public/assets/style.css?ver={version}" />'
    )


def _amelia_readme(stable: str, *, lite: bool = False) -> str:
    edition = "Amelia Lite WordPress Booking Plugin" if lite else "Amelia Booking Plugin"
    return (
        "=== Booking for Appointments and Events Calendar - Amelia ===\n"
        f"Stable tag: {stable}\n\n"
        f"**{edition}** is an appointment booking system.\n"
        "Donate link: https://wpamelia.com/\n"
    )


def _assert_amelia_static_gets_only(transport):
    assert {call[0] for call in transport.calls} <= {"GET"}
    assert all(call[2] is None and call[3] is False for call in transport.calls)
    paths = [call[1] for call in transport.calls]
    blob = " ".join(paths).lower()
    for banned in _AMELIA_EVENT_PATHS + ("tag[", "tag%5b", "sleep(", "benchmark(", "select "):
        assert banned.lower() not in blob
    for path in paths:
        assert path == AMELIA_README or not path.startswith("/wp-content/plugins/ameliabooking/")


@pytest.mark.parametrize("version,vulnerable", [
    ("9.9.1", True), ("9.9.2", False), ("9.9.3", False),
    ("4.0", True), ("4.0.0", True), ("3.9.9", False), ("3.0", False),
    ("2.4.14", False), ("1.2.38", False), ("10.0.0", False),
])
def test_amelia_pro_version_matrix(version, vulnerable):
    from agents.cve_checks.amelia_pro import in_range, is_commercial_pro
    from agents.cve_checks.versions import parse_dotted
    parsed = parse_dotted(version)
    assert bool(is_commercial_pro(parsed) and in_range(parsed)) is vulnerable


def test_amelia_pro_991_asset_is_critical_and_passive(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    found = AMELIA_PRO.run({}, _ctx(body=_amelia_asset_html("9.9.1")))
    assert transport.calls == []
    assert AMELIA_PRO.agent == "misconfig"
    assert len(found) == 1
    assert found[0]["severity"] == "critical"
    assert found[0]["check"]["match"] == "amelia-pro:9.9.1"
    assert UNCONFIRMED in found[0]["title"]
    assert "CVE-2026-116751" in found[0]["title"]
    assert "9.9.2" in found[0]["fix"]
    assert "licensed update channel" in found[0]["fix"].lower()
    assert "exploit" not in found[0]["title"].lower()
    assert "No event-filter request" in found[0]["evidence"]
    assert "not CISA KEV" in found[0]["evidence"]


def test_amelia_pro_40_asset_is_critical(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    found = AMELIA_PRO.run({}, _ctx(body=_amelia_asset_html("4.0")))
    assert transport.calls == []
    assert found[0]["severity"] == "critical"
    assert found[0]["check"]["match"] == "amelia-pro:4.0.0"


def test_amelia_pro_992_and_3x_are_not_flagged(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    assert AMELIA_PRO.run({}, _ctx(body=_amelia_asset_html("9.9.2"))) == []
    assert AMELIA_PRO.run({}, _ctx(body=_amelia_asset_html("3.5.0"))) == []
    assert transport.calls == []


def test_amelia_lite_asset_never_yields_vulnerable(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    found = AMELIA_PRO.run({}, _ctx(body=_amelia_asset_html("2.4.14")))
    assert transport.calls == []
    assert found == []
    assert _critical(found) == []


def test_amelia_lite_readme_never_yields_vulnerable(monkeypatch):
    transport = Transport()
    transport.routes[AMELIA_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _amelia_readme("2.4.14", lite=True),
    }
    _install(monkeypatch, transport)
    found = AMELIA_PRO.run({}, _ctx())
    _assert_amelia_static_gets_only(transport)
    assert [call[1] for call in transport.calls] == [AMELIA_README]
    assert found == []
    assert _critical(found) == []


def test_amelia_unknown_edition_is_informational(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    html = (
        '<script src="/wp-content/plugins/ameliabooking/v3/public/assets/public.js">'
        "</script>"
    )
    found = AMELIA_PRO.run({}, _ctx(body=html))
    assert transport.calls == []
    assert len(found) == 1
    assert found[0]["severity"] == "info"
    assert found[0]["check"]["match"] == "amelia-pro:unknown"
    assert UNCONFIRMED not in found[0]["title"]
    assert "verify Pro version is 9.9.2 or later" in found[0]["title"]


def test_amelia_pro_readme_stable_tag_is_one_static_get(monkeypatch):
    transport = Transport()
    transport.routes[AMELIA_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _amelia_readme("9.9.1", lite=False),
    }
    _install(monkeypatch, transport)
    found = AMELIA_PRO.run({}, _ctx())
    _assert_amelia_static_gets_only(transport)
    assert [call[1] for call in transport.calls] == [AMELIA_README]
    assert found[0]["severity"] == "critical"
    assert found[0]["check"]["match"] == "amelia-pro:9.9.1"


def test_amelia_absent_has_no_finding(monkeypatch):
    transport = Transport()
    transport.routes[AMELIA_README] = {"status": 404, "body": "missing"}
    _install(monkeypatch, transport)
    assert AMELIA_PRO.run({}, _ctx(body="<html><body>hello</body></html>")) == []
    assert [call[1] for call in transport.calls] == [AMELIA_README]


def test_amelia_check_source_is_get_only_static_fingerprint():
    text = (ROOT / "agents" / "cve_checks" / "amelia_pro.py").read_text(encoding="utf-8")
    assert "fetch_path(ctx, README" in text
    assert text.count("fetch_path(") == 1
    assert "root_observation" in text
    assert "post_brotli" not in text
    assert "urlopen" not in text
    assert "http.client" not in text
    assert "admin-ajax" not in text.lower()
    assert "tag[" not in text
    assert "SLEEP(" not in text
    assert "BENCHMARK(" not in text
    assert "Never requests Amelia event-filter" in text
    assert AMELIA_PRO.agent == "misconfig"

# --- Vite development server (GHSA-p4f5-76q4-ffq7) --------------------------

_VITE_CLIENT_JS = """
console.debug("[vite] connecting...");
export function createHotContext(ownerPath) { return ownerPath; }
new WebSocket(url, "vite-hmr");
style.setAttribute("data-vite-dev-id", id);
export function injectQuery(url, queryToInject) { return url; }
"""

_VITE_HTML = (
    '<html><head>'
    '<script type="module" src="/@vite/client"></script>'
    '<script type="module" src="/@react-refresh"></script>'
    '</head><body></body></html>'
)

_PROD_HTML = (
    '<html><head>'
    '<script type="module" crossorigin src="/assets/index-a1b2c3d4.js"></script>'
    '<link rel="stylesheet" crossorigin href="/assets/index-e5f6g7h8.css">'
    '</head><body><div id="app"></div></body></html>'
)


@pytest.mark.parametrize("version,vulnerable", [
    ((4, 5, 0), True), ((5, 4, 11), True),
    ((6, 4, 5), True), ((6, 4, 6), False),
    ((7, 3, 7), True), ((7, 3, 8), False),
    ((8, 1, 6), True), ((8, 1, 7), False),
    ((8, 2, 4), True), ((8, 2, 5), False),
    ((8, 3, 6), True), ((8, 3, 7), False),
    ((8, 4, 0), False), ((3, 2, 0), False),
])
def test_vite_version_matrix(version, vulnerable):
    assert affected_vite(version) is vulnerable


@pytest.mark.parametrize("version,vulnerable", [
    ((1, 5, 0), True), ((1, 4, 9), True), ((1, 5, 1), False), ((1, 6, 0), False),
])
def test_vite_plus_version_matrix(version, vulnerable):
    assert affected_vite_plus(version) is vulnerable


def test_vite_html_markers_are_critical_and_skip_client_get(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    found = VITE_DEV.run({}, _ctx(body=_VITE_HTML))
    assert transport.calls == []
    assert len(found) == 1
    assert found[0]["severity"] == "critical"
    assert found[0]["title"] == VITE_TITLE
    assert "dev server exposed" in found[0]["evidence"].lower()
    assert "never run" in found[0]["evidence"].lower()
    assert "production" in found[0]["evidence"].lower()
    assert "exploit" not in found[0]["title"].lower()
    assert found[0]["check"]["match"] == "vite-dev:recon HTML"
    assert VITE_DEV.agent == "misconfig"


def test_vite_mocked_client_js_is_critical(monkeypatch):
    transport = Transport()
    transport.routes[VITE_CLIENT] = {
        "status": 200,
        "body": _VITE_CLIENT_JS,
        "content_type": "text/javascript",
    }
    _install(monkeypatch, transport)
    found = VITE_DEV.run({}, _ctx(body="<html><body>app</body></html>"))
    assert [call[1] for call in transport.calls] == [VITE_CLIENT]
    assert all(call[0] == "GET" and call[2] is None for call in transport.calls)
    assert found and found[0]["severity"] == "critical"
    assert found[0]["title"] == VITE_TITLE
    assert found[0]["check"]["match"] == f"vite-dev:GET {VITE_CLIENT}"


def test_vite_production_build_html_is_none(monkeypatch):
    transport = Transport()
    transport.routes[VITE_CLIENT] = {"status": 404, "body": "Not Found"}
    _install(monkeypatch, transport)
    assert VITE_DEV.run({}, _ctx(body=_PROD_HTML)) == []
    assert [call[1] for call in transport.calls] == [VITE_CLIENT]


def test_vite_client_404_is_none(monkeypatch):
    transport = Transport()
    transport.routes[VITE_CLIENT] = {"status": 404, "body": "missing"}
    _install(monkeypatch, transport)
    assert VITE_DEV.run({}, _ctx()) == []
    assert [call[1] for call in transport.calls] == [VITE_CLIENT]


def test_vite_never_requests_fs_or_id_paths(monkeypatch):
    transport = Transport()
    transport.routes[VITE_CLIENT] = {
        "status": 200,
        "body": _VITE_CLIENT_JS,
        "content_type": "text/javascript",
    }
    _install(monkeypatch, transport)
    VITE_DEV.run({}, _ctx(body=_VITE_HTML))
    VITE_DEV.run({}, _ctx(body="<html></html>"))
    paths = [call[1] for call in transport.calls]
    assert paths == [VITE_CLIENT]
    blob = " ".join(paths)
    assert "/@fs/" not in blob
    assert "/@id/" not in blob
    assert "__vite-browser-external" not in blob
    assert "__vite-optional-peer-dep" not in blob
    text = (ROOT / "agents" / "cve_checks" / "vite_dev_server.py").read_text(
        encoding="utf-8"
    )
    assert "fetch_path(ctx, CLIENT_PATH" in text
    assert text.count("fetch_path(") == 1
    assert "CLIENT_PATH = \"/@vite/client\"" in text
    assert "post_brotli" not in text
    assert "urlopen" not in text
    assert "decoy-secret" not in text
    assert "getBuiltinModule" not in text
    assert "does_not_send" in text or "Never requests" in text


def test_vite_kill_switch_stops_the_check(monkeypatch):
    def opener(_req, timeout=None):
        raise AssertionError("kill switch did not stop the request")

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(
        target="http://127.0.0.1:8081/", actor="tester", run_id="run_vite_stop",
    )
    lease.stop()
    try:
        with control.scope(lease):
            with pytest.raises(control.ScanStopped):
                VITE_DEV.run({}, _ctx())
    finally:
        control.release(lease.run_id)


def test_vite_non_allowlisted_host_is_refused():
    with pytest.raises(main.ScopeError) as exc:
        main.allowlisted_host("https://vite.attacker.example/")
    assert "allowlist" in str(exc.value)


def test_vite_passive_version_refines_evidence(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    ctx = _ctx(body=_VITE_HTML)
    ctx.findings = [{
        "title": "Exposed dependency file: /package-lock.json",
        "evidence": 'node_modules/vite": {"version": "6.4.5", "resolved": "..."}',
        "check": {"match": "exposed:/package-lock.json"},
    }]
    found = VITE_DEV.run({}, ctx)
    assert found and found[0]["severity"] == "critical"
    assert "6.4.5" in found[0]["evidence"]
    assert UNCONFIRMED in found[0]["evidence"]
    assert transport.calls == []

# --- WP Duplicate / LocalSync (CVE-2026-123751) ------------------------------

WP_DUPLICATE_README = "/wp-content/plugins/local-sync/readme.txt"


def _wp_duplicate_readme(tag=None):
    lines = [
        "=== WP Duplicate ===",
        "Contributors: revmakx, localsync",
        "Requires at least: 3.0.1",
        "Tested up to: 6.8",
    ]
    if tag is not None:
        lines.append(f"Stable tag: {tag}")
    lines.extend([
        "",
        "Formerly LocalSync. Clone and migrate WordPress sites.",
    ])
    return "\n".join(lines) + "\n"


def _assert_wp_duplicate_one_readme_get(transport):
    assert [call[0] for call in transport.calls] == ["GET"]
    assert [call[1] for call in transport.calls] == [WP_DUPLICATE_README]
    assert all(call[2] is None and call[3] is False for call in transport.calls)


@pytest.mark.parametrize("tag", ["1.1.11", "1.1.10", "1.0.0"])
def test_wp_duplicate_vulnerable_stable_tags_are_critical(monkeypatch, tag):
    transport = Transport()
    transport.routes[WP_DUPLICATE_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _wp_duplicate_readme(tag),
    }
    _install(monkeypatch, transport)
    found = WP_DUPLICATE.run({}, _ctx())
    _assert_wp_duplicate_one_readme_get(transport)
    assert len(found) == 1
    assert found[0]["severity"] == "critical"
    assert found[0]["check"]["match"] == f"wp-duplicate:{tag}"
    assert UNCONFIRMED in found[0]["title"]
    assert "CVE-2026-123751" in found[0]["evidence"]
    assert "unauthenticated file upload" in found[0]["evidence"]
    assert "no fix" in found[0]["evidence"].lower()
    assert "remove the plugin" in found[0]["evidence"].lower()
    # Consent-first copy: describe wild exploitation, never claim the scanner exploits.
    assert "scanner" not in found[0]["evidence"].lower()
    assert "we exploit" not in found[0]["evidence"].lower()
    assert "No upload" in found[0]["evidence"]


def test_wp_duplicate_higher_version_is_not_critical(monkeypatch):
    transport = Transport()
    transport.routes[WP_DUPLICATE_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _wp_duplicate_readme("1.1.12"),
    }
    _install(monkeypatch, transport)
    found = WP_DUPLICATE.run({}, _ctx())
    _assert_wp_duplicate_one_readme_get(transport)
    assert _critical(found) == []
    assert len(found) == 1
    assert found[0]["severity"] == "info"
    assert found[0]["check"]["match"] == "wp-duplicate:review:1.1.12"
    assert "review" in found[0]["title"].lower()


def test_wp_duplicate_missing_plugin_has_no_finding(monkeypatch):
    transport = Transport()
    transport.routes[WP_DUPLICATE_README] = {"status": 404, "body": "missing"}
    _install(monkeypatch, transport)
    assert WP_DUPLICATE.run({}, _ctx()) == []
    _assert_wp_duplicate_one_readme_get(transport)


def test_wp_duplicate_unparseable_readme_is_high(monkeypatch):
    transport = Transport()
    transport.routes[WP_DUPLICATE_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _wp_duplicate_readme(None),
    }
    _install(monkeypatch, transport)
    found = WP_DUPLICATE.run({}, _ctx())
    _assert_wp_duplicate_one_readme_get(transport)
    assert len(found) == 1
    assert found[0]["severity"] == "high"
    assert found[0]["check"]["match"] == "wp-duplicate:unknown"
    assert "remove" in found[0]["evidence"].lower() or "confirm" in found[0]["evidence"].lower()


def test_wp_duplicate_exactly_one_get_to_readme_and_nothing_else(monkeypatch):
    transport = Transport()
    transport.routes[WP_DUPLICATE_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _wp_duplicate_readme("1.1.11"),
    }
    _install(monkeypatch, transport)
    WP_DUPLICATE.run({}, _ctx())
    assert len(transport.calls) == 1
    assert transport.calls[0] == ("GET", WP_DUPLICATE_README, None, False)
    blob = " ".join(call[1] for call in transport.calls)
    assert "admin-ajax" not in blob
    assert "upload" not in blob.lower() or "readme" in blob
    assert "sync" not in blob.lower() or "local-sync" in blob
    assert "localsync/readme" not in blob
    assert "wp-duplicate/readme" not in blob


def test_wp_duplicate_check_source_is_get_only_readme_fingerprint():
    text = (ROOT / "agents" / "cve_checks" / "wp_duplicate.py").read_text(encoding="utf-8")
    assert "fetch_path(ctx, README" in text
    assert text.count("fetch_path(") == 1
    assert "post_brotli" not in text
    assert "urlopen" not in text
    assert "http.client" not in text
    assert "multipart" not in text.lower()
    # admin-ajax may appear only in negative safety copy, never as a requested path.
    assert "admin-ajax.php" not in text.lower()
    assert "Never requests upload or sync endpoints, admin-ajax" in text
    assert WP_DUPLICATE.agent == "misconfig"
    assert WP_DUPLICATE.cve == "CVE-2026-123751"
    assert "local-sync" in WP_DUPLICATE.sends
    assert "admin-ajax" in WP_DUPLICATE.does_not_send.lower()

# --- LatePoint --------------------------------------------------------------

LATEPOINT_README = "/wp-content/plugins/latepoint/readme.txt"


def _latepoint_readme(tag=None, *, changelog=None, name="LatePoint"):
    lines = [
        f"=== Appointment Booking Plugin – {name} | Calendar & Scheduling for WordPress ===",
        "Contributors: latepoint",
        "Requires at least: 5.0",
        "Tested up to: 6.8",
    ]
    if tag is not None:
        lines.append(f"Stable tag: {tag}")
    lines.extend([
        "",
        "LatePoint is an appointment booking and scheduling plugin for WordPress.",
        "",
        "== Changelog ==",
        "",
    ])
    if changelog is not None:
        lines.append(f"= {changelog} =")
        lines.append("* Security and maintenance release.")
    elif tag is not None:
        lines.append(f"= {tag} =")
        lines.append("* Release notes.")
    return "\n".join(lines) + "\n"


def _assert_latepoint_readme_get_only(transport):
    assert [call[0] for call in transport.calls] == ["GET"]
    assert [call[1] for call in transport.calls] == [LATEPOINT_README]
    assert all(call[2] is None and call[3] is False for call in transport.calls)
    blob = " ".join(call[1] for call in transport.calls).lower()
    for banned in (
        "admin-ajax.php",
        "customer_cabinet__change_password",
        "steps__start_from_order_intent",
        "password_reset_token",
        "order_intent_key",
        "is null",
        "is not null",
    ):
        assert banned not in blob


@pytest.mark.parametrize("tag,vulnerable", [
    ("5.7.6", True),
    ("5.7.5", True),
    ("5.0.0", True),
    ("5.7.7", False),
    ("5.8.0", False),
    ("6.0.0", False),
])
def test_latepoint_version_matrix(tag, vulnerable):
    from agents.cve_checks.latepoint import affected
    from agents.cve_checks.versions import parse_dotted

    assert bool(affected(parse_dotted(tag))) is vulnerable


@pytest.mark.parametrize("tag,flagged", [
    ("5.7.6", True),
    ("5.7.7", False),
    ("5.8.0", False),
])
def test_latepoint_readme_stable_tag(monkeypatch, tag, flagged):
    transport = Transport()
    transport.routes[LATEPOINT_README] = {
        "status": 200, "content_type": "text/plain", "body": _latepoint_readme(tag),
    }
    _install(monkeypatch, transport)
    found = LATEPOINT.run({}, _ctx())
    _assert_latepoint_readme_get_only(transport)
    if flagged:
        assert len(found) == 1
        assert found[0]["severity"] == "critical"
        assert UNCONFIRMED in found[0]["title"]
        assert found[0]["check"]["match"] == f"latepoint:{tag}"
        assert "CVE-2026-118066" in found[0]["evidence"]
        assert "Patchstack telemetry, not CISA KEV" in found[0]["evidence"]
        assert "admin-ajax.php" in found[0]["evidence"]
    else:
        assert found == []


def test_latepoint_changelog_fallback_when_stable_tag_missing(monkeypatch):
    transport = Transport()
    transport.routes[LATEPOINT_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _latepoint_readme(None, changelog="5.7.6"),
    }
    _install(monkeypatch, transport)
    found = LATEPOINT.run({}, _ctx())
    _assert_latepoint_readme_get_only(transport)
    assert len(found) == 1
    assert found[0]["severity"] == "critical"
    assert found[0]["check"]["match"] == "latepoint:5.7.6"
    assert "changelog version" in found[0]["evidence"]


def test_latepoint_404_is_none(monkeypatch):
    transport = Transport()
    transport.routes[LATEPOINT_README] = {"status": 404, "body": "missing"}
    _install(monkeypatch, transport)
    assert LATEPOINT.run({}, _ctx()) == []
    _assert_latepoint_readme_get_only(transport)


@pytest.mark.parametrize("body", [
    "<html><head></head><body>LatePoint Stable tag: 5.7.6</body></html>",
    "=== Some Other Plugin ===\nStable tag: 5.7.6\n",
    "not a readme at all",
])
def test_latepoint_malformed_readme_is_none(monkeypatch, body):
    transport = Transport()
    transport.routes[LATEPOINT_README] = {
        "status": 200, "content_type": "text/html", "body": body,
    }
    _install(monkeypatch, transport)
    assert LATEPOINT.run({}, _ctx()) == []
    _assert_latepoint_readme_get_only(transport)


def test_latepoint_readme_without_version_is_info(monkeypatch):
    transport = Transport()
    transport.routes[LATEPOINT_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": (
            "=== Appointment Booking Plugin – LatePoint ===\n"
            "Contributors: latepoint\n"
            "Requires at least: 5.0\n\n"
            "LatePoint booking plugin.\n"
        ),
    }
    _install(monkeypatch, transport)
    found = LATEPOINT.run({}, _ctx())
    _assert_latepoint_readme_get_only(transport)
    assert len(found) == 1
    assert found[0]["severity"] == "info"
    assert found[0]["check"]["match"] == "latepoint:unknown"


def test_latepoint_only_issues_readme_get(monkeypatch):
    transport = Transport()
    transport.routes[LATEPOINT_README] = {
        "status": 200, "content_type": "text/plain", "body": _latepoint_readme("5.7.6"),
    }
    transport.routes["/wp-admin/admin-ajax.php"] = {
        "status": 200, "body": "should-never-be-fetched",
    }
    _install(monkeypatch, transport)
    found = LATEPOINT.run({}, _ctx())
    _assert_latepoint_readme_get_only(transport)
    assert found and found[0]["severity"] == "critical"
    assert all(call[0] == "GET" for call in transport.calls)
    assert "admin-ajax.php" not in " ".join(call[1] for call in transport.calls)


def test_latepoint_non_allowlisted_host_is_refused():
    with pytest.raises(main.ScopeError) as exc:
        main.allowlisted_host("https://latepoint.attacker.example/wp-content/plugins/latepoint/readme.txt")
    assert "allowlist" in str(exc.value)


def test_latepoint_kill_switch_stops_the_check(monkeypatch):
    def opener(_req, timeout=None):
        raise AssertionError("kill switch did not stop the request")

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(
        target="http://127.0.0.1:8081/", actor="tester", run_id="run_latepoint_stop",
    )
    lease.stop()
    try:
        with control.scope(lease):
            with pytest.raises(control.ScanStopped):
                LATEPOINT.run({}, _ctx())
    finally:
        control.release(lease.run_id)


def test_latepoint_check_source_is_get_only_readme_fingerprint():
    text = (ROOT / "agents" / "cve_checks" / "latepoint.py").read_text(encoding="utf-8")
    assert "fetch_path(ctx, README" in text
    assert text.count("fetch_path(") == 1
    assert "post_brotli" not in text
    assert "urlopen" not in text
    assert "http.client" not in text
    assert LATEPOINT.agent == "auth"
    assert LATEPOINT.cve == "CVE-2026-118066"
    # does_not_send documents banned routes; run() must still only call fetch_path once.
    assert "Never requests admin-ajax.php" in text
    assert "customer_cabinet__change_password" in text
    assert "params[password_reset_token]" in text

# --- Xen Orchestra (VSA-2026-062) -------------------------------------------

XO_SIGNIN = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Xen Orchestra</title>
  <meta name="author" content="Vates SAS">
  <link rel="stylesheet" href="/v5/index.css">
  <link rel="icon" href="/v5/assets/favicon.svg" type="image/svg+xml">
</head>
<body>
  <img src="/v5/assets/logo.svg">
  <h2>Welcome to</h2>
  <form action="signin/local" method="post">
    <input name="username" type="text">
    <input name="password" type="password">
    <button>Sign in with password</button>
  </form>
</body>
</html>
"""

XO_FIXED_SERVER = (
    XO_SIGNIN.replace("</title>", "</title>\n  <!-- xo-server/5.213.1 -->")
)
XO_VULN_SERVER = (
    XO_SIGNIN.replace("</title>", "</title>\n  <!-- xo-server/5.213.0 -->")
)
XO_FIXED_PRODUCT = (
    XO_SIGNIN.replace("</title>", "</title>\n  <!-- Xen Orchestra 6.10.1 -->")
)
XO_VULN_PRODUCT = (
    XO_SIGNIN.replace("</title>", "</title>\n  <!-- Xen Orchestra 6.10.0 -->")
)


def test_xen_orchestra_login_without_version_is_high_exposure(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    found = XEN_ORCHESTRA.run({}, _ctx(body=XO_SIGNIN))
    assert transport.calls == []
    assert len(found) == 1
    assert found[0]["severity"] == "high"
    assert found[0]["check"]["id"] == "xen-orchestra"
    assert found[0]["check"]["match"] == "xen-orchestra:exposure"
    assert found[0]["confidence"] == "needs verification"
    assert "publicly reachable" in found[0]["title"].lower()
    assert "5.211.2" in found[0]["title"]
    assert "5.213.1" in found[0]["title"]
    assert "needs verification" in found[0]["evidence"].lower()
    assert "authenticationToken" in found[0]["evidence"]
    assert "/rest/v0" in found[0]["evidence"]
    assert "exploit" not in found[0]["title"].lower()


def test_xen_orchestra_vulnerable_xo_server_version_is_critical(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    found = XEN_ORCHESTRA.run({}, _ctx(body=XO_VULN_SERVER))
    assert transport.calls == []
    assert len(found) == 1
    assert found[0]["severity"] == "critical"
    assert UNCONFIRMED in found[0]["title"]
    assert found[0]["check"]["match"] == "xen-orchestra:xo-server:5.213.0"
    assert "5.213.0" in found[0]["evidence"]
    assert "VSA-2026-062" in found[0]["evidence"]


def test_xen_orchestra_vulnerable_product_version_is_critical(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    found = XEN_ORCHESTRA.run({}, _ctx(body=XO_VULN_PRODUCT))
    assert transport.calls == []
    assert found[0]["severity"] == "critical"
    assert found[0]["check"]["match"] == "xen-orchestra:product:6.10.0"


@pytest.mark.parametrize("body", [XO_FIXED_SERVER, XO_FIXED_PRODUCT])
def test_xen_orchestra_fixed_version_is_not_a_vuln_finding(monkeypatch, body):
    transport = Transport()
    _install(monkeypatch, transport)
    assert XEN_ORCHESTRA.run({}, _ctx(body=body)) == []
    assert transport.calls == []


def test_xen_orchestra_non_xo_page_is_none(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    html = "<html><title>Dashboard</title><body>hello</body></html>"
    assert XEN_ORCHESTRA.run({}, _ctx(body=html)) == []
    assert transport.calls == []


def test_xen_orchestra_empty_root_falls_back_to_one_get(monkeypatch):
    transport = Transport()
    transport.routes["/"] = {
        "status": 200,
        "content_type": "text/html",
        "body": XO_SIGNIN,
    }
    _install(monkeypatch, transport)
    found = XEN_ORCHESTRA.run({}, _ctx(body=""))
    assert transport.calls == [("GET", "/", None, False)]
    assert found[0]["severity"] == "high"
    assert found[0]["check"]["match"] == "xen-orchestra:exposure"
    assert "GET /" in found[0]["evidence"]


def test_xen_orchestra_never_sends_auth_cookie_or_rest(monkeypatch):
    transport = Transport()
    transport.routes["/"] = {
        "status": 200,
        "content_type": "text/html",
        "body": XO_SIGNIN,
    }
    _install(monkeypatch, transport)
    found = XEN_ORCHESTRA.run({}, _ctx(body=""))
    assert transport.calls == [("GET", "/", None, False)]
    paths = [call[1] for call in transport.calls]
    assert all("/rest" not in path for path in paths)
    assert all("/api" not in path for path in paths)
    text = (ROOT / "agents" / "cve_checks" / "xen_orchestra.py").read_text(
        encoding="utf-8"
    )
    assert "fetch_path(ctx, ROOT" in text
    assert text.count("fetch_path(") == 1
    assert "root_observation" in text
    assert "post_brotli" not in text
    assert "urlopen" not in text
    assert "http.client" not in text
    # Documentation may name the banned cookie; the check must never set one.
    assert "authenticationToken=" not in text
    assert "Set-Cookie" not in text
    assert XEN_ORCHESTRA.agent == "misconfig"
    assert found and found[0]["severity"] == "high"
    # Transport records only path/session/follow — session must stay None.
    assert all(call[2] is None for call in transport.calls)


def test_xen_orchestra_non_allowlisted_host_is_refused():
    with pytest.raises(main.ScopeError) as exc:
        main.allowlisted_host("https://xo.attacker.example/")
    assert "allowlist" in str(exc.value)


def test_xen_orchestra_kill_switch_stops_the_check(monkeypatch):
    def opener(_req, timeout=None):
        raise AssertionError("kill switch did not stop the request")

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(
        target="http://127.0.0.1:8081/", actor="tester", run_id="run_xo_stop",
    )
    lease.stop()
    try:
        with control.scope(lease):
            with pytest.raises(control.ScanStopped):
                XEN_ORCHESTRA.run({}, _ctx(body=""))
    finally:
        control.release(lease.run_id)


@pytest.mark.parametrize("version,vulnerable", [
    ((5, 211, 1), True), ((5, 211, 2), False), ((5, 211, 3), False),
    ((5, 213, 0), True), ((5, 213, 1), False), ((5, 212, 0), True),
    ((5, 210, 9), True), ((5, 214, 0), False),
])
def test_xen_orchestra_xo_server_version_matrix(version, vulnerable):
    from agents.cve_checks.xen_orchestra import below_fix
    assert below_fix("xo-server", version) is vulnerable


@pytest.mark.parametrize("version,vulnerable", [
    ((6, 9, 1), True), ((6, 9, 2), False),
    ((6, 10, 0), True), ((6, 10, 1), False),
    ((6, 8, 0), True), ((6, 11, 0), False),
])
def test_xen_orchestra_product_version_matrix(version, vulnerable):
    from agents.cve_checks.xen_orchestra import below_fix
    assert below_fix("product", version) is vulnerable


# --- SliceWP (CVE-2026-120043) ----------------------------------------------

SLICEWP_README = "/wp-content/plugins/slicewp/readme.txt"
_SLICEWP_BANNED = (
    "/my-account",
    "/my-account/",
    "woocommerce-register",
    "user_register",
    "wp-login.php",
    "email=",
    "SLEEP(",
    "BENCHMARK(",
    "UNION SELECT",
    "' OR ",
)


def _slicewp_asset_html(version: str | None = None) -> str:
    if version is None:
        return (
            '<script src="/wp-content/plugins/slicewp/assets/js/script.js">'
            "</script>"
            '<link rel="stylesheet" href="/wp-content/plugins/slicewp/'
            'assets/css/style.css" />'
        )
    return (
        f'<script src="/wp-content/plugins/slicewp/assets/js/script.js'
        f'?ver={version}"></script>'
        f'<link rel="stylesheet" href="/wp-content/plugins/slicewp/'
        f'assets/css/style.css?ver={version}" />'
    )


def _slicewp_readme(stable: str) -> str:
    return (
        "=== Affiliate Program Suite - SliceWP Affiliates ===\n"
        f"Stable tag: {stable}\n"
        "Contributors: slicewp\n"
        "Requires at least: 5.0\n\n"
        "SliceWP is an affiliate program suite for WordPress.\n"
    )


def _assert_slicewp_passive(transport):
    assert {call[0] for call in transport.calls} <= {"GET"}
    assert all(call[2] is None and call[3] is False for call in transport.calls)
    paths = [call[1] for call in transport.calls]
    blob = " ".join(paths)
    for banned in _SLICEWP_BANNED:
        assert banned.lower() not in blob.lower()
    for path in paths:
        assert path == SLICEWP_README
    assert paths.count(SLICEWP_README) <= 1


@pytest.mark.parametrize("version,vulnerable", [
    ("1.2.14", True), ("1.2.13", True), ("1.2.10", True), ("1.0.0", True),
    ("1.2.15", False), ("1.2.16", False), ("1.3.0", False), ("2.0.0", False),
])
def test_slicewp_version_matrix(version, vulnerable):
    from agents.cve_checks.slicewp import affected
    from agents.cve_checks.versions import parse_dotted
    assert bool(affected(parse_dotted(version))) is vulnerable


def test_slicewp_asset_ver_1214_is_critical_and_passive(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    found = SLICEWP.run({}, _ctx(body=_slicewp_asset_html("1.2.14")))
    assert transport.calls == []
    assert SLICEWP.agent == "misconfig"
    assert len(found) == 1
    assert found[0]["severity"] == "critical"
    assert found[0]["check"]["match"] == "slicewp:1.2.14"
    assert UNCONFIRMED in found[0]["title"]
    assert "CVE-2026-120043" in found[0]["title"]
    assert "CVE-2026-120043" in found[0]["evidence"]
    assert "1.2.15" in found[0]["fix"]
    assert "WooCommerce My Account registration" in found[0]["evidence"]
    assert "does not confirm" in found[0]["evidence"]
    assert "exploit" not in found[0]["title"].lower()
    assert "not CISA KEV" in found[0]["evidence"]


def test_slicewp_1215_and_130_are_not_flagged(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    assert SLICEWP.run({}, _ctx(body=_slicewp_asset_html("1.2.15"))) == []
    assert SLICEWP.run({}, _ctx(body=_slicewp_asset_html("1.3.0"))) == []
    assert transport.calls == []


def test_slicewp_readme_fallback_1210_is_vulnerable(monkeypatch):
    transport = Transport()
    transport.routes[SLICEWP_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _slicewp_readme("1.2.10"),
    }
    _install(monkeypatch, transport)
    found = SLICEWP.run({}, _ctx(body=_slicewp_asset_html(None)))
    _assert_slicewp_passive(transport)
    assert [call[1] for call in transport.calls] == [SLICEWP_README]
    assert found[0]["severity"] == "critical"
    assert found[0]["check"]["match"] == "slicewp:1.2.10"
    assert "CVE-2026-120043" in found[0]["evidence"]
    assert "1.2.15" in found[0]["fix"]


def test_slicewp_plugin_present_no_version_is_info(monkeypatch):
    transport = Transport()
    transport.routes[SLICEWP_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": (
            "=== Affiliate Program Suite - SliceWP Affiliates ===\n"
            "Contributors: slicewp\n"
            "Requires at least: 5.0\n\n"
            "SliceWP is an affiliate program suite for WordPress.\n"
        ),
    }
    _install(monkeypatch, transport)
    found = SLICEWP.run({}, _ctx(body=_slicewp_asset_html(None)))
    _assert_slicewp_passive(transport)
    assert len(found) == 1
    assert found[0]["severity"] == "info"
    assert found[0]["check"]["match"] == "slicewp:unknown"
    assert "CVE-2026-120043" in found[0]["title"]


def test_slicewp_absent_sends_nothing(monkeypatch):
    transport = Transport()
    transport.routes[SLICEWP_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _slicewp_readme("1.2.10"),
    }
    transport.routes["/my-account/"] = {"status": 200, "body": "register"}
    _install(monkeypatch, transport)
    assert SLICEWP.run({}, _ctx(body="<html><body>hello</body></html>")) == []
    assert transport.calls == []


def test_slicewp_at_most_one_readme_get_and_never_registration(monkeypatch):
    transport = Transport()
    transport.routes[SLICEWP_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _slicewp_readme("1.2.14"),
    }
    transport.routes["/my-account/"] = {"status": 200, "body": "register form"}
    transport.routes["/my-account/?action=register"] = {
        "status": 200, "body": "should-never-be-fetched",
    }
    _install(monkeypatch, transport)
    found = SLICEWP.run({}, _ctx(body=_slicewp_asset_html(None)))
    _assert_slicewp_passive(transport)
    assert [call[1] for call in transport.calls] == [SLICEWP_README]
    assert all(call[0] == "GET" for call in transport.calls)
    assert found and found[0]["severity"] == "critical"
    blob = " ".join(call[1] for call in transport.calls).lower()
    assert "my-account" not in blob
    assert "register" not in blob
    assert "email" not in blob


def test_slicewp_non_allowlisted_host_is_refused():
    with pytest.raises(main.ScopeError) as exc:
        main.allowlisted_host(
            "https://slicewp.attacker.example/wp-content/plugins/slicewp/readme.txt"
        )
    assert "allowlist" in str(exc.value)


def test_slicewp_check_source_is_get_only_static_fingerprint():
    text = (ROOT / "agents" / "cve_checks" / "slicewp.py").read_text(encoding="utf-8")
    assert "fetch_path(ctx, README" in text
    assert text.count("fetch_path(") == 1
    assert "root_observation" in text
    assert "post_brotli" not in text
    assert "urlopen" not in text
    assert "http.client" not in text
    assert "my-account" in text.lower()
    assert "Never requests" in text or "never requests" in text.lower()
    assert SLICEWP.agent == "misconfig"
    assert SLICEWP.cve == "CVE-2026-120043"
    assert "1.2.15" in SLICEWP.fixed


# --- WP Data Access (CVE-2026-118267) ---------------------------------------

WPDA_README = "/wp-content/plugins/wp-data-access/readme.txt"
_WP_ROOT = (
    '<meta name="generator" content="WordPress 6.8.1" />'
    '<link rel="https://api.w.org/" href="http://127.0.0.1:8081/wp-json/" />'
)


def _wpda_readme(tag=None, *, changelog=None, name="WP Data Access"):
    lines = [
        f"=== {name} ===",
        "Contributors: wpdataaccess",
        "Requires at least: 5.0",
        "Tested up to: 6.8",
    ]
    if tag is not None:
        lines.append(f"Stable tag: {tag}")
    lines.extend([
        "",
        "WP Data Access is a WordPress database and App Builder plugin.",
        "",
        "== Changelog ==",
        "",
    ])
    if changelog is not None:
        lines.append(f"= {changelog} =")
        lines.append("* Security and maintenance release.")
    elif tag is not None:
        lines.append(f"= {tag} =")
        lines.append("* Release notes.")
    return "\n".join(lines) + "\n"


def _assert_wpda_readme_get_only(transport):
    assert [call[0] for call in transport.calls] == ["GET"]
    assert [call[1] for call in transport.calls] == [WPDA_README]
    assert all(call[2] is None and call[3] is False for call in transport.calls)
    blob = " ".join(call[1] for call in transport.calls).lower()
    for banned in (
        "wpda/app",
        "wpda/app/update",
        "wpda/app/delete",
        "wpda/app/insert",
        "wp-login",
        "wp-register",
        "admin-ajax.php",
    ):
        assert banned not in blob


@pytest.mark.parametrize("tag,vulnerable", [
    ("5.5.89", True),
    ("5.5.88", True),
    ("5.0.0", True),
    ("5.5.90", False),
    ("5.5.91", False),
    ("5.6.0", False),
])
def test_wp_data_access_version_matrix(tag, vulnerable):
    from agents.cve_checks.wp_data_access import affected
    from agents.cve_checks.versions import parse_dotted

    assert bool(affected(parse_dotted(tag))) is vulnerable


@pytest.mark.parametrize("tag,flagged", [
    ("5.5.89", True),
    ("5.5.90", False),
    ("5.6.0", False),
])
def test_wp_data_access_readme_stable_tag(monkeypatch, tag, flagged):
    transport = Transport()
    transport.routes[WPDA_README] = {
        "status": 200, "content_type": "text/plain", "body": _wpda_readme(tag),
    }
    _install(monkeypatch, transport)
    found = WP_DATA_ACCESS.run({}, _ctx(body=_WP_ROOT))
    _assert_wpda_readme_get_only(transport)
    if flagged:
        assert len(found) == 1
        assert found[0]["severity"] == "high"
        assert UNCONFIRMED in found[0]["title"]
        assert found[0]["check"]["match"] == f"wp-data-access:{tag}"
        assert "CVE-2026-118267" in found[0]["evidence"]
        assert "Patchstack telemetry, not CISA KEV" in found[0]["evidence"]
        assert "Data App" in found[0]["evidence"]
        assert "wpda/app" in found[0]["evidence"]
        assert "does not confirm" in found[0]["evidence"]
        assert "exploit" not in found[0]["title"].lower()
        assert "we exploit" not in found[0]["evidence"].lower()
        assert "No wpda/app" in found[0]["evidence"] or "no wpda/app" in found[0]["evidence"]
    else:
        assert found == []


def test_wp_data_access_changelog_fallback_when_stable_tag_missing(monkeypatch):
    transport = Transport()
    transport.routes[WPDA_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _wpda_readme(None, changelog="5.5.89"),
    }
    _install(monkeypatch, transport)
    found = WP_DATA_ACCESS.run({}, _ctx(body=_WP_ROOT))
    _assert_wpda_readme_get_only(transport)
    assert len(found) == 1
    assert found[0]["severity"] == "high"
    assert found[0]["check"]["match"] == "wp-data-access:5.5.89"
    assert "changelog version" in found[0]["evidence"]


def test_wp_data_access_404_is_none(monkeypatch):
    transport = Transport()
    transport.routes[WPDA_README] = {"status": 404, "body": "missing"}
    _install(monkeypatch, transport)
    assert WP_DATA_ACCESS.run({}, _ctx(body=_WP_ROOT)) == []
    _assert_wpda_readme_get_only(transport)


@pytest.mark.parametrize("body", [
    "<html><head></head><body>WP Data Access Stable tag: 5.5.89</body></html>",
    "=== Some Other Plugin ===\nStable tag: 5.5.89\n",
    "not a readme at all",
])
def test_wp_data_access_malformed_readme_is_none(monkeypatch, body):
    transport = Transport()
    transport.routes[WPDA_README] = {
        "status": 200, "content_type": "text/html", "body": body,
    }
    _install(monkeypatch, transport)
    assert WP_DATA_ACCESS.run({}, _ctx(body=_WP_ROOT)) == []
    _assert_wpda_readme_get_only(transport)


def test_wp_data_access_unparseable_readme_is_present_unknown(monkeypatch):
    transport = Transport()
    transport.routes[WPDA_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": (
            "=== WP Data Access ===\n"
            "Contributors: wpdataaccess\n"
            "Requires at least: 5.0\n\n"
            "WP Data Access plugin.\n"
        ),
    }
    _install(monkeypatch, transport)
    found = WP_DATA_ACCESS.run({}, _ctx(body=_WP_ROOT))
    _assert_wpda_readme_get_only(transport)
    assert len(found) == 1
    assert found[0]["severity"] == "info"
    assert found[0]["check"]["match"] == "wp-data-access:unknown"
    assert "present, version unknown" in found[0]["title"].lower()
    assert "low confidence" in found[0]["title"].lower()


def test_wp_data_access_non_wordpress_is_skipped(monkeypatch):
    transport = Transport()
    transport.routes[WPDA_README] = {
        "status": 200, "content_type": "text/plain", "body": _wpda_readme("5.5.89"),
    }
    _install(monkeypatch, transport)
    assert WP_DATA_ACCESS.run({}, _ctx(body="<html><body>hello</body></html>")) == []
    assert transport.calls == []


def test_wp_data_access_only_issues_readme_get(monkeypatch):
    transport = Transport()
    transport.routes[WPDA_README] = {
        "status": 200, "content_type": "text/plain", "body": _wpda_readme("5.5.89"),
    }
    transport.routes["/wp-json/wpda/app/update"] = {
        "status": 200, "body": "should-never-be-fetched",
    }
    transport.routes["/wp-login.php"] = {
        "status": 200, "body": "should-never-be-fetched",
    }
    _install(monkeypatch, transport)
    found = WP_DATA_ACCESS.run({}, _ctx(body=_WP_ROOT))
    _assert_wpda_readme_get_only(transport)
    assert found and found[0]["severity"] == "high"
    assert all(call[0] == "GET" for call in transport.calls)
    blob = " ".join(call[1] for call in transport.calls)
    assert "wpda/app" not in blob
    assert "wp-login" not in blob


def test_wp_data_access_non_allowlisted_host_is_refused():
    with pytest.raises(main.ScopeError) as exc:
        main.allowlisted_host(
            "https://wpda.attacker.example/wp-content/plugins/wp-data-access/readme.txt"
        )
    assert "allowlist" in str(exc.value)


def test_wp_data_access_kill_switch_stops_the_check(monkeypatch):
    def opener(_req, timeout=None):
        raise AssertionError("kill switch did not stop the request")

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(
        target="http://127.0.0.1:8081/", actor="tester", run_id="run_wpda_stop",
    )
    lease.stop()
    try:
        with control.scope(lease):
            with pytest.raises(control.ScanStopped):
                WP_DATA_ACCESS.run({}, _ctx(body=_WP_ROOT))
    finally:
        control.release(lease.run_id)


def test_wp_data_access_check_source_is_get_only_readme_fingerprint():
    text = (ROOT / "agents" / "cve_checks" / "wp_data_access.py").read_text(encoding="utf-8")
    assert "fetch_path(ctx, README" in text
    assert text.count("fetch_path(") == 1
    assert "root_observation" in text
    assert "looks_like_wordpress" in text
    assert "post_brotli" not in text
    assert "urlopen" not in text
    assert "http.client" not in text
    assert WP_DATA_ACCESS.agent == "misconfig"
    assert WP_DATA_ACCESS.cve == "CVE-2026-118267"
    assert "5.5.90" in WP_DATA_ACCESS.fixed
    assert "Never requests wpda/app" in text
    assert "wpda/app/update" in text
    assert "login" in text.lower()
    assert "registration" in text.lower()


# --- Apache mod_http2 (CVE-2026-119618) -------------------------------------

@pytest.mark.parametrize("version,vulnerable", [
    ("2.4.54", False),
    ("2.4.55", True),
    ("2.4.62", True),
    ("2.4.70", True),
    ("2.4.71", False),
    ("2.4.72", False),
    ("2.2.34", False),
])
def test_apache_mod_http2_version_matrix(version, vulnerable):
    from agents.cve_checks.apache_mod_http2 import affected

    parts = tuple(int(part) for part in version.split("."))
    assert affected(parts) is vulnerable


def test_apache_2470_with_h2_is_high_and_passive(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    found = APACHE_MOD_HTTP2.run({}, _ctx(headers={
        "server": "Apache/2.4.70",
        "alt-svc": 'h2=":443"; ma=3600',
    }))
    assert transport.calls == []
    assert len(found) == 1
    assert found[0]["severity"] == "high"
    assert UNCONFIRMED in found[0]["title"]
    assert found[0]["check"]["match"] == "apache-mod-http2:2.4.70:h2"
    assert "CVE-2026-119618" in found[0]["evidence"]
    assert "backport" in found[0]["evidence"].lower()
    assert "2.4.71" in found[0]["fix"]
    assert "exploit" not in found[0]["title"].lower()
    assert "we exploit" not in found[0]["evidence"].lower()


def test_apache_2462_without_h2_is_medium(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    found = APACHE_MOD_HTTP2.run({}, _ctx(headers={"server": "Apache/2.4.62"}))
    assert transport.calls == []
    assert len(found) == 1
    assert found[0]["severity"] == "medium"
    assert found[0]["check"]["match"] == "apache-mod-http2:2.4.62:no-h2"
    assert "mod_http2" in found[0]["evidence"]


def test_apache_2471_and_2454_are_clean(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    assert APACHE_MOD_HTTP2.run({}, _ctx(headers={
        "server": "Apache/2.4.71",
        "upgrade": "h2c",
    })) == []
    assert APACHE_MOD_HTTP2.run({}, _ctx(headers={
        "server": "Apache/2.4.54",
        "alt-svc": 'h2=":443"',
    })) == []
    assert transport.calls == []


def test_apache_without_version_and_nginx_yield_no_finding(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    assert APACHE_MOD_HTTP2.run({}, _ctx(headers={"server": "Apache"})) == []
    assert APACHE_MOD_HTTP2.run({}, _ctx(server="Apache")) == []
    assert APACHE_MOD_HTTP2.run({}, _ctx(headers={"server": "nginx/1.24.0"})) == []
    assert APACHE_MOD_HTTP2.run({}, _ctx(headers={
        "server": "nginx/1.24.0",
        "alt-svc": 'h2=":443"',
    })) == []
    assert transport.calls == []


def test_apache_mod_http2_upgrade_h2c_counts_as_http2(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    found = APACHE_MOD_HTTP2.run({}, _ctx(headers={
        "server": "Apache/2.4.70 (Unix)",
        "upgrade": "h2c",
    }))
    assert transport.calls == []
    assert found and found[0]["severity"] == "high"
    assert found[0]["check"]["match"] == "apache-mod-http2:2.4.70:h2"


def test_apache_mod_http2_negotiated_protocol_on_recon_root(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    ctx = _ctx(headers={"server": "Apache/2.4.55"})
    ctx.recon_root["alpn"] = "h2"
    found = APACHE_MOD_HTTP2.run({}, ctx)
    assert transport.calls == []
    assert found and found[0]["severity"] == "high"


def test_apache_mod_http2_check_source_is_passive_fingerprint_only():
    text = (ROOT / "agents" / "cve_checks" / "apache_mod_http2.py").read_text(
        encoding="utf-8",
    )
    assert "root_observation" in text
    assert "fetch_path" not in text
    assert "post_brotli" not in text
    assert "urlopen" not in text
    assert "http.client" not in text
    assert "import socket" not in text
    assert "h2c" in text.lower()
    assert "alt-svc" in text.lower() or "Alt-Svc" in text
    assert "concurrent" in text.lower() or "parallel" in text.lower()
    assert APACHE_MOD_HTTP2.agent == "misconfig"
    assert APACHE_MOD_HTTP2.cve == "CVE-2026-119618"
    assert "2.4.71" in APACHE_MOD_HTTP2.fixed
    assert "No extra request" in APACHE_MOD_HTTP2.sends
    assert "HTTP/2 frame" in APACHE_MOD_HTTP2.does_not_send


# --- ACF Extended PRO (CVE-2026-120534) -------------------------------------

ACFE_PRO_README = "/wp-content/plugins/acf-extended-pro/readme.txt"
ACFE_FREE_README = "/wp-content/plugins/acf-extended/readme.txt"
_WP_HTML = (
    '<meta name="generator" content="WordPress 6.8.1" />'
    '<link rel="stylesheet" href="/wp-includes/css/dist/block-library/style.min.css" />'
)


def _acfe_pro_readme(tag=None, *, name="Advanced Custom Fields: Extended PRO"):
    lines = [
        f"=== {name} ===",
        "Contributors: hwk-fr",
        "Requires at least: 4.9",
        "Tested up to: 7.1",
        "Requires PHP: 5.6",
    ]
    if tag is not None:
        lines.append(f"Stable tag: {tag}")
    lines.extend(
        [
            "",
            "All-in-one enhancement suite (PRO).",
            "",
            "== Changelog ==",
            "",
        ]
    )
    if tag is not None:
        lines.extend([f"= {tag} =", "", "* Security release notes"])
    return "\n".join(lines) + "\n"


def _acfe_free_readme(tag="0.9.2.6"):
    return (
        "=== Advanced Custom Fields: Extended ===\n"
        "Contributors: hwk-fr\n"
        "Requires at least: 4.9\n"
        "Tested up to: 7.1\n"
        "Requires PHP: 5.6\n"
        f"Stable tag: {tag}\n"
        "\n"
        "All-in-one enhancement suite that improves WordPress & Advanced Custom Fields.\n"
        "\n"
        "== 💎 Pro Highlight ==\n"
        "\n"
        "* 20+ New ACF Fields\n"
        "\n"
        "== Changelog ==\n"
        "\n"
        f"= {tag} =\n"
        "\n"
        "**ACF Extended Pro {tag}:**\n"
        "\n"
        "* Module: Forms – Fixed security issue with shortcode preview\n"
    )


def _assert_acfe_readme_gets_only(transport, *, max_gets=2):
    assert all(call[0] == "GET" for call in transport.calls)
    assert all(call[2] is None and call[3] is False for call in transport.calls)
    paths = [call[1] for call in transport.calls]
    assert len(paths) <= max_gets
    allowed = {ACFE_PRO_README, ACFE_FREE_README}
    assert set(paths) <= allowed
    blob = " ".join(paths).lower()
    for banned in (
        "admin-ajax",
        "wp-json",
        "shortcode_preview",
        "render_field",
        "call_user_func",
        "acfe_form",
        "dynamic",
    ):
        assert banned not in blob
    assert "post" not in {call[0].lower() for call in transport.calls}


@pytest.mark.parametrize("version,vulnerable", [
    ("0.9.2.6", True),
    ("0.9.2.5", True),
    ("0.9.1.0", True),
    ("0.9.2.7", False),
    ("0.9.2.8", False),
    ("0.9.3.0", False),
])
def test_acf_extended_pro_version_matrix(version, vulnerable):
    from agents.cve_checks.acf_extended_pro import affected
    from agents.cve_checks.versions import parse_dotted

    assert affected(parse_dotted(version)) is vulnerable


def test_acf_extended_pro_0926_is_critical_and_passive(monkeypatch):
    transport = Transport()
    transport.routes[ACFE_PRO_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _acfe_pro_readme("0.9.2.6"),
    }
    _install(monkeypatch, transport)
    found = ACF_EXTENDED_PRO.run({}, _ctx(body=_WP_HTML))
    _assert_acfe_readme_gets_only(transport, max_gets=1)
    assert transport.calls == [("GET", ACFE_PRO_README, None, False)]
    assert len(found) == 1
    assert found[0]["severity"] == "critical"
    assert found[0]["check"]["match"] == "acf-extended-pro:0.9.2.6"
    assert UNCONFIRMED in found[0]["title"]
    assert UNCONFIRMED in found[0]["evidence"]
    assert "shortcode_preview" in found[0]["evidence"]
    assert "OpenSSL" in found[0]["evidence"]
    assert "form submission" in found[0]["evidence"].lower()
    assert "0.9.2.7" in found[0]["evidence"]
    assert "0.9.2.8" in found[0]["fix"]


@pytest.mark.parametrize("tag", ["0.9.2.7", "0.9.2.8"])
def test_acf_extended_pro_fixed_versions_are_not_flagged(monkeypatch, tag):
    transport = Transport()
    transport.routes[ACFE_PRO_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _acfe_pro_readme(tag),
    }
    _install(monkeypatch, transport)
    found = ACF_EXTENDED_PRO.run({}, _ctx(body=_WP_HTML))
    _assert_acfe_readme_gets_only(transport, max_gets=1)
    assert found == []


def test_acf_extended_free_readme_only_is_not_flagged(monkeypatch):
    transport = Transport()
    transport.routes[ACFE_PRO_README] = {"status": 404, "body": ""}
    transport.routes[ACFE_FREE_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _acfe_free_readme("0.9.2.6"),
    }
    _install(monkeypatch, transport)
    found = ACF_EXTENDED_PRO.run({}, _ctx(body=_WP_HTML))
    _assert_acfe_readme_gets_only(transport, max_gets=2)
    assert [call[1] for call in transport.calls] == [ACFE_PRO_README, ACFE_FREE_README]
    assert found == []


def test_acf_extended_pro_404_has_no_finding(monkeypatch):
    transport = Transport()
    transport.routes[ACFE_PRO_README] = {"status": 404, "body": ""}
    transport.routes[ACFE_FREE_README] = {"status": 404, "body": ""}
    _install(monkeypatch, transport)
    found = ACF_EXTENDED_PRO.run({}, _ctx(body=_WP_HTML))
    _assert_acfe_readme_gets_only(transport, max_gets=2)
    assert found == []


def test_acf_extended_pro_unknown_version_is_low_confidence(monkeypatch):
    transport = Transport()
    transport.routes[ACFE_PRO_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _acfe_pro_readme(None),
    }
    _install(monkeypatch, transport)
    found = ACF_EXTENDED_PRO.run({}, _ctx(body=_WP_HTML))
    _assert_acfe_readme_gets_only(transport, max_gets=1)
    assert len(found) == 1
    assert found[0]["severity"] == "info"
    assert found[0]["confidence"] == "low"
    assert found[0]["check"]["match"] == "acf-extended-pro:unknown"
    assert "low confidence" in found[0]["title"].lower()


def test_acf_extended_pro_without_wordpress_sends_nothing(monkeypatch):
    transport = Transport()
    transport.routes[ACFE_PRO_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _acfe_pro_readme("0.9.2.6"),
    }
    _install(monkeypatch, transport)
    found = ACF_EXTENDED_PRO.run({}, _ctx(body="<html><body>hello</body></html>"))
    assert transport.calls == []
    assert found == []


def test_acf_extended_pro_at_most_two_readme_gets(monkeypatch):
    transport = Transport()
    transport.routes[ACFE_PRO_README] = {"status": 404, "body": ""}
    transport.routes[ACFE_FREE_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _acfe_pro_readme(
            "0.9.2.6", name="Advanced Custom Fields: Extended PRO"
        ),
    }
    _install(monkeypatch, transport)
    found = ACF_EXTENDED_PRO.run({}, _ctx(body=_WP_HTML))
    _assert_acfe_readme_gets_only(transport, max_gets=2)
    assert len(transport.calls) == 2
    assert found[0]["check"]["match"] == "acf-extended-pro:0.9.2.6"


def test_acf_extended_pro_non_allowlisted_host_is_refused():
    with pytest.raises(main.ScopeError) as exc:
        main.allowlisted_host(
            "https://acfe.attacker.example/wp-content/plugins/acf-extended-pro/readme.txt"
        )
    assert "allowlist" in str(exc.value)


def test_acf_extended_pro_check_source_is_get_only_readme_fingerprint():
    text = (
        ROOT / "agents" / "cve_checks" / "acf_extended_pro.py"
    ).read_text(encoding="utf-8")
    assert 'PRIMARY = "/wp-content/plugins/acf-extended-pro/readme.txt"' in text
    assert 'ALTERNATE = "/wp-content/plugins/acf-extended/readme.txt"' in text
    assert "fetch_path(ctx, path" in text
    assert text.count("fetch_path(") == 1
    assert "_probe(ctx, PRIMARY" in text
    assert "_probe(ctx, ALTERNATE" in text
    assert "root_observation" in text
    assert "post_brotli" not in text
    assert "urlopen" not in text
    assert "http.client" not in text
    assert "admin-ajax" in text.lower()
    assert "Never submits" in text or "never submits" in text.lower()
    assert ACF_EXTENDED_PRO.agent == "misconfig"
    assert ACF_EXTENDED_PRO.cve == "CVE-2026-120534"
    assert "0.9.2.7" in ACF_EXTENDED_PRO.fixed
    assert "0.9.2.8" in ACF_EXTENDED_PRO.fixed

# --- Drupal Commerce Core (CVE-2026-118539 / SA-CONTRIB-2026-254) ------------

COMMERCE_INFO = "/modules/contrib/commerce/commerce.info.yml"
_COMMERCE_BANNED = (
    "/jsonapi/",
    "jsonapi",
    "/cart/add",
    "checkout",
    "PATCH",
    "add-to-cart",
    "commerce_order",
    "order_items",
)


def _drupal_commerce_html(extra="", generator=True, settings=True):
    parts = ['<html><head>']
    if generator:
        parts.append(
            '<meta name="Generator" content="Drupal 10 (https://www.drupal.org)" />'
        )
    parts.append("</head><body>")
    if settings:
        parts.append("<script>window.drupalSettings = {};</script>")
    parts.append(extra)
    parts.append("</body></html>")
    return "".join(parts)


def _commerce_markup():
    return (
        '<div class="commerce-cart-block block-commerce-cart">'
        '<a href="/cart">View cart</a></div>'
        '<div class="commerce-product">widget</div>'
    )


def _commerce_info_yml(version):
    return (
        "name: Commerce\n"
        "type: module\n"
        "description: 'Drupal Commerce'\n"
        "package: Commerce\n"
        "core_version_requirement: '^9 || ^10 || ^11'\n"
        f"version: '{version}'\n"
        "project: 'commerce'\n"
        "datestamp: 1730000000\n"
    )


def _assert_commerce_passive(transport):
    assert all(call[0] == "GET" for call in transport.calls)
    assert all(call[2] is None and call[3] is False for call in transport.calls)
    paths = [call[1] for call in transport.calls]
    assert paths.count(COMMERCE_INFO) <= 1
    blob = " ".join(paths).lower()
    for banned in _COMMERCE_BANNED:
        assert banned.lower() not in blob


@pytest.mark.parametrize("version,vulnerable", [
    ("3.3.12", True), ("3.3.0", True), ("3.0.0", True), ("3.3.13", False),
    ("3.3.14", False), ("3.4.0", False),
    ("8.x-2.40", True), ("8.x-2.0", True), ("2.40", True), ("2.40.0", True),
    ("8.x-2.41", False), ("2.41", False), ("2.41.0", False), ("2.42.0", False),
    ("1.0.0", True), ("4.0.0", False),
])
def test_commerce_core_version_matrix(version, vulnerable):
    from agents.cve_checks.commerce_core import affected, parse_commerce_version
    parsed = parse_commerce_version(version)
    assert parsed is not None
    assert bool(affected(parsed)) is vulnerable


@pytest.mark.parametrize("tag,flagged", [
    ("3.3.12", True),
    ("3.3.13", False),
    ("8.x-2.40", True),
    ("8.x-2.41", False),
])
def test_commerce_core_info_yml_version_matrix(monkeypatch, tag, flagged):
    transport = Transport()
    transport.routes[COMMERCE_INFO] = {
        "status": 200,
        "content_type": "text/yaml",
        "body": _commerce_info_yml(tag),
    }
    _install(monkeypatch, transport)
    body = _drupal_commerce_html(_commerce_markup())
    found = COMMERCE_CORE.run({}, _ctx(
        headers={"x-generator": "Drupal 10 (https://www.drupal.org)"},
        body=body,
    ))
    _assert_commerce_passive(transport)
    assert [call[1] for call in transport.calls] == [COMMERCE_INFO]
    if flagged:
        assert len(found) == 1
        assert found[0]["severity"] == "critical"
        assert UNCONFIRMED in found[0]["title"]
        assert "CVE-2026-118539" in found[0]["title"]
        assert "CVE-2026-118539" in found[0]["evidence"]
        assert "SA-CONTRIB-2026-254" in found[0]["evidence"]
        assert "not CISA KEV" in found[0]["evidence"]
        assert "3.3.13" in found[0]["fix"]
        assert "8.x-2.41" in found[0]["fix"]
        assert "exploit" not in found[0]["title"].lower()
        assert "exploits" not in found[0]["evidence"].lower().replace(
            "exploitation", ""
        )
    else:
        assert found == []


def test_commerce_core_info_yml_403_with_markup_is_info(monkeypatch):
    transport = Transport()
    transport.routes[COMMERCE_INFO] = {
        "status": 403,
        "content_type": "text/plain",
        "body": "Forbidden",
    }
    _install(monkeypatch, transport)
    found = COMMERCE_CORE.run({}, _ctx(
        headers={"x-generator": "Drupal 10 (https://www.drupal.org)"},
        body=_drupal_commerce_html(_commerce_markup()),
    ))
    _assert_commerce_passive(transport)
    assert [call[1] for call in transport.calls] == [COMMERCE_INFO]
    assert len(found) == 1
    assert found[0]["severity"] == "info"
    assert found[0]["check"]["match"] == "commerce-core:unknown"
    assert "low confidence" in found[0]["evidence"]
    assert "3.3.13" in found[0]["evidence"]
    assert "8.x-2.41" in found[0]["evidence"]
    assert "audit orders" in found[0]["evidence"]
    assert "CVE-2026-118539" in found[0]["title"]


def test_commerce_core_non_drupal_is_skipped(monkeypatch):
    transport = Transport()
    transport.routes[COMMERCE_INFO] = {
        "status": 200,
        "content_type": "text/yaml",
        "body": _commerce_info_yml("3.3.12"),
    }
    transport.routes["/cart"] = {"status": 200, "body": "cart"}
    transport.routes["/jsonapi/commerce_order/commerce_order"] = {
        "status": 200, "body": "{}",
    }
    _install(monkeypatch, transport)
    assert COMMERCE_CORE.run({}, _ctx(
        body='<html><body><a href="/cart">cart</a>'
             '<div class="commerce-product"></div></body></html>',
    )) == []
    assert transport.calls == []


def test_commerce_core_drupal_without_commerce_sends_nothing(monkeypatch):
    transport = Transport()
    transport.routes[COMMERCE_INFO] = {
        "status": 200,
        "content_type": "text/yaml",
        "body": _commerce_info_yml("3.3.12"),
    }
    _install(monkeypatch, transport)
    assert COMMERCE_CORE.run({}, _ctx(
        headers={"x-generator": "Drupal 10 (https://www.drupal.org)"},
        body=_drupal_commerce_html("<p>Hello</p>"),
    )) == []
    assert transport.calls == []


def test_commerce_core_reuses_composer_lock_version_from_findings(monkeypatch):
    transport = Transport()
    transport.routes[COMMERCE_INFO] = {
        "status": 200,
        "content_type": "text/yaml",
        "body": _commerce_info_yml("3.3.12"),
    }
    _install(monkeypatch, transport)
    ctx = _ctx(
        headers={"x-generator": "Drupal 10 (https://www.drupal.org)"},
        body=_drupal_commerce_html(_commerce_markup()),
    )
    ctx.findings = [{
        "title": "Exposed dependency file: /composer.lock",
        "evidence": (
            'GET /composer.lock -> 200. {"packages":[{"name":"drupal/commerce",'
            '"version":"3.3.12","source":{}}]}'
        ),
        "check": {"match": "exposed:/composer.lock"},
    }]
    found = COMMERCE_CORE.run({}, ctx)
    assert transport.calls == []
    assert found and found[0]["severity"] == "critical"
    assert found[0]["check"]["match"] == "commerce-core:3.3.12"
    assert "composer.lock" in found[0]["evidence"]


def test_commerce_core_at_most_one_info_yml_get_and_never_mutates(monkeypatch):
    transport = Transport()
    transport.routes[COMMERCE_INFO] = {
        "status": 200,
        "content_type": "text/yaml",
        "body": _commerce_info_yml("8.x-2.40"),
    }
    transport.routes["/cart"] = {"status": 200, "body": "should-never-be-fetched"}
    transport.routes["/cart/add"] = {"status": 200, "body": "nope"}
    transport.routes["/checkout"] = {"status": 200, "body": "nope"}
    transport.routes["/jsonapi/commerce_order/commerce_order"] = {
        "status": 200, "body": "{}",
    }
    _install(monkeypatch, transport)
    found = COMMERCE_CORE.run({}, _ctx(
        headers={"x-generator": "Drupal 10 (https://www.drupal.org)"},
        body=_drupal_commerce_html(_commerce_markup()),
    ))
    _assert_commerce_passive(transport)
    assert [call[1] for call in transport.calls] == [COMMERCE_INFO]
    assert all(call[0] == "GET" for call in transport.calls)
    assert found and found[0]["severity"] == "critical"
    assert found[0]["check"]["match"] == "commerce-core:8.x-2.40"
    blob = " ".join(call[1] for call in transport.calls).lower()
    assert "jsonapi" not in blob
    assert "/cart" not in blob
    assert "checkout" not in blob


def test_commerce_core_non_allowlisted_host_is_refused():
    with pytest.raises(main.ScopeError) as exc:
        main.allowlisted_host(
            "https://commerce.attacker.example/modules/contrib/commerce/"
            "commerce.info.yml"
        )
    assert "allowlist" in str(exc.value)


def test_commerce_core_check_source_is_get_only_static_fingerprint():
    text = (
        ROOT / "agents" / "cve_checks" / "commerce_core.py"
    ).read_text(encoding="utf-8")
    assert "fetch_path(ctx, INFO_YML" in text
    assert text.count("fetch_path(") == 1
    assert "root_observation" in text
    assert "post_brotli" not in text
    assert "urlopen" not in text
    assert "http.client" not in text
    assert "Never adds to cart" in text or "never adds to cart" in text.lower()
    assert "JSON:API" in text or "jsonapi" in text.lower()
    assert COMMERCE_CORE.agent == "misconfig"
    assert COMMERCE_CORE.cve == "CVE-2026-118539"
    assert "3.3.13" in COMMERCE_CORE.fixed
    assert "8.x-2.41" in COMMERCE_CORE.fixed


# --- Gravity Forms (CVE-2026-103039) ----------------------------------------

GF_CHANGELOG = "/wp-content/plugins/gravityforms/change_log.txt"
_GF_WP_ROOT = (
    '<meta name="generator" content="WordPress 6.8.1" />'
    '<link rel="https://api.w.org/" href="http://127.0.0.1:8081/wp-json/" />'
)
_GF_BANNED = (
    "admin-ajax.php",
    "admin-ajax",
    "/wp-admin",
    "wp-json/gf",
    "gf_submit",
    "gform_submit",
    "maybe_unserialize",
    "O:8:",
    "O:7:",
)


def _gf_asset_html(version: str | None = None) -> str:
    if version is None:
        return (
            f"{_GF_WP_ROOT}"
            '<script src="/wp-content/plugins/gravityforms/js/gravityforms.min.js">'
            "</script>"
            '<link rel="stylesheet" href="/wp-content/plugins/gravityforms/'
            'css/formreset.min.css" />'
        )
    return (
        f"{_GF_WP_ROOT}"
        f'<script src="/wp-content/plugins/gravityforms/js/gravityforms.min.js'
        f'?ver={version}"></script>'
        f'<link rel="stylesheet" href="/wp-content/plugins/gravityforms/'
        f'css/formreset.min.css?ver={version}" />'
    )


def _gf_changelog(version: str) -> str:
    return (
        f"### {version} | 2026-10-01\n"
        "- Added security enhancements.\n"
        "- Fixed an issue in Gravity Forms form display.\n"
        "- Updated gform_enqueue_scripts handling.\n"
    )


def _assert_gf_passive(transport):
    assert {call[0] for call in transport.calls} <= {"GET"}
    assert all(call[2] is None and call[3] is False for call in transport.calls)
    paths = [call[1] for call in transport.calls]
    blob = " ".join(paths)
    for banned in _GF_BANNED:
        assert banned.lower() not in blob.lower()
    for path in paths:
        assert path == GF_CHANGELOG
    assert paths.count(GF_CHANGELOG) <= 1


@pytest.mark.parametrize("version,vulnerable", [
    ("3.1.2", True), ("3.1.1", True), ("3.0.0", True), ("2.9.21", True),
    ("3.1.3", False), ("3.2.0", False), ("3.2.1", False), ("4.0.0", False),
])
def test_gravity_forms_version_matrix(version, vulnerable):
    from agents.cve_checks.gravity_forms import affected
    from agents.cve_checks.versions import parse_dotted
    assert bool(affected(parse_dotted(version))) is vulnerable


def test_gravity_forms_no_wordpress_sends_nothing(monkeypatch):
    transport = Transport()
    transport.routes[GF_CHANGELOG] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _gf_changelog("3.1.2"),
    }
    _install(monkeypatch, transport)
    assert GRAVITY_FORMS.run(
        {}, _ctx(body="<html><body>hello static site</body></html>"),
    ) == []
    assert transport.calls == []


def test_gravity_forms_wordpress_without_plugin_sends_nothing(monkeypatch):
    transport = Transport()
    transport.routes[GF_CHANGELOG] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _gf_changelog("3.1.2"),
    }
    _install(monkeypatch, transport)
    assert GRAVITY_FORMS.run({}, _ctx(body=_GF_WP_ROOT)) == []
    assert transport.calls == []


def test_gravity_forms_asset_ver_312_is_critical_and_passive(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    found = GRAVITY_FORMS.run({}, _ctx(body=_gf_asset_html("3.1.2")))
    assert transport.calls == []
    assert GRAVITY_FORMS.agent == "misconfig"
    assert len(found) == 1
    assert found[0]["severity"] == "critical"
    assert found[0]["check"]["match"] == "gravityforms:3.1.2"
    assert UNCONFIRMED in found[0]["title"]
    assert "CVE-2026-103039" in found[0]["title"]
    assert "CVE-2026-103039" in found[0]["evidence"]
    assert "3.1.3" in found[0]["fix"]
    assert "Patchstack" in found[0]["evidence"]
    assert "Wordfence" in found[0]["evidence"]
    assert "not CISA KEV" in found[0]["evidence"]
    assert "does not confirm" in found[0]["evidence"]
    assert "exploit" not in found[0]["title"].lower()
    assert "we exploit" not in found[0]["evidence"].lower()


def test_gravity_forms_313_and_321_are_not_flagged(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    assert GRAVITY_FORMS.run({}, _ctx(body=_gf_asset_html("3.1.3"))) == []
    assert GRAVITY_FORMS.run({}, _ctx(body=_gf_asset_html("3.2.1"))) == []
    assert transport.calls == []


def test_gravity_forms_plugin_present_no_version_one_get_then_info(monkeypatch):
    transport = Transport()
    transport.routes[GF_CHANGELOG] = {
        "status": 404,
        "content_type": "text/plain",
        "body": "missing",
    }
    _install(monkeypatch, transport)
    found = GRAVITY_FORMS.run({}, _ctx(body=_gf_asset_html(None)))
    _assert_gf_passive(transport)
    assert [call[1] for call in transport.calls] == [GF_CHANGELOG]
    assert len(found) == 1
    assert found[0]["severity"] == "info"
    assert found[0]["check"]["match"] == "gravityforms:unknown"
    assert "CVE-2026-103039" in found[0]["title"]


def test_gravity_forms_changelog_fallback_312_is_vulnerable(monkeypatch):
    transport = Transport()
    transport.routes[GF_CHANGELOG] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _gf_changelog("3.1.2"),
    }
    _install(monkeypatch, transport)
    found = GRAVITY_FORMS.run({}, _ctx(body=_gf_asset_html(None)))
    _assert_gf_passive(transport)
    assert [call[1] for call in transport.calls] == [GF_CHANGELOG]
    assert found[0]["severity"] == "critical"
    assert found[0]["check"]["match"] == "gravityforms:3.1.2"
    assert "CVE-2026-103039" in found[0]["evidence"]
    assert "3.1.3" in found[0]["fix"]


def test_gravity_forms_changelog_fallback_313_is_none(monkeypatch):
    transport = Transport()
    transport.routes[GF_CHANGELOG] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _gf_changelog("3.1.3"),
    }
    _install(monkeypatch, transport)
    assert GRAVITY_FORMS.run({}, _ctx(body=_gf_asset_html(None))) == []
    _assert_gf_passive(transport)


def test_gravity_forms_at_most_one_changelog_get_and_never_form_endpoints(
    monkeypatch,
):
    transport = Transport()
    transport.routes[GF_CHANGELOG] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _gf_changelog("3.1.2"),
    }
    transport.routes["/wp-admin/admin-ajax.php"] = {
        "status": 200, "body": "should-never-be-fetched",
    }
    transport.routes["/wp-json/gf/v2/forms"] = {
        "status": 200, "body": "should-never-be-fetched",
    }
    _install(monkeypatch, transport)
    found = GRAVITY_FORMS.run({}, _ctx(body=_gf_asset_html(None)))
    _assert_gf_passive(transport)
    assert [call[1] for call in transport.calls] == [GF_CHANGELOG]
    assert all(call[0] == "GET" for call in transport.calls)
    assert found and found[0]["severity"] == "critical"
    blob = " ".join(call[1] for call in transport.calls).lower()
    assert "admin-ajax" not in blob
    assert "wp-json" not in blob
    assert "wp-admin" not in blob


def test_gravity_forms_kill_switch_before_first_request_is_none(monkeypatch):
    def opener(_req, timeout=None):
        raise AssertionError("kill switch did not stop the request")

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(
        target="http://127.0.0.1:8081/", actor="tester", run_id="run_gf_stop",
    )
    lease.stop()
    try:
        with control.scope(lease):
            with pytest.raises(control.ScanStopped):
                GRAVITY_FORMS.run({}, _ctx(body=_gf_asset_html(None)))
    finally:
        control.release(lease.run_id)


def test_gravity_forms_requests_are_get_audited_and_have_no_body(monkeypatch):
    seen = {"calls": 0, "methods": [], "data": []}

    def opener(req, timeout=None):
        seen["calls"] += 1
        seen["methods"].append(req.get_method())
        seen["data"].append(req.data)
        return _Resp(
            body=_gf_changelog("3.1.2").encode(),
            headers=[("content-type", "text/plain")],
        )

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(
        target="http://127.0.0.1:8081/", actor="tester", run_id="run_gf_audit",
    )
    try:
        with control.scope(lease), control.agent("misconfig"):
            found = GRAVITY_FORMS.run({}, _ctx(body=_gf_asset_html(None)))
    finally:
        control.release(lease.run_id)
    assert seen["calls"] == 1
    assert seen["methods"] == ["GET"]
    assert seen["data"] == [None]
    assert found and found[0]["severity"] == "critical"
    import audit
    rows = [row for row in audit.recent(20) if row["kind"] == "request"]
    assert rows
    assert rows[-1]["action"] == "GET"
    assert rows[-1]["agent"] == "misconfig"
    assert GF_CHANGELOG in rows[-1]["url"]
    assert "body" not in rows[-1]


def test_gravity_forms_non_allowlisted_host_is_refused():
    with pytest.raises(main.ScopeError) as exc:
        main.allowlisted_host(
            "https://gf.attacker.example/wp-content/plugins/gravityforms/"
            "change_log.txt"
        )
    assert "allowlist" in str(exc.value)


def test_gravity_forms_check_source_is_get_only_static_fingerprint():
    text = (
        ROOT / "agents" / "cve_checks" / "gravity_forms.py"
    ).read_text(encoding="utf-8")
    assert "fetch_path(ctx, CHANGELOG" in text
    assert text.count("fetch_path(") == 1
    assert "root_observation" in text
    assert "looks_like_wordpress" in text
    assert "post_brotli" not in text
    assert "urlopen" not in text
    assert "http.client" not in text
    assert "admin-ajax" in text.lower()
    assert "Never requests" in text or "never requests" in text.lower()
    assert "O:" in text or "serialized" in text.lower()
    assert GRAVITY_FORMS.agent == "misconfig"
    assert GRAVITY_FORMS.cve == "CVE-2026-103039"
    assert "3.1.3" in GRAVITY_FORMS.fixed
