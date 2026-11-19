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
from agents.cve_checks.gravity_forms_chunked import CHECK as GRAVITY_FORMS_CHUNKED
from agents.cve_checks.ai_engine import CHECK as AI_ENGINE
from agents.cve_checks.ai_engine_upload import CHECK as AI_ENGINE_UPLOAD
from agents.cve_checks.commerce_core import CHECK as COMMERCE_CORE
from agents.cve_checks.craft_cms import CHECK as CRAFT_CMS
from agents.cve_checks.wpforo import CHECK as WPFORO
from agents.cve_checks.ninja_forms_uploads import CHECK as NINJA_FORMS_UPLOADS
from agents.cve_checks.apache_mod_http2 import CHECK as APACHE_MOD_HTTP2
from agents.cve_checks.supabase_storage import CHECK as SUPABASE_STORAGE
from agents.cve_checks.vite_dev_server import CHECK as VITE_DEV
from agents.cve_checks.vite_dev_server import CLIENT_PATH as VITE_CLIENT
from agents.cve_checks.vite_dev_server import TITLE as VITE_TITLE
from agents.cve_checks.vite_dev_server import affected_vite, affected_vite_plus
from agents.cve_checks.wedevs import CHECK as WEDEVS
from agents.cve_checks.masteriyo import CHECK as MASTERIYO
from agents.cve_checks.wordpress import CHECK as WORDPRESS
from agents.cve_checks.xen_orchestra import CHECK as XEN_ORCHESTRA
from agents.cve_checks.wp_data_access import CHECK as WP_DATA_ACCESS
from agents.cve_checks.wp_duplicate import CHECK as WP_DUPLICATE
from agents.cve_checks.yootheme import CHECK as YOOTHEME
from agents.cve_checks.btcpay import CHECK as BTCPAY
from agents.cve_checks.bricksforge import CHECK as BRICKSFORGE
from agents.cve_checks.automatorwp_webhooks import CHECK as AUTOMATORWP_WEBHOOKS
from agents.cve_checks.estatik import CHECK as ESTATIK
from agents.cve_checks.ultra_addons_cf7 import CHECK as ULTRA_ADDONS_CF7
from agents.cve_checks.confluence_axis import CHECK as CONFLUENCE_AXIS
from agents.cve_checks.mercury import CHECK as MERCURY
from agents.cve_checks.mercury import TERMINALS as MERCURY_TERMINALS
from agents.cve_checks.litellm_guardrail import CHECK as LITELLM_GUARDRAIL
from agents.cve_checks.litellm_guardrail import READINESS as LITELLM_READINESS
from agents.cve_checks.apache_roller import CHECK as APACHE_ROLLER
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
    "[attribute]",
    "%5Battribute%5D",
    "craft.search",
    "gf_upload",
    "GFAsyncUpload",
    "wpforo.nonces",
    "href[locale]",
    "href%5Blocale%5D",
    "wpforo_ajax",
    "saveProgress",
    "nf_ajax_submit",
    "file_path",
    "wp-json/mwai",
    "/wp-json/mwai/",
    "mwai/",
    "/mwai-ui/",
    "wp-json/bricksforge",
    "/wp-json/bricksforge/v1/form_submit",
    "bricksforge_regenerate_nonce",
    "bricksforge_form_submit",
    "temporaryFileUploads",
    "/wp-content/uploads/bricksforge/tmp/",
    "bricksforge/tmp",
    "/wp-json/automatorwp",
    "automatorwp/webhooks",
    "wp-json/automatorwp",
    "lostpassword",
    "wp-login.php",
    "/wp-admin",
    "user_id=",
    "password=",
    "listing-search",
    "template=",
    "path=",
    "../",
    "%2e%2e",
    "%2E%2E",
    "wp-json/contact-form-7",
    "/wp-json/contact-form-7/",
    "contact-form-7/v1",
    "wpcf7",
    "..%2f",
    "wp-config.php",
    "uacf7_wpcf7_mail_components",
    "/pdf",
    ".pdf",
    "/rpc/",
    "/rpc/soap-axis",
    "/rpc/xmlrpc",
    "soap-axis",
    "?wsdl",
    "wsdl",
    "text/xml",
    "application/soap",
    "exceptionName",
    "POST /api/terminals",
    "/terminals/websocket",
    "/api/kernels",
    "/api/sessions",
    "/api/contents",
    "/api/shutdown",
    "/guardrails/test_custom_code",
    "/key/generate",
    "/config/update",
    "/chat/completions",
    "/roller-services/xmlrpc",
    "/roller/roller-services/xmlrpc",
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
    # wpForo only probes readme when WordPress + plugin path are present.
    assert paths.count("/wp-content/plugins/wpforo/readme.txt") == 0
    # Ninja Forms File Uploads only probes changelog.txt when WordPress + plugin path are present.
    assert paths.count("/wp-content/plugins/ninja-forms-uploads/changelog.txt") == 0
    # Craft CMS only probes /admin/login after a Craft fingerprint on the root response.
    assert paths.count("/admin/login") == 0
    # AI Engine only probes readme when WordPress + plugin path are present.
    assert paths.count("/wp-content/plugins/ai-engine/readme.txt") == 0
    # Bricksforge only probes after WordPress is visible in crawled HTML.
    assert paths.count("/wp-content/plugins/bricksforge/readme.txt") == 0
    assert paths.count("/wp-content/plugins/bricksforge/changelog.txt") == 0
    assert paths.count("/wp-content/uploads/") == 0
    # yootheme and btcpay each fetch the in-scope `/`, plus xen-orchestra's empty-body fallback
    assert paths.count("/") == 3
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
    assert "attribute" not in blob.lower()
    assert "craft.search" not in blob.lower()
    assert "wpforo" not in blob.lower()
    assert "href[locale]" not in blob.lower()
    assert "wpforo.nonces" not in blob.lower()
    assert "ninja-forms-uploads" not in blob.lower()
    assert "saveprogress" not in blob.lower()
    assert "nf_ajax_submit" not in blob.lower()
    assert "/admin/login" not in paths
    assert "wp-json/mwai" not in blob.lower()
    assert all("mcp" not in path.lower() for path in paths)
    assert "ai-engine" not in blob.lower()
    assert "bricksforge" not in blob.lower()
    assert "temporaryfileuploads" not in blob.lower()
    assert "wp-json/bricksforge" not in blob.lower()
    # AutomatorWP Webhooks only probes after WordPress is visible in crawled HTML.
    assert paths.count("/wp-content/plugins/automatorwp-webhooks/readme.txt") == 0
    assert paths.count("/wp-content/plugins/automatorwp-pro-webhooks/readme.txt") == 0
    assert "automatorwp" not in blob.lower()
    assert "/wp-json/automatorwp" not in blob.lower()
    # Estatik only probes readme when WordPress + plugin path are present.
    assert paths.count("/wp-content/plugins/estatik/readme.txt") == 0
    assert "estatik" not in blob.lower()
    assert "listing-search" not in blob.lower()
    # Ultra Addons for CF7 only probes readme when WordPress + plugin path are present.
    assert paths.count(
        "/wp-content/plugins/ultimate-addons-for-contact-form-7/readme.txt"
    ) == 0
    assert "ultimate-addons-for-contact-form-7" not in blob.lower()
    assert "wp-json/contact-form-7" not in blob.lower()
    # Confluence Axis only probes /login.action after a Confluence fingerprint.
    assert paths.count("/login.action") == 0
    assert "/rpc/" not in blob
    assert "soap-axis" not in blob.lower()
    assert "xmlrpc" not in blob.lower()
    assert "wsdl" not in blob.lower()
    # Mercury only probes /api/terminals after a Mercury HTML fingerprint.
    assert paths.count("/api/terminals") == 0
    assert "/terminals/websocket" not in blob
    assert "/api/kernels" not in blob
    assert "/api/sessions" not in blob
    assert "/api/contents" not in blob
    assert "/api/shutdown" not in blob
    assert "POST /api/terminals" not in blob
    # LiteLLM only probes /health/readiness after a LiteLLM fingerprint.
    assert paths.count("/health/readiness") == 0
    assert "/guardrails/test_custom_code" not in blob
    assert "/key/generate" not in blob
    assert "/config/update" not in blob
    assert "/chat/completions" not in blob
    # Apache Roller is passive HTML only; never probes XML-RPC or admin/login.
    assert "/roller-services/xmlrpc" not in blob
    assert "/roller/roller-services/xmlrpc" not in blob
    assert "/roller-ui/login" not in blob
    assert "/roller-ui/admin" not in blob
    assert "/roller-services/rest" not in blob
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
    # `brotli` is only needed to decode-validate the constant; the runtime ships the
    # bytes hardcoded. Skip (like the Playwright tests) when it isn't installed, so a
    # bare-venv `pytest` doesn't error on a package the scanner never imports.
    brotli = pytest.importorskip("brotli")
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


# --- Masteriyo LMS ----------------------------------------------------------

MASTERIYO_README = "/wp-content/plugins/learning-management-system/readme.txt"


def _masteriyo_readme(tag=None):
    lines = [
        "=== Masteriyo LMS ===",
        "Contributors: Masteriyo, themeisle",
        "Requires at least: 6.6",
    ]
    if tag is not None:
        lines.append(f"Stable tag: {tag}")
    return "\n".join(lines) + "\n"


def _assert_masteriyo_one_get(transport):
    assert transport.calls == [("GET", MASTERIYO_README, None, False)]


@pytest.mark.parametrize("tag,critical", [
    ("2.3.2", True),
    ("2.3.1", True),
    ("2.3", True),
    ("1.0.0", True),
    ("2.3.3", False),
    ("2.3.10", False),
    ("3.5.1", False),
])
def test_masteriyo_stable_tag_range(monkeypatch, tag, critical):
    transport = Transport()
    transport.routes[MASTERIYO_README] = {
        "status": 200, "content_type": "text/plain", "body": _masteriyo_readme(tag),
    }
    _install(monkeypatch, transport)
    found = MASTERIYO.run({}, _ctx())
    _assert_masteriyo_one_get(transport)
    if critical:
        assert len(found) == 1
        assert found[0]["severity"] == "critical"
        assert found[0]["check"]["match"] == f"masteriyo:{tag}"
        assert UNCONFIRMED in found[0]["title"]
        assert UNCONFIRMED in found[0]["evidence"]
        assert "CVE-2026-73996" in found[0]["evidence"]
        assert "2.3.3" in found[0]["fix"]
        assert "CISA" not in found[0]["title"]
        assert "CISA" not in found[0]["evidence"]
        assert "actively exploited" not in found[0]["title"].lower()
        blob = json.dumps(found)
        assert "<?php" not in blob
        assert "proven" not in blob.lower()
    else:
        assert found == []


def test_masteriyo_232_request_budget_is_exactly_one_get(monkeypatch):
    transport = Transport()
    transport.routes[MASTERIYO_README] = {
        "status": 200, "content_type": "text/plain", "body": _masteriyo_readme("2.3.2"),
    }
    _install(monkeypatch, transport)
    found = MASTERIYO.run({}, _ctx())
    _assert_masteriyo_one_get(transport)
    assert found[0]["severity"] == "critical"
    text = (ROOT / "agents" / "cve_checks" / "masteriyo.py").read_text(encoding="utf-8")
    assert text.count("fetch_path(") == 1
    assert "post_brotli" not in text
    assert "recon.post" not in text
    assert "recon.send" not in text
    for banned in ("/wp-admin", "admin-ajax", "async-upload", "<?php", "php://", "../", "multipart"):
        assert banned not in text


@pytest.mark.parametrize("status,body", [
    (404, ""),
    (200, "<!doctype html><html><head><title>Masteriyo</title></head><body>Stable tag: 2.3.2</body></html>"),
    (200, "<html><body><p>Masteriyo LMS Stable tag: 2.3.2</p></body></html>"),
    (200, "=== Some Other Plugin ===\nContributors: someone\nStable tag: 2.3.2\n"),
    (200, "Masteriyo is mentioned here.\nStable tag: 2.3.2\n"),
])
def test_masteriyo_missing_or_non_plugin_content_is_clean(monkeypatch, status, body):
    transport = Transport()
    transport.routes[MASTERIYO_README] = {
        "status": status, "content_type": "text/html", "body": body,
    }
    _install(monkeypatch, transport)
    assert MASTERIYO.run({}, _ctx()) == []
    _assert_masteriyo_one_get(transport)


def test_masteriyo_readme_without_stable_tag_is_info(monkeypatch):
    transport = Transport()
    transport.routes[MASTERIYO_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _masteriyo_readme(None),
    }
    _install(monkeypatch, transport)
    found = MASTERIYO.run({}, _ctx())
    _assert_masteriyo_one_get(transport)
    assert len(found) == 1
    assert found[0]["severity"] == "info"
    assert found[0]["check"]["match"] == "masteriyo:unknown"
    assert "CVE-2026-73996" in found[0]["evidence"]
    assert UNCONFIRMED not in found[0]["title"]


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


# --- BTCPay Server (CVE-2026-119757) ----------------------------------------

_FORBIDDEN = (
    "macaroon",
    "/api/v1",
    "/lnd",
)


def _btcpay_html(version=None, *, assets=True, footer=True, extra=""):
    links = ""
    if assets:
        links = (
            '<link href="/main/site.css?v=abc" rel="stylesheet" />'
            '<link href="/main/layout.css?v=def" rel="stylesheet" />'
            '<link href="/main/fonts/OpenSans.css?v=ghi" rel="stylesheet" />'
        )
    ver = ""
    if version:
        ver = f'<div class="text-center">\u00a9 BTCPay Server v{version}</div>'
    foot = ""
    if footer:
        foot = f'<footer class="btcpay-footer d-print-none">{ver}</footer>'
    elif ver:
        foot = ver
    return f"<html><head>{links}</head><body>{foot}{extra}</body></html>"


def _record(transport):
    seen = []
    original = transport.fetch

    def fetch(url, session=None, max_bytes=65536, follow=False):
        seen.append((url, session, follow, max_bytes))
        return original(url, session=session, max_bytes=max_bytes, follow=follow)

    transport.fetch = fetch
    return seen


def _assert_btcpay_passive(transport, seen):
    assert len(seen) <= 1
    assert len(transport.calls) <= 1
    for url, session, follow, _max in seen:
        assert session is None and follow is False
        assert "?" not in url
        blob = url.lower()
        for banned in _FORBIDDEN:
            assert banned not in blob
    for method, path, session, follow in transport.calls:
        assert method == "GET"
        assert session is None and follow is False
        blob = path.lower()
        for banned in _FORBIDDEN:
            assert banned not in blob


@pytest.mark.parametrize("numeric,prerelease,kind", [
    ((2, 4, 1), None, "affected"),
    ((2, 4, 0), None, "affected"),
    ((1, 13, 1), None, "affected"),
    ((1, 0, 5, 7), None, "affected"),
    ((2, 4, 2), None, "patched"),
    ((2, 4, 7), None, "patched"),
    ((2, 4, 2), "rc1", "affected"),
    ((2, 4, 2), "rc2", "affected"),
    ((2, 4, 2), "rc.1", "affected"),
    ((2, 4, 0), "rc3", "affected"),
    ((2, 4, 1), "rc1", "affected"),
    ((2, 4, 3), "rc1", "patched"),
    ((2, 4), None, "ambiguous"),
    ((2, 4, 2, 1), None, "ambiguous"),
])
def test_btcpay_version_matrix(numeric, prerelease, kind):
    from agents.cve_checks.btcpay import classify
    assert classify(numeric, prerelease) == kind


@pytest.mark.parametrize("version", ["2.4.1", "2.4.1+fbf761f", "1.13.1", "1.0.5.7"])
def test_btcpay_affected_footer_is_critical_and_passive(monkeypatch, version):
    transport = Transport()
    _install(monkeypatch, transport)
    found = BTCPAY.run({}, _ctx(body=_btcpay_html(version)))
    _assert_btcpay_passive(transport, [])
    assert transport.calls == []
    assert len(found) == 1
    assert found[0]["severity"] == "critical"
    assert found[0]["layer"] == "surface"
    assert found[0]["check"]["id"] == "btcpay-server"
    label = version.split("+", 1)[0]
    assert found[0]["check"]["match"] == f"btcpay:{label}"
    assert UNCONFIRMED in found[0]["title"]
    assert UNCONFIRMED in found[0]["evidence"]
    assert "CVE-2026-119757" in found[0]["evidence"]
    assert "2.4.2" in found[0]["fix"]
    assert "KEV" not in json.dumps(found)
    assert "CISA" not in json.dumps(found)
    assert BTCPAY.agent == "secrets"


@pytest.mark.parametrize("version", ["2.4.2", "2.4.2+fbf761f", "2.4.7", "2.4.3-rc1"])
def test_btcpay_patched_footer_is_clean(monkeypatch, version):
    transport = Transport()
    _install(monkeypatch, transport)
    assert BTCPAY.run({}, _ctx(body=_btcpay_html(version))) == []
    assert transport.calls == []


@pytest.mark.parametrize("version,label", [
    ("2.4.2-rc1", "2.4.2-rc1"),
    ("2.4.2-rc2+abc", "2.4.2-rc2"),
    ("2.4.2-rc.1", "2.4.2-rc.1"),
    ("2.4.0-rc3", "2.4.0-rc3"),
])
def test_btcpay_prerelease_cases(monkeypatch, version, label):
    transport = Transport()
    _install(monkeypatch, transport)
    found = BTCPAY.run({}, _ctx(body=_btcpay_html(version)))
    assert transport.calls == []
    assert len(found) == 1
    assert found[0]["severity"] == "critical"
    assert found[0]["check"]["match"] == f"btcpay:{label}"
    assert UNCONFIRMED in found[0]["title"]
    assert UNCONFIRMED in found[0]["evidence"]
    if label.startswith("2.4.2-"):
        assert "release candidates are affected" in found[0]["evidence"]


def test_btcpay_branding_without_version_is_info(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    html = _btcpay_html(
        extra='<script src="/vendor/jquery/jquery.min.js?ver=2.4.1"></script>',
    )
    found = BTCPAY.run({}, _ctx(body=html))
    assert transport.calls == []
    assert len(found) == 1
    assert found[0]["severity"] == "info"
    assert found[0]["check"]["match"] == "btcpay:unknown"
    assert UNCONFIRMED not in found[0]["title"]
    assert "2.4.1" not in found[0]["title"]
    checkout = (
        '<link href="/checkout/checkout.css?v=abc" rel="stylesheet" />'
        '<link href="/main/site.css?v=abc" rel="stylesheet" />'
        '<link href="/main/layout.css?v=def" rel="stylesheet" />'
    )
    assert BTCPAY.run({}, _ctx(body=checkout))[0]["severity"] == "info"
    copied = _btcpay_html(footer=False, assets=False, extra="&copy; BTCPay Server v2.4")
    ambiguous = BTCPAY.run({}, _ctx(body=copied))
    assert ambiguous[0]["severity"] == "info"
    assert ambiguous[0]["check"]["match"] == "btcpay:unknown"


def test_btcpay_non_product_html_is_not_a_finding(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    html = (
        "<html><body><p>Security Advisory: BTCPay Server before 2.4.2, "
        "including 2.4.2 release candidates. LND 0.21.1. Bootstrap 5.3.2.</p>"
        '<script src="/js/app.js?ver=2.4.1"></script>'
        '<a href="https://blog.btcpayserver.org/security-advisory-btcpay-server-2-4-2/">advisory</a>'
        '<link href="/main/site.css?v=2.4.1" rel="stylesheet" />'
        "</body></html>"
    )
    assert BTCPAY.run({}, _ctx(body=html)) == []
    assert BTCPAY.run({}, _ctx(body="<html><p>juice shop</p></html>")) == []
    assert transport.calls == []


def test_btcpay_cached_html_does_not_fetch_linked_paths(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    html = _btcpay_html(
        "2.4.1",
        extra='<a href="/admin.macaroon">no</a><a href="/api/v1/server/info">no</a>',
    )
    ctx = _ctx(body=html)
    ctx.session = {"cookie": "do-not-send"}
    found = BTCPAY.run({}, ctx)
    assert transport.calls == []
    assert found[0]["severity"] == "critical"
    assert "macaroon" not in json.dumps(found).lower()


def test_btcpay_cache_miss_is_one_query_free_get(monkeypatch):
    transport = Transport()
    seen = _record(transport)
    transport.routes["/login"] = {
        "status": 200,
        "content_type": "text/html",
        "body": _btcpay_html("2.4.1"),
    }
    transport.routes["/admin.macaroon"] = {"status": 200, "body": "secret"}
    transport.routes["/api/v1/server/info"] = {"status": 200, "body": "{}"}
    _install(monkeypatch, transport)
    ctx = _ctx(body="")
    ctx.url = "http://127.0.0.1:8081/login?return=/admin.macaroon"
    ctx.recon_root = {**ctx.recon_root, "url": ctx.url, "body_snippet": ""}
    ctx.session = {"cookie": "do-not-send"}
    found = BTCPAY.run({}, ctx)
    assert [url for url, _session, _follow, _max in seen] == ["http://127.0.0.1:8081/login"]
    _assert_btcpay_passive(transport, seen)
    assert found[0]["severity"] == "critical"
    assert found[0]["check"]["match"] == "btcpay:2.4.1"


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8081/admin.macaroon",
    "http://127.0.0.1:8081/data/Admin.Macaroon",
    "http://127.0.0.1:8081/files/%6dacaroon",
    "http://127.0.0.1:8081/files/%256dacaroon",
    "http://127.0.0.1:8081/api/v1/server/info",
    "http://127.0.0.1:8081/lnd/v1/getinfo",
])
def test_btcpay_refuses_forbidden_paths_without_a_request(monkeypatch, url):
    transport = Transport()
    seen = _record(transport)
    _install(monkeypatch, transport)
    ctx = _ctx(body="")
    ctx.url = url
    ctx.recon_root = {**ctx.recon_root, "url": url, "body_snippet": ""}
    assert BTCPAY.run({}, ctx) == []
    assert seen == []
    assert transport.calls == []


def test_btcpay_registry_keeps_existing_checks():
    ids = [check.id for check in CHECKS]
    assert ids[-1] == "apache-roller"
    assert ids[-2] == "litellm-guardrail"
    assert ids[-3] == "mercury"
    assert ids[-4] == "confluence-axis"
    assert ids[-5] == "ultra-addons-cf7"
    assert ids[-6] == "estatik"
    assert ids[-7] == "automatorwp-webhooks"
    assert ids[-8] == "bricksforge"
    for required in (
        "php2shell", "wordpress-core", "yootheme-pro", "mlflow", "masteriyo-lms",
        "btcpay-server", "bricksforge", "automatorwp-webhooks", "estatik",
        "ultra-addons-cf7", "ai-engine", "ai-engine-upload", "confluence-axis",
        "mercury", "litellm-guardrail", "apache-roller",
    ):
        assert required in ids
    assert ids[-9] == "btcpay-server"
    assert "ai-engine-upload" in ids
    assert ids.index("ai-engine-upload") == ids.index("ai-engine") + 1
    assert BTCPAY.agent == "secrets"
    assert BRICKSFORGE.agent == "misconfig"
    assert AUTOMATORWP_WEBHOOKS.agent == "auth"
    assert ESTATIK.agent == "misconfig"
    assert ULTRA_ADDONS_CF7.agent == "misconfig"
    assert AI_ENGINE.agent == "misconfig"
    assert AI_ENGINE_UPLOAD.agent == "misconfig"
    assert CONFLUENCE_AXIS.agent == "misconfig"
    assert MERCURY.agent == "misconfig"
    assert LITELLM_GUARDRAIL.agent == "misconfig"
    assert APACHE_ROLLER.agent == "misconfig"


def test_verifier_confirms_btcpay_then_rejects_a_patched_build():
    html = _btcpay_html("2.4.1")
    found = BTCPAY.run({}, _ctx(body=html))[0]
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
    fresh["body_snippet"] = _btcpay_html("2.4.2")
    ok, verdict, _note = verifier._verify_deterministic(
        found, fresh, fresh["raw_headers"], [], fresh["url"], None,
    )
    assert not ok and verdict == "rejected"


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
    "gf_upload",
    "GFAsyncUpload",
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


# --- Gravity Forms chunked upload (CVE-2026-119529) ------------------------

@pytest.mark.parametrize("version,vulnerable", [
    ("3.1.2", True), ("3.1.3", True), ("3.2.0", True), ("3.2.1", True),
    ("3.2.2", False), ("3.3.0", False), ("4.0.0", False),
])
def test_gravity_forms_chunked_version_matrix(version, vulnerable):
    from agents.cve_checks.gravity_forms_chunked import affected
    from agents.cve_checks.versions import parse_dotted
    assert bool(affected(parse_dotted(version))) is vulnerable


def test_gravity_forms_312_reports_both_cves(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    ctx = _ctx(body=_gf_asset_html("3.1.2"))
    first = GRAVITY_FORMS.run({}, ctx)
    second = GRAVITY_FORMS_CHUNKED.run({}, ctx)
    assert transport.calls == []
    assert len(first) == 1 and first[0]["severity"] == "critical"
    assert "CVE-2026-103039" in first[0]["title"]
    assert len(second) == 1 and second[0]["severity"] == "medium"
    assert "CVE-2026-119529" in second[0]["title"]
    assert "3.2.2" in second[0]["fix"]
    assert "exploit" not in second[0]["title"].lower()
    assert "we exploit" not in second[0]["evidence"].lower()


def test_gravity_forms_321_reports_119529_only(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    ctx = _ctx(body=_gf_asset_html("3.2.1"))
    assert GRAVITY_FORMS.run({}, ctx) == []
    found = GRAVITY_FORMS_CHUNKED.run({}, ctx)
    assert transport.calls == []
    assert len(found) == 1
    assert found[0]["severity"] == "medium"
    assert "CVE-2026-119529" in found[0]["title"]
    assert found[0]["check"]["match"] == "gravityforms-chunked:3.2.1"
    assert "3.2.2" in found[0]["fix"]
    assert "SSI" in found[0]["evidence"] or "ssi" in found[0]["evidence"].lower()
    assert "VulnCheck" in found[0]["evidence"] or "vulncheck" in found[0]["evidence"].lower()


def test_gravity_forms_322_reports_none(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    ctx = _ctx(body=_gf_asset_html("3.2.2"))
    assert GRAVITY_FORMS.run({}, ctx) == []
    assert GRAVITY_FORMS_CHUNKED.run({}, ctx) == []
    assert transport.calls == []


def test_gravity_forms_both_cves_share_one_changelog_get(monkeypatch):
    transport = Transport()
    transport.routes[GF_CHANGELOG] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _gf_changelog("3.1.2"),
    }
    transport.routes["/wp-admin/admin-ajax.php"] = {
        "status": 200, "body": "should-never-be-fetched",
    }
    transport.routes["/?gf_page=upload"] = {
        "status": 200, "body": "should-never-be-fetched",
    }
    _install(monkeypatch, transport)
    ctx = _ctx(body=_gf_asset_html(None))
    first = GRAVITY_FORMS.run({}, ctx)
    second = GRAVITY_FORMS_CHUNKED.run({}, ctx)
    _assert_gf_passive(transport)
    assert [call[1] for call in transport.calls] == [GF_CHANGELOG]
    assert [call[1] for call in transport.calls].count(GF_CHANGELOG) == 1
    assert first and first[0]["severity"] == "critical"
    assert "CVE-2026-103039" in first[0]["evidence"]
    assert second and second[0]["severity"] == "medium"
    assert "CVE-2026-119529" in second[0]["evidence"]
    blob = " ".join(call[1] for call in transport.calls).lower()
    assert "gf_upload" not in blob
    assert "gfasyncupload" not in blob
    assert "admin-ajax" not in blob


def test_gravity_forms_chunked_no_wordpress_sends_nothing(monkeypatch):
    transport = Transport()
    transport.routes[GF_CHANGELOG] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _gf_changelog("3.2.1"),
    }
    _install(monkeypatch, transport)
    assert GRAVITY_FORMS_CHUNKED.run(
        {}, _ctx(body="<html><body>hello static site</body></html>"),
    ) == []
    assert transport.calls == []


def test_gravity_forms_chunked_wordpress_without_plugin_sends_nothing(monkeypatch):
    transport = Transport()
    transport.routes[GF_CHANGELOG] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _gf_changelog("3.2.1"),
    }
    _install(monkeypatch, transport)
    assert GRAVITY_FORMS_CHUNKED.run({}, _ctx(body=_GF_WP_ROOT)) == []
    assert transport.calls == []


def test_gravity_forms_chunked_plugin_present_no_version_one_get_then_info(
    monkeypatch,
):
    transport = Transport()
    transport.routes[GF_CHANGELOG] = {
        "status": 404,
        "content_type": "text/plain",
        "body": "missing",
    }
    _install(monkeypatch, transport)
    found = GRAVITY_FORMS_CHUNKED.run({}, _ctx(body=_gf_asset_html(None)))
    _assert_gf_passive(transport)
    assert [call[1] for call in transport.calls] == [GF_CHANGELOG]
    assert len(found) == 1
    assert found[0]["severity"] == "info"
    assert found[0]["check"]["match"] == "gravityforms-chunked:unknown"
    assert "CVE-2026-119529" in found[0]["title"]


def test_gravity_forms_chunked_changelog_fallback_321_is_vulnerable(monkeypatch):
    transport = Transport()
    transport.routes[GF_CHANGELOG] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _gf_changelog("3.2.1"),
    }
    _install(monkeypatch, transport)
    found = GRAVITY_FORMS_CHUNKED.run({}, _ctx(body=_gf_asset_html(None)))
    _assert_gf_passive(transport)
    assert found[0]["severity"] == "medium"
    assert found[0]["check"]["match"] == "gravityforms-chunked:3.2.1"
    assert "CVE-2026-119529" in found[0]["evidence"]
    assert "3.2.2" in found[0]["fix"]


def test_gravity_forms_chunked_changelog_fallback_322_is_none(monkeypatch):
    transport = Transport()
    transport.routes[GF_CHANGELOG] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _gf_changelog("3.2.2"),
    }
    _install(monkeypatch, transport)
    assert GRAVITY_FORMS_CHUNKED.run({}, _ctx(body=_gf_asset_html(None))) == []
    _assert_gf_passive(transport)


def test_gravity_forms_chunked_kill_switch_before_first_request_is_none(monkeypatch):
    def opener(_req, timeout=None):
        raise AssertionError("kill switch did not stop the request")

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(
        target="http://127.0.0.1:8081/", actor="tester", run_id="run_gf_chunk_stop",
    )
    lease.stop()
    try:
        with control.scope(lease):
            with pytest.raises(control.ScanStopped):
                GRAVITY_FORMS_CHUNKED.run({}, _ctx(body=_gf_asset_html(None)))
    finally:
        control.release(lease.run_id)


def test_gravity_forms_chunked_check_source_reuses_helpers_no_upload():
    text = (
        ROOT / "agents" / "cve_checks" / "gravity_forms_chunked.py"
    ).read_text(encoding="utf-8")
    assert "fetch_path" not in text
    assert "resolve_plugin_version" in text
    assert "urlopen" not in text
    assert "http.client" not in text
    assert "gf_upload" in text
    assert "GFAsyncUpload" in text
    assert GRAVITY_FORMS_CHUNKED.agent == "misconfig"
    assert GRAVITY_FORMS_CHUNKED.cve == "CVE-2026-119529"
    assert "3.2.2" in GRAVITY_FORMS_CHUNKED.fixed

# --- Craft CMS (CVE-2026-123488) --------------------------------------------

CRAFT_LOGIN = "/admin/login"
_CRAFT_BANNED = (
    "attribute",
    "[attribute]",
    "%5Battribute%5D",
    "craft.search",
    "SLEEP(",
    "BENCHMARK(",
    "-- ",
    "UNION SELECT",
    "DROP TABLE",
)


def _craft_login_html(version=None):
    ver = f"Craft CMS {version}" if version else "Craft CMS"
    return (
        "<!DOCTYPE html><html><head><title>Sign In</title></head>"
        f'<body><a id="poweredby" href="https://craftcms.com/" '
        f'title="Powered by Craft CMS">{ver}</a>'
        '<form method="post"><input name="loginName">'
        '<input name="password" type="password"></form>'
        "</body></html>"
    )


def _craft_root(*, powered=True, cookie=None, resources=False, body_extra=""):
    headers = {}
    if powered:
        headers["x-powered-by"] = "Craft CMS"
    if cookie:
        headers["set-cookie"] = cookie
    body = "<html><body><p>Welcome</p>"
    if resources:
        body += '<link href="/cpresources/abc123/css/cp.css" rel="stylesheet">'
    body += body_extra + "</body></html>"
    return headers, body


def _assert_craft_passive(transport):
    assert all(call[0] == "GET" for call in transport.calls)
    assert all(call[2] is None and call[3] is False for call in transport.calls)
    for _method, path, _session, _follow in transport.calls:
        low = path.lower()
        for banned in _CRAFT_BANNED:
            assert banned.lower() not in low


def test_craft_cms_no_fingerprint_sends_nothing(monkeypatch):
    transport = Transport()
    transport.routes[CRAFT_LOGIN] = {
        "status": 200,
        "content_type": "text/html",
        "body": _craft_login_html("4.18.8"),
    }
    _install(monkeypatch, transport)
    assert CRAFT_CMS.run({}, _ctx(body="<html><body>hello</body></html>")) == []
    assert transport.calls == []


@pytest.mark.parametrize("version,flagged", [
    ("4.18.8", True),
    ("4.18.9", False),
    ("4.0.0", True),
    ("5.11.1", True),
    ("5.11.2", False),
    ("5.0.0", True),
    ("3.9.15", False),
    ("3.5.0", False),
    ("6.0.0", False),
])
def test_craft_cms_login_version_matrix(monkeypatch, version, flagged):
    transport = Transport()
    transport.routes[CRAFT_LOGIN] = {
        "status": 200,
        "content_type": "text/html",
        "body": _craft_login_html(version),
    }
    _install(monkeypatch, transport)
    headers, body = _craft_root()
    found = CRAFT_CMS.run({}, _ctx(headers=headers, body=body))
    _assert_craft_passive(transport)
    assert [call[1] for call in transport.calls] == [CRAFT_LOGIN]
    if flagged:
        assert len(found) == 1
        assert found[0]["severity"] == "critical"
        assert UNCONFIRMED in found[0]["title"]
        assert "CVE-2026-123488" in found[0]["title"]
        assert "CVE-2026-123488" in found[0]["evidence"]
        assert "GHSA-qcvp-ggx3-97r6" in found[0]["evidence"]
        assert "4.18.9" in found[0]["fix"]
        assert "5.11.2" in found[0]["fix"]
        assert found[0]["check"]["match"] == f"craft-cms:{version}"
        assert "exploit" not in found[0]["title"].lower()
        assert "exploits" not in found[0]["evidence"].lower().replace(
            "exploited", ""
        )
    else:
        assert found == []


def test_craft_cms_fingerprint_without_version_is_info(monkeypatch):
    transport = Transport()
    transport.routes[CRAFT_LOGIN] = {
        "status": 200,
        "content_type": "text/html",
        "body": _craft_login_html(None),
    }
    _install(monkeypatch, transport)
    headers, body = _craft_root()
    found = CRAFT_CMS.run({}, _ctx(headers=headers, body=body))
    _assert_craft_passive(transport)
    assert [call[1] for call in transport.calls] == [CRAFT_LOGIN]
    assert len(found) == 1
    assert found[0]["severity"] == "info"
    assert found[0]["check"]["match"] == "craft-cms:unknown"
    assert "version not visible" in found[0]["title"]
    assert "4.18.9" in found[0]["title"]
    assert "5.11.2" in found[0]["title"]
    assert "CVE-2026-123488" in found[0]["title"]
    assert "exploited" in found[0]["title"].lower()
    assert "exploits" not in found[0]["evidence"].lower().replace("exploited", "")


@pytest.mark.parametrize("headers,body", [
    ({"x-powered-by": "Craft CMS"}, "<html><body>hi</body></html>"),
    (
        {"set-cookie": "CraftSessionId=abc; Path=/; HttpOnly"},
        "<html><body>hi</body></html>",
    ),
    (
        {"set-cookie": "CRAFT_CSRF_TOKEN=xyz; Path=/"},
        "<html><body>hi</body></html>",
    ),
    ({}, '<html><body><script src="/cpresources/hash/cp.js"></script></body></html>'),
])
def test_craft_cms_fingerprint_signals(monkeypatch, headers, body):
    transport = Transport()
    transport.routes[CRAFT_LOGIN] = {
        "status": 200,
        "content_type": "text/html",
        "body": _craft_login_html("5.11.1"),
    }
    _install(monkeypatch, transport)
    found = CRAFT_CMS.run({}, _ctx(headers=headers, body=body))
    assert transport.calls
    assert found and found[0]["severity"] == "critical"


def test_craft_cms_root_version_skips_login_get(monkeypatch):
    transport = Transport()
    transport.routes[CRAFT_LOGIN] = {
        "status": 200,
        "content_type": "text/html",
        "body": _craft_login_html("4.18.8"),
    }
    _install(monkeypatch, transport)
    found = CRAFT_CMS.run({}, _ctx(
        headers={"x-powered-by": "Craft CMS"},
        body='<meta name="generator" content="Craft CMS 4.18.8">',
    ))
    assert transport.calls == []
    assert found and found[0]["severity"] == "critical"
    assert found[0]["check"]["match"] == "craft-cms:4.18.8"
    assert "root response" in found[0]["evidence"]


def test_craft_cms_set_cookie_list_from_recon_root(monkeypatch):
    transport = Transport()
    transport.routes[CRAFT_LOGIN] = {
        "status": 200,
        "content_type": "text/html",
        "body": _craft_login_html(None),
    }
    _install(monkeypatch, transport)
    ctx = _ctx(body="<html><body>home</body></html>")
    ctx.recon_root["set_cookie"] = ["CraftSessionId=sess; Path=/"]
    found = CRAFT_CMS.run({}, ctx)
    assert [call[1] for call in transport.calls] == [CRAFT_LOGIN]
    assert found and found[0]["severity"] == "info"


def test_craft_cms_at_most_one_get_and_never_mutates(monkeypatch):
    transport = Transport()
    transport.routes[CRAFT_LOGIN] = {
        "status": 200,
        "content_type": "text/html",
        "body": _craft_login_html("5.11.1"),
    }
    transport.routes["/index.php"] = {"status": 200, "body": "nope"}
    transport.routes["/actions/users/login"] = {"status": 200, "body": "nope"}
    _install(monkeypatch, transport)
    headers, body = _craft_root(resources=True)
    found = CRAFT_CMS.run({}, _ctx(headers=headers, body=body))
    _assert_craft_passive(transport)
    assert [call[1] for call in transport.calls] == [CRAFT_LOGIN]
    assert found and found[0]["severity"] == "critical"


def test_craft_cms_no_request_url_contains_attribute(monkeypatch):
    transport = Transport()
    transport.routes[CRAFT_LOGIN] = {
        "status": 200,
        "content_type": "text/html",
        "body": _craft_login_html("4.18.8"),
    }
    _install(monkeypatch, transport)
    CRAFT_CMS.run({}, _ctx(headers={"x-powered-by": "Craft CMS"}))
    for _method, path, _session, _follow in transport.calls:
        assert "attribute" not in path.lower()
        assert "%5battribute%5d" not in path.lower()
        assert "[attribute]" not in path.lower()


def test_craft_cms_kill_switch_stops_before_first_request(monkeypatch):
    def opener(_req, timeout=None):
        raise AssertionError("kill switch did not stop the request")

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(
        target="http://127.0.0.1:8081/", actor="tester", run_id="run_craft_stop",
    )
    lease.stop()
    try:
        with control.scope(lease):
            with pytest.raises(control.ScanStopped):
                CRAFT_CMS.run({}, _ctx(headers={"x-powered-by": "Craft CMS"}))
    finally:
        control.release(lease.run_id)


def test_craft_cms_get_is_audited(monkeypatch):
    seen = {}

    def opener(req, timeout=None):
        seen["method"] = req.get_method()
        seen["url"] = req.full_url
        seen["calls"] = seen.get("calls", 0) + 1
        return _Resp(
            body=_craft_login_html("5.11.1").encode(),
            headers=[("content-type", "text/html")],
        )

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(
        target="http://127.0.0.1:8081/", actor="tester", run_id="run_craft_audit",
    )
    try:
        with control.scope(lease), control.agent("recon"):
            found = CRAFT_CMS.run({}, _ctx(headers={"x-powered-by": "Craft CMS"}))
    finally:
        control.release(lease.run_id)
    assert seen["calls"] == 1
    assert seen["method"] == "GET"
    assert CRAFT_LOGIN in seen["url"]
    assert "attribute" not in seen["url"].lower()
    assert found and found[0]["severity"] == "critical"
    import audit
    rows = [row for row in audit.recent(20) if row["kind"] == "request"]
    assert rows[-1]["action"] == "GET"
    assert rows[-1]["agent"] == "recon"
    assert "body" not in rows[-1]


def test_craft_cms_version_matrix_helper():
    from agents.cve_checks.craft_cms import affected

    assert affected((4, 18, 8)) is True
    assert affected((4, 18, 9)) is False
    assert affected((5, 11, 1)) is True
    assert affected((5, 11, 2)) is False
    assert affected((3, 9, 15)) is False
    assert affected((6, 0, 0)) is False


def test_craft_cms_check_source_is_get_only_static_fingerprint():
    text = (
        ROOT / "agents" / "cve_checks" / "craft_cms.py"
    ).read_text(encoding="utf-8")
    assert "fetch_path(ctx, LOGIN" in text
    assert text.count("fetch_path(") == 1
    assert "root_observation" in text
    assert "post_brotli" not in text
    assert "urlopen" not in text
    assert "http.client" not in text
    assert "craft.search" in text.lower()
    assert "[attribute]" in text
    assert CRAFT_CMS.agent == "recon"
    assert CRAFT_CMS.cve == "CVE-2026-123488"
    assert "4.18.9" in CRAFT_CMS.fixed
    assert "5.11.2" in CRAFT_CMS.fixed
    assert CRAFT_CMS.id == "craft-cms"


# --- wpForo Forum (CVE-2026-119155) ----------------------------------------

WPFORO_README = "/wp-content/plugins/wpforo/readme.txt"
_WPFORO_WP_ROOT = (
    '<meta name="generator" content="WordPress 6.8.1" />'
    '<link rel="https://api.w.org/" href="http://127.0.0.1:8081/wp-json/" />'
)
_WPFORO_BANNED = (
    "wpforo.nonces",
    "href[locale]",
    "href%5Blocale%5D",
    "wpforo_ajax",
    "admin-ajax.php",
    "admin-ajax",
    "/wp-admin",
    "SLEEP(",
    "BENCHMARK(",
    "locale=",
    "href=",
)


def _wpforo_asset_html(version: str | None = None) -> str:
    if version is None:
        return (
            f"{_WPFORO_WP_ROOT}"
            '<script src="/wp-content/plugins/wpforo/assets/js/frontend.js">'
            "</script>"
            '<link rel="stylesheet" href="/wp-content/plugins/wpforo/'
            'assets/css/frontend.css" />'
        )
    return (
        f"{_WPFORO_WP_ROOT}"
        f'<script src="/wp-content/plugins/wpforo/assets/js/frontend.js'
        f'?ver={version}"></script>'
        f'<link rel="stylesheet" href="/wp-content/plugins/wpforo/'
        f'assets/css/frontend.css?ver={version}" />'
    )


def _wpforo_readme(stable: str) -> str:
    return (
        "=== wpForo Forum ===\n"
        "Contributors: gvectors-team\n"
        f"Stable tag: {stable}\n"
        "Requires at least: 5.0\n"
        "\n"
        "wpForo is a full-featured WordPress forum plugin.\n"
    )


def _assert_wpforo_passive(transport):
    assert {call[0] for call in transport.calls} <= {"GET"}
    assert all(call[2] is None and call[3] is False for call in transport.calls)
    paths = [call[1] for call in transport.calls]
    blob = " ".join(paths)
    for banned in _WPFORO_BANNED:
        assert banned.lower() not in blob.lower()
    for path in paths:
        assert path == WPFORO_README
    assert paths.count(WPFORO_README) <= 1


@pytest.mark.parametrize("version,vulnerable", [
    ("3.2.2", True), ("3.2.1", True), ("3.1.0", True), ("2.9.0", True),
    ("3.2.3", False), ("3.2.4", False), ("3.3.0", False), ("4.0.0", False),
])
def test_wpforo_version_matrix(version, vulnerable):
    from agents.cve_checks.wpforo import affected
    from agents.cve_checks.versions import parse_dotted
    assert bool(affected(parse_dotted(version))) is vulnerable


def test_wpforo_no_wordpress_sends_nothing(monkeypatch):
    transport = Transport()
    transport.routes[WPFORO_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _wpforo_readme("3.2.2"),
    }
    _install(monkeypatch, transport)
    assert WPFORO.run(
        {}, _ctx(body="<html><body>hello static site</body></html>"),
    ) == []
    assert transport.calls == []


def test_wpforo_wordpress_without_plugin_sends_nothing(monkeypatch):
    transport = Transport()
    transport.routes[WPFORO_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _wpforo_readme("3.2.2"),
    }
    _install(monkeypatch, transport)
    assert WPFORO.run({}, _ctx(body=_WPFORO_WP_ROOT)) == []
    assert transport.calls == []


def test_wpforo_asset_ver_322_is_critical_and_passive(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    found = WPFORO.run({}, _ctx(body=_wpforo_asset_html("3.2.2")))
    assert transport.calls == []
    assert WPFORO.agent == "misconfig"
    assert len(found) == 1
    assert found[0]["severity"] == "critical"
    assert found[0]["check"]["match"] == "wpforo:3.2.2"
    assert UNCONFIRMED in found[0]["title"]
    assert "CVE-2026-119155" in found[0]["title"]
    assert "CVE-2026-119155" in found[0]["evidence"]
    assert "3.2.3" in found[0]["fix"]
    assert "Patchstack" in found[0]["evidence"]
    assert "Wordfence" in found[0]["evidence"]
    assert "not CISA KEV" in found[0]["evidence"]
    assert "wpforo.nonces" in found[0]["evidence"]
    assert "href[locale]" in found[0]["evidence"]
    assert "wordfence.com" in found[0]["evidence"]
    assert "wpdeeply.com" in found[0]["evidence"]
    assert "euvd.enisa.europa.eu" in found[0]["evidence"]
    assert "exploit" not in found[0]["title"].lower()
    assert "we exploit" not in found[0]["evidence"].lower()


def test_wpforo_323_and_324_are_not_flagged(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    assert WPFORO.run({}, _ctx(body=_wpforo_asset_html("3.2.3"))) == []
    assert WPFORO.run({}, _ctx(body=_wpforo_asset_html("3.2.4"))) == []
    assert transport.calls == []


def test_wpforo_plugin_present_no_version_one_get_then_info(monkeypatch):
    transport = Transport()
    transport.routes[WPFORO_README] = {
        "status": 404,
        "content_type": "text/plain",
        "body": "missing",
    }
    _install(monkeypatch, transport)
    found = WPFORO.run({}, _ctx(body=_wpforo_asset_html(None)))
    _assert_wpforo_passive(transport)
    assert [call[1] for call in transport.calls] == [WPFORO_README]
    assert len(found) == 1
    assert found[0]["severity"] == "info"
    assert found[0]["check"]["match"] == "wpforo:unknown"
    assert "CVE-2026-119155" in found[0]["title"]


def test_wpforo_readme_fallback_322_is_vulnerable(monkeypatch):
    transport = Transport()
    transport.routes[WPFORO_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _wpforo_readme("3.2.2"),
    }
    _install(monkeypatch, transport)
    found = WPFORO.run({}, _ctx(body=_wpforo_asset_html(None)))
    _assert_wpforo_passive(transport)
    assert [call[1] for call in transport.calls] == [WPFORO_README]
    assert found[0]["severity"] == "critical"
    assert found[0]["check"]["match"] == "wpforo:3.2.2"
    assert "CVE-2026-119155" in found[0]["evidence"]
    assert "3.2.3" in found[0]["fix"]
    assert "salts" in found[0]["fix"].lower() or "credentials" in found[0]["fix"].lower()


def test_wpforo_readme_fallback_323_and_324_are_none(monkeypatch):
    transport = Transport()
    for fixed in ("3.2.3", "3.2.4"):
        transport.routes[WPFORO_README] = {
            "status": 200,
            "content_type": "text/plain",
            "body": _wpforo_readme(fixed),
        }
        _install(monkeypatch, transport)
        assert WPFORO.run({}, _ctx(body=_wpforo_asset_html(None))) == []
        _assert_wpforo_passive(transport)
        transport.calls.clear()


def test_wpforo_at_most_one_readme_get_and_never_forbidden_paths(monkeypatch):
    transport = Transport()
    transport.routes[WPFORO_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _wpforo_readme("3.2.2"),
    }
    transport.routes["/wp-admin/admin-ajax.php"] = {
        "status": 200, "body": "should-never-be-fetched",
    }
    transport.routes["/wp-admin/admin-ajax.php?action=wpforo_ajax"] = {
        "status": 200, "body": "should-never-be-fetched",
    }
    _install(monkeypatch, transport)
    found = WPFORO.run({}, _ctx(body=_wpforo_asset_html(None)))
    _assert_wpforo_passive(transport)
    assert [call[1] for call in transport.calls] == [WPFORO_README]
    assert all(call[0] == "GET" for call in transport.calls)
    assert found and found[0]["severity"] == "critical"
    blob = " ".join(call[1] for call in transport.calls).lower()
    assert "admin-ajax" not in blob
    assert "wpforo.nonces" not in blob
    assert "href[locale]" not in blob
    assert "locale" not in blob
    assert "wp-admin" not in blob


def test_wpforo_kill_switch_before_first_request_is_none(monkeypatch):
    def opener(_req, timeout=None):
        raise AssertionError("kill switch did not stop the request")

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(
        target="http://127.0.0.1:8081/", actor="tester", run_id="run_wpforo_stop",
    )
    lease.stop()
    try:
        with control.scope(lease):
            with pytest.raises(control.ScanStopped):
                WPFORO.run({}, _ctx(body=_wpforo_asset_html(None)))
    finally:
        control.release(lease.run_id)


def test_wpforo_requests_are_get_audited_and_have_no_body(monkeypatch):
    seen = {"calls": 0, "methods": [], "data": []}

    def opener(req, timeout=None):
        seen["calls"] += 1
        seen["methods"].append(req.get_method())
        seen["data"].append(req.data)
        return _Resp(
            body=_wpforo_readme("3.2.2").encode(),
            headers=[("content-type", "text/plain")],
        )

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(
        target="http://127.0.0.1:8081/", actor="tester", run_id="run_wpforo_audit",
    )
    try:
        with control.scope(lease), control.agent("misconfig"):
            found = WPFORO.run({}, _ctx(body=_wpforo_asset_html(None)))
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
    assert WPFORO_README in rows[-1]["url"]
    assert "body" not in rows[-1]


def test_wpforo_non_allowlisted_host_is_refused():
    with pytest.raises(main.ScopeError) as exc:
        main.allowlisted_host(
            "https://wpforo.attacker.example/wp-content/plugins/wpforo/"
            "readme.txt"
        )
    assert "allowlist" in str(exc.value)


def test_wpforo_check_source_is_get_only_static_fingerprint():
    text = (
        ROOT / "agents" / "cve_checks" / "wpforo.py"
    ).read_text(encoding="utf-8")
    assert "fetch_path(ctx, README" in text
    assert text.count("fetch_path(") == 1
    assert "root_observation" in text
    assert "looks_like_wordpress" in text
    assert "post_brotli" not in text
    assert "urlopen" not in text
    assert "http.client" not in text
    assert "wpforo.nonces" in text
    assert "href[locale]" in text or "href" in text.lower()
    assert "Never" in text or "never" in text
    assert WPFORO.agent == "misconfig"
    assert WPFORO.cve == "CVE-2026-119155"
    assert "3.2.3" in WPFORO.fixed
    assert WPFORO.id == "wpforo"


# --- Ninja Forms File Uploads (CVE-2026-126537) -----------------------------

NFU_CHANGELOG = "/wp-content/plugins/ninja-forms-uploads/changelog.txt"
_NFU_WP_ROOT = (
    '<meta name="generator" content="WordPress 6.8.1" />'
    '<link rel="https://api.w.org/" href="http://127.0.0.1:8081/wp-json/" />'
)
_NFU_BANNED = (
    "saveProgress",
    "file_path",
    "nf_ajax_submit",
    "admin-ajax.php",
    "admin-ajax",
    "/wp-admin",
    "files[].data",
)


def _nfu_asset_html(version: str | None = None) -> str:
    if version is None:
        return (
            f"{_NFU_WP_ROOT}"
            '<script src="/wp-content/plugins/ninja-forms-uploads/assets/'
            'js/front-end.js"></script>'
            '<link rel="stylesheet" href="/wp-content/plugins/'
            'ninja-forms-uploads/assets/css/display-front.css" />'
        )
    return (
        f"{_NFU_WP_ROOT}"
        f'<script src="/wp-content/plugins/ninja-forms-uploads/assets/'
        f'js/front-end.js?ver={version}"></script>'
        f'<link rel="stylesheet" href="/wp-content/plugins/'
        f'ninja-forms-uploads/assets/css/display-front.css?ver={version}" />'
    )


def _nfu_changelog(version: str) -> str:
    return (
        f"#### {version} (2 November 2026)\n"
        "\n"
        "Security Enhancements:\n"
        "\n"
        "- harden handling of uploaded file data during form submission\n"
        "- bind stored uploads to their form and field in merge tags\n"
        "\n"
        "Bug Fixes:\n"
        "\n"
        "- fix Ninja Forms File Uploads merge tags for NF_FU fields\n"
    )


def _assert_nfu_passive(transport):
    assert {call[0] for call in transport.calls} <= {"GET"}
    assert all(call[2] is None and call[3] is False for call in transport.calls)
    paths = [call[1] for call in transport.calls]
    blob = " ".join(paths)
    for banned in _NFU_BANNED:
        assert banned.lower() not in blob.lower()
    for path in paths:
        assert path == NFU_CHANGELOG
    assert paths.count(NFU_CHANGELOG) <= 1


@pytest.mark.parametrize("version,vulnerable", [
    ("3.3.36", True), ("3.3.35", True), ("3.3.0", True), ("3.2.0", True),
    ("3.3.37", False), ("3.3.38", False), ("3.4.0", False), ("4.0.0", False),
])
def test_ninja_forms_uploads_version_matrix(version, vulnerable):
    from agents.cve_checks.ninja_forms_uploads import affected
    from agents.cve_checks.versions import parse_dotted
    assert bool(affected(parse_dotted(version))) is vulnerable


def test_ninja_forms_uploads_no_wordpress_sends_nothing(monkeypatch):
    transport = Transport()
    transport.routes[NFU_CHANGELOG] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _nfu_changelog("3.3.36"),
    }
    _install(monkeypatch, transport)
    assert NINJA_FORMS_UPLOADS.run(
        {}, _ctx(body="<html><body>hello static site</body></html>"),
    ) == []
    assert transport.calls == []


def test_ninja_forms_uploads_wordpress_without_plugin_sends_nothing(monkeypatch):
    transport = Transport()
    transport.routes[NFU_CHANGELOG] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _nfu_changelog("3.3.36"),
    }
    _install(monkeypatch, transport)
    assert NINJA_FORMS_UPLOADS.run({}, _ctx(body=_NFU_WP_ROOT)) == []
    assert transport.calls == []


def test_ninja_forms_uploads_asset_ver_336_is_critical_and_passive(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    found = NINJA_FORMS_UPLOADS.run({}, _ctx(body=_nfu_asset_html("3.3.36")))
    assert transport.calls == []
    assert NINJA_FORMS_UPLOADS.agent == "misconfig"
    assert len(found) == 1
    assert found[0]["severity"] == "critical"
    assert found[0]["check"]["match"] == "ninja-forms-uploads:3.3.36"
    assert UNCONFIRMED in found[0]["title"]
    assert "CVE-2026-126537" in found[0]["title"]
    assert "CVE-2026-126537" in found[0]["evidence"]
    assert "3.3.37" in found[0]["fix"]
    assert "license-gated" in found[0]["fix"]
    assert "wp-config.php" in found[0]["fix"]
    assert "Rapid7" in found[0]["evidence"]
    assert "VulnCheck" in found[0]["evidence"]
    assert "saveProgress" not in " ".join(call[1] for call in transport.calls)
    assert "exploit" not in found[0]["title"].lower()
    assert "we exploit" not in found[0]["evidence"].lower()


def test_ninja_forms_uploads_337_is_not_flagged(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    assert NINJA_FORMS_UPLOADS.run({}, _ctx(body=_nfu_asset_html("3.3.37"))) == []
    assert transport.calls == []


def test_ninja_forms_uploads_plugin_present_no_version_one_get_then_info(
    monkeypatch,
):
    transport = Transport()
    transport.routes[NFU_CHANGELOG] = {
        "status": 404,
        "content_type": "text/plain",
        "body": "missing",
    }
    _install(monkeypatch, transport)
    found = NINJA_FORMS_UPLOADS.run({}, _ctx(body=_nfu_asset_html(None)))
    _assert_nfu_passive(transport)
    assert [call[1] for call in transport.calls] == [NFU_CHANGELOG]
    assert len(found) == 1
    assert found[0]["severity"] == "info"
    assert found[0]["check"]["match"] == "ninja-forms-uploads:unknown"
    assert "CVE-2026-126537" in found[0]["title"]


def test_ninja_forms_uploads_changelog_fallback_336_is_vulnerable(monkeypatch):
    transport = Transport()
    transport.routes[NFU_CHANGELOG] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _nfu_changelog("3.3.36"),
    }
    _install(monkeypatch, transport)
    found = NINJA_FORMS_UPLOADS.run({}, _ctx(body=_nfu_asset_html(None)))
    _assert_nfu_passive(transport)
    assert [call[1] for call in transport.calls] == [NFU_CHANGELOG]
    assert found[0]["severity"] == "critical"
    assert found[0]["check"]["match"] == "ninja-forms-uploads:3.3.36"
    assert "CVE-2026-126537" in found[0]["evidence"]
    assert "3.3.37" in found[0]["fix"]


def test_ninja_forms_uploads_changelog_fallback_337_is_none(monkeypatch):
    transport = Transport()
    transport.routes[NFU_CHANGELOG] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _nfu_changelog("3.3.37"),
    }
    _install(monkeypatch, transport)
    assert NINJA_FORMS_UPLOADS.run({}, _ctx(body=_nfu_asset_html(None))) == []
    _assert_nfu_passive(transport)


def test_ninja_forms_uploads_at_most_one_changelog_get_and_never_form_endpoints(
    monkeypatch,
):
    transport = Transport()
    transport.routes[NFU_CHANGELOG] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _nfu_changelog("3.3.36"),
    }
    transport.routes["/wp-admin/admin-ajax.php"] = {
        "status": 200, "body": "should-never-be-fetched",
    }
    transport.routes["/wp-admin/admin-ajax.php?action=nf_ajax_submit"] = {
        "status": 200, "body": "should-never-be-fetched",
    }
    _install(monkeypatch, transport)
    found = NINJA_FORMS_UPLOADS.run({}, _ctx(body=_nfu_asset_html(None)))
    _assert_nfu_passive(transport)
    assert [call[1] for call in transport.calls] == [NFU_CHANGELOG]
    assert all(call[0] == "GET" for call in transport.calls)
    assert found and found[0]["severity"] == "critical"
    blob = " ".join(call[1] for call in transport.calls).lower()
    assert "admin-ajax" not in blob
    assert "nf_ajax_submit" not in blob
    assert "saveprogress" not in blob
    assert "file_path" not in blob
    assert "wp-admin" not in blob


def test_ninja_forms_uploads_kill_switch_before_first_request_is_none(monkeypatch):
    def opener(_req, timeout=None):
        raise AssertionError("kill switch did not stop the request")

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(
        target="http://127.0.0.1:8081/", actor="tester", run_id="run_nfu_stop",
    )
    lease.stop()
    try:
        with control.scope(lease):
            with pytest.raises(control.ScanStopped):
                NINJA_FORMS_UPLOADS.run({}, _ctx(body=_nfu_asset_html(None)))
    finally:
        control.release(lease.run_id)


def test_ninja_forms_uploads_requests_are_get_audited_and_have_no_body(monkeypatch):
    seen = {"calls": 0, "methods": [], "data": []}

    def opener(req, timeout=None):
        seen["calls"] += 1
        seen["methods"].append(req.get_method())
        seen["data"].append(req.data)
        return _Resp(
            body=_nfu_changelog("3.3.36").encode(),
            headers=[("content-type", "text/plain")],
        )

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(
        target="http://127.0.0.1:8081/", actor="tester", run_id="run_nfu_audit",
    )
    try:
        with control.scope(lease), control.agent("misconfig"):
            found = NINJA_FORMS_UPLOADS.run({}, _ctx(body=_nfu_asset_html(None)))
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
    assert NFU_CHANGELOG in rows[-1]["url"]
    assert "body" not in rows[-1]


def test_ninja_forms_uploads_non_allowlisted_host_is_refused():
    with pytest.raises(main.ScopeError) as exc:
        main.allowlisted_host(
            "https://nfu.attacker.example/wp-content/plugins/"
            "ninja-forms-uploads/changelog.txt"
        )
    assert "allowlist" in str(exc.value)


def test_ninja_forms_uploads_check_source_is_get_only_static_fingerprint():
    text = (
        ROOT / "agents" / "cve_checks" / "ninja_forms_uploads.py"
    ).read_text(encoding="utf-8")
    assert "fetch_path(ctx, CHANGELOG" in text
    assert text.count("fetch_path(") == 1
    assert "root_observation" in text
    assert "looks_like_wordpress" in text
    assert "changelog.txt" in text
    assert "readme.txt" in text  # documents why changelog was chosen over readme
    assert "post_brotli" not in text
    assert "urlopen" not in text
    assert "http.client" not in text
    assert "saveProgress" in text
    assert "nf_ajax_submit" in text
    assert "file_path" in text
    assert "Never submits" in text or "never submits" in text.lower()
    assert NINJA_FORMS_UPLOADS.agent == "misconfig"
    assert NINJA_FORMS_UPLOADS.cve == "CVE-2026-126537"
    assert NINJA_FORMS_UPLOADS.id == "ninja-forms-uploads"
    assert "3.3.37" in NINJA_FORMS_UPLOADS.fixed


# --- AI Engine (CVE-2026-123478 + CVE-2026-125804) ------------------------

AI_ENGINE_README = "/wp-content/plugins/ai-engine/readme.txt"
_AI_ENGINE_WP_ROOT = (
    '<meta name="generator" content="WordPress 6.8.1" />'
    '<link rel="https://api.w.org/" href="http://127.0.0.1:8081/wp-json/" />'
)
_AI_ENGINE_BANNED = (
    "wp-json/mwai",
    "/wp-json/mwai/",
    "mwai/",
    "/mwai-ui/",
    "mwai-ui",
    "mcp",
    "admin-ajax.php",
    "/wp-admin",
    "<script",
    "chatbot",
)


def _ai_engine_asset_html(version: str | None = None) -> str:
    if version is None:
        return (
            f"{_AI_ENGINE_WP_ROOT}"
            '<script src="/wp-content/plugins/ai-engine/app/index.js">'
            "</script>"
            '<link rel="stylesheet" href="/wp-content/plugins/ai-engine/'
            'app/index.css" />'
        )
    return (
        f"{_AI_ENGINE_WP_ROOT}"
        f'<script src="/wp-content/plugins/ai-engine/app/index.js'
        f'?ver={version}"></script>'
        f'<link rel="stylesheet" href="/wp-content/plugins/ai-engine/'
        f'app/index.css?ver={version}" />'
    )


def _ai_engine_readme(stable: str) -> str:
    return (
        "=== AI Engine ===\n"
        f"Stable tag: {stable}\n"
        "Contributors: tigroumeow\n"
        "Requires at least: 5.0\n\n"
        "AI Engine – MCP Server & AI Chatbot by Meow Apps.\n"
    )


def _assert_ai_engine_passive(transport):
    assert {call[0] for call in transport.calls} <= {"GET"}
    assert all(call[2] is None and call[3] is False for call in transport.calls)
    paths = [call[1] for call in transport.calls]
    blob = " ".join(paths)
    for banned in _AI_ENGINE_BANNED:
        assert banned.lower() not in blob.lower()
    for path in paths:
        assert path == AI_ENGINE_README
        assert "wp-json/mwai" not in path.lower()
        assert "/mwai-ui/" not in path.lower()
        assert "mcp" not in path.lower()
    assert paths.count(AI_ENGINE_README) <= 1


@pytest.mark.parametrize("version,vulnerable", [
    ("3.9.1", True), ("3.9.0", True), ("3.8.0", True), ("3.0.0", True),
    ("3.9.2", False), ("3.9.3", False), ("3.10.0", False), ("4.0.0", False),
])
def test_ai_engine_version_matrix(version, vulnerable):
    from agents.cve_checks.ai_engine import affected
    from agents.cve_checks.versions import parse_dotted
    assert bool(affected(parse_dotted(version))) is vulnerable


@pytest.mark.parametrize("version,vulnerable", [
    ("3.9.3", True), ("3.9.2", True), ("3.9.1", True), ("3.8.0", True),
    ("3.9.4", False), ("3.10.0", False), ("4.0.0", False),
])
def test_ai_engine_upload_version_matrix(version, vulnerable):
    from agents.cve_checks.ai_engine_upload import affected
    from agents.cve_checks.versions import parse_dotted
    assert bool(affected(parse_dotted(version))) is vulnerable


def test_ai_engine_no_wordpress_sends_nothing(monkeypatch):
    transport = Transport()
    transport.routes[AI_ENGINE_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _ai_engine_readme("3.9.1"),
    }
    _install(monkeypatch, transport)
    ctx = _ctx(body="<html><body>hello static site</body></html>")
    assert AI_ENGINE.run({}, ctx) == []
    assert AI_ENGINE_UPLOAD.run({}, ctx) == []
    assert transport.calls == []


def test_ai_engine_wordpress_without_plugin_sends_nothing(monkeypatch):
    transport = Transport()
    transport.routes[AI_ENGINE_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _ai_engine_readme("3.9.1"),
    }
    transport.routes["/wp-json/mwai/v1/simpleChatbotQuery"] = {
        "status": 200, "body": "should-never-be-fetched",
    }
    transport.routes["/mwai-ui/v1/files/upload"] = {
        "status": 200, "body": "should-never-be-fetched",
    }
    _install(monkeypatch, transport)
    ctx = _ctx(body=_AI_ENGINE_WP_ROOT)
    assert AI_ENGINE.run({}, ctx) == []
    assert AI_ENGINE_UPLOAD.run({}, ctx) == []
    assert transport.calls == []


def test_ai_engine_asset_ver_391_is_high_and_passive(monkeypatch):
    # 3.9.1 is under both floors: CVE-2026-123478 and CVE-2026-125804.
    transport = Transport()
    _install(monkeypatch, transport)
    ctx = _ctx(body=_ai_engine_asset_html("3.9.1"))
    found = AI_ENGINE.run({}, ctx)
    upload = AI_ENGINE_UPLOAD.run({}, ctx)
    assert transport.calls == []
    assert AI_ENGINE.agent == "misconfig"
    assert len(found) == 1
    assert found[0]["severity"] == "high"
    assert found[0]["check"]["match"] == "ai-engine:3.9.1"
    assert UNCONFIRMED in found[0]["title"]
    assert "CVE-2026-123478" in found[0]["title"]
    assert "CVE-2026-123478" in found[0]["evidence"]
    assert "3.9.2" in found[0]["fix"]
    assert "chatbot" in found[0]["fix"].lower()
    assert "admin" in found[0]["fix"].lower()
    assert "CVSS 7.1" in found[0]["evidence"]
    assert "VulnCheck" in found[0]["evidence"]
    assert "wordsec.net" in found[0]["evidence"]
    assert "laskyr.com" in found[0]["evidence"]
    assert "vexday.io" in found[0]["evidence"]
    assert "exploit" not in found[0]["title"].lower()
    assert "we exploit" not in found[0]["evidence"].lower()
    assert len(upload) == 1
    assert upload[0]["severity"] == "high"
    assert upload[0]["check"]["match"] == "ai-engine-upload:3.9.1"
    assert "CVE-2026-125804" in upload[0]["title"]
    assert "3.9.4" in upload[0]["fix"]
    assert "3.9.2" in upload[0]["fix"] and "3.9.3" in upload[0]["fix"]
    assert "not enough" in upload[0]["fix"].lower()


def test_ai_engine_392_is_not_flagged(monkeypatch):
    # CVE-2026-123478 is fixed in 3.9.2, but CVE-2026-125804 still affects
    # 3.9.2/3.9.3 — raise the floor to 3.9.4 for the upload XSS sibling.
    transport = Transport()
    _install(monkeypatch, transport)
    ctx = _ctx(body=_ai_engine_asset_html("3.9.2"))
    assert AI_ENGINE.run({}, ctx) == []
    found = AI_ENGINE_UPLOAD.run({}, ctx)
    assert transport.calls == []
    assert len(found) == 1
    assert found[0]["severity"] == "high"
    assert "CVE-2026-125804" in found[0]["title"]
    assert found[0]["check"]["match"] == "ai-engine-upload:3.9.2"
    assert "3.9.4" in found[0]["fix"]
    assert "not enough" in found[0]["fix"].lower()


def test_ai_engine_393_reports_125804_only(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    ctx = _ctx(body=_ai_engine_asset_html("3.9.3"))
    assert AI_ENGINE.run({}, ctx) == []
    found = AI_ENGINE_UPLOAD.run({}, ctx)
    assert transport.calls == []
    assert len(found) == 1
    assert found[0]["severity"] == "high"
    assert "CVE-2026-125804" in found[0]["title"]
    assert found[0]["check"]["match"] == "ai-engine-upload:3.9.3"
    assert "3.9.4" in found[0]["fix"]
    assert "mwai-ui" in found[0]["evidence"].lower()
    assert "Patchstack" in found[0]["evidence"] or "patchstack" in found[0]["evidence"].lower()
    assert "exploit" not in found[0]["title"].lower()
    assert "we exploit" not in found[0]["evidence"].lower()


def test_ai_engine_394_reports_none(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    ctx = _ctx(body=_ai_engine_asset_html("3.9.4"))
    assert AI_ENGINE.run({}, ctx) == []
    assert AI_ENGINE_UPLOAD.run({}, ctx) == []
    assert transport.calls == []


def test_ai_engine_plugin_present_no_version_one_get_then_info(monkeypatch):
    transport = Transport()
    transport.routes[AI_ENGINE_README] = {
        "status": 404,
        "content_type": "text/plain",
        "body": "missing",
    }
    _install(monkeypatch, transport)
    found = AI_ENGINE.run({}, _ctx(body=_ai_engine_asset_html(None)))
    _assert_ai_engine_passive(transport)
    assert [call[1] for call in transport.calls] == [AI_ENGINE_README]
    assert len(found) == 1
    assert found[0]["severity"] == "info"
    assert found[0]["check"]["match"] == "ai-engine:unknown"
    assert "CVE-2026-123478" in found[0]["title"]


def test_ai_engine_readme_fallback_391_is_vulnerable(monkeypatch):
    # 3.9.1 via shared readme: both CVEs, readme fetched at most once.
    transport = Transport()
    transport.routes[AI_ENGINE_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _ai_engine_readme("3.9.1"),
    }
    _install(monkeypatch, transport)
    ctx = _ctx(body=_ai_engine_asset_html(None))
    found = AI_ENGINE.run({}, ctx)
    upload = AI_ENGINE_UPLOAD.run({}, ctx)
    _assert_ai_engine_passive(transport)
    assert [call[1] for call in transport.calls] == [AI_ENGINE_README]
    assert [call[1] for call in transport.calls].count(AI_ENGINE_README) == 1
    assert found[0]["severity"] == "high"
    assert found[0]["check"]["match"] == "ai-engine:3.9.1"
    assert "CVE-2026-123478" in found[0]["evidence"]
    assert "3.9.2" in found[0]["fix"]
    assert upload[0]["severity"] == "high"
    assert upload[0]["check"]["match"] == "ai-engine-upload:3.9.1"
    assert "CVE-2026-125804" in upload[0]["evidence"]
    assert "3.9.4" in upload[0]["fix"]


def test_ai_engine_readme_fallback_392_is_none(monkeypatch):
    # Previously asserted 3.9.2 was fully clean for AI Engine. CVE-2026-123478
    # remains clean at 3.9.2; CVE-2026-125804 still flags through 3.9.3.
    transport = Transport()
    transport.routes[AI_ENGINE_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _ai_engine_readme("3.9.2"),
    }
    _install(monkeypatch, transport)
    ctx = _ctx(body=_ai_engine_asset_html(None))
    assert AI_ENGINE.run({}, ctx) == []
    found = AI_ENGINE_UPLOAD.run({}, ctx)
    _assert_ai_engine_passive(transport)
    assert [call[1] for call in transport.calls].count(AI_ENGINE_README) == 1
    assert found and found[0]["severity"] == "high"
    assert "CVE-2026-125804" in found[0]["title"]
    assert "3.9.4" in found[0]["fix"]
    assert "not enough" in found[0]["fix"].lower()


def test_ai_engine_both_cves_share_one_readme_get(monkeypatch):
    transport = Transport()
    transport.routes[AI_ENGINE_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _ai_engine_readme("3.9.1"),
    }
    transport.routes["/wp-json/mwai/v1/simpleChatbotQuery"] = {
        "status": 200, "body": "should-never-be-fetched",
    }
    transport.routes["/mwai-ui/v1/files/upload"] = {
        "status": 200, "body": "should-never-be-fetched",
    }
    _install(monkeypatch, transport)
    ctx = _ctx(body=_ai_engine_asset_html(None))
    first = AI_ENGINE.run({}, ctx)
    second = AI_ENGINE_UPLOAD.run({}, ctx)
    _assert_ai_engine_passive(transport)
    assert [call[1] for call in transport.calls] == [AI_ENGINE_README]
    assert [call[1] for call in transport.calls].count(AI_ENGINE_README) == 1
    assert first and first[0]["severity"] == "high"
    assert "CVE-2026-123478" in first[0]["evidence"]
    assert second and second[0]["severity"] == "high"
    assert "CVE-2026-125804" in second[0]["evidence"]
    blob = " ".join(call[1] for call in transport.calls).lower()
    assert "wp-json/mwai" not in blob
    assert "/mwai-ui/" not in blob
    assert "mcp" not in blob


def test_ai_engine_at_most_one_readme_get_and_never_mwai_or_mcp(monkeypatch):
    transport = Transport()
    transport.routes[AI_ENGINE_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _ai_engine_readme("3.9.1"),
    }
    transport.routes["/wp-json/mwai/v1/simpleChatbotQuery"] = {
        "status": 200, "body": "should-never-be-fetched",
    }
    transport.routes["/wp-json/mwai/v1/mcp"] = {
        "status": 200, "body": "should-never-be-fetched",
    }
    transport.routes["/mwai-ui/v1/files/upload"] = {
        "status": 200, "body": "should-never-be-fetched",
    }
    transport.routes["/mcp"] = {
        "status": 200, "body": "should-never-be-fetched",
    }
    _install(monkeypatch, transport)
    ctx = _ctx(body=_ai_engine_asset_html(None))
    found = AI_ENGINE.run({}, ctx)
    upload = AI_ENGINE_UPLOAD.run({}, ctx)
    _assert_ai_engine_passive(transport)
    assert [call[1] for call in transport.calls] == [AI_ENGINE_README]
    assert all(call[0] == "GET" for call in transport.calls)
    assert found and found[0]["severity"] == "high"
    assert upload and upload[0]["severity"] == "high"
    blob = " ".join(call[1] for call in transport.calls).lower()
    assert "wp-json/mwai" not in blob
    assert "/mwai-ui/" not in blob
    assert "mcp" not in blob
    assert "chatbot" not in blob
    assert "<script" not in blob


def test_ai_engine_kill_switch_before_first_request_is_none(monkeypatch):
    def opener(_req, timeout=None):
        raise AssertionError("kill switch did not stop the request")

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(
        target="http://127.0.0.1:8081/", actor="tester", run_id="run_ai_engine_stop",
    )
    lease.stop()
    try:
        with control.scope(lease):
            with pytest.raises(control.ScanStopped):
                AI_ENGINE.run({}, _ctx(body=_ai_engine_asset_html(None)))
    finally:
        control.release(lease.run_id)


def test_ai_engine_upload_kill_switch_before_first_request_is_none(monkeypatch):
    def opener(_req, timeout=None):
        raise AssertionError("kill switch did not stop the request")

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(
        target="http://127.0.0.1:8081/", actor="tester",
        run_id="run_ai_engine_upload_stop",
    )
    lease.stop()
    try:
        with control.scope(lease):
            with pytest.raises(control.ScanStopped):
                AI_ENGINE_UPLOAD.run({}, _ctx(body=_ai_engine_asset_html(None)))
    finally:
        control.release(lease.run_id)


def test_ai_engine_requests_are_get_audited_and_have_no_body(monkeypatch):
    seen = {"calls": 0, "methods": [], "data": []}

    def opener(req, timeout=None):
        seen["calls"] += 1
        seen["methods"].append(req.get_method())
        seen["data"].append(req.data)
        return _Resp(
            body=_ai_engine_readme("3.9.1").encode(),
            headers=[("content-type", "text/plain")],
        )

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(
        target="http://127.0.0.1:8081/", actor="tester", run_id="run_ai_engine_audit",
    )
    try:
        with control.scope(lease), control.agent("misconfig"):
            found = AI_ENGINE.run({}, _ctx(body=_ai_engine_asset_html(None)))
    finally:
        control.release(lease.run_id)
    assert seen["calls"] == 1
    assert seen["methods"] == ["GET"]
    assert seen["data"] == [None]
    assert found and found[0]["severity"] == "high"
    import audit
    rows = [row for row in audit.recent(20) if row["kind"] == "request"]
    assert rows
    assert rows[-1]["action"] == "GET"
    assert rows[-1]["agent"] == "misconfig"
    assert AI_ENGINE_README in rows[-1]["url"]
    assert "body" not in rows[-1]
    assert "wp-json/mwai" not in rows[-1]["url"].lower()
    assert "/mwai-ui/" not in rows[-1]["url"].lower()
    assert "mcp" not in rows[-1]["url"].lower()


def test_ai_engine_non_allowlisted_host_is_refused():
    with pytest.raises(main.ScopeError) as exc:
        main.allowlisted_host(
            "https://ai-engine.attacker.example/wp-content/plugins/ai-engine/"
            "readme.txt"
        )
    assert "allowlist" in str(exc.value)


def test_ai_engine_check_source_is_get_only_static_fingerprint():
    text = (
        ROOT / "agents" / "cve_checks" / "ai_engine.py"
    ).read_text(encoding="utf-8")
    assert "fetch_path(ctx, README" in text
    assert text.count("fetch_path(") == 1
    assert "root_observation" in text
    assert "looks_like_wordpress" in text
    assert "resolve_plugin_version" in text
    assert "post_brotli" not in text
    assert "urlopen" not in text
    assert "http.client" not in text
    assert "wp-json/mwai" in text.lower()
    assert "/mwai-ui/" in text.lower()
    assert "Never sends chatbot" in text or "never sends chatbot" in text.lower()
    assert AI_ENGINE.agent == "misconfig"
    assert AI_ENGINE.cve == "CVE-2026-123478"
    assert AI_ENGINE.id == "ai-engine"
    assert "3.9.2" in AI_ENGINE.fixed


def test_ai_engine_upload_check_source_reuses_helpers_no_upload():
    text = (
        ROOT / "agents" / "cve_checks" / "ai_engine_upload.py"
    ).read_text(encoding="utf-8")
    assert "fetch_path" not in text
    assert "resolve_plugin_version" in text
    assert "urlopen" not in text
    assert "http.client" not in text
    assert "/mwai-ui/" in text.lower()
    assert "wp-json/mwai" in text.lower()
    assert "Never sends chatbot" in text or "never sends chatbot" in text.lower()
    assert AI_ENGINE_UPLOAD.agent == "misconfig"
    assert AI_ENGINE_UPLOAD.cve == "CVE-2026-125804"
    assert AI_ENGINE_UPLOAD.id == "ai-engine-upload"
    assert "3.9.4" in AI_ENGINE_UPLOAD.fixed
    assert "3.9.2" in AI_ENGINE_UPLOAD.fixed or "3.9.3" in AI_ENGINE_UPLOAD.fixed


def test_ai_engine_upload_soft404_readme_is_none(monkeypatch):
    transport = Transport()
    transport.routes[AI_ENGINE_README] = {
        "status": 200,
        "content_type": "text/html",
        "body": (
            "<!DOCTYPE html><html><head><title>Home</title></head>"
            "<body>catch-all soft 404 page</body></html>"
        ),
    }
    _install(monkeypatch, transport)
    ctx = _ctx(body=_ai_engine_asset_html(None))
    assert AI_ENGINE.run({}, ctx)[0]["severity"] == "info"
    assert AI_ENGINE_UPLOAD.run({}, ctx)[0]["severity"] == "info"
    _assert_ai_engine_passive(transport)
    assert [call[1] for call in transport.calls].count(AI_ENGINE_README) == 1


def test_ai_engine_upload_no_wordpress_sends_nothing(monkeypatch):
    transport = Transport()
    transport.routes[AI_ENGINE_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _ai_engine_readme("3.9.3"),
    }
    _install(monkeypatch, transport)
    assert AI_ENGINE_UPLOAD.run(
        {}, _ctx(body="<html><body>hello static site</body></html>"),
    ) == []
    assert transport.calls == []


def test_ai_engine_upload_plugin_present_no_version_one_get_then_info(monkeypatch):
    transport = Transport()
    transport.routes[AI_ENGINE_README] = {
        "status": 404,
        "content_type": "text/plain",
        "body": "missing",
    }
    _install(monkeypatch, transport)
    found = AI_ENGINE_UPLOAD.run({}, _ctx(body=_ai_engine_asset_html(None)))
    _assert_ai_engine_passive(transport)
    assert [call[1] for call in transport.calls] == [AI_ENGINE_README]
    assert len(found) == 1
    assert found[0]["severity"] == "info"
    assert found[0]["check"]["match"] == "ai-engine-upload:unknown"
    assert "CVE-2026-125804" in found[0]["title"]

# --- Bricksforge (CVE-2026-85097) ----------------------------------------

BF_README = "/wp-content/plugins/bricksforge/readme.txt"
BF_CHANGELOG = "/wp-content/plugins/bricksforge/changelog.txt"
_BF_WP_ROOT = (
    '<meta name="generator" content="WordPress 6.8.1" />'
    '<link rel="https://api.w.org/" href="http://127.0.0.1:8081/wp-json/" />'
)
_BF_BANNED = (
    "wp-json/bricksforge",
    "/wp-json/bricksforge/v1/form_submit",
    "bricksforge_regenerate_nonce",
    "bricksforge_form_submit",
    "temporaryFileUploads",
    "/wp-content/uploads/bricksforge/tmp/",
    "bricksforge/tmp",
    "admin-ajax.php",
    "admin-ajax",
    "/wp-admin",
)


def _bf_asset_html(version: str | None = None) -> str:
    if version is None:
        return (
            f"{_BF_WP_ROOT}"
            '<script src="/wp-content/plugins/bricksforge/assets/js/app.js">'
            "</script>"
            '<link rel="stylesheet" href="/wp-content/plugins/bricksforge/'
            'assets/css/app.css" />'
        )
    return (
        f"{_BF_WP_ROOT}"
        f'<script src="/wp-content/plugins/bricksforge/assets/js/app.js'
        f'?ver={version}"></script>'
        f'<link rel="stylesheet" href="/wp-content/plugins/bricksforge/'
        f'assets/css/app.css?ver={version}" />'
    )


def _bf_readme(stable: str | None) -> str:
    lines = [
        "=== Bricksforge ===",
        "Contributors: bricksforge",
        "Requires at least: 5.0",
        "Tested up to: 6.8",
    ]
    if stable is not None:
        lines.append(f"Stable tag: {stable}")
    lines.extend(
        [
            "",
            "Bricksforge – One Plugin. Countless Possibilities.",
            "",
            "== Changelog ==",
            "",
        ]
    )
    if stable is not None:
        lines.extend([f"= {stable} =", "", "* Security release notes"])
    return "\n".join(lines) + "\n"


def _bf_changelog(version: str) -> str:
    return (
        f"### {version}\n"
        "\n"
        "Bricksforge security and maintenance release.\n"
        "- Hardened Pro Forms temporary upload handling.\n"
    )


def _assert_bf_passive(transport, max_gets=2):
    assert {call[0] for call in transport.calls} <= {"GET"}
    assert all(call[2] is None and call[3] is False for call in transport.calls)
    paths = [call[1] for call in transport.calls]
    blob = " ".join(paths)
    for banned in _BF_BANNED:
        assert banned.lower() not in blob.lower()
    assert len(paths) <= max_gets
    for path in paths:
        assert path in (BF_README, BF_CHANGELOG)
    assert paths.count(BF_README) <= 1
    assert paths.count(BF_CHANGELOG) <= 1


@pytest.mark.parametrize("version,vulnerable", [
    ("3.1.8.9", True), ("3.1.8.8", True), ("3.1.0", True), ("2.0.0", True),
    ("3.1.8.10", False), ("4.0.0", False), ("4.0.1", False), ("4.1.0", False),
])
def test_bricksforge_version_matrix(version, vulnerable):
    from agents.cve_checks.bricksforge import affected
    from agents.cve_checks.versions import parse_dotted
    assert bool(affected(parse_dotted(version))) is vulnerable


def test_bricksforge_no_wordpress_sends_nothing(monkeypatch):
    transport = Transport()
    transport.routes[BF_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _bf_readme("3.1.8.9"),
    }
    _install(monkeypatch, transport)
    assert BRICKSFORGE.run(
        {}, _ctx(body="<html><body>hello static site</body></html>"),
    ) == []
    assert transport.calls == []


def test_bricksforge_readme_3189_is_critical_and_passive(monkeypatch):
    transport = Transport()
    transport.routes[BF_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _bf_readme("3.1.8.9"),
    }
    _install(monkeypatch, transport)
    found = BRICKSFORGE.run({}, _ctx(body=_BF_WP_ROOT))
    _assert_bf_passive(transport, max_gets=1)
    assert [call[1] for call in transport.calls] == [BF_README]
    assert BRICKSFORGE.agent == "misconfig"
    assert len(found) == 1
    assert found[0]["severity"] == "critical"
    assert found[0]["check"]["match"] == "bricksforge:3.1.8.9"
    assert UNCONFIRMED in found[0]["title"]
    assert "CVE-2026-85097" in found[0]["title"]
    assert "CVE-2026-85097" in found[0]["evidence"]
    assert "4.0.1" in found[0]["fix"]
    assert "3.1.8.10" in found[0]["fix"]
    assert "bricksforge/tmp" in found[0]["fix"]
    assert "Patchstack" in found[0]["evidence"]
    assert "not CISA KEV" in found[0]["evidence"]
    assert "exploit" not in found[0]["title"].lower()
    assert "we exploit" not in found[0]["evidence"].lower()


@pytest.mark.parametrize("tag", ["3.1.8.10", "4.0.1"])
def test_bricksforge_fixed_versions_are_not_flagged(monkeypatch, tag):
    transport = Transport()
    transport.routes[BF_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _bf_readme(tag),
    }
    _install(monkeypatch, transport)
    assert BRICKSFORGE.run({}, _ctx(body=_BF_WP_ROOT)) == []
    _assert_bf_passive(transport, max_gets=1)


def test_bricksforge_asset_ver_3189_is_critical_without_request(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    found = BRICKSFORGE.run({}, _ctx(body=_bf_asset_html("3.1.8.9")))
    assert transport.calls == []
    assert len(found) == 1
    assert found[0]["severity"] == "critical"
    assert found[0]["check"]["match"] == "bricksforge:3.1.8.9"
    assert UNCONFIRMED in found[0]["title"]


def test_bricksforge_asset_ver_401_is_none(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    assert BRICKSFORGE.run({}, _ctx(body=_bf_asset_html("4.0.1"))) == []
    assert transport.calls == []


def test_bricksforge_404_has_no_finding(monkeypatch):
    transport = Transport()
    transport.routes[BF_README] = {"status": 404, "body": ""}
    transport.routes[BF_CHANGELOG] = {"status": 404, "body": ""}
    _install(monkeypatch, transport)
    found = BRICKSFORGE.run({}, _ctx(body=_BF_WP_ROOT))
    _assert_bf_passive(transport, max_gets=2)
    assert [call[1] for call in transport.calls] == [BF_README, BF_CHANGELOG]
    assert found == []


def test_bricksforge_present_unknown_version_is_low_confidence_info(monkeypatch):
    transport = Transport()
    transport.routes[BF_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _bf_readme(None),
    }
    transport.routes[BF_CHANGELOG] = {"status": 404, "body": ""}
    _install(monkeypatch, transport)
    found = BRICKSFORGE.run({}, _ctx(body=_bf_asset_html(None)))
    _assert_bf_passive(transport, max_gets=2)
    assert len(found) == 1
    assert found[0]["severity"] == "info"
    assert found[0]["confidence"] == "low"
    assert found[0]["check"]["match"] == "bricksforge:unknown"
    assert "low confidence" in found[0]["title"].lower()
    assert "CVE-2026-85097" in found[0]["title"]


def test_bricksforge_request_budget_at_most_two_gets_and_audited(monkeypatch):
    seen = {"calls": 0, "methods": [], "data": []}

    def opener(req, timeout=None):
        seen["calls"] += 1
        seen["methods"].append(req.get_method())
        seen["data"].append(req.data)
        path = urlparse(req.full_url).path
        if path.endswith("readme.txt"):
            body = b"not a bricksforge readme"
        else:
            body = _bf_changelog("3.1.8.9").encode()
        return _Resp(body=body, headers=[("content-type", "text/plain")])

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(
        target="http://127.0.0.1:8081/", actor="tester",
        run_id="run_bricksforge_audit",
    )
    try:
        with control.scope(lease), control.agent("misconfig"):
            found = BRICKSFORGE.run({}, _ctx(body=_BF_WP_ROOT))
    finally:
        control.release(lease.run_id)
    assert seen["calls"] == 2
    assert seen["methods"] == ["GET", "GET"]
    assert seen["data"] == [None, None]
    assert found and found[0]["severity"] == "critical"
    assert found[0]["check"]["match"] == "bricksforge:3.1.8.9"
    import audit
    rows = [
        row for row in audit.recent(20)
        if row["kind"] == "request" and row.get("run_id") == "run_bricksforge_audit"
    ]
    assert len(rows) == 2
    assert {row["action"] for row in rows} == {"GET"}
    assert {row["agent"] for row in rows} == {"misconfig"}
    urls = " ".join(row["url"] for row in rows)
    assert BF_README in urls
    assert BF_CHANGELOG in urls
    assert all("body" not in row for row in rows)
    blob = urls.lower()
    for banned in _BF_BANNED:
        assert banned.lower() not in blob


def test_bricksforge_kill_switch_before_first_request_is_none(monkeypatch):
    def opener(_req, timeout=None):
        raise AssertionError("kill switch did not stop the request")

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(
        target="http://127.0.0.1:8081/", actor="tester",
        run_id="run_bricksforge_stop",
    )
    lease.stop()
    try:
        with control.scope(lease):
            with pytest.raises(control.ScanStopped):
                BRICKSFORGE.run({}, _ctx(body=_BF_WP_ROOT))
    finally:
        control.release(lease.run_id)


def test_bricksforge_non_allowlisted_host_is_refused():
    with pytest.raises(main.ScopeError) as exc:
        main.allowlisted_host(
            "https://bricksforge.attacker.example/wp-content/plugins/bricksforge/"
            "readme.txt"
        )
    assert "allowlist" in str(exc.value)


def test_bricksforge_check_source_is_get_only_static_fingerprint():
    text = (
        ROOT / "agents" / "cve_checks" / "bricksforge.py"
    ).read_text(encoding="utf-8")
    assert 'README = "/wp-content/plugins/bricksforge/readme.txt"' in text
    assert 'CHANGELOG = "/wp-content/plugins/bricksforge/changelog.txt"' in text
    assert "fetch_path(ctx, path" in text
    assert text.count("fetch_path(") == 1
    assert "root_observation" in text
    assert "looks_like_wordpress" in text
    assert "post_brotli" not in text
    assert "urlopen" not in text
    assert "http.client" not in text
    assert "temporaryFileUploads" in text
    assert "form_submit" in text
    assert "bricksforge_regenerate_nonce" in text
    assert BRICKSFORGE.agent == "misconfig"
    assert BRICKSFORGE.cve == "CVE-2026-85097"
    assert BRICKSFORGE.id == "bricksforge"
    assert "3.1.8.10" in BRICKSFORGE.fixed
    assert "4.0.1" in BRICKSFORGE.fixed

# --- AutomatorWP Pro Webhooks (CVE-2026-126173) -----------------------------

AWP_PRIMARY = "/wp-content/plugins/automatorwp-webhooks/readme.txt"
AWP_ALTERNATE = "/wp-content/plugins/automatorwp-pro-webhooks/readme.txt"
_AWP_WP_ROOT = (
    '<meta name="generator" content="WordPress 6.8.1" />'
    '<link rel="https://api.w.org/" href="http://127.0.0.1:8081/wp-json/" />'
)
_AWP_BANNED = (
    "/wp-json/automatorwp",
    "automatorwp/webhooks",
    "wp-json/automatorwp",
    "password=",
    "user_id=",
    "lostpassword",
    "wp-login.php",
    "/wp-admin",
    "admin-ajax.php",
)


def _awp_asset_html(version: str | None = None) -> str:
    if version is None:
        return (
            f"{_AWP_WP_ROOT}"
            '<script src="/wp-content/plugins/automatorwp-webhooks/assets/js/'
            'automatorwp-webhooks-admin.js"></script>'
        )
    return (
        f"{_AWP_WP_ROOT}"
        f'<script src="/wp-content/plugins/automatorwp-webhooks/assets/js/'
        f'automatorwp-webhooks-admin.js?ver={version}"></script>'
    )


def _awp_readme(stable: str | None, *, name="AutomatorWP - Webhooks") -> str:
    lines = [
        f"=== {name} ===",
        "Contributors: automatorwp, rubengc, eneribs",
        "Requires at least: 4.4",
        "Tested up to: 7.1",
    ]
    if stable is not None:
        lines.append(f"Stable tag: {stable}")
    lines.extend(
        [
            "",
            "New triggers and actions to send and receive data from webhooks.",
            "",
            "== Changelog ==",
            "",
        ]
    )
    if stable is not None:
        lines.extend([f"= {stable} =", "", "* Security release notes"])
    return "\n".join(lines) + "\n"


def _assert_awp_passive(transport, *, max_gets=2):
    assert {call[0] for call in transport.calls} <= {"GET"}
    assert all(call[2] is None and call[3] is False for call in transport.calls)
    paths = [call[1] for call in transport.calls]
    assert len(paths) <= max_gets
    allowed = {AWP_PRIMARY, AWP_ALTERNATE}
    assert set(paths) <= allowed
    blob = " ".join(paths).lower()
    for banned in _AWP_BANNED:
        assert banned.lower() not in blob


@pytest.mark.parametrize("version,vulnerable", [
    ("1.4.4", True), ("1.4.3", True), ("1.3.6", True), ("1.0.0", True),
    ("1.4.5", False), ("1.4.6", False), ("1.5.0", False), ("2.0.0", False),
])
def test_automatorwp_webhooks_version_matrix(version, vulnerable):
    from agents.cve_checks.automatorwp_webhooks import affected
    from agents.cve_checks.versions import parse_dotted
    assert bool(affected(parse_dotted(version))) is vulnerable


def test_automatorwp_webhooks_144_is_medium_unconfirmed_config_dependent(
    monkeypatch,
):
    transport = Transport()
    transport.routes[AWP_PRIMARY] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _awp_readme("1.4.4"),
    }
    _install(monkeypatch, transport)
    found = AUTOMATORWP_WEBHOOKS.run({}, _ctx(body=_AWP_WP_ROOT))
    _assert_awp_passive(transport, max_gets=1)
    assert transport.calls == [("GET", AWP_PRIMARY, None, False)]
    assert AUTOMATORWP_WEBHOOKS.agent == "auth"
    assert len(found) == 1
    assert found[0]["severity"] == "medium"
    assert found[0]["check"]["match"] == "automatorwp-webhooks:1.4.4"
    assert UNCONFIRMED in found[0]["title"]
    assert UNCONFIRMED in found[0]["evidence"]
    assert "config-dependent" in found[0]["evidence"].lower()
    assert "cannot be seen from outside" in found[0]["evidence"].lower()
    assert "CVE-2026-126173" in found[0]["title"]
    assert "1.4.5" in found[0]["fix"]
    assert "Patchstack" in found[0]["evidence"]
    assert "Brandefense" in found[0]["evidence"]
    assert "not CISA KEV" in found[0]["evidence"]
    assert "Receive Webhook" in found[0]["fix"]
    assert "exploit" not in found[0]["title"].lower()
    assert "we exploit" not in found[0]["evidence"].lower()


def test_automatorwp_webhooks_145_is_none(monkeypatch):
    transport = Transport()
    transport.routes[AWP_PRIMARY] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _awp_readme("1.4.5"),
    }
    _install(monkeypatch, transport)
    found = AUTOMATORWP_WEBHOOKS.run({}, _ctx(body=_AWP_WP_ROOT))
    _assert_awp_passive(transport, max_gets=1)
    assert found == []


def test_automatorwp_webhooks_version_via_ver_query(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    found = AUTOMATORWP_WEBHOOKS.run({}, _ctx(body=_awp_asset_html("1.4.4")))
    assert transport.calls == []
    assert len(found) == 1
    assert found[0]["severity"] == "medium"
    assert found[0]["check"]["match"] == "automatorwp-webhooks:1.4.4"
    assert UNCONFIRMED in found[0]["title"]
    assert "config-dependent" in found[0]["evidence"].lower()


def test_automatorwp_webhooks_fixed_ver_query_is_none(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    assert AUTOMATORWP_WEBHOOKS.run({}, _ctx(body=_awp_asset_html("1.4.5"))) == []
    assert transport.calls == []


def test_automatorwp_webhooks_non_wordpress_sends_nothing(monkeypatch):
    transport = Transport()
    transport.routes[AWP_PRIMARY] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _awp_readme("1.4.4"),
    }
    _install(monkeypatch, transport)
    assert AUTOMATORWP_WEBHOOKS.run(
        {}, _ctx(body="<html><body>hello static site</body></html>"),
    ) == []
    assert transport.calls == []


def test_automatorwp_webhooks_404_has_no_finding(monkeypatch):
    transport = Transport()
    transport.routes[AWP_PRIMARY] = {"status": 404, "body": ""}
    transport.routes[AWP_ALTERNATE] = {"status": 404, "body": ""}
    _install(monkeypatch, transport)
    found = AUTOMATORWP_WEBHOOKS.run({}, _ctx(body=_AWP_WP_ROOT))
    _assert_awp_passive(transport, max_gets=2)
    assert found == []


def test_automatorwp_webhooks_unknown_version_is_info(monkeypatch):
    transport = Transport()
    transport.routes[AWP_PRIMARY] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _awp_readme(None),
    }
    _install(monkeypatch, transport)
    found = AUTOMATORWP_WEBHOOKS.run({}, _ctx(body=_AWP_WP_ROOT))
    _assert_awp_passive(transport, max_gets=1)
    assert len(found) == 1
    assert found[0]["severity"] == "info"
    assert found[0]["check"]["match"] == "automatorwp-webhooks:unknown"
    assert "CVE-2026-126173" in found[0]["title"]


def test_automatorwp_webhooks_finding_labeled_config_dependent_unconfirmed(
    monkeypatch,
):
    transport = Transport()
    _install(monkeypatch, transport)
    found = AUTOMATORWP_WEBHOOKS.run({}, _ctx(body=_awp_asset_html("1.4.4")))
    assert found
    assert UNCONFIRMED in found[0]["title"]
    assert UNCONFIRMED in found[0]["evidence"]
    assert "config-dependent" in found[0]["evidence"].lower()
    assert "cannot be seen from outside" in found[0]["evidence"].lower()


def test_automatorwp_webhooks_request_budget_at_most_two_get_audited(
    monkeypatch,
):
    seen = {"calls": 0, "methods": [], "data": []}

    def opener(req, timeout=None):
        seen["calls"] += 1
        seen["methods"].append(req.get_method())
        seen["data"].append(req.data)
        path = urlparse(req.full_url).path
        if path == AWP_PRIMARY:
            return _Resp(status=404, body=b"missing")
        return _Resp(
            body=_awp_readme(
                "1.4.4", name="AutomatorWP Pro Webhooks"
            ).encode(),
            headers=[("content-type", "text/plain")],
        )

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(
        target="http://127.0.0.1:8081/",
        actor="tester",
        run_id="run_awp_audit",
    )
    try:
        with control.scope(lease), control.agent("auth"):
            found = AUTOMATORWP_WEBHOOKS.run({}, _ctx(body=_AWP_WP_ROOT))
    finally:
        control.release(lease.run_id)
    assert seen["calls"] <= 2
    assert seen["calls"] == 2
    assert seen["methods"] == ["GET", "GET"]
    assert seen["data"] == [None, None]
    assert found and found[0]["severity"] == "medium"
    import audit
    rows = [row for row in audit.recent(20) if row["kind"] == "request"]
    assert rows
    assert rows[-1]["action"] == "GET"
    assert rows[-1]["agent"] == "auth"
    assert "body" not in rows[-1]
    blob = " ".join(row["url"] for row in rows[-2:]).lower()
    for banned in _AWP_BANNED:
        assert banned.lower() not in blob


def test_automatorwp_webhooks_kill_switch_before_first_request_is_none(
    monkeypatch,
):
    def opener(_req, timeout=None):
        raise AssertionError("kill switch did not stop the request")

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(
        target="http://127.0.0.1:8081/",
        actor="tester",
        run_id="run_awp_stop",
    )
    lease.stop()
    try:
        with control.scope(lease):
            with pytest.raises(control.ScanStopped):
                AUTOMATORWP_WEBHOOKS.run({}, _ctx(body=_AWP_WP_ROOT))
    finally:
        control.release(lease.run_id)


def test_automatorwp_webhooks_alternate_readme_fallback(monkeypatch):
    transport = Transport()
    transport.routes[AWP_PRIMARY] = {"status": 404, "body": ""}
    transport.routes[AWP_ALTERNATE] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _awp_readme("1.4.4", name="AutomatorWP Pro Webhooks"),
    }
    _install(monkeypatch, transport)
    found = AUTOMATORWP_WEBHOOKS.run({}, _ctx(body=_AWP_WP_ROOT))
    _assert_awp_passive(transport, max_gets=2)
    assert [call[1] for call in transport.calls] == [AWP_PRIMARY, AWP_ALTERNATE]
    assert found[0]["severity"] == "medium"
    assert found[0]["check"]["match"] == "automatorwp-webhooks:1.4.4"


def test_automatorwp_webhooks_plugin_present_no_version_then_info(monkeypatch):
    transport = Transport()
    transport.routes[AWP_PRIMARY] = {"status": 404, "body": ""}
    transport.routes[AWP_ALTERNATE] = {"status": 404, "body": ""}
    _install(monkeypatch, transport)
    found = AUTOMATORWP_WEBHOOKS.run({}, _ctx(body=_awp_asset_html(None)))
    _assert_awp_passive(transport, max_gets=2)
    assert len(found) == 1
    assert found[0]["severity"] == "info"
    assert found[0]["check"]["match"] == "automatorwp-webhooks:unknown"


def test_automatorwp_webhooks_non_allowlisted_host_is_refused():
    with pytest.raises(main.ScopeError) as exc:
        main.allowlisted_host(
            "https://awp.attacker.example/wp-content/plugins/"
            "automatorwp-webhooks/readme.txt"
        )
    assert "allowlist" in str(exc.value)


def test_automatorwp_webhooks_check_source_is_get_only_passive():
    text = (
        ROOT / "agents" / "cve_checks" / "automatorwp_webhooks.py"
    ).read_text(encoding="utf-8")
    assert 'PRIMARY = "/wp-content/plugins/automatorwp-webhooks/readme.txt"' in text
    assert (
        'ALTERNATE = "/wp-content/plugins/automatorwp-pro-webhooks/readme.txt"'
        in text
    )
    assert "fetch_path(ctx, path" in text
    assert text.count("fetch_path(") == 1
    assert "root_observation" in text
    assert "looks_like_wordpress" in text
    assert "post_brotli" not in text
    assert "urlopen" not in text
    assert "http.client" not in text
    assert "/wp-json/automatorwp" in text
    assert "/wp-admin" in text
    assert AUTOMATORWP_WEBHOOKS.agent == "auth"
    assert AUTOMATORWP_WEBHOOKS.cve == "CVE-2026-126173"
    assert AUTOMATORWP_WEBHOOKS.id == "automatorwp-webhooks"
    assert "1.4.5" in AUTOMATORWP_WEBHOOKS.fixed

# --- Estatik (CVE-2026-125795) ---------------------------------------------

ESTATIK_README = "/wp-content/plugins/estatik/readme.txt"
_ESTATIK_WP_ROOT = (
    '<meta name="generator" content="WordPress 6.8.1" />'
    '<link rel="https://api.w.org/" href="http://127.0.0.1:8081/wp-json/" />'
)
_ESTATIK_BANNED = (
    "listing-search",
    "admin-ajax.php",
    "admin-ajax",
    "template=",
    "path=",
    "../",
    "%2e%2e",
    "%2E%2E",
    "/wp-admin",
)


def _estatik_asset_html(version: str | None = None) -> str:
    if version is None:
        return (
            f"{_ESTATIK_WP_ROOT}"
            '<script src="/wp-content/plugins/estatik/assets/js/public.js">'
            "</script>"
            '<link rel="stylesheet" href="/wp-content/plugins/estatik/'
            'assets/css/public.css" />'
        )
    return (
        f"{_ESTATIK_WP_ROOT}"
        f'<script src="/wp-content/plugins/estatik/assets/js/public.js'
        f'?ver={version}"></script>'
        f'<link rel="stylesheet" href="/wp-content/plugins/estatik/'
        f'assets/css/public.css?ver={version}" />'
    )


def _estatik_readme(stable: str) -> str:
    return (
        "=== Estatik ===\n"
        f"Stable tag: {stable}\n"
        "Contributors: estatik\n"
        "Requires at least: 5.0\n\n"
        "Estatik real estate plugin for WordPress.\n"
    )


def _assert_estatik_passive(transport):
    assert {call[0] for call in transport.calls} <= {"GET"}
    assert all(call[2] is None and call[3] is False for call in transport.calls)
    paths = [call[1] for call in transport.calls]
    blob = " ".join(paths)
    for banned in _ESTATIK_BANNED:
        assert banned.lower() not in blob.lower()
    for path in paths:
        assert path == ESTATIK_README
        assert "listing-search" not in path.lower()
        assert "admin-ajax" not in path.lower()
        assert "template=" not in path.lower()
        assert ".." not in path
    assert paths.count(ESTATIK_README) <= 1


@pytest.mark.parametrize("version,vulnerable", [
    ("4.3.6", True), ("4.3.5", True), ("4.2.0", True), ("4.0.0", True),
    ("4.3.7", False), ("4.3.8", False), ("4.4.0", False), ("5.0.0", False),
])
def test_estatik_version_matrix(version, vulnerable):
    from agents.cve_checks.estatik import affected
    from agents.cve_checks.versions import parse_dotted
    assert bool(affected(parse_dotted(version))) is vulnerable


def test_estatik_no_wordpress_sends_nothing(monkeypatch):
    transport = Transport()
    transport.routes[ESTATIK_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _estatik_readme("4.3.6"),
    }
    _install(monkeypatch, transport)
    assert ESTATIK.run(
        {}, _ctx(body="<html><body>hello static site</body></html>"),
    ) == []
    assert transport.calls == []


def test_estatik_wordpress_without_plugin_sends_nothing(monkeypatch):
    transport = Transport()
    transport.routes[ESTATIK_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _estatik_readme("4.3.6"),
    }
    transport.routes["/listing-search"] = {
        "status": 200, "body": "should-never-be-fetched",
    }
    transport.routes["/wp-admin/admin-ajax.php"] = {
        "status": 200, "body": "should-never-be-fetched",
    }
    _install(monkeypatch, transport)
    assert ESTATIK.run({}, _ctx(body=_ESTATIK_WP_ROOT)) == []
    assert transport.calls == []


def test_estatik_asset_ver_436_is_critical_and_passive(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    found = ESTATIK.run({}, _ctx(body=_estatik_asset_html("4.3.6")))
    assert transport.calls == []
    assert ESTATIK.agent == "misconfig"
    assert len(found) == 1
    assert found[0]["severity"] == "critical"
    assert found[0]["check"]["match"] == "estatik:4.3.6"
    assert UNCONFIRMED in found[0]["title"]
    assert "CVE-2026-125795" in found[0]["title"]
    assert "CVE-2026-125795" in found[0]["evidence"]
    assert "4.3.7" in found[0]["fix"]
    assert "CVSS 9.8" in found[0]["evidence"]
    assert "CWE-98" in found[0]["evidence"]
    assert "Patchstack" in found[0]["evidence"]
    assert "local file inclusion" in found[0]["evidence"].lower()
    assert "GHSA-3cfv-f88w-c563" in found[0]["evidence"]
    assert "patchstack.com" in found[0]["evidence"]
    assert "laskyr.com" in found[0]["evidence"]
    assert "openadvisories.org" in found[0]["evidence"]
    assert "exploit" not in found[0]["title"].lower()
    assert "we exploit" not in found[0]["evidence"].lower()


def test_estatik_437_is_not_flagged(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    assert ESTATIK.run({}, _ctx(body=_estatik_asset_html("4.3.7"))) == []
    assert transport.calls == []


def test_estatik_plugin_present_no_version_one_get_then_info(monkeypatch):
    transport = Transport()
    transport.routes[ESTATIK_README] = {
        "status": 404,
        "content_type": "text/plain",
        "body": "missing",
    }
    _install(monkeypatch, transport)
    found = ESTATIK.run({}, _ctx(body=_estatik_asset_html(None)))
    _assert_estatik_passive(transport)
    assert [call[1] for call in transport.calls] == [ESTATIK_README]
    assert len(found) == 1
    assert found[0]["severity"] == "info"
    assert found[0]["check"]["match"] == "estatik:unknown"
    assert "CVE-2026-125795" in found[0]["title"]


def test_estatik_readme_fallback_436_is_vulnerable(monkeypatch):
    transport = Transport()
    transport.routes[ESTATIK_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _estatik_readme("4.3.6"),
    }
    _install(monkeypatch, transport)
    found = ESTATIK.run({}, _ctx(body=_estatik_asset_html(None)))
    _assert_estatik_passive(transport)
    assert [call[1] for call in transport.calls] == [ESTATIK_README]
    assert found[0]["severity"] == "critical"
    assert found[0]["check"]["match"] == "estatik:4.3.6"
    assert "CVE-2026-125795" in found[0]["evidence"]
    assert "4.3.7" in found[0]["fix"]


def test_estatik_readme_fallback_437_is_none(monkeypatch):
    transport = Transport()
    transport.routes[ESTATIK_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _estatik_readme("4.3.7"),
    }
    _install(monkeypatch, transport)
    assert ESTATIK.run({}, _ctx(body=_estatik_asset_html(None))) == []
    _assert_estatik_passive(transport)


def test_estatik_soft_404_readme_is_ignored(monkeypatch):
    transport = Transport()
    transport.routes[ESTATIK_README] = {
        "status": 200,
        "content_type": "text/html",
        "body": (
            "<!DOCTYPE html><html><head><title>Not Found</title></head>"
            "<body><h1>404</h1><p>Estatik Stable tag: 4.3.6</p></body></html>"
        ),
    }
    _install(monkeypatch, transport)
    found = ESTATIK.run({}, _ctx(body=_estatik_asset_html(None)))
    _assert_estatik_passive(transport)
    assert [call[1] for call in transport.calls] == [ESTATIK_README]
    assert all(item["check"]["match"] != "estatik:4.3.6" for item in found)
    assert all(item["severity"] != "critical" for item in found)
    assert len(found) == 1
    assert found[0]["severity"] == "info"
    assert found[0]["check"]["match"] == "estatik:unknown"


def test_estatik_at_most_one_readme_get_and_never_listing_search(monkeypatch):
    transport = Transport()
    transport.routes[ESTATIK_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _estatik_readme("4.3.6"),
    }
    transport.routes["/listing-search"] = {
        "status": 200, "body": "should-never-be-fetched",
    }
    transport.routes["/wp-admin/admin-ajax.php"] = {
        "status": 200, "body": "should-never-be-fetched",
    }
    transport.routes["/?template=../../etc/passwd"] = {
        "status": 200, "body": "should-never-be-fetched",
    }
    _install(monkeypatch, transport)
    found = ESTATIK.run({}, _ctx(body=_estatik_asset_html(None)))
    _assert_estatik_passive(transport)
    assert [call[1] for call in transport.calls] == [ESTATIK_README]
    assert all(call[0] == "GET" for call in transport.calls)
    assert found and found[0]["severity"] == "critical"
    blob = " ".join(call[1] for call in transport.calls).lower()
    assert "listing-search" not in blob
    assert "admin-ajax" not in blob
    assert "template=" not in blob
    assert ".." not in blob
    assert "path=" not in blob


def test_estatik_kill_switch_before_first_request_is_none(monkeypatch):
    def opener(_req, timeout=None):
        raise AssertionError("kill switch did not stop the request")

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(
        target="http://127.0.0.1:8081/", actor="tester",
        run_id="run_estatik_stop",
    )
    lease.stop()
    try:
        with control.scope(lease):
            with pytest.raises(control.ScanStopped):
                ESTATIK.run({}, _ctx(body=_estatik_asset_html(None)))
    finally:
        control.release(lease.run_id)


def test_estatik_requests_are_get_audited_and_have_no_body(monkeypatch):
    seen = {"calls": 0, "methods": [], "data": []}

    def opener(req, timeout=None):
        seen["calls"] += 1
        seen["methods"].append(req.get_method())
        seen["data"].append(req.data)
        return _Resp(
            body=_estatik_readme("4.3.6").encode(),
            headers=[("content-type", "text/plain")],
        )

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(
        target="http://127.0.0.1:8081/", actor="tester",
        run_id="run_estatik_audit",
    )
    try:
        with control.scope(lease), control.agent("misconfig"):
            found = ESTATIK.run({}, _ctx(body=_estatik_asset_html(None)))
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
    assert ESTATIK_README in rows[-1]["url"]
    assert "body" not in rows[-1]
    assert "listing-search" not in rows[-1]["url"].lower()
    assert "admin-ajax" not in rows[-1]["url"].lower()
    assert "template=" not in rows[-1]["url"].lower()


def test_estatik_non_allowlisted_host_is_refused():
    with pytest.raises(main.ScopeError) as exc:
        main.allowlisted_host(
            "https://estatik.attacker.example/wp-content/plugins/estatik/"
            "readme.txt"
        )
    assert "allowlist" in str(exc.value)


def test_estatik_check_source_is_get_only_static_fingerprint():
    text = (
        ROOT / "agents" / "cve_checks" / "estatik.py"
    ).read_text(encoding="utf-8")
    assert "fetch_path(ctx, README" in text
    assert text.count("fetch_path(") == 1
    assert "root_observation" in text
    assert "looks_like_wordpress" in text
    assert "post_brotli" not in text
    assert "urlopen" not in text
    assert "http.client" not in text
    assert "listing-search" in text.lower()
    assert "template" in text.lower()
    assert "Never calls listing-search" in text or "never calls listing-search" in text.lower()
    assert ESTATIK.agent == "misconfig"
    assert ESTATIK.cve == "CVE-2026-125795"
    assert ESTATIK.id == "estatik"
    assert "4.3.7" in ESTATIK.fixed

# --- Ultra Addons for CF7 (CVE-2026-100386 / CVE-2026-102435) ---------------

UACF7_README = (
    "/wp-content/plugins/ultimate-addons-for-contact-form-7/readme.txt"
)
_UACF7_WP_ROOT = (
    '<meta name="generator" content="WordPress 6.8.1" />'
    '<link rel="https://api.w.org/" href="http://127.0.0.1:8081/wp-json/" />'
)
_UACF7_BANNED = (
    "wp-json/contact-form-7",
    "/wp-json/contact-form-7/",
    "contact-form-7/v1",
    "wpcf7",
    "admin-ajax",
    "/wp-admin",
    "../",
    "..%2f",
    "wp-config.php",
    "uacf7_wpcf7_mail_components",
    "/pdf",
    ".pdf",
)


def _uacf7_asset_html(version: str | None = None) -> str:
    if version is None:
        return (
            f"{_UACF7_WP_ROOT}"
            '<script src="/wp-content/plugins/ultimate-addons-for-contact-form-7/'
            'assets/js/uacf7-frontend.js"></script>'
            '<link rel="stylesheet" href="/wp-content/plugins/'
            'ultimate-addons-for-contact-form-7/assets/css/uacf7-frontend.css" />'
        )
    return (
        f"{_UACF7_WP_ROOT}"
        f'<script src="/wp-content/plugins/ultimate-addons-for-contact-form-7/'
        f'assets/js/uacf7-frontend.js?ver={version}"></script>'
        f'<link rel="stylesheet" href="/wp-content/plugins/'
        f'ultimate-addons-for-contact-form-7/assets/css/'
        f'uacf7-frontend.css?ver={version}" />'
    )


def _uacf7_readme(stable: str) -> str:
    return (
        "=== Ultra Addons for Contact Form 7 ===\n"
        f"Stable tag: {stable}\n"
        "Contributors: themefic, hasanet, mdashikul\n"
        "Requires at least: 5.4\n\n"
        "Ultra Addons for Contact Form 7 — PDF Generator and more.\n"
    )


def _assert_uacf7_passive(transport):
    assert {call[0] for call in transport.calls} <= {"GET"}
    assert all(call[2] is None and call[3] is False for call in transport.calls)
    paths = [call[1] for call in transport.calls]
    blob = " ".join(paths).lower()
    for banned in _UACF7_BANNED:
        assert banned.lower() not in blob
    for path in paths:
        assert path == UACF7_README
    assert paths.count(UACF7_README) <= 1


@pytest.mark.parametrize("version,vulnerable", [
    ("3.5.54", True), ("3.5.53", True), ("3.5.0", True), ("3.0.0", True),
    ("3.5.55", False), ("3.5.56", False), ("3.5.57", False), ("3.6.0", False),
])
def test_ultra_addons_cf7_version_matrix(version, vulnerable):
    from agents.cve_checks.ultra_addons_cf7 import affected
    from agents.cve_checks.versions import parse_dotted
    assert bool(affected(parse_dotted(version))) is vulnerable


def test_ultra_addons_cf7_no_wordpress_sends_nothing(monkeypatch):
    transport = Transport()
    transport.routes[UACF7_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _uacf7_readme("3.5.54"),
    }
    _install(monkeypatch, transport)
    assert ULTRA_ADDONS_CF7.run(
        {}, _ctx(body="<html><body>hello static site</body></html>"),
    ) == []
    assert transport.calls == []


def test_ultra_addons_cf7_wordpress_without_plugin_sends_nothing(monkeypatch):
    transport = Transport()
    transport.routes[UACF7_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _uacf7_readme("3.5.54"),
    }
    transport.routes["/wp-json/contact-form-7/v1/contact-forms"] = {
        "status": 200, "body": "should-never-be-fetched",
    }
    transport.routes["/wp-admin/admin-ajax.php"] = {
        "status": 200, "body": "should-never-be-fetched",
    }
    _install(monkeypatch, transport)
    assert ULTRA_ADDONS_CF7.run({}, _ctx(body=_UACF7_WP_ROOT)) == []
    assert transport.calls == []


def test_ultra_addons_cf7_asset_ver_3554_is_high_and_passive(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    found = ULTRA_ADDONS_CF7.run({}, _ctx(body=_uacf7_asset_html("3.5.54")))
    assert transport.calls == []
    assert ULTRA_ADDONS_CF7.agent == "misconfig"
    assert len(found) == 1
    assert found[0]["severity"] == "high"
    assert found[0]["check"]["match"] == "ultra-addons-cf7:3.5.54"
    assert UNCONFIRMED in found[0]["title"]
    assert "CVE-2026-100386" in found[0]["title"]
    assert "CVE-2026-102435" in found[0]["title"]
    assert "CVE-2026-100386" in found[0]["evidence"]
    assert "CVE-2026-102435" in found[0]["evidence"]
    assert "PDF Generator" in found[0]["evidence"]
    assert "CVSS 7.5" in found[0]["evidence"]
    assert "Patchstack" in found[0]["evidence"]
    assert "3.5.55" in found[0]["fix"]
    assert "3.5.57" in found[0]["fix"]
    assert "salt" in found[0]["fix"].lower()
    assert "wordfence.com" in found[0]["evidence"]
    assert "laskyr.com" in found[0]["evidence"]
    assert "nvd.nist.gov" in found[0]["evidence"]
    assert "exploit" not in found[0]["title"].lower()
    assert "we exploit" not in found[0]["evidence"].lower()


def test_ultra_addons_cf7_3555_is_not_flagged(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    assert ULTRA_ADDONS_CF7.run({}, _ctx(body=_uacf7_asset_html("3.5.55"))) == []
    assert transport.calls == []


def test_ultra_addons_cf7_plugin_present_no_version_one_get_then_info(monkeypatch):
    transport = Transport()
    transport.routes[UACF7_README] = {
        "status": 404,
        "content_type": "text/plain",
        "body": "missing",
    }
    _install(monkeypatch, transport)
    found = ULTRA_ADDONS_CF7.run({}, _ctx(body=_uacf7_asset_html(None)))
    _assert_uacf7_passive(transport)
    assert [call[1] for call in transport.calls] == [UACF7_README]
    assert len(found) == 1
    assert found[0]["severity"] == "info"
    assert found[0]["check"]["match"] == "ultra-addons-cf7:unknown"


def test_ultra_addons_cf7_readme_fallback_3554_is_vulnerable(monkeypatch):
    transport = Transport()
    transport.routes[UACF7_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _uacf7_readme("3.5.54"),
    }
    _install(monkeypatch, transport)
    found = ULTRA_ADDONS_CF7.run({}, _ctx(body=_uacf7_asset_html(None)))
    _assert_uacf7_passive(transport)
    assert [call[1] for call in transport.calls] == [UACF7_README]
    assert len(found) == 1
    assert found[0]["severity"] == "high"
    assert found[0]["check"]["match"] == "ultra-addons-cf7:3.5.54"
    assert "CVE-2026-100386" in found[0]["evidence"]
    assert "CVE-2026-102435" in found[0]["evidence"]


def test_ultra_addons_cf7_readme_fallback_3555_is_none(monkeypatch):
    transport = Transport()
    transport.routes[UACF7_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _uacf7_readme("3.5.55"),
    }
    _install(monkeypatch, transport)
    assert ULTRA_ADDONS_CF7.run({}, _ctx(body=_uacf7_asset_html(None))) == []
    _assert_uacf7_passive(transport)


@pytest.mark.parametrize("body", [
    "<!doctype html><html><head><title>Ultra</title></head>"
    "<body>Stable tag: 3.5.54</body></html>",
    "<html><body><p>Ultra Addons Stable tag: 3.5.54</p></body></html>",
    "=== Some Other Plugin ===\nContributors: someone\nStable tag: 3.5.54\n",
    "Ultra Addons is mentioned here.\nStable tag: 3.5.54\n",
])
def test_ultra_addons_cf7_soft404_or_wrong_readme_is_none(monkeypatch, body):
    transport = Transport()
    transport.routes[UACF7_README] = {
        "status": 200,
        "content_type": "text/html",
        "body": body,
    }
    _install(monkeypatch, transport)
    found = ULTRA_ADDONS_CF7.run({}, _ctx(body=_uacf7_asset_html(None)))
    _assert_uacf7_passive(transport)
    assert [call[1] for call in transport.calls] == [UACF7_README]
    assert all(
        item["check"]["match"] != "ultra-addons-cf7:3.5.54" for item in found
    )
    assert all(item["severity"] != "high" for item in found)
    assert len(found) == 1
    assert found[0]["severity"] == "info"
    assert found[0]["check"]["match"] == "ultra-addons-cf7:unknown"


def test_ultra_addons_cf7_at_most_one_readme_get_and_never_cf7_ajax(
    monkeypatch,
):
    transport = Transport()
    transport.routes[UACF7_README] = {
        "status": 200,
        "content_type": "text/plain",
        "body": _uacf7_readme("3.5.54"),
    }
    transport.routes["/wp-json/contact-form-7/v1/contact-forms/1/feedback"] = {
        "status": 200, "body": "should-never-be-fetched",
    }
    transport.routes["/wp-admin/admin-ajax.php"] = {
        "status": 200, "body": "should-never-be-fetched",
    }
    transport.routes["/wp-content/uploads/uacf7-pdf/report.pdf"] = {
        "status": 200, "body": "should-never-be-fetched",
    }
    _install(monkeypatch, transport)
    found = ULTRA_ADDONS_CF7.run({}, _ctx(body=_uacf7_asset_html(None)))
    _assert_uacf7_passive(transport)
    assert [call[1] for call in transport.calls] == [UACF7_README]
    assert all(call[0] == "GET" for call in transport.calls)
    assert found and found[0]["severity"] == "high"
    blob = " ".join(call[1] for call in transport.calls).lower()
    for banned in _UACF7_BANNED:
        assert banned.lower() not in blob


def test_ultra_addons_cf7_kill_switch_before_first_request_is_none(monkeypatch):
    def opener(_req, timeout=None):
        raise AssertionError("kill switch did not stop the request")

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(
        target="http://127.0.0.1:8081/",
        actor="tester",
        run_id="run_uacf7_stop",
    )
    lease.stop()
    try:
        with control.scope(lease):
            with pytest.raises(control.ScanStopped):
                ULTRA_ADDONS_CF7.run({}, _ctx(body=_uacf7_asset_html(None)))
    finally:
        control.release(lease.run_id)


def test_ultra_addons_cf7_requests_are_get_audited_and_have_no_body(monkeypatch):
    seen = {"calls": 0, "methods": [], "data": []}

    def opener(req, timeout=None):
        seen["calls"] += 1
        seen["methods"].append(req.get_method())
        seen["data"].append(req.data)
        return _Resp(
            body=_uacf7_readme("3.5.54").encode(),
            headers=[("content-type", "text/plain")],
        )

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(
        target="http://127.0.0.1:8081/",
        actor="tester",
        run_id="run_uacf7_audit",
    )
    try:
        with control.scope(lease), control.agent("misconfig"):
            found = ULTRA_ADDONS_CF7.run({}, _ctx(body=_uacf7_asset_html(None)))
    finally:
        control.release(lease.run_id)
    assert seen["calls"] == 1
    assert seen["methods"] == ["GET"]
    assert seen["data"] == [None]
    assert found and found[0]["severity"] == "high"
    import audit
    rows = [row for row in audit.recent(20) if row["kind"] == "request"]
    assert rows
    assert rows[-1]["action"] == "GET"
    assert rows[-1]["agent"] == "misconfig"
    assert UACF7_README in rows[-1]["url"]
    assert "body" not in rows[-1]
    assert "wp-json/contact-form-7" not in rows[-1]["url"].lower()
    assert "admin-ajax" not in rows[-1]["url"].lower()
    assert ".pdf" not in rows[-1]["url"].lower()


def test_ultra_addons_cf7_non_allowlisted_host_is_refused():
    with pytest.raises(main.ScopeError) as exc:
        main.allowlisted_host(
            "https://uacf7.attacker.example/wp-content/plugins/"
            "ultimate-addons-for-contact-form-7/readme.txt"
        )
    assert "allowlist" in str(exc.value)


def test_ultra_addons_cf7_check_source_is_get_only_static_fingerprint():
    text = (
        ROOT / "agents" / "cve_checks" / "ultra_addons_cf7.py"
    ).read_text(encoding="utf-8")
    assert (
        'README = "/wp-content/plugins/ultimate-addons-for-contact-form-7/'
        'readme.txt"'
    ) in text
    assert "fetch_path(ctx, README" in text
    assert text.count("fetch_path(") == 1
    assert "root_observation" in text
    assert "looks_like_wordpress" in text
    assert "post_brotli" not in text
    assert "urlopen" not in text
    assert "http.client" not in text
    assert "/wp-json/contact-form-7/" in text
    assert "admin-ajax" in text
    assert "path" in text.lower()
    assert ULTRA_ADDONS_CF7.agent == "misconfig"
    assert ULTRA_ADDONS_CF7.cve == "CVE-2026-100386 / CVE-2026-102435"
    assert ULTRA_ADDONS_CF7.id == "ultra-addons-cf7"
    assert "3.5.55" in ULTRA_ADDONS_CF7.fixed
    assert "3.5.57" in ULTRA_ADDONS_CF7.fixed

# --- Confluence Axis (CVE-2026-90436) ---------------------------------------

CONFLUENCE_LOGIN = "/login.action"
_CONFLUENCE_BANNED = (
    "/rpc/",
    "/rpc/soap-axis",
    "/rpc/xmlrpc",
    "soap-axis",
    "?wsdl",
    "wsdl",
    "text/xml",
    "application/soap",
    "exceptionName",
    "<Fault",
    "SOAP",
)


def _confluence_html(version=None, *, powered=True, ajs_other=True):
    metas = []
    if version is not None:
        metas.append(
            f'<meta name="ajs-version-number" content="{version}">'
        )
    if ajs_other:
        metas.append('<meta name="ajs-build-number" content="9012">')
        metas.append('<meta name="ajs-context-path" content="">')
    footer = (
        '<li>Powered by Atlassian Confluence</li>' if powered else ""
    )
    return (
        "<!DOCTYPE html><html><head><title>Confluence</title>"
        + "".join(metas)
        + "</head><body><p>Home</p>"
        + footer
        + "</body></html>"
    )


def _confluence_login_html(version=None):
    ver_meta = (
        f'<meta name="ajs-version-number" content="{version}">'
        if version is not None
        else ""
    )
    return (
        "<!DOCTYPE html><html><head><title>Log In - Confluence</title>"
        f'{ver_meta}'
        '<meta name="ajs-build-number" content="9012">'
        "</head><body>"
        '<form action="/dologin.action" method="post">'
        '<input name="os_username"><input name="os_password" type="password">'
        "</form>"
        "<li>Powered by Atlassian Confluence</li>"
        "</body></html>"
    )


def _assert_confluence_passive(transport):
    assert all(call[0] == "GET" for call in transport.calls)
    assert all(call[2] is None and call[3] is False for call in transport.calls)
    for _method, path, _session, _follow in transport.calls:
        low = path.lower()
        for banned in _CONFLUENCE_BANNED:
            assert banned.lower() not in low
        assert "/rpc/" not in low
        assert "soap" not in low
        assert "wsdl" not in low
        assert "xmlrpc" not in low


def test_confluence_axis_non_confluence_sends_nothing(monkeypatch):
    transport = Transport()
    transport.routes[CONFLUENCE_LOGIN] = {
        "status": 200,
        "content_type": "text/html",
        "body": _confluence_login_html("9.2.27"),
    }
    transport.routes["/rpc/"] = {"status": 200, "body": "axis"}
    transport.routes["/rpc/soap-axis/confluenceservice-v2"] = {
        "status": 200, "body": "axis",
    }
    _install(monkeypatch, transport)
    assert CONFLUENCE_AXIS.run(
        {}, _ctx(body="<html><body>hello</body></html>")
    ) == []
    assert transport.calls == []


@pytest.mark.parametrize("version,flagged", [
    ("9.2.27", True),
    ("9.2.28", False),
    ("8.5.0", True),
    ("8.5.22", True),
    ("10.0.0", False),
    ("10.0.1", False),
    ("9.0.0", True),
    ("1.0.0", True),
    ("9.2.29", False),
])
def test_confluence_axis_version_matrix(monkeypatch, version, flagged):
    transport = Transport()
    transport.routes["/rpc/"] = {"status": 200, "body": "should-never"}
    _install(monkeypatch, transport)
    found = CONFLUENCE_AXIS.run(
        {}, _ctx(body=_confluence_html(version)),
    )
    _assert_confluence_passive(transport)
    assert transport.calls == []
    if flagged:
        assert len(found) == 1
        assert found[0]["severity"] == "critical"
        assert UNCONFIRMED in found[0]["title"]
        assert "CVE-2026-90436" in found[0]["title"]
        assert "CVE-2026-90436" in found[0]["evidence"]
        assert "Remote API" in found[0]["evidence"]
        assert "9.2.28" in found[0]["fix"]
        assert "10.x" in found[0]["fix"] or "10.x" in found[0]["evidence"]
        assert found[0]["check"]["match"] == f"confluence-axis:{version}"
        assert "exploit" not in found[0]["title"].lower()
        assert "exploits" not in found[0]["evidence"].lower().replace(
            "exploited", ""
        )
        assert "rapid7.com" in found[0]["evidence"]
        assert "confluence.atlassian.com/security" in found[0]["evidence"]
    else:
        assert found == []


def test_confluence_axis_version_matrix_helper():
    from agents.cve_checks.confluence_axis import affected

    assert affected((9, 2, 27)) is True
    assert affected((9, 2, 28)) is False
    assert affected((8, 5, 0)) is True
    assert affected((8, 5, 22)) is True
    assert affected((10, 0, 0)) is False
    assert affected((10, 0, 1)) is False
    assert affected((9, 0, 0)) is True
    assert affected((1, 0, 0)) is True


def test_confluence_axis_atlassian_net_skipped(monkeypatch):
    transport = Transport()
    transport.routes[CONFLUENCE_LOGIN] = {
        "status": 200,
        "content_type": "text/html",
        "body": _confluence_login_html("9.2.27"),
    }
    _install(monkeypatch, transport)
    ctx = _ctx(body=_confluence_html("9.2.27"))
    ctx.url = "https://example.atlassian.net/wiki"
    ctx.recon_root = {
        **ctx.recon_root,
        "url": "https://example.atlassian.net/wiki",
        "body_snippet": _confluence_html("9.2.27"),
    }
    assert CONFLUENCE_AXIS.run({}, ctx) == []
    assert transport.calls == []


def test_confluence_axis_fingerprint_without_version_fetches_login(
    monkeypatch,
):
    transport = Transport()
    transport.routes[CONFLUENCE_LOGIN] = {
        "status": 200,
        "content_type": "text/html",
        "body": _confluence_login_html("9.2.27"),
    }
    transport.routes["/rpc/"] = {"status": 200, "body": "nope"}
    transport.routes["/rpc/xmlrpc"] = {"status": 200, "body": "nope"}
    transport.routes["/rpc/soap-axis/confluenceservice-v2?wsdl"] = {
        "status": 200, "body": "nope",
    }
    _install(monkeypatch, transport)
    found = CONFLUENCE_AXIS.run(
        {},
        _ctx(body=_confluence_html(None, powered=True, ajs_other=True)),
    )
    _assert_confluence_passive(transport)
    assert [call[1] for call in transport.calls] == [CONFLUENCE_LOGIN]
    assert found and found[0]["severity"] == "critical"
    assert found[0]["check"]["match"] == "confluence-axis:9.2.27"
    assert "GET /login.action" in found[0]["evidence"]


def test_confluence_axis_root_version_skips_login_get(monkeypatch):
    transport = Transport()
    transport.routes[CONFLUENCE_LOGIN] = {
        "status": 200,
        "content_type": "text/html",
        "body": _confluence_login_html("9.2.27"),
    }
    _install(monkeypatch, transport)
    found = CONFLUENCE_AXIS.run({}, _ctx(body=_confluence_html("8.5.3")))
    assert transport.calls == []
    assert found and found[0]["severity"] == "critical"
    assert found[0]["check"]["match"] == "confluence-axis:8.5.3"
    assert "root response" in found[0]["evidence"]


def test_confluence_axis_powered_by_footer_fingerprint(monkeypatch):
    transport = Transport()
    transport.routes[CONFLUENCE_LOGIN] = {
        "status": 200,
        "content_type": "text/html",
        "body": _confluence_login_html("9.2.27"),
    }
    _install(monkeypatch, transport)
    body = (
        "<html><body><p>Space</p>"
        "<li>Powered by Atlassian Confluence</li></body></html>"
    )
    found = CONFLUENCE_AXIS.run({}, _ctx(body=body))
    assert [call[1] for call in transport.calls] == [CONFLUENCE_LOGIN]
    assert found and found[0]["severity"] == "critical"


def test_confluence_axis_fingerprint_without_version_is_info(monkeypatch):
    transport = Transport()
    transport.routes[CONFLUENCE_LOGIN] = {
        "status": 200,
        "content_type": "text/html",
        "body": _confluence_login_html(None),
    }
    _install(monkeypatch, transport)
    found = CONFLUENCE_AXIS.run(
        {},
        _ctx(body=_confluence_html(None, powered=True, ajs_other=True)),
    )
    _assert_confluence_passive(transport)
    assert [call[1] for call in transport.calls] == [CONFLUENCE_LOGIN]
    assert len(found) == 1
    assert found[0]["severity"] == "info"
    assert found[0]["check"]["match"] == "confluence-axis:unknown"
    assert "version not visible" in found[0]["title"]
    assert "CVE-2026-90436" in found[0]["title"]
    assert "exploited" in found[0]["title"].lower()
    assert "exploits" not in found[0]["evidence"].lower().replace(
        "exploited", ""
    )


def test_confluence_axis_soft_404_login_is_info_not_critical(monkeypatch):
    transport = Transport()
    transport.routes[CONFLUENCE_LOGIN] = {
        "status": 200,
        "content_type": "text/html",
        "body": (
            "<!DOCTYPE html><html><head><title>Not Found</title></head>"
            "<body><h1>404</h1><p>Everything is fine</p></body></html>"
        ),
    }
    _install(monkeypatch, transport)
    found = CONFLUENCE_AXIS.run(
        {},
        _ctx(body=_confluence_html(None, powered=True, ajs_other=True)),
    )
    _assert_confluence_passive(transport)
    assert [call[1] for call in transport.calls] == [CONFLUENCE_LOGIN]
    assert all(item["severity"] != "critical" for item in found)
    assert len(found) == 1
    assert found[0]["severity"] == "info"
    assert found[0]["check"]["match"] == "confluence-axis:unknown"


def test_confluence_axis_catch_all_200_without_fingerprint_no_finding(
    monkeypatch,
):
    transport = Transport()
    transport.routes[CONFLUENCE_LOGIN] = {
        "status": 200,
        "content_type": "text/html",
        "body": _confluence_login_html("9.2.27"),
    }
    transport.routes["/"] = {"status": 200, "body": "catch-all"}
    _install(monkeypatch, transport)
    assert CONFLUENCE_AXIS.run(
        {}, _ctx(body="<html><body>generic site</body></html>")
    ) == []
    assert transport.calls == []


def test_confluence_axis_never_requests_rpc_or_wsdl(monkeypatch):
    transport = Transport()
    transport.routes[CONFLUENCE_LOGIN] = {
        "status": 200,
        "content_type": "text/html",
        "body": _confluence_login_html("9.2.27"),
    }
    for path in (
        "/rpc/",
        "/rpc/soap-axis/confluenceservice-v2",
        "/rpc/xmlrpc",
        "/rpc/soap-axis/confluenceservice-v2?wsdl",
        "/plugins/servlet/soap-axis1/confluenceservice-v2",
    ):
        transport.routes[path] = {"status": 200, "body": "axis"}
    _install(monkeypatch, transport)
    CONFLUENCE_AXIS.run(
        {},
        _ctx(body=_confluence_html(None, powered=True, ajs_other=True)),
    )
    _assert_confluence_passive(transport)
    paths = [call[1] for call in transport.calls]
    assert paths == [CONFLUENCE_LOGIN]
    blob = " ".join(paths).lower()
    for banned in _CONFLUENCE_BANNED:
        assert banned.lower() not in blob
    assert "/rpc/" not in blob


def test_confluence_axis_at_most_one_get_and_never_mutates(monkeypatch):
    transport = Transport()
    transport.routes[CONFLUENCE_LOGIN] = {
        "status": 200,
        "content_type": "text/html",
        "body": _confluence_login_html("8.5.1"),
    }
    transport.routes["/dologin.action"] = {"status": 200, "body": "nope"}
    transport.routes["/rpc/xmlrpc"] = {"status": 200, "body": "nope"}
    _install(monkeypatch, transport)
    found = CONFLUENCE_AXIS.run(
        {},
        _ctx(body=_confluence_html(None, powered=True, ajs_other=True)),
    )
    _assert_confluence_passive(transport)
    assert [call[1] for call in transport.calls] == [CONFLUENCE_LOGIN]
    assert all(call[0] == "GET" for call in transport.calls)
    assert found and found[0]["severity"] == "critical"


def test_confluence_axis_kill_switch_before_first_request_is_none(monkeypatch):
    def opener(_req, timeout=None):
        raise AssertionError("kill switch did not stop the request")

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(
        target="http://127.0.0.1:8081/", actor="tester",
        run_id="run_confluence_stop",
    )
    lease.stop()
    try:
        with control.scope(lease):
            with pytest.raises(control.ScanStopped):
                CONFLUENCE_AXIS.run(
                    {},
                    _ctx(
                        body=_confluence_html(
                            None, powered=True, ajs_other=True
                        )
                    ),
                )
    finally:
        control.release(lease.run_id)


def test_confluence_axis_get_is_audited(monkeypatch):
    seen = {"calls": 0, "methods": [], "data": []}

    def opener(req, timeout=None):
        seen["calls"] += 1
        seen["methods"].append(req.get_method())
        seen["data"].append(req.data)
        return _Resp(
            body=_confluence_login_html("9.2.27").encode(),
            headers=[("content-type", "text/html")],
        )

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(
        target="http://127.0.0.1:8081/", actor="tester",
        run_id="run_confluence_audit",
    )
    try:
        with control.scope(lease), control.agent("misconfig"):
            found = CONFLUENCE_AXIS.run(
                {},
                _ctx(
                    body=_confluence_html(None, powered=True, ajs_other=True)
                ),
            )
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
    assert CONFLUENCE_LOGIN in rows[-1]["url"]
    assert "body" not in rows[-1]
    assert "/rpc/" not in rows[-1]["url"].lower()
    assert "wsdl" not in rows[-1]["url"].lower()
    assert "soap" not in rows[-1]["url"].lower()


def test_confluence_axis_ajs_version_rev_attr_order(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    body = (
        '<html><head><meta content="9.2.27" name="ajs-version-number">'
        "</head><body>Powered by Atlassian Confluence</body></html>"
    )
    found = CONFLUENCE_AXIS.run({}, _ctx(body=body))
    assert transport.calls == []
    assert found and found[0]["check"]["match"] == "confluence-axis:9.2.27"


def test_confluence_axis_remote_api_dependency_in_finding(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    found = CONFLUENCE_AXIS.run({}, _ctx(body=_confluence_html("9.2.27")))
    assert found
    assert UNCONFIRMED in found[0]["title"]
    assert "Remote API" in found[0]["evidence"]
    assert "does not confirm" in found[0]["evidence"].lower()
    assert "disable" in found[0]["fix"].lower()


def test_confluence_axis_check_source_is_get_only_passive():
    text = (
        ROOT / "agents" / "cve_checks" / "confluence_axis.py"
    ).read_text(encoding="utf-8")
    assert 'LOGIN = "/login.action"' in text
    assert "fetch_path(ctx, LOGIN" in text
    assert text.count("fetch_path(") == 1
    assert "root_observation" in text
    assert "post_brotli" not in text
    assert "urlopen" not in text
    assert "http.client" not in text
    assert "/rpc/" in text
    assert "soap-axis" in text or "Axis/SOAP" in text
    assert "wsdl" in text
    assert CONFLUENCE_AXIS.agent == "misconfig"
    assert CONFLUENCE_AXIS.cve == "CVE-2026-90436"
    assert CONFLUENCE_AXIS.id == "confluence-axis"
    assert "9.2.28" in CONFLUENCE_AXIS.fixed


# --- Mercury terminals (CVE-2026-111057) ------------------------------------

_MERCURY_BANNED = (
    "POST /api/terminals",
    "/terminals/websocket",
    "/api/kernels",
    "/api/sessions",
    "/api/contents",
    "/api/shutdown",
    "/files",
    "/lab",
)


def _mercury_html(version=None):
    version_bit = (
        f'<meta name="generator" content="Mercury {version}">'
        if version is not None
        else ""
    )
    return (
        "<!doctype html><html lang=\"en\"><head>"
        "<title>Mercury</title>"
        f"{version_bit}"
        "<style>:root { --mercury-content-background-color: #fff; "
        "--mercury-topbar-background-color: #0b0b0c; "
        "--mercury-font-family: sans-serif; "
        "--mercury-text-color: #0f172a; }</style>"
        "</head><body>"
        '<a class="brand" href="/">Mercury</a>'
        '<p class="lead"><b>Welcome to Mercury.</b> '
        "You're viewing notebooks turned into user-friendly apps.</p>"
        '<footer class="ftr"><div class="ftr-inner">'
        "MLJAR - next generation of AI tools</div></footer>"
        "</body></html>"
    )


def _assert_mercury_passive(transport):
    assert all(call[0] == "GET" for call in transport.calls)
    assert all(call[2] is None and call[3] is False for call in transport.calls)
    for _method, path, _session, _follow in transport.calls:
        low = path.lower()
        for banned in _MERCURY_BANNED:
            assert banned.lower() not in low
        assert path == MERCURY_TERMINALS or not path.startswith("/api/")


def test_mercury_terminals_empty_list_is_critical(monkeypatch):
    transport = Transport()
    transport.routes[MERCURY_TERMINALS] = {
        "status": 200,
        "content_type": "application/json",
        "body": "[]",
    }
    _install(monkeypatch, transport)
    found = MERCURY.run({}, _ctx(body=_mercury_html()))
    _assert_mercury_passive(transport)
    assert [call[1] for call in transport.calls] == [MERCURY_TERMINALS]
    assert len(found) == 1
    assert found[0]["severity"] == "critical"
    assert found[0]["check"]["id"] == "mercury"
    assert found[0]["check"]["match"] == "mercury:unknown:terminals-open"
    assert "unauthenticated" in found[0]["title"].lower()
    assert "terminal" in found[0]["title"].lower()
    assert "CVE-2026-111057" in found[0]["evidence"]
    assert "not in CISA KEV" in found[0]["evidence"]
    assert "not established" in found[0]["evidence"].lower()
    assert "POST /api/terminals" not in found[0]["evidence"] or (
        "no POST /api/terminals" in found[0]["evidence"]
    )
    assert "exploit" not in found[0]["title"].lower()
    assert "exploits" not in found[0]["evidence"].lower().replace(
        "exploitation", ""
    )


def test_mercury_terminals_named_list_is_critical(monkeypatch):
    transport = Transport()
    transport.routes[MERCURY_TERMINALS] = {
        "status": 200,
        "content_type": "application/json",
        "headers": {"content-type": "application/json"},
        "body": json.dumps([
            {"name": "1", "last_activity": "2026-08-21T12:00:00.000Z"},
        ]),
    }
    _install(monkeypatch, transport)
    found = MERCURY.run({}, _ctx(body=_mercury_html()))
    _assert_mercury_passive(transport)
    assert [call[1] for call in transport.calls] == [MERCURY_TERMINALS]
    assert found and found[0]["severity"] == "critical"
    assert found[0]["check"]["match"] == "mercury:unknown:terminals-open"


def test_mercury_terminals_403_no_terminal_finding(monkeypatch):
    transport = Transport()
    transport.routes[MERCURY_TERMINALS] = {
        "status": 403,
        "content_type": "application/json",
        "body": '{"message": "Forbidden"}',
    }
    _install(monkeypatch, transport)
    found = MERCURY.run({}, _ctx(body=_mercury_html()))
    _assert_mercury_passive(transport)
    assert [call[1] for call in transport.calls] == [MERCURY_TERMINALS]
    assert found == []
    assert all(
        "terminals-open" not in (item.get("check") or {}).get("match", "")
        for item in found
    )


def test_mercury_terminals_html_catch_all_200_is_none(monkeypatch):
    transport = Transport()
    transport.routes[MERCURY_TERMINALS] = {
        "status": 200,
        "content_type": "text/html",
        "body": "<!DOCTYPE html><html><body>catch-all app shell</body></html>",
    }
    _install(monkeypatch, transport)
    found = MERCURY.run({}, _ctx(body=_mercury_html()))
    _assert_mercury_passive(transport)
    assert [call[1] for call in transport.calls] == [MERCURY_TERMINALS]
    assert found == []


def test_mercury_non_mercury_sends_nothing(monkeypatch):
    transport = Transport()
    transport.routes[MERCURY_TERMINALS] = {
        "status": 200,
        "content_type": "application/json",
        "body": "[]",
    }
    transport.routes["/api/kernels"] = {"status": 200, "body": "[]"}
    transport.routes["/api/shutdown"] = {"status": 200, "body": "nope"}
    _install(monkeypatch, transport)
    assert MERCURY.run(
        {}, _ctx(body="<html><body>hello mercury the planet</body></html>")
    ) == []
    assert transport.calls == []


@pytest.mark.parametrize("version,severity,match_suffix", [
    ("3.2.3", "critical", "terminals-cve"),
    ("3.2.5", "high", "kernels-cve"),
    ("3.2.10", "medium", "xss-cve"),
    ("3.2.11", None, None),
    ("3.2.13", None, None),
    ("3.0.0", "critical", "terminals-cve"),
    ("3.2.4", "high", "kernels-cve"),
    ("3.2.6", "medium", "xss-cve"),
])
def test_mercury_version_matrix(monkeypatch, version, severity, match_suffix):
    transport = Transport()
    transport.routes[MERCURY_TERMINALS] = {
        "status": 403,
        "content_type": "application/json",
        "body": '{"message": "Forbidden"}',
    }
    transport.routes["/api/kernels"] = {"status": 200, "body": "nope"}
    _install(monkeypatch, transport)
    found = MERCURY.run({}, _ctx(body=_mercury_html(version)))
    _assert_mercury_passive(transport)
    assert [call[1] for call in transport.calls] == [MERCURY_TERMINALS]
    if severity is None:
        assert found == []
    else:
        assert len(found) == 1
        assert found[0]["severity"] == severity
        assert UNCONFIRMED in found[0]["title"]
        assert "CVE-2026-111057" in found[0]["title"]
        assert found[0]["check"]["match"] == f"mercury:{version}:{match_suffix}"
        assert "3.2.11" in found[0]["fix"]
        assert "not in CISA KEV" in found[0]["evidence"]
        assert "exploit" not in found[0]["title"].lower()


def test_mercury_version_matrix_helper():
    from agents.cve_checks.mercury import version_severity

    assert version_severity((3, 2, 3)) == "critical"
    assert version_severity((3, 2, 4)) == "high"
    assert version_severity((3, 2, 5)) == "high"
    assert version_severity((3, 2, 6)) == "medium"
    assert version_severity((3, 2, 10)) == "medium"
    assert version_severity((3, 2, 11)) is None
    assert version_severity((3, 2, 13)) is None


def test_mercury_open_terminals_prefers_exposure_over_version(monkeypatch):
    transport = Transport()
    transport.routes[MERCURY_TERMINALS] = {
        "status": 200,
        "content_type": "application/json",
        "body": "[]",
    }
    _install(monkeypatch, transport)
    found = MERCURY.run({}, _ctx(body=_mercury_html("3.2.3")))
    assert found and found[0]["severity"] == "critical"
    assert found[0]["check"]["match"] == "mercury:3.2.3:terminals-open"
    assert "3.2.3" in found[0]["evidence"]


def test_mercury_fingerprint_markers_from_templates(monkeypatch):
    transport = Transport()
    transport.routes[MERCURY_TERMINALS] = {
        "status": 403,
        "content_type": "application/json",
        "body": "{}",
    }
    _install(monkeypatch, transport)
    bodies = [
        '<div id="mercury-loader" class="mercury-starting-loader"></div>',
        '<div class="mercury-page-header"><div class="mercury-page-brand">'
        "Mercury</div></div>",
        "<noscript>Mercury requires JavaScript.</noscript>",
        "footer: MLJAR - next generation of AI tools",
    ]
    for body in bodies:
        transport.calls.clear()
        assert MERCURY.run({}, _ctx(body=body)) == []
        assert [call[1] for call in transport.calls] == [MERCURY_TERMINALS]


def test_mercury_never_requests_forbidden_paths(monkeypatch):
    transport = Transport()
    transport.routes[MERCURY_TERMINALS] = {
        "status": 200,
        "content_type": "application/json",
        "body": "[]",
    }
    for path in (
        "/api/kernels",
        "/api/sessions",
        "/api/contents",
        "/api/shutdown",
        "/terminals/websocket/1",
        "/files/",
        "/lab",
    ):
        transport.routes[path] = {"status": 200, "body": "nope"}
    _install(monkeypatch, transport)
    MERCURY.run({}, _ctx(body=_mercury_html()))
    _assert_mercury_passive(transport)
    paths = [call[1] for call in transport.calls]
    assert paths == [MERCURY_TERMINALS]
    blob = " ".join(paths)
    for banned in _MERCURY_BANNED:
        assert banned not in blob


def test_mercury_at_most_one_get_and_never_mutates(monkeypatch):
    transport = Transport()
    transport.routes[MERCURY_TERMINALS] = {
        "status": 200,
        "content_type": "application/json",
        "body": '[{"name":"1","last_activity":"2026-08-21T12:00:00.000Z"}]',
    }
    _install(monkeypatch, transport)
    found = MERCURY.run({}, _ctx(body=_mercury_html()))
    _assert_mercury_passive(transport)
    assert [call[1] for call in transport.calls] == [MERCURY_TERMINALS]
    assert all(call[0] == "GET" for call in transport.calls)
    assert found and found[0]["severity"] == "critical"


def test_mercury_kill_switch_before_first_request_is_none(monkeypatch):
    def opener(_req, timeout=None):
        raise AssertionError("kill switch did not stop the request")

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(
        target="http://127.0.0.1:8081/", actor="tester",
        run_id="run_mercury_stop",
    )
    lease.stop()
    try:
        with control.scope(lease):
            with pytest.raises(control.ScanStopped):
                MERCURY.run({}, _ctx(body=_mercury_html()))
    finally:
        control.release(lease.run_id)


def test_mercury_get_is_audited(monkeypatch):
    seen = {"calls": 0, "methods": [], "data": []}

    def opener(req, timeout=None):
        seen["calls"] += 1
        seen["methods"].append(req.get_method())
        seen["data"].append(req.data)
        return _Resp(
            body=b"[]",
            headers=[("content-type", "application/json")],
        )

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(
        target="http://127.0.0.1:8081/", actor="tester",
        run_id="run_mercury_audit",
    )
    try:
        with control.scope(lease), control.agent("misconfig"):
            found = MERCURY.run({}, _ctx(body=_mercury_html()))
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
    assert MERCURY_TERMINALS in rows[-1]["url"]
    assert "body" not in rows[-1]
    assert "/api/kernels" not in rows[-1]["url"].lower()
    assert "websocket" not in rows[-1]["url"].lower()
    assert "/api/shutdown" not in rows[-1]["url"].lower()


def test_mercury_soft_404_json_object_is_not_terminal_finding(monkeypatch):
    transport = Transport()
    transport.routes[MERCURY_TERMINALS] = {
        "status": 200,
        "content_type": "application/json",
        "body": '{"error":"not found"}',
    }
    _install(monkeypatch, transport)
    assert MERCURY.run({}, _ctx(body=_mercury_html())) == []


def test_mercury_list_item_without_name_is_not_terminal_finding(monkeypatch):
    transport = Transport()
    transport.routes[MERCURY_TERMINALS] = {
        "status": 200,
        "content_type": "application/json",
        "body": '[{"last_activity":"2026-08-21T12:00:00.000Z"}]',
    }
    _install(monkeypatch, transport)
    assert MERCURY.run({}, _ctx(body=_mercury_html())) == []


def test_mercury_check_source_is_get_only_passive():
    text = (
        ROOT / "agents" / "cve_checks" / "mercury.py"
    ).read_text(encoding="utf-8")
    assert 'TERMINALS = "/api/terminals"' in text
    assert "fetch_path(ctx, TERMINALS" in text
    assert text.count("fetch_path(") == 1
    assert "root_observation" in text
    assert "post_brotli" not in text
    assert "urlopen" not in text
    assert "http.client" not in text
    assert "POST /api/terminals" in text or "Never POST" in text
    assert "/terminals/websocket" in text
    assert "/api/kernels" in text
    assert "/api/sessions" in text
    assert "/api/contents" in text
    assert "/api/shutdown" in text
    assert MERCURY.agent == "misconfig"
    assert MERCURY.cve == "CVE-2026-111057"
    assert MERCURY.id == "mercury"
    assert "3.2.11" in MERCURY.fixed
    assert "3.2.4" in MERCURY.fixed


# --- LiteLLM guardrail sandbox escape (CVE-2026-40217) ---------------------

_LITELLM_BANNED = (
    "/guardrails/test_custom_code",
    "/key/generate",
    "/config/update",
    "/chat/completions",
    "/key/",
    "/user/",
    "/team/",
    "/config/",
    "/model/new",
    "Authorization",
    "x-litellm-api-key",
)


def _litellm_html():
    return (
        "<!DOCTYPE html><html><head>"
        "<title>LiteLLM API - Swagger UI</title>"
        '<link rel="stylesheet" href="/swagger/swagger-ui.css">'
        '<link rel="icon" href="/swagger/favicon.png">'
        "</head><body>"
        "<div id=\"swagger-ui\"></div>"
        "<p>Proxy Server to call 100+ LLMs in the OpenAI format</p>"
        "<p>LiteLLM Admin Panel on /ui</p>"
        '<script src="/swagger/swagger-ui-bundle.js"></script>'
        "</body></html>"
    )


def _litellm_readiness(version: str) -> dict:
    return {
        "status": 200,
        "content_type": "application/json",
        "headers": {"content-type": "application/json"},
        "body": json.dumps({
            "status": "healthy",
            "db": "connected",
            "cache": None,
            "litellm_version": version,
            "success_callbacks": [],
        }),
    }


def _assert_litellm_passive(transport):
    assert all(call[0] == "GET" for call in transport.calls)
    assert all(call[2] is None and call[3] is False for call in transport.calls)
    for _method, path, _session, _follow in transport.calls:
        low = path.lower()
        for banned in _LITELLM_BANNED:
            assert banned.lower() not in low
        assert path == LITELLM_READINESS or not path.startswith("/guardrails")
        assert not path.startswith("/key")
        assert not path.startswith("/user")
        assert not path.startswith("/team")
        assert not path.startswith("/config")
        assert path != "/chat/completions"
        assert path != "/model/new"


@pytest.mark.parametrize("version", ["1.83.9", "1.81.8", "1.82.5", "1.83.10"])
def test_litellm_vulnerable_versions_are_high(monkeypatch, version):
    transport = Transport()
    transport.routes[LITELLM_READINESS] = _litellm_readiness(version)
    transport.routes["/guardrails/test_custom_code"] = {"status": 200, "body": "nope"}
    transport.routes["/key/generate"] = {"status": 200, "body": "nope"}
    transport.routes["/chat/completions"] = {"status": 200, "body": "nope"}
    _install(monkeypatch, transport)
    found = LITELLM_GUARDRAIL.run({}, _ctx(body=_litellm_html()))
    _assert_litellm_passive(transport)
    assert [call[1] for call in transport.calls] == [LITELLM_READINESS]
    assert len(found) == 1
    assert found[0]["severity"] == "high"
    assert found[0]["check"]["id"] == "litellm-guardrail"
    assert found[0]["check"]["match"] == f"litellm:{version}"
    assert UNCONFIRMED in found[0]["title"]
    assert "CVE-2026-40217" in found[0]["title"]
    assert "CISA KEV" in found[0]["evidence"] or "exploited in the wild" in found[0]["evidence"].lower()
    assert "proxy-admin" in found[0]["evidence"].lower()
    assert "1.83.11" in found[0]["fix"]
    assert "exploit" not in found[0]["title"].lower()
    assert "exploits" not in found[0]["evidence"].lower().replace("exploited", "")


@pytest.mark.parametrize("version", ["1.83.11", "1.84.0", "1.81.7", "1.80.0"])
def test_litellm_fixed_or_pre_intro_versions_are_none(monkeypatch, version):
    transport = Transport()
    transport.routes[LITELLM_READINESS] = _litellm_readiness(version)
    _install(monkeypatch, transport)
    found = LITELLM_GUARDRAIL.run({}, _ctx(body=_litellm_html()))
    _assert_litellm_passive(transport)
    assert [call[1] for call in transport.calls] == [LITELLM_READINESS]
    assert found == []


@pytest.mark.parametrize("status,body,content_type", [
    (401, '{"detail":"Unauthorized"}', "application/json"),
    (404, "Not Found", "text/plain"),
    (200, "<!DOCTYPE html><html><body>catch-all app shell</body></html>", "text/html"),
    (200, '{"status":"healthy","db":"connected"}', "application/json"),
])
def test_litellm_opaque_readiness_is_not_high(monkeypatch, status, body, content_type):
    transport = Transport()
    transport.routes[LITELLM_READINESS] = {
        "status": status,
        "content_type": content_type,
        "headers": {"content-type": content_type},
        "body": body,
    }
    _install(monkeypatch, transport)
    found = LITELLM_GUARDRAIL.run({}, _ctx(body=_litellm_html()))
    _assert_litellm_passive(transport)
    assert [call[1] for call in transport.calls] == [LITELLM_READINESS]
    assert all(item["severity"] != "high" for item in found)
    if found:
        assert found[0]["severity"] == "info"
        assert found[0]["check"]["match"] == "litellm:unknown"


def test_litellm_non_litellm_sends_nothing(monkeypatch):
    transport = Transport()
    transport.routes[LITELLM_READINESS] = _litellm_readiness("1.83.9")
    transport.routes["/guardrails/test_custom_code"] = {"status": 200, "body": "nope"}
    transport.routes["/chat/completions"] = {"status": 200, "body": "nope"}
    _install(monkeypatch, transport)
    assert LITELLM_GUARDRAIL.run(
        {}, _ctx(body="<html><body>hello litellm the library docs</body></html>")
    ) == []
    assert transport.calls == []


def test_litellm_fingerprint_markers(monkeypatch):
    transport = Transport()
    transport.routes[LITELLM_READINESS] = _litellm_readiness("1.83.11")
    _install(monkeypatch, transport)
    bodies = [
        "<title>LiteLLM API - Swagger UI</title>",
        "LiteLLM Admin Panel on /ui Create, Edit Keys with SSO",
        "Proxy Server to call 100+ LLMs in the OpenAI format",
        '<script src="/ui/_next/static/chunks/main.js"></script>',
        (
            '<title>LiteLLM API</title>'
            '<script src="/swagger/swagger-ui-bundle.js"></script>'
        ),
    ]
    for body in bodies:
        transport.calls.clear()
        assert LITELLM_GUARDRAIL.run({}, _ctx(body=body)) == []
        assert [call[1] for call in transport.calls] == [LITELLM_READINESS]


def test_litellm_never_requests_forbidden_paths(monkeypatch):
    transport = Transport()
    transport.routes[LITELLM_READINESS] = _litellm_readiness("1.83.9")
    for path in (
        "/guardrails/test_custom_code",
        "/key/generate",
        "/key/info",
        "/user/list",
        "/team/list",
        "/config/update",
        "/model/new",
        "/chat/completions",
    ):
        transport.routes[path] = {"status": 200, "body": "nope"}
    _install(monkeypatch, transport)
    LITELLM_GUARDRAIL.run({}, _ctx(body=_litellm_html()))
    _assert_litellm_passive(transport)
    paths = [call[1] for call in transport.calls]
    assert paths == [LITELLM_READINESS]
    blob = " ".join(paths)
    for banned in _LITELLM_BANNED:
        assert banned not in blob


def test_litellm_at_most_one_get_and_never_mutates(monkeypatch):
    transport = Transport()
    transport.routes[LITELLM_READINESS] = _litellm_readiness("1.81.8")
    _install(monkeypatch, transport)
    found = LITELLM_GUARDRAIL.run({}, _ctx(body=_litellm_html()))
    _assert_litellm_passive(transport)
    assert [call[1] for call in transport.calls] == [LITELLM_READINESS]
    assert all(call[0] == "GET" for call in transport.calls)
    assert found and found[0]["severity"] == "high"


def test_litellm_kill_switch_before_first_request_is_none(monkeypatch):
    def opener(_req, timeout=None):
        raise AssertionError("kill switch did not stop the request")

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(
        target="http://127.0.0.1:8081/", actor="tester",
        run_id="run_litellm_stop",
    )
    lease.stop()
    try:
        with control.scope(lease):
            with pytest.raises(control.ScanStopped):
                LITELLM_GUARDRAIL.run({}, _ctx(body=_litellm_html()))
    finally:
        control.release(lease.run_id)


def test_litellm_get_is_audited(monkeypatch):
    seen = {"calls": 0, "methods": [], "data": []}

    def opener(req, timeout=None):
        seen["calls"] += 1
        seen["methods"].append(req.get_method())
        seen["data"].append(req.data)
        headers = req.header_items() if hasattr(req, "header_items") else []
        header_blob = " ".join(f"{k}:{v}" for k, v in headers).lower()
        assert "authorization" not in header_blob
        assert "x-litellm-api-key" not in header_blob
        return _Resp(
            body=json.dumps({
                "status": "healthy",
                "db": "connected",
                "litellm_version": "1.83.9",
            }).encode(),
            headers=[("content-type", "application/json")],
        )

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(
        target="http://127.0.0.1:8081/", actor="tester",
        run_id="run_litellm_audit",
    )
    try:
        with control.scope(lease), control.agent("misconfig"):
            found = LITELLM_GUARDRAIL.run({}, _ctx(body=_litellm_html()))
    finally:
        control.release(lease.run_id)
    assert seen["calls"] == 1
    assert seen["methods"] == ["GET"]
    assert seen["data"] == [None]
    assert found and found[0]["severity"] == "high"
    import audit
    rows = [row for row in audit.recent(20) if row["kind"] == "request"]
    assert rows
    assert rows[-1]["action"] == "GET"
    assert rows[-1]["agent"] == "misconfig"
    assert LITELLM_READINESS in rows[-1]["url"]
    assert "body" not in rows[-1]
    assert "/guardrails/test_custom_code" not in rows[-1]["url"].lower()
    assert "/key/" not in rows[-1]["url"].lower()
    assert "/chat/completions" not in rows[-1]["url"].lower()


def test_litellm_affected_helper():
    from agents.cve_checks.litellm_guardrail import affected

    assert affected((1, 81, 8)) is True
    assert affected((1, 83, 9)) is True
    assert affected((1, 83, 10)) is True
    assert affected((1, 83, 11)) is False
    assert affected((1, 81, 7)) is False
    assert affected((1, 84, 0)) is False


def test_litellm_check_source_is_get_only_passive():
    text = (
        ROOT / "agents" / "cve_checks" / "litellm_guardrail.py"
    ).read_text(encoding="utf-8")
    assert 'READINESS = "/health/readiness"' in text
    assert "fetch_path(ctx, READINESS" in text
    assert text.count("fetch_path(") == 1
    assert "root_observation" in text
    assert "post_brotli" not in text
    assert "urlopen" not in text
    assert "http.client" not in text
    assert "/guardrails/test_custom_code" in text
    assert "/key/" in text
    assert "/chat/completions" in text
    assert "1.83.11" in text
    assert "1.83.10" in text  # discrepancy comment
    assert LITELLM_GUARDRAIL.agent == "misconfig"
    assert LITELLM_GUARDRAIL.cve == "CVE-2026-40217"
    assert LITELLM_GUARDRAIL.id == "litellm-guardrail"
    assert "1.83.11" in LITELLM_GUARDRAIL.fixed


# --- Apache Roller (CVE-2026-129448) ----------------------------------------

_ROLLER_BANNED = (
    "/roller-services/xmlrpc",
    "/roller/roller-services/xmlrpc",
    "/roller-ui/login",
    "/roller-ui/admin",
    "/roller-services/rest",
)


def _roller_html(version=None, *, ui=True, powered=True, generator=False, theme=False):
    parts = ['<!doctype html><html><head><title>blog</title>']
    if generator and version:
        parts.append(
            f'<meta name="generator" content="Apache Roller {version}" />'
        )
    elif generator:
        parts.append('<meta name="generator" content="Apache Roller" />')
    if ui:
        parts.append(
            '<link rel="stylesheet" href="/roller-ui/styles/roller.css" />'
            '<script src="/roller-ui/scripts/jquery4-summernote-compat.js"></script>'
        )
    if theme:
        parts.append(
            '<link rel="stylesheet" href="/themes/basic/basic-custom.css" />'
        )
        if version:
            parts.append(
                f'<link rel="stylesheet" href="/themes/gaurav/css/style.css?ver={version}" />'
            )
    parts.append("</head><body>")
    if powered and version:
        parts.append(
            'Powered by <a href="http://roller.apache.org">Apache Roller '
            f"Weblogger</a> Version {version} (build)"
        )
    elif powered:
        parts.append("Powered by Apache Roller")
    parts.append("</body></html>")
    return "".join(parts)


def _assert_roller_passive(transport):
    assert transport.calls == []
    blob = " ".join(call[1] for call in transport.calls)
    for banned in _ROLLER_BANNED:
        assert banned not in blob
    for banned in BANNED:
        assert banned not in blob


@pytest.mark.parametrize("version,flagged", [
    ("6.1.4", True),
    ("6.1.5", True),
    ("6.1.6", False),
    ("6.1.7", False),
    ("3.1", False),
    ("3.1.0", False),
    ("4.0.0", True),
    ("5.1.2", True),
])
def test_apache_roller_version_matrix(monkeypatch, version, flagged):
    transport = Transport()
    transport.routes["/roller-services/xmlrpc"] = {"status": 200, "body": "nope"}
    transport.routes["/roller/roller-services/xmlrpc"] = {"status": 200, "body": "nope"}
    transport.routes["/roller-ui/login.rol"] = {"status": 200, "body": "login"}
    _install(monkeypatch, transport)
    found = APACHE_ROLLER.run({}, _ctx(body=_roller_html(version)))
    _assert_roller_passive(transport)
    if flagged:
        assert len(found) == 1
        assert found[0]["severity"] == "critical"
        assert UNCONFIRMED in found[0]["title"]
        assert "CVE-2026-129448" in found[0]["title"]
        parts = tuple(int(x) for x in version.split("."))
        label = ".".join(str(p) for p in (parts + (0, 0, 0))[:3])
        assert found[0]["check"]["match"] == f"apache-roller:{label}"
        assert "CVE-2026-82384" in found[0]["evidence"]
        assert "exploited per apache" in found[0]["evidence"].lower()
        assert (
            "not listed in cisa kev" in found[0]["evidence"].lower()
            or "not in cisa kev" in found[0]["evidence"].lower()
        )
        assert "6.1.6" in found[0]["fix"]
        assert "enabledForExtensions" in found[0]["fix"]
        assert "exploit" not in found[0]["title"].lower()
        assert "exploits" not in found[0]["evidence"].lower().replace(
            "exploited", ""
        )
    else:
        assert found == []


def test_apache_roller_generator_meta_version(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    body = (
        '<html><head><meta name="generator" content="Apache Roller 6.1.4" />'
        "</head><body></body></html>"
    )
    found = APACHE_ROLLER.run({}, _ctx(body=body))
    _assert_roller_passive(transport)
    assert found and found[0]["severity"] == "critical"
    assert found[0]["check"]["match"] == "apache-roller:6.1.4"
    assert "generator meta" in found[0]["evidence"]


def test_apache_roller_asset_query_version(monkeypatch):
    transport = Transport()
    _install(monkeypatch, transport)
    found = APACHE_ROLLER.run(
        {},
        _ctx(body=_roller_html("6.1.5", powered=False, theme=True)),
    )
    _assert_roller_passive(transport)
    assert found and found[0]["severity"] == "critical"
    assert found[0]["check"]["match"] == "apache-roller:6.1.5"


def test_apache_roller_no_version_is_info(monkeypatch):
    transport = Transport()
    transport.routes["/roller-services/xmlrpc"] = {"status": 200, "body": "x"}
    _install(monkeypatch, transport)
    found = APACHE_ROLLER.run({}, _ctx(body=_roller_html(None)))
    _assert_roller_passive(transport)
    assert len(found) == 1
    assert found[0]["severity"] == "info"
    assert found[0]["check"]["match"] == "apache-roller:unknown"
    assert "version hidden" in found[0]["title"]
    assert "6.1.6" in found[0]["title"]
    assert "web.xml" in found[0]["title"]
    assert "CVE-2026-129448" in found[0]["title"]
    assert "not in CISA KEV" in found[0]["evidence"]


def test_apache_roller_non_roller_sends_nothing(monkeypatch):
    transport = Transport()
    transport.routes["/roller-services/xmlrpc"] = {"status": 200, "body": "x"}
    transport.routes["/roller/roller-services/xmlrpc"] = {"status": 200, "body": "x"}
    transport.routes["/roller-ui/login.rol"] = {"status": 200, "body": "x"}
    _install(monkeypatch, transport)
    assert APACHE_ROLLER.run(
        {}, _ctx(body="<html><body>hello roller derby</body></html>")
    ) == []
    assert transport.calls == []


@pytest.mark.parametrize("body", [
    '<link rel="stylesheet" href="/roller-ui/styles/roller.css" />',
    '<script src="/roller-ui/scripts/date-fields.js"></script>',
    '<a href="/roller-ui/menu.rol">Main Menu</a>',
    '<link rel="stylesheet" href="/themes/frontpage/x.css" />',
    '<link rel="stylesheet" href="/themes/hyde/theme.css" />',
    "Powered by Apache Roller",
    'Powered by <a href="http://roller.apache.org">Apache Roller Weblogger</a>',
    '<link rel="search" href="/roller-services/opensearch" />',
    "<generator>Apache Roller 6.1.5</generator>",
])
def test_apache_roller_fingerprint_markers(monkeypatch, body):
    transport = Transport()
    _install(monkeypatch, transport)
    found = APACHE_ROLLER.run({}, _ctx(body=f"<html><body>{body}</body></html>"))
    _assert_roller_passive(transport)
    # Markers without a version → info; feed generator body includes 6.1.5.
    if "6.1.5" in body and "generator" in body.lower():
        assert found and found[0]["severity"] == "critical"
    else:
        assert found and found[0]["severity"] == "info"


def test_apache_roller_never_requests_forbidden_paths(monkeypatch):
    transport = Transport()
    for path in _ROLLER_BANNED + (
        "/roller-ui/login.rol",
        "/roller-ui/admin/globalConfig.rol",
        "/roller-services/rest/weblogs",
    ):
        transport.routes[path] = {"status": 200, "body": "nope"}
    _install(monkeypatch, transport)
    APACHE_ROLLER.run({}, _ctx(body=_roller_html("6.1.4")))
    _assert_roller_passive(transport)
    paths = [call[1] for call in transport.calls]
    blob = " ".join(paths)
    for banned in _ROLLER_BANNED:
        assert banned not in blob


def test_apache_roller_kill_switch_makes_no_request(monkeypatch):
    def opener(_req, timeout=None):
        raise AssertionError("kill switch / Roller check must not open a socket")

    monkeypatch.setattr(recon._no_redirect_opener, "open", opener)
    lease = control.acquire(
        target="http://127.0.0.1:8081/", actor="tester",
        run_id="run_roller_stop",
    )
    lease.stop()
    try:
        with control.scope(lease):
            found = APACHE_ROLLER.run({}, _ctx(body=_roller_html("6.1.5")))
    finally:
        control.release(lease.run_id)
    # Passive HTML reuse: no outbound request, so kill switch never trips.
    assert found and found[0]["severity"] == "critical"


def test_apache_roller_get_only_and_audited_when_transport_used(monkeypatch):
    """Zero-request check: no GETs, so audit stays quiet for this check alone."""
    transport = Transport()
    _install(monkeypatch, transport)
    lease = control.acquire(
        target="http://127.0.0.1:8081/", actor="tester",
        run_id="run_roller_audit",
    )
    try:
        with control.scope(lease), control.agent("misconfig"):
            found = APACHE_ROLLER.run({}, _ctx(body=_roller_html("6.1.4")))
    finally:
        control.release(lease.run_id)
    assert transport.calls == []
    assert all(call[0] == "GET" for call in transport.calls)
    assert found and found[0]["severity"] == "critical"
    import audit
    rows = [
        row for row in audit.recent(20)
        if row["kind"] == "request" and row.get("run_id") == "run_roller_audit"
    ]
    assert rows == []


def test_apache_roller_check_source_is_passive_only():
    text = (
        ROOT / "agents" / "cve_checks" / "apache_roller.py"
    ).read_text(encoding="utf-8")
    assert "root_observation" in text
    assert "fetch_path" not in text
    assert "post_brotli" not in text
    assert "urlopen" not in text
    assert "http.client" not in text
    assert "/roller-services/xmlrpc" in text
    assert "/roller/roller-services/xmlrpc" in text
    assert "enabledForExtensions" in text
    assert APACHE_ROLLER.agent == "misconfig"
    assert APACHE_ROLLER.cve == "CVE-2026-129448"
    assert APACHE_ROLLER.id == "apache-roller"
    assert "6.1.6" in APACHE_ROLLER.fixed
    assert "No extra request" in APACHE_ROLLER.sends
    assert "xmlrpc" in APACHE_ROLLER.does_not_send.lower()


def test_apache_roller_affected_helper():
    from agents.cve_checks.apache_roller import affected

    assert affected((6, 1, 4)) is True
    assert affected((6, 1, 5)) is True
    assert affected((6, 1, 6)) is False
    assert affected((4, 0, 0)) is True
    assert affected((3, 1, 0)) is False
    assert affected((3, 1)) is False
