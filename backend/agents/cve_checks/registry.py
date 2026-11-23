"""The check list. Append a module's CHECK here; the planner picks it up."""
from types import SimpleNamespace

from . import (
    acf_extended_pro,
    ai_engine,
    ai_engine_upload,
    amelia_pro,
    apache_mod_http2,
    apache_roller,
    automatorwp_webhooks,
    bricksforge,
    btcpay,
    commerce_core,
    confluence_axis,
    contact_form_7,
    craft_cms,
    dependency_files,
    dokan,
    drupal_install,
    estatik,
    gpustack_auth,
    gravity_forms,
    gravity_forms_chunked,
    langflow,
    latepoint,
    litellm_guardrail,
    magento,
    mercury,
    miniorange_otp,
    metabase,
    mlflow_gateway,
    monai_label,
    nextjs,
    nextjs_nov2026,
    nginx2root,
    ninja_forms_uploads,
    node_brotli,
    nodered,
    php2shell,
    php_nov2026,
    redcap,
    registration_form_woocommerce,
    rtmedia,
    slicewp,
    supabase_storage,
    ultra_addons_cf7,
    vite_dev_server,
    wedevs,
    wordpress,
    wp_data_access,
    wp_duplicate,
    wpforo,
    xen_orchestra,
    yootheme,
    masteriyo,
)
from .spec import CveCheck


CHECKS: tuple[CveCheck, ...] = (
    php2shell.CHECK,
    nextjs.CHECK,
    nextjs_nov2026.CHECK,
    node_brotli.CHECK,
    wedevs.CHECK,
    nodered.CHECK,
    wordpress.CHECK,
    dependency_files.CHECK,
    metabase.CHECK,
    langflow.CHECK,
    magento.CHECK,
    yootheme.CHECK,
    mlflow_gateway.CHECK,
    supabase_storage.CHECK,
    amelia_pro.CHECK,
    contact_form_7.CHECK,
    registration_form_woocommerce.CHECK,
    wp_duplicate.CHECK,
    gpustack_auth.CHECK,
    vite_dev_server.CHECK,
    latepoint.CHECK,
    xen_orchestra.CHECK,
    slicewp.CHECK,
    wp_data_access.CHECK,
    apache_mod_http2.CHECK,
    acf_extended_pro.CHECK,
    commerce_core.CHECK,
    gravity_forms.CHECK,
    gravity_forms_chunked.CHECK,
    craft_cms.CHECK,
    wpforo.CHECK,
    ninja_forms_uploads.CHECK,
    ai_engine.CHECK,
    ai_engine_upload.CHECK,
    masteriyo.CHECK,
    btcpay.CHECK,
    bricksforge.CHECK,
    automatorwp_webhooks.CHECK,
    estatik.CHECK,
    ultra_addons_cf7.CHECK,
    confluence_axis.CHECK,
    mercury.CHECK,
    litellm_guardrail.CHECK,
    drupal_install.CHECK,
    redcap.CHECK,
    apache_roller.CHECK,
    php_nov2026.CHECK,
    nginx2root.CHECK,
    monai_label.CHECK,
    rtmedia.CHECK,
    dokan.CHECK,
    miniorange_otp.CHECK,
)

_ids = [check.id for check in CHECKS]
if len(_ids) != len(set(_ids)):
    raise RuntimeError(f"duplicate CVE check id: {_ids}")

BY_ID = {check.id: check for check in CHECKS}


def plan_units(ctx) -> list[dict]:
    url = getattr(ctx, "url", "") or ""
    return [
        {
            "specialist": check.agent,
            "section": {"kind": "cve", "check_id": check.id, "url": url},
        }
        for check in CHECKS
    ]


def run(section, ctx) -> list[dict]:
    check = BY_ID.get((section or {}).get("check_id"))
    if check is None:
        return []
    return check.run(section or {}, ctx) or []


def verify_finding(chk: dict, url: str, session, fresh: dict) -> tuple[bool, str, str]:
    """Re-run a GET-based check. A one-shot probe is left unverified on purpose."""
    if chk.get("once"):
        return (
            False,
            "unverified",
            "single valid Brotli request was not repeated",
        )
    check = BY_ID.get(chk.get("id"))
    if check is None:
        return False, "unverified", "unknown cve check"
    ctx = SimpleNamespace(
        url=url,
        recon_root=fresh or {},
        surface={"json_endpoints": []},
        session=None,
        fingerprint={},
    )
    found = check.run({}, ctx) or []
    match = chk.get("match")
    for item in found:
        if (item.get("check") or {}).get("match") == match:
            return True, "confirmed", f"re-check still observes {match}"
    return False, "rejected", f"re-check no longer observes {match}"
