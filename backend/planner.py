"""
PLAN phase — pair sections with the specialists relevant to them.

A work unit = {"specialist": name, "section": {...}}. The orchestrator runs these in
parallel. This is where "agents focused on specific sections" becomes concrete, and
where stack-awareness lives (e.g. PHP targets get the php-flavored injection checks).
"""
MAX_INJECTION_UNITS = 20


def plan(ctx) -> list[dict]:
    units: list[dict] = []
    surface = ctx.surface

    # site-wide specialists: one unit each, pointed at the root
    units.append({"specialist": "config_headers", "section": {"kind": "site", "url": ctx.url}})
    units.append({"specialist": "exposed_paths", "section": {"kind": "site", "url": ctx.url}})

    # injection specialist: one unit per discovered input/param (bounded)
    inj = 0
    for f in surface.get("forms", []):
        for name in f.get("inputs", []):
            if inj >= MAX_INJECTION_UNITS:
                break
            units.append({"specialist": "injection", "section": {
                "kind": "form_param", "url": f["action"], "method": f["method"],
                "param": name, "inputs": f["inputs"],
            }})
            inj += 1
    for p in surface.get("params", []):
        if inj >= MAX_INJECTION_UNITS:
            break
        units.append({"specialist": "injection", "section": {
            "kind": "query_param", "url": p["page"], "method": "get", "param": p["param"],
        }})
        inj += 1

    return units
