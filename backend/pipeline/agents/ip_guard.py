import json
from core.config import llm, KNOWN_LICENSES, IP_SCAN_SCHEMA
from core.state import DevState, should_stop
from core.utils import extract_json, make_audit_entry


def ip_guard_agent(state: DevState) -> dict:
    if should_stop(state):
        print("[ip_guard_agent] pipeline stopped — skipping")
        return {}
    print("[ip_guard_agent] Starting")
    manifest  = state["intent_manifest"]
    raw_libs  = []
    for module in manifest.get("modules", []):
        raw_libs.extend(module.get("tech_stack", []))
    raw_libs.extend(manifest.get("constraints", {}).get("ip_notes", []))
    local_flags = [
        f"{lib} ({KNOWN_LICENSES[lib.lower()]['license']} — copyleft)"
        for lib in raw_libs
        if lib.lower() in KNOWN_LICENSES and KNOWN_LICENSES[lib.lower()]["risk"] == "high"
    ]
    response  = llm.invoke(
        f"You are an IP compliance officer. Review: {json.dumps(raw_libs)}. "
        f"High-risk flags: {json.dumps(local_flags) if local_flags else 'None'}. "
        f"Respond ONLY with valid JSON:\n{IP_SCAN_SCHEMA}"
    )
    clearance = extract_json(response.text)
    print(f"[ip_guard_agent] Done — overall risk: {clearance.get('overall_risk')}")
    return {
        "ip_clearance": clearance,
        "audit_log": [make_audit_entry("ip_guard_agent", f"IP scan — risk: {clearance.get('overall_risk')}", {"overall_risk": clearance.get("overall_risk"), "flagged_items": clearance.get("flagged_items", [])})],
    }