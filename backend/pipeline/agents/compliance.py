import json
from core.config import llm, COMPLIANCE_FRAMEWORKS, COMPLIANCE_SCHEMA
from core.state import DevState, should_stop
from core.utils import extract_json, make_audit_entry


def compliance_agent(state: DevState) -> dict:
    if should_stop(state):
        print("[compliance_agent] pipeline stopped — skipping")
        return {}
    print("[compliance_agent] Starting")
    manifest      = state["intent_manifest"]
    ip_clearance  = state["ip_clearance"]
    manifest_text = json.dumps(manifest).lower()
    triggered     = [k for k, fw in COMPLIANCE_FRAMEWORKS.items() if any(t in manifest_text for t in fw["triggers"])]
    fw_context    = "\n".join([
        f"{COMPLIANCE_FRAMEWORKS[k]['full_name']}:\n" + "\n".join(f"  - {r}" for r in COMPLIANCE_FRAMEWORKS[k]["rules"])
        for k in triggered
    ])
    response = llm.invoke(
        f"You are a regulatory compliance officer.\n"
        f"Manifest: {json.dumps(manifest)}\n"
        f"IP risk: {ip_clearance.get('overall_risk')}\n"
        f"Frameworks: {fw_context if fw_context else 'None detected'}\n"
        f"Respond ONLY with valid JSON:\n{COMPLIANCE_SCHEMA}"
    )
    rules    = extract_json(response.text)
    fw_names = [f["name"] for f in rules.get("applicable_frameworks", [])]
    print(f"[compliance_agent] Done — frameworks: {fw_names}")
    return {
        "compliance_rules": rules,
        "audit_log": [make_audit_entry("compliance_agent", f"Compliance mapped — frameworks: {', '.join(fw_names)}", {"frameworks": fw_names, "gaps_found": len(rules.get("gaps", []))})],
    }