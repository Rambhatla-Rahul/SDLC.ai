import json
from core.config import llm, EXPLAINABILITY_SCHEMA
from core.state import DevState, should_stop
from core.utils import extract_json, make_audit_entry


def explainability_agent(state: DevState) -> dict:
    if should_stop(state):
        print("[explainability_agent] pipeline stopped — skipping")
        return {}
    print("[explainability_agent] Starting")
    manifest   = state["intent_manifest"]
    arch       = state["architecture"]
    compliance = state["compliance_rules"]
    code       = state["generated_code"]
    security   = state["security_report"]
    decisions  = state["hitl_decisions"] or []
    hitl_trail = [
        {"gate": d.get("gate"), "choice": d.get("choice"), "approver": d.get("approver"), "notes": d.get("extra_notes") or d.get("feedback") or "none", "risks_acknowledged": d.get("risk_acknowledged", False)}
        for d in decisions
    ]
    response = llm.invoke(
        f"You are a technical documentation specialist producing an explainability report "
        f"for non-technical stakeholders, regulators, and auditors.\n"
        f"Intent: {state['raw_input']}\n"
        f"Manifest: {json.dumps(manifest)}\n"
        f"Architecture: pattern={arch.get('selected_pattern')}, layers={json.dumps([l['name'] for l in arch.get('layers', [])])}\n"
        f"Compliance frameworks: {json.dumps([f['name'] for f in compliance.get('applicable_frameworks', [])])}\n"
        f"Files: {json.dumps([{'filename': m['filename'], 'layer': m['layer'], 'description': m['description']} for m in code.get('modules', [])])}\n"
        f"Security findings: {json.dumps(security.get('findings', []))}\n"
        f"Human review trail: {json.dumps(hitl_trail)}\n"
        f"Respond ONLY with valid JSON:\n{EXPLAINABILITY_SCHEMA}"
    )
    docs = extract_json(response.text)
    print(f"[explainability_agent] Done — {len(docs.get('decision_log', []))} decisions")
    return {
        "explainability_docs": docs,
        "audit_log": [make_audit_entry("explainability_agent", f"Explainability docs — {len(docs.get('decision_log', []))} decisions", {"decisions_documented": len(docs.get("decision_log", []))})],
    }