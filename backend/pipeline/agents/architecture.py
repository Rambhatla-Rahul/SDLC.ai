import json
from core.config import llm, ARCHITECTURE_PATTERNS, ARCHITECTURE_SCHEMA
from core.state import DevState, should_stop
from core.utils import extract_json, make_audit_entry


def architecture_agent(state: DevState) -> dict:
    if should_stop(state):
        print("[architecture_agent] pipeline stopped — skipping")
        return {}
    print("[architecture_agent] Starting")
    manifest      = state["intent_manifest"]
    compliance    = state["compliance_rules"]
    ip            = state["ip_clearance"]
    arch_feedback = state.get("arch_feedback", "")
    frameworks    = [f["name"] for f in compliance.get("applicable_frameworks", [])]
    pat_context   = "\n".join([f"{k}: {v['description']} | best_for: {v['best_for']}" for k, v in ARCHITECTURE_PATTERNS.items()])
    feedback_block = f"\nIMPORTANT - Reviewer instruction: {arch_feedback}\nYou MUST apply this." if arch_feedback else ""
    response = llm.invoke(
        f"You are a senior software architect.\n"
        f"Intent: {json.dumps(manifest)}"
        f"{feedback_block}\n"
        f"Compliance: {', '.join(frameworks)}\n"
        f"Rules: {json.dumps(compliance.get('consolidated_rules', []))}\n"
        f"Gaps: {json.dumps(compliance.get('gaps', []))}\n"
        f"IP risk: {ip.get('overall_risk')}\n"
        f"Patterns: {pat_context}\n"
        f"Select best pattern, define layers, map compliance rules, address all gaps.\n"
        f"Respond ONLY with valid JSON:\n{ARCHITECTURE_SCHEMA}"
    )
    arch = extract_json(response.text)
    print(f"[architecture_agent] Done — pattern: {arch.get('selected_pattern')}")
    return {
        "architecture": arch,
        "audit_log": [make_audit_entry("architecture_agent", f"Architecture — pattern: {arch.get('selected_pattern')}", {"pattern": arch.get("selected_pattern"), "gaps_addressed": arch.get("gaps_addressed", [])})],
    }