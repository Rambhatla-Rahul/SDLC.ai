import json
from core.config import llm, CODEGEN_SCHEMA
from core.state import DevState, should_stop
from core.utils import extract_json, make_audit_entry


def codegen_agent(state: DevState) -> dict:
    if should_stop(state):
        print("[codegen_agent] pipeline stopped — skipping")
        return {}
    current_retries = state.get("security_retries", 0)
    print(f"[codegen_agent] Starting — security_retries so far: {current_retries}")
    manifest   = state["intent_manifest"]
    arch       = state["architecture"]
    compliance = state["compliance_rules"]
    ip         = state["ip_clearance"]
    response   = llm.invoke(
        f"You are a senior Python engineer generating complete end to end production-grade code.\n"
        f"Intent: {json.dumps(manifest)}\n"
        f"Architecture: {arch.get('selected_pattern')}\n"
        f"Layers: {json.dumps([l['name'] for l in arch.get('layers', [])])}\n"
        f"Infrastructure: {json.dumps(arch.get('infrastructure', {}))}\n"
        f"Security Controls: {json.dumps(arch.get('security_controls', []))}\n"
        f"Compliance Rules: {json.dumps(compliance.get('consolidated_rules', []))}\n"
        f"IP Cleared Libraries: {json.dumps([lib['name'] for lib in ip.get('scanned_libraries', [])])}\n"
        f"CRITICAL: Use os.getenv() for ALL secrets. Add type hints. Add try/except. "
        f"Add # [GDPR] / # [OWASP] inline comments. Add docstrings. Implement ALL acceptance criteria endpoints.\n"
        f"Respond ONLY with valid JSON:\n{CODEGEN_SCHEMA}"
    )
    code    = extract_json(response.text)
    modules = code.get("modules", [])
    print(f"[codegen_agent] Done — {len(modules)} files generated: {[m['filename'] for m in modules]}")
    return {
        "generated_code":   code,
        "security_retries": current_retries + 1,
        "audit_log": [make_audit_entry("codegen_agent", f"Code generated — {len(modules)} files", {"files_generated": [m["filename"] for m in modules]})],
    }