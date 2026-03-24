import json
from core.config import llm, OPTIMIZER_SCHEMA
from core.state import DevState, should_stop
from core.utils import extract_json, make_audit_entry


def optimizer_agent(state: DevState) -> dict:
    if should_stop(state):
        print("[optimizer_agent] pipeline stopped — skipping")
        return {}
    print("[optimizer_agent] Starting")
    code      = state["generated_code"]
    security  = state.get("security_report") or {}
    quality   = state.get("quality_report")  or {}
    code_dump = "\n\n".join([f"### {m['filename']}\n{m['code']}" for m in code.get("modules", [])])
    try:
        response = llm.invoke(
            f"You are a senior Python engineer performing proactive code optimization.\n"
            f"Code:\n{code_dump}\n"
            f"Fix proactively: 1) Replace ALL hardcoded secrets with os.getenv() "
            f"2) Fix unlicensed jwt imports — use PyJWT 3) Add type hints "
            f"4) Add try/except with HTTPException 5) Disable echo=True 6) Add missing docstrings\n"
            f"Security findings: {json.dumps(security.get('findings', [])) if security else 'Not yet scanned'}\n"
            f"Quality issues: {json.dumps(quality.get('recommendations', [])) if quality else 'Not yet assessed'}\n"
            f"CRITICAL JSON RULES: escape ALL double quotes inside code as \\\". "
            f"Do NOT use actual newlines inside string values.\n"
            f"IMPORTANT: rewritten_modules must contain COMPLETE rewritten file code with ALL fixes applied.\n"
            f"Respond ONLY with valid JSON:\n{OPTIMIZER_SCHEMA}"
        )
        opts = extract_json(response.text)
    except Exception as e:
        print(f"[optimizer_agent] JSON parse failed — skipping optimization: {e}")
        return {
            "generated_code": code,
            "audit_log": [make_audit_entry("optimizer_agent", "Optimization skipped — JSON parse error", {"error": str(e)})],
        }
    rewritten_map   = {r["filename"]: r["code"] for r in opts.get("rewritten_modules", [])}
    updated_modules = []
    for module in code.get("modules", []):
        updated = module.copy()
        if module["filename"] in rewritten_map:
            updated["code"]           = rewritten_map[module["filename"]]
            updated["code_optimized"] = True
        module_opts = [o for o in opts.get("optimizations", []) if o.get("filename") == module["filename"]]
        if module_opts:
            updated["optimizations_applied"] = module_opts
        updated_modules.append(updated)
    print(f"[optimizer_agent] Done — {len(opts.get('optimizations', []))} optimizations, files rewritten: {list(rewritten_map.keys())}")
    return {
        "generated_code": {**code, "modules": updated_modules},
        "audit_log": [make_audit_entry("optimizer_agent", f"Optimization — {len(opts.get('optimizations', []))} improvements | tech debt: {opts.get('tech_debt_score')}/100", {"optimizations": len(opts.get("optimizations", [])), "files_rewritten": list(rewritten_map.keys())})],
    }