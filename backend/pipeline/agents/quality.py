import json
from core.config import llm, QUALITY_SCHEMA
from core.state import DevState, should_stop
from core.utils import extract_json, make_audit_entry


def run_local_quality_checks(state: DevState) -> dict:
    modules  = state["generated_code"].get("modules", [])
    manifest = state["intent_manifest"]
    security = state["security_report"]
    local_results = []
    for module in modules:
        filename, code = module.get("filename", "unknown"), module.get("code", "")
        local_results.append({"filename": filename, "test_name": "docstring_check",      "status": "pass" if ('"""' in code or "'''" in code) else "warning", "detail": "Docstrings present" if ('"""' in code or "'''" in code) else "No docstrings found"})
        local_results.append({"filename": filename, "test_name": "type_hint_check",      "status": "pass" if ("->" in code or ": str" in code or ": dict" in code) else "warning", "detail": "Type hints present" if ("->" in code or ": str" in code or ": dict" in code) else "No type hints"})
        local_results.append({"filename": filename, "test_name": "error_handling_check", "status": "pass" if ("try:" in code or "except" in code or "HTTPException" in code) else "warning", "detail": "Error handling present" if ("try:" in code or "except" in code or "HTTPException" in code) else "No error handling"})
        local_results.append({"filename": filename, "test_name": "async_check",          "status": "pass" if ("async def" in code or "await" in code) else "warning", "detail": "Async support present" if ("async def" in code or "await" in code) else "No async functions"})
    code_dump    = " ".join([m.get("code", "") for m in modules])
    keywords_map = {
        "register":      ["register", "signup", "UserCreate"],
        "log in":        ["login", "token", "create_access_token"],
        "dashboard":     ["dashboard", "protected", "Depends"],
        "postgresql":    ["postgresql", "asyncpg", "create_async_engine"],
        "authenticated": ["Depends", "get_current_user", "verify_token"],
        "persisted":     ["session", "db", "commit", "add"],
    }
    criteria_results = []
    for criterion in manifest.get("acceptance_criteria", []):
        matched, evidence = False, "not found in generated code"
        for keyword, signals in keywords_map.items():
            if keyword in criterion.lower():
                for signal in signals:
                    if signal in code_dump:
                        matched, evidence = True, f"'{signal}' found in generated code"
                        break
        criteria_results.append({"criterion": criterion, "status": "met" if matched else "partial", "evidence": evidence})
    critical_blockers = [f"{f['filename']}: {f['rule']}" for f in security.get("findings", []) if f["severity"] == "critical"]
    return {"local_results": local_results, "criteria_results": criteria_results, "critical_blockers": critical_blockers}


def quality_agent(state: DevState) -> dict:
    if should_stop(state):
        print("[quality_agent] pipeline stopped — skipping")
        return {}
    print("[quality_agent] Starting")
    manifest  = state["intent_manifest"]
    arch      = state["architecture"]
    code      = state["generated_code"]
    security  = state["security_report"]
    explain   = state["explainability_docs"]
    modules   = code.get("modules", [])
    local     = run_local_quality_checks(state)
    code_dump = "\n\n".join([f"### {m['filename']}\n{m['code']}" for m in modules])
    response  = llm.invoke(
        f"You are a senior quality engineer.\n"
        f"Acceptance Criteria: {json.dumps(manifest.get('acceptance_criteria', []))}\n"
        f"Architecture: {arch.get('selected_pattern')}\n"
        f"Code:\n{code_dump}\n"
        f"Local quality results: {json.dumps(local['local_results'])}\n"
        f"Acceptance pre-check: {json.dumps(local['criteria_results'])}\n"
        f"Security: overall_risk={security.get('overall_security_risk')}, passed={security.get('passed')}, "
        f"critical_count={sum(1 for f in security.get('findings', []) if f['severity'] == 'critical')}\n"
        f"Critical blockers: {json.dumps(local['critical_blockers'])}\n"
        f"Explainability: {len(explain.get('decision_log', []))} decisions, {len(explain.get('module_explanations', []))} modules\n"
        f"Score rubric: acceptance_criteria=30pts, code_quality=25pts, security=25pts, explainability=20pts\n"
        f"Set passed=true ONLY if score>=50 AND no critical findings.\n"
        f"Respond ONLY with valid JSON:\n{QUALITY_SCHEMA}"
    )
    report = extract_json(response.text)
    report["security_integration"] = {
        "security_findings_addressed": len(local["critical_blockers"]) == 0,
        "critical_blockers":           local["critical_blockers"],
        "ready_for_deploy":            len(local["critical_blockers"]) == 0 and report.get("overall_quality_score", 0) >= 50,
    }
    critical_count = sum(1 for f in security.get("findings", []) if f["severity"] == "critical")
    report["passed"] = critical_count == 0 and report.get("overall_quality_score", 0) >= 50
    score, passed   = report.get("overall_quality_score", 0), report.get("passed", False)
    print(f"[quality_agent] Done — score: {score}/100, passed: {passed}")
    return {
        "quality_report": report,
        "audit_log": [make_audit_entry("quality_agent", f"Quality — score: {score}/100 | passed: {passed}", {"score": score, "passed": passed, "critical_blockers": local["critical_blockers"]})],
    }