import re
import json
from core.config import llm, SECURITY_RULES, SECURITY_SCHEMA
from core.state import DevState, should_stop
from core.utils import extract_json, make_audit_entry


def run_local_security_scan(modules: list, ip_clearance: dict) -> list:
    cleared_libs = {lib["name"].lower() for lib in ip_clearance.get("scanned_libraries", [])}
    stdlib = {
        "os", "sys", "re", "json", "datetime", "typing", "pathlib", "hashlib",
        "hmac", "secrets", "logging", "functools", "itertools", "collections",
        "abc", "enum", "pydantic", "starlette", "asyncpg", "sqlalchemy",
        "alembic", "pytest", "httpx", "uvicorn", "fastapi",
    }
    findings = []
    for module in modules:
        filename, code = module.get("filename", "unknown"), module.get("code", "")
        for rule_name, rule in SECURITY_RULES.items():
            if rule["pattern"] is None:
                continue
            matches = re.findall(rule["pattern"], code, re.MULTILINE)
            if matches:
                findings.append({"filename": filename, "rule": rule_name, "severity": rule["severity"], "owasp_ref": rule["owasp"], "line_hint": str(matches[0])[:120], "fix": rule["fix"], "source": "local_scan"})
        for imp in re.findall(r'^(?:import|from)\s+(\w+)', code, re.MULTILINE):
            if imp.lower() not in stdlib and imp.lower() not in cleared_libs:
                findings.append({"filename": filename, "rule": "unlicensed_import", "severity": "high", "owasp_ref": "IP Compliance", "line_hint": f"import {imp}", "fix": f"'{imp}' was not IP-cleared — verify license before use", "source": "local_scan"})
    return findings


def check_compliance_tag_coverage(modules: list) -> dict:
    files_with, files_without = [], []
    for module in modules:
        (files_with if re.search(r'#\s*\[(GDPR|OWASP|HIPAA|PCI)', module.get("code", "")) else files_without).append(module.get("filename", "unknown"))
    total = len(modules)
    return {"files_with_tags": len(files_with), "files_without_tags": files_without, "coverage_percent": round((len(files_with) / total * 100) if total > 0 else 0, 1)}


def security_agent(state: DevState) -> dict:
    if should_stop(state):
        print("[security_agent] pipeline stopped — skipping")
        return {}
    print("[security_agent] Starting")
    modules        = state["generated_code"].get("modules", [])
    ip_clearance   = state["ip_clearance"]
    local_findings = run_local_security_scan(modules, ip_clearance)
    tag_coverage   = check_compliance_tag_coverage(modules)
    code_dump      = "\n\n".join([f"### {m['filename']}\n{m['code']}" for m in modules])
    response       = llm.invoke(
        f"You are a senior application security engineer performing a code review.\n"
        f"Code:\n{code_dump}\n"
        f"Local findings: {json.dumps(local_findings)}\n"
        f"IP Cleared: {json.dumps([lib['name'] for lib in ip_clearance.get('scanned_libraries', [])])}\n"
        f"Set passed=true ONLY if zero critical findings.\n"
        f"Respond ONLY with valid JSON:\n{SECURITY_SCHEMA}"
    )
    report        = extract_json(response.text)
    existing_keys = {(f["filename"], f["rule"]) for f in report.get("findings", [])}
    for lf in local_findings:
        if (lf["filename"], lf["rule"]) not in existing_keys:
            report.setdefault("findings", []).append(lf)
    report["compliance_tag_coverage"] = tag_coverage
    findings       = report.get("findings", [])
    critical_count = sum(1 for f in findings if f["severity"] == "critical")
    high_count     = sum(1 for f in findings if f["severity"] == "high")
    report["passed"] = critical_count == 0
    passed         = report["passed"]
    overall_risk   = report.get("overall_security_risk", "unknown")
    print(f"[security_agent] Done — risk: {overall_risk}, passed: {passed}, retries: {state.get('security_retries', 0)}")
    return {
        "security_report": report,
        "audit_log": [make_audit_entry("security_agent", f"Security scan — risk: {overall_risk} | findings: {len(findings)} (critical: {critical_count}, high: {high_count}) | passed: {passed}", {"total_findings": len(findings), "critical": critical_count, "high": high_count, "passed": passed, "overall_risk": overall_risk, "tag_coverage": tag_coverage["coverage_percent"]})],
    }