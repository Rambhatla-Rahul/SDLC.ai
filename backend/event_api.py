import os
import re
import json
import hashlib
import operator
import asyncio
from datetime import datetime, timezone
from typing import Dict, List, Optional, Annotated, TypedDict, Any
from uuid import uuid4

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver
from langchain_ollama import ChatOllama


load_dotenv()

llm = ChatGoogleGenerativeAI(
    model="gemini-3.1-flash-lite-preview",
    api_key=os.getenv("GEMINI_API_KEY"),
    temperature=0.1,
)

code_gen_llm = ChatOllama(
    model="qwen3.5:9b",
    temperature=0.1,
)

app = FastAPI(title="AI-Native Dev Pipeline", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ConnectionManager:
    def __init__(self):
        self._connections: Dict[str, WebSocket] = {}

    async def connect(self, thread_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections[thread_id] = websocket
        print(f"[ws] Client connected: {thread_id}")

    def disconnect(self, thread_id: str) -> None:
        self._connections.pop(thread_id, None)
        print(f"[ws] Client disconnected: {thread_id}")

    async def send(self, thread_id: str, data: dict) -> bool:
        ws = self._connections.get(thread_id)
        if not ws:
            return False
        try:
            await ws.send_json(data)
            return True
        except Exception as e:
            print(f"[ws] Send error for {thread_id}: {e}")
            self.disconnect(thread_id)
            return False

    def is_connected(self, thread_id: str) -> bool:
        return thread_id in self._connections


ws_manager = ConnectionManager()

pipeline_queues:        Dict[str, asyncio.Queue]  = {}
pipeline_resume_events: Dict[str, asyncio.Event]  = {}
pipeline_tasks:         Dict[str, asyncio.Task]   = {}
pipeline_meta:          Dict[str, Dict[str, Any]] = {}


class DevState(TypedDict):
    raw_input:           str
    intent_manifest:     Optional[Dict]
    compliance_rules:    Optional[Dict]
    ip_clearance:        Optional[Dict]
    architecture:        Optional[Dict]
    generated_code:      Optional[Dict]
    explainability_docs: Optional[Dict]
    security_report:     Optional[Dict]
    quality_report:      Optional[Dict]
    hitl_decisions:      Optional[List]
    audit_log:           Annotated[List[Dict], operator.add]
    drift_alerts:        Optional[List]
    security_retries:    int
    arch_feedback:       Optional[str]


class RunRequest(BaseModel):
    raw_input: str


class HITLDecisionRequest(BaseModel):
    choice:            str
    approver:          str
    role:              Optional[str] = ""
    feedback:          Optional[str] = None
    extra_notes:       Optional[str] = None
    justification:     Optional[str] = None
    risk_acknowledged: Optional[bool] = False


def extract_json(text: str) -> dict:
    if hasattr(text, "text"):
        text = text.text
    if not isinstance(text, str):
        text = str(text)
    
    text = re.sub(r"```(?:json)?", "", text).replace("```", "").strip()
    
    # try direct parse first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    
    # try finding outermost { } block
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ValueError(f"No JSON found in response:\n{text[:500]}")
    
    try:
        return json.loads(match.group())
    except json.JSONDecodeError:
        pass
    
    # last resort — use raw_decode to get the first valid JSON object
    decoder = json.JSONDecoder()
    start   = text.find("{")
    if start == -1:
        raise ValueError(f"No JSON object found:\n{text[:500]}")
    try:
        obj, _ = decoder.raw_decode(text, start)
        return obj
    except json.JSONDecodeError as e:
        raise ValueError(f"JSON parse failed: {e}\nText preview:\n{text[:500]}")


def make_audit_entry(agent: str, summary: str, data: dict) -> dict:

    return {
        "agent":     agent,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary":   summary,
        "data":      data,
}


def compute_hash(data) -> str:
    return hashlib.md5(json.dumps(data, sort_keys=True, default=str).encode()).hexdigest()


def get_config(thread_id: str) -> dict:
    return {"configurable": {"thread_id": thread_id}}


def should_stop(state: DevState) -> bool:
    return state.get("pipeline_stopped", False)


def get_gate_context(state_values: dict, gate: str) -> dict:
    if gate == "hitl_gate_1":
        return {
            "intent_manifest": state_values.get("intent_manifest"),
            "ip_clearance":    state_values.get("ip_clearance"),
        }
    if gate == "hitl_gate_2":
        return {
            "architecture":     state_values.get("architecture"),
            "compliance_rules": state_values.get("compliance_rules"),
        }
    if gate == "hitl_gate_3":
        return {
            "security_report": state_values.get("security_report"),
            "quality_report":  state_values.get("quality_report"),
            "architecture":    state_values.get("architecture"),
        }
    return {}


def get_node_summary(node_name: str, node_output: dict) -> dict:
    try:
        extractors = {
            "intent_agent":         lambda o: {"app_type": o.get("intent_manifest", {}).get("app_type"), "modules": len(o.get("intent_manifest", {}).get("modules", []))},
            "ip_guard_agent":       lambda o: {"overall_risk": o.get("ip_clearance", {}).get("overall_risk"), "flagged": len(o.get("ip_clearance", {}).get("flagged_items", []))},
            "compliance_agent":     lambda o: {"frameworks": [f["name"] for f in o.get("compliance_rules", {}).get("applicable_frameworks", [])], "risk": o.get("compliance_rules", {}).get("overall_compliance_risk")},
            "architecture_agent":   lambda o: {"pattern": o.get("architecture", {}).get("selected_pattern"), "layers": len(o.get("architecture", {}).get("layers", []))},
            "codegen_agent":        lambda o: {"files": [m["filename"] for m in o.get("generated_code", {}).get("modules", [])]},
            "optimizer_agent":      lambda o: {"optimizations": sum(len(m.get("optimizations_applied", [])) for m in o.get("generated_code", {}).get("modules", []))},
            "security_agent":       lambda o: {"risk": o.get("security_report", {}).get("overall_security_risk"), "findings": len(o.get("security_report", {}).get("findings", [])), "passed": o.get("security_report", {}).get("passed")},
            "explainability_agent": lambda o: {"decisions": len(o.get("explainability_docs", {}).get("decision_log", [])), "modules": len(o.get("explainability_docs", {}).get("module_explanations", []))},
            "quality_agent":        lambda o: {"score": o.get("quality_report", {}).get("overall_quality_score"), "passed": o.get("quality_report", {}).get("passed")},
            "audit_agent":          lambda o: {"final_status": (o.get("quality_report") or {}).get("final_audit", {}).get("final_status")},
        }
        fn = extractors.get(node_name)
        return fn(node_output) if fn else {}
    except Exception:
        return {}


KNOWN_LICENSES = {
    "fastapi":    {"license": "MIT",        "risk": "low"},
    "sqlalchemy": {"license": "MIT",        "risk": "low"},
    "pydantic":   {"license": "MIT",        "risk": "low"},
    "uvicorn":    {"license": "BSD",        "risk": "low"},
    "postgresql": {"license": "PostgreSQL", "risk": "low"},
    "alembic":    {"license": "MIT",        "risk": "low"},
    "passlib":    {"license": "BSD",        "risk": "low"},
    "jose":       {"license": "MIT",        "risk": "low"},
    "httpx":      {"license": "BSD",        "risk": "low"},
    "starlette":  {"license": "BSD",        "risk": "low"},
    "asyncpg":    {"license": "Apache-2.0", "risk": "low"},
    "pyjwt":      {"license": "MIT",        "risk": "low"},
    "jinja2":     {"license": "BSD",        "risk": "low"},
    "celery":     {"license": "BSD",        "risk": "low"},
    "redis":      {"license": "BSD",        "risk": "low"},
    "gpl":        {"license": "GPL",        "risk": "high"},
    "mysql":      {"license": "GPL",        "risk": "high"},
}

COMPLIANCE_FRAMEWORKS = {
    "gdpr": {
        "full_name": "General Data Protection Regulation",
        "triggers":  ["user data", "login", "personal data", "email", "profile", "authentication"],
        "rules": [
            "User data must be encrypted at rest and in transit",
            "Users must be able to request data deletion",
            "Explicit consent required before data collection",
            "Data breach notification within 72 hours",
            "Minimal data collection principle must be followed",
        ],
    },
    "owasp": {
        "full_name": "OWASP Top 10",
        "triggers":  ["login", "authentication", "api", "web", "dashboard", "jwt", "password"],
        "rules": [
            "Protect against SQL injection via parameterised queries",
            "Implement proper session management and token expiry",
            "Enforce HTTPS and secure cookie flags",
            "Rate limit authentication endpoints",
            "Validate and sanitise all user inputs",
        ],
    },
    "hipaa": {
        "full_name": "Health Insurance Portability and Accountability Act",
        "triggers":  ["health", "medical", "patient", "diagnosis", "prescription"],
        "rules": [
            "PHI must be encrypted at rest and in transit",
            "Access logs must be maintained for all PHI access",
            "Role-based access control for all health data",
        ],
    },
    "pci_dss": {
        "full_name": "Payment Card Industry Data Security Standard",
        "triggers":  ["payment", "card", "billing", "checkout", "stripe", "transaction"],
        "rules": [
            "Card data must never be stored in plaintext",
            "Use tokenisation for all payment data",
            "Strict access control to cardholder data",
        ],
    },
}

ARCHITECTURE_PATTERNS = {
    "layered":          {"description": "Traditional N-tier",                                       "best_for": ["web apps", "dashboards"],    "trade_offs": {"scalability": "medium", "complexity": "low",  "security": "high"}},
    "microservices":    {"description": "Independent services via APIs",                            "best_for": ["large teams", "high scale"], "trade_offs": {"scalability": "high",   "complexity": "high", "security": "medium"}},
    "modular_monolith": {"description": "Single deployable with strict internal module boundaries", "best_for": ["small teams", "early stage"],"trade_offs": {"scalability": "medium", "complexity": "low",  "security": "high"}},
}

SECURITY_RULES = {
    "hardcoded_secrets": {"pattern": r'(SECRET_KEY|PASSWORD|API_KEY|TOKEN|secret|password)\s*=\s*["\'][^"\']+["\']', "severity": "critical", "owasp": "A02:2021 Cryptographic Failures",    "fix": "Move to environment variables"},
    "sql_injection":     {"pattern": r'execute\s*\(\s*[f"\'].*\{',                                                  "severity": "critical", "owasp": "A03:2021 Injection",                  "fix": "Use SQLAlchemy ORM or parameterized queries"},
    "debug_mode":        {"pattern": r'DEBUG\s*=\s*True|reload\s*=\s*True',                                         "severity": "high",     "owasp": "A05:2021 Security Misconfiguration",  "fix": "Disable debug/reload in production"},
    "http_not_https":    {"pattern": r'http://(?!localhost|127\.0\.0\.1)',                                           "severity": "high",     "owasp": "A02:2021 Cryptographic Failures",    "fix": "Use HTTPS for all external URLs"},
    "bare_except":       {"pattern": r'except\s*:',                                                                 "severity": "medium",   "owasp": "A09:2021 Security Logging Failures", "fix": "Catch specific exceptions"},
    "unlicensed_import": {"pattern": None,                                                                           "severity": "high",     "owasp": "IP Compliance",                      "fix": "Use only IP-cleared libraries"},
}

INTENT_SCHEMA         = '{"app_type":"string","modules":[{"name":"string","description":"string","tech_stack":["string"]}],"constraints":{"security":["string"],"compliance":["string"],"performance":["string"],"ip_notes":["string"]},"acceptance_criteria":["string"]}'
IP_SCAN_SCHEMA        = '{"scanned_libraries":[{"name":"string","license":"string","risk_level":"low|medium|high","reason":"string"}],"overall_risk":"low|medium|high","flagged_items":["string"],"recommendation":"string"}'
COMPLIANCE_SCHEMA     = '{"applicable_frameworks":[{"name":"string","reason":"string","rules":["string"],"priority":"mandatory|recommended"}],"consolidated_rules":[{"rule":"string","framework":"string","implementation_hint":"string"}],"gaps":["string"],"overall_compliance_risk":"low|medium|high"}'
ARCHITECTURE_SCHEMA   = '{"selected_pattern":"string","pattern_rationale":"string","layers":[{"name":"string","responsibility":"string","components":["string"],"tech":["string"],"compliance_controls":["string"]}],"infrastructure":{"database":"string","cache":"string","tls":"string","rate_limiter":"string","audit_store":"string"},"security_controls":["string"],"trade_off_matrix":{"scalability":"low|medium|high","complexity":"low|medium|high","security":"low|medium|high","compliance_fit":"low|medium|high"},"gaps_addressed":["string"],"residual_risks":["string"]}'
CODEGEN_SCHEMA        = '{"modules":[{"filename":"string","layer":"string","description":"string","rationale":"string","compliance_controls":["string"],"code":"string"}],"project_structure":["string"],"setup_instructions":["string"],"dependencies":["string"]}'
OPTIMIZER_SCHEMA      = '{"optimizations":[{"filename":"string","type":"performance|readability|security|tech_debt","original":"string","improved":"string","reason":"string"}],"rewritten_modules":[{"filename":"string","code":"string"}],"tech_debt_score":"number","summary":"string"}'
SECURITY_SCHEMA       = '{"findings":[{"filename":"string","rule":"string","severity":"critical|high|medium|low","owasp_ref":"string","line_hint":"string","fix":"string"}],"unlicensed_imports":["string"],"compliance_tag_coverage":{"files_with_tags":"number","files_without_tags":["string"],"coverage_percent":"number"},"overall_security_risk":"critical|high|medium|low","passed":"boolean","summary":"string"}'
QUALITY_SCHEMA        = '{"test_results":[{"filename":"string","test_name":"string","status":"pass|fail|warning","detail":"string"}],"acceptance_criteria_check":[{"criterion":"string","status":"met|not_met|partial","evidence":"string"}],"code_quality":{"has_docstrings":"boolean","has_type_hints":"boolean","has_error_handling":"boolean","has_async_support":"boolean","missing_docstrings_in":["string"],"missing_error_handling_in":["string"]},"security_integration":{"security_findings_addressed":"boolean","critical_blockers":["string"],"ready_for_deploy":"boolean"},"overall_quality_score":"number","passed":"boolean","recommendations":["string"],"summary":"string"}'
EXPLAINABILITY_SCHEMA = '{"decision_log":[{"decision_point":"string","what_was_decided":"string","why":"string","alternatives_considered":["string"],"trade_offs_accepted":["string"],"constraint_satisfied":["string"]}],"module_explanations":[{"filename":"string","purpose":"string","key_decisions":["string"],"compliance_mapping":["string"]}],"glossary":[{"term":"string","plain_english":"string"}],"audit_narrative":"string"}'


def intent_agent(state: DevState) -> dict:
    print(state["raw_input"])
    if should_stop(state):
        print("[intent_agent] pipeline stopped — skipping")
        return {}
    print("[intent_agent] Starting")
    prompt = f"""
You are an AI software architect. Convert the user description into a structured intent manifest.

IMPORTANT: If there is a [Human modification] or [HITL feedback] section below,
you MUST follow those instructions and they override everything else.
If told to use PostgreSQL, use PostgreSQL — not MongoDB.
The modification is a hard requirement, not a suggestion.

User input:
{state["raw_input"]}

Respond ONLY with valid JSON, no explanation, no markdown:
{INTENT_SCHEMA}
"""
    response = llm.invoke(prompt)
    manifest = extract_json(response.text)
    print(f"[intent_agent] Done — app_type: {manifest.get('app_type')}, modules: {[m['name'] for m in manifest.get('modules', [])]}")
    return {
        "intent_manifest": manifest,
        "audit_log": [make_audit_entry("intent_agent", f"Parsed intent for: {state['raw_input'][:80]}", {"app_type": manifest.get("app_type")})],
    }


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
    local_flags = [f"{lib} ({KNOWN_LICENSES[lib.lower()]['license']} — copyleft)" for lib in raw_libs if lib.lower() in KNOWN_LICENSES and KNOWN_LICENSES[lib.lower()]["risk"] == "high"]
    response  = llm.invoke(f"You are an IP compliance officer. Review: {json.dumps(raw_libs)}. High-risk flags: {json.dumps(local_flags) if local_flags else 'None'}. Respond ONLY with valid JSON:\n{IP_SCAN_SCHEMA}")
    clearance = extract_json(response.text)
    print(f"[ip_guard_agent] Done — overall risk: {clearance.get('overall_risk')}")
    return {
        "ip_clearance": clearance,
        "audit_log": [make_audit_entry("ip_guard_agent", f"IP scan — risk: {clearance.get('overall_risk')}", {"overall_risk": clearance.get("overall_risk"), "flagged_items": clearance.get("flagged_items", [])})],
    }


def compliance_agent(state: DevState) -> dict:
    if should_stop(state):
        print("[compliance_agent] pipeline stopped — skipping")
        return {}
    print("[compliance_agent] Starting")
    manifest      = state["intent_manifest"]
    ip_clearance  = state["ip_clearance"]
    manifest_text = json.dumps(manifest).lower()
    triggered     = [k for k, fw in COMPLIANCE_FRAMEWORKS.items() if any(t in manifest_text for t in fw["triggers"])]
    fw_context    = "\n".join([f"{COMPLIANCE_FRAMEWORKS[k]['full_name']}:\n" + "\n".join(f"  - {r}" for r in COMPLIANCE_FRAMEWORKS[k]["rules"]) for k in triggered])
    response      = llm.invoke(f"You are a regulatory compliance officer.\nManifest: {json.dumps(manifest)}\nIP risk: {ip_clearance.get('overall_risk')}\nFrameworks: {fw_context if fw_context else 'None detected'}\nRespond ONLY with valid JSON:\n{COMPLIANCE_SCHEMA}")
    rules         = extract_json(response.text)
    fw_names      = [f["name"] for f in rules.get("applicable_frameworks", [])]
    print(f"[compliance_agent] Done — frameworks: {fw_names}")
    return {
        "compliance_rules": rules,
        "audit_log": [make_audit_entry("compliance_agent", f"Compliance mapped — frameworks: {', '.join(fw_names)}", {"frameworks": fw_names, "gaps_found": len(rules.get("gaps", []))})],
    }


def architecture_agent(state: DevState) -> dict:
    if should_stop(state):
        print("[architecture_agent] pipeline stopped — skipping")
        return {}
    print("[architecture_agent] Starting")
    manifest    = state["intent_manifest"]
    compliance  = state["compliance_rules"]
    ip          = state["ip_clearance"]
    arch_feedback = state.get("arch_feedback", "")
    frameworks  = [f["name"] for f in compliance.get("applicable_frameworks", [])]
    pat_context = "\n".join([f"{k}: {v['description']} | best_for: {v['best_for']}" for k, v in ARCHITECTURE_PATTERNS.items()])
    response    = llm.invoke(f"You are a senior software architect.\nIntent: {json.dumps(manifest)}"+
                              (f"\nIMPORTANT - Reviewer instruction: {arch_feedback}\nYou MUST apply this." if arch_feedback else "")+
                              f"\nCompliance: {', '.join(frameworks)}\nRules: {json.dumps(compliance.get('consolidated_rules', []))}\nGaps: {json.dumps(compliance.get('gaps', []))}\nIP risk: {ip.get('overall_risk')}\nPatterns: {pat_context}\nSelect best pattern, define layers, map compliance rules, address all gaps.\nRespond ONLY with valid JSON:\n{ARCHITECTURE_SCHEMA}")
    arch        = extract_json(response.text)
    print(f"[architecture_agent] Done — pattern: {arch.get('selected_pattern')}")
    return {
        "architecture": arch,
        "audit_log": [make_audit_entry("architecture_agent", f"Architecture — pattern: {arch.get('selected_pattern')}", {"pattern": arch.get("selected_pattern"), "gaps_addressed": arch.get("gaps_addressed", [])})],
    }


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
    response   = llm.invoke(f"""You are a senior Python engineer generating complete end to end production-grade code.
Intent: {json.dumps(manifest)}
Architecture: {arch.get('selected_pattern')}
Layers: {json.dumps([l['name'] for l in arch.get('layers', [])])}
Infrastructure: {json.dumps(arch.get('infrastructure', {}))}
Security Controls: {json.dumps(arch.get('security_controls', []))}
Compliance Rules: {json.dumps(compliance.get('consolidated_rules', []))}
IP Cleared Libraries: {json.dumps([lib['name'] for lib in ip.get('scanned_libraries', [])])}
CRITICAL: Use os.getenv() for ALL secrets. Add type hints. Add try/except. Add # [GDPR] / # [OWASP] inline comments. Add docstrings. Implement ALL acceptance criteria endpoints.
Respond ONLY with valid JSON:
{CODEGEN_SCHEMA}""")
    code    = extract_json(response.text)
    modules = code.get("modules", [])
    print(f"[codegen_agent] Done — {len(modules)} files generated: {[m['filename'] for m in modules]}")
    return {
        "generated_code":   code,
        "security_retries": current_retries + 1,
        "audit_log": [make_audit_entry("codegen_agent", f"Code generated — {len(modules)} files", {"files_generated": [m["filename"] for m in modules]})],
    }


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
        response = llm.invoke(f"""You are a senior Python engineer performing proactive code optimization.
Code:
{code_dump}
Fix proactively: 1) Replace ALL hardcoded secrets with os.getenv() 2) Fix unlicensed jwt imports — use PyJWT 3) Add type hints 4) Add try/except with HTTPException 5) Disable echo=True 6) Add missing docstrings
Security findings: {json.dumps(security.get('findings', [])) if security else "Not yet scanned"}
Quality issues: {json.dumps(quality.get('recommendations', [])) if quality else "Not yet assessed"}
CRITICAL JSON RULES: escape ALL double quotes inside code as \\". Do NOT use actual newlines inside string values.
IMPORTANT: rewritten_modules must contain COMPLETE rewritten file code with ALL fixes applied.
Respond ONLY with valid JSON:
{OPTIMIZER_SCHEMA}""")
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


# def run_local_security_scan(modules: list, ip_clearance: dict) -> list:
#     cleared_libs = {lib["name"].lower() for lib in ip_clearance.get("scanned_libraries", [])}
#     stdlib = {"os","sys","re","json","datetime","typing","pathlib","hashlib","hmac","secrets","logging","functools","itertools","collections","abc","enum","pydantic","starlette","asyncpg","sqlalchemy","alembic","pytest","httpx","uvicorn","fastapi"}
#     findings = []
#     for module in modules:
#         filename, code = module.get("filename", "unknown"), module.get("code", "")
#         for rule_name, rule in SECURITY_RULES.items():
#             if rule["pattern"] is None:
#                 continue
#             matches = re.findall(rule["pattern"], code, re.MULTILINE)
#             if matches:
#                 findings.append({"filename": filename, "rule": rule_name, "severity": rule["severity"], "owasp_ref": rule["owasp"], "line_hint": str(matches[0])[:120], "fix": rule["fix"], "source": "local_scan"})
#         for imp in re.findall(r'^(?:import|from)\s+(\w+)', code, re.MULTILINE):
#             if imp.lower() not in stdlib and imp.lower() not in cleared_libs:
#                 findings.append({"filename": filename, "rule": "unlicensed_import", "severity": "high", "owasp_ref": "IP Compliance", "line_hint": f"import {imp}", "fix": f"'{imp}' not IP-cleared", "source": "local_scan"})
#     return findings


# def check_compliance_tag_coverage(modules: list) -> dict:
#     files_with, files_without = [], []
#     for module in modules:
#         (files_with if re.search(r'#\s*\[(GDPR|OWASP|HIPAA|PCI)', module.get("code", "")) else files_without).append(module.get("filename", "unknown"))
#     total = len(modules)
#     return {"files_with_tags": len(files_with), "files_without_tags": files_without, "coverage_percent": round((len(files_with) / total * 100) if total > 0 else 0, 1)}


# def security_agent(state: DevState) -> dict:
#     if should_stop(state):
#         print("[security_agent] pipeline stopped — skipping")
#         return {}
#     print("[security_agent] Starting")
#     modules        = state["generated_code"].get("modules", [])
#     ip_clearance   = state["ip_clearance"]
#     local_findings = run_local_security_scan(modules, ip_clearance)
#     tag_coverage   = check_compliance_tag_coverage(modules)
#     code_dump      = "\n\n".join([f"### {m['filename']}\n{m['code']}" for m in modules])
#     response       = llm.invoke(f"You are a senior application security engineer.\nCode:\n{code_dump}\nLocal findings: {json.dumps(local_findings)}\nIP Cleared: {json.dumps([lib['name'] for lib in ip_clearance.get('scanned_libraries', [])])}\nSet passed=true ONLY if zero critical findings.\nRespond ONLY with valid JSON:\n{SECURITY_SCHEMA}")
#     report         = extract_json(response.text)
#     existing_keys  = {(f["filename"], f["rule"]) for f in report.get("findings", [])}
#     for lf in local_findings:
#         if (lf["filename"], lf["rule"]) not in existing_keys:
#             report.setdefault("findings", []).append(lf)
#     report["compliance_tag_coverage"] = tag_coverage
#     critical_count = sum(1 for f in report.get("findings", []) if f["severity"] == "critical")
#     report["passed"] = critical_count == 0
#     print(f"[security_agent] Done — risk: {report.get('overall_security_risk')}, passed: {report['passed']}, retries used: {state.get('security_retries', 0)}")
#     return {
#         "security_report": report,
#         "audit_log": [make_audit_entry("security_agent", f"Security scan — risk: {report.get('overall_security_risk')} | passed: {report.get('passed')}", {"total_findings": len(report.get("findings", [])), "critical": critical_count, "passed": report.get("passed")})],
#     }



def run_local_security_scan(modules: list, ip_clearance: dict) -> dict:

    local_findings = []
    cleared_libs   = {
        lib["name"].lower()
        for lib in ip_clearance.get("scanned_libraries", [])
    }

    for module in modules:
        filename = module.get("filename", "unknown")
        code     = module.get("code", "")

        for rule_name, rule in SECURITY_RULES.items():
            if rule["pattern"] is None:
                continue
            matches = re.findall(rule["pattern"], code, re.MULTILINE)
            if matches:
                local_findings.append({
                    "filename":  filename,
                    "rule":      rule_name,
                    "severity":  rule["severity"],
                    "owasp_ref": rule["owasp"],
                    "line_hint": str(matches[0])[:120],
                    "fix":       rule["fix"],
                    "source":    "local_scan",
                })

        imports = re.findall(r'^(?:import|from)\s+(\w+)', code, re.MULTILINE)
        for imp in imports:
            imp_lower = imp.lower()
            stdlib = {
                "os", "sys", "re", "json", "datetime", "typing",
                "pathlib", "hashlib", "hmac", "secrets", "logging",
                "functools", "itertools", "collections", "abc", "enum","pydantic", "starlette", "asyncpg", "sqlalchemy", "alembic", "pytest", "httpx", "uvicorn", "fastapi"
            }
            if imp_lower not in stdlib and imp_lower not in cleared_libs:
                local_findings.append({
                    "filename":  filename,
                    "rule":      "unlicensed_import",
                    "severity":  "high",
                    "owasp_ref": "IP Compliance",
                    "line_hint": f"import {imp}",
                    "fix":       f"'{imp}' was not IP-cleared — verify license before use",
                    "source":    "local_scan",
                })

    return local_findings


def check_compliance_tag_coverage(modules: list) -> dict:
    """Check every file has compliance inline comments."""
    files_with    = []
    files_without = []

    for module in modules:
        code     = module.get("code", "")
        filename = module.get("filename", "unknown")
        has_tags = bool(re.search(r'#\s*\[(GDPR|OWASP|HIPAA|PCI)', code))
        if has_tags:
            files_with.append(filename)
        else:
            files_without.append(filename)

    total    = len(modules)
    coverage = round((len(files_with) / total * 100) if total > 0 else 0, 1)

    return {
        "files_with_tags":    len(files_with),
        "files_without_tags": files_without,
        "coverage_percent":   coverage,
    }


def security_agent(state: DevState) -> dict:
    code_state   = state["generated_code"]
    ip_clearance = state["ip_clearance"]
    modules      = code_state.get("modules", [])

    local_findings       = run_local_security_scan(modules, ip_clearance)
    tag_coverage         = check_compliance_tag_coverage(modules)

    code_dump = "\n\n".join([
        f"### {m['filename']}\n{m['code']}"
        for m in modules
    ])

    prompt = f"""
You are a senior application security engineer performing a code review.

Review the following generated Python code for security vulnerabilities.

Code:
{code_dump}

Local scan already detected these issues (include them in your findings):
{json.dumps(local_findings, indent=2)}

IP Cleared Libraries:
{json.dumps([lib['name'] for lib in ip_clearance.get('scanned_libraries', [])], indent=2)}

Compliance Tag Coverage:
{json.dumps(tag_coverage, indent=2)}

Check specifically for:
1. Hardcoded secrets, keys, or passwords
2. SQL injection vulnerabilities
3. Missing authentication on protected routes
4. Insecure JWT configuration (weak algo, no expiry)
5. Missing input validation
6. Debug mode enabled in production
7. Any imports not in the IP-cleared list
8. Missing or incorrect compliance inline comments
9. Insecure cookie configuration
10. Any other OWASP Top 10 violations

Severity levels:
- critical : exploitable immediately, must fix before deploy
- high     : significant risk, should fix before deploy
- medium   : moderate risk, fix soon
- low      : minor issue, fix when possible

Set "passed" to true ONLY if there are zero critical findings.

Respond ONLY with valid JSON matching this schema, no explanation, no markdown:
{SECURITY_SCHEMA}
"""

    response = llm.invoke(prompt)
    report   = extract_json(response.text)

    existing_keys = {
        (f["filename"], f["rule"])
        for f in report.get("findings", [])
    }
    for lf in local_findings:
        key = (lf["filename"], lf["rule"])
        if key not in existing_keys:
            report.setdefault("findings", []).append(lf)

    report["compliance_tag_coverage"] = tag_coverage

    findings        = report.get("findings", [])
    critical_count  = sum(1 for f in findings if f["severity"] == "critical")
    high_count      = sum(1 for f in findings if f["severity"] == "high")
    passed          = report.get("passed", False)
    overall_risk    = report.get("overall_security_risk", "unknown")

    audit_entry = make_audit_entry(
        agent   = "security_agent",
        summary = (
            f"Security scan complete — risk: {overall_risk} | "
            f"findings: {len(findings)} "
            f"(critical: {critical_count}, high: {high_count}) | "
            f"passed: {passed}"
        ),
        data    = {
            "total_findings":  len(findings),
            "critical":        critical_count,
            "high":            high_count,
            "passed":          passed,
            "overall_risk":    overall_risk,
            "tag_coverage":    tag_coverage["coverage_percent"],
        }
    )

    return {
        "security_report": report,
        "audit_log":       [audit_entry],
    }

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
    hitl_trail = [{"gate": d.get("gate"), "choice": d.get("choice"), "approver": d.get("approver"), "notes": d.get("extra_notes") or d.get("feedback") or "none", "risks_acknowledged": d.get("risk_acknowledged", False)} for d in decisions]
    response   = llm.invoke(f"""You are a technical documentation specialist producing an explainability report for non-technical stakeholders, regulators, and auditors.
Intent: {state['raw_input']}
Manifest: {json.dumps(manifest)}
Architecture: pattern={arch.get('selected_pattern')}, layers={json.dumps([l['name'] for l in arch.get('layers', [])])}
Compliance frameworks: {json.dumps([f['name'] for f in compliance.get('applicable_frameworks', [])])}
Files: {json.dumps([{'filename': m['filename'], 'layer': m['layer'], 'description': m['description']} for m in code.get('modules', [])])}
Security findings: {json.dumps(security.get('findings', []))}
Human review trail: {json.dumps(hitl_trail)}
Respond ONLY with valid JSON:
{EXPLAINABILITY_SCHEMA}""")
    docs = extract_json(response.text)
    print(f"[explainability_agent] Done — {len(docs.get('decision_log', []))} decisions")
    return {
        "explainability_docs": docs,
        "audit_log": [make_audit_entry("explainability_agent", f"Explainability docs — {len(docs.get('decision_log', []))} decisions", {"decisions_documented": len(docs.get("decision_log", []))})],
    }


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
    keywords_map = {"register": ["register", "signup", "UserCreate"], "log in": ["login", "token", "create_access_token"], "dashboard": ["dashboard", "protected", "Depends"], "postgresql": ["postgresql", "asyncpg", "create_async_engine"], "authenticated": ["Depends", "get_current_user", "verify_token"], "persisted": ["session", "db", "commit", "add"]}
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
    manifest = state["intent_manifest"]
    arch     = state["architecture"]
    code     = state["generated_code"]
    security = state["security_report"]
    explain  = state["explainability_docs"]
    modules  = code.get("modules", [])
    local    = run_local_quality_checks(state)
    code_dump = "\n\n".join([f"### {m['filename']}\n{m['code']}" for m in modules])
    response  = llm.invoke(f"""You are a senior quality engineer.
Acceptance Criteria: {json.dumps(manifest.get('acceptance_criteria', []))}
Architecture: {arch.get('selected_pattern')}
Code:
{code_dump}
Local quality results: {json.dumps(local['local_results'])}
Acceptance pre-check: {json.dumps(local['criteria_results'])}
Security: overall_risk={security.get('overall_security_risk')}, passed={security.get('passed')}, critical_count={sum(1 for f in security.get('findings', []) if f['severity'] == 'critical')}
Critical blockers: {json.dumps(local['critical_blockers'])}
Explainability: {len(explain.get('decision_log', []))} decisions, {len(explain.get('module_explanations', []))} modules
Score rubric: acceptance_criteria=30pts, code_quality=25pts, security=25pts, explainability=20pts
Set passed=true ONLY if score>=50 AND no critical findings.
Respond ONLY with valid JSON:
{QUALITY_SCHEMA}""")
    report = extract_json(response.text)
    report["security_integration"] = {"security_findings_addressed": len(local["critical_blockers"]) == 0, "critical_blockers": local["critical_blockers"], "ready_for_deploy": len(local["critical_blockers"]) == 0 and report.get("overall_quality_score", 0) >= 50}
    critical_count = sum(1 for f in security.get("findings", []) if f["severity"] == "critical")
    report["passed"] = critical_count == 0 and report.get("overall_quality_score", 0) >= 50
    score, passed   = report.get("overall_quality_score", 0), report.get("passed", False)
    print(f"[quality_agent] Done — score: {score}/100, passed: {passed}")
    return {
        "quality_report": report,
        "audit_log": [make_audit_entry("quality_agent", f"Quality — score: {score}/100 | passed: {passed}", {"score": score, "passed": passed, "critical_blockers": local["critical_blockers"]})],
    }


def audit_agent(state: DevState) -> dict:
    if should_stop(state):
        print("[audit_agent] pipeline stopped — skipping")
        return {}
    print("[audit_agent] Starting")
    manifest   = state["intent_manifest"]
    arch       = state["architecture"]
    compliance = state["compliance_rules"]
    ip         = state["ip_clearance"]
    code       = state["generated_code"]
    security   = state["security_report"]
    quality    = state["quality_report"]
    decisions  = state["hitl_decisions"] or []
    audit_log  = state["audit_log"]
    immutable_digest = {"intent_hash": compute_hash(manifest), "architecture_hash": compute_hash(arch), "code_hash": compute_hash([m["filename"] for m in code.get("modules", [])]), "audit_chain_hash": compute_hash(audit_log)}
    accountability   = [{"gate": d.get("gate"), "approver": d.get("approver"), "decision": d.get("choice"), "timestamp": d.get("timestamp"), "risks_acknowledged": d.get("risk_acknowledged", False), "notes": d.get("extra_notes") or d.get("feedback") or "none"} for d in decisions]
    blocking_issues  = [f"{f['filename']}: {f['rule']}" for f in security.get("findings", []) if f["severity"] == "critical"]
    if not quality.get("passed"):
        blocking_issues.append(f"Quality score {quality.get('overall_quality_score')}/100 — below threshold")
    blocking_issues.extend([f"Unmet criterion: {c['criterion']}" for c in quality.get("acceptance_criteria_check", []) if c["status"] == "not_met"])
    frameworks     = [f["name"] for f in compliance.get("applicable_frameworks", [])]
    gaps           = compliance.get("gaps", [])
    gaps_addressed = arch.get("gaps_addressed", [])
    unresolved     = [g for g in gaps if not any(any(w in a.lower() for w in g.lower().split()[:3]) for a in gaps_addressed)]
    compliance_sign_off = {"gdpr_controls_verified": "GDPR" in frameworks, "owasp_controls_verified": "OWASP Top 10" in frameworks, "ip_clearance_verified": ip.get("overall_risk") in ("low", "medium"), "gaps_resolved": len(unresolved) == 0, "unresolved_items": unresolved}
    final_status = "requires_remediation" if blocking_issues else ("blocked" if not quality.get("passed") else "approved_for_deploy")
    response = llm.invoke(f"You are a senior compliance auditor. Write a single paragraph audit statement for a regulator.\nAgents: {len(audit_log)}, HITL: {len(decisions)}, findings: {len(security.get('findings', []))}, quality: {quality.get('overall_quality_score')}/100, status: {final_status}\nHuman trail: {json.dumps(accountability)}\nBlocking: {json.dumps(blocking_issues) if blocking_issues else 'None'}\nCompliance: {json.dumps(compliance_sign_off)}\nReturn ONLY the paragraph as plain text.")
    sign_off = response.text.strip()
    report   = {"pipeline_summary": {"total_agents_run": len(audit_log), "total_hitl_decisions": len(decisions), "total_findings": len(security.get("findings", [])), "pipeline_passed": len(blocking_issues) == 0, "blocking_issues": blocking_issues}, "compliance_sign_off": compliance_sign_off, "human_accountability": accountability, "immutable_digest": immutable_digest, "final_status": final_status, "sign_off_note": sign_off}
    print(f"[audit_agent] Done — status: {final_status}")
    return {
        "audit_log": [make_audit_entry("audit_agent", f"Final audit — status: {final_status.upper()}", {"final_status": final_status, "blocking_issues": len(blocking_issues), "immutable_digest": immutable_digest})],
        "quality_report": {**quality, "final_audit": report},
    }


def route_after_hitl_1(state: DevState) -> str:
    decisions = state.get("hitl_decisions") or []
    gate1     = [d for d in decisions if d.get("gate") == "hitl_gate_1"]
    if gate1 and gate1[-1]["choice"] in ("R", "M"):
        print("Fired Intent")
        result = "intent_agent"
    else:
        print("Fired Compliance")
        result = "compliance_agent"
    print(f"[route_hitl_1] → {result}")
    return result


def route_after_hitl_2(state: DevState) -> str:
    decisions = state.get("hitl_decisions") or []
    gate2     = [d for d in decisions if d.get("gate") == "hitl_gate_2"]
    result    = "codegen_agent" if (gate2 and gate2[-1]["choice"] in ("A")) else "architecture_agent"
    print("THIS IS THE RESULT : ================>",result)
    print(f"[route_hitl_2] → {result}")
    return result


def route_after_security(state: DevState) -> str:
    if should_stop(state):
        return "explainability_agent"
    passed  = state.get("security_report", {}).get("passed")
    retries = state.get("security_retries", 0)
    print(f"[route_security] passed={passed} | security_retries={retries}")
    if passed:
        return "explainability_agent"
    if retries >= 3:
        print("[route_security] Max retries reached — forcing forward")
        return "explainability_agent"
    return "codegen_agent"


def route_after_quality(state: DevState) -> str:
    if should_stop(state):
        return "audit_agent"
    quality  = state.get("quality_report", {})
    security = state.get("security_report", {})
    retries  = state.get("security_retries", 0)
    print(f"[route_quality] passed={quality.get('passed')} | security_passed={security.get('passed')} | retries={retries}")
    if retries >= 3:
        return "audit_agent"
    if quality.get("passed") and security.get("passed"):
        return "audit_agent"
    return "codegen_agent"


def route_after_hitl_3(state: DevState) -> str:
    decisions = state.get("hitl_decisions") or []
    gate3     = [d for d in decisions if d.get("gate") == "hitl_gate_3"]
    choice    = gate3[-1]["choice"] if gate3 else None
    result    = END if choice in ("A", "H") else "codegen_agent"
    print(f"[route_hitl_3] choice={choice} → {'END' if result == END else result}")
    return result


def passthrough_node(state: DevState) -> dict:
    return {}


def intent_node(state: DevState) -> dict:
    return intent_agent(state)

def ip_guard_node(state: DevState) -> dict:
    return ip_guard_agent(state)

def hitl_1_node(state: DevState) -> dict:
    return passthrough_node(state)

def compliance_node(state: DevState) -> dict:
    return compliance_agent(state)

def architecture_node(state: DevState) -> dict:
    return architecture_agent(state)

def hitl_2_node(state: DevState) -> dict:
    return passthrough_node(state)

def codegen_node(state: DevState) -> dict:
    return codegen_agent(state)

def optimizer_node(state: DevState) -> dict:
    return optimizer_agent(state)

def security_node(state: DevState) -> dict:
    return security_agent(state)

def explainability_node(state: DevState) -> dict:
    return explainability_agent(state)

def quality_node(state: DevState) -> dict:
    return quality_agent(state)

def audit_node(state: DevState) -> dict:
    return audit_agent(state)

def hitl_3_node(state: DevState) -> dict:
    return passthrough_node(state)

def build_graph() -> StateGraph:
    graph = StateGraph(DevState)

    graph.add_node("intent_agent",         intent_node)
    graph.add_node("ip_guard_agent",       ip_guard_node)
    graph.add_node("hitl_gate_1",          hitl_1_node)
    graph.add_node("compliance_agent",     compliance_node)
    graph.add_node("architecture_agent",   architecture_node)
    graph.add_node("hitl_gate_2",          hitl_2_node)
    graph.add_node("codegen_agent",        codegen_node)
    graph.add_node("optimizer_agent",      optimizer_node)
    graph.add_node("security_agent",       security_node)
    graph.add_node("explainability_agent", explainability_node)
    graph.add_node("quality_agent",        quality_node)
    graph.add_node("audit_agent",          audit_node)
    graph.add_node("hitl_gate_3",          hitl_3_node)

    graph.set_entry_point("intent_agent")

    graph.add_edge("intent_agent",         "ip_guard_agent")
    graph.add_edge("ip_guard_agent",       "hitl_gate_1")
    graph.add_edge("compliance_agent",     "architecture_agent")
    graph.add_edge("architecture_agent",   "hitl_gate_2")
    graph.add_edge("codegen_agent",        "optimizer_agent")
    graph.add_edge("optimizer_agent",      "security_agent")
    graph.add_edge("explainability_agent", "quality_agent")
    graph.add_edge("quality_agent",        "audit_agent")
    graph.add_edge("audit_agent",          "hitl_gate_3")

    graph.add_conditional_edges(
        "hitl_gate_1",
        route_after_hitl_1,
        {
            "compliance_agent": "compliance_agent",
            "intent_agent":     "intent_agent",
        }
    )

    graph.add_conditional_edges(
        "hitl_gate_2",
        route_after_hitl_2,
        {
            "codegen_agent":      "codegen_agent",
            "architecture_agent": "architecture_agent",
            "hitl_gate_2":        "hitl_gate_2",
        }
    )

    graph.add_conditional_edges(
        "security_agent",
        route_after_security,
        {
            "explainability_agent": "explainability_agent",
            "codegen_agent":        "codegen_agent",
        }
    )

    graph.add_conditional_edges(
        "quality_agent",
        route_after_quality,
        {
            "audit_agent":   "audit_agent",
            "codegen_agent": "codegen_agent",
        }
    )

    graph.add_conditional_edges(
        "hitl_gate_3",
        route_after_hitl_3,
        {
            END:             END,
            "codegen_agent": "codegen_agent",
        }
    )

    return graph


memory         = MemorySaver()
pipeline_graph = build_graph().compile(
    checkpointer=memory,
    interrupt_before=["hitl_gate_1", "hitl_gate_2", "hitl_gate_3"],
)


async def run_pipeline_background(thread_id: str, initial_state: dict) -> None:
    config = get_config(thread_id)
    queue  = pipeline_queues[thread_id]
    loop   = asyncio.get_running_loop()

    def _emit_sync(event: dict) -> None:
        loop.call_soon_threadsafe(queue.put_nowait, event)

    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    input_state: Any = initial_state

    try:
        while True:
            def _stream_segment() -> None:
                for event in pipeline_graph.stream(input_state, config):
                    for node_name, node_output in event.items():
                        _emit_sync({
                            "type":      "node_completed",
                            "node":      node_name,
                            "summary":   get_node_summary(node_name, node_output),
                            "timestamp": _now(),
                        })

            await asyncio.to_thread(_stream_segment)

            current    = await asyncio.to_thread(pipeline_graph.get_state, config)
            next_nodes = list(current.next)
            state_vals = current.values

            if not next_nodes:
                final_audit = (state_vals.get("quality_report") or {}).get("final_audit", {})
                await queue.put({
                    "type":             "pipeline_complete",
                    "thread_id":        thread_id,
                    "final_status":     final_audit.get("final_status"),
                    "sign_off_note":    final_audit.get("sign_off_note"),
                    "immutable_digest": final_audit.get("immutable_digest"),
                    "audit_log":        state_vals.get("audit_log", []),
                    "timestamp":        _now(),
                })
                pipeline_meta[thread_id].update({"status": "complete", "final_status": final_audit.get("final_status")})
                break

            paused_at = next_nodes[0]
            gate_ctx  = get_gate_context(state_vals, paused_at)
            await queue.put({
                "type":         "hitl_pause",
                "thread_id":    thread_id,
                "paused_at":    paused_at,
                "gate_context": gate_ctx,
                "audit_log":    state_vals.get("audit_log", []),
                "timestamp":    _now(),
            })
            pipeline_meta[thread_id].update({"status": "paused_at_hitl", "paused_at": paused_at})

            resume_evt = asyncio.Event()
            pipeline_resume_events[thread_id] = resume_evt
            await resume_evt.wait()
            pipeline_resume_events.pop(thread_id, None)

            input_state = None

    except Exception as exc:
        err_msg = str(exc)
        print(f"[pipeline_background] ERROR thread={thread_id}: {err_msg}")
        await queue.put({"type": "error", "thread_id": thread_id, "message": err_msg, "timestamp": datetime.now(timezone.utc).isoformat()})
        pipeline_meta[thread_id]["status"] = "error"
    finally:
        pipeline_tasks.pop(thread_id, None)


@app.websocket("/ws/pipeline/{thread_id}")
async def pipeline_websocket(websocket: WebSocket, thread_id: str):
    if thread_id not in pipeline_queues:
        await websocket.accept()
        await websocket.send_json({"type": "error", "message": f"Pipeline '{thread_id}' not found. Call POST /pipeline/start first."})
        await websocket.close()
        return

    await ws_manager.connect(thread_id, websocket)
    queue = pipeline_queues[thread_id]

    try:
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=60.0)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
                continue

            await websocket.send_json(event)

            if event.get("type") in ("pipeline_complete", "error"):
                await asyncio.sleep(0.3)
                break

    except WebSocketDisconnect:
        print(f"[ws] Client disconnected early: {thread_id}")
    except Exception as exc:
        print(f"[ws] Unexpected error for {thread_id}: {exc}")
    finally:
        ws_manager.disconnect(thread_id)


@app.get("/")
def health():
    return {
        "status":    "AI-Native Dev Pipeline running",
        "version":   "2.0.0",
        "transport": {
            "rest":      "POST /pipeline/start | POST /pipeline/{id}/decide | GET /pipeline/{id}/state | GET /pipeline/{id}/result",
            "websocket": "ws://host/ws/pipeline/{thread_id}",
        },
    }


@app.post("/pipeline/start")
async def start_pipeline(request: RunRequest):
    thread_id = str(uuid4())
    config    = get_config(thread_id)

    initial_state: DevState = {
        "raw_input":           request.raw_input,
        "intent_manifest":     None,
        "compliance_rules":    None,
        "ip_clearance":        None,
        "architecture":        None,
        "generated_code":      None,
        "explainability_docs": None,
        "security_report":     None,
        "quality_report":      None,
        "hitl_decisions":      [],
        "audit_log":           [],
        "drift_alerts":        None,
        "security_retries":    0,
        "pipeline_stopped":    False,
    }

    pipeline_queues[thread_id] = asyncio.Queue()
    pipeline_meta[thread_id]   = {"status": "running", "paused_at": None}

    task = asyncio.create_task(run_pipeline_background(thread_id, initial_state))
    pipeline_tasks[thread_id] = task

    print(f"\n{'='*60}")
    print(f"[pipeline] New run — thread_id: {thread_id}")
    print(f"[pipeline] Input: {request.raw_input[:80]}")
    print(f"{'='*60}\n")

    return {
        "thread_id": thread_id,
        "status":    "started",
        "ws_url":    f"/ws/pipeline/{thread_id}",
        "message":   "Connect to ws_url for real-time events. Use /decide for HITL gates.",
    }


@app.post("/pipeline/{thread_id}/decide")
async def hitl_decide(thread_id: str, request: HITLDecisionRequest):

    config = get_config(thread_id)

    if thread_id not in pipeline_queues:
        raise HTTPException(status_code=404, detail=f"Pipeline not found: {thread_id}")

    current    = await asyncio.to_thread(pipeline_graph.get_state, config)
    next_nodes = list(current.next)

    if not next_nodes:
        raise HTTPException(status_code=400, detail="Pipeline is not paused — it may have already completed.")

    paused_at = next_nodes[0]
    if paused_at not in ("hitl_gate_1", "hitl_gate_2", "hitl_gate_3"):
        raise HTTPException(status_code=400, detail=f"Not at a HITL gate — currently at: {paused_at}")

    if request.choice not in ("A", "R", "M", "H"):
        raise HTTPException(status_code=422, detail="choice must be one of: A, R, M, H")

    print(f"[{paused_at}] Decision — choice: {request.choice}, approver: {request.approver}")

    decision = {
        "gate":              paused_at,
        "approved":          request.choice in ("A", "M"),
        "choice":            request.choice,
        "approver":          request.approver,
        "role":              request.role,
        "feedback":          request.feedback,
        "extra_notes":       request.extra_notes,
        "justification":     request.justification,
        "risk_acknowledged": request.risk_acknowledged,
        "timestamp":         datetime.now(timezone.utc).isoformat(),
    }

    existing_decisions = current.values.get("hitl_decisions") or []
    audit_entry        = make_audit_entry(paused_at, f"Gate decision: {request.choice} by {request.approver}", decision)

    # ── handle M at gate 1 — bake modification into raw_input ──────
    state_update: dict = {"hitl_decisions": existing_decisions + [decision], "audit_log": [audit_entry]}
    
    if paused_at == "hitl_gate_1" and request.choice == "M" and request.feedback:
        
        base_input  = re.sub(r'\n\n\[Human modification.*', '', current.values.get("raw_input", ""), flags=re.DOTALL).strip()
        state_update["raw_input"] = (
            f"{base_input}\n\n"
            f"[IMPORTANT - Human modification]: {request.feedback}\n"
            f"You MUST follow this instruction exactly and override any previous tech stack decisions."
        )
        print(f"[hitl_gate_1] Modification baked into raw_input: {request.feedback}")

    # ── handle gate 3 A/H — set pipeline_stopped ───────────────────
    if paused_at == "hitl_gate_3" and request.choice in ("A", "H"):
        state_update["pipeline_stopped"] = True
        print(f"[hitl_gate_3] pipeline_stopped=True — all downstream nodes will no-op")

# ── reset security_retries on gate 2 approval ──────────────────
    # if paused_at == "hitl_gate_2" and request.choice in ("A", "M"):
    #     state_update["security_retries"] = 0
    #     print(f"[hitl_gate_2] security_retries reset to 0")

    if paused_at == "hitl_gate_2":
        if request.choice in ("A"):
            state_update["security_retries"] = 0
            print(f"[hitl_gate_2] security_retries reset to 0")
        
        if request.choice == "M" and request.feedback:
            state_update["arch_feedback"] = request.feedback
            print(f"[hitl_gate_2] architecture_feedback set: {request.feedback}")
            

    await asyncio.to_thread(
        pipeline_graph.update_state,
        config,
        state_update,
        as_node=paused_at,
    )

    # ── resume the background pipeline task ────────────────────────
    resume_evt = pipeline_resume_events.get(thread_id)
    if resume_evt:
        resume_evt.set()
        print(f"[{paused_at}] Resume event fired for thread: {thread_id}")
    else:
        print(f"[{paused_at}] WARNING: No resume event found for thread: {thread_id}")
    
    return {
        "thread_id": thread_id,
        "gate":      paused_at,
        "decision":  request.choice,
        "status":    "resumed",
        "message":   "Decision recorded. Pipeline resuming — watch WebSocket for updates.",
    }


@app.get("/pipeline/{thread_id}/state")
async def get_pipeline_state(thread_id: str):
    config = get_config(thread_id)

    if thread_id not in pipeline_queues and thread_id not in pipeline_meta:
        raise HTTPException(status_code=404, detail=f"Pipeline not found: {thread_id}")

    current      = await asyncio.to_thread(pipeline_graph.get_state, config)
    next_nodes   = list(current.next)
    state_values = current.values
    meta         = pipeline_meta.get(thread_id, {})
    final_audit  = (state_values.get("quality_report") or {}).get("final_audit", {})

    return {
        "thread_id":        thread_id,
        "status":           meta.get("status", "unknown"),
        "paused_at":        next_nodes[0] if next_nodes else None,
        "final_status":     final_audit.get("final_status"),
        "security_retries": state_values.get("security_retries", 0),
        "pipeline_stopped": state_values.get("pipeline_stopped", False),
        "audit_log":        state_values.get("audit_log", []),
        "hitl_decisions":   state_values.get("hitl_decisions", []),
        "immutable_digest": final_audit.get("immutable_digest"),
    }


@app.get("/pipeline/{thread_id}/result")
async def get_pipeline_result(thread_id: str):
    config = get_config(thread_id)

    if thread_id not in pipeline_queues and thread_id not in pipeline_meta:
        raise HTTPException(status_code=404, detail=f"Pipeline not found: {thread_id}")

    current      = await asyncio.to_thread(pipeline_graph.get_state, config)
    state_values = current.values
    final_audit  = (state_values.get("quality_report") or {}).get("final_audit", {})

    return {
        "thread_id":           thread_id,
        "final_status":        final_audit.get("final_status"),
        "intent_manifest":     state_values.get("intent_manifest"),
        "compliance_rules":    state_values.get("compliance_rules"),
        "ip_clearance":        state_values.get("ip_clearance"),
        "architecture":        state_values.get("architecture"),
        "generated_code":      state_values.get("generated_code"),
        "explainability_docs": state_values.get("explainability_docs"),
        "security_report":     state_values.get("security_report"),
        "quality_report":      state_values.get("quality_report"),
        "hitl_decisions":      state_values.get("hitl_decisions"),
        "audit_log":           state_values.get("audit_log"),
        "immutable_digest":    final_audit.get("immutable_digest"),
        "sign_off_note":       final_audit.get("sign_off_note"),
    }


@app.delete("/pipeline/{thread_id}")
async def cancel_pipeline(thread_id: str):
    task = pipeline_tasks.get(thread_id)
    if task and not task.done():
        task.cancel()
        print(f"[pipeline] Cancelled task for thread: {thread_id}")

    pipeline_queues.pop(thread_id, None)
    pipeline_meta.pop(thread_id, None)
    pipeline_resume_events.pop(thread_id, None)
    pipeline_tasks.pop(thread_id, None)

    return {"thread_id": thread_id, "status": "cancelled"}


@app.get("/pipelines")
async def list_pipelines():
    return {
        "pipelines": [
            {
                "thread_id": tid,
                "status":    meta.get("status"),
                "paused_at": meta.get("paused_at"),
            }
            for tid, meta in pipeline_meta.items()
        ]
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=False)