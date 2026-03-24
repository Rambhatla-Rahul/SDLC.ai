from langchain_google_genai import ChatGoogleGenerativeAI
from pydantic import BaseModel, Field
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import StateGraph, END
import os
import json
import time
from dotenv import load_dotenv
from typing import Any, Dict, List, Optional, Literal, TypedDict, Annotated
import operator
from dataclasses import dataclass, asdict
import re
from datetime import datetime, timezone
import hashlib


load_dotenv()
GOOGLE_API_KEY = os.getenv("GEMINI_API_KEY")


llm = ChatGoogleGenerativeAI(
    model="gemini-3.1-flash-lite-preview", 
    api_key=GOOGLE_API_KEY,
    temperature=0.1)

# llm.invoke("hi").text

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


def extract_json(text: str) -> dict:
    text = re.sub(r"```(?:json)?", "", text).replace("```", "").strip()
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ValueError(f"No JSON object found in LLM response:\n{text}")
    return json.loads(match.group())


def make_audit_entry(agent: str, summary: str, data: dict) -> dict:

    return {
        "agent":     agent,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary":   summary,
        "data":      data,
    }

from datetime import datetime, timezone

timestamp = datetime.now(timezone.utc).isoformat()

# print(timestamp)

INTENT_SCHEMA = """
{
  "app_type": "string — e.g. REST API, CLI tool, web app",
  "modules": [
    {
      "name": "string",
      "description": "string",
      "tech_stack": ["string"]
    }
  ],
  "constraints": {
    "security": ["string"],
    "compliance": ["string — e.g. GDPR, HIPAA"],
    "performance": ["string"],
    "ip_notes": ["string — any third-party libraries or frameworks mentioned"]
  },
  "acceptance_criteria": ["string"]
}
"""

def intent_agent(state: DevState) -> dict:
    prompt = f"""
You are an AI software architect. Convert the user's description into a
structured intent manifest. Respond ONLY with valid JSON — no explanation,
no markdown, no extra text.

User input:
{state["raw_input"]}

Return exactly this JSON schema (fill in real values, do not include comments):
{INTENT_SCHEMA}
"""

    response = llm.invoke(prompt)
    manifest = extract_json(response.text)

    audit_entry = make_audit_entry(
        agent   = "intent_agent",
        summary = f"Parsed intent for: {state['raw_input'][:80]}",
        data    = {"app_type": manifest.get("app_type"), "modules": [m["name"] for m in manifest.get("modules", [])]}
    )

    return {
        "intent_manifest": manifest,
        "audit_log":       [audit_entry],   
    }


import re

KNOWN_LICENSES = {
    # safe for commercial use
    "fastapi":      {"license": "MIT",        "risk": "low"},
    "sqlalchemy":   {"license": "MIT",        "risk": "low"},
    "pydantic":     {"license": "MIT",        "risk": "low"},
    "uvicorn":      {"license": "BSD",        "risk": "low"},
    "postgresql":   {"license": "PostgreSQL", "risk": "low"},
    "alembic":      {"license": "MIT",        "risk": "low"},
    "passlib":      {"license": "BSD",        "risk": "low"},
    "jose":         {"license": "MIT",        "risk": "low"},
    "httpx":        {"license": "BSD",        "risk": "low"},
    "pydantic":     {"license": "MIT",        "risk": "low"},
    "starlette":    {"license": "BSD",        "risk": "low"},
    "asyncpg":      {"license": "Apache-2.0", "risk": "low"},
    # caution — copyleft
    "gpl":          {"license": "GPL",        "risk": "high"},
    "mysql":        {"license": "GPL",        "risk": "high"},
    "celery":       {"license": "BSD",        "risk": "low"},
    "redis":        {"license": "BSD",        "risk": "low"},
}

IP_SCAN_SCHEMA = """
{
  "scanned_libraries": [
    {
      "name": "string",
      "license": "string",
      "risk_level": "low | medium | high",
      "reason": "string — one sentence explanation"
    }
  ],
  "overall_risk": "low | medium | high",
  "flagged_items": ["string — only items with medium or high risk"],
  "recommendation": "string — what to do next"
}
"""

def ip_guard_agent(state: DevState) -> dict:
    manifest = state["intent_manifest"]

    raw_libs = []

    for module in manifest.get("modules", []):
        raw_libs.extend(module.get("tech_stack", []))

    raw_libs.extend(
        manifest.get("constraints", {}).get("ip_notes", [])
    )

    local_flags = []
    for lib in raw_libs:
        key = lib.lower().strip()
        if key in KNOWN_LICENSES and KNOWN_LICENSES[key]["risk"] == "high":
            local_flags.append(f"{lib} ({KNOWN_LICENSES[key]['license']} — copyleft risk)")

    prompt = f"""
You are an IP and software license compliance officer.

Review the following libraries and frameworks extracted from a software project.
For each one, identify its open source license and assess the risk for commercial use.

Libraries to scan:
{json.dumps(raw_libs, indent=2)}

Known high-risk flags detected by local scan (include these in your response):
{json.dumps(local_flags, indent=2) if local_flags else "None detected"}

Risk levels:
- low    : permissive license (MIT, BSD, Apache 2.0, PostgreSQL) — safe for commercial use
- medium : weak copyleft (LGPL, MPL) — usable but requires care
- high   : strong copyleft (GPL, AGPL) — may require open-sourcing your code

Respond ONLY with valid JSON matching this schema exactly, no explanation, no markdown:
{IP_SCAN_SCHEMA}
"""

    response = llm.invoke(prompt)
    clearance = extract_json(response.text)

    overall_risk = clearance.get("overall_risk", "unknown")

    audit_entry = make_audit_entry(
        agent   = "ip_guard_agent",
        summary = f"IP scan complete — overall risk: {overall_risk}",
        data    = {
            "libraries_scanned": len(clearance.get("scanned_libraries", [])),
            "flagged_items":     clearance.get("flagged_items", []),
            "overall_risk":      overall_risk,
        }
    )

    return {
        "ip_clearance": clearance,
        "audit_log":    [audit_entry],
    }



def display_hitl_summary(state: DevState):
    manifest  = state["intent_manifest"]
    clearance = state["ip_clearance"]

    print("\n" + "="*60)
    print("  HITL GATE 1 — INTENT + IP REVIEW")
    print("="*60)

    print("\n[ Intent Manifest ]")
    print(f"  App type : {manifest.get('app_type')}")
    print(f"  Modules  :")
    for m in manifest.get("modules", []):
        print(f"    - {m['name']} → {', '.join(m.get('tech_stack', []))}")
    print(f"  Security constraints  : {manifest.get('constraints', {}).get('security', [])}")
    print(f"  Compliance constraints: {manifest.get('constraints', {}).get('compliance', [])}")
    print(f"  Acceptance criteria   :")
    for ac in manifest.get("acceptance_criteria", []):
        print(f"    - {ac}")

    print("\n[ IP Clearance Report ]")
    risk = clearance.get("overall_risk", "unknown")
    risk_display = {"low": "LOW", "medium": "MEDIUM ⚠", "high": "HIGH ✗"}.get(risk, risk.upper())
    print(f"  Overall risk : {risk_display}")
    
    flagged = clearance.get("flagged_items", [])
    if flagged:
        print(f"  Flagged items:")
        for item in flagged:
            print(f"    ! {item}")
    else:
        print(f"  Flagged items: none")

    print(f"  Recommendation: {clearance.get('recommendation', 'N/A')}")

    print("\n[ Scanned Libraries ]")
    for lib in clearance.get("scanned_libraries", []):
        risk_tag = {"low": "[ok]", "medium": "[warn]", "high": "[RISK]"}.get(lib["risk_level"], "[?]")
        print(f"  {risk_tag:8s} {lib['name']:20s} {lib['license']:15s} — {lib['reason']}")

    print("\n" + "-"*60)


def get_human_decision(state: DevState) -> dict:

    display_hitl_summary(state)

    print("\nOptions:")
    print("  [A] Approve — proceed to compliance + architecture agents")
    print("  [R] Reject  — send back to intent_agent with feedback")
    print("  [M] Modify  — approve with notes (human adds constraints)")
    print()

    while True:
        choice = input("Your decision [A/R/M]: ").strip().upper()
        if choice in ("A", "R", "M"):
            break
        print("  Invalid input — please enter A, R, or M")

    feedback    = None
    extra_notes = None

    if choice == "R":
        feedback = input("Rejection reason (will be passed back to intent_agent): ").strip()

    if choice == "M":
        extra_notes = input("Additional constraints or notes to add: ").strip()

    decision = {
        "gate":        "hitl_gate_1",
        "approved":    choice in ("A", "M"),
        "choice":      choice,
        "approver":    input("Your name (for audit log): ").strip(),
        "feedback":    feedback,
        "extra_notes": extra_notes,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
    }

    return decision


def hitl_gate_1(state: DevState) -> dict:

    if not state.get("intent_manifest") or not state.get("ip_clearance"):
        raise ValueError("hitl_gate_1 requires both intent_manifest and ip_clearance in state")

    decision = get_human_decision(state)

    updated_manifest = state["intent_manifest"]

    if decision.get("extra_notes"):
        existing = updated_manifest.get("constraints", {})
        existing.setdefault("human_notes", []).append(decision["extra_notes"])
        updated_manifest["constraints"] = existing

    # if rejected, stamp the feedback onto raw_input so intent_agent can use it
    updated_raw = state["raw_input"]
    if not decision["approved"] and decision.get("feedback"):
        updated_raw = f"{state['raw_input']}\n\n[HITL feedback]: {decision['feedback']}"

    audit_entry = make_audit_entry(
        agent   = "hitl_gate_1",
        summary = f"Gate 1 decision: {decision['choice']} by {decision['approver']}",
        data    = decision,
    )

    return {
        "hitl_decisions":  (state["hitl_decisions"] or []) + [decision],
        "intent_manifest": updated_manifest,
        "raw_input":       updated_raw,      
        "audit_log":       [audit_entry],
    }


def route_after_hitl_1(state: DevState) -> str:

    last_decision = state["hitl_decisions"][-1]

    if last_decision["approved"]:
        return "compliance_agent" 
    else:
        return "intent_agent"       
    


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
        ]
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
        ]
    },
    "hipaa": {
        "full_name": "Health Insurance Portability and Accountability Act",
        "triggers":  ["health", "medical", "patient", "diagnosis", "prescription", "ehr"],
        "rules": [
            "PHI must be encrypted at rest and in transit",
            "Access logs must be maintained for all PHI access",
            "Role-based access control for all health data",
            "Business Associate Agreements required for third parties",
        ]
    },
    "pci_dss": {
        "full_name": "Payment Card Industry Data Security Standard",
        "triggers":  ["payment", "card", "billing", "checkout", "stripe", "transaction"],
        "rules": [
            "Card data must never be stored in plaintext",
            "Use tokenisation for all payment data",
            "Quarterly vulnerability scans required",
            "Strict access control to cardholder data",
        ]
    },
}

COMPLIANCE_SCHEMA = """
{
  "applicable_frameworks": [
    {
      "name": "string — e.g. GDPR, OWASP Top 10",
      "reason": "string — why this framework applies",
      "rules": ["string — specific rule that must be implemented"],
      "priority": "mandatory | recommended"
    }
  ],
  "consolidated_rules": [
    {
      "rule": "string — the actual requirement",
      "framework": "string — which framework it comes from",
      "implementation_hint": "string — how to implement in the tech stack"
    }
  ],
  "gaps": ["string — things in the intent manifest that may violate compliance"],
  "overall_compliance_risk": "low | medium | high"
}
"""

def detect_frameworks_locally(manifest: dict) -> list[str]:

    manifest_text = json.dumps(manifest).lower()

    triggered = []
    for fw_key, fw in COMPLIANCE_FRAMEWORKS.items():
        if any(trigger in manifest_text for trigger in fw["triggers"]):
            triggered.append(fw_key)

    return triggered


def compliance_agent(state: DevState) -> dict:
    manifest         = state["intent_manifest"]
    ip_clearance     = state["ip_clearance"]
    triggered_fws    = detect_frameworks_locally(manifest)

    framework_context = ""
    for fw_key in triggered_fws:
        fw = COMPLIANCE_FRAMEWORKS[fw_key]
        framework_context += f"\n{fw['full_name']} ({fw_key.upper()}):\n"
        for rule in fw["rules"]:
            framework_context += f"  - {rule}\n"

    prompt = f"""
You are a regulatory compliance officer reviewing a software project.

Intent Manifest:
{json.dumps(manifest, indent=2)}

IP Clearance Summary:
- Overall risk: {ip_clearance.get('overall_risk')}
- Flagged items: {ip_clearance.get('flagged_items', [])}

Locally detected applicable frameworks and their rules:
{framework_context if framework_context else "None auto-detected — use your judgment."}

Your tasks:
1. Confirm which compliance frameworks apply and why
2. List every specific rule that must be implemented given the tech stack
3. Identify any gaps or risks in the current intent manifest
4. Give each rule an implementation hint specific to the tech stack

Respond ONLY with valid JSON matching this schema, no explanation, no markdown:
{COMPLIANCE_SCHEMA}
"""

    response  = llm.invoke(prompt)
    rules     = extract_json(response.text)

    risk      = rules.get("overall_compliance_risk", "unknown")
    fw_names  = [f["name"] for f in rules.get("applicable_frameworks", [])]
    gaps      = rules.get("gaps", [])

    audit_entry = make_audit_entry(
        agent   = "compliance_agent",
        summary = f"Compliance mapped — risk: {risk} | frameworks: {', '.join(fw_names)}",
        data    = {
            "frameworks_detected":   triggered_fws,
            "frameworks_confirmed":  fw_names,
            "consolidated_rules":    len(rules.get("consolidated_rules", [])),
            "gaps_found":            len(gaps),
            "overall_risk":          risk,
        }
    )

    return {
        "compliance_rules": rules,
        "audit_log":        [audit_entry],
    }

ARCHITECTURE_PATTERNS = {
    "layered": {
        "description": "Traditional N-tier: presentation, business logic, data",
        "best_for":    ["web apps", "dashboards", "CRUD applications"],
        "trade_offs":  {"scalability": "medium", "complexity": "low", "security": "high"}
    },
    "microservices": {
        "description": "Independent services communicating via APIs",
        "best_for":    ["large teams", "high scale", "independent deployments"],
        "trade_offs":  {"scalability": "high", "complexity": "high", "security": "medium"}
    },
    "modular_monolith": {
        "description": "Single deployable unit with strict internal module boundaries",
        "best_for":    ["small teams", "early stage", "web apps"],
        "trade_offs":  {"scalability": "medium", "complexity": "low", "security": "high"}
    },
}

ARCHITECTURE_SCHEMA = """
{
  "selected_pattern": "string — layered | microservices | modular_monolith",
  "pattern_rationale": "string — why this pattern was chosen",
  "layers": [
    {
      "name": "string — e.g. API Layer, Auth Layer, Data Layer",
      "responsibility": "string — what this layer does",
      "components": ["string — specific classes, services or modules"],
      "tech": ["string — specific libraries or tools"],
      "compliance_controls": ["string — which compliance rules this layer satisfies"]
    }
  ],
  "infrastructure": {
    "database":    "string",
    "cache":       "string",
    "tls":         "string",
    "rate_limiter":"string",
    "audit_store": "string"
  },
  "security_controls": ["string — specific security measures built into the architecture"],
  "trade_off_matrix": {
    "scalability":  "low | medium | high",
    "complexity":   "low | medium | high",
    "security":     "low | medium | high",
    "compliance_fit":"low | medium | high"
  },
  "gaps_addressed": ["string — which compliance gaps from previous agent are now covered"],
  "residual_risks": ["string — anything still not addressed"]
}
"""

def architecture_agent(state: DevState) -> dict:
    manifest         = state["intent_manifest"]
    compliance       = state["compliance_rules"]
    ip_clearance     = state["ip_clearance"]

    # pull compliance gaps so arch agent explicitly addresses them
    gaps             = compliance.get("gaps", [])
    consolidated     = compliance.get("consolidated_rules", [])
    frameworks       = [f["name"] for f in compliance.get("applicable_frameworks", [])]

    # build pattern context for the prompt
    pattern_context  = ""
    for name, pattern in ARCHITECTURE_PATTERNS.items():
        pattern_context += f"\n{name}:\n"
        pattern_context += f"  Description : {pattern['description']}\n"
        pattern_context += f"  Best for    : {', '.join(pattern['best_for'])}\n"
        pattern_context += f"  Trade-offs  : {pattern['trade_offs']}\n"

    prompt = f"""
You are a senior software architect designing a production-grade system.

Intent Manifest:
{json.dumps(manifest, indent=2)}

Compliance Frameworks Active: {', '.join(frameworks)}

Compliance Rules to Satisfy:
{json.dumps(consolidated, indent=2)}

Compliance Gaps That Must Be Addressed in Architecture:
{json.dumps(gaps, indent=2)}

IP Clearance:
- Overall risk  : {ip_clearance.get('overall_risk')}
- Flagged items : {ip_clearance.get('flagged_items', [])}

Available Architecture Patterns:
{pattern_context}

Your tasks:
1. Select the most appropriate architecture pattern given the app type,
   team size implied by the manifest, and compliance requirements
2. Define each layer with its responsibilities, components, and tech
3. Map every compliance rule to the layer that satisfies it
4. Address every compliance gap explicitly in either a layer or infrastructure
5. Score the architecture on the trade-off matrix
6. List any residual risks that could not be fully addressed

Respond ONLY with valid JSON matching this schema, no explanation, no markdown:
{ARCHITECTURE_SCHEMA}
"""

    response = llm.invoke(prompt)
    arch     = extract_json(response.text)

    pattern  = arch.get("selected_pattern", "unknown")
    gaps_addressed = arch.get("gaps_addressed", [])
    residual = arch.get("residual_risks", [])

    audit_entry = make_audit_entry(
        agent   = "architecture_agent",
        summary = f"Architecture synthesised — pattern: {pattern} | gaps addressed: {len(gaps_addressed)}",
        data    = {
            "pattern":          pattern,
            "layers":           [l["name"] for l in arch.get("layers", [])],
            "gaps_addressed":   gaps_addressed,
            "residual_risks":   residual,
            "trade_off_matrix": arch.get("trade_off_matrix", {}),
        }
    )

    return {
        "architecture": arch,
        "audit_log":    [audit_entry],
    }


def display_hitl2_summary(state: DevState):
    arch       = state["architecture"]
    compliance = state["compliance_rules"]

    print("\n" + "="*60)
    print("  HITL GATE 2 — ARCHITECTURE + COMPLIANCE REVIEW")
    print("="*60)

    print(f"\n[ Selected Pattern ]  {arch.get('selected_pattern', '').upper()}")
    print(f"  Rationale: {arch.get('pattern_rationale')}")

    print("\n[ Trade-off Matrix ]")
    for k, v in arch.get("trade_off_matrix", {}).items():
        bar = {"low": "░░░░░░", "medium": "███░░░", "high": "██████"}.get(v, "?")
        print(f"  {k:20s} {bar}  {v.upper()}")

    print("\n[ Layers ]")
    for layer in arch.get("layers", []):
        print(f"  {layer['name']}")
        print(f"    Tech      : {', '.join(layer.get('tech', []))}")
        print(f"    Satisfies : {', '.join(layer.get('compliance_controls', []))}")

    print("\n[ Infrastructure ]")
    for k, v in arch.get("infrastructure", {}).items():
        print(f"  {k:15s} : {v}")

    print("\n[ Compliance Gaps Addressed ]")
    original_gaps = compliance.get("gaps", [])
    gaps_addressed = arch.get("gaps_addressed", [])
    
    # cross check — flag any gap not addressed
    unresolved = []
    for gap in original_gaps:
        matched = any(
            any(word in addressed.lower() for word in gap.lower().split()[:3])
            for addressed in gaps_addressed
        )
        if matched:
            print(f"  [ok] {gap}")
        else:
            print(f"  [!!] UNRESOLVED: {gap}")
            unresolved.append(gap)

    if arch.get("residual_risks"):
        print("\n[ Residual Risks — Human Sign-off Required ]")
        for r in arch.get("residual_risks", []):
            print(f"  [!] {r}")

    if unresolved:
        print("\n[ WARNING — Unresolved Gaps Detected ]")
        for u in unresolved:
            print(f"  [!!] {u}")

    print("\n" + "-"*60)


def get_human_decision_2(state: DevState) -> dict:
    display_hitl2_summary(state)

    arch     = state["architecture"]
    residual = arch.get("residual_risks", [])

    # auto warn if residual risks exist
    if residual:
        print(f"\n  NOTE: {len(residual)} residual risk(s) require acknowledgement:")
        for r in residual:
            print(f"    [!] {r}")
        print()

    print("Options:")
    print("  [A] Approve — proceed to codegen + explainability agents")
    print("  [R] Reject  — send back to architecture_agent with feedback")
    print("  [M] Modify  — approve with additional arch constraints")
    print()

    while True:
        choice = input("Your decision [A/R/M]: ").strip().upper()
        if choice in ("A", "R", "M"):
            break
        print("  Invalid input — please enter A, R, or M")

    feedback    = None
    extra_notes = None
    risk_acknowledged = False

    if choice == "R":
        feedback = input("Rejection reason (passed back to architecture_agent): ").strip()

    if choice == "M":
        extra_notes = input("Additional architecture constraints: ").strip()

    # force acknowledgement if residual risks exist
    if residual and choice in ("A", "M"):
        print("\n  Residual risks must be explicitly acknowledged before approval.")
        ack = input("  Type ACKNOWLEDGE to confirm you accept these risks: ").strip().upper()
        risk_acknowledged = ack == "ACKNOWLEDGE"
        if not risk_acknowledged:
            print("  Acknowledgement not confirmed — defaulting to rejection.")
            choice   = "R"
            feedback = "Residual risks not acknowledged by reviewer."

    decision = {
        "gate":               "hitl_gate_2",
        "approved":           choice in ("A", "M"),
        "choice":             choice,
        "approver":           input("Your name (for audit log): ").strip(),
        "feedback":           feedback,
        "extra_notes":        extra_notes,
        "risk_acknowledged":  risk_acknowledged,
        "residual_risks_seen": arch.get("residual_risks", []),
        "timestamp":          datetime.now(timezone.utc).isoformat(),
    }

    return decision


def hitl_gate_2(state: DevState) -> dict:

    if not state.get("architecture") or not state.get("compliance_rules"):
        raise ValueError("hitl_gate_2 requires architecture and compliance_rules in state")

    decision = get_human_decision_2(state)

    updated_arch = state["architecture"]

    # merge extra constraints into architecture if modified
    if decision.get("extra_notes"):
        updated_arch.setdefault("human_constraints", []).append(decision["extra_notes"])

    # if rejected stamp feedback for architecture_agent rerun
    updated_raw = state["raw_input"]
    if not decision["approved"] and decision.get("feedback"):
        updated_raw = (
            f"{state['raw_input']}\n\n"
            f"[HITL Gate 2 feedback]: {decision['feedback']}"
        )

    audit_entry = make_audit_entry(
        agent   = "hitl_gate_2",
        summary = f"Gate 2 decision: {decision['choice']} by {decision['approver']} | risks acknowledged: {decision['risk_acknowledged']}",
        data    = decision,
    )

    return {
        "hitl_decisions": (state["hitl_decisions"] or []) + [decision],
        "architecture":   updated_arch,
        "raw_input":      updated_raw,
        "audit_log":      [audit_entry],
    }


def route_after_hitl_2(state: DevState) -> str:
    last = state["hitl_decisions"][-1]

    if last["gate"] != "hitl_gate_2":
        raise ValueError("route_after_hitl_2 called but last decision is not from gate 2")

    if last["approved"]:
        return "codegen_agent"
    else:
        return "architecture_agent"
    

CODEGEN_SCHEMA = """
{
  "modules": [
    {
      "filename": "string — e.g. auth/router.py",
      "layer": "string — which arch layer this belongs to",
      "description": "string — what this file does",
      "rationale": "string — why it was built this way",
      "compliance_controls": ["string — which rules this file satisfies"],
      "code": "string — the actual python code"
    }
  ],
  "project_structure": ["string — full file tree e.g. app/main.py"],
  "setup_instructions": ["string — how to run the project"],
  "dependencies": ["string — pip install requirements"]
}
"""

def codegen_agent(state: DevState) -> dict:
    manifest    = state["intent_manifest"]
    arch        = state["architecture"]
    compliance  = state["compliance_rules"]
    ip          = state["ip_clearance"]

    layers              = arch.get("layers", [])
    infra               = arch.get("infrastructure", {})
    security_controls   = arch.get("security_controls", [])
    consolidated_rules  = compliance.get("consolidated_rules", [])
    human_constraints   = arch.get("human_constraints", [])

    prompt = f"""
You are a senior Python engineer generating production-grade code.

Intent Manifest:
{json.dumps(manifest, indent=2)}

Approved Architecture:
- Pattern    : {arch.get('selected_pattern')}
- Layers     : {json.dumps([l['name'] for l in layers], indent=2)}
- Infrastructure: {json.dumps(infra, indent=2)}

Security Controls to Implement:
{json.dumps(security_controls, indent=2)}

Compliance Rules to Satisfy in Code:
{json.dumps(consolidated_rules, indent=2)}

Human Constraints Added at Review:
{json.dumps(human_constraints, indent=2) if human_constraints else "None"}

IP Cleared Libraries Only:
{json.dumps([lib['name'] for lib in ip.get('scanned_libraries', [])], indent=2)}

Your tasks:
1. Generate all necessary Python files to implement the approved architecture
2. Every function must have a docstring explaining what it does and why
3. Every file must have a module-level comment mapping it to an architecture layer
4. Security controls must be implemented exactly as specified — no shortcuts
5. Compliance rules must be visible in the code as inline comments
   e.g. # [GDPR] encrypted at rest via TDE  or  # [OWASP] parameterized query
6. Use ONLY the IP-cleared libraries listed above
7. Include a main.py, requirements.txt content, and alembic setup

Respond ONLY with valid JSON matching this schema, no explanation, no markdown:
{CODEGEN_SCHEMA}
"""

    response = llm.invoke(prompt)
    code     = extract_json(response.text)

    modules        = code.get("modules", [])
    files_generated = [m["filename"] for m in modules]

    audit_entry = make_audit_entry(
        agent   = "codegen_agent",
        summary = f"Code generated — {len(modules)} files | pattern: {arch.get('selected_pattern')}",
        data    = {
            "files_generated":   files_generated,
            "dependencies":      code.get("dependencies", []),
            "pattern":           arch.get("selected_pattern"),
            "compliance_tagged": True,
        }
    )

    return {
        "generated_code": code,
        "audit_log":      [audit_entry],
    }

SECURITY_RULES = {
    "hardcoded_secrets": {
        "pattern":     r'(SECRET_KEY|PASSWORD|API_KEY|TOKEN|secret|password)\s*=\s*["\'][^"\']+["\']',
        "severity":    "critical",
        "owasp":       "A02:2021 Cryptographic Failures",
        "fix":         "Move to environment variables using python-dotenv or secrets manager",
    },
    "sql_injection": {
        "pattern":     r'execute\s*\(\s*[f"\'].*\{',
        "severity":    "critical",
        "owasp":       "A03:2021 Injection",
        "fix":         "Use SQLAlchemy ORM or parameterized queries only",
    },
    "debug_mode": {
        "pattern":     r'DEBUG\s*=\s*True|reload\s*=\s*True',
        "severity":    "high",
        "owasp":       "A05:2021 Security Misconfiguration",
        "fix":         "Disable debug/reload in production — use environment flag",
    },
    "http_not_https": {
        "pattern":     r'http://(?!localhost|127\.0\.0\.1)',
        "severity":    "high",
        "owasp":       "A02:2021 Cryptographic Failures",
        "fix":         "Use HTTPS for all external URLs",
    },
    "bare_except": {
        "pattern":     r'except\s*:',
        "severity":    "medium",
        "owasp":       "A09:2021 Security Logging and Monitoring Failures",
        "fix":         "Catch specific exceptions — bare except hides security errors",
    },
    "missing_auth_dependency": {
        "pattern":     r'@router\.(get|post|put|delete)\s*\([^)]*\)\s*\nasync def(?!.*Depends)',
        "severity":    "high",
        "owasp":       "A01:2021 Broken Access Control",
        "fix":         "Add FastAPI Depends(get_current_user) to protected routes",
    },
    "unlicensed_import": {
        "pattern":     None,   # handled separately via ip_clearance check
        "severity":    "high",
        "owasp":       "IP Compliance",
        "fix":         "Use only IP-cleared libraries",
    },
}

SECURITY_SCHEMA = """
{
  "findings": [
    {
      "filename":    "string",
      "rule":        "string — which security rule was violated",
      "severity":    "critical | high | medium | low",
      "owasp_ref":   "string — OWASP category",
      "line_hint":   "string — the problematic code snippet",
      "fix":         "string — how to fix it"
    }
  ],
  "unlicensed_imports": ["string — any imports not in ip_clearance"],
  "compliance_tag_coverage": {
    "files_with_tags":    "number — files containing compliance comments",
    "files_without_tags": ["string — filenames missing compliance comments"],
    "coverage_percent":   "number"
  },
  "overall_security_risk": "critical | high | medium | low",
  "passed":                "boolean — true only if no critical findings",
  "summary":               "string — one paragraph summary"
}
"""

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


EXPLAINABILITY_SCHEMA = """
{
  "decision_log": [
    {
      "decision_point": "string — e.g. Architecture Pattern Selection",
      "what_was_decided": "string — the actual decision made",
      "why": "string — plain English reasoning",
      "alternatives_considered": ["string — other options that were evaluated"],
      "trade_offs_accepted": ["string — what was given up"],
      "constraint_satisfied": ["string — which intent/compliance constraint this serves"]
    }
  ],
  "module_explanations": [
    {
      "filename": "string",
      "purpose": "string — what this file does in plain English",
      "key_decisions": ["string — notable implementation choices"],
      "compliance_mapping": ["string — which rules this file satisfies and how"]
    }
  ],
  "glossary": [
    {
      "term": "string — technical term used in the project",
      "plain_english": "string — what it means for a non-technical stakeholder"
    }
  ],
  "audit_narrative": "string — a single paragraph telling the full story of how this system was built, what decisions were made, and why — written for a regulator or auditor"
}
"""

def explainability_agent(state: DevState) -> dict:
    manifest    = state["intent_manifest"]
    arch        = state["architecture"]
    compliance  = state["compliance_rules"]
    code        = state["generated_code"]
    security    = state["security_report"]
    decisions   = state["hitl_decisions"]

    hitl_trail = []
    for d in decisions:
        hitl_trail.append({
            "gate":     d.get("gate"),
            "choice":   d.get("choice"),
            "approver": d.get("approver"),
            "notes":    d.get("extra_notes") or d.get("feedback") or "none",
            "risks_acknowledged": d.get("risk_acknowledged", False),
        })

    prompt = f"""
You are a technical documentation specialist and compliance explainer.

Your job is to produce a complete explainability report for a software system
that was designed and built by an AI pipeline. This report must be readable by:
- Non-technical business stakeholders
- Regulators and auditors
- Future developers joining the project

Here is everything the pipeline produced:

Original User Intent:
{state['raw_input']}

Intent Manifest:
{json.dumps(manifest, indent=2)}

Architecture Decisions:
- Pattern   : {arch.get('selected_pattern')}
- Rationale : {arch.get('pattern_rationale')}
- Layers    : {json.dumps([l['name'] for l in arch.get('layers', [])], indent=2)}
- Residual Risks: {json.dumps(arch.get('residual_risks', []), indent=2)}

Compliance Frameworks Applied:
{json.dumps([f['name'] for f in compliance.get('applicable_frameworks', [])], indent=2)}

Compliance Rules Enforced:
{json.dumps(compliance.get('consolidated_rules', []), indent=2)}

Generated Files:
{json.dumps([{
    'filename': m['filename'],
    'layer': m['layer'],
    'description': m['description'],
    'compliance_controls': m.get('compliance_controls', [])
} for m in code.get('modules', [])], indent=2)}

Security Findings:
{json.dumps(security.get('findings', []), indent=2)}

Human Review Trail:
{json.dumps(hitl_trail, indent=2)}

Your tasks:
1. Document every major decision point with plain English reasoning
2. Explain each generated file to a non-technical audience
3. Build a glossary of technical terms used
4. Write an audit narrative — one paragraph that tells the full story
   of how this system was designed, reviewed, and built

Respond ONLY with valid JSON matching this schema, no explanation, no markdown:
{EXPLAINABILITY_SCHEMA}
"""

    response = llm.invoke(prompt)
    docs     = extract_json(response.text)

    decisions_documented = len(docs.get("decision_log", []))
    modules_explained    = len(docs.get("module_explanations", []))
    glossary_terms       = len(docs.get("glossary", []))

    audit_entry = make_audit_entry(
        agent   = "explainability_agent",
        summary = (
            f"Explainability docs generated — "
            f"{decisions_documented} decisions | "
            f"{modules_explained} modules | "
            f"{glossary_terms} glossary terms"
        ),
        data    = {
            "decisions_documented": decisions_documented,
            "modules_explained":    modules_explained,
            "glossary_terms":       glossary_terms,
            "audit_narrative_len":  len(docs.get("audit_narrative", "")),
        }
    )

    return {
        "explainability_docs": docs,
        "audit_log":           [audit_entry],
    }


QUALITY_SCHEMA = """
{
  "test_results": [
    {
      "filename":    "string — file being tested",
      "test_name":   "string — what was tested",
      "status":      "pass | fail | warning",
      "detail":      "string — what was found"
    }
  ],
  "acceptance_criteria_check": [
    {
      "criterion":   "string — from intent manifest",
      "status":      "met | not_met | partial",
      "evidence":    "string — which file/function satisfies this"
    }
  ],
  "code_quality": {
    "has_docstrings":         "boolean",
    "has_type_hints":         "boolean",
    "has_error_handling":     "boolean",
    "has_async_support":      "boolean",
    "missing_docstrings_in":  ["string — filenames"],
    "missing_error_handling_in": ["string — filenames"]
  },
  "security_integration": {
    "security_findings_addressed": "boolean",
    "critical_blockers":           ["string — unresolved critical findings"],
    "ready_for_deploy":            "boolean"
  },
  "overall_quality_score":  "number — 0 to 100",
  "passed":                 "boolean — true only if score >= 70 and no critical blockers",
  "recommendations":        ["string — specific improvements to make"],
  "summary":                "string — one paragraph quality assessment"
}
"""

def run_local_quality_checks(state: DevState) -> dict:
    """
    Fast local checks before hitting the LLM.
    Checks docstrings, type hints, error handling, async support.
    """
    modules        = state["generated_code"].get("modules", [])
    manifest       = state["intent_manifest"]
    security       = state["security_report"]

    local_results  = []
    quality_issues = {
        "missing_docstrings":      [],
        "missing_type_hints":      [],
        "missing_error_handling":  [],
        "missing_async":           [],
    }

    for module in modules:
        filename = module.get("filename", "unknown")
        code     = module.get("code", "")

        # check docstrings
        has_docstring = '"""' in code or "'''" in code
        if not has_docstring:
            quality_issues["missing_docstrings"].append(filename)
            local_results.append({
                "filename":  filename,
                "test_name": "docstring_check",
                "status":    "warning",
                "detail":    "No docstrings found — functions lack documentation",
            })
        else:
            local_results.append({
                "filename":  filename,
                "test_name": "docstring_check",
                "status":    "pass",
                "detail":    "Docstrings present",
            })

        # check type hints
        has_type_hints = "->" in code or ": str" in code or ": dict" in code
        if not has_type_hints:
            quality_issues["missing_type_hints"].append(filename)
            local_results.append({
                "filename":  filename,
                "test_name": "type_hint_check",
                "status":    "warning",
                "detail":    "No type hints detected",
            })
        else:
            local_results.append({
                "filename":  filename,
                "test_name": "type_hint_check",
                "status":    "pass",
                "detail":    "Type hints present",
            })

        # check error handling
        has_error_handling = "try:" in code or "except" in code or "HTTPException" in code
        if not has_error_handling:
            quality_issues["missing_error_handling"].append(filename)
            local_results.append({
                "filename":  filename,
                "test_name": "error_handling_check",
                "status":    "warning",
                "detail":    "No error handling found — add try/except or HTTPException",
            })
        else:
            local_results.append({
                "filename":  filename,
                "test_name": "error_handling_check",
                "status":    "pass",
                "detail":    "Error handling present",
            })

        # check async support
        has_async = "async def" in code or "await" in code
        if not has_async:
            quality_issues["missing_async"].append(filename)
            local_results.append({
                "filename":  filename,
                "test_name": "async_check",
                "status":    "warning",
                "detail":    "No async functions — consider async for I/O bound operations",
            })
        else:
            local_results.append({
                "filename":  filename,
                "test_name": "async_check",
                "status":    "pass",
                "detail":    "Async support present",
            })

    criteria         = manifest.get("acceptance_criteria", [])
    code_dump        = " ".join([m.get("code", "") for m in modules])
    criteria_results = []

    keywords_map = {
        "register":       ["register", "signup", "UserCreate"],
        "log in":         ["login", "token", "create_access_token"],
        "dashboard":      ["dashboard", "protected", "Depends"],
        "postgresql":     ["postgresql", "asyncpg", "create_async_engine"],
        "authenticated":  ["Depends", "get_current_user", "verify_token"],
        "persisted":      ["session", "db", "commit", "add"],
    }

    for criterion in criteria:
        matched = False
        evidence = "not found in generated code"
        criterion_lower = criterion.lower()

        for keyword, code_signals in keywords_map.items():
            if keyword in criterion_lower:
                for signal in code_signals:
                    if signal in code_dump:
                        matched   = True
                        evidence  = f"'{signal}' found in generated code"
                        break

        criteria_results.append({
            "criterion": criterion,
            "status":    "met" if matched else "partial",
            "evidence":  evidence,
        })

    # check if critical security findings are still unresolved
    critical_blockers = [
        f"{f['filename']}: {f['rule']}"
        for f in security.get("findings", [])
        if f["severity"] == "critical"
    ]

    return {
        "local_results":      local_results,
        "criteria_results":   criteria_results,
        "quality_issues":     quality_issues,
        "critical_blockers":  critical_blockers,
    }


def quality_agent(state: DevState) -> dict:
    manifest  = state["intent_manifest"]
    arch      = state["architecture"]
    code      = state["generated_code"]
    security  = state["security_report"]
    explain   = state["explainability_docs"]
    modules   = code.get("modules", [])

    # ── local checks first ─────────────────────────────────────────
    local     = run_local_quality_checks(state)

    code_dump = "\n\n".join([
        f"### {m['filename']}\n{m['code']}"
        for m in modules
    ])

    prompt = f"""
You are a senior software quality engineer performing a final quality assessment.

Original Acceptance Criteria:
{json.dumps(manifest.get('acceptance_criteria', []), indent=2)}

Architecture Pattern: {arch.get('selected_pattern')}

Generated Code:
{code_dump}

Local Quality Check Results:
{json.dumps(local['local_results'], indent=2)}

Acceptance Criteria Pre-check:
{json.dumps(local['criteria_results'], indent=2)}

Security Report Summary:
- Overall risk    : {security.get('overall_security_risk')}
- Passed          : {security.get('passed')}
- Critical count  : {sum(1 for f in security.get('findings', []) if f['severity'] == 'critical')}
- Critical blockers: {json.dumps(local['critical_blockers'], indent=2)}

Explainability Coverage:
- Decisions documented : {len(explain.get('decision_log', []))}
- Modules explained    : {len(explain.get('module_explanations', []))}
- Glossary terms       : {len(explain.get('glossary', []))}

Your tasks:
1. Validate every acceptance criterion against the generated code
2. Assess overall code quality — docstrings, type hints, error handling, async
3. Check if security findings are acknowledged and have a remediation path
4. Score the overall quality from 0-100 using this rubric:
   - Acceptance criteria met      : 30 points
   - Code quality                 : 25 points
   - Security findings addressed  : 25 points
   - Explainability coverage      : 20 points
5. Set passed = true ONLY if score >= 70 AND no unresolved critical security findings
6. Give specific, actionable recommendations

Respond ONLY with valid JSON matching this schema, no explanation, no markdown:
{QUALITY_SCHEMA}
"""

    response = llm.invoke(prompt)
    report   = extract_json(response.text)

    # always override security_integration with our local check
    report["security_integration"] = {
        "security_findings_addressed": len(local["critical_blockers"]) == 0,
        "critical_blockers":           local["critical_blockers"],
        "ready_for_deploy":            len(local["critical_blockers"]) == 0
                                       and report.get("overall_quality_score", 0) >= 70,
    }

    # passed only if no critical blockers AND score >= 70
    critical_count = sum(
        1 for f in security.get("findings", [])
        if f["severity"] == "critical"
    )
    report["passed"] = (
        critical_count == 0
        and report.get("overall_quality_score", 0) >= 70
    )

    score   = report.get("overall_quality_score", 0)
    passed  = report.get("passed", False)

    audit_entry = make_audit_entry(
        agent   = "quality_agent",
        summary = (
            f"Quality assessment complete — "
            f"score: {score}/100 | "
            f"passed: {passed} | "
            f"critical blockers: {len(local['critical_blockers'])}"
        ),
        data    = {
            "score":             score,
            "passed":            passed,
            "critical_blockers": local["critical_blockers"],
            "criteria_met":      sum(
                1 for c in report.get("acceptance_criteria_check", [])
                if c["status"] == "met"
            ),
            "recommendations":   report.get("recommendations", []),
        }
    )

    return {
        "quality_report": report,
        "audit_log":      [audit_entry],
    }

AUDIT_SCHEMA = """
{
  "pipeline_summary": {
    "total_agents_run":      "number",
    "total_hitl_decisions":  "number",
    "total_findings":        "number",
    "pipeline_passed":       "boolean",
    "blocking_issues":       ["string"]
  },
  "compliance_sign_off": {
    "gdpr_controls_verified":  "boolean",
    "owasp_controls_verified": "boolean",
    "ip_clearance_verified":   "boolean",
    "gaps_resolved":           "boolean",
    "unresolved_items":        ["string"]
  },
  "human_accountability": [
    {
      "gate":      "string",
      "approver":  "string",
      "decision":  "string",
      "timestamp": "string",
      "risks_acknowledged": "boolean",
      "notes":     "string"
    }
  ],
  "immutable_digest": {
    "intent_hash":       "string — md5 of intent manifest",
    "architecture_hash": "string — md5 of architecture",
    "code_hash":         "string — md5 of generated code filenames",
    "audit_chain_hash":  "string — md5 of full audit log"
  },
  "final_status":  "approved_for_deploy | blocked | requires_remediation",
  "sign_off_note": "string — one paragraph final audit statement"
}
"""

def compute_hash(data) -> str:
    """Compute MD5 hash of any serializable data for audit digest."""
    raw = json.dumps(data, sort_keys=True, default=str)
    return hashlib.md5(raw.encode()).hexdigest()


def audit_agent(state: DevState) -> dict:
    manifest    = state["intent_manifest"]
    arch        = state["architecture"]
    compliance  = state["compliance_rules"]
    ip          = state["ip_clearance"]
    code        = state["generated_code"]
    security    = state["security_report"]
    quality     = state["quality_report"]
    explain     = state["explainability_docs"]
    decisions   = state["hitl_decisions"]
    audit_log   = state["audit_log"]

    # ── compute immutable digest ────────────────────────────────────
    immutable_digest = {
        "intent_hash":       compute_hash(manifest),
        "architecture_hash": compute_hash(arch),
        "code_hash":         compute_hash([
            m["filename"] for m in code.get("modules", [])
        ]),
        "audit_chain_hash":  compute_hash(audit_log),
    }

    # ── build human accountability trail ───────────────────────────
    accountability = []
    for d in decisions:
        accountability.append({
            "gate":               d.get("gate"),
            "approver":           d.get("approver"),
            "decision":           d.get("choice"),
            "timestamp":          d.get("timestamp"),
            "risks_acknowledged": d.get("risk_acknowledged", False),
            "notes":              d.get("extra_notes") or d.get("feedback") or "none",
        })

    # ── check blocking issues ───────────────────────────────────────
    blocking_issues = []

    # critical security findings
    critical_findings = [
        f"{f['filename']}: {f['rule']}"
        for f in security.get("findings", [])
        if f["severity"] == "critical"
    ]
    blocking_issues.extend(critical_findings)

    # quality not passed
    if not quality.get("passed"):
        blocking_issues.append(
            f"Quality score {quality.get('overall_quality_score')}/100 — below threshold"
        )

    # unmet acceptance criteria
    unmet = [
        c["criterion"]
        for c in quality.get("acceptance_criteria_check", [])
        if c["status"] == "not_met"
    ]
    blocking_issues.extend([f"Unmet criterion: {u}" for u in unmet])

    # ── compliance verification ─────────────────────────────────────
    frameworks    = [
        f["name"] for f in compliance.get("applicable_frameworks", [])
    ]
    gaps          = compliance.get("gaps", [])
    gaps_addressed = arch.get("gaps_addressed", [])
    unresolved    = [
        g for g in gaps
        if not any(
            any(w in a.lower() for w in g.lower().split()[:3])
            for a in gaps_addressed
        )
    ]

    compliance_sign_off = {
        "gdpr_controls_verified":  "GDPR" in frameworks,
        "owasp_controls_verified": "OWASP Top 10" in frameworks,
        "ip_clearance_verified":   ip.get("overall_risk") in ("low", "medium"),
        "gaps_resolved":           len(unresolved) == 0,
        "unresolved_items":        unresolved,
    }

    # ── determine final status ──────────────────────────────────────
    if blocking_issues:
        final_status = "requires_remediation"
    elif not quality.get("passed"):
        final_status = "blocked"
    else:
        final_status = "approved_for_deploy"

    # ── LLM generates the sign-off note ────────────────────────────
    prompt = f"""
You are a senior compliance auditor writing a final audit statement
for a software system built by an AI pipeline.

Pipeline Summary:
- Agents run        : {len(audit_log)}
- HITL decisions    : {len(decisions)}
- Security findings : {len(security.get('findings', []))}
- Quality score     : {quality.get('overall_quality_score')}/100
- Final status      : {final_status}

Human Accountability Trail:
{json.dumps(accountability, indent=2)}

Blocking Issues:
{json.dumps(blocking_issues, indent=2) if blocking_issues else "None"}

Compliance Sign-off:
{json.dumps(compliance_sign_off, indent=2)}

Immutable Digest:
{json.dumps(immutable_digest, indent=2)}

Write a single paragraph audit statement that:
1. States what was built and by whom it was reviewed
2. Confirms which compliance frameworks were verified
3. Lists any blocking issues that prevent deployment
4. States the final deployment status clearly
5. Is written for a regulator or external auditor

Return ONLY the paragraph as a plain string — no JSON, no markdown.
"""

    response  = llm.invoke(prompt)
    sign_off  = response.text.strip()

    # ── build final report ──────────────────────────────────────────
    report = {
        "pipeline_summary": {
            "total_agents_run":     len(audit_log),
            "total_hitl_decisions": len(decisions),
            "total_findings":       len(security.get("findings", [])),
            "pipeline_passed":      len(blocking_issues) == 0,
            "blocking_issues":      blocking_issues,
        },
        "compliance_sign_off":  compliance_sign_off,
        "human_accountability": accountability,
        "immutable_digest":     immutable_digest,
        "final_status":         final_status,
        "sign_off_note":        sign_off,
    }

    status_display = {
        "approved_for_deploy":  "APPROVED FOR DEPLOY",
        "blocked":              "BLOCKED",
        "requires_remediation": "REQUIRES REMEDIATION",
    }.get(final_status, final_status.upper())

    audit_entry = make_audit_entry(
        agent   = "audit_agent",
        summary = (
            f"Final audit complete — "
            f"status: {status_display} | "
            f"blocking issues: {len(blocking_issues)} | "
            f"digest: {immutable_digest['audit_chain_hash'][:8]}..."
        ),
        data    = {
            "final_status":         final_status,
            "blocking_issues":      len(blocking_issues),
            "pipeline_passed":      len(blocking_issues) == 0,
            "immutable_digest":     immutable_digest,
            "compliance_sign_off":  compliance_sign_off,
        }
    )

    return {
        "audit_log": [audit_entry],
        "quality_report": {
            **quality,
            "final_audit": report,
        }
    }

def display_hitl3_summary(state: DevState):
    security  = state["security_report"]
    quality   = state["quality_report"]
    audit     = quality.get("final_audit", {})
    arch      = state["architecture"]

    print("\n" + "="*60)
    print("  HITL GATE 3 — FINAL DEPLOY SIGN-OFF")
    print("="*60)

    # ── final status banner ────────────────────────────────────────
    final_status = audit.get("final_status", "unknown")
    status_display = {
        "approved_for_deploy":  "APPROVED FOR DEPLOY",
        "blocked":              "BLOCKED",
        "requires_remediation": "REQUIRES REMEDIATION",
    }.get(final_status, final_status.upper())
    print(f"\n[ Pipeline Status ]  {status_display}")

    # ── pipeline summary ───────────────────────────────────────────
    ps = audit.get("pipeline_summary", {})
    print("\n[ Pipeline Summary ]")
    print(f"  Agents run        : {ps.get('total_agents_run')}")
    print(f"  HITL decisions    : {ps.get('total_hitl_decisions')}")
    print(f"  Security findings : {ps.get('total_findings')}")
    print(f"  Quality score     : {quality.get('overall_quality_score')}/100")

    blocking = ps.get("blocking_issues", [])
    if blocking:
        print("\n[ Blocking Issues ]")
        for b in blocking:
            print(f"  [!!] {b}")
    else:
        print("\n[ Blocking Issues ]  None")

    print("\n[ Security Findings ]")
    findings = security.get("findings", [])
    if findings:
        for f in findings:
            print(f"  [{f['severity'].upper():8s}] {f['filename']} — {f['rule']}")
            print(f"             Fix: {f['fix']}")
    else:
        print("  No findings")

    print("\n[ Compliance Sign-off ]")
    cs = audit.get("compliance_sign_off", {})
    print(f"  GDPR verified  : {cs.get('gdpr_controls_verified')}")
    print(f"  OWASP verified : {cs.get('owasp_controls_verified')}")
    print(f"  IP clearance   : {cs.get('ip_clearance_verified')}")
    print(f"  Gaps resolved  : {cs.get('gaps_resolved')}")
    if cs.get("unresolved_items"):
        for u in cs["unresolved_items"]:
            print(f"  [!] Unresolved : {u}")

    print("\n[ Human Accountability Trail ]")
    for h in audit.get("human_accountability", []):
        print(f"  {h['gate']:15s} | {h['approver']:10s} | "
              f"{h['decision']} | ack risks: {h['risks_acknowledged']} "
              f"| {h['timestamp']}")

    if arch.get("residual_risks"):
        print("\n[ Residual Risks ]")
        for r in arch.get("residual_risks", []):
            print(f"  [!] {r}")

    # ── immutable digest ───────────────────────────────────────────
    print("\n[ Immutable Digest ]")
    d = audit.get("immutable_digest", {})
    for k, v in d.items():
        print(f"  {k:20s} : {v}")

    print(f"\n[ Audit Sign-off Note ]\n  {audit.get('sign_off_note', '')}")

    print("\n" + "-"*60)


def get_human_decision_3(state: DevState) -> dict:
    display_hitl3_summary(state)

    audit    = state["quality_report"].get("final_audit", {})
    blocking = audit.get("pipeline_summary", {}).get("blocking_issues", [])
    security = state["security_report"]

    critical_count = sum(
        1 for f in security.get("findings", [])
        if f["severity"] == "critical"
    )

    if blocking:
        print(f"\n  WARNING: {len(blocking)} blocking issue(s) detected.")
        print("  Approving with blockers creates a formal risk acceptance record.")
        print("  You may still approve but must provide justification.\n")

    print("Options:")
    print("  [A] Approve    — sign off and deploy")
    print("  [R] Reject     — send back to codegen_agent for fixes")
    print("  [H] Hold       — pause pipeline, escalate to senior reviewer")
    print()

    while True:
        choice = input("Your decision [A/R/H]: ").strip().upper()
        if choice in ("A", "R", "H"):
            break
        print("  Invalid input — please enter A, R, or H")

    feedback      = None
    justification = None

    if choice == "R":
        feedback = input(
            "What must be fixed before resubmission: "
        ).strip()

    if choice == "H":
        feedback = input(
            "Escalation reason (will be logged): "
        ).strip()

    if choice == "A" and blocking:
        print(f"\n  {len(blocking)} blocking issue(s) exist.")
        justification = input(
            "  Provide formal justification for approving with blockers: "
        ).strip()
        if not justification:
            print("  No justification provided — defaulting to Hold.")
            choice   = "H"
            feedback = "Approved with blockers but no justification provided."

    if choice == "A" and critical_count > 0:
        print(f"\n  {critical_count} critical security finding(s) require acknowledgement.")
        ack = input(
            "  Type ACCEPT RISK to formally accept these risks: "
        ).strip().upper()
        if ack != "ACCEPT RISK":
            print("  Risk not accepted — defaulting to Reject.")
            choice   = "R"
            feedback = "Critical findings not formally accepted by reviewer."

    approver = input("\nYour name (for audit log): ").strip()
    role     = input("Your role (e.g. Tech Lead, CTO): ").strip()

    decision = {
        "gate":             "hitl_gate_3",
        "approved":         choice == "A",
        "choice":           choice,
        "approver":         approver,
        "role":             role,
        "feedback":         feedback,
        "justification":    justification,
        "blocking_count":   len(blocking),
        "critical_count":   critical_count,
        "timestamp":        datetime.now(timezone.utc).isoformat()
    }

    return decision


def hitl_gate_3(state: DevState) -> dict:

    if not state.get("quality_report") or not state.get("security_report"):
        raise ValueError(
            "hitl_gate_3 requires quality_report and security_report in state"
        )

    decision = get_human_decision_3(state)

    updated_raw = state["raw_input"]
    if not decision["approved"] and decision.get("feedback"):
        updated_raw = (
            f"{state['raw_input']}\n\n"
            f"[HITL Gate 3 feedback]: {decision['feedback']}\n"
            f"Security findings to fix: "
            f"{[f['rule'] for f in state['security_report'].get('findings', [])]}"
        )

    status = {
        "A": "APPROVED FOR DEPLOY",
        "R": "REJECTED — REWORK REQUIRED",
        "H": "ON HOLD — ESCALATED",
    }.get(decision["choice"], "UNKNOWN")

    audit_entry = make_audit_entry(
        agent   = "hitl_gate_3",
        summary = (
            f"Gate 3 decision: {decision['choice']} "
            f"by {decision['approver']} ({decision['role']}) | "
            f"status: {status} | "
            f"blocking issues: {decision['blocking_count']} | "
            f"critical findings: {decision['critical_count']}"
        ),
        data    = decision,
    )

    return {
        "hitl_decisions": (state["hitl_decisions"] or []) + [decision],
        "raw_input":      updated_raw,
        "audit_log":      [audit_entry],
    }


def route_after_hitl_3(state: DevState) -> str:
    last = state["hitl_decisions"][-1]

    if last["gate"] != "hitl_gate_3":
        raise ValueError(
            "route_after_hitl_3 called but last decision is not from gate 3"
        )

    if last["choice"] == "A":
        return "optimizer_agent"     # approved → optimize then monitor
    elif last["choice"] == "R":
        return "codegen_agent"       # rejected → fix and rerun
    else:
        return "end"                 # hold → escalate, stop pipeline
    


OPTIMIZER_SCHEMA = """
{
  "optimizations": [
    {
      "filename":    "string",
      "type":        "performance | readability | security | tech_debt",
      "original":    "string — what was there",
      "improved":    "string — what it should be",
      "reason":      "string — why this is better"
    }
  ],
  "rewritten_modules": [
    {
      "filename": "string",
      "code":     "string — the FULL rewritten code with all fixes applied"
    }
  ],
  "tech_debt_score":   "number — 0 to 100 (100 = no debt)",
  "summary":           "string — one paragraph optimization summary"
}
"""

def optimizer_agent(state: DevState) -> dict:
    code     = state["generated_code"]
    security = state.get("security_report") or {}
    quality  = state.get("quality_report")  or {}

    code_dump = "\n\n".join([
        f"### {m['filename']}\n{m['code']}"
        for m in code.get("modules", [])
    ])

    prompt = f"""
You are a senior Python engineer performing a proactive code optimization pass.

Generated Code:
{code_dump}

Known issues to fix proactively:
1. Replace ALL hardcoded secrets with os.getenv() calls
   e.g. SECRET_KEY = os.getenv("SECRET_KEY", "")
   e.g. DATABASE_URL = os.getenv("DATABASE_URL", "")
2. Replace bare 'import jwt' with 'import PyJWT' — use PyJWT correctly
3. Add type hints to all function signatures and return types
4. Add try/except with HTTPException around all database and auth operations
5. Disable echo=True in SQLAlchemy engine
6. Add missing docstrings to any functions that lack them
7. Any other performance or readability improvements

Previously detected security findings:
{json.dumps(security.get('findings', []), indent=2) if security else "Not yet scanned — fix proactively"}

Previously detected quality issues:
{json.dumps(quality.get('recommendations', []), indent=2) if quality else "Not yet assessed — fix proactively"}

IMPORTANT: In rewritten_modules return the COMPLETE rewritten file code
with ALL fixes applied — not just the changed lines.

Respond ONLY with valid JSON matching this schema, no explanation, no markdown:
{OPTIMIZER_SCHEMA}
"""

    response = llm.invoke(prompt)
    opts     = extract_json(response.text)

    rewritten_map = {
        r["filename"]: r["code"]
        for r in opts.get("rewritten_modules", [])
    }

    updated_modules = []
    for module in code.get("modules", []):
        filename = module["filename"]
        updated  = module.copy()

        if filename in rewritten_map:
            updated["code"]              = rewritten_map[filename]  
            updated["code_optimized"]    = True

        module_opts = [
            o for o in opts.get("optimizations", [])
            if o.get("filename") == filename
        ]
        if module_opts:
            updated["optimizations_applied"] = module_opts

        updated_modules.append(updated)

    updated_code = {**code, "modules": updated_modules}

    audit_entry = make_audit_entry(
        agent   = "optimizer_agent",
        summary = (
            f"Optimization complete — "
            f"{len(opts.get('optimizations', []))} improvements | "
            f"tech debt score: {opts.get('tech_debt_score')}/100"
        ),
        data    = {
            "optimizations":    len(opts.get("optimizations", [])),
            "tech_debt_score":  opts.get("tech_debt_score"),
            "files_rewritten":  list(rewritten_map.keys()),
            "types": list({
                o["type"] for o in opts.get("optimizations", [])
            }),
        }
    )

    return {
        "generated_code": updated_code,
        "audit_log":      [audit_entry],
    }


from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Send

# ── conditional routing functions ──────────────────────────────────

def route_after_hitl_1(state: DevState) -> str:
    last = state["hitl_decisions"][-1]
    if last["choice"] in ("A", "M"):
        return "compliance_agent"
    return "intent_agent"

def route_after_hitl_2(state: DevState) -> str:
    last = state["hitl_decisions"][-1]
    if last["gate"] != "hitl_gate_2":
        return "hitl_gate_2"
    if last["choice"] in ("A", "M"):
        return "codegen_agent"
    return "architecture_agent"

def route_after_security(state: DevState) -> str:
    report = state.get("security_report", {})
    if report.get("passed"):
        return "explainability_agent"
    return "codegen_agent"          # loop back — fix and rescan

def route_after_quality(state: DevState) -> str:
    report = state.get("quality_report", {})
    if report.get("passed"):
        return "audit_agent"
    return "codegen_agent"          # loop back — fix and rescan

def route_after_hitl_3(state: DevState) -> str:
    last = state["hitl_decisions"][-1]
    if last["gate"] != "hitl_gate_3":
        return "hitl_gate_3"
    if last["choice"] == "A":
        return END
    elif last["choice"] == "R":
        return "codegen_agent"
    return END                      # H — hold, stop pipeline

# ── node wrappers ───────────────────────────────────────────────────
# LangGraph nodes must return state updates as dicts
# our agents already do this — just wire them directly

def intent_node(state: DevState) -> dict:
    return intent_agent(state)

def ip_guard_node(state: DevState) -> dict:
    return ip_guard_agent(state)

def hitl_1_node(state: DevState) -> dict:
    return hitl_gate_1(state)

def compliance_node(state: DevState) -> dict:
    return compliance_agent(state)

def architecture_node(state: DevState) -> dict:
    return architecture_agent(state)

def hitl_2_node(state: DevState) -> dict:
    return hitl_gate_2(state)

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
    return hitl_gate_3(state)


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
    graph.add_edge("security_agent",       "explainability_agent")
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

def compile_graph():
    graph     = build_graph()
    memory    = MemorySaver()

    app = graph.compile(
        checkpointer   = memory,
        interrupt_before = [
            "hitl_gate_1",
            "hitl_gate_2",
            "hitl_gate_3",
        ]
    )
    return app


def run_pipeline(raw_input: str):
    app    = compile_graph()
    config = {"configurable": {"thread_id": "dev-pipeline-1"}}

    initial_state: DevState = {
        "raw_input":           raw_input,
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
    }

    print("="*60)
    print("  AI-NATIVE DEV PIPELINE — LANGGRAPH")
    print("="*60)

    print("\n>> Phase 1: intent + IP scan...")
    for event in app.stream(initial_state, config):
        for node_name, node_output in event.items():
            print(f"  [node] {node_name}")

    print("\n>> Pipeline paused at hitl_gate_1")
    current = app.get_state(config)

    gate1_result = hitl_gate_1(current.values)
    app.update_state(config, gate1_result, as_node="hitl_gate_1")

    print("\n>> Phase 2: compliance + architecture...")
    for event in app.stream(None, config):
        for node_name, node_output in event.items():
            print(f"  [node] {node_name}")

    print("\n>> Pipeline paused at hitl_gate_2")
    current = app.get_state(config)

    gate2_result = hitl_gate_2(current.values)
    app.update_state(config, gate2_result, as_node="hitl_gate_2")

    print("\n>> Phase 3: codegen → optimizer → security → quality → audit...")
    for event in app.stream(None, config):
        for node_name, node_output in event.items():
            print(f"  [node] {node_name}")

    # ── HITL gate 3 ────────────────────────────────────────────────
    print("\n>> Pipeline paused at hitl_gate_3")
    current = app.get_state(config)

    gate3_result = hitl_gate_3(current.values)
    app.update_state(config, gate3_result, as_node="hitl_gate_3")

    print("\n>> Phase 4: finalising...")
    for event in app.stream(None, config):
        for node_name, node_output in event.items():
            print(f"  [node] {node_name}")

    final = app.get_state(config)
    final_state = final.values

    print("\n" + "="*60)
    print("  PIPELINE COMPLETE")
    print("="*60)

    audit = final_state.get("quality_report", {}).get("final_audit", {})
    print(f"\n  Final status  : {audit.get('final_status', '').upper()}")
    print(f"  Agents run    : {len(final_state.get('audit_log', []))}")
    print(f"  HITL decisions: {len(final_state.get('hitl_decisions', []))}")

    print("\n  Immutable Digest:")
    for k, v in audit.get("immutable_digest", {}).items():
        print(f"    {k:20s} : {v}")

    print("\n  Full Audit Log:")
    for entry in final_state.get("audit_log", []):
        print(f"    [{entry['timestamp']}] "
              f"{entry['agent']:20s} — {entry['summary']}")

    return final_state


# if __name__ == "__main__":
#     final_state = run_pipeline(
#         "Build a FastAPI web app with login and dashboard using PostgreSQL"
#     )




from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any
from uuid import uuid4
import json

# from pipeline import compile_graph, hitl_gate_1, hitl_gate_2, hitl_gate_3

app = FastAPI()

pipelines: Dict[str, Any] = {}

class RunRequest(BaseModel):
    raw_input: str

class HITLRequest(BaseModel):
    decision: Dict[str, Any]

def create_initial_state(raw_input: str):
    return {
        "raw_input": raw_input,
        "intent_manifest": None,
        "compliance_rules": None,
        "ip_clearance": None,
        "architecture": None,
        "generated_code": None,
        "explainability_docs": None,
        "security_report": None,
        "quality_report": None,
        "hitl_decisions": [],
        "audit_log": [],
        "drift_alerts": None,
    }

@app.post("/run")
def run_pipeline(req: RunRequest):
    thread_id = str(uuid4())
    config = {"configurable": {"thread_id": thread_id}}
    app_graph = compile_graph()
    state = create_initial_state(req.raw_input)

    pipelines[thread_id] = {
        "app": app_graph,
        "config": config
    }

    for event in app_graph.stream(state, config):
        pass

    return {"thread_id": thread_id, "status": "paused_at_hitl_gate_1"}

@app.get("/status/{thread_id}")
def get_status(thread_id: str):
    if thread_id not in pipelines:
        raise HTTPException(status_code=404, detail="Pipeline not found")

    app_graph = pipelines[thread_id]["app"]
    config = pipelines[thread_id]["config"]

    state = app_graph.get_state(config)

    return {
        "thread_id": thread_id,
        "state": state.values
    }

@app.post("/hitl/{gate}/{thread_id}")
def hitl_decision(gate: int, thread_id: str, req: HITLRequest):
    if thread_id not in pipelines:
        raise HTTPException(status_code=404, detail="Pipeline not found")

    app_graph = pipelines[thread_id]["app"]
    config = pipelines[thread_id]["config"]
    current = app_graph.get_state(config)

    if gate == 1:
        result = hitl_gate_1(current.values)
        node = "hitl_gate_1"
    elif gate == 2:
        result = hitl_gate_2(current.values)
        node = "hitl_gate_2"
    elif gate == 3:
        result = hitl_gate_3(current.values)
        node = "hitl_gate_3"
    else:
        raise HTTPException(status_code=400, detail="Invalid gate")

    app_graph.update_state(config, result, as_node=node)

    for event in app_graph.stream(None, config):
        pass

    return {"thread_id": thread_id, "status": "continued"}

@app.get("/audit/{thread_id}")
def get_audit(thread_id: str):
    if thread_id not in pipelines:
        raise HTTPException(status_code=404, detail="Pipeline not found")

    app_graph = pipelines[thread_id]["app"]
    config = pipelines[thread_id]["config"]

    state = app_graph.get_state(config)
    values = state.values

    return {
        "final_audit": values.get("quality_report", {}).get("final_audit"),
        "audit_log": values.get("audit_log")
    }

