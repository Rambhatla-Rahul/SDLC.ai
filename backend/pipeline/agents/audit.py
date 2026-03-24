import json
from core.config import llm
from core.state import DevState, should_stop
from core.utils import extract_json, make_audit_entry, compute_hash


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

    immutable_digest = {
        "intent_hash":       compute_hash(manifest),
        "architecture_hash": compute_hash(arch),
        "code_hash":         compute_hash([m["filename"] for m in code.get("modules", [])]),
        "audit_chain_hash":  compute_hash(audit_log),
    }
    accountability = [
        {
            "gate":               d.get("gate"),
            "approver":           d.get("approver"),
            "decision":           d.get("choice"),
            "timestamp":          d.get("timestamp"),
            "risks_acknowledged": d.get("risk_acknowledged", False),
            "notes":              d.get("extra_notes") or d.get("feedback") or "none",
        }
        for d in decisions
    ]
    blocking_issues = [f"{f['filename']}: {f['rule']}" for f in security.get("findings", []) if f["severity"] == "critical"]
    if not quality.get("passed"):
        blocking_issues.append(f"Quality score {quality.get('overall_quality_score')}/100 — below threshold")
    blocking_issues.extend([f"Unmet criterion: {c['criterion']}" for c in quality.get("acceptance_criteria_check", []) if c["status"] == "not_met"])

    frameworks     = [f["name"] for f in compliance.get("applicable_frameworks", [])]
    gaps           = compliance.get("gaps", [])
    gaps_addressed = arch.get("gaps_addressed", [])
    unresolved     = [g for g in gaps if not any(any(w in a.lower() for w in g.lower().split()[:3]) for a in gaps_addressed)]
    compliance_sign_off = {
        "gdpr_controls_verified":  "GDPR" in frameworks,
        "owasp_controls_verified": "OWASP Top 10" in frameworks,
        "ip_clearance_verified":   ip.get("overall_risk") in ("low", "medium"),
        "gaps_resolved":           len(unresolved) == 0,
        "unresolved_items":        unresolved,
    }
    final_status = "requires_remediation" if blocking_issues else ("blocked" if not quality.get("passed") else "approved_for_deploy")

    response = llm.invoke(
        f"You are a senior compliance auditor. Write a single paragraph audit statement for a regulator.\n"
        f"Agents: {len(audit_log)}, HITL: {len(decisions)}, findings: {len(security.get('findings', []))}, "
        f"quality: {quality.get('overall_quality_score')}/100, status: {final_status}\n"
        f"Human trail: {json.dumps(accountability)}\n"
        f"Blocking: {json.dumps(blocking_issues) if blocking_issues else 'None'}\n"
        f"Compliance: {json.dumps(compliance_sign_off)}\n"
        f"Return ONLY the paragraph as plain text."
    )
    sign_off = response.text.strip()
    report   = {
        "pipeline_summary":    {"total_agents_run": len(audit_log), "total_hitl_decisions": len(decisions), "total_findings": len(security.get("findings", [])), "pipeline_passed": len(blocking_issues) == 0, "blocking_issues": blocking_issues},
        "compliance_sign_off": compliance_sign_off,
        "human_accountability": accountability,
        "immutable_digest":    immutable_digest,
        "final_status":        final_status,
        "sign_off_note":       sign_off,
    }
    print(f"[audit_agent] Done — status: {final_status}")
    return {
        "audit_log": [make_audit_entry("audit_agent", f"Final audit — status: {final_status.upper()}", {"final_status": final_status, "blocking_issues": len(blocking_issues), "immutable_digest": immutable_digest})],
        "quality_report": {**quality, "final_audit": report},
    }