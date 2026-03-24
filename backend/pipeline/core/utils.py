import re
import json
import hashlib
from datetime import datetime, timezone


# def extract_json(text) -> dict:
#     if hasattr(text, "text"):
#         text = text.text
#     if not isinstance(text, str):
#         text = str(text)
#     text = re.sub(r"```(?:json)?", "", text).replace("```", "").strip()
#     try:
#         return json.loads(text)
#     except json.JSONDecodeError:
#         pass
#     match = re.search(r"\{.*\}", text, re.DOTALL)
#     if not match:
#         raise ValueError(f"No JSON found in response:\n{text[:500]}")
#     try:
#         return json.loads(match.group())
#     except json.JSONDecodeError:
#         pass
#     decoder = json.JSONDecoder()
#     start   = text.find("{")
#     if start == -1:
#         raise ValueError(f"No JSON object found:\n{text[:500]}")
#     try:
#         obj, _ = decoder.raw_decode(text, start)
#         return obj
#     except json.JSONDecodeError as e:
#         raise ValueError(f"JSON parse failed: {e}\nText preview:\n{text[:500]}")
def extract_json(text) -> dict:
    if hasattr(text, "text"):
        text = text.text
    if not isinstance(text, str):
        text = str(text)

    text = re.sub(r"```(?:json)?", "", text).replace("```", "").strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ValueError(f"No JSON found in response:\n{text[:500]}")

    try:
        return json.loads(match.group())
    except json.JSONDecodeError:
        pass

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