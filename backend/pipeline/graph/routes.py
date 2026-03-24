from langgraph.graph import END
from core.state import DevState, should_stop


def route_after_hitl_1(state: DevState) -> str:
    decisions = state.get("hitl_decisions") or []
    gate1     = [d for d in decisions if d.get("gate") == "hitl_gate_1"]
    if gate1 and gate1[-1]["choice"] in ("R", "M"):
        result = "intent_agent"
    else:
        result = "compliance_agent"
    print(f"[route_hitl_1] → {result}")
    return result


def route_after_hitl_2(state: DevState) -> str:
    decisions = state.get("hitl_decisions") or []
    gate2     = [d for d in decisions if d.get("gate") == "hitl_gate_2"]
    result    = "codegen_agent" if (gate2 and gate2[-1]["choice"] == "A") else "architecture_agent"
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