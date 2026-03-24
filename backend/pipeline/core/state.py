import operator
from typing import Dict, List, Optional, Annotated, TypedDict


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
    pipeline_stopped:    bool
    arch_feedback:       Optional[str]


def should_stop(state: DevState) -> bool:
    return state.get("pipeline_stopped", False)


def initial_state(raw_input: str) -> DevState:
    return {
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
        "security_retries":    0,
        "pipeline_stopped":    False,
        "arch_feedback":       None,
    }