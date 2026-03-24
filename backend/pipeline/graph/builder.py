from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from core.state import DevState
from agents.intent import intent_agent
from agents.ip_guard import ip_guard_agent
from agents.compliance import compliance_agent
from agents.architecture import architecture_agent
from agents.codegen import codegen_agent
from agents.optimizer import optimizer_agent
from agents.security import security_agent
from agents.explainability import explainability_agent
from agents.quality import quality_agent
from agents.audit import audit_agent
from graph.routes import (
    route_after_hitl_1,
    route_after_hitl_2,
    route_after_security,
    route_after_quality,
    route_after_hitl_3,
)


def passthrough_node(state: DevState) -> dict:
    return {}


def build_graph() -> StateGraph:
    graph = StateGraph(DevState)

    graph.add_node("intent_agent",         intent_agent)
    graph.add_node("ip_guard_agent",       ip_guard_agent)
    graph.add_node("hitl_gate_1",          passthrough_node)
    graph.add_node("compliance_agent",     compliance_agent)
    graph.add_node("architecture_agent",   architecture_agent)
    graph.add_node("hitl_gate_2",          passthrough_node)
    graph.add_node("codegen_agent",        codegen_agent)
    graph.add_node("optimizer_agent",      optimizer_agent)
    graph.add_node("security_agent",       security_agent)
    graph.add_node("explainability_agent", explainability_agent)
    graph.add_node("quality_agent",        quality_agent)
    graph.add_node("audit_agent",          audit_agent)
    graph.add_node("hitl_gate_3",          passthrough_node)

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

    graph.add_conditional_edges("hitl_gate_1",    route_after_hitl_1,  {"compliance_agent": "compliance_agent", "intent_agent": "intent_agent"})
    graph.add_conditional_edges("hitl_gate_2",    route_after_hitl_2,  {"codegen_agent": "codegen_agent", "architecture_agent": "architecture_agent"})
    graph.add_conditional_edges("security_agent", route_after_security, {"explainability_agent": "explainability_agent", "codegen_agent": "codegen_agent"})
    graph.add_conditional_edges("quality_agent",  route_after_quality,  {"audit_agent": "audit_agent", "codegen_agent": "codegen_agent"})
    graph.add_conditional_edges("hitl_gate_3",    route_after_hitl_3,  {END: END, "codegen_agent": "codegen_agent"})

    return graph


def compile_pipeline():
    memory = MemorySaver()
    return build_graph().compile(
        checkpointer=memory,
        interrupt_before=["hitl_gate_1", "hitl_gate_2", "hitl_gate_3"],
    )


pipeline_graph = compile_pipeline()