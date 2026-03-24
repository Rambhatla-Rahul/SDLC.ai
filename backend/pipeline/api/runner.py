import asyncio
from datetime import datetime, timezone
from typing import Any, Dict

from graph.builder import pipeline_graph
from core.utils import get_node_summary


pipeline_queues:        Dict[str, asyncio.Queue] = {}
pipeline_resume_events: Dict[str, asyncio.Event] = {}
pipeline_tasks:         Dict[str, asyncio.Task]  = {}
pipeline_meta:          Dict[str, Dict[str, Any]]= {}


def get_config(thread_id: str) -> dict:
    return {"configurable": {"thread_id": thread_id}}


def get_gate_context(state_values: dict, gate: str) -> dict:
    if gate == "hitl_gate_1":
        return {"intent_manifest": state_values.get("intent_manifest"), "ip_clearance": state_values.get("ip_clearance")}
    if gate == "hitl_gate_2":
        return {"architecture": state_values.get("architecture"), "compliance_rules": state_values.get("compliance_rules")}
    if gate == "hitl_gate_3":
        return {"security_report": state_values.get("security_report"), "quality_report": state_values.get("quality_report"), "architecture": state_values.get("architecture")}
    return {}


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