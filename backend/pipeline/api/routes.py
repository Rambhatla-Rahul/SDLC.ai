import re
import asyncio
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect

from core.state import initial_state
from core.utils import make_audit_entry
from graph.builder import pipeline_graph
from api.models import RunRequest, HITLDecisionRequest
from api.ws_manager import ws_manager
from api.runner import (
    pipeline_queues,
    pipeline_resume_events,
    pipeline_tasks,
    pipeline_meta,
    get_config,
    get_gate_context,
    run_pipeline_background,
)

router = APIRouter()


@router.get("/")
def health():
    return {
        "status":    "AI-Native Dev Pipeline running",
        "version":   "2.0.0",
        "transport": {
            "rest":      "POST /pipeline/start | POST /pipeline/{id}/decide | GET /pipeline/{id}/state | GET /pipeline/{id}/result",
            "websocket": "ws://host/ws/pipeline/{thread_id}",
        },
    }


@router.websocket("/ws/pipeline/{thread_id}")
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


@router.post("/pipeline/start")
async def start_pipeline(request: RunRequest):
    thread_id = str(uuid4())

    pipeline_queues[thread_id] = asyncio.Queue()
    pipeline_meta[thread_id]   = {"status": "running", "paused_at": None}

    task = asyncio.create_task(run_pipeline_background(thread_id, initial_state(request.raw_input)))
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


@router.post("/pipeline/{thread_id}/decide")
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
    state_update: dict = {"hitl_decisions": existing_decisions + [decision], "audit_log": [audit_entry]}

    if paused_at == "hitl_gate_1" and request.choice == "M" and request.feedback:
        base_input = re.sub(r'\n\n\[Human modification.*', '', current.values.get("raw_input", ""), flags=re.DOTALL).strip()
        state_update["raw_input"] = (
            f"{base_input}\n\n"
            f"[IMPORTANT - Human modification]: {request.feedback}\n"
            f"You MUST follow this instruction exactly and override any previous tech stack decisions."
        )
        print(f"[hitl_gate_1] Modification baked into raw_input: {request.feedback}")

    if paused_at == "hitl_gate_3" and request.choice in ("A", "H"):
        state_update["pipeline_stopped"] = True
        print(f"[hitl_gate_3] pipeline_stopped=True")

    if paused_at == "hitl_gate_2":
        if request.choice == "A":
            state_update["security_retries"] = 0
            print(f"[hitl_gate_2] security_retries reset to 0")
        if request.choice == "M" and request.feedback:
            state_update["arch_feedback"] = request.feedback
            print(f"[hitl_gate_2] arch_feedback set: {request.feedback}")

    await asyncio.to_thread(pipeline_graph.update_state, config, state_update, as_node=paused_at)

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


@router.get("/pipeline/{thread_id}/state")
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


@router.get("/pipeline/{thread_id}/result")
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


@router.delete("/pipeline/{thread_id}")
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


@router.get("/pipelines")
async def list_pipelines():
    return {
        "pipelines": [
            {"thread_id": tid, "status": meta.get("status"), "paused_at": meta.get("paused_at")}
            for tid, meta in pipeline_meta.items()
        ]
    }