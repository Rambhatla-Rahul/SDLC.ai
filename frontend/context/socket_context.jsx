"use client"
import { File } from "lucide-react";
/**
 * PipelineContext.jsx
 *
 * React Context that owns the full lifecycle of one pipeline run:
 *   1. POST /pipeline/start   → receive thread_id
 *   2. WebSocket connection   → stream node_completed / hitl_pause /
 *                               pipeline_complete / error events
 *   3. POST /pipeline/{id}/decide  → submit HITL decisions
 *
 * Usage
 * ─────
 *   // Wrap your app (or just the pipeline section):
 *   <PipelineProvider apiBase="http://localhost:8000">
 *     <YourApp />
 *   </PipelineProvider>
 *
 *   // Consume anywhere in the tree:
 *   const { status, events, stages, start, decide } = usePipeline();
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from "react";

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/** Ordered pipeline stages — used to drive progress UI */
export const PIPELINE_STAGES = [
  { id: "intent_agent",         label: "Intent Parser",       kind: "agent", icon:File,status:'completed' },
  { id: "ip_guard_agent",       label: "IP Guard",            kind: "agent", icon:File,status:'completed' },
  { id: "hitl_gate_1",          label: "Human Review I",      kind: "gate", icon:File,status:'completed'  },
  { id: "compliance_agent",     label: "Compliance",          kind: "agent", icon:File,status:'completed' },
  { id: "architecture_agent",   label: "Architect",           kind: "agent", icon:File,status:'completed' },
  { id: "hitl_gate_2",          label: "Human Review II",     kind: "gate", icon:File,status:'completed'  },
  { id: "codegen_agent",        label: "Code Generator",      kind: "agent", icon:File,status:'completed' },
  { id: "optimizer_agent",      label: "Optimizer",           kind: "agent", icon:File,status:'completed' },
  { id: "security_agent",       label: "Security Scan",       kind: "agent", icon:File,status:'completed' },
  { id: "explainability_agent", label: "Explainability",      kind: "agent", icon:File,status:'completed' },
  { id: "quality_agent",        label: "Quality Gate",        kind: "agent", icon:File,status:'completed' },
  { id: "audit_agent",          label: "Audit Logger",        kind: "agent", icon:File,status:'completed' },
  { id: "hitl_gate_3",          label: "Human Review III",    kind: "gate", icon:File,status:'completed'  },
];

/**
 * @typedef {"pending"|"running"|"complete"|"waiting"|"error"} StageStatus
 * @typedef {"idle"|"starting"|"running"|"paused"|"complete"|"error"} PipelineStatus
 *
 * @typedef {Object} PipelineEvent
 * @property {string} type        - node_completed | hitl_pause | pipeline_complete | error | ping
 * @property {string} timestamp   - ISO string
 * @property {string} [node]      - for node_completed
 * @property {Object} [summary]   - for node_completed
 * @property {string} [paused_at] - for hitl_pause
 * @property {Object} [gate_context] - for hitl_pause
 * @property {string} [message]   - for error
 *
 * @typedef {Object} HITLDecision
 * @property {"A"|"R"|"M"|"H"} choice
 * @property {string} approver
 * @property {string} [role]
 * @property {string} [feedback]
 * @property {boolean} [risk_acknowledged]
 *
 * @typedef {Object} PipelineContextValue
 * @property {PipelineStatus}             status
 * @property {string|null}                threadId
 * @property {string|null}                pausedAt
 * @property {Object}                     gateContext
 * @property {PipelineEvent[]}            events
 * @property {Object.<string,StageStatus>} stages
 * @property {Object|null}                result
 * @property {string|null}                error
 * @property {function(string): Promise<void>} start
 * @property {function(HITLDecision): Promise<void>} decide
 * @property {function(): void}           reset
 */

// ─────────────────────────────────────────────────────────────────────────────
// Context
// ─────────────────────────────────────────────────────────────────────────────

const PipelineContext = createContext(/** @type {PipelineContextValue|null} */ (null));

// ─────────────────────────────────────────────────────────────────────────────
// Initial state factory
// ─────────────────────────────────────────────────────────────────────────────

const initialStages = () =>
  Object.fromEntries(PIPELINE_STAGES.map(({ id }) => [id, "pending"]));

const initialState = () => ({
  status:      "idle",
  threadId:    null,
  pausedAt:    null,
  gateContext: {},
  events:      [],
  stages:      initialStages(),
  result:      null,
  error:       null,
});

// ─────────────────────────────────────────────────────────────────────────────
// Provider
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @param {{ apiBase?: string, wsBase?: string, children: React.ReactNode }} props
 */
export function PipelineProvider({
  apiBase = "http://localhost:8000",
  wsBase,          // auto-derived from apiBase if omitted
  children,
}) {
  // Derive WebSocket base from HTTP base when not explicitly provided
  const resolvedWsBase =
    wsBase ?? apiBase.replace(/^http/, "ws");

  const [state, setState] = useState(initialState());

  /** Stable ref to the live WebSocket so we can close it on reset/unmount */
  const wsRef        = useRef(/** @type {WebSocket|null} */ (null));
  /** Ref to the current threadId to avoid stale closures in WS callbacks */
  const threadIdRef  = useRef(/** @type {string|null} */ (null));

  // ── Helpers ───────────────────────────────────────────────────────────────

  /** Append an event to the log and derive any stage-status side effects. */
  const handleEvent = useCallback((/** @type {PipelineEvent} */ event) => {
    setState((prev) => {
      const newEvents = [
        ...prev.events,
        { ...event, timestamp: event.timestamp ?? new Date().toISOString() },
      ];

      let patch = { events: newEvents };

      switch (event.type) {
        case "node_completed": {
          const node = event.node;
          patch.stages = { ...prev.stages, [node]: "complete" };
          // Mark the *next* agent stage as running if it exists
          const idx = PIPELINE_STAGES.findIndex((s) => s.id === node);
          const next = PIPELINE_STAGES[idx + 1];
          if (next && prev.stages[next.id] === "pending") {
            patch.stages[next.id] = "running";
          }
          break;
        }

        case "hitl_pause": {
          const gate = event.paused_at;
          patch.status      = "paused";
          patch.pausedAt    = gate;
          patch.gateContext = event.gate_context ?? {};
          patch.stages      = { ...prev.stages, [gate]: "waiting" };
          break;
        }

        case "pipeline_complete": {
          patch.status = "complete";
          patch.result = event;              // full payload stored here
          // Mark any still-pending stages as complete
          const finalStages = { ...prev.stages };
          Object.keys(finalStages).forEach((id) => {
            if (finalStages[id] === "pending" || finalStages[id] === "running") {
              finalStages[id] = "complete";
            }
          });
          patch.stages = finalStages;
          break;
        }

        case "error": {
          patch.status = "error";
          patch.error  = event.message ?? "Unknown pipeline error";
          break;
        }

        // "ping" — keepalive, nothing to update
        default:
          break;
      }

      return { ...prev, ...patch };
    });
  }, []);

  // ── WebSocket connection ───────────────────────────────────────────────────

  const openWebSocket = useCallback(
    (threadId) => {
      // Close any existing connection
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }

      const url = `${resolvedWsBase}/ws/pipeline/${threadId}`;
      const ws  = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        console.debug(`[Pipeline WS] Connected → ${url}`);
      };

      ws.onmessage = ({ data }) => {
        let event;
        try {
          event = JSON.parse(data);
        } catch {
          console.warn("[Pipeline WS] Non-JSON message:", data);
          return;
        }
        handleEvent(event);

        // Close socket after terminal events (server will close too, but be explicit)
        if (event.type === "pipeline_complete" || event.type === "error") {
          ws.close();
        }
      };

      ws.onerror = (err) => {
        console.error("[Pipeline WS] Error:", err);
        handleEvent({
          type:    "error",
          message: "WebSocket connection error — check that the server is running.",
        });
      };

      ws.onclose = ({ code, reason }) => {
        console.debug(`[Pipeline WS] Closed — code: ${code}, reason: ${reason || "none"}`);
        // If closed unexpectedly while still running, surface an error
        setState((prev) => {
          if (prev.status === "running") {
            return {
              ...prev,
              status: "error",
              error: `WebSocket closed unexpectedly (code ${code}).`,
            };
          }
          return prev;
        });
      };
    },
    [resolvedWsBase, handleEvent],
  );

  // ── Public API ────────────────────────────────────────────────────────────

  /**
   * Start a new pipeline run.
   * @param {string} rawInput - Plain-language description of what to build.
   */
  const start = useCallback(
    async (rawInput) => {
      setState((prev) => ({ ...prev, status: "starting", error: null }));

      let threadId;
      try {
        const res = await fetch(`${apiBase}/pipeline/start`, {
          method:  "POST",
          headers: { "Content-Type": "application/json" },
          body:    JSON.stringify({ raw_input: rawInput }),
        });
        if (!res.ok) {
          const body = await res.text();
          throw new Error(`Server returned ${res.status}: ${body}`);
        }
        const data = await res.json();
        threadId   = data.thread_id;
      } catch (err) {
        setState((prev) => ({
          ...prev,
          status: "error",
          error:  err.message,
        }));
        return;
      }

      threadIdRef.current = threadId;

      setState((prev) => ({
        ...prev,
        status:   "running",
        threadId,
        stages:   { ...initialStages(), [PIPELINE_STAGES[0].id]: "running" },
        events:   [],
        result:   null,
        error:    null,
      }));

      openWebSocket(threadId);
    },
    [apiBase, openWebSocket],
  );

  /**
   * Submit a HITL decision at the current paused gate.
   * @param {HITLDecision} decision
   */
  const decide = useCallback(
    async (decision) => {
      const threadId = threadIdRef.current;
      if (!threadId) {
        console.warn("[Pipeline] decide() called with no active thread");
        return;
      }

      try {
        const res = await fetch(`${apiBase}/pipeline/${threadId}/decide`, {
          method:  "POST",
          headers: { "Content-Type": "application/json" },
          body:    JSON.stringify(decision),
        });
        if (!res.ok) {
          const body = await res.text();
          throw new Error(`Decision failed (${res.status}): ${body}`);
        }
      } catch (err) {
        setState((prev) => ({
          ...prev,
          status: "error",
          error:  err.message,
        }));
        return;
      }

      // Optimistically update local state — WS will confirm
      setState((prev) => ({
        ...prev,
        status:      "running",
        pausedAt:    null,
        gateContext: {},
        stages: {
          ...prev.stages,
          ...(prev.pausedAt ? { [prev.pausedAt]: "complete" } : {}),
        },
      }));
    },
    [apiBase],
  );

  /** Tear down and reset everything back to idle. */
  const reset = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    threadIdRef.current = null;
    setState(initialState());
  }, []);

  // ── Cleanup on unmount ────────────────────────────────────────────────────

  useEffect(() => {
    return () => {
      if (wsRef.current) wsRef.current.close();
    };
  }, []);

  // ── Fetch full result once pipeline completes ─────────────────────────────

  useEffect(() => {
    if (state.status !== "complete" || !state.threadId) return;

    (async () => {
      try {
        const res = await fetch(
          `${apiBase}/pipeline/${state.threadId}/result`,
        );
        if (res.ok) {
          const fullResult = await res.json();
          setState((prev) => ({ ...prev, result: fullResult }));
        }
      } catch {
        // Non-fatal — we already have partial data from the WS event
      }
    })();
  }, [state.status, state.threadId, apiBase]);

  // ─────────────────────────────────────────────────────────────────────────

  const value = {
    ...state,
    start,
    decide,
    reset,
  };

  return (
    <PipelineContext.Provider value={value}>
      {children}
    </PipelineContext.Provider>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Hook
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Access the pipeline context anywhere inside <PipelineProvider>.
 * @returns {PipelineContextValue}
 */
export function usePipeline() {
  const ctx = useContext(PipelineContext);
  if (!ctx) {
    throw new Error("usePipeline must be used inside <PipelineProvider>");
  }
  return ctx;
}

export default PipelineContext;