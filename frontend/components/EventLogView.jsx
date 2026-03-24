"use client"
import React from 'react'
import { usePipeline } from '@/context/socket_context'
import { C } from '@/constants/constants';



const EVENT_COLORS = {
  node_completed:    C.green,
  hitl_pause:        C.blue,
  pipeline_complete: C.amber,
  error:             C.red,
  ping:              C.muted,
};


function formatEvent(ev) {
  switch (ev.type) {
    case "node_completed": {
      const s = ev.summary ?? {};
      const parts = Object.entries(s)
        .slice(0, 3)
        .map(([k, v]) => `${k}=${Array.isArray(v) ? v.length : v}`)
        .join("  |  ");
      return `✅ [${ev.node}]${parts ? "  " + parts : ""}`;
    }
    case "hitl_pause":
      return `⏸  PAUSED at ${ev.paused_at}`;
    case "pipeline_complete":
      return `🏁 COMPLETE — ${ev.final_status ?? "?"}`;
    case "error":
      return `❌ ${ev.message ?? "Error"}`;
    case "ping":
      return "· keepalive";
    default:
      return JSON.stringify(ev).slice(0, 80);
  }
}



const EventLogView = () => {
  const {events,threadId} = usePipeline();
  return (
    <div
    className='w-full'
              style={{
                minWidth:    280,
                padding:     "20px 14px",
                display:     "flex",
                flexDirection: "column",
                gap:         10,
              }}
            >
              <div style={{ fontSize: 10, color: C.muted, letterSpacing: "0.06em" }}>
                LIVE EVENT STREAM
                <span style={{ marginLeft: 8, color: C.border }}>({events.length})</span>
              </div>
              <EventLog events={events} />
              {threadId && (
                <div style={{ fontSize: 9, color: C.border, wordBreak: "break-all" }}>
                  ws://.../ws/pipeline/{threadId.slice(0, 18)}…
                </div>
              )}
    </div>
    
  )
}


function EventLog({ events }) {
  return (
    <div
      style={{
        background:  "#070a0e",
        border:      `1px solid ${C.border}`,
        borderRadius: 4,
        padding:     "10px 12px",
        height:      320,
        overflowY:   "auto",
        fontFamily:  "monospace",
        fontSize:    11,
        lineHeight:  1.75,
        display:     "flex",
        flexDirection: "column-reverse",   // newest at top
      }}
    >
      {events.length === 0 ? (
        <span style={{ color: C.muted }}>Waiting for events…</span>
      ) : (
        [...events].reverse().map((ev, i) => {
          const ts    = ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : "";
          const color = EVENT_COLORS[ev.type] ?? C.text;
          const text  = formatEvent(ev);
          return (
            <div key={i} style={{ paddingBottom: 1 }}>
              <span style={{ color: C.muted, marginRight: 6 }}>{ts}</span>
              <span style={{ color }}>{text}</span>
            </div>
          );
        })
      )}
    </div>
  );
}

export default EventLogView;
