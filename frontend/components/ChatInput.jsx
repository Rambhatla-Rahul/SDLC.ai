import { C } from "@/constants/constants";
import { usePipeline } from "@/context/socket_context";
import { useRef, useState } from "react";




export default function ChatInput({ onSend }) {
  const [value, setValue] = useState("");
  const textareaRef = useRef(null);
  const {reset} = usePipeline();
  const MAX_LINES = 5;
  const LINE_HEIGHT = 24;

  const resizeTextarea = () => {
    const el = textareaRef.current;
    el.style.height = "auto";

    const maxHeight = MAX_LINES * LINE_HEIGHT;
    el.style.height = Math.min(el.scrollHeight, maxHeight) + "px";
  };

  const handleChange = (e) => {
    setValue(e.target.value);
    resizeTextarea();
  };

  const handleSend = () => {
    const message = value.trim();
    if (!message) return;

    onSend(message);   // send to parent
    setValue("");

    textareaRef.current.style.height = "auto";
  };

  const handleKeyDown = (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };


  const {status,start} = usePipeline();
  const canStart = value.trim().length > 0 && !["starting", "running", "paused"].includes(status);
  return (
    <>
        {/* <textarea
        ref={textareaRef}
        value={value}
        rows={1}
        placeholder="What do you wish to create today..."
        className="w-full bg-zinc-950 border border-zinc-800 rounded-lg py-3 px-4 text-sm text-zinc-200
        focus:outline-none focus:border-emerald-500/50 resize-none overflow-y-auto [&::-webkit-scrollbar]:w-2 [&::-webkit-scrollbar-track]"
        onChange={handleChange}
        onKeyDown={handleKeyDown}
        />
        <button
            className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-emerald-400 transition-colors p-2"
            onClick={onSend}
        >
            <Send size={16} />
        </button> */}
        <div>
            <div style={{ fontSize: 10, color: C.muted, marginBottom: 6, letterSpacing: "0.06em" }}>WHAT TO BUILD</div>
            <textarea
              rows={5}
              ref={textareaRef}
              value={value}
              onChange={handleChange}
              placeholder="e.g. Build a FastAPI app with JWT auth, user registration, and PostgreSQL."
              disabled={["starting", "running", "paused"].includes(status)}
              style={{
                width:        "100%",
                background:   C.surface2,
                border:       `1px solid ${C.border}`,
                borderRadius:  4,
                color:         C.text,
                fontFamily:    "monospace",
                fontSize:      11,
                padding:       "8px 10px",
                resize:        "vertical",
                boxSizing:     "border-box",
                outline:       "none",
              }}
            />
            <button
              onClick={() => start(value.trim())}
              disabled={!canStart}
              style={{
                marginTop:    8,
                width:        "100%",
                padding:      "9px 0",
                background:   canStart ? C.amber : C.amberDim,
                color:        "#0a0c0f",
                border:       "none",
                borderRadius:  4,
                fontFamily:    "monospace",
                fontWeight:    700,
                fontSize:      12,
                letterSpacing: "0.08em",
                cursor:        canStart ? "pointer" : "not-allowed",
                opacity:       canStart ? 1 : 0.5,
              }}
            >
              ⚡ RUN PIPELINE
            </button>

            {["complete", "error"].includes(status) && (
              <button
                onClick={reset}
                style={{
                  marginTop:    6,
                  width:        "100%",
                  padding:      "7px 0",
                  background:   "transparent",
                  color:        C.muted,
                  border:       `1px solid ${C.border}`,
                  borderRadius:  4,
                  fontFamily:    "monospace",
                  fontSize:      11,
                  cursor:        "pointer",
                }}
              >
                ↺ RESET
              </button>
            )}
          </div>
    </>
  );
}