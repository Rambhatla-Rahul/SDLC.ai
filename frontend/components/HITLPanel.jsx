"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
ChevronDown,
ChevronUp,
PauseCircle,
Send,
} from "lucide-react";

const HITLPanel = ({ pausedAt, gateContext, decide }) => {
const GATE_LABELS = {
hitl_gate_1: "Gate I — Intent & IP Review",
hitl_gate_2: "Gate II — Architecture & Compliance Review",
hitl_gate_3: "Gate III — Security & Quality Sign-off",
};

const [choice, setChoice] = useState("A");
const [approver, setApprover] = useState("");
const [feedback, setFeedback] = useState("");
const [riskAck, setRiskAck] = useState(false);
const [expanded, setExpanded] = useState({});

const handleSubmit = () => {
if (!approver.trim()) return alert("Please enter an approver name.");
decide({
choice,
approver,
feedback: feedback || undefined,
risk_acknowledged: riskAck,
});
};

const CHOICE_OPTIONS = [
{ value: "A", label: "A — Approve" },
{ value: "M", label: "M — Modify (approve w/ notes)" },
{ value: "R", label: "R — Reject (re-run stage)" },
{ value: "H", label: "H — Hold (terminate)" },
];

return ( <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">

  <div className="w-[720px] max-h-[85vh] overflow-y-auto rounded-xl border border-neutral-800 bg-neutral-950 shadow-2xl p-6 [&::-webkit-scrollbar]:w-2 [&::-webkit-scrollbar-track]:bg-transparent [&::-webkit-scrollbar-thumb]:bg-zinc-700/50 [&::-webkit-scrollbar-thumb]:rounded-full hover:[&::-webkit-scrollbar-thumb]:bg-zinc-600/50">

    {/* Title */}
    <div className="flex items-center gap-3 mb-6 text-gray-100 font-mono text-xs uppercase tracking-widest font-bold">
      <PauseCircle size={16} />
      {GATE_LABELS[pausedAt] ?? pausedAt}
    </div>

    {/* Gate context */}
    <div className="space-y-2">
      {Object.entries(gateContext).map(([key, val]) => {
        if (!val) return null;
        const isOpen = expanded[key] ?? false;

        return (
          <div
            key={key}
            className="border border-neutral-800 rounded-md overflow-hidden"
          >
            <button
              onClick={() =>
                setExpanded((p) => ({ ...p, [key]: !isOpen }))
              }
              className="w-full flex items-center justify-between px-3 py-2 bg-neutral-900 hover:bg-neutral-800 transition font-mono text-xs text-white"
            >
              <span className="text-emerald-500">{key}</span>

              {isOpen ? (
                <ChevronUp size={16} className="text-amber-500" />
              ) : (
                <ChevronDown size={16} className="text-amber-500" />
              )}
            </button>

            <AnimatePresence>
              {isOpen && (
                <motion.pre
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: "auto", opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  transition={{ duration: 0.25 }}
                  className="bg-black text-neutral-300 text-[11px] font-mono p-3 overflow-auto [&::-webkit-scrollbar]:h-1 [&::-webkit-scrollbar]:w-1 [&::-webkit-scrollbar-track]:bg-transparent [&::-webkit-scrollbar-thumb]:bg-zinc-700/50 [&::-webkit-scrollbar-thumb]:rounded-full hover:[&::-webkit-scrollbar-thumb]:bg-zinc-600/50 max-h-55"
                >
                  {JSON.stringify(val, null, 2)}
                </motion.pre>
              )}
            </AnimatePresence>
          </div>
        );
      })}
    </div>

    {/* Decision form */}
    <div className="grid grid-cols-2 gap-4 mt-6">

      <div>
        <label className="block mb-1 text-[10px] font-mono text-neutral-400">
          CHOICE
        </label>

        <select
          value={choice}
          onChange={(e) => setChoice(e.target.value)}
          className="w-full bg-neutral-900 border border-neutral-800 rounded-md px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-amber-500"
        >
          {CHOICE_OPTIONS.map(({ value, label }) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>
      </div>

      <div>
        <label className="block mb-1 text-[10px] font-mono text-neutral-400">
          APPROVER *
        </label>

        <input
          type="text"
          placeholder="your name"
          value={approver}
          onChange={(e) => setApprover(e.target.value)}
          className="w-full bg-neutral-900 border border-neutral-800 rounded-md px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-emerald-500"
        />
      </div>
    </div>

    {/* Feedback */}
    <div className="mt-4">
      <label className="block mb-1 text-[10px] font-mono text-neutral-400">
        FEEDBACK
      </label>

      <textarea
        rows={3}
        placeholder="Optional notes..."
        value={feedback}
        onChange={(e) => setFeedback(e.target.value)}
        className="w-full bg-neutral-900 border border-neutral-800 rounded-md px-3 py-2 text-sm font-mono resize-y focus:outline-none focus:ring-2 focus:ring-emerald-500"
      />
    </div>

    {/* Risk checkbox */}
    <div className="flex items-center gap-2 mt-4">
      <input
        type="checkbox"
        id="riskAck"
        checked={riskAck}
        onChange={(e) => setRiskAck(e.target.checked)}
        className="accent-emerald-500 text-black"
      />

      <label
        htmlFor="riskAck"
        className="text-xs text-neutral-400 font-mono cursor-pointer"
      >
        I acknowledge any flagged risks
      </label>
    </div>

    {/* Submit */}
    <button
      onClick={handleSubmit}
      className={`mt-6 w-full flex items-center justify-center gap-2 rounded-md py-2 text-sm font-mono font-bold tracking-wider transition
        bg-emerald-500 hover:cursor-pointer hover:bg-emerald-600
       text-black`}
    >
      <Send size={16} />
      SUBMIT DECISION
    </button>

  </div>
</div>


);
};

export default HITLPanel;
