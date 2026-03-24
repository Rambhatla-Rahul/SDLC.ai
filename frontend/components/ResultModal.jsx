"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
FileCode,
ShieldAlert,
Gauge,
ClipboardCheck,
FileLock,
CheckCircle,
XCircle,
ChevronDown,
} from "lucide-react";

const ResultPanel = ({ result }) => {
const [tab, setTab] = useState("code");

const TABS = [
{ id: "code", icon: FileCode },
{ id: "security", icon: ShieldAlert },
{ id: "quality", icon: Gauge },
{ id: "compliance", icon: ClipboardCheck },
{ id: "audit", icon: FileLock },
];

if (!result) return null;

const gc = result.generated_code ?? {};
const sr = result.security_report ?? {};
const qr = result.quality_report ?? {};
const cr = result.compliance_rules ?? {};
const fa = qr.final_audit ?? {};

const modules = gc.modules ?? [];
const findings = sr.findings ?? [];

const SEV_COLORS = {
critical: "text-red-500",
high: "text-red-500",
medium: "text-amber-500",
low: "text-emerald-500",
};

return ( <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/60 backdrop-blur-sm">

  <div className="w-[900px] max-h-[85vh] overflow-hidden rounded-xl border border-zinc-800 bg-zinc-950 shadow-2xl">

    {/* Tabs */}
    <div className="flex border-b border-zinc-800 px-4">

      {TABS.map(({ id, icon: Icon }) => (
        <button
          key={id}
          onClick={() => setTab(id)}
          className={`flex items-center gap-2 px-4 py-3 font-mono text-xs tracking-wider transition
          ${
            tab === id
              ? "text-amber-500 border-b-2 border-amber-500"
              : "text-zinc-400 hover:text-zinc-200"
          }`}
        >
          <Icon size={14} />
          {id.toUpperCase()}
        </button>
      ))}

    </div>

    {/* Content */}
    <div className="p-6 overflow-y-auto max-h-[70vh]">

      <AnimatePresence mode="wait">

        <motion.div
          key={tab}
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -8 }}
          transition={{ duration: 0.2 }}
        >

          {/* CODE */}
          {tab === "code" && (
            <div className="space-y-3">

              {modules.length === 0 && (
                <p className="text-zinc-400 font-mono text-sm">
                  No code generated yet.
                </p>
              )}

              {modules.map((m) => (
                <details
                  key={m.filename}
                  className="border border-zinc-800 rounded-md overflow-hidden"
                >
                  <summary className="flex items-center justify-between px-4 py-2 bg-zinc-900 cursor-pointer font-mono text-xs text-zinc-200">
                    <span className="text-amber-500">{m.filename}</span>
                    <span className="text-zinc-500">{m.layer} layer</span>
                  </summary>

                  <pre className="bg-black text-zinc-300 text-xs font-mono p-4 overflow-x-auto whitespace-pre-wrap">
                    {typeof m.code === "string" ? m.code.replace(/\\n/g, "\n") : ""}
                  </pre>
                </details>
              ))}

            </div>
          )}

          {/* SECURITY */}
          {tab === "security" && (
            <div className="space-y-4 font-mono text-xs">

              <div className="flex gap-6 text-zinc-400">
                <span>
                  Risk:{" "}
                  <span className={SEV_COLORS[sr.overall_security_risk]}>
                    {sr.overall_security_risk ?? "unknown"}
                  </span>
                </span>

                <span className="flex">
                  Passed:{" "}
                  {sr.passed ? (
                    <span className="text-emerald-500 flex items-center gap-1">
                      <CheckCircle size={14} /> YES
                    </span>
                  ) : (
                    <span className="text-red-500 flex items-center gap-1">
                      <XCircle size={14} /> NO
                    </span>
                  )}
                </span>

                <span>{findings.length} findings</span>
              </div>

              {findings.map((f, i) => (
                <div
                  key={i}
                  className="border-b border-zinc-800 pb-2"
                >
                  <div className="flex gap-2">
                    <span
                      className={`${SEV_COLORS[f.severity]} font-bold`}
                    >
                      {f.severity?.toUpperCase()}
                    </span>

                    <span className="text-zinc-200">
                      {f.filename}
                    </span>

                    <span className="text-zinc-500">
                      {f.rule}
                    </span>
                  </div>

                  <div className="text-zinc-500 text-[11px] mt-1">
                    {f.owasp_ref} → {f.fix}
                  </div>
                </div>
              ))}

              {findings.length === 0 && (
                <p className="text-emerald-500">No findings</p>
              )}

            </div>
          )}

          {/* QUALITY */}
          {tab === "quality" && (
            <div className="text-center font-mono">

              <div
                className={`text-6xl font-bold
                ${
                  qr.overall_quality_score >= 70
                    ? "text-emerald-500"
                    : qr.overall_quality_score >= 50
                    ? "text-amber-500"
                    : "text-red-500"
                }`}
              >
                {qr.overall_quality_score ?? "—"}
              </div>

              <div className="text-zinc-500 text-xs">
                QUALITY SCORE / 100
              </div>

              <div className="mt-3">
                {qr.passed ? (
                  <span className="text-emerald-500 font-bold">
                    PASSED
                  </span>
                ) : (
                  <span className="text-red-500 font-bold">
                    FAILED
                  </span>
                )}
              </div>

              <div className="mt-6 text-left space-y-1">
                {(qr.recommendations ?? []).map((r, i) => (
                  <div
                    key={i}
                    className="text-zinc-300 text-xs"
                  >
                    • {r}
                  </div>
                ))}
              </div>

            </div>
          )}

          {/* COMPLIANCE */}
          {tab === "compliance" && (
            <div className="space-y-3">

              {(cr.applicable_frameworks ?? []).map((fw) => (
                <details
                  key={fw.name}
                  className="border border-zinc-800 rounded-md"
                >
                  <summary className="flex items-center justify-between px-4 py-2 bg-zinc-900 cursor-pointer font-mono text-xs">
                    <span className="text-amber-500">
                      {fw.name}
                    </span>
                    <span className="text-zinc-500">
                      {fw.priority}
                    </span>
                  </summary>

                  <div className="p-4 text-xs font-mono text-zinc-300 space-y-1">
                    {(fw.rules ?? []).map((r, i) => (
                      <div key={i}>• {r}</div>
                    ))}
                  </div>
                </details>
              ))}

            </div>
          )}

          {/* AUDIT */}
          {tab === "audit" && (
            <div className="space-y-4 font-mono text-xs">

              {fa.final_status && (
                <div>
                  <span className="text-zinc-400">
                    Final status:
                  </span>{" "}
                  <span
                    className={`font-bold
                    ${
                      fa.final_status === "approved_for_deploy"
                        ? "text-emerald-500"
                        : fa.final_status ===
                          "requires_remediation"
                        ? "text-amber-500"
                        : "text-red-500"
                    }`}
                  >
                    {fa.final_status.replace(/_/g, " ").toUpperCase()}
                  </span>
                </div>
              )}

              {fa.sign_off_note && (
                <p className="border-l-2 border-amber-500 pl-3 italic text-zinc-300">
                  {fa.sign_off_note}
                </p>
              )}

              {fa.immutable_digest && (
                <details className="border border-zinc-800 rounded-md">
                  <summary className="flex items-center gap-2 px-4 py-2 bg-zinc-900 cursor-pointer">
                    <ChevronDown size={14} />
                    Immutable Digest
                  </summary>

                  <pre className="bg-black text-emerald-500 text-xs p-4 overflow-x-auto">
                    {JSON.stringify(fa.immutable_digest, null, 2)}
                  </pre>
                </details>
              )}

            </div>
          )}
        <button >
          Return
        </button>
        </motion.div>

      </AnimatePresence>

    </div>

  </div>

</div>


);
};

export default ResultPanel;
