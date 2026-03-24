"use client";

import React, { useEffect, useState } from "react";
import { motion } from "framer-motion";
import {
  BluetoothIcon,
  Check,
  FileExclamationPoint,
  FileWarningIcon,
  StopCircleIcon,
} from "lucide-react";
import { PIPELINE_STAGES, usePipeline } from "@/context/socket_context";

const STAGE_ICONS = {
  pending: FileWarningIcon,
  running: BluetoothIcon,
  complete: Check,
  waiting: FileExclamationPoint,
  error: StopCircleIcon,
};

function StageList({ stages }) {
  const stageArray = PIPELINE_STAGES;

  const [lastActiveIndex, setLastActiveIndex] = useState(0);

  const runningIndex = stageArray.findIndex(
    (s) => stages[s.id] === "running"
  );

  const pausedIndex = stageArray.findIndex(
    (s) => stages[s.id] === "waiting"
  );

  const paused = pausedIndex !== -1;

  useEffect(() => {
    if (runningIndex !== -1) {
      setLastActiveIndex(runningIndex);
    }
  }, [runningIndex]);

  const activeIndex = paused ? pausedIndex : lastActiveIndex;

  return (
    <div className="flex flex-col">

      {stageArray.map((stage, index) => {
        const { id, label } = stage;
        const status = stages[id] ?? "pending";

        const Icon = STAGE_ICONS[status] ?? FileWarningIcon;

        const isActive =
          index === activeIndex;

        const isComplete =
          index < activeIndex;

        const connectorFilled =
          index < activeIndex;

        const isLast =
          index === stageArray.length - 1;

        return (
          <div key={id} className="flex flex-col">

            {/* Node */}
            <div className="flex items-center gap-3">

              <div
                className={`w-4 h-4 rounded-full flex items-center justify-center border
                ${
                  isComplete
                    ? "bg-emerald-500 border-emerald-500"
                    : isActive
                    ? "bg-amber-500 border-amber-500"
                    : "bg-zinc-900 border-zinc-700"
                }`}
              >
                <Icon size={10} className="text-black" />
              </div>

              <span
                className={`text-[11px] font-mono
                ${
                  isActive
                    ? "text-amber-500"
                    : isComplete
                    ? "text-emerald-500"
                    : "text-zinc-400"
                }`}
              >
                {label}
              </span>
            </div>

            {/* Connector */}
            {!isLast && (
              <div className="ml-[7px] h-6 w-[2px] bg-zinc-800 relative">

                <motion.div
                  className={`absolute top-0 left-0 w-[2px] ${
                    paused ? "bg-amber-500" : "bg-emerald-500"
                  }`}
                  animate={{
                    height: connectorFilled ? "100%" : "0%",
                  }}
                  transition={{
                    duration: 0.35,
                    ease: "easeInOut",
                  }}
                />

              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

const Sidebar = () => {
  const { stages } = usePipeline();

  return (
    <nav className="w-12 lg:w-56 border-r border-zinc-800 bg-zinc-950 flex flex-col py-6 px-3 lg:px-5 shrink-0">
      <StageList stages={stages} />
    </nav>
  );
};

export default Sidebar;



{/* <div className="flex items-center gap-3 px-2 mb-10 text-emerald-500">
      <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center shrink-0">
        <Workflow size={18} />
      </div>
      <span className="font-bold hidden lg:block tracking-tight">SDLC<span className="text-zinc-100 hidden lg:inline">.ai</span></span>
    </div>

    <div className="space-y-2 flex-1 w-full">
      {[
        { id: 'orchestrator', label: 'Orchestrator', icon: LayoutDashboard, active: true },
        { id: 'settings', label: 'Settings', icon: Settings, active: false }
      ].map((item) => (
        <button 
          key={item.id}
          className={`w-full flex items-center gap-3 p-3 rounded-xl transition-all ${item.active ? 'bg-zinc-800/50 text-emerald-400 font-medium' : 'text-zinc-500 hover:text-zinc-300 hover:bg-zinc-900/50'}`}
        >
          <item.icon size={18} className="shrink-0" />
          <span className="hidden lg:block text-sm">{item.label}</span>
        </button>
      ))}
    </div>
    
    <div className="mt-auto hidden lg:block bg-zinc-900/40 p-4 rounded-xl border border-zinc-800/50">
      <div className="text-xs text-zinc-500 mb-2">Platform Status</div>
      <div className="flex items-center gap-2">
        <span className="flex h-2 w-2 relative">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
          <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
        </span>
        <span className="text-sm font-medium text-emerald-500">AI Agents Active</span>
      </div>
    </div> */}