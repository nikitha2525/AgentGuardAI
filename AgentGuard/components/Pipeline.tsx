"use client";

import { PipelineStageResult } from "@/lib/types";
import { Check, Flag, Ban, Radar } from "lucide-react";

interface Props {
  pipeline: PipelineStageResult[] | null;
  activeIndex: number | null; // index currently being animated through, or null when idle/settled
}

const STAGE_ICON: Record<PipelineStageResult["status"], typeof Check> = {
  pass: Check,
  flag: Flag,
  halt: Ban,
};

const STAGE_COLOR: Record<PipelineStageResult["status"], string> = {
  pass: "border-signal-allow text-signal-allow",
  flag: "border-signal-review text-signal-review",
  halt: "border-signal-block text-signal-block",
};

const IDLE_STAGES = ["Intercept request", "Threat analysis", "Permission check", "Risk scoring", "Decision"];

export default function Pipeline({ pipeline, activeIndex }: Props) {
  return (
    <div className="rounded-xl border border-graphite-700 bg-graphite-850 shadow-panel p-5">
      <h2 className="font-display text-sm font-medium tracking-wide text-mist-300 uppercase mb-4">
        Firewall pipeline
      </h2>
      <ol className="flex flex-col gap-0">
        {IDLE_STAGES.map((label, idx) => {
          const settled = pipeline?.[idx];
          const isActive = activeIndex === idx;
          const isDone = pipeline !== null && (activeIndex === null || idx < activeIndex);
          const showResult = settled && (isDone || (activeIndex === null && pipeline));

          const Icon = showResult ? STAGE_ICON[settled!.status] : Radar;
          const colorClass = showResult
            ? STAGE_COLOR[settled!.status]
            : isActive
            ? "border-signal-analyze text-signal-analyze"
            : "border-graphite-600 text-mist-500";

          return (
            <li key={label} className="flex gap-3">
              <div className="flex flex-col items-center">
                <div
                  className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-full border-2 bg-graphite-900 ${colorClass} ${
                    isActive ? "animate-pulseDot" : ""
                  }`}
                >
                  <Icon size={14} />
                </div>
                {idx < IDLE_STAGES.length - 1 && (
                  <div
                    className={`w-px flex-1 min-h-[22px] ${
                      isDone || showResult ? "bg-graphite-500" : "bg-graphite-700"
                    }`}
                  />
                )}
              </div>
              <div className="pb-6 pt-1">
                <p
                  className={`text-sm font-medium ${
                    isActive ? "text-mist-100" : showResult ? "text-mist-100" : "text-mist-500"
                  }`}
                >
                  {label}
                </p>
                {showResult && (
                  <p className="text-xs font-mono text-mist-500 mt-0.5">{settled!.label}</p>
                )}
                {isActive && !showResult && (
                  <p className="text-xs font-mono text-signal-analyze mt-0.5">running\u2026</p>
                )}
              </div>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
