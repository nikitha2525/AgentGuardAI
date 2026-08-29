"use client";

import { Decision } from "@/lib/types";

const DECISION_COLOR: Record<Decision, string> = {
  ALLOW: "#2FB170",
  REVIEW: "#F5A623",
  BLOCK: "#E5484D",
};

export default function RiskGauge({ score, decision }: { score: number; decision: Decision | null }) {
  const radius = 46;
  const circumference = 2 * Math.PI * radius;
  const pct = Math.max(0, Math.min(100, score));
  const dash = (pct / 100) * circumference;
  const color = decision ? DECISION_COLOR[decision] : "#4A5461";

  return (
    <div className="relative flex h-32 w-32 items-center justify-center shrink-0">
      <svg viewBox="0 0 110 110" className="h-32 w-32 -rotate-90">
        <circle cx="55" cy="55" r={radius} fill="none" stroke="#252B33" strokeWidth="9" />
        <circle
          cx="55"
          cy="55"
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="9"
          strokeLinecap="round"
          strokeDasharray={`${dash} ${circumference}`}
          className="transition-all duration-700 ease-out"
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className="font-mono text-2xl font-semibold tabular-nums text-mist-100">{pct}</span>
        <span className="text-[10px] uppercase tracking-wider text-mist-500">risk score</span>
      </div>
    </div>
  );
}
