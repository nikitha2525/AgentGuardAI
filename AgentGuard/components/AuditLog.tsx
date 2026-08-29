"use client";

import { AnalyzeResponse } from "@/lib/types";
import { TOOL_META, ACTION_META } from "@/lib/types";
import DecisionBadge from "./DecisionBadge";
import { ClipboardList } from "lucide-react";

export default function AuditLog({ entries }: { entries: AnalyzeResponse[] }) {
  return (
    <div className="rounded-xl border border-graphite-700 bg-graphite-850 shadow-panel p-5">
      <div className="flex items-center gap-2 mb-4">
        <ClipboardList size={15} className="text-mist-500" />
        <h2 className="font-display text-sm font-medium tracking-wide text-mist-300 uppercase">
          Audit &amp; monitoring log
        </h2>
        <span className="ml-auto text-xs font-mono text-mist-500">{entries.length} events</span>
      </div>

      {entries.length === 0 ? (
        <p className="text-sm text-mist-500 font-mono py-6 text-center">
          No requests analyzed yet in this session.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-[11px] uppercase tracking-wide text-mist-500 border-b border-graphite-700">
                <th className="py-2 pr-4 font-medium">Time</th>
                <th className="py-2 pr-4 font-medium">Tool / action</th>
                <th className="py-2 pr-4 font-medium">Signals</th>
                <th className="py-2 pr-4 font-medium">Score</th>
                <th className="py-2 pr-4 font-medium">Decision</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <tr key={e.id} className="border-b border-graphite-800 last:border-0">
                  <td className="py-2.5 pr-4 font-mono text-xs text-mist-500 whitespace-nowrap">
                    {new Date(e.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="py-2.5 pr-4 whitespace-nowrap">
                    <span className="text-mist-100">{TOOL_META[e.input.tool].label}</span>
                    <span className="text-mist-500"> / {ACTION_META[e.input.action].label}</span>
                  </td>
                  <td className="py-2.5 pr-4 font-mono text-xs text-mist-500">
                    {e.findings.length === 0 ? "\u2014" : e.findings.length}
                  </td>
                  <td className="py-2.5 pr-4 font-mono tabular-nums text-mist-100">{e.riskScore}</td>
                  <td className="py-2.5 pr-4">
                    <DecisionBadge decision={e.decision} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
