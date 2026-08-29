"use client";

import { useState } from "react";
import { Send, Sparkles } from "lucide-react";
import { ACTION_META, ActionVerb, TOOL_META, ToolId } from "@/lib/types";
import { DEMO_SCENARIOS } from "@/lib/detectors";

interface Props {
  onSubmit: (input: { agentPrompt: string; tool: ToolId; action: ActionVerb }) => void;
  isAnalyzing: boolean;
}

export default function RequestForm({ onSubmit, isAnalyzing }: Props) {
  const [agentPrompt, setAgentPrompt] = useState(DEMO_SCENARIOS[0].body.agentPrompt);
  const [tool, setTool] = useState<ToolId>(DEMO_SCENARIOS[0].body.tool);
  const [action, setAction] = useState<ActionVerb>(DEMO_SCENARIOS[0].body.action);

  function loadScenario(idx: number) {
    const s = DEMO_SCENARIOS[idx];
    setAgentPrompt(s.body.agentPrompt);
    setTool(s.body.tool);
    setAction(s.body.action);
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!agentPrompt.trim() || isAnalyzing) return;
    onSubmit({ agentPrompt, tool, action });
  }

  return (
    <form
      onSubmit={handleSubmit}
      className="rounded-xl border border-graphite-700 bg-graphite-850 shadow-panel p-5 flex flex-col gap-4"
    >
      <div className="flex items-center justify-between">
        <h2 className="font-display text-sm font-medium tracking-wide text-mist-300 uppercase">
          Proposed agent action
        </h2>
        <span className="flex items-center gap-1 text-[11px] font-mono text-mist-500">
          <Sparkles size={12} />
          try a scenario
        </span>
      </div>

      <div className="flex flex-wrap gap-2">
        {DEMO_SCENARIOS.map((s, idx) => (
          <button
            key={s.label}
            type="button"
            onClick={() => loadScenario(idx)}
            className="text-xs font-mono px-2.5 py-1.5 rounded-md border border-graphite-600 bg-graphite-800 text-mist-300 hover:border-signal-analyze hover:text-mist-100 transition-colors"
          >
            {s.label}
          </button>
        ))}
      </div>

      <label className="flex flex-col gap-1.5">
        <span className="text-xs font-medium text-mist-500">Agent request text</span>
        <textarea
          value={agentPrompt}
          onChange={(e) => setAgentPrompt(e.target.value)}
          rows={6}
          className="w-full resize-none rounded-lg border border-graphite-600 bg-graphite-900 px-3 py-2.5 text-sm font-mono text-mist-100 placeholder:text-mist-500 focus:border-signal-analyze outline-none"
          placeholder="What is the agent asking to do?"
        />
      </label>

      <div className="grid grid-cols-2 gap-3">
        <label className="flex flex-col gap-1.5">
          <span className="text-xs font-medium text-mist-500">Target tool</span>
          <select
            value={tool}
            onChange={(e) => setTool(e.target.value as ToolId)}
            className="rounded-lg border border-graphite-600 bg-graphite-900 px-3 py-2.5 text-sm text-mist-100 focus:border-signal-analyze outline-none"
          >
            {Object.entries(TOOL_META).map(([id, meta]) => (
              <option key={id} value={id}>
                {meta.label}
              </option>
            ))}
          </select>
        </label>

        <label className="flex flex-col gap-1.5">
          <span className="text-xs font-medium text-mist-500">Requested action</span>
          <select
            value={action}
            onChange={(e) => setAction(e.target.value as ActionVerb)}
            className="rounded-lg border border-graphite-600 bg-graphite-900 px-3 py-2.5 text-sm text-mist-100 focus:border-signal-analyze outline-none"
          >
            {Object.entries(ACTION_META).map(([id, meta]) => (
              <option key={id} value={id}>
                {meta.label}
              </option>
            ))}
          </select>
        </label>
      </div>

      <button
        type="submit"
        disabled={isAnalyzing || !agentPrompt.trim()}
        className="mt-1 inline-flex items-center justify-center gap-2 rounded-lg bg-signal-analyze px-4 py-2.5 text-sm font-medium text-white transition-opacity hover:opacity-90 disabled:opacity-40 disabled:cursor-not-allowed"
      >
        <Send size={15} />
        {isAnalyzing ? "Analyzing\u2026" : "Send through AgentGuard"}
      </button>
    </form>
  );
}
