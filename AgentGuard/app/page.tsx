"use client";

import { useRef, useState } from "react";
import { ShieldHalf } from "lucide-react";
import RequestForm from "@/components/RequestForm";
import Pipeline from "@/components/Pipeline";
import RiskGauge from "@/components/RiskGauge";
import DecisionBadge from "@/components/DecisionBadge";
import ThreatBreakdown from "@/components/ThreatBreakdown";
import AuditLog from "@/components/AuditLog";
import AboutSection from "@/components/AboutSection";
import { ActionVerb, AnalyzeResponse, ToolId } from "@/lib/types";

const STAGE_COUNT = 5;
const STAGE_DELAY_MS = 260;
const MIN_VISIBLE_MS = 1250;

export default function Home() {
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [activeIndex, setActiveIndex] = useState<number | null>(null);
  const [result, setResult] = useState<AnalyzeResponse | null>(null);
  const [history, setHistory] = useState<AnalyzeResponse[]>([]);
  const [error, setError] = useState<string | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  async function handleSubmit(input: { agentPrompt: string; tool: ToolId; action: ActionVerb }) {
    setIsAnalyzing(true);
    setError(null);
    setActiveIndex(0);

    timerRef.current = setInterval(() => {
      setActiveIndex((i) => (i === null ? 0 : Math.min(i + 1, STAGE_COUNT - 1)));
    }, STAGE_DELAY_MS);

    const started = Date.now();

    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(input),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "Analysis request failed.");

      const elapsed = Date.now() - started;
      if (elapsed < MIN_VISIBLE_MS) {
        await new Promise((r) => setTimeout(r, MIN_VISIBLE_MS - elapsed));
      }

      if (timerRef.current) clearInterval(timerRef.current);
      setActiveIndex(null);
      setResult(data as AnalyzeResponse);
      setHistory((h) => [data as AnalyzeResponse, ...h].slice(0, 25));
    } catch (e) {
      if (timerRef.current) clearInterval(timerRef.current);
      setActiveIndex(null);
      setError(e instanceof Error ? e.message : "Something went wrong.");
    } finally {
      setIsAnalyzing(false);
    }
  }

  return (
    <main className="mx-auto max-w-6xl px-5 py-10 sm:px-8">
      <header className="flex flex-col gap-3 mb-10">
        <div className="flex items-center gap-2.5">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-signal-analyze/15 border border-signal-analyze/40">
            <ShieldHalf size={18} className="text-signal-analyze" />
          </div>
          <span className="font-display text-lg font-medium tracking-tight text-mist-100">
            AgentGuard
          </span>
          <span className="ml-1 rounded-full border border-graphite-600 px-2 py-0.5 text-[10px] font-mono uppercase tracking-wide text-mist-500">
            prototype
          </span>
        </div>
        <h1 className="font-display text-2xl sm:text-3xl font-medium tracking-tight text-mist-100 max-w-2xl">
          A runtime security firewall between an AI agent and its tools.
        </h1>
        <p className="text-sm text-mist-500 max-w-2xl leading-relaxed">
          Submit a proposed agent action below. AgentGuard intercepts it, checks it for prompt
          injection and sensitive-data exposure, verifies tool permissions, calculates a risk
          score, and allows or blocks it before execution &mdash; with an explainable reason every
          time.
        </p>
      </header>

      <section className="grid grid-cols-1 lg:grid-cols-[1fr_1fr] gap-5 mb-6">
        <RequestForm onSubmit={handleSubmit} isAnalyzing={isAnalyzing} />
        <Pipeline pipeline={result?.pipeline ?? null} activeIndex={activeIndex} />
      </section>

      {error && (
        <div className="mb-6 rounded-lg border border-signal-block/40 bg-signal-block/10 px-4 py-3 text-sm text-signal-block">
          {error}
        </div>
      )}

      {result && !isAnalyzing && (
        <section className="rounded-xl border border-graphite-700 bg-graphite-850 shadow-panel p-5 mb-6">
          <div className="flex flex-col sm:flex-row gap-6">
            <div className="flex items-center gap-5">
              <RiskGauge score={result.riskScore} decision={result.decision} />
              <div className="flex flex-col gap-2">
                <DecisionBadge decision={result.decision} />
                <p className="text-sm text-mist-300 max-w-md leading-relaxed">{result.summary}</p>
              </div>
            </div>
          </div>
          <div className="mt-5 pt-5 border-t border-graphite-700">
            <h3 className="font-display text-sm font-medium tracking-wide text-mist-300 uppercase mb-3">
              Detected signals
            </h3>
            <ThreatBreakdown findings={result.findings} />
          </div>
        </section>
      )}

      <div className="mb-14">
        <AuditLog entries={history} />
      </div>

      <div className="mb-10 border-t border-graphite-800 pt-10">
        <AboutSection />
      </div>

      <footer className="border-t border-graphite-800 pt-6 pb-2 text-xs text-mist-500 font-mono">
        AgentGuard prototype &mdash; Team NetGen Builders. Detection logic runs entirely in this
        app for demonstration; no external services are called.
      </footer>
    </main>
  );
}
