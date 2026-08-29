import {
  ShieldAlert,
  KeyRound,
  Lock,
  Gauge,
  Ban,
  GitBranch,
  FileSearch,
  Activity,
} from "lucide-react";

const FEATURES = [
  {
    icon: ShieldAlert,
    title: "Prompt injection detection",
    body: "Identifies malicious instructions designed to manipulate AI agents mid-task.",
  },
  {
    icon: KeyRound,
    title: "Sensitive data detection",
    body: "Flags PII, credentials, API keys, and confidential information before they leave the agent.",
  },
  {
    icon: Lock,
    title: "Tool permission control",
    body: "Allows or denies access to databases, APIs, files, email, and payment systems per action.",
  },
  {
    icon: Gauge,
    title: "Real-time risk scoring",
    body: "Assigns a weighted risk score based on the requested action and every detected threat.",
  },
  {
    icon: Ban,
    title: "Action blocking",
    body: "Prevents unauthorized or high-risk actions from reaching the tool before execution.",
  },
  {
    icon: GitBranch,
    title: "Attack chain analysis",
    body: "Traces how a malicious input could have led to an unauthorized downstream action.",
  },
  {
    icon: FileSearch,
    title: "Explainable alerts",
    body: "Every decision ships with the specific rule and evidence that produced it \u2014 no black box.",
  },
  {
    icon: Activity,
    title: "Audit & monitoring",
    body: "Records agent activity, threats, blocked actions, and security events for review.",
  },
];

const TECH = ["Python", "FastAPI", "NLP / ML", "React", "PostgreSQL / SQLite", "REST APIs"];

export default function AboutSection() {
  return (
    <div className="flex flex-col gap-10">
      <section>
        <h2 className="font-display text-sm font-medium tracking-wide text-mist-300 uppercase mb-4">
          Features
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {FEATURES.map((f) => (
            <div
              key={f.title}
              className="rounded-xl border border-graphite-700 bg-graphite-850 p-4 flex flex-col gap-2.5"
            >
              <f.icon size={18} className="text-signal-analyze" />
              <p className="text-sm font-medium text-mist-100">{f.title}</p>
              <p className="text-xs text-mist-500 leading-relaxed">{f.body}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="grid grid-cols-1 lg:grid-cols-[1.3fr_1fr] gap-6">
        <div className="rounded-xl border border-graphite-700 bg-graphite-850 p-5">
          <h2 className="font-display text-sm font-medium tracking-wide text-mist-300 uppercase mb-4">
            System workflow
          </h2>
          <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
            {["Input", "Threat analysis", "Permission check", "Risk score", "Allow / Block", "Alert & log"].map(
              (step, i, arr) => (
                <div key={step} className="flex items-center gap-2">
                  <span className="rounded-md border border-graphite-600 bg-graphite-900 px-2.5 py-1.5 text-mist-300">
                    {step}
                  </span>
                  {i < arr.length - 1 && <span className="text-mist-500">&rarr;</span>}
                </div>
              )
            )}
          </div>
          <p className="text-sm text-mist-500 leading-relaxed mt-4">
            AgentGuard sits between an AI agent and its tools. Every proposed action is
            intercepted, analyzed for prompt injection and data leakage, checked against a
            tool-permission matrix, scored for risk, and then allowed or blocked before it ever
            reaches the underlying system.
          </p>
        </div>

        <div className="rounded-xl border border-graphite-700 bg-graphite-850 p-5">
          <h2 className="font-display text-sm font-medium tracking-wide text-mist-300 uppercase mb-4">
            Technology
          </h2>
          <div className="flex flex-wrap gap-2">
            {TECH.map((t) => (
              <span
                key={t}
                className="rounded-md border border-graphite-600 bg-graphite-900 px-2.5 py-1.5 text-xs font-mono text-mist-300"
              >
                {t}
              </span>
            ))}
          </div>
          <p className="text-sm text-mist-500 leading-relaxed mt-4">
            This prototype implements the detection and scoring pipeline as deterministic,
            explainable heuristics in TypeScript so the full decision path is inspectable end to
            end. The production system replaces the rule layer with the NLP/ML classifiers and
            FastAPI service described in the proposal, without changing the pipeline contract.
          </p>
        </div>
      </section>
    </div>
  );
}
