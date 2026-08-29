import { Finding } from "@/lib/types";
import { AlertTriangle, Info, Siren } from "lucide-react";

const SEVERITY_ICON = { low: Info, medium: AlertTriangle, high: Siren };
const SEVERITY_COLOR = {
  low: "text-mist-500 border-graphite-600",
  medium: "text-signal-review border-signal-review/30",
  high: "text-signal-block border-signal-block/30",
};

const CATEGORY_LABEL: Record<Finding["category"], string> = {
  prompt_injection: "Prompt injection",
  sensitive_data: "Sensitive data",
  tool_permission: "Tool permission",
  behavioral: "Behavioral",
};

export default function ThreatBreakdown({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) {
    return (
      <p className="text-sm text-mist-500 font-mono">
        No threat, data-exposure, or permission signals detected in this request.
      </p>
    );
  }

  return (
    <ul className="flex flex-col gap-2">
      {findings.map((f) => {
        const Icon = SEVERITY_ICON[f.severity];
        return (
          <li
            key={f.id}
            className={`flex items-start gap-2.5 rounded-lg border bg-graphite-900/60 px-3 py-2.5 ${SEVERITY_COLOR[f.severity]}`}
          >
            <Icon size={16} className="mt-0.5 shrink-0" />
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <p className="text-sm font-medium text-mist-100">{f.label}</p>
                <span className="text-[10px] uppercase tracking-wide text-mist-500 font-mono shrink-0">
                  {CATEGORY_LABEL[f.category]}
                </span>
              </div>
              <p className="text-xs text-mist-500 mt-0.5">{f.detail}</p>
            </div>
            <span className="ml-auto shrink-0 font-mono text-xs tabular-nums text-mist-500">
              +{f.weight}
            </span>
          </li>
        );
      })}
    </ul>
  );
}
