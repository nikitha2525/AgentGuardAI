import { Decision } from "@/lib/types";
import { ShieldCheck, ShieldAlert, ShieldX } from "lucide-react";

const CONFIG: Record<Decision, { label: string; icon: typeof ShieldCheck; className: string }> = {
  ALLOW: {
    label: "Allowed",
    icon: ShieldCheck,
    className: "bg-signal-allow/15 text-signal-allow border-signal-allow/40",
  },
  REVIEW: {
    label: "Flagged for review",
    icon: ShieldAlert,
    className: "bg-signal-review/15 text-signal-review border-signal-review/40",
  },
  BLOCK: {
    label: "Blocked",
    icon: ShieldX,
    className: "bg-signal-block/15 text-signal-block border-signal-block/40",
  },
};

export default function DecisionBadge({ decision }: { decision: Decision }) {
  const { label, icon: Icon, className } = CONFIG[decision];
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-sm font-medium ${className}`}
    >
      <Icon size={15} />
      {label}
    </span>
  );
}
