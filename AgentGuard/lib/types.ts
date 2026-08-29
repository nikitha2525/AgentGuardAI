export type ToolId =
  | "database"
  | "file_system"
  | "email"
  | "external_api"
  | "payment_system"
  | "user_directory";

export type ActionVerb = "read" | "write" | "delete" | "send" | "execute" | "transfer";

export type Decision = "ALLOW" | "REVIEW" | "BLOCK";

export interface Finding {
  id: string;
  category: "prompt_injection" | "sensitive_data" | "tool_permission" | "behavioral";
  label: string;
  detail: string;
  weight: number;
  severity: "low" | "medium" | "high";
}

export interface PipelineStageResult {
  stage: "intercept" | "analyze" | "verify" | "score" | "decide";
  label: string;
  status: "pass" | "flag" | "halt";
}

export interface AnalyzeRequestBody {
  agentPrompt: string;
  tool: ToolId;
  action: ActionVerb;
}

export interface AnalyzeResponse {
  id: string;
  timestamp: string;
  input: AnalyzeRequestBody;
  findings: Finding[];
  riskScore: number;
  decision: Decision;
  pipeline: PipelineStageResult[];
  summary: string;
}

export const TOOL_META: Record<ToolId, { label: string; baseRisk: number }> = {
  database: { label: "Database", baseRisk: 12 },
  file_system: { label: "File System", baseRisk: 8 },
  email: { label: "Email / Messaging", baseRisk: 10 },
  external_api: { label: "External API", baseRisk: 14 },
  payment_system: { label: "Payment System", baseRisk: 22 },
  user_directory: { label: "User Directory", baseRisk: 16 },
};

export const ACTION_META: Record<ActionVerb, { label: string; multiplier: number }> = {
  read: { label: "Read", multiplier: 0.6 },
  write: { label: "Write", multiplier: 1.0 },
  delete: { label: "Delete", multiplier: 1.4 },
  send: { label: "Send", multiplier: 1.1 },
  execute: { label: "Execute", multiplier: 1.3 },
  transfer: { label: "Transfer", multiplier: 1.6 },
};
