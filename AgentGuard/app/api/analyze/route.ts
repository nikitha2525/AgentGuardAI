import { NextRequest, NextResponse } from "next/server";
import { analyzeRequest } from "@/lib/detectors";
import { ActionVerb, ToolId } from "@/lib/types";

const VALID_TOOLS: ToolId[] = [
  "database",
  "file_system",
  "email",
  "external_api",
  "payment_system",
  "user_directory",
];

const VALID_ACTIONS: ActionVerb[] = ["read", "write", "delete", "send", "execute", "transfer"];

export async function POST(req: NextRequest) {
  let payload: unknown;
  try {
    payload = await req.json();
  } catch {
    return NextResponse.json({ error: "Request body must be valid JSON." }, { status: 400 });
  }

  const { agentPrompt, tool, action } = (payload ?? {}) as Record<string, unknown>;

  if (typeof agentPrompt !== "string" || agentPrompt.trim().length === 0) {
    return NextResponse.json({ error: "agentPrompt is required." }, { status: 400 });
  }
  if (typeof tool !== "string" || !VALID_TOOLS.includes(tool as ToolId)) {
    return NextResponse.json({ error: `tool must be one of: ${VALID_TOOLS.join(", ")}` }, { status: 400 });
  }
  if (typeof action !== "string" || !VALID_ACTIONS.includes(action as ActionVerb)) {
    return NextResponse.json({ error: `action must be one of: ${VALID_ACTIONS.join(", ")}` }, { status: 400 });
  }

  const result = analyzeRequest({
    agentPrompt: agentPrompt.slice(0, 4000),
    tool: tool as ToolId,
    action: action as ActionVerb,
  });

  return NextResponse.json(result, { status: 200 });
}
