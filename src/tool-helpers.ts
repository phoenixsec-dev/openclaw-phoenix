export type ToolResult = {
  content: Array<{ type: "text"; text: string }>;
  details: unknown;
};

export type PhoenixCallerContext = {
  agentId?: string;
  sessionKey?: string;
  sessionId?: string;
  messageChannel?: string;
  requesterSenderId?: string;
  senderIsOwner?: boolean;
};

export function jsonResult(payload: unknown): ToolResult {
  return {
    content: [{ type: "text", text: JSON.stringify(payload, null, 2) }],
    details: payload,
  };
}

export function readStringParam(
  params: Record<string, unknown>,
  key: string,
  options: { required?: boolean } = {},
): string | undefined {
  const raw = params[key];
  if (typeof raw !== "string") {
    if (options.required) {
      throw new Error(`${key} required`);
    }
    return undefined;
  }
  const trimmed = raw.trim();
  if (!trimmed) {
    if (options.required) {
      throw new Error(`${key} required`);
    }
    return undefined;
  }
  return trimmed;
}

export function readStringArrayParam(
  params: Record<string, unknown>,
  key: string,
  options: { required?: boolean } = {},
): string[] | undefined {
  const raw = params[key];
  if (Array.isArray(raw)) {
    const values = raw.filter((entry) => typeof entry === "string").map((entry) => entry.trim()).filter(Boolean);
    if (values.length === 0 && options.required) {
      throw new Error(`${key} required`);
    }
    return values.length > 0 ? values : undefined;
  }
  if (typeof raw === "string") {
    const trimmed = raw.trim();
    if (!trimmed) {
      if (options.required) {
        throw new Error(`${key} required`);
      }
      return undefined;
    }
    return [trimmed];
  }
  if (options.required) {
    throw new Error(`${key} required`);
  }
  return undefined;
}
