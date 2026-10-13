/**
 * Asking a configured AI provider to read something a page already has.
 * Mirrors crates/lovelyhawk-backend/src/ai_assist_api.rs.
 */
export type AiAssistTask = "explain-log" | "explain-ioc" | "explain-terminal";
export type AiReach = "local" | "internet";
export type AiProtocol = "openai" | "anthropic";
export type AiAssistState = "running" | "completed" | "cancelled" | "failed";

export const AI_ASSIST_LIMITS = Object.freeze({
  maximumContentBytes: 96 * 1_024,
  maximumAnswerChars: 64 * 1_024,
  maximumProviders: 64,
} as const);

export interface AiProviderChoice {
  id: string;
  label: string;
  protocol: AiProtocol;
  model: string;
  reach: AiReach;
}

export interface AiProviderChoices {
  providers: AiProviderChoice[];
  defaultProviderId: string | null;
}

export interface AiAssistStarted {
  handle: string;
  providerLabel: string;
  model: string;
  reach: AiReach;
}

export interface AiAssistProgress {
  state: AiAssistState;
  /** Text that arrived since the last poll. */
  text: string;
  totalChars: number;
  truncated: boolean;
  error: string | null;
  historyId: string | null;
}

export interface AiAssistCancelled {
  cancelled: boolean;
}

export type AiAssistRequest =
  | { action: "providers" }
  | { action: "start"; providerId: string; task: AiAssistTask; content: string }
  | { action: "poll" | "cancel"; handle: string };

export type AiAssistResponse = AiProviderChoices | AiAssistStarted | AiAssistProgress | AiAssistCancelled;

const encoder = new TextEncoder();

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const own = Object.keys(value);
  return own.length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function text(value: unknown, maximum: number): value is string {
  return typeof value === "string" && value.length <= maximum;
}

function isHandle(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(value);
}

/** A provider id as settings accept them (valid_provider_id in core's settings.rs). */
export function isAiProviderId(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u.test(value);
}

export function isAiAssistTask(value: unknown): value is AiAssistTask {
  return value === "explain-log" || value === "explain-ioc" || value === "explain-terminal";
}

function isReach(value: unknown): value is AiReach {
  return value === "local" || value === "internet";
}

export function isAiAssistRequest(value: unknown): value is AiAssistRequest {
  if (!record(value) || typeof value.action !== "string") return false;
  switch (value.action) {
    case "providers":
      return exactKeys(value, ["action"]);
    case "start":
      return exactKeys(value, ["action", "providerId", "task", "content"]) && isAiProviderId(value.providerId) &&
        isAiAssistTask(value.task) && typeof value.content === "string" && value.content.trim() !== "" &&
        encoder.encode(value.content).byteLength <= AI_ASSIST_LIMITS.maximumContentBytes;
    case "poll":
    case "cancel":
      return exactKeys(value, ["action", "handle"]) && isHandle(value.handle);
    default:
      return false;
  }
}

function isChoice(value: unknown): value is AiProviderChoice {
  return record(value) && exactKeys(value, ["id", "label", "protocol", "model", "reach"]) &&
    isAiProviderId(value.id) && text(value.label, 256) && (value.protocol === "openai" || value.protocol === "anthropic") &&
    text(value.model, 512) && isReach(value.reach);
}

/** The answer has the shape its request asks for, and says nothing else. */
export function matchesAiAssistResponse(request: AiAssistRequest, value: unknown): value is AiAssistResponse {
  if (!record(value)) return false;
  switch (request.action) {
    case "providers":
      return exactKeys(value, ["providers", "defaultProviderId"]) && Array.isArray(value.providers) &&
        value.providers.length <= AI_ASSIST_LIMITS.maximumProviders && value.providers.every(isChoice) &&
        (value.defaultProviderId === null ||
          (isAiProviderId(value.defaultProviderId) &&
            value.providers.some((provider) => (provider as AiProviderChoice).id === value.defaultProviderId)));
    case "start":
      return exactKeys(value, ["handle", "providerLabel", "model", "reach"]) && isHandle(value.handle) &&
        text(value.providerLabel, 256) && text(value.model, 512) && isReach(value.reach);
    case "poll":
      return exactKeys(value, ["state", "text", "totalChars", "truncated", "error", "historyId"]) &&
        ["running", "completed", "cancelled", "failed"].includes(value.state as string) &&
        text(value.text, AI_ASSIST_LIMITS.maximumAnswerChars) &&
        typeof value.totalChars === "number" && Number.isSafeInteger(value.totalChars) && value.totalChars >= 0 &&
        value.totalChars <= AI_ASSIST_LIMITS.maximumAnswerChars && typeof value.truncated === "boolean" &&
        (value.error === null || text(value.error, 1_024)) &&
        (value.historyId === null || text(value.historyId, 256)) &&
        // Only a finished answer is kept, and only a failed one has an error.
        (value.historyId === null || value.state === "completed") &&
        (value.error === null || value.state === "failed");
    case "cancel":
      return exactKeys(value, ["cancelled"]) && typeof value.cancelled === "boolean";
  }
}
