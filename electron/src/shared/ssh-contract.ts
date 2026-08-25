export type SshHostRole = "target" | "jump-host";

export type SshAttemptStage =
  | "running"
  | "awaiting-host-key"
  | "awaiting-mfa"
  | "probe-succeeded"
  | "connected"
  | "failed"
  | "cancelled";

export interface SshAttemptStarted {
  attemptHandle: string;
  stage: "running";
}

export interface SshHostKeyPrompt {
  promptHandle: string;
  role: SshHostRole;
  host: string;
  port: number;
  username: string;
  fingerprint: string;
}

export interface SshMfaField {
  prompt: string;
  echo: boolean;
}

export interface SshMfaPrompt {
  promptHandle: string;
  role: SshHostRole;
  host: string;
  port: number;
  username: string;
  name: string;
  instructions: string;
  prompts: SshMfaField[];
}

export interface SshTargetSummary {
  connectionId: string;
  host: string;
  port: number;
  username: string;
  timestamp: string;
}

export interface SshAttemptError {
  code: "host-key-changed" | "ssh-attempt-failed";
  message: string;
  role?: SshHostRole;
  host?: string;
  port?: number;
  repinSupported?: false;
}

export type SshAttemptStatus =
  | { stage: "running" }
  | { stage: "awaiting-host-key"; hostKeyPrompt: SshHostKeyPrompt }
  | { stage: "awaiting-mfa"; mfaPrompt: SshMfaPrompt }
  | { stage: "probe-succeeded"; target: SshTargetSummary }
  | { stage: "connected"; bindingHandle: string; target: SshTargetSummary }
  | { stage: "failed"; error: SshAttemptError }
  | { stage: "cancelled" };

export interface SshAttemptCancellation {
  cancelled: true;
}

export interface SshBindingDisconnection {
  disconnected: true;
  targetCleared: boolean;
}

type JsonRecord = Record<string, unknown>;

const textEncoder = new TextEncoder();

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: JsonRecord, expected: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && keys.every((key) => expected.includes(key));
}

function isUtf8BoundedString(value: unknown, maximumBytes: number): value is string {
  return typeof value === "string" && textEncoder.encode(value).byteLength <= maximumBytes;
}

function isLabel(value: unknown, maximumBytes: number): value is string {
  return (
    isUtf8BoundedString(value, maximumBytes) &&
    value.trim().length > 0 &&
    !/[\u0000-\u001f\u007f-\u009f]/u.test(value)
  );
}

function isPort(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 1 && value <= 65_535;
}

export function isSshOpaqueHandle(value: unknown): value is string {
  return (
    isUtf8BoundedString(value, 128) &&
    value.length > 0 &&
    /^[A-Za-z0-9-]+$/u.test(value)
  );
}

function isHostRole(value: unknown): value is SshHostRole {
  return value === "target" || value === "jump-host";
}

function isHostKeyPrompt(value: unknown): value is SshHostKeyPrompt {
  if (!isRecord(value)) return false;
  return (
    hasExactKeys(value, [
      "promptHandle",
      "role",
      "host",
      "port",
      "username",
      "fingerprint",
    ]) &&
    isSshOpaqueHandle(value.promptHandle) &&
    isHostRole(value.role) &&
    isLabel(value.host, 253) &&
    isPort(value.port) &&
    isLabel(value.username, 32) &&
    isLabel(value.fingerprint, 256) &&
    value.fingerprint.startsWith("SHA256:")
  );
}

function isMfaField(value: unknown): value is SshMfaField {
  return (
    isRecord(value) &&
    hasExactKeys(value, ["prompt", "echo"]) &&
    isUtf8BoundedString(value.prompt, 4_096) &&
    typeof value.echo === "boolean"
  );
}

function isMfaPrompt(value: unknown): value is SshMfaPrompt {
  if (!isRecord(value)) return false;
  return (
    hasExactKeys(value, [
      "promptHandle",
      "role",
      "host",
      "port",
      "username",
      "name",
      "instructions",
      "prompts",
    ]) &&
    isSshOpaqueHandle(value.promptHandle) &&
    isHostRole(value.role) &&
    isLabel(value.host, 253) &&
    isPort(value.port) &&
    isLabel(value.username, 32) &&
    isUtf8BoundedString(value.name, 4_096) &&
    isUtf8BoundedString(value.instructions, 16 * 1_024) &&
    Array.isArray(value.prompts) &&
    value.prompts.length > 0 &&
    value.prompts.length <= 16 &&
    value.prompts.every(isMfaField)
  );
}

function isTargetSummary(value: unknown): value is SshTargetSummary {
  if (!isRecord(value)) return false;
  return (
    hasExactKeys(value, ["connectionId", "host", "port", "username", "timestamp"]) &&
    isLabel(value.connectionId, 128) &&
    isLabel(value.host, 253) &&
    isPort(value.port) &&
    isLabel(value.username, 32) &&
    isLabel(value.timestamp, 64)
  );
}

function isAttemptError(value: unknown): value is SshAttemptError {
  if (!isRecord(value)) return false;
  if (value.code === "ssh-attempt-failed") {
    return hasExactKeys(value, ["code", "message"]) && isLabel(value.message, 1_024);
  }
  return (
    value.code === "host-key-changed" &&
    hasExactKeys(value, ["code", "message", "role", "host", "port", "repinSupported"]) &&
    isLabel(value.message, 1_024) &&
    isHostRole(value.role) &&
    isLabel(value.host, 253) &&
    isPort(value.port) &&
    value.repinSupported === false
  );
}

export function isSshAttemptStarted(value: unknown): value is SshAttemptStarted {
  return (
    isRecord(value) &&
    hasExactKeys(value, ["attemptHandle", "stage"]) &&
    isSshOpaqueHandle(value.attemptHandle) &&
    value.stage === "running"
  );
}

export function isSshAttemptStatus(value: unknown): value is SshAttemptStatus {
  if (!isRecord(value) || typeof value.stage !== "string") return false;
  switch (value.stage) {
    case "running":
    case "cancelled":
      return hasExactKeys(value, ["stage"]);
    case "awaiting-host-key":
      return hasExactKeys(value, ["stage", "hostKeyPrompt"]) && isHostKeyPrompt(value.hostKeyPrompt);
    case "awaiting-mfa":
      return hasExactKeys(value, ["stage", "mfaPrompt"]) && isMfaPrompt(value.mfaPrompt);
    case "probe-succeeded":
      return hasExactKeys(value, ["stage", "target"]) && isTargetSummary(value.target);
    case "connected":
      return (
        hasExactKeys(value, ["stage", "bindingHandle", "target"]) &&
        isSshOpaqueHandle(value.bindingHandle) &&
        isTargetSummary(value.target)
      );
    case "failed":
      return hasExactKeys(value, ["stage", "error"]) && isAttemptError(value.error);
    default:
      return false;
  }
}

export function isSshAttemptCancellation(value: unknown): value is SshAttemptCancellation {
  return isRecord(value) && hasExactKeys(value, ["cancelled"]) && value.cancelled === true;
}

export function isSshBindingDisconnection(value: unknown): value is SshBindingDisconnection {
  return (
    isRecord(value) &&
    hasExactKeys(value, ["disconnected", "targetCleared"]) &&
    value.disconnected === true &&
    typeof value.targetCleared === "boolean"
  );
}

export function isSshMfaResponses(value: unknown): value is string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 16) return false;
  let totalBytes = 0;
  for (const response of value) {
    if (!isUtf8BoundedString(response, 4_096)) return false;
    totalBytes += textEncoder.encode(response).byteLength;
    if (totalBytes > 32 * 1_024) return false;
  }
  return true;
}
