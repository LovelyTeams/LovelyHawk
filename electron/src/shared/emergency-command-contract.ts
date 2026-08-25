export const emergencyCommandCategories = [
  "permissions", "accounts", "network", "processes", "persistence", "logs", "files", "containers", "system",
] as const;
export const emergencyCommandResultKinds = [
  "success", "empty", "non-zero", "timeout", "missing-command", "permission-denied", "unknown-exit",
] as const;

export type EmergencyCommandCategory = typeof emergencyCommandCategories[number];
export type EmergencyCommandResultKind = typeof emergencyCommandResultKinds[number];

export interface EmergencyCommandCatalogItem {
  commandHandle: string;
  category: EmergencyCommandCategory;
  title: string;
  description: string;
  timeoutSeconds: number;
}

export interface EmergencyCommandCatalog {
  snapshotHandle: string;
  expiresInSeconds: number;
  commands: EmergencyCommandCatalogItem[];
}

export interface EmergencyCommandResult {
  snapshotHandle: string;
  commandHandle: string;
  resultKind: EmergencyCommandResultKind;
  exitCode: number | null;
  output: string;
  observedLineCount: number;
  displayedLineCount: number;
  /** Displayed line indexes the core judged abnormal, ascending. */
  findingLines: number[];
  /** Why those lines were marked, or null when the command marks nothing. */
  findingReason: string | null;
  truncated: boolean;
}

export interface EmergencyCommandApi {
  loadEmergencyCommandCatalog(bindingHandle: string): Promise<unknown>;
  runEmergencyCommand(bindingHandle: string, snapshotHandle: string, commandHandle: string): Promise<unknown>;
}

type JsonRecord = Record<string, unknown>;
const encoder = new TextEncoder();
const categorySet = new Set<string>(emergencyCommandCategories);
const resultKindSet = new Set<string>(emergencyCommandResultKinds);

function record(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exact(value: JsonRecord, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && actual.every((key) => keys.includes(key));
}

function text(value: unknown, maximumBytes: number, allowEmpty = true): value is string {
  return typeof value === "string" && (allowEmpty || value.length > 0) &&
    encoder.encode(value).byteLength <= maximumBytes;
}

function unsigned(value: unknown, maximum: number): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= maximum;
}

function signedI32OrNull(value: unknown): value is number | null {
  return value === null || typeof value === "number" && Number.isInteger(value) &&
    value >= -2_147_483_648 && value <= 2_147_483_647;
}

function serializedWithin(value: unknown, maximumBytes: number): boolean {
  try {
    const encoded = JSON.stringify(value);
    return typeof encoded === "string" && encoder.encode(encoded).byteLength <= maximumBytes;
  } catch {
    return false;
  }
}

export function isEmergencyCommandOpaqueHandle(value: unknown): value is string {
  return text(value, 128, false) && /^[A-Za-z0-9-]+$/u.test(value);
}

function catalogText(value: unknown, maximumBytes: number): value is string {
  return text(value, maximumBytes, false) && !/[\u0000-\u001f\u007f]/u.test(value);
}

function catalogItem(value: unknown): value is EmergencyCommandCatalogItem {
  return record(value) && exact(value, [
    "commandHandle", "category", "title", "description", "timeoutSeconds",
  ]) && isEmergencyCommandOpaqueHandle(value.commandHandle) && typeof value.category === "string" &&
    categorySet.has(value.category) && catalogText(value.title, 128) && catalogText(value.description, 512) &&
    unsigned(value.timeoutSeconds, 60) && value.timeoutSeconds > 0;
}

export function isEmergencyCommandCatalog(value: unknown): value is EmergencyCommandCatalog {
  if (!record(value) || !exact(value, ["snapshotHandle", "expiresInSeconds", "commands"]) ||
    !isEmergencyCommandOpaqueHandle(value.snapshotHandle) || value.expiresInSeconds !== 300 ||
    !Array.isArray(value.commands) || value.commands.length > 256 || !value.commands.every(catalogItem) ||
    !serializedWithin(value, 256 * 1_024)) return false;
  const commands = value.commands as EmergencyCommandCatalogItem[];
  return new Set(commands.map((command) => command.commandHandle)).size === commands.length;
}

/**
 * Output is shown as the target printed it. Only control characters and the
 * per-line byte ceiling are enforced, because those break rendering; nothing is
 * filtered on how the text looks.
 */
function outputLine(value: string): boolean {
  return encoder.encode(value).byteLength <= 4 * 1_024 &&
    !/[\r\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value);
}

function outputLines(value: string): string[] {
  return value.length === 0 ? [] : value.split("\n");
}

export function isEmergencyCommandResult(value: unknown): value is EmergencyCommandResult {
  if (!record(value) || !exact(value, [
    "snapshotHandle", "commandHandle", "resultKind", "exitCode", "output", "observedLineCount",
    "displayedLineCount", "findingLines", "findingReason", "truncated",
  ]) || !isEmergencyCommandOpaqueHandle(value.snapshotHandle) ||
    !isEmergencyCommandOpaqueHandle(value.commandHandle) || typeof value.resultKind !== "string" ||
    !resultKindSet.has(value.resultKind) || !signedI32OrNull(value.exitCode) || !text(value.output, 256 * 1_024) ||
    !unsigned(value.observedLineCount, 2 * 1_024 * 1_024) || !unsigned(value.displayedLineCount, 2_000) ||
    typeof value.truncated !== "boolean" ||
    !Array.isArray(value.findingLines) || value.findingLines.length > 2_000 ||
    !(value.findingReason === null || catalogText(value.findingReason, 512)) ||
    !serializedWithin(value, 384 * 1_024)) return false;
  const lines = outputLines(value.output);
  if (lines.length !== value.displayedLineCount || value.displayedLineCount > value.observedLineCount ||
    !lines.every(outputLine) || value.observedLineCount > value.displayedLineCount && !value.truncated) return false;
  // A mark has to point at a line that is actually here.
  const marks = value.findingLines as unknown[];
  if (!marks.every((mark, index) => unsigned(mark, 1_999) && mark < lines.length &&
    (index === 0 || mark > (marks[index - 1] as number)))) return false;
  if (value.resultKind === "success") return value.exitCode === 0 && value.output.length > 0;
  if (value.resultKind === "empty") return value.exitCode === 0 && value.output.length === 0;
  if (value.resultKind === "non-zero") return value.exitCode !== null && value.exitCode !== 0;
  if (value.resultKind === "unknown-exit") return value.exitCode === null;
  return true;
}
