export const sftpBrowserEntryKinds = ["directory", "file", "symlink", "other"] as const;
export const sftpBrowserEntryActions = ["browse", "preview", "none"] as const;

export type SftpBrowserEntryKind = typeof sftpBrowserEntryKinds[number];
export type SftpBrowserEntryAction = typeof sftpBrowserEntryActions[number];

export interface SftpBrowserEntry {
  entryHandle: string;
  name: string;
  nameTruncated: boolean;
  kind: SftpBrowserEntryKind;
  action: SftpBrowserEntryAction;
  sizeBytes: string;
  modifiedAt: string | null;
  /** Permission bits as four octal digits, when the server reports them. */
  mode: string | null;
  /** Numeric owner and group, reported as they arrive. */
  ownerId: number | null;
  groupId: number | null;
}

export interface SftpDirectorySnapshot {
  browserHandle: string;
  directoryHandle: string;
  parentDirectoryHandle: string | null;
  directoryLabel: string;
  directoryLabelTruncated: boolean;
  expiresInSeconds: number;
  observedEntryCount: number;
  displayedEntryCount: number;
  truncated: boolean;
  entries: SftpBrowserEntry[];
}

export interface SftpTextPreview {
  browserHandle: string;
  fileHandle: string;
  text: string;
  observedLineCount: number;
  displayedLineCount: number;
  truncated: boolean;
}

/**
 * The browser lives in the SSH terminal window, which exists for exactly one
 * target, so the binding is implicit: main resolves it from the calling window
 * and the renderer never holds it.
 */
export interface SftpTransferResult {
  /** False when the operator dismissed the save dialog. */
  saved: boolean;
  /** The name the file was written under, for the operator's confirmation. */
  fileName: string | null;
  bytes: string | null;
}

export const sftpOperationKinds = [
  "create-directory", "rename", "chmod", "remove", "archive", "upload",
] as const;
export const sftpArchiveFormats = ["tar", "tar-gzip", "tar-zstd"] as const;

export type SftpOperationKind = typeof sftpOperationKinds[number];
export type SftpArchiveFormat = typeof sftpArchiveFormats[number];

/** What the core will do, written out before anything is touched. */
export interface SftpOperationPlan {
  planHandle: string;
  browserHandle: string;
  kind: SftpOperationKind;
  summary: string;
  dangerous: boolean;
  /** What could be put back if verification fails, when a backup was taken. */
  restoreDescription: string | null;
  state: "planned" | "confirmed" | "spent";
  expiresInSeconds: number;
}

/** What actually happened, after the core verified its own work. */
export interface SftpOperationReceipt {
  planHandle: string;
  kind: SftpOperationKind;
  passed: boolean;
  detail: string;
  /** True when verification failed and the backup was put back. */
  restored: boolean;
}

export interface SftpStagedUpload {
  stagedHandle: string;
  name: string;
  bytes: string;
}

/** The capabilities an operation names, never a path, a mode owner or a target. */
export interface SftpOperationInput {
  kind: SftpOperationKind;
  entryHandles: string[];
  name?: string;
  mode?: number;
  format?: SftpArchiveFormat;
  stagedHandle?: string;
}

export interface SftpBrowserApi {
  openSftpBrowser(): Promise<unknown>;
  listSftpDirectory(browserHandle: string, directoryHandle: string): Promise<unknown>;
  readSftpText(browserHandle: string, fileHandle: string): Promise<unknown>;
  /** Asks main for a save location, then copies the file there. */
  downloadSftpEntry(browserHandle: string, fileHandle: string): Promise<unknown>;
  /** Nothing changes until confirm and execute follow this plan. */
  planSftpOperation(browserHandle: string, input: SftpOperationInput): Promise<unknown>;
  confirmSftpOperation(planHandle: string): Promise<unknown>;
  executeSftpOperation(planHandle: string): Promise<unknown>;
  cancelSftpOperation(planHandle: string): Promise<unknown>;
  /**
   * Stages a file where an upload plan can name it. With a handle from the
   * local pane it stages that file; without one main asks the operator to pick
   * a file. Either way the renderer never sees a local path.
   */
  stageSftpUpload(localFileHandle?: string): Promise<unknown>;
}

type JsonRecord = Record<string, unknown>;
const encoder = new TextEncoder();
const kindSet = new Set<string>(sftpBrowserEntryKinds);
const actionSet = new Set<string>(sftpBrowserEntryActions);
const maximumU64 = "18446744073709551615";
// Written as an escape so the source file stays plain text.
const CONTROL_CHARACTERS = new RegExp("[\u0000-\u001f\u007f]", "u");

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

function serializedWithin(value: unknown, maximumBytes: number): boolean {
  try {
    const encoded = JSON.stringify(value);
    return typeof encoded === "string" && encoder.encode(encoded).byteLength <= maximumBytes;
  } catch {
    return false;
  }
}

export function isSftpBrowserOpaqueHandle(value: unknown): value is string {
  return text(value, 128, false) && /^[A-Za-z0-9-]+$/u.test(value);
}

/** A remote name is shown as it is; only control characters are refused. */
function safeName(value: unknown, truncated: unknown, maximumBytes: number): value is string {
  return text(value, maximumBytes, false) && typeof truncated === "boolean" &&
    !/[\u0000-\u001f\u007f]/u.test(value);
}

function u64String(value: unknown): value is string {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]{0,19})$/u.test(value)) return false;
  return value.length < maximumU64.length || value.length === maximumU64.length && value <= maximumU64;
}

function timestampOrNull(value: unknown): value is string | null {
  return value === null || text(value, 64, false) &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/u.test(value) &&
    Number.isFinite(Date.parse(value));
}

/** Four octal digits, or nothing: anything else is not a mode we can show. */
function modeOrNull(value: unknown): value is string | null {
  return value === null || typeof value === "string" && /^[0-7]{4}$/u.test(value);
}

/** A POSIX id fits in 32 bits and is never negative. */
function idOrNull(value: unknown): value is number | null {
  return value === null ||
    typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 4_294_967_295;
}

function entry(value: unknown): value is SftpBrowserEntry {
  if (!record(value) || !exact(value, [
    "entryHandle", "name", "nameTruncated", "kind", "action", "sizeBytes", "modifiedAt",
    "mode", "ownerId", "groupId",
  ]) || !isSftpBrowserOpaqueHandle(value.entryHandle) ||
    !safeName(value.name, value.nameTruncated, 256) ||
    typeof value.kind !== "string" || !kindSet.has(value.kind) ||
    typeof value.action !== "string" || !actionSet.has(value.action) ||
    !u64String(value.sizeBytes) || !timestampOrNull(value.modifiedAt) ||
    !modeOrNull(value.mode) || !idOrNull(value.ownerId) || !idOrNull(value.groupId)) return false;
  if (value.kind === "file") return value.action === "preview";
  if (value.kind === "directory") return value.action === "browse" || value.action === "none";
  return value.action === "none";
}

export function isSftpDirectorySnapshot(value: unknown): value is SftpDirectorySnapshot {
  if (!record(value) || !exact(value, [
    "browserHandle", "directoryHandle", "parentDirectoryHandle", "directoryLabel",
    "directoryLabelTruncated", "expiresInSeconds", "observedEntryCount",
    "displayedEntryCount", "truncated", "entries",
  ]) || !isSftpBrowserOpaqueHandle(value.browserHandle) ||
    !isSftpBrowserOpaqueHandle(value.directoryHandle) ||
    !(value.parentDirectoryHandle === null || isSftpBrowserOpaqueHandle(value.parentDirectoryHandle)) ||
    value.parentDirectoryHandle === value.directoryHandle ||
    !safeName(value.directoryLabel, value.directoryLabelTruncated, 256) ||
    !unsigned(value.expiresInSeconds, 300) || value.expiresInSeconds === 0 ||
    !unsigned(value.observedEntryCount, 50_000) || !unsigned(value.displayedEntryCount, 128) ||
    typeof value.truncated !== "boolean" || !Array.isArray(value.entries) ||
    value.entries.length !== value.displayedEntryCount || !value.entries.every(entry) ||
    value.displayedEntryCount > value.observedEntryCount ||
    value.truncated !== (value.observedEntryCount > value.displayedEntryCount) ||
    !serializedWithin(value, 128 * 1_024)) return false;
  const entries = value.entries as SftpBrowserEntry[];
  return new Set(entries.map((item) => item.entryHandle)).size === entries.length &&
    !entries.some((item) => item.entryHandle === value.directoryHandle ||
      item.entryHandle === value.parentDirectoryHandle);
}

/** File text is shown as the target has it; only control characters are refused. */
function outputLine(value: string): boolean {
  return encoder.encode(value).byteLength <= 4 * 1_024 &&
    !/[\r\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value);
}

function textLines(value: string, displayedLineCount: number): string[] | null {
  if (value.length === 0) return displayedLineCount === 0 ? [] : displayedLineCount === 1 ? [""] : null;
  const lines = value.split("\n");
  return lines.length === displayedLineCount ? lines : null;
}

export function isSftpTransferResult(value: unknown): value is SftpTransferResult {
  if (!record(value) || !exact(value, ["saved", "fileName", "bytes"]) ||
    typeof value.saved !== "boolean") return false;
  if (!value.saved) return value.fileName === null && value.bytes === null;
  return safeName(value.fileName, false, 256) && u64String(value.bytes);
}

const operationKindSet = new Set<string>(sftpOperationKinds);

/** Plan text is drawn in a dialog, so it stays one bounded line. */
function planText(value: unknown, maximumBytes: number): value is string {
  return text(value, maximumBytes, false) && !CONTROL_CHARACTERS.test(value);
}

const archiveFormatSet = new Set<string>(sftpArchiveFormats);

/**
 * The renderer's request, checked before it reaches the sidecar. Each kind
 * names exactly the capabilities it needs, and nothing carries a path.
 */
export function isSftpOperationInput(value: unknown): value is SftpOperationInput {
  if (!record(value) || typeof value.kind !== "string" || !operationKindSet.has(value.kind) ||
    !Array.isArray(value.entryHandles) || value.entryHandles.length === 0 ||
    value.entryHandles.length > 64 ||
    !value.entryHandles.every(isSftpBrowserOpaqueHandle)) return false;
  const named = value.name === null || value.name === undefined
    ? null
    : safeName(value.name, false, 255) ? value.name : false;
  if (named === false) return false;
  const single = value.entryHandles.length === 1;
  switch (value.kind) {
    case "create-directory":
    case "rename":
      return single && named !== null;
    case "chmod":
      return single && named === null && unsigned(value.mode, 0o7777);
    case "remove":
      return single && named === null;
    case "archive":
      return named !== null && typeof value.format === "string" &&
        archiveFormatSet.has(value.format);
    case "upload":
      return single && named !== null && isSftpBrowserOpaqueHandle(value.stagedHandle);
    default:
      return false;
  }
}

export function isSftpOperationPlan(value: unknown): value is SftpOperationPlan {
  return record(value) && exact(value, [
    "planHandle", "browserHandle", "kind", "summary", "dangerous", "restoreDescription",
    "state", "expiresInSeconds",
  ]) && isSftpBrowserOpaqueHandle(value.planHandle) &&
    isSftpBrowserOpaqueHandle(value.browserHandle) &&
    typeof value.kind === "string" && operationKindSet.has(value.kind) &&
    planText(value.summary, 1_024) && typeof value.dangerous === "boolean" &&
    (value.restoreDescription === null || planText(value.restoreDescription, 1_024)) &&
    (value.state === "planned" || value.state === "confirmed" || value.state === "spent") &&
    unsigned(value.expiresInSeconds, 300) && value.expiresInSeconds > 0;
}

export function isSftpOperationReceipt(value: unknown): value is SftpOperationReceipt {
  return record(value) && exact(value, ["planHandle", "kind", "passed", "detail", "restored"]) &&
    isSftpBrowserOpaqueHandle(value.planHandle) &&
    typeof value.kind === "string" && operationKindSet.has(value.kind) &&
    typeof value.passed === "boolean" && planText(value.detail, 1_024) &&
    typeof value.restored === "boolean" &&
    // Nothing is put back when the work passed.
    !(value.passed && value.restored);
}

export function isSftpStagedUpload(value: unknown): value is SftpStagedUpload {
  return record(value) && exact(value, ["stagedHandle", "name", "bytes"]) &&
    isSftpBrowserOpaqueHandle(value.stagedHandle) &&
    safeName(value.name, false, 256) && u64String(value.bytes);
}

export function isSftpTextPreview(value: unknown): value is SftpTextPreview {
  if (!record(value) || !exact(value, [
    "browserHandle", "fileHandle", "text", "observedLineCount", "displayedLineCount", "truncated",
  ]) || !isSftpBrowserOpaqueHandle(value.browserHandle) || !isSftpBrowserOpaqueHandle(value.fileHandle) ||
    !text(value.text, 256 * 1_024) || !unsigned(value.observedLineCount, 2 * 1_024 * 1_024) ||
    !unsigned(value.displayedLineCount, 2_000) ||
    typeof value.truncated !== "boolean" || !serializedWithin(value, 384 * 1_024)) return false;
  const lines = textLines(value.text, value.displayedLineCount);
  return lines !== null && value.displayedLineCount <= value.observedLineCount &&
    lines.every(outputLine) && !(value.observedLineCount > value.displayedLineCount && !value.truncated);
}
