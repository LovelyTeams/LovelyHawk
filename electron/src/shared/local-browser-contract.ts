export const localBrowserEntryKinds = ["directory", "file", "other"] as const;

export type LocalBrowserEntryKind = typeof localBrowserEntryKinds[number];

export interface LocalBrowserEntry {
  entryHandle: string;
  name: string;
  nameTruncated: boolean;
  kind: LocalBrowserEntryKind;
  /** Directories report "0"; only files carry a meaningful size. */
  sizeBytes: string;
  modifiedAt: string | null;
}

export interface LocalDirectorySnapshot {
  directoryHandle: string;
  parentDirectoryHandle: string | null;
  /** Display text for the path bar; the renderer never holds a real path. */
  directoryLabel: string;
  directoryLabelTruncated: boolean;
  observedEntryCount: number;
  displayedEntryCount: number;
  truncated: boolean;
  entries: LocalBrowserEntry[];
}

/**
 * Reading the operator's own machine. Directories are addressed by opaque
 * handles main resolves, so a renderer can never name a filesystem path.
 */
export interface LocalBrowserApi {
  openLocalBrowser(): Promise<unknown>;
  listLocalDirectory(directoryHandle: string): Promise<unknown>;
}

type JsonRecord = Record<string, unknown>;
const encoder = new TextEncoder();
const kindSet = new Set<string>(localBrowserEntryKinds);
const maximumU64 = "18446744073709551615";
// Written as an escape so the source file stays plain text.
const CONTROL_CHARACTERS = new RegExp("[\u0000-\u001f\u007f]", "u");

export const LOCAL_BROWSER_LIMITS = Object.freeze({
  maximumDisplayedEntries: 256,
  maximumObservedEntries: 50_000,
  maximumNameBytes: 256,
  maximumLabelBytes: 512,
  maximumSerializedBytes: 128 * 1_024,
});

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

export function isLocalBrowserOpaqueHandle(value: unknown): value is string {
  return text(value, 128, false) && /^[A-Za-z0-9-]+$/u.test(value);
}

/** Names and labels are shown as the filesystem has them; only control
 * characters are refused, because they break the row they are drawn in. */
function displayText(value: unknown, truncated: unknown, maximumBytes: number): value is string {
  return text(value, maximumBytes, false) && typeof truncated === "boolean" &&
    !CONTROL_CHARACTERS.test(value);
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

function entry(value: unknown): value is LocalBrowserEntry {
  return record(value) && exact(value, [
    "entryHandle", "name", "nameTruncated", "kind", "sizeBytes", "modifiedAt",
  ]) && isLocalBrowserOpaqueHandle(value.entryHandle) &&
    displayText(value.name, value.nameTruncated, LOCAL_BROWSER_LIMITS.maximumNameBytes) &&
    typeof value.kind === "string" && kindSet.has(value.kind) &&
    u64String(value.sizeBytes) && timestampOrNull(value.modifiedAt);
}

export function isLocalDirectorySnapshot(value: unknown): value is LocalDirectorySnapshot {
  if (!record(value) || !exact(value, [
    "directoryHandle", "parentDirectoryHandle", "directoryLabel", "directoryLabelTruncated",
    "observedEntryCount", "displayedEntryCount", "truncated", "entries",
  ]) || !isLocalBrowserOpaqueHandle(value.directoryHandle) ||
    !(value.parentDirectoryHandle === null || isLocalBrowserOpaqueHandle(value.parentDirectoryHandle)) ||
    value.parentDirectoryHandle === value.directoryHandle ||
    !displayText(value.directoryLabel, value.directoryLabelTruncated,
      LOCAL_BROWSER_LIMITS.maximumLabelBytes) ||
    !unsigned(value.observedEntryCount, LOCAL_BROWSER_LIMITS.maximumObservedEntries) ||
    !unsigned(value.displayedEntryCount, LOCAL_BROWSER_LIMITS.maximumDisplayedEntries) ||
    typeof value.truncated !== "boolean" || !Array.isArray(value.entries) ||
    value.entries.length !== value.displayedEntryCount || !value.entries.every(entry) ||
    value.displayedEntryCount > value.observedEntryCount ||
    value.truncated !== (value.observedEntryCount > value.displayedEntryCount) ||
    !serializedWithin(value, LOCAL_BROWSER_LIMITS.maximumSerializedBytes)) return false;
  const entries = value.entries as LocalBrowserEntry[];
  return new Set(entries.map((item) => item.entryHandle)).size === entries.length &&
    !entries.some((item) => item.entryHandle === value.directoryHandle ||
      item.entryHandle === value.parentDirectoryHandle);
}
