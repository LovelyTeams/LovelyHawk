/**
 * Looking around inside a container or a pod: one directory at a time, and
 * for a pod, one text file. Shared by the Docker and Kubernetes pages.
 *
 * Names are whatever the image holds, so they are data: displayed, never
 * parsed into anything. A path the page sends back is checked here and again
 * by the backend, and the place it is looked up in is the list's own handle.
 */

export type ExecEntryKind = "directory" | "file" | "symlink" | "other";

export interface ExecDirectoryEntry {
  name: string;
  kind: ExecEntryKind;
  /** Null where the image has no `stat`, or it could not describe the entry. */
  size: number | null;
  modifiedUnix: number | null;
  /** Permission bits as `stat` prints them, e.g. `755`. */
  mode: string | null;
  /** False for a name this tool cannot name again (control characters, a backslash, bytes that are not UTF-8). */
  openable: boolean;
}

export interface ExecDirectoryListing {
  path: string;
  entries: readonly ExecDirectoryEntry[];
  truncated: boolean;
}

export interface PodFile {
  path: string;
  text: string;
  bytes: number;
  sha256: string;
}

export interface ContainerFilesApi {
  listDockerContainerDirectory(
    bindingHandle: string,
    snapshotHandle: string,
    containerHandle: string,
    path: string,
  ): Promise<unknown>;
}

export interface PodFilesApi {
  listKubernetesPodDirectory(
    bindingHandle: string,
    snapshotHandle: string,
    rowHandle: string,
    path: string,
    /** One of the pod's containers; null for its default one. */
    container: string | null,
  ): Promise<unknown>;
  readKubernetesPodFile(
    bindingHandle: string,
    snapshotHandle: string,
    rowHandle: string,
    path: string,
    /** One of the pod's containers; null for its default one. */
    container: string | null,
  ): Promise<unknown>;
}

export const MAX_EXEC_DIRECTORY_ENTRIES = 1_000;
export const MAX_POD_FILE_BYTES = 1024 * 1024;
const MAX_PATH = 4_096;
const MAX_NAME = 1_024;
const KINDS: readonly string[] = ["directory", "file", "symlink", "other"];
const encoder = new TextEncoder();

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && keys.every((key) => key in value);
}

function carriesControlCharacter(value: string): boolean {
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

function isNullableSafeInteger(value: unknown): value is number | null {
  return value === null || (typeof value === "number" && Number.isSafeInteger(value));
}

/**
 * The same rule the backend applies: absolute, no empty, `.` or `..`
 * component, no trailing slash except the root, no backslash or control
 * character.
 */
export function isExecDirectoryPath(value: unknown): value is string {
  if (typeof value !== "string" || !value.startsWith("/") || value.length > MAX_PATH) return false;
  if (value === "/") return true;
  if (value.endsWith("/") || value.includes("\\") || carriesControlCharacter(value)) return false;
  return value.slice(1).split("/").every((part) => part !== "" && part !== "." && part !== "..");
}

/** A file's path: a directory path that is not the root. */
export function isExecFilePath(value: unknown): value is string {
  return isExecDirectoryPath(value) && value !== "/";
}

export function joinExecPath(directory: string, name: string): string {
  return directory === "/" ? `/${name}` : `${directory}/${name}`;
}

/** The directory above, or null at the root. */
export function parentExecPath(path: string): string | null {
  if (path === "/") return null;
  const cut = path.lastIndexOf("/");
  return cut <= 0 ? "/" : path.slice(0, cut);
}

function isEntry(value: unknown): value is ExecDirectoryEntry {
  if (!isRecord(value)) return false;
  return (
    hasExactKeys(value, ["name", "kind", "size", "modifiedUnix", "mode", "openable"]) &&
    typeof value.name === "string" &&
    value.name.length > 0 &&
    value.name.length <= MAX_NAME &&
    !value.name.includes("/") &&
    typeof value.kind === "string" &&
    KINDS.includes(value.kind) &&
    isNullableSafeInteger(value.size) &&
    (value.size === null || value.size >= 0) &&
    isNullableSafeInteger(value.modifiedUnix) &&
    (value.mode === null || (typeof value.mode === "string" && /^[0-7]{1,4}$/u.test(value.mode))) &&
    typeof value.openable === "boolean"
  );
}

export function isExecDirectoryListing(value: unknown): value is ExecDirectoryListing {
  if (!isRecord(value)) return false;
  return (
    hasExactKeys(value, ["path", "entries", "truncated"]) &&
    isExecDirectoryPath(value.path) &&
    Array.isArray(value.entries) &&
    value.entries.length <= MAX_EXEC_DIRECTORY_ENTRIES &&
    value.entries.every(isEntry) &&
    typeof value.truncated === "boolean"
  );
}

export function isPodFile(value: unknown): value is PodFile {
  if (!isRecord(value)) return false;
  return (
    hasExactKeys(value, ["path", "text", "bytes", "sha256"]) &&
    isExecFilePath(value.path) &&
    typeof value.text === "string" &&
    typeof value.bytes === "number" &&
    Number.isSafeInteger(value.bytes) &&
    value.bytes <= MAX_POD_FILE_BYTES &&
    value.bytes === encoder.encode(value.text).byteLength &&
    typeof value.sha256 === "string" &&
    /^[0-9a-f]{64}$/u.test(value.sha256)
  );
}
