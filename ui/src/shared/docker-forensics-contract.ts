/**
 * Two questions a responder asks of a container before anything else, both
 * answered from the host and both read-only: what changed in its filesystem
 * since the image (`docker diff`), and what is running in it (`docker top`).
 *
 * Paths and command lines are whatever the container holds, so they are data:
 * shown, never parsed into anything the page acts on.
 */

export type DockerChangeKind = "added" | "changed" | "deleted";

export interface DockerContainerChanges {
  snapshotHandle: string;
  containerHandle: string;
  items: ReadonlyArray<{ kind: DockerChangeKind; path: string }>;
  truncated: boolean;
  /** Lines that did not read as a change, counted rather than shown as one. */
  unreadableLines: number;
}

export interface DockerContainerProcesses {
  snapshotHandle: string;
  containerHandle: string;
  /** The runtime's own column titles: `ps -ef`'s for Docker, Podman's own. */
  titles: readonly string[];
  rows: ReadonlyArray<readonly string[]>;
  truncated: boolean;
}

export interface DockerForensicsApi {
  getDockerContainerChanges(bindingHandle: string, snapshotHandle: string, containerHandle: string): Promise<unknown>;
  getDockerContainerProcesses(bindingHandle: string, snapshotHandle: string, containerHandle: string): Promise<unknown>;
}

export const MAX_DOCKER_CHANGES = 5_000;
export const MAX_DOCKER_PROCESSES = 2_000;
const MAX_FIELD = 4 * 1_024;
const MAX_COLUMNS = 16;
const CHANGE_KINDS: readonly string[] = ["added", "changed", "deleted"];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && keys.every((key) => key in value);
}

function isHandle(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 128;
}

function isField(value: unknown): value is string {
  return typeof value === "string" && value.length <= MAX_FIELD;
}

export function isDockerContainerChanges(value: unknown): value is DockerContainerChanges {
  if (!isRecord(value)) return false;
  return (
    hasExactKeys(value, ["snapshotHandle", "containerHandle", "items", "truncated", "unreadableLines"]) &&
    isHandle(value.snapshotHandle) &&
    isHandle(value.containerHandle) &&
    Array.isArray(value.items) &&
    value.items.length <= MAX_DOCKER_CHANGES &&
    value.items.every((item: unknown) =>
      isRecord(item) && hasExactKeys(item, ["kind", "path"]) &&
      typeof item.kind === "string" && CHANGE_KINDS.includes(item.kind) &&
      isField(item.path) && item.path.startsWith("/")) &&
    typeof value.truncated === "boolean" &&
    typeof value.unreadableLines === "number" &&
    Number.isSafeInteger(value.unreadableLines) &&
    value.unreadableLines >= 0
  );
}

export function isDockerContainerProcesses(value: unknown): value is DockerContainerProcesses {
  if (!isRecord(value)) return false;
  if (
    !hasExactKeys(value, ["snapshotHandle", "containerHandle", "titles", "rows", "truncated"]) ||
    !isHandle(value.snapshotHandle) ||
    !isHandle(value.containerHandle) ||
    !Array.isArray(value.titles) ||
    value.titles.length === 0 ||
    value.titles.length > MAX_COLUMNS ||
    !value.titles.every(isField) ||
    !Array.isArray(value.rows) ||
    value.rows.length > MAX_DOCKER_PROCESSES ||
    typeof value.truncated !== "boolean"
  ) return false;
  const columns = value.titles.length;
  return value.rows.every((row: unknown) => Array.isArray(row) && row.length === columns && row.every(isField));
}

/** Which column holds what, by the runtime's own title, so both layouts read the same. */
export function dockerProcessColumn(titles: readonly string[], ...names: string[]): number {
  return titles.findIndex((title) => names.includes(title.toUpperCase()));
}
