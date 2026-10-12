/**
 * Acting on a container the Docker pane already listed.
 *
 * The renderer holds a container handle its own snapshot minted and a plan
 * handle the sidecar minted. It never holds a container id, a runtime verb or
 * a command, so the worst a compromised renderer can ask for is an action on
 * a container the operator is already looking at — and only after the operator
 * approved that exact plan.
 */

/** The closed set of actions. Anything else is not describable from here. */
export const DOCKER_WRITE_ACTIONS = [
  "start",
  "stop",
  "restart",
  "pause",
  "unpause",
  "kill",
  "remove",
] as const;

export type DockerWriteAction = (typeof DOCKER_WRITE_ACTIONS)[number];

/**
 * A plan can also write a file or copy one. Those name a path inside the
 * container or on the connected host — never on the operator's computer —
 * and go through the same plan, confirm, read-back and backup.
 */
export const DOCKER_FILE_PLAN_KINDS = ["write-file", "copy-file"] as const;
export type DockerPlanKind = DockerWriteAction | (typeof DOCKER_FILE_PLAN_KINDS)[number];

export const DOCKER_FILE_COPY_DIRECTIONS = ["container-to-host", "host-to-container", "in-container"] as const;
export type DockerFileCopyDirection = (typeof DOCKER_FILE_COPY_DIRECTIONS)[number];

/** The core's limit for one edited or copied file. */
export const MAX_DOCKER_FILE_BYTES = 2 * 1024 * 1024;
export const MAX_DOCKER_FILE_PATH = 4_096;

/** A text file opened from a container; the handle is what a save names. */
export interface DockerContainerFile {
  fileHandle: string;
  containerHandle: string;
  containerName: string;
  path: string;
  text: string;
  bytes: number;
}

export interface DockerActionPlan {
  planHandle: string;
  containerHandle: string;
  /** Display only. The identity comes from the handle. */
  containerName: string;
  action: DockerPlanKind;
  actionLabel: string;
  /** What the host said the container was doing when the plan was made. */
  beforeState: string;
  summary: string;
  dangerous: boolean;
  restoreDescription: string | null;
  confirmed: boolean;
  expiresInSeconds: number;
}

export interface DockerActionReceipt {
  planHandle: string;
  containerName: string;
  actionLabel: string;
  /**
   * Whether the host, read back afterwards, is in the state the plan said it
   * would be. A command that exited zero is not the same claim.
   */
  verified: boolean;
  detail: string;
  restored: boolean;
}

export interface DockerActionCancellation {
  cancelled: boolean;
}

export interface DockerWriteApi {
  planDockerContainerAction(
    bindingHandle: string,
    snapshotHandle: string,
    containerHandle: string,
    containerName: string,
    action: DockerWriteAction,
  ): Promise<unknown>;
  confirmDockerContainerAction(bindingHandle: string, planHandle: string): Promise<unknown>;
  executeDockerContainerAction(bindingHandle: string, planHandle: string): Promise<unknown>;
  cancelDockerContainerAction(bindingHandle: string, planHandle: string): Promise<unknown>;
  /** Opens one text file inside a listed container. */
  readDockerContainerFile(
    bindingHandle: string,
    snapshotHandle: string,
    containerHandle: string,
    containerName: string,
    path: string,
  ): Promise<unknown>;
  /** Plans saving new text over a file opened above; confirmed and run like an action. */
  planDockerFileWrite(bindingHandle: string, fileHandle: string, text: string): Promise<unknown>;
  /** Plans copying one file between a listed container and its host, or within it. */
  planDockerFileCopy(
    bindingHandle: string,
    snapshotHandle: string,
    containerHandle: string,
    containerName: string,
    direction: DockerFileCopyDirection,
    source: string,
    target: string,
  ): Promise<unknown>;
  /**
   * Open a terminal window with a shell inside a listed container.
   *
   * Filed with the write capabilities rather than the read ones, because a
   * shell is the widest write there is: everything the plan/confirm pipeline
   * carefully describes before doing, an operator in here can do by typing.
   * What keeps it bounded is that it opens a window rather than running
   * anything — nothing is executed on the caller's behalf.
   */
  openDockerContainerTerminal(
    snapshotHandle: string,
    containerHandle: string,
    containerName: string,
  ): Promise<unknown>;
}

const MAX_TEXT = 512;
const FIRST_PRINTABLE_CODE_POINT = 0x20;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && keys.every((key) => key in value);
}

function isBoundedText(value: unknown, limit = MAX_TEXT): value is string {
  return typeof value === "string" && value.length <= limit;
}

function isHandle(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 128;
}

/**
 * Written as a scan rather than a character-class regular expression: the
 * class would need literal control characters or escapes for them in the
 * source, and a source file carrying invisible bytes is one nobody can review.
 */
function carriesControlCharacter(value: string): boolean {
  for (const character of value) {
    if ((character.codePointAt(0) ?? 0) < FIRST_PRINTABLE_CODE_POINT) return true;
  }
  return false;
}

export function isDockerWriteAction(value: unknown): value is DockerWriteAction {
  return typeof value === "string" &&
    (DOCKER_WRITE_ACTIONS as readonly string[]).includes(value);
}

export function isDockerPlanKind(value: unknown): value is DockerPlanKind {
  return isDockerWriteAction(value) ||
    (typeof value === "string" && (DOCKER_FILE_PLAN_KINDS as readonly string[]).includes(value));
}

export function isDockerFileCopyDirection(value: unknown): value is DockerFileCopyDirection {
  return typeof value === "string" &&
    (DOCKER_FILE_COPY_DIRECTIONS as readonly string[]).includes(value);
}

/** An absolute path to a file, as typed; the core checks it again. */
export function isDockerFilePath(value: unknown): value is string {
  return typeof value === "string" &&
    value.startsWith("/") &&
    value.length > 1 &&
    value.length <= MAX_DOCKER_FILE_PATH &&
    !value.endsWith("/") &&
    !carriesControlCharacter(value);
}

const encoder = new TextEncoder();

export function isDockerFileText(value: unknown): value is string {
  return typeof value === "string" && encoder.encode(value).byteLength <= MAX_DOCKER_FILE_BYTES;
}

export function isDockerContainerFile(value: unknown): value is DockerContainerFile {
  if (!isRecord(value)) return false;
  return (
    hasExactKeys(value, ["fileHandle", "containerHandle", "containerName", "path", "text", "bytes"]) &&
    isHandle(value.fileHandle) &&
    isHandle(value.containerHandle) &&
    isBoundedText(value.containerName, 256) &&
    isDockerFilePath(value.path) &&
    isDockerFileText(value.text) &&
    typeof value.bytes === "number" &&
    Number.isSafeInteger(value.bytes) &&
    value.bytes === encoder.encode(value.text).byteLength
  );
}

/**
 * The name a dialog will display, on its way back down.
 *
 * Bounded and free of control characters, and that is the whole contract:
 * nothing resolves through it, so it is checked for being displayable rather
 * than for being true. A container really can be named something hostile, and
 * refusing to show that would hide it from the operator who needs to see it.
 */
export function isDockerContainerName(value: unknown): value is string {
  return typeof value === "string" &&
    value.length > 0 &&
    value.length <= 256 &&
    !carriesControlCharacter(value);
}

export function isDockerActionPlan(value: unknown): value is DockerActionPlan {
  if (!isRecord(value)) return false;
  return (
    hasExactKeys(value, [
      "planHandle",
      "containerHandle",
      "containerName",
      "action",
      "actionLabel",
      "beforeState",
      "summary",
      "dangerous",
      "restoreDescription",
      "confirmed",
      "expiresInSeconds",
    ]) &&
    isHandle(value.planHandle) &&
    isHandle(value.containerHandle) &&
    isBoundedText(value.containerName, 256) &&
    isDockerPlanKind(value.action) &&
    isBoundedText(value.actionLabel, 64) &&
    isBoundedText(value.beforeState, 64) &&
    isBoundedText(value.summary) &&
    typeof value.dangerous === "boolean" &&
    (value.restoreDescription === null || isBoundedText(value.restoreDescription)) &&
    typeof value.confirmed === "boolean" &&
    typeof value.expiresInSeconds === "number" &&
    Number.isInteger(value.expiresInSeconds) &&
    value.expiresInSeconds > 0 &&
    value.expiresInSeconds <= 3_600
  );
}

export function isDockerActionReceipt(value: unknown): value is DockerActionReceipt {
  if (!isRecord(value)) return false;
  return (
    hasExactKeys(value, [
      "planHandle",
      "containerName",
      "actionLabel",
      "verified",
      "detail",
      "restored",
    ]) &&
    isHandle(value.planHandle) &&
    isBoundedText(value.containerName, 256) &&
    isBoundedText(value.actionLabel, 64) &&
    typeof value.verified === "boolean" &&
    isBoundedText(value.detail) &&
    typeof value.restored === "boolean"
  );
}

export function isDockerActionCancellation(value: unknown): value is DockerActionCancellation {
  if (!isRecord(value)) return false;
  return hasExactKeys(value, ["cancelled"]) && value.cancelled === true;
}
