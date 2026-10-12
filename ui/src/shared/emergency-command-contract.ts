export const emergencyCommandCategories = [
  "permissions", "accounts", "network", "processes", "persistence", "logs", "files", "containers", "system",
] as const;
export const emergencyCommandResultKinds = [
  "success", "empty", "non-zero", "timeout", "missing-command", "permission-denied", "unknown-exit",
] as const;

export const emergencyPathActions = ["disarm", "quarantine"] as const;

export type EmergencyCommandCategory = typeof emergencyCommandCategories[number];
export type EmergencyCommandResultKind = typeof emergencyCommandResultKinds[number];
export type EmergencyPathAction = typeof emergencyPathActions[number];

export interface EmergencyCommandCatalogItem {
  commandHandle: string;
  category: EmergencyCommandCategory;
  title: string;
  description: string;
  timeoutSeconds: number;
}

export const emergencyCommandPlaces = ["container", "pod"] as const;
export type EmergencyCommandPlace = typeof emergencyCommandPlaces[number];

/**
 * A place on this target that a check can be pointed at.
 *
 * A container of its runtime, or a pod of the cluster it can reach. Name and
 * image so a person can pick the right one; a handle so the run can name it.
 * No container id and no raw pod reference — the same rule the Docker and
 * Kubernetes panes follow.
 */
export interface EmergencyCommandContainer {
  containerHandle: string;
  /**
   * Which kind of place this is.
   *
   * Carried rather than guessed from the name, so the pane can say "容器" or
   * "Pod" truthfully instead of calling everything a container.
   */
  kind: EmergencyCommandPlace;
  /** A container's name, or a pod as `namespace/name`. */
  name: string;
  image: string;
}

/**
 * Whether the commands were chosen for this machine or are the portable set.
 *
 * A closed pair of words, never the distribution itself: what the operator
 * needs to know is whether the answers they are about to get are the good ones.
 */
export type EmergencyCommandSet = "detected" | "portable";

export interface EmergencyCommandCatalog {
  snapshotHandle: string;
  expiresInSeconds: number;
  commandSet: EmergencyCommandSet;
  commands: EmergencyCommandCatalogItem[];
  /**
   * Empty when the target has no container runtime, which is the ordinary
   * case and not an error.
   */
  containers: EmergencyCommandContainer[];
}

/**
 * A file one output line named, offered back as a capability.
 *
 * The window shows `path` and acts through `pathHandle`. It never sends a path
 * of its own, so an action can only ever reach a file the target itself
 * printed into this result.
 */
export interface EmergencyCommandPathOffer {
  pathHandle: string;
  /** Which displayed output line this path was read from. */
  line: number;
  path: string;
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
  /** The files this output named, at most one per displayed line. */
  paths: EmergencyCommandPathOffer[];
}

/** What the target says about one of those files right now. */
export interface EmergencyPathDetail {
  pathHandle: string;
  path: string;
  kind: "file" | "directory" | "symlink" | "other";
  /** Byte count as text, because a file can be larger than a safe integer. */
  size: string;
  /** Four octal digits, or null when the target did not report permissions. */
  mode: string | null;
  ownerId: number | null;
  groupId: number | null;
  modifiedAt: string | null;
  executable: boolean;
}

/** What an action would do, before any of it is done. */
export interface EmergencyPathPlan {
  planHandle: string;
  pathHandle: string;
  path: string;
  action: EmergencyPathAction;
  summary: string;
  dangerous: boolean;
  restoreDescription: string | null;
  state: "planned" | "confirmed" | "spent";
  expiresInSeconds: number;
}

/** What happened, after the target was checked. */
export interface EmergencyPathReceipt {
  planHandle: string;
  path: string;
  action: EmergencyPathAction;
  passed: boolean;
  detail: string;
  restored: boolean;
  /** Refused by a check before anything was written; nothing needed restoring. */
  untouched: boolean;
  /** Done, verified and reversible: the receipt may offer to undo it for a while. */
  undoable: boolean;
}

export interface EmergencyCommandApi {
  loadEmergencyCommandCatalog(bindingHandle: string): Promise<unknown>;
  /**
   * Runs one catalogue check.
   *
   * With a container handle the same check runs inside that container instead
   * of on the target itself; the handle must come from the same catalogue.
   */
  runEmergencyCommand(
    bindingHandle: string,
    snapshotHandle: string,
    commandHandle: string,
    containerHandle?: string,
  ): Promise<unknown>;
  inspectEmergencyPath(bindingHandle: string, pathHandle: string): Promise<unknown>;
  planEmergencyPathAction(
    bindingHandle: string,
    pathHandle: string,
    action: EmergencyPathAction,
  ): Promise<unknown>;
  confirmEmergencyPathAction(bindingHandle: string, planHandle: string): Promise<unknown>;
  executeEmergencyPathAction(bindingHandle: string, planHandle: string): Promise<unknown>;
  cancelEmergencyPathAction(bindingHandle: string, planHandle: string): Promise<void>;
  /** Puts a finished action back, only while the file is as the action left it. */
  undoEmergencyPathAction(bindingHandle: string, planHandle: string): Promise<unknown>;
  /**
   * Finds, in this catalogue, the check a command-history record ran. Which
   * check that was stays with the backend; only this snapshot's handle comes
   * back, or why there is none.
   */
  locateEmergencyHistoryCommand(bindingHandle: string, snapshotHandle: string, historyId: string): Promise<unknown>;
}

export const emergencyHistoryLocationStatuses = ["found", "missing", "not-recorded", "not-in-catalog"] as const;
export type EmergencyHistoryLocationStatus = typeof emergencyHistoryLocationStatuses[number];

/** Where a history record's check sits in the current catalogue, if anywhere. */
export interface EmergencyHistoryLocation {
  status: EmergencyHistoryLocationStatus;
  commandHandle: string | null;
}

type JsonRecord = Record<string, unknown>;
const encoder = new TextEncoder();
const categorySet = new Set<string>(emergencyCommandCategories);
const resultKindSet = new Set<string>(emergencyCommandResultKinds);
const placeSet = new Set<string>(emergencyCommandPlaces);
const pathActionSet = new Set<string>(emergencyPathActions);
const pathKindSet = new Set<string>(["file", "directory", "symlink", "other"]);
const planStateSet = new Set<string>(["planned", "confirmed", "spent"]);

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
  if (!record(value) || !exact(value, ["snapshotHandle", "expiresInSeconds", "commandSet", "commands", "containers"]) ||
    !isEmergencyCommandOpaqueHandle(value.snapshotHandle) || value.expiresInSeconds !== 300 ||
    (value.commandSet !== "detected" && value.commandSet !== "portable") ||
    !Array.isArray(value.commands) || value.commands.length > 256 || !value.commands.every(catalogItem) ||
    !Array.isArray(value.containers) || value.containers.length > 64 ||
    !value.containers.every(catalogContainer) ||
    !serializedWithin(value, 256 * 1_024)) return false;
  const commands = value.commands as EmergencyCommandCatalogItem[];
  const containers = value.containers as EmergencyCommandContainer[];
  return new Set(commands.map((command) => command.commandHandle)).size === commands.length &&
    new Set(containers.map((container) => container.containerHandle)).size === containers.length;
}

function catalogContainer(value: unknown): value is EmergencyCommandContainer {
  return record(value) && exact(value, ["containerHandle", "kind", "name", "image"]) &&
    isEmergencyCommandOpaqueHandle(value.containerHandle) &&
    typeof value.kind === "string" && placeSet.has(value.kind) &&
    catalogText(value.name, 128) && catalogText(value.image, 128);
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

/**
 * A path the sidecar read out of its own output. It is displayed, never sent
 * back, so the check is only that it is drawable and could name a real file.
 */
function offeredPath(value: unknown): value is string {
  return text(value, 1_024, false) && value.startsWith("/") && !/[\u0000-\u001f\u007f]/u.test(value);
}

function pathOffer(value: unknown): value is EmergencyCommandPathOffer {
  return record(value) && exact(value, ["pathHandle", "line", "path"]) &&
    isEmergencyCommandOpaqueHandle(value.pathHandle) && unsigned(value.line, 1_999) &&
    offeredPath(value.path);
}

export function isEmergencyCommandResult(value: unknown): value is EmergencyCommandResult {
  if (!record(value) || !exact(value, [
    "snapshotHandle", "commandHandle", "resultKind", "exitCode", "output", "observedLineCount",
    "displayedLineCount", "findingLines", "findingReason", "truncated", "paths",
  ]) || !isEmergencyCommandOpaqueHandle(value.snapshotHandle) ||
    !isEmergencyCommandOpaqueHandle(value.commandHandle) || typeof value.resultKind !== "string" ||
    !resultKindSet.has(value.resultKind) || !signedI32OrNull(value.exitCode) || !text(value.output, 256 * 1_024) ||
    !unsigned(value.observedLineCount, 2 * 1_024 * 1_024) || !unsigned(value.displayedLineCount, 2_000) ||
    typeof value.truncated !== "boolean" ||
    !Array.isArray(value.findingLines) || value.findingLines.length > 2_000 ||
    !(value.findingReason === null || catalogText(value.findingReason, 512)) ||
    !Array.isArray(value.paths) || value.paths.length > 500 || !value.paths.every(pathOffer) ||
    !serializedWithin(value, 384 * 1_024)) return false;
  const lines = outputLines(value.output);
  if (lines.length !== value.displayedLineCount || value.displayedLineCount > value.observedLineCount ||
    !lines.every(outputLine) || value.observedLineCount > value.displayedLineCount && !value.truncated) return false;
  // A mark has to point at a line that is actually here.
  const marks = value.findingLines as unknown[];
  if (!marks.every((mark, index) => unsigned(mark, 1_999) && mark < lines.length &&
    (index === 0 || mark > (marks[index - 1] as number)))) return false;
  // An offer has to point at a line that is here, name what that line says,
  // and be the only offer for it.
  const offers = value.paths as EmergencyCommandPathOffer[];
  if (new Set(offers.map((offer) => offer.pathHandle)).size !== offers.length ||
    new Set(offers.map((offer) => offer.line)).size !== offers.length ||
    !offers.every((offer) => offer.line < lines.length &&
      (lines[offer.line] as string).includes(offer.path.slice(offer.path.lastIndexOf("/") + 1)))) return false;
  if (value.resultKind === "success") return value.exitCode === 0 && value.output.length > 0;
  if (value.resultKind === "empty") return value.exitCode === 0 && value.output.length === 0;
  if (value.resultKind === "non-zero") return value.exitCode !== null && value.exitCode !== 0;
  if (value.resultKind === "unknown-exit") return value.exitCode === null;
  return true;
}

export function isEmergencyPathDetail(value: unknown): value is EmergencyPathDetail {
  return record(value) && exact(value, [
    "pathHandle", "path", "kind", "size", "mode", "ownerId", "groupId", "modifiedAt", "executable",
  ]) && isEmergencyCommandOpaqueHandle(value.pathHandle) && offeredPath(value.path) &&
    typeof value.kind === "string" && pathKindSet.has(value.kind) &&
    typeof value.size === "string" && /^\d{1,20}$/u.test(value.size) &&
    (value.mode === null || typeof value.mode === "string" && /^[0-7]{4}$/u.test(value.mode)) &&
    (value.ownerId === null || unsigned(value.ownerId, 4_294_967_295)) &&
    (value.groupId === null || unsigned(value.groupId, 4_294_967_295)) &&
    (value.modifiedAt === null || catalogText(value.modifiedAt, 64)) &&
    typeof value.executable === "boolean";
}

export function isEmergencyPathPlan(value: unknown): value is EmergencyPathPlan {
  return record(value) && exact(value, [
    "planHandle", "pathHandle", "path", "action", "summary", "dangerous", "restoreDescription",
    "state", "expiresInSeconds",
  ]) && isEmergencyCommandOpaqueHandle(value.planHandle) &&
    isEmergencyCommandOpaqueHandle(value.pathHandle) && offeredPath(value.path) &&
    typeof value.action === "string" && pathActionSet.has(value.action) &&
    catalogText(value.summary, 512) && typeof value.dangerous === "boolean" &&
    (value.restoreDescription === null || catalogText(value.restoreDescription, 512)) &&
    typeof value.state === "string" && planStateSet.has(value.state) &&
    unsigned(value.expiresInSeconds, 300) && value.expiresInSeconds > 0;
}

export function isEmergencyPathReceipt(value: unknown): value is EmergencyPathReceipt {
  return record(value) && exact(value, [
    "planHandle", "path", "action", "passed", "detail", "restored", "untouched", "undoable",
  ]) && isEmergencyCommandOpaqueHandle(value.planHandle) && offeredPath(value.path) &&
    typeof value.action === "string" && pathActionSet.has(value.action) &&
    typeof value.passed === "boolean" && catalogText(value.detail, 512) &&
    typeof value.restored === "boolean" && typeof value.untouched === "boolean" &&
    typeof value.undoable === "boolean" &&
    // Only a refusal can leave the file untouched, and then nothing was restored.
    (!value.untouched || (!value.passed && !value.restored)) &&
    // Only a verified action can be offered for undo.
    (!value.undoable || value.passed);
}

/** What an undo did: put back and read back, or refused with the reason. */
export interface EmergencyPathUndoResult {
  planHandle: string;
  path: string;
  undone: boolean;
  detail: string;
}

const historyLocationStatusSet = new Set<string>(emergencyHistoryLocationStatuses);

export function isEmergencyHistoryLocation(value: unknown): value is EmergencyHistoryLocation {
  return record(value) && exact(value, ["status", "commandHandle"]) &&
    typeof value.status === "string" && historyLocationStatusSet.has(value.status) &&
    // A handle exactly when it was found.
    (value.status === "found"
      ? isEmergencyCommandOpaqueHandle(value.commandHandle)
      : value.commandHandle === null);
}

export function isEmergencyPathUndoResult(value: unknown): value is EmergencyPathUndoResult {
  return record(value) && exact(value, ["planHandle", "path", "undone", "detail"]) &&
    isEmergencyCommandOpaqueHandle(value.planHandle) && offeredPath(value.path) &&
    typeof value.undone === "boolean" && catalogText(value.detail, 512);
}

export function isEmergencyPathAction(value: unknown): value is EmergencyPathAction {
  return typeof value === "string" && pathActionSet.has(value);
}
