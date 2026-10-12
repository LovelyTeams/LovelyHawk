/**
 * Java hot update: find the JVMs on the bound host, open a JAR one of them
 * runs, and replace one class inside it through a plan, a confirmation and a
 * verified, restorable write.
 *
 * The page sends handles the backend made, a class entry the backend listed,
 * and at most one typed absolute .jar path to read; the replacement class is
 * staged by the host from its open dialog.
 */

export const javaToolNames = ["java", "jar", "jcmd", "jstack", "jmap", "jstat", "javap"] as const;
export type JavaToolName = typeof javaToolNames[number];

export type JavaHotUpdateRequest =
  | { action: "scan"; bindingHandle: string }
  | { action: "inspect"; bindingHandle: string; snapshotHandle: string; jarHandle: string }
  /** A JAR the scan did not list, typed by the operator; only read, like a listed one. */
  | { action: "inspect-path"; bindingHandle: string; snapshotHandle: string; path: string }
  | { action: "plan"; bindingHandle: string; snapshotHandle: string; jarHandle: string; entry: string; stagedHandle: string }
  | { action: "history"; bindingHandle: string }
  | { action: "plan-restore"; bindingHandle: string; recordId: string }
  | { action: "confirm" | "execute" | "cancel"; bindingHandle: string; planHandle: string }
  | { action: "discard-staged"; bindingHandle: string; stagedHandle: string };

export interface JavaProcess {
  pid: number;
  user: string;
  cpuPercent: number;
  memoryPercent: number;
  elapsedSeconds: number;
  /** As `ps` showed it, cut at 512 bytes by the collector. */
  command: string;
  commandTruncated: boolean;
  /** Whether this login could read the process's open files (root, or the process's own account). */
  openFilesReadable: boolean;
  /** Some of the JARs it holds open are not listed: too many, or names that cannot be used safely. */
  openJarsIncomplete: boolean;
  /** The JARs its command line names and the ones it holds open. */
  jarHandles: string[];
}

/** Most JARs one scan offers, across all processes. */
export const MAX_JAVA_JAR_OFFERS = 512;

export interface JavaJarOffer {
  jarHandle: string;
  path: string;
}

export interface JavaScan {
  kind: "scan";
  snapshotHandle: string;
  version: string | null;
  tools: { tool: JavaToolName; available: boolean }[];
  processes: JavaProcess[];
  jars: JavaJarOffer[];
  /** More JARs were found than are offered. */
  jarsTruncated: boolean;
  expiresInSeconds: number;
}

export interface JavaJar {
  kind: "jar";
  jarHandle: string;
  path: string;
  sizeBytes: number;
  sha256: string;
  classCount: number;
  classes: string[];
  truncated: boolean;
}

export interface JavaPlan {
  kind: "plan";
  planHandle: string;
  operation: "update" | "restore";
  summary: string;
  jarPath: string;
  entry: string;
  classSha256: string;
  restoreDescription: string | null;
  confirmed: boolean;
  expiresInSeconds: number;
}

export interface JavaReceipt {
  kind: "receipt";
  planHandle: string;
  operation: "update" | "restore";
  verified: boolean;
  recordId: string | null;
  jarPath: string;
  entry: string;
  jarSha256: string | null;
  detail: string;
}

export interface JavaRecord {
  recordId: string;
  jarPath: string;
  entry: string;
  state: "applied" | "restored";
  beforeJarSha256: string;
  appliedJarSha256: string;
  classSha256: string;
  createdAt: string;
  updatedAt: string;
}

export interface JavaHistory {
  kind: "history";
  records: JavaRecord[];
  truncated: boolean;
}

export interface JavaCancelled {
  kind: "cancelled";
  cancelled: boolean;
}

export type JavaHotUpdateResponse = JavaScan | JavaJar | JavaPlan | JavaReceipt | JavaHistory | JavaCancelled;

export interface JavaStagedClass {
  stagedHandle: string;
  name: string;
  sizeBytes: number;
  sha256: string;
}

/** What the host's open dialog gave back: nothing chosen, or a staged class. */
export type JavaClassStageResult = { staged: false; class: null } | { staged: true; class: JavaStagedClass };

export interface JavaHotUpdateApi {
  javaHotUpdate(request: JavaHotUpdateRequest): Promise<unknown>;
  /** Opens the host's file dialog for a .class file and stages it; the page never sees the path. */
  stageJavaClass(bindingHandle: string): Promise<unknown>;
}

type JsonRecord = Record<string, unknown>;
const encoder = new TextEncoder();
const CONTROL = /[\u0000-\u001f\u007f]/u;
const HANDLE = /^[A-Za-z0-9-]{1,128}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const ENTRY_COMPONENT = /^[A-Za-z0-9_$.-]+$/u;

function record(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function keys(value: JsonRecord, expected: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === expected.length && expected.every((key) => Object.hasOwn(value, key));
}
function text(value: unknown, maximumBytes: number): value is string {
  return typeof value === "string" && encoder.encode(value).byteLength <= maximumBytes && !CONTROL.test(value);
}
function integer(value: unknown, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= minimum && value <= maximum;
}
function percent(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 100_000;
}
function sha(value: unknown): value is string {
  return typeof value === "string" && SHA256.test(value);
}

export function isJavaHandle(value: unknown): value is string {
  return typeof value === "string" && HANDLE.test(value);
}

/** A class inside an archive, as the backend lists it and accepts it back. */
export function isJavaClassEntry(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0 || encoder.encode(value).byteLength > 1_024 ||
    value.startsWith("/") || !value.endsWith(".class")) return false;
  return value.split("/").every((part) => part !== "" && part !== "." && part !== ".." && ENTRY_COMPONENT.test(part));
}

function remotePath(value: unknown): value is string {
  return text(value, 4_096) && value.startsWith("/");
}
function jarPath(value: unknown): value is string {
  return remotePath(value) && value.toLowerCase().endsWith(".jar");
}

/**
 * A JAR path the operator typed, held to the backend's rule: absolute, plain
 * components, no backslash, no surrounding spaces, a name ending in `.jar`.
 */
export function isTypedJarPath(value: unknown): value is string {
  if (!jarPath(value) || value.trim() !== value || value.includes("\\") || value.endsWith("/")) return false;
  const parts = value.slice(1).split("/");
  const name = parts[parts.length - 1] ?? "";
  return name.length > 4 && parts.every((part) => part !== "" && part !== "." && part !== "..");
}

const REQUEST_FIELDS: Record<JavaHotUpdateRequest["action"], readonly string[]> = {
  scan: [],
  inspect: ["snapshotHandle", "jarHandle"],
  "inspect-path": ["snapshotHandle", "path"],
  plan: ["snapshotHandle", "jarHandle", "entry", "stagedHandle"],
  history: [],
  "plan-restore": ["recordId"],
  confirm: ["planHandle"],
  execute: ["planHandle"],
  cancel: ["planHandle"],
  "discard-staged": ["stagedHandle"],
};

export function isJavaHotUpdateRequest(value: unknown): value is JavaHotUpdateRequest {
  if (!record(value) || typeof value.action !== "string" || !Object.hasOwn(REQUEST_FIELDS, value.action)) return false;
  const extra = REQUEST_FIELDS[value.action as JavaHotUpdateRequest["action"]];
  return keys(value, ["action", "bindingHandle", ...extra]) && isJavaHandle(value.bindingHandle) &&
    extra.every((name) => name === "entry" ? isJavaClassEntry(value[name])
      : name === "path" ? isTypedJarPath(value[name]) : isJavaHandle(value[name]));
}

function process(value: unknown): value is JavaProcess {
  return record(value) && keys(value, ["pid", "user", "cpuPercent", "memoryPercent", "elapsedSeconds", "command", "commandTruncated",
    "openFilesReadable", "openJarsIncomplete", "jarHandles"]) &&
    integer(value.pid, 2, 4_294_967_295) && text(value.user, 256) && percent(value.cpuPercent) && percent(value.memoryPercent) &&
    integer(value.elapsedSeconds) && text(value.command, 512) && typeof value.commandTruncated === "boolean" &&
    typeof value.openFilesReadable === "boolean" && typeof value.openJarsIncomplete === "boolean" &&
    // Unread open files cannot be incompletely listed.
    (value.openFilesReadable || !value.openJarsIncomplete) &&
    Array.isArray(value.jarHandles) && value.jarHandles.length <= MAX_JAVA_JAR_OFFERS && value.jarHandles.every(isJavaHandle) &&
    new Set(value.jarHandles).size === value.jarHandles.length;
}

function scan(value: JsonRecord): value is JsonRecord & JavaScan {
  if (!keys(value, ["kind", "snapshotHandle", "version", "tools", "processes", "jars", "jarsTruncated", "expiresInSeconds"]) ||
    !isJavaHandle(value.snapshotHandle) || !(value.version === null || text(value.version, 256)) ||
    !integer(value.expiresInSeconds, 1, 3_600) || !Array.isArray(value.tools) || !Array.isArray(value.processes) ||
    !Array.isArray(value.jars) || typeof value.jarsTruncated !== "boolean") return false;
  const tools = value.tools;
  if (tools.length !== javaToolNames.length || !tools.every((tool, index) => record(tool) && keys(tool, ["tool", "available"]) &&
    tool.tool === javaToolNames[index] && typeof tool.available === "boolean")) return false;
  if (value.processes.length > 50 || !value.processes.every(process)) return false;
  if (value.jars.length > MAX_JAVA_JAR_OFFERS || !value.jars.every((jar) => record(jar) && keys(jar, ["jarHandle", "path"]) &&
    isJavaHandle(jar.jarHandle) && jarPath(jar.path))) return false;
  const offered = new Set((value.jars as JavaJarOffer[]).map((jar) => jar.jarHandle));
  return offered.size === value.jars.length &&
    new Set((value.jars as JavaJarOffer[]).map((jar) => jar.path)).size === value.jars.length &&
    (value.processes as JavaProcess[]).every((item) => item.jarHandles.every((handle) => offered.has(handle)));
}

function jar(value: JsonRecord): value is JsonRecord & JavaJar {
  return keys(value, ["kind", "jarHandle", "path", "sizeBytes", "sha256", "classCount", "classes", "truncated"]) &&
    isJavaHandle(value.jarHandle) && jarPath(value.path) && integer(value.sizeBytes) && sha(value.sha256) &&
    integer(value.classCount) && Array.isArray(value.classes) && value.classes.length <= 500 &&
    value.classes.every(isJavaClassEntry) && new Set(value.classes).size === value.classes.length &&
    typeof value.truncated === "boolean" && value.classes.length <= value.classCount &&
    value.truncated === (value.classCount > value.classes.length);
}

function plan(value: JsonRecord): value is JsonRecord & JavaPlan {
  return keys(value, ["kind", "planHandle", "operation", "summary", "jarPath", "entry", "classSha256", "restoreDescription", "confirmed", "expiresInSeconds"]) &&
    isJavaHandle(value.planHandle) && (value.operation === "update" || value.operation === "restore") &&
    text(value.summary, 2_048) && jarPath(value.jarPath) && isJavaClassEntry(value.entry) && sha(value.classSha256) &&
    (value.restoreDescription === null || text(value.restoreDescription, 2_048)) && typeof value.confirmed === "boolean" &&
    integer(value.expiresInSeconds, 0, 3_600);
}

function receipt(value: JsonRecord): value is JsonRecord & JavaReceipt {
  return keys(value, ["kind", "planHandle", "operation", "verified", "recordId", "jarPath", "entry", "jarSha256", "detail"]) &&
    isJavaHandle(value.planHandle) && (value.operation === "update" || value.operation === "restore") &&
    typeof value.verified === "boolean" && (value.recordId === null || isJavaHandle(value.recordId)) &&
    jarPath(value.jarPath) && isJavaClassEntry(value.entry) && (value.jarSha256 === null || sha(value.jarSha256)) &&
    text(value.detail, 2_048) && (value.verified ? value.recordId !== null && value.jarSha256 !== null : true);
}

function javaRecord(value: unknown): value is JavaRecord {
  return record(value) && keys(value, ["recordId", "jarPath", "entry", "state", "beforeJarSha256", "appliedJarSha256", "classSha256", "createdAt", "updatedAt"]) &&
    isJavaHandle(value.recordId) && jarPath(value.jarPath) && isJavaClassEntry(value.entry) &&
    (value.state === "applied" || value.state === "restored") && sha(value.beforeJarSha256) && sha(value.appliedJarSha256) &&
    sha(value.classSha256) && text(value.createdAt, 64) && text(value.updatedAt, 64);
}

export function isJavaHotUpdateResponse(value: unknown): value is JavaHotUpdateResponse {
  if (!record(value)) return false;
  switch (value.kind) {
    case "scan": return scan(value);
    case "jar": return jar(value);
    case "plan": return plan(value);
    case "receipt": return receipt(value);
    case "history": return keys(value, ["kind", "records", "truncated"]) && Array.isArray(value.records) &&
      value.records.length <= 64 && value.records.every(javaRecord) && typeof value.truncated === "boolean";
    case "cancelled": return keys(value, ["kind", "cancelled"]) && typeof value.cancelled === "boolean";
    default: return false;
  }
}

/** The answer must be the kind the request asks for, about the thing it named. */
export function matchesJavaHotUpdateResponse(request: JavaHotUpdateRequest, value: unknown): value is JavaHotUpdateResponse {
  if (!isJavaHotUpdateResponse(value)) return false;
  switch (request.action) {
    case "scan": return value.kind === "scan";
    case "inspect": return value.kind === "jar" && value.jarHandle === request.jarHandle;
    case "inspect-path": return value.kind === "jar" && value.path === request.path;
    case "plan": return value.kind === "plan" && value.operation === "update" && !value.confirmed && value.entry === request.entry;
    case "plan-restore": return value.kind === "plan" && value.operation === "restore" && !value.confirmed;
    case "confirm": return value.kind === "plan" && value.confirmed && value.planHandle === request.planHandle;
    case "execute": return value.kind === "receipt" && value.planHandle === request.planHandle;
    case "history": return value.kind === "history";
    case "cancel":
    case "discard-staged": return value.kind === "cancelled";
  }
}

export function isJavaClassStageResult(value: unknown): value is JavaClassStageResult {
  if (!record(value) || !keys(value, ["staged", "class"])) return false;
  if (value.staged === false) return value.class === null;
  const staged = value.class;
  return value.staged === true && record(staged) && keys(staged, ["stagedHandle", "name", "sizeBytes", "sha256"]) &&
    isJavaHandle(staged.stagedHandle) && text(staged.name, 1_024) && staged.name.toLowerCase().endsWith(".class") &&
    !staged.name.includes("/") && !staged.name.includes("\\") && integer(staged.sizeBytes, 1, 16 * 1_024 * 1_024) && sha(staged.sha256);
}
