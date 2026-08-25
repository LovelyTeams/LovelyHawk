export const KUBERNETES_READ_TABS = [
  "namespaces",
  "pods",
  "deployments",
  "nodes",
] as const;

export type KubernetesReadTab = (typeof KUBERNETES_READ_TABS)[number];
export type KubernetesContentKind = "detail" | "pod-logs";
export const KUBERNETES_REDACTED_TEXT = "[SENSITIVE KUBERNETES TEXT REDACTED]" as const;

export interface KubernetesAvailability {
  kubectlInstalled: boolean;
  apiReachable: boolean;
  currentContext: string;
  contextTruncated: boolean;
}

export interface KubernetesNamespaceCapability {
  snapshotHandle: string;
  rowHandle: string;
}

export interface KubernetesListInput {
  tab: KubernetesReadTab;
  namespaceScope: KubernetesNamespaceCapability | null;
}

interface KubernetesRowBase {
  rowHandle: string;
  textTruncated: boolean;
}

export interface KubernetesNamespaceRow extends KubernetesRowBase {
  kind: "namespace";
  name: string;
  phase: string;
  createdAt: string;
}

export interface KubernetesPodRow extends KubernetesRowBase {
  kind: "pod";
  namespace: string;
  name: string;
  phase: string;
  readyContainers: number;
  totalContainers: number;
  restarts: number;
  node: string;
  podIp: string;
  images: string[];
  createdAt: string;
  supportsLogs: true;
}

export interface KubernetesDeploymentRow extends KubernetesRowBase {
  kind: "deployment";
  namespace: string;
  name: string;
  desiredReplicas: number;
  readyReplicas: number;
  availableReplicas: number;
  updatedReplicas: number;
  images: string[];
  createdAt: string;
}

export interface KubernetesNodeRow extends KubernetesRowBase {
  kind: "node";
  name: string;
  ready: boolean;
  unschedulable: boolean;
  roles: string[];
  kubeletVersion: string;
  internalIp: string;
  cpuCapacity: string;
  memoryCapacity: string;
  podCapacity: string;
  createdAt: string;
}

export type KubernetesReadRow =
  | KubernetesNamespaceRow
  | KubernetesPodRow
  | KubernetesDeploymentRow
  | KubernetesNodeRow;

export interface KubernetesSnapshot {
  snapshotHandle: string;
  tab: KubernetesReadTab;
  namespaceScoped: boolean;
  displayed: number;
  truncated: boolean;
  expiresInSeconds: number;
  rows: KubernetesReadRow[];
}

export interface KubernetesTextResult {
  snapshotHandle: string;
  rowHandle: string;
  contentKind: KubernetesContentKind;
  text: string;
  truncated: boolean;
}

export interface KubernetesReadApi {
  getKubernetesAvailability(bindingHandle: string): Promise<unknown>;
  listKubernetesResources(bindingHandle: string, input: KubernetesListInput): Promise<unknown>;
  getKubernetesResourceDetail(
    bindingHandle: string,
    snapshotHandle: string,
    rowHandle: string,
  ): Promise<unknown>;
  getKubernetesPodLogs(
    bindingHandle: string,
    snapshotHandle: string,
    rowHandle: string,
  ): Promise<unknown>;
}

type JsonRecord = Record<string, unknown>;
const encoder = new TextEncoder();

function record(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exact(value: JsonRecord, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && actual.every((key) => keys.includes(key));
}

function text(value: unknown, maximumBytes: number, allowEmpty = true): value is string {
  return typeof value === "string" && (allowEmpty || value.length > 0) &&
    encoder.encode(value).byteLength <= maximumBytes &&
    !/[\u0000-\u001f\u007f]/u.test(value);
}

function multiline(value: unknown, maximumBytes: number): value is string {
  return typeof value === "string" && encoder.encode(value).byteLength <= maximumBytes &&
    !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value);
}

/**
 * Bounded, control-character-free text. It does not judge the content: a
 * collected line that mentions a credential is the evidence, and refusing it
 * here would reject the whole response rather than one line.
 */
function publicText(value: unknown, maximumBytes: number, allowEmpty = true): value is string {
  return text(value, maximumBytes, allowEmpty) &&
    (value === KUBERNETES_REDACTED_TEXT ||
      !value.includes(KUBERNETES_REDACTED_TEXT));
}

function publicMultiline(value: unknown, maximumBytes: number): value is string {
  return multiline(value, maximumBytes) && value.split("\n").every((line) =>
    line === KUBERNETES_REDACTED_TEXT ||
    !line.includes(KUBERNETES_REDACTED_TEXT));
}

function unsigned(value: unknown, maximum = Number.MAX_SAFE_INTEGER): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= maximum;
}

export function isKubernetesReadTab(value: unknown): value is KubernetesReadTab {
  return typeof value === "string" &&
    KUBERNETES_READ_TABS.some((candidate) => candidate === value);
}

export function isKubernetesOpaqueHandle(value: unknown): value is string {
  return text(value, 128, false) && /^[A-Za-z0-9-]+$/u.test(value);
}

export function isKubernetesNamespaceCapability(
  value: unknown,
): value is KubernetesNamespaceCapability {
  return record(value) && exact(value, ["snapshotHandle", "rowHandle"]) &&
    isKubernetesOpaqueHandle(value.snapshotHandle) &&
    isKubernetesOpaqueHandle(value.rowHandle);
}

export function isKubernetesListInput(value: unknown): value is KubernetesListInput {
  if (!record(value) || !exact(value, ["tab", "namespaceScope"]) ||
    !isKubernetesReadTab(value.tab) ||
    !(value.namespaceScope === null || isKubernetesNamespaceCapability(value.namespaceScope))) {
    return false;
  }
  return value.tab === "pods" || value.tab === "deployments"
    ? true
    : value.namespaceScope === null;
}

export function isKubernetesAvailability(value: unknown): value is KubernetesAvailability {
  return record(value) && exact(value, [
    "kubectlInstalled", "apiReachable", "currentContext", "contextTruncated",
  ]) && typeof value.kubectlInstalled === "boolean" &&
    typeof value.apiReachable === "boolean" && publicText(value.currentContext, 1_024) &&
    typeof value.contextTruncated === "boolean" &&
    (value.currentContext !== KUBERNETES_REDACTED_TEXT || value.contextTruncated) &&
    (!value.apiReachable || value.kubectlInstalled);
}

function stringArray(value: unknown, maximumItems: number): value is string[] {
  return Array.isArray(value) && value.length <= maximumItems &&
    value.every((item) => publicText(item, 4 * 1_024));
}

function rowBytes(value: JsonRecord): boolean {
  return jsonBytesAtMost(value, 48 * 1_024);
}

function containsFixedRedactionMarker(value: JsonRecord): boolean {
  return Object.values(value).some((item) => item === KUBERNETES_REDACTED_TEXT ||
    Array.isArray(item) && item.some((entry) => entry === KUBERNETES_REDACTED_TEXT));
}

function jsonBytesAtMost(value: unknown, maximumBytes: number): boolean {
  try {
    return encoder.encode(JSON.stringify(value)).byteLength <= maximumBytes;
  } catch {
    return false;
  }
}

export function isKubernetesReadRow(value: unknown): value is KubernetesReadRow {
  if (!record(value) || !isKubernetesOpaqueHandle(value.rowHandle) ||
    typeof value.textTruncated !== "boolean") return false;
  if (!value.textTruncated && containsFixedRedactionMarker(value)) return false;
  if (value.kind === "namespace") {
    return exact(value, ["kind", "rowHandle", "name", "phase", "createdAt", "textTruncated"]) &&
      publicText(value.name, 4 * 1_024) && publicText(value.phase, 4 * 1_024) &&
      publicText(value.createdAt, 4 * 1_024) && rowBytes(value);
  }
  if (value.kind === "pod") {
    return exact(value, [
      "kind", "rowHandle", "namespace", "name", "phase", "readyContainers",
      "totalContainers", "restarts", "node", "podIp", "images", "createdAt",
      "supportsLogs", "textTruncated",
    ]) && publicText(value.namespace, 4 * 1_024) && publicText(value.name, 4 * 1_024) &&
      publicText(value.phase, 4 * 1_024) && unsigned(value.readyContainers) &&
      unsigned(value.totalContainers) && value.readyContainers <= value.totalContainers &&
      unsigned(value.restarts) && publicText(value.node, 4 * 1_024) &&
      publicText(value.podIp, 4 * 1_024) && stringArray(value.images, 16) &&
      publicText(value.createdAt, 4 * 1_024) && value.supportsLogs === true && rowBytes(value);
  }
  if (value.kind === "deployment") {
    return exact(value, [
      "kind", "rowHandle", "namespace", "name", "desiredReplicas", "readyReplicas",
      "availableReplicas", "updatedReplicas", "images", "createdAt", "textTruncated",
    ]) && publicText(value.namespace, 4 * 1_024) && publicText(value.name, 4 * 1_024) &&
      unsigned(value.desiredReplicas) && unsigned(value.readyReplicas) &&
      unsigned(value.availableReplicas) && unsigned(value.updatedReplicas) &&
      stringArray(value.images, 16) && publicText(value.createdAt, 4 * 1_024) && rowBytes(value);
  }
  if (value.kind === "node") {
    return exact(value, [
      "kind", "rowHandle", "name", "ready", "unschedulable", "roles",
      "kubeletVersion", "internalIp", "cpuCapacity", "memoryCapacity", "podCapacity",
      "createdAt", "textTruncated",
    ]) && publicText(value.name, 4 * 1_024) && typeof value.ready === "boolean" &&
      typeof value.unschedulable === "boolean" && stringArray(value.roles, 16) &&
      publicText(value.kubeletVersion, 4 * 1_024) && publicText(value.internalIp, 4 * 1_024) &&
      publicText(value.cpuCapacity, 4 * 1_024) && publicText(value.memoryCapacity, 4 * 1_024) &&
      publicText(value.podCapacity, 4 * 1_024) && publicText(value.createdAt, 4 * 1_024) && rowBytes(value);
  }
  return false;
}

function expectedKind(tab: KubernetesReadTab): KubernetesReadRow["kind"] {
  switch (tab) {
    case "namespaces": return "namespace";
    case "pods": return "pod";
    case "deployments": return "deployment";
    case "nodes": return "node";
  }
}

export function isKubernetesSnapshot(value: unknown): value is KubernetesSnapshot {
  if (!record(value) || !exact(value, [
    "snapshotHandle", "tab", "namespaceScoped", "displayed", "truncated",
    "expiresInSeconds", "rows",
  ]) || !isKubernetesOpaqueHandle(value.snapshotHandle) || !isKubernetesReadTab(value.tab) ||
    typeof value.namespaceScoped !== "boolean" || !unsigned(value.displayed, 500) ||
    typeof value.truncated !== "boolean" || !unsigned(value.expiresInSeconds, 300) ||
    value.expiresInSeconds === 0 || !Array.isArray(value.rows) ||
    value.rows.length !== value.displayed || !value.rows.every(isKubernetesReadRow)) return false;
  if ((value.tab === "namespaces" || value.tab === "nodes") && value.namespaceScoped) return false;
  const kind = expectedKind(value.tab);
  const handles = value.rows.map((row) => row.rowHandle);
  return value.rows.every((row) => row.kind === kind) &&
    new Set(handles).size === handles.length &&
    jsonBytesAtMost(value, 2 * 1_024 * 1_024);
}

export function isKubernetesTextResult(value: unknown): value is KubernetesTextResult {
  if (!record(value) || !exact(value, [
    "snapshotHandle", "rowHandle", "contentKind", "text", "truncated",
  ]) || !isKubernetesOpaqueHandle(value.snapshotHandle) ||
    !isKubernetesOpaqueHandle(value.rowHandle) ||
    (value.contentKind !== "detail" && value.contentKind !== "pod-logs") ||
    typeof value.truncated !== "boolean") return false;
  return publicMultiline(
    value.text,
    value.contentKind === "detail" ? 256 * 1_024 : 512 * 1_024,
  ) && (!value.text.includes(KUBERNETES_REDACTED_TEXT) || value.truncated);
}
