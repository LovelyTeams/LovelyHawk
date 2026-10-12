export const KUBERNETES_READ_TABS = [
  "namespaces",
  "pods",
  "deployments",
  "nodes",
] as const;

export type KubernetesReadTab = (typeof KUBERNETES_READ_TABS)[number];
/** `pod-previous-logs`: what the container printed in its previous run, before it was restarted. */
export type KubernetesContentKind = "detail" | "pod-logs" | "pod-previous-logs";
export const KUBERNETES_REDACTED_TEXT = "[SENSITIVE KUBERNETES TEXT REDACTED]" as const;

export interface KubernetesAvailability {
  kubectlInstalled: boolean;
  apiReachable: boolean;
  currentContext: string;
  contextTruncated: boolean;
  /**
   * The namespace kubectl falls back to: the current context's, or
   * `default` when the context names none. null without a context.
   */
  contextNamespace: string | null;
}

export interface KubernetesNamespaceCapability {
  snapshotHandle: string;
  rowHandle: string;
}

/**
 * The namespace the kubeconfig's current context names — for an account
 * that may not list namespaces. The page never sends a namespace name.
 */
export interface KubernetesContextNamespaceScope {
  context: true;
}

export type KubernetesNamespaceScope =
  | KubernetesNamespaceCapability
  | KubernetesContextNamespaceScope;

export interface KubernetesListInput {
  tab: KubernetesReadTab;
  namespaceScope: KubernetesNamespaceScope | null;
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
  /** The pod's app containers, to choose one for logs, a shell or files. */
  containers: KubernetesPodContainer[];
  /** The one used when none is chosen: one of `containers`, or null. */
  defaultContainer: string | null;
}

export interface KubernetesPodContainer {
  /** A DNS label, as Kubernetes requires. */
  name: string;
  image: string;
  ready: boolean;
  running: boolean;
  restarts: number;
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
    previous: boolean,
    /** One of the pod's containers; null for its default one. */
    container: string | null,
  ): Promise<unknown>;
}

type JsonRecord = Record<string, unknown>;
const encoder = new TextEncoder();

/** A Kubernetes container name: a DNS label. */
export function isKubernetesContainerName(value: unknown): value is string {
  return typeof value === "string" && /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/u.test(value);
}

function isPodContainer(value: unknown): value is KubernetesPodContainer {
  return record(value) && exact(value, ["name", "image", "ready", "running", "restarts"]) &&
    isKubernetesContainerName(value.name) && publicText(value.image, 4 * 1_024) &&
    typeof value.ready === "boolean" && typeof value.running === "boolean" && unsigned(value.restarts);
}

function podContainers(value: JsonRecord): boolean {
  const { containers, defaultContainer } = value;
  if (!Array.isArray(containers) || containers.length > 16 || !containers.every(isPodContainer)) return false;
  const names = containers.map((container: KubernetesPodContainer) => container.name);
  // Names are unique within a pod, and the default is one of them.
  return new Set(names).size === names.length &&
    (defaultContainer === null || typeof defaultContainer === "string" && names.includes(defaultContainer));
}

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

export function isKubernetesContextNamespaceScope(
  value: unknown,
): value is KubernetesContextNamespaceScope {
  return record(value) && exact(value, ["context"]) && value.context === true;
}

/** A Kubernetes namespace name: a lowercase DNS-1123 label of at most 63 bytes. */
export function isKubernetesNamespaceName(value: unknown): value is string {
  return typeof value === "string" && value.length <= 63 &&
    /^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$/u.test(value);
}

export function isKubernetesListInput(value: unknown): value is KubernetesListInput {
  if (!record(value) || !exact(value, ["tab", "namespaceScope"]) ||
    !isKubernetesReadTab(value.tab) ||
    !(value.namespaceScope === null || isKubernetesNamespaceCapability(value.namespaceScope) ||
      isKubernetesContextNamespaceScope(value.namespaceScope))) {
    return false;
  }
  return value.tab === "pods" || value.tab === "deployments"
    ? true
    : value.namespaceScope === null;
}

export function isKubernetesAvailability(value: unknown): value is KubernetesAvailability {
  return record(value) && exact(value, [
    "kubectlInstalled", "apiReachable", "currentContext", "contextTruncated", "contextNamespace",
  ]) && typeof value.kubectlInstalled === "boolean" &&
    (value.contextNamespace === null || isKubernetesNamespaceName(value.contextNamespace)) &&
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
      "supportsLogs", "containers", "defaultContainer", "textTruncated",
    ]) && podContainers(value) && publicText(value.namespace, 4 * 1_024) && publicText(value.name, 4 * 1_024) &&
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
    (value.contentKind !== "detail" && value.contentKind !== "pod-logs" && value.contentKind !== "pod-previous-logs") ||
    typeof value.truncated !== "boolean") return false;
  return publicMultiline(
    value.text,
    value.contentKind === "detail" ? 256 * 1_024 : 512 * 1_024,
  ) && (!value.text.includes(KUBERNETES_REDACTED_TEXT) || value.truncated);
}

/**
 * A listed object's manifest written to a file the operator chose. The
 * contents went from the backend to the file; the page only learns whether
 * it was saved and under what name.
 */
export interface KubernetesManifestExportResult {
  saved: boolean;
  fileName: string | null;
}

/** Saving a listed Pod, Deployment or Node's manifest; the object is the list's handles. */
export interface KubernetesManifestExportApi {
  exportKubernetesManifest(bindingHandle: string, snapshotHandle: string, rowHandle: string): Promise<unknown>;
}

export function isKubernetesManifestExportResult(value: unknown): value is KubernetesManifestExportResult {
  if (!record(value) || !exact(value, ["saved", "fileName"]) || typeof value.saved !== "boolean") return false;
  if (!value.saved) return value.fileName === null;
  return text(value.fileName, 240, false) && value.fileName !== "." && value.fileName !== ".." &&
    !/[\u0000-\u001f<>:"/\\|?*]/u.test(value.fileName) && !/[. ]$/u.test(value.fileName) &&
    /\.ya?ml$/iu.test(value.fileName);
}
