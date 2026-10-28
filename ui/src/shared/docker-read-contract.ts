export type DockerCollectionKind =
  | "stats"
  | "images"
  | "networks"
  | "volumes"
  | "compose-projects";
export type DockerResourceKind = "container" | "image" | "network" | "volume";
export type DockerSecuritySeverity = "critical" | "high" | "medium" | "low" | "info";
export type DockerSecurityCategory =
  | "privileged"
  | "capabilities"
  | "network"
  | "mount"
  | "image"
  | "resource-limits"
  | "health";

export const DOCKER_REDACTED_TEXT = "[SENSITIVE DOCKER TEXT REDACTED]" as const;

export interface DockerContainerItem {
  containerHandle: string;
  /**
   * The runtime's own twelve-character short id, for display only.
   *
   * Shown beside the name so what the pane says matches what an operator sees
   * in `docker ps` on the machine. Every call still addresses a container by
   * `containerHandle`; nothing resolves through this.
   */
  shortId: string;
  name: string;
  image: string;
  state: string;
  status: string;
  ports: string;
  createdAt: string;
}

/** The two runtimes the sidecar knows how to ask. */
export const CONTAINER_RUNTIMES = ["docker", "podman"] as const;
export type ContainerRuntime = (typeof CONTAINER_RUNTIMES)[number];

export interface DockerContainerSnapshot {
  snapshotHandle: string;
  expiresInSeconds: number;
  containers: DockerContainerItem[];
  truncated: boolean;
  /**
   * Which runtime this snapshot was actually taken from.
   *
   * Assuming Docker was wrong on every openEuler, Anolis or RHEL-family host,
   * where Podman is the default and `docker` often does not exist at all. The
   * pane says what it is looking at rather than what it hoped for.
   */
  runtime: ContainerRuntime;
  /** Every runtime whose binary the host has, answering or not. */
  installedRuntimes: ContainerRuntime[];
}

export interface DockerStatsItem {
  containerHandle: string;
  name: string;
  cpuPercent: string;
  memoryUsage: string;
  memoryPercent: string;
  networkIo: string;
  blockIo: string;
  pids: number | null;
}

export interface DockerImageItem {
  imageHandle: string;
  /** The 12 characters the runtime prints. Display only — nothing is looked
   * up by it, because a short id is not unique by construction. */
  shortId: string;
  repository: string;
  tag: string;
  digest: string;
  createdAt: string;
  size: string;
}

export interface DockerNetworkItem {
  networkHandle: string;
  name: string;
  driver: string;
  scope: string;
  internal: boolean;
  ipv6: boolean;
}

export interface DockerVolumeItem {
  volumeHandle: string;
  name: string;
  driver: string;
  mountpoint: string;
  scope: string;
  labels: string;
}

export interface DockerComposeProjectItem {
  name: string;
  status: string;
  configFiles: string;
  services: number;
  running: number;
  stopped: number;
}

interface DockerCollectionBase {
  snapshotHandle: string;
  truncated: boolean;
}

export interface DockerStatsCollection extends DockerCollectionBase {
  kind: "stats";
  items: DockerStatsItem[];
}

export interface DockerImagesCollection extends DockerCollectionBase {
  kind: "images";
  items: DockerImageItem[];
}

export interface DockerNetworksCollection extends DockerCollectionBase {
  kind: "networks";
  items: DockerNetworkItem[];
}

export interface DockerVolumesCollection extends DockerCollectionBase {
  kind: "volumes";
  items: DockerVolumeItem[];
}

export interface DockerComposeCollection extends DockerCollectionBase {
  kind: "compose-projects";
  items: DockerComposeProjectItem[];
}

export type DockerReadCollection =
  | DockerStatsCollection
  | DockerImagesCollection
  | DockerNetworksCollection
  | DockerVolumesCollection
  | DockerComposeCollection;

export interface DockerField {
  label: string;
  value: string;
}

export interface DockerMount {
  kind: string;
  source: string;
  destination: string;
  mode: string;
  readWrite: boolean;
}

export interface DockerContainerNetwork {
  name: string;
  macAddress: string;
  ipv4Address: string;
  ipv6Address: string;
}

export interface DockerContainerInspection {
  kind: "container";
  snapshotHandle: string;
  resourceHandle: string;
  name: string;
  fields: DockerField[];
  mounts: DockerMount[];
  networks: DockerContainerNetwork[];
  truncated: boolean;
}

export interface DockerIpam {
  subnet: string;
  gateway: string;
  ipRange: string;
}

export interface DockerAttachment {
  name: string;
  macAddress: string;
  ipv4Address: string;
  ipv6Address: string;
}

export interface DockerMetadata {
  key: string;
  value: string;
}

export interface DockerNetworkInspection {
  kind: "network";
  snapshotHandle: string;
  resourceHandle: string;
  name: string;
  driver: string;
  scope: string;
  internal: boolean;
  ipv6: boolean;
  attachable: boolean;
  ingress: boolean;
  ipamDriver: string;
  ipam: DockerIpam[];
  attachments: DockerAttachment[];
  options: DockerMetadata[];
  labels: DockerMetadata[];
  truncated: boolean;
}

export interface DockerVolumeInspection {
  kind: "volume";
  snapshotHandle: string;
  resourceHandle: string;
  name: string;
  driver: string;
  mountpoint: string;
  scope: string;
  createdAt: string;
  options: DockerMetadata[];
  labels: DockerMetadata[];
  truncated: boolean;
}

/** One step of the image's build history — the instruction that made a layer. */
export interface DockerImageHistoryStep {
  createdAt: string;
  createdBy: string;
  size: string;
  comment: string;
}

export interface DockerImageInspection {
  kind: "image";
  snapshotHandle: string;
  resourceHandle: string;
  shortId: string;
  repository: string;
  tag: string;
  digest: string;
  size: string;
  createdAt: string;
  architecture: string;
  os: string;
  author: string;
  /** Already a sentence: an image that set no user runs as root, and this
   * says so rather than arriving empty. */
  user: string;
  entrypoint: string[];
  command: string[];
  workingDir: string;
  environment: string[];
  exposedPorts: string[];
  declaredVolumes: string[];
  labels: DockerMetadata[];
  layers: string[];
  repoTags: string[];
  repoDigests: string[];
  history: DockerImageHistoryStep[];
  truncated: boolean;
}

export type DockerReadInspection =
  | DockerContainerInspection
  | DockerImageInspection
  | DockerNetworkInspection
  | DockerVolumeInspection;

export interface DockerSecurityFinding {
  severity: DockerSecuritySeverity;
  severityLabel: string;
  category: DockerSecurityCategory;
  categoryLabel: string;
  containerName: string;
  description: string;
  recommendation: string;
  textTruncated: boolean;
}

export interface DockerSecuritySummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
  score: number;
}

export interface DockerSecurityAudit {
  snapshotHandle: string;
  containersScanned: number;
  findings: DockerSecurityFinding[];
  summary: DockerSecuritySummary;
  truncated: boolean;
}

export interface DockerLogs {
  snapshotHandle: string;
  containerHandle: string;
  tail: number;
  text: string;
  truncated: boolean;
}

export interface DockerReadApi {
  refreshDockerContainers(bindingHandle: string): Promise<unknown>;
  getDockerCollection(
    bindingHandle: string,
    snapshotHandle: string,
    kind: DockerCollectionKind,
  ): Promise<unknown>;
  inspectDockerResource(
    bindingHandle: string,
    snapshotHandle: string,
    kind: DockerResourceKind,
    resourceHandle: string,
  ): Promise<unknown>;
  getDockerSecurityAudit(bindingHandle: string, snapshotHandle: string): Promise<unknown>;
  getDockerLogs(
    bindingHandle: string,
    snapshotHandle: string,
    containerHandle: string,
    tail: number,
  ): Promise<unknown>;
}

type JsonRecord = Record<string, unknown>;
const encoder = new TextEncoder();
const collectionKinds = new Set<DockerCollectionKind>([
  "stats", "images", "networks", "volumes", "compose-projects",
]);
const resourceKinds = new Set<DockerResourceKind>(["container", "image", "network", "volume"]);
const securitySeverities = new Set<DockerSecuritySeverity>([
  "critical", "high", "medium", "low", "info",
]);
const securityCategories = new Set<DockerSecurityCategory>([
  "privileged", "capabilities", "network", "mount", "image", "resource-limits", "health",
]);

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
    !/[\u0000-\u001f\u007f]/u.test(value) &&
    (value === DOCKER_REDACTED_TEXT ||
      !value.includes(DOCKER_REDACTED_TEXT));
}

function multilineText(value: unknown, maximumBytes: number): value is string {
  return typeof value === "string" && encoder.encode(value).byteLength <= maximumBytes &&
    !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value) &&
    value.split("\n").every((line) => line === DOCKER_REDACTED_TEXT ||
      !line.includes(DOCKER_REDACTED_TEXT));
}

function containsFixedRedactionMarker(value: unknown, seen = new Set<object>()): boolean {
  if (typeof value === "string") return value.includes(DOCKER_REDACTED_TEXT);
  if (typeof value !== "object" || value === null || seen.has(value)) return false;
  seen.add(value);
  return (Array.isArray(value) ? value : Object.values(value))
    .some((item) => containsFixedRedactionMarker(item, seen));
}

function markerRequiresProjectionFlag(value: unknown, projected: boolean): boolean {
  return projected || !containsFixedRedactionMarker(value);
}

function unsigned(value: unknown, maximum: number): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= maximum;
}

function optionalUnsigned(value: unknown, maximum: number): value is number | null {
  return value === null || unsigned(value, maximum);
}

function uniqueHandles<T>(items: T[], select: (item: T) => unknown): boolean {
  const handles = items.map(select);
  return handles.every(isDockerOpaqueHandle) && new Set(handles).size === handles.length;
}

function withinTextBudget(values: Iterable<string>, maximumBytes: number): boolean {
  let total = 0;
  for (const value of values) {
    total += encoder.encode(value).byteLength;
    if (total > maximumBytes) return false;
  }
  return true;
}

export function isDockerOpaqueHandle(value: unknown): value is string {
  return text(value, 128, false) && /^[A-Za-z0-9-]+$/u.test(value);
}

export function isDockerCollectionKind(value: unknown): value is DockerCollectionKind {
  return typeof value === "string" && collectionKinds.has(value as DockerCollectionKind);
}

export function isDockerResourceKind(value: unknown): value is DockerResourceKind {
  return typeof value === "string" && resourceKinds.has(value as DockerResourceKind);
}

export function isDockerLogTail(value: unknown): value is number {
  return unsigned(value, 1_000) && value > 0;
}

function container(value: unknown): value is DockerContainerItem {
  return record(value) && exact(value, [
    "containerHandle", "shortId", "name", "image", "state", "status", "ports", "createdAt",
  ]) && isDockerOpaqueHandle(value.containerHandle) && isDockerShortId(value.shortId) &&
    text(value.name, 512) &&
    text(value.image, 2_048) && text(value.state, 128) && text(value.status, 1_024) &&
    text(value.ports, 4_096) && text(value.createdAt, 1_024);
}

/**
 * A short id and nothing longer.
 *
 * Bounded at twelve hexadecimal characters on purpose: it is the display form,
 * and a field that would accept a full-length id is a field someone could
 * later be tempted to address a container with.
 */
export function isDockerShortId(value: unknown): value is string {
  return typeof value === "string" &&
    value.length > 0 && value.length <= 12 &&
    /^[0-9a-f]+$/u.test(value);
}

export function isContainerRuntime(value: unknown): value is ContainerRuntime {
  return typeof value === "string" &&
    (CONTAINER_RUNTIMES as readonly string[]).includes(value);
}

export function isDockerContainerSnapshot(value: unknown): value is DockerContainerSnapshot {
  if (!record(value) || !exact(value, [
    "snapshotHandle", "expiresInSeconds", "containers", "truncated",
    "runtime", "installedRuntimes",
  ]) || !isDockerOpaqueHandle(value.snapshotHandle) ||
    !unsigned(value.expiresInSeconds, 300) || value.expiresInSeconds === 0 ||
    !Array.isArray(value.containers) || value.containers.length > 500 ||
    typeof value.truncated !== "boolean" ||
    !isContainerRuntime(value.runtime) ||
    !Array.isArray(value.installedRuntimes) ||
    value.installedRuntimes.length > CONTAINER_RUNTIMES.length ||
    !value.installedRuntimes.every(isContainerRuntime) ||
    // The runtime that answered has to be one the host was found to have.
    !value.installedRuntimes.includes(value.runtime)) return false;
  return value.containers.every(container) &&
    uniqueHandles(value.containers as DockerContainerItem[], (item) => item.containerHandle) &&
    withinTextBudget((value.containers as DockerContainerItem[]).flatMap((item) => [
      item.name, item.image, item.state, item.status, item.ports, item.createdAt,
    ]), 1_024 * 1_024) && markerRequiresProjectionFlag(value.containers, value.truncated);
}

function stats(value: unknown): value is DockerStatsItem {
  return record(value) && exact(value, [
    "containerHandle", "name", "cpuPercent", "memoryUsage", "memoryPercent",
    "networkIo", "blockIo", "pids",
  ]) && isDockerOpaqueHandle(value.containerHandle) && text(value.name, 512) &&
    text(value.cpuPercent, 128) && text(value.memoryUsage, 256) &&
    text(value.memoryPercent, 128) && text(value.networkIo, 256) &&
    text(value.blockIo, 256) && optionalUnsigned(value.pids, Number.MAX_SAFE_INTEGER);
}

function image(value: unknown): value is DockerImageItem {
  return record(value) && exact(value, [
    "imageHandle", "shortId", "repository", "tag", "digest", "createdAt", "size",
  ]) && isDockerOpaqueHandle(value.imageHandle) && isDockerShortId(value.shortId) &&
    text(value.repository, 2_048) && text(value.tag, 1_024) && text(value.digest, 512) &&
    text(value.createdAt, 1_024) && text(value.size, 256);
}

function network(value: unknown): value is DockerNetworkItem {
  return record(value) && exact(value, [
    "networkHandle", "name", "driver", "scope", "internal", "ipv6",
  ]) && isDockerOpaqueHandle(value.networkHandle) && text(value.name, 512) &&
    text(value.driver, 256) && text(value.scope, 256) &&
    typeof value.internal === "boolean" && typeof value.ipv6 === "boolean";
}

function volume(value: unknown): value is DockerVolumeItem {
  return record(value) && exact(value, [
    "volumeHandle", "name", "driver", "mountpoint", "scope", "labels",
  ]) && isDockerOpaqueHandle(value.volumeHandle) && text(value.name, 512) &&
    text(value.driver, 256) && text(value.mountpoint, 4_096) && text(value.scope, 256) &&
    text(value.labels, 4_096);
}

function composeProject(value: unknown): value is DockerComposeProjectItem {
  if (!record(value) || !exact(value, [
    "name", "status", "configFiles", "services", "running", "stopped",
  ]) || !text(value.name, 512) || !text(value.status, 512) || !text(value.configFiles, 4_096) ||
    !unsigned(value.services, Number.MAX_SAFE_INTEGER) ||
    !unsigned(value.running, Number.MAX_SAFE_INTEGER) ||
    !unsigned(value.stopped, Number.MAX_SAFE_INTEGER)) return false;
  return value.running <= value.services && value.stopped <= value.services;
}

export function isDockerReadCollection(value: unknown): value is DockerReadCollection {
  if (!record(value) || !exact(value, ["kind", "snapshotHandle", "items", "truncated"]) ||
    !isDockerCollectionKind(value.kind) || !isDockerOpaqueHandle(value.snapshotHandle) ||
    !Array.isArray(value.items) || typeof value.truncated !== "boolean") return false;
  switch (value.kind) {
    case "stats":
      return value.items.length <= 500 && value.items.every(stats) &&
        uniqueHandles(value.items as DockerStatsItem[], (item) => item.containerHandle) &&
        collectionTextWithinBudget(value.items as DockerStatsItem[], "stats") &&
        markerRequiresProjectionFlag(value.items, value.truncated);
    case "images":
      return value.items.length <= 500 && value.items.every(image) &&
        uniqueHandles(value.items as DockerImageItem[], (item) => item.imageHandle) &&
        collectionTextWithinBudget(value.items as DockerImageItem[], "images") &&
        markerRequiresProjectionFlag(value.items, value.truncated);
    case "networks":
      return value.items.length <= 256 && value.items.every(network) &&
        uniqueHandles(value.items as DockerNetworkItem[], (item) => item.networkHandle) &&
        collectionTextWithinBudget(value.items as DockerNetworkItem[], "networks") &&
        markerRequiresProjectionFlag(value.items, value.truncated);
    case "volumes":
      return value.items.length <= 256 && value.items.every(volume) &&
        uniqueHandles(value.items as DockerVolumeItem[], (item) => item.volumeHandle) &&
        collectionTextWithinBudget(value.items as DockerVolumeItem[], "volumes") &&
        markerRequiresProjectionFlag(value.items, value.truncated);
    case "compose-projects":
      return value.items.length <= 256 && value.items.every(composeProject) &&
        collectionTextWithinBudget(value.items as DockerComposeProjectItem[], "compose-projects") &&
        markerRequiresProjectionFlag(value.items, value.truncated);
  }
}

function collectionTextWithinBudget(
  items: DockerReadCollection["items"],
  kind: DockerCollectionKind,
): boolean {
  const values: string[] = [];
  switch (kind) {
    case "stats":
      for (const item of items as DockerStatsItem[]) values.push(
        item.name, item.cpuPercent, item.memoryUsage, item.memoryPercent, item.networkIo, item.blockIo,
      );
      break;
    case "images":
      for (const item of items as DockerImageItem[]) values.push(
        item.repository, item.tag, item.digest, item.createdAt, item.size,
      );
      break;
    case "networks":
      for (const item of items as DockerNetworkItem[]) values.push(item.name, item.driver, item.scope);
      break;
    case "volumes":
      for (const item of items as DockerVolumeItem[]) values.push(
        item.name, item.driver, item.mountpoint, item.scope, item.labels,
      );
      break;
    case "compose-projects":
      for (const item of items as DockerComposeProjectItem[]) values.push(item.name, item.status, item.configFiles);
      break;
  }
  return withinTextBudget(values, 1_024 * 1_024);
}

function field(value: unknown): value is DockerField {
  return record(value) && exact(value, ["label", "value"]) &&
    text(value.label, 256) && text(value.value, 4_096);
}

function mount(value: unknown): value is DockerMount {
  return record(value) && exact(value, ["kind", "source", "destination", "mode", "readWrite"]) &&
    text(value.kind, 128) && text(value.source, 4_096) && text(value.destination, 4_096) &&
    text(value.mode, 512) && typeof value.readWrite === "boolean";
}

function containerNetwork(value: unknown): value is DockerContainerNetwork {
  return record(value) && exact(value, ["name", "macAddress", "ipv4Address", "ipv6Address"]) &&
    text(value.name, 512) && text(value.macAddress, 256) && text(value.ipv4Address, 256) &&
    text(value.ipv6Address, 256);
}

function ipam(value: unknown): value is DockerIpam {
  return record(value) && exact(value, ["subnet", "gateway", "ipRange"]) &&
    text(value.subnet, 512) && text(value.gateway, 512) && text(value.ipRange, 512);
}

function attachment(value: unknown): value is DockerAttachment {
  return record(value) && exact(value, ["name", "macAddress", "ipv4Address", "ipv6Address"]) &&
    text(value.name, 512) && text(value.macAddress, 256) && text(value.ipv4Address, 512) &&
    text(value.ipv6Address, 512);
}

function metadata(value: unknown): value is DockerMetadata {
  return record(value) && exact(value, ["key", "value"]) &&
    text(value.key, 512) && text(value.value, 2_048);
}

function inspectionBase(value: JsonRecord, kind: DockerResourceKind): boolean {
  return value.kind === kind && isDockerOpaqueHandle(value.snapshotHandle) &&
    isDockerOpaqueHandle(value.resourceHandle) && typeof value.truncated === "boolean";
}

export function isDockerReadInspection(value: unknown): value is DockerReadInspection {
  if (
    !record(value) ||
    !isDockerResourceKind(value.kind) ||
    typeof value.truncated !== "boolean"
  ) return false;
  if (value.kind === "container") {
    return exact(value, [
      "kind", "snapshotHandle", "resourceHandle", "name", "fields", "mounts", "networks", "truncated",
    ]) && inspectionBase(value, "container") && text(value.name, 512) &&
      Array.isArray(value.fields) && value.fields.length <= 64 && value.fields.every(field) &&
      Array.isArray(value.mounts) && value.mounts.length <= 128 && value.mounts.every(mount) &&
      Array.isArray(value.networks) && value.networks.length <= 128 && value.networks.every(containerNetwork) &&
      inspectionTextWithinBudget(value as unknown as DockerContainerInspection) &&
      markerRequiresProjectionFlag(value, value.truncated);
  }
  if (value.kind === "image") {
    return exact(value, [
      "kind", "snapshotHandle", "resourceHandle", "shortId", "repository", "tag", "digest",
      "size", "createdAt", "architecture", "os", "author", "user", "entrypoint", "command",
      "workingDir", "environment", "exposedPorts", "declaredVolumes", "labels", "layers",
      "repoTags", "repoDigests", "history", "truncated",
    ]) && inspectionBase(value, "image") && isDockerShortId(value.shortId) &&
      text(value.repository, 2_048) && text(value.tag, 1_024) && text(value.digest, 512) &&
      text(value.size, 256) && text(value.createdAt, 512) && text(value.architecture, 128) &&
      text(value.os, 128) && text(value.author, 512) && text(value.user, 256) &&
      text(value.workingDir, 1_024) &&
      textList(value.entrypoint, 4_096) && textList(value.command, 4_096) &&
      textList(value.environment, 4_096) && textList(value.exposedPorts, 256) &&
      textList(value.declaredVolumes, 4_096) && textList(value.layers, 256) &&
      textList(value.repoTags, 2_048) && textList(value.repoDigests, 512) &&
      Array.isArray(value.labels) && value.labels.length <= 128 && value.labels.every(metadata) &&
      Array.isArray(value.history) && value.history.length <= 128 &&
      value.history.every(historyStep) &&
      inspectionTextWithinBudget(value as unknown as DockerImageInspection) &&
      markerRequiresProjectionFlag(value, value.truncated);
  }
  if (value.kind === "network") {
    return exact(value, [
      "kind", "snapshotHandle", "resourceHandle", "name", "driver", "scope", "internal", "ipv6",
      "attachable", "ingress", "ipamDriver", "ipam", "attachments", "options", "labels", "truncated",
    ]) && inspectionBase(value, "network") && text(value.name, 512) && text(value.driver, 256) &&
      text(value.scope, 256) && typeof value.internal === "boolean" && typeof value.ipv6 === "boolean" &&
      typeof value.attachable === "boolean" && typeof value.ingress === "boolean" &&
      text(value.ipamDriver, 256) && Array.isArray(value.ipam) && value.ipam.length <= 128 &&
      value.ipam.every(ipam) && Array.isArray(value.attachments) && value.attachments.length <= 256 &&
      value.attachments.every(attachment) && Array.isArray(value.options) && value.options.length <= 128 &&
      value.options.every(metadata) && Array.isArray(value.labels) && value.labels.length <= 128 &&
      value.labels.every(metadata) && inspectionTextWithinBudget(value as unknown as DockerNetworkInspection) &&
      markerRequiresProjectionFlag(value, value.truncated);
  }
  return exact(value, [
    "kind", "snapshotHandle", "resourceHandle", "name", "driver", "mountpoint", "scope",
    "createdAt", "options", "labels", "truncated",
  ]) && inspectionBase(value, "volume") && text(value.name, 512) && text(value.driver, 256) &&
    text(value.mountpoint, 4_096) && text(value.scope, 256) && text(value.createdAt, 512) &&
    Array.isArray(value.options) && value.options.length <= 128 && value.options.every(metadata) &&
    Array.isArray(value.labels) && value.labels.length <= 128 && value.labels.every(metadata) &&
    inspectionTextWithinBudget(value as unknown as DockerVolumeInspection) &&
    markerRequiresProjectionFlag(value, value.truncated);
}

/** A bounded array of bounded strings — the shape every image list field has. */
function textList(value: unknown, maximum: number): value is string[] {
  return Array.isArray(value) && value.length <= 128 &&
    value.every((item) => text(item, maximum));
}

function historyStep(value: unknown): value is DockerImageHistoryStep {
  return record(value) && exact(value, ["createdAt", "createdBy", "size", "comment"]) &&
    text(value.createdAt, 512) && text(value.createdBy, 8_192) &&
    text(value.size, 128) && text(value.comment, 1_024);
}

function inspectionTextWithinBudget(inspection: DockerReadInspection): boolean {
  // An image has no single name: it is a repository and a tag, and either can
  // be absent. Every other kind carries one.
  const values: string[] = inspection.kind === "image" ? [] : [inspection.name];
  if (inspection.kind === "image") {
    values.push(
      inspection.repository, inspection.tag, inspection.digest, inspection.size,
      inspection.createdAt, inspection.architecture, inspection.os, inspection.author,
      inspection.user, inspection.workingDir,
      ...inspection.entrypoint, ...inspection.command, ...inspection.environment,
      ...inspection.exposedPorts, ...inspection.declaredVolumes, ...inspection.layers,
      ...inspection.repoTags, ...inspection.repoDigests,
    );
    for (const item of inspection.labels) values.push(item.key, item.value);
    for (const item of inspection.history) values.push(
      item.createdAt, item.createdBy, item.size, item.comment,
    );
  } else if (inspection.kind === "container") {
    for (const item of inspection.fields) values.push(item.label, item.value);
    for (const item of inspection.mounts) values.push(item.kind, item.source, item.destination, item.mode);
    for (const item of inspection.networks) values.push(
      item.name, item.macAddress, item.ipv4Address, item.ipv6Address,
    );
  } else if (inspection.kind === "network") {
    values.push(inspection.driver, inspection.scope, inspection.ipamDriver);
    for (const item of inspection.ipam) values.push(item.subnet, item.gateway, item.ipRange);
    for (const item of inspection.attachments) values.push(
      item.name, item.macAddress, item.ipv4Address, item.ipv6Address,
    );
    for (const item of [...inspection.options, ...inspection.labels]) values.push(item.key, item.value);
  } else {
    values.push(inspection.driver, inspection.mountpoint, inspection.scope, inspection.createdAt);
    for (const item of [...inspection.options, ...inspection.labels]) values.push(item.key, item.value);
  }
  return withinTextBudget(values, 512 * 1_024);
}

function securitySummary(value: unknown): value is DockerSecuritySummary {
  return record(value) && exact(value, ["critical", "high", "medium", "low", "info", "total", "score"]) &&
    unsigned(value.critical, 10_000) && unsigned(value.high, 10_000) &&
    unsigned(value.medium, 10_000) && unsigned(value.low, 10_000) && unsigned(value.info, 10_000) &&
    unsigned(value.total, 10_000) && unsigned(value.score, 100);
}

function securityFinding(value: unknown): value is DockerSecurityFinding {
  return record(value) && exact(value, [
    "severity", "severityLabel", "category", "categoryLabel", "containerName",
    "description", "recommendation", "textTruncated",
  ]) && typeof value.severity === "string" && securitySeverities.has(value.severity as DockerSecuritySeverity) &&
    text(value.severityLabel, 128) && typeof value.category === "string" &&
    securityCategories.has(value.category as DockerSecurityCategory) && text(value.categoryLabel, 128) &&
    text(value.containerName, 512) && text(value.description, 4_096) && text(value.recommendation, 4_096) &&
    typeof value.textTruncated === "boolean" && markerRequiresProjectionFlag(value, value.textTruncated);
}

export function isDockerSecurityAudit(value: unknown): value is DockerSecurityAudit {
  if (!record(value) || !exact(value, [
    "snapshotHandle", "containersScanned", "findings", "summary", "truncated",
  ]) || !isDockerOpaqueHandle(value.snapshotHandle) || !unsigned(value.containersScanned, 1_000) ||
    !Array.isArray(value.findings) || value.findings.length > 500 || !value.findings.every(securityFinding) ||
    !securitySummary(value.summary) || typeof value.truncated !== "boolean") return false;
  const audit = value as unknown as DockerSecurityAudit;
  const summaryTotal = audit.summary.critical + audit.summary.high + audit.summary.medium +
    audit.summary.low + audit.summary.info;
  const findingCounts: Record<DockerSecuritySeverity, number> = {
    critical: 0, high: 0, medium: 0, low: 0, info: 0,
  };
  const textValues: string[] = [];
  for (const finding of audit.findings) {
    findingCounts[finding.severity] += 1;
    textValues.push(
      finding.severityLabel,
      finding.categoryLabel,
      finding.containerName,
      finding.description,
      finding.recommendation,
    );
  }
  return summaryTotal === audit.summary.total &&
    findingCounts.critical <= audit.summary.critical && findingCounts.high <= audit.summary.high &&
    findingCounts.medium <= audit.summary.medium && findingCounts.low <= audit.summary.low &&
    findingCounts.info <= audit.summary.info && withinTextBudget(textValues, 1_024 * 1_024);
}

export function isDockerLogs(value: unknown): value is DockerLogs {
  return record(value) && exact(value, [
    "snapshotHandle", "containerHandle", "tail", "text", "truncated",
  ]) && isDockerOpaqueHandle(value.snapshotHandle) && isDockerOpaqueHandle(value.containerHandle) &&
    isDockerLogTail(value.tail) && multilineText(value.text, 256 * 1_024) &&
    typeof value.truncated === "boolean" && markerRequiresProjectionFlag(value.text, value.truncated);
}
