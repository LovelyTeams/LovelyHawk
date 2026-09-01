export type SystemInfoGroupKey = "realtime" | "persistence" | "security" | "workload";

export const SYSTEM_INFO_TAB_KEYS = [
  "processes",
  "network",
  "services",
  "established",
  "open-ports",
  "users",
  "autostart",
  "cron",
  "ssh-keys",
  "login-history",
  "suid-files",
  "autoruns",
  "firewall",
  "env-vars",
  "shell-configs",
  "packages",
  "sudoers",
  "timers",
  "kernel-modules",
  "rootcheck",
  "sensitive",
  "recent-files",
  "docker",
  "kubernetes",
  "web-apps",
] as const;

export type SystemInfoTabKey = (typeof SYSTEM_INFO_TAB_KEYS)[number];
export type SystemInfoRisk = "normal" | "warning" | "high";

export interface SystemInfoTabCatalogEntry {
  key: SystemInfoTabKey;
  label: string;
  group: SystemInfoGroupKey;
  groupLabel: string;
  columns: string[];
}

export interface SystemInfoSummary {
  hostname: string;
  operatingSystem: string;
  kernel: string;
  architecture: string;
  virtualization: string;
  bootTime: string;
  timezone: string;
  locale: string;
  initSystem: string;
  packageManager: string;
  selinux: string;
  apparmor: string;
  uptimeSeconds: number;
  loadAverage: [string, string, string];
  cpuModel: string;
  cpuCores: number;
  memoryTotalBytes: number;
  memoryAvailableBytes: number;
  swapTotalBytes: number;
  swapFreeBytes: number;
  rootDevice: string;
  rootFilesystem: string;
  rootTotalBytes: number;
  rootAvailableBytes: number;
  primaryIp: string;
  defaultGateway: string;
  dnsServers: string;
  processCount: number;
  loggedInUsers: number;
  networkConnections: number;
  receivedBytes: number;
  transmittedBytes: number;
}

export interface SystemInfoRow {
  id: string;
  cells: string[];
  risk: SystemInfoRisk;
  /** Whether this row has a detail behind it. Most rows do not. */
  detail: boolean;
}

export interface SystemInfoTable {
  snapshotHandle: string;
  tab: SystemInfoTabKey;
  columns: string[];
  rows: SystemInfoRow[];
  truncated: boolean;
}

export interface SystemInfoDetailField {
  label: string;
  value: string;
}

export interface SystemInfoDetail {
  tab: SystemInfoTabKey;
  rowId: string;
  fields: SystemInfoDetailField[];
}

/**
 * What a right-click on one row may ask for.
 *
 * `inspect` runs a read-only command on the target and shows its output.
 * `change` asks for a plan first; nothing runs until the operator has read it
 * and confirmed, and the plan is spent by one execution.
 */
export type SystemInfoRowActionKind = "inspect" | "change";

export interface SystemInfoRowActionEntry {
  /** A fixed key such as `process.open-files`; the sidecar accepts no other. */
  key: string;
  label: string;
  kind: SystemInfoRowActionKind;
  /** Whether the menu paints it as something that stops or removes. */
  dangerous: boolean;
}

export interface SystemInfoRowActionGroup {
  key: string;
  label: string;
  actions: SystemInfoRowActionEntry[];
}

/** The actions one row can take, decided by the sidecar from the row it kept. */
export interface SystemInfoRowActions {
  tab: SystemInfoTabKey;
  rowId: string;
  /** What the row is, in the table's own words. Display only. */
  subject: string;
  groups: SystemInfoRowActionGroup[];
}

export interface SystemInfoRowInspection {
  tab: SystemInfoTabKey;
  rowId: string;
  action: string;
  label: string;
  subject: string;
  output: string;
  truncated: boolean;
}

/** What a change would do, before any of it is done. */
export interface SystemInfoRowPlan {
  planHandle: string;
  tab: SystemInfoTabKey;
  rowId: string;
  action: string;
  label: string;
  subject: string;
  summary: string;
  dangerous: boolean;
  restoreDescription: string | null;
  confirmed: boolean;
  expiresInSeconds: number;
}

/** What happened, after the target was read back. */
export interface SystemInfoRowReceipt {
  planHandle: string;
  tab: SystemInfoTabKey;
  rowId: string;
  action: string;
  label: string;
  subject: string;
  /** Whether the target, read again afterwards, is in the state the plan said. */
  verified: boolean;
  detail: string;
  restored: boolean;
}

export interface SystemInfoApi {
  getSystemInfoCatalog(): Promise<unknown>;
  getSystemInfoSummary(bindingHandle: string): Promise<unknown>;
  collectSystemInfo(
    bindingHandle: string,
    tab: SystemInfoTabKey,
    maximumRows: number,
  ): Promise<unknown>;
  getSystemInfoDetail(
    bindingHandle: string,
    snapshotHandle: string,
    rowId: string,
  ): Promise<unknown>;
  listSystemInfoRowActions(
    bindingHandle: string,
    snapshotHandle: string,
    rowId: string,
  ): Promise<unknown>;
  inspectSystemInfoRow(
    bindingHandle: string,
    snapshotHandle: string,
    rowId: string,
    action: string,
  ): Promise<unknown>;
  planSystemInfoRowAction(
    bindingHandle: string,
    snapshotHandle: string,
    rowId: string,
    action: string,
  ): Promise<unknown>;
  confirmSystemInfoRowAction(bindingHandle: string, planHandle: string): Promise<unknown>;
  executeSystemInfoRowAction(bindingHandle: string, planHandle: string): Promise<unknown>;
  cancelSystemInfoRowAction(bindingHandle: string, planHandle: string): Promise<void>;
}

interface CatalogDefinition {
  key: SystemInfoTabKey;
  label: string;
  group: SystemInfoGroupKey;
  groupLabel: string;
  columns: readonly string[];
}

export const SYSTEM_INFO_CATALOG: readonly CatalogDefinition[] = [
  { key: "processes", label: "进程详情", group: "realtime", groupLabel: "实时态势", columns: ["风险", "PID", "PPID", "用户", "状态", "CPU%", "内存%", "运行秒数", "命令"] },
  { key: "network", label: "网络详情", group: "realtime", groupLabel: "实时态势", columns: ["协议", "本地地址", "远程地址", "状态", "PID", "进程"] },
  { key: "services", label: "系统服务", group: "realtime", groupLabel: "实时态势", columns: ["服务名", "状态", "启用状态", "描述"] },
  { key: "established", label: "外连排查", group: "realtime", groupLabel: "实时态势", columns: ["本地地址", "远程地址", "远程端口", "PID", "进程", "用户"] },
  { key: "open-ports", label: "开放端口", group: "realtime", groupLabel: "实时态势", columns: ["协议", "地址", "端口", "PID", "进程", "用户"] },
  { key: "users", label: "用户列表", group: "persistence", groupLabel: "账户与持久化", columns: ["用户名", "UID", "GID", "主目录", "Shell"] },
  { key: "autostart", label: "自启动", group: "persistence", groupLabel: "账户与持久化", columns: ["服务名", "命令", "状态", "类型"] },
  { key: "cron", label: "计划任务", group: "persistence", groupLabel: "账户与持久化", columns: ["用户", "时间表", "命令", "来源"] },
  { key: "ssh-keys", label: "SSH 密钥", group: "persistence", groupLabel: "账户与持久化", columns: ["用户", "密钥类型", "公钥内容", "备注", "文件路径"] },
  { key: "login-history", label: "登录历史", group: "persistence", groupLabel: "账户与持久化", columns: ["用户", "终端", "来源 IP", "登录时间", "状态"] },
  { key: "suid-files", label: "SUID 文件", group: "persistence", groupLabel: "账户与持久化", columns: ["文件路径", "权限", "所有者", "大小", "修改时间", "风险"] },
  { key: "autoruns", label: "启动项汇总", group: "persistence", groupLabel: "账户与持久化", columns: ["类型", "名称", "状态", "路径/命令", "用户"] },
  { key: "firewall", label: "防火墙", group: "security", groupLabel: "安全与痕迹", columns: ["链", "目标", "协议", "源地址", "目标地址", "选项"] },
  { key: "env-vars", label: "环境变量", group: "security", groupLabel: "安全与痕迹", columns: ["变量名", "值", "风险"] },
  { key: "shell-configs", label: "Shell 配置", group: "security", groupLabel: "安全与痕迹", columns: ["文件", "所有者", "修改时间", "行号", "内容", "风险"] },
  { key: "packages", label: "软件包", group: "security", groupLabel: "安全与痕迹", columns: ["软件包名", "版本", "安装时间", "来源"] },
  { key: "sudoers", label: "Sudoers", group: "security", groupLabel: "安全与痕迹", columns: ["用户/组", "主机", "命令", "免密", "来源"] },
  { key: "timers", label: "定时器", group: "security", groupLabel: "安全与痕迹", columns: ["定时器", "下次触发", "剩余时间", "上次触发", "触发单元"] },
  { key: "kernel-modules", label: "内核模块", group: "security", groupLabel: "安全与痕迹", columns: ["模块名", "大小", "引用计数", "风险"] },
  { key: "rootcheck", label: "Rootkit 检查", group: "security", groupLabel: "安全与痕迹", columns: ["检查项", "结果", "详情"] },
  { key: "sensitive", label: "敏感文件", group: "security", groupLabel: "安全与痕迹", columns: ["文件路径", "类型", "权限", "所有者", "修改时间"] },
  { key: "recent-files", label: "最近文件", group: "security", groupLabel: "安全与痕迹", columns: ["文件路径", "修改时间", "大小", "所有者", "风险"] },
  { key: "docker", label: "Docker", group: "workload", groupLabel: "工作负载", columns: ["ID", "名称", "镜像", "状态", "端口", "创建时间"] },
  { key: "kubernetes", label: "Kubernetes", group: "workload", groupLabel: "工作负载", columns: ["Namespace", "名称", "Ready", "状态", "重启", "Age"] },
  { key: "web-apps", label: "Web 应用", group: "workload", groupLabel: "工作负载", columns: ["类型", "路径/URL", "状态", "配置文件", "运行用户"] },
];

type JsonRecord = Record<string, unknown>;
const encoder = new TextEncoder();
const MAX_TABLE_BYTES = 512 * 1_024;
const MAX_DETAIL_BYTES = 256 * 1_024;

const summaryStringKeys = [
  "hostname", "operatingSystem", "kernel", "architecture", "virtualization", "bootTime",
  "timezone", "locale", "initSystem", "packageManager", "selinux", "apparmor", "cpuModel",
  "rootDevice", "rootFilesystem", "primaryIp", "defaultGateway", "dnsServers",
] as const;

const summaryNumberKeys = [
  "uptimeSeconds", "cpuCores", "memoryTotalBytes", "memoryAvailableBytes", "swapTotalBytes",
  "swapFreeBytes", "rootTotalBytes", "rootAvailableBytes", "processCount", "loggedInUsers",
  "networkConnections", "receivedBytes", "transmittedBytes",
] as const;

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exact(value: JsonRecord, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && actual.every((key) => keys.includes(key));
}

function utf8(value: unknown, maximumBytes: number, allowEmpty = false): value is string {
  return (
    typeof value === "string" &&
    (allowEmpty || value.length > 0) &&
    encoder.encode(value).byteLength <= maximumBytes
  );
}

function safeUnsigned(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function sameStrings(actual: unknown, expected: readonly string[]): actual is string[] {
  return (
    Array.isArray(actual) &&
    actual.length === expected.length &&
    actual.every((value, index) => value === expected[index])
  );
}

export function isSystemInfoTabKey(value: unknown): value is SystemInfoTabKey {
  return typeof value === "string" && SYSTEM_INFO_TAB_KEYS.some((key) => key === value);
}

export function isSystemInfoMaximumRows(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 1 && value <= 500;
}

export function isSystemInfoOpaqueHandle(value: unknown): value is string {
  return utf8(value, 128) && /^[A-Za-z0-9-]+$/u.test(value);
}

export function isSystemInfoCatalog(value: unknown): value is SystemInfoTabCatalogEntry[] {
  if (!Array.isArray(value) || value.length !== SYSTEM_INFO_CATALOG.length) return false;
  return value.every((entry, index) => {
    const expected = SYSTEM_INFO_CATALOG[index];
    if (expected === undefined || !isRecord(entry)) return false;
    return (
      exact(entry, ["key", "label", "group", "groupLabel", "columns"]) &&
      entry.key === expected.key &&
      entry.label === expected.label &&
      entry.group === expected.group &&
      entry.groupLabel === expected.groupLabel &&
      sameStrings(entry.columns, expected.columns)
    );
  });
}

export function isSystemInfoSummary(value: unknown): value is SystemInfoSummary {
  if (
    !isRecord(value) ||
    !exact(value, [...summaryStringKeys, ...summaryNumberKeys, "loadAverage"])
  ) return false;
  let totalBytes = 0;
  for (const key of summaryStringKeys) {
    const item = value[key];
    if (!utf8(item, 4_096, true)) return false;
    totalBytes += encoder.encode(item).byteLength;
  }
  if (
    !Array.isArray(value.loadAverage) ||
    value.loadAverage.length !== 3 ||
    !value.loadAverage.every((item) => utf8(item, 128, true))
  ) return false;
  totalBytes += value.loadAverage.reduce((total, item) => total + encoder.encode(item).byteLength, 0);
  return (
    totalBytes <= 64 * 1_024 &&
    summaryNumberKeys.every((key) => safeUnsigned(value[key]))
  );
}

export function isSystemInfoTable(value: unknown): value is SystemInfoTable {
  if (
    !isRecord(value) ||
    !exact(value, ["snapshotHandle", "tab", "columns", "rows", "truncated"]) ||
    !isSystemInfoOpaqueHandle(value.snapshotHandle) ||
    !isSystemInfoTabKey(value.tab) ||
    typeof value.truncated !== "boolean" ||
    !Array.isArray(value.rows) ||
    value.rows.length > 500
  ) return false;
  const definition = SYSTEM_INFO_CATALOG.find((entry) => entry.key === value.tab);
  if (definition === undefined || !sameStrings(value.columns, definition.columns)) return false;

  let totalBytes = definition.columns.reduce(
    (total, column) => total + encoder.encode(column).byteLength,
    0,
  );
  const rowIds = new Set<string>();
  for (const row of value.rows) {
    if (
      !isRecord(row) ||
      !exact(row, ["id", "cells", "risk", "detail"]) ||
      !utf8(row.id, 256) ||
      rowIds.has(row.id) ||
      !Array.isArray(row.cells) ||
      row.cells.length !== definition.columns.length ||
      typeof row.detail !== "boolean" ||
      (row.risk !== "normal" && row.risk !== "warning" && row.risk !== "high")
    ) return false;
    rowIds.add(row.id);
    totalBytes += encoder.encode(row.id).byteLength;
    for (const cell of row.cells) {
      if (!utf8(cell, 64 * 1_024, true)) return false;
      totalBytes += encoder.encode(cell).byteLength;
      if (totalBytes > MAX_TABLE_BYTES) return false;
    }
  }
  return totalBytes <= MAX_TABLE_BYTES;
}

export function isSystemInfoDetail(value: unknown): value is SystemInfoDetail {
  if (
    !isRecord(value) ||
    !exact(value, ["tab", "rowId", "fields"]) ||
    !isSystemInfoTabKey(value.tab) ||
    !utf8(value.rowId, 256) ||
    !Array.isArray(value.fields) ||
    value.fields.length > 64
  ) return false;
  let totalBytes = encoder.encode(value.rowId).byteLength;
  for (const field of value.fields) {
    if (
      !isRecord(field) ||
      !exact(field, ["label", "value"]) ||
      !utf8(field.label, 256) ||
      !utf8(field.value, 128 * 1_024, true)
    ) return false;
    totalBytes += encoder.encode(field.label).byteLength + encoder.encode(field.value).byteLength;
    if (totalBytes > MAX_DETAIL_BYTES) return false;
  }
  return true;
}

const MAX_ROW_ACTION_GROUPS = 16;
const MAX_ROW_ACTIONS = 128;
const MAX_ROW_INSPECTION_BYTES = 256 * 1_024;
const MAX_ROW_PLAN_TEXT_BYTES = 4_096;
const ROW_ACTION_KEY_PATTERN = /^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*){1,2}$/u;
const ROW_ACTION_GROUP_PATTERN = /^[a-z][a-z0-9-]*$/u;

/** Two or three kebab-case segments, nothing else: `process.signal.kill`. */
export function isSystemInfoRowActionKey(value: unknown): value is string {
  return utf8(value, 64) && ROW_ACTION_KEY_PATTERN.test(value);
}

export function isSystemInfoRowActionKind(value: unknown): value is SystemInfoRowActionKind {
  return value === "inspect" || value === "change";
}

function isRowSubject(value: unknown): value is string {
  return utf8(value, 1_024, true);
}

export function isSystemInfoRowActions(value: unknown): value is SystemInfoRowActions {
  if (
    !isRecord(value) ||
    !exact(value, ["tab", "rowId", "subject", "groups"]) ||
    !isSystemInfoTabKey(value.tab) ||
    !utf8(value.rowId, 256) ||
    !isRowSubject(value.subject) ||
    !Array.isArray(value.groups) ||
    value.groups.length > MAX_ROW_ACTION_GROUPS
  ) return false;
  const groupKeys = new Set<string>();
  const actionKeys = new Set<string>();
  for (const group of value.groups) {
    if (
      !isRecord(group) ||
      !exact(group, ["key", "label", "actions"]) ||
      !utf8(group.key, 64) ||
      !ROW_ACTION_GROUP_PATTERN.test(group.key) ||
      groupKeys.has(group.key) ||
      !utf8(group.label, 128) ||
      !Array.isArray(group.actions) ||
      group.actions.length === 0
    ) return false;
    groupKeys.add(group.key);
    for (const action of group.actions) {
      if (
        !isRecord(action) ||
        !exact(action, ["key", "label", "kind", "dangerous"]) ||
        !isSystemInfoRowActionKey(action.key) ||
        actionKeys.has(action.key) ||
        !utf8(action.label, 128) ||
        !isSystemInfoRowActionKind(action.kind) ||
        typeof action.dangerous !== "boolean"
      ) return false;
      actionKeys.add(action.key);
      if (actionKeys.size > MAX_ROW_ACTIONS) return false;
    }
  }
  return true;
}

export function isSystemInfoRowInspection(value: unknown): value is SystemInfoRowInspection {
  return (
    isRecord(value) &&
    exact(value, ["tab", "rowId", "action", "label", "subject", "output", "truncated"]) &&
    isSystemInfoTabKey(value.tab) &&
    utf8(value.rowId, 256) &&
    isSystemInfoRowActionKey(value.action) &&
    utf8(value.label, 128) &&
    isRowSubject(value.subject) &&
    utf8(value.output, MAX_ROW_INSPECTION_BYTES, true) &&
    typeof value.truncated === "boolean"
  );
}

export function isSystemInfoRowPlan(value: unknown): value is SystemInfoRowPlan {
  return (
    isRecord(value) &&
    exact(value, [
      "planHandle", "tab", "rowId", "action", "label", "subject", "summary", "dangerous",
      "restoreDescription", "confirmed", "expiresInSeconds",
    ]) &&
    isSystemInfoOpaqueHandle(value.planHandle) &&
    isSystemInfoTabKey(value.tab) &&
    utf8(value.rowId, 256) &&
    isSystemInfoRowActionKey(value.action) &&
    utf8(value.label, 128) &&
    isRowSubject(value.subject) &&
    utf8(value.summary, MAX_ROW_PLAN_TEXT_BYTES) &&
    typeof value.dangerous === "boolean" &&
    (value.restoreDescription === null || utf8(value.restoreDescription, MAX_ROW_PLAN_TEXT_BYTES)) &&
    typeof value.confirmed === "boolean" &&
    safeUnsigned(value.expiresInSeconds) &&
    value.expiresInSeconds >= 1 &&
    value.expiresInSeconds <= 3_600
  );
}

export function isSystemInfoRowReceipt(value: unknown): value is SystemInfoRowReceipt {
  return (
    isRecord(value) &&
    exact(value, [
      "planHandle", "tab", "rowId", "action", "label", "subject", "verified", "detail", "restored",
    ]) &&
    isSystemInfoOpaqueHandle(value.planHandle) &&
    isSystemInfoTabKey(value.tab) &&
    utf8(value.rowId, 256) &&
    isSystemInfoRowActionKey(value.action) &&
    utf8(value.label, 128) &&
    isRowSubject(value.subject) &&
    typeof value.verified === "boolean" &&
    utf8(value.detail, MAX_ROW_PLAN_TEXT_BYTES, true) &&
    typeof value.restored === "boolean"
  );
}
