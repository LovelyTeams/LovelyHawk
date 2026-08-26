import type {
  ConfigCatalog,
  ConfigClipboardResult,
  ConfigClosedResult,
  ConfigDraft,
  ConfigExportResult,
  ConfigGenerateInput,
} from "./config-contract.js";
import type {
  SshAttemptCancellation,
  SshAttemptStarted,
  SshAttemptStatus,
  SshBindingDisconnection,
} from "./ssh-contract.js";
import type {
  SystemInfoDetail,
  SystemInfoSummary,
  SystemInfoTabCatalogEntry,
  SystemInfoTabKey,
  SystemInfoTable,
} from "./system-info-contract.js";
import type {
  SettingsAiApiKeyReplacementInput,
  SettingsAiApiKeyReplacementResult,
  SettingsMutationCancellation,
  SettingsMutationProposal,
  SettingsMutationResult,
  SettingsSaveInput,
  SettingsSnapshot,
  SettingsTheme,
} from "./settings-contract.js";
import type {
  AiHistoryExportFormat,
  AiHistoryExportResult,
  AiHistoryListPage,
  AiHistoryMutationCancellation,
  AiHistoryMutationProposal,
  AiHistoryMutationResult,
  AiHistoryRecord,
} from "./ai-history-contract.js";
import type {
  CommandHistoryListPage,
  CommandHistoryMutationCancellation,
  CommandHistoryMutationProposal,
  CommandHistoryMutationResult,
  CommandHistoryRecord,
  CommandReplayIntent,
} from "./command-history-contract.js";
import type {
  DisposalReportContent,
  DisposalReportExportFormat,
  DisposalReportExportResult,
  DisposalReportPreviewFormat,
  DisposalReportSnapshot,
} from "./disposal-report-contract.js";
import type { TerminalWindowLaunchResult } from "./terminal-contract.js";
import type {
  SnapshotDetail,
  SnapshotDiffInput,
  SnapshotDiffResult,
  SnapshotListResult,
} from "./snapshot-read-contract.js";
import type {
  FirewallHistory,
  FirewallInspection,
} from "./firewall-read-contract.js";
import type {
  BaselineCatalog,
  BaselineHistory,
  BaselineScan,
} from "./baseline-read-contract.js";
import type {
  MiddlewareConfiguration,
  MiddlewareDiscovery,
  MiddlewareHistory,
} from "./middleware-read-contract.js";
import type {
  CheckAuditCatalog,
  CheckAuditCatalogInput,
  CheckAuditLogInput,
  CheckAuditLogResult,
  CheckAuditStatus,
} from "./check-audit-read-contract.js";
import type {
  LogCorrelationInput,
  LogCorrelationResult,
  LogIocSearchInput,
  LogIocSearchResult,
  LogSourceReadInput,
  LogSourceReadResult,
  LogSourceSnapshot,
} from "./log-analysis-read-contract.js";
import type {
  KubernetesAvailability,
  KubernetesListInput,
  KubernetesSnapshot,
  KubernetesTextResult,
} from "./kubernetes-read-contract.js";
import type {
  DockerCollectionKind,
  DockerContainerSnapshot,
  DockerLogs,
  DockerReadCollection,
  DockerReadInspection,
  DockerResourceKind,
  DockerSecurityAudit,
} from "./docker-read-contract.js";
import type {
  EmergencyCommandCatalog,
  EmergencyCommandResult,
  EmergencyPathAction,
  EmergencyPathDetail,
  EmergencyPathPlan,
  EmergencyPathReceipt,
} from "./emergency-command-contract.js";
import type {
  LocalDirectorySnapshot,
} from "./local-browser-contract.js";
import type {
  SftpDirectorySnapshot,
  SftpTextPreview,
} from "./sftp-browser-contract.js";
import type {
  PacketCaptureInterfaceList,
  PacketCapturePoll,
  PacketCaptureStarted,
  PacketCaptureStartInput,
  PacketCaptureStopped,
} from "./packet-capture-live-contract.js";
import type {
  ApplicationLogClearResult,
  ApplicationLogExportResult,
  ApplicationLogFilter,
  ApplicationLogLevel,
  ApplicationLogLevelResult,
  ApplicationLogPreview,
  ApplicationLogSnapshot,
} from "./application-log-contract.js";
import type {
  IntegrityBaselineList,
  IntegrityComparisonCancellation,
  IntegrityComparisonPoll,
  IntegrityComparisonStarted,
  IntegrityPresetCatalog,
} from "./integrity-contract.js";

export * from "./config-contract.js";
export * from "./ssh-contract.js";
export * from "./system-info-contract.js";
export * from "./settings-contract.js";
export * from "./ai-history-contract.js";
export * from "./command-history-contract.js";
export * from "./disposal-report-contract.js";
export * from "./terminal-contract.js";
export * from "./snapshot-read-contract.js";
export * from "./firewall-read-contract.js";
export * from "./baseline-read-contract.js";
export * from "./middleware-read-contract.js";
export * from "./check-audit-read-contract.js";
export * from "./log-analysis-read-contract.js";
export * from "./kubernetes-read-contract.js";
export * from "./docker-read-contract.js";
export * from "./emergency-command-contract.js";
export * from "./sftp-browser-contract.js";
export * from "./local-browser-contract.js";
export * from "./packet-capture-live-contract.js";
export * from "./application-log-contract.js";
export * from "./integrity-contract.js";

export const BACKEND_PROTOCOL = "lovelyres-backend/v1" as const;

export const pageGroups = [
  "target",
  "triage",
  "investigation",
  "response",
  "operations",
  "intelligence",
] as const;

export type PageGroup = (typeof pageGroups)[number];
export type CapabilityRequirement =
  | "connected-target"
  | "local-workspace"
  | "optional-ai";
export type MigrationState = "ready" | "pending";

export interface PageDescriptor {
  id: string;
  group: PageGroup;
  title: string;
  icon: string;
  capability: CapabilityRequirement;
  summary: string;
  primaryAction: string;
  sections: string[];
  migrationState: MigrationState;
}

export interface BootstrapResult {
  productName: string;
  appVersion: string;
  protocolVersion: typeof BACKEND_PROTOCOL;
  pages: PageDescriptor[];
  securityReferenceFavoriteIds: string[];
}

export type SshAuthMethod =
  | "password"
  | "keyboard-interactive"
  | "public-key"
  | "agent"
  | "certificate";

export interface ConnectionSummary {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  authMethod: SshAuthMethod;
  tags: string[];
  group: string | null;
  environment: string | null;
  lastConnectedAt: string | null;
  hasPassword: boolean;
  hasKeyPassphrase: boolean;
  jumpHostHasPassword: boolean;
  jumpHostHasKeyPassphrase: boolean;
}

export interface JumpHostEditView {
  host: string;
  port: number;
  username: string;
  authMethod: SshAuthMethod;
  privateKeyPath: string | null;
  certificatePath: string | null;
  agentIdentityFingerprint: string | null;
  hostKeyFingerprint: string | null;
}

export interface ConnectionEditView {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  authMethod: SshAuthMethod;
  privateKeyPath: string | null;
  certificatePath: string | null;
  agentIdentityFingerprint: string | null;
  jumpHost: JumpHostEditView | null;
  tags: string[];
  notes: string | null;
  environment: string | null;
  role: string | null;
  group: string | null;
  hostKeyFingerprint: string | null;
  hasPassword: boolean;
  hasKeyPassphrase: boolean;
  jumpHostHasPassword: boolean;
  jumpHostHasKeyPassphrase: boolean;
  lastConnectedAt: string | null;
}

export interface JumpHostDraftInput {
  host: string;
  port: number;
  username: string;
  authMethod: SshAuthMethod;
  privateKeyPath: string | null;
  certificatePath: string | null;
  agentIdentityFingerprint: string | null;
}

export interface ConnectionDraftInput {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  authMethod: SshAuthMethod;
  privateKeyPath: string | null;
  certificatePath: string | null;
  agentIdentityFingerprint: string | null;
  jumpHost: JumpHostDraftInput | null;
  tags: string[];
  notes: string | null;
  environment: string | null;
  role: string | null;
  group: string | null;
}

export type SecretWrite =
  | { action: "keep" }
  | { action: "remove" }
  | { action: "replace"; value: string };

export interface ConnectionSecretWrites {
  password?: SecretWrite;
  keyPassphrase?: SecretWrite;
  jumpHostPassword?: SecretWrite;
  jumpHostKeyPassphrase?: SecretWrite;
}

export interface ConnectionWriteInput {
  connection: ConnectionDraftInput;
  secrets?: ConnectionSecretWrites;
}

export interface ConnectionDeletePrompt {
  handle: string;
  connectionId: string;
  connectionName: string;
  confirmationText: string;
}

export interface ConnectionDeleteResult {
  operationId: string;
  verified: boolean;
  verificationDetail: string;
}

export interface ConnectionDeleteCancellation {
  cancelled: true;
}

export interface ConnectionImportResult {
  cancelled: boolean;
  imported: number;
  skippedExisting: number;
  skippedDuplicate: number;
}

export interface ConnectionExportResult {
  cancelled: boolean;
  count: number;
  fileName: string | null;
}

export interface InternalConnectionImportResult {
  imported: number;
  skippedExisting: number;
  skippedDuplicate: number;
}

export interface InternalConnectionExportResult {
  count: number;
}

export interface SecurityReferenceFavoritesResult {
  favoriteIds: string[];
}

export interface NoteSummary {
  id: string;
  title: string;
  contentPreview: string;
  contentTruncated: boolean;
  tags: string[];
  createdAt: number;
  updatedAt: number;
  pinned: boolean;
  revision: string;
}

export interface NoteResult {
  id: string;
  title: string;
  content: string;
  tags: string[];
  createdAt: number;
  updatedAt: number;
  pinned: boolean;
  revision: string;
}

export interface NoteListPage {
  total: number;
  offset: number;
  hasMore: boolean;
  items: NoteSummary[];
}

export interface NoteCreateInput {
  mutationId: string;
  title?: string;
  content: string;
  tags: string[];
}

export interface NoteUpdateInput {
  id: string;
  expectedRevision: string;
  mutationId: string;
  title?: string;
  content?: string;
  tags?: string[];
}

export interface NoteDeleteProposal {
  handle: string;
  summary: string;
  expiresInSeconds: number;
}

export interface NoteDeleteResult {
  noteId: string;
  affectedRecords: number;
  verified: boolean;
}

export interface NoteDeleteCancellation {
  cancelled: true;
}

export interface NotesTextExport {
  noteCount: number;
  text: string;
}

export interface LovelyResApi {
  bootstrap(): Promise<BootstrapResult>;
  listConnections(): Promise<ConnectionSummary[]>;
  getConnection(id: string): Promise<ConnectionEditView>;
  createConnection(input: ConnectionWriteInput): Promise<ConnectionEditView>;
  updateConnection(input: ConnectionWriteInput): Promise<ConnectionEditView>;
  planConnectionDelete(id: string): Promise<ConnectionDeletePrompt>;
  confirmConnectionDelete(handle: string): Promise<ConnectionDeleteResult>;
  cancelConnectionDelete(handle: string): Promise<ConnectionDeleteCancellation>;
  importConnections(): Promise<ConnectionImportResult>;
  exportConnections(): Promise<ConnectionExportResult>;
  startSshConnect(connectionId: string): Promise<SshAttemptStarted>;
  startSshProbe(input: ConnectionWriteInput): Promise<SshAttemptStarted>;
  getSshAttempt(attemptHandle: string): Promise<SshAttemptStatus>;
  confirmSshHostKey(
    attemptHandle: string,
    promptHandle: string,
  ): Promise<SshAttemptStatus>;
  respondSshMfa(
    attemptHandle: string,
    promptHandle: string,
    responses: string[],
  ): Promise<SshAttemptStatus>;
  cancelSshAttempt(attemptHandle: string): Promise<SshAttemptCancellation>;
  disconnectSshBinding(bindingHandle: string): Promise<SshBindingDisconnection>;
  openSshTerminal(): Promise<TerminalWindowLaunchResult>;
  getSystemInfoCatalog(): Promise<SystemInfoTabCatalogEntry[]>;
  getSystemInfoSummary(bindingHandle: string): Promise<SystemInfoSummary>;
  collectSystemInfo(
    bindingHandle: string,
    tab: SystemInfoTabKey,
    maximumRows: number,
  ): Promise<SystemInfoTable>;
  getSystemInfoDetail(
    bindingHandle: string,
    snapshotHandle: string,
    rowId: string,
  ): Promise<SystemInfoDetail>;
  listSnapshots(bindingHandle: string): Promise<SnapshotListResult>;
  getSnapshotDetail(bindingHandle: string, snapshotHandle: string): Promise<SnapshotDetail>;
  diffForensicSnapshots(
    bindingHandle: string,
    input: SnapshotDiffInput,
  ): Promise<SnapshotDiffResult>;
  inspectFirewall(bindingHandle: string): Promise<FirewallInspection>;
  listFirewallChangeHistory(bindingHandle: string): Promise<FirewallHistory>;
  getBaselineCatalog(): Promise<BaselineCatalog>;
  scanBaseline(bindingHandle: string): Promise<BaselineScan>;
  listBaselineHistory(bindingHandle: string): Promise<BaselineHistory>;
  discoverMiddleware(bindingHandle: string): Promise<MiddlewareDiscovery>;
  loadMiddlewareConfiguration(
    bindingHandle: string,
    discoveryHandle: string,
    instanceHandle: string,
  ): Promise<MiddlewareConfiguration>;
  listMiddlewareHistory(bindingHandle: string): Promise<MiddlewareHistory>;
  getCheckAuditCatalog(
    bindingHandle: string,
    input: CheckAuditCatalogInput,
  ): Promise<CheckAuditCatalog>;
  collectCheckAuditStatus(
    bindingHandle: string,
    snapshotHandle: string,
  ): Promise<CheckAuditStatus>;
  readCheckAuditLog(
    bindingHandle: string,
    snapshotHandle: string,
    input: CheckAuditLogInput,
  ): Promise<CheckAuditLogResult>;
  discoverLogSources(bindingHandle: string): Promise<LogSourceSnapshot>;
  readLogSource(
    bindingHandle: string,
    snapshotHandle: string,
    sourceHandle: string,
    input: LogSourceReadInput,
  ): Promise<LogSourceReadResult>;
  correlateLogSources(
    bindingHandle: string,
    snapshotHandle: string,
    input: LogCorrelationInput,
  ): Promise<LogCorrelationResult>;
  searchLogIocs(
    bindingHandle: string,
    snapshotHandle: string,
    input: LogIocSearchInput,
  ): Promise<LogIocSearchResult>;
  getKubernetesAvailability(bindingHandle: string): Promise<KubernetesAvailability>;
  listKubernetesResources(
    bindingHandle: string,
    input: KubernetesListInput,
  ): Promise<KubernetesSnapshot>;
  getKubernetesResourceDetail(
    bindingHandle: string,
    snapshotHandle: string,
    rowHandle: string,
  ): Promise<KubernetesTextResult>;
  getKubernetesPodLogs(
    bindingHandle: string,
    snapshotHandle: string,
    rowHandle: string,
  ): Promise<KubernetesTextResult>;
  refreshDockerContainers(bindingHandle: string): Promise<DockerContainerSnapshot>;
  getDockerCollection(
    bindingHandle: string,
    snapshotHandle: string,
    kind: DockerCollectionKind,
  ): Promise<DockerReadCollection>;
  inspectDockerResource(
    bindingHandle: string,
    snapshotHandle: string,
    kind: DockerResourceKind,
    resourceHandle: string,
  ): Promise<DockerReadInspection>;
  getDockerSecurityAudit(
    bindingHandle: string,
    snapshotHandle: string,
  ): Promise<DockerSecurityAudit>;
  getDockerLogs(
    bindingHandle: string,
    snapshotHandle: string,
    containerHandle: string,
    tail: number,
  ): Promise<DockerLogs>;
  loadEmergencyCommandCatalog(bindingHandle: string): Promise<EmergencyCommandCatalog>;
  runEmergencyCommand(
    bindingHandle: string,
    snapshotHandle: string,
    commandHandle: string,
  ): Promise<EmergencyCommandResult>;
  inspectEmergencyPath(bindingHandle: string, pathHandle: string): Promise<EmergencyPathDetail>;
  planEmergencyPathAction(
    bindingHandle: string,
    pathHandle: string,
    action: EmergencyPathAction,
  ): Promise<EmergencyPathPlan>;
  confirmEmergencyPathAction(bindingHandle: string, planHandle: string): Promise<EmergencyPathPlan>;
  executeEmergencyPathAction(
    bindingHandle: string,
    planHandle: string,
  ): Promise<EmergencyPathReceipt>;
  cancelEmergencyPathAction(bindingHandle: string, planHandle: string): Promise<void>;
  listPacketCaptureInterfaces(bindingHandle: string): Promise<PacketCaptureInterfaceList>;
  startPacketCapture(
    bindingHandle: string,
    interfaceHandle: string,
    input: PacketCaptureStartInput,
  ): Promise<PacketCaptureStarted>;
  pollPacketCapture(
    bindingHandle: string,
    captureHandle: string,
    afterSequence: number,
  ): Promise<PacketCapturePoll>;
  stopPacketCapture(
    bindingHandle: string,
    captureHandle: string,
  ): Promise<PacketCaptureStopped>;
  listApplicationLogs(filter: ApplicationLogFilter): Promise<ApplicationLogSnapshot>;
  setApplicationLogLevel(level: ApplicationLogLevel): Promise<ApplicationLogLevelResult>;
  clearApplicationLogBuffer(): Promise<ApplicationLogClearResult>;
  getApplicationLogPreview(filter: ApplicationLogFilter): Promise<ApplicationLogPreview>;
  exportApplicationLogs(filter: ApplicationLogFilter): Promise<ApplicationLogExportResult>;
  getIntegrityPresets(): Promise<IntegrityPresetCatalog>;
  listIntegrityBaselines(bindingHandle: string): Promise<IntegrityBaselineList>;
  startIntegrityComparison(
    bindingHandle: string,
    baselineHandle: string,
  ): Promise<IntegrityComparisonStarted>;
  pollIntegrityComparison(
    bindingHandle: string,
    operationHandle: string,
    afterEvent: number,
    limit: number,
  ): Promise<IntegrityComparisonPoll>;
  cancelIntegrityComparison(
    bindingHandle: string,
    operationHandle: string,
  ): Promise<IntegrityComparisonCancellation>;
  loadSettings(): Promise<SettingsSnapshot>;
  saveSettings(input: SettingsSaveInput): Promise<SettingsSnapshot>;
  setWindowTheme(input: WindowThemeInput): Promise<WindowThemeApplied>;
  replaceSettingsAiApiKey(
    input: SettingsAiApiKeyReplacementInput,
  ): Promise<SettingsAiApiKeyReplacementResult>;
  planSettingsAiApiKeyClear(providerId: string): Promise<SettingsMutationProposal>;
  planSettingsAiProviderRemoval(providerId: string): Promise<SettingsMutationProposal>;
  confirmSettingsMutation(mutationHandle: string): Promise<SettingsMutationResult>;
  cancelSettingsMutation(mutationHandle: string): Promise<SettingsMutationCancellation>;
  listAiHistory(query: string, offset: number, limit: number): Promise<AiHistoryListPage>;
  getAiHistoryRecord(id: string): Promise<AiHistoryRecord>;
  planAiHistoryRemove(id: string): Promise<AiHistoryMutationProposal>;
  planAiHistoryClear(): Promise<AiHistoryMutationProposal>;
  confirmAiHistoryMutation(handle: string): Promise<AiHistoryMutationResult>;
  cancelAiHistoryMutation(handle: string): Promise<AiHistoryMutationCancellation>;
  exportAiHistory(format: AiHistoryExportFormat): Promise<AiHistoryExportResult>;
  listCommandHistory(
    bindingHandle: string,
    query: string,
    offset: number,
    limit: number,
  ): Promise<CommandHistoryListPage>;
  getCommandHistory(bindingHandle: string, recordId: string): Promise<CommandHistoryRecord>;
  planCommandReplay(bindingHandle: string, recordId: string): Promise<CommandReplayIntent>;
  planCommandHistoryRemove(bindingHandle: string, recordId: string): Promise<CommandHistoryMutationProposal>;
  planCommandHistoryClear(bindingHandle: string): Promise<CommandHistoryMutationProposal>;
  confirmCommandHistoryMutation(bindingHandle: string, mutationHandle: string): Promise<CommandHistoryMutationResult>;
  cancelCommandHistoryMutation(bindingHandle: string, mutationHandle: string): Promise<CommandHistoryMutationCancellation>;
  generateDisposalReport(bindingHandle: string): Promise<DisposalReportSnapshot>;
  getDisposalReportContent(
    bindingHandle: string,
    reportHandle: string,
    format: DisposalReportPreviewFormat,
  ): Promise<DisposalReportContent>;
  exportDisposalReport(
    bindingHandle: string,
    reportHandle: string,
    format: DisposalReportExportFormat,
  ): Promise<DisposalReportExportResult>;
  getConfigCatalog(): Promise<ConfigCatalog>;
  generateConfig(input: ConfigGenerateInput): Promise<ConfigDraft>;
  reviseConfig(
    handle: string,
    revision: number,
    input: ConfigGenerateInput,
  ): Promise<ConfigDraft>;
  copyConfig(handle: string, revision: number): Promise<ConfigClipboardResult>;
  exportConfigArtifact(
    handle: string,
    revision: number,
    artifactKey: string,
  ): Promise<ConfigExportResult>;
  closeConfigDraft(handle: string, revision: number): Promise<ConfigClosedResult>;
  setSecurityReferenceFavorites(
    favoriteIds: string[],
  ): Promise<SecurityReferenceFavoritesResult>;
  listNotes(query: string, offset: number, limit: number): Promise<NoteListPage>;
  getNote(id: string): Promise<NoteResult>;
  createNote(input: NoteCreateInput): Promise<NoteResult>;
  updateNote(input: NoteUpdateInput): Promise<NoteResult>;
  setNotePinned(id: string, pinned: boolean, expectedRevision: string, mutationId: string): Promise<NoteResult>;
  addNoteTag(id: string, tag: string, expectedRevision: string, mutationId: string): Promise<NoteResult>;
  removeNoteTag(id: string, tag: string, expectedRevision: string, mutationId: string): Promise<NoteResult>;
  planNoteDelete(id: string, expectedRevision: string, mutationId: string): Promise<NoteDeleteProposal>;
  confirmNoteDelete(handle: string, mutationId: string): Promise<NoteDeleteResult>;
  cancelNoteDelete(handle: string, mutationId: string): Promise<NoteDeleteCancellation>;
  exportNotes(id: string | null): Promise<NotesTextExport>;
  writeClipboard(text: string): Promise<void>;
  onBeforeClose(handler: () => Promise<boolean>): () => void;
  notifyRendererReady(): void;
}

/**
 * The active theme plus whether a modal currently owns the renderer. Main
 * derives every native color from the shared theme registry, so the renderer
 * never sends raw colors across the boundary.
 */
export interface WindowThemeInput {
  theme: SettingsTheme;
  /** True while a modal backdrop dims the page behind it. */
  scrim: boolean;
}

export interface WindowThemeApplied {
  theme: SettingsTheme;
  scrim: boolean;
}

type JsonRecord = Record<string, unknown>;

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: JsonRecord, expected: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && keys.every((key) => expected.includes(key));
}

export function isWindowThemeInput(value: unknown): value is WindowThemeInput {
  return (
    isRecord(value) &&
    hasExactKeys(value, ["theme", "scrim"]) &&
    typeof value.theme === "string" &&
    typeof value.scrim === "boolean"
  );
}

function hasOnlyKeys(value: JsonRecord, allowed: readonly string[]): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}

function isUtf8BoundedString(value: unknown, maximumBytes: number): value is string {
  return (
    typeof value === "string" &&
    value.length <= maximumBytes &&
    new TextEncoder().encode(value).byteLength <= maximumBytes
  );
}

function hasUnsupportedControl(value: string, multiline = false): boolean {
  const controls = multiline
    ? /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/u
    : /[\u0000-\u001f\u007f-\u009f]/u;
  return controls.test(value);
}

function isBoundedLabel(value: unknown, maximumBytes: number): value is string {
  return (
    isUtf8BoundedString(value, maximumBytes) &&
    value.trim().length > 0 &&
    !hasUnsupportedControl(value)
  );
}

function isNullableBoundedText(
  value: unknown,
  maximumBytes: number,
  multiline = false,
): value is string | null {
  return (
    value === null ||
    (isUtf8BoundedString(value, maximumBytes) && !hasUnsupportedControl(value, multiline))
  );
}

function isNullablePath(value: unknown): value is string | null {
  return value === null || isBoundedLabel(value, 4_096);
}

function isNullableFingerprint(value: unknown): value is string | null {
  return (
    value === null ||
    (isBoundedLabel(value, 256) && value.startsWith("SHA256:"))
  );
}

const sshAuthMethods: readonly SshAuthMethod[] = [
  "password",
  "keyboard-interactive",
  "public-key",
  "agent",
  "certificate",
];

function isSshAuthMethod(value: unknown): value is SshAuthMethod {
  return typeof value === "string" && sshAuthMethods.includes(value as SshAuthMethod);
}

function isStringArray(value: unknown, maximum = 1_024): value is string[] {
  return (
    Array.isArray(value) &&
    value.length <= maximum &&
    value.every((item) => typeof item === "string")
  );
}

function isPageDescriptor(value: unknown): value is PageDescriptor {
  if (!isRecord(value)) return false;
  return (
    typeof value.id === "string" &&
    typeof value.title === "string" &&
    typeof value.icon === "string" &&
    typeof value.summary === "string" &&
    typeof value.primaryAction === "string" &&
    pageGroups.includes(value.group as PageGroup) &&
    ["connected-target", "local-workspace", "optional-ai"].includes(
      value.capability as CapabilityRequirement,
    ) &&
    ["ready", "pending"].includes(value.migrationState as MigrationState) &&
    isStringArray(value.sections, 32)
  );
}

export function isBootstrapResult(value: unknown): value is BootstrapResult {
  if (!isRecord(value)) return false;
  return (
    value.productName === "LovelyRes" &&
    typeof value.appVersion === "string" &&
    value.protocolVersion === BACKEND_PROTOCOL &&
    Array.isArray(value.pages) &&
    value.pages.length === 19 &&
    value.pages.every(isPageDescriptor) &&
    new Set(value.pages.map((page) => page.id)).size === value.pages.length &&
    isStringArray(value.securityReferenceFavoriteIds, 512)
  );
}

function isConnectionSummary(value: unknown): value is ConnectionSummary {
  if (!isRecord(value)) return false;
  return (
    hasExactKeys(value, [
      "id",
      "name",
      "host",
      "port",
      "username",
      "authMethod",
      "tags",
      "group",
      "environment",
      "lastConnectedAt",
      "hasPassword",
      "hasKeyPassphrase",
      "jumpHostHasPassword",
      "jumpHostHasKeyPassphrase",
    ]) &&
    isConnectionIdentity(value) &&
    isConnectionTags(value.tags) &&
    isNullableBoundedText(value.group, 256) &&
    isNullableBoundedText(value.environment, 256) &&
    (value.lastConnectedAt === null || isBoundedLabel(value.lastConnectedAt, 64)) &&
    typeof value.hasPassword === "boolean" &&
    typeof value.hasKeyPassphrase === "boolean" &&
    typeof value.jumpHostHasPassword === "boolean" &&
    typeof value.jumpHostHasKeyPassphrase === "boolean"
  );
}

export function isConnectionSummaryArray(value: unknown): value is ConnectionSummary[] {
  return Array.isArray(value) && value.length <= 1_000 && value.every(isConnectionSummary);
}

function isConnectionIdentity(value: JsonRecord): boolean {
  return (
    isConnectionId(value.id) &&
    isBoundedLabel(value.name, 256) &&
    isBoundedLabel(value.host, 253) &&
    isSafeInteger(value.port, 1, 65_535) &&
    isBoundedLabel(value.username, 32) &&
    isSshAuthMethod(value.authMethod)
  );
}

function isConnectionTags(value: unknown): value is string[] {
  return (
    Array.isArray(value) &&
    value.length <= 20 &&
    value.every((tag) => isBoundedLabel(tag, 64)) &&
    new Set(value).size === value.length
  );
}

function isJumpHostEditView(value: unknown): value is JumpHostEditView {
  if (!isRecord(value)) return false;
  return (
    hasExactKeys(value, [
      "host",
      "port",
      "username",
      "authMethod",
      "privateKeyPath",
      "certificatePath",
      "agentIdentityFingerprint",
      "hostKeyFingerprint",
    ]) &&
    isBoundedLabel(value.host, 253) &&
    isSafeInteger(value.port, 1, 65_535) &&
    isBoundedLabel(value.username, 32) &&
    isSshAuthMethod(value.authMethod) &&
    isNullablePath(value.privateKeyPath) &&
    isNullablePath(value.certificatePath) &&
    isNullableFingerprint(value.agentIdentityFingerprint) &&
    isNullableFingerprint(value.hostKeyFingerprint)
  );
}

export function isConnectionEditView(value: unknown): value is ConnectionEditView {
  if (!isRecord(value)) return false;
  return (
    hasExactKeys(value, [
      "id",
      "name",
      "host",
      "port",
      "username",
      "authMethod",
      "privateKeyPath",
      "certificatePath",
      "agentIdentityFingerprint",
      "jumpHost",
      "tags",
      "notes",
      "environment",
      "role",
      "group",
      "hostKeyFingerprint",
      "hasPassword",
      "hasKeyPassphrase",
      "jumpHostHasPassword",
      "jumpHostHasKeyPassphrase",
      "lastConnectedAt",
    ]) &&
    isConnectionIdentity(value) &&
    isNullablePath(value.privateKeyPath) &&
    isNullablePath(value.certificatePath) &&
    isNullableFingerprint(value.agentIdentityFingerprint) &&
    (value.jumpHost === null || isJumpHostEditView(value.jumpHost)) &&
    isConnectionTags(value.tags) &&
    isNullableBoundedText(value.notes, 16 * 1_024, true) &&
    isNullableBoundedText(value.environment, 256) &&
    isNullableBoundedText(value.role, 256) &&
    isNullableBoundedText(value.group, 256) &&
    isNullableFingerprint(value.hostKeyFingerprint) &&
    typeof value.hasPassword === "boolean" &&
    typeof value.hasKeyPassphrase === "boolean" &&
    typeof value.jumpHostHasPassword === "boolean" &&
    typeof value.jumpHostHasKeyPassphrase === "boolean" &&
    (value.lastConnectedAt === null || isBoundedLabel(value.lastConnectedAt, 64))
  );
}

function isJumpHostDraftInput(value: unknown): value is JumpHostDraftInput {
  if (!isRecord(value)) return false;
  return (
    hasExactKeys(value, [
      "host",
      "port",
      "username",
      "authMethod",
      "privateKeyPath",
      "certificatePath",
      "agentIdentityFingerprint",
    ]) &&
    isBoundedLabel(value.host, 253) &&
    isSafeInteger(value.port, 1, 65_535) &&
    isBoundedLabel(value.username, 32) &&
    isSshAuthMethod(value.authMethod) &&
    isNullablePath(value.privateKeyPath) &&
    isNullablePath(value.certificatePath) &&
    isNullableFingerprint(value.agentIdentityFingerprint) &&
    authFieldsMatch(
      value.authMethod,
      value.privateKeyPath,
      value.certificatePath,
      value.agentIdentityFingerprint,
    )
  );
}

function authFieldsMatch(
  authMethod: SshAuthMethod,
  privateKeyPath: string | null,
  certificatePath: string | null,
  agentIdentityFingerprint: string | null,
): boolean {
  switch (authMethod) {
    case "password":
    case "keyboard-interactive":
      return (
        privateKeyPath === null &&
        certificatePath === null &&
        agentIdentityFingerprint === null
      );
    case "public-key":
      return (
        privateKeyPath !== null &&
        certificatePath === null &&
        agentIdentityFingerprint === null
      );
    case "agent":
      return privateKeyPath === null && certificatePath === null;
    case "certificate":
      return (
        privateKeyPath !== null &&
        certificatePath !== null &&
        agentIdentityFingerprint === null
      );
  }
}

function isSecretWrite(value: unknown): value is SecretWrite {
  if (!isRecord(value) || typeof value.action !== "string") return false;
  if (value.action === "keep" || value.action === "remove") {
    return hasExactKeys(value, ["action"]);
  }
  return (
    value.action === "replace" &&
    hasExactKeys(value, ["action", "value"]) &&
    isUtf8BoundedString(value.value, 16 * 1_024) &&
    value.value.length > 0
  );
}

function isConnectionSecretWrites(value: unknown): value is ConnectionSecretWrites {
  if (!isRecord(value)) return false;
  const keys = [
    "password",
    "keyPassphrase",
    "jumpHostPassword",
    "jumpHostKeyPassphrase",
  ] as const;
  return (
    hasOnlyKeys(value, keys) &&
    keys.every((key) => value[key] === undefined || isSecretWrite(value[key]))
  );
}

function isConnectionDraftInput(value: unknown): value is ConnectionDraftInput {
  if (!isRecord(value)) return false;
  return (
    hasExactKeys(value, [
      "id",
      "name",
      "host",
      "port",
      "username",
      "authMethod",
      "privateKeyPath",
      "certificatePath",
      "agentIdentityFingerprint",
      "jumpHost",
      "tags",
      "notes",
      "environment",
      "role",
      "group",
    ]) &&
    isConnectionIdentity(value) &&
    isNullablePath(value.privateKeyPath) &&
    isNullablePath(value.certificatePath) &&
    isNullableFingerprint(value.agentIdentityFingerprint) &&
    authFieldsMatch(
      value.authMethod as SshAuthMethod,
      value.privateKeyPath,
      value.certificatePath,
      value.agentIdentityFingerprint,
    ) &&
    (value.jumpHost === null || isJumpHostDraftInput(value.jumpHost)) &&
    isConnectionTags(value.tags) &&
    isNullableBoundedText(value.notes, 16 * 1_024, true) &&
    isNullableBoundedText(value.environment, 256) &&
    isNullableBoundedText(value.role, 256) &&
    isNullableBoundedText(value.group, 256)
  );
}

export function isConnectionWriteInput(value: unknown): value is ConnectionWriteInput {
  if (!isRecord(value)) return false;
  return (
    hasOnlyKeys(value, ["connection", "secrets"]) &&
    Object.hasOwn(value, "connection") &&
    isConnectionDraftInput(value.connection) &&
    (value.secrets === undefined || isConnectionSecretWrites(value.secrets))
  );
}

export function isConnectionId(value: unknown): value is string {
  return isBoundedLabel(value, 128);
}

export function isConnectionDeleteHandle(value: unknown): value is string {
  return (
    isUtf8BoundedString(value, 128) &&
    value.length > 0 &&
    /^[A-Za-z0-9-]+$/u.test(value)
  );
}

export function isConnectionDeletePrompt(value: unknown): value is ConnectionDeletePrompt {
  if (!isRecord(value)) return false;
  return (
    hasExactKeys(value, [
      "handle",
      "connectionId",
      "connectionName",
      "confirmationText",
    ]) &&
    isConnectionDeleteHandle(value.handle) &&
    isConnectionId(value.connectionId) &&
    isBoundedLabel(value.connectionName, 256) &&
    isBoundedLabel(value.confirmationText, 2_048)
  );
}

export function isConnectionDeleteResult(value: unknown): value is ConnectionDeleteResult {
  if (!isRecord(value)) return false;
  return (
    hasExactKeys(value, ["operationId", "verified", "verificationDetail"]) &&
    isBoundedLabel(value.operationId, 128) &&
    typeof value.verified === "boolean" &&
    isUtf8BoundedString(value.verificationDetail, 4_096)
  );
}

export function isConnectionDeleteCancellation(
  value: unknown,
): value is ConnectionDeleteCancellation {
  return isRecord(value) && hasExactKeys(value, ["cancelled"]) && value.cancelled === true;
}

export function isInternalConnectionImportResult(
  value: unknown,
): value is InternalConnectionImportResult {
  return (
    isRecord(value) &&
    hasExactKeys(value, ["imported", "skippedExisting", "skippedDuplicate"]) &&
    isSafeInteger(value.imported, 0, 1_000) &&
    isSafeInteger(value.skippedExisting, 0, 1_000) &&
    isSafeInteger(value.skippedDuplicate, 0, 1_000)
  );
}

export function isConnectionImportResult(value: unknown): value is ConnectionImportResult {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["cancelled", "imported", "skippedExisting", "skippedDuplicate"]) ||
    typeof value.cancelled !== "boolean" ||
    !isSafeInteger(value.imported, 0, 1_000) ||
    !isSafeInteger(value.skippedExisting, 0, 1_000) ||
    !isSafeInteger(value.skippedDuplicate, 0, 1_000)
  ) {
    return false;
  }
  return (
    !value.cancelled ||
    (value.imported === 0 && value.skippedExisting === 0 && value.skippedDuplicate === 0)
  );
}

export function isInternalConnectionExportResult(
  value: unknown,
): value is InternalConnectionExportResult {
  return (
    isRecord(value) &&
    hasExactKeys(value, ["count"]) &&
    isSafeInteger(value.count, 0, 1_000)
  );
}

function isConnectionExportFileName(value: unknown): value is string {
  return (
    isUtf8BoundedString(value, 512) &&
    value.trim().length > 0 &&
    !value.includes("/") &&
    !value.includes("\\") &&
    !hasUnsupportedControl(value)
  );
}

export function isConnectionExportResult(value: unknown): value is ConnectionExportResult {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["cancelled", "count", "fileName"]) ||
    typeof value.cancelled !== "boolean" ||
    !isSafeInteger(value.count, 0, 1_000) ||
    (value.fileName !== null && !isConnectionExportFileName(value.fileName))
  ) {
    return false;
  }
  return value.cancelled
    ? value.count === 0 && value.fileName === null
    : value.fileName !== null;
}

export function isSecurityReferenceFavoritesResult(
  value: unknown,
): value is SecurityReferenceFavoritesResult {
  return isRecord(value) && isStringArray(value.favoriteIds, 512);
}

function isSafeInteger(value: unknown, minimum: number, maximum: number): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= minimum &&
    value <= maximum
  );
}

function isNoteSummary(value: unknown): value is NoteSummary {
    if (!isRecord(value)) return false;
    return (
    hasExactKeys(value, ["id", "title", "contentPreview", "contentTruncated", "tags", "createdAt", "updatedAt", "pinned", "revision"]) &&
    isUtf8BoundedString(value.id, 128) &&
    isUtf8BoundedString(value.title, 1_024) &&
    isUtf8BoundedString(value.contentPreview, 1_024) &&
    typeof value.contentTruncated === "boolean" &&
    isStringArray(value.tags, 32) &&
    isSafeInteger(value.createdAt, 0, Number.MAX_SAFE_INTEGER) &&
    isSafeInteger(value.updatedAt, 0, Number.MAX_SAFE_INTEGER) &&
    typeof value.pinned === "boolean" &&
    isRevision(value.revision)
  );
}

export function isNoteListPage(value: unknown): value is NoteListPage {
  if (!isRecord(value)) return false;
  return (
    hasExactKeys(value, ["total", "offset", "hasMore", "items"]) &&
    isSafeInteger(value.total, 0, 1_000) &&
    isSafeInteger(value.offset, 0, 100_000) &&
    typeof value.hasMore === "boolean" &&
    Array.isArray(value.items) &&
    value.items.length <= 100 &&
    value.items.every(isNoteSummary)
  );
}

export function isNoteResult(value: unknown): value is NoteResult {
  if (!isRecord(value)) return false;
  return (
    hasExactKeys(value, ["id", "title", "content", "tags", "createdAt", "updatedAt", "pinned", "revision"]) &&
    isUtf8BoundedString(value.id, 128) &&
    isUtf8BoundedString(value.title, 1_024) &&
    isUtf8BoundedString(value.content, 4 * 1_048_576) &&
    isStringArray(value.tags, 32) &&
    isSafeInteger(value.createdAt, 0, Number.MAX_SAFE_INTEGER) &&
    isSafeInteger(value.updatedAt, 0, Number.MAX_SAFE_INTEGER) &&
    typeof value.pinned === "boolean" &&
    isRevision(value.revision)
  );
}

export function isNoteDeleteProposal(value: unknown): value is NoteDeleteProposal {
  if (!isRecord(value)) return false;
  return (
    hasExactKeys(value, ["handle", "summary", "expiresInSeconds"]) &&
    typeof value.handle === "string" &&
    value.handle.length > 0 &&
    value.handle.length <= 128 &&
    typeof value.summary === "string" &&
    value.summary.length > 0 &&
    value.summary.length <= 2_048 &&
    isSafeInteger(value.expiresInSeconds, 1, 3_600)
  );
}

export function isNoteDeleteResult(value: unknown): value is NoteDeleteResult {
  if (!isRecord(value)) return false;
  return (
    hasExactKeys(value, ["noteId", "affectedRecords", "verified"]) &&
    isUtf8BoundedString(value.noteId, 128) &&
    isSafeInteger(value.affectedRecords, 1, 1) &&
    value.verified === true
  );
}

export function isNoteDeleteCancellation(value: unknown): value is NoteDeleteCancellation {
  return isRecord(value) && hasExactKeys(value, ["cancelled"]) && value.cancelled === true;
}

export function isNotesTextExport(value: unknown): value is NotesTextExport {
  if (!isRecord(value)) return false;
  return (
    hasExactKeys(value, ["noteCount", "text"]) &&
    isSafeInteger(value.noteCount, 0, 1_000) &&
    typeof value.text === "string" &&
    isUtf8BoundedString(value.text, 120 * 1_024)
  );
}

function isRevision(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/u.test(value);
}
