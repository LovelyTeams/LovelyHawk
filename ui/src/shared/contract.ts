import type { WindowsRdpRequest, WindowsRdpStatus } from "./windows-rdp-contract.js";
import type { JavaClassStageResult, JavaHotUpdateRequest, JavaHotUpdateResponse } from "./java-hot-update-contract.js";
import type { WindowsFileSaveResult, WindowsIncidentRequest, WindowsIncidentResponse } from "./windows-incident-contract.js";
import type { NginxRepairRequest, NginxRepairResponse } from "./nginx-repair-contract.js";
import type { LogRulesRequest, LogRulesResponse } from "./log-rules-contract.js";
import type { AiAssistRequest, AiAssistResponse } from "./ai-assist-contract.js";
import type { PostgresqlRuntimeRequest, PostgresqlRuntimeResponse } from "./postgresql-runtime-contract.js";
import type { FileEvidenceRequest, FileEvidenceResult } from "./file-evidence-contract.js";
import type { PacketCaptureEvidenceRequest, PacketCaptureEvidenceResult } from "./packet-capture-evidence-contract.js";
import type { PodFileEvidenceRequest, PodFileEvidenceResult } from "./pod-file-evidence-contract.js";
import type { ConfigVisualAnswer, ConfigVisualCopyResult, ConfigVisualProduct, ConfigVisualRequest, ConfigVisualSaveResult, ConfigVisualView } from "./config-visual-contract.js";
import type { CaseWorkspaceRequest, CaseWorkspaceResult } from "./case-workspace-contract.js";
import type { CaseLibraryRequest, CaseLibraryResult } from "./case-library-contract.js";
import type { ExecDirectoryListing, PodFile } from "./exec-files-contract.js";
import type { DockerContainerChanges, DockerContainerProcesses } from "./docker-forensics-contract.js";
import type {
  ConfigBundleExportResult,
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
  SystemInfoRowActions,
  SystemInfoRowInspection,
  SystemInfoRowPlan,
  SystemInfoRowReceipt,
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
  BaselineCatalog,
  BaselineFile,
  BaselineHistory,
  BaselineScan,
} from "./baseline-read-contract.js";
import type {
  BaselineAction,
  BaselineActionCancellation,
  BaselinePlan,
  BaselineReceipt,
} from "./baseline-write-contract.js";
import type {
  CheckAuditCatalog,
  CheckAuditCatalogInput,
  CheckAuditLogInput,
  CheckAuditLogResult,
  CheckAuditStatus,
} from "./check-audit-read-contract.js";
import type {
  CheckAuditAction,
  CheckAuditActionCancellation,
  CheckAuditPlan,
  CheckAuditReceipt,
} from "./check-audit-write-contract.js";
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
  KubernetesManifestExportResult,
  KubernetesSnapshot,
  KubernetesTextResult,
} from "./kubernetes-read-contract.js";
import type {
  KubernetesActionCancellation,
  KubernetesActionPlan,
  KubernetesActionReceipt,
  KubernetesWriteAction,
} from "./kubernetes-write-contract.js";
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
  DockerActionCancellation,
  DockerActionPlan,
  DockerActionReceipt,
  DockerContainerFile,
  DockerFileCopyDirection,
  DockerWriteAction,
} from "./docker-write-contract.js";
import type {
  EmergencyCommandCatalog,
  EmergencyCommandResult,
  EmergencyPathAction,
  EmergencyPathDetail,
  EmergencyPathPlan,
  EmergencyPathReceipt,
  EmergencyPathUndoResult,
  EmergencyHistoryLocation,
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
  IntegrityCreationCancellation,
  IntegrityCreationPoll,
  IntegrityCreationStarted,
  IntegrityPresetCatalog,
  IntegrityPresetId,
} from "./integrity-contract.js";

export * from "./config-contract.js";
export * from "./ssh-contract.js";
export * from "./system-info-contract.js";
export * from "./settings-contract.js";
export * from "./ai-history-contract.js";
export * from "./command-history-contract.js";
export * from "./disposal-report-contract.js";
export * from "./terminal-contract.js";
export * from "./baseline-read-contract.js";
export * from "./baseline-write-contract.js";
export * from "./check-audit-read-contract.js";
export * from "./check-audit-write-contract.js";
export * from "./log-analysis-read-contract.js";
export * from "./kubernetes-read-contract.js";
export * from "./kubernetes-write-contract.js";
export * from "./docker-read-contract.js";
export * from "./docker-write-contract.js";
export * from "./emergency-command-contract.js";
export * from "./sftp-browser-contract.js";
export * from "./local-browser-contract.js";
export * from "./packet-capture-live-contract.js";
export * from "./application-log-contract.js";
export * from "./integrity-contract.js";

export const BACKEND_PROTOCOL = "lovelyhawk-backend/v1" as const;

export const pageGroups = [
  "target",
  "triage",
  "investigation",
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

/** Which credential file the editor asks the system file dialog for. */
export type ConnectionCredentialFileKind = "private-key" | "certificate";

/** The chosen path, or `null` when the dialog was cancelled. */
export interface ConnectionCredentialFileChoice {
  path: string | null;
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

export interface LovelyHawkApi {
  caseLibrary(request: CaseLibraryRequest): Promise<CaseLibraryResult | null>;
  caseWorkspace(request: CaseWorkspaceRequest): Promise<CaseWorkspaceResult>;
  postgresqlRuntime(request: PostgresqlRuntimeRequest): Promise<PostgresqlRuntimeResponse>;
  fileEvidence(request: FileEvidenceRequest): Promise<FileEvidenceResult | null>;
  packetCaptureEvidence(request: PacketCaptureEvidenceRequest): Promise<PacketCaptureEvidenceResult | null>;
  podFileEvidence(request: PodFileEvidenceRequest): Promise<PodFileEvidenceResult | null>;
  nginxRepair(request: NginxRepairRequest): Promise<NginxRepairResponse>;
  /** The operator's own log match rules; local only, nothing reaches a target. */
  logRules(request: LogRulesRequest): Promise<LogRulesResponse>;
  /** Asks a configured AI provider to read what a page holds; only on the operator's request. */
  aiAssist(request: AiAssistRequest): Promise<AiAssistResponse>;
  javaHotUpdate(request: JavaHotUpdateRequest): Promise<JavaHotUpdateResponse>;
  stageJavaClass(bindingHandle: string): Promise<JavaClassStageResult>;
  windowsRdp(request: WindowsRdpRequest): Promise<WindowsRdpStatus>;
  readonly windowsChannel: import("./windows-channel-contract").WindowsChannelOwnerApi;
  windowsIncident(request: WindowsIncidentRequest): Promise<WindowsIncidentResponse>;
  saveWindowsFile(fileId: string): Promise<WindowsFileSaveResult>;
  bootstrap(): Promise<BootstrapResult>;
  appUpdate(request: import("./update-contract").AppUpdateRequest): Promise<import("./update-contract").AppUpdateResponse>;
  listConnections(): Promise<ConnectionSummary[]>;
  getConnection(id: string): Promise<ConnectionEditView>;
  createConnection(input: ConnectionWriteInput): Promise<ConnectionEditView>;
  updateConnection(input: ConnectionWriteInput): Promise<ConnectionEditView>;
  planConnectionDelete(id: string): Promise<ConnectionDeletePrompt>;
  confirmConnectionDelete(handle: string): Promise<ConnectionDeleteResult>;
  cancelConnectionDelete(handle: string): Promise<ConnectionDeleteCancellation>;
  importConnections(): Promise<ConnectionImportResult>;
  exportConnections(): Promise<ConnectionExportResult>;
  chooseConnectionCredentialFile(kind: ConnectionCredentialFileKind): Promise<ConnectionCredentialFileChoice>;
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
  openSystemInfoFile(bindingHandle: string, snapshotHandle: string, rowId: string): Promise<TerminalWindowLaunchResult>;
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
  /**
   * The right-click menu for one row. The sidecar decides which of its fixed
   * actions apply from the row it kept; the window only ever names a row.
   */
  listSystemInfoRowActions(
    bindingHandle: string,
    snapshotHandle: string,
    rowId: string,
  ): Promise<SystemInfoRowActions>;
  inspectSystemInfoRow(
    bindingHandle: string,
    snapshotHandle: string,
    rowId: string,
    action: string,
  ): Promise<SystemInfoRowInspection>;
  planSystemInfoRowAction(
    bindingHandle: string,
    snapshotHandle: string,
    rowId: string,
    action: string,
  ): Promise<SystemInfoRowPlan>;
  confirmSystemInfoRowAction(bindingHandle: string, planHandle: string): Promise<SystemInfoRowPlan>;
  executeSystemInfoRowAction(
    bindingHandle: string,
    planHandle: string,
  ): Promise<SystemInfoRowReceipt>;
  cancelSystemInfoRowAction(bindingHandle: string, planHandle: string): Promise<void>;
  getBaselineCatalog(): Promise<BaselineCatalog>;
  scanBaseline(bindingHandle: string): Promise<BaselineScan>;
  listBaselineHistory(bindingHandle: string): Promise<BaselineHistory>;
  readBaselineFile(bindingHandle: string, itemHandle: string): Promise<BaselineFile>;
  planBaselineAction(bindingHandle: string, action: BaselineAction): Promise<BaselinePlan>;
  confirmBaselineAction(bindingHandle: string, planHandle: string): Promise<BaselinePlan>;
  executeBaselineAction(bindingHandle: string, planHandle: string): Promise<BaselineReceipt>;
  cancelBaselineAction(bindingHandle: string, planHandle: string): Promise<BaselineActionCancellation>;
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
  planCheckAuditAction(
    bindingHandle: string,
    snapshotHandle: string,
    action: CheckAuditAction,
  ): Promise<CheckAuditPlan>;
  confirmCheckAuditAction(bindingHandle: string, planHandle: string): Promise<CheckAuditPlan>;
  executeCheckAuditAction(bindingHandle: string, planHandle: string): Promise<CheckAuditReceipt>;
  cancelCheckAuditAction(bindingHandle: string, planHandle: string): Promise<CheckAuditActionCancellation>;
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
    previous: boolean,
    /** One of the pod's containers; null for its default one. */
    container: string | null,
  ): Promise<KubernetesTextResult>;
  planKubernetesWorkloadAction(
    bindingHandle: string,
    snapshotHandle: string,
    rowHandle: string,
    resourceName: string,
    action: KubernetesWriteAction,
  ): Promise<KubernetesActionPlan>;
  confirmKubernetesWorkloadAction(
    bindingHandle: string,
    planHandle: string,
  ): Promise<KubernetesActionPlan>;
  executeKubernetesWorkloadAction(
    bindingHandle: string,
    planHandle: string,
  ): Promise<KubernetesActionReceipt>;
  cancelKubernetesWorkloadAction(
    bindingHandle: string,
    planHandle: string,
  ): Promise<KubernetesActionCancellation>;
  /** What a listed container changed relative to its image (`docker diff`). */
  getDockerContainerChanges(
    bindingHandle: string,
    snapshotHandle: string,
    containerHandle: string,
  ): Promise<DockerContainerChanges>;
  /** The processes in a listed, running container (`docker top`). */
  getDockerContainerProcesses(
    bindingHandle: string,
    snapshotHandle: string,
    containerHandle: string,
  ): Promise<DockerContainerProcesses>;
  /** One directory inside a listed container, by the snapshot's handle. */
  listDockerContainerDirectory(
    bindingHandle: string,
    snapshotHandle: string,
    containerHandle: string,
    path: string,
  ): Promise<ExecDirectoryListing>;
  /** One directory inside a listed pod's container (null: its default one). */
  listKubernetesPodDirectory(
    bindingHandle: string,
    snapshotHandle: string,
    rowHandle: string,
    path: string,
    container: string | null,
  ): Promise<ExecDirectoryListing>;
  /** One text file inside a listed pod, read-only, checked against its length and digest. */
  readKubernetesPodFile(
    bindingHandle: string,
    snapshotHandle: string,
    rowHandle: string,
    path: string,
    container: string | null,
  ): Promise<PodFile>;
  /** A terminal window with a shell in a listed pod; see openDockerContainerTerminal. */
  openKubernetesPodTerminal(
    snapshotHandle: string,
    rowHandle: string,
    podName: string,
    /** One of the pod's containers; null for its default one. */
    container: string | null,
  ): Promise<TerminalWindowLaunchResult>;
  /**
   * A listed Pod, Deployment or Node's live manifest (YAML) into a new file
   * the host asks where to put. The page never sees the contents.
   */
  exportKubernetesManifest(
    bindingHandle: string,
    snapshotHandle: string,
    rowHandle: string,
  ): Promise<KubernetesManifestExportResult>;
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
  planDockerContainerAction(
    bindingHandle: string,
    snapshotHandle: string,
    containerHandle: string,
    containerName: string,
    action: DockerWriteAction,
  ): Promise<DockerActionPlan>;
  confirmDockerContainerAction(
    bindingHandle: string,
    planHandle: string,
  ): Promise<DockerActionPlan>;
  executeDockerContainerAction(
    bindingHandle: string,
    planHandle: string,
  ): Promise<DockerActionReceipt>;
  cancelDockerContainerAction(
    bindingHandle: string,
    planHandle: string,
  ): Promise<DockerActionCancellation>;
  readDockerContainerFile(
    bindingHandle: string,
    snapshotHandle: string,
    containerHandle: string,
    containerName: string,
    path: string,
  ): Promise<DockerContainerFile>;
  planDockerFileWrite(bindingHandle: string, fileHandle: string, text: string): Promise<DockerActionPlan>;
  planDockerFileCopy(
    bindingHandle: string,
    snapshotHandle: string,
    containerHandle: string,
    containerName: string,
    direction: DockerFileCopyDirection,
    source: string,
    target: string,
  ): Promise<DockerActionPlan>;
  /**
   * Open a terminal window with a shell inside a listed container.
   *
   * No binding handle: the window is opened against whatever target is current,
   * the same way the host terminal is. The name is display only — the window's
   * own title bar is the only thing that reads it.
   */
  openDockerContainerTerminal(
    snapshotHandle: string,
    containerHandle: string,
    containerName: string,
  ): Promise<TerminalWindowLaunchResult>;
  loadEmergencyCommandCatalog(bindingHandle: string): Promise<EmergencyCommandCatalog>;
  runEmergencyCommand(
    bindingHandle: string,
    snapshotHandle: string,
    commandHandle: string,
    /** Absent runs it on the target; present runs it inside that container. */
    containerHandle?: string,
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
  undoEmergencyPathAction(bindingHandle: string, planHandle: string): Promise<EmergencyPathUndoResult>;
  locateEmergencyHistoryCommand(
    bindingHandle: string,
    snapshotHandle: string,
    historyId: string,
  ): Promise<EmergencyHistoryLocation>;
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
  startIntegrityBaselineCreation(
    bindingHandle: string,
    presetIds: readonly IntegrityPresetId[],
  ): Promise<IntegrityCreationStarted>;
  pollIntegrityBaselineCreation(bindingHandle: string, operationHandle: string): Promise<IntegrityCreationPoll>;
  cancelIntegrityBaselineCreation(
    bindingHandle: string,
    operationHandle: string,
  ): Promise<IntegrityCreationCancellation>;
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
  /** Every file of a multi-file draft into one new folder; the host asks where. */
  exportConfigBundle(handle: string, revision: number): Promise<ConfigBundleExportResult>;
  closeConfigDraft(handle: string, revision: number): Promise<ConfigClosedResult>;
  configVisual(request: ConfigVisualRequest): Promise<ConfigVisualAnswer>;
  importConfigVisual(product: ConfigVisualProduct): Promise<ConfigVisualView | null>;
  importConfigVisualDatabase(artifactKey: string): Promise<ConfigVisualView | null>;
  copyConfigVisual(documentHandle: string, revision: number): Promise<ConfigVisualCopyResult>;
  saveConfigVisual(documentHandle: string, revision: number): Promise<ConfigVisualSaveResult>;
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
  /**
   * Answers the host's close question. Closing the main window closes every
   * editor window too, so the handler is told how many hold unsaved text.
   */
  onBeforeClose(handler: (context: BeforeCloseContext) => Promise<boolean>): () => void;
  /** Editor windows holding unsaved text; disconnecting closes them. */
  unsavedEditorCount(): Promise<number>;
  notifyRendererReady(): void;
}

export interface BeforeCloseContext {
  unsavedEditors: number;
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
    value.productName === "LovelyHawk" &&
    typeof value.appVersion === "string" &&
    value.protocolVersion === BACKEND_PROTOCOL &&
    Array.isArray(value.pages) &&
    value.pages.length === 14 &&
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

export function isConnectionCredentialFileKind(value: unknown): value is ConnectionCredentialFileKind {
  return value === "private-key" || value === "certificate";
}

export function isConnectionCredentialFileChoice(value: unknown): value is ConnectionCredentialFileChoice {
  return isRecord(value) && hasExactKeys(value, ["path"]) && isNullablePath(value.path);
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
