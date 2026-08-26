import { contextBridge, ipcRenderer } from "electron";

import type {
  AiHistoryExportFormat,
  ApplicationLogFilter,
  ApplicationLogLevel,
  CheckAuditCatalogInput,
  CheckAuditLogInput,
  DockerCollectionKind,
  DockerResourceKind,
  EmergencyPathAction,
  LogCorrelationInput,
  LogIocSearchInput,
  LogSourceReadInput,
  KubernetesListInput,
  ConfigGenerateInput,
  ConnectionWriteInput,
  DisposalReportExportFormat,
  DisposalReportPreviewFormat,
  LovelyResApi,
  NoteCreateInput,
  NoteUpdateInput,
  PacketCaptureStartInput,
  SettingsAiApiKeyReplacementInput,
  SettingsSaveInput,
  SnapshotDiffInput,
  SystemInfoTabKey,
  WindowThemeInput,
} from "../shared/contract.js";

const api: LovelyResApi = Object.freeze({
  bootstrap: () => ipcRenderer.invoke("lovelyres:bootstrap"),
  listConnections: () => ipcRenderer.invoke("lovelyres:connections:list"),
  getConnection: (id: string) => ipcRenderer.invoke("lovelyres:connections:get", id),
  createConnection: (input: ConnectionWriteInput) =>
    ipcRenderer.invoke("lovelyres:connections:create", input),
  updateConnection: (input: ConnectionWriteInput) =>
    ipcRenderer.invoke("lovelyres:connections:update", input),
  planConnectionDelete: (id: string) =>
    ipcRenderer.invoke("lovelyres:connections:delete:plan", id),
  confirmConnectionDelete: (handle: string) =>
    ipcRenderer.invoke("lovelyres:connections:delete:confirm", handle),
  cancelConnectionDelete: (handle: string) =>
    ipcRenderer.invoke("lovelyres:connections:delete:cancel", handle),
  importConnections: () => ipcRenderer.invoke("lovelyres:connections:import"),
  exportConnections: () => ipcRenderer.invoke("lovelyres:connections:export"),
  startSshConnect: (connectionId: string) =>
    ipcRenderer.invoke("lovelyres:ssh:connect:start", connectionId),
  startSshProbe: (input: ConnectionWriteInput) =>
    ipcRenderer.invoke("lovelyres:ssh:probe:start", input),
  getSshAttempt: (attemptHandle: string) =>
    ipcRenderer.invoke("lovelyres:ssh:attempt:get", attemptHandle),
  confirmSshHostKey: (attemptHandle: string, promptHandle: string) =>
    ipcRenderer.invoke("lovelyres:ssh:host-key:confirm", { attemptHandle, promptHandle }),
  respondSshMfa: (attemptHandle: string, promptHandle: string, responses: string[]) =>
    ipcRenderer.invoke("lovelyres:ssh:mfa:respond", {
      attemptHandle,
      promptHandle,
      responses,
    }),
  cancelSshAttempt: (attemptHandle: string) =>
    ipcRenderer.invoke("lovelyres:ssh:attempt:cancel", attemptHandle),
  disconnectSshBinding: (bindingHandle: string) =>
    ipcRenderer.invoke("lovelyres:ssh:binding:disconnect", bindingHandle),
  openSshTerminal: () => ipcRenderer.invoke("lovelyres:terminal-window:open"),
  getSystemInfoCatalog: () => ipcRenderer.invoke("lovelyres:system-info:catalog:get"),
  getSystemInfoSummary: (bindingHandle: string) =>
    ipcRenderer.invoke("lovelyres:system-info:summary:get", bindingHandle),
  collectSystemInfo: (bindingHandle: string, tab: SystemInfoTabKey, maximumRows: number) =>
    ipcRenderer.invoke("lovelyres:system-info:table:collect", {
      bindingHandle,
      tab,
      maximumRows,
    }),
  getSystemInfoDetail: (bindingHandle: string, snapshotHandle: string, rowId: string) =>
    ipcRenderer.invoke("lovelyres:system-info:detail:get", {
      bindingHandle,
      snapshotHandle,
      rowId,
    }),
  listSnapshots: (bindingHandle: string) =>
    ipcRenderer.invoke("lovelyres:snapshot:list", bindingHandle),
  getSnapshotDetail: (bindingHandle: string, snapshotHandle: string) =>
    ipcRenderer.invoke("lovelyres:snapshot:detail:get", { bindingHandle, snapshotHandle }),
  diffForensicSnapshots: (bindingHandle: string, input: SnapshotDiffInput) =>
    ipcRenderer.invoke("lovelyres:snapshot:forensic:diff", { bindingHandle, input }),
  inspectFirewall: (bindingHandle: string) =>
    ipcRenderer.invoke("lovelyres:firewall:inspect", bindingHandle),
  listFirewallChangeHistory: (bindingHandle: string) =>
    ipcRenderer.invoke("lovelyres:firewall:change-history:list", bindingHandle),
  getBaselineCatalog: () => ipcRenderer.invoke("lovelyres:baseline:catalog:get"),
  scanBaseline: (bindingHandle: string) =>
    ipcRenderer.invoke("lovelyres:baseline:scan", bindingHandle),
  listBaselineHistory: (bindingHandle: string) =>
    ipcRenderer.invoke("lovelyres:baseline:history:list", bindingHandle),
  discoverMiddleware: (bindingHandle: string) =>
    ipcRenderer.invoke("lovelyres:middleware:discover", bindingHandle),
  loadMiddlewareConfiguration: (
    bindingHandle: string,
    discoveryHandle: string,
    instanceHandle: string,
  ) => ipcRenderer.invoke("lovelyres:middleware:configuration:load", {
    bindingHandle,
    discoveryHandle,
    instanceHandle,
  }),
  listMiddlewareHistory: (bindingHandle: string) =>
    ipcRenderer.invoke("lovelyres:middleware:history:list", bindingHandle),
  getCheckAuditCatalog: (bindingHandle: string, input: CheckAuditCatalogInput) =>
    ipcRenderer.invoke("lovelyres:check-audit:catalog:get", { bindingHandle, input }),
  collectCheckAuditStatus: (bindingHandle: string, snapshotHandle: string) =>
    ipcRenderer.invoke("lovelyres:check-audit:status:collect", {
      bindingHandle,
      snapshotHandle,
    }),
  readCheckAuditLog: (
    bindingHandle: string,
    snapshotHandle: string,
    input: CheckAuditLogInput,
  ) => ipcRenderer.invoke("lovelyres:check-audit:log:read", {
    bindingHandle,
    snapshotHandle,
    input,
  }),
  discoverLogSources: (bindingHandle: string) =>
    ipcRenderer.invoke("lovelyres:log-analysis:sources:discover", bindingHandle),
  readLogSource: (
    bindingHandle: string,
    snapshotHandle: string,
    sourceHandle: string,
    input: LogSourceReadInput,
  ) => ipcRenderer.invoke("lovelyres:log-analysis:source:read", {
    bindingHandle,
    snapshotHandle,
    sourceHandle,
    input,
  }),
  correlateLogSources: (
    bindingHandle: string,
    snapshotHandle: string,
    input: LogCorrelationInput,
  ) => ipcRenderer.invoke("lovelyres:log-analysis:sources:correlate", {
    bindingHandle,
    snapshotHandle,
    input,
  }),
  searchLogIocs: (
    bindingHandle: string,
    snapshotHandle: string,
    input: LogIocSearchInput,
  ) => ipcRenderer.invoke("lovelyres:log-analysis:iocs:search", {
    bindingHandle,
    snapshotHandle,
    input,
  }),
  getKubernetesAvailability: (bindingHandle: string) =>
    ipcRenderer.invoke("lovelyres:kubernetes:availability:get", bindingHandle),
  listKubernetesResources: (bindingHandle: string, input: KubernetesListInput) =>
    ipcRenderer.invoke("lovelyres:kubernetes:resources:list", { bindingHandle, input }),
  getKubernetesResourceDetail: (
    bindingHandle: string,
    snapshotHandle: string,
    rowHandle: string,
  ) => ipcRenderer.invoke("lovelyres:kubernetes:resource:detail:get", {
    bindingHandle,
    snapshotHandle,
    rowHandle,
  }),
  getKubernetesPodLogs: (
    bindingHandle: string,
    snapshotHandle: string,
    rowHandle: string,
  ) => ipcRenderer.invoke("lovelyres:kubernetes:pod:logs:get", {
    bindingHandle,
    snapshotHandle,
    rowHandle,
  }),
  refreshDockerContainers: (bindingHandle: string) =>
    ipcRenderer.invoke("lovelyres:docker:containers:refresh", { bindingHandle }),
  getDockerCollection: (
    bindingHandle: string,
    snapshotHandle: string,
    kind: DockerCollectionKind,
  ) => ipcRenderer.invoke("lovelyres:docker:collection:get", {
    bindingHandle,
    snapshotHandle,
    kind,
  }),
  inspectDockerResource: (
    bindingHandle: string,
    snapshotHandle: string,
    kind: DockerResourceKind,
    resourceHandle: string,
  ) => ipcRenderer.invoke("lovelyres:docker:resource:inspect", {
    bindingHandle,
    snapshotHandle,
    kind,
    resourceHandle,
  }),
  getDockerSecurityAudit: (bindingHandle: string, snapshotHandle: string) =>
    ipcRenderer.invoke("lovelyres:docker:security:audit:get", {
      bindingHandle,
      snapshotHandle,
    }),
  getDockerLogs: (
    bindingHandle: string,
    snapshotHandle: string,
    containerHandle: string,
    tail: number,
  ) => ipcRenderer.invoke("lovelyres:docker:container:logs:get", {
    bindingHandle,
    snapshotHandle,
    containerHandle,
    tail,
  }),
  loadEmergencyCommandCatalog: (bindingHandle: string) =>
    ipcRenderer.invoke("lovelyres:emergency-command:catalog:load", bindingHandle),
  runEmergencyCommand: (
    bindingHandle: string,
    snapshotHandle: string,
    commandHandle: string,
  ) => ipcRenderer.invoke("lovelyres:emergency-command:run", {
    bindingHandle,
    snapshotHandle,
    commandHandle,
  }),
  inspectEmergencyPath: (bindingHandle: string, pathHandle: string) =>
    ipcRenderer.invoke("lovelyres:emergency-command:path:inspect", {
      bindingHandle,
      pathHandle,
    }),
  planEmergencyPathAction: (
    bindingHandle: string,
    pathHandle: string,
    action: EmergencyPathAction,
  ) => ipcRenderer.invoke("lovelyres:emergency-command:path:plan", {
    bindingHandle,
    pathHandle,
    action,
  }),
  confirmEmergencyPathAction: (bindingHandle: string, planHandle: string) =>
    ipcRenderer.invoke("lovelyres:emergency-command:path:confirm", {
      bindingHandle,
      planHandle,
    }),
  executeEmergencyPathAction: (bindingHandle: string, planHandle: string) =>
    ipcRenderer.invoke("lovelyres:emergency-command:path:execute", {
      bindingHandle,
      planHandle,
    }),
  cancelEmergencyPathAction: (bindingHandle: string, planHandle: string) =>
    ipcRenderer.invoke("lovelyres:emergency-command:path:cancel", {
      bindingHandle,
      planHandle,
    }),
  listPacketCaptureInterfaces: (bindingHandle: string) =>
    ipcRenderer.invoke("lovelyres:packet-capture:interfaces:list", { bindingHandle }),
  startPacketCapture: (
    bindingHandle: string,
    interfaceHandle: string,
    input: PacketCaptureStartInput,
  ) => ipcRenderer.invoke("lovelyres:packet-capture:start", {
    bindingHandle,
    interfaceHandle,
    input,
  }),
  pollPacketCapture: (
    bindingHandle: string,
    captureHandle: string,
    afterSequence: number,
  ) => ipcRenderer.invoke("lovelyres:packet-capture:poll", {
    bindingHandle,
    captureHandle,
    afterSequence,
  }),
  stopPacketCapture: (bindingHandle: string, captureHandle: string) =>
    ipcRenderer.invoke("lovelyres:packet-capture:stop", {
      bindingHandle,
      captureHandle,
    }),
  listApplicationLogs: (filter: ApplicationLogFilter) =>
    ipcRenderer.invoke("lovelyres:application-log:list", filter),
  setApplicationLogLevel: (level: ApplicationLogLevel) =>
    ipcRenderer.invoke("lovelyres:application-log:level:set", level),
  clearApplicationLogBuffer: () =>
    ipcRenderer.invoke("lovelyres:application-log:buffer:clear"),
  getApplicationLogPreview: (filter: ApplicationLogFilter) =>
    ipcRenderer.invoke("lovelyres:application-log:preview:get", filter),
  exportApplicationLogs: (filter: ApplicationLogFilter) =>
    ipcRenderer.invoke("lovelyres:application-log:export", filter),
  getIntegrityPresets: () =>
    ipcRenderer.invoke("lovelyres:integrity:presets:get"),
  listIntegrityBaselines: (bindingHandle: string) =>
    ipcRenderer.invoke("lovelyres:integrity:baselines:list", { bindingHandle }),
  startIntegrityComparison: (bindingHandle: string, baselineHandle: string) =>
    ipcRenderer.invoke("lovelyres:integrity:comparison:start", {
      bindingHandle,
      baselineHandle,
    }),
  pollIntegrityComparison: (
    bindingHandle: string,
    operationHandle: string,
    afterEvent: number,
    limit: number,
  ) => ipcRenderer.invoke("lovelyres:integrity:comparison:poll", {
    bindingHandle,
    operationHandle,
    afterEvent,
    limit,
  }),
  cancelIntegrityComparison: (bindingHandle: string, operationHandle: string) =>
    ipcRenderer.invoke("lovelyres:integrity:comparison:cancel", {
      bindingHandle,
      operationHandle,
    }),
  loadSettings: () => ipcRenderer.invoke("lovelyres:settings:get"),
  saveSettings: (input: SettingsSaveInput) =>
    ipcRenderer.invoke("lovelyres:settings:save", input),
  setWindowTheme: (input: WindowThemeInput) =>
    ipcRenderer.invoke("lovelyres:ui:window-theme", input),
  replaceSettingsAiApiKey: (input: SettingsAiApiKeyReplacementInput) =>
    ipcRenderer.invoke("lovelyres:settings:ai-api-key:replace", input),
  planSettingsAiApiKeyClear: (providerId: string) =>
    ipcRenderer.invoke("lovelyres:settings:ai-api-key:clear:plan", providerId),
  planSettingsAiProviderRemoval: (providerId: string) =>
    ipcRenderer.invoke("lovelyres:settings:ai-provider:remove:plan", providerId),
  confirmSettingsMutation: (mutationHandle: string) =>
    ipcRenderer.invoke("lovelyres:settings:mutation:confirm", mutationHandle),
  cancelSettingsMutation: (mutationHandle: string) =>
    ipcRenderer.invoke("lovelyres:settings:mutation:cancel", mutationHandle),
  listAiHistory: (query: string, offset: number, limit: number) =>
    ipcRenderer.invoke("lovelyres:ai-history:list", { query, offset, limit }),
  getAiHistoryRecord: (id: string) => ipcRenderer.invoke("lovelyres:ai-history:get", id),
  planAiHistoryRemove: (id: string) =>
    ipcRenderer.invoke("lovelyres:ai-history:remove:plan", id),
  planAiHistoryClear: () => ipcRenderer.invoke("lovelyres:ai-history:clear:plan"),
  confirmAiHistoryMutation: (handle: string) =>
    ipcRenderer.invoke("lovelyres:ai-history:mutation:confirm", handle),
  cancelAiHistoryMutation: (handle: string) =>
    ipcRenderer.invoke("lovelyres:ai-history:mutation:cancel", handle),
  exportAiHistory: (format: AiHistoryExportFormat) =>
    ipcRenderer.invoke("lovelyres:ai-history:export", format),
  listCommandHistory: (bindingHandle: string, query: string, offset: number, limit: number) =>
    ipcRenderer.invoke("lovelyres:command-history:list", {
      bindingHandle, query, offset, limit,
    }),
  getCommandHistory: (bindingHandle: string, recordId: string) =>
    ipcRenderer.invoke("lovelyres:command-history:get", { bindingHandle, recordId }),
  planCommandReplay: (bindingHandle: string, recordId: string) =>
    ipcRenderer.invoke("lovelyres:command-history:replay:plan", { bindingHandle, recordId }),
  planCommandHistoryRemove: (bindingHandle: string, recordId: string) =>
    ipcRenderer.invoke("lovelyres:command-history:remove:plan", { bindingHandle, recordId }),
  planCommandHistoryClear: (bindingHandle: string) =>
    ipcRenderer.invoke("lovelyres:command-history:clear:plan", bindingHandle),
  confirmCommandHistoryMutation: (bindingHandle: string, mutationHandle: string) =>
    ipcRenderer.invoke("lovelyres:command-history:mutation:confirm", {
      bindingHandle, mutationHandle,
    }),
  cancelCommandHistoryMutation: (bindingHandle: string, mutationHandle: string) =>
    ipcRenderer.invoke("lovelyres:command-history:mutation:cancel", {
      bindingHandle, mutationHandle,
    }),
  generateDisposalReport: (bindingHandle: string) =>
    ipcRenderer.invoke("lovelyres:disposal-report:generate", bindingHandle),
  getDisposalReportContent: (
    bindingHandle: string,
    reportHandle: string,
    format: DisposalReportPreviewFormat,
  ) => ipcRenderer.invoke("lovelyres:disposal-report:content:get", {
    bindingHandle, reportHandle, format,
  }),
  exportDisposalReport: (
    bindingHandle: string,
    reportHandle: string,
    format: DisposalReportExportFormat,
  ) => ipcRenderer.invoke("lovelyres:disposal-report:export", {
    bindingHandle, reportHandle, format,
  }),
  getConfigCatalog: () => ipcRenderer.invoke("lovelyres:config:catalog:get"),
  generateConfig: (input: ConfigGenerateInput) =>
    ipcRenderer.invoke("lovelyres:config:generate", input),
  reviseConfig: (handle: string, revision: number, input: ConfigGenerateInput) =>
    ipcRenderer.invoke("lovelyres:config:revise", { handle, revision, input }),
  copyConfig: (handle: string, revision: number) =>
    ipcRenderer.invoke("lovelyres:config:copy", { handle, revision }),
  exportConfigArtifact: (handle: string, revision: number, artifactKey: string) =>
    ipcRenderer.invoke("lovelyres:config:artifact:export", {
      handle,
      revision,
      artifactKey,
    }),
  closeConfigDraft: (handle: string, revision: number) =>
    ipcRenderer.invoke("lovelyres:config:draft:close", { handle, revision }),
  setSecurityReferenceFavorites: (favoriteIds: string[]) =>
    ipcRenderer.invoke("lovelyres:security-reference:set-favorites", favoriteIds),
  listNotes: (query: string, offset: number, limit: number) =>
    ipcRenderer.invoke("lovelyres:notes:list", { query, offset, limit }),
  getNote: (id: string) => ipcRenderer.invoke("lovelyres:notes:get", id),
  createNote: (input: NoteCreateInput) =>
    ipcRenderer.invoke("lovelyres:notes:create", input),
  updateNote: (input: NoteUpdateInput) =>
    ipcRenderer.invoke("lovelyres:notes:update", input),
  setNotePinned: (id: string, pinned: boolean, expectedRevision: string, mutationId: string) =>
    ipcRenderer.invoke("lovelyres:notes:set-pinned", { id, pinned, expectedRevision, mutationId }),
  addNoteTag: (id: string, tag: string, expectedRevision: string, mutationId: string) =>
    ipcRenderer.invoke("lovelyres:notes:add-tag", { id, tag, expectedRevision, mutationId }),
  removeNoteTag: (id: string, tag: string, expectedRevision: string, mutationId: string) =>
    ipcRenderer.invoke("lovelyres:notes:remove-tag", { id, tag, expectedRevision, mutationId }),
  planNoteDelete: (id: string, expectedRevision: string, mutationId: string) =>
    ipcRenderer.invoke("lovelyres:notes:delete:plan", { id, expectedRevision, mutationId }),
  confirmNoteDelete: (handle: string, mutationId: string) =>
    ipcRenderer.invoke("lovelyres:notes:delete:confirm", { handle, mutationId }),
  cancelNoteDelete: (handle: string, mutationId: string) =>
    ipcRenderer.invoke("lovelyres:notes:delete:cancel", { handle, mutationId }),
  exportNotes: (id: string | null) => ipcRenderer.invoke("lovelyres:notes:export", id),
  writeClipboard: (text: string) => ipcRenderer.invoke("lovelyres:clipboard:write-text", text),
  onBeforeClose: (handler: () => Promise<boolean>) => {
    const listener = () => {
      void handler().then(
        (allowed) => ipcRenderer.send("lovelyres:before-close-result", allowed === true),
        () => ipcRenderer.send("lovelyres:before-close-result", false),
      );
    };
    ipcRenderer.on("lovelyres:before-close", listener);
    return () => ipcRenderer.removeListener("lovelyres:before-close", listener);
  },
  notifyRendererReady: () => ipcRenderer.send("lovelyres:renderer-ready"),
});

contextBridge.exposeInMainWorld("lovelyres", api);
