import { readFileSync } from "node:fs";

import { describe, expect, it, vi } from "vitest";

import {
  AI_HISTORY_RPC_METHODS,
  APPLICATION_LOG_RPC_METHODS,
  BASELINE_READ_RPC_METHODS,
  BackendClient,
  CHECK_AUDIT_READ_RPC_METHODS,
  COMMAND_HISTORY_RPC_METHODS,
  DISPOSAL_REPORT_RPC_METHODS,
  DOCKER_READ_RPC_METHODS,
  INTEGRITY_RPC_METHODS,
  KUBERNETES_READ_RPC_METHODS,
  LOG_ANALYSIS_READ_RPC_METHODS,
  PACKET_CAPTURE_LIVE_RPC_METHODS,
  SETTINGS_RPC_METHODS,
  SYSTEM_INFO_RPC_METHODS,
  TERMINAL_RPC_METHODS,
} from "./backend-client";
import type { BackendTransport } from "./transport";

describe("sidecar request deadlines", () => {
  const source = readFileSync(new URL("./backend-client.ts", import.meta.url), "utf8");

  /**
   * A client bound below the sidecar's own turns a slow target into "the
   * request timed out", which says nothing an operator can act on, and drops
   * the specific answer the sidecar was about to give. It happened on a lab
   * host where a system-info tab needed more than the fifteen seconds every
   * request used to get.
   */
  it("waits longer than the deadline the sidecar applies", () => {
    const value = (name: string): number => {
      const match = new RegExp(`const ${name} = ([0-9_]+);`, "u").exec(source);
      return Number((match?.[1] ?? "0").replace(/_/gu, ""));
    };
    const sidecar = (file: string, name: string): number => {
      const text = readFileSync(
        new URL(`../../../crates/lovelyhawk-backend/src/${file}`, import.meta.url),
        "utf8",
      );
      const match = new RegExp(`const ${name}: Duration = Duration::from_secs\((\d+)\)`, "u")
        .exec(text);
      return Number(match?.[1] ?? 0) * 1_000;
    };

    const run = value("EMERGENCY_COMMAND_RUN_TIMEOUT_MS");
    expect(run).toBeGreaterThan(sidecar("emergency_command_api.rs", "EXECUTION_DEADLINE"));
    const operation = value("SFTP_OPERATION_TIMEOUT_MS");
    expect(operation).toBeGreaterThan(sidecar("sftp_browser_api.rs", "EXECUTE_DEADLINE"));
    const transfer = value("SFTP_TRANSFER_TIMEOUT_MS");
    expect(transfer).toBeGreaterThan(sidecar("sftp_browser_api.rs", "TRANSFER_DEADLINE"));
    // A container action covers the mutation, the journal, the verification
    // read and possibly a restore, so its sidecar deadline is the longest one
    // here and the client's has to clear it.
    const action = value("DOCKER_ACTION_TIMEOUT_MS");
    expect(action).toBeGreaterThan(sidecar("docker_write_api.rs", "EXECUTE_DEADLINE"));
    expect(value("KUBERNETES_ACTION_TIMEOUT_MS")).toBeGreaterThan(sidecar("kubernetes_write_api.rs", "EXECUTE_DEADLINE"));

    // Anything that runs a command on a target waits past the forty-five
    // seconds the core allows a single one.
    expect(value("REMOTE_REQUEST_TIMEOUT_MS")).toBeGreaterThan(45_000);
    expect(value("BASELINE_FILE_TIMEOUT_MS")).toBeGreaterThan(2 * 45_000);
    const fileRead = source.slice(source.indexOf("async readBaselineFile("), source.indexOf("async getCheckAuditCatalog("));
    expect(fileRead).toContain("}, BASELINE_FILE_TIMEOUT_MS)");
    expect(source).toContain('"system-info",');
    expect(source).toContain("timeoutMs = defaultTimeoutFor(method)");
  });
});

describe("terminal backend client boundary", () => {
  it("pins all seven internal RPC methods, which only the desktop host calls", () => {
    expect(TERMINAL_RPC_METHODS).toEqual({
      open: "terminal.open",
      poll: "terminal.poll",
      input: "terminal.input",
      resize: "terminal.resize",
      renderSnapshot: "terminal.render-snapshot",
      search: "terminal.search",
      close: "terminal.close",
    });
    expect(Object.keys(TERMINAL_RPC_METHODS)).toHaveLength(7);
    // A page never names a terminal handle: the terminal window's own API asks
    // the host, which resolves the handle from the window it created.
    const client = readFileSync(new URL("./backend-client.ts", import.meta.url), "utf8");
    expect(client).not.toMatch(/#request\(TERMINAL_RPC_METHODS\./u);
    const host = readFileSync(new URL("../../../crates/lovelyhawk-desktop/src/backend_bridge.rs", import.meta.url), "utf8");
    const allowed = host.slice(host.indexOf("const MAIN_WINDOW_METHODS"), host.indexOf("];"));
    for (const method of Object.values(TERMINAL_RPC_METHODS)) expect(allowed).not.toContain(`"${method}"`);
  });
});

describe("disposal report backend client boundary", () => {
  it("pins exactly three target-scoped RPC methods and validates every DTO", () => {
    expect(DISPOSAL_REPORT_RPC_METHODS).toEqual({
      generate: "disposal-report.generate",
      content: "disposal-report.content.get",
      export: "disposal-report.export",
    });
    expect(Object.keys(DISPOSAL_REPORT_RPC_METHODS)).toHaveLength(3);
    expect(BackendClient.prototype.generateDisposalReport.toString()).toContain("isDisposalReportSnapshot");
    expect(BackendClient.prototype.getDisposalReportContent.toString()).toContain("isDisposalReportContent");
    // The export payload stays in the host, which writes the file itself.
    expect(Object.getOwnPropertyNames(BackendClient.prototype)).not.toContain("prepareDisposalReportExport");
  });
});

describe("command history backend client boundary", () => {
  it("pins exactly seven target-scoped RPC methods and validates every DTO", () => {
    expect(COMMAND_HISTORY_RPC_METHODS).toEqual({
      list: "command-history.list",
      get: "command-history.get",
      planReplay: "command-history.replay.plan",
      planRemove: "command-history.remove.plan",
      planClear: "command-history.clear.plan",
      confirm: "command-history.mutation.confirm",
      cancel: "command-history.mutation.cancel",
    });
    expect(Object.keys(COMMAND_HISTORY_RPC_METHODS)).toHaveLength(7);
    expect(BackendClient.prototype.listCommandHistory.toString()).toContain("isCommandHistoryListPage");
    expect(BackendClient.prototype.getCommandHistory.toString()).toContain("isCommandHistoryRecord");
    expect(BackendClient.prototype.planCommandReplay.toString()).toContain("isCommandReplayIntent");
    expect(BackendClient.prototype.planCommandHistoryRemove.toString()).toContain("isCommandHistoryMutationProposal");
    expect(BackendClient.prototype.planCommandHistoryClear.toString()).toContain("isCommandHistoryMutationProposal");
    expect(BackendClient.prototype.confirmCommandHistoryMutation.toString()).toContain("isCommandHistoryMutationResult");
    expect(BackendClient.prototype.cancelCommandHistoryMutation.toString()).toContain("isCommandHistoryMutationCancellation");
  });
});

describe("AI history backend client boundary", () => {
  it("pins exactly seven RPC methods and validates every DTO", () => {
    expect(AI_HISTORY_RPC_METHODS).toEqual({
      list: "ai-history.list",
      get: "ai-history.get",
      planRemove: "ai-history.remove.plan",
      planClear: "ai-history.clear.plan",
      confirm: "ai-history.mutation.confirm",
      cancel: "ai-history.mutation.cancel",
      export: "ai-history.export",
    });
    expect(Object.keys(AI_HISTORY_RPC_METHODS)).toHaveLength(7);
    expect(BackendClient.prototype.listAiHistory.toString()).toContain("isAiHistoryListPage");
    expect(BackendClient.prototype.getAiHistoryRecord.toString()).toContain("isAiHistoryRecord");
    expect(BackendClient.prototype.planAiHistoryRemove.toString()).toContain("isAiHistoryMutationProposal");
    expect(BackendClient.prototype.planAiHistoryClear.toString()).toContain("isAiHistoryMutationProposal");
    expect(BackendClient.prototype.confirmAiHistoryMutation.toString()).toContain("isAiHistoryMutationResult");
    expect(BackendClient.prototype.cancelAiHistoryMutation.toString()).toContain("isAiHistoryMutationCancellation");
    expect(Object.getOwnPropertyNames(BackendClient.prototype)).not.toContain("prepareAiHistoryExport");
  });
});

describe("system-info backend client boundary", () => {
  it("pins exactly ten RPC methods and validates every response DTO", () => {
    expect(SYSTEM_INFO_RPC_METHODS).toEqual({
      catalog: "system-info.catalog.get",
      summary: "system-info.summary.get",
      collect: "system-info.table.collect",
      detail: "system-info.detail.get",
      rowActions: "system-info.row.actions.list",
      rowInspect: "system-info.row.inspect",
      rowPlan: "system-info.row.action.plan",
      rowConfirm: "system-info.row.action.confirm",
      rowExecute: "system-info.row.action.execute",
      rowCancel: "system-info.row.action.cancel",
    });
    expect(Object.keys(SYSTEM_INFO_RPC_METHODS)).toHaveLength(10);
    expect(BackendClient.prototype.getSystemInfoCatalog.toString()).toContain("isSystemInfoCatalog");
    expect(BackendClient.prototype.getSystemInfoSummary.toString()).toContain("isSystemInfoSummary");
    expect(BackendClient.prototype.collectSystemInfo.toString()).toContain("isSystemInfoTable");
    expect(BackendClient.prototype.getSystemInfoDetail.toString()).toContain("isSystemInfoDetail");
    // Row actions: every response is checked and correlated with what was
    // asked, so a reply about another row or another action is refused.
    const rowActions = BackendClient.prototype.listSystemInfoRowActions.toString();
    expect(rowActions).toContain("isSystemInfoRowActions");
    expect(rowActions).toContain("value.rowId !== rowId");
    const inspect = BackendClient.prototype.inspectSystemInfoRow.toString();
    expect(inspect).toContain("isSystemInfoRowActionKey");
    expect(inspect).toContain("isSystemInfoRowInspection");
    expect(inspect).toContain("value.action !== action");
    const plan = BackendClient.prototype.planSystemInfoRowAction.toString();
    expect(plan).toContain("isSystemInfoRowActionKey");
    expect(plan).toContain("isSystemInfoRowPlan");
    expect(plan).toContain("value.action !== action");
    const confirm = BackendClient.prototype.confirmSystemInfoRowAction.toString();
    expect(confirm).toContain("value.planHandle !== planHandle");
    expect(confirm).toContain("!value.confirmed");
    const execute = BackendClient.prototype.executeSystemInfoRowAction.toString();
    expect(execute).toContain("isSystemInfoRowReceipt");
    expect(execute).toContain("value.planHandle !== planHandle");
    const cancel = BackendClient.prototype.cancelSystemInfoRowAction.toString();
    expect(cancel).toContain("isSystemInfoOpaqueHandle");
    expect(cancel).toContain("planHandle");
  });
});

describe("Baseline read backend client boundary", () => {
  it("pins exactly four RPC methods and validates every input and response DTO", () => {
    expect(BASELINE_READ_RPC_METHODS).toEqual({
      catalog: "baseline.catalog.get",
      scan: "baseline.scan",
      listHistory: "baseline.history.list",
      readFile: "baseline.file.read",
    });
    expect(Object.keys(BASELINE_READ_RPC_METHODS)).toHaveLength(4);
    expect(BackendClient.prototype.getBaselineCatalog.toString()).toContain("isBaselineCatalog");
    expect(BackendClient.prototype.scanBaseline.toString()).toContain("isBaselineScan");
    expect(BackendClient.prototype.scanBaseline.toString()).toContain("isBaselineOpaqueHandle");
    expect(BackendClient.prototype.listBaselineHistory.toString()).toContain("isBaselineHistory");
    expect(BackendClient.prototype.listBaselineHistory.toString())
      .toContain("isBaselineOpaqueHandle");
    expect(BackendClient.prototype.readBaselineFile.toString()).toContain("isBaselineFile");
    // Both handles are checked, and the reply has to be about the one asked for.
    expect(BackendClient.prototype.readBaselineFile.toString())
      .toContain("isBaselineOpaqueHandle");
    expect(BackendClient.prototype.readBaselineFile.toString())
      .toContain("value.itemHandle !== itemHandle");
  });
});

describe("Check Audit read backend client boundary", () => {
  it("pins exactly three target-scoped RPC methods and strictly validates correlated DTOs", () => {
    expect(CHECK_AUDIT_READ_RPC_METHODS).toEqual({
      catalog: "check-audit.catalog.get",
      collectStatus: "check-audit.status.collect",
      readLog: "check-audit.log.read",
    });
    expect(Object.keys(CHECK_AUDIT_READ_RPC_METHODS)).toHaveLength(3);
    expect(BackendClient.prototype.getCheckAuditCatalog.toString())
      .toContain("isCheckAuditCatalogInput");
    expect(BackendClient.prototype.getCheckAuditCatalog.toString())
      .toContain("isCheckAuditCatalog");
    expect(BackendClient.prototype.getCheckAuditCatalog.toString())
      .toContain("value.customCount !== input.customCommandNames.length");
    expect(BackendClient.prototype.collectCheckAuditStatus.toString())
      .toContain("value.snapshotHandle !== snapshotHandle");
    expect(BackendClient.prototype.readCheckAuditLog.toString())
      .toContain("isCheckAuditLogInput");
    expect(BackendClient.prototype.readCheckAuditLog.toString())
      .toContain("value.limit !== input.limit");
  });
});

describe("Log Analysis read backend client boundary", () => {
  it("pins exactly four target-scoped RPC methods and validates correlated DTOs", () => {
    expect(LOG_ANALYSIS_READ_RPC_METHODS).toEqual({
      discoverSources: "log-analysis.sources.discover",
      readSource: "log-analysis.source.read",
      correlateSources: "log-analysis.sources.correlate",
      searchIocs: "log-analysis.iocs.search",
    });
    expect(Object.keys(LOG_ANALYSIS_READ_RPC_METHODS)).toHaveLength(4);
    expect(BackendClient.prototype.discoverLogSources.toString())
      .toContain("isLogSourceSnapshot");
    expect(BackendClient.prototype.readLogSource.toString())
      .toContain("isLogSourceReadInput");
    expect(BackendClient.prototype.readLogSource.toString())
      .toContain("value.sourceHandle !== sourceHandle");
    expect(BackendClient.prototype.correlateLogSources.toString())
      .toContain("isLogCorrelationResult");
    expect(BackendClient.prototype.correlateLogSources.toString())
      .toContain("handle !== input.sourceHandles[index]");
    expect(BackendClient.prototype.searchLogIocs.toString())
      .toContain("isLogIocSearchInput");
    expect(BackendClient.prototype.searchLogIocs.toString())
      .toContain("!input.indicators.includes(result.indicator)");
  });
});

describe("Kubernetes read backend client boundary", () => {
  it("pins exactly four target-scoped RPC methods and validates correlated DTOs", () => {
    expect(KUBERNETES_READ_RPC_METHODS).toEqual({
      availability: "kubernetes.availability.get",
      listResources: "kubernetes.resources.list",
      resourceDetail: "kubernetes.resource.detail.get",
      podLogs: "kubernetes.pod.logs.get",
    });
    expect(Object.keys(KUBERNETES_READ_RPC_METHODS)).toHaveLength(4);
    expect(BackendClient.prototype.getKubernetesAvailability.toString())
      .toContain("isKubernetesAvailability");
    expect(BackendClient.prototype.listKubernetesResources.toString())
      .toContain("isKubernetesListInput");
    expect(BackendClient.prototype.listKubernetesResources.toString())
      .toContain("value.tab !== input.tab");
    expect(BackendClient.prototype.listKubernetesResources.toString())
      .toContain("value.namespaceScoped !== (input.namespaceScope !== null)");
    expect(BackendClient.prototype.getKubernetesResourceDetail.toString())
      .toContain('value.contentKind !== "detail"');
    expect(BackendClient.prototype.getKubernetesPodLogs.toString())
      .toContain('value.contentKind !== (previous ? "pod-previous-logs" : "pod-logs")');
    for (const method of [
      BackendClient.prototype.getKubernetesAvailability,
      BackendClient.prototype.listKubernetesResources,
      BackendClient.prototype.getKubernetesResourceDetail,
      BackendClient.prototype.getKubernetesPodLogs,
    ]) expect(method.toString()).toContain("isKubernetesOpaqueHandle");
  });
});

describe("Docker read backend client boundary", () => {
  it("pins exactly five target-scoped RPC methods and validates correlated DTOs", () => {
    expect(DOCKER_READ_RPC_METHODS).toEqual({
      refreshContainers: "docker.containers.refresh",
      getCollection: "docker.collection.get",
      inspectResource: "docker.resource.inspect",
      getSecurityAudit: "docker.security.audit.get",
      getContainerLogs: "docker.container.logs.get",
    });
    expect(Object.keys(DOCKER_READ_RPC_METHODS)).toHaveLength(5);
    expect(BackendClient.prototype.refreshDockerContainers.toString())
      .toContain("isDockerContainerSnapshot");
    expect(BackendClient.prototype.getDockerCollection.toString())
      .toContain("value.kind !== kind");
    expect(BackendClient.prototype.inspectDockerResource.toString())
      .toContain("value.resourceHandle !== resourceHandle");
    expect(BackendClient.prototype.getDockerSecurityAudit.toString())
      .toContain("value.snapshotHandle !== snapshotHandle");
    expect(BackendClient.prototype.getDockerLogs.toString())
      .toContain("value.containerHandle !== containerHandle");
    expect(BackendClient.prototype.getDockerLogs.toString())
      .toContain("value.tail !== tail");
    for (const method of [
      BackendClient.prototype.refreshDockerContainers,
      BackendClient.prototype.getDockerCollection,
      BackendClient.prototype.inspectDockerResource,
      BackendClient.prototype.getDockerSecurityAudit,
      BackendClient.prototype.getDockerLogs,
    ]) expect(method.toString()).toContain("isDockerOpaqueHandle");
  });
});

describe("Packet Capture Live backend client boundary", () => {
  it("pins exactly four binding-scoped RPC methods and validates correlated DTOs", () => {
    expect(PACKET_CAPTURE_LIVE_RPC_METHODS).toEqual({
      listInterfaces: "packet-capture.interfaces.list",
      start: "packet-capture.start",
      poll: "packet-capture.poll",
      stop: "packet-capture.stop",
    });
    expect(Object.keys(PACKET_CAPTURE_LIVE_RPC_METHODS)).toHaveLength(4);
    expect(BackendClient.prototype.listPacketCaptureInterfaces.toString())
      .toContain("isPacketCaptureInterfaceList");
    expect(BackendClient.prototype.startPacketCapture.toString())
      .toContain("value.captureHandle === interfaceHandle");
    expect(BackendClient.prototype.pollPacketCapture.toString())
      .toContain("value.captureHandle !== captureHandle");
    expect(BackendClient.prototype.pollPacketCapture.toString())
      .toContain("event.sequence <= afterSequence");
    expect(BackendClient.prototype.stopPacketCapture.toString())
      .toContain("isPacketCaptureStopped");
    for (const method of [
      BackendClient.prototype.listPacketCaptureInterfaces,
      BackendClient.prototype.startPacketCapture,
      BackendClient.prototype.pollPacketCapture,
      BackendClient.prototype.stopPacketCapture,
    ]) expect(method.toString()).toContain("isPacketCaptureOpaqueHandle");
  });
});

describe("Application Log backend client boundary", () => {
  it("pins exactly five process-local RPC methods and validates every DTO", () => {
    expect(APPLICATION_LOG_RPC_METHODS).toEqual({
      list: "application-log.list",
      setLevel: "application-log.level.set",
      clearBuffer: "application-log.buffer.clear",
      preview: "application-log.preview.get",
      prepareExport: "application-log.export.prepare",
    });
    expect(Object.keys(APPLICATION_LOG_RPC_METHODS)).toHaveLength(5);
    expect(BackendClient.prototype.listApplicationLogs.toString())
      .toContain("isApplicationLogSnapshot");
    expect(BackendClient.prototype.setApplicationLogLevel.toString())
      .toContain("value.level !== level");
    expect(BackendClient.prototype.clearApplicationLogBuffer.toString())
      .toContain("isApplicationLogClearResult");
    expect(BackendClient.prototype.getApplicationLogPreview.toString())
      .toContain("isApplicationLogPreview");
    expect(Object.getOwnPropertyNames(BackendClient.prototype)).not.toContain("prepareApplicationLogExport");
  });
});

describe("File Integrity backend client boundary", () => {
  it("pins exact five read-only RPC methods plus baseline creation, and validates correlated DTOs", () => {
    expect(INTEGRITY_RPC_METHODS).toEqual({
      presets: "integrity.presets.get",
      listBaselines: "integrity.baselines.list",
      startComparison: "integrity.comparison.start",
      pollComparison: "integrity.comparison.poll",
      cancelComparison: "integrity.comparison.cancel",
      startCreation: "integrity.baseline.create.start",
      pollCreation: "integrity.baseline.create.poll",
      cancelCreation: "integrity.baseline.create.cancel",
    });
    expect(Object.keys(INTEGRITY_RPC_METHODS)).toHaveLength(8);
    // Creation is checked whole: preset ids and plain absolute paths only.
    expect(BackendClient.prototype.startIntegrityBaselineCreation.toString())
      .toContain("isIntegrityCreationRequest");
    expect(BackendClient.prototype.getIntegrityPresets.toString())
      .toContain("isIntegrityPresetCatalog");
    expect(BackendClient.prototype.listIntegrityBaselines.toString())
      .toContain("baseline.baselineHandle === bindingHandle");
    expect(BackendClient.prototype.startIntegrityComparison.toString())
      .toContain("value.baselineHandle !== baselineHandle");
    expect(BackendClient.prototype.startIntegrityComparison.toString())
      .toContain("value.operationHandle === baselineHandle");
    expect(BackendClient.prototype.pollIntegrityComparison.toString())
      .toContain("value.operationHandle !== operationHandle");
    expect(BackendClient.prototype.pollIntegrityComparison.toString())
      .toContain("event.sequence <= afterEvent");
    expect(BackendClient.prototype.cancelIntegrityComparison.toString())
      .toContain("isIntegrityComparisonCancellation");
    for (const method of [
      BackendClient.prototype.listIntegrityBaselines,
      BackendClient.prototype.startIntegrityComparison,
      BackendClient.prototype.pollIntegrityComparison,
      BackendClient.prototype.cancelIntegrityComparison,
    ]) expect(method.toString()).toContain("isIntegrityOpaqueHandle");
  });
});

describe("settings backend client boundary", () => {
  it("pins exactly seven RPC methods and validates the secret lifecycle DTOs", () => {
    expect(SETTINGS_RPC_METHODS).toEqual({
      get: "settings.get",
      save: "settings.save",
      replaceAiApiKey: "settings.ai-api-key.replace",
      planAiApiKeyClear: "settings.ai-api-key.clear.plan",
      planAiProviderRemoval: "settings.ai-provider.remove.plan",
      confirmMutation: "settings.mutation.confirm",
      cancelMutation: "settings.mutation.cancel",
    });
    expect(Object.keys(SETTINGS_RPC_METHODS)).toHaveLength(7);
    expect(BackendClient.prototype.loadSettings.toString()).toContain("isSettingsSnapshot");
    expect(BackendClient.prototype.saveSettings.toString()).toContain("isSettingsSaveInput");
    expect(BackendClient.prototype.saveSettings.toString()).toContain("isSettingsSnapshot");
    expect(BackendClient.prototype.replaceSettingsAiApiKey.toString()).toContain("isSettingsAiApiKeyReplacementInput");
    expect(BackendClient.prototype.replaceSettingsAiApiKey.toString()).toContain("isSettingsAiApiKeyReplacementResult");
    expect(BackendClient.prototype.planSettingsAiApiKeyClear.toString()).toContain("isSettingsMutationProposal");
    expect(BackendClient.prototype.planSettingsAiProviderRemoval.toString()).toContain("isSettingsMutationProposal");
    expect(BackendClient.prototype.confirmSettingsMutation.toString()).toContain("isSettingsMutationResult");
    expect(BackendClient.prototype.cancelSettingsMutation.toString()).toContain("isSettingsMutationCancellation");
  });
});


class RecordingTransport implements BackendTransport {
  readonly calls: Array<{ method: string; params: object; timeoutMs: number }> = [];
  constructor(private readonly answer: unknown) {}
  call(method: string, params: object, timeoutMs: number): Promise<unknown> {
    this.calls.push({ method, params, timeoutMs });
    return Promise.resolve(this.answer);
  }
}

describe("desktop host transport", () => {
  it("sends one backend method with its params and the method's own deadline", async () => {
    const transport = new RecordingTransport({ id: "x", stage: "connecting" });
    const client = new BackendClient(transport);
    await expect(client.getSshAttempt("attempt")).rejects.toThrow("invalid SSH attempt status");
    expect(transport.calls).toEqual([{ method: "ssh.attempt.get", params: { attemptHandle: "attempt" }, timeoutMs: 15_000 }]);
  });

  it("gives a failed SSH attempt the operator's sentence for its code, not the backend's English", async () => {
    const changed = {
      stage: "failed",
      error: {
        code: "host-key-changed",
        message: "The recorded SSH host key changed. Automatic repinning is not supported.",
        role: "target",
        host: "192.0.2.10",
        port: 22,
        repinSupported: false,
      },
    };
    const refused = await new BackendClient(new RecordingTransport(changed)).getSshAttempt("attempt");
    expect(refused).toEqual({ ...changed, error: { ...changed.error, message: expect.stringMatching(/[一-鿿]/u) } });
    expect(refused.stage === "failed" && refused.error.message).not.toMatch(/[A-Za-z]{4,}/u);
    const generic = await new BackendClient(new RecordingTransport({
      stage: "failed", error: { code: "ssh-attempt-failed", message: "LovelyHawk could not complete the SSH attempt." },
    })).confirmSshHostKey("attempt", "prompt");
    expect(generic.stage === "failed" && generic.error.message).toBe("SSH 连接没有完成，详细原因见应用日志。");
    // Anything that is not a failure passes through untouched.
    expect(await new BackendClient(new RecordingTransport({ stage: "running" })).respondSshMfa("attempt", "prompt", ["x"]))
      .toEqual({ stage: "running" });
  });

  it("refuses an oversized request before it reaches the host", async () => {
    const call = vi.fn();
    const client = new BackendClient({ call });
    const huge = "x".repeat(8 * 1_024 * 1_024 + 1);
    await expect(client.createNote({ mutationId: "m".repeat(16), content: huge, tags: [] }))
      .rejects.toThrow("too large");
    expect(call).not.toHaveBeenCalled();
  });

  it("keeps path-bearing actions out of the generic client", async () => {
    const call = vi.fn();
    const client = new BackendClient({ call });
    await expect(client.caseLibrary({ action: "export", snapshotHandle: "s" })).rejects.toThrow("案件库请求无效");
    await expect(client.fileEvidence({ action: "begin", bindingHandle: "b", pathHandle: "p" })).rejects.toThrow("留证请求无效");
    expect(call).not.toHaveBeenCalled();
  });
});
