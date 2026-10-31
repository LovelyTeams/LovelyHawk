import { isWindowsRdpRequest, isWindowsRdpStatus } from "../shared/windows-rdp-contract.js";
import { isAppUpdateRequest, matchesAppUpdateResponse } from "../shared/update-contract.js";
import { createWindowsChannelOwnerApi } from "./windows-channel-api";
import { listen } from "@tauri-apps/api/event";

import { isCaseLibraryRequest, matchesCaseLibraryResult, type CaseLibraryRequest } from "../shared/case-library-contract.js";
import { isCaseWorkspaceRequest } from "../shared/case-workspace-contract.js";
import { isFileEvidenceRequest, matchesFileEvidenceResult, type FileEvidenceRequest } from "../shared/file-evidence-contract.js";
import { isPacketCaptureEvidenceRequest, matchesPacketCaptureEvidenceResult, type PacketCaptureEvidenceRequest } from "../shared/packet-capture-evidence-contract.js";
import { isPodFileEvidenceRequest, matchesPodFileEvidenceResult, type PodFileEvidenceRequest } from "../shared/pod-file-evidence-contract.js";
import { isConfigVisualCopyResult, isConfigVisualProduct, isConfigVisualRequest, isConfigVisualSaveResult, isConfigVisualView } from "../shared/config-visual-contract.js";
import { isNginxRepairRequest } from "../shared/nginx-repair-contract.js";
import { isLogRulesRequest } from "../shared/log-rules-contract.js";
import { isAiAssistRequest } from "../shared/ai-assist-contract.js";
import { isJavaClassStageResult, isJavaHandle, isJavaHotUpdateRequest } from "../shared/java-hot-update-contract.js";
import { isWindowsFileId, isWindowsFileSaveResult, isWindowsIncidentRequest } from "../shared/windows-incident-contract.js";
import { isPostgresqlRuntimeRequest } from "../shared/postgresql-runtime-contract.js";
import { isThemeId } from "../shared/theme-contract.js";
import {
  isAiHistoryExportFormat,
  isAiHistoryExportResult,
  isAiHistoryId,
  isAiHistoryOpaqueHandle,
  isAiHistoryPageRequest,
  isAiHistoryQuery,
  isApplicationLogExportResult,
  isApplicationLogFilter,
  isApplicationLogLevel,
  isBaselineOpaqueHandle,
  isBaselineAction,
  isCheckAuditCatalogInput,
  isCheckAuditLogInput,
  isCheckAuditOpaqueHandle,
  isCheckAuditAction,
  isCommandHistoryId,
  isCommandHistoryOpaqueHandle,
  isCommandHistoryPageRequest,
  isCommandHistoryQuery,
  isConfigBundleExportResult,
  isConfigClipboardResult,
  isConfigExportResult,
  isConfigGenerateInput,
  isConnectionDeleteHandle,
  isConnectionCredentialFileChoice,
  isConnectionCredentialFileKind,
  isConnectionExportResult,
  isConnectionId,
  isConnectionImportResult,
  isConnectionWriteInput,
  isDisposalReportExportFormat,
  isDisposalReportExportResult,
  isDisposalReportOpaqueHandle,
  isDisposalReportPreviewFormat,
  isDockerCollectionKind,
  isDockerContainerName,
  isDockerFileCopyDirection,
  isDockerFilePath,
  isDockerFileText,
  isDockerLogTail,
  isDockerOpaqueHandle,
  isDockerResourceKind,
  isDockerWriteAction,
  isEmergencyCommandOpaqueHandle,
  isEmergencyPathAction,
  isIntegrityOpaqueHandle,
  isIntegrityPollRequest,
  isIntegrityCreationRequest,
  type IntegrityPresetId,
  isKubernetesListInput,
  isKubernetesContainerName,
  isKubernetesManifestExportResult,
  isKubernetesOpaqueHandle,
  isKubernetesPodDisplayName,
  isKubernetesResourceName,
  isKubernetesWriteAction,
  isLogAnalysisOpaqueHandle,
  isLogCorrelationInput,
  isLogIocSearchInput,
  isLogSourceReadInput,
  isPacketCaptureCursor,
  isPacketCaptureOpaqueHandle,
  isPacketCaptureStartInput,
  isSettingsAiApiKeyReplacementInput,
  isSettingsMutationHandle,
  isSettingsProviderId,
  isSettingsSaveInput,
  isSshMfaResponses,
  isSshOpaqueHandle,
  isSystemInfoMaximumRows,
  isSystemInfoOpaqueHandle,
  isSystemInfoRowActionKey,
  isSystemInfoTabKey,
  isTerminalWindowLaunchResult,
  isWindowThemeInput,
  type BeforeCloseContext,
  type LovelyHawkApi,
  type WindowThemeApplied,
} from "../shared/contract.js";
import { isExecDirectoryPath, isExecFilePath } from "../shared/exec-files-contract.js";
import { BackendClient } from "./backend-client.js";
import { hostBackendTransport, invokeHost, utf8ByteLength, type BackendTransport } from "./transport.js";

/** A system dialog stays open as long as the operator needs it. */
const DIALOG_TIMEOUT_MS = 60 * 60 * 1_000;
const LOCAL_TIMEOUT_MS = 15_000;
const MAX_CLIPBOARD_BYTES = 128 * 1_024;
export const BEFORE_CLOSE_EVENT = "lovelyhawk://before-close";

function refuse(message: string): never {
  throw new Error(message);
}

function requireArity(values: unknown[], count: number, message: string): void {
  if (values.length !== count) refuse(message);
}

function boundedString(value: unknown, maximum: number, allowEmpty = true): value is string {
  return typeof value === "string" && utf8ByteLength(value) <= maximum && (allowEmpty || value.trim().length > 0);
}

function isMutationId(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{16,64}$/u.test(value);
}

function isNoteRevision(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/u.test(value);
}

function isNoteId(value: unknown): value is string {
  return boundedString(value, 128, false);
}

function isNoteTags(value: unknown): value is string[] {
  return Array.isArray(value) && value.length <= 32 && value.every((tag) => boundedString(tag, 64, false));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}

function isConfigRevision(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function isConfigIdentifier(value: unknown): value is string {
  return boundedString(value, 128, false) && /^[A-Za-z0-9._-]+$/u.test(value);
}

function isNoteCreate(value: unknown): boolean {
  return isRecord(value) && hasOnlyKeys(value, ["mutationId", "title", "content", "tags"]) &&
    isMutationId(value.mutationId) && (value.title === undefined || boundedString(value.title, 1_024)) &&
    boundedString(value.content, 4 * 1_048_576) && isNoteTags(value.tags);
}

function isNoteUpdate(value: unknown): boolean {
  return isRecord(value) && hasOnlyKeys(value, ["id", "expectedRevision", "mutationId", "title", "content", "tags"]) &&
    isNoteId(value.id) && isNoteRevision(value.expectedRevision) && isMutationId(value.mutationId) &&
    (value.title === undefined || boundedString(value.title, 1_024)) &&
    (value.content === undefined || boundedString(value.content, 4 * 1_048_576)) &&
    (value.tags === undefined || isNoteTags(value.tags));
}

function isSystemInfoRowId(value: unknown): value is string {
  return boundedString(value, 256, false);
}

async function verified<T>(work: Promise<unknown>, guard: (value: unknown) => value is T, message: string): Promise<T> {
  const value = await work;
  if (!guard(value)) refuse(message);
  return value;
}

/**
 * The main window's API: arity and shape checked here, then a validated
 * backend call or one of the host commands that keep local paths and export
 * payloads out of the page.
 */
export function createMainApi(transport: BackendTransport = hostBackendTransport): LovelyHawkApi {
  const backend = new BackendClient(transport);
  const host = (command: string, args: Record<string, unknown> = {}, timeoutMs = LOCAL_TIMEOUT_MS) =>
    invokeHost(command, args, timeoutMs);

  const api: LovelyHawkApi = {
    appUpdate: async (...values: unknown[]) => {
      requireArity(values, 1, "更新请求无效。");
      const request = values[0];
      if (!isAppUpdateRequest(request)) refuse("更新请求无效。");
      const result = await host("app_update", { request }, request.action === "download" ? DIALOG_TIMEOUT_MS : 35_000);
      if (!matchesAppUpdateResponse(request, result)) refuse("更新结果未通过校验，请重新检查。");
      return result;
    },
    caseLibrary: async (...values: unknown[]) => {
      requireArity(values, 1, "案件库请求无效。");
      const request = values[0];
      if (!isCaseLibraryRequest(request)) refuse("案件库请求无效。");
      if (request.action !== "export") return backend.caseLibrary(request);
      const result = await host("case_library_export", { request }, DIALOG_TIMEOUT_MS);
      if (result === null) return null;
      if (!matchesCaseLibraryResult(request as CaseLibraryRequest, result)) refuse("案件库结果未通过校验，请刷新核对。");
      return result;
    },
    caseWorkspace: async (...values: unknown[]) => {
      requireArity(values, 1, "案件请求无效。");
      if (!isCaseWorkspaceRequest(values[0])) refuse("案件请求无效。");
      return backend.caseWorkspace(values[0]);
    },
    postgresqlRuntime: async (...values: unknown[]) => {
      requireArity(values, 1, "数据库请求无效。");
      if (!isPostgresqlRuntimeRequest(values[0])) refuse("数据库请求无效。");
      return backend.postgresqlRuntime(values[0]);
    },
    fileEvidence: async (...values: unknown[]) => {
      requireArity(values, 1, "留证请求无效。");
      const request = values[0];
      if (!isFileEvidenceRequest(request)) refuse("留证请求无效。");
      if (request.action !== "begin") return backend.fileEvidence(request);
      const result = await host("file_evidence_begin", { request }, DIALOG_TIMEOUT_MS);
      if (result === null) return null;
      if (!matchesFileEvidenceResult(request as FileEvidenceRequest, result)) refuse("留证响应与本次请求不一致。");
      return result;
    },
    packetCaptureEvidence: async (...values: unknown[]) => {
      requireArity(values, 1, "抓包留证请求无效。");
      const request = values[0];
      if (!isPacketCaptureEvidenceRequest(request)) refuse("抓包留证请求无效。");
      if (request.action !== "begin") return backend.packetCaptureEvidence(request);
      const result = await host("packet_capture_evidence_begin", { request }, DIALOG_TIMEOUT_MS);
      if (result === null) return null;
      if (!matchesPacketCaptureEvidenceResult(request as PacketCaptureEvidenceRequest, result)) {
        refuse("抓包留证响应与本次请求不一致。");
      }
      return result;
    },
    podFileEvidence: async (...values: unknown[]) => {
      requireArity(values, 1, "Pod 文件留证请求无效。");
      const request = values[0];
      if (!isPodFileEvidenceRequest(request)) refuse("Pod 文件留证请求无效。");
      if (request.action !== "begin") return backend.podFileEvidence(request);
      const result = await host("pod_file_evidence_begin", { request }, DIALOG_TIMEOUT_MS);
      if (result === null) return null;
      if (!matchesPodFileEvidenceResult(request as PodFileEvidenceRequest, result)) {
        refuse("Pod 文件留证响应与本次请求不一致。");
      }
      return result;
    },
    aiAssist: async (...values: unknown[]) => {
      requireArity(values, 1, "AI 解读请求无效。");
      if (!isAiAssistRequest(values[0])) refuse("AI 解读请求无效。");
      return backend.aiAssist(values[0]);
    },
    logRules: async (...values: unknown[]) => {
      requireArity(values, 1, "日志匹配规则请求无效。");
      if (!isLogRulesRequest(values[0])) refuse("日志匹配规则请求无效。");
      return backend.logRules(values[0]);
    },
    nginxRepair: async (...values: unknown[]) => {
      requireArity(values, 1, "Nginx 修补请求无效。");
      if (!isNginxRepairRequest(values[0])) refuse("Nginx 修补请求无效。");
      return backend.nginxRepair(values[0]);
    },
    javaHotUpdate: async (...values: unknown[]) => {
      requireArity(values, 1, "Java 热更新请求无效。");
      if (!isJavaHotUpdateRequest(values[0])) refuse("Java 热更新请求无效。");
      return backend.javaHotUpdate(values[0]);
    },
    windowsRdp: async (...values: unknown[]) => {
      requireArity(values, 1, "远程桌面请求无效。");
      if (!isWindowsRdpRequest(values[0])) refuse("远程桌面请求无效。");
      return verified(host("windows_rdp", { request: values[0] }), isWindowsRdpStatus, "远程桌面状态无法核实。");
    },
    windowsChannel: createWindowsChannelOwnerApi(),
    windowsIncident: async (...values: unknown[]) => {
      requireArity(values, 1, "Windows 应急响应请求无效。");
      if (!isWindowsIncidentRequest(values[0])) refuse("Windows 应急响应请求无效。");
      return backend.windowsIncident(values[0]);
    },
    saveWindowsFile: async (...values: unknown[]) => {
      requireArity(values, 1, "取证文件请求无效。");
      if (!isWindowsFileId(values[0])) refuse("取证文件请求无效。");
      return verified(host("windows_file_save", { fileId: values[0] }, DIALOG_TIMEOUT_MS),
        isWindowsFileSaveResult, "文件保存结果无法核实，请检查保存位置后重试。");
    },
    stageJavaClass: async (...values: unknown[]) => {
      requireArity(values, 1, "类文件请求无效。");
      if (!isJavaHandle(values[0])) refuse("类文件请求无效。");
      return verified(host("java_class_stage", { bindingHandle: values[0] }, DIALOG_TIMEOUT_MS),
        isJavaClassStageResult, "所选类文件的结果无法核实。");
    },
    bootstrap: async (...values: unknown[]) => {
      requireArity(values, 0, "Invalid bootstrap request.");
      return backend.bootstrap();
    },
    listConnections: async (...values: unknown[]) => {
      requireArity(values, 0, "Invalid connection list request.");
      return backend.listConnections();
    },
    getConnection: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid connection get request.");
      if (!isConnectionId(values[0])) refuse("Invalid connection identifier.");
      return backend.getConnection(values[0]);
    },
    createConnection: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid connection creation request.");
      if (!isConnectionWriteInput(values[0])) refuse("Invalid connection creation request.");
      return backend.createConnection(values[0]);
    },
    updateConnection: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid connection update request.");
      if (!isConnectionWriteInput(values[0])) refuse("Invalid connection update request.");
      return backend.updateConnection(values[0]);
    },
    planConnectionDelete: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid connection delete plan request.");
      if (!isConnectionId(values[0])) refuse("Invalid connection identifier.");
      return backend.planConnectionDelete(values[0]);
    },
    confirmConnectionDelete: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid connection delete confirmation request.");
      if (!isConnectionDeleteHandle(values[0])) refuse("Invalid connection delete plan handle.");
      return backend.confirmConnectionDelete(values[0]);
    },
    cancelConnectionDelete: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid connection delete cancellation request.");
      if (!isConnectionDeleteHandle(values[0])) refuse("Invalid connection delete plan handle.");
      return backend.cancelConnectionDelete(values[0]);
    },
    importConnections: async (...values: unknown[]) => {
      requireArity(values, 0, "Invalid connection import request.");
      return verified(host("connections_import", {}, DIALOG_TIMEOUT_MS), isConnectionImportResult,
        "The connection import result is invalid.");
    },
    exportConnections: async (...values: unknown[]) => {
      requireArity(values, 0, "Invalid connection export request.");
      return verified(host("connections_export", {}, DIALOG_TIMEOUT_MS), isConnectionExportResult,
        "The connection export result is invalid.");
    },
    chooseConnectionCredentialFile: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid credential file request.");
      if (!isConnectionCredentialFileKind(values[0])) refuse("Invalid credential file request.");
      return verified(host("connection_credential_file", { kind: values[0] }, DIALOG_TIMEOUT_MS),
        isConnectionCredentialFileChoice, "The credential file choice is invalid.");
    },
    startSshConnect: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid SSH connect request.");
      if (!isConnectionId(values[0])) refuse("Invalid SSH connect request.");
      return backend.startSshConnect(values[0]);
    },
    startSshProbe: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid SSH probe request.");
      if (!isConnectionWriteInput(values[0])) refuse("Invalid SSH probe request.");
      return backend.startSshProbe(values[0]);
    },
    getSshAttempt: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid SSH attempt request.");
      if (!isSshOpaqueHandle(values[0])) refuse("Invalid SSH attempt request.");
      return backend.getSshAttempt(values[0]);
    },
    confirmSshHostKey: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid SSH host-key confirmation request.");
      const [attemptHandle, promptHandle] = values;
      if (!isSshOpaqueHandle(attemptHandle) || !isSshOpaqueHandle(promptHandle)) {
        refuse("Invalid SSH host-key confirmation request.");
      }
      return backend.confirmSshHostKey(attemptHandle, promptHandle);
    },
    respondSshMfa: async (...values: unknown[]) => {
      requireArity(values, 3, "Invalid SSH MFA response request.");
      const [attemptHandle, promptHandle, responses] = values;
      if (!isSshOpaqueHandle(attemptHandle) || !isSshOpaqueHandle(promptHandle) || !isSshMfaResponses(responses)) {
        refuse("Invalid SSH MFA response request.");
      }
      return backend.respondSshMfa(attemptHandle, promptHandle, responses);
    },
    cancelSshAttempt: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid SSH attempt cancellation request.");
      if (!isSshOpaqueHandle(values[0])) refuse("Invalid SSH attempt cancellation request.");
      return backend.cancelSshAttempt(values[0]);
    },
    disconnectSshBinding: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid SSH binding disconnection request.");
      if (!isSshOpaqueHandle(values[0])) refuse("Invalid SSH binding disconnection request.");
      return backend.disconnectSshBinding(values[0]);
    },
    openSshTerminal: async (...values: unknown[]) => {
      requireArity(values, 0, "Invalid terminal window launch request.");
      return verified(host("terminal_window_open"), isTerminalWindowLaunchResult, "The terminal window launch result is invalid.");
    },
    openSystemInfoFile: async (...values: unknown[]) => {
      requireArity(values, 3, "Invalid system-information file request.");
      const [bindingHandle, snapshotHandle, rowId] = values;
      if (!isSshOpaqueHandle(bindingHandle) || !isSystemInfoOpaqueHandle(snapshotHandle) ||
        !isSystemInfoRowId(rowId)) refuse("Invalid system-information file request.");
      return verified(host("system_info_file_open", { bindingHandle, snapshotHandle, rowId }),
        isTerminalWindowLaunchResult, "The file editor launch result is invalid.");
    },
    getSystemInfoCatalog: async (...values: unknown[]) => {
      requireArity(values, 0, "Invalid system-information catalog request.");
      return backend.getSystemInfoCatalog();
    },
    getSystemInfoSummary: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid system-information summary request.");
      if (!isSshOpaqueHandle(values[0])) refuse("Invalid system-information summary request.");
      return backend.getSystemInfoSummary(values[0]);
    },
    collectSystemInfo: async (...values: unknown[]) => {
      requireArity(values, 3, "Invalid system-information collection request.");
      const [bindingHandle, tab, maximumRows] = values;
      if (!isSshOpaqueHandle(bindingHandle) || !isSystemInfoTabKey(tab) || !isSystemInfoMaximumRows(maximumRows)) {
        refuse("Invalid system-information collection request.");
      }
      return backend.collectSystemInfo(bindingHandle, tab, maximumRows);
    },
    getSystemInfoDetail: async (...values: unknown[]) => {
      requireArity(values, 3, "Invalid system-information detail request.");
      const [bindingHandle, snapshotHandle, rowId] = values;
      if (!isSshOpaqueHandle(bindingHandle) || !isSystemInfoOpaqueHandle(snapshotHandle) || !isSystemInfoRowId(rowId)) {
        refuse("Invalid system-information detail request.");
      }
      return backend.getSystemInfoDetail(bindingHandle, snapshotHandle, rowId);
    },
    listSystemInfoRowActions: async (...values: unknown[]) => {
      requireArity(values, 3, "Invalid system-information row actions request.");
      const [bindingHandle, snapshotHandle, rowId] = values;
      if (!isSshOpaqueHandle(bindingHandle) || !isSystemInfoOpaqueHandle(snapshotHandle) || !isSystemInfoRowId(rowId)) {
        refuse("Invalid system-information row actions request.");
      }
      return backend.listSystemInfoRowActions(bindingHandle, snapshotHandle, rowId);
    },
    inspectSystemInfoRow: async (...values: unknown[]) => {
      requireArity(values, 4, "Invalid system-information row inspection request.");
      const [bindingHandle, snapshotHandle, rowId, action] = values;
      if (!isSshOpaqueHandle(bindingHandle) || !isSystemInfoOpaqueHandle(snapshotHandle) ||
        !isSystemInfoRowId(rowId) || !isSystemInfoRowActionKey(action)) {
        refuse("Invalid system-information row inspection request.");
      }
      return backend.inspectSystemInfoRow(bindingHandle, snapshotHandle, rowId, action);
    },
    planSystemInfoRowAction: async (...values: unknown[]) => {
      requireArity(values, 4, "Invalid system-information row plan request.");
      const [bindingHandle, snapshotHandle, rowId, action] = values;
      if (!isSshOpaqueHandle(bindingHandle) || !isSystemInfoOpaqueHandle(snapshotHandle) ||
        !isSystemInfoRowId(rowId) || !isSystemInfoRowActionKey(action)) {
        refuse("Invalid system-information row plan request.");
      }
      return backend.planSystemInfoRowAction(bindingHandle, snapshotHandle, rowId, action);
    },
    confirmSystemInfoRowAction: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid system-information row confirmation request.");
      const [bindingHandle, planHandle] = values;
      if (!isSshOpaqueHandle(bindingHandle) || !isSystemInfoOpaqueHandle(planHandle)) {
        refuse("Invalid system-information row confirmation request.");
      }
      return backend.confirmSystemInfoRowAction(bindingHandle, planHandle);
    },
    executeSystemInfoRowAction: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid system-information row execution request.");
      const [bindingHandle, planHandle] = values;
      if (!isSshOpaqueHandle(bindingHandle) || !isSystemInfoOpaqueHandle(planHandle)) {
        refuse("Invalid system-information row execution request.");
      }
      return backend.executeSystemInfoRowAction(bindingHandle, planHandle);
    },
    cancelSystemInfoRowAction: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid system-information row cancellation request.");
      const [bindingHandle, planHandle] = values;
      if (!isSshOpaqueHandle(bindingHandle) || !isSystemInfoOpaqueHandle(planHandle)) {
        refuse("Invalid system-information row cancellation request.");
      }
      return backend.cancelSystemInfoRowAction(bindingHandle, planHandle);
    },
    getBaselineCatalog: async (...values: unknown[]) => {
      requireArity(values, 0, "Invalid baseline catalog request.");
      return backend.getBaselineCatalog();
    },
    scanBaseline: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid baseline scan request.");
      if (!isBaselineOpaqueHandle(values[0])) refuse("Invalid baseline scan request.");
      return backend.scanBaseline(values[0]);
    },
    listBaselineHistory: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid baseline history request.");
      if (!isBaselineOpaqueHandle(values[0])) refuse("Invalid baseline history request.");
      return backend.listBaselineHistory(values[0]);
    },
    planBaselineAction: async (...values: unknown[]) => {
      requireArity(values, 2, "基线修改请求无效。");
      const [bindingHandle, action] = values;
      if (!isBaselineOpaqueHandle(bindingHandle) || !isBaselineAction(action)) refuse("基线修改请求无效。");
      return backend.planBaselineAction(bindingHandle, action);
    },
    confirmBaselineAction: async (...values: unknown[]) => {
      requireArity(values, 2, "基线修改确认无效。");
      const [bindingHandle, planHandle] = values;
      if (!isBaselineOpaqueHandle(bindingHandle) || !isBaselineOpaqueHandle(planHandle)) refuse("基线修改确认无效。");
      return backend.confirmBaselineAction(bindingHandle, planHandle);
    },
    executeBaselineAction: async (...values: unknown[]) => {
      requireArity(values, 2, "基线修改执行请求无效。");
      const [bindingHandle, planHandle] = values;
      if (!isBaselineOpaqueHandle(bindingHandle) || !isBaselineOpaqueHandle(planHandle)) refuse("基线修改执行请求无效。");
      return backend.executeBaselineAction(bindingHandle, planHandle);
    },
    cancelBaselineAction: async (...values: unknown[]) => {
      requireArity(values, 2, "基线修改取消请求无效。");
      const [bindingHandle, planHandle] = values;
      if (!isBaselineOpaqueHandle(bindingHandle) || !isBaselineOpaqueHandle(planHandle)) refuse("基线修改取消请求无效。");
      return backend.cancelBaselineAction(bindingHandle, planHandle);
    },
    readBaselineFile: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid baseline file request.");
      const [bindingHandle, itemHandle] = values;
      if (!isBaselineOpaqueHandle(bindingHandle) || !isBaselineOpaqueHandle(itemHandle)) refuse("Invalid baseline file request.");
      return backend.readBaselineFile(bindingHandle, itemHandle);
    },
    getCheckAuditCatalog: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid command-audit catalog request.");
      const [bindingHandle, input] = values;
      if (!isCheckAuditOpaqueHandle(bindingHandle) || !isCheckAuditCatalogInput(input)) refuse("Invalid command-audit catalog request.");
      return backend.getCheckAuditCatalog(bindingHandle, input);
    },
    collectCheckAuditStatus: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid command-audit status request.");
      const [bindingHandle, snapshotHandle] = values;
      if (!isCheckAuditOpaqueHandle(bindingHandle) || !isCheckAuditOpaqueHandle(snapshotHandle)) {
        refuse("Invalid command-audit status request.");
      }
      return backend.collectCheckAuditStatus(bindingHandle, snapshotHandle);
    },
    readCheckAuditLog: async (...values: unknown[]) => {
      requireArity(values, 3, "Invalid command-audit log request.");
      const [bindingHandle, snapshotHandle, input] = values;
      if (!isCheckAuditOpaqueHandle(bindingHandle) || !isCheckAuditOpaqueHandle(snapshotHandle) || !isCheckAuditLogInput(input)) {
        refuse("Invalid command-audit log request.");
      }
      return backend.readCheckAuditLog(bindingHandle, snapshotHandle, input);
    },
    planCheckAuditAction: async (...values: unknown[]) => {
      requireArity(values, 3, "命令采集请求无效。");
      const [bindingHandle, snapshotHandle, action] = values;
      if (!isCheckAuditOpaqueHandle(bindingHandle) || !isCheckAuditOpaqueHandle(snapshotHandle) || !isCheckAuditAction(action)) {
        refuse("命令采集请求无效。");
      }
      return backend.planCheckAuditAction(bindingHandle, snapshotHandle, action);
    },
    confirmCheckAuditAction: async (...values: unknown[]) => {
      requireArity(values, 2, "命令采集确认无效。");
      const [bindingHandle, planHandle] = values;
      if (!isCheckAuditOpaqueHandle(bindingHandle) || !isCheckAuditOpaqueHandle(planHandle)) refuse("命令采集确认无效。");
      return backend.confirmCheckAuditAction(bindingHandle, planHandle);
    },
    executeCheckAuditAction: async (...values: unknown[]) => {
      requireArity(values, 2, "命令采集执行请求无效。");
      const [bindingHandle, planHandle] = values;
      if (!isCheckAuditOpaqueHandle(bindingHandle) || !isCheckAuditOpaqueHandle(planHandle)) refuse("命令采集执行请求无效。");
      return backend.executeCheckAuditAction(bindingHandle, planHandle);
    },
    cancelCheckAuditAction: async (...values: unknown[]) => {
      requireArity(values, 2, "命令采集取消请求无效。");
      const [bindingHandle, planHandle] = values;
      if (!isCheckAuditOpaqueHandle(bindingHandle) || !isCheckAuditOpaqueHandle(planHandle)) refuse("命令采集取消请求无效。");
      return backend.cancelCheckAuditAction(bindingHandle, planHandle);
    },
    discoverLogSources: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid log source discovery request.");
      if (!isLogAnalysisOpaqueHandle(values[0])) refuse("Invalid log source discovery request.");
      return backend.discoverLogSources(values[0]);
    },
    readLogSource: async (...values: unknown[]) => {
      requireArity(values, 4, "Invalid log source read request.");
      const [bindingHandle, snapshotHandle, sourceHandle, input] = values;
      if (!isLogAnalysisOpaqueHandle(bindingHandle) || !isLogAnalysisOpaqueHandle(snapshotHandle) ||
        !isLogAnalysisOpaqueHandle(sourceHandle) || !isLogSourceReadInput(input)) {
        refuse("Invalid log source read request.");
      }
      return backend.readLogSource(bindingHandle, snapshotHandle, sourceHandle, input);
    },
    correlateLogSources: async (...values: unknown[]) => {
      requireArity(values, 3, "Invalid log correlation request.");
      const [bindingHandle, snapshotHandle, input] = values;
      if (!isLogAnalysisOpaqueHandle(bindingHandle) || !isLogAnalysisOpaqueHandle(snapshotHandle) || !isLogCorrelationInput(input)) {
        refuse("Invalid log correlation request.");
      }
      return backend.correlateLogSources(bindingHandle, snapshotHandle, input);
    },
    searchLogIocs: async (...values: unknown[]) => {
      requireArity(values, 3, "Invalid log IOC search request.");
      const [bindingHandle, snapshotHandle, input] = values;
      if (!isLogAnalysisOpaqueHandle(bindingHandle) || !isLogAnalysisOpaqueHandle(snapshotHandle) || !isLogIocSearchInput(input)) {
        refuse("Invalid log IOC search request.");
      }
      return backend.searchLogIocs(bindingHandle, snapshotHandle, input);
    },
    getKubernetesAvailability: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid Kubernetes availability request.");
      if (!isKubernetesOpaqueHandle(values[0])) refuse("Invalid Kubernetes availability request.");
      return backend.getKubernetesAvailability(values[0]);
    },
    listKubernetesResources: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid Kubernetes resource list request.");
      const [bindingHandle, input] = values;
      if (!isKubernetesOpaqueHandle(bindingHandle) || !isKubernetesListInput(input)) refuse("Invalid Kubernetes resource list request.");
      return backend.listKubernetesResources(bindingHandle, input);
    },
    getKubernetesResourceDetail: async (...values: unknown[]) => {
      requireArity(values, 3, "Invalid Kubernetes resource detail request.");
      const [bindingHandle, snapshotHandle, rowHandle] = values;
      if (![bindingHandle, snapshotHandle, rowHandle].every(isKubernetesOpaqueHandle)) refuse("Invalid Kubernetes resource detail request.");
      return backend.getKubernetesResourceDetail(bindingHandle as string, snapshotHandle as string, rowHandle as string);
    },
    getKubernetesPodLogs: async (...values: unknown[]) => {
      requireArity(values, 5, "Invalid Kubernetes pod log request.");
      const [bindingHandle, snapshotHandle, rowHandle, previous, container] = values;
      if (![bindingHandle, snapshotHandle, rowHandle].every(isKubernetesOpaqueHandle) || typeof previous !== "boolean" ||
        !(container === null || isKubernetesContainerName(container))) {
        refuse("Invalid Kubernetes pod log request.");
      }
      return backend.getKubernetesPodLogs(bindingHandle as string, snapshotHandle as string, rowHandle as string,
        previous as boolean, container as string | null);
    },
    planKubernetesWorkloadAction: async (...values: unknown[]) => {
      requireArity(values, 5, "Invalid Kubernetes workload action request.");
      const [bindingHandle, snapshotHandle, rowHandle, resourceName, action] = values;
      if (![bindingHandle, snapshotHandle, rowHandle].every(isKubernetesOpaqueHandle) ||
        !isKubernetesResourceName(resourceName) || !isKubernetesWriteAction(action)) {
        refuse("Invalid Kubernetes workload action request.");
      }
      return backend.planKubernetesWorkloadAction(bindingHandle as string, snapshotHandle as string, rowHandle as string, resourceName, action);
    },
    confirmKubernetesWorkloadAction: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid Kubernetes workload action plan handle.");
      const [bindingHandle, planHandle] = values;
      if (!isKubernetesOpaqueHandle(bindingHandle) || !isKubernetesOpaqueHandle(planHandle)) refuse("Invalid Kubernetes workload action plan handle.");
      return backend.confirmKubernetesWorkloadAction(bindingHandle, planHandle);
    },
    executeKubernetesWorkloadAction: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid Kubernetes workload action plan handle.");
      const [bindingHandle, planHandle] = values;
      if (!isKubernetesOpaqueHandle(bindingHandle) || !isKubernetesOpaqueHandle(planHandle)) refuse("Invalid Kubernetes workload action plan handle.");
      return backend.executeKubernetesWorkloadAction(bindingHandle, planHandle);
    },
    cancelKubernetesWorkloadAction: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid Kubernetes workload action plan handle.");
      const [bindingHandle, planHandle] = values;
      if (!isKubernetesOpaqueHandle(bindingHandle) || !isKubernetesOpaqueHandle(planHandle)) refuse("Invalid Kubernetes workload action plan handle.");
      return backend.cancelKubernetesWorkloadAction(bindingHandle, planHandle);
    },
    getDockerContainerChanges: async (...values: unknown[]) => {
      requireArity(values, 3, "Invalid container changes request.");
      const [bindingHandle, snapshotHandle, containerHandle] = values;
      if (![bindingHandle, snapshotHandle, containerHandle].every(isDockerOpaqueHandle)) {
        refuse("Invalid container changes request.");
      }
      return backend.getDockerContainerChanges(bindingHandle as string, snapshotHandle as string, containerHandle as string);
    },
    getDockerContainerProcesses: async (...values: unknown[]) => {
      requireArity(values, 3, "Invalid container processes request.");
      const [bindingHandle, snapshotHandle, containerHandle] = values;
      if (![bindingHandle, snapshotHandle, containerHandle].every(isDockerOpaqueHandle)) {
        refuse("Invalid container processes request.");
      }
      return backend.getDockerContainerProcesses(bindingHandle as string, snapshotHandle as string, containerHandle as string);
    },
    listDockerContainerDirectory: async (...values: unknown[]) => {
      requireArity(values, 4, "Invalid container directory request.");
      const [bindingHandle, snapshotHandle, containerHandle, path] = values;
      if (!isDockerOpaqueHandle(bindingHandle) || !isDockerOpaqueHandle(snapshotHandle) ||
        !isDockerOpaqueHandle(containerHandle) || !isExecDirectoryPath(path)) {
        refuse("Invalid container directory request.");
      }
      return backend.listDockerContainerDirectory(bindingHandle, snapshotHandle, containerHandle, path);
    },
    listKubernetesPodDirectory: async (...values: unknown[]) => {
      requireArity(values, 5, "Invalid pod directory request.");
      const [bindingHandle, snapshotHandle, rowHandle, path, container] = values;
      if (![bindingHandle, snapshotHandle, rowHandle].every(isKubernetesOpaqueHandle) || !isExecDirectoryPath(path) ||
        !(container === null || isKubernetesContainerName(container))) {
        refuse("Invalid pod directory request.");
      }
      return backend.listKubernetesPodDirectory(bindingHandle as string, snapshotHandle as string, rowHandle as string,
        path, container as string | null);
    },
    readKubernetesPodFile: async (...values: unknown[]) => {
      requireArity(values, 5, "Invalid pod file request.");
      const [bindingHandle, snapshotHandle, rowHandle, path, container] = values;
      if (![bindingHandle, snapshotHandle, rowHandle].every(isKubernetesOpaqueHandle) || !isExecFilePath(path) ||
        !(container === null || isKubernetesContainerName(container))) {
        refuse("Invalid pod file request.");
      }
      return backend.readKubernetesPodFile(bindingHandle as string, snapshotHandle as string, rowHandle as string,
        path, container as string | null);
    },
    openKubernetesPodTerminal: async (...values: unknown[]) => {
      requireArity(values, 4, "Invalid pod terminal launch request.");
      const [snapshotHandle, rowHandle, podName, container] = values;
      if (!isKubernetesOpaqueHandle(snapshotHandle) || !isKubernetesOpaqueHandle(rowHandle) ||
        !isKubernetesPodDisplayName(podName) || !(container === null || isKubernetesContainerName(container))) {
        refuse("Invalid pod terminal launch request.");
      }
      return verified(host("pod_terminal_open", { snapshotHandle, rowHandle, podName, container }),
        isTerminalWindowLaunchResult, "The terminal window launch result is invalid.");
    },
    exportKubernetesManifest: async (...values: unknown[]) => {
      requireArity(values, 3, "Invalid Kubernetes manifest export request.");
      const [bindingHandle, snapshotHandle, rowHandle] = values;
      if (![bindingHandle, snapshotHandle, rowHandle].every(isKubernetesOpaqueHandle)) {
        refuse("Invalid Kubernetes manifest export request.");
      }
      return verified(host("kubernetes_manifest_export", { bindingHandle, snapshotHandle, rowHandle }, DIALOG_TIMEOUT_MS),
        isKubernetesManifestExportResult, "The Kubernetes manifest export result is invalid.");
    },
    refreshDockerContainers: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid Docker container refresh request.");
      if (!isDockerOpaqueHandle(values[0])) refuse("Invalid Docker container refresh request.");
      return backend.refreshDockerContainers(values[0]);
    },
    getDockerCollection: async (...values: unknown[]) => {
      requireArity(values, 3, "Invalid Docker collection request.");
      const [bindingHandle, snapshotHandle, kind] = values;
      if (!isDockerOpaqueHandle(bindingHandle) || !isDockerOpaqueHandle(snapshotHandle) || !isDockerCollectionKind(kind)) {
        refuse("Invalid Docker collection request.");
      }
      return backend.getDockerCollection(bindingHandle, snapshotHandle, kind);
    },
    inspectDockerResource: async (...values: unknown[]) => {
      requireArity(values, 4, "Invalid Docker inspection request.");
      const [bindingHandle, snapshotHandle, kind, resourceHandle] = values;
      if (!isDockerOpaqueHandle(bindingHandle) || !isDockerOpaqueHandle(snapshotHandle) ||
        !isDockerResourceKind(kind) || !isDockerOpaqueHandle(resourceHandle)) {
        refuse("Invalid Docker inspection request.");
      }
      return backend.inspectDockerResource(bindingHandle, snapshotHandle, kind, resourceHandle);
    },
    getDockerSecurityAudit: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid Docker security audit request.");
      const [bindingHandle, snapshotHandle] = values;
      if (!isDockerOpaqueHandle(bindingHandle) || !isDockerOpaqueHandle(snapshotHandle)) refuse("Invalid Docker security audit request.");
      return backend.getDockerSecurityAudit(bindingHandle, snapshotHandle);
    },
    getDockerLogs: async (...values: unknown[]) => {
      requireArity(values, 4, "Invalid Docker log request.");
      const [bindingHandle, snapshotHandle, containerHandle, tail] = values;
      if (!isDockerOpaqueHandle(bindingHandle) || !isDockerOpaqueHandle(snapshotHandle) ||
        !isDockerOpaqueHandle(containerHandle) || !isDockerLogTail(tail)) {
        refuse("Invalid Docker log request.");
      }
      return backend.getDockerLogs(bindingHandle, snapshotHandle, containerHandle, tail);
    },
    planDockerContainerAction: async (...values: unknown[]) => {
      requireArity(values, 5, "Invalid Docker container action request.");
      const [bindingHandle, snapshotHandle, containerHandle, containerName, action] = values;
      if (!isDockerOpaqueHandle(bindingHandle) || !isDockerOpaqueHandle(snapshotHandle) ||
        !isDockerOpaqueHandle(containerHandle) || !isDockerContainerName(containerName) || !isDockerWriteAction(action)) {
        refuse("Invalid Docker container action request.");
      }
      return backend.planDockerContainerAction(bindingHandle, snapshotHandle, containerHandle, containerName, action);
    },
    confirmDockerContainerAction: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid Docker container action plan handle.");
      const [bindingHandle, planHandle] = values;
      if (!isDockerOpaqueHandle(bindingHandle) || !isDockerOpaqueHandle(planHandle)) refuse("Invalid Docker container action plan handle.");
      return backend.confirmDockerContainerAction(bindingHandle, planHandle);
    },
    executeDockerContainerAction: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid Docker container action plan handle.");
      const [bindingHandle, planHandle] = values;
      if (!isDockerOpaqueHandle(bindingHandle) || !isDockerOpaqueHandle(planHandle)) refuse("Invalid Docker container action plan handle.");
      return backend.executeDockerContainerAction(bindingHandle, planHandle);
    },
    cancelDockerContainerAction: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid Docker container action plan handle.");
      const [bindingHandle, planHandle] = values;
      if (!isDockerOpaqueHandle(bindingHandle) || !isDockerOpaqueHandle(planHandle)) refuse("Invalid Docker container action plan handle.");
      return backend.cancelDockerContainerAction(bindingHandle, planHandle);
    },
    readDockerContainerFile: async (...values: unknown[]) => {
      requireArity(values, 5, "Invalid Docker container file request.");
      const [bindingHandle, snapshotHandle, containerHandle, containerName, path] = values;
      if (!isDockerOpaqueHandle(bindingHandle) || !isDockerOpaqueHandle(snapshotHandle) ||
        !isDockerOpaqueHandle(containerHandle) || !isDockerContainerName(containerName) || !isDockerFilePath(path)) {
        refuse("Invalid Docker container file request.");
      }
      return backend.readDockerContainerFile(bindingHandle, snapshotHandle, containerHandle, containerName, path);
    },
    planDockerFileWrite: async (...values: unknown[]) => {
      requireArity(values, 3, "Invalid Docker container file write request.");
      const [bindingHandle, fileHandle, text] = values;
      if (!isDockerOpaqueHandle(bindingHandle) || !isDockerOpaqueHandle(fileHandle) || !isDockerFileText(text)) {
        refuse("Invalid Docker container file write request.");
      }
      return backend.planDockerFileWrite(bindingHandle, fileHandle, text);
    },
    planDockerFileCopy: async (...values: unknown[]) => {
      requireArity(values, 7, "Invalid Docker container file copy request.");
      const [bindingHandle, snapshotHandle, containerHandle, containerName, direction, source, target] = values;
      if (!isDockerOpaqueHandle(bindingHandle) || !isDockerOpaqueHandle(snapshotHandle) ||
        !isDockerOpaqueHandle(containerHandle) || !isDockerContainerName(containerName) ||
        !isDockerFileCopyDirection(direction) || !isDockerFilePath(source) || !isDockerFilePath(target)) {
        refuse("Invalid Docker container file copy request.");
      }
      return backend.planDockerFileCopy(bindingHandle, snapshotHandle, containerHandle, containerName, direction, source, target);
    },
    openDockerContainerTerminal: async (...values: unknown[]) => {
      requireArity(values, 3, "Invalid container terminal launch request.");
      const [snapshotHandle, containerHandle, containerName] = values;
      if (!isDockerOpaqueHandle(snapshotHandle) || !isDockerOpaqueHandle(containerHandle) || !isDockerContainerName(containerName)) {
        refuse("Invalid container terminal launch request.");
      }
      return verified(host("container_terminal_open", { snapshotHandle, containerHandle, containerName }),
        isTerminalWindowLaunchResult, "The terminal window launch result is invalid.");
    },
    loadEmergencyCommandCatalog: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid emergency command catalog request.");
      if (!isEmergencyCommandOpaqueHandle(values[0])) refuse("Invalid emergency command catalog request.");
      return backend.loadEmergencyCommandCatalog(values[0]);
    },
    runEmergencyCommand: async (...values: unknown[]) => {
      // The container handle is optional, as it was across the old preload.
      if (values.length !== 3 && values.length !== 4) refuse("Invalid emergency command run request.");
      const [bindingHandle, snapshotHandle, commandHandle, containerHandle] = values;
      if (!isEmergencyCommandOpaqueHandle(bindingHandle) || !isEmergencyCommandOpaqueHandle(snapshotHandle) ||
        !isEmergencyCommandOpaqueHandle(commandHandle) ||
        !(containerHandle === undefined || isEmergencyCommandOpaqueHandle(containerHandle))) {
        refuse("Invalid emergency command run request.");
      }
      return backend.runEmergencyCommand(bindingHandle, snapshotHandle, commandHandle, containerHandle);
    },
    inspectEmergencyPath: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid emergency path inspection request.");
      const [bindingHandle, pathHandle] = values;
      if (!isEmergencyCommandOpaqueHandle(bindingHandle) || !isEmergencyCommandOpaqueHandle(pathHandle)) {
        refuse("Invalid emergency path inspection request.");
      }
      return backend.inspectEmergencyPath(bindingHandle, pathHandle);
    },
    planEmergencyPathAction: async (...values: unknown[]) => {
      requireArity(values, 3, "Invalid emergency path plan request.");
      const [bindingHandle, pathHandle, action] = values;
      if (!isEmergencyCommandOpaqueHandle(bindingHandle) || !isEmergencyCommandOpaqueHandle(pathHandle) || !isEmergencyPathAction(action)) {
        refuse("Invalid emergency path plan request.");
      }
      return backend.planEmergencyPathAction(bindingHandle, pathHandle, action);
    },
    confirmEmergencyPathAction: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid emergency path plan handle.");
      const [bindingHandle, planHandle] = values;
      if (!isEmergencyCommandOpaqueHandle(bindingHandle) || !isEmergencyCommandOpaqueHandle(planHandle)) refuse("Invalid emergency path plan handle.");
      return backend.confirmEmergencyPathAction(bindingHandle, planHandle);
    },
    executeEmergencyPathAction: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid emergency path plan handle.");
      const [bindingHandle, planHandle] = values;
      if (!isEmergencyCommandOpaqueHandle(bindingHandle) || !isEmergencyCommandOpaqueHandle(planHandle)) refuse("Invalid emergency path plan handle.");
      return backend.executeEmergencyPathAction(bindingHandle, planHandle);
    },
    cancelEmergencyPathAction: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid emergency path plan handle.");
      const [bindingHandle, planHandle] = values;
      if (!isEmergencyCommandOpaqueHandle(bindingHandle) || !isEmergencyCommandOpaqueHandle(planHandle)) refuse("Invalid emergency path plan handle.");
      return backend.cancelEmergencyPathAction(bindingHandle, planHandle);
    },
    undoEmergencyPathAction: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid emergency path undo request.");
      const [bindingHandle, planHandle] = values;
      if (!isEmergencyCommandOpaqueHandle(bindingHandle) || !isEmergencyCommandOpaqueHandle(planHandle)) refuse("Invalid emergency path undo request.");
      return backend.undoEmergencyPathAction(bindingHandle, planHandle);
    },
    locateEmergencyHistoryCommand: async (...values: unknown[]) => {
      requireArity(values, 3, "Invalid emergency history lookup.");
      const [bindingHandle, snapshotHandle, historyId] = values;
      if (!isEmergencyCommandOpaqueHandle(bindingHandle) || !isEmergencyCommandOpaqueHandle(snapshotHandle) ||
        !isCommandHistoryId(historyId)) refuse("Invalid emergency history lookup.");
      return backend.locateEmergencyHistoryCommand(bindingHandle, snapshotHandle, historyId);
    },
    listPacketCaptureInterfaces: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid packet capture interface request.");
      if (!isPacketCaptureOpaqueHandle(values[0])) refuse("Invalid packet capture interface request.");
      return backend.listPacketCaptureInterfaces(values[0]);
    },
    startPacketCapture: async (...values: unknown[]) => {
      requireArity(values, 3, "Invalid packet capture start request.");
      const [bindingHandle, interfaceHandle, input] = values;
      if (!isPacketCaptureOpaqueHandle(bindingHandle) || !isPacketCaptureOpaqueHandle(interfaceHandle) || !isPacketCaptureStartInput(input)) {
        refuse("Invalid packet capture start request.");
      }
      return backend.startPacketCapture(bindingHandle, interfaceHandle, input);
    },
    pollPacketCapture: async (...values: unknown[]) => {
      requireArity(values, 3, "Invalid packet capture poll request.");
      const [bindingHandle, captureHandle, afterSequence] = values;
      if (!isPacketCaptureOpaqueHandle(bindingHandle) || !isPacketCaptureOpaqueHandle(captureHandle) || !isPacketCaptureCursor(afterSequence)) {
        refuse("Invalid packet capture poll request.");
      }
      return backend.pollPacketCapture(bindingHandle, captureHandle, afterSequence);
    },
    stopPacketCapture: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid packet capture stop request.");
      const [bindingHandle, captureHandle] = values;
      if (!isPacketCaptureOpaqueHandle(bindingHandle) || !isPacketCaptureOpaqueHandle(captureHandle)) refuse("Invalid packet capture stop request.");
      return backend.stopPacketCapture(bindingHandle, captureHandle);
    },
    listApplicationLogs: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid application log list request.");
      if (!isApplicationLogFilter(values[0])) refuse("Invalid application log list request.");
      return backend.listApplicationLogs(values[0]);
    },
    setApplicationLogLevel: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid application log level request.");
      if (!isApplicationLogLevel(values[0])) refuse("Invalid application log level request.");
      return backend.setApplicationLogLevel(values[0]);
    },
    clearApplicationLogBuffer: async (...values: unknown[]) => {
      requireArity(values, 0, "Invalid application log clear request.");
      return backend.clearApplicationLogBuffer();
    },
    getApplicationLogPreview: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid application log preview request.");
      if (!isApplicationLogFilter(values[0])) refuse("Invalid application log preview request.");
      return backend.getApplicationLogPreview(values[0]);
    },
    exportApplicationLogs: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid application log export request.");
      if (!isApplicationLogFilter(values[0])) refuse("Invalid application log export request.");
      return verified(host("application_log_export", { filter: values[0] }, DIALOG_TIMEOUT_MS),
        isApplicationLogExportResult, "The application log export result is invalid.");
    },
    getIntegrityPresets: async (...values: unknown[]) => {
      requireArity(values, 0, "Invalid file-integrity preset request.");
      return backend.getIntegrityPresets();
    },
    listIntegrityBaselines: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid file-integrity baseline list request.");
      if (!isIntegrityOpaqueHandle(values[0])) refuse("Invalid file-integrity baseline list request.");
      return backend.listIntegrityBaselines(values[0]);
    },
    startIntegrityComparison: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid file-integrity comparison request.");
      const [bindingHandle, baselineHandle] = values;
      if (!isIntegrityOpaqueHandle(bindingHandle) || !isIntegrityOpaqueHandle(baselineHandle) || bindingHandle === baselineHandle) {
        refuse("Invalid file-integrity comparison request.");
      }
      return backend.startIntegrityComparison(bindingHandle, baselineHandle);
    },
    pollIntegrityComparison: async (...values: unknown[]) => {
      requireArity(values, 4, "Invalid file-integrity poll request.");
      const [bindingHandle, operationHandle, afterEvent, limit] = values;
      if (!isIntegrityOpaqueHandle(bindingHandle) || !isIntegrityOpaqueHandle(operationHandle) ||
        bindingHandle === operationHandle || !isIntegrityPollRequest(afterEvent, limit)) {
        refuse("Invalid file-integrity poll request.");
      }
      return backend.pollIntegrityComparison(bindingHandle, operationHandle, afterEvent as number, limit as number);
    },
    cancelIntegrityComparison: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid file-integrity cancellation request.");
      const [bindingHandle, operationHandle] = values;
      if (!isIntegrityOpaqueHandle(bindingHandle) || !isIntegrityOpaqueHandle(operationHandle) || bindingHandle === operationHandle) {
        refuse("Invalid file-integrity cancellation request.");
      }
      return backend.cancelIntegrityComparison(bindingHandle, operationHandle);
    },
    startIntegrityBaselineCreation: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid file-integrity baseline request.");
      const [bindingHandle, presetIds] = values;
      if (!isIntegrityOpaqueHandle(bindingHandle) || !isIntegrityCreationRequest(presetIds)) {
        refuse("Invalid file-integrity baseline request.");
      }
      return backend.startIntegrityBaselineCreation(bindingHandle, [...(presetIds as IntegrityPresetId[])]);
    },
    pollIntegrityBaselineCreation: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid file-integrity baseline poll.");
      const [bindingHandle, operationHandle] = values;
      if (!isIntegrityOpaqueHandle(bindingHandle) || !isIntegrityOpaqueHandle(operationHandle) || bindingHandle === operationHandle) {
        refuse("Invalid file-integrity baseline poll.");
      }
      return backend.pollIntegrityBaselineCreation(bindingHandle, operationHandle);
    },
    cancelIntegrityBaselineCreation: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid file-integrity baseline cancellation.");
      const [bindingHandle, operationHandle] = values;
      if (!isIntegrityOpaqueHandle(bindingHandle) || !isIntegrityOpaqueHandle(operationHandle) || bindingHandle === operationHandle) {
        refuse("Invalid file-integrity baseline cancellation.");
      }
      return backend.cancelIntegrityBaselineCreation(bindingHandle, operationHandle);
    },
    loadSettings: async (...values: unknown[]) => {
      requireArity(values, 0, "Invalid settings load request.");
      return backend.loadSettings();
    },
    saveSettings: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid settings save request.");
      if (!isSettingsSaveInput(values[0])) refuse("Invalid settings save request.");
      return backend.saveSettings(values[0]);
    },
    setWindowTheme: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid window theme request.");
      const input = values[0];
      if (!isWindowThemeInput(input) || !isThemeId(input.theme)) refuse("Invalid window theme request.");
      const applied = await host("window_theme", { theme: input.theme, scrim: input.scrim });
      if (!isWindowThemeInput(applied) || applied.theme !== input.theme || applied.scrim !== input.scrim) {
        refuse("The window theme result is invalid.");
      }
      return applied as WindowThemeApplied;
    },
    replaceSettingsAiApiKey: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid AI key replacement request.");
      if (!isSettingsAiApiKeyReplacementInput(values[0])) refuse("Invalid AI key replacement request.");
      return backend.replaceSettingsAiApiKey(values[0]);
    },
    planSettingsAiApiKeyClear: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid AI key clear request.");
      if (!isSettingsProviderId(values[0])) refuse("Invalid AI key clear request.");
      return backend.planSettingsAiApiKeyClear(values[0]);
    },
    planSettingsAiProviderRemoval: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid AI provider removal request.");
      if (!isSettingsProviderId(values[0])) refuse("Invalid AI provider removal request.");
      return backend.planSettingsAiProviderRemoval(values[0]);
    },
    confirmSettingsMutation: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid settings confirmation request.");
      if (!isSettingsMutationHandle(values[0])) refuse("Invalid settings confirmation request.");
      return backend.confirmSettingsMutation(values[0]);
    },
    cancelSettingsMutation: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid settings cancellation request.");
      if (!isSettingsMutationHandle(values[0])) refuse("Invalid settings cancellation request.");
      return backend.cancelSettingsMutation(values[0]);
    },
    listAiHistory: async (...values: unknown[]) => {
      requireArity(values, 3, "Invalid AI history list request.");
      const [query, offset, limit] = values;
      if (!isAiHistoryQuery(query) || !isAiHistoryPageRequest(offset, limit)) refuse("Invalid AI history list request.");
      return backend.listAiHistory(query, offset as number, limit as number);
    },
    getAiHistoryRecord: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid AI history record request.");
      if (!isAiHistoryId(values[0])) refuse("Invalid AI history record request.");
      return backend.getAiHistoryRecord(values[0]);
    },
    planAiHistoryRemove: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid AI history removal request.");
      if (!isAiHistoryId(values[0])) refuse("Invalid AI history removal request.");
      return backend.planAiHistoryRemove(values[0]);
    },
    planAiHistoryClear: async (...values: unknown[]) => {
      requireArity(values, 0, "Invalid AI history clear plan request.");
      return backend.planAiHistoryClear();
    },
    confirmAiHistoryMutation: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid AI history confirmation request.");
      if (!isAiHistoryOpaqueHandle(values[0])) refuse("Invalid AI history confirmation request.");
      return backend.confirmAiHistoryMutation(values[0]);
    },
    cancelAiHistoryMutation: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid AI history cancellation request.");
      if (!isAiHistoryOpaqueHandle(values[0])) refuse("Invalid AI history cancellation request.");
      return backend.cancelAiHistoryMutation(values[0]);
    },
    exportAiHistory: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid AI history export request.");
      if (!isAiHistoryExportFormat(values[0])) refuse("Invalid AI history export request.");
      return verified(host("ai_history_export", { format: values[0] }, DIALOG_TIMEOUT_MS),
        isAiHistoryExportResult, "The AI history export result is invalid.");
    },
    listCommandHistory: async (...values: unknown[]) => {
      requireArity(values, 4, "Invalid command history list request.");
      const [bindingHandle, query, offset, limit] = values;
      if (!isCommandHistoryOpaqueHandle(bindingHandle) || !isCommandHistoryQuery(query) ||
        !isCommandHistoryPageRequest(offset, limit)) {
        refuse("Invalid command history list request.");
      }
      return backend.listCommandHistory(bindingHandle, query, offset as number, limit as number);
    },
    getCommandHistory: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid command history request.");
      const [bindingHandle, recordId] = values;
      if (!isCommandHistoryOpaqueHandle(bindingHandle) || !isCommandHistoryId(recordId)) refuse("Invalid command history request.");
      return backend.getCommandHistory(bindingHandle, recordId);
    },
    planCommandReplay: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid command replay request.");
      const [bindingHandle, recordId] = values;
      if (!isCommandHistoryOpaqueHandle(bindingHandle) || !isCommandHistoryId(recordId)) refuse("Invalid command replay request.");
      return backend.planCommandReplay(bindingHandle, recordId);
    },
    planCommandHistoryRemove: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid command history removal request.");
      const [bindingHandle, recordId] = values;
      if (!isCommandHistoryOpaqueHandle(bindingHandle) || !isCommandHistoryId(recordId)) refuse("Invalid command history removal request.");
      return backend.planCommandHistoryRemove(bindingHandle, recordId);
    },
    planCommandHistoryClear: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid command history clear request.");
      if (!isCommandHistoryOpaqueHandle(values[0])) refuse("Invalid command history clear request.");
      return backend.planCommandHistoryClear(values[0]);
    },
    confirmCommandHistoryMutation: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid command history confirmation request.");
      const [bindingHandle, mutationHandle] = values;
      if (!isCommandHistoryOpaqueHandle(bindingHandle) || !isCommandHistoryOpaqueHandle(mutationHandle)) {
        refuse("Invalid command history confirmation request.");
      }
      return backend.confirmCommandHistoryMutation(bindingHandle, mutationHandle);
    },
    cancelCommandHistoryMutation: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid command history cancellation request.");
      const [bindingHandle, mutationHandle] = values;
      if (!isCommandHistoryOpaqueHandle(bindingHandle) || !isCommandHistoryOpaqueHandle(mutationHandle)) {
        refuse("Invalid command history cancellation request.");
      }
      return backend.cancelCommandHistoryMutation(bindingHandle, mutationHandle);
    },
    generateDisposalReport: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid disposal report generation request.");
      if (!isDisposalReportOpaqueHandle(values[0])) refuse("Invalid disposal report generation request.");
      return backend.generateDisposalReport(values[0]);
    },
    getDisposalReportContent: async (...values: unknown[]) => {
      requireArity(values, 3, "Invalid disposal report content request.");
      const [bindingHandle, reportHandle, format] = values;
      if (!isDisposalReportOpaqueHandle(bindingHandle) || !isDisposalReportOpaqueHandle(reportHandle) ||
        !isDisposalReportPreviewFormat(format)) {
        refuse("Invalid disposal report content request.");
      }
      return backend.getDisposalReportContent(bindingHandle, reportHandle, format);
    },
    exportDisposalReport: async (...values: unknown[]) => {
      requireArity(values, 3, "Invalid disposal report export request.");
      const [bindingHandle, reportHandle, format] = values;
      if (!isDisposalReportOpaqueHandle(bindingHandle) || !isDisposalReportOpaqueHandle(reportHandle) ||
        !isDisposalReportExportFormat(format)) {
        refuse("Invalid disposal report export request.");
      }
      return verified(host("disposal_report_export", { bindingHandle, reportHandle, format }, DIALOG_TIMEOUT_MS),
        isDisposalReportExportResult, "The disposal report export result is invalid.");
    },
    getConfigCatalog: async (...values: unknown[]) => {
      requireArity(values, 0, "Invalid configuration catalog request.");
      return backend.getConfigCatalog();
    },
    generateConfig: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid configuration generation request.");
      if (!isConfigGenerateInput(values[0])) refuse("Invalid configuration generation request.");
      return backend.generateConfig(values[0]);
    },
    reviseConfig: async (...values: unknown[]) => {
      requireArity(values, 3, "Invalid configuration revision request.");
      const [handle, revision, input] = values;
      if (!isConfigIdentifier(handle) || !isConfigRevision(revision) || !isConfigGenerateInput(input)) {
        refuse("Invalid configuration revision request.");
      }
      return backend.reviseConfig(handle, revision, input);
    },
    copyConfig: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid configuration copy request.");
      const [handle, revision] = values;
      if (!isConfigIdentifier(handle) || !isConfigRevision(revision)) refuse("Invalid configuration copy request.");
      return verified(host("config_copy", { handle, revision }, 60_000), isConfigClipboardResult,
        "The configuration copy result is invalid.");
    },
    exportConfigArtifact: async (...values: unknown[]) => {
      requireArity(values, 3, "Invalid configuration export request.");
      const [handle, revision, artifactKey] = values;
      if (!isConfigIdentifier(handle) || !isConfigRevision(revision) || !isConfigIdentifier(artifactKey)) {
        refuse("Invalid configuration export request.");
      }
      return verified(host("config_artifact_export", { handle, revision, artifactKey }, DIALOG_TIMEOUT_MS),
        isConfigExportResult, "The configuration export result is invalid.");
    },
    exportConfigBundle: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid configuration export request.");
      const [handle, revision] = values;
      if (!isConfigIdentifier(handle) || !isConfigRevision(revision)) refuse("Invalid configuration export request.");
      return verified(host("config_bundle_export", { handle, revision }, DIALOG_TIMEOUT_MS),
        isConfigBundleExportResult, "The configuration export result is invalid.");
    },
    configVisual: async (...values: unknown[]) => {
      requireArity(values, 1, "可视化编辑请求无效。");
      if (!isConfigVisualRequest(values[0])) refuse("可视化编辑请求无效。");
      return backend.configVisual(values[0]);
    },
    importConfigVisual: async (...values: unknown[]) => {
      requireArity(values, 1, "导入请求无效。");
      const [product] = values;
      if (!isConfigVisualProduct(product)) refuse("导入请求无效。");
      const result = await host("config_visual_import", { product }, DIALOG_TIMEOUT_MS);
      if (result === null) return null;
      if (!isConfigVisualView(result) || result.source !== "import" || result.revision !== 1 ||
        result.product !== product) {
        refuse("导入结果未通过校验。");
      }
      return result;
    },
    importConfigVisualDatabase: async (...values: unknown[]) => {
      requireArity(values, 1, "导入请求无效。");
      const [artifactKey] = values;
      if (typeof artifactKey !== "string" || !/^[a-z0-9][a-z0-9.-]{0,127}$/u.test(artifactKey)) refuse("导入请求无效。");
      const result = await host("config_visual_import_database", { artifactKey }, DIALOG_TIMEOUT_MS);
      if (result === null) return null;
      if (!isConfigVisualView(result) || result.source !== "import" || result.revision !== 1 ||
        result.product !== "database" || result.database?.artifactKey !== artifactKey) {
        refuse("导入结果未通过校验。");
      }
      return result;
    },
    copyConfigVisual: async (...values: unknown[]) => {
      requireArity(values, 2, "配置复制请求无效。");
      const [documentHandle, revision] = values;
      if (!isConfigIdentifier(documentHandle) || !isConfigRevision(revision)) refuse("配置复制请求无效。");
      return verified(host("config_visual_copy", { documentHandle, revision }, 60_000),
        isConfigVisualCopyResult, "配置复制结果未通过校验。");
    },
    saveConfigVisual: async (...values: unknown[]) => {
      requireArity(values, 2, "配置保存请求无效。");
      const [documentHandle, revision] = values;
      if (!isConfigIdentifier(documentHandle) || !isConfigRevision(revision)) refuse("配置保存请求无效。");
      return verified(host("config_visual_save", { documentHandle, revision }, DIALOG_TIMEOUT_MS),
        isConfigVisualSaveResult, "配置保存结果未通过校验。");
    },
    closeConfigDraft: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid configuration close request.");
      const [handle, revision] = values;
      if (!isConfigIdentifier(handle) || !isConfigRevision(revision)) refuse("Invalid configuration close request.");
      return backend.closeConfigDraft(handle, revision);
    },
    setSecurityReferenceFavorites: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid security-reference favorites.");
      const value = values[0];
      if (!Array.isArray(value) || value.length > 512 ||
        !value.every((item) => typeof item === "string" && item.length <= 128)) {
        refuse("Invalid security-reference favorites.");
      }
      return backend.setSecurityReferenceFavorites(value as string[]);
    },
    listNotes: async (...values: unknown[]) => {
      requireArity(values, 3, "Invalid notes list request.");
      const [query, offset, limit] = values;
      if (!boundedString(query, 256) || !Number.isSafeInteger(offset) || (offset as number) < 0 ||
        (offset as number) > 100_000 || !Number.isSafeInteger(limit) || (limit as number) < 1 || (limit as number) > 100) {
        refuse("Invalid notes list request.");
      }
      return backend.listNotes(query, offset as number, limit as number);
    },
    getNote: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid note get request.");
      if (!isNoteId(values[0])) refuse("Invalid note identifier.");
      return backend.getNote(values[0]);
    },
    createNote: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid note creation request.");
      if (!isNoteCreate(values[0])) refuse("Invalid note creation request.");
      return backend.createNote(values[0] as Parameters<LovelyHawkApi["createNote"]>[0]);
    },
    updateNote: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid note update request.");
      if (!isNoteUpdate(values[0])) refuse("Invalid note update request.");
      return backend.updateNote(values[0] as Parameters<LovelyHawkApi["updateNote"]>[0]);
    },
    setNotePinned: async (...values: unknown[]) => {
      requireArity(values, 4, "Invalid note pin request.");
      const [id, pinned, expectedRevision, mutationId] = values;
      if (!isNoteId(id) || typeof pinned !== "boolean" || !isNoteRevision(expectedRevision) || !isMutationId(mutationId)) {
        refuse("Invalid note pin request.");
      }
      return backend.setNotePinned(id, pinned, expectedRevision, mutationId);
    },
    addNoteTag: async (...values: unknown[]) => {
      requireArity(values, 4, "Invalid note tag request.");
      const [id, tag, expectedRevision, mutationId] = values;
      if (!isNoteId(id) || !boundedString(tag, 64, false) || !isNoteRevision(expectedRevision) || !isMutationId(mutationId)) {
        refuse("Invalid note tag request.");
      }
      return backend.addNoteTag(id, tag, expectedRevision, mutationId);
    },
    removeNoteTag: async (...values: unknown[]) => {
      requireArity(values, 4, "Invalid note tag request.");
      const [id, tag, expectedRevision, mutationId] = values;
      if (!isNoteId(id) || !boundedString(tag, 64, false) || !isNoteRevision(expectedRevision) || !isMutationId(mutationId)) {
        refuse("Invalid note tag request.");
      }
      return backend.removeNoteTag(id, tag, expectedRevision, mutationId);
    },
    planNoteDelete: async (...values: unknown[]) => {
      requireArity(values, 3, "Invalid note delete plan request.");
      const [id, expectedRevision, mutationId] = values;
      if (!isNoteId(id) || !isNoteRevision(expectedRevision) || !isMutationId(mutationId)) refuse("Invalid note delete plan request.");
      return backend.planNoteDelete(id, expectedRevision, mutationId);
    },
    confirmNoteDelete: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid delete confirmation request.");
      const [handle, mutationId] = values;
      if (!boundedString(handle, 128, false) || !isMutationId(mutationId)) refuse("Invalid delete plan handle.");
      return backend.confirmNoteDelete(handle, mutationId);
    },
    cancelNoteDelete: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid delete cancellation request.");
      const [handle, mutationId] = values;
      if (!boundedString(handle, 128, false) || !isMutationId(mutationId)) refuse("Invalid delete plan handle.");
      return backend.cancelNoteDelete(handle, mutationId);
    },
    exportNotes: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid notes export request.");
      const id = values[0];
      if (id !== null && !isNoteId(id)) refuse("Invalid notes export request.");
      return backend.exportNotes(id as string | null);
    },
    writeClipboard: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid clipboard payload.");
      const text = values[0];
      if (typeof text !== "string" || utf8ByteLength(text) > MAX_CLIPBOARD_BYTES) refuse("Invalid clipboard payload.");
      await host("clipboard_write", { text });
    },
    unsavedEditorCount: async (...values: unknown[]) => {
      requireArity(values, 0, "Invalid unsaved-editor request.");
      const value = await host("unsaved_editor_count");
      const count = (value as { count?: unknown } | null)?.count;
      if (typeof count !== "number" || !Number.isSafeInteger(count) || count < 0 || count > 1_000) {
        refuse("The unsaved-editor count is invalid.");
      }
      return count;
    },
    onBeforeClose: (handler: (context: BeforeCloseContext) => Promise<boolean>) => {
      let disposed = false;
      let unlisten: (() => void) | null = null;
      void listen(BEFORE_CLOSE_EVENT, (event) => {
        // The host numbers each close request so an answer that arrives after a
        // newer request cannot decide it.
        const payload = event.payload as { request?: unknown; unsavedEditors?: unknown } | null;
        const request = payload?.request;
        if (typeof request !== "number" || !Number.isSafeInteger(request) || request < 1) return;
        const unsavedEditors = payload?.unsavedEditors;
        // An unreadable count is treated as "some", so the operator is asked.
        const context: BeforeCloseContext = {
          unsavedEditors: typeof unsavedEditors === "number" && Number.isSafeInteger(unsavedEditors) && unsavedEditors >= 0
            ? unsavedEditors
            : 1,
        };
        void handler(context).then(
          (allowed) => host("close_decision", { request, allowed: allowed === true }),
          () => host("close_decision", { request, allowed: false }),
        ).catch(() => undefined);
      }).then((stop) => {
        if (disposed) stop();
        else unlisten = stop;
      });
      return () => {
        disposed = true;
        unlisten?.();
      };
    },
    notifyRendererReady: () => {
      void host("renderer_ready").catch(() => undefined);
    },
  } as LovelyHawkApi;
  return Object.freeze(api);
}
