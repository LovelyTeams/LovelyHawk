import { describe, expect, it } from "vitest";

import {
  BACKEND_PROTOCOL,
  isBootstrapResult,
  isConnectionDeletePrompt,
  isConnectionDeleteResult,
  isConnectionEditView,
  isConnectionCredentialFileChoice,
  isConnectionCredentialFileKind,
  isConnectionExportResult,
  isConnectionImportResult,
  isConnectionSummaryArray,
  isConnectionWriteInput,
  isNoteDeleteProposal,
  isNoteListPage,
  isNoteResult,
  isSystemInfoCatalog,
  SYSTEM_INFO_CATALOG,
  type LovelyHawkApi,
  type AiHistoryExportResult,
  type AiHistoryListPage,
  type AiHistoryMutationCancellation,
  type AiHistoryMutationProposal,
  type AiHistoryMutationResult,
  type AiHistoryRecord,
  type BaselineCatalog,
  type BaselineHistory,
  type BaselineScan,
  type PacketCaptureInterfaceList,
  type PacketCapturePoll,
  type PacketCaptureStarted,
  type PacketCaptureStartInput,
  type PacketCaptureStopped,
  type ApplicationLogClearResult,
  type ApplicationLogExportResult,
  type ApplicationLogFilter,
  type ApplicationLogLevelResult,
  type ApplicationLogPreview,
  type ApplicationLogSnapshot,
  type IntegrityBaselineList,
  type IntegrityComparisonCancellation,
  type IntegrityComparisonPoll,
  type IntegrityComparisonStarted,
  type IntegrityPresetCatalog,
  type CommandHistoryListPage,
  type CommandHistoryMutationCancellation,
  type CommandHistoryMutationProposal,
  type CommandHistoryMutationResult,
  type CommandHistoryRecord,
  type CommandReplayIntent,
  type DisposalReportContent,
  type DisposalReportExportResult,
  type DisposalReportSnapshot,
  type DockerCollectionKind,
  type DockerContainerSnapshot,
  type DockerLogs,
  type DockerReadCollection,
  type DockerReadInspection,
  type DockerResourceKind,
  type DockerSecurityAudit,
  type KubernetesAvailability,
  type KubernetesListInput,
  type KubernetesSnapshot,
  type KubernetesTextResult,
  type SettingsSaveInput,
  type SettingsAiApiKeyReplacementResult,
  type SettingsMutationCancellation,
  type SettingsMutationProposal,
  type SettingsMutationResult,
  type SettingsSnapshot,
  type SystemInfoDetail,
  type SystemInfoSummary,
  type SystemInfoTable,
  type TerminalWindowLaunchResult,
} from "./contract";

describe("backend response validation", () => {
  it("re-exports exactly five process-local application log methods with concrete results", () => {
    const api: Pick<
      LovelyHawkApi,
      | "listApplicationLogs"
      | "setApplicationLogLevel"
      | "clearApplicationLogBuffer"
      | "getApplicationLogPreview"
      | "exportApplicationLogs"
    > = {
      listApplicationLogs: async (_filter: ApplicationLogFilter) => ({}) as ApplicationLogSnapshot,
      setApplicationLogLevel: async () => ({}) as ApplicationLogLevelResult,
      clearApplicationLogBuffer: async () => ({}) as ApplicationLogClearResult,
      getApplicationLogPreview: async () => ({}) as ApplicationLogPreview,
      exportApplicationLogs: async () => ({}) as ApplicationLogExportResult,
    };
    expect(Object.keys(api)).toEqual([
      "listApplicationLogs",
      "setApplicationLogLevel",
      "clearApplicationLogBuffer",
      "getApplicationLogPreview",
      "exportApplicationLogs",
    ]);
  });

  it("re-exports exact five binding-only Integrity methods with concrete results", () => {
    const api: Pick<
      LovelyHawkApi,
      | "getIntegrityPresets"
      | "listIntegrityBaselines"
      | "startIntegrityComparison"
      | "pollIntegrityComparison"
      | "cancelIntegrityComparison"
    > = {
      getIntegrityPresets: async () => ({}) as IntegrityPresetCatalog,
      listIntegrityBaselines: async (_bindingHandle: string) => ({}) as IntegrityBaselineList,
      startIntegrityComparison: async (_bindingHandle: string, _baselineHandle: string) =>
        ({}) as IntegrityComparisonStarted,
      pollIntegrityComparison: async (
        _bindingHandle: string,
        _operationHandle: string,
        _afterEvent: number,
        _limit: number,
      ) => ({}) as IntegrityComparisonPoll,
      cancelIntegrityComparison: async (_bindingHandle: string, _operationHandle: string) =>
        ({}) as IntegrityComparisonCancellation,
    };
    expect(Object.keys(api)).toEqual([
      "getIntegrityPresets",
      "listIntegrityBaselines",
      "startIntegrityComparison",
      "pollIntegrityComparison",
      "cancelIntegrityComparison",
    ]);
    expect(api.getIntegrityPresets).toHaveLength(0);
    expect(api.listIntegrityBaselines).toHaveLength(1);
    expect(api.startIntegrityComparison).toHaveLength(2);
    expect(api.pollIntegrityComparison).toHaveLength(4);
    expect(api.cancelIntegrityComparison).toHaveLength(2);
  });

  it("re-exports exactly three Baseline read methods with concrete bounded results", () => {
    const api: Pick<
      LovelyHawkApi,
      "getBaselineCatalog" | "scanBaseline" | "listBaselineHistory"
    > = {
      getBaselineCatalog: async () => ({}) as BaselineCatalog,
      scanBaseline: async (_bindingHandle: string) => ({}) as BaselineScan,
      listBaselineHistory: async (_bindingHandle: string) => ({}) as BaselineHistory,
    };
    expect(Object.keys(api)).toEqual([
      "getBaselineCatalog",
      "scanBaseline",
      "listBaselineHistory",
    ]);
    expect(api.getBaselineCatalog).toHaveLength(0);
    expect(api.scanBaseline).toHaveLength(1);
    expect(api.listBaselineHistory).toHaveLength(1);
  });

  it("re-exports exactly four target-opaque Kubernetes read methods", () => {
    const api: Pick<
      LovelyHawkApi,
      | "getKubernetesAvailability"
      | "listKubernetesResources"
      | "getKubernetesResourceDetail"
      | "getKubernetesPodLogs"
    > = {
      getKubernetesAvailability: async (_bindingHandle: string) => ({}) as KubernetesAvailability,
      listKubernetesResources: async (
        _bindingHandle: string,
        _input: KubernetesListInput,
      ) => ({}) as KubernetesSnapshot,
      getKubernetesResourceDetail: async (
        _bindingHandle: string,
        _snapshotHandle: string,
        _rowHandle: string,
      ) => ({}) as KubernetesTextResult,
      getKubernetesPodLogs: async (
        _bindingHandle: string,
        _snapshotHandle: string,
        _rowHandle: string,
        _previous: boolean,
      ) => ({}) as KubernetesTextResult,
    };
    expect(Object.keys(api)).toEqual([
      "getKubernetesAvailability",
      "listKubernetesResources",
      "getKubernetesResourceDetail",
      "getKubernetesPodLogs",
    ]);
    expect(api.getKubernetesAvailability).toHaveLength(1);
    expect(api.listKubernetesResources).toHaveLength(2);
    expect(api.getKubernetesResourceDetail).toHaveLength(3);
    expect(api.getKubernetesPodLogs).toHaveLength(4);
  });

  it("re-exports exactly five target-opaque Docker read methods", () => {
    const api: Pick<
      LovelyHawkApi,
      | "refreshDockerContainers"
      | "getDockerCollection"
      | "inspectDockerResource"
      | "getDockerSecurityAudit"
      | "getDockerLogs"
    > = {
      refreshDockerContainers: async (_bindingHandle: string) => ({}) as DockerContainerSnapshot,
      getDockerCollection: async (
        _bindingHandle: string,
        _snapshotHandle: string,
        _kind: DockerCollectionKind,
      ) => ({}) as DockerReadCollection,
      inspectDockerResource: async (
        _bindingHandle: string,
        _snapshotHandle: string,
        _kind: DockerResourceKind,
        _resourceHandle: string,
      ) => ({}) as DockerReadInspection,
      getDockerSecurityAudit: async (
        _bindingHandle: string,
        _snapshotHandle: string,
      ) => ({}) as DockerSecurityAudit,
      getDockerLogs: async (
        _bindingHandle: string,
        _snapshotHandle: string,
        _containerHandle: string,
        _tail: number,
      ) => ({}) as DockerLogs,
    };
    expect(Object.keys(api)).toEqual([
      "refreshDockerContainers",
      "getDockerCollection",
      "inspectDockerResource",
      "getDockerSecurityAudit",
      "getDockerLogs",
    ]);
    expect(api.refreshDockerContainers).toHaveLength(1);
    expect(api.getDockerCollection).toHaveLength(3);
    expect(api.inspectDockerResource).toHaveLength(4);
    expect(api.getDockerSecurityAudit).toHaveLength(2);
    expect(api.getDockerLogs).toHaveLength(4);
  });

  it("re-exports exactly four binding-only Packet Capture Live methods", () => {
    const api: Pick<
      LovelyHawkApi,
      | "listPacketCaptureInterfaces"
      | "startPacketCapture"
      | "pollPacketCapture"
      | "stopPacketCapture"
    > = {
      listPacketCaptureInterfaces: async (_bindingHandle: string) =>
        ({}) as PacketCaptureInterfaceList,
      startPacketCapture: async (
        _bindingHandle: string,
        _interfaceHandle: string,
        _input: PacketCaptureStartInput,
      ) => ({}) as PacketCaptureStarted,
      pollPacketCapture: async (
        _bindingHandle: string,
        _captureHandle: string,
        _afterSequence: number,
      ) => ({}) as PacketCapturePoll,
      stopPacketCapture: async (_bindingHandle: string, _captureHandle: string) =>
        ({}) as PacketCaptureStopped,
    };
    expect(Object.keys(api)).toEqual([
      "listPacketCaptureInterfaces",
      "startPacketCapture",
      "pollPacketCapture",
      "stopPacketCapture",
    ]);
    expect(api.listPacketCaptureInterfaces).toHaveLength(1);
    expect(api.startPacketCapture).toHaveLength(3);
    expect(api.pollPacketCapture).toHaveLength(3);
    expect(api.stopPacketCapture).toHaveLength(2);
  });

  it("exposes one handle-free main-window terminal launch method", () => {
    const api: Pick<LovelyHawkApi, "openSshTerminal"> = {
      openSshTerminal: async () => ({ opened: true, reused: false }) satisfies TerminalWindowLaunchResult,
    };
    expect(Object.keys(api)).toEqual(["openSshTerminal"]);
    expect(api.openSshTerminal).toHaveLength(0);
  });

  it("fixes exactly five public Settings secret lifecycle methods", () => {
    const api: Pick<
      LovelyHawkApi,
      | "replaceSettingsAiApiKey"
      | "planSettingsAiApiKeyClear"
      | "planSettingsAiProviderRemoval"
      | "confirmSettingsMutation"
      | "cancelSettingsMutation"
    > = {
      replaceSettingsAiApiKey: async () => ({}) as SettingsAiApiKeyReplacementResult,
      planSettingsAiApiKeyClear: async () => ({}) as SettingsMutationProposal,
      planSettingsAiProviderRemoval: async () => ({}) as SettingsMutationProposal,
      confirmSettingsMutation: async () => ({}) as SettingsMutationResult,
      cancelSettingsMutation: async () => ({}) as SettingsMutationCancellation,
    };
    expect(Object.keys(api)).toEqual([
      "replaceSettingsAiApiKey",
      "planSettingsAiApiKeyClear",
      "planSettingsAiProviderRemoval",
      "confirmSettingsMutation",
      "cancelSettingsMutation",
    ]);
  });

  it("fixes exactly three target-scoped public disposal report methods", () => {
    const api: Pick<
      LovelyHawkApi,
      | "generateDisposalReport"
      | "getDisposalReportContent"
      | "exportDisposalReport"
    > = {
      generateDisposalReport: async () => ({}) as DisposalReportSnapshot,
      getDisposalReportContent: async () => ({}) as DisposalReportContent,
      exportDisposalReport: async () => ({}) as DisposalReportExportResult,
    };
    expect(Object.keys(api)).toEqual([
      "generateDisposalReport",
      "getDisposalReportContent",
      "exportDisposalReport",
    ]);
  });

  it("fixes exactly seven public command history methods with concrete results", () => {
    const api: Pick<
      LovelyHawkApi,
      | "listCommandHistory"
      | "getCommandHistory"
      | "planCommandReplay"
      | "planCommandHistoryRemove"
      | "planCommandHistoryClear"
      | "confirmCommandHistoryMutation"
      | "cancelCommandHistoryMutation"
    > = {
      listCommandHistory: async () => ({}) as CommandHistoryListPage,
      getCommandHistory: async () => ({}) as CommandHistoryRecord,
      planCommandReplay: async () => ({}) as CommandReplayIntent,
      planCommandHistoryRemove: async () => ({}) as CommandHistoryMutationProposal,
      planCommandHistoryClear: async () => ({}) as CommandHistoryMutationProposal,
      confirmCommandHistoryMutation: async () => ({}) as CommandHistoryMutationResult,
      cancelCommandHistoryMutation: async () => ({}) as CommandHistoryMutationCancellation,
    };
    expect(Object.keys(api)).toEqual([
      "listCommandHistory",
      "getCommandHistory",
      "planCommandReplay",
      "planCommandHistoryRemove",
      "planCommandHistoryClear",
      "confirmCommandHistoryMutation",
      "cancelCommandHistoryMutation",
    ]);
  });

  it("fixes exactly seven public AI history methods", () => {
    const api: Pick<
      LovelyHawkApi,
      | "listAiHistory"
      | "getAiHistoryRecord"
      | "planAiHistoryRemove"
      | "planAiHistoryClear"
      | "confirmAiHistoryMutation"
      | "cancelAiHistoryMutation"
      | "exportAiHistory"
    > = {
      listAiHistory: async () => ({}) as AiHistoryListPage,
      getAiHistoryRecord: async () => ({}) as AiHistoryRecord,
      planAiHistoryRemove: async () => ({}) as AiHistoryMutationProposal,
      planAiHistoryClear: async () => ({}) as AiHistoryMutationProposal,
      confirmAiHistoryMutation: async () => ({}) as AiHistoryMutationResult,
      cancelAiHistoryMutation: async () => ({}) as AiHistoryMutationCancellation,
      exportAiHistory: async () => ({}) as AiHistoryExportResult,
    };
    expect(Object.keys(api)).toEqual([
      "listAiHistory",
      "getAiHistoryRecord",
      "planAiHistoryRemove",
      "planAiHistoryClear",
      "confirmAiHistoryMutation",
      "cancelAiHistoryMutation",
      "exportAiHistory",
    ]);
  });

  it("re-exports the closed system-info/settings contracts and fixes six public API methods", () => {
    const catalog = SYSTEM_INFO_CATALOG.map((entry) => ({
      ...entry,
      columns: [...entry.columns],
    }));
    expect(isSystemInfoCatalog(catalog)).toBe(true);

    const api: Pick<
      LovelyHawkApi,
      | "getSystemInfoCatalog"
      | "getSystemInfoSummary"
      | "collectSystemInfo"
      | "getSystemInfoDetail"
      | "loadSettings"
      | "saveSettings"
    > = {
      getSystemInfoCatalog: async () => catalog,
      getSystemInfoSummary: async () => ({}) as SystemInfoSummary,
      collectSystemInfo: async () => ({}) as SystemInfoTable,
      getSystemInfoDetail: async () => ({}) as SystemInfoDetail,
      loadSettings: async () => ({}) as SettingsSnapshot,
      saveSettings: async (_input: SettingsSaveInput) => ({}) as SettingsSnapshot,
    };
    expect(Object.keys(api)).toEqual([
      "getSystemInfoCatalog",
      "getSystemInfoSummary",
      "collectSystemInfo",
      "getSystemInfoDetail",
      "loadSettings",
      "saveSettings",
    ]);
  });

  it("rejects duplicate or incomplete page registries", () => {
    const page = {
      id: "system-info",
      group: "target",
      title: "主机全景",
      icon: "◎",
      capability: "connected-target",
      summary: "summary",
      primaryAction: "refresh",
      sections: ["one"],
      migrationState: "pending",
    };
    expect(
      isBootstrapResult({
        productName: "LovelyHawk",
        appVersion: "1.0.0",
        protocolVersion: BACKEND_PROTOCOL,
        pages: Array.from({ length: 19 }, () => page),
        securityReferenceFavoriteIds: [],
      }),
    ).toBe(false);
  });

  it("accepts the credential-free connection summary and rejects shape drift", () => {
    const summary = {
      id: "one",
      name: "one",
      host: "127.0.0.1",
      port: 22,
      username: "root",
      authMethod: "password",
      tags: ["critical"],
      group: null,
      environment: null,
      lastConnectedAt: null,
      hasPassword: true,
      hasKeyPassphrase: false,
      jumpHostHasPassword: false,
      jumpHostHasKeyPassphrase: false,
    };
    expect(isConnectionSummaryArray([summary])).toBe(true);
    expect(isConnectionSummaryArray([{ ...summary, password: "must-not-return" }])).toBe(false);
    expect(
      isConnectionSummaryArray([
        {
          ...summary,
          port: 0,
          authMethod: "shell",
        },
      ]),
    ).toBe(false);
  });

  it("validates connection write secrets as bounded, write-only discriminated inputs", () => {
    const connection = {
      id: "server-1",
      name: "Incident host",
      host: "10.0.0.8",
      port: 22,
      username: "root",
      authMethod: "password",
      privateKeyPath: null,
      certificatePath: null,
      agentIdentityFingerprint: null,
      jumpHost: null,
      tags: ["critical"],
      notes: "plain text",
      environment: "competition",
      role: null,
      group: "red-team",
    };
    const input = {
      connection,
      secrets: { password: { action: "replace", value: "never-return-this" } },
    };
    expect(isConnectionWriteInput(input)).toBe(true);
    expect(isConnectionWriteInput({ ...input, debug: true })).toBe(false);
    expect(
      isConnectionWriteInput({
        ...input,
        secrets: { password: { action: "replace", value: "密".repeat(6_000) } },
      }),
    ).toBe(false);
    expect(
      isConnectionWriteInput({
        ...input,
        secrets: { password: { action: "keep", value: "smuggled" } },
      }),
    ).toBe(false);
    expect(
      isConnectionWriteInput({
        ...input,
        connection: { ...connection, privateKeyPath: "C:\\keys\\id_ed25519" },
      }),
    ).toBe(false);
  });

  it("rejects credentials and unknown fields in edit and delete responses", () => {
    const edit = {
      id: "server-1",
      name: "Incident host",
      host: "10.0.0.8",
      port: 22,
      username: "root",
      authMethod: "password",
      privateKeyPath: null,
      certificatePath: null,
      agentIdentityFingerprint: null,
      jumpHost: null,
      tags: [],
      notes: null,
      environment: null,
      role: null,
      group: null,
      hostKeyFingerprint: null,
      hasPassword: true,
      hasKeyPassphrase: false,
      jumpHostHasPassword: false,
      jumpHostHasKeyPassphrase: false,
      lastConnectedAt: null,
    };
    expect(isConnectionEditView(edit)).toBe(true);
    expect(isConnectionEditView({ ...edit, password: "must-not-return" })).toBe(false);

    const prompt = {
      handle: "connection-delete-123",
      connectionId: "server-1",
      connectionName: "Incident host",
      confirmationText: "Delete Incident host",
    };
    expect(isConnectionDeletePrompt(prompt)).toBe(true);
    expect(isConnectionDeletePrompt({ ...prompt, metadata: {} })).toBe(false);
    expect(
      isConnectionDeleteResult({
        operationId: "connection-delete-123",
        verified: true,
        verificationDetail: "connection absent",
      }),
    ).toBe(true);
  });

  it("keeps connection file outcomes count-only and cancellation-exact", () => {
    expect(
      isConnectionImportResult({
        cancelled: false,
        imported: 2,
        skippedExisting: 3,
        skippedDuplicate: 4,
      }),
    ).toBe(true);
    expect(
      isConnectionImportResult({
        cancelled: true,
        imported: 1,
        skippedExisting: 0,
        skippedDuplicate: 0,
      }),
    ).toBe(false);
    expect(
      isConnectionExportResult({
        cancelled: false,
        count: 5,
        fileName: "incident-connections.json",
      }),
    ).toBe(true);
    expect(
      isConnectionExportResult({
        cancelled: false,
        count: 5,
        fileName: "C:\\private\\incident-connections.json",
      }),
    ).toBe(false);
    expect(
      isConnectionExportResult({
        cancelled: true,
        count: 0,
        fileName: "leaked.json",
      }),
    ).toBe(false);
  });

  it("accepts a chosen credential path or a cancelled dialog, and nothing else", () => {
    expect(isConnectionCredentialFileKind("private-key")).toBe(true);
    expect(isConnectionCredentialFileKind("certificate")).toBe(true);
    expect(isConnectionCredentialFileKind("public-key")).toBe(false);
    expect(isConnectionCredentialFileChoice({ path: "C:\\Users\\ops\\.ssh\\id_ed25519" })).toBe(true);
    expect(isConnectionCredentialFileChoice({ path: null })).toBe(true);
    expect(isConnectionCredentialFileChoice({ path: "x".repeat(4_097) })).toBe(false);
    expect(isConnectionCredentialFileChoice({ path: null, contents: "-----BEGIN" })).toBe(false);
    expect(isConnectionCredentialFileChoice({})).toBe(false);
  });

  it("accepts bounded note DTOs while rejecting oversized pages and delete handles", () => {
    const note = {
      id: "note-1",
      title: "<img src=x onerror=steal()>",
      content: "ordinary text",
      tags: ["取证"],
      createdAt: 1,
      updatedAt: 2,
      pinned: false,
      revision: "a".repeat(64),
    };
    const { content: _content, ...summaryFields } = note;
    expect(isNoteResult(note)).toBe(true);
    expect(
      isNoteListPage({
        total: 1,
        offset: 0,
        hasMore: false,
        items: [
          {
            ...summaryFields,
            contentPreview: "ordinary text",
            contentTruncated: false,
          },
        ],
      }),
    ).toBe(true);
    expect(
      isNoteListPage({ total: 0, offset: 0, hasMore: false, items: Array(101).fill({}) }),
    ).toBe(false);
    expect(
      isNoteDeleteProposal({
        handle: "x".repeat(129),
        summary: "delete",
        expiresInSeconds: 300,
      }),
    ).toBe(false);
    expect(isNoteResult({ ...note, unexpected: true })).toBe(false);
    expect(isNoteResult({ ...note, content: "界".repeat(1_398_102) })).toBe(false);
  });
});
