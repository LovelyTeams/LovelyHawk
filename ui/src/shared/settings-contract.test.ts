import { describe, expect, it } from "vitest";

import {
  isSettingsAiApiKeyReplacementInput,
  isSettingsAiApiKeyReplacementResult,
  isSettingsMutationCancellation,
  isSettingsMutationHandle,
  isSettingsMutationProposal,
  isSettingsMutationResult,
  isSettingsSaveInput,
  isSettingsSnapshot,
  type SettingsSnapshot,
} from "./settings-contract";

function fixture(): SettingsSnapshot {
  return {
    theme: "dark",
    language: "zh-CN",
    autoConnect: false,
    defaultSshPort: 22,
    terminalFontSize: 14,
    maxLogLines: 1_000,
    logLevel: "info",
    notifications: {
      enabled: true,
      connectionStatus: true,
      commandCompletion: false,
      errorAlerts: true,
    },
    security: {
      savePasswords: false,
      sessionTimeoutMs: 86_400_000,
      requireConfirmation: false,
    },
    ui: {
      sidebarWidth: 280,
      showStatusBar: true,
      compactMode: false,
      animationsEnabled: true,
    },
    docker: {
      autoRefresh: true,
      refreshIntervalMs: 5_000,
      showSystemContainers: false,
    },
    ssh: {
      keepAliveIntervalMs: 30_000,
      connectionTimeoutMs: 0,
      maxRetries: 3,
    },
    ai: {
      providers: [{
        id: "provider-1",
        label: "Local provider",
        kind: "open-ai-compatible",
        endpoint: "http://127.0.0.1:11434/v1",
        model: "local-model",
        enabled: true,
        hasApiKey: true,
      }],
      defaultProviderId: "provider-1",
      proxy: null,
    },
  };
}

describe("settings process-boundary validators", () => {
  it("accepts the exact bounded credential-free snapshot", () => {
    const value = fixture();
    expect(isSettingsSnapshot(value)).toBe(true);
    expect(JSON.stringify(value)).not.toContain("apiKey");
    expect(isSettingsSnapshot({ ...value, dataRoot: "C:/Users/person/AppData" })).toBe(false);
    expect(isSettingsSnapshot({ ...value, path: "/tmp/settings.json" })).toBe(false);
    expect(isSettingsSnapshot({ ...value, secret: "Bearer hidden" })).toBe(false);
  });

  it("distinguishes save inputs from safe snapshots and rejects secret fields", () => {
    const snapshot = fixture();
    const { hasApiKey: _hasApiKey, ...provider } = snapshot.ai.providers[0]!;
    const input = { ...snapshot, ai: { ...snapshot.ai, providers: [provider] } };
    expect(isSettingsSaveInput(input)).toBe(true);
    expect(isSettingsSnapshot(input)).toBe(false);
    expect(isSettingsSaveInput({
      ...input,
      ai: { ...input.ai, providers: [{ ...provider, apiKey: "must-not-cross" }] },
    })).toBe(false);
  });

  it("enforces core numeric, provider, URL and aggregate bounds", () => {
    const value = fixture();
    expect(isSettingsSnapshot({ ...value, defaultSshPort: 0 })).toBe(false);
    expect(isSettingsSnapshot({ ...value, terminalFontSize: 73 })).toBe(false);
    expect(isSettingsSnapshot({ ...value, ui: { ...value.ui, sidebarWidth: 199 } })).toBe(false);
    expect(isSettingsSnapshot({ ...value, ssh: { ...value.ssh, connectionTimeoutMs: 999 } })).toBe(false);
    expect(isSettingsSnapshot({
      ...value,
      ai: { ...value.ai, providers: [{ ...value.ai.providers[0]!, id: "../hostile" }] },
    })).toBe(false);
    expect(isSettingsSnapshot({
      ...value,
      ai: { ...value.ai, providers: [{ ...value.ai.providers[0]!, endpoint: "file:///etc/passwd" }] },
    })).toBe(false);
    expect(isSettingsSnapshot({
      ...value,
      ai: { ...value.ai, providers: [{ ...value.ai.providers[0]!, label: "x".repeat(129) }] },
    })).toBe(false);
  });

  it("permits hostile-looking plain text but rejects control characters and dangling defaults", () => {
    const value = fixture();
    const hostile = "</option><script>steal()</script>";
    expect(isSettingsSnapshot({
      ...value,
      ai: { ...value.ai, providers: [{ ...value.ai.providers[0]!, label: hostile }] },
    })).toBe(true);
    expect(isSettingsSnapshot({
      ...value,
      ai: { ...value.ai, providers: [{ ...value.ai.providers[0]!, label: "line\nbreak" }] },
    })).toBe(false);
    expect(isSettingsSnapshot({
      ...value,
      ai: { ...value.ai, defaultProviderId: "missing" },
    })).toBe(false);
  });

  it("accepts only exact bounded write-only API key replacements", () => {
    const input = { providerId: "provider-1", apiKey: "sk-short-lived" };
    expect(isSettingsAiApiKeyReplacementInput(input)).toBe(true);
    expect(isSettingsAiApiKeyReplacementInput({ ...input, path: "/tmp/key" })).toBe(false);
    expect(isSettingsAiApiKeyReplacementInput({ ...input, providerId: "../provider" })).toBe(false);
    expect(isSettingsAiApiKeyReplacementInput({ ...input, apiKey: "key\nheader" })).toBe(false);
    expect(isSettingsAiApiKeyReplacementInput({ ...input, apiKey: "密".repeat(5_462) })).toBe(false);
    expect(isSettingsAiApiKeyReplacementResult({
      providerId: "provider-1",
      hasApiKey: true,
    })).toBe(true);
    expect(isSettingsAiApiKeyReplacementResult({
      providerId: "provider-1",
      hasApiKey: true,
      apiKey: "must-not-return",
    })).toBe(false);
  });

  it("enforces opaque single-use mutation proposal and result shapes", () => {
    const proposal = {
      handle: "d14ecae2-f005-4a1a-8d51-3a3db0cf4ed4",
      kind: "clear-ai-api-key",
      summary: "永久清除 AI Provider 的 API Key；此操作不可恢复。",
      expiresInSeconds: 120,
    };
    expect(isSettingsMutationHandle(proposal.handle)).toBe(true);
    expect(isSettingsMutationProposal(proposal)).toBe(true);
    expect(isSettingsMutationProposal({ ...proposal, providerId: "provider-1" })).toBe(false);
    expect(isSettingsMutationProposal({ ...proposal, summary: "bad\nsummary" })).toBe(false);
    expect(isSettingsMutationResult({ kind: "clear-ai-api-key", verified: true })).toBe(true);
    expect(isSettingsMutationResult({ kind: "clear-ai-api-key", verified: false })).toBe(false);
    expect(isSettingsMutationCancellation({ cancelled: true })).toBe(true);
    expect(isSettingsMutationCancellation({ cancelled: true, handle: proposal.handle })).toBe(false);
  });
});
