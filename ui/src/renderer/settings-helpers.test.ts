import { describe, expect, it, vi } from "vitest";

import type { SettingsSnapshot } from "../shared/settings-contract";
import {
  applySettingsMutation,
  cloneSettings,
  beforeSettingsTransition,
  confirmSettingsClose,
  createProvider,
  nextProviderId,
  nextSettingsFocusIndex,
  settingsAreEqual,
  settingsEscapeIntent,
  setSettingsApiKeyPresence,
  toSettingsSaveInput,
} from "./settings-helpers";

function fixture(): SettingsSnapshot {
  return {
    theme: "light",
    language: "zh-CN",
    autoConnect: false,
    defaultSshPort: 22,
    terminalFontSize: 14,
    maxLogLines: 1_000,
    logLevel: "info",
    notifications: { enabled: true, connectionStatus: true, commandCompletion: false, errorAlerts: true },
    security: { savePasswords: false, sessionTimeoutMs: 86_400_000, requireConfirmation: false },
    ui: { sidebarWidth: 280, showStatusBar: true, compactMode: false, animationsEnabled: true },
    docker: { autoRefresh: true, refreshIntervalMs: 5_000, showSystemContainers: false },
    ssh: { keepAliveIntervalMs: 30_000, connectionTimeoutMs: 0, maxRetries: 3 },
    ai: {
      providers: [{
        id: "provider-1",
        label: "One",
        kind: "open-ai-compatible",
        endpoint: "https://example.test/v1",
        model: "model",
        enabled: true,
        hasApiKey: true,
      }],
      defaultProviderId: "provider-1",
      proxy: null,
    },
  };
}

describe("settings overlay helpers", () => {
  it("deep-clones drafts and strips key-presence metadata from save input", () => {
    const original = fixture();
    const cloned = cloneSettings(original);
    cloned.ai.providers[0]!.label = "changed";
    expect(original.ai.providers[0]!.label).toBe("One");
    expect(settingsAreEqual(original, cloned)).toBe(false);

    const input = toSettingsSaveInput(original);
    expect(input.ai.providers[0]).not.toHaveProperty("hasApiKey");
    expect(JSON.stringify(input)).not.toMatch(/apiKey|secret|ciphertext/u);
  });

  it("runs the dirty close handshake only for modified settings", async () => {
    const confirmDiscard = vi.fn(async () => false);
    await expect(confirmSettingsClose(false, confirmDiscard)).resolves.toBe(true);
    expect(confirmDiscard).not.toHaveBeenCalled();
    await expect(confirmSettingsClose(true, confirmDiscard)).resolves.toBe(false);
    expect(confirmDiscard).toHaveBeenCalledOnce();
  });

  it("fails closed when navigation races an unmounted Settings guard", async () => {
    const beforeClose = vi.fn(async () => true);
    await expect(beforeSettingsTransition(false, null)).resolves.toBe(true);
    await expect(beforeSettingsTransition(true, null)).resolves.toBe(false);
    await expect(beforeSettingsTransition(true, { beforeClose })).resolves.toBe(true);
    expect(beforeClose).toHaveBeenCalledOnce();
  });

  it("wraps focus in both directions and handles an empty trap", () => {
    expect(nextSettingsFocusIndex(2, 3, false)).toBe(0);
    expect(nextSettingsFocusIndex(0, 3, true)).toBe(2);
    expect(nextSettingsFocusIndex(-1, 3, false)).toBe(0);
    expect(nextSettingsFocusIndex(-1, 3, true)).toBe(2);
    expect(nextSettingsFocusIndex(0, 0, false)).toBe(-1);
  });

  it("routes Escape to the innermost safe action", () => {
    expect(settingsEscapeIntent(false, false)).toBe("close-settings");
    expect(settingsEscapeIntent(true, false)).toBe("cancel-mutation");
    expect(settingsEscapeIntent(true, true)).toBe("blocked");
  });

  it("allocates bounded stable provider IDs and safe defaults", () => {
    const providers = fixture().ai.providers;
    expect(nextProviderId(providers)).toBe("provider-2");
    expect(createProvider(providers)).toMatchObject({
      id: "provider-2",
      hasApiKey: false,
      endpoint: "",
    });
  });

  it("applies verified key clearing and provider removal without mutating the draft", () => {
    const original = fixture();
    const cleared = setSettingsApiKeyPresence(original, "provider-1", false);
    expect(cleared.ai.providers[0]?.hasApiKey).toBe(false);
    expect(original.ai.providers[0]?.hasApiKey).toBe(true);

    const removed = applySettingsMutation(original, "remove-ai-provider", "provider-1");
    expect(removed.ai.providers).toEqual([]);
    expect(removed.ai.defaultProviderId).toBeNull();
    expect(original.ai.providers).toHaveLength(1);
  });
});
