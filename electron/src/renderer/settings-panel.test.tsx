import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type {
  SettingsMutationProposal,
  SettingsAiApiKeyReplacementResult,
  SettingsMutationCancellation,
  SettingsMutationResult,
  SettingsPanelApi,
  SettingsSnapshot,
} from "../shared/settings-contract";
import { SettingsDangerConfirmationDialog, SettingsPanel } from "./SettingsPanel";

const api: SettingsPanelApi = {
  loadSettings: vi.fn(async () => ({}) as SettingsSnapshot),
  saveSettings: vi.fn(async () => ({}) as SettingsSnapshot),
  replaceSettingsAiApiKey: vi.fn(async () => ({}) as SettingsAiApiKeyReplacementResult),
  planSettingsAiApiKeyClear: vi.fn(async () => ({}) as SettingsMutationProposal),
  planSettingsAiProviderRemoval: vi.fn(async () => ({}) as SettingsMutationProposal),
  confirmSettingsMutation: vi.fn(async () => ({}) as SettingsMutationResult),
  cancelSettingsMutation: vi.fn(async () => ({}) as SettingsMutationCancellation),
};

function fixture(providerLabel = "Local provider"): SettingsSnapshot {
  return {
    theme: "dark",
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
        label: providerLabel,
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

describe("standalone Settings overlay", () => {
  it("renders an accessible modal with the four fixed tabs and no path input", () => {
    const markup = renderToStaticMarkup(
      <SettingsPanel api={api} onClose={vi.fn()} initialSnapshot={fixture()} />,
    );
    expect(markup).toContain('role="dialog"');
    expect(markup).toContain('aria-modal="true"');
    expect(markup).toContain("通用");
    expect(markup).toContain("连接");
    expect(markup).toContain("终端");
    expect(markup).toContain("AI");
    expect(markup).not.toMatch(/data root|dataRoot|settings\.json|AppData/u);
  });

  it("renders hostile provider text inertly and never renders a credential value", () => {
    const hostile = "</option><script>steal('Bearer-secret')</script>";
    const markup = renderToStaticMarkup(
      <SettingsPanel
        api={api}
        onClose={vi.fn()}
        initialSnapshot={fixture(hostile)}
        initialTab="ai"
      />,
    );
    expect(markup).toContain("&lt;/option&gt;&lt;script&gt;steal(&#x27;Bearer-secret&#x27;)&lt;/script&gt;");
    expect(markup).not.toContain("<script>steal");
    expect(markup).toContain("已加密保存");
    expect(markup).not.toMatch(/api[_ -]?key["'=:\s]+Bearer|ciphertext|sessionId|targetGuard/iu);
    expect(markup).toContain('type="password"');
    expect(markup).toContain("只写替换");
    expect(markup).toContain("清除 Key…");
    expect(markup).toContain("删除 Provider…");
    expect(markup).toMatch(/type="password"[^>]*value=""/u);
  });

  it("renders the exact hostile core summary as plain text in an accessible danger modal", () => {
    const proposal: SettingsMutationProposal = {
      handle: "d14ecae2-f005-4a1a-8d51-3a3db0cf4ed4",
      kind: "remove-ai-provider",
      summary: "永久删除 Provider </p><script>steal()</script>；此操作不可恢复。",
      expiresInSeconds: 120,
    };
    const markup = renderToStaticMarkup(
      <SettingsDangerConfirmationDialog
        proposal={proposal}
        busy={false}
        onCancel={vi.fn()}
        onConfirm={vi.fn()}
      />,
    );
    expect(markup).toContain('role="alertdialog"');
    expect(markup).toContain('aria-modal="true"');
    expect(markup).toContain("&lt;/p&gt;&lt;script&gt;steal()&lt;/script&gt;");
    expect(markup).not.toContain("<script>steal");
    expect(markup).toContain("失败或状态未知时不会自动重试");
  });
});
