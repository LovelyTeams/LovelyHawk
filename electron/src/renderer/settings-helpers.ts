import type {
  SettingsAiProvider,
  SettingsMutationKind,
  SettingsSaveInput,
  SettingsSnapshot,
} from "../shared/settings-contract";

export type SettingsTab = "general" | "connections" | "terminal" | "ai";

export interface SettingsCloseGuard {
  beforeClose(): Promise<boolean>;
}

export const SETTINGS_TABS: readonly { id: SettingsTab; label: string }[] = [
  { id: "general", label: "通用" },
  { id: "connections", label: "连接" },
  { id: "terminal", label: "终端" },
  { id: "ai", label: "AI" },
];

export function cloneSettings(value: SettingsSnapshot): SettingsSnapshot {
  return {
    ...value,
    notifications: { ...value.notifications },
    security: { ...value.security },
    ui: { ...value.ui },
    docker: { ...value.docker },
    ssh: { ...value.ssh },
    ai: {
      providers: value.ai.providers.map((provider) => ({ ...provider })),
      defaultProviderId: value.ai.defaultProviderId,
      proxy: value.ai.proxy === null ? null : { ...value.ai.proxy },
    },
  };
}

export function settingsAreEqual(left: SettingsSnapshot, right: SettingsSnapshot): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

export function toSettingsSaveInput(value: SettingsSnapshot): SettingsSaveInput {
  return {
    ...cloneSettings(value),
    ai: {
      providers: value.ai.providers.map(({ hasApiKey: _hasApiKey, ...provider }) => provider),
      defaultProviderId: value.ai.defaultProviderId,
      proxy: value.ai.proxy === null ? null : { ...value.ai.proxy },
    },
  };
}

export function setSettingsApiKeyPresence(
  value: SettingsSnapshot,
  providerId: string,
  hasApiKey: boolean,
): SettingsSnapshot {
  const next = cloneSettings(value);
  const provider = next.ai.providers.find(({ id }) => id === providerId);
  if (provider !== undefined) provider.hasApiKey = hasApiKey;
  return next;
}

export function applySettingsMutation(
  value: SettingsSnapshot,
  kind: SettingsMutationKind,
  providerId: string,
): SettingsSnapshot {
  if (kind === "clear-ai-api-key") {
    return setSettingsApiKeyPresence(value, providerId, false);
  }
  const next = cloneSettings(value);
  next.ai.providers = next.ai.providers.filter(({ id }) => id !== providerId);
  if (next.ai.defaultProviderId === providerId) {
    next.ai.defaultProviderId = next.ai.providers[0]?.id ?? null;
  }
  return next;
}

export function nextSettingsFocusIndex(
  currentIndex: number,
  focusableCount: number,
  backwards: boolean,
): number {
  if (focusableCount <= 0) return -1;
  if (currentIndex < 0) return backwards ? focusableCount - 1 : 0;
  return backwards
    ? (currentIndex - 1 + focusableCount) % focusableCount
    : (currentIndex + 1) % focusableCount;
}

export type SettingsEscapeIntent = "close-settings" | "cancel-mutation" | "blocked";

export function settingsEscapeIntent(
  hasPendingMutation: boolean,
  confirmingMutation: boolean,
): SettingsEscapeIntent {
  if (!hasPendingMutation) return "close-settings";
  return confirmingMutation ? "blocked" : "cancel-mutation";
}

export async function confirmSettingsClose(
  dirty: boolean,
  confirmDiscard: () => boolean | Promise<boolean>,
): Promise<boolean> {
  return dirty ? await confirmDiscard() : true;
}

/** Fail closed while an open Settings panel has not mounted its close guard. */
export async function beforeSettingsTransition(
  settingsOpen: boolean,
  guard: SettingsCloseGuard | null,
): Promise<boolean> {
  if (!settingsOpen) return true;
  return guard !== null && await guard.beforeClose() === true;
}

export function nextProviderId(providers: readonly SettingsAiProvider[]): string {
  const ids = new Set(providers.map((provider) => provider.id));
  for (let index = 1; index <= 32; index += 1) {
    const candidate = `provider-${index}`;
    if (!ids.has(candidate)) return candidate;
  }
  return "provider-32";
}

export function createProvider(providers: readonly SettingsAiProvider[]): SettingsAiProvider {
  const id = nextProviderId(providers);
  return {
    id,
    label: `Provider ${providers.length + 1}`,
    kind: "open-ai-compatible",
    endpoint: "",
    model: "gpt-4.1-mini",
    enabled: true,
    hasApiKey: false,
  };
}
