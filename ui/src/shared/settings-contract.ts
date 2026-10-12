export type SettingsTheme = "light" | "dark" | "sakura" | "incident-canvas";
export type SettingsLanguage = "zh-CN" | "en-US";
export type SettingsLogLevel = "debug" | "info" | "warn" | "error";
export type SettingsAiProviderKind = "open-ai-compatible" | "anthropic" | "gemini";
export type SettingsProxyType = "http" | "socks5";

export interface SettingsNotifications {
  enabled: boolean;
  connectionStatus: boolean;
  commandCompletion: boolean;
  errorAlerts: boolean;
}

export interface SettingsSecurity {
  savePasswords: boolean;
  sessionTimeoutMs: number;
  requireConfirmation: boolean;
}

export interface SettingsUi {
  sidebarWidth: number;
  showStatusBar: boolean;
  compactMode: boolean;
  animationsEnabled: boolean;
}

export interface SettingsDocker {
  autoRefresh: boolean;
  refreshIntervalMs: number;
  showSystemContainers: boolean;
}

export interface SettingsSsh {
  keepAliveIntervalMs: number;
  connectionTimeoutMs: number;
  maxRetries: number;
}

export interface SettingsProxy {
  proxyType: SettingsProxyType;
  proxyUrl: string;
}

export interface SettingsAiProviderInput {
  id: string;
  label: string;
  kind: SettingsAiProviderKind;
  endpoint: string;
  model: string;
  enabled: boolean;
}

export interface SettingsAiProvider extends SettingsAiProviderInput {
  /** Credential-presence metadata only. API keys and ciphertext never cross this boundary. */
  hasApiKey: boolean;
}

export interface SettingsAi {
  providers: SettingsAiProvider[];
  defaultProviderId: string | null;
  proxy: SettingsProxy | null;
}

export interface SettingsAiInput {
  providers: SettingsAiProviderInput[];
  defaultProviderId: string | null;
  proxy: SettingsProxy | null;
}

export interface SettingsSnapshot {
  theme: SettingsTheme;
  language: SettingsLanguage;
  autoConnect: boolean;
  defaultSshPort: number;
  terminalFontSize: number;
  maxLogLines: number;
  logLevel: SettingsLogLevel;
  notifications: SettingsNotifications;
  security: SettingsSecurity;
  ui: SettingsUi;
  docker: SettingsDocker;
  ssh: SettingsSsh;
  ai: SettingsAi;
}

export interface SettingsSaveInput extends Omit<SettingsSnapshot, "ai"> {
  ai: SettingsAiInput;
}

export interface SettingsAiApiKeyReplacementInput {
  providerId: string;
  /** Write-only. Callers must clear their local input immediately after invocation. */
  apiKey: string;
}

export interface SettingsAiApiKeyReplacementResult {
  providerId: string;
  hasApiKey: true;
}

export type SettingsMutationKind = "clear-ai-api-key" | "remove-ai-provider";

export interface SettingsMutationProposal {
  handle: string;
  kind: SettingsMutationKind;
  summary: string;
  expiresInSeconds: number;
}

export interface SettingsMutationResult {
  kind: SettingsMutationKind;
  verified: true;
}

export interface SettingsMutationCancellation {
  cancelled: true;
}

export interface SettingsPanelApi {
  loadSettings(): Promise<SettingsSnapshot>;
  saveSettings(input: SettingsSaveInput): Promise<SettingsSnapshot>;
  replaceSettingsAiApiKey(
    input: SettingsAiApiKeyReplacementInput,
  ): Promise<SettingsAiApiKeyReplacementResult>;
  planSettingsAiApiKeyClear(providerId: string): Promise<SettingsMutationProposal>;
  planSettingsAiProviderRemoval(providerId: string): Promise<SettingsMutationProposal>;
  confirmSettingsMutation(mutationHandle: string): Promise<SettingsMutationResult>;
  cancelSettingsMutation(mutationHandle: string): Promise<SettingsMutationCancellation>;
}

type JsonRecord = Record<string, unknown>;

const encoder = new TextEncoder();
const MAX_SETTINGS_BYTES = 128 * 1_024;
const MAX_AI_PROVIDERS = 32;
const SETTINGS_KEYS = [
  "theme",
  "language",
  "autoConnect",
  "defaultSshPort",
  "terminalFontSize",
  "maxLogLines",
  "logLevel",
  "notifications",
  "security",
  "ui",
  "docker",
  "ssh",
  "ai",
] as const;

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exact(value: JsonRecord, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && actual.every((key) => keys.includes(key));
}

function oneOf<const T extends readonly string[]>(value: unknown, values: T): value is T[number] {
  return typeof value === "string" && values.some((candidate) => candidate === value);
}

function integerIn(value: unknown, minimum: number, maximum: number): value is number {
  return Number.isSafeInteger(value) && Number(value) >= minimum && Number(value) <= maximum;
}

function boundedText(
  value: unknown,
  maximumBytes: number,
  allowEmpty = false,
  rejectControls = false,
): value is string {
  return (
    typeof value === "string" &&
    (allowEmpty || value.trim().length > 0) &&
    encoder.encode(value).byteLength <= maximumBytes &&
    (!rejectControls || !/[\u0000-\u001f\u007f]/u.test(value))
  );
}

function safeUrl(value: unknown, schemes: readonly string[]): value is string {
  if (!boundedText(value, 2_048, false, true)) return false;
  try {
    const parsed = new URL(value);
    if (
      !schemes.includes(parsed.protocol.slice(0, -1)) ||
      parsed.username !== "" ||
      parsed.password !== "" ||
      parsed.hostname === ""
    ) return false;
    const host = parsed.hostname.replace(/^\[|\]$/gu, "").toLowerCase();
    return (
      host !== "0.0.0.0" &&
      host !== "::" &&
      !host.startsWith("169.254.") &&
      !/^fe[89ab][0-9a-f]:/u.test(host)
    );
  } catch {
    return false;
  }
}

function isNotifications(value: unknown): value is SettingsNotifications {
  return isRecord(value) &&
    exact(value, ["enabled", "connectionStatus", "commandCompletion", "errorAlerts"]) &&
    Object.values(value).every((item) => typeof item === "boolean");
}

function isSecurity(value: unknown): value is SettingsSecurity {
  return isRecord(value) &&
    exact(value, ["savePasswords", "sessionTimeoutMs", "requireConfirmation"]) &&
    typeof value.savePasswords === "boolean" &&
    integerIn(value.sessionTimeoutMs, 60_000, 86_400_000) &&
    typeof value.requireConfirmation === "boolean";
}

function isUi(value: unknown): value is SettingsUi {
  return isRecord(value) &&
    exact(value, ["sidebarWidth", "showStatusBar", "compactMode", "animationsEnabled"]) &&
    integerIn(value.sidebarWidth, 200, 800) &&
    typeof value.showStatusBar === "boolean" &&
    typeof value.compactMode === "boolean" &&
    typeof value.animationsEnabled === "boolean";
}

function isDocker(value: unknown): value is SettingsDocker {
  return isRecord(value) &&
    exact(value, ["autoRefresh", "refreshIntervalMs", "showSystemContainers"]) &&
    typeof value.autoRefresh === "boolean" &&
    integerIn(value.refreshIntervalMs, 1_000, 60_000) &&
    typeof value.showSystemContainers === "boolean";
}

function isSsh(value: unknown): value is SettingsSsh {
  if (!isRecord(value) || !exact(value, ["keepAliveIntervalMs", "connectionTimeoutMs", "maxRetries"])) {
    return false;
  }
  return integerIn(value.keepAliveIntervalMs, 5_000, 300_000) &&
    (value.connectionTimeoutMs === 0 || integerIn(value.connectionTimeoutMs, 1_000, 600_000)) &&
    integerIn(value.maxRetries, 1, 10);
}

function isProxy(value: unknown): value is SettingsProxy {
  if (!isRecord(value) || !exact(value, ["proxyType", "proxyUrl"])) return false;
  if (!oneOf(value.proxyType, ["http", "socks5"] as const)) return false;
  return safeUrl(value.proxyUrl, value.proxyType === "http" ? ["http", "https"] : ["socks5"]);
}

function isProvider(
  value: unknown,
  includeKeyPresence: boolean,
): value is SettingsAiProvider | SettingsAiProviderInput {
  if (!isRecord(value)) return false;
  const keys = ["id", "label", "kind", "endpoint", "model", "enabled"];
  if (includeKeyPresence) keys.push("hasApiKey");
  return exact(value, keys) &&
    boundedText(value.id, 64, false, true) &&
    /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u.test(value.id) &&
    boundedText(value.label, 128, false, true) &&
    oneOf(value.kind, ["open-ai-compatible", "anthropic", "gemini"] as const) &&
    safeUrl(value.endpoint, ["http", "https"]) &&
    boundedText(value.model, 256, false, true) &&
    typeof value.enabled === "boolean" &&
    (!includeKeyPresence || typeof value.hasApiKey === "boolean");
}

export function isSettingsProviderId(value: unknown): value is string {
  return boundedText(value, 64, false, true) &&
    /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u.test(value);
}

function isAi(value: unknown, includeKeyPresence: boolean): value is SettingsAi | SettingsAiInput {
  if (!isRecord(value) || !exact(value, ["providers", "defaultProviderId", "proxy"])) return false;
  if (!Array.isArray(value.providers) || value.providers.length > MAX_AI_PROVIDERS) return false;
  if (!value.providers.every((provider) => isProvider(provider, includeKeyPresence))) return false;
  const ids = value.providers.map((provider) => (provider as SettingsAiProviderInput).id);
  if (new Set(ids).size !== ids.length) return false;
  if (value.defaultProviderId !== null && (
    !boundedText(value.defaultProviderId, 64, false, true) ||
    !ids.includes(value.defaultProviderId)
  )) return false;
  return value.proxy === null || isProxy(value.proxy);
}

function isSettings(value: unknown, includeKeyPresence: boolean): boolean {
  if (!isRecord(value) || !exact(value, SETTINGS_KEYS)) return false;
  if (
    !oneOf(value.theme, ["light", "dark", "sakura", "incident-canvas"] as const) ||
    !oneOf(value.language, ["zh-CN", "en-US"] as const) ||
    typeof value.autoConnect !== "boolean" ||
    !integerIn(value.defaultSshPort, 1, 65_535) ||
    !integerIn(value.terminalFontSize, 8, 72) ||
    !integerIn(value.maxLogLines, 1, 100_000) ||
    !oneOf(value.logLevel, ["debug", "info", "warn", "error"] as const) ||
    !isNotifications(value.notifications) ||
    !isSecurity(value.security) ||
    !isUi(value.ui) ||
    !isDocker(value.docker) ||
    !isSsh(value.ssh) ||
    !isAi(value.ai, includeKeyPresence)
  ) return false;
  return encoder.encode(JSON.stringify(value)).byteLength <= MAX_SETTINGS_BYTES;
}

export function isSettingsSnapshot(value: unknown): value is SettingsSnapshot {
  return isSettings(value, true);
}

export function isSettingsSaveInput(value: unknown): value is SettingsSaveInput {
  return isSettings(value, false);
}

export function isSettingsAiApiKeyReplacementInput(
  value: unknown,
): value is SettingsAiApiKeyReplacementInput {
  return isRecord(value) &&
    exact(value, ["providerId", "apiKey"]) &&
    isSettingsProviderId(value.providerId) &&
    typeof value.apiKey === "string" &&
    value.apiKey.length > 0 &&
    encoder.encode(value.apiKey).byteLength <= 16 * 1_024 &&
    !/[\u0000-\u001f\u007f-\u009f]/u.test(value.apiKey);
}

export function isSettingsAiApiKeyReplacementResult(
  value: unknown,
): value is SettingsAiApiKeyReplacementResult {
  return isRecord(value) &&
    exact(value, ["providerId", "hasApiKey"]) &&
    isSettingsProviderId(value.providerId) &&
    value.hasApiKey === true;
}

export function isSettingsMutationHandle(value: unknown): value is string {
  return typeof value === "string" &&
    encoder.encode(value).byteLength <= 128 &&
    /^[A-Za-z0-9-]+$/u.test(value);
}

function isSettingsMutationKind(value: unknown): value is SettingsMutationKind {
  return value === "clear-ai-api-key" || value === "remove-ai-provider";
}

export function isSettingsMutationProposal(value: unknown): value is SettingsMutationProposal {
  return isRecord(value) &&
    exact(value, ["handle", "kind", "summary", "expiresInSeconds"]) &&
    isSettingsMutationHandle(value.handle) &&
    isSettingsMutationKind(value.kind) &&
    boundedText(value.summary, 2_048, false, true) &&
    integerIn(value.expiresInSeconds, 1, 600);
}

export function isSettingsMutationResult(value: unknown): value is SettingsMutationResult {
  return isRecord(value) &&
    exact(value, ["kind", "verified"]) &&
    isSettingsMutationKind(value.kind) &&
    value.verified === true;
}

export function isSettingsMutationCancellation(
  value: unknown,
): value is SettingsMutationCancellation {
  return isRecord(value) && exact(value, ["cancelled"]) && value.cancelled === true;
}
