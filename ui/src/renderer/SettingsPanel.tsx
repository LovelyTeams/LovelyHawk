import {
  forwardRef,
  useCallback,
  useEffect,
  useImperativeHandle,
  useMemo,
  useRef,
  useState,
  type ChangeEvent,
  type Ref,
  type ReactNode,
} from "react";

import {
  isSettingsAiApiKeyReplacementInput,
  isSettingsAiApiKeyReplacementResult,
  isSettingsMutationCancellation,
  isSettingsMutationProposal,
  isSettingsMutationResult,
  isSettingsSaveInput,
  isSettingsSnapshot,
  type SettingsAiProvider,
  type SettingsMutationKind,
  type SettingsMutationProposal,
  type SettingsPanelApi,
  type SettingsSnapshot,
} from "../shared/settings-contract";
import {
  applySettingsMutation,
  cloneSettings,
  confirmSettingsClose,
  createProvider,
  nextSettingsFocusIndex,
  SETTINGS_TABS,
  setSettingsApiKeyPresence,
  settingsEscapeIntent,
  settingsAreEqual,
  toSettingsSaveInput,
  type SettingsTab,
} from "./settings-helpers";
import { THEMES } from "./theme/theme";
import { DialogHost } from "./DialogHost";
import { useConfirmDialog } from "./use-confirm-dialog";
import "./settings-panel.css";
import { planExpiryLabel } from "./plan-expiry";

const FOCUSABLE_SELECTOR = [
  "button:not([disabled])",
  "[href]",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  '[tabindex]:not([tabindex="-1"])',
].join(",");
const MAX_API_KEY_INPUT_CHARS = 16 * 1_024;

export interface SettingsPanelHandle {
  /** Returns false when a dirty draft must remain open. */
  beforeClose(): Promise<boolean>;
}

interface SettingsPanelProps {
  api: SettingsPanelApi;
  onClose: () => void;
  onSaved?: () => void;
  confirmDiscard?: () => boolean | Promise<boolean>;
  /** Explicit trigger to restore when the App shell made its background inert before mount. */
  returnFocusElement?: HTMLElement | null;
  /** The workspace sibling to make inert while this modal is mounted. */
  backgroundElement?: HTMLElement | null;
  /** Optional already-validated bootstrap value; the normal integration loads through api. */
  initialSnapshot?: SettingsSnapshot;
  initialTab?: SettingsTab;
}

type Notice = { text: string; error: boolean };
type PendingSettingsMutation = {
  proposal: SettingsMutationProposal;
  providerId: string;
};

export const SettingsPanel = forwardRef<SettingsPanelHandle, SettingsPanelProps>(
  function SettingsPanel(
    {
      api,
      onClose,
      onSaved,
      confirmDiscard,
      returnFocusElement = null,
      backgroundElement = null,
      initialSnapshot,
      initialTab = "general",
    },
    forwardedRef,
  ) {
    const initialRef = useRef<SettingsSnapshot | null>(
      initialSnapshot !== undefined && isSettingsSnapshot(initialSnapshot)
        ? cloneSettings(initialSnapshot)
        : null,
    );
    const [baseline, setBaseline] = useState<SettingsSnapshot | null>(() => initialRef.current);
    const [draft, setDraft] = useState<SettingsSnapshot | null>(() =>
      initialRef.current === null ? null : cloneSettings(initialRef.current)
    );
    const [activeTab, setActiveTab] = useState<SettingsTab>(initialTab);
    const [selectedProviderId, setSelectedProviderId] = useState<string | null>(
      () => initialRef.current?.ai.defaultProviderId ?? initialRef.current?.ai.providers[0]?.id ?? null,
    );
    const [loading, setLoading] = useState(initialRef.current === null);
    const [saving, setSaving] = useState(false);
    const [apiKeyDraft, setApiKeyDraft] = useState("");
    const [credentialBusy, setCredentialBusy] = useState(false);
    const [planningMutation, setPlanningMutation] = useState(false);
    const [pendingMutation, setPendingMutation] = useState<PendingSettingsMutation | null>(null);
    const [confirmingMutation, setConfirmingMutation] = useState(false);
    const [notice, setNotice] = useState<Notice | null>(null);
    const discardConfirm = useConfirmDialog();
    const dialogRef = useRef<HTMLElement>(null);
    const closeButtonRef = useRef<HTMLButtonElement>(null);
    const mutationDialogRef = useRef<HTMLElement>(null);
    const mutationCancelButtonRef = useRef<HTMLButtonElement>(null);
    const mutationReturnFocusRef = useRef<HTMLElement | null>(null);
    const secretOperationGenerationRef = useRef(0);
    const mutationOperationGenerationRef = useRef(0);
    const closingRef = useRef(false);
    const mountedRef = useRef(true);

    const metadataDirty = baseline !== null && draft !== null && !settingsAreEqual(baseline, draft);
    const dirty = metadataDirty || apiKeyDraft.length > 0;
    const secretLifecycleAvailable =
      api.replaceSettingsAiApiKey !== undefined &&
      api.planSettingsAiApiKeyClear !== undefined &&
      api.planSettingsAiProviderRemoval !== undefined &&
      api.confirmSettingsMutation !== undefined &&
      api.cancelSettingsMutation !== undefined;

    useEffect(() => {
      mountedRef.current = true;
      if (initialRef.current !== null) return () => { mountedRef.current = false; };
      let current = true;
      void api.loadSettings().then((response) => {
        if (!current || !isSettingsSnapshot(response)) {
          if (current) {
            setNotice({ text: "设置响应格式异常，没有采用。", error: true });
            setLoading(false);
          }
          return;
        }
        const loaded = cloneSettings(response);
        setBaseline(loaded);
        setDraft(cloneSettings(loaded));
        setSelectedProviderId(loaded.ai.defaultProviderId ?? loaded.ai.providers[0]?.id ?? null);
        setLoading(false);
      }).catch(() => {
        if (current) {
          setNotice({ text: "无法读取程序目录下 data 文件夹中的设置。", error: true });
          setLoading(false);
        }
      });
      return () => {
        current = false;
        mountedRef.current = false;
      };
    }, [api]);

    useEffect(() => {
      if (draft === null) return;
      if (selectedProviderId !== null && draft.ai.providers.some(({ id }) => id === selectedProviderId)) {
        return;
      }
      setSelectedProviderId(draft.ai.defaultProviderId ?? draft.ai.providers[0]?.id ?? null);
    }, [draft, selectedProviderId]);

    useEffect(() => {
      secretOperationGenerationRef.current += 1;
      mutationOperationGenerationRef.current += 1;
      setApiKeyDraft("");
      setCredentialBusy(false);
      setPlanningMutation(false);
      setConfirmingMutation(false);
      setPendingMutation(null);
    }, [selectedProviderId]);

    const askToDiscard = useCallback(() => {
      if (confirmDiscard !== undefined) return confirmDiscard();
      return discardConfirm.ask(
        "放弃未保存的更改",
        "设置尚未保存。确定放弃这些更改吗？",
        "放弃更改",
      );
    }, [confirmDiscard, discardConfirm]);

    const beforeClose = useCallback(async () => {
      if (
        saving || credentialBusy || planningMutation || confirmingMutation ||
        pendingMutation !== null
      ) return false;
      return confirmSettingsClose(dirty, askToDiscard);
    }, [
      askToDiscard,
      confirmingMutation,
      credentialBusy,
      dirty,
      pendingMutation,
      planningMutation,
      saving,
    ]);

    useImperativeHandle(forwardedRef, () => ({ beforeClose }), [beforeClose]);

    const requestClose = useCallback(async () => {
      if (closingRef.current) return;
      closingRef.current = true;
      try {
        if (await beforeClose()) onClose();
      } finally {
        closingRef.current = false;
      }
    }, [beforeClose, onClose]);

    useEffect(() => {
      const previousFocus = document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;
      const previousAriaHidden = backgroundElement?.getAttribute("aria-hidden") ?? null;
      const previousInert = backgroundElement?.inert ?? false;
      if (backgroundElement !== null) {
        backgroundElement.inert = true;
        backgroundElement.setAttribute("aria-hidden", "true");
      }
      closeButtonRef.current?.focus({ preventScroll: true });
      return () => {
        if (backgroundElement !== null) {
          backgroundElement.inert = previousInert;
          if (previousAriaHidden === null) backgroundElement.removeAttribute("aria-hidden");
          else backgroundElement.setAttribute("aria-hidden", previousAriaHidden);
        }
        const focusTarget = returnFocusElement ?? previousFocus;
        if (focusTarget?.isConnected) focusTarget.focus({ preventScroll: true });
      };
    }, [backgroundElement, returnFocusElement]);

    useEffect(() => {
      if (pendingMutation === null) return;
      const panel = dialogRef.current;
      const previousAriaHidden = panel?.getAttribute("aria-hidden") ?? null;
      const previousInert = panel?.inert ?? false;
      if (panel !== null) {
        panel.inert = true;
        panel.setAttribute("aria-hidden", "true");
      }
      mutationCancelButtonRef.current?.focus({ preventScroll: true });
      return () => {
        if (panel !== null) {
          panel.inert = previousInert;
          if (previousAriaHidden === null) panel.removeAttribute("aria-hidden");
          else panel.setAttribute("aria-hidden", previousAriaHidden);
        }
        const requestedFocusTarget = mutationReturnFocusRef.current;
        mutationReturnFocusRef.current = null;
        const focusTarget = requestedFocusTarget?.isConnected
          ? requestedFocusTarget
          : closeButtonRef.current;
        if (focusTarget?.isConnected) focusTarget.focus({ preventScroll: true });
      };
    }, [pendingMutation?.proposal.handle]);

    useEffect(() => {
      function handleKeyDown(event: KeyboardEvent) {
        if (event.key === "Escape") {
          event.preventDefault();
          switch (settingsEscapeIntent(pendingMutation !== null, confirmingMutation)) {
            case "cancel-mutation":
              void cancelDangerousMutation();
              break;
            case "close-settings":
              void requestClose();
              break;
            case "blocked":
              break;
          }
          return;
        }
        if (event.key !== "Tab") return;
        const dialog = pendingMutation === null ? dialogRef.current : mutationDialogRef.current;
        if (dialog === null) return;
        const focusable = Array.from(dialog.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR));
        const currentIndex = focusable.findIndex((element) => element === document.activeElement);
        const nextIndex = nextSettingsFocusIndex(currentIndex, focusable.length, event.shiftKey);
        event.preventDefault();
        if (nextIndex === -1) dialog.focus({ preventScroll: true });
        else focusable[nextIndex]?.focus({ preventScroll: true });
      }
      document.addEventListener("keydown", handleKeyDown);
      return () => document.removeEventListener("keydown", handleKeyDown);
    }, [confirmingMutation, pendingMutation, requestClose]);

    function update(mutator: (next: SettingsSnapshot) => void) {
      setDraft((current) => {
        if (current === null) return null;
        const next = cloneSettings(current);
        mutator(next);
        return next;
      });
      setNotice(null);
    }

    async function save() {
      if (draft === null || saving) return;
      if (apiKeyDraft.length > 0) {
        setNotice({ text: "API Key 不会随普通保存提交；请先只写替换或清空输入。", error: true });
        return;
      }
      if (!isSettingsSnapshot(draft)) {
        setNotice({ text: "请修正越界或无效的设置值后再保存。", error: true });
        return;
      }
      const input = toSettingsSaveInput(draft);
      if (!isSettingsSaveInput(input)) {
        setNotice({ text: "设置内容不符合要求，没有保存。", error: true });
        return;
      }
      setSaving(true);
      setNotice({ text: "正在原子保存设置…", error: false });
      try {
        const response = await api.saveSettings(input);
        if (!mountedRef.current) return;
        if (!isSettingsSnapshot(response)) {
          setNotice({ text: "保存结果无法确认，请重新打开设置核对。", error: true });
          return;
        }
        const saved = cloneSettings(response);
        setBaseline(saved);
        setDraft(cloneSettings(saved));
        setNotice({ text: "设置已保存到程序目录下的 data 文件夹。", error: false });
        onSaved?.();
      } catch {
        if (mountedRef.current) {
          setNotice({ text: "设置保存失败；未显示后端错误正文。", error: true });
        }
      } finally {
        if (mountedRef.current) setSaving(false);
      }
    }

    const selectedProvider = useMemo(() =>
      draft?.ai.providers.find(({ id }) => id === selectedProviderId) ?? null,
    [draft, selectedProviderId]);
    const baselineProviderIds = useMemo(
      () => new Set(baseline?.ai.providers.map(({ id }) => id) ?? []),
      [baseline],
    );

    function updateProvider(mutator: (provider: SettingsAiProvider) => void) {
      if (selectedProviderId === null) return;
      update((next) => {
        const provider = next.ai.providers.find(({ id }) => id === selectedProviderId);
        if (provider !== undefined) mutator(provider);
      });
    }

    function addProvider() {
      if (draft === null || draft.ai.providers.length >= 32) return;
      const provider = createProvider(draft.ai.providers);
      update((next) => next.ai.providers.push(provider));
      setSelectedProviderId(provider.id);
    }

    function removeUnsavedProvider() {
      if (selectedProviderId === null || baselineProviderIds.has(selectedProviderId)) return;
      update((next) => {
        next.ai.providers = next.ai.providers.filter(({ id }) => id !== selectedProviderId);
        if (next.ai.defaultProviderId === selectedProviderId) next.ai.defaultProviderId = null;
      });
      setSelectedProviderId(null);
    }

    async function replaceApiKey() {
      const replace = api.replaceSettingsAiApiKey;
      if (
        replace === undefined || selectedProvider === null ||
        !baselineProviderIds.has(selectedProvider.id) || credentialBusy
      ) return;
      const input = { providerId: selectedProvider.id, apiKey: apiKeyDraft };
      if (!isSettingsAiApiKeyReplacementInput(input)) {
        setApiKeyDraft("");
        setNotice({ text: "API Key 必须非空、不含控制字符且不超过 16 KiB。", error: true });
        return;
      }
      const providerId = input.providerId;
      const generation = ++secretOperationGenerationRef.current;
      setCredentialBusy(true);
      setApiKeyDraft("");
      setNotice({ text: "正在以只写方式替换 API Key…", error: false });
      try {
        const request = replace(input);
        input.apiKey = "";
        const response = await request;
        if (!mountedRef.current || secretOperationGenerationRef.current !== generation) return;
        if (
          !isSettingsAiApiKeyReplacementResult(response) ||
          response.providerId !== providerId
        ) {
          setNotice({ text: "API Key 替换的结果无法确认，请重新打开设置核对。", error: true });
          return;
        }
        setBaseline((current) =>
          current === null ? null : setSettingsApiKeyPresence(current, providerId, true)
        );
        setDraft((current) =>
          current === null ? null : setSettingsApiKeyPresence(current, providerId, true)
        );
        setNotice({ text: "API Key 已加密保存，明文输入已清空。", error: false });
      } catch {
        if (mountedRef.current && secretOperationGenerationRef.current === generation) {
          setNotice({ text: "API Key 替换失败；明文输入已清空，后端错误正文未显示。", error: true });
        }
      } finally {
        input.apiKey = "";
        if (mountedRef.current && secretOperationGenerationRef.current === generation) {
          setCredentialBusy(false);
        }
      }
    }

    async function planDangerousMutation(
      kind: SettingsMutationKind,
      returnFocus: HTMLElement,
    ) {
      if (
        selectedProvider === null || !baselineProviderIds.has(selectedProvider.id) ||
        planningMutation || pendingMutation !== null
      ) return;
      const plan = kind === "clear-ai-api-key"
        ? api.planSettingsAiApiKeyClear
        : api.planSettingsAiProviderRemoval;
      if (plan === undefined) {
        setNotice({ text: "这个版本还不能在这里执行这项危险操作。", error: true });
        return;
      }
      const providerId = selectedProvider.id;
      const generation = ++mutationOperationGenerationRef.current;
      setPlanningMutation(true);
      setNotice({ text: "正在创建单次危险操作计划…", error: false });
      try {
        const response = await plan(providerId);
        if (!mountedRef.current || mutationOperationGenerationRef.current !== generation) return;
        if (!isSettingsMutationProposal(response) || response.kind !== kind) {
          setNotice({ text: "危险操作计划的格式异常，没有采用。", error: true });
          return;
        }
        mutationReturnFocusRef.current = returnFocus;
        setPendingMutation({ proposal: response, providerId });
        setNotice(null);
      } catch {
        if (mountedRef.current && mutationOperationGenerationRef.current === generation) {
          setNotice({ text: "无法创建危险操作计划；后端错误正文未显示。", error: true });
        }
      } finally {
        if (mountedRef.current && mutationOperationGenerationRef.current === generation) {
          setPlanningMutation(false);
        }
      }
    }

    async function cancelDangerousMutation() {
      const current = pendingMutation;
      if (current === null || confirmingMutation) return;
      const cancel = api.cancelSettingsMutation;
      const generation = ++mutationOperationGenerationRef.current;
      setPendingMutation(null);
      if (cancel === undefined) {
        setNotice({ text: "已关闭确认，没有执行；这次确认会在到期后自动失效。", error: true });
        return;
      }
      try {
        const response = await cancel(current.proposal.handle);
        if (!mountedRef.current || mutationOperationGenerationRef.current !== generation) return;
        if (!isSettingsMutationCancellation(response)) {
          setNotice({ text: "取消的结果无法确认，但操作没有执行；这次确认会在到期后自动失效。", error: true });
          return;
        }
        setNotice({ text: "已取消，没有做任何改动。", error: false });
      } catch {
        if (mountedRef.current && mutationOperationGenerationRef.current === generation) {
          setNotice({ text: "取消没有成功送达，但操作没有执行；这次确认会在到期后自动失效。", error: true });
        }
      }
    }

    async function confirmDangerousMutation() {
      const current = pendingMutation;
      const confirm = api.confirmSettingsMutation;
      if (current === null || confirm === undefined || confirmingMutation) return;
      const generation = ++mutationOperationGenerationRef.current;
      setConfirmingMutation(true);
      try {
        const response = await confirm(current.proposal.handle);
        if (!mountedRef.current || mutationOperationGenerationRef.current !== generation) return;
        if (!isSettingsMutationResult(response) || response.kind !== current.proposal.kind) {
          setNotice({ text: "危险操作的结果无法确认；请关闭后重新打开设置核对。", error: true });
          return;
        }
        setBaseline((value) => value === null
          ? null
          : applySettingsMutation(value, current.proposal.kind, current.providerId));
        setDraft((value) => value === null
          ? null
          : applySettingsMutation(value, current.proposal.kind, current.providerId));
        if (current.proposal.kind === "remove-ai-provider") setSelectedProviderId(null);
        setNotice({
          text: current.proposal.kind === "clear-ai-api-key"
            ? "API Key 已清除。"
            : "AI 服务商及其 API Key 已删除。",
          error: false,
        });
      } catch {
        if (mountedRef.current && mutationOperationGenerationRef.current === generation) {
          setNotice({ text: "危险操作状态未知；计划不会重试，请关闭后重新载入设置。", error: true });
        }
      } finally {
        if (mountedRef.current && mutationOperationGenerationRef.current === generation) {
          setPendingMutation(null);
          setConfirmingMutation(false);
        }
      }
    }

    return (
      <div className="settings-overlay" data-testid="settings-overlay">
        <section
          ref={dialogRef}
          className="settings-panel"
          role="dialog"
          aria-modal="true"
          aria-labelledby="settings-title"
          aria-describedby="settings-boundary-note"
          tabIndex={-1}
        >
          <header className="settings-header">
            <div>
              <h2 id="settings-title">设置</h2>
              <p id="settings-boundary-note">设置保存在程序目录下的数据文件夹；API Key 加密保存，只能整体替换。</p>
            </div>
            <button
              ref={closeButtonRef}
              type="button"
              className="settings-icon-button"
              aria-label="关闭设置"
              onClick={() => { void requestClose(); }}
            >
              ×
            </button>
          </header>

          <div className="settings-layout">
            <nav className="settings-tabs" role="tablist" aria-label="设置分类">
              {SETTINGS_TABS.map((tab) => (
                <button
                  key={tab.id}
                  id={`settings-tab-${tab.id}`}
                  type="button"
                  role="tab"
                  aria-selected={activeTab === tab.id}
                  aria-controls={`settings-page-${tab.id}`}
                  tabIndex={activeTab === tab.id ? 0 : -1}
                  className={activeTab === tab.id ? "is-active" : undefined}
                  onClick={() => setActiveTab(tab.id)}
                >
                  {tab.label}
                </button>
              ))}
            </nav>

            <main className="settings-content">
              {loading && <p className="settings-empty">正在读取设置…</p>}
              {!loading && draft === null && (
                <div className="settings-empty">
                  <p>设置不可用。</p>
                  <button type="button" onClick={() => { void requestClose(); }}>关闭</button>
                </div>
              )}
              {draft !== null && activeTab === "general" && (
                <SettingsSection id="general" title="通用设置" description="主题、界面、日志与通知。">
                  <SettingsGrid>
                    <SelectField
                      label="主题"
                      value={draft.theme}
                      options={THEMES.map((theme) => [theme.id, theme.label] as [string, string])}
                      onChange={(value) => update((next) => { next.theme = value as SettingsSnapshot["theme"]; })}
                    />
                    <SelectField
                      label="语言"
                      value={draft.language}
                      options={[["zh-CN", "简体中文"], ["en-US", "English"]]}
                      onChange={(value) => update((next) => { next.language = value as SettingsSnapshot["language"]; })}
                    />
                    <NumberField
                      label="侧栏宽度（px）"
                      value={draft.ui.sidebarWidth}
                      minimum={200}
                      maximum={800}
                      onChange={(value) => update((next) => { next.ui.sidebarWidth = value; })}
                    />
                    <SelectField
                      label="诊断日志级别"
                      value={draft.logLevel}
                      options={[["debug", "DEBUG"], ["info", "INFO"], ["warn", "WARN"], ["error", "ERROR"]]}
                      onChange={(value) => update((next) => { next.logLevel = value as SettingsSnapshot["logLevel"]; })}
                    />
                  </SettingsGrid>
                  <ToggleGrid>
                    <Toggle label="自动连接" checked={draft.autoConnect} onChange={(checked) => update((next) => { next.autoConnect = checked; })} />
                    <Toggle label="紧凑模式" checked={draft.ui.compactMode} onChange={(checked) => update((next) => { next.ui.compactMode = checked; })} />
                    <Toggle label="界面动画" checked={draft.ui.animationsEnabled} onChange={(checked) => update((next) => { next.ui.animationsEnabled = checked; })} />
                    <Toggle label="显示状态栏" checked={draft.ui.showStatusBar} onChange={(checked) => update((next) => { next.ui.showStatusBar = checked; })} />
                    <Toggle label="启用通知" checked={draft.notifications.enabled} onChange={(checked) => update((next) => { next.notifications.enabled = checked; })} />
                    <Toggle label="连接状态通知" checked={draft.notifications.connectionStatus} onChange={(checked) => update((next) => { next.notifications.connectionStatus = checked; })} />
                    <Toggle label="命令完成通知" checked={draft.notifications.commandCompletion} onChange={(checked) => update((next) => { next.notifications.commandCompletion = checked; })} />
                    <Toggle label="错误提醒" checked={draft.notifications.errorAlerts} onChange={(checked) => update((next) => { next.notifications.errorAlerts = checked; })} />
                  </ToggleGrid>
                </SettingsSection>
              )}

              {draft !== null && activeTab === "connections" && (
                <SettingsSection id="connections" title="连接设置" description="SSH、安全与 Docker 刷新策略。">
                  <SettingsGrid>
                    <NumberField label="默认 SSH 端口" value={draft.defaultSshPort} minimum={1} maximum={65_535} onChange={(value) => update((next) => { next.defaultSshPort = value; })} />
                    <NumberField label="会话超时（分钟）" value={draft.security.sessionTimeoutMs / 60_000} minimum={1} maximum={1_440} onChange={(value) => update((next) => { next.security.sessionTimeoutMs = value * 60_000; })} />
                    <NumberField label="保活间隔（秒）" value={draft.ssh.keepAliveIntervalMs / 1_000} minimum={5} maximum={300} onChange={(value) => update((next) => { next.ssh.keepAliveIntervalMs = value * 1_000; })} />
                    <NumberField label="连接超时（秒，0 禁用）" value={draft.ssh.connectionTimeoutMs / 1_000} minimum={0} maximum={600} onChange={(value) => update((next) => { next.ssh.connectionTimeoutMs = value * 1_000; })} />
                    <NumberField label="最大重试次数" value={draft.ssh.maxRetries} minimum={1} maximum={10} onChange={(value) => update((next) => { next.ssh.maxRetries = value; })} />
                    <NumberField label="Docker 刷新周期（秒）" value={draft.docker.refreshIntervalMs / 1_000} minimum={1} maximum={60} onChange={(value) => update((next) => { next.docker.refreshIntervalMs = value * 1_000; })} />
                  </SettingsGrid>
                  <ToggleGrid>
                    <Toggle label="保存密码" checked={draft.security.savePasswords} onChange={(checked) => update((next) => { next.security.savePasswords = checked; })} />
                    <Toggle label="危险操作要求确认" checked={draft.security.requireConfirmation} onChange={(checked) => update((next) => { next.security.requireConfirmation = checked; })} />
                    <Toggle label="Docker 自动刷新" checked={draft.docker.autoRefresh} onChange={(checked) => update((next) => { next.docker.autoRefresh = checked; })} />
                    <Toggle label="显示系统容器" checked={draft.docker.showSystemContainers} onChange={(checked) => update((next) => { next.docker.showSystemContainers = checked; })} />
                  </ToggleGrid>
                </SettingsSection>
              )}

              {draft !== null && activeTab === "terminal" && (
                <SettingsSection id="terminal" title="终端设置" description="终端仅使用随应用分发的 Cascadia Mono。">
                  <div className="settings-fixed-value">
                    <span>字体</span><strong>Cascadia Mono</strong>
                  </div>
                  <SettingsGrid>
                    <NumberField label="字号（px）" value={draft.terminalFontSize} minimum={8} maximum={72} onChange={(value) => update((next) => { next.terminalFontSize = value; })} />
                    <NumberField label="最大滚动历史行数" value={draft.maxLogLines} minimum={1} maximum={100_000} onChange={(value) => update((next) => { next.maxLogLines = value; })} />
                  </SettingsGrid>
                </SettingsSection>
              )}

              {draft !== null && activeTab === "ai" && (
                <SettingsSection id="ai" title="AI 服务商" description="配置信息正常保存；API Key 只能替换，清除与删除需要单独确认。">
                  <div className="settings-provider-toolbar">
                    <label>
                      <span>服务商</span>
                      <select
                        value={selectedProviderId ?? ""}
                        disabled={credentialBusy || planningMutation || pendingMutation !== null}
                        onChange={(event) => setSelectedProviderId(event.target.value || null)}
                      >
                        <option value="">未选择</option>
                        {draft.ai.providers.map((provider) => <option key={provider.id} value={provider.id}>{provider.label}</option>)}
                      </select>
                    </label>
                    <button
                      type="button"
                      onClick={addProvider}
                      disabled={draft.ai.providers.length >= 32 || credentialBusy || planningMutation || pendingMutation !== null}
                    >新增服务商</button>
                    {selectedProvider !== null && !baselineProviderIds.has(selectedProvider.id) && (
                      <button
                        type="button"
                        className="settings-danger-link"
                        onClick={removeUnsavedProvider}
                        disabled={credentialBusy || planningMutation || pendingMutation !== null}
                      >撤销新增</button>
                    )}
                  </div>
                  {selectedProvider !== null ? (
                    <SettingsGrid>
                      <TextField
                        label="服务商标识"
                        value={selectedProvider.id}
                        maximumLength={64}
                        disabled={baselineProviderIds.has(selectedProvider.id)}
                        onChange={(value) => {
                          const previousId = selectedProvider.id;
                          updateProvider((provider) => { provider.id = value; });
                          update((next) => {
                            if (next.ai.defaultProviderId === previousId) next.ai.defaultProviderId = value;
                          });
                          setSelectedProviderId(value);
                        }}
                      />
                      <TextField label="显示名称" value={selectedProvider.label} maximumLength={128} onChange={(value) => updateProvider((provider) => { provider.label = value; })} />
                      <TextField label="接口地址" value={selectedProvider.endpoint} maximumLength={2_048} onChange={(value) => updateProvider((provider) => { provider.endpoint = value; })} />
                      <TextField label="模型" value={selectedProvider.model} maximumLength={256} onChange={(value) => updateProvider((provider) => { provider.model = value; })} />
                      <SelectField
                        label="类型"
                        value={selectedProvider.kind}
                        options={[["open-ai-compatible", "OpenAI 兼容接口"], ["anthropic", "Anthropic"], ["gemini", "Gemini"]]}
                        onChange={(value) => updateProvider((provider) => { provider.kind = value as SettingsAiProvider["kind"]; })}
                      />
                      <div className="settings-credential-editor">
                        <div className="settings-credential-state" aria-label="API Key 状态">
                          <span>API Key</span>
                          <strong>{selectedProvider.hasApiKey ? "已加密保存" : "未配置"}</strong>
                        </div>
                        <label className="settings-field">
                          <span>{selectedProvider.hasApiKey ? "替换 API Key" : "设置 API Key"}</span>
                          <input
                            data-testid="settings-api-key-input"
                            type="password"
                            value={apiKeyDraft}
                            maxLength={MAX_API_KEY_INPUT_CHARS}
                            autoComplete="new-password"
                            spellCheck={false}
                            disabled={
                              !secretLifecycleAvailable ||
                              !baselineProviderIds.has(selectedProvider.id) ||
                              credentialBusy || planningMutation || pendingMutation !== null
                            }
                            onChange={(event) => setApiKeyDraft(event.target.value)}
                          />
                        </label>
                        <div className="settings-credential-actions">
                          <button
                            data-testid="settings-api-key-replace"
                            type="button"
                            onClick={() => { void replaceApiKey(); }}
                            disabled={
                              !secretLifecycleAvailable || apiKeyDraft.length === 0 ||
                              !baselineProviderIds.has(selectedProvider.id) || credentialBusy ||
                              planningMutation || pendingMutation !== null
                            }
                          >{credentialBusy ? "替换中…" : "只写替换"}</button>
                          <button
                            data-testid="settings-api-key-clear"
                            type="button"
                            className="settings-danger-link"
                            disabled={
                              !secretLifecycleAvailable || !selectedProvider.hasApiKey ||
                              !baselineProviderIds.has(selectedProvider.id) || credentialBusy ||
                              planningMutation || pendingMutation !== null
                            }
                            onClick={(event) => {
                              void planDangerousMutation("clear-ai-api-key", event.currentTarget);
                            }}
                          >清除 Key…</button>
                          <button
                            data-testid="settings-provider-remove"
                            type="button"
                            className="settings-danger-link"
                            disabled={
                              !secretLifecycleAvailable || !baselineProviderIds.has(selectedProvider.id) ||
                              credentialBusy || planningMutation || pendingMutation !== null
                            }
                            onClick={(event) => {
                              void planDangerousMutation("remove-ai-provider", event.currentTarget);
                            }}
                          >删除服务商…</button>
                        </div>
                        {!secretLifecycleAvailable && (
                          <p className="settings-boundary-warning">这个版本还不能在这里管理 API 密钥。</p>
                        )}
                      </div>
                      <Toggle label="启用此服务商" checked={selectedProvider.enabled} onChange={(checked) => updateProvider((provider) => { provider.enabled = checked; })} />
                    </SettingsGrid>
                  ) : <p className="settings-empty">尚未配置 AI 服务商。</p>}

                  <div className="settings-subsection">
                    <h3>默认服务商与代理</h3>
                    <SettingsGrid>
                      <SelectField
                        label="默认服务商"
                        value={draft.ai.defaultProviderId ?? ""}
                        options={[["", "未设置"], ...draft.ai.providers.map(({ id, label }) => [id, label] as [string, string])]}
                        onChange={(value) => update((next) => { next.ai.defaultProviderId = value === "" ? null : value; })}
                      />
                      <Toggle
                        label="启用代理"
                        checked={draft.ai.proxy !== null}
                        onChange={(checked) => update((next) => {
                          next.ai.proxy = checked ? { proxyType: "http", proxyUrl: "" } : null;
                        })}
                      />
                      {draft.ai.proxy !== null && (
                        <>
                          <SelectField
                            label="代理类型"
                            value={draft.ai.proxy.proxyType}
                            options={[["http", "HTTP / HTTPS"], ["socks5", "SOCKS5"]]}
                            onChange={(value) => update((next) => {
                              if (next.ai.proxy !== null) {
                                next.ai.proxy.proxyType = value as "http" | "socks5";
                                next.ai.proxy.proxyUrl = "";
                              }
                            })}
                          />
                          <TextField label="代理 URL" value={draft.ai.proxy.proxyUrl} maximumLength={2_048} onChange={(value) => update((next) => { if (next.ai.proxy !== null) next.ai.proxy.proxyUrl = value; })} />
                        </>
                      )}
                    </SettingsGrid>
                  </div>
                </SettingsSection>
              )}
            </main>
          </div>

          <footer className="settings-footer">
            <div aria-live="polite">
              {notice !== null && <p className={notice.error ? "is-error" : undefined}>{notice.text}</p>}
              {notice === null && dirty && <p>有未保存的更改</p>}
            </div>
            <div className="settings-footer-actions">
              <button
                type="button"
                onClick={() => { void requestClose(); }}
                disabled={saving || credentialBusy || planningMutation || confirmingMutation || pendingMutation !== null}
              >取消</button>
              <button
                type="button"
                className="settings-primary"
                onClick={() => { void save(); }}
                disabled={
                  saving || !metadataDirty || apiKeyDraft.length > 0 || credentialBusy || planningMutation ||
                  confirmingMutation || pendingMutation !== null
                }
              >
                {saving ? "保存中…" : "保存设置"}
              </button>
            </div>
          </footer>
        </section>
        {pendingMutation !== null && (
          <SettingsDangerConfirmationDialog
            proposal={pendingMutation.proposal}
            busy={confirmingMutation}
            dialogRef={mutationDialogRef}
            cancelButtonRef={mutationCancelButtonRef}
            onCancel={() => { void cancelDangerousMutation(); }}
            onConfirm={() => { void confirmDangerousMutation(); }}
          />
        )}
        {discardConfirm.dialog !== null ? (
          <DialogHost dialog={discardConfirm.dialog} onResolve={discardConfirm.resolve} />
        ) : null}
      </div>
    );
  },
);

export function SettingsDangerConfirmationDialog({
  proposal,
  busy,
  dialogRef,
  cancelButtonRef,
  onCancel,
  onConfirm,
}: {
  proposal: SettingsMutationProposal;
  busy: boolean;
  dialogRef?: Ref<HTMLElement>;
  cancelButtonRef?: Ref<HTMLButtonElement>;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const action = proposal.kind === "clear-ai-api-key" ? "永久清除 API Key" : "永久删除 AI 服务商";
  return (
    <div className="settings-danger-overlay" data-testid="settings-danger-overlay">
      <section
        ref={dialogRef}
        className="settings-danger-dialog"
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="settings-danger-title"
        aria-describedby="settings-danger-summary settings-danger-expiry"
        tabIndex={-1}
      >
        <p className="settings-eyebrow">危险操作</p>
        <h3 id="settings-danger-title">{action}</h3>
        <p id="settings-danger-summary" className="settings-danger-summary">{proposal.summary}</p>
        <p id="settings-danger-expiry" className="settings-danger-expiry">
          这次确认在 {planExpiryLabel(proposal.expiresInSeconds)}内有效；失败或结果不明时不会自动重试。
        </p>
        <div className="settings-danger-actions">
          <button data-testid="settings-mutation-cancel" ref={cancelButtonRef} type="button" disabled={busy} onClick={onCancel}>取消</button>
          <button data-testid="settings-mutation-confirm" type="button" className="settings-danger-confirm" disabled={busy} onClick={onConfirm}>
            {busy ? "验证中…" : `确认${action}`}
          </button>
        </div>
      </section>
    </div>
  );
}

function SettingsSection({
  id,
  title,
  description,
  children,
}: { id: SettingsTab; title: string; description: string; children: ReactNode }) {
  return (
    <section
      id={`settings-page-${id}`}
      role="tabpanel"
      aria-labelledby={`settings-tab-${id}`}
      className="settings-page"
    >
      <header><h3>{title}</h3><p>{description}</p></header>
      {children}
    </section>
  );
}

function SettingsGrid({ children }: { children: ReactNode }) {
  return <div className="settings-grid">{children}</div>;
}

function ToggleGrid({ children }: { children: ReactNode }) {
  return <div className="settings-toggle-grid">{children}</div>;
}

function Toggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: (checked: boolean) => void }) {
  return (
    <label className="settings-toggle">
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} />
      <span aria-hidden="true" className="settings-toggle-track"><span /></span>
      <span>{label}</span>
    </label>
  );
}

function NumberField({
  label,
  value,
  minimum,
  maximum,
  onChange,
}: {
  label: string;
  value: number;
  minimum: number;
  maximum: number;
  onChange: (value: number) => void;
}) {
  function change(event: ChangeEvent<HTMLInputElement>) {
    const parsed = Number(event.target.value);
    if (Number.isSafeInteger(parsed)) onChange(parsed);
  }
  return (
    <label className="settings-field">
      <span>{label}</span>
      <input type="number" value={value} min={minimum} max={maximum} step={1} onChange={change} />
    </label>
  );
}

function TextField({
  label,
  value,
  maximumLength,
  disabled = false,
  onChange,
}: {
  label: string;
  value: string;
  maximumLength: number;
  disabled?: boolean;
  onChange: (value: string) => void;
}) {
  return (
    <label className="settings-field">
      <span>{label}</span>
      <input type="text" value={value} maxLength={maximumLength} disabled={disabled} onChange={(event) => onChange(event.target.value)} />
    </label>
  );
}

function SelectField({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: readonly (readonly [string, string])[];
  onChange: (value: string) => void;
}) {
  return (
    <label className="settings-field">
      <span>{label}</span>
      <select value={value} onChange={(event) => onChange(event.target.value)}>
        {options.map(([optionValue, optionLabel]) => <option key={optionValue || "none"} value={optionValue}>{optionLabel}</option>)}
      </select>
    </label>
  );
}
