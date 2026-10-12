import {
  useEffect,
  useMemo,
  useReducer,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
} from "react";

import type {
  ConnectionCredentialFileKind,
  ConnectionDeletePrompt,
  ConnectionDraftInput,
  ConnectionEditView,
  ConnectionSummary,
  ConnectionWriteInput,
  SshAuthMethod,
} from "../shared/contract";
import type {
  SshAttemptStarted,
  SshAttemptStatus,
  SshTargetSummary,
} from "../shared/ssh-contract";
import {
  connectionExportNotice,
  connectionImportNotice,
  connectionSecretWrites,
  emptySecretDrafts,
  nextFocusIndex,
  parseConnectionTags,
  secretDraftReducer,
  type SecretDraftAction,
  type SecretDrafts,
  type SecretSlot,
} from "./connection-helpers";
import { DialogHost } from "./DialogHost";
import { errorText } from "./error-text";
import { useConfirmDialog } from "./use-confirm-dialog";
import { SshAttemptDialog, type SshAttemptApi } from "./SshAttemptDialog";
import { useModalScrim } from "./modal-scrim";

const authOptions: ReadonlyArray<{ value: SshAuthMethod; label: string }> = [
  { value: "password", label: "密码" },
  { value: "keyboard-interactive", label: "交互认证 / MFA" },
  { value: "public-key", label: "SSH 私钥" },
  { value: "agent", label: "SSH Agent" },
  { value: "certificate", label: "OpenSSH 证书" },
];

/** What the caller wants to do with `initialConnectionId` once it is loaded. */
export type ConnectionManagerIntent = "connect" | "edit" | "delete";

interface ConnectionManagerProps {
  initialConnectionId: string | null;
  startCreating: boolean;
  initialIntent?: ConnectionManagerIntent;
  onClose(): void;
  onConnectionsChanged(connections: ConnectionSummary[]): void;
  onTargetConnected(bindingHandle: string, target: SshTargetSummary): void;
}

type SshAttemptMode = "probe" | "connect";

interface ActiveSshAttempt {
  started: SshAttemptStarted;
  mode: SshAttemptMode;
}

const sshApi: SshAttemptApi = {
  getAttempt: (handle) => window.lovelyhawk.getSshAttempt(handle),
  confirmHostKey: (attemptHandle, promptHandle) =>
    window.lovelyhawk.confirmSshHostKey(attemptHandle, promptHandle),
  respondMfa: (attemptHandle, promptHandle, responses) =>
    window.lovelyhawk.respondSshMfa(attemptHandle, promptHandle, responses),
  cancelAttempt: (handle) => window.lovelyhawk.cancelSshAttempt(handle),
  disconnectBinding: (handle) => window.lovelyhawk.disconnectSshBinding(handle),
};

interface ConnectionForm {
  id: string;
  name: string;
  host: string;
  port: string;
  username: string;
  authMethod: SshAuthMethod;
  privateKeyPath: string;
  certificatePath: string;
  agentIdentityFingerprint: string;
  jumpEnabled: boolean;
  jumpHost: string;
  jumpPort: string;
  jumpUsername: string;
  jumpAuthMethod: SshAuthMethod;
  jumpPrivateKeyPath: string;
  jumpCertificatePath: string;
  jumpAgentIdentityFingerprint: string;
  tags: string;
  notes: string;
  environment: string;
  role: string;
  group: string;
}

type CredentialPathField = "privateKeyPath" | "certificatePath" | "jumpPrivateKeyPath" | "jumpCertificatePath";

export function ConnectionManager({
  initialConnectionId,
  startCreating,
  initialIntent,
  onClose,
  onConnectionsChanged,
  onTargetConnected,
}: ConnectionManagerProps) {
  useModalScrim();
  const [connections, setConnections] = useState<ConnectionSummary[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(initialConnectionId);
  const [selected, setSelected] = useState<ConnectionEditView | null>(null);
  const [form, setForm] = useState<ConnectionForm | null>(null);
  const [creating, setCreating] = useState(false);
  const [secrets, dispatchSecrets] = useReducer(
    secretDraftReducer,
    undefined,
    emptySecretDrafts,
  );
  const [editorDirty, setEditorDirty] = useState(false);
  const [query, setQuery] = useState("");
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  // A list that could not be read is unknown, not empty.
  const [listUnreadable, setListUnreadable] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [deletePrompt, setDeletePrompt] = useState<ConnectionDeletePrompt | null>(null);
  const [sshAttempt, setSshAttempt] = useState<ActiveSshAttempt | null>(null);
  const formRef = useRef<ConnectionForm | null>(null);
  const choosingFileRef = useRef(false);
  const discardConfirm = useConfirmDialog();
  const managerRef = useRef<HTMLElement>(null);
  const managerInitialFocusRef = useRef<HTMLInputElement>(null);
  const deleteDialogRef = useRef<HTMLElement>(null);
  const deleteCancelRef = useRef<HTMLButtonElement>(null);
  const deleteReturnFocusRef = useRef<HTMLElement | null>(null);
  const deleteWasOpenRef = useRef(false);
  const sshReturnFocusRef = useRef<HTMLElement | null>(null);
  const editorDirtyRef = useRef(false);
  // A connect intent shows only the SSH attempt dialog; the manager chrome
  // stays hidden unless the attempt fails and the user has to fix something.
  const [chromeHidden, setChromeHidden] = useState(initialIntent === "connect");
  const operationInFlightRef = useRef(false);
  const mountedRef = useRef(false);
  const readGenerationRef = useRef(0);
  const interactionLocked = busy || loading || sshAttempt !== null;

  const visibleConnections = useMemo(() => {
    const normalized = query.trim().toLocaleLowerCase();
    if (normalized === "") return connections;
    return connections.filter((connection) =>
      [
        connection.name,
        connection.host,
        connection.username,
        connection.group ?? "",
        connection.environment ?? "",
        ...connection.tags,
      ].some((value) => value.toLocaleLowerCase().includes(normalized)),
    );
  }, [connections, query]);

  useEffect(() => {
    mountedRef.current = true;
    const focusFrame = requestAnimationFrame(() => managerInitialFocusRef.current?.focus());
    return () => {
      cancelAnimationFrame(focusFrame);
      mountedRef.current = false;
      readGenerationRef.current += 1;
    };
  }, []);

  useEffect(() => {
    if (deletePrompt !== null) {
      deleteWasOpenRef.current = true;
      const focusFrame = requestAnimationFrame(() => {
        (deleteCancelRef.current ?? deleteDialogRef.current)?.focus();
      });
      return () => cancelAnimationFrame(focusFrame);
    }
    if (!deleteWasOpenRef.current) return;
    deleteWasOpenRef.current = false;
    const returnTarget = deleteReturnFocusRef.current;
    deleteReturnFocusRef.current = null;
    const focusFrame = requestAnimationFrame(() => {
      if (returnTarget?.isConnected) returnTarget.focus();
      else managerInitialFocusRef.current?.focus();
    });
    return () => cancelAnimationFrame(focusFrame);
  }, [deletePrompt]);

  useEffect(() => {
    void (async () => {
      // The loaded view is passed straight through: state set above is not
      // readable in this closure yet.
      const loaded = await refreshConnections(initialConnectionId);
      if (!mountedRef.current) return;
      if (startCreating) {
        openCreateForm();
        return;
      }
      if (initialIntent === undefined || loaded === null || loaded.id !== initialConnectionId) {
        return;
      }
      if (initialIntent === "connect") void startConnect(loaded.id);
      else if (initialIntent === "edit") beginEdit(loaded);
      else void requestDelete(loaded);
    })();
  }, [initialConnectionId, initialIntent, startCreating]);

  function beginRead(): number {
    readGenerationRef.current += 1;
    return readGenerationRef.current;
  }

  function readIsCurrent(generation: number): boolean {
    return mountedRef.current && readGenerationRef.current === generation;
  }

  function invalidateReads() {
    readGenerationRef.current += 1;
  }

  function replaceForm(next: ConnectionForm | null) {
    formRef.current = next;
    setForm(next);
  }

  function markEditorDirty(next: boolean) {
    editorDirtyRef.current = next;
    setEditorDirty(next);
  }

  function resetSecrets() {
    dispatchSecrets({ type: "reset" });
  }

  function finishEditing() {
    invalidateReads();
    replaceForm(null);
    setCreating(false);
    markEditorDirty(false);
    resetSecrets();
  }

  async function confirmDiscardEditor(): Promise<boolean> {
    if (!editorDirtyRef.current) return true;
    return discardConfirm.ask(
      "放弃未保存的更改",
      "当前连接配置尚未保存。确定放弃这些更改吗？",
      "放弃更改",
    );
  }

  async function cancelEditor() {
    if (!(await confirmDiscardEditor())) return;
    finishEditing();
  }

  async function requestClose() {
    if (formRef.current !== null && !(await confirmDiscardEditor())) return;
    invalidateReads();
    resetSecrets();
    onClose();
  }

  async function refreshConnections(
    preferredId: string | null = selectedId,
  ): Promise<ConnectionEditView | null> {
    const generation = beginRead();
    setLoading(true);
    try {
      let result: ConnectionSummary[];
      try {
        result = await window.lovelyhawk.listConnections();
      } catch (reason: unknown) {
        if (readIsCurrent(generation)) setListUnreadable(true);
        throw reason;
      }
      if (!readIsCurrent(generation)) return null;
      setListUnreadable(false);
      setConnections(result);
      onConnectionsChanged(result);
      if (formRef.current !== null) {
        setError(null);
        return null;
      }
      const nextId =
        preferredId !== null && result.some((connection) => connection.id === preferredId)
          ? preferredId
          : result[0]?.id ?? null;
      setSelectedId(nextId);
      if (nextId === null) {
        setSelected(null);
        setError(null);
        return null;
      }
      const connection = await window.lovelyhawk.getConnection(nextId);
      if (!readIsCurrent(generation) || formRef.current !== null) return null;
      setSelected(connection);
      setError(null);
      return connection;
    } catch (reason: unknown) {
      if (readIsCurrent(generation)) {
        setError(messageFrom(reason, "连接列表或详情读取失败。"));
      }
      return null;
    } finally {
      if (readIsCurrent(generation)) setLoading(false);
    }
  }

  async function loadConnection(id: string) {
    if (interactionLocked || !(await confirmDiscardEditor())) return;
    const generation = beginRead();
    setLoading(true);
    try {
      const connection = await window.lovelyhawk.getConnection(id);
      if (!readIsCurrent(generation)) return;
      setSelectedId(id);
      setSelected(connection);
      replaceForm(null);
      setCreating(false);
      markEditorDirty(false);
      resetSecrets();
      setError(null);
    } catch (reason: unknown) {
      if (readIsCurrent(generation)) {
        setError(messageFrom(reason, "连接详情读取失败。"));
      }
    } finally {
      if (readIsCurrent(generation)) setLoading(false);
    }
  }

  async function importConnections() {
    if (interactionLocked) return;
    setBusy(true);
    setNotice(null);
    setError(null);
    try {
      const result = await window.lovelyhawk.importConnections();
      if (!mountedRef.current) return;
      if (!result.cancelled) await refreshConnections(selectedId);
      if (mountedRef.current) setNotice(connectionImportNotice(result));
    } catch (reason: unknown) {
      if (mountedRef.current) {
        setError(messageFrom(reason, "连接导入失败。"));
      }
    } finally {
      if (mountedRef.current) setBusy(false);
    }
  }

  async function exportConnections() {
    if (interactionLocked) return;
    setBusy(true);
    setNotice(null);
    setError(null);
    try {
      const result = await window.lovelyhawk.exportConnections();
      if (mountedRef.current) setNotice(connectionExportNotice(result));
    } catch (reason: unknown) {
      if (mountedRef.current) {
        setError(messageFrom(reason, "连接导出失败。"));
      }
    } finally {
      if (mountedRef.current) setBusy(false);
    }
  }

  async function beginCreate() {
    if (interactionLocked || !(await confirmDiscardEditor())) return;
    openCreateForm();
  }

  function openCreateForm() {
    invalidateReads();
    setSelected(null);
    setSelectedId(null);
    setCreating(true);
    replaceForm(emptyConnectionForm());
    markEditorDirty(false);
    resetSecrets();
    setNotice(null);
    setError(null);
  }

  function beginEdit(view: ConnectionEditView | null = selected) {
    if (view === null || interactionLocked) return;
    invalidateReads();
    setCreating(false);
    replaceForm(formFromView(view));
    markEditorDirty(false);
    resetSecrets();
    setNotice(null);
    setError(null);
  }

  function updateForm(next: ConnectionForm) {
    replaceForm(next);
    markEditorDirty(true);
  }

  function updateSecrets(action: SecretDraftAction) {
    dispatchSecrets(action);
    markEditorDirty(true);
  }

  /** Fills a key or certificate path from the system file dialog. */
  async function chooseCredentialFile(kind: ConnectionCredentialFileKind, field: CredentialPathField) {
    if (choosingFileRef.current) return;
    const editing = formRef.current?.id ?? null;
    choosingFileRef.current = true;
    setError(null);
    try {
      const choice = await window.lovelyhawk.chooseConnectionCredentialFile(kind);
      // The editor may have closed or moved to another connection meanwhile.
      const current = formRef.current;
      if (!mountedRef.current || choice.path === null || current === null || current.id !== editing) return;
      updateForm({ ...current, [field]: choice.path });
    } catch (reason: unknown) {
      if (mountedRef.current) setError(messageFrom(reason, "没能选择文件。"));
    } finally {
      choosingFileRef.current = false;
    }
  }

  async function saveConnection() {
    // `busy` only disables the button after the next render, so a fast second
    // submit would create the same connection twice; this ref closes that gap.
    if (form === null || operationInFlightRef.current) return;
    let input: ConnectionWriteInput;
    try {
      input = writeInput(form, secrets);
    } catch (reason: unknown) {
      setError(messageFrom(reason, "连接配置无效。"));
      return;
    }
    const wasCreating = creating;
    operationInFlightRef.current = true;
    setBusy(true);
    try {
      const saved = wasCreating
        ? await window.lovelyhawk.createConnection(input)
        : await window.lovelyhawk.updateConnection(input);
      if (!mountedRef.current) return;
      setSelected(saved);
      setSelectedId(saved.id);
      finishEditing();
      setNotice(wasCreating ? "连接已写入便携加密存储。" : "连接配置已更新。");
      setError(null);
      await refreshConnections(saved.id);
    } catch (reason: unknown) {
      if (mountedRef.current) setError(messageFrom(reason, "连接没有保存：有内容不符合要求，请检查主机名、用户名和指纹的格式。"));
    } finally {
      operationInFlightRef.current = false;
      resetSecrets();
      if (mountedRef.current) setBusy(false);
    }
  }

  async function startProbe() {
    if (operationInFlightRef.current) return;
    let input: ConnectionWriteInput;
    try {
      if (form !== null) input = writeInput(form, secrets);
      else if (selected !== null) input = writeInput(formFromView(selected), emptySecretDrafts());
      else return;
    } catch (reason: unknown) {
      setError(messageFrom(reason, "连接配置无效，无法测试。"));
      return;
    }
    sshReturnFocusRef.current = activeElement();
    operationInFlightRef.current = true;
    setBusy(true);
    try {
      const started = await window.lovelyhawk.startSshProbe(input);
      if (!mountedRef.current) {
        void window.lovelyhawk.cancelSshAttempt(started.attemptHandle).catch(() => undefined);
        return;
      }
      setSshAttempt({ started, mode: "probe" });
      setNotice(null);
      setError(null);
    } catch (reason: unknown) {
      if (mountedRef.current) {
        sshReturnFocusRef.current = null;
        setError(messageFrom(reason, "SSH 测试启动失败。"));
      }
    } finally {
      operationInFlightRef.current = false;
      if (mountedRef.current) setBusy(false);
    }
  }

  async function startConnect(connectionId: string | null = selected?.id ?? null) {
    if (form !== null || connectionId === null || operationInFlightRef.current) return;
    sshReturnFocusRef.current = activeElement();
    operationInFlightRef.current = true;
    setBusy(true);
    try {
      // A new connection replaces the current one and closes its editor
      // windows; unsaved text there is asked about first.
      const unsavedEditors = await window.lovelyhawk.unsavedEditorCount().catch(() => null);
      if (unsavedEditors !== 0) {
        setChromeHidden(false);
        const leave = await discardConfirm.ask(
          "放弃编辑窗口里未保存的修改？",
          unsavedEditors === null
            ? "无法确认文件编辑窗口里是否还有未保存的修改。连接新目标会关闭当前连接的这些窗口，未保存的修改会丢失。"
            : `还有 ${unsavedEditors} 个文件编辑窗口有没保存到服务器的修改。连接新目标会关闭它们，这些修改会丢失。`,
          "放弃修改并连接",
        );
        if (!leave || !mountedRef.current) return;
      }
      const started = await window.lovelyhawk.startSshConnect(connectionId);
      if (!mountedRef.current) {
        void window.lovelyhawk.cancelSshAttempt(started.attemptHandle).catch(() => undefined);
        return;
      }
      setSshAttempt({ started, mode: "connect" });
      setNotice(null);
      setError(null);
    } catch (reason: unknown) {
      if (mountedRef.current) {
        sshReturnFocusRef.current = null;
        setChromeHidden(false);
        setError(messageFrom(reason, "SSH 目标连接启动失败。"));
      }
    } finally {
      operationInFlightRef.current = false;
      if (mountedRef.current) setBusy(false);
    }
  }

  function handleSshTerminal(status: SshAttemptStatus) {
    if (status.stage === "connected") {
      onTargetConnected(status.bindingHandle, status.target);
      setNotice(`已连接 ${status.target.username}@${status.target.host}:${status.target.port}。`);
      setError(null);
      // Connecting is the end of this panel's job: close it so the app lands on
      // the newly bound target instead of leaving stacked modals behind.
      invalidateReads();
      resetSecrets();
      setSshAttempt(null);
      onClose();
      return;
    }
    setChromeHidden(false);
    if (status.stage === "probe-succeeded") {
      setNotice(`SSH 配置验证通过：${status.target.username}@${status.target.host}:${status.target.port}。`);
      setError(null);
    } else if (status.stage === "failed") {
      setError(status.error.message);
      setNotice(null);
    } else if (status.stage === "cancelled") {
      setNotice("SSH 尝试已取消，之后迟到的连接结果不会被采用。");
      setError(null);
    }
  }

  function closeSshAttempt() {
    setChromeHidden(false);
    setSshAttempt(null);
    const returnTarget = sshReturnFocusRef.current;
    sshReturnFocusRef.current = null;
    requestAnimationFrame(() => {
      if (returnTarget?.isConnected) returnTarget.focus();
      else managerInitialFocusRef.current?.focus();
    });
  }

  async function requestDelete(view: ConnectionEditView | null = selected) {
    if (view === null) return;
    deleteReturnFocusRef.current =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    setBusy(true);
    try {
      const prompt = await window.lovelyhawk.planConnectionDelete(view.id);
      if (!mountedRef.current) return;
      setDeletePrompt(prompt);
      setError(null);
    } catch (reason: unknown) {
      if (mountedRef.current) {
        deleteReturnFocusRef.current = null;
        setError(messageFrom(reason, "删除计划创建失败。"));
      }
    } finally {
      if (mountedRef.current) setBusy(false);
    }
  }

  async function confirmDelete() {
    if (deletePrompt === null) return;
    setBusy(true);
    try {
      const outcome = await window.lovelyhawk.confirmConnectionDelete(deletePrompt.handle);
      if (!mountedRef.current) return;
      if (!outcome.verified) throw new Error("删除结果未通过独立验证。");
      setDeletePrompt(null);
      setSelected(null);
      setSelectedId(null);
      setNotice("连接与已保存凭据已永久删除，并完成审计验证。");
      setError(null);
      await refreshConnections(null);
    } catch (reason: unknown) {
      if (mountedRef.current) {
        setDeletePrompt(null);
        setError(messageFrom(reason, "连接删除失败。"));
      }
    } finally {
      if (mountedRef.current) setBusy(false);
    }
  }

  async function cancelDelete() {
    if (deletePrompt === null || busy) return;
    setBusy(true);
    try {
      await window.lovelyhawk.cancelConnectionDelete(deletePrompt.handle);
      if (!mountedRef.current) return;
      setDeletePrompt(null);
      setNotice("连接删除已取消。");
      setError(null);
    } catch (reason: unknown) {
      if (mountedRef.current) {
        setError(messageFrom(reason, "连接删除计划取消失败。"));
        requestAnimationFrame(() => deleteCancelRef.current?.focus());
      }
    } finally {
      if (mountedRef.current) setBusy(false);
    }
  }

  function handleManagerKeyDown(event: ReactKeyboardEvent<HTMLElement>) {
    if (event.key === "Tab") {
      trapDialogFocus(event, managerRef.current);
      return;
    }
    if (event.key !== "Escape" || event.nativeEvent.isComposing || busy) return;
    event.preventDefault();
    if (form !== null) void cancelEditor();
    else void requestClose();
  }

  function handleDeleteKeyDown(event: ReactKeyboardEvent<HTMLElement>) {
    if (event.key === "Tab") {
      trapDialogFocus(event, deleteDialogRef.current);
      return;
    }
    if (event.key !== "Escape" || event.nativeEvent.isComposing || busy) return;
    event.preventDefault();
    event.stopPropagation();
    void cancelDelete();
  }

  return (
    <div className="connection-manager-backdrop">
      <section
        ref={managerRef}
        className={chromeHidden ? "connection-manager is-hidden" : "connection-manager"}
        role="dialog"
        aria-modal="true"
        aria-labelledby="connection-manager-title"
        aria-hidden={deletePrompt !== null || sshAttempt !== null || discardConfirm.dialog !== null ? true : undefined}
        inert={deletePrompt !== null || sshAttempt !== null || discardConfirm.dialog !== null ? true : undefined}
        onKeyDown={handleManagerKeyDown}
      >
        <header className="connection-manager-header">
          <div>
            <h1 id="connection-manager-title">连接管理</h1>
            <p>密码等凭据加密保存在本地。</p>
          </div>
          <div>
            <button type="button" disabled={interactionLocked} onClick={() => void refreshConnections()}>刷新</button>
            <button type="button" data-testid="connection-import" disabled={interactionLocked} onClick={() => void importConnections()}>导入 JSON</button>
            <button type="button" data-testid="connection-export" disabled={interactionLocked} onClick={() => void exportConnections()}>导出 JSON</button>
            <button type="button" className="primary-button" disabled={interactionLocked} onClick={() => void beginCreate()}>新建连接</button>
            <button type="button" className="close-button" aria-label="关闭连接管理" disabled={busy} onClick={() => void requestClose()}>×</button>
          </div>
        </header>

        {error !== null ? <div className="connection-notice error" role="alert">{error}</div> : null}
        {notice !== null ? <div className="connection-notice" role="status">{notice}</div> : null}

        <div className="connection-manager-body">
          <aside className="connection-sidebar">
            <label className="connection-search">
              <span aria-hidden="true">⌕</span>
              <input ref={managerInitialFocusRef} aria-label="搜索连接" maxLength={256} value={query} placeholder="名称、主机、标签…" onChange={(event) => setQuery(event.currentTarget.value)} />
            </label>
            <div className="connection-sidebar-meta"><strong>{listUnreadable ? "连接未读出" : `${connections.length} 个连接`}</strong><span>{loading ? "读取中…" : "凭据已加密"}</span></div>
            <div className="connection-list" aria-label="已保存连接">
              {visibleConnections.map((connection) => (
                <button
                  type="button"
                  className={selectedId === connection.id && form === null ? "connection-list-row active" : "connection-list-row"}
                  key={connection.id}
                  disabled={interactionLocked}
                  onClick={() => void loadConnection(connection.id)}
                >
                  <span className="connection-list-avatar">{connection.name.slice(0, 1).toLocaleUpperCase()}</span>
                  <span><strong>{connection.name}</strong><small>{connection.username}@{connection.host}:{connection.port}</small></span>
                  <i>{connection.hasPassword || connection.hasKeyPassphrase ? "●" : "○"}</i>
                </button>
              ))}
              {!loading && listUnreadable ? <div className="connection-list-empty">已保存的连接没有读出来，原因见上方提示。</div> : null}
              {!loading && !listUnreadable && visibleConnections.length === 0 ? (
                <div className="connection-list-empty">
                  {connections.length === 0 ? "还没有保存的连接。点上方“新建连接”填写主机与账号，或“导入 JSON”。" : "没有匹配的连接，换个名称、主机或标签试试。"}
                </div>
              ) : null}
            </div>
          </aside>

          <main className="connection-detail">
            {form !== null ? (
              <ConnectionEditor
                busy={interactionLocked}
                creating={creating}
                form={form}
                secrets={secrets}
                stored={selected}
                onFormChange={updateForm}
                onSecretAction={updateSecrets}
                onCancel={() => void cancelEditor()}
                onSave={() => void saveConnection()}
                onProbe={() => void startProbe()}
                onChooseFile={(kind, field) => void chooseCredentialFile(kind, field)}
              />
            ) : selected !== null ? (
              <ConnectionDetails
                connection={selected}
                busy={interactionLocked}
                onEdit={() => beginEdit()}
                onDelete={() => void requestDelete()}
                onProbe={() => void startProbe()}
                onConnect={() => void startConnect()}
              />
            ) : (
              <div className="connection-detail-empty">
                <span>⌁</span><h2>选择或新建连接</h2><p>从左侧选择一个连接查看详情，或新建一个连接。</p>
              </div>
            )}
          </main>
        </div>
      </section>

      {deletePrompt !== null ? (
        <div className="connection-delete-backdrop">
          <section
            ref={deleteDialogRef}
            className="danger-dialog"
            role="alertdialog"
            aria-modal="true"
            aria-labelledby="connection-delete-title"
            aria-describedby="connection-delete-description"
            tabIndex={-1}
            onKeyDown={handleDeleteKeyDown}
          >
            <span className="danger-dialog-icon" aria-hidden="true">!</span>
            <p className="eyebrow">危险操作</p>
            <h2 id="connection-delete-title">永久删除连接？</h2>
            <p id="connection-delete-description">{deletePrompt.confirmationText}</p>
            <small>删除后无法恢复。</small>
            {error !== null ? <div className="danger-dialog-error" role="alert">{error}</div> : null}
            <div>
              <button ref={deleteCancelRef} type="button" disabled={busy} onClick={() => void cancelDelete()}>取消</button>
              <button type="button" className="danger-confirm" disabled={busy} onClick={() => void confirmDelete()}>确认永久删除</button>
            </div>
          </section>
        </div>
      ) : null}
      {discardConfirm.dialog !== null ? (
        <DialogHost dialog={discardConfirm.dialog} onResolve={discardConfirm.resolve} />
      ) : null}
      {sshAttempt !== null ? (
        <SshAttemptDialog
          attempt={sshAttempt.started}
          mode={sshAttempt.mode}
          api={sshApi}
          onTerminal={handleSshTerminal}
          onClose={closeSshAttempt}
        />
      ) : null}
    </div>
  );
}

const focusableSelector = [
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  "a[href]",
  '[tabindex]:not([tabindex="-1"])',
].join(",");

function trapDialogFocus(
  event: ReactKeyboardEvent<HTMLElement>,
  dialog: HTMLElement | null,
) {
  if (dialog === null) return;
  const items = Array.from(dialog.querySelectorAll<HTMLElement>(focusableSelector)).filter(
    (item) => !item.hidden && item.getAttribute("aria-hidden") !== "true",
  );
  const currentIndex = items.indexOf(document.activeElement as HTMLElement);
  const nextIndex = nextFocusIndex(currentIndex, items.length, event.shiftKey);
  event.preventDefault();
  if (nextIndex === null) dialog.focus();
  else items[nextIndex]?.focus();
}

function ConnectionDetails({
  connection,
  busy,
  onEdit,
  onDelete,
  onProbe,
  onConnect,
}: {
  connection: ConnectionEditView;
  busy: boolean;
  onEdit(): void;
  onDelete(): void;
  onProbe(): void;
  onConnect(): void;
}) {
  return (
    <section className="connection-details-view">
      <header>
        <div className="connection-hero-avatar">{connection.name.slice(0, 1).toLocaleUpperCase()}</div>
        <div><p className="eyebrow">已保存的目标</p><h2>{connection.name}</h2><span>{connection.username}@{connection.host}:{connection.port}</span></div>
        <div><button type="button" disabled={busy} onClick={onProbe}>测试连接</button><button type="button" className="primary-button" disabled={busy} onClick={onConnect}>连接目标</button></div>
      </header>
      <div className="connection-fact-grid">
        <Fact label="认证方式" value={authLabel(connection.authMethod)} />
        <Fact label="凭据状态" value={credentialLabel(connection)} />
        <Fact label="环境" value={connection.environment ?? "未分类"} />
        <Fact label="角色" value={connection.role ?? "未设置"} />
        <Fact label="分组" value={connection.group ?? "未分组"} />
        <Fact label="最近连接" value={connection.lastConnectedAt ?? "尚未连接"} />
      </div>
      <section className="connection-detail-section"><h3>主机密钥</h3><p>目标主机密钥指纹</p><code>{connection.hostKeyFingerprint ?? "首次连接时需要独立核验指纹"}</code></section>
      {connection.privateKeyPath !== null || connection.certificatePath !== null ? <section className="connection-detail-section"><h3>认证文件</h3>
        {connection.privateKeyPath !== null ? <><p>私钥</p><code>{connection.privateKeyPath}</code></> : null}
        {connection.certificatePath !== null ? <><p>用户证书</p><code>{connection.certificatePath}</code></> : null}
      </section> : null}
      {connection.jumpHost !== null ? <section className="connection-detail-section"><h3>堡垒机 / ProxyJump</h3><p>{connection.jumpHost.username}@{connection.jumpHost.host}:{connection.jumpHost.port} · {authLabel(connection.jumpHost.authMethod)}</p><code>{connection.jumpHost.hostKeyFingerprint ?? "首次连接时需要独立核验指纹"}</code></section> : null}
      <section className="connection-detail-section"><h3>分类与备注</h3><div className="connection-tags">{connection.tags.map((tag) => <span key={tag}>#{tag}</span>)}</div><p className="connection-notes-text">{connection.notes ?? "无备注"}</p></section>
      <footer><button type="button" disabled={busy} onClick={onEdit}>编辑配置</button><button type="button" className="danger-button" disabled={busy} onClick={onDelete}>永久删除</button></footer>
    </section>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return <div><span>{label}</span><strong>{value}</strong></div>;
}

function ConnectionEditor({
  busy,
  creating,
  form,
  secrets,
  stored,
  onFormChange,
  onSecretAction,
  onCancel,
  onSave,
  onProbe,
  onChooseFile,
}: {
  busy: boolean;
  creating: boolean;
  form: ConnectionForm;
  secrets: SecretDrafts;
  stored: ConnectionEditView | null;
  onFormChange(value: ConnectionForm): void;
  onSecretAction(action: SecretDraftAction): void;
  onCancel(): void;
  onSave(): void;
  onProbe(): void;
  onChooseFile(kind: ConnectionCredentialFileKind, field: CredentialPathField): void;
}) {
  const patchForm = <Key extends keyof ConnectionForm>(key: Key, value: ConnectionForm[Key]) =>
    onFormChange({ ...form, [key]: value });
  const changeAuthMethod = (value: SshAuthMethod) => {
    if (value === form.authMethod) return;
    patchForm("authMethod", value);
    onSecretAction({ type: "clear-scope", scope: "target" });
  };
  const changeJumpAuthMethod = (value: SshAuthMethod) => {
    if (value === form.jumpAuthMethod) return;
    patchForm("jumpAuthMethod", value);
    onSecretAction({ type: "clear-scope", scope: "jump" });
  };
  const toggleJumpHost = () => {
    const enabled = !form.jumpEnabled;
    patchForm("jumpEnabled", enabled);
    if (!enabled) onSecretAction({ type: "clear-scope", scope: "jump" });
  };
  return (
    <form className="connection-editor" onSubmit={(event) => { event.preventDefault(); onSave(); }}>
      <header><div><h2>{creating ? "新建连接" : `编辑 ${stored?.name ?? "连接"}`}</h2></div><span>密码提交后会立即从表单清空</span></header>
      <EditorSection title="目标端点">
        <div className="connection-form-grid four-columns">
          <Field label="连接名称"><input required maxLength={256} value={form.name} onChange={(event) => patchForm("name", event.currentTarget.value)} /></Field>
          <Field label="主机名或 IP"><input required maxLength={253} value={form.host} onChange={(event) => patchForm("host", event.currentTarget.value)} /></Field>
          <Field label="端口"><input required inputMode="numeric" value={form.port} onChange={(event) => patchForm("port", event.currentTarget.value)} /></Field>
          <Field label="Linux 用户名"><input required maxLength={32} value={form.username} onChange={(event) => patchForm("username", event.currentTarget.value)} /></Field>
        </div>
        {stored?.hostKeyFingerprint != null && (form.host.trim() !== stored.host || form.port.trim() !== String(stored.port))
          ? <p className="connection-section-hint" role="note" data-testid="connection-pin-note">主机或端口改了，原来记住的主机密钥指纹不再适用；保存后第一次连接时需要重新核验。</p>
          : null}
      </EditorSection>
      <EditorSection title="认证方式">
        <AuthPicker value={form.authMethod} onChange={changeAuthMethod} />
        <AuthFields
          prefix=""
          method={form.authMethod}
          privateKeyPath={form.privateKeyPath}
          certificatePath={form.certificatePath}
          agentIdentityFingerprint={form.agentIdentityFingerprint}
          password={secrets.password}
          keyPassphrase={secrets.keyPassphrase}
          storedPassword={stored?.hasPassword ?? false}
          storedKeyPassphrase={stored?.hasKeyPassphrase ?? false}
          removePassword={secrets.removePassword}
          removeKeyPassphrase={secrets.removeKeyPassphrase}
          patchForm={patchForm}
          onChooseFile={onChooseFile}
          busy={busy}
          onSecretAction={onSecretAction}
        />
      </EditorSection>
      <EditorSection title="堡垒机 / ProxyJump" action={<button type="button" className={form.jumpEnabled ? "toggle-button active" : "toggle-button"} onClick={toggleJumpHost}>{form.jumpEnabled ? "已启用" : "未启用"}</button>}>
        {form.jumpEnabled ? <>
          <div className="connection-form-grid three-columns">
            <Field label="堡垒机地址"><input required maxLength={253} value={form.jumpHost} onChange={(event) => patchForm("jumpHost", event.currentTarget.value)} /></Field>
            <Field label="堡垒机端口"><input required inputMode="numeric" value={form.jumpPort} onChange={(event) => patchForm("jumpPort", event.currentTarget.value)} /></Field>
            <Field label="堡垒机用户名"><input required maxLength={32} value={form.jumpUsername} onChange={(event) => patchForm("jumpUsername", event.currentTarget.value)} /></Field>
          </div>
          <AuthPicker value={form.jumpAuthMethod} onChange={changeJumpAuthMethod} />
          <AuthFields
            prefix="jump"
            method={form.jumpAuthMethod}
            privateKeyPath={form.jumpPrivateKeyPath}
            certificatePath={form.jumpCertificatePath}
            agentIdentityFingerprint={form.jumpAgentIdentityFingerprint}
            password={secrets.jumpHostPassword}
            keyPassphrase={secrets.jumpHostKeyPassphrase}
            storedPassword={stored?.jumpHostHasPassword ?? false}
            storedKeyPassphrase={stored?.jumpHostHasKeyPassphrase ?? false}
            removePassword={secrets.removeJumpHostPassword}
            removeKeyPassphrase={secrets.removeJumpHostKeyPassphrase}
            patchForm={patchForm}
            onChooseFile={onChooseFile}
            busy={busy}
            onSecretAction={onSecretAction}
          />
        </> : <p className="connection-section-hint">直接连接目标；启用后可为堡垒机单独设置认证方式，并单独核验它的主机密钥。</p>}
      </EditorSection>
      <EditorSection title="分类与备注">
        <div className="connection-form-grid three-columns">
          <Field label="环境"><input maxLength={256} value={form.environment} placeholder="production / ctf" onChange={(event) => patchForm("environment", event.currentTarget.value)} /></Field>
          <Field label="角色"><input maxLength={256} value={form.role} placeholder="web / db / k8s" onChange={(event) => patchForm("role", event.currentTarget.value)} /></Field>
          <Field label="分组"><input maxLength={256} value={form.group} onChange={(event) => patchForm("group", event.currentTarget.value)} /></Field>
        </div>
        <Field label="标签（中英文逗号分隔，最多 20 个）"><input value={form.tags} onChange={(event) => patchForm("tags", event.currentTarget.value)} /></Field>
        <Field label="备注"><textarea maxLength={16 * 1_024} rows={4} value={form.notes} onChange={(event) => patchForm("notes", event.currentTarget.value)} /></Field>
      </EditorSection>
      <footer><button type="button" disabled={busy} onClick={onCancel}>取消</button><button type="button" disabled={busy} onClick={onProbe}>测试当前配置</button><button type="submit" className="primary-button" disabled={busy}>{busy ? "处理中…" : "保存配置"}</button></footer>
    </form>
  );
}

function EditorSection({ title, action, children }: { title: string; action?: React.ReactNode; children: React.ReactNode }) {
  return <section className="connection-editor-section"><header><h3>{title}</h3>{action}</header>{children}</section>;
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return <label className="connection-field"><span>{label}</span>{children}</label>;
}

function AuthPicker({ value, onChange }: { value: SshAuthMethod; onChange(value: SshAuthMethod): void }) {
  return <div className="auth-picker">{authOptions.map((option) => <button type="button" className={value === option.value ? "active" : ""} key={option.value} onClick={() => onChange(option.value)}>{option.label}</button>)}</div>;
}

function AuthFields({
  prefix,
  method,
  privateKeyPath,
  certificatePath,
  agentIdentityFingerprint,
  password,
  keyPassphrase,
  storedPassword,
  storedKeyPassphrase,
  removePassword,
  removeKeyPassphrase,
  patchForm,
  onChooseFile,
  busy,
  onSecretAction,
}: {
  prefix: "" | "jump";
  method: SshAuthMethod;
  privateKeyPath: string;
  certificatePath: string;
  agentIdentityFingerprint: string;
  password: string;
  keyPassphrase: string;
  storedPassword: boolean;
  storedKeyPassphrase: boolean;
  removePassword: boolean;
  removeKeyPassphrase: boolean;
  patchForm<Key extends keyof ConnectionForm>(key: Key, value: ConnectionForm[Key]): void;
  onChooseFile(kind: ConnectionCredentialFileKind, field: CredentialPathField): void;
  busy: boolean;
  onSecretAction(action: SecretDraftAction): void;
}) {
  const privateKeyField = prefix === "jump" ? "jumpPrivateKeyPath" : "privateKeyPath";
  const certificateField = prefix === "jump" ? "jumpCertificatePath" : "certificatePath";
  const fingerprintField = prefix === "jump" ? "jumpAgentIdentityFingerprint" : "agentIdentityFingerprint";
  const passwordField = prefix === "jump" ? "jumpHostPassword" : "password";
  const passphraseField = prefix === "jump" ? "jumpHostKeyPassphrase" : "keyPassphrase";
  const note = droppedSecretsNote(method, storedPassword, storedKeyPassphrase);
  const dropped = note === null ? null : <p className="connection-section-hint" role="note">{note}</p>;
  if (method === "keyboard-interactive") return <><p className="connection-section-hint">连接时按服务器提示输入密码、验证码或 MFA 响应；响应不会持久化。</p>{dropped}</>;
  if (method === "password") return <><SecretField label="SSH 密码" slot={passwordField} value={password} stored={storedPassword} remove={removePassword} required onSecretAction={onSecretAction} />{dropped}</>;
  if (method === "agent") return <><Field label="Agent 身份指纹（可选，SHA256:…）"><input maxLength={256} value={agentIdentityFingerprint} onChange={(event) => patchForm(fingerprintField, event.currentTarget.value)} /></Field>{dropped}</>;
  const owner = prefix === "jump" ? "堡垒机" : "目标";
  return <><div className="connection-form-grid two-columns">
    <PathField label="私钥文件（本机绝对路径）" chooseLabel={`选择文件：${owner}私钥`} value={privateKeyPath} busy={busy}
      onChange={(value) => patchForm(privateKeyField, value)} onChoose={() => onChooseFile("private-key", privateKeyField)} />
    <SecretField label="私钥口令（可选）" slot={passphraseField} value={keyPassphrase} stored={storedKeyPassphrase} remove={removeKeyPassphrase} onSecretAction={onSecretAction} />
    {method === "certificate" ? <PathField label="OpenSSH 用户证书（本机绝对路径）" chooseLabel={`选择文件：${owner}用户证书`} value={certificatePath} busy={busy}
      onChange={(value) => patchForm(certificateField, value)} onChoose={() => onChooseFile("certificate", certificateField)} /> : null}
  </div>{dropped}</>;
}

/** A local path that can be typed or filled from the system file dialog. */
function PathField({ label, chooseLabel, value, busy, onChange, onChoose }: {
  label: string;
  chooseLabel: string;
  value: string;
  busy: boolean;
  onChange(value: string): void;
  onChoose(): void;
}) {
  return <div className="connection-path-field">
    <Field label={label}><input required maxLength={4_096} value={value} onChange={(event) => onChange(event.currentTarget.value)} /></Field>
    <button type="button" aria-label={chooseLabel} disabled={busy} onClick={onChoose}>选择文件…</button>
  </div>;
}

/**
 * A write-only secret. A required one (the password of password login) has
 * no remove button: removing it could only end in a refused save. Switching
 * to another login method removes it instead, and the editor says so.
 */
function SecretField({ label, slot, value, stored, remove, required = false, onSecretAction }: { label: string; slot: SecretSlot; value: string; stored: boolean; remove: boolean; required?: boolean; onSecretAction(action: SecretDraftAction): void }) {
  const input = <Field label={`${label} · ${remove ? "将移除" : stored ? "已有保存值" : "尚未保存"}`}><input type="password" autoComplete="new-password" maxLength={16 * 1_024} value={value} placeholder={stored ? "留空以保持现有值" : "输入新值"} onChange={(event) => onSecretAction({ type: "replace", slot, value: event.currentTarget.value })} /></Field>;
  if (required) return input;
  return <div className="connection-secret-field">{input}<button type="button" disabled={!stored && !remove} onClick={() => onSecretAction({ type: "toggle-remove", slot })}>{remove ? "改为保留" : "移除已保存值"}</button></div>;
}

/** Saved secrets the chosen login method no longer uses are deleted on save. */
function droppedSecretsNote(method: SshAuthMethod, storedPassword: boolean, storedKeyPassphrase: boolean): string | null {
  const dropped = [
    storedPassword && method !== "password" ? "SSH 密码" : null,
    storedKeyPassphrase && !usesPrivateKey(method) ? "私钥口令" : null,
  ].filter((name) => name !== null);
  if (dropped.length === 0) return null;
  const names = dropped.join("和");
  return `保存后会删除已保存的${/^[A-Za-z]/u.test(names) ? " " : ""}${names}。`;
}

function emptyConnectionForm(): ConnectionForm {
  return {
    id: crypto.randomUUID(), name: "", host: "", port: "22", username: "root",
    authMethod: "password", privateKeyPath: "", certificatePath: "", agentIdentityFingerprint: "",
    jumpEnabled: false, jumpHost: "", jumpPort: "22", jumpUsername: "root", jumpAuthMethod: "password",
    jumpPrivateKeyPath: "", jumpCertificatePath: "", jumpAgentIdentityFingerprint: "",
    tags: "", notes: "", environment: "", role: "", group: "",
  };
}

function formFromView(view: ConnectionEditView): ConnectionForm {
  return {
    id: view.id, name: view.name, host: view.host, port: String(view.port), username: view.username,
    authMethod: view.authMethod, privateKeyPath: view.privateKeyPath ?? "", certificatePath: view.certificatePath ?? "", agentIdentityFingerprint: view.agentIdentityFingerprint ?? "",
    jumpEnabled: view.jumpHost !== null, jumpHost: view.jumpHost?.host ?? "", jumpPort: String(view.jumpHost?.port ?? 22), jumpUsername: view.jumpHost?.username ?? "root", jumpAuthMethod: view.jumpHost?.authMethod ?? "password",
    jumpPrivateKeyPath: view.jumpHost?.privateKeyPath ?? "", jumpCertificatePath: view.jumpHost?.certificatePath ?? "", jumpAgentIdentityFingerprint: view.jumpHost?.agentIdentityFingerprint ?? "",
    tags: view.tags.join(", "), notes: view.notes ?? "", environment: view.environment ?? "", role: view.role ?? "", group: view.group ?? "",
  };
}

function writeInput(form: ConnectionForm, secrets: SecretDrafts): ConnectionWriteInput {
  const port = parsePort(form.port, "SSH 端口");
  const tags = parseConnectionTags(form.tags);
  if (tags.length > 20) throw new Error("连接标签最多 20 个。");
  const connection: ConnectionDraftInput = {
    id: form.id,
    name: form.name.trim(),
    host: form.host.trim(),
    port,
    username: form.username.trim(),
    authMethod: form.authMethod,
    privateKeyPath: usesPrivateKey(form.authMethod) ? requiredText(form.privateKeyPath, "私钥绝对路径") : null,
    certificatePath: form.authMethod === "certificate" ? requiredText(form.certificatePath, "证书绝对路径") : null,
    agentIdentityFingerprint: form.authMethod === "agent" ? agentFingerprint(form.agentIdentityFingerprint, "Agent 身份指纹") : null,
    jumpHost: form.jumpEnabled ? {
      host: form.jumpHost.trim(), port: parsePort(form.jumpPort, "堡垒机端口"), username: form.jumpUsername.trim(), authMethod: form.jumpAuthMethod,
      privateKeyPath: usesPrivateKey(form.jumpAuthMethod) ? requiredText(form.jumpPrivateKeyPath, "堡垒机私钥绝对路径") : null,
      certificatePath: form.jumpAuthMethod === "certificate" ? requiredText(form.jumpCertificatePath, "堡垒机证书绝对路径") : null,
      agentIdentityFingerprint: form.jumpAuthMethod === "agent" ? agentFingerprint(form.jumpAgentIdentityFingerprint, "堡垒机 Agent 身份指纹") : null,
    } : null,
    tags,
    notes: optionalText(form.notes), environment: optionalText(form.environment), role: optionalText(form.role), group: optionalText(form.group),
  };
  const secretWrites = connectionSecretWrites(form, secrets);
  return { connection, secrets: secretWrites };
}

function parsePort(value: string, label: string): number {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new Error(`${label}必须是 1–65535 的整数。`);
  return port;
}

function requiredText(value: string, label: string): string {
  const normalized = value.trim();
  if (normalized === "") throw new Error(`${label}不能为空。`);
  return normalized;
}

function optionalText(value: string): string | null {
  const normalized = value.trim();
  return normalized === "" ? null : normalized;
}

/** OpenSSH prints agent identities as `SHA256:…` with `ssh-add -l -E sha256`. */
function agentFingerprint(value: string, label: string): string | null {
  const normalized = optionalText(value);
  if (normalized !== null && !(normalized.startsWith("SHA256:") && normalized.length > "SHA256:".length)) {
    throw new Error(`${label}应以 SHA256: 开头，可以用 ssh-add -l -E sha256 查看；不需要指定时留空。`);
  }
  return normalized;
}

function usesPrivateKey(method: SshAuthMethod): boolean {
  return method === "public-key" || method === "certificate";
}

function authLabel(method: SshAuthMethod): string {
  return authOptions.find((option) => option.value === method)?.label ?? method;
}

function credentialLabel(connection: ConnectionEditView): string {
  if (connection.authMethod === "password") return connection.hasPassword ? "密码已保存" : "缺少密码";
  if (usesPrivateKey(connection.authMethod)) return connection.hasKeyPassphrase ? "私钥口令已保存" : "私钥（无已保存口令）";
  if (connection.authMethod === "agent") return "本机 SSH Agent";
  return "连接时交互输入";
}

function messageFrom(reason: unknown, fallback: string): string {
  return errorText(reason, fallback);
}

function activeElement(): HTMLElement | null {
  return document.activeElement instanceof HTMLElement ? document.activeElement : null;
}
