import { useEffect, useReducer, useRef, useState, type MouseEvent } from "react";

import {
  isSftpDirectorySnapshot,
  isSftpOperationPlan,
  isSftpOperationReceipt,
  isSftpStagedUpload,
  isSftpTextPreview,
  isSftpTransferResult,
  type SftpOperationInput,
  type SftpOperationPlan,
  type SftpOperationReceipt,
  sftpBrowserEntryKinds,
  type SftpBrowserApi,
  type SftpBrowserEntry,
  type SftpDirectorySnapshot,
  type SftpTextPreview,
} from "../shared/sftp-browser-contract";
import type { LocalBrowserApi } from "../shared/local-browser-contract";
import { LocalFilePane } from "./LocalFilePane";
import { SftpContextMenu, type SftpMenuAction } from "./SftpContextMenu";
import { SftpOperationDialog, type SftpOperationDraft } from "./SftpOperationDialog";
import {
  ArchiveIcon,
  DownloadIcon,
  EntryKindIcon,
  HomeIcon,
  NewFolderIcon,
  RefreshIcon,
  TrashIcon,
  UpIcon,
  UploadIcon,
} from "./file-icons";
import {
  displaySftpBytes,
  displaySftpModifiedAt,
  filterSftpBrowserEntries,
  sftpBrowserActionLabel,
  sftpBrowserKindLabel,
  sftpBrowserScope,
  type SftpBrowserKindFilter,
} from "./sftp-browser-helpers";
import {
  createSftpBrowserState,
  sftpBrowserReducer,
  type SftpBrowserLoadStatus,
  type SftpDirectoryRequest,
  type SftpPreviewRequest,
} from "./sftp-browser-state";
import "./sftp-browser.css";

export interface SftpBrowserConnection {
  scopeKey: string;
}

export interface SftpBrowserPageProps {
  connection: SftpBrowserConnection | null;
  api: SftpBrowserApi & LocalBrowserApi;
  active?: boolean;
}

interface PendingDirectory {
  scope: string;
  request: SftpDirectoryRequest;
}

interface PendingPreview {
  scope: string;
  request: SftpPreviewRequest;
}

export function SftpBrowserPage({
  connection,
  api,
  active = true,
}: SftpBrowserPageProps) {
  const [state, dispatch] = useReducer(sftpBrowserReducer, undefined, createSftpBrowserState);
  const [reopenVersion, setReopenVersion] = useState(0);
  const [pendingDirectory, setPendingDirectory] = useState<PendingDirectory | null>(null);
  const [pendingPreview, setPendingPreview] = useState<PendingPreview | null>(null);
  const [transferNotice, setTransferNotice] = useState<string | null>(null);
  const transferInFlight = useRef(false);
  const [menu, setMenu] = useState<
    { position: { x: number; y: number }; entry: SftpBrowserEntry | null } | null
  >(null);
  const [draft, setDraft] = useState<SftpOperationDraft | null>(null);
  const [plan, setPlan] = useState<SftpOperationPlan | null>(null);
  const [receipt, setReceipt] = useState<SftpOperationReceipt | null>(null);
  const [operationError, setOperationError] = useState<string | null>(null);
  const [operationBusy, setOperationBusy] = useState(false);
  const operationInFlight = useRef(false);
  const requestRef = useRef(0);
  const scope = connection === null ? null : sftpBrowserScope(connection);
  const enabled = active && connection !== null;
  const visibleState = state.scope === scope ? state : createSftpBrowserState(scope);

  useEffect(() => {
    dispatch({ type: "scope-changed", scope });
  }, [scope]);

  useEffect(() => {
    if (enabled) return;
    setPendingDirectory(null);
    setPendingPreview(null);
    dispatch({ type: "deactivated", scope });
  }, [enabled, scope]);

  useEffect(() => {
    if (!enabled || scope === null || state.scope !== scope) return;
    const request: SftpDirectoryRequest = {
      id: ++requestRef.current,
      mode: "open",
      browserHandle: null,
      directoryHandle: null,
    };
    let cancelled = false;
    dispatch({ type: "directory-started", scope, request });
    void api.openSftpBrowser().then((value) => {
      if (cancelled) return;
      if (!isSftpDirectorySnapshot(value) || value.parentDirectoryHandle !== null) throw new Error();
      dispatch({ type: "directory-loaded", scope, request, directory: value });
    }).catch(() => {
      if (!cancelled) dispatch({
        type: "directory-failed",
        scope,
        request,
        error: "无法从服务器根目录打开只读 SFTP 浏览器；绑定、权限或固定入口可能不可用。",
      });
    });
    return () => {
      cancelled = true;
    };
  }, [api, enabled, reopenVersion, scope, state.scope]);

  useEffect(() => {
    if (!enabled || scope === null || pendingDirectory?.scope !== scope ||
      pendingDirectory.request.mode !== "list") return;
    const request = pendingDirectory.request;
    let cancelled = false;
    dispatch({ type: "directory-started", scope, request });
    void api.listSftpDirectory(
      request.browserHandle!,
      request.directoryHandle!,
    ).then((value) => {
      if (cancelled) return;
      if (!isSftpDirectorySnapshot(value) || value.browserHandle !== request.browserHandle ||
        value.directoryHandle !== request.directoryHandle) throw new Error();
      dispatch({ type: "directory-loaded", scope, request, directory: value });
    }).catch(() => {
      if (!cancelled) dispatch({
        type: "directory-failed",
        scope,
        request,
        error: "目录读取失败；能力可能过期、目标已切换、权限不足或条目已变化。",
      });
    });
    return () => {
      cancelled = true;
    };
  }, [api, enabled, pendingDirectory, scope]);

  useEffect(() => {
    if (!enabled || scope === null || pendingPreview?.scope !== scope) return;
    const request = pendingPreview.request;
    let cancelled = false;
    dispatch({ type: "preview-started", scope, request });
    void api.readSftpText(request.browserHandle, request.fileHandle).then((value) => {
      if (cancelled) return;
      if (!isSftpTextPreview(value) || value.browserHandle !== request.browserHandle ||
        value.fileHandle !== request.fileHandle) throw new Error();
      dispatch({ type: "preview-loaded", scope, request, preview: value });
    }).catch(() => {
      if (!cancelled) dispatch({
        type: "preview-failed",
        scope,
        request,
        error: "文本预览失败：文件可能不是 UTF-8 文本，或会话已过期。",
      });
    });
    return () => {
      cancelled = true;
    };
  }, [api, enabled, pendingPreview, scope]);

  if (connection === null) {
    return (
      <main className="sftp-browser-page sftp-browser-disconnected">
        <h1>SFTP 只读浏览器</h1>
        <p>连接 SSH 目标后，可浏览服务器目录并预览 UTF-8 文本文件。</p>
      </main>
    );
  }

  if (!active) {
    return (
      <main className="sftp-browser-page sftp-browser-disconnected">
        <h1>SFTP 浏览器已停用</h1>
        <p>页面失活会清空目录与预览状态，并拒绝仍在途的旧目标结果。</p>
      </main>
    );
  }

  const connectedScope = scope ?? "";
  const directory = visibleState.directory;
  const entries = filterSftpBrowserEntries(directory?.entries ?? [], visibleState.kind, visibleState.search);
  const selected = directory?.entries.find((entry) =>
    entry.entryHandle === visibleState.selectedEntryHandle) ?? null;
  const busy = visibleState.directoryStatus === "loading" || visibleState.previewStatus === "loading";

  function requestDirectory(directoryHandle: string) {
    if (directory === null || busy) return;
    setPendingPreview(null);
    setPendingDirectory({
      scope: connectedScope,
      request: {
        id: ++requestRef.current,
        mode: "list",
        browserHandle: directory.browserHandle,
        directoryHandle,
      },
    });
  }

  function requestPreview() {
    if (directory === null || selected?.action !== "preview" || busy) return;
    setPendingPreview({
      scope: connectedScope,
      request: {
        id: ++requestRef.current,
        browserHandle: directory.browserHandle,
        fileHandle: selected.entryHandle,
      },
    });
  }

  function selectEntry(entryHandle: string) {
    setPendingPreview(null);
    dispatch({ type: "entry-selected", entryHandle });
  }

  async function downloadSelected(): Promise<void> {
    // A second click while the dialog is open would open a second dialog.
    if (transferInFlight.current) return;
    const browserHandle = visibleState.directory?.browserHandle ?? null;
    const fileHandle = visibleState.selectedEntryHandle;
    if (browserHandle === null || fileHandle === null) return;
    transferInFlight.current = true;
    setTransferNotice(null);
    try {
      const value = await api.downloadSftpEntry(browserHandle, fileHandle);
      if (!isSftpTransferResult(value)) throw new Error();
      setTransferNotice(value.saved
        ? `已保存为 ${value.fileName}（${displaySftpBytes(value.bytes ?? "0")}）。`
        : "已取消保存。");
    } catch {
      setTransferNotice("下载失败；文件可能已变化，或所选位置不可写。");
    } finally {
      transferInFlight.current = false;
    }
  }

  function openMenu(event: MouseEvent, entry: SftpBrowserEntry | null): void {
    event.preventDefault();
    if (entry !== null) selectEntry(entry.entryHandle);
    setMenu({ position: { x: event.clientX, y: event.clientY }, entry });
  }

  function startOperation(action: SftpMenuAction, entry: SftpBrowserEntry | null): void {
    setMenu(null);
    setPlan(null);
    setReceipt(null);
    setOperationError(null);
    if (action === "open" && entry !== null) return requestDirectory(entry.entryHandle);
    if (action === "preview") return requestPreview();
    if (action === "download") return void downloadSelected();
    if (action === "open") return;
    const subject = entry === null ? (directory?.directoryLabel ?? "当前目录") : entry.name;
    const rename = action === "rename" ? entry?.name : undefined;
    setDraft(rename === undefined
      ? { kind: action, subject }
      : { kind: action, subject, name: rename });
  }

  async function buildPlan(next: SftpOperationDraft): Promise<void> {
    if (operationInFlight.current) return;
    const browserHandle = visibleState.directory?.browserHandle ?? null;
    const directoryHandle = visibleState.directory?.directoryHandle ?? null;
    const entryHandle = visibleState.selectedEntryHandle;
    if (browserHandle === null || directoryHandle === null) return;
    const handles = next.kind === "create-directory" || next.kind === "upload"
      ? [directoryHandle]
      : entryHandle === null ? [] : [entryHandle];
    if (handles.length === 0) {
      setOperationError("请先选择一个条目。");
      return;
    }
    operationInFlight.current = true;
    setOperationBusy(true);
    setOperationError(null);
    try {
      let stagedHandle: string | null = null;
      if (next.kind === "upload") {
        const staged = next.localFileHandle === undefined
          ? await api.stageSftpUpload()
          : await api.stageSftpUpload(next.localFileHandle);
        const upload = stagedUpload(staged);
        if (upload === null) {
          setDraft(null);
          return;
        }
        stagedHandle = upload.stagedHandle;
        if (next.name === undefined || next.name.length === 0) {
          next = { ...next, name: upload.name };
        }
      }
      const input: SftpOperationInput = { kind: next.kind, entryHandles: handles };
      if (next.name !== undefined && next.name.length > 0) input.name = next.name;
      if (next.mode !== undefined && next.mode.length > 0) {
        input.mode = Number.parseInt(next.mode, 8);
      }
      if (next.format !== undefined) input.format = next.format;
      if (stagedHandle !== null) input.stagedHandle = stagedHandle;
      const value = await api.planSftpOperation(browserHandle, input);
      if (!isSftpOperationPlan(value)) throw new Error();
      setDraft(next);
      setPlan(value);
    } catch {
      setOperationError("无法生成计划；条目可能已变化，或参数不被接受。");
    } finally {
      operationInFlight.current = false;
      setOperationBusy(false);
    }
  }

  async function runPlan(): Promise<void> {
    if (operationInFlight.current || plan === null) return;
    operationInFlight.current = true;
    setOperationBusy(true);
    setOperationError(null);
    try {
      const confirmed = await api.confirmSftpOperation(plan.planHandle);
      if (!isSftpOperationPlan(confirmed)) throw new Error();
      const value = await api.executeSftpOperation(plan.planHandle);
      if (!isSftpOperationReceipt(value)) throw new Error();
      setReceipt(value);
      if (value.passed && directory !== null) requestDirectory(directory.directoryHandle);
    } catch {
      setOperationError("执行失败；目标可能已变化，或计划已过期。");
    } finally {
      operationInFlight.current = false;
      setOperationBusy(false);
    }
  }

  function closeOperation(): void {
    if (plan !== null && receipt === null) void api.cancelSftpOperation(plan.planHandle);
    setDraft(null);
    setPlan(null);
    setReceipt(null);
    setOperationError(null);
  }

  function updateFilter(kind: SftpBrowserKindFilter) {
    setPendingPreview(null);
    dispatch({ type: "kind-selected", kind });
  }

  return (
    <main className="sftp-browser-page">
      <header className="sftp-browser-header">
        <h1>文件管理 (SFTP)</h1>
        <span className="sftp-browser-mode">只读</span>
      </header>
      <div className="sftp-browser-actions" role="toolbar" aria-label="文件操作">
        <button type="button" className="sftp-browser-action" disabled={busy || directory === null}
          onClick={() => directory !== null && requestDirectory(directory.directoryHandle)}>
          <RefreshIcon />{visibleState.directoryStatus === "loading" ? "读取中" : "刷新"}
        </button>
        <button type="button" className="sftp-browser-action is-upload"
          disabled={busy || directory === null}
          onClick={() => {
            setPlan(null);
            setReceipt(null);
            setOperationError(null);
            setDraft({ kind: "upload", subject: directory?.directoryLabel ?? "当前目录" });
          }}>
          <UploadIcon />上传
        </button>
        <button type="button" className="sftp-browser-action is-download"
          disabled={busy || selected?.kind !== "file"}
          onClick={() => void downloadSelected()}>
          <DownloadIcon />下载
        </button>
        <button type="button" className="sftp-browser-action is-danger"
          disabled={busy || selected === null}
          onClick={() => startOperation("remove", selected)}>
          <TrashIcon />删除
        </button>
        <button type="button" className="sftp-browser-action" disabled={busy || directory === null}
          onClick={() => startOperation("create-directory", null)}>
          <NewFolderIcon />新建文件夹
        </button>
        <button type="button" className="sftp-browser-action" disabled={busy || selected === null}
          onClick={() => startOperation("archive", selected)}>
          <ArchiveIcon />打包
        </button>
      </div>

      {visibleState.directoryStatus === "loading" && directory === null ? (
        <SftpBrowserStatus label="正在绑定 SFTP 会话并读取固定根目录…" />
      ) : visibleState.directoryStatus === "error" && directory === null ? (
        <SftpBrowserError message={visibleState.directoryError ?? "SFTP 浏览器不可用。"} />
      ) : directory === null ? (
        <SftpBrowserEmpty title="尚未打开浏览器" detail="重新打开固定根目录后重试。" />
      ) : (
        <>
          {visibleState.directoryStatus === "error" && <SftpBrowserError
            message={visibleState.directoryError ?? "目录读取失败。"} compact />}
          <div className="sftp-browser-panes">
            <LocalFilePane
              api={api}
              active={enabled}
              onUpload={(entryHandle, name) => {
                setMenu(null);
                setPlan(null);
                setReceipt(null);
                setOperationError(null);
                setDraft({
                  kind: "upload",
                  subject: directory?.directoryLabel ?? "当前目录",
                  name,
                  localFileHandle: entryHandle,
                });
              }}
            />

            <section className="sftp-browser-pane" aria-label="远程文件">
              <header className="sftp-browser-pane-head">
                <strong>远程文件</strong>
                <label className="sftp-browser-filter">
                  <span className="terminal-sr-only">筛选名称</span>
                  <input value={visibleState.search} maxLength={256} placeholder="筛选名称"
                    onChange={(event) => {
                      setPendingPreview(null);
                      dispatch({ type: "search-changed", value: event.currentTarget.value });
                    }} />
                </label>
                <select aria-label="类型" value={visibleState.kind}
                  onChange={(event) => updateFilter(event.currentTarget.value as SftpBrowserKindFilter)}>
                  <option value="all">全部</option>
                  {sftpBrowserEntryKinds.map((kind) => <option key={kind} value={kind}>
                    {sftpBrowserKindLabel(kind)}
                  </option>)}
                </select>
              </header>
              <div className="sftp-browser-pathbar">
                <button type="button" title="上一级" aria-label="上一级"
                  disabled={busy || directory.parentDirectoryHandle === null}
                  onClick={() => directory.parentDirectoryHandle !== null &&
                    requestDirectory(directory.parentDirectoryHandle)}>
                  <UpIcon />
                </button>
                <button type="button" title="回到根目录" aria-label="回到根目录" disabled={busy ||
                  visibleState.rootDirectoryHandle === null ||
                  directory.directoryHandle === visibleState.rootDirectoryHandle}
                  onClick={() => visibleState.rootDirectoryHandle !== null &&
                    requestDirectory(visibleState.rootDirectoryHandle)}>
                  <HomeIcon />
                </button>
                <span className="sftp-browser-path-value">{directory.directoryLabel}</span>
              </div>
              <div className="sftp-browser-pane-body">
                <SftpBrowserTable entries={entries} selectedHandle={visibleState.selectedEntryHandle}
                  search={visibleState.search} busy={busy} onSelect={selectEntry}
                  onBrowse={(entryHandle) => requestDirectory(entryHandle)}
                  onContextMenu={openMenu} />
              </div>
              <footer className="sftp-browser-pane-foot">
                <span>
                  {directory.displayedEntryCount} 个项目（
                  {entries.filter((item) => item.kind === "directory").length} 个文件夹，
                  {entries.filter((item) => item.kind !== "directory").length} 个文件）
                </span>
                <span>能力约 {Math.max(1, Math.ceil(directory.expiresInSeconds / 60))} 分钟内有效</span>
              </footer>
            </section>
          </div>
          {directory.truncated && <p className="sftp-browser-warning" role="status">
            目录共有 {directory.observedEntryCount} 项，当前只显示前 {directory.displayedEntryCount} 项。
          </p>}

          <SftpBrowserDetail
            transferNotice={transferNotice}
            selected={selected}
            previewStatus={visibleState.previewStatus}
            preview={visibleState.preview}
            previewError={visibleState.previewError}
          />

          {menu === null ? null : (
            <SftpContextMenu
              position={menu.position}
              entry={menu.entry}
              busy={busy}
              onAction={(action) => startOperation(action, menu.entry)}
              onDismiss={() => setMenu(null)}
            />
          )}
          {draft === null ? null : (
            <SftpOperationDialog
              draft={draft}
              plan={plan}
              receipt={receipt}
              busy={operationBusy}
              error={operationError}
              onPlan={(next) => void buildPlan(next)}
              onConfirm={() => void runPlan()}
              onClose={closeOperation}
            />
          )}
        </>
      )}
    </main>
  );
}

/** Main answers either a staged file or a dismissed dialog. */
function stagedUpload(value: unknown): { stagedHandle: string; name: string } | null {
  if (typeof value !== "object" || value === null) return null;
  const reply = value as { staged?: unknown; upload?: unknown };
  if (reply.staged !== true || !isSftpStagedUpload(reply.upload)) return null;
  return { stagedHandle: reply.upload.stagedHandle, name: reply.upload.name };
}

const PENDING_WRITE = "写操作尚未接入：核心已有计划-确认-执行模型，Electron 边界还没开放。";

/** One row per entry: name, size, modified — the columns the design asks for. */
export function SftpBrowserTable({
  entries,
  selectedHandle,
  search,
  busy,
  onSelect,
  onBrowse,
  onContextMenu,
}: {
  entries: SftpBrowserEntry[];
  selectedHandle: string | null;
  search: string;
  busy: boolean;
  onSelect: (entryHandle: string) => void;
  onBrowse: (entryHandle: string) => void;
  onContextMenu?: (event: MouseEvent, entry: SftpBrowserEntry | null) => void;
}) {
  return (
    <div className="sftp-browser-rows" role="list"
      onContextMenu={(event) => onContextMenu?.(event, null)}>
      <div className="sftp-browser-table-head" aria-hidden="true">
        <span>名称</span><span>大小</span><span>修改时间</span>
      </div>
      {entries.length === 0 ? (
        <SftpBrowserEmpty
          title={search.trim() === "" ? "目录为空" : "没有匹配条目"}
          detail={search.trim() === "" ? "当前目录没有条目。" : "调整筛选条件。"}
          compact
        />
      ) : entries.map((entry) => (
        <button
          type="button"
          role="listitem"
          key={entry.entryHandle}
          className={entry.entryHandle === selectedHandle
            ? "sftp-browser-row is-selected"
            : "sftp-browser-row"}
          disabled={busy}
          aria-pressed={entry.entryHandle === selectedHandle}
          onClick={() => onSelect(entry.entryHandle)}
          onDoubleClick={() => entry.action === "browse" && onBrowse(entry.entryHandle)}
          onContextMenu={(event) => {
            event.stopPropagation();
            onContextMenu?.(event, entry);
          }}
        >
          <span className="sftp-browser-row-name">
            <span className={`sftp-browser-row-kind is-${entry.kind}`}>
              <EntryKindIcon kind={entry.kind} />
            </span>
            <span className="sftp-browser-row-label">{entry.name}</span>
            {entry.nameTruncated ? <em>名称已截断</em> : null}
          </span>
          <span className="sftp-browser-row-size">
            {entry.kind === "directory" ? "—" : displaySftpBytes(entry.sizeBytes)}
          </span>
          <span className="sftp-browser-row-time">{displaySftpModifiedAt(entry.modifiedAt)}</span>
        </button>
      ))}
    </div>
  );
}

/**
 * The preview surface. The row already shows name, size and time, and the
 * context menu owns the actions, so this only appears when it has something
 * the table cannot show: file text, a transfer result, or a read failure.
 */
export function SftpBrowserDetail({
  selected,
  previewStatus,
  preview,
  previewError,
  transferNotice = null,
}: {
  selected: SftpBrowserEntry | null;
  previewStatus: SftpBrowserLoadStatus;
  preview: SftpTextPreview | null;
  previewError: string | null;
  transferNotice?: string | null;
}) {
  const previewing = selected?.action === "preview" &&
    (previewStatus === "loading" || previewStatus === "error" || preview !== null);
  if (transferNotice === null && !previewing) return null;
  return (
    <section className="sftp-browser-detail" aria-label="预览">
      {transferNotice === null ? null : (
        <p className="sftp-browser-transfer" role="status">{transferNotice}</p>
      )}
      {previewing ? (
        <>
          <p className="sftp-browser-preview-name">{selected?.name}</p>
          {previewStatus === "loading" ? <SftpBrowserStatus label="正在读取文本…" compact />
            : previewStatus === "error"
              ? <SftpBrowserError message={previewError ?? "文本预览不可用。"} compact />
              : preview === null ? null : <SftpTextPreviewView preview={preview} />}
        </>
      ) : null}
    </section>
  );
}

export function SftpTextPreviewView({ preview }: { preview: SftpTextPreview }) {
  return (
    <div className="sftp-browser-preview">
      <header>
        <strong>UTF-8 纯文本预览</strong>
        <span>{preview.displayedLineCount}/{preview.observedLineCount} 行</span>
      </header>
      {preview.truncated && <p className="sftp-browser-warning" role="status">
        文本已按行数或大小上限截断。
      </p>}
      {preview.text.length === 0 ? <SftpBrowserEmpty title="文件没有可显示文本"
        detail="常规 UTF-8 文件为空，或仅包含一个空行。" compact /> :
        <pre className="sftp-browser-preview-text">{preview.text}</pre>}
    </div>
  );
}

export function SftpBrowserStatus({ label, compact = false }: { label: string; compact?: boolean }) {
  return <div className={compact ? "sftp-browser-status is-compact" : "sftp-browser-status"}
    aria-live="polite"><span aria-hidden="true" />{label}</div>;
}

export function SftpBrowserError({ message, compact = false }: { message: string; compact?: boolean }) {
  return <div className={compact ? "sftp-browser-error is-compact" : "sftp-browser-error"}
    role="alert"><strong>读取失败</strong><p>{message}</p></div>;
}

export function SftpBrowserEmpty({ title, detail, compact = false }: {
  title: string;
  detail: string;
  compact?: boolean;
}) {
  return <div className={compact ? "sftp-browser-empty is-compact" : "sftp-browser-empty"}>
    <strong>{title}</strong><p>{detail}</p>
  </div>;
}
