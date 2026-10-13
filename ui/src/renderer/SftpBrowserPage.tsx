import { useEffect, useReducer, useRef, useState, type MouseEvent } from "react";

import { errorText } from "./error-text";
import { targetFailureMessage } from "./target-lost";
import { useListExpiry } from "./use-list-expiry";

import {
  isSftpDirectorySnapshot,
  isSftpOperationPlan,
  isSftpOperationReceipt,
  isSftpOperationUndoResult,
  isSftpStagedUpload,
  isSftpTextPreview,
  isSftpTransferResult,
  isSftpTransferCancelResult,
  type SftpOperationInput,
  type SftpOperationPlan,
  type SftpOperationReceipt,
  type SftpOperationUndoResult,
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
import { SftpPropertiesDialog } from "./SftpPropertiesDialog";
import {
  ArchiveIcon,
  DownloadIcon,
  EntryKindIcon,
  HomeIcon,
  NewFolderIcon,
  RefreshIcon,
  TerminalHereIcon,
  TrashIcon,
  UpIcon,
  UploadIcon,
} from "./file-icons";
import {
  compactSftpBytes,
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
  // The download running now, shown with a way to stop it.
  const [downloading, setDownloading] = useState<{ browserHandle: string; name: string; cancelling: boolean } | null>(null);
  const [cancellingUpload, setCancellingUpload] = useState(false);
  const transferInFlight = useRef(false);
  // Opening a window is remote work too: a double click would ask twice.
  const fileWindowInFlight = useRef(false);
  const [menu, setMenu] = useState<
    { position: { x: number; y: number }; entry: SftpBrowserEntry | null } | null
  >(null);
  const [draft, setDraft] = useState<SftpOperationDraft | null>(null);
  const [plan, setPlan] = useState<SftpOperationPlan | null>(null);
  const [receipt, setReceipt] = useState<SftpOperationReceipt | null>(null);
  const [undoResult, setUndoResult] = useState<SftpOperationUndoResult | null>(null);
  const [undoSpent, setUndoSpent] = useState(false);
  const [operationError, setOperationError] = useState<string | null>(null);
  // Opening an editor or a terminal window happens outside any dialog, so its
  // failure needs a place of its own in the pane.
  const [windowError, setWindowError] = useState<string | null>(null);
  const [operationBusy, setOperationBusy] = useState(false);
  const [properties, setProperties] = useState<SftpBrowserEntry | null>(null);
  const operationInFlight = useRef(false);
  const requestRef = useRef(0);
  // The backend said this browser is gone (expired or closed): listing again
  // cannot help, only opening a new one can.
  const [browserGone, setBrowserGone] = useState(false);
  const scope = connection === null ? null : sftpBrowserScope(connection);
  const enabled = active && connection !== null;
  const visibleState = state.scope === scope ? state : createSftpBrowserState(scope);
  // Every listing renews the browser on the backend, and each listing is a new
  // snapshot, so the deadline is counted from the one on screen.
  const listExpiry = useListExpiry(visibleState.directory, visibleState.directory?.expiresInSeconds ?? null);

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
      setBrowserGone(false);
      dispatch({ type: "directory-loaded", scope, request, directory: value });
    }).catch((reason: unknown) => {
      if (!cancelled) dispatch({
        type: "directory-failed",
        scope,
        request,
        error: sftpOpenFailureMessage(reason),
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
    }).catch((reason: unknown) => {
      if (cancelled) return;
      const gone = sftpBrowserGone(reason);
      if (gone) setBrowserGone(true);
      dispatch({
        type: "directory-failed",
        scope,
        request,
        error: gone
          ? "目录列表已过期（超过 5 分钟没有读取目录），点“重新打开”从起始目录重新读取。"
          : targetFailureMessage(reason, "目录读取失败；目录入口可能已过期、目标已切换、权限不足或条目已变化。"),
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
    }).catch((reason: unknown) => {
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
        <h1>文件管理 (SFTP)</h1>
        <p>连接 SSH 目标后，可浏览服务器目录、预览 UTF-8 文本，并在确认计划后传输和管理文件。</p>
      </main>
    );
  }

  if (!active) {
    return (
      <main className="sftp-browser-page sftp-browser-disconnected">
        <h1>文件管理已暂停</h1>
        <p>离开这里时会清空目录和预览；回来后重新读取，不会显示之前目标的旧结果。</p>
      </main>
    );
  }

  const connectedScope = scope ?? "";
  const directory = visibleState.directory;
  const entries = filterSftpBrowserEntries(directory?.entries ?? [], visibleState.kind, visibleState.search);
  const selected = directory?.entries.find((entry) =>
    entry.entryHandle === visibleState.selectedEntryHandle) ?? null;
  const busy = visibleState.directoryStatus === "loading" || visibleState.previewStatus === "loading";
  // Past its deadline, everything bound to this listing would be refused; say
  // so before a click is sent, and offer the one thing that helps.
  const listStale = directory !== null && (listExpiry.expired || browserGone);
  const staleTitle = listStale ? "目录列表已过期，先点“重新打开”" : undefined;

  /** A new browser from the start directory: the expired one cannot be renewed. */
  function reopenBrowser() {
    if (busy || downloading !== null) return;
    setPendingDirectory(null);
    setPendingPreview(null);
    setWindowError(null);
    setBrowserGone(false);
    setReopenVersion((version) => version + 1);
  }

  function requestDirectory(directoryHandle: string) {
    if (directory === null || busy) return;
    if (listStale) return reopenBrowser();
    setPendingPreview(null);
    setWindowError(null);
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

  /**
   * Opens one file in a window of its own.
   *
   * The pane hands over the two opaque handles it already holds and nothing
   * else; the window asks main what it was opened for, and main answers with
   * what it recorded. `editable` is settled here and cannot be changed from
   * inside the window.
   */
  async function openFileWindow(entry: SftpBrowserEntry | null, editable: boolean) {
    const file = entry ?? selected;
    if (directory === null || file === null || file.action !== "preview") return;
    if (listStale) return void setWindowError("目录列表已过期，先点“重新打开”。");
    if (fileWindowInFlight.current) return;
    fileWindowInFlight.current = true;
    setWindowError(null);
    try {
      await api.openFileEditor(directory.browserHandle, file.entryHandle, file.name, editable);
    } catch (reason) {
      setWindowError(errorText(reason, "打不开这个文件的窗口，连接可能已经断了。"));
    } finally {
      fileWindowInFlight.current = false;
    }
  }

  /**
   * Opens a new terminal window that starts in a folder: the one asked about,
   * or the one on screen. The window opens the shell itself, at its own size,
   * and says there if the folder can no longer be entered.
   */
  async function openFolderTerminal(entry: SftpBrowserEntry | null) {
    if (directory === null || (entry !== null && entry.kind !== "directory")) return;
    if (fileWindowInFlight.current) return;
    fileWindowInFlight.current = true;
    setWindowError(null);
    try {
      await api.openDirectoryTerminal(
        directory.browserHandle,
        entry?.entryHandle ?? directory.directoryHandle,
        entry?.name ?? directory.directoryLabel,
      );
    } catch (reason) {
      setWindowError(errorText(reason, "打不开新的终端窗口，连接可能已经断了。"));
    } finally {
      fileWindowInFlight.current = false;
    }
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
    setDownloading({ browserHandle, name: selected?.name ?? "所选文件", cancelling: false });
    try {
      const value = await api.downloadSftpEntry(browserHandle, fileHandle);
      if (!isSftpTransferResult(value)) throw new Error();
      setTransferNotice(value.saved
        ? `已保存为 ${value.fileName}（${displaySftpBytes(value.bytes ?? "0")}）。`
        : "已取消保存。");
    } catch (reason) {
      setTransferNotice(transferStopped(reason)
        ? "已取消下载，写到一半的文件已经删除。"
        : "下载失败；文件可能已变化，或所选位置不可写。");
    } finally {
      transferInFlight.current = false;
      setDownloading(null);
    }
  }

  /**
   * Stops this browser's running upload or download. The transfer removes
   * what it wrote and then answers its own request, which reports the result;
   * when nothing was running yet the button simply comes back.
   */
  async function cancelTransfer(browserHandle: string, onSettled: (reached: boolean) => void): Promise<void> {
    try {
      const value = await api.cancelSftpTransfer(browserHandle);
      onSettled(isSftpTransferCancelResult(value) && value.cancelled > 0);
    } catch {
      onSettled(false);
    }
  }

  function openMenu(event: MouseEvent, entry: SftpBrowserEntry | null): void {
    event.preventDefault();
    if (entry !== null) selectEntry(entry.entryHandle);
    setMenu({ position: { x: event.clientX, y: event.clientY }, entry });
  }

  function startOperation(action: SftpMenuAction, entry: SftpBrowserEntry | null): void {
    setMenu(null);
    // The context menu reaches here as well as the toolbar.
    if (listStale) return void setWindowError("目录列表已过期，先点“重新打开”。");
    // A new window beside this one: a plan or a receipt on screen stays.
    if (action === "terminal") return void openFolderTerminal(entry);
    setPlan(null);
    clearReceipt();
    setOperationError(null);
    if (action === "open" && entry !== null) return requestDirectory(entry.entryHandle);
    // Both open the same window; only the permission to write differs, and
    // that is settled by main when it creates the window.
    if (action === "preview" || action === "edit") {
      return void openFileWindow(entry, action === "edit");
    }
    if (action === "download") return void downloadSelected();
    if (action === "properties") {
      if (entry !== null) setProperties(entry);
      return;
    }
    if (action === "open") return;
    const subject = entry === null ? (directory?.directoryLabel ?? "当前目录") : entry.name;
    const next: SftpOperationDraft = { kind: action, subject };
    if (action === "rename" && entry !== null) next.name = entry.name;
    // Adjust the mode the server reported rather than typing one from memory.
    if (action === "chmod" && entry !== null && entry.mode !== null) next.mode = entry.mode;
    setProperties(null);
    setDraft(next);
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
      setCancellingUpload(false);
    }
  }

  /**
   * Puts the operation on the receipt back, once. The core reads the target
   * again first and refuses when it changed after the operation, so a later
   * change is never overwritten; whatever comes back, it is not offered again.
   */
  async function undoOperation(): Promise<void> {
    if (operationInFlight.current || receipt === null || !receipt.undoable || undoSpent) return;
    const { planHandle } = receipt;
    operationInFlight.current = true;
    setUndoSpent(true);
    setOperationBusy(true);
    setOperationError(null);
    try {
      const value = await api.undoSftpOperation(planHandle);
      if (!isSftpOperationUndoResult(value) || value.planHandle !== planHandle) {
        throw new Error("无法核对撤销的结果，请刷新查看现在的状态，勿重复操作。");
      }
      setUndoResult(value);
      if (directory !== null) requestDirectory(directory.directoryHandle);
    } catch (error) {
      setOperationError(sftpUndoFailure(error));
    } finally {
      operationInFlight.current = false;
      setOperationBusy(false);
    }
  }

  function clearReceipt(): void {
    setReceipt(null);
    setUndoResult(null);
    setUndoSpent(false);
  }

  function closeOperation(): void {
    if (plan !== null && receipt === null) void api.cancelSftpOperation(plan.planHandle);
    setDraft(null);
    setPlan(null);
    clearReceipt();
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
      </header>
      <div className="sftp-browser-actions" role="toolbar" aria-label="文件操作">
        {listStale ? (
          <button type="button" className="sftp-browser-action is-attention" data-testid="sftp-reopen"
            disabled={busy || downloading !== null}
            title={downloading !== null ? "等下载结束或取消后再重新打开" : "目录列表已过期，从起始目录重新读取"}
            onClick={reopenBrowser}>
            <RefreshIcon />重新打开
          </button>
        ) : (
          <button type="button" className="sftp-browser-action" disabled={busy || directory === null}
            onClick={() => directory !== null && requestDirectory(directory.directoryHandle)}>
            <RefreshIcon />{visibleState.directoryStatus === "loading" ? "读取中" : "刷新"}
          </button>
        )}
        <button type="button" className="sftp-browser-action is-upload"
          disabled={busy || directory === null || listStale} title={staleTitle}
          onClick={() => {
            setPlan(null);
            clearReceipt();
            setOperationError(null);
            setDraft({ kind: "upload", subject: directory?.directoryLabel ?? "当前目录" });
          }}>
          <UploadIcon />上传
        </button>
        <button type="button" className="sftp-browser-action is-download"
          disabled={busy || selected?.kind !== "file" || listStale} title={staleTitle}
          onClick={() => void downloadSelected()}>
          <DownloadIcon />下载
        </button>
        <button type="button" className="sftp-browser-action is-danger"
          disabled={busy || selected === null || listStale} title={staleTitle}
          onClick={() => startOperation("remove", selected)}>
          <TrashIcon />删除
        </button>
        <button type="button" className="sftp-browser-action" disabled={busy || directory === null || listStale}
          title={staleTitle}
          onClick={() => startOperation("create-directory", null)}>
          <NewFolderIcon />新建文件夹
        </button>
        <button type="button" className="sftp-browser-action" disabled={busy || selected === null || listStale}
          title={staleTitle}
          onClick={() => startOperation("archive", selected)}>
          <ArchiveIcon />打包
        </button>
        <button type="button" className="sftp-browser-action" disabled={directory === null || listStale}
          data-testid="sftp-terminal-here" title={staleTitle ?? "在当前文件夹打开一个新的终端窗口"}
          onClick={() => startOperation("terminal", null)}>
          <TerminalHereIcon />在这里打开终端
        </button>
      </div>

      {visibleState.directoryStatus === "loading" && directory === null ? (
        <SftpBrowserStatus label="正在打开文件管理并读取根目录…" />
      ) : visibleState.directoryStatus === "error" && directory === null ? (
        <SftpBrowserError message={visibleState.directoryError ?? "文件管理不可用，请关闭后重新打开再试。"} />
      ) : directory === null ? (
        <SftpBrowserEmpty title="文件管理还没有打开" detail="关闭后重新打开文件管理再试。" />
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
                clearReceipt();
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
                {listStale ? (
                  <span className="sftp-browser-expired" role="status" data-testid="sftp-list-expired">
                    目录列表已过期，点“重新打开”从起始目录重新读取
                  </span>
                ) : (
                  <span title="每次读取目录都会重新计时；超过这个时间再操作会被拒绝，刷新目录即可继续。">
                    目录列表约 {listExpiry.minutesLeft ?? Math.max(1, Math.ceil(directory.expiresInSeconds / 60))} 分钟内有效
                  </span>
                )}
              </footer>
            </section>
          </div>
          {directory.truncated && <p className="sftp-browser-warning" role="status">
            目录共有 {directory.observedEntryCount} 项，当前只显示前 {directory.displayedEntryCount} 项。
          </p>}

          {/* Only the transfer result stays inline. The panel that used to sit
              here held a text preview as well, and it cost a permanent third
              of the pane to show a few wrapped lines of a file — the file now
              opens in a window of its own, where it can be read and edited at
              a usable size. */}
          {downloading === null ? null : (
            <p className="sftp-browser-transfer is-running" role="status">
              <span>正在下载 {downloading.name}…</span>
              <button type="button" disabled={downloading.cancelling} data-testid="sftp-cancel-download"
                onClick={() => {
                  const current = downloading;
                  setDownloading({ ...current, cancelling: true });
                  void cancelTransfer(current.browserHandle, (reached) => {
                    if (!reached) setDownloading((now) => now === null ? null : { ...now, cancelling: false });
                  });
                }}>
                {downloading.cancelling ? "正在取消…" : "取消下载"}
              </button>
            </p>
          )}
          {transferNotice === null || downloading !== null ? null : (
            <p className="sftp-browser-transfer" role="status">{transferNotice}</p>
          )}
          {windowError === null ? null : (
            <p className="sftp-browser-transfer is-error" role="alert" data-testid="sftp-window-error">{windowError}</p>
          )}

          {menu === null ? null : (
            <SftpContextMenu
              position={menu.position}
              entry={menu.entry}
              busy={busy}
              onAction={(action) => startOperation(action, menu.entry)}
              onDismiss={() => setMenu(null)}
            />
          )}
          {properties === null ? null : (
        <SftpPropertiesDialog
          entry={properties}
          onChmod={() => startOperation("chmod", properties)}
          onClose={() => setProperties(null)}
        />
      )}
      {draft === null ? null : (
            <SftpOperationDialog
              draft={draft}
              plan={plan}
              receipt={receipt}
              undo={undoResult}
              undoSpent={undoSpent}
              busy={operationBusy}
              error={operationError}
              onPlan={(next) => void buildPlan(next)}
              onConfirm={() => void runPlan()}
              onUndo={() => void undoOperation()}
              cancellingTransfer={cancellingUpload}
              onCancelTransfer={plan?.kind === "upload" && receipt === null ? () => {
                setCancellingUpload(true);
                void cancelTransfer(plan.browserHandle, (reached) => {
                  if (!reached) setCancellingUpload(false);
                });
              } : undefined}
              onClose={closeOperation}
            />
          )}
        </>
      )}
    </main>
  );
}

/**
 * Says what a failed undo means for the target. An undo the backend no longer
 * holds was refused before anything was touched; one that ran out of time may
 * or may not have reached the target. The window is the backend's UNDO_TTL.
 */
export function sftpUndoFailure(reason: unknown): string {
  const text = reason instanceof Error ? reason.message : "";
  if (/\(sftp-browser-unavailable\)\s*$/u.test(text)) {
    return "撤销的时限已过（完成后 10 分钟内有效），没有改动任何东西。请刷新后再决定。";
  }
  if (/\(sftp-browser-timeout\)\s*$/u.test(text)) {
    return "撤销没有在时限内返回结果，不确定是否已经放回。请刷新查看现在的状态。";
  }
  return errorText(reason, "撤销没有完成；请刷新查看现在的状态。");
}

/** Whether a transfer failed because the operator stopped it. */
export function transferStopped(reason: unknown): boolean {
  return reason instanceof Error && /\(sftp-browser-cancelled\)\s*$/u.test(reason.message);
}

/** Main answers either a staged file or a dismissed dialog. */
function stagedUpload(value: unknown): { stagedHandle: string; name: string } | null {
  if (typeof value !== "object" || value === null) return null;
  const reply = value as { staged?: unknown; upload?: unknown };
  if (reply.staged !== true || !isSftpStagedUpload(reply.upload)) return null;
  return { stagedHandle: reply.upload.stagedHandle, name: reply.upload.name };
}

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
            <span className="sftp-browser-row-label" title={entry.name}>{entry.name}</span>
            {entry.nameTruncated ? <em>名称已截断</em> : null}
          </span>
          <span className="sftp-browser-row-size" title={entry.kind === "directory" ? undefined : displaySftpBytes(entry.sizeBytes)}>
            {entry.kind === "directory" ? "—" : compactSftpBytes(entry.sizeBytes)}
          </span>
          <span className="sftp-browser-row-time">{displaySftpModifiedAt(entry.modifiedAt)}</span>
        </button>
      ))}
    </div>
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

/**
 * Why the file browser would not open, in terms an operator can act on.
 *
 * The old text named three things that might be wrong — the binding, the
 * permissions, the fixed entry point — and the most common cause was none of
 * them: an `sshd` with no `Subsystem sftp` line takes the request, never
 * finishes the handshake, and the browser reads as broken. Guessing three
 * wrong causes is worse than naming the one the target reported.
 */
/**
 * Whether a refusal means this browser no longer exists on the backend —
 * expired or closed — so that listing again cannot help and only opening a
 * new one can. The code is the backend's, kept at the end of the message.
 */
export function sftpBrowserGone(reason: unknown): boolean {
  const text = reason instanceof Error ? reason.message : String(reason ?? "");
  return /\(sftp-browser-unavailable\)\s*$/u.test(text);
}

export function sftpOpenFailureMessage(reason: unknown): string {
  const text = reason instanceof Error ? reason.message : "";
  if (text.includes("sftp-browser-subsystem-unavailable")) {
    return "这台目标机没有完成 SFTP 握手，多半是它的 SSH 服务没有开启 sftp 子系统"
      + "（sshd_config 里缺少 Subsystem sftp 那一行）。终端命令仍然可用。";
  }
  if (text.includes("sftp-browser-timeout")) {
    return "打开文件管理超时：目标机没有在限定时间内回应。";
  }
  if (text.includes("sftp-browser-capacity")) {
    return "同时打开的文件管理太多了，关掉一个再试。";
  }
  return targetFailureMessage(
    reason,
    "无法打开文件管理：目标机没有接受这次请求，可能是当前账号没有使用 SFTP 的权限。",
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
