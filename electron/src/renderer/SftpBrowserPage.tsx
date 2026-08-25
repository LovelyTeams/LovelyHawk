import { useEffect, useReducer, useRef, useState } from "react";

import {
  isSftpDirectorySnapshot,
  isSftpTextPreview,
  sftpBrowserEntryKinds,
  type SftpBrowserApi,
  type SftpBrowserEntry,
  type SftpDirectorySnapshot,
  type SftpTextPreview,
} from "../shared/sftp-browser-contract";
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
  api: SftpBrowserApi;
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

  function updateFilter(kind: SftpBrowserKindFilter) {
    setPendingPreview(null);
    dispatch({ type: "kind-selected", kind });
  }

  return (
    <main className="sftp-browser-page">
      <header className="sftp-browser-header">
        <div>
          <h1>SFTP 只读浏览器</h1>
          </div>
        <div className="sftp-browser-header-actions">
          <button type="button" disabled={busy || directory === null}
            onClick={() => directory !== null && requestDirectory(directory.directoryHandle)}>
            {visibleState.directoryStatus === "loading" ? "读取中…" : "刷新当前目录"}
          </button>
          <button type="button" disabled={busy} onClick={() => setReopenVersion((value) => value + 1)}>
            重新打开根目录
          </button>
        </div>
      </header>
      <p className="sftp-browser-boundary">
        只浏览目录与预览 UTF-8 文本文件；不跟随符号链接，远端名称与内容一律按纯文本处理。
      </p>

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
          <div className="sftp-browser-toolbar">
            <div className="sftp-browser-navigation" aria-label="SFTP 目录导航">
              <button type="button" disabled={busy || directory.parentDirectoryHandle === null}
                onClick={() => directory.parentDirectoryHandle !== null && requestDirectory(directory.parentDirectoryHandle)}>
                上一级
              </button>
              <button type="button" disabled={busy || visibleState.rootDirectoryHandle === null ||
                directory.directoryHandle === visibleState.rootDirectoryHandle}
                onClick={() => visibleState.rootDirectoryHandle !== null &&
                  requestDirectory(visibleState.rootDirectoryHandle)}>
                根目录
              </button>
              <strong>{directory.directoryLabel}</strong>
            </div>
            <label>搜索
              <input value={visibleState.search} maxLength={256} placeholder="本地筛选名称"
                onChange={(event) => {
                  setPendingPreview(null);
                  dispatch({ type: "search-changed", value: event.currentTarget.value });
                }} />
            </label>
            <label>类型
              <select value={visibleState.kind}
                onChange={(event) => updateFilter(event.currentTarget.value as SftpBrowserKindFilter)}>
                <option value="all">全部</option>
                {sftpBrowserEntryKinds.map((kind) => <option key={kind} value={kind}>
                  {sftpBrowserKindLabel(kind)}
                </option>)}
              </select>
            </label>
            <span>{entries.length}/{directory.displayedEntryCount} 可见 · 能力约 {
              Math.max(1, Math.ceil(directory.expiresInSeconds / 60))} 分钟内有效</span>
          </div>
          {directory.truncated && <p className="sftp-browser-warning" role="status">
            目录共有 {directory.observedEntryCount} 项，当前只显示前 {directory.displayedEntryCount} 项。
          </p>}
          {directory.directoryLabelTruncated && <p className="sftp-browser-warning" role="status">
            当前目录显示名称已按字节上限截断。
          </p>}
          <SftpBrowserWorkbench
            entries={entries}
            selected={selected}
            selectedHandle={visibleState.selectedEntryHandle}
            previewStatus={visibleState.previewStatus}
            preview={visibleState.preview}
            previewError={visibleState.previewError}
            search={visibleState.search}
            busy={busy}
            onSelect={selectEntry}
            onBrowse={(entryHandle) => requestDirectory(entryHandle)}
            onPreview={requestPreview}
          />
        </>
      )}
    </main>
  );
}

export function SftpBrowserWorkbench({
  entries,
  selected,
  selectedHandle,
  previewStatus,
  preview,
  previewError,
  search,
  busy,
  onSelect,
  onBrowse,
  onPreview,
}: {
  entries: SftpBrowserEntry[];
  selected: SftpBrowserEntry | null;
  selectedHandle: string | null;
  previewStatus: SftpBrowserLoadStatus;
  preview: SftpTextPreview | null;
  previewError: string | null;
  search: string;
  busy: boolean;
  onSelect: (entryHandle: string) => void;
  onBrowse: (entryHandle: string) => void;
  onPreview: () => void;
}) {
  return (
    <section className="sftp-browser-workbench" aria-label="SFTP 目录内容">
      <aside className="sftp-browser-list">
        {entries.length === 0 ? <SftpBrowserEmpty
          title={search.trim() === "" ? "目录为空" : "没有匹配条目"}
          detail={search.trim() === "" ? "当前目录没有条目。" : "调整本地筛选条件。"}
          compact /> : entries.map((entry) => (
            <button type="button" key={entry.entryHandle}
              className={entry.entryHandle === selectedHandle ? "sftp-browser-entry is-selected" : "sftp-browser-entry"}
              onClick={() => onSelect(entry.entryHandle)}>
              <span className={`sftp-browser-entry-kind is-${entry.kind}`}>{sftpBrowserKindLabel(entry.kind)}</span>
              <strong>{entry.name}</strong>
              <small>{displaySftpBytes(entry.sizeBytes)} · {sftpBrowserActionLabel(entry)}</small>
              {entry.nameTruncated && <em>名称已截断</em>}
            </button>
          ))}
      </aside>
      <div className="sftp-browser-detail">
        {selected === null ? <SftpBrowserEmpty title="未选择条目" detail="从左侧选择一个条目。" /> : (
          <>
            <header className="sftp-browser-detail-header">
              <div>
                <span>{sftpBrowserKindLabel(selected.kind)} · {sftpBrowserActionLabel(selected)}</span>
                <h2>{selected.name}</h2>
                <p>{displaySftpBytes(selected.sizeBytes)} · {displaySftpModifiedAt(selected.modifiedAt)}</p>
              </div>
              {selected.action === "browse" && <button type="button" disabled={busy}
                onClick={() => onBrowse(selected.entryHandle)}>打开目录</button>}
              {selected.action === "preview" && <button type="button" disabled={busy}
                onClick={onPreview}>{previewStatus === "loading" ? "读取中…" : "预览文本"}</button>}
            </header>
            {selected.nameTruncated && <p className="sftp-browser-warning">此显示名称已按字节上限截断。</p>}
            {selected.action === "none" ? <SftpBrowserEmpty
              title={selected.kind === "symlink" ? "符号链接不会跟随" : "此条目不可打开"}
              detail="该条目不是目录，也不是可预览的文本文件。" compact /> :
              selected.action === "browse" ? <SftpBrowserEmpty title="目录"
                detail="打开后查看下一层目录。" compact /> :
                previewStatus === "loading" ? <SftpBrowserStatus label="正在读取文本…" compact /> :
                  previewStatus === "error" ? <SftpBrowserError message={previewError ?? "文本预览不可用。"} compact /> :
                    preview === null ? <SftpBrowserEmpty title="尚未读取文本"
                      detail="手动预览后，纯文本结果会显示在这里。" compact /> :
                      <SftpTextPreviewView preview={preview} />}
          </>
        )}
      </div>
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
