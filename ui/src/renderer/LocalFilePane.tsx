import { useEffect, useState } from "react";

import {
  isLocalDirectorySnapshot,
  type LocalBrowserApi,
  type LocalBrowserEntry,
  type LocalDirectorySnapshot,
} from "../shared/local-browser-contract";
import { EntryKindIcon, HomeIcon, UpIcon, UploadIcon } from "./file-icons";
import { compactSftpBytes, displaySftpBytes, displaySftpModifiedAt } from "./sftp-browser-helpers";
import { SftpBrowserEmpty, SftpBrowserError, SftpBrowserStatus } from "./SftpBrowserPage";

export interface LocalFilePaneProps {
  api: LocalBrowserApi;
  active?: boolean;
  /**
   * Sends the selected file to the remote pane. The pane hands over the entry
   * handle it was given, never a path, and the upload is still planned and
   * confirmed like any other change.
   */
  onUpload?: (entryHandle: string, name: string) => void;
}

type Status = "idle" | "loading" | "ready" | "error";

/**
 * The operator's own machine, in the same shape as the remote pane. Every
 * directory it can open arrived as an opaque handle, so this pane never holds a
 * filesystem path — only the label main sends for the path bar.
 */
export function LocalFilePane({ api, active = true, onUpload }: LocalFilePaneProps) {
  const [directory, setDirectory] = useState<LocalDirectorySnapshot | null>(null);
  const [status, setStatus] = useState<Status>("idle");
  const [error, setError] = useState<string | null>(null);
  const [selectedHandle, setSelectedHandle] = useState<string | null>(null);
  // A monotonic token: each navigation supersedes whatever was in flight.
  const [request, setRequest] = useState<{ token: number; directoryHandle: string | null }>({
    token: 0,
    directoryHandle: null,
  });

  useEffect(() => {
    if (!active) {
      setDirectory(null);
      setStatus("idle");
      setSelectedHandle(null);
      return;
    }
    let cancelled = false;
    setStatus("loading");
    setError(null);
    const pending = request.directoryHandle === null
      ? api.openLocalBrowser()
      : api.listLocalDirectory(request.directoryHandle);
    void pending.then((value) => {
      if (cancelled) return;
      if (!isLocalDirectorySnapshot(value)) throw new Error();
      setDirectory(value);
      setSelectedHandle(null);
      setStatus("ready");
    }).catch(() => {
      if (cancelled) return;
      setStatus("error");
      setError("无法读取本地目录；目录可能已被移动，或当前账号没有读取权限。");
    });
    return () => {
      cancelled = true;
    };
  }, [active, api, request]);

  function navigate(directoryHandle: string): void {
    setRequest((current) => ({ token: current.token + 1, directoryHandle }));
  }

  const busy = status === "loading";
  const selectedFile = directory?.entries.find(
    (entry) => entry.entryHandle === selectedHandle && entry.kind === "file",
  ) ?? null;
  const folders = directory?.entries.filter((entry) => entry.kind === "directory").length ?? 0;
  const files = (directory?.displayedEntryCount ?? 0) - folders;
  return (
    <section className="sftp-browser-pane is-local" aria-label="本地文件">
      <header className="sftp-browser-pane-head">
        <strong>本地文件</strong>
        {onUpload === undefined ? null : (
          <button
            type="button"
            className="sftp-browser-pane-action"
            disabled={busy || selectedFile === null}
            title={selectedFile === null ? "先选择一个文件" : `上传 ${selectedFile.name} 到远端目录`}
            onClick={() => selectedFile !== null && onUpload(selectedFile.entryHandle, selectedFile.name)}
          >
            <UploadIcon />上传到远端
          </button>
        )}
        <button type="button" disabled={busy} title="回到主目录" aria-label="回到主目录"
          onClick={() => setRequest((current) => ({ token: current.token + 1, directoryHandle: null }))}>
          <HomeIcon />
        </button>
      </header>
      <div className="sftp-browser-pathbar">
        <button type="button" title="上一级" aria-label="上一级"
          disabled={busy || directory === null || directory.parentDirectoryHandle === null}
          onClick={() => directory?.parentDirectoryHandle != null && navigate(directory.parentDirectoryHandle)}>
          <UpIcon />
        </button>
        <span className="sftp-browser-path-value">
          {directory === null ? "读取中…" : directory.directoryLabel}
        </span>
      </div>
      <div className="sftp-browser-pane-body">
        {status === "loading" && directory === null ? <SftpBrowserStatus label="正在读取本地目录…" compact /> :
          status === "error" && directory === null
            ? <SftpBrowserError message={error ?? "本地目录不可用。"} compact />
            : directory === null ? <SftpBrowserEmpty title="尚未读取" detail="打开主目录后重试。" compact /> : (
              <div className="sftp-browser-rows" role="list">
                <div className="sftp-browser-table-head" aria-hidden="true">
                  <span>名称</span><span>大小</span><span>修改时间</span>
                </div>
                {directory.entries.length === 0 ? (
                  <SftpBrowserEmpty title="目录为空" detail="当前目录没有条目。" compact />
                ) : directory.entries.map((entry) => (
                  <LocalRow
                    key={entry.entryHandle}
                    entry={entry}
                    selected={entry.entryHandle === selectedHandle}
                    busy={busy}
                    onSelect={() => setSelectedHandle(entry.entryHandle)}
                    onOpen={() => entry.kind === "directory" && navigate(entry.entryHandle)}
                  />
                ))}
              </div>
            )}
      </div>
      <footer className="sftp-browser-pane-foot">
        <span>
          {directory === null ? "—" : `${directory.displayedEntryCount} 个项目（${folders} 个文件夹，${files} 个文件）`}
        </span>
        {directory?.truncated === true
          ? <span>共 {directory.observedEntryCount} 项，只显示前 {directory.displayedEntryCount} 项</span>
          : null}
      </footer>
    </section>
  );
}

function LocalRow({ entry, selected, busy, onSelect, onOpen }: {
  entry: LocalBrowserEntry;
  selected: boolean;
  busy: boolean;
  onSelect: () => void;
  onOpen: () => void;
}) {
  return (
    <button
      type="button"
      role="listitem"
      className={selected ? "sftp-browser-row is-selected" : "sftp-browser-row"}
      disabled={busy}
      aria-pressed={selected}
      onClick={onSelect}
      onDoubleClick={onOpen}
    >
      <span className="sftp-browser-row-name">
        <span className={`sftp-browser-row-kind is-${entry.kind}`}>
          <EntryKindIcon kind={entry.kind} />
        </span>
        <span className="sftp-browser-row-label">{entry.name}</span>
        {entry.nameTruncated ? <em>名称已截断</em> : null}
      </span>
      <span className="sftp-browser-row-size" title={entry.kind === "directory" ? undefined : displaySftpBytes(entry.sizeBytes)}>
        {entry.kind === "directory" ? "—" : compactSftpBytes(entry.sizeBytes)}
      </span>
      <span className="sftp-browser-row-time">{displaySftpModifiedAt(entry.modifiedAt)}</span>
    </button>
  );
}
