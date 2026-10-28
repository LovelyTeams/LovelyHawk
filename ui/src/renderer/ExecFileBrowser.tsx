import { useEffect, useRef, useState } from "react";

import {
  isExecDirectoryListing,
  isExecDirectoryPath,
  joinExecPath,
  MAX_EXEC_DIRECTORY_ENTRIES,
  parentExecPath,
  type ExecDirectoryEntry,
  type ExecDirectoryListing,
} from "../shared/exec-files-contract";
import { errorText } from "./error-text";
import "./exec-file-browser.css";

export interface ExecFileAction {
  label: string;
  testId: string;
  /** What the button says to a screen reader, with the name filled in. */
  describe: (name: string) => string;
  run: (path: string, entry: ExecDirectoryEntry) => void;
  /** Unavailable for now (another job of its kind is running); the description says why. */
  disabled?: boolean;
}

export interface ExecFileBrowserProps {
  /** Lists one directory inside the container or pod; rejects with the reason. */
  list: (path: string) => Promise<unknown>;
  /** What a regular file offers. Directories are entered; nothing else is opened. */
  fileActions: readonly ExecFileAction[];
  initialPath?: string;
  /** While the surrounding dialog is busy, nothing here starts another call. */
  disabled?: boolean;
}

/**
 * Where a responder looks first inside a container: configuration, the
 * scratch directories where dropped files land, home directories and logs.
 */
const PLACES: ReadonlyArray<{ path: string; hint: string }> = [
  { path: "/", hint: "根目录" },
  { path: "/etc", hint: "配置文件" },
  { path: "/tmp", hint: "临时目录，常见落地文件" },
  { path: "/var/tmp", hint: "重启后仍保留的临时目录" },
  { path: "/dev/shm", hint: "内存文件系统，常被用来藏文件" },
  { path: "/root", hint: "root 的家目录" },
  { path: "/home", hint: "普通账号的家目录" },
  { path: "/var/log", hint: "日志" },
];

type Sort = "name" | "modified";

/**
 * One directory at a time inside a container or a pod.
 *
 * Read-only: entering a directory lists it, and a file goes to whatever the
 * dialog around this offers (open, copy out). Names are shown as they are,
 * with control characters made visible, because a name built to look like
 * another is exactly what a responder needs to see.
 */
export function ExecFileBrowser({ list, fileActions, initialPath = "/", disabled = false }: ExecFileBrowserProps) {
  const [listing, setListing] = useState<ExecDirectoryListing | null>(null);
  const [status, setStatus] = useState<"loading" | "ready" | "error">("loading");
  const [error, setError] = useState<string | null>(null);
  const [pathInput, setPathInput] = useState(initialPath);
  const [filter, setFilter] = useState("");
  const [sort, setSort] = useState<Sort>("name");
  // Only the latest request may land: a slow listing of a directory the
  // operator has already left must not replace the one they moved to.
  const requestRef = useRef(0);
  const listRef = useRef(list);
  listRef.current = list;

  async function go(path: string) {
    if (!isExecDirectoryPath(path)) {
      setError("路径要以 / 开头，不能有 .. 或结尾的 /，例如 /etc/nginx。");
      setStatus("error");
      return;
    }
    const request = ++requestRef.current;
    setStatus("loading");
    setError(null);
    setPathInput(path);
    try {
      const value = await listRef.current(path);
      if (request !== requestRef.current) return;
      if (!isExecDirectoryListing(value) || value.path !== path) throw new Error();
      setListing(value);
      setFilter("");
      setStatus("ready");
    } catch (reason: unknown) {
      if (request !== requestRef.current) return;
      setError(errorText(reason, "没能列出这个目录。"));
      setStatus("error");
    }
  }

  useEffect(() => {
    void go(initialPath);
    return () => {
      requestRef.current += 1;
    };
    // The first listing only; later ones are the operator's.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const current = listing?.path ?? null;
  const parent = current === null ? null : parentExecPath(current);
  const needle = filter.trim().toLocaleLowerCase();
  const entries = (listing?.entries ?? [])
    .filter((entry) => needle === "" || entry.name.toLocaleLowerCase().includes(needle));
  const shown = sort === "name"
    ? entries
    : [...entries].sort((left, right) => (right.modifiedUnix ?? -Infinity) - (left.modifiedUnix ?? -Infinity));
  const directories = listing?.entries.filter((entry) => entry.kind === "directory").length ?? 0;
  const busy = disabled || status === "loading";

  return (
    <div className="exec-browser" data-testid="exec-file-browser">
      <form
        className="exec-browser-path"
        onSubmit={(event) => {
          event.preventDefault();
          void go(pathInput.trim());
        }}
      >
        <button type="button" disabled={busy || parent === null} aria-label="上一级目录"
          onClick={() => parent !== null && void go(parent)}>上一级</button>
        <label>
          <span className="exec-browser-visually-hidden">目录路径</span>
          <input value={pathInput} maxLength={4_096} spellCheck={false} data-testid="exec-browser-path"
            onChange={(event) => setPathInput(event.currentTarget.value)} />
        </label>
        <button type="submit" disabled={busy}>前往</button>
        <button type="button" disabled={busy || current === null} onClick={() => current !== null && void go(current)}>刷新</button>
      </form>

      <div className="exec-browser-places" aria-label="常看的位置">
        {PLACES.map((place) => (
          <button key={place.path} type="button" title={place.hint} disabled={busy}
            aria-pressed={current === place.path} onClick={() => void go(place.path)}>{place.path}</button>
        ))}
      </div>

      <div className="exec-browser-tools">
        <label>
          <span className="exec-browser-visually-hidden">按名称筛选</span>
          <input value={filter} placeholder="按名称筛选当前目录" maxLength={256} data-testid="exec-browser-filter"
            onChange={(event) => setFilter(event.currentTarget.value)} />
        </label>
        <div className="exec-browser-sort" role="group" aria-label="排序">
          <button type="button" aria-pressed={sort === "name"} onClick={() => setSort("name")}>按名称</button>
          <button type="button" aria-pressed={sort === "modified"} onClick={() => setSort("modified")}>最近修改在前</button>
        </div>
        {listing !== null ? (
          <span className="exec-browser-count" role="status">
            {listing.entries.length} 项，其中目录 {directories} 个{needle === "" ? "" : `；筛选后 ${entries.length} 项`}
          </span>
        ) : null}
      </div>

      {status === "loading" ? <p className="exec-browser-note" role="status">正在列出 {pathInput}…</p> : null}
      {status === "error" && error !== null ? <p className="exec-browser-error" role="alert">{error}</p> : null}
      {listing?.truncated === true ? (
        <p className="exec-browser-warning" role="status">
          这个目录不止 {MAX_EXEC_DIRECTORY_ENTRIES} 项，或列表没有传完，下面不是全部内容。可以在路径栏直接输入子目录。
        </p>
      ) : null}

      {listing !== null ? (
        <div className="exec-browser-table" aria-busy={status === "loading"}>
          <table>
            <thead>
              <tr>
                <th scope="col">名称</th>
                <th scope="col" className="is-numeric">大小</th>
                <th scope="col">修改时间（本机时区）</th>
                <th scope="col">权限</th>
                <th scope="col"><span className="exec-browser-visually-hidden">操作</span></th>
              </tr>
            </thead>
            <tbody>
              {shown.length === 0 ? (
                <tr><td colSpan={5} className="exec-browser-empty">
                  {listing.entries.length === 0 ? "这个目录是空的。" : "没有名称匹配筛选的条目。"}
                </td></tr>
              ) : shown.map((entry) => {
                const path = joinExecPath(listing.path, entry.name);
                const flags = modeFlags(entry);
                return (
                  <tr key={entry.name} className={entry.name.startsWith(".") ? "is-hidden" : undefined}>
                    <th scope="row">
                      <span className={`exec-browser-kind is-${entry.kind}`}>{KIND_LABEL[entry.kind]}</span>
                      {entry.kind === "directory" && entry.openable ? (
                        <button type="button" className="exec-browser-name" disabled={busy}
                          data-testid="exec-browser-enter" onClick={() => void go(path)}>{visibleName(entry.name)}</button>
                      ) : (
                        <span className="exec-browser-name"
                          title={entry.openable ? undefined : "名称里有控制字符、反斜杠或非 UTF-8 字节，不能从这里打开"}>
                          {visibleName(entry.name)}
                        </span>
                      )}
                    </th>
                    <td className="is-numeric">{entry.kind === "directory" ? "" : sizeText(entry.size)}</td>
                    <td>{timeText(entry.modifiedUnix)}</td>
                    <td>
                      <span className={flags === null ? "exec-browser-mode" : "exec-browser-mode is-notable"}
                        title={flags ?? undefined}>{entry.mode ?? "—"}</span>
                    </td>
                    <td className="exec-browser-actions">
                      {entry.kind === "file" && entry.openable ? fileActions.map((action) => (
                        <button key={action.testId} type="button" disabled={busy || action.disabled === true}
                          data-testid={action.testId}
                          aria-label={action.describe(visibleName(entry.name))}
                          onClick={() => action.run(path, entry)}>{action.label}</button>
                      )) : null}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  );
}

const KIND_LABEL: Record<ExecDirectoryEntry["kind"], string> = {
  directory: "目录",
  file: "文件",
  symlink: "链接",
  other: "其他",
};

/** Control characters as escapes, so `a\nb` cannot pass for two rows. */
export function visibleName(name: string): string {
  let shown = "";
  for (const character of name) {
    const code = character.codePointAt(0) ?? 0;
    if (code === 0x0a) shown += "\\n";
    else if (code === 0x09) shown += "\\t";
    else if (code < 0x20 || code === 0x7f) shown += `\\x${code.toString(16).padStart(2, "0")}`;
    else shown += character;
  }
  return shown;
}

/** Bits worth a second look: anyone may write it, or it runs as its owner. */
export function modeFlags(entry: Pick<ExecDirectoryEntry, "mode" | "kind">): string | null {
  if (entry.mode === null || entry.kind === "symlink") return null;
  const digits = entry.mode.padStart(4, "0");
  const notes: string[] = [];
  const special = Number(digits[0]);
  if (special & 4) notes.push("带 setuid 位，执行时以属主身份运行");
  if (special & 2) notes.push("带 setgid 位");
  if (Number(digits[3]) & 2 && !(entry.kind === "directory" && special & 1)) notes.push("所有人可写");
  return notes.length === 0 ? null : notes.join("；");
}

export function sizeText(size: number | null): string {
  if (size === null) return "—";
  if (size < 1024) return `${size} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let value = size / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value >= 10 ? value.toFixed(0) : value.toFixed(1)} ${units[unit]}`;
}

function timeText(unix: number | null): string {
  if (unix === null) return "—";
  const date = new Date(unix * 1_000);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString("zh-CN", { hour12: false });
}
