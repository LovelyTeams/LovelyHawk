import { useEffect, useMemo, useRef, useState, type CSSProperties } from "react";

import type { WindowsFileEntry, WindowsFilePreview, WindowsFilesSnapshot } from "../shared/windows-incident-contract";
import { WinIrTree } from "./WinIrTree";
import { ColumnResizer, DataTable, DetailPane, FilterChips, RiskBadge, RiskCell, SearchBox, SourceTime, WinIrModal, riskSort, type Column } from "./WinIrKit";
import { WinIrRelated, type RelatedContext } from "./WinIrRelated";
import { RELATED_ID } from "./win-ir-links";
import {
  FILE_KIND_LABEL,
  decodeBase64,
  decodeTextPreview,
  fileExtension,
  fileKind,
  formatBytes,
  hexDump,
  matchesQuery,
  parentPath,
  parsePeHeader,
  pathSegments,
  type FileKind,
} from "./win-ir-helpers";

const QUICK_PLACES: ReadonlyArray<{ label: string; path: string; hint: string }> = [
  { label: "系统盘", path: "C:\\", hint: "C 盘根目录" },
  { label: "用户目录", path: "C:\\Users", hint: "所有用户的配置文件" },
  { label: "公共目录", path: "C:\\Users\\Public", hint: "所有用户可写，常见落地位置" },
  { label: "当前用户临时目录", path: "%TEMP%", hint: "落地执行的高发位置" },
  { label: "系统临时目录", path: "C:\\Windows\\Temp", hint: "服务与系统账户的临时文件" },
  { label: "全局启动目录", path: "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp", hint: "所有用户登录时运行" },
  { label: "ProgramData", path: "C:\\ProgramData", hint: "隐藏目录，常被用于驻留" },
  { label: "计划任务目录", path: "C:\\Windows\\System32\\Tasks", hint: "计划任务定义文件" },
  { label: "IIS 站点目录", path: "C:\\inetpub\\wwwroot", hint: "排查网页后门" },
  { label: "Prefetch", path: "C:\\Windows\\Prefetch", hint: "程序执行痕迹" },
];

type KindFilter = "all" | "folder" | "executable" | "script" | "web" | "hidden" | "risky";

function FileIcon({ kind }: { kind: FileKind }) {
  const common = { viewBox: "0 0 16 16", width: 16, height: 16, fill: "none", stroke: "currentColor", strokeWidth: 1.4, strokeLinejoin: "round" as const, "aria-hidden": true };
  return (
    <span className={`wir-file-icon is-${kind}`}>
      {kind === "folder" ? (
        <svg {...common}><path d="M1.8 4.2a1 1 0 0 1 1-1h3.4l1.4 1.6h5.6a1 1 0 0 1 1 1v6.6a1 1 0 0 1-1 1H2.8a1 1 0 0 1-1-1Z" /></svg>
      ) : kind === "executable" ? (
        <svg {...common}><rect x="2" y="2.6" width="12" height="10.8" rx="1.6" /><path d="M2 5.6h12M5 9h2M5 11h4" /></svg>
      ) : kind === "script" || kind === "web" ? (
        <svg {...common}><path d="M3.4 1.8h6l3.2 3.2v9.2H3.4Z" /><path d="m6.6 8.2-1.6 1.6 1.6 1.6M9.4 8.2l1.6 1.6-1.6 1.6" /></svg>
      ) : kind === "archive" ? (
        <svg {...common}><path d="M3.4 1.8h9.2v12.4H3.4Z" /><path d="M8 1.8v2M8 5v1.4M8 7.6V9" /><rect x="6.8" y="9.6" width="2.4" height="2.4" rx=".5" /></svg>
      ) : (
        <svg {...common}><path d="M3.4 1.8h6l3.2 3.2v9.2H3.4Z" /><path d="M9.4 1.8V5h3.2" /></svg>
      )}
    </span>
  );
}

export interface FileManagerProps {
  snapshot: WindowsFilesSnapshot | null;
  busy: boolean;
  connected: boolean;
  revealPath?: string | null;
  related?: RelatedContext;
  onNavigate: (path: string) => void;
  onPreview: (path: string) => Promise<WindowsFilePreview>;
  onPull: (path: string) => void;
  onDelete?: (entry: WindowsFileEntry) => void;
  onCopy: (text: string) => void;
}

/**
 * The remote Windows file system as an explorer window: places on the left,
 * an address bar with history, a sortable listing and a properties / preview
 * pane. Preview reads the first 16 KB only; deleting a file requires confirmation.
 */
export function WinIrFileManager({ snapshot, busy, connected, revealPath, related, onNavigate, onPreview, onPull, onDelete, onCopy }: FileManagerProps) {
  const [trail, setTrail] = useState<{ items: string[]; index: number }>({ items: [], index: -1 });
  const travellingRef = useRef<number | null>(null);
  const history = trail.items;
  const historyIndex = trail.index;
  const [address, setAddress] = useState(snapshot?.currentPath ?? "C:\\Users\\Public");
  const [showDetails, setShowDetails] = useState(true);
  const [placesWidth, setPlacesWidth] = useState(240);
  const addressRef = useRef<HTMLInputElement>(null);
  const [query, setQuery] = useState("");
  const [kindFilter, setKindFilter] = useState<KindFilter>("all");
  const [selected, setSelected] = useState<string | null>(null);
  const [preview, setPreview] = useState<{ path: string; data: WindowsFilePreview | null; error: string | null; loading: boolean; mode: "text" | "hex" } | null>(null);
  const previousPath = useRef<string | null>(null);
  const previewRequest = useRef(0);

  const currentPath = snapshot?.currentPath ?? null;
  useEffect(() => {
    if (currentPath === null || currentPath === previousPath.current) return;
    previousPath.current = currentPath;
    setAddress(currentPath);
    setSelected(null);
    setPreview(null);
    const travelled = travellingRef.current;
    travellingRef.current = null;
    setTrail(({ items, index }) => {
      // Back and forward move within the trail; anything else cuts the
      // forward branch, as in Explorer.
      if (travelled !== null && items[travelled] === currentPath) return { items, index: travelled };
      if (items[index] === currentPath) return { items, index };
      const next = [...items.slice(0, index + 1), currentPath].slice(-50);
      return { items: next, index: next.length - 1 };
    });
  }, [currentPath]);

  useEffect(() => {
    previewRequest.current += 1;
    setPreview(null);
    return () => { previewRequest.current += 1; };
  }, [snapshot, connected]);
  useEffect(() => {
    if (revealPath && snapshot?.entries.some((entry) => entry.fullPath.toLowerCase() === revealPath.toLowerCase())) {
      setSelected(snapshot.entries.find((entry) => entry.fullPath.toLowerCase() === revealPath.toLowerCase())!.fullPath);
      setQuery(""); setKindFilter("all");
    }
  }, [revealPath, snapshot?.currentPath]);

  const travel = (index: number) => {
    const target = history[index];
    if (target === undefined) return;
    travellingRef.current = index;
    onNavigate(target);
  };

  const entries = snapshot?.entries ?? [];
  const counts = useMemo(() => ({
    all: entries.length,
    folder: entries.filter((entry) => entry.entryType === "dir").length,
    executable: entries.filter((entry) => fileKind(entry.name, entry.entryType === "dir") === "executable").length,
    script: entries.filter((entry) => fileKind(entry.name, entry.entryType === "dir") === "script").length,
    web: entries.filter((entry) => fileKind(entry.name, entry.entryType === "dir") === "web").length,
    hidden: entries.filter((entry) => entry.hidden).length,
    risky: entries.filter((entry) => entry.riskLevel === "high" || entry.riskLevel === "medium").length,
  }), [entries]);

  const visible = useMemo(() => entries.filter((entry) => {
    const kind = fileKind(entry.name, entry.entryType === "dir");
    if (kindFilter === "hidden" && !entry.hidden) return false;
    if (kindFilter === "risky" && entry.riskLevel !== "high" && entry.riskLevel !== "medium") return false;
    if (kindFilter !== "all" && kindFilter !== "hidden" && kindFilter !== "risky" && kind !== kindFilter) return false;
    return matchesQuery(query, entry.name, entry.sha256);
  }), [entries, kindFilter, query]);

  const selectedEntry = entries.find((entry) => entry.fullPath === selected) ?? null;
  const open = (entry: WindowsFileEntry) => {
    if (!connected || busy) return;
    if (entry.entryType === "dir") onNavigate(entry.fullPath);
    else { setShowDetails(true); void loadPreview(entry.fullPath); }
  };
  const up = currentPath === null ? null : parentPath(currentPath);

  async function loadPreview(path: string) {
    if (!connected || busy) return;
    const request = ++previewRequest.current;
    setPreview({ path, data: null, error: null, loading: true, mode: "text" });
    try {
      const data = await onPreview(path);
      setPreview((current) => request === previewRequest.current && current?.path === path ? { ...current, data, loading: false } : current);
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : "读取预览失败。";
      setPreview((current) => request === previewRequest.current && current?.path === path ? { ...current, error: message, loading: false } : current);
    }
  }

  const columns: Column<WindowsFileEntry>[] = [
    {
      key: "name", label: "名称",
      sort: (entry) => entry.name.toLowerCase(),
      render: (entry) => (
        <span className={`wir-file-name${entry.hidden ? " is-hidden" : ""}`}>
          <FileIcon kind={fileKind(entry.name, entry.entryType === "dir")} />
          <span title={entry.name}>{entry.name}</span>
          {entry.hidden ? <i className="wir-tag">隐藏</i> : null}
          {entry.system ? <i className="wir-tag">系统</i> : null}
        </span>
      ),
    },
    { key: "time", label: "修改时间", width: "196px", mono: true, sort: (entry) => entry.lastWriteTime, render: (entry) => <SourceTime value={entry.lastWriteTime} /> },
    {
      key: "type", label: "类型", width: "100px",
      sort: (entry) => fileExtension(entry.name),
      render: (entry) => {
        const kind = fileKind(entry.name, entry.entryType === "dir");
        const extension = fileExtension(entry.name);
        return kind === "folder" ? FILE_KIND_LABEL.folder : `${FILE_KIND_LABEL[kind]}${extension ? ` (.${extension})` : ""}`;
      },
    },
    { key: "size", label: "大小", width: "82px", sort: (entry) => entry.sizeBytes, render: (entry) => (entry.entryType === "dir" ? "" : formatBytes(entry.sizeBytes)) },
    { key: "risk", label: "风险", width: "78px", sort: riskSort((entry) => entry.riskLevel), render: (entry) => <RiskCell level={entry.riskLevel} /> },
  ];

  const previewBytes = preview?.data ? decodeBase64(preview.data.previewB64) : null;
  const text = previewBytes ? decodeTextPreview(previewBytes) : null;
  const pe = previewBytes ? parsePeHeader(previewBytes) : null;

  return (
    <div className="wir-explorer wir-file-explorer" onKeyDown={(event) => {
      if (event.altKey && event.key === "ArrowUp" && up && connected && !busy) { event.preventDefault(); onNavigate(up); }
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "l") { event.preventDefault(); addressRef.current?.focus(); addressRef.current?.select(); }
      if (event.key === "F5" && connected && !busy) { event.preventDefault(); onNavigate(currentPath ?? address); }
    }}>
      <div className="wir-explorer-bar">
        <div className="wir-nav-buttons">
          <button type="button" className="wir-icon-button" aria-label="后退" title="后退" disabled={busy || !connected || historyIndex <= 0} onClick={() => travel(historyIndex - 1)}>←</button>
          <button type="button" className="wir-icon-button" aria-label="前进" title="前进" disabled={busy || !connected || historyIndex >= history.length - 1} onClick={() => travel(historyIndex + 1)}>→</button>
          <button type="button" className="wir-icon-button" aria-label="上一级" title="上一级" disabled={busy || !connected || up === null} onClick={() => up && onNavigate(up)}>↑</button>
          <button type="button" className="wir-icon-button" aria-label="刷新" title="刷新" disabled={busy || !connected} onClick={() => onNavigate(currentPath ?? address)}>⟳</button>
        </div>
        <form
          className="wir-address"
          onSubmit={(event) => {
            event.preventDefault();
            if (connected && !busy && address.trim() !== "") onNavigate(address.trim());
          }}
        >
          <div className="wir-crumbs" aria-label="当前位置">
            {currentPath === null ? null : pathSegments(currentPath).map((segment, index, all) => (
              <span key={segment.path}>
                <button type="button" disabled={busy || !connected || index === all.length - 1} onClick={() => onNavigate(segment.path)}>{segment.label}</button>
                {index < all.length - 1 ? <i aria-hidden="true">›</i> : null}
              </span>
            ))}
          </div>
          <input
            ref={addressRef}
            value={address}
            aria-label="目录路径"
            placeholder="输入远程目录路径，如 C:\\Users\\Public 或 %TEMP%"
            spellCheck={false}
            onChange={(event) => setAddress(event.target.value)}
          />
          <button type="submit" className="win-ir-btn is-primary" disabled={busy || !connected}>转到</button>
        </form>
        <SearchBox value={query} onChange={setQuery} placeholder="在当前文件夹中筛选名称或 SHA256" />
      </div>

      <div className="wir-explorer-body is-resizable" style={{ "--wir-places-width": `${placesWidth}px` } as CSSProperties}>
        <ColumnResizer label="调整左侧位置栏宽度" width={placesWidth} min={160} max={520} onChange={setPlacesWidth} />
        <nav className="wir-places" aria-label="快速访问">
          <p>此电脑</p>
          <WinIrTree label="文件夹树" roots={[{ label: pathSegments(currentPath ?? "C:\\")[0]?.label ?? "C:", path: pathSegments(currentPath ?? "C:\\")[0]?.path ?? "C:\\" }]}
            currentPath={currentPath} ancestors={currentPath ? pathSegments(currentPath) : []}
            children={entries.filter((entry) => entry.entryType === "dir").map((entry) => ({ label: entry.name, path: entry.fullPath }))}
            disabled={busy || !connected} onNavigate={onNavigate} />
          <p>快速访问</p>
          {QUICK_PLACES.map((place) => (
            <button
              key={place.path}
              type="button"
              title={`${place.hint}\n${place.path}`}
              className={currentPath !== null && currentPath.toLowerCase() === place.path.toLowerCase() ? "is-active" : undefined}
              disabled={busy || !connected}
              onClick={() => onNavigate(place.path)}
            >
              <FileIcon kind="folder" />
              <span>{place.label}</span>
            </button>
          ))}
        </nav>

        <section className="wir-explorer-main" aria-label="目录内容">
          <div className="wir-explorer-actions" role="toolbar" aria-label="文件操作">
            <button type="button" className="win-ir-btn" disabled={!selectedEntry || busy || !connected} onClick={() => selectedEntry && open(selectedEntry)}>{selectedEntry?.entryType === "dir" ? "打开文件夹" : "预览文件"}</button>
            <button type="button" className="win-ir-btn" disabled={!selectedEntry} onClick={() => selectedEntry && onCopy(selectedEntry.fullPath)}>复制完整路径</button>
            <button type="button" className="win-ir-btn" disabled={!selectedEntry || selectedEntry.entryType === "dir" || selectedEntry.sizeBytes > 8 * 1024 * 1024 || busy || !connected} onClick={() => selectedEntry && onPull(selectedEntry.fullPath)}>取证拉取</button>
            {onDelete ? <button type="button" className="win-ir-btn is-danger" disabled={!selectedEntry || selectedEntry.entryType === "dir" || busy || !connected} onClick={() => selectedEntry && onDelete(selectedEntry)}>删除文件</button> : null}
            <button type="button" className="win-ir-btn" aria-pressed={showDetails} onClick={() => setShowDetails(!showDetails)}>详情窗格</button>
          </div>
          <FilterChips<KindFilter>
            label="按类型筛选"
            value={kindFilter}
            onChange={setKindFilter}
            options={[
              { value: "all", label: "全部", count: counts.all },
              { value: "folder", label: "文件夹", count: counts.folder },
              { value: "executable", label: "可执行", count: counts.executable },
              { value: "script", label: "脚本", count: counts.script },
              { value: "web", label: "网页脚本", count: counts.web },
              { value: "hidden", label: "隐藏", count: counts.hidden },
              { value: "risky", label: "可疑", count: counts.risky, tone: "high" },
            ]}
          />
          <div className={selectedEntry && showDetails ? "wir-master is-split" : "wir-master"}>
            <DataTable
              label="目录内容"
              columns={columns}
              rows={visible}
              rowKey={(entry) => entry.fullPath}
              rowGroup={(entry) => entry.entryType === "dir" ? 0 : 1}
              selectedKey={selected}
              onSelect={(entry) => {
                setSelected(entry?.fullPath ?? null);
                if (entry?.fullPath !== preview?.path) { previewRequest.current += 1; setPreview(null); }
              }}
              onActivate={open}
              rowRisk={(entry) => entry.riskLevel}
              defaultSort={{ key: "name", descending: false }}
              empty={snapshot === null ? "从左侧选择一个位置，或在地址栏输入目录后点「转到」。" : entries.length === 0 ? "本次目录读取没有返回项目。" : "没有符合筛选条件的项目。"}
            />
            {selectedEntry && showDetails ? (
              <DetailPane
                title={selectedEntry.name}
                subtitle={selectedEntry.entryType === "dir" ? "文件夹" : `${FILE_KIND_LABEL[fileKind(selectedEntry.name, false)]} · ${formatBytes(selectedEntry.sizeBytes)}`}
                risk={selectedEntry.riskLevel}
                reasons={selectedEntry.riskReason ? [selectedEntry.riskReason] : []}
                onClose={() => setSelected(null)}
                onCopy={onCopy}
                fields={[
                  { label: "完整路径", value: selectedEntry.fullPath, mono: true },
                  { label: "修改时间", value: selectedEntry.lastWriteTime, mono: true },
                  ...(selectedEntry.entryType === "dir" ? [] : [{ label: "大小", value: `${formatBytes(selectedEntry.sizeBytes)}（${selectedEntry.sizeBytes} 字节）` }]),
                  { label: "属性", value: [selectedEntry.hidden ? "隐藏" : "", selectedEntry.system ? "系统" : ""].filter(Boolean).join("、") || "常规" },
                  ...(selectedEntry.sha256 ? [{ label: "SHA256", value: selectedEntry.sha256, mono: true }] : []),
                ]}
                actions={selectedEntry.entryType === "dir" ? (
                  <button type="button" className="win-ir-btn is-primary" disabled={busy || !connected} onClick={() => onNavigate(selectedEntry.fullPath)}>打开文件夹</button>
                ) : (
                  <>
                    <button type="button" className="win-ir-btn" onClick={() => onCopy(selectedEntry.fullPath)}>复制路径</button>
                    <button type="button" className="win-ir-btn" disabled={busy || !connected || preview?.loading === true} onClick={() => void loadPreview(selectedEntry.fullPath)}>预览前 16 KB</button>
                    <button type="button" className="win-ir-btn is-primary" disabled={busy || !connected || selectedEntry.sizeBytes > 8 * 1024 * 1024} title="拉取到会话缓存并校验 SHA256；单个文件上限 8 MB，尚未保存到磁盘" onClick={() => onPull(selectedEntry.fullPath)}>取证拉取（≤ 8 MB）</button>
                    {onDelete ? <button type="button" className="win-ir-btn is-danger" disabled={busy || !connected} onClick={() => onDelete(selectedEntry)}>删除文件</button> : null}
                  </>
                )}
              >
                {related && selectedEntry.entryType !== "dir" ? <WinIrRelated key={selectedEntry.fullPath} context={related} query={{ paths: [selectedEntry.fullPath], exclude: RELATED_ID.file(selectedEntry.fullPath) }} /> : null}
              </DetailPane>
            ) : null}
          </div>
          <footer className="wir-explorer-status">
            <span>{snapshot ? `${snapshot.truncated ? "至少 " : ""}${snapshot.totalEntries} 个项目${snapshot.truncated ? `，本次只列出 ${entries.length} 个` : ""}` : "未打开文件夹"}</span>
            <span>文件夹 {counts.folder} · 文件 {counts.all - counts.folder} · 隐藏 {counts.hidden}</span>
            {counts.risky > 0 ? <span className="wir-status-risk">可疑 {counts.risky}</span> : null}
            <span className="wir-status-hint">双击 / Enter 打开目录或预览 · Alt+↑ 上一级 · Ctrl+L 地址栏 · F5 刷新</span>
          </footer>
        </section>
      </div>
      {preview !== null ? (
        <WinIrModal wide title={preview.path.split(/[\\/]/u).at(-1) || preview.path} subtitle={preview.path} onClose={() => { previewRequest.current += 1; setPreview(null); }}
          actions={<>
            <button type="button" className="win-ir-btn" onClick={() => onCopy(preview.path)}>复制路径</button>
            {selectedEntry && selectedEntry.fullPath === preview.path ? <button type="button" className="win-ir-btn is-primary" disabled={busy || !connected || selectedEntry.sizeBytes > 8 * 1024 * 1024} title="拉取到会话缓存并校验 SHA256；单个文件上限 8 MB，尚未保存到磁盘" onClick={() => onPull(selectedEntry.fullPath)}>取证拉取（≤ 8 MB）</button> : null}
          </>}>
          <div className="wir-preview">
            {preview.loading ? <p className="wir-muted">正在读取文件开头…</p> : null}
            {preview.error ? <p className="wir-preview-error" role="alert">{preview.error}</p> : null}
            {preview.data && previewBytes ? (
              <>
                <div className="wir-preview-head">
                  <span>已读取 {formatBytes(preview.data.previewBytes)}{preview.data.truncated ? `，共 ${formatBytes(preview.data.sizeBytes)}，只显示开头` : "（完整内容）"}</span>
                  <FilterChips<"text" | "hex">
                    label="预览方式"
                    value={text === null ? "hex" : preview.mode}
                    onChange={(mode) => setPreview((current) => current === null ? current : { ...current, mode })}
                    options={text === null ? [{ value: "hex", label: "十六进制" }] : [{ value: "text", label: `文本（${text.encoding}）` }, { value: "hex", label: "十六进制" }]}
                  />
                </div>
                {pe ? (
                  <dl className="wir-pe">
                    <div><dt>文件类型</dt><dd>{pe.kind} · {pe.machine}</dd></div>
                    <div><dt>子系统</dt><dd>{pe.subsystem}</dd></div>
                    <div><dt>编译时间</dt><dd className="is-mono">{pe.compiledAt ?? "未记录"}（可被伪造）</dd></div>
                    <div><dt>节区</dt><dd className="is-mono">{pe.sections.join("  ") || "未在预览范围内"}</dd></div>
                  </dl>
                ) : null}
                <pre className="wir-preview-body">{text !== null && preview.mode === "text" ? text.text : hexDump(previewBytes)}</pre>
              </>
            ) : null}
          </div>
        </WinIrModal>
      ) : null}
    </div>
  );
}
