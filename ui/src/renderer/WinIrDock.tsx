import { Activity, useId, useRef, type ReactNode } from "react";

import type { useWindowsIncident } from "./use-windows-incident";
import type { WindowsDockTab } from "./WinIrConsole";
import { collectedTime, CORE_COLLECTION, moduleLabel } from "./win-ir-model";

const TABS: readonly { key: WindowsDockTab; label: string }[] = [
  { key: "tasks", label: "任务" }, { key: "files", label: "接收文件" },
  { key: "command", label: "命令检查台" }, { key: "logs", label: "通信日志" },
];

export function WinIrDock({ data, expanded, tab, onTab, onToggle, children }: {
  data: ReturnType<typeof useWindowsIncident>; expanded: boolean; tab: WindowsDockTab;
  onTab: (tab: WindowsDockTab) => void; onToggle: () => void; children: ReactNode;
}) {
  const id = useId();
  const root = useRef<HTMLElement>(null);
  const files = data.status?.receivedFiles ?? [];
  const unsaved = files.filter((file) => !data.savedFiles.has(file.fileId)).length;
  function collapse() {
    onToggle();
    root.current?.querySelector<HTMLButtonElement>('[role="tab"][aria-selected="true"]')?.focus();
  }
  return <aside ref={root} className={`wir-channel-drawer wir-dock${expanded ? " is-expanded" : ""} is-${tab}`} aria-label="通道与传输面板" onKeyDown={(event) => {
    if (event.key === "Escape" && expanded && !event.defaultPrevented && !document.querySelector('[role="dialog"], [role="alertdialog"]') && !(event.target instanceof HTMLTextAreaElement)) {
      event.stopPropagation(); collapse();
    }
  }}>
    <header>
      <div className="wir-dock-tabs" role="tablist" aria-label="任务与传输" onKeyDown={(event) => {
        const index = TABS.findIndex((item) => item.key === tab);
        const next = event.key === "ArrowRight" ? (index + 1) % TABS.length : event.key === "ArrowLeft" ? (index + TABS.length - 1) % TABS.length : event.key === "Home" ? 0 : event.key === "End" ? TABS.length - 1 : null;
        if (next === null) return;
        event.preventDefault(); event.stopPropagation();
        onTab(TABS[next]!.key);
        event.currentTarget.querySelectorAll<HTMLButtonElement>('[role="tab"]')[next]?.focus();
      }}>
        {TABS.map((item) => <button key={item.key} id={`${id}-${item.key}`} type="button" role="tab" aria-selected={tab === item.key} aria-expanded={expanded && tab === item.key} aria-controls={`${id}-panel`} tabIndex={tab === item.key ? 0 : -1} onClick={() => onTab(item.key)}>
          {item.label}{item.key === "tasks" && data.busy ? <em>1</em> : item.key === "files" && files.length ? <em>{files.length}</em> : null}
        </button>)}
      </div>
      <span className="wir-dock-summary">{data.busy ? data.busy : unsaved ? `${unsaved} 个文件待保存` : "当前无进行中的任务"}</span>
      <button type="button" className="wir-icon-button" aria-label={expanded ? "收起通道与传输" : "展开通道与传输"} aria-expanded={expanded} onClick={() => expanded ? collapse() : onToggle()}>{expanded ? "⌄" : "⌃"}</button>
    </header>
    <Activity mode={expanded ? "visible" : "hidden"}>
      <div id={`${id}-panel`} className="wir-channel-content" role="tabpanel" aria-labelledby={`${id}-${tab}`} tabIndex={0}>
        <Activity mode={tab === "tasks" ? "visible" : "hidden"}>
          <div className="wir-task-panel">
            <div className="wir-task-current" role="status">
              {data.busy ? <span className="win-ir-spinner" aria-hidden="true" /> : null}
              <strong>{data.busy || "当前没有进行中的任务"}</strong>
              {data.batch ? <><span>{data.batch.done} / {data.batch.total}</span><button type="button" className="win-ir-btn" disabled={data.batch.stopping} onClick={data.cancelBatch}>{data.batch.stopping ? "本项结束后停止…" : "停止后续采集"}</button></> : null}
            </div>
            <div className="wir-task-history" aria-label="核心模块采集记录">
              {CORE_COLLECTION.map((key) => <div key={key} className={data.collectionErrors[key] ? "has-error" : ""}>
                <strong>{moduleLabel(key)}</strong><span>{data.collectionErrors[key] ? "上次采集失败" : data.collectedAt[key] ? `采集于 ${collectedTime(data.collectedAt[key])}` : "尚未采集"}</span>
                {data.collectionErrors[key] ? <><p>{data.collectionErrors[key]}{data.collectedAt[key] ? "；保留上一份成功结果。" : ""}</p><button type="button" className="win-ir-btn" disabled={data.busy !== null || data.sessionKey === null} onClick={() => void data.collect(key)}>重试{moduleLabel(key)}</button></> : null}
              </div>)}
            </div>
          </div>
        </Activity>
        {children}
      </div>
    </Activity>
  </aside>;
}
