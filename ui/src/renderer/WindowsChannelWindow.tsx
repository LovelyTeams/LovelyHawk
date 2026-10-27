import { Activity, useCallback, useEffect, useId, useRef, useState } from "react";
import { CHANNEL_TABS, type ChannelRead, type ChannelNotification, type WindowsChannelAction, type WindowsChannelTab, type WindowsChannelView } from "../shared/windows-channel-contract";
import { WindowControls } from "./WindowControls";
import { WinIrConsole } from "./WinIrConsole";
import { collectedTime, moduleLabel } from "./win-ir-model";
import { errorText } from "./error-text";
import "./windows-incident.css";
import "./win-ir-workspace.css";
import "./windows-channel.css";

const LABELS = { tasks: "任务", files: "接收文件", command: "命令检查台", logs: "通信日志" };

export function WindowsChannelWindow() {
  const api = window.lovelyhawkChannel;
  const [view, setView] = useState<WindowsChannelView | null>(null);
  const [tab, setTab] = useState<WindowsChannelTab>("tasks");
  const [pending, setPending] = useState(false);
  const [notice, setNotice] = useState<(ChannelNotification & { localOnly?: boolean }) | null>(null);
  const [failed, setFailed] = useState(false);
  const current = useRef<ChannelRead | null>(null);
  const waiting = useRef<{ id: number; resolve: (ok: boolean) => void } | null>(null);
  const working = useRef(false);
  const id = useId();
  useEffect(() => {
    let stopped = false;
    let revision = 0;
    let opened = 0;
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      try {
        const result = await api.read(revision);
        if (stopped) return;
        current.current = result;
        revision = result.revision;
        if (result.view) setView(result.view);
        if (opened !== result.openRequest) { opened = result.openRequest; setTab(result.tab); }
        document.documentElement.dataset.theme = result.theme;
        setFailed(false);
        if (waiting.current && result.completion?.id === waiting.current.id) {
          waiting.current.resolve(result.completion.ok); waiting.current = null;
        }
      } catch (reason) {
        if (!stopped) { setFailed(true); setNotice({message: errorText(reason, "无法同步工作台，请从主窗口重新打开。"), severity: "error"}); waiting.current?.resolve(false); waiting.current = null; }
      }
      if (!stopped) timer = setTimeout(() => void poll(), 250);
    }
    void poll();
    return () => { stopped = true; clearTimeout(timer); waiting.current?.resolve(false); waiting.current = null; };
  }, [api]);
  useEffect(() => {
    if (!notice) return;
    if (!notice.localOnly) void api.notify({ message: notice.message, severity: notice.severity }).catch(() => undefined);
    const timer = setTimeout(() => setNotice(null), 5500);
    return () => clearTimeout(timer);
  }, [api, notice]);
  const dirty = useCallback((value: boolean) => { void api.dirty(value).catch(reason => setNotice({message: errorText(reason, "草稿状态同步失败，请保留此窗口。"), severity: "error"})); }, [api]);

  async function act(action: WindowsChannelAction, binding = current.current?.binding): Promise<boolean> {
    if (working.current || binding === undefined || failed) return false;
    working.current = true; setPending(true);
    try {
      const ticket = await api.act(binding, action);
      // The completion is retained by the host, including if the owner was fast
      // enough to finish before the next poll installed this waiter.
      const ok = await new Promise<boolean>(resolve => { waiting.current = { id: ticket, resolve }; });
      if (!ok) setNotice({message: "操作未完成或已取消；主窗口通知中保留了具体原因。请核对后再试。", severity: "info", localOnly: true});
      return ok;
    } catch (reason) { setNotice({message: errorText(reason, "操作未提交，请核对连接后重试。"), severity: "error"}); return false; }
    finally { working.current = false; setPending(false); }
  }
  async function copy(text: string) {
    try { await api.copy(text); setNotice({message: "已复制到剪贴板。", severity: "info"}); }
    catch (reason) { setNotice({message: errorText(reason, "复制失败，请缩小选择范围。"), severity: "error"}); }
  }
  const connected = view?.connected && !failed;
  const busy = pending || view?.busy !== null;
  return <div className="windows-channel-window" data-testid="windows-channel-window">
    <header className="windows-channel-titlebar" data-tauri-drag-region>
      <strong data-tauri-drag-region>通道与传输</strong>
      <span data-tauri-drag-region>{view?.hostname ?? "正在连接工作台…"}</span>
      <span className={`wir-tag ${connected ? "is-good" : "is-caution"}`}>{connected ? "已连接" : "未连接"}</span>
      <WindowControls />
    </header>
    <nav className="windows-channel-tabs" role="tablist" aria-label="任务与传输" onKeyDown={event => {
      const index = CHANNEL_TABS.indexOf(tab);
      const next = event.key === "ArrowRight" ? (index + 1) % 4 : event.key === "ArrowLeft" ? (index + 3) % 4 : event.key === "Home" ? 0 : event.key === "End" ? 3 : null;
      if (next === null) return;
      event.preventDefault(); setTab(CHANNEL_TABS[next]!);
      event.currentTarget.querySelectorAll<HTMLButtonElement>("button")[next]?.focus();
    }}>
      {CHANNEL_TABS.map(key => <button type="button" key={key} id={`${id}-${key}`} role="tab" aria-selected={tab === key} aria-controls={`${id}-panel`} tabIndex={tab === key ? 0 : -1} onClick={() => setTab(key)}>{LABELS[key]}{key === "files" && view?.files.length ? <em>{view.files.length}</em> : key === "tasks" && view?.busy ? <em>1</em> : null}</button>)}
      <span role="status">{view?.busy ?? (pending ? "正在提交操作…" : "当前无进行中的任务")}</span>
    </nav>
    <main className={`windows-channel-body is-${tab}`} id={`${id}-panel`} role="tabpanel" aria-labelledby={`${id}-${tab}`} tabIndex={0}>
      {view ? <>
        <Activity mode={tab === "tasks" ? "visible" : "hidden"}>
          <section className="wir-task-panel">
            <h2>任务进度与采集记录</h2>
            <div className="wir-task-current" role="status"><strong>{view.busy ?? "当前没有进行中的任务"}</strong>{view.batch ? <><span>{view.batch.done} / {view.batch.total}</span><button type="button" className="win-ir-btn" disabled={view.batch.stopping || pending} onClick={() => void act({ kind: "cancel-batch" })}>{view.batch.stopping ? "本项结束后停止…" : "停止后续采集"}</button></> : null}</div>
            <div className="wir-task-history" aria-label="核心模块采集记录">{view.history.map(row => <div key={row.key} className={row.error ? "has-error" : ""}><strong>{moduleLabel(row.key)}</strong><span>{row.error ? "上次采集失败" : row.time ? `采集于 ${collectedTime(row.time)}` : "尚未采集"}</span>{row.error ? <><p>{row.error}{row.time ? "；保留上一份成功结果。" : ""}</p><button type="button" className="win-ir-btn" disabled={busy || !connected} onClick={() => void act({ kind: "collect", key: row.key })}>重试{moduleLabel(row.key)}</button></> : null}</div>)}</div>
          </section>
        </Activity>
        <WinIrConsole panel={tab} status={{ messagesSent: view.messagesSent, messagesReceived: view.messagesReceived, recentLogs: view.logs, receivedFiles: view.files, registration: { registered: view.registered } }}
          busy={busy} sessionKey={connected ? String(current.current?.binding) : null} hostname={view.hostname}
          output={view.output} suggestion={view.suggestion} savedFiles={new Set(view.savedFiles)} canSave={view.canSave}
          onCopy={text => void copy(text)} onSave={fileId => void act({ kind: "save", fileId })}
          onSend={text => act({ kind: "send", text })} onRun={(command, binding) => act({ kind: "run", command }, Number(binding))}
          onUnregister={() => void act({ kind: "unregister" })} onDirtyChange={dirty} />
      </> : <p className="wir-empty">正在同步工作台…</p>}
    </main>
    <footer className="windows-channel-footer"><span>{failed ? "同步中断，操作已停用；请返回主窗口检查连接。" : "关闭此窗口只会收起；任务继续，草稿与输出保留到离开工作台。"}</span><span>操作结果保留在主窗口通知中</span></footer>
    {notice ? <div className="windows-channel-toast" role="status">{notice.message}<button type="button" aria-label="关闭提示" onClick={() => setNotice(null)}>×</button></div> : null}
  </div>;
}
