import { createContext, useContext, useEffect, useRef, type ReactNode } from "react";
import type { AppNotification, NotificationSeverity } from "./notification-state";
import { isModalScrimActive, useModalScrim } from "./modal-scrim";
import "./notification-stack.css";

export type PublishNotification = (source: string, message: string, severity: NotificationSeverity, key?: string) => void;
export const NotificationOpenContext = createContext<(() => void) | null>(null);
export const NotificationContext = createContext<PublishNotification | null>(null);

/** Explicit operation feedback only. Task state, input validation and evidence stay in their views. */
export function TransientNotice({ source, message, severity = "info", children, inline = false }: {
  source: string; message: string; severity?: NotificationSeverity; children?: ReactNode; inline?: boolean;
}) {
  const publish = useContext(NotificationContext);
  const previous = useRef<string | null>(null);
  useEffect(() => {
    if (!message) { previous.current = null; return; }
    const key = `${source}\0${severity}\0${message}`;
    if (publish && message && previous.current !== key) { previous.current = key; publish(source, message, severity); }
  }, [publish, source, message, severity]);
  // Standalone editor windows and isolated component tests have no main-window center.
  return publish && !inline && !(severity === "error" && isModalScrimActive()) ? null : children ?? <p role={severity === "error" ? "alert" : "status"}>{message}</p>;
}

const LABELS = { info: "信息", success: "成功", warning: "提醒", error: "失败" };
export function NotificationCenter({ history, omitted, onClose, onClear, onRemove }: {
  history: readonly AppNotification[]; omitted: number; onClose: () => void; onClear: () => void; onRemove: (id: string) => void;
}) {
  useModalScrim();
  const root = useRef<HTMLElement>(null);
  const close = useRef<HTMLButtonElement>(null);
  const closeRef = useRef(onClose); closeRef.current = onClose;
  useEffect(() => {
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    close.current?.focus();
    function keydown(event: KeyboardEvent) {
      if (event.key === "Escape") { event.preventDefault(); event.stopPropagation(); closeRef.current(); }
      if (event.key !== "Tab") return;
      const buttons = Array.from(root.current?.querySelectorAll<HTMLElement>('button:not(:disabled), [tabindex="0"]') ?? []);
      const index = buttons.indexOf(document.activeElement as HTMLElement);
      if (index < 0 || (event.shiftKey ? index === 0 : index === buttons.length - 1)) { event.preventDefault(); (event.shiftKey ? buttons.at(-1) : buttons[0])?.focus(); }
    }
    document.addEventListener("keydown", keydown, true);
    return () => { document.removeEventListener("keydown", keydown, true); if (previous?.isConnected) previous.focus({preventScroll:true}); };
  }, []);
  return <div className="notification-center-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
    <section className="notification-center" role="dialog" aria-modal="true" aria-labelledby="notification-center-title" ref={root}>
      <header><div><h2 id="notification-center-title">通知</h2><p>本次运行的操作反馈 · {history.length} 条</p></div><button ref={close} type="button" className="notification-dismiss" aria-label="关闭通知中心" onClick={onClose}>×</button></header>
      <div className="notification-center-list" tabIndex={0} role="region" aria-label="通知记录">
        {!history.length ? <p className="notification-empty">暂无通知。操作结果将在这里保留，短提示消失后仍可查看。</p> : <ol>{history.map((item) => <li key={item.id} className={`notification-card is-${item.severity}`}>
          <span className="notification-marker" aria-hidden="true"/><div><strong>{item.source ?? "应用"} · {LABELS[item.severity]}</strong><time dateTime={new Date(item.createdAt ?? 0).toISOString()}>{new Date(item.createdAt ?? 0).toLocaleTimeString()}</time><p>{item.message}</p></div><button type="button" className="notification-dismiss" aria-label="移除此通知" onClick={() => onRemove(item.id)}>×</button>
        </li>)}</ol>}
      </div>
      <footer><span>{omitted ? `仅保留最近 64 条，已有 ${omitted} 条较早通知被移出。` : "通知仅在本次运行保留，不代替操作与证据记录。"}</span><button type="button" disabled={!history.length} onClick={onClear}>清空通知</button></footer>
    </section>
  </div>;
}
