import { useEffect, useId, useRef, useState, type ReactNode } from "react";

/** A non-modal reader below the list; closing returns keyboard focus to that list. */
export function WinIrInspector({ title, tabs, onClose, reveal }:  {
  title: string; tabs: readonly { id: string; label: string; content: ReactNode }[]; onClose: () => void; reveal?: { id: string; request: number };
}) {
  const id = useId();
  const [active, setActive] = useState(tabs[0]!.id);
  const [height, setHeight] = useState(310);
  const drag = useRef<{ y: number; height: number } | null>(null);
  useEffect(() => { if (reveal) setActive(reveal.id); }, [reveal?.id, reveal?.request]);
  const current = tabs.find((tab) => tab.id === active) ?? tabs[0]!;
  function close(element: HTMLElement) {
    const table = element.closest(".wir-explorer")?.querySelector<HTMLElement>('table[role="grid"]');
    onClose(); requestAnimationFrame(() => table?.focus({ preventScroll: true }));
  }
  return <section className="wir-inspector" aria-label={`${title} 详情`} style={{ height }} onKeyDown={(event) => {
    if (event.key === "Escape") { event.stopPropagation(); close(event.currentTarget); }
  }}>
    <div role="separator" aria-label="调整底部详情高度" aria-orientation="horizontal" aria-valuenow={height} aria-valuemin={200} aria-valuemax={640} tabIndex={0} className="wir-row-resizer"
      onPointerDown={(event) => { drag.current = { y: event.clientY, height }; event.currentTarget.setPointerCapture(event.pointerId); }}
      onPointerMove={(event) => { if (drag.current) setHeight(Math.max(200, Math.min(640, drag.current.height + drag.current.y - event.clientY))); }}
      onPointerUp={() => { drag.current = null; }} onPointerCancel={() => { drag.current = null; }}
      onKeyDown={(event) => { if (["ArrowUp", "ArrowDown", "Home", "End"].includes(event.key)) { event.preventDefault(); const key = event.key; setHeight((before) => key === "Home" ? 200 : key === "End" ? 640 : Math.max(200, Math.min(640, before + (key === "ArrowUp" ? 30 : -30)))); } }} />
    <header><strong title={title}>{title}</strong><button type="button" className="wir-icon-button" aria-label="关闭详情" onClick={(event) => close(event.currentTarget)}>×</button></header>
    <div className="wir-detail-tabs" role="tablist" aria-label="详情内容">{tabs.map((tab, index) => <button type="button" key={tab.id} id={`${id}-${tab.id}`} role="tab" aria-controls={`${id}-panel`} aria-selected={current.id === tab.id} tabIndex={current.id === tab.id ? 0 : -1}
      onClick={() => setActive(tab.id)} onKeyDown={(event) => {
        if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
        event.preventDefault(); const next = event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : (index + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
        setActive(tabs[next]!.id); (event.currentTarget.parentElement?.children[next] as HTMLElement)?.focus();
      }}>{tab.label}</button>)}</div>
    <div id={`${id}-panel`} className="wir-inspector-content" role="tabpanel" aria-labelledby={`${id}-${current.id}`} tabIndex={0}>{current.content}</div>
  </section>;
}
