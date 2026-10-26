import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from "react";

import type { WindowsRiskLevel } from "../shared/windows-incident-contract";
import { RISK_LABEL, RISK_ORDER, type RiskFilter } from "./win-ir-helpers";
import { useModalScrim } from "./modal-scrim";

/**
 * A page-level dialog: dims the window, keeps focus inside until closed,
 * closes on Escape and returns focus to where it was opened from.
 */
export function WinIrModal({ title, subtitle, onClose, children, actions, wide = false }: {
  title: string; subtitle?: string; onClose: () => void; children: ReactNode; actions?: ReactNode; wide?: boolean;
}) {
  useModalScrim();
  const root = useRef<HTMLElement>(null);
  const closeButton = useRef<HTMLButtonElement>(null);
  const closeRef = useRef(onClose); closeRef.current = onClose;
  const titleId = useId();
  useEffect(() => {
    const returnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    closeButton.current?.focus();
    function keydown(event: globalThis.KeyboardEvent) {
      if (event.key === "Escape") { event.preventDefault(); event.stopPropagation(); closeRef.current(); return; }
      if (event.key !== "Tab" || !root.current) return;
      const items = [...root.current.querySelectorAll<HTMLElement>('button:not([disabled]), input:not([disabled]), [tabindex="0"]')];
      const index = items.indexOf(document.activeElement as HTMLElement);
      if (index < 0 || (event.shiftKey ? index === 0 : index === items.length - 1)) { event.preventDefault(); (event.shiftKey ? items.at(-1) : items[0])?.focus(); }
    }
    function focusin(event: FocusEvent) {
      if (event.target instanceof Node && root.current && !root.current.contains(event.target)) closeButton.current?.focus();
    }
    document.addEventListener("keydown", keydown, true);
    document.addEventListener("focusin", focusin);
    return () => {
      document.removeEventListener("keydown", keydown, true);
      document.removeEventListener("focusin", focusin);
      if (returnFocus?.isConnected) returnFocus.focus({ preventScroll: true });
    };
  }, []);
  return <div className="wir-modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) closeRef.current(); }}>
    <section ref={root} className={`wir-modal${wide ? " is-wide" : ""}`} role="dialog" aria-modal="true" aria-labelledby={titleId}>
      <header>
        <div><h2 id={titleId} title={title}>{title}</h2>{subtitle ? <p>{subtitle}</p> : null}</div>
        <button ref={closeButton} type="button" className="wir-icon-button" aria-label="关闭" title="关闭（Esc）" onClick={onClose}>×</button>
      </header>
      <div className="wir-modal-body">{children}</div>
      {actions ? <footer>{actions}</footer> : null}
    </section>
  </div>;
}

/**
 * A vertical divider that resizes the column on its left: drag it, or focus it
 * and use ←/→ (Shift for larger steps) and Home/End.
 */
export function ColumnResizer({ label, width, min, max, onChange }: {
  label: string; width: number; min: number; max: number; onChange: (width: number) => void;
}) {
  const clamp = (value: number) => Math.round(Math.min(max, Math.max(min, value)));
  return <div className="wir-resizer" role="separator" aria-orientation="vertical" aria-label={label} aria-valuenow={width} aria-valuemin={min} aria-valuemax={max} tabIndex={0}
    style={{ left: width - 3 }}
    onPointerDown={(event) => {
      event.preventDefault();
      const start = event.clientX, from = width, target = event.currentTarget;
      target.setPointerCapture(event.pointerId);
      const move = (next: PointerEvent) => onChange(clamp(from + next.clientX - start));
      const up = () => { target.removeEventListener("pointermove", move); target.removeEventListener("pointerup", up); target.removeEventListener("pointercancel", up); };
      target.addEventListener("pointermove", move);
      target.addEventListener("pointerup", up);
      target.addEventListener("pointercancel", up);
    }}
    onKeyDown={(event) => {
      const step = event.shiftKey ? 48 : 16;
      const next = event.key === "ArrowLeft" ? width - step : event.key === "ArrowRight" ? width + step : event.key === "Home" ? min : event.key === "End" ? max : null;
      if (next === null) return;
      event.preventDefault();
      onChange(clamp(next));
    }} />;
}

/** Runs the handler once per cross-link request, when the module has data to resolve it against. */
export function useFocusRequest<T>(focus: { target: T; request: number } | null | undefined, ready: boolean, handle: (target: T) => void) {
  const handled = useRef<number | null>(null);
  useEffect(() => {
    if (!focus || !ready || handled.current === focus.request) return;
    handled.current = focus.request;
    handle(focus.target);
  });
}

export function CollectionWarnings({ warnings }: { warnings: readonly string[] }) {
  return warnings.length ? <details className="wir-collection-warnings"><summary>采集范围与缺口 · {warnings.length} 项</summary><ul>{warnings.map((warning, index) => <li key={index}>{warning}</li>)}</ul></details> : null;
}

export function RiskBadge({ level, label }: { level: WindowsRiskLevel; label?: string }) {
  return <span className={`wir-badge is-${level}`}>{label ?? RISK_LABEL[level]}</span>;
}

/** A table's risk cell: only marked records carry a badge, so the marked ones stand out. */
export function RiskCell({ level }: { level: WindowsRiskLevel }) {
  return level === "normal" ? <span className="wir-risk-none" title={RISK_LABEL.normal} aria-label={RISK_LABEL.normal}>—</span> : <RiskBadge level={level} />;
}

/** The source clock on one line; its full precision remains in the title and copied evidence. */
export function SourceTime({ value }: { value: string }) {
  const parts = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.\d+)?(Z|[+-]\d{2}:\d{2})?$/u.exec(value);
  return parts ? <span className="wir-source-time" title={value}><span>{parts[1]} {parts[2]}</span>{parts[3] ? <small>{parts[3] === "Z" ? "UTC" : parts[3]}</small> : null}</span> : <span className="wir-clip" title={value}>{value || "未取得"}</span>;
}

export interface StatCard {
  label: string;
  value: string | number;
  hint?: string;
  tone?: WindowsRiskLevel | "info";
  onClick?: () => void;
}

/** The figures at the top of a module, coloured by what they mean. */
export function StatStrip({ cards }: { cards: readonly StatCard[] }) {
  return (
    <div className="wir-stats">
      {cards.map((card) => {
        const body = (
          <>
            <span>{card.label}</span>
            <strong>{card.value}</strong>
            {card.hint ? <small>{card.hint}</small> : null}
          </>
        );
        const className = `wir-stat is-${card.tone ?? "info"}`;
        return card.onClick ? (
          <button key={card.label} type="button" className={className} onClick={card.onClick}>{body}</button>
        ) : (
          <div key={card.label} className={className}>{body}</div>
        );
      })}
    </div>
  );
}

export interface ChipOption<T extends string> {
  value: T;
  label: string;
  count?: number | undefined;
  tone?: WindowsRiskLevel | "info";
}

export function FilterChips<T extends string>({ label, options, value, onChange }: {
  label: string;
  options: readonly ChipOption<T>[];
  value: T;
  onChange: (value: T) => void;
}) {
  return (
    <div className="wir-chips" role="group" aria-label={label}>
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          className={`wir-chip${option.tone ? ` is-${option.tone}` : ""}`}
          aria-pressed={value === option.value}
          onClick={() => onChange(option.value)}
        >
          {option.label}
          {option.count === undefined ? null : <em>{option.count}</em>}
        </button>
      ))}
    </div>
  );
}

export function riskChipOptions(counts: Record<RiskFilter, number>): ChipOption<RiskFilter>[] {
  return [
    { value: "all", label: "全部", count: counts.all },
    { value: "high", label: "高危", count: counts.high, tone: "high" },
    { value: "medium", label: "中危", count: counts.medium, tone: "medium" },
    { value: "low", label: "关注", count: counts.low, tone: "low" },
    { value: "normal", label: "未标记", count: counts.normal, tone: "normal" },
  ];
}

export function SearchBox({ value, onChange, placeholder }: { value: string; onChange: (value: string) => void; placeholder: string }) {
  return (
    <label className="wir-search">
      <svg viewBox="0 0 16 16" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" aria-hidden="true">
        <circle cx="7" cy="7" r="4.6" /><path d="m10.6 10.6 3.4 3.4" />
      </svg>
      <input
        type="search"
        value={value}
        aria-label={placeholder}
        placeholder={placeholder}
        spellCheck={false}
        onChange={(event) => onChange(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === "Escape" && value !== "") {
            event.stopPropagation();
            onChange("");
          }
        }}
      />
    </label>
  );
}

export interface Column<T> {
  key: string;
  label: string;
  width?: string;
  mono?: boolean;
  render: (row: T) => ReactNode;
  /** Sorting value; the column cannot be sorted without one. */
  sort?: ((row: T) => string | number) | undefined;
}

export function riskSort<T>(risk: (row: T) => WindowsRiskLevel) {
  return (row: T) => RISK_ORDER[risk(row)];
}

interface DataTableProps<T> {
  label: string;
  columns: readonly Column<T>[];
  rows: readonly T[];
  rowKey: (row: T) => string;
  selectedKey: string | null;
  onSelect: (row: T | null) => void;
  onActivate?: (row: T) => void;
  rowRisk?: (row: T) => WindowsRiskLevel;
  rowClass?: (row: T) => string;
  rowGroup?: (row: T) => number;
  empty: ReactNode;
  defaultSort?: { key: string; descending: boolean } | undefined;
  pageSize?: number | undefined;
  /** Other keys on the selected row; return true when handled. */
  onRowKey?: ((key: string, row: T) => boolean) | undefined;
  keyHint?: string;
  /** Columns left out of the view; sorting by them still applies. */
  hiddenColumns?: ReadonlySet<string> | undefined;
}

/**
 * A sortable list with one selected row: click a header to sort, ↑/↓ to move,
 * Enter to open, Escape to clear the selection.
 */
export function DataTable<T>({ label, columns, rows, rowKey, selectedKey, onSelect, onActivate, rowRisk, rowClass, rowGroup, empty, defaultSort, pageSize = 100, onRowKey, keyHint = "↑↓ 切换", hiddenColumns }: DataTableProps<T>) {
  const shown = hiddenColumns ? columns.filter((column) => !hiddenColumns.has(column.key)) : columns;
  const [sort, setSort] = useState<{ key: string; descending: boolean } | null>(defaultSort ?? null);
  const bodyRef = useRef<HTMLDivElement>(null);
  const tableId = useId();
  const [page, setPage] = useState(0);
  const sorted = useMemo(() => {
    const column = columns.find((candidate) => candidate.key === sort?.key);
    if (column?.sort === undefined || sort === null) return rows;
    const value = column.sort;
    const direction = sort.descending ? -1 : 1;
    return [...rows].sort((a, b) => {
      const group = rowGroup ? rowGroup(a) - rowGroup(b) : 0;
      if (group !== 0) return group;
      const left = value(a);
      const right = value(b);
      return (typeof left === "number" && typeof right === "number"
        ? left - right
        : String(left).localeCompare(String(right), "zh-CN", { numeric: true })) * direction;
    });
  }, [columns, rows, rowGroup, sort]);
  const pageCount = Math.max(1, Math.ceil(sorted.length / pageSize));
  const pageIndex = Math.min(page, pageCount - 1);
  const pageRows = sorted.slice(pageIndex * pageSize, (pageIndex + 1) * pageSize);
  useEffect(() => {
    if (selectedKey === null) return;
    const index = sorted.findIndex((row) => rowKey(row) === selectedKey);
    if (index >= 0) setPage(Math.floor(index / pageSize));
    else onSelect(null);
  }, [onSelect, rowKey, selectedKey, sorted]);

  useEffect(() => {
    if (selectedKey === null) return;
    const row = bodyRef.current?.querySelector<HTMLElement>(`[data-row-key="${CSS.escape(selectedKey)}"]`);
    row?.scrollIntoView({ block: "nearest" });
  }, [selectedKey]);

  function onKeyDown(event: KeyboardEvent<HTMLTableElement>) {
    if (event.target instanceof HTMLElement && event.target.closest("button, input, select")) return;
    if (sorted.length === 0) return;
    const index = selectedKey === null ? -1 : sorted.findIndex((row) => rowKey(row) === selectedKey);
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const next = event.key === "ArrowDown" ? Math.min(sorted.length - 1, index + 1) : Math.max(0, index - 1);
      onSelect(sorted[next] ?? null);
    } else if (event.key === "Enter" && index >= 0 && onActivate) {
      event.preventDefault();
      onActivate(sorted[index]!);
    } else if (event.key === "Escape" && selectedKey !== null) {
      event.preventDefault();
      event.stopPropagation();
      onSelect(null);
    } else if (index >= 0 && onRowKey?.(event.key, sorted[index]!)) {
      event.preventDefault();
    }
  }

  if (rows.length === 0) return <div className="wir-empty">{empty}</div>;
  return (
    <div className="wir-table-container">
    <div className="wir-table" ref={bodyRef}>
      <table role="grid" tabIndex={0} aria-label={`${label}：↑↓ 选择，Enter 打开`} aria-rowcount={sorted.length + 1}
        aria-activedescendant={selectedKey !== null && pageRows.some((row) => rowKey(row) === selectedKey) ? `${tableId}-row-${pageRows.findIndex((row) => rowKey(row) === selectedKey)}` : undefined} onKeyDown={onKeyDown}>
        <colgroup>{shown.map((column) => <col key={column.key} style={column.width ? { width: column.width } : undefined} />)}</colgroup>
        <thead>
          <tr>
            {shown.map((column) => {
              const active = sort?.key === column.key;
              return (
                <th key={column.key} aria-sort={active ? (sort.descending ? "descending" : "ascending") : undefined}>
                  {column.sort ? (
                    <button
                      type="button"
                      className={active ? "is-sorted" : undefined}
                      onClick={() => setSort(active ? { key: column.key, descending: !sort.descending } : { key: column.key, descending: column.key === "risk" })}
                    >
                      {column.label}
                      <i aria-hidden="true">{active ? (sort.descending ? "↓" : "↑") : "↕"}</i>
                    </button>
                  ) : column.label}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {pageRows.map((row, index) => {
            const key = rowKey(row);
            const risk = rowRisk?.(row);
            const classes = [risk ? `is-${risk}` : "", key === selectedKey ? "is-selected" : "", rowClass?.(row) ?? ""].filter(Boolean).join(" ");
            return (
              <tr
                key={key}
                id={`${tableId}-row-${index}`}
                aria-rowindex={pageIndex * pageSize + index + 2}
                data-row-key={key}
                className={classes || undefined}
                aria-selected={key === selectedKey}
                onClick={() => onSelect(row)}
                onDoubleClick={() => onActivate?.(row)}
              >
                {shown.map((column) => (
                  <td key={column.key} className={column.mono ? "is-mono" : undefined}>{column.render(row)}</td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
    <div className="wir-table-footer">
      <span>{sorted.length} 条记录 · 点击查看详情 · {keyHint}</span>
      {pageCount > 1 ? <div><button type="button" className="wir-icon-button" aria-label="上一页" disabled={pageIndex === 0} onClick={() => { onSelect(null); setPage(pageIndex - 1); }}>‹</button><span>{pageIndex + 1} / {pageCount}</span><button type="button" className="wir-icon-button" aria-label="下一页" disabled={pageIndex + 1 >= pageCount} onClick={() => { onSelect(null); setPage(pageIndex + 1); }}>›</button></div> : null}
    </div>
    </div>
  );
}

export interface DetailField {
  label: string;
  value: string;
  mono?: boolean;
}

/** The selected record's fields beside the list, with copy and actions. */
export function DetailPane({ title, subtitle, risk, reasons, fields, children, actions, onClose, onCopy, copyText, tabs, className }: {
  title: string;
  subtitle?: string;
  risk?: WindowsRiskLevel;
  reasons?: readonly string[];
  fields: readonly DetailField[];
  children?: ReactNode;
  actions?: ReactNode;
  onClose: () => void;
  onCopy?: (text: string) => void;
  /** Copied instead of the visible fields, for panes that show one page at a time. */
  copyText?: string;
  tabs?: ReactNode;
  className?: string;
}) {
  const copyAll = () => onCopy?.(copyText ?? [`${title}${subtitle ? ` · ${subtitle}` : ""}`, ...fields.map((field) => `${field.label}：${field.value}`), ...(reasons ?? []).map((reason) => `风险：${reason}`)].join("\n"));
  return (
    <aside className={`wir-detail${className ? ` ${className}` : ""}`} aria-label={`${title} 详情`} onKeyDown={(event) => {
      if (event.key === "Escape") {
        const table = (event.currentTarget.closest(".wir-explorer, .wir-module") ?? event.currentTarget.parentElement)?.querySelector<HTMLElement>('table[role="grid"]');
        event.stopPropagation(); onClose(); table?.focus();
      }
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "c" && !window.getSelection()?.toString() && onCopy) { event.preventDefault(); copyAll(); }
    }}>
      <header>
        <div>
          {risk ? <RiskBadge level={risk} /> : null}
          <h3 title={title}>{title}</h3>
          {subtitle ? <p>{subtitle}</p> : null}
        </div>
        <button type="button" className="wir-icon-button" aria-label="关闭详情" title="关闭详情（Esc）" onClick={onClose}>×</button>
      </header>
      {tabs}
      {reasons && reasons.length > 0 ? (
        <ul className={`wir-reasons is-${risk ?? "low"}`}>{reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>
      ) : null}
      {fields.length ? <dl>
        {fields.map((field) => (
          <div key={field.label}>
            <dt>{field.label}</dt>
            <dd className={field.mono ? "is-mono" : undefined}>{field.value === "" ? "—" : field.value}</dd>
          </div>
        ))}
      </dl> : null}
      {children}
      <footer>
        {onCopy ? <button type="button" className="win-ir-btn" onClick={copyAll}>复制全部字段</button> : null}
        {actions}
      </footer>
    </aside>
  );
}

/** Pages inside a detail pane; ←/→ move between them. */
export function DetailTabs<T extends string>({ label, options, value, onChange }: {
  label: string;
  options: readonly ChipOption<T>[];
  value: T;
  onChange: (value: T) => void;
}) {
  const id = useId();
  return (
    <div className="wir-detail-tabs" role="tablist" aria-label={label} onKeyDown={(event) => {
      if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
      event.preventDefault();
      event.stopPropagation();
      const index = options.findIndex((option) => option.value === value);
      const next = options[(index + (event.key === "ArrowRight" ? 1 : options.length - 1)) % options.length]!;
      onChange(next.value);
      event.currentTarget.querySelector<HTMLElement>(`#${CSS.escape(`${id}-${next.value}`)}`)?.focus();
    }}>
      {options.map((option) => (
        <button key={option.value} id={`${id}-${option.value}`} type="button" role="tab" aria-selected={value === option.value} tabIndex={value === option.value ? 0 : -1} onClick={() => onChange(option.value)}>
          {option.label}
          {option.count === undefined ? null : <em>{option.count}</em>}
        </button>
      ))}
    </div>
  );
}

export function ModuleHeader({ title, description, collectedAt, busy, actionLabel, onCollect, extra }: {
  title: string;
  description: string;
  collectedAt: string | null;
  busy: boolean;
  actionLabel: string;
  onCollect: () => void;
  extra?: ReactNode;
}) {
  return (
    <header className="wir-module-head">
      <div>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      <div className="wir-module-actions">
        {collectedAt ? <span className="wir-collected">采集于 {collectedAt}</span> : <span className="wir-collected">尚未采集</span>}
        {extra}
        <button type="button" className="win-ir-btn is-primary" disabled={busy} onClick={onCollect}>{actionLabel}</button>
      </div>
    </header>
  );
}
