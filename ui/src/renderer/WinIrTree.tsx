import { useEffect, useMemo, useState } from "react";

export interface TreeLocation { label: string; path: string }

/** Lazy directory/key navigation. Only successful reads populate the tree. */
export function WinIrTree({ label, roots, currentPath, ancestors, children, disabled, onNavigate }: {
  label: string; roots: readonly TreeLocation[]; currentPath: string | null;
  ancestors: readonly TreeLocation[]; children: readonly TreeLocation[];
  disabled: boolean; onNavigate: (path: string) => void;
}) {
  const [cache, setCache] = useState<Map<string, readonly TreeLocation[]>>(new Map());
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [focus, setFocus] = useState(roots[0]?.path ?? "");
  const key = (path: string) => path.replace(/\\+$/u, "").toLowerCase();
  const signature = JSON.stringify({ currentPath, children, ancestors });
  useEffect(() => {
    if (!currentPath) return;
    setCache((previous) => {
      const next = new Map(previous);
      for (let i = 0; i + 1 < ancestors.length; i++) {
        const parent = ancestors[i]!; const child = ancestors[i + 1]!;
        const known = next.get(key(parent.path)) ?? [];
        if (!known.some((entry) => key(entry.path) === key(child.path))) next.set(key(parent.path), [...known, child]);
      }
      next.delete(key(currentPath));
      next.set(key(currentPath), children);
      while (next.size > 64) next.delete(next.keys().next().value!);
      return next;
    });
    setExpanded((previous) => new Set([...previous, ...ancestors.map((item) => key(item.path)), key(currentPath)]));
    setFocus(currentPath);
  }, [signature]);
  const rows = useMemo(() => {
    const result: Array<TreeLocation & { depth: number }> = [];
    const stack = roots.slice().reverse().map((entry) => ({ ...entry, depth: 1 }));
    const seen = new Set<string>();
    while (stack.length && result.length < 2000) {
      const row = stack.pop()!; const id = key(row.path);
      if (seen.has(id)) continue;
      seen.add(id); result.push(row);
      if (expanded.has(id)) for (const child of (cache.get(id) ?? []).slice().reverse()) stack.push({ ...child, depth: row.depth + 1 });
    }
    return result;
  }, [cache, expanded, roots]);
  function toggle(path: string) {
    const id = key(path);
    if (!cache.has(id)) { onNavigate(path); return; }
    setExpanded((previous) => { const next = new Set(previous); if (next.has(id)) next.delete(id); else next.add(id); return next; });
  }
  const hasFocus = rows.some((row) => key(row.path) === key(focus));
  return <div className="wir-tree-scroll"><div role="tree" aria-label={label} className="wir-tree">
    {rows.map((row, index) => {
      const id = key(row.path); const known = cache.get(id); const hasChildren = known === undefined || known.length > 0;
      return <div key={id} role="treeitem" aria-level={row.depth} aria-selected={currentPath !== null && key(currentPath) === id}
        aria-expanded={hasChildren ? expanded.has(id) : undefined} aria-disabled={disabled}
        tabIndex={key(focus) === id || (!hasFocus && index === 0) ? 0 : -1}
        className="wir-tree-row" style={{ paddingInlineStart: `${8 + Math.min(row.depth - 1, 16) * 15}px` }} title={row.path}
        onFocus={() => setFocus(row.path)} onClick={() => { if (!disabled) onNavigate(row.path); }}
        onKeyDown={(event) => {
          const move = (target: number) => { const next = event.currentTarget.parentElement?.children[target] as HTMLElement | undefined; next?.focus(); };
          if (event.key === "ArrowDown") { event.preventDefault(); move(Math.min(index + 1, rows.length - 1)); }
          if (event.key === "ArrowUp") { event.preventDefault(); move(Math.max(index - 1, 0)); }
          if (event.key === "Home") { event.preventDefault(); move(0); }
          if (event.key === "End") { event.preventDefault(); move(rows.length - 1); }
          if (disabled) return;
          if (event.key === "Enter" || event.key === " ") { event.preventDefault(); onNavigate(row.path); }
          if (event.key === "ArrowRight") { event.preventDefault(); if (!expanded.has(id)) toggle(row.path); else move(Math.min(index + 1, rows.length - 1)); }
          if (event.key === "ArrowLeft") { event.preventDefault(); if (expanded.has(id)) toggle(row.path); else { let parent = index - 1; while (parent >= 0 && rows[parent]!.depth >= row.depth) parent--; if (parent >= 0) move(parent); } }
        }}>
        <span className="wir-tree-chevron" aria-hidden="true" onClick={(event) => { event.stopPropagation(); if (!disabled && hasChildren) toggle(row.path); }}>{hasChildren ? expanded.has(id) ? "⌄" : "›" : ""}</span>
        <svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" aria-hidden="true"><path d="M2 4h5l2 2h5v7H2Z" /></svg>
        <span>{row.label}</span>
      </div>;
    })}
  </div>{rows.length === 2000 ? <small>树中仅显示前 2,000 项；可用地址栏继续定位。</small> : null}</div>;
}
