import { useEffect, useMemo, useRef, useState, type ReactElement } from "react";

import type { PageDescriptor, PageGroup } from "../shared/contract";
import { NavIcon } from "./nav-icons";

export interface SidebarNavProps {
  pages: readonly PageDescriptor[];
  groupLabels: Record<PageGroup, string>;
  activePageId: string;
  /** Pages that need a target are marked while nothing is connected. */
  targetConnected: boolean;
  busy: boolean;
  /** Icon-only rail: groups give way to one column of page icons. */
  rail: boolean;
  onNavigate: (pageId: string) => void;
}

const GROUP_ICON_PROPS = {
  viewBox: "0 0 16 16",
  width: 14,
  height: 14,
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.5,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
  "aria-hidden": true,
};

const GROUP_ICONS: Record<PageGroup, () => ReactElement> = {
  target: () => (
    <svg {...GROUP_ICON_PROPS}><circle cx="8" cy="8" r="5.6" /><circle cx="8" cy="8" r="2.2" /><path d="M8 1v2M8 13v2M1 8h2M13 8h2" /></svg>
  ),
  triage: () => (
    <svg {...GROUP_ICON_PROPS}><path d="M8 1.8 13.4 4v3.8c0 3-2.2 5.2-5.4 6.4C4.8 13 2.6 10.8 2.6 7.8V4Z" /><path d="M8 5v3.4M8 10.6h.01" /></svg>
  ),
  investigation: () => (
    <svg {...GROUP_ICON_PROPS}><circle cx="7" cy="7" r="4.4" /><path d="m10.4 10.4 3.8 3.8M5.2 7h3.6" /></svg>
  ),
  operations: () => (
    <svg {...GROUP_ICON_PROPS}><path d="M9.8 2.4a3.4 3.4 0 0 0-3.6 4.4L2.2 10.8a1.4 1.4 0 0 0 2 2l4-4a3.4 3.4 0 0 0 4.4-3.6l-2 2-1.8-.4-.4-1.8Z" /></svg>
  ),
  intelligence: () => (
    <svg {...GROUP_ICON_PROPS}><path d="M8 1.8 9.3 6l4 1.3-4 1.3L8 12.8 6.7 8.6l-4-1.3 4-1.3Z" /><path d="M12.6 11.4v3M11.1 12.9h3" /></svg>
  ),
};

/** The icon square of a navigation group, shared with the Windows workbench navigation. */
export function NavGroupIcon({ group }: { group: PageGroup }) {
  const Icon = GROUP_ICONS[group];
  return <Icon />;
}

export function SearchIcon() {
  return (
    <svg viewBox="0 0 16 16" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" aria-hidden="true">
      <circle cx="7" cy="7" r="4.6" /><path d="m10.6 10.6 3.4 3.4" />
    </svg>
  );
}

export function ChevronIcon() {
  return (
    <svg className="nav-group-chevron" viewBox="0 0 16 16" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="m6 3.5 4.5 4.5L6 12.5" />
    </svg>
  );
}

function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  return target.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName);
}

/**
 * The main navigation: pages in their groups, each group folding on its own
 * header, with a filter that `/` focuses. Every page stays one click away — a
 * folded group only hides its rows, the filter only narrows them, and the
 * active page's group always opens.
 */
export function SidebarNav({ pages, groupLabels, activePageId, targetConnected, busy, rail, onNavigate }: SidebarNavProps) {
  const [closed, setClosed] = useState<ReadonlySet<PageGroup>>(() => new Set());
  const [query, setQuery] = useState("");
  const searchRef = useRef<HTMLInputElement>(null);
  const needle = query.trim().toLowerCase();

  const activeGroup = pages.find((page) => page.id === activePageId)?.group;
  useEffect(() => {
    if (activeGroup === undefined) return;
    setClosed((current) => {
      if (!current.has(activeGroup)) return current;
      const next = new Set(current);
      next.delete(activeGroup);
      return next;
    });
  }, [activeGroup, activePageId]);

  useEffect(() => {
    if (rail) return undefined;
    function onKey(event: KeyboardEvent) {
      if (event.key !== "/" || event.ctrlKey || event.metaKey || event.altKey || isTypingTarget(event.target)) return;
      if (document.querySelector('[aria-modal="true"]') !== null) return;
      const input = searchRef.current;
      if (input === null || input.closest("[inert]") !== null) return;
      event.preventDefault();
      input.focus();
      input.select();
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [rail]);

  const visible = useMemo(() => {
    const matches = (page: PageDescriptor) =>
      needle === "" || page.title.toLowerCase().includes(needle) || page.summary.toLowerCase().includes(needle);
    return (Object.keys(groupLabels) as PageGroup[])
      .map((group) => ({ group, pages: pages.filter((page) => page.group === group && matches(page)) }));
  }, [groupLabels, needle, pages]);
  const matchCount = visible.reduce((sum, entry) => sum + entry.pages.length, 0);

  function toggle(group: PageGroup) {
    setClosed((current) => {
      const next = new Set(current);
      if (next.has(group)) next.delete(group);
      else next.add(group);
      return next;
    });
  }

  return (
    <>
      {rail ? null : (
        <div className="sidebar-search">
          <SearchIcon />
          <input
            ref={searchRef}
            type="search"
            value={query}
            data-testid="sidebar-filter"
            aria-label="筛选页面"
            placeholder="筛选页面"
            autoComplete="off"
            spellCheck={false}
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Escape" && query !== "") {
                event.preventDefault();
                event.stopPropagation();
                setQuery("");
              }
            }}
          />
          {query === "" ? <kbd aria-hidden="true">/</kbd> : (
            <button type="button" className="sidebar-search-clear" aria-label="清除筛选" title="清除筛选" onClick={() => { setQuery(""); searchRef.current?.focus(); }}>×</button>
          )}
        </div>
      )}
      <nav aria-label="主导航" aria-busy={busy}>
        {needle !== "" && matchCount === 0 ? (
          <p className="nav-empty" role="status">没有名称或说明包含“{query.trim()}”的页面。</p>
        ) : null}
        {visible.map(({ group, pages: groupPages }) => {
          if (groupPages.length === 0) return null;
          const open = rail || needle !== "" || !closed.has(group);
          const Icon = GROUP_ICONS[group];
          const itemsId = `nav-group-items-${group}`;
          return (
            <section className={`nav-group nav-group--${group}${open ? " is-open" : ""}`} key={group} aria-label={groupLabels[group]}>
              {rail ? null : (
                <button
                  type="button"
                  className="nav-group-row"
                  aria-expanded={open}
                  aria-controls={itemsId}
                  disabled={needle !== ""}
                  onClick={() => toggle(group)}
                >
                  <span className="nav-group-icon"><Icon /></span>
                  <span className="nav-group-label">{groupLabels[group]}</span>
                  <span className="nav-group-count" aria-label={`${groupPages.length} 个页面`}>{groupPages.length}</span>
                  <ChevronIcon />
                </button>
              )}
              <div className="nav-group-items" id={itemsId} inert={open ? undefined : true}>
                <div className="nav-group-items-inner">
                  {groupPages.map((page) => {
                    const waiting = !targetConnected && page.capability === "connected-target";
                    const active = page.id === activePageId;
                    return (
                      <button
                        className={["nav-item", active ? "active" : "", waiting ? "needs-target" : ""].filter(Boolean).join(" ")}
                        key={page.id}
                        type="button"
                        disabled={busy}
                        aria-current={active ? "page" : undefined}
                        aria-label={rail ? page.title : undefined}
                        title={waiting ? `${page.title}：连接目标后可用` : rail ? page.title : page.summary}
                        onClick={() => onNavigate(page.id)}
                      >
                        <span className="nav-icon"><NavIcon pageId={page.id} glyph={page.icon} /></span>
                        <strong>{page.title}</strong>
                        {waiting ? <i className="nav-needs-target" aria-label="需要连接目标" /> : null}
                      </button>
                    );
                  })}
                </div>
              </div>
            </section>
          );
        })}
      </nav>
    </>
  );
}
