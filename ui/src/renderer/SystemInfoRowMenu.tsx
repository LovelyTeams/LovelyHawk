import {
  useCallback,
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
  type MouseEvent as ReactMouseEvent,
} from "react";

import type {
  SystemInfoRow,
  SystemInfoRowActionEntry,
  SystemInfoRowActions,
} from "../shared/system-info-contract";
import { ChevronIcon } from "./emergency-command-icons";
import { CopyIcon, InfoIcon } from "./file-icons";
import { menuMaxHeight, menuStep, placeMenu, placeSubmenu, refitMenu } from "./menu-placement";

/** The things the window can do by itself, without asking the target. */
export type SystemInfoRowLocalAction = "copy-cell" | "copy-row" | "detail";

export interface SystemInfoRowMenuProps {
  /** Where the menu was summoned, in client coordinates. */
  position: { x: number; y: number };
  row: SystemInfoRow;
  /** The cell under the cursor, or null when the click missed every cell. */
  cell: string | null;
  /** Null while the sidecar is still saying which actions apply. */
  actions: SystemInfoRowActions | null;
  error: string | null;
  onLocal: (action: SystemInfoRowLocalAction) => void;
  onAction: (action: SystemInfoRowActionEntry) => void;
  onDismiss: () => void;
}

/**
 * How long the pointer rests on a group before its submenu opens. Long enough
 * that crossing another group on the way into an open submenu does not swap
 * it; short enough that pointing at a group feels immediate.
 */
const HOVER_INTENT_MS = 140;

const ITEM_SELECTOR = ':scope > button[role="menuitem"]';
const TOP_LEVEL_SELECTOR = `${ITEM_SELECTOR}, :scope > .system-info-row-menu-groups > .system-info-row-menu-group > button[role="menuitem"]`;

type ArrowKey = "ArrowDown" | "ArrowUp" | "Home" | "End";

function isArrowKey(key: string): key is ArrowKey {
  return key === "ArrowDown" || key === "ArrowUp" || key === "Home" || key === "End";
}

/**
 * What can be done with the row the operator right-clicked.
 *
 * The local items are there at once. The rest arrive from the sidecar, which
 * decided them from the row it kept, already grouped; each group is one entry
 * here with its actions in a submenu, so a service's thirty actions read as
 * seven choices. Nothing here changes the target: a read-only item runs and
 * shows its output, and a change asks for a plan the operator still has to
 * confirm.
 */
export function SystemInfoRowMenu({
  position,
  row,
  cell,
  actions,
  error,
  onLocal,
  onAction,
  onDismiss,
}: SystemInfoRowMenuProps) {
  const ref = useRef<HTMLDivElement>(null);
  const idPrefix = useId();
  // Measured, then placed, before the browser paints. See menu-placement.ts.
  const [placed, setPlaced] = useState<{ x: number; y: number } | null>(null);
  const [ceiling, setCeiling] = useState<number | null>(null);
  // The group whose submenu is showing, where it sits, and whether the
  // keyboard opened it (and so expects focus inside).
  const [openGroup, setOpenGroup] = useState<string | null>(null);
  const [submenuAt, setSubmenuAt] = useState<{ x: number; y: number } | null>(null);
  const focusSubmenu = useRef(false);
  // Bumped on every keyboard open, so Enter on a group the pointer already
  // opened still moves focus in.
  const [focusRequest, setFocusRequest] = useState(0);
  const openGroupRef = useRef<string | null>(null);
  openGroupRef.current = openGroup;
  const hoverTimer = useRef<number | null>(null);

  const cancelHover = useCallback(() => {
    if (hoverTimer.current !== null) window.clearTimeout(hoverTimer.current);
    hoverTimer.current = null;
  }, []);

  const showGroup = useCallback((key: string | null, withFocus = false) => {
    cancelHover();
    focusSubmenu.current = withFocus && key !== null;
    if (focusSubmenu.current) setFocusRequest((count) => count + 1);
    if (openGroupRef.current !== key) setSubmenuAt(null);
    openGroupRef.current = key;
    setOpenGroup(key);
  }, [cancelHover]);

  const hoverGroup = useCallback((key: string | null) => {
    cancelHover();
    hoverTimer.current = window.setTimeout(() => showGroup(key), HOVER_INTENT_MS);
  }, [cancelHover, showGroup]);

  /** Closes the open submenu and puts focus back on the group that opened it. */
  const closeGroup = useCallback(() => {
    const key = openGroupRef.current;
    showGroup(null);
    if (key !== null) ref.current?.querySelector<HTMLElement>(`[data-group-key="${CSS.escape(key)}"]`)?.focus();
  }, [showGroup]);

  useEffect(() => cancelHover, [cancelHover]);

  useLayoutEffect(() => {
    const node = ref.current;
    if (node === null) return;
    const box = node.getBoundingClientRect();
    const viewport = { width: window.innerWidth, height: window.innerHeight };
    setPlaced(placeMenu(position, { width: box.width, height: box.height }, viewport));
    setCeiling(menuMaxHeight(viewport.height));
  }, [position, row]);

  // The target's actions arrive after the menu opened, and the menu was placed
  // for its three local items. Measure again once they land: it stays put while
  // it still fits, and otherwise moves so the new items are not cut off by the
  // bottom of the window.
  useLayoutEffect(() => {
    const node = ref.current;
    if (node === null) return;
    const box = node.getBoundingClientRect();
    const viewport = { width: window.innerWidth, height: window.innerHeight };
    setPlaced((current) => current === null
      ? current
      : refitMenu(current, position, { width: box.width, height: box.height }, viewport));
  }, [actions, error, position]);

  // New actions are a new list: whatever submenu was open belonged to the old one.
  useEffect(() => {
    showGroup(null);
  }, [actions, showGroup]);

  // Place the open submenu beside its group once the menu itself has a place.
  useLayoutEffect(() => {
    if (openGroup === null || placed === null) return;
    const node = ref.current;
    const parent = node?.querySelector<HTMLElement>(`[data-group-key="${CSS.escape(openGroup)}"]`);
    const submenu = parent?.nextElementSibling;
    if (parent === null || parent === undefined || !(submenu instanceof HTMLElement)) return;
    const anchor = parent.getBoundingClientRect();
    const box = submenu.getBoundingClientRect();
    const viewport = { width: window.innerWidth, height: window.innerHeight };
    setSubmenuAt(placeSubmenu(anchor, { width: box.width, height: box.height }, viewport));
  }, [openGroup, placed]);

  useEffect(() => {
    if (submenuAt === null || !focusSubmenu.current) return;
    focusSubmenu.current = false;
    const parent = openGroup === null
      ? null
      : ref.current?.querySelector<HTMLElement>(`[data-group-key="${CSS.escape(openGroup)}"]`);
    parent?.nextElementSibling?.querySelector<HTMLElement>(ITEM_SELECTOR)?.focus();
  }, [openGroup, submenuAt, focusRequest]);

  // Focus moves in once the menu has a place: until then it is hidden, and a
  // hidden button refuses focus, which left the keyboard on the page behind.
  const focusedOnOpen = useRef(false);
  useEffect(() => {
    if (placed === null || focusedOnOpen.current) return;
    focusedOnOpen.current = true;
    ref.current?.querySelector("button")?.focus();
  }, [placed]);

  useEffect(() => {
    function dismissOnOutside(event: MouseEvent): void {
      if (!(event.target instanceof Node) || ref.current?.contains(event.target) !== true) {
        onDismiss();
      }
    }
    function dismissOnEscape(event: KeyboardEvent): void {
      if (event.key !== "Escape") return;
      // One level at a time, as a native menu does.
      if (openGroupRef.current !== null) {
        event.preventDefault();
        event.stopPropagation();
        closeGroup();
        return;
      }
      onDismiss();
    }
    window.addEventListener("mousedown", dismissOnOutside, true);
    window.addEventListener("keydown", dismissOnEscape, true);
    return () => {
      window.removeEventListener("mousedown", dismissOnOutside, true);
      window.removeEventListener("keydown", dismissOnEscape, true);
    };
  }, [closeGroup, onDismiss]);

  function handleKeyDown(event: ReactKeyboardEvent<HTMLDivElement>): void {
    const target = event.target instanceof HTMLElement ? event.target : null;
    const menu = ref.current;
    if (target === null || menu === null) return;
    const submenu = target.closest<HTMLElement>(".system-info-row-submenu");
    if (isArrowKey(event.key)) {
      const items = [...(submenu ?? menu).querySelectorAll<HTMLElement>(submenu ? ITEM_SELECTOR : TOP_LEVEL_SELECTOR)];
      const next = items[menuStep(items.indexOf(target), items.length, event.key)];
      if (next !== undefined) {
        event.preventDefault();
        next.focus();
      }
      return;
    }
    const groupKey = target.dataset.groupKey;
    if (event.key === "ArrowRight" && submenu === null && groupKey !== undefined) {
      event.preventDefault();
      showGroup(groupKey, true);
    } else if (event.key === "ArrowLeft" && submenu !== null) {
      event.preventDefault();
      closeGroup();
    }
  }

  function toggleGroup(event: ReactMouseEvent<HTMLButtonElement>, key: string): void {
    // A click with no pointer behind it (Enter or Space) moves focus in, as
    // ArrowRight does; a pointer click leaves it where the pointer is.
    const fromKeyboard = event.detail === 0;
    if (openGroup === key && !fromKeyboard) showGroup(null);
    else showGroup(key, fromKeyboard);
  }

  const title = actions?.subject ?? row.cells.find((value) => value.trim().length > 0) ?? "";
  const groups = actions?.groups ?? [];
  return (
    <div
      ref={ref}
      className="system-info-row-menu"
      role="menu"
      data-testid="system-info-row-menu"
      onKeyDown={handleKeyDown}
      onScroll={(event) => {
        // The submenu is placed against where its group was; once the list
        // scrolls under it, it would point at the wrong line.
        if (event.target === ref.current && openGroupRef.current !== null) showGroup(null);
      }}
      style={{
        left: `${(placed ?? position).x}px`,
        top: `${(placed ?? position).y}px`,
        maxHeight: ceiling === null ? undefined : `${ceiling}px`,
        visibility: placed === null ? "hidden" : undefined,
      }}
    >
      {title.length > 0 ? <p className="system-info-row-menu-title" title={title}>{title}</p> : null}
      {cell !== null && cell.trim().length > 0 ? (
        <button type="button" role="menuitem" onMouseEnter={() => hoverGroup(null)} onClick={() => onLocal("copy-cell")}>
          <CopyIcon />复制这一格
        </button>
      ) : null}
      <button type="button" role="menuitem" onMouseEnter={() => hoverGroup(null)} onClick={() => onLocal("copy-row")}>
        <CopyIcon />复制整行
      </button>
      {row.detail ? (
        <button type="button" role="menuitem" onMouseEnter={() => hoverGroup(null)} onClick={() => onLocal("detail")}>
          <InfoIcon />查看详情
        </button>
      ) : null}
      {actions === null && error === null ? (
        <p className="system-info-row-menu-note" role="status">正在读取这一行能做什么…</p>
      ) : null}
      {error !== null ? <p className="system-info-row-menu-note is-error" role="alert">{error}</p> : null}
      {groups.length > 0 ? (
        <div className="system-info-row-menu-groups" role="none">
          {groups.map((group) => {
            const open = openGroup === group.key;
            const submenuId = `${idPrefix}-${group.key}`;
            const changes = group.actions.some((action) => action.kind === "change" || action.dangerous);
            return (
              <div key={group.key} className="system-info-row-menu-group" role="none">
                <button
                  type="button"
                  role="menuitem"
                  aria-haspopup="menu"
                  aria-expanded={open}
                  aria-controls={submenuId}
                  data-group-key={group.key}
                  className={`system-info-row-menu-parent${open ? " is-open" : ""}${changes ? " is-change" : ""}`}
                  onMouseEnter={() => hoverGroup(group.key)}
                  onClick={(event) => toggleGroup(event, group.key)}
                >
                  <span className="system-info-row-menu-label">{group.label}</span>
                  <span className="system-info-row-menu-count" aria-label={`${group.actions.length} 项`}>
                    {group.actions.length}
                  </span>
                  <ChevronIcon open={false} />
                </button>
                <div
                  id={submenuId}
                  className="system-info-row-submenu"
                  role="menu"
                  aria-label={group.label}
                  hidden={!open}
                  onMouseEnter={cancelHover}
                  style={{
                    left: submenuAt === null ? undefined : `${submenuAt.x}px`,
                    top: submenuAt === null ? undefined : `${submenuAt.y}px`,
                    maxHeight: ceiling === null ? undefined : `${ceiling}px`,
                    visibility: open && submenuAt === null ? "hidden" : undefined,
                  }}
                >
                  {group.actions.map((action) => (
                    <button
                      type="button"
                      role="menuitem"
                      key={action.key}
                      className={action.dangerous ? "is-dangerous" : action.kind === "change" ? "is-change" : ""}
                      onClick={() => onAction(action)}
                    >
                      {action.label}
                    </button>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      ) : null}
      {actions !== null && actions.groups.length === 0 ? (
        <p className="system-info-row-menu-note">这一行在目标机上没有可用的操作。</p>
      ) : null}
    </div>
  );
}
