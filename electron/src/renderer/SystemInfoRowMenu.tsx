import { useEffect, useLayoutEffect, useRef, useState } from "react";

import type {
  SystemInfoRow,
  SystemInfoRowActionEntry,
  SystemInfoRowActions,
} from "../shared/system-info-contract";
import { CopyIcon, InfoIcon } from "./file-icons";
import { menuMaxHeight, placeMenu } from "./menu-placement";

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
 * What can be done with the row the operator right-clicked.
 *
 * The local items are there at once. The rest arrive from the sidecar, which
 * decided them from the row it kept, and fill in below without the menu
 * moving. Nothing here changes the target: a read-only item runs and shows its
 * output, and a change asks for a plan the operator still has to confirm.
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
  // Measured, then placed, before the browser paints. See menu-placement.ts.
  const [placed, setPlaced] = useState<{ x: number; y: number } | null>(null);
  const [ceiling, setCeiling] = useState<number | null>(null);

  useLayoutEffect(() => {
    const node = ref.current;
    if (node === null) return;
    const box = node.getBoundingClientRect();
    const viewport = { width: window.innerWidth, height: window.innerHeight };
    setPlaced(placeMenu(position, { width: box.width, height: box.height }, viewport));
    setCeiling(menuMaxHeight(viewport.height));
    // Placement is decided once, when the menu opens: the actions that arrive
    // later grow it downwards inside its own scroll rather than moving it.
  }, [position, row]);

  useEffect(() => {
    ref.current?.querySelector("button")?.focus();
    function dismissOnOutside(event: MouseEvent): void {
      if (!(event.target instanceof Node) || ref.current?.contains(event.target) !== true) {
        onDismiss();
      }
    }
    function dismissOnEscape(event: KeyboardEvent): void {
      if (event.key === "Escape") onDismiss();
    }
    window.addEventListener("mousedown", dismissOnOutside, true);
    window.addEventListener("keydown", dismissOnEscape, true);
    return () => {
      window.removeEventListener("mousedown", dismissOnOutside, true);
      window.removeEventListener("keydown", dismissOnEscape, true);
    };
  }, [onDismiss]);

  const title = actions?.subject ?? row.cells.find((value) => value.trim().length > 0) ?? "";
  return (
    <div
      ref={ref}
      className="system-info-row-menu"
      role="menu"
      data-testid="system-info-row-menu"
      style={{
        left: `${(placed ?? position).x}px`,
        top: `${(placed ?? position).y}px`,
        maxHeight: ceiling === null ? undefined : `${ceiling}px`,
        visibility: placed === null ? "hidden" : undefined,
      }}
    >
      {title.length > 0 ? <p className="system-info-row-menu-title" title={title}>{title}</p> : null}
      {cell !== null && cell.trim().length > 0 ? (
        <button type="button" role="menuitem" onClick={() => onLocal("copy-cell")}>
          <CopyIcon />复制这一格
        </button>
      ) : null}
      <button type="button" role="menuitem" onClick={() => onLocal("copy-row")}>
        <CopyIcon />复制整行
      </button>
      {row.detail ? (
        <button type="button" role="menuitem" onClick={() => onLocal("detail")}>
          <InfoIcon />查看详情
        </button>
      ) : null}
      {actions === null && error === null ? (
        <p className="system-info-row-menu-note" role="status">正在读取这一行能做什么…</p>
      ) : null}
      {error !== null ? <p className="system-info-row-menu-note is-error" role="alert">{error}</p> : null}
      {actions?.groups.map((group) => (
        <section key={group.key} className="system-info-row-menu-group">
          <h3>{group.label}</h3>
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
        </section>
      ))}
      {actions !== null && actions.groups.length === 0 ? (
        <p className="system-info-row-menu-note">这一行在目标机上没有可用的操作。</p>
      ) : null}
    </div>
  );
}
