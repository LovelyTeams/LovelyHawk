import { useEffect, useLayoutEffect, useRef, useState, type ReactElement } from "react";

import { menuMaxHeight, placeMenu } from "./menu-placement";

import type { EmergencyCommandPathOffer } from "../shared/emergency-command-contract";
import { InfoIcon, PermissionIcon, TrashIcon } from "./file-icons";
import "./emergency-path.css";

export type EmergencyPathMenuAction = "properties" | "evidence" | "disarm" | "quarantine";

export interface EmergencyPathMenuProps {
  /** Where the menu was summoned, in client coordinates. */
  position: { x: number; y: number };
  offer: EmergencyCommandPathOffer;
  busy: boolean;
  onAction: (action: EmergencyPathMenuAction) => void;
  onDismiss: () => void;
}

interface MenuItem {
  action: EmergencyPathMenuAction;
  label: string;
  hint: string;
  icon: ReactElement;
  dangerous?: boolean;
}

const ITEMS: MenuItem[] = [
  { action: "evidence", label: "下载留证", hint: "保存原始文件、来源和完整性摘要", icon: <InfoIcon /> },
  {
    action: "properties",
    label: "查看属性",
    hint: "只读取，不改动",
    icon: <InfoIcon />,
  },
  {
    action: "disarm",
    label: "去掉执行权限",
    hint: "移除直接执行权限，保留文件用于取证",
    icon: <PermissionIcon />,
  },
  {
    action: "quarantine",
    label: "隔离",
    hint: "移到备份区，之后还能取回",
    icon: <TrashIcon />,
    dangerous: true,
  },
];

/**
 * What can be done to the file this output line named.
 *
 * Nothing here changes anything: choosing an item asks for a plan, and the
 * operator still has to read it and confirm.
 */
export function EmergencyPathMenu({
  position,
  offer,
  busy,
  onAction,
  onDismiss,
}: EmergencyPathMenuProps) {
  const ref = useRef<HTMLDivElement>(null);
  // Measured, then placed, before the browser paints. See menu-placement.ts:
  // this menu had the same edge problem the SFTP one did.
  const [placed, setPlaced] = useState<{ x: number; y: number } | null>(null);
  const [ceiling, setCeiling] = useState<number | null>(null);

  useLayoutEffect(() => {
    const node = ref.current;
    if (node === null) return;
    const box = node.getBoundingClientRect();
    const viewport = { width: window.innerWidth, height: window.innerHeight };
    setPlaced(placeMenu(position, { width: box.width, height: box.height }, viewport));
    setCeiling(menuMaxHeight(viewport.height));
  }, [position, offer]);

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

  return (
    <div
      ref={ref}
      className="emergency-path-menu"
      role="menu"
      data-testid="emergency-path-menu"
      style={{
        left: `${(placed ?? position).x}px`,
        top: `${(placed ?? position).y}px`,
        maxHeight: ceiling === null ? undefined : `${ceiling}px`,
        visibility: placed === null ? "hidden" : undefined,
      }}
    >
      <p className="emergency-path-menu-title" title={offer.path}>{offer.path}</p>
      {ITEMS.map((item) => (
        <button
          type="button"
          role="menuitem"
          key={item.action}
          className={item.dangerous === true ? "is-dangerous" : ""}
          disabled={busy}
          onClick={() => onAction(item.action)}
        >
          {item.icon}
          <span>{item.label}<em>{item.hint}</em></span>
        </button>
      ))}
    </div>
  );
}
