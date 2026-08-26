import { useEffect, useRef, type ReactElement } from "react";

import type { EmergencyCommandPathOffer } from "../shared/emergency-command-contract";
import { InfoIcon, PermissionIcon, TrashIcon } from "./file-icons";

export type EmergencyPathMenuAction = "properties" | "disarm" | "quarantine";

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
  {
    action: "properties",
    label: "查看属性",
    hint: "只读取，不改动",
    icon: <InfoIcon />,
  },
  {
    action: "disarm",
    label: "去掉执行权限",
    hint: "让它跑不起来，文件留着取证",
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
      style={{ left: `${position.x}px`, top: `${position.y}px` }}
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
