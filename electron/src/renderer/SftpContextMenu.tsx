import { useEffect, useRef, type ReactElement } from "react";

import type { SftpBrowserEntry } from "../shared/sftp-browser-contract";
import {
  ArchiveIcon,
  DownloadIcon,
  FolderIcon,
  NewFolderIcon,
  PermissionIcon,
  PreviewIcon,
  TrashIcon,
} from "./file-icons";

export type SftpMenuAction =
  | "open"
  | "preview"
  | "download"
  | "rename"
  | "chmod"
  | "archive"
  | "remove"
  | "create-directory";

export interface SftpContextMenuProps {
  /** Where the menu was summoned, in client coordinates. */
  position: { x: number; y: number };
  /** Null when the operator asked the directory itself rather than a row. */
  entry: SftpBrowserEntry | null;
  busy: boolean;
  onAction: (action: SftpMenuAction) => void;
  onDismiss: () => void;
}

interface MenuItem {
  action: SftpMenuAction;
  label: string;
  icon: ReactElement;
  dangerous?: boolean;
}

/**
 * The actions for one entry. Nothing here runs anything: choosing an item asks
 * for a plan, and the operator still has to read and confirm it.
 */
export function SftpContextMenu({
  position,
  entry,
  busy,
  onAction,
  onDismiss,
}: SftpContextMenuProps) {
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

  const items = menuItems(entry);
  return (
    <div
      ref={ref}
      className="sftp-context-menu"
      role="menu"
      data-testid="sftp-context-menu"
      style={{ left: `${position.x}px`, top: `${position.y}px` }}
    >
      {entry === null ? null : <p className="sftp-context-menu-title">{entry.name}</p>}
      {items.map((item) => (
        <button
          type="button"
          role="menuitem"
          key={item.action}
          className={item.dangerous === true ? "is-dangerous" : ""}
          disabled={busy}
          onClick={() => onAction(item.action)}
        >
          {item.icon}{item.label}
        </button>
      ))}
    </div>
  );
}

export function menuItems(entry: SftpBrowserEntry | null): MenuItem[] {
  if (entry === null) {
    return [{ action: "create-directory", label: "新建文件夹", icon: <NewFolderIcon /> }];
  }
  const items: MenuItem[] = [];
  if (entry.action === "browse") {
    items.push({ action: "open", label: "打开", icon: <FolderIcon /> });
  }
  if (entry.action === "preview") {
    items.push({ action: "preview", label: "预览文本", icon: <PreviewIcon /> });
  }
  if (entry.kind === "file") {
    items.push({ action: "download", label: "下载", icon: <DownloadIcon /> });
  }
  items.push({ action: "rename", label: "重命名", icon: <PermissionIcon /> });
  items.push({ action: "chmod", label: "设置权限", icon: <PermissionIcon /> });
  items.push({ action: "archive", label: "打包", icon: <ArchiveIcon /> });
  items.push({ action: "create-directory", label: "新建文件夹", icon: <NewFolderIcon /> });
  items.push({ action: "remove", label: "删除", icon: <TrashIcon />, dangerous: true });
  return items;
}
