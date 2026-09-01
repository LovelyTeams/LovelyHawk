import { useEffect, useLayoutEffect, useRef, useState, type ReactElement } from "react";

import { menuMaxHeight, placeMenu } from "./menu-placement";

import type { SftpBrowserEntry } from "../shared/sftp-browser-contract";
import {
  ArchiveIcon,
  DownloadIcon,
  FolderIcon,
  InfoIcon,
  NewFolderIcon,
  PermissionIcon,
  PreviewIcon,
  RenameIcon,
  TrashIcon,
} from "./file-icons";

export type SftpMenuAction =
  | "open"
  | "preview"
  | "edit"
  | "download"
  | "rename"
  | "chmod"
  | "archive"
  | "remove"
  | "create-directory"
  | "properties";

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
  // Measured, then placed, before the browser paints — so the menu is never
  // seen at the raw cursor position and then jumping.
  const [placed, setPlaced] = useState<{ x: number; y: number } | null>(null);
  const [ceiling, setCeiling] = useState<number | null>(null);

  useLayoutEffect(() => {
    const node = ref.current;
    if (node === null) return;
    const box = node.getBoundingClientRect();
    const viewport = { width: window.innerWidth, height: window.innerHeight };
    setPlaced(placeMenu(position, { width: box.width, height: box.height }, viewport));
    setCeiling(menuMaxHeight(viewport.height));
  }, [position, entry]);

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
      style={{
        left: `${(placed ?? position).x}px`,
        top: `${(placed ?? position).y}px`,
        maxHeight: ceiling === null ? undefined : `${ceiling}px`,
        // Hidden for the one frame between mounting and being measured. It is
        // laid out either way, so the measurement is real.
        visibility: placed === null ? "hidden" : undefined,
      }}
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
    // Both open the same window on the same file. 预览 opens it without the
    // ability to write, which is what "just let me look" should mean.
    items.push({ action: "preview", label: "预览文本", icon: <PreviewIcon /> });
    items.push({ action: "edit", label: "编辑文本", icon: <RenameIcon /> });
  }
  if (entry.kind === "file") {
    items.push({ action: "download", label: "下载", icon: <DownloadIcon /> });
  }
  items.push({ action: "rename", label: "重命名", icon: <RenameIcon /> });
  items.push({ action: "chmod", label: "设置权限", icon: <PermissionIcon /> });
  items.push({ action: "archive", label: "打包", icon: <ArchiveIcon /> });
  items.push({ action: "create-directory", label: "新建文件夹", icon: <NewFolderIcon /> });
  items.push({ action: "remove", label: "删除", icon: <TrashIcon />, dangerous: true });
  items.push({ action: "properties", label: "属性", icon: <InfoIcon /> });
  return items;
}
