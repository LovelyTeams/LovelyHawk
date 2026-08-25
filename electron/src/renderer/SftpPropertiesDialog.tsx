import type { SftpBrowserEntry } from "../shared/sftp-browser-contract";
import { EntryKindIcon, PermissionIcon } from "./file-icons";
import { displaySftpBytes, displaySftpModifiedAt } from "./sftp-browser-helpers";
import { useModalScrim } from "./modal-scrim";

export interface SftpPropertiesDialogProps {
  entry: SftpBrowserEntry;
  /** Opens the permission flow with the mode below already filled in. */
  onChmod: () => void;
  onClose: () => void;
}

const KIND_LABELS: Record<SftpBrowserEntry["kind"], string> = {
  directory: "目录",
  file: "文件",
  symlink: "软链接",
  other: "其他（设备、套接字或管道）",
};

/**
 * What the listing knows about one entry, read-only. The permission bits matter
 * most here: a set-user-ID binary or a world-writable directory is exactly what
 * an operator is looking for, and until now the panel showed neither.
 */
export function SftpPropertiesDialog({ entry, onChmod, onClose }: SftpPropertiesDialogProps) {
  useModalScrim();
  const unknown = "服务器未提供";
  return (
    <div className="sftp-operation-backdrop" role="presentation">
      <section
        className="sftp-operation-dialog sftp-properties-dialog"
        role="dialog"
        aria-modal="true"
        aria-label={`${entry.name} 的属性`}
        data-testid="sftp-properties-dialog"
      >
        <header>
          <h2>
            <span className={`sftp-browser-row-kind is-${entry.kind}`}>
              <EntryKindIcon kind={entry.kind} />
            </span>
            属性
          </h2>
          <p>{entry.name}{entry.nameTruncated ? "（名称已截断）" : ""}</p>
        </header>

        <dl className="sftp-properties-list">
          <div>
            <dt>类型</dt>
            <dd>{KIND_LABELS[entry.kind]}</dd>
          </div>
          <div>
            <dt>大小</dt>
            <dd>
              {entry.kind === "directory" ? "—" : displaySftpBytes(entry.sizeBytes)}
              {entry.kind === "directory" ? "" : ` （${entry.sizeBytes} 字节）`}
            </dd>
          </div>
          <div>
            <dt>权限</dt>
            <dd>
              {entry.mode === null ? unknown : `${entry.mode}  ${symbolicMode(entry.mode)}`}
              {entry.mode !== null && specialBits(entry.mode).length > 0 ? (
                <em className="sftp-properties-flag">{specialBits(entry.mode).join("、")}</em>
              ) : null}
            </dd>
          </div>
          <div>
            <dt>属主 / 属组</dt>
            <dd>
              {entry.ownerId === null && entry.groupId === null
                ? unknown
                : `${entry.ownerId ?? "?"} / ${entry.groupId ?? "?"}`}
            </dd>
          </div>
          <div>
            <dt>修改时间</dt>
            <dd>{entry.modifiedAt === null ? unknown : displaySftpModifiedAt(entry.modifiedAt)}</dd>
          </div>
        </dl>

        <footer>
          <button type="button" onClick={onClose}>关闭</button>
          <button type="button" className="is-primary" onClick={onChmod}>
            <PermissionIcon />设置权限
          </button>
        </footer>
      </section>
    </div>
  );
}

/** "0644" becomes "rw-r--r--", with the set-ID and sticky bits shown in place. */
export function symbolicMode(mode: string): string {
  if (!/^[0-7]{4}$/u.test(mode)) return "";
  const [special, ...triples] = [...mode].map((digit) => Number.parseInt(digit, 8));
  const flags = special ?? 0;
  return triples
    .map((bits, index) => {
      const read = (bits & 0b100) === 0 ? "-" : "r";
      const write = (bits & 0b010) === 0 ? "-" : "w";
      const execute = (bits & 0b001) !== 0;
      // The set-ID and sticky bits ride on the execute slot, in upper case when
      // execute itself is off, so nothing about the mode is hidden.
      const marked = index === 0 && (flags & 0b100) !== 0 ? (execute ? "s" : "S")
        : index === 1 && (flags & 0b010) !== 0 ? (execute ? "s" : "S")
          : index === 2 && (flags & 0b001) !== 0 ? (execute ? "t" : "T")
            : execute ? "x" : "-";
      return `${read}${write}${marked}`;
    })
    .join("");
}

/** The bits worth calling out by name during triage. */
export function specialBits(mode: string): string[] {
  if (!/^[0-7]{4}$/u.test(mode)) return [];
  const flags = Number.parseInt(mode[0] ?? "0", 8);
  const other = Number.parseInt(mode[3] ?? "0", 8);
  const found: string[] = [];
  if ((flags & 0b100) !== 0) found.push("set-user-ID");
  if ((flags & 0b010) !== 0) found.push("set-group-ID");
  if ((flags & 0b001) !== 0) found.push("粘滞位");
  if ((other & 0b010) !== 0) found.push("其他用户可写");
  return found;
}
