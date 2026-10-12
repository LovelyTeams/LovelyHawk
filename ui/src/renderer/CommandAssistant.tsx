import { useState } from "react";

/**
 * Fixed snippets the operator can drop into the terminal. Nothing is executed
 * here: a chip types its text into the terminal and leaves the newline to the
 * operator, so a half-formed command never runs by accident.
 */
export interface CommandSnippet {
  label: string;
  /** What lands in the terminal; usually the label plus a trailing space. */
  text: string;
}

export interface CommandAssistantGroup {
  id: string;
  label: string;
  snippets: CommandSnippet[];
}

function group(id: string, label: string, entries: (string | [string, string])[]): CommandAssistantGroup {
  return {
    id,
    label,
    snippets: entries.map((entry) => typeof entry === "string"
      ? { label: entry, text: `${entry} ` }
      : { label: entry[0], text: entry[1] }),
  };
}

export const commandAssistantGroups: CommandAssistantGroup[] = [
  group("common", "常用", ["ls -la", "cd ..", "pwd", "cat", "grep", "find . -name", "tar -czvf", "df -h"]),
  group("files", "文件", [
    "ls -lah", "du -sh *", "stat", "head -n 50", "tail -f", "file", "md5sum", "find . -mtime -1",
  ]),
  group("system", "系统", [
    "uname -a", "uptime", "free -h", "lsblk", "systemctl status", "journalctl -n 100", "dmesg | tail",
  ]),
  group("network", "网络", [
    "ss -tulpn", "ss -tanp", "ip -o addr", "ip route", "cat /etc/resolv.conf", "arp -an",
  ]),
  group("process", "进程", [
    "ps -ef", "ps aux --sort=-pcpu", "top -b -n 1", "lsof -nPi", "pstree -ap", "ls -l /proc",
  ]),
  group("permission", "权限", [
    "id", "getent passwd", "sudo -l", "find / -perm -4000 -type f", "lsattr", "getfacl",
  ]),
];

export interface CommandAssistantProps {
  onInsert: (text: string) => void;
  disabled?: boolean;
}

export function CommandAssistant({ onInsert, disabled = false }: CommandAssistantProps) {
  const [open, setOpen] = useState(true);
  const [activeGroupId, setActiveGroupId] = useState(commandAssistantGroups[0]!.id);
  const active = commandAssistantGroups.find((entry) => entry.id === activeGroupId)
    ?? commandAssistantGroups[0]!;
  return (
    <section className={open ? "command-assistant is-open" : "command-assistant"} aria-label="命令助手">
      <div className="command-assistant-bar">
        <button
          type="button"
          className="command-assistant-toggle"
          data-testid="toggle-command-assistant"
          aria-expanded={open}
          onClick={() => setOpen((value) => !value)}
        >
          命令助手
        </button>
        {open ? (
          <nav className="command-assistant-groups" aria-label="命令分类">
            {commandAssistantGroups.map((entry) => (
              <button
                type="button"
                key={entry.id}
                className={entry.id === active.id ? "is-active" : ""}
                aria-pressed={entry.id === active.id}
                onClick={() => setActiveGroupId(entry.id)}
              >
                {entry.label}
              </button>
            ))}
          </nav>
        ) : null}
      </div>
      {open ? (
        <div className="command-assistant-snippets">
          {active.snippets.map((snippet) => (
            <button
              type="button"
              key={snippet.label}
              disabled={disabled}
              title={`插入 ${snippet.label}，回车由你按`}
              onClick={() => onInsert(snippet.text)}
            >
              {snippet.label}
            </button>
          ))}
        </div>
      ) : null}
    </section>
  );
}
