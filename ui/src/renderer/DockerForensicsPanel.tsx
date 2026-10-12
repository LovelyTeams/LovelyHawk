import { useRef, useState } from "react";

import {
  dockerProcessColumn,
  isDockerContainerChanges,
  isDockerContainerProcesses,
  type DockerChangeKind,
  type DockerContainerChanges,
  type DockerContainerProcesses,
  type DockerForensicsApi,
} from "../shared/docker-forensics-contract";
import { errorText } from "./error-text";

export interface DockerForensicsPanelProps {
  api: DockerForensicsApi;
  bindingHandle: string;
  snapshotHandle: string;
  containerHandle: string;
  /** Processes exist only in a running container; its changes are kept either way. */
  running: boolean;
}

type Load<T> =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "ready"; value: T }
  | { status: "error"; message: string };

const KIND_LABEL: Record<DockerChangeKind, string> = { added: "新增", changed: "修改", deleted: "删除" };

/**
 * Where a change is worth reading first, and why. A hint, not a verdict:
 * every one of these also changes in ordinary use, and the reason is shown so
 * the operator can judge rather than trust a colour.
 */
export function changeAttention(path: string, kind: DockerChangeKind): string | null {
  const lowered = path.toLowerCase();
  if (lowered === "/etc/ld.so.preload") return "动态链接预加载，常被用来劫持进程";
  if (/^\/etc\/(passwd|shadow|group|gshadow|sudoers)(\.d\/.*)?$/u.test(lowered)) return "账号与权限配置";
  if (/(^|\/)\.ssh\/|authorized_keys/u.test(lowered)) return "SSH 登录凭据";
  if (/^\/(etc\/cron|var\/spool\/cron|etc\/anacrontab)/u.test(lowered)) return "计划任务，常见持久化位置";
  if (/^\/etc\/(rc\.local|init\.d\/|systemd\/|profile)|\/\.(bashrc|profile|bash_profile)$/u.test(lowered)) {
    return "登录或启动时会执行的脚本";
  }
  if (kind !== "deleted" && /^\/(tmp|var\/tmp|dev\/shm)\//u.test(lowered)) return "临时目录里的文件，常见落地位置";
  if (kind !== "deleted" && /^\/(usr\/(local\/)?)?s?bin\//u.test(lowered)) return "可执行程序目录";
  if (kind === "deleted" && /^\/var\/log\//u.test(lowered)) return "被删除的日志";
  return null;
}

/** Command-line traits often seen in a foothold. Again a hint, with its reason. */
export function processAttention(command: string): string | null {
  const lowered = command.toLowerCase();
  if (/\/dev\/(tcp|udp)\//u.test(lowered) || /\b(bash|sh) -i\b/u.test(lowered)) return "交互式 shell 接到网络上，常见于反弹 shell";
  if (/\b(nc|ncat|netcat|socat)\b.*\s-(e|c)\b/u.test(lowered)) return "网络工具带了执行参数，常见于反弹 shell";
  if (/(curl|wget)\b[^|]*\|\s*(ba)?sh\b/u.test(lowered)) return "下载后直接交给 shell 执行";
  if (/\b(xmrig|minerd|cpuminer|stratum\+tcp)\b/u.test(lowered)) return "挖矿程序的常见名称或协议";
  if (/(^|\s)\/(tmp|var\/tmp|dev\/shm)\//u.test(lowered)) return "从临时目录运行";
  return null;
}

/**
 * The two questions asked of a container before anything else, answered from
 * the host: what changed since the image, and what is running. Each is read on
 * request and kept until the dialog closes; reading again replaces it.
 */
export function DockerForensicsPanel({ api, bindingHandle, snapshotHandle, containerHandle, running }: DockerForensicsPanelProps) {
  const [changes, setChanges] = useState<Load<DockerContainerChanges>>({ status: "idle" });
  const [processes, setProcesses] = useState<Load<DockerContainerProcesses>>({ status: "idle" });
  const [kindFilter, setKindFilter] = useState<DockerChangeKind | "all">("all");
  const [notableOnly, setNotableOnly] = useState(false);
  const [changeQuery, setChangeQuery] = useState("");
  // One read of each in flight at a time; a second click waits for the first.
  const busy = useRef({ changes: false, processes: false });

  async function readChanges() {
    if (busy.current.changes) return;
    busy.current.changes = true;
    setChanges({ status: "loading" });
    try {
      const value = await api.getDockerContainerChanges(bindingHandle, snapshotHandle, containerHandle);
      if (!isDockerContainerChanges(value) || value.containerHandle !== containerHandle) throw new Error();
      setChanges({ status: "ready", value });
    } catch (reason: unknown) {
      setChanges({ status: "error", message: errorText(reason, "没能读取这个容器的文件改动。") });
    } finally {
      busy.current.changes = false;
    }
  }

  async function readProcesses() {
    if (busy.current.processes) return;
    busy.current.processes = true;
    setProcesses({ status: "loading" });
    try {
      const value = await api.getDockerContainerProcesses(bindingHandle, snapshotHandle, containerHandle);
      if (!isDockerContainerProcesses(value) || value.containerHandle !== containerHandle) throw new Error();
      setProcesses({ status: "ready", value });
    } catch (reason: unknown) {
      setProcesses({ status: "error", message: errorText(reason, "没能读取这个容器里的进程。") });
    } finally {
      busy.current.processes = false;
    }
  }

  return (
    <section className="docker-forensics" aria-label="快速排查" data-testid="docker-forensics">
      <h3>快速排查</h3>

      <div className="docker-forensics-block">
        <header>
          <h4>文件改动（与镜像相比）</h4>
          <button type="button" data-testid="docker-forensics-changes" disabled={changes.status === "loading"}
            onClick={() => void readChanges()}>
            {changes.status === "loading" ? "读取中…" : changes.status === "idle" ? "读取改动" : "重新读取"}
          </button>
        </header>
        <p className="docker-muted">
          只列容器自己的可写层：运行中写的日志、缓存也会出现在这里；挂载的卷和绑定目录里的文件不在其中。
        </p>
        {changes.status === "error" ? <p className="docker-error" role="alert">{changes.message}</p> : null}
        {changes.status === "ready" ? (
          <ChangesView
            changes={changes.value}
            kindFilter={kindFilter}
            onKindFilter={setKindFilter}
            notableOnly={notableOnly}
            onNotableOnly={setNotableOnly}
            query={changeQuery}
            onQuery={setChangeQuery}
          />
        ) : null}
      </div>

      <div className="docker-forensics-block">
        <header>
          <h4>运行中的进程</h4>
          <button type="button" data-testid="docker-forensics-processes"
            disabled={!running || processes.status === "loading"}
            title={running ? undefined : "容器没在运行，没有进程可看"}
            onClick={() => void readProcesses()}>
            {processes.status === "loading" ? "读取中…" : processes.status === "idle" ? "读取进程" : "重新读取"}
          </button>
        </header>
        <p className="docker-muted">
          由运行时从宿主机一侧读取，不依赖容器里的 ps，容器里被替换的 ps 也骗不过它。Docker 显示的是宿主机上的进程号。
        </p>
        {processes.status === "error" ? <p className="docker-error" role="alert">{processes.message}</p> : null}
        {processes.status === "ready" ? <ProcessesView processes={processes.value} /> : null}
      </div>
    </section>
  );
}

function ChangesView({ changes, kindFilter, onKindFilter, notableOnly, onNotableOnly, query, onQuery }: {
  changes: DockerContainerChanges;
  kindFilter: DockerChangeKind | "all";
  onKindFilter(kind: DockerChangeKind | "all"): void;
  notableOnly: boolean;
  onNotableOnly(value: boolean): void;
  query: string;
  onQuery(value: string): void;
}) {
  const counts = { added: 0, changed: 0, deleted: 0 };
  for (const item of changes.items) counts[item.kind] += 1;
  const needle = query.trim().toLowerCase();
  const rows = changes.items
    .map((item) => ({ ...item, attention: changeAttention(item.path, item.kind) }))
    .filter((item) => (kindFilter === "all" || item.kind === kindFilter) &&
      (!notableOnly || item.attention !== null) &&
      (needle === "" || item.path.toLowerCase().includes(needle)));
  const notable = changes.items.filter((item) => changeAttention(item.path, item.kind) !== null).length;
  if (changes.items.length === 0) {
    return <p className="docker-muted" role="status">和镜像相比没有任何改动。</p>;
  }
  return (
    <div className="docker-forensics-result">
      <div className="docker-forensics-tools" role="group" aria-label="筛选改动">
        {(["all", "added", "changed", "deleted"] as const).map((kind) => (
          <button key={kind} type="button" aria-pressed={kindFilter === kind} onClick={() => onKindFilter(kind)}>
            {kind === "all" ? `全部 ${changes.items.length}` : `${KIND_LABEL[kind]} ${counts[kind]}`}
          </button>
        ))}
        <button type="button" aria-pressed={notableOnly} data-testid="docker-forensics-notable"
          onClick={() => onNotableOnly(!notableOnly)}>值得先看 {notable}</button>
        <input value={query} placeholder="按路径筛选" maxLength={256} aria-label="按路径筛选改动"
          onChange={(event) => onQuery(event.currentTarget.value)} />
      </div>
      {changes.truncated ? (
        <p className="docker-warning" role="status">改动太多，只显示前 {changes.items.length} 条。</p>
      ) : null}
      {changes.unreadableLines > 0 ? (
        <p className="docker-muted">另有 {changes.unreadableLines} 行输出不是改动记录，没有列出。</p>
      ) : null}
      <ul className="docker-forensics-list">
        {rows.map((item, index) => (
          <li key={`${item.kind}:${item.path}:${index}`} className={item.attention === null ? undefined : "is-notable"}>
            <span className={`docker-change is-${item.kind}`}>{KIND_LABEL[item.kind]}</span>
            <code>{item.path}</code>
            {item.attention === null ? null : <em>{item.attention}</em>}
          </li>
        ))}
      </ul>
      {rows.length === 0 ? <p className="docker-muted">没有符合筛选的改动。</p> : null}
    </div>
  );
}

function ProcessesView({ processes }: { processes: DockerContainerProcesses }) {
  const command = dockerProcessColumn(processes.titles, "CMD", "COMMAND");
  if (processes.rows.length === 0) {
    return <p className="docker-muted" role="status">运行时没有报告任何进程。</p>;
  }
  return (
    <div className="docker-forensics-result">
      {processes.truncated ? (
        <p className="docker-warning" role="status">进程太多，只显示前 {processes.rows.length} 个。</p>
      ) : null}
      <div className="docker-forensics-table">
        <table>
          <thead>
            <tr>{processes.titles.map((title, index) => <th key={index} scope="col">{title}</th>)}<th scope="col">提示</th></tr>
          </thead>
          <tbody>
            {processes.rows.map((row, index) => {
              const attention = command < 0 ? null : processAttention(row[command] ?? "");
              return (
                <tr key={index} className={attention === null ? undefined : "is-notable"}>
                  {row.map((field, column) => <td key={column}>{column === command ? <code>{field}</code> : field}</td>)}
                  <td>{attention ?? ""}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
