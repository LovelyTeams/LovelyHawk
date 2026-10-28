import type {
  ContainerRuntime,
  DockerCollectionKind,
  DockerContainerItem,
  DockerSecuritySeverity,
} from "../shared/docker-read-contract";
import type { DockerIconName } from "./docker-icons";
import type { DockerTab } from "./docker-read-state";

export function dockerReadScope(
  bindingHandle: string,
): string {
  return bindingHandle;
}

export function dockerCollectionForTab(tab: DockerTab): DockerCollectionKind | null {
  switch (tab) {
    case "containers": return "stats";
    case "images": return "images";
    case "networks": return "networks";
    case "volumes": return "volumes";
    case "compose-projects": return "compose-projects";
    case "security": return null;
  }
}

/**
 * What to say when the container list could not be taken.
 *
 * "No container runtime here" and "the runtime is installed but not talking"
 * are different problems with different next steps, and neither is the same as
 * "no containers" — which is what this page said on every Podman host before
 * the runtime was detected rather than assumed.
 */
export function containerRuntimeMessage(reason: unknown): string {
  const message = reason instanceof Error ? reason.message : String(reason ?? "");
  if (message.includes("docker-runtime-absent")) {
    return "这台主机上没有装 Docker，也没有装 Podman。";
  }
  if (message.includes("docker-runtime-not-running")) {
    return "这台主机装了容器运行时，但它没有响应——可能是服务没起来，或者当前用户读不到它的套接字。";
  }
  return "无法读取当前目标的容器清单。";
}

/**
 * What the operator can do about a container list that could not be taken,
 * and what it does not mean: nothing could be inspected, which is not the same
 * as there being no containers.
 */
export function containerRuntimeNextStep(message: string | null): string {
  if (message === "这台主机上没有装 Docker，也没有装 Podman。") {
    return "当前登录账号能找到的 docker 和 podman 命令都不存在，所以没能检查任何容器或镜像。这不代表主机上一定没有容器：也可能用了别的运行时，或命令不在这个账号的 PATH 里。";
  }
  if (message?.startsWith("这台主机装了容器运行时，但它没有响应") === true) {
    return "可以到“主机全景 › 系统服务”看 docker / podman 服务是否在运行；如果服务正常，换用 root 或 docker 组里的账号连接再试。";
  }
  return "可以点右上角“刷新”再试一次；连接断开过的话，先重新连接。";
}

/** How the pane names the runtime it is actually looking at. */
export function containerRuntimeLabel(runtime: ContainerRuntime): string {
  return runtime === "podman" ? "Podman" : "Docker";
}

/**
 * Which of three tones a container state reads as.
 *
 * Only three, and deliberately: green for "doing its job", red for "stopped
 * being able to", grey for everything in between. A palette with one colour
 * per state would make the table decorative rather than scannable.
 */
export function dockerStateTone(state: string): "up" | "down" | "other" {
  if (state === "running") return "up";
  if (state === "exited" || state === "dead") return "down";
  return "other";
}

const DOCKER_STATE_TEXT: Record<string, string> = {
  running: "运行中",
  exited: "已停止",
  paused: "已暂停",
  restarting: "重启中",
  created: "已创建",
  dead: "已失效",
  removing: "删除中",
};

/** The container's state in words; a state the runtime adds later shows as it came. */
export function dockerStateText(state: string): string {
  return DOCKER_STATE_TEXT[state] ?? (state || "—");
}

const DURATION_UNITS: Record<string, string> = {
  second: "秒", seconds: "秒", minute: "分钟", minutes: "分钟", hour: "小时", hours: "小时",
  day: "天", days: "天", week: "周", weeks: "周", month: "个月", months: "个月", year: "年", years: "年",
};

/** Docker's human durations ("4 minutes", "About an hour", "Less than a second"). */
function dockerDurationText(text: string): string | null {
  const value = text.trim();
  if (/^Less than a second$/iu.test(value)) return "不到 1 秒";
  const about = /^About an? (minute|hour)$/iu.exec(value);
  if (about !== null) return `约 1 ${DURATION_UNITS[about[1]!.toLowerCase()]}`;
  const plain = /^(\d+|an?) (seconds?|minutes?|hours?|days?|weeks?|months?|years?)$/iu.exec(value);
  if (plain === null) return null;
  const count = /^\d+$/u.test(plain[1]!) ? plain[1]! : "1";
  return `${count} ${DURATION_UNITS[plain[2]!.toLowerCase()]}`;
}

const HEALTH_TEXT: Record<string, string> = {
  healthy: "健康检查通过",
  unhealthy: "健康检查未通过",
  "health: starting": "健康检查进行中",
  paused: "已暂停",
};

/**
 * Docker's status line in Chinese: "Up 4 minutes (healthy)" becomes
 * "已运行 4 分钟，健康检查通过", "Exited (137) 2 hours ago" becomes
 * "2 小时前退出，退出码 137". A line it does not recognise is shown as the
 * runtime wrote it — a wrong translation would be worse than English.
 */
export function dockerStatusText(status: string): string {
  const value = status.trim();
  if (value === "") return "—";
  const suffixMatch = /^(.*?)\s*\(([^()]+)\)$/u.exec(value);
  let main = value;
  let suffix = "";
  if (suffixMatch !== null && HEALTH_TEXT[suffixMatch[2]!.toLowerCase()] !== undefined) {
    main = suffixMatch[1]!;
    suffix = `，${HEALTH_TEXT[suffixMatch[2]!.toLowerCase()]}`;
  }
  const up = /^Up (.+)$/u.exec(main);
  if (up !== null) {
    const duration = dockerDurationText(up[1]!);
    return duration === null ? value : `已运行 ${duration}${suffix}`;
  }
  const ended = /^(Exited|Restarting) \((-?\d+)\) (.+) ago$/u.exec(main);
  if (ended !== null) {
    const duration = dockerDurationText(ended[3]!);
    if (duration === null) return value;
    return ended[1] === "Exited"
      ? `${duration}前退出，退出码 ${ended[2]}${suffix}`
      : `重启中，${duration}前以退出码 ${ended[2]} 结束${suffix}`;
  }
  if (main === "Created") return `已创建，还没启动${suffix}`;
  if (main === "Dead") return "已失效";
  if (main === "Removal In Progress") return "正在删除";
  return value;
}

/**
 * How many rows a tab has, for the tab strip to show.
 *
 * `null` when the answer is not known yet — a tab the operator has not opened
 * has nothing loaded behind it, and showing `0` there would be a claim rather
 * than a blank. The security tab is excluded on purpose: its number is a count
 * of findings, and putting that beside row counts would read as one more
 * inventory rather than as a verdict.
 */
export function dockerTabCount(
  state: { snapshot: { containers: readonly unknown[] } | null;
    collections: Partial<Record<DockerCollectionKind, { items: readonly unknown[] }>> },
  tab: DockerTab,
): number | null {
  if (tab === "containers") return state.snapshot?.containers.length ?? null;
  if (tab === "security") return null;
  const kind = dockerCollectionForTab(tab);
  if (kind === null) return null;
  return state.collections[kind]?.items.length ?? null;
}

export const DOCKER_PAGE_SIZES = [10, 25, 50, 100] as const;

/**
 * The used half of a `used / limit` reading.
 *
 * The runtime prints both in one string. The limit is the machine's memory and
 * is the same on every row, so repeating it down the column costs width and
 * says nothing; it is still shown in full in the detail panel.
 */
export function dockerMemoryUsed(usage: string | undefined): string {
  if (usage === undefined) return "";
  const [used] = usage.split("/");
  return (used ?? "").trim();
}

/**
 * A percentage string as a number, or null when it is not one.
 *
 * The runtime writes `0.42%`, and a row that never reported gets an empty
 * string. Null means "draw nothing", which is different from drawing a bar at
 * zero — an empty bar reads as a measurement of zero.
 */
export function dockerPercentValue(percent: string | undefined): number | null {
  if (percent === undefined) return null;
  const match = /^\s*(?<value>\d+(?:\.\d+)?)\s*%\s*$/u.exec(percent);
  if (match?.groups?.value === undefined) return null;
  const value = Number(match.groups.value);
  if (!Number.isFinite(value)) return null;
  return Math.max(0, Math.min(100, value));
}

/** The states present in this snapshot, so the filter offers only real ones. */
export function dockerDistinctStates(
  containers: readonly { state: string }[],
): readonly string[] {
  return [...new Set(containers.map((item) => item.state).filter((value) => value !== ""))].sort();
}

export function dockerDistinctImages(
  containers: readonly { image: string }[],
): readonly string[] {
  return [...new Set(containers.map((item) => item.image).filter((value) => value !== ""))].sort();
}

export interface DockerStatCard {
  id: string;
  icon: DockerIconName;
  tone: "total" | "running" | "stopped" | "images" | "networks" | "volumes";
  label: string;
  /** Null when the collection behind it has not been read yet. */
  value: string | null;
  detail: string;
}

/**
 * The summary row above the table.
 *
 * A card whose collection has not been loaded shows no number at all rather
 * than a zero: on this page a zero is an answer — "there are no volumes" — and
 * showing one for "not read yet" is the same class of wrong answer as reading
 * a Podman machine as an empty Docker one.
 */
export function dockerStatCards(
  state: {
    snapshot: { containers: readonly { state: string }[] } | null;
    collections: Partial<Record<DockerCollectionKind, { items: readonly unknown[] }>>;
  },
): readonly DockerStatCard[] {
  const containers = state.snapshot?.containers ?? [];
  const total = containers.length;
  const running = containers.filter((item) => item.state === "running").length;
  const stopped = total - running;
  const share = (count: number) => (total === 0 ? "—" : `${Math.round((count / total) * 100)}%`);
  const collection = (kind: DockerCollectionKind) => {
    const items = state.collections[kind]?.items;
    return items === undefined ? null : String(items.length);
  };
  return [
    {
      id: "total", icon: "container" as const, tone: "total" as const, label: "容器总数",
      value: String(total), detail: "全部容器",
    },
    {
      id: "running", icon: "running" as const, tone: "running" as const, label: "运行中",
      value: String(running), detail: `${share(running)} 运行中`,
    },
    {
      id: "stopped", icon: "stopped" as const, tone: "stopped" as const, label: "已停止",
      value: String(stopped), detail: `${share(stopped)} 已停止`,
    },
    {
      id: "images", icon: "images" as const, tone: "images" as const, label: "镜像",
      value: collection("images"), detail: "本地镜像数",
    },
    {
      id: "networks", icon: "networks" as const, tone: "networks" as const, label: "网络",
      value: collection("networks"), detail: "自定义网络",
    },
    {
      id: "volumes", icon: "volumes" as const, tone: "volumes" as const, label: "存储卷",
      value: collection("volumes"), detail: "本地存储卷",
    },
  ];
}

export function dockerTabLabel(tab: DockerTab): string {
  switch (tab) {
    case "containers": return "容器";
    case "images": return "镜像";
    case "networks": return "网络";
    case "volumes": return "存储卷";
    case "compose-projects": return "Compose";
    case "security": return "安全审计";
  }
}

export function filterDockerContainers(
  containers: readonly DockerContainerItem[],
  query: string,
): DockerContainerItem[] {
  const needle = query.trim().toLocaleLowerCase();
  if (needle.length === 0) return [...containers];
  return containers.filter((container) => [
    container.name,
    container.image,
    container.state,
    container.status,
    container.ports,
    container.createdAt,
  ].some((value) => value.toLocaleLowerCase().includes(needle)));
}

export function dockerSecuritySeverityLabel(severity: DockerSecuritySeverity): string {
  switch (severity) {
    case "critical": return "严重";
    case "high": return "高";
    case "medium": return "中";
    case "low": return "低";
    case "info": return "信息";
  }
}

export function dockerBooleanLabel(value: boolean): string {
  return value ? "是" : "否";
}

export function dockerSnapshotMinutes(expiresInSeconds: number): string {
  return `${Math.max(1, Math.ceil(expiresInSeconds / 60))} 分钟`;
}
