import type {
  KubernetesNamespaceCapability,
  KubernetesNamespaceScope,
  KubernetesReadRow,
  KubernetesReadTab,
  KubernetesSnapshot,
} from "../shared/kubernetes-read-contract";

export const KUBERNETES_ROW_WINDOW = 60;
const encoder = new TextEncoder();

export function kubernetesReadScope(bindingHandle: string): string {
  return bindingHandle;
}

export function kubernetesTabLabel(tab: KubernetesReadTab): string {
  switch (tab) {
    case "namespaces": return "Namespaces";
    case "pods": return "Pods";
    case "deployments": return "Deployments";
    case "nodes": return "Nodes";
  }
}

export function boundKubernetesQuery(value: string): string {
  if (encoder.encode(value).byteLength <= 256) return value;
  let output = "";
  for (const character of value) {
    if (encoder.encode(output + character).byteLength > 256) break;
    output += character;
  }
  return output;
}

export function kubernetesNamespaceCapability(
  snapshot: KubernetesSnapshot,
  rowHandle: string,
): KubernetesNamespaceCapability | null {
  if (snapshot.tab !== "namespaces" ||
    !snapshot.rows.some((row) => row.kind === "namespace" && row.rowHandle === rowHandle)) {
    return null;
  }
  return { snapshotHandle: snapshot.snapshotHandle, rowHandle };
}

export function kubernetesNamespaceKey(
  scope: KubernetesNamespaceScope | null,
): string {
  if (scope === null) return "all";
  if ("context" in scope) return "context";
  return `${scope.snapshotHandle}:${scope.rowHandle}`;
}

export function kubernetesListContext(
  tab: KubernetesReadTab,
  scope: KubernetesNamespaceScope | null,
): string {
  return tab === "pods" || tab === "deployments"
    ? kubernetesNamespaceKey(scope)
    : "all";
}

export function kubernetesRowSearchText(row: KubernetesReadRow): string {
  switch (row.kind) {
    case "namespace": return `${row.name} ${row.phase} ${row.createdAt}`;
    case "pod": return [
      row.namespace, row.name, row.phase, row.node, row.podIp, ...row.images,
    ].join(" ");
    case "deployment": return [row.namespace, row.name, ...row.images].join(" ");
    case "node": return [
      row.name, row.ready ? "ready" : "notready", row.unschedulable ? "unschedulable" : "schedulable",
      row.kubeletVersion, row.internalIp, ...row.roles,
    ].join(" ");
  }
}

export function filteredKubernetesRows(
  snapshot: KubernetesSnapshot | null,
  query: string,
): KubernetesReadRow[] {
  if (snapshot === null) return [];
  const normalized = query.trim().toLocaleLowerCase();
  return [...snapshot.rows]
    .filter((row) => normalized === "" ||
      kubernetesRowSearchText(row).toLocaleLowerCase().includes(normalized))
    .sort((left, right) => {
      const leftNamespace = "namespace" in left ? left.namespace : "";
      const rightNamespace = "namespace" in right ? right.namespace : "";
      return leftNamespace.localeCompare(rightNamespace) ||
        left.name.localeCompare(right.name) || left.rowHandle.localeCompare(right.rowHandle);
    });
}

export function windowedKubernetesRows(
  rows: readonly KubernetesReadRow[],
  page: number,
): KubernetesReadRow[] {
  const safePage = Math.max(0, Math.floor(page));
  return rows.slice(
    safePage * KUBERNETES_ROW_WINDOW,
    (safePage + 1) * KUBERNETES_ROW_WINDOW,
  );
}

/**
 * The row's state, pulled out of the subtitle so it can be seen rather than
 * read.
 *
 * The subtitle used to run six dot-separated facts together, with the one an
 * operator scans for — is this thing healthy — sitting third in the same
 * weight as the node name. Three tones, matching the container table: green
 * for working, red for stopped working, grey for everything else.
 */
export function kubernetesRowState(
  row: KubernetesReadRow,
): { label: string; tone: "up" | "down" | "other" } {
  switch (row.kind) {
    case "namespace":
      return { label: row.phase || "未知", tone: row.phase === "Active" ? "up" : "other" };
    case "pod":
      return {
        label: row.phase || "未知",
        tone: row.phase === "Running" || row.phase === "Succeeded"
          ? "up"
          // Anything Kubernetes spells with "BackOff", "Error" or "Failed" is
          // a pod that is not doing its job, whatever the exact word.
          : /BackOff|Error|Failed|Evicted|Unknown/u.test(row.phase)
            ? "down"
            : "other",
      };
    case "deployment":
      if (row.desiredReplicas === 0) return { label: "已设为 0 副本", tone: "other" };
      return {
        label: `${row.readyReplicas}/${row.desiredReplicas}`,
        tone: row.readyReplicas === row.desiredReplicas && row.availableReplicas === row.desiredReplicas &&
          row.updatedReplicas === row.desiredReplicas
          ? "up"
          : row.readyReplicas === 0
            ? "down"
            : "other",
      };
    case "node":
      return {
        label: row.ready ? (row.unschedulable ? "已暂停调度" : "Ready") : "NotReady",
        tone: row.ready ? (row.unschedulable ? "other" : "up") : "down",
      };
  }
}

/**
 * Whether this row is something an operator has to look at.
 *
 * The first question on this page is not "what is running" — it is "what is
 * broken". A cluster with two hundred pods puts the three that matter
 * somewhere in the middle of the list, and scrolling for them is how they get
 * missed.
 *
 * Deliberately wider than "the phase is bad": a pod that says Running while
 * only two of its three containers are ready is not fine, and a pod that has
 * restarted is worth a look even though it is up right now.
 */
export function kubernetesRowNeedsAttention(row: KubernetesReadRow): boolean {
  switch (row.kind) {
    case "namespace":
      return row.phase !== "" && row.phase !== "Active";
    // Restarts alone do not count: one node reboot restarts every pod on it,
    // and a list where every row is red tells the operator nothing. They are
    // still marked, apart — see kubernetesRowRestarted.
    case "pod":
      return kubernetesRowState(row).tone !== "up" ||
        row.readyContainers < row.totalContainers;
    case "deployment":
      return row.readyReplicas !== row.desiredReplicas || row.availableReplicas !== row.desiredReplicas ||
        row.updatedReplicas !== row.desiredReplicas || row.desiredReplicas === 0;
    case "node":
      return !row.ready || row.unschedulable;
  }
}

/**
 * A pod that is up and ready but has restarted: worth noticing (a crash, an
 * OOM kill, someone killing its process), not proof that anything is wrong.
 * Shown in its own colour and counted on its own, never as "要看的".
 */
export function kubernetesRowRestarted(row: KubernetesReadRow): boolean {
  return row.kind === "pod" && row.restarts > 0 && !kubernetesRowNeedsAttention(row);
}

/** How long ago, from a timestamp the cluster reported. */
export function kubernetesRowAge(createdAt: string, now: number = Date.now()): string {
  const started = Date.parse(createdAt);
  if (!Number.isFinite(started)) return "—";
  const seconds = Math.max(0, Math.floor((now - started) / 1000));
  if (seconds < 60) return `${seconds} 秒`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} 分钟`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours} 小时`;
  return `${Math.floor(hours / 24)} 天`;
}

/** What is left once the state has been lifted out into its own mark. */
export function kubernetesRowSubtitle(row: KubernetesReadRow): string {
  switch (row.kind) {
    case "namespace": return row.createdAt || "时间不可用";
    case "pod": return `${row.namespace} · Ready ${row.readyContainers}/${row.totalContainers} · 重启 ${row.restarts} · ${row.node || "—"} · ${row.podIp || "无 IP"}`;
    case "deployment": return `${row.namespace} · Available ${row.availableReplicas} · Updated ${row.updatedReplicas}`;
    case "node": return `${row.roles.join(", ") || "无角色"} · ${row.internalIp || "无内部 IP"} · CPU ${row.cpuCapacity || "—"} · MEM ${row.memoryCapacity || "—"} · Pods ${row.podCapacity || "—"}`;
  }
}

export function kubernetesRowName(row: KubernetesReadRow): string {
  return row.name;
}

/**
 * The columns one tab shows, and how to read each one from a row.
 *
 * The list used to render every field as one run-on line — "frontend · Ready
 * 1/1 · 重启 0 · worker-1 · 10.42.0.9" — which cannot be scanned down. Restart
 * counts are exactly the thing you want to run your eye down a column of.
 */
export interface KubernetesColumn {
  key: string;
  label: string;
  /** Right-aligned for counts, so digits line up. */
  numeric?: boolean;
  read(row: KubernetesReadRow, now?: number): string;
}

export function kubernetesColumns(tab: KubernetesReadTab): readonly KubernetesColumn[] {
  switch (tab) {
    case "namespaces":
      return [
        { key: "name", label: "名称", read: (row) => row.name },
        { key: "age", label: "存在时长", read: (row, now) =>
          row.kind === "namespace" ? kubernetesRowAge(row.createdAt, now) : "—" },
      ];
    case "pods":
      return [
        { key: "name", label: "名称", read: (row) => row.name },
        { key: "namespace", label: "命名空间", read: (row) =>
          row.kind === "pod" ? row.namespace : "—" },
        { key: "ready", label: "就绪", numeric: true, read: (row) =>
          row.kind === "pod" ? `${row.readyContainers}/${row.totalContainers}` : "—" },
        { key: "restarts", label: "重启", numeric: true, read: (row) =>
          row.kind === "pod" ? String(row.restarts) : "—" },
        { key: "node", label: "节点", read: (row) =>
          row.kind === "pod" ? row.node || "—" : "—" },
        { key: "ip", label: "地址", read: (row) =>
          row.kind === "pod" ? row.podIp || "—" : "—" },
        { key: "age", label: "存在时长", read: (row, now) =>
          row.kind === "pod" ? kubernetesRowAge(row.createdAt, now) : "—" },
      ];
    case "deployments":
      return [
        { key: "name", label: "名称", read: (row) => row.name },
        { key: "namespace", label: "命名空间", read: (row) =>
          row.kind === "deployment" ? row.namespace : "—" },
        { key: "available", label: "可用", numeric: true, read: (row) =>
          row.kind === "deployment" ? String(row.availableReplicas) : "—" },
        { key: "updated", label: "已更新", numeric: true, read: (row) =>
          row.kind === "deployment" ? String(row.updatedReplicas) : "—" },
        { key: "age", label: "存在时长", read: (row, now) =>
          row.kind === "deployment" ? kubernetesRowAge(row.createdAt, now) : "—" },
      ];
    case "nodes":
      return [
        { key: "name", label: "名称", read: (row) => row.name },
        { key: "roles", label: "角色", read: (row) =>
          row.kind === "node" ? row.roles.join(", ") || "—" : "—" },
        { key: "ip", label: "内部地址", read: (row) =>
          row.kind === "node" ? row.internalIp || "—" : "—" },
        { key: "cpu", label: "CPU", numeric: true, read: (row) =>
          row.kind === "node" ? row.cpuCapacity || "—" : "—" },
        { key: "memory", label: "内存", numeric: true, read: (row) =>
          row.kind === "node" ? row.memoryCapacity || "—" : "—" },
        { key: "pods", label: "Pod 上限", numeric: true, read: (row) =>
          row.kind === "node" ? row.podCapacity || "—" : "—" },
      ];
  }
}

export interface KubernetesStatCard {
  id: string;
  label: string;
  /** Null when this tab has not been read yet: a zero would be a claim. */
  value: string | null;
  detail: string;
  tone: "plain" | "good" | "bad";
}

/**
 * The counts above the table.
 *
 * Only tabs that have actually been read contribute a number. A tab nobody has
 * opened has nothing loaded behind it, and showing `0` there would say "there
 * are no nodes" when the truth is "nobody looked".
 */
export function kubernetesStatCards(
  rowsByTab: Partial<Record<KubernetesReadTab, readonly KubernetesReadRow[]>>,
): readonly KubernetesStatCard[] {
  const count = (tab: KubernetesReadTab) => rowsByTab[tab]?.length ?? null;
  const pods = rowsByTab.pods ?? null;
  const attention = pods === null
    ? null
    : pods.filter(kubernetesRowNeedsAttention).length;
  const running = pods === null
    ? null
    : pods.filter((row) => !kubernetesRowNeedsAttention(row)).length;
  const restarted = pods === null ? 0 : pods.filter(kubernetesRowRestarted).length;
  return [
    {
      id: "pods",
      label: "Pod 总数",
      value: count("pods") === null ? null : String(count("pods")),
      detail: "当前范围",
      tone: "plain",
    },
    {
      id: "healthy",
      label: "正常",
      value: running === null ? null : String(running),
      detail: restarted > 0 ? `就绪运行，其中 ${restarted} 个重启过` : "就绪运行",
      tone: "good",
    },
    {
      id: "attention",
      label: "要看的",
      value: attention === null ? null : String(attention),
      detail: "没就绪或状态异常",
      tone: attention !== null && attention > 0 ? "bad" : "plain",
    },
    {
      id: "deployments",
      label: "Deployment",
      value: count("deployments") === null ? null : String(count("deployments")),
      detail: "当前范围",
      tone: "plain",
    },
    {
      id: "nodes",
      label: "节点",
      value: count("nodes") === null ? null : String(count("nodes")),
      detail: "集群全部",
      tone: "plain",
    },
    {
      id: "namespaces",
      label: "命名空间",
      value: count("namespaces") === null ? null : String(count("namespaces")),
      detail: "集群全部",
      tone: "plain",
    },
  ];
}
