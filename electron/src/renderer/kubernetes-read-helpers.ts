import type {
  KubernetesNamespaceCapability,
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
  capability: KubernetesNamespaceCapability | null,
): string {
  return capability === null
    ? "all"
    : `${capability.snapshotHandle}:${capability.rowHandle}`;
}

export function kubernetesListContext(
  tab: KubernetesReadTab,
  capability: KubernetesNamespaceCapability | null,
): string {
  return tab === "pods" || tab === "deployments"
    ? kubernetesNamespaceKey(capability)
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

export function kubernetesRowSubtitle(row: KubernetesReadRow): string {
  switch (row.kind) {
    case "namespace": return `${row.phase || "未知状态"} · ${row.createdAt || "时间不可用"}`;
    case "pod": return `${row.namespace} · ${row.phase || "未知状态"} · Ready ${row.readyContainers}/${row.totalContainers} · 重启 ${row.restarts} · Node ${row.node || "—"} · IP ${row.podIp || "—"}`;
    case "deployment": return `${row.namespace} · Ready ${row.readyReplicas}/${row.desiredReplicas} · Available ${row.availableReplicas} · Updated ${row.updatedReplicas}`;
    case "node": return `${row.ready ? "Ready" : "NotReady"} · ${row.unschedulable ? "Unschedulable" : "Schedulable"} · ${row.roles.join(", ") || "无角色"} · ${row.internalIp || "无内部 IP"} · CPU ${row.cpuCapacity || "—"} · MEM ${row.memoryCapacity || "—"} · Pods ${row.podCapacity || "—"}`;
  }
}

export function kubernetesRowName(row: KubernetesReadRow): string {
  return row.name;
}
