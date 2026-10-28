import type { KubernetesReadRow } from "../shared/kubernetes-read-contract";
import type { KubernetesWriteAction } from "../shared/kubernetes-write-contract";

/**
 * What the operator can do to the row they selected.
 *
 * Deployments scale; nodes go in and out of scheduling, and only the direction
 * they are not already in is offered. Namespaces and Pods have no action at
 * all — the core has none for them, so offering one would be a button that
 * only ever produces an error.
 *
 * The replica count is not decided here: the caller asks for it. This says
 * which shapes apply, not what to put in them.
 */
export function availableKubernetesActions(
  row: KubernetesReadRow,
): readonly KubernetesWriteAction["kind"][] {
  switch (row.kind) {
    case "deployment":
      return ["scale-deployment"];
    case "node":
      return row.unschedulable ? ["uncordon"] : ["cordon"];
    case "namespace":
    case "pod":
      return [];
  }
}

export function kubernetesActionLabel(kind: KubernetesWriteAction["kind"]): string {
  switch (kind) {
    case "scale-deployment":
      return "调整副本数";
    case "cordon":
      return "标记为不可调度";
    case "uncordon":
      return "恢复可调度";
  }
}
