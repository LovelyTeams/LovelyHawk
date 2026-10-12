import type {
  KubernetesActionPlan,
  KubernetesActionReceipt,
  KubernetesWriteAction,
} from "../shared/kubernetes-write-contract";

/**
 * One workload action at a time, from the moment the operator picks one to the
 * moment they close the receipt.
 *
 * Kept apart from the read state on purpose: a snapshot refresh must never
 * disturb a dialog the operator is reading, and an action must never look like
 * it succeeded because a list happened to reload.
 */
export interface KubernetesActionState {
  /** Null when no dialog is open. Everything else is meaningless without it. */
  request: {
    rowHandle: string;
    resourceName: string;
    action: KubernetesWriteAction;
    actionLabel: string;
  } | null;
  plan: KubernetesActionPlan | null;
  receipt: KubernetesActionReceipt | null;
  busy: boolean;
  error: string | null;
  /**
   * Which request the in-flight reply belongs to. A reply that names an older
   * one is a late result from a dialog the operator already closed.
   */
  requestId: number;
}

export type KubernetesActionEvent =
  | {
      type: "opened";
      requestId: number;
      rowHandle: string;
      resourceName: string;
      action: KubernetesWriteAction;
      actionLabel: string;
    }
  | { type: "planned"; requestId: number; plan: KubernetesActionPlan }
  | { type: "executing"; requestId: number }
  | { type: "executed"; requestId: number; receipt: KubernetesActionReceipt }
  | { type: "failed"; requestId: number; message: string }
  | { type: "closed" };

export function createKubernetesActionState(): KubernetesActionState {
  return { request: null, plan: null, receipt: null, busy: false, error: null, requestId: 0 };
}

export function kubernetesActionReducer(
  state: KubernetesActionState,
  event: KubernetesActionEvent,
): KubernetesActionState {
  switch (event.type) {
    case "opened":
      return {
        request: {
          rowHandle: event.rowHandle,
          resourceName: event.resourceName,
          action: event.action,
          actionLabel: event.actionLabel,
        },
        plan: null,
        receipt: null,
        busy: true,
        error: null,
        requestId: event.requestId,
      };
    case "planned":
      if (event.requestId !== state.requestId || state.request === null) return state;
      return { ...state, plan: event.plan, busy: false, error: null };
    case "executing":
      if (event.requestId !== state.requestId || state.request === null) return state;
      return { ...state, busy: true, error: null };
    case "executed":
      if (event.requestId !== state.requestId || state.request === null) return state;
      return { ...state, receipt: event.receipt, busy: false, error: null };
    case "failed":
      if (event.requestId !== state.requestId || state.request === null) return state;
      return { ...state, plan: null, busy: false, error: event.message };
    case "closed":
      // The counter carries over, so anything still in flight for the dialog
      // just closed can no longer land on the next one.
      return { ...createKubernetesActionState(), requestId: state.requestId + 1 };
  }
}
