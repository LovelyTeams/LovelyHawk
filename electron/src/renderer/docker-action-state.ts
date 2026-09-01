import type {
  DockerActionPlan,
  DockerActionReceipt,
  DockerWriteAction,
} from "../shared/docker-write-contract";

/**
 * One container action at a time, from the moment the operator picks one to
 * the moment they close the receipt.
 *
 * Kept apart from the read state on purpose: a snapshot refresh must never
 * disturb a dialog the operator is reading, and an action must never look like
 * it succeeded because a list happened to reload.
 */
export interface DockerActionState {
  /** Null when no dialog is open. Everything else is meaningless without it. */
  request: {
    containerHandle: string;
    containerName: string;
    action: DockerWriteAction;
    actionLabel: string;
  } | null;
  plan: DockerActionPlan | null;
  receipt: DockerActionReceipt | null;
  busy: boolean;
  error: string | null;
  /**
   * Which request the in-flight reply belongs to. A reply that names an older
   * one is a late result from a dialog the operator already closed.
   */
  requestId: number;
}

export type DockerActionEvent =
  | {
      type: "opened";
      containerHandle: string;
      containerName: string;
      action: DockerWriteAction;
      actionLabel: string;
    }
  | { type: "planned"; requestId: number; plan: DockerActionPlan }
  | { type: "executing"; requestId: number }
  | { type: "executed"; requestId: number; receipt: DockerActionReceipt }
  | { type: "failed"; requestId: number; message: string }
  | { type: "closed" };

export function createDockerActionState(): DockerActionState {
  return { request: null, plan: null, receipt: null, busy: false, error: null, requestId: 0 };
}

export function dockerActionReducer(
  state: DockerActionState,
  event: DockerActionEvent,
): DockerActionState {
  switch (event.type) {
    case "opened":
      return {
        request: {
          containerHandle: event.containerHandle,
          containerName: event.containerName,
          action: event.action,
          actionLabel: event.actionLabel,
        },
        plan: null,
        receipt: null,
        busy: true,
        error: null,
        requestId: state.requestId + 1,
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
      return { ...state, busy: false, error: event.message };
    case "closed":
      // The counter carries over, so anything still in flight for the dialog
      // just closed can no longer land on the next one.
      return { ...createDockerActionState(), requestId: state.requestId + 1 };
  }
}
