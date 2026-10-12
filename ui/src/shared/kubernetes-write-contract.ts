/**
 * Acting on a workload the Kubernetes pane already listed.
 *
 * The renderer holds a row handle its own snapshot minted and a plan handle
 * the sidecar minted. It never holds a namespace, a name or a UID, so the
 * worst a compromised renderer can ask for is an action on a resource the
 * operator is already looking at — and only after the operator approved that
 * exact plan.
 */

/**
 * The closed set of actions.
 *
 * Scaling names a count; cordon and uncordon name nothing at all. There is no
 * shape here that can describe a delete, an exec, or an arbitrary patch.
 */
export type KubernetesWriteAction =
  | { kind: "scale-deployment"; replicas: number }
  | { kind: "cordon" }
  | { kind: "uncordon" };

/** The ceiling the sidecar and the core both enforce. */
export const MAX_KUBERNETES_REPLICAS = 1_000;

export interface KubernetesActionPlan {
  planHandle: string;
  rowHandle: string;
  /** Display only. The workload comes from the handle. */
  resourceName: string;
  action: string;
  actionLabel: string;
  summary: string;
  dangerous: boolean;
  restoreDescription: string | null;
  confirmed: boolean;
  expiresInSeconds: number;
}

export interface KubernetesActionReceipt {
  planHandle: string;
  resourceName: string;
  actionLabel: string;
  /**
   * Whether the cluster, read back afterwards, is in the state the plan said
   * it would be. An accepted patch is not the same claim.
   */
  verified: boolean;
  detail: string;
  restored: boolean;
}

export interface KubernetesActionCancellation {
  cancelled: boolean;
}

export interface KubernetesWriteApi {
  planKubernetesWorkloadAction(
    bindingHandle: string,
    snapshotHandle: string,
    rowHandle: string,
    resourceName: string,
    action: KubernetesWriteAction,
  ): Promise<unknown>;
  confirmKubernetesWorkloadAction(bindingHandle: string, planHandle: string): Promise<unknown>;
  executeKubernetesWorkloadAction(bindingHandle: string, planHandle: string): Promise<unknown>;
  cancelKubernetesWorkloadAction(bindingHandle: string, planHandle: string): Promise<unknown>;
  /**
   * Open a terminal window with a shell inside a listed, running pod.
   *
   * Filed with the writes for the reason a container shell is: everything the
   * plan/confirm pipeline describes before doing, an operator in a shell can
   * do by typing. It opens a window and runs nothing on the caller's behalf.
   * No binding handle — the window opens against the current target — and the
   * name is display only, for the window's title bar.
   */
  openKubernetesPodTerminal(
    snapshotHandle: string,
    rowHandle: string,
    podName: string,
    /** One of the pod's containers; null for its default one. */
    container: string | null,
  ): Promise<unknown>;
}

const MAX_TEXT = 512;
const FIRST_PRINTABLE_CODE_POINT = 0x20;
const ACTION_IDS = ["scale-deployment", "cordon", "uncordon"] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && keys.every((key) => key in value);
}

function isBoundedText(value: unknown, limit = MAX_TEXT): value is string {
  return typeof value === "string" && value.length <= limit;
}

function isHandle(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 128;
}

/**
 * Written as a scan rather than a character-class regular expression: the
 * class would need literal control characters or escapes for them in the
 * source, and a source file carrying invisible bytes is one nobody can review.
 */
function carriesControlCharacter(value: string): boolean {
  for (const character of value) {
    if ((character.codePointAt(0) ?? 0) < FIRST_PRINTABLE_CODE_POINT) return true;
  }
  return false;
}

export function isKubernetesWriteAction(value: unknown): value is KubernetesWriteAction {
  if (!isRecord(value)) return false;
  if (value.kind === "cordon" || value.kind === "uncordon") {
    return hasExactKeys(value, ["kind"]);
  }
  return (
    hasExactKeys(value, ["kind", "replicas"]) &&
    value.kind === "scale-deployment" &&
    typeof value.replicas === "number" &&
    Number.isInteger(value.replicas) &&
    value.replicas >= 0 &&
    value.replicas <= MAX_KUBERNETES_REPLICAS
  );
}

/**
 * The name a dialog will display, on its way back down.
 *
 * Bounded and free of control characters, and that is the whole contract:
 * nothing resolves through it, so it is checked for being displayable rather
 * than for being true.
 */
export function isKubernetesResourceName(value: unknown): value is string {
  return typeof value === "string" &&
    value.length > 0 &&
    value.length <= 256 &&
    !carriesControlCharacter(value);
}

/**
 * A pod as a window title shows it, `namespace/name`: display only, like a
 * resource name, but long enough for a 63-byte namespace and a 253-byte pod.
 */
export function isKubernetesPodDisplayName(value: unknown): value is string {
  return typeof value === "string" &&
    value.length > 0 &&
    value.length <= 512 &&
    !carriesControlCharacter(value);
}

export function isKubernetesActionPlan(value: unknown): value is KubernetesActionPlan {
  if (!isRecord(value)) return false;
  return (
    hasExactKeys(value, [
      "planHandle",
      "rowHandle",
      "resourceName",
      "action",
      "actionLabel",
      "summary",
      "dangerous",
      "restoreDescription",
      "confirmed",
      "expiresInSeconds",
    ]) &&
    isHandle(value.planHandle) &&
    isHandle(value.rowHandle) &&
    isBoundedText(value.resourceName, 256) &&
    typeof value.action === "string" &&
    (ACTION_IDS as readonly string[]).includes(value.action) &&
    isBoundedText(value.actionLabel, 64) &&
    isBoundedText(value.summary) &&
    typeof value.dangerous === "boolean" &&
    (value.restoreDescription === null || isBoundedText(value.restoreDescription)) &&
    typeof value.confirmed === "boolean" &&
    typeof value.expiresInSeconds === "number" &&
    Number.isInteger(value.expiresInSeconds) &&
    value.expiresInSeconds > 0 &&
    value.expiresInSeconds <= 3_600
  );
}

export function isKubernetesActionReceipt(value: unknown): value is KubernetesActionReceipt {
  if (!isRecord(value)) return false;
  return (
    hasExactKeys(value, [
      "planHandle",
      "resourceName",
      "actionLabel",
      "verified",
      "detail",
      "restored",
    ]) &&
    isHandle(value.planHandle) &&
    isBoundedText(value.resourceName, 256) &&
    isBoundedText(value.actionLabel, 64) &&
    typeof value.verified === "boolean" &&
    isBoundedText(value.detail) &&
    typeof value.restored === "boolean"
  );
}

export function isKubernetesActionCancellation(
  value: unknown,
): value is KubernetesActionCancellation {
  if (!isRecord(value)) return false;
  return hasExactKeys(value, ["cancelled"]) && value.cancelled === true;
}
