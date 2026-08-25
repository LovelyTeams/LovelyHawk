export const MAX_NOTIFICATIONS = 64;
export const DEFAULT_NOTIFICATION_TIMEOUT_MS = 3_000;
export const ERROR_NOTIFICATION_TIMEOUT_MS = 5_000;

export type NotificationSeverity = "info" | "success" | "warning" | "error";

/**
 * Renderer notifications carry no caller-provided text. Each intent resolves to a
 * fixed public message here so errors, handles, credentials, and paths cannot be
 * copied into the toast surface by mistake.
 */
export type NotificationIntent =
  | "background-task-started"
  | "settings-saved"
  | "application-log-copied"
  | "attention-required"
  | "operation-failed"
  | "manual-action-required";

export interface AppNotification {
  id: string;
  intent: NotificationIntent;
  severity: NotificationSeverity;
  message: string;
  expiresAt: number | null;
}

export interface NotificationState {
  nextId: number;
  /** Newest first. */
  notifications: AppNotification[];
}

export type NotificationAction =
  | { type: "show"; intent: NotificationIntent; now: number }
  | { type: "dismiss"; id: string }
  | { type: "expire"; now: number }
  | { type: "clear" };

interface NotificationSpec {
  severity: NotificationSeverity;
  message: string;
  timeoutMs: number | null;
}

export const initialNotificationState: NotificationState = {
  nextId: 0,
  notifications: [],
};

export function notificationTimeoutMs(severity: NotificationSeverity): number {
  return severity === "error"
    ? ERROR_NOTIFICATION_TIMEOUT_MS
    : DEFAULT_NOTIFICATION_TIMEOUT_MS;
}

export function notificationReducer(
  state: NotificationState,
  action: NotificationAction,
): NotificationState {
  switch (action.type) {
    case "show":
      return showNotification(state, action.intent, action.now);
    case "dismiss": {
      const notifications = state.notifications.filter(({ id }) => id !== action.id);
      return notifications.length === state.notifications.length
        ? state
        : { ...state, notifications };
    }
    case "expire": {
      if (!isSafeTimestamp(action.now)) return state;
      const notifications = state.notifications.filter(
        ({ expiresAt }) => expiresAt === null || expiresAt > action.now,
      );
      return notifications.length === state.notifications.length
        ? state
        : { ...state, notifications };
    }
    case "clear":
      return state.notifications.length === 0
        ? state
        : { ...state, notifications: [] };
  }
}

function showNotification(
  state: NotificationState,
  intent: NotificationIntent,
  now: number,
): NotificationState {
  if (!isSafeTimestamp(now)) return state;
  const spec = notificationSpec(intent);
  if (spec === null) return state;
  const expiresAt = spec.timeoutMs === null ? null : now + spec.timeoutMs;
  const existingIndex = state.notifications.findIndex(
    (notification) => notification.intent === intent,
  );
  if (existingIndex >= 0) {
    const existing = state.notifications[existingIndex];
    if (existing === undefined) return state;
    const notifications = state.notifications.slice();
    notifications.splice(existingIndex, 1);
    notifications.unshift({
      ...existing,
      severity: spec.severity,
      message: spec.message,
      expiresAt,
    });
    return { ...state, notifications };
  }

  const nextId = state.nextId >= Number.MAX_SAFE_INTEGER ? 1 : state.nextId + 1;
  const notifications = state.notifications.slice();
  if (notifications.length >= MAX_NOTIFICATIONS) {
    notifications.splice(oldestEvictionIndex(notifications), 1);
  }
  notifications.unshift({
    id: `notification-${nextId}`,
    intent,
    severity: spec.severity,
    message: spec.message,
    expiresAt,
  });
  return { nextId, notifications };
}

function oldestEvictionIndex(notifications: readonly AppNotification[]): number {
  for (let index = notifications.length - 1; index >= 0; index -= 1) {
    if (notifications[index]?.expiresAt !== null) return index;
  }
  return notifications.length - 1;
}

function isSafeTimestamp(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0 &&
    value <= Number.MAX_SAFE_INTEGER - ERROR_NOTIFICATION_TIMEOUT_MS;
}

function notificationSpec(intent: NotificationIntent): NotificationSpec | null {
  switch (intent) {
    case "background-task-started":
      return {
        severity: "info",
        message: "后台任务已开始。",
        timeoutMs: DEFAULT_NOTIFICATION_TIMEOUT_MS,
      };
    case "settings-saved":
      return {
        severity: "success",
        message: "设置已安全保存。",
        timeoutMs: DEFAULT_NOTIFICATION_TIMEOUT_MS,
      };
    case "application-log-copied":
      return {
        severity: "success",
        message: "已复制脱敏后的应用日志。",
        timeoutMs: DEFAULT_NOTIFICATION_TIMEOUT_MS,
      };
    case "attention-required":
      return {
        severity: "warning",
        message: "需要人工检查后再继续。",
        timeoutMs: DEFAULT_NOTIFICATION_TIMEOUT_MS,
      };
    case "operation-failed":
      return {
        severity: "error",
        message: "操作失败；详细内容未显示。",
        timeoutMs: ERROR_NOTIFICATION_TIMEOUT_MS,
      };
    case "manual-action-required":
      return {
        severity: "warning",
        message: "需要人工处理；完成后请手动关闭此通知。",
        timeoutMs: null,
      };
    default:
      return null;
  }
}
