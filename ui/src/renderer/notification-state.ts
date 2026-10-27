export const MAX_NOTIFICATIONS = 64;
export const DEFAULT_NOTIFICATION_TIMEOUT_MS = 3_000;
export const ERROR_NOTIFICATION_TIMEOUT_MS = 5_000;
export type NotificationSeverity = "info" | "success" | "warning" | "error";
/** Fixed intents never accept caller text. Explicit public page notices use a separate action. */
export type NotificationIntent = "background-task-started" | "settings-saved" | "application-log-copied" | "attention-required" | "operation-failed" | "manual-action-required";
export interface AppNotification {
  id: string; intent: NotificationIntent | "page-message"; severity: NotificationSeverity; message: string;
  expiresAt: number | null; source?: string; createdAt?: number; read?: boolean;
}
export interface NotificationState {
  nextId: number;
  /** Only the latest toast; expiry never deletes history. */
  notifications: AppNotification[];
  history: AppNotification[];
  omitted: number;
}
export type NotificationAction =
  | { type: "show"; intent: NotificationIntent; now: number }
  | { type: "message"; source: string; message: string; severity: NotificationSeverity; now: number }
  | { type: "dismiss" | "remove"; id: string }
  | { type: "expire" | "resume"; now: number }
  | { type: "read" | "clear" };
interface NotificationSpec { severity: NotificationSeverity; message: string; timeoutMs: number | null }
export const initialNotificationState: NotificationState = { nextId: 0, notifications: [], history: [], omitted: 0 };
export function notificationTimeoutMs(severity: NotificationSeverity): number {
  return severity === "error" ? ERROR_NOTIFICATION_TIMEOUT_MS : DEFAULT_NOTIFICATION_TIMEOUT_MS;
}
/** Notices already intended for display; never pass command output, scripts or evidence here. */
export function publicNotificationText(text: string): string {
  const safe = text.replace(/[\u0000-\u0008\u000b-\u001f\u007f\u202a-\u202e\u2066-\u2069]/gu, "")
    .replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|$)/gu, "[私钥已隐藏]")
    .replace(/(\b(?:password|passwd|pwd|token|secret|authorization|api[_-]?key)|密码|口令)(\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s;,]+)/giu, "$1$2[已隐藏]")
    .replace(/(\b[a-z]+:\/\/)[^\s/@]+:[^\s/@]+@/giu, "$1[已隐藏]@");
  return safe.length > 4000 ? `${safe.slice(0,4000)}\n【内容已截断】` : safe;
}
export function notificationReducer(state: NotificationState, action: NotificationAction): NotificationState {
  switch (action.type) {
    case "show": case "message": {
      if (!Number.isSafeInteger(action.now) || action.now < 0 || action.now > Number.MAX_SAFE_INTEGER - ERROR_NOTIFICATION_TIMEOUT_MS) return state;
      const spec = action.type === "show" ? notificationSpec(action.intent) :
        ["info","success","warning","error"].includes(action.severity) && typeof action.message === "string" && typeof action.source === "string" && action.source.length <= 80
          ? {severity:action.severity,message:publicNotificationText(action.message),timeoutMs:notificationTimeoutMs(action.severity)} : null;
      if (!spec || !spec.message) return state;
      const source = action.type === "message" ? action.source : "应用";
      const intent = action.type === "show" ? action.intent : "page-message";
      const existing = state.notifications.find((n) => n.intent === intent && n.source === source && n.message === spec.message);
      const nextId = existing ? state.nextId : state.nextId >= Number.MAX_SAFE_INTEGER ? 1 : state.nextId + 1;
      const item: AppNotification = { id:existing?.id ?? `notification-${nextId}`,intent,source,severity:spec.severity,message:spec.message,createdAt:action.now,expiresAt:action.now + notificationTimeoutMs(spec.severity),read:false };
      const history = [item,...state.history.filter((n) => n.id !== item.id)];
      const excess = Math.max(0,history.length-MAX_NOTIFICATIONS);
      return {nextId,notifications:[item],history:history.slice(0,MAX_NOTIFICATIONS),omitted:state.omitted+excess};
    }
    case "dismiss": return {...state,notifications:state.notifications.filter((n) => n.id !== action.id)};
    case "remove": return {...state,notifications:state.notifications.filter((n) => n.id !== action.id),history:state.history.filter((n) => n.id !== action.id)};
    case "expire": {
      if (!Number.isSafeInteger(action.now) || action.now < 0) return state;
      const notifications=state.notifications.filter((n) => n.expiresAt === null || n.expiresAt > action.now);
      return notifications.length === state.notifications.length ? state : {...state,notifications};
    }
    case "resume": if (!Number.isSafeInteger(action.now) || action.now < 0 || action.now > Number.MAX_SAFE_INTEGER - ERROR_NOTIFICATION_TIMEOUT_MS) return state; return {...state,notifications:state.notifications.map((n) => ({...n,expiresAt:action.now+notificationTimeoutMs(n.severity)}))};
    case "read": return !state.notifications.length && state.history.every((n) => n.read) ? state : {...state,notifications:[],history:state.history.map((n) => ({...n,read:true}))};
    case "clear": return {...state,notifications:[],history:[],omitted:0};
  }
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
        message: "需要人工处理；请在通知中心查看并跟进。",
        timeoutMs: DEFAULT_NOTIFICATION_TIMEOUT_MS,
      };
    default:
      return null;
  }
}
