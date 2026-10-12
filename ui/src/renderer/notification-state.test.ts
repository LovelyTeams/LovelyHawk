import { describe, expect, it } from "vitest";

import {
  DEFAULT_NOTIFICATION_TIMEOUT_MS,
  ERROR_NOTIFICATION_TIMEOUT_MS,
  MAX_NOTIFICATIONS,
  initialNotificationState,
  notificationReducer,
  notificationTimeoutMs,
  type AppNotification,
  type NotificationAction,
  type NotificationIntent,
  type NotificationState,
} from "./notification-state";

const intents: NotificationIntent[] = [
  "background-task-started",
  "settings-saved",
  "application-log-copied",
  "attention-required",
  "operation-failed",
  "manual-action-required",
];

function show(
  state: NotificationState,
  intent: NotificationIntent,
  now: number,
): NotificationState {
  return notificationReducer(state, { type: "show", intent, now });
}

describe("notification state", () => {
  it("uses fixed messages and ignores caller-provided hostile fields", () => {
    const messages = intents.map((intent) => show(initialNotificationState, intent, 0)
      .notifications[0]?.message);
    expect(messages).toEqual([
      "后台任务已开始。",
      "设置已安全保存。",
      "已复制脱敏后的应用日志。",
      "需要人工检查后再继续。",
      "操作失败；详细内容未显示。",
      "需要人工处理；完成后请手动关闭此通知。",
    ]);
    const action = {
      type: "show",
      intent: "settings-saved",
      now: 0,
      message: "ssh://name:secret@host/private/path Error Debug credential",
    } as unknown as NotificationAction;
    expect(notificationReducer(initialNotificationState, action).notifications[0]?.message)
      .toBe("设置已安全保存。");
  });

  it("deduplicates intents, preserves ids, moves renewals first, and resets expiry", () => {
    const first = show(initialNotificationState, "settings-saved", 100);
    const id = first.notifications[0]!.id;
    const withNewer = show(first, "background-task-started", 200);
    const renewed = show(withNewer, "settings-saved", 2_000);
    expect(renewed.notifications.map(({ intent }) => intent)).toEqual([
      "settings-saved",
      "background-task-started",
    ]);
    expect(renewed.notifications[0]).toMatchObject({
      id,
      expiresAt: 5_000,
    });
    expect(notificationReducer(renewed, { type: "expire", now: 3_100 })).toBe(renewed);
    expect(notificationReducer(renewed, { type: "expire", now: 5_000 })
      .notifications.map(({ intent }) => intent)).toEqual([]);
  });

  it("uses three seconds for timed non-errors, five seconds for errors, and supports persistent dismissal", () => {
    expect(notificationTimeoutMs("info")).toBe(DEFAULT_NOTIFICATION_TIMEOUT_MS);
    expect(notificationTimeoutMs("success")).toBe(DEFAULT_NOTIFICATION_TIMEOUT_MS);
    expect(notificationTimeoutMs("warning")).toBe(DEFAULT_NOTIFICATION_TIMEOUT_MS);
    expect(notificationTimeoutMs("error")).toBe(ERROR_NOTIFICATION_TIMEOUT_MS);
    const error = show(initialNotificationState, "operation-failed", 20);
    expect(error.notifications[0]?.expiresAt).toBe(5_020);
    const persistent = show(error, "manual-action-required", 30);
    expect(persistent.notifications[0]?.expiresAt).toBeNull();
    const dismissed = notificationReducer(persistent, {
      type: "dismiss",
      id: persistent.notifications[0]!.id,
    });
    expect(dismissed.notifications.some(({ intent }) => intent === "manual-action-required"))
      .toBe(false);
  });

  it("bounds malformed floods and evicts the oldest timed notification first", () => {
    const notifications = Array.from({ length: MAX_NOTIFICATIONS }, (_, index): AppNotification => ({
      id: `existing-${index}`,
      intent: "attention-required",
      severity: "warning",
      message: "fixed",
      expiresAt: index === MAX_NOTIFICATIONS - 1 ? 10_000 : null,
    }));
    const state = show({ nextId: MAX_NOTIFICATIONS, notifications }, "settings-saved", 0);
    expect(state.notifications).toHaveLength(MAX_NOTIFICATIONS);
    expect(state.notifications[0]?.intent).toBe("settings-saved");
    expect(state.notifications.some(({ id }) => id === `existing-${MAX_NOTIFICATIONS - 1}`))
      .toBe(false);
  });

  it("fails closed for invalid clocks and unknown runtime intents", () => {
    expect(show(initialNotificationState, "settings-saved", Number.NaN))
      .toBe(initialNotificationState);
    const invalid = {
      type: "show",
      intent: "private-path-payload",
      now: 0,
    } as unknown as NotificationAction;
    expect(notificationReducer(initialNotificationState, invalid)).toBe(initialNotificationState);
  });
});
