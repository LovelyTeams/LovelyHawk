import { useEffect, useRef } from "react";

import type { AppNotification } from "./notification-state";
import "./notification-stack.css";

export interface NotificationStackProps {
  notifications: readonly AppNotification[];
  modalOpen: boolean;
  onDismiss(id: string): void;
  onExpire(now: number): void;
  clock?: () => number;
}

const severityLabels: Record<AppNotification["severity"], string> = {
  info: "信息",
  success: "成功",
  warning: "警告",
  error: "错误",
};

interface NotificationFocusTarget {
  isConnected: boolean;
  focus(options?: FocusOptions): void;
}

export function restoreNotificationFocus(target: NotificationFocusTarget | null): void {
  if (target?.isConnected) target.focus({ preventScroll: true });
}

export function NotificationStack({
  notifications,
  modalOpen,
  onDismiss,
  onExpire,
  clock = Date.now,
}: NotificationStackProps) {
  const returnFocusRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    const now = clock();
    const nextDeadline = notifications.reduce<number | null>((next, notification) => {
      if (notification.expiresAt === null) return next;
      return next === null || notification.expiresAt < next
        ? notification.expiresAt
        : next;
    }, null);
    if (nextDeadline === null) return;
    const timer = globalThis.setTimeout(
      () => onExpire(clock()),
      Math.max(0, Math.min(nextDeadline - now, 2_147_483_647)),
    );
    return () => globalThis.clearTimeout(timer);
  }, [clock, notifications, onExpire]);

  return (
    <div
      className={modalOpen
        ? "notification-overlay-layer is-modal-blocked"
        : "notification-overlay-layer"}
      aria-hidden={modalOpen ? true : undefined}
      inert={modalOpen ? true : undefined}
      onFocusCapture={(event) => {
        const previous = event.relatedTarget;
        if (
          previous instanceof HTMLElement &&
          !event.currentTarget.contains(previous)
        ) {
          returnFocusRef.current = previous;
        }
      }}
    >
      {notifications.length === 0 ? null : (
        <ol
          className="notification-stack"
          aria-label="应用通知"
          aria-live={modalOpen ? "off" : "polite"}
          aria-relevant="additions text"
        >
          {notifications.map((notification) => (
            <li
              key={notification.id}
              className={`notification-card is-${notification.severity}`}
              role={notification.severity === "error" ? "alert" : "status"}
              aria-atomic="true"
            >
              <span className="notification-marker" aria-hidden="true" />
              <div>
                <strong>{severityLabels[notification.severity]}</strong>
                <p>{notification.message}</p>
              </div>
              <button
                className="notification-dismiss"
                type="button"
                aria-label={`关闭${severityLabels[notification.severity]}通知`}
                onClick={() => {
                  restoreNotificationFocus(returnFocusRef.current);
                  onDismiss(notification.id);
                }}
              >
                ×
              </button>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}
