import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { AppNotification, NotificationState } from "./notification-state";
import {
  initialNotificationState,
  notificationReducer,
} from "./notification-state";

type EffectSetup = () => void | (() => void);

const hookHarness = vi.hoisted(() => ({
  effects: [] as EffectSetup[],
}));

vi.mock("react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react")>();
  return {
    ...actual,
    useEffect: (effect: EffectSetup) => {
      hookHarness.effects.push(effect);
    },
    useRef: <T,>(initialValue: T) => ({ current: initialValue }),
  };
});

import { NotificationStack } from "./NotificationStack";

function renderTimerEffect(
  notifications: readonly AppNotification[],
  onExpire: (now: number) => void,
): void | (() => void) {
  hookHarness.effects.length = 0;
  NotificationStack({
    notifications,
    modalOpen: false,
    onDismiss: vi.fn(),
    onExpire,
  });
  expect(hookHarness.effects).toHaveLength(1);
  return hookHarness.effects[0]?.();
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(0);
});

afterEach(() => {
  hookHarness.effects.length = 0;
  vi.useRealTimers();
});

describe("NotificationStack timer effect lifecycle", () => {
  it("cleans the previous effect and does not let its old deadline delete a renewal", () => {
    let state: NotificationState = notificationReducer(initialNotificationState, {
      type: "show",
      intent: "settings-saved",
      now: 0,
    });
    const onExpire = vi.fn((now: number) => {
      state = notificationReducer(state, { type: "expire", now });
    });
    const cleanupOld = renderTimerEffect(state.notifications, onExpire);

    vi.advanceTimersByTime(1_000);
    state = notificationReducer(state, {
      type: "show",
      intent: "settings-saved",
      now: Date.now(),
    });
    expect(state.notifications[0]?.expiresAt).toBe(4_000);
    if (typeof cleanupOld === "function") cleanupOld();
    const cleanupRenewed = renderTimerEffect(state.notifications, onExpire);

    vi.advanceTimersByTime(2_000);
    expect(Date.now()).toBe(3_000);
    expect(onExpire).not.toHaveBeenCalled();
    expect(notificationReducer(state, { type: "expire", now: 3_000 })).toBe(state);

    vi.advanceTimersByTime(1_000);
    expect(onExpire).toHaveBeenCalledOnce();
    expect(onExpire).toHaveBeenCalledWith(4_000);
    expect(state.notifications).toEqual([]);
    if (typeof cleanupRenewed === "function") cleanupRenewed();
  });

  it("cancels the armed timer during unmount cleanup", () => {
    const state = notificationReducer(initialNotificationState, {
      type: "show",
      intent: "operation-failed",
      now: 0,
    });
    const onExpire = vi.fn();
    const cleanup = renderTimerEffect(state.notifications, onExpire);
    expect(cleanup).toBeTypeOf("function");
    if (typeof cleanup === "function") cleanup();

    vi.advanceTimersByTime(5_000);
    expect(onExpire).not.toHaveBeenCalled();
  });

  it("expires manual-action toast but retains its history", () => {
    const state = notificationReducer(initialNotificationState, {
      type: "show",
      intent: "manual-action-required",
      now: 0,
    });
    const onExpire = vi.fn();
    expect(renderTimerEffect(state.notifications, onExpire)).toBeTypeOf("function");
    vi.advanceTimersByTime(3000);
    expect(onExpire).toHaveBeenCalledOnce();
    expect(notificationReducer(state,{type:"expire",now:3000}).history).toHaveLength(1);
  });
});
