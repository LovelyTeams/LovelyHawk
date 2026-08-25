import { describe, expect, it } from "vitest";

import type { ApplicationLogSnapshot } from "../shared/application-log-contract";
import {
  applicationLogReducer,
  initialApplicationLogState,
} from "./application-log-state";

const snapshot: ApplicationLogSnapshot = {
  capacity: 500,
  totalBuffered: 1,
  totalMatched: 1,
  displayed: 1,
  currentLevel: "info",
  generation: 1,
  entries: [{
    sequence: 1,
    timestampUnixMs: 1_777_000_000_000,
    level: "info",
    module: "lovelyres_test",
    message: "ready",
    details: [],
  }],
};

describe("application log reducer", () => {
  it("drops late loads after a newer refresh starts", () => {
    let state = applicationLogReducer(initialApplicationLogState, { type: "load-started", request: 1 });
    state = applicationLogReducer(state, { type: "load-started", request: 2 });
    expect(applicationLogReducer(state, {
      type: "load-completed", request: 1, snapshot,
    })).toBe(state);
    expect(applicationLogReducer(state, {
      type: "load-completed", request: 2, snapshot,
    }).snapshot).toBe(snapshot);
  });

  it("keeps the previous bounded snapshot visible when a refresh fails", () => {
    let state = applicationLogReducer(initialApplicationLogState, { type: "load-started", request: 1 });
    state = applicationLogReducer(state, { type: "load-completed", request: 1, snapshot });
    state = applicationLogReducer(state, { type: "load-started", request: 2 });
    state = applicationLogReducer(state, { type: "load-failed", request: 2, error: "redacted" });
    expect(state.status).toBe("error");
    expect(state.snapshot).toBe(snapshot);
    expect(state.error).toBe("redacted");
  });

  it("updates only exact bounded filter state", () => {
    const state = applicationLogReducer(initialApplicationLogState, {
      type: "filter-changed",
      filter: { minimumLevel: "warn", search: "timeout" },
    });
    expect(state.filter).toEqual({ minimumLevel: "warn", search: "timeout" });
  });

  it("clears visible rows and rejects a load that completed across the clear boundary", () => {
    let state = applicationLogReducer(initialApplicationLogState, { type: "load-started", request: 1 });
    state = applicationLogReducer(state, { type: "load-completed", request: 1, snapshot });
    state = applicationLogReducer(state, { type: "load-started", request: 2 });
    state = applicationLogReducer(state, { type: "buffer-cleared", generation: 7 });
    expect(state.snapshot).toEqual({
      ...snapshot,
      totalBuffered: 0,
      totalMatched: 0,
      displayed: 0,
      generation: 7,
      entries: [],
    });
    expect(state.request).toBeNull();
    expect(applicationLogReducer(state, {
      type: "load-completed",
      request: 2,
      snapshot,
    })).toBe(state);
  });
});
