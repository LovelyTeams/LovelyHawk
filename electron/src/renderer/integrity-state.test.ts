import { describe, expect, it } from "vitest";

import {
  INTEGRITY_PRESET_DEFINITIONS,
  type IntegrityBaselineList,
  type IntegrityComparison,
  type IntegrityComparisonPoll,
  type IntegrityPresetCatalog,
} from "../shared/integrity-contract";
import { createIntegrityState, integrityReducer } from "./integrity-state";

const catalog: IntegrityPresetCatalog = {
  presets: INTEGRITY_PRESET_DEFINITIONS.map((preset) => ({ ...preset })),
  maximumSelected: 6,
};

const baselines: IntegrityBaselineList = {
  items: [
    {
      baselineHandle: "baseline-one",
      createdAt: "2026-08-25T00:00:00Z",
      paths: ["/var/www"],
      pathsTruncated: false,
      redactedPathCount: 0,
      textProjected: false,
      fileCount: 2,
    },
    {
      baselineHandle: "baseline-two",
      createdAt: "2026-08-24T00:00:00Z",
      paths: ["/usr/bin"],
      pathsTruncated: false,
      redactedPathCount: 0,
      textProjected: false,
      fileCount: 3,
    },
  ],
  truncated: false,
};

const comparison: IntegrityComparison = {
  baselineHandle: "baseline-one",
  added: 1,
  removed: 0,
  modified: 0,
  displayed: 1,
  redactedPathCount: 0,
  textProjected: false,
  truncated: false,
  entries: [{
    path: "/srv/added",
    pathRedacted: false,
    pathTruncated: false,
    pathProjected: false,
    kind: "added",
    severity: "high",
  }],
};

function listedState(scope = "binding-new") {
  let state = createIntegrityState(scope);
  state = integrityReducer(state, { type: "catalog-started", scope });
  state = integrityReducer(state, { type: "catalog-loaded", scope, catalog });
  state = integrityReducer(state, { type: "list-started", scope, request: 1 });
  return integrityReducer(state, { type: "list-loaded", scope, request: 1, list: baselines });
}

function runningState() {
  let state = listedState();
  state = integrityReducer(state, {
    type: "comparison-start-requested",
    scope: "binding-new",
    request: 2,
    baselineHandle: "baseline-one",
  });
  return integrityReducer(state, {
    type: "comparison-started",
    scope: "binding-new",
    request: 2,
    baselineHandle: "baseline-one",
    started: {
      operationHandle: "operation-one",
      baselineHandle: "baseline-one",
      stage: "running",
      expiresInSeconds: 300,
    },
  });
}

function poll(stage: IntegrityComparisonPoll["stage"], cursor: number): IntegrityComparisonPoll {
  return {
    operationHandle: "operation-one",
    baselineHandle: "baseline-one",
    stage,
    events: [{ sequence: cursor, kind: stage === "running" ? "started" : stage }],
    nextEventCursor: cursor,
    eventsTruncated: false,
    comparison: stage === "completed" ? comparison : null,
    errorCode: stage === "failed" ? "comparison-failed" : null,
  };
}

describe("integrity reducer", () => {
  it("drops late baseline lists from an old binding or request", () => {
    let state = createIntegrityState("binding-new");
    state = integrityReducer(state, {
      type: "list-started",
      scope: "binding-new",
      request: 7,
    });
    const oldBinding = integrityReducer(state, {
      type: "list-loaded",
      scope: "binding-old",
      request: 7,
      list: baselines,
    });
    const oldRequest = integrityReducer(state, {
      type: "list-loaded",
      scope: "binding-new",
      request: 6,
      list: baselines,
    });
    expect(oldBinding).toBe(state);
    expect(oldRequest).toBe(state);
    expect(state.baselineList).toBeNull();
  });

  it("rejects a late start after target switch and clears opaque operation state", () => {
    let state = listedState();
    state = integrityReducer(state, {
      type: "comparison-start-requested",
      scope: "binding-new",
      request: 2,
      baselineHandle: "baseline-one",
    });
    state = integrityReducer(state, { type: "scope-changed", scope: "binding-next" });
    const late = integrityReducer(state, {
      type: "comparison-started",
      scope: "binding-new",
      request: 2,
      baselineHandle: "baseline-one",
      started: {
        operationHandle: "operation-late",
        baselineHandle: "baseline-one",
        stage: "running",
        expiresInSeconds: 300,
      },
    });
    expect(late).toBe(state);
    expect(late.operationHandle).toBeNull();
    expect(late.baselineList).toBeNull();
  });

  it("correlates poll request, cursor, operation, and baseline before applying", () => {
    let state = runningState();
    state = integrityReducer(state, {
      type: "poll-started",
      scope: "binding-new",
      operationHandle: "operation-one",
      request: 3,
      afterEvent: 0,
    });
    const wrongCursor = integrityReducer(state, {
      type: "poll-loaded",
      scope: "binding-new",
      operationHandle: "operation-one",
      request: 3,
      afterEvent: 1,
      poll: poll("completed", 2),
    });
    const wrongHandle = integrityReducer(state, {
      type: "poll-loaded",
      scope: "binding-new",
      operationHandle: "operation-other",
      request: 3,
      afterEvent: 0,
      poll: poll("completed", 2),
    });
    expect(wrongCursor).toBe(state);
    expect(wrongHandle).toBe(state);
    expect(state.comparison).toBeNull();
  });

  it("advances the cursor monotonically and accepts one correlated completion", () => {
    let state = runningState();
    state = integrityReducer(state, {
      type: "poll-started",
      scope: "binding-new",
      operationHandle: "operation-one",
      request: 3,
      afterEvent: 0,
    });
    state = integrityReducer(state, {
      type: "poll-loaded",
      scope: "binding-new",
      operationHandle: "operation-one",
      request: 3,
      afterEvent: 0,
      poll: poll("running", 1),
    });
    expect(state.eventCursor).toBe(1);
    state = integrityReducer(state, {
      type: "poll-started",
      scope: "binding-new",
      operationHandle: "operation-one",
      request: 4,
      afterEvent: 1,
    });
    state = integrityReducer(state, {
      type: "poll-loaded",
      scope: "binding-new",
      operationHandle: "operation-one",
      request: 4,
      afterEvent: 1,
      poll: poll("completed", 2),
    });
    expect(state.operationStage).toBe("completed");
    expect(state.eventCursor).toBe(2);
    expect(state.comparison).toEqual(comparison);
  });

  it("blocks baseline switches while active and consumes cancellation once", () => {
    let state = runningState();
    const switched = integrityReducer(state, {
      type: "baseline-selected",
      scope: "binding-new",
      handle: "baseline-two",
    });
    expect(switched).toBe(state);
    state = integrityReducer(state, {
      type: "cancel-started",
      scope: "binding-new",
      operationHandle: "operation-one",
    });
    state = integrityReducer(state, {
      type: "cancelled",
      scope: "binding-new",
      operationHandle: "operation-one",
    });
    expect(state.operationStage).toBe("cancelled");
    expect(state.comparison).toBeNull();
    const duplicate = integrityReducer(state, {
      type: "cancelled",
      scope: "binding-new",
      operationHandle: "operation-one",
    });
    expect(duplicate).toBe(state);
  });
});
