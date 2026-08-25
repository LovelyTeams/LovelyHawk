import { describe, expect, it } from "vitest";

import type {
  QuickDetectionCatalog,
  QuickDetectionPoll,
} from "../shared/quick-detection-contract";
import {
  createQuickDetectionState,
  quickDetectionReducer,
} from "./quick-detection-state";
import type { QuickDetectionState } from "./quick-detection-state";

const catalog: QuickDetectionCatalog = {
  modules: [
    { id: "port-scan", label: "端口", description: "端口", category: "security", categoryLabel: "安全" },
    { id: "ssh-audit", label: "SSH", description: "SSH", category: "security", categoryLabel: "安全" },
  ] as QuickDetectionCatalog["modules"],
  profiles: [
    { id: "selected", label: "自选", moduleIds: [] },
    { id: "competition-triage", label: "排查", moduleIds: ["port-scan", "ssh-audit"] },
  ],
  maximumFindingsPerModule: 200,
};

function runningState(scope = "binding", scanHandle = "scan-1"): QuickDetectionState {
  let state = quickDetectionReducer(createQuickDetectionState(), { type: "scope-changed", scope });
  state = {
    ...state,
    planStatus: "ready",
    plan: {
      planHandle: "plan-1", profile: "selected", moduleIds: ["port-scan", "ssh-audit"],
      moduleCount: 2, maximumFindingsPerModule: 200, expiresInSeconds: 300, summary: "closed plan",
    },
  };
  state = quickDetectionReducer(state, {
    type: "scan-starting", scope, request: 1, planHandle: "plan-1",
  });
  return quickDetectionReducer(state, {
    type: "scan-started", scope, request: 1, planHandle: "plan-1",
    started: { scanHandle, stage: "running", total: 2, expiresInSeconds: 1_800 },
  });
}

describe("quick-detection reducer", () => {
  it("rejects late catalog responses after target scope changes", () => {
    let state = quickDetectionReducer(createQuickDetectionState(), { type: "scope-changed", scope: "binding-a" });
    state = quickDetectionReducer(state, { type: "catalog-started", scope: "binding-a" });
    state = quickDetectionReducer(state, { type: "scope-changed", scope: "binding-b" });
    state = quickDetectionReducer(state, { type: "catalog-loaded", scope: "binding-a", catalog });
    expect(state.scope).toBe("binding-b");
    expect(state.catalog).toBeNull();
  });

  it("switches profiles, toggles modules, and invalidates immutable plans", () => {
    let state = quickDetectionReducer(createQuickDetectionState(), { type: "scope-changed", scope: "binding" });
    state = quickDetectionReducer(state, { type: "catalog-loaded", scope: "binding", catalog });
    expect(state.selectedModules).toEqual(["port-scan", "ssh-audit"]);
    state = quickDetectionReducer(state, { type: "profile-selected", profile: "selected" });
    state = quickDetectionReducer(state, { type: "module-toggled", module: "port-scan" });
    expect(state.selectedModules).toEqual(["ssh-audit"]);
    expect(state.plan).toBeNull();
  });

  it("applies only the current scan cursor and exposes a terminal report handle", () => {
    let state = runningState();
    const poll: QuickDetectionPoll = {
      scanHandle: "scan-1", stage: "completed", completed: 2, total: 2, currentModule: null,
      cancelRequested: false,
      events: [{
        sequence: 1, kind: "module-finished", module: "ssh-audit", outcome: "failed",
        completed: 1, total: 2,
      }],
      nextEventCursor: 1, eventsTruncated: false, reportHandle: "report-1", errorCode: null,
    };
    state = quickDetectionReducer(state, {
      type: "poll-started", scope: "binding", scanHandle: "scan-1", request: 2, afterEvent: 0,
    });
    state = quickDetectionReducer(state, {
      type: "poll-loaded", scope: "binding", scanHandle: "stale", request: 2, afterEvent: 0, poll,
    });
    expect(state.scanStage).toBe("running");
    state = quickDetectionReducer(state, {
      type: "poll-loaded", scope: "binding", scanHandle: "scan-1", request: 2, afterEvent: 0, poll,
    });
    expect(state.scanStage).toBe("completed");
    expect(state.selectedReportHandle).toBe("report-1");
    expect(state.moduleProgress["ssh-audit"]?.outcome).toBe("failed");
  });

  it("marks cancellation without allowing target-late updates", () => {
    let state = runningState();
    state = quickDetectionReducer(state, { type: "cancel-marked", scope: "binding", scanHandle: "scan-1" });
    expect(state.scanStage).toBe("cancelling");
    state = quickDetectionReducer(state, { type: "scope-changed", scope: "other" });
    state = quickDetectionReducer(state, {
      type: "scan-cancel-failed", scope: "binding", scanHandle: "scan-1", error: "late",
    });
    expect(state.error).toBeNull();
  });

  it("rejects an older poll after a newer cursor request is active", () => {
    let state = runningState();
    state = quickDetectionReducer(state, {
      type: "poll-started", scope: "binding", scanHandle: "scan-1", request: 2, afterEvent: 0,
    });
    const first: QuickDetectionPoll = {
      scanHandle: "scan-1", stage: "running", completed: 1, total: 2,
      currentModule: "ssh-audit", cancelRequested: false, events: [], nextEventCursor: 1,
      eventsTruncated: false, reportHandle: null, errorCode: null,
    };
    state = quickDetectionReducer(state, {
      type: "poll-loaded", scope: "binding", scanHandle: "scan-1", request: 2, afterEvent: 0, poll: first,
    });
    state = quickDetectionReducer(state, {
      type: "poll-started", scope: "binding", scanHandle: "scan-1", request: 3, afterEvent: 1,
    });
    state = quickDetectionReducer(state, {
      type: "poll-loaded", scope: "binding", scanHandle: "scan-1", request: 2, afterEvent: 0,
      poll: { ...first, stage: "completed", completed: 2, currentModule: null, reportHandle: "report-late" },
    });
    expect(state.eventCursor).toBe(1);
    expect(state.scanStage).toBe("running");
    expect(state.pollRequest).toBe(3);
  });

  it("rejects a late scan start after the opaque binding changes", () => {
    let state = quickDetectionReducer(createQuickDetectionState(), { type: "scope-changed", scope: "binding-a" });
    state = {
      ...state,
      planStatus: "ready",
      plan: {
        planHandle: "plan-a", profile: "selected", moduleIds: ["ssh-audit"], moduleCount: 1,
        maximumFindingsPerModule: 200, expiresInSeconds: 300, summary: "closed plan",
      },
    };
    state = quickDetectionReducer(state, {
      type: "scan-starting", scope: "binding-a", request: 7, planHandle: "plan-a",
    });
    state = quickDetectionReducer(state, { type: "scope-changed", scope: "binding-b" });
    state = quickDetectionReducer(state, {
      type: "scan-started", scope: "binding-a", request: 7, planHandle: "plan-a",
      started: { scanHandle: "late-scan", stage: "running", total: 1, expiresInSeconds: 1_800 },
    });
    expect(state.scope).toBe("binding-b");
    expect(state.scanHandle).toBeNull();
  });

  it("rejects superseded history and report responses", () => {
    let state = quickDetectionReducer(createQuickDetectionState(), { type: "scope-changed", scope: "binding" });
    state = quickDetectionReducer(state, { type: "history-started", scope: "binding", request: 1 });
    state = quickDetectionReducer(state, { type: "history-started", scope: "binding", request: 2 });
    state = quickDetectionReducer(state, {
      type: "history-loaded", scope: "binding", request: 1,
      history: { total: 0, offset: 0, hasMore: false, items: [] },
    });
    expect(state.historyStatus).toBe("loading");
    expect(state.historyRequest).toBe(2);

    state = quickDetectionReducer(state, { type: "report-selected", handle: "report-a" });
    state = quickDetectionReducer(state, {
      type: "report-started", scope: "binding", request: 3, handle: "report-a",
    });
    state = quickDetectionReducer(state, { type: "report-selected", handle: "report-b" });
    state = quickDetectionReducer(state, {
      type: "report-failed", scope: "binding", request: 3, handle: "report-a", error: "late",
    });
    expect(state.selectedReportHandle).toBe("report-b");
    expect(state.reportStatus).toBe("idle");
    expect(state.error).toBeNull();
  });
});
