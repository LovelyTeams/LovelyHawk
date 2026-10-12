import { describe, expect, it, vi } from "vitest";

import type { IntegrityApi } from "../shared/integrity-contract";
import {
  cancelIntegrityLifecycle,
  formatIntegrityTime,
  integrityKindLabel,
  integrityOperationIsActive,
  integritySeverityLabel,
} from "./integrity-helpers";

function apiWithCancel(cancel: IntegrityApi["cancelIntegrityComparison"]): IntegrityApi {
  return {
    getIntegrityPresets: async () => ({}),
    listIntegrityBaselines: async () => ({}),
    startIntegrityComparison: async () => ({}),
    pollIntegrityComparison: async () => ({}),
    cancelIntegrityComparison: cancel,
    startIntegrityBaselineCreation: async () => ({}),
    pollIntegrityBaselineCreation: async () => ({}),
    cancelIntegrityBaselineCreation: async () => ({}),
  };
}

describe("integrity renderer helpers", () => {
  it("formats timestamps and closed labels without interpreting remote text", () => {
    expect(formatIntegrityTime("not-a-time")).toBe("时间不可用");
    expect(formatIntegrityTime("2026-08-25T00:00:00Z")).not.toBe("时间不可用");
    expect(integrityKindLabel("added")).toBe("新增");
    expect(integrityKindLabel("removed")).toBe("已移除");
    expect(integritySeverityLabel("high")).toBe("高危");
  });

  it("treats only start, run, and cancellation as active", () => {
    expect(integrityOperationIsActive("starting")).toBe(true);
    expect(integrityOperationIsActive("running")).toBe(true);
    expect(integrityOperationIsActive("cancelling")).toBe(true);
    expect(integrityOperationIsActive("completed")).toBe(false);
    expect(integrityOperationIsActive("cancelled")).toBe(false);
  });

  it("cancels an active opaque operation on lifecycle cleanup only", async () => {
    const cancel = vi.fn(async () => ({ cancelled: true }));
    const api = apiWithCancel(cancel);
    await cancelIntegrityLifecycle(api, "binding-one", "operation-one", "running");
    await cancelIntegrityLifecycle(api, "binding-one", "operation-one", "completed");
    await cancelIntegrityLifecycle(api, null, "operation-one", "running");
    expect(cancel).toHaveBeenCalledTimes(1);
    expect(cancel).toHaveBeenCalledWith("binding-one", "operation-one");
  });
});
