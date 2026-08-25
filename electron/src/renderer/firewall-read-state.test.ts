import { describe, expect, it } from "vitest";

import type {
  FirewallHistory,
  FirewallInspection,
} from "../shared/firewall-read-contract";
import { createFirewallReadState, firewallReadReducer } from "./firewall-read-state";

const snapshotHandle = "11111111-1111-4111-8111-111111111111";
const historyHandle = "22222222-2222-4222-8222-222222222222";
const firstChange = "33333333-3333-4333-8333-333333333333";
const secondChange = "44444444-4444-4444-8444-444444444444";

const inspection: FirewallInspection = {
  snapshotHandle,
  backend: "iptables",
  engine: "iptables",
  active: true,
  rules: "-A INPUT -j ACCEPT",
  rulesTruncated: false,
  capturedAt: "2026-08-24T00:00:00Z",
  expiresInSeconds: 300,
};

function history(handles = [firstChange, secondChange]): FirewallHistory {
  return {
    historyHandle,
    entries: handles.map((changeHandle, index) => ({
      changeHandle,
      backend: "iptables",
      engine: "iptables",
      changeKind: "block-ipv4",
      label: `record ${index}`,
      state: "restored",
      sshPort: 22,
      createdAt: "2026-08-24T00:00:00Z",
      deadmanDeadline: "2026-08-24T00:01:00Z",
      updatedAt: "2026-08-24T00:02:00Z",
      textTruncated: false,
    })),
    displayed: handles.length,
    truncated: false,
    expiresInSeconds: 300,
  };
}

describe("firewall read reducer", () => {
  it("rejects inspection and history results from an older target scope", () => {
    let state = createFirewallReadState("scope-one");
    state = firewallReadReducer(state, { type: "inspection-started", scope: "scope-one", request: 1 });
    state = firewallReadReducer(state, { type: "history-started", scope: "scope-one", request: 2 });
    state = firewallReadReducer(state, { type: "scope-changed", scope: "scope-two" });
    const lateInspection = firewallReadReducer(state, {
      type: "inspection-loaded", scope: "scope-one", request: 1, inspection,
    });
    const lateHistory = firewallReadReducer(state, {
      type: "history-loaded", scope: "scope-one", request: 2, history: history(),
    });
    expect(lateInspection).toBe(state);
    expect(lateHistory).toBe(state);
  });

  it("retains a stable history selection and drops one removed by refresh", () => {
    let state = createFirewallReadState("scope-one");
    state = firewallReadReducer(state, { type: "history-started", scope: "scope-one", request: 1 });
    state = firewallReadReducer(state, {
      type: "history-loaded", scope: "scope-one", request: 1, history: history(),
    });
    state = firewallReadReducer(state, {
      type: "history-selected", scope: "scope-one", changeHandle: secondChange,
    });
    state = firewallReadReducer(state, { type: "history-started", scope: "scope-one", request: 2 });
    state = firewallReadReducer(state, {
      type: "history-loaded", scope: "scope-one", request: 2, history: history([secondChange]),
    });
    expect(state.selectedChangeHandle).toBe(secondChange);
    state = firewallReadReducer(state, { type: "history-started", scope: "scope-one", request: 3 });
    state = firewallReadReducer(state, {
      type: "history-loaded", scope: "scope-one", request: 3, history: history([firstChange]),
    });
    expect(state.selectedChangeHandle).toBe(firstChange);
  });

  it("rejects late clipboard outcomes after the inspection changes", () => {
    let state = createFirewallReadState("scope-one");
    state = firewallReadReducer(state, { type: "inspection-started", scope: "scope-one", request: 1 });
    state = firewallReadReducer(state, {
      type: "inspection-loaded", scope: "scope-one", request: 1, inspection,
    });
    state = firewallReadReducer(state, {
      type: "copy-started", scope: "scope-one", request: 2, snapshotHandle,
    });
    state = firewallReadReducer(state, { type: "inspection-started", scope: "scope-one", request: 3 });
    state = firewallReadReducer(state, {
      type: "inspection-loaded",
      scope: "scope-one",
      request: 3,
      inspection: { ...inspection, snapshotHandle: secondChange },
    });
    const late = firewallReadReducer(state, {
      type: "copy-finished", scope: "scope-one", request: 2, snapshotHandle, truncated: false,
    });
    expect(late).toBe(state);
    expect(late.notice).not.toBe("有界规则纯文本已复制。");
  });

  it("reports the exact 128 KiB clipboard truncation outcome", () => {
    let state = createFirewallReadState("scope-one");
    state = firewallReadReducer(state, {
      type: "inspection-started", scope: "scope-one", request: 1,
    });
    state = firewallReadReducer(state, {
      type: "inspection-loaded", scope: "scope-one", request: 1, inspection,
    });
    state = firewallReadReducer(state, {
      type: "copy-started", scope: "scope-one", request: 2, snapshotHandle,
    });
    state = firewallReadReducer(state, {
      type: "copy-finished",
      scope: "scope-one",
      request: 2,
      snapshotHandle,
      truncated: true,
    });
    expect(state.notice).toContain("128 KiB");
    expect(state.notice).toContain("截断");
  });

  it("keeps the two tabs closed and bounds hostile UTF-8 search text", () => {
    let state = createFirewallReadState("scope-one");
    state = firewallReadReducer(state, { type: "tab-selected", scope: "scope-one", tab: "history" });
    expect(state.activeTab).toBe("history");
    state = firewallReadReducer(state, { type: "rule-query-changed", query: "界".repeat(100) });
    expect(new TextEncoder().encode(state.ruleQuery).byteLength).toBeLessThanOrEqual(256);
  });

  it("clears target-derived state on deactivation", () => {
    let state = createFirewallReadState("scope-one");
    state = firewallReadReducer(state, { type: "inspection-started", scope: "scope-one", request: 1 });
    state = firewallReadReducer(state, {
      type: "inspection-loaded", scope: "scope-one", request: 1, inspection,
    });
    state = firewallReadReducer(state, { type: "deactivated", scope: "scope-one" });
    expect(state.inspection).toBeNull();
    expect(state.history).toBeNull();
    expect(state.activeTab).toBe("rules");
  });
});
