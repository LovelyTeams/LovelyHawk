import { describe, expect, it } from "vitest";

import type {
  PacketCaptureInterfaceList,
  PacketCapturePacketEvent,
  PacketCapturePoll,
} from "../shared/packet-capture-live-contract";
import {
  createPacketCaptureLiveState,
  packetCaptureLiveReducer,
} from "./packet-capture-live-state";

const interfaceHandle = "11111111-1111-4111-8111-111111111111";
const captureHandle = "22222222-2222-4222-8222-222222222222";
const interfaces: PacketCaptureInterfaceList = {
  interfaces: [{
    interfaceHandle,
    name: "eth0",
    mac: null,
    addresses: ["10.0.0.1/24"],
    textTruncated: false,
  }],
  displayed: 1,
  truncated: false,
  expiresInSeconds: 300,
};

function packet(sequence: number, raw = "packet"): PacketCapturePacketEvent {
  return {
    kind: "packet",
    sequence,
    observedAt: "2026-08-24T00:00:00Z",
    timestamp: "now",
    protocol: "HTTPS",
    source: "10.0.0.1.443",
    destination: "10.0.0.2.51000",
    length: "42",
    info: raw,
    raw,
    textTruncated: false,
  };
}

function poll(
  events: PacketCapturePoll["events"],
  overrides: Partial<PacketCapturePoll> = {},
): PacketCapturePoll {
  const sequences = events.map((event) => event.sequence);
  return {
    captureHandle,
    status: "running",
    oldestSequence: sequences[0] ?? 0,
    latestSequence: sequences.at(-1) ?? 0,
    cursorReset: false,
    hasMore: false,
    truncated: false,
    droppedEvents: 0,
    retainedPackets: events.filter((event) => event.kind === "packet").length,
    packets: events.filter((event) => event.kind === "packet").length,
    bytes: events.filter((event) => event.kind === "packet").length * 42,
    events,
    ...overrides,
  };
}

function runningState(scope = "scope-one") {
  let state = createPacketCaptureLiveState(scope);
  state = packetCaptureLiveReducer(state, { type: "interfaces-started", scope, request: 1 });
  state = packetCaptureLiveReducer(state, {
    type: "interfaces-loaded",
    scope,
    request: 1,
    interfaces,
  });
  state = packetCaptureLiveReducer(state, {
    type: "start-started",
    scope,
    request: 2,
    interfaceHandle,
  });
  return packetCaptureLiveReducer(state, {
    type: "start-loaded",
    scope,
    request: 2,
    interfaceHandle,
    capture: { captureHandle, status: "running", expiresInSeconds: 150 },
  });
}

describe("packet capture live reducer", () => {
  it("retains a stable interface handle and rejects an older target result", () => {
    let state = createPacketCaptureLiveState("scope-one");
    state = packetCaptureLiveReducer(state, {
      type: "interfaces-started",
      scope: "scope-one",
      request: 1,
    });
    state = packetCaptureLiveReducer(state, {
      type: "interfaces-loaded",
      scope: "scope-one",
      request: 1,
      interfaces,
    });
    expect(state.selectedInterfaceHandle).toBe(interfaceHandle);
    state = packetCaptureLiveReducer(state, {
      type: "interfaces-started",
      scope: "scope-one",
      request: 2,
    });
    const refreshed = packetCaptureLiveReducer(state, {
      type: "interfaces-loaded",
      scope: "scope-one",
      request: 2,
      interfaces: { ...interfaces, interfaces: [{ ...interfaces.interfaces[0]!, name: "renamed" }] },
    });
    expect(refreshed.selectedInterfaceHandle).toBe(interfaceHandle);

    const switched = packetCaptureLiveReducer(refreshed, {
      type: "scope-changed",
      scope: "scope-two",
    });
    const late = packetCaptureLiveReducer(switched, {
      type: "interfaces-loaded",
      scope: "scope-one",
      request: 2,
      interfaces,
    });
    expect(late).toBe(switched);
    expect(late.interfaces).toBeNull();
  });

  it("rejects a start completion after target switch", () => {
    let state = createPacketCaptureLiveState("scope-one");
    state = packetCaptureLiveReducer(state, { type: "interfaces-started", scope: "scope-one", request: 1 });
    state = packetCaptureLiveReducer(state, {
      type: "interfaces-loaded", scope: "scope-one", request: 1, interfaces,
    });
    state = packetCaptureLiveReducer(state, {
      type: "start-started", scope: "scope-one", request: 2, interfaceHandle,
    });
    state = packetCaptureLiveReducer(state, { type: "scope-changed", scope: "scope-two" });
    const late = packetCaptureLiveReducer(state, {
      type: "start-loaded",
      scope: "scope-one",
      request: 2,
      interfaceHandle,
      capture: { captureHandle, status: "running", expiresInSeconds: 150 },
    });
    expect(late).toBe(state);
    expect(late.captureHandle).toBeNull();
  });

  it("merges ordered polls, retains selection, and never jumps to latest past hasMore", () => {
    let state = runningState();
    state = packetCaptureLiveReducer(state, {
      type: "poll-started",
      scope: "scope-one",
      request: 3,
      captureHandle,
      afterSequence: 0,
    });
    state = packetCaptureLiveReducer(state, {
      type: "poll-loaded",
      scope: "scope-one",
      request: 3,
      captureHandle,
      afterSequence: 0,
      result: poll([
        { kind: "started", sequence: 1, observedAt: "2026-08-24T00:00:00Z" },
        packet(2),
      ], { latestSequence: 10, hasMore: true, truncated: true, packets: 9, bytes: 378 }),
    });
    expect(state.afterSequence).toBe(2);
    state = packetCaptureLiveReducer(state, { type: "packet-selected", sequence: 2 });
    state = packetCaptureLiveReducer(state, {
      type: "poll-started",
      scope: "scope-one",
      request: 4,
      captureHandle,
      afterSequence: 2,
    });
    state = packetCaptureLiveReducer(state, {
      type: "poll-loaded",
      scope: "scope-one",
      request: 4,
      captureHandle,
      afterSequence: 2,
      result: poll([packet(3)], {
        oldestSequence: 1,
        latestSequence: 3,
        packets: 2,
        bytes: 84,
      }),
    });
    expect(state.packets.map((item) => item.sequence)).toEqual([2, 3]);
    expect(state.selectedPacketSequence).toBe(2);
  });

  it("resets the local journal and stale selection on a server cursor reset", () => {
    let state = runningState();
    state = { ...state, packets: [packet(2)], selectedPacketSequence: 2, afterSequence: 2 };
    state = packetCaptureLiveReducer(state, {
      type: "poll-started",
      scope: "scope-one",
      request: 3,
      captureHandle,
      afterSequence: 2,
    });
    state = packetCaptureLiveReducer(state, {
      type: "poll-loaded",
      scope: "scope-one",
      request: 3,
      captureHandle,
      afterSequence: 2,
      result: poll([packet(50, "retained")], {
        oldestSequence: 50,
        latestSequence: 50,
        cursorReset: true,
        truncated: true,
        droppedEvents: 48,
        packets: 50,
        bytes: 2_100,
      }),
    });
    expect(state.packets.map((item) => item.sequence)).toEqual([50]);
    expect(state.selectedPacketSequence).toBeNull();
    expect(state.afterSequence).toBe(50);
  });

  it("keeps tcpdump's own last line when it fails, as its output and never as the reason", () => {
    let state = runningState();
    state = packetCaptureLiveReducer(state, {
      type: "poll-started", scope: "scope-one", request: 3, captureHandle, afterSequence: 0,
    });
    const observedAt = "2026-10-11T06:35:40.952288100+00:00";
    state = packetCaptureLiveReducer(state, {
      type: "poll-loaded", scope: "scope-one", request: 3, captureHandle, afterSequence: 0,
      result: poll([
        { kind: "info", sequence: 1, observedAt, message: "tcpdump: can't parse filter expression: syntax error", textTruncated: false },
        { kind: "failed", sequence: 2, observedAt, code: "capture-failed", reason: null },
      ] as PacketCapturePoll["events"], { status: "failed" }),
    });
    expect(state.captureStatus).toBe("failed");
    expect(state.info).toBe("tcpdump 在目标机上的输出：tcpdump: can't parse filter expression: syntax error");
    expect(state.error).toContain("tcpdump 以失败结束");
    expect(state.error).not.toContain("can't parse");
  });

  it("chooses the real network card, and keeps the chosen one across reloads by name", () => {
    const card = (handle: string, name: string) => ({ interfaceHandle: handle, name, mac: null, addresses: [], textTruncated: false });
    const listed = (...cards: ReturnType<typeof card>[]) => ({ ...interfaces, interfaces: cards, displayed: cards.length });
    let state = createPacketCaptureLiveState("scope-one");
    state = packetCaptureLiveReducer(state, { type: "interfaces-started", scope: "scope-one", request: 1 });
    state = packetCaptureLiveReducer(state, { type: "interfaces-loaded", scope: "scope-one", request: 1,
      interfaces: listed(card("h-lo", "lo"), card("h-eth0", "eth0"), card("h-eth1", "eth1")) });
    expect(state.selectedInterfaceHandle).toBe("h-eth0");
    state = packetCaptureLiveReducer(state, { type: "interface-selected", scope: "scope-one", handle: "h-eth1" });
    // A reload hands out new handles; the same card is chosen again.
    state = packetCaptureLiveReducer(state, { type: "interfaces-started", scope: "scope-one", request: 2 });
    state = packetCaptureLiveReducer(state, { type: "interfaces-loaded", scope: "scope-one", request: 2,
      interfaces: listed(card("n-lo", "lo"), card("n-eth0", "eth0"), card("n-eth1", "eth1")) });
    expect(state.selectedInterfaceHandle).toBe("n-eth1");
    // Only a loopback: it is what there is.
    let lonely = createPacketCaptureLiveState("scope-one");
    lonely = packetCaptureLiveReducer(lonely, { type: "interfaces-started", scope: "scope-one", request: 1 });
    lonely = packetCaptureLiveReducer(lonely, { type: "interfaces-loaded", scope: "scope-one", request: 1, interfaces: listed(card("h-lo", "lo")) });
    expect(lonely.selectedInterfaceHandle).toBe("h-lo");
  });

  it("keeps tcpdump's line from an earlier poll, and a list reload does not wipe the failure", () => {
    // As on Alma: the line came in one poll, the failure in the next, and
    // the network-card list reloads when the capture is released.
    let state = runningState();
    const observedAt = "2026-10-11T06:58:33.496426900+00:00";
    state = packetCaptureLiveReducer(state, { type: "poll-started", scope: "scope-one", request: 3, captureHandle, afterSequence: 0 });
    state = packetCaptureLiveReducer(state, {
      type: "poll-loaded", scope: "scope-one", request: 3, captureHandle, afterSequence: 0,
      result: poll([{ kind: "info", sequence: 1, observedAt, message: "tcpdump: can't parse filter expression: syntax error", textTruncated: false }] as PacketCapturePoll["events"]),
    });
    state = packetCaptureLiveReducer(state, { type: "poll-started", scope: "scope-one", request: 4, captureHandle, afterSequence: 1 });
    state = packetCaptureLiveReducer(state, {
      type: "poll-loaded", scope: "scope-one", request: 4, captureHandle, afterSequence: 1,
      result: poll([
        { kind: "failed", sequence: 2, observedAt, code: "capture-failed", reason: null },
        { kind: "stopped", sequence: 3, observedAt },
      ] as PacketCapturePoll["events"], { status: "failed" }),
    });
    expect(state.info).toBe("tcpdump 在目标机上的输出：tcpdump: can't parse filter expression: syntax error");
    expect(state.error).toContain("tcpdump 以失败结束");
    state = packetCaptureLiveReducer(state, { type: "capture-released", scope: "scope-one", captureHandle, failed: true });
    state = packetCaptureLiveReducer(state, { type: "interfaces-started", scope: "scope-one", request: 5 });
    expect(state.error).toContain("tcpdump 以失败结束");
    expect(state.info).toContain("can't parse filter expression");
  });

  it("drops the last live capture's failure when a capture kept as a file starts, never a running one's", () => {
    let state = runningState();
    const observedAt = "2026-10-11T06:58:33.496426900+00:00";
    state = packetCaptureLiveReducer(state, { type: "poll-started", scope: "scope-one", request: 3, captureHandle, afterSequence: 0 });
    state = packetCaptureLiveReducer(state, {
      type: "poll-loaded", scope: "scope-one", request: 3, captureHandle, afterSequence: 0,
      result: poll([
        { kind: "info", sequence: 1, observedAt, message: "tcpdump: can't parse filter expression: syntax error", textTruncated: false },
        { kind: "failed", sequence: 2, observedAt, code: "capture-failed", reason: null },
      ] as PacketCapturePoll["events"], { status: "failed" }),
    });
    // Still holding the capture: nothing is cleared yet.
    expect(packetCaptureLiveReducer(state, { type: "earlier-result-cleared" })).toBe(state);
    state = packetCaptureLiveReducer(state, { type: "capture-released", scope: "scope-one", captureHandle, failed: true });
    const cleared = packetCaptureLiveReducer(state, { type: "earlier-result-cleared" });
    expect(cleared).toMatchObject({ captureStatus: "idle", info: null, error: null, notice: null, lastTcpdumpLine: null });
    expect(cleared.selectedInterfaceHandle).toBe(state.selectedInterfaceHandle);
  });

  it("byte-bounds form/search values and resets live capability on deactivation", () => {
    let state = runningState();
    const unchanged = packetCaptureLiveReducer(state, {
      type: "filter-changed",
      value: "should not change while running",
    });
    expect(unchanged).toBe(state);
    state = packetCaptureLiveReducer(state, { type: "deactivated", scope: "scope-one" });
    expect(state.captureHandle).toBeNull();
    state = packetCaptureLiveReducer(state, { type: "search-changed", value: "界".repeat(100) });
    expect(new TextEncoder().encode(state.search).byteLength).toBeLessThanOrEqual(256);
    expect(state.form).toEqual({ filter: "", packetLimit: "5000", durationSeconds: "60" });
  });
});
