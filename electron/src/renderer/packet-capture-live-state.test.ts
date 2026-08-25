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
