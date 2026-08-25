import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  isPacketCaptureCursor,
  isPacketCaptureInterfaceList,
  isPacketCaptureLiveEvent,
  isPacketCapturePoll,
  isPacketCaptureStartInput,
  isPacketCaptureStarted,
  isPacketCaptureStopped,
} from "./packet-capture-live-contract";

const interfaceHandle = "11111111-1111-4111-8111-111111111111";
const captureHandle = "22222222-2222-4222-8222-222222222222";
const hostile = "</pre><script>steal()</script><img src=x onerror=steal()>";
const packet = {
  kind: "packet",
  sequence: 2,
  observedAt: "2026-08-24T00:00:00Z",
  timestamp: "2026-08-24 00:00:00",
  protocol: "HTTPS",
  source: "10.0.0.1.443",
  destination: "10.0.0.2.51000",
  length: "42",
  info: hostile,
  raw: hostile,
  textTruncated: false,
} as const;

describe("packet capture live strict boundary", () => {
  it("accepts only non-negative safe integer cursors", () => {
    expect(isPacketCaptureCursor(0)).toBe(true);
    expect(isPacketCaptureCursor(Number.MAX_SAFE_INTEGER)).toBe(true);
    expect(isPacketCaptureCursor(-1)).toBe(false);
    expect(isPacketCaptureCursor(1.5)).toBe(false);
    expect(isPacketCaptureCursor(Number.MAX_SAFE_INTEGER + 1)).toBe(false);
  });

  it("accepts only exact core-compatible bounded capture parameters", () => {
    expect(isPacketCaptureStartInput({
      filter: "tcp port 443; id",
      packetLimit: 5_000,
      durationSeconds: 60,
    })).toBe(true);
    expect(isPacketCaptureStartInput({
      filter: "tcp\tport 443",
      packetLimit: 5_000,
      durationSeconds: 60,
    })).toBe(true);
    expect(isPacketCaptureStartInput({
      filter: "tcp\nport 443",
      packetLimit: 5_000,
      durationSeconds: 60,
    })).toBe(false);
    expect(isPacketCaptureStartInput({
      filter: "tcp\0port 443",
      packetLimit: 5_000,
      durationSeconds: 60,
    })).toBe(false);
    expect(isPacketCaptureStartInput({
      filter: null,
      packetLimit: 100_001,
      durationSeconds: 60,
    })).toBe(false);
    expect(isPacketCaptureStartInput({
      filter: null,
      packetLimit: 1,
      durationSeconds: 301,
    })).toBe(false);
    expect(isPacketCaptureStartInput({
      filter: null,
      packetLimit: 1,
      durationSeconds: 10,
      interface: "eth0",
    })).toBe(false);
  });

  it("keeps interface results exact, bounded, and capability based", () => {
    const list = {
      interfaces: [{
        interfaceHandle,
        name: hostile,
        mac: null,
        addresses: ["10.0.0.1/24"],
        textTruncated: false,
      }],
      displayed: 1,
      truncated: false,
      expiresInSeconds: 300,
    };
    expect(isPacketCaptureInterfaceList(list)).toBe(true);
    expect(isPacketCaptureInterfaceList({ ...list, command: "ip addr" })).toBe(false);
    expect(isPacketCaptureInterfaceList({ ...list, displayed: 2 })).toBe(false);
    expect(isPacketCaptureInterfaceList({
      ...list,
      interfaces: [{ ...list.interfaces[0], name: "password=hunter2" }],
    })).toBe(false);
    expect(isPacketCaptureInterfaceList({
      ...list,
      interfaces: [{ ...list.interfaces[0], name: '{"password":"hunter2"}' }],
    })).toBe(false);
    expect(isPacketCaptureInterfaceList({
      ...list,
      interfaces: [{ ...list.interfaces[0], addresses: ["https://user:pass@example.invalid/x"] }],
    })).toBe(false);
    expect(isPacketCaptureInterfaceList({
      ...list,
      interfaces: [{ ...list.interfaces[0], mac: "bad\u0007mac" }],
    })).toBe(false);
    expect(isPacketCaptureInterfaceList({
      ...list,
      interfaces: [{ ...list.interfaces[0], interfaceHandle: "eth0" }],
    })).toBe(false);
  });

  it("accepts hostile packet text without accepting core IDs or hidden paths", () => {
    expect(isPacketCaptureLiveEvent(packet)).toBe(true);
    expect(isPacketCaptureLiveEvent({ ...packet, packetId: 42 })).toBe(false);
    expect(isPacketCaptureLiveEvent({ ...packet, captureId: "core-secret" })).toBe(false);
    expect(isPacketCaptureLiveEvent({ ...packet, raw: "\u0000bad" })).toBe(false);
    expect(isPacketCaptureLiveEvent({ ...packet, info: "Authorization: Bearer secret" })).toBe(false);
    expect(isPacketCaptureLiveEvent({
      ...packet,
      raw: "https://operator:password@example.invalid/private",
    })).toBe(false);
    expect(isPacketCaptureLiveEvent({ ...packet, raw: "x".repeat(16 * 1_024 + 1) })).toBe(false);
  });

  it("requires ordered cursor-coherent bounded polls", () => {
    const poll = {
      captureHandle,
      status: "running",
      oldestSequence: 1,
      latestSequence: 2,
      cursorReset: false,
      hasMore: false,
      truncated: false,
      droppedEvents: 0,
      retainedPackets: 1,
      packets: 1,
      bytes: 42,
      events: [{ kind: "started", sequence: 1, observedAt: "2026-08-24T00:00:00Z" }, packet],
    };
    expect(isPacketCapturePoll(poll)).toBe(true);
    expect(isPacketCapturePoll({ ...poll, events: [packet, poll.events[0]] })).toBe(false);
    expect(isPacketCapturePoll({ ...poll, droppedEvents: 1 })).toBe(false);
    expect(isPacketCapturePoll({ ...poll, droppedEvents: 1, truncated: true })).toBe(true);
    expect(isPacketCapturePoll({ ...poll, latestSequence: 1 })).toBe(false);
  });

  it("requires exact start and stop outcomes", () => {
    expect(isPacketCaptureStarted({
      captureHandle,
      status: "running",
      expiresInSeconds: 150,
    })).toBe(true);
    expect(isPacketCaptureStarted({
      captureHandle,
      status: "running",
      expiresInSeconds: 500,
    })).toBe(false);
    expect(isPacketCaptureStopped({ stopped: true })).toBe(true);
    expect(isPacketCaptureStopped({ stopped: true, path: "/tmp/capture.pcap" })).toBe(false);
  });

  it("has exactly four methods and no renderer-supplied interface identity or remote primitive", () => {
    const source = readFileSync(new URL("./packet-capture-live-contract.ts", import.meta.url), "utf8");
    const api = source.slice(
      source.indexOf("export interface PacketCaptureLiveApi"),
      source.indexOf("type JsonRecord"),
    );
    expect((api.match(/Promise<unknown>/gu) ?? [])).toHaveLength(4);
    for (const method of [
      "listPacketCaptureInterfaces", "startPacketCapture",
      "pollPacketCapture", "stopPacketCapture",
    ]) expect(api).toContain(method);
    for (const forbidden of [
      "interfaceName", "sessionId", "targetGuard", "generation", "identity",
      "command", "remotePath", "captureId", "pcapPath",
    ]) expect(api).not.toContain(forbidden);
  });
});
