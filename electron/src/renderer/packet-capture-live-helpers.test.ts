import { describe, expect, it } from "vitest";

import type { PacketCapturePacketEvent } from "../shared/packet-capture-live-contract";
import {
  boundPacketCaptureText,
  filterPacketCapturePackets,
  formatPacketCaptureBytes,
  packetCaptureProtocolSummary,
  packetCaptureScope,
  packetCaptureStartInput,
} from "./packet-capture-live-helpers";

function packet(sequence: number, protocol: string, info: string): PacketCapturePacketEvent {
  return {
    kind: "packet",
    sequence,
    observedAt: "2026-08-24T00:00:00Z",
    timestamp: "now",
    protocol,
    source: "10.0.0.1.443",
    destination: "10.0.0.2.51000",
    length: "42",
    info,
    raw: info,
    textTruncated: false,
  };
}

describe("packet capture live helpers", () => {
  it("scopes lifecycle only to the opaque binding handle", () => {
    expect(packetCaptureScope("binding-one")).toBe("binding-one");
    expect(packetCaptureScope("binding-one")).not.toBe(packetCaptureScope("binding-two"));
  });

  it("builds only core-compatible typed parameters", () => {
    expect(packetCaptureStartInput({
      filter: "  tcp port 443  ",
      packetLimit: "5000",
      durationSeconds: "60",
    })).toEqual({ filter: "tcp port 443", packetLimit: 5_000, durationSeconds: 60 });
    expect(packetCaptureStartInput({
      filter: "tcp\nport 443",
      packetLimit: "5000",
      durationSeconds: "60",
    })).toBeNull();
    expect(packetCaptureStartInput({
      filter: "",
      packetLimit: "0",
      durationSeconds: "60",
    })).toBeNull();
  });

  it("bounds UTF-8 text without splitting a scalar", () => {
    expect(boundPacketCaptureText("界".repeat(100), 256)).toBe("界".repeat(85));
  });

  it("filters hostile plain text and computes a bounded protocol summary", () => {
    const packets = [
      packet(1, "HTTPS", "</button><script>steal()</script>"),
      packet(2, "DNS", "query example.invalid"),
      packet(3, "HTTPS", "response"),
    ];
    expect(filterPacketCapturePackets(packets, "SCRIPT")).toHaveLength(1);
    expect(packetCaptureProtocolSummary(packets)).toEqual([
      { protocol: "HTTPS", count: 2 },
      { protocol: "DNS", count: 1 },
    ]);
  });

  it("formats byte counters without changing the underlying number", () => {
    expect(formatPacketCaptureBytes(42)).toBe("42 B");
    expect(formatPacketCaptureBytes(1_536)).toBe("1.5 KiB");
  });
});
