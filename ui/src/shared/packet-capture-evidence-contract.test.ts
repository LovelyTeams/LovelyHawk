import { describe, expect, it } from "vitest";

import {
  isPacketCaptureEvidenceRequest,
  isPacketCaptureEvidenceResult,
  matchesPacketCaptureEvidenceResult,
  type PacketCaptureEvidenceRequest,
} from "./packet-capture-evidence-contract";

const BINDING = "00000000-0000-4000-8000-000000000001";
const INTERFACE = "00000000-0000-4000-8000-000000000002";
const begin: PacketCaptureEvidenceRequest = {
  action: "begin", bindingHandle: BINDING, interfaceHandle: INTERFACE,
  input: { filter: "icmp", packetLimit: 6, durationSeconds: 20 },
};
export const captureEvidence = {
  jobHandle: "00000000-0000-4000-8000-000000000003", interface: "eth0", durationSeconds: 20, packetLimit: 6,
  filtered: true, targetLabel: "root@192.0.2.10:22", folderName: "LovelyHawk-evidence-12345678-1234-4234-8234-123456789012",
  caseTitle: "案件", state: "completed", copiedBytes: 900, verifiedBytes: 900, totalBytes: 900, sha256: "a".repeat(64),
  detail: "已保存", tcpdumpLine: null, temporaryFile: "removed",
};

describe("packet capture evidence boundary", () => {
  it("accepts an interface only by its handle and never a folder, a path or a name", () => {
    expect(isPacketCaptureEvidenceRequest(begin)).toBe(true);
    expect(isPacketCaptureEvidenceRequest({ action: "poll", bindingHandle: BINDING, jobHandle: "job" })).toBe(true);
    for (const bad of [
      { ...begin, selectedDirectory: "C:/private" },
      { ...begin, interface: "eth0" },
      { ...begin, remotePath: "/tmp/x.pcap" },
      { ...begin, interfaceHandle: "eth0" },
      { ...begin, input: { ...begin.input, command: "id" } },
      { ...begin, input: { filter: "icmp\nid", packetLimit: 6, durationSeconds: 20 } },
      { ...begin, input: { filter: null, packetLimit: 0, durationSeconds: 20 } },
      { ...begin, input: { filter: null, packetLimit: null, durationSeconds: 301 } },
      { action: "export", bindingHandle: BINDING, jobHandle: "job" },
      { action: "poll", bindingHandle: BINDING, jobHandle: "job", path: "/etc/shadow" },
    ]) expect(isPacketCaptureEvidenceRequest(bad), JSON.stringify(bad)).toBe(false);
  });

  it("requires a complete digest only for kept files and tcpdump's words only for a refusal", () => {
    expect(isPacketCaptureEvidenceResult(captureEvidence)).toBe(true);
    const capturing = { ...captureEvidence, state: "capturing", copiedBytes: 0, verifiedBytes: 0, totalBytes: 0, sha256: null, temporaryFile: "pending" };
    expect(isPacketCaptureEvidenceResult(capturing)).toBe(true);
    const refused = { ...capturing, state: "failed", tcpdumpLine: "tcpdump: syntax error", temporaryFile: "none" };
    expect(isPacketCaptureEvidenceResult(refused)).toBe(true);
    for (const bad of [
      { ...captureEvidence, sha256: null },
      { ...captureEvidence, verifiedBytes: 800 },
      { ...captureEvidence, copiedBytes: 901 },
      { ...captureEvidence, totalBytes: 600 * 1024 * 1024, copiedBytes: 600 * 1024 * 1024, verifiedBytes: 600 * 1024 * 1024 },
      { ...captureEvidence, tcpdumpLine: "tcpdump: anything" },
      { ...refused, tcpdumpLine: "line\u001b[31m" },
      { ...captureEvidence, interface: "eth0; id" },
      { ...captureEvidence, folderName: "../../escape" },
      { ...captureEvidence, temporaryFile: "somewhere" },
      { ...captureEvidence, localPath: "C:/private" },
      { ...captureEvidence, state: "collecting" },
    ]) expect(isPacketCaptureEvidenceResult(bad), JSON.stringify(bad).slice(0, 120)).toBe(false);
  });

  it("ties a start to its own parameters and a poll to its own job", () => {
    const capturing = { ...captureEvidence, state: "capturing", copiedBytes: 0, verifiedBytes: 0, totalBytes: 0, sha256: null, temporaryFile: "pending" };
    expect(matchesPacketCaptureEvidenceResult(begin, capturing)).toBe(true);
    expect(matchesPacketCaptureEvidenceResult(begin, null)).toBe(true);
    expect(matchesPacketCaptureEvidenceResult(begin, { ...capturing, durationSeconds: 30 })).toBe(false);
    expect(matchesPacketCaptureEvidenceResult(begin, { ...capturing, filtered: false })).toBe(false);
    expect(matchesPacketCaptureEvidenceResult(begin, captureEvidence)).toBe(false);
    const poll: PacketCaptureEvidenceRequest = { action: "poll", bindingHandle: BINDING, jobHandle: captureEvidence.jobHandle };
    expect(matchesPacketCaptureEvidenceResult(poll, captureEvidence)).toBe(true);
    expect(matchesPacketCaptureEvidenceResult({ ...poll, jobHandle: "other" }, captureEvidence)).toBe(false);
    expect(matchesPacketCaptureEvidenceResult(poll, null)).toBe(false);
  });
});
