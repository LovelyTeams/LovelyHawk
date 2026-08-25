import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  forensicCollectors,
  fullyRedactedForensicCollectors,
  isSnapshotDetail,
  isSnapshotDiffInput,
  isSnapshotDiffResult,
  isSnapshotListResult,
} from "./snapshot-read-contract";

const hostile = "</pre><script>steal()</script><img src=x onerror=steal()>";
const redacted = "[SENSITIVE SNAPSHOT TEXT REDACTED]";
const failed = "[FORENSIC COLLECTOR FAILED]";
const fullyRedacted = new Set<string>(fullyRedactedForensicCollectors);

const list = {
  expiresInSeconds: 300,
  snapshots: [{
    snapshotHandle: "directory-opaque",
    kind: "directory",
    capturedAt: "2026-08-24T00:00:00+00:00",
    itemCount: 1,
    completedCollectors: null,
    failedCollectors: null,
  }, {
    snapshotHandle: "forensic-opaque",
    kind: "forensic",
    capturedAt: "2026-08-23T00:00:00+00:00",
    itemCount: 12,
    completedCollectors: 12,
    failedCollectors: 1,
  }],
  directoryCount: 1,
  forensicCount: 1,
  truncated: false,
};

const forensicDetail = {
  snapshotHandle: "forensic-opaque",
  kind: "forensic",
  capturedAt: "2026-08-23T00:00:00+00:00",
  totalCollectors: 12,
  completedCollectors: 12,
  failedCollectors: 1,
  fields: forensicCollectors.map((collector, index) => ({
    collector,
    text: fullyRedacted.has(collector) ? redacted : index === 1 ? hostile : "",
    redactedLineCount: fullyRedacted.has(collector) ? 1 : 0,
    truncated: false,
  })),
  redactedLineCount: fullyRedactedForensicCollectors.length,
  truncated: false,
};

const diff = {
  olderSnapshotHandle: "older-opaque",
  newerSnapshotHandle: "newer-opaque",
  fields: forensicCollectors.map((collector, index) => ({
    collector,
    added: index === 1 ? [hostile] : [],
    removed: [],
    redactedLineCount: 0,
    truncated: false,
  })),
  addedLineCount: 1,
  removedLineCount: 0,
  redactedLineCount: 0,
  truncated: false,
};

describe("snapshot read strict boundary", () => {
  it("exposes exactly three fixed public methods with concrete bounded results", () => {
    const source = readFileSync(new URL("./snapshot-read-contract.ts", import.meta.url), "utf8");
    const api = source.match(/export interface SnapshotReadApi \{([\s\S]*?)\n\}/u)?.[1] ?? "";
    expect([...api.matchAll(/^\s{2}([A-Za-z][A-Za-z0-9]*)\(/gmu)].map((match) => match[1])).toEqual([
      "listSnapshots", "getSnapshotDetail", "diffForensicSnapshots",
    ]);
    for (const forbidden of ["sessionId", "targetGeneration", "remoteRoot", "snapshotId", "sha256", "command"])
      expect(api).not.toContain(forbidden);
    expect(api).toContain("Promise<SnapshotListResult>");
    expect(api).toContain("Promise<SnapshotDetail>");
    expect(api).toContain("Promise<SnapshotDiffResult>");
    expect(api).not.toContain("Promise<unknown>");
  });

  it("accepts only exact opaque diff inputs", () => {
    expect(isSnapshotDiffInput({ olderSnapshotHandle: "older", newerSnapshotHandle: "newer" })).toBe(true);
    expect(isSnapshotDiffInput({ olderSnapshotHandle: "same", newerSnapshotHandle: "same" })).toBe(false);
    expect(isSnapshotDiffInput({
      olderSnapshotHandle: "older", newerSnapshotHandle: "newer", snapshotId: "raw",
    })).toBe(false);
  });

  it("validates bounded ordered list metadata without target or digest fields", () => {
    expect(isSnapshotListResult(list)).toBe(true);
    expect(isSnapshotListResult({ ...list, host: "target.test" })).toBe(false);
    expect(isSnapshotListResult({
      ...list,
      snapshots: [{ ...list.snapshots[0], remoteRoot: "/tmp/private" }, list.snapshots[1]],
    })).toBe(false);
    expect(isSnapshotListResult({ ...list, directoryCount: 2 })).toBe(false);
    expect(isSnapshotListResult({ ...list, snapshots: [...list.snapshots].reverse() })).toBe(false);
    expect(isSnapshotListResult({
      ...list,
      snapshots: [{ ...list.snapshots[0], capturedAt: "today" }, list.snapshots[1]],
    })).toBe(false);
  });

  it("requires exact directory metadata and honest unverified archive availability", () => {
    const detail = {
      snapshotHandle: "directory-opaque",
      kind: "directory",
      capturedAt: "2026-08-24T00:00:00+00:00",
      items: [{
        preset: "etc", kind: "directory", bytes: "18446744073709551615", present: true,
        archiveAvailability: "not-checked",
      }],
      truncated: false,
    };
    expect(isSnapshotDetail(detail)).toBe(true);
    expect(isSnapshotDetail({ ...detail, remoteRoot: "/tmp/private" })).toBe(false);
    expect(isSnapshotDetail({ ...detail, items: [{ ...detail.items[0], sha256: "a".repeat(64) }] })).toBe(false);
    expect(isSnapshotDetail({
      ...detail, items: [{ ...detail.items[0], bytes: "18446744073709551616" }],
    })).toBe(false);
  });

  it("accepts hostile forensic text only as bounded data and rejects credential markers", () => {
    expect(isSnapshotDetail(forensicDetail)).toBe(true);
    expect(isSnapshotDetail({ ...forensicDetail, sessionId: "secret" })).toBe(false);
    expect(isSnapshotDetail({
      ...forensicDetail,
      fields: forensicDetail.fields.map((field, index) => index === 0 ? {
        ...field, text: "authorization: Bearer secret",
      } : field),
    })).toBe(false);
    expect(isSnapshotDetail({
      ...forensicDetail,
      fields: [...forensicDetail.fields].reverse(),
    })).toBe(false);
  });

  it("pins seven high-risk collectors to fixed markers in detail and diff", () => {
    expect(fullyRedactedForensicCollectors).toEqual([
      "processes", "loginHistory", "cronJobs", "authorizedKeys", "sudoers", "recentModifiedFiles", "envVariables",
    ]);
    const bypasses = new Map<string, string>([
      ["processes", "mysql -uroot -pS3cr3t"],
      ["loginHistory", "PASSWORD = secret"],
      ["cronJobs", "backup --token hidden"],
      ["authorizedKeys", "-----BEGIN OPENSSH PRIVATE KEY-----\nprivate-material\n-----END OPENSSH PRIVATE KEY-----"],
      ["sudoers", "operator ALL=(ALL) NOPASSWD: /bin/sh"],
      ["recentModifiedFiles", "/etc/shadow\n/usr/local/private/app.conf"],
      ["envVariables", "PASSWORD = secret"],
    ]);
    for (const [collector, leaked] of bypasses) {
      expect(isSnapshotDetail({
        ...forensicDetail,
        fields: forensicDetail.fields.map((field) => field.collector === collector ? {
          ...field, text: leaked,
        } : field),
      })).toBe(false);
    }
    expect(isSnapshotDetail({
      ...forensicDetail,
      fields: forensicDetail.fields.map((field) => field.collector === "processes" ? {
        ...field, text: failed,
      } : field),
    })).toBe(true);

    const markerOnlyDiff = {
      ...diff,
      fields: diff.fields.map((field) => field.collector === "processes" ? {
        ...field, added: [redacted], removed: [failed], redactedLineCount: 2,
      } : field),
      addedLineCount: 2,
      removedLineCount: 1,
      redactedLineCount: 2,
    };
    expect(isSnapshotDiffResult(markerOnlyDiff)).toBe(true);
    for (const leaked of ["mysql -uroot -pNewSecret", "PASSWORD = old-secret", "-----BEGIN PRIVATE KEY-----"]) {
      expect(isSnapshotDiffResult({
        ...markerOnlyDiff,
        fields: markerOnlyDiff.fields.map((field) => field.collector === "processes" ? {
          ...field, added: [leaked],
        } : field),
      })).toBe(false);
    }
  });

  it("rejects credential-shaped text even in the bounded public collector allowlist", () => {
    for (const leaked of [
      "mysql -uroot -pS3cr3t",
      "PASSWORD = secret",
      "-----BEGIN OPENSSH PRIVATE KEY-----",
    ]) {
      expect(isSnapshotDetail({
        ...forensicDetail,
        fields: forensicDetail.fields.map((field) => field.collector === "startupServices" ? {
          ...field, text: leaked,
        } : field),
      })).toBe(false);
    }
  });

  it("validates exact diff counts, order, line and serialized bounds", () => {
    expect(isSnapshotDiffResult(diff)).toBe(true);
    expect(isSnapshotDiffResult({ ...diff, addedLineCount: 2 })).toBe(false);
    expect(isSnapshotDiffResult({ ...diff, olderId: "raw" })).toBe(false);
    expect(isSnapshotDiffResult({
      ...diff,
      fields: diff.fields.map((field, index) => index === 0 ? {
        ...field, added: ["token=secret"],
      } : field),
    })).toBe(false);
    expect(isSnapshotDiffResult({
      ...diff,
      fields: diff.fields.map((field, index) => index === 1 ? {
        ...field, added: ["x".repeat(4 * 1_024 + 1)],
      } : field),
    })).toBe(false);
  });

  it("enforces the serialized cap after hostile JSON escaping", () => {
    const escaped = "\u0000".repeat(4 * 1_024);
    expect(isSnapshotDiffResult({
      ...diff,
      fields: diff.fields.map((field, index) => index === 1 ? {
        ...field,
        added: Array.from({ length: 128 }, () => escaped),
      } : field),
      addedLineCount: 128,
    })).toBe(false);
  });
});
