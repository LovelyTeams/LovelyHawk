import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  isFirewallHistory,
  isFirewallHistoryEntry,
  isFirewallInspection,
} from "./firewall-read-contract";

const snapshotHandle = "11111111-1111-4111-8111-111111111111";
const historyHandle = "22222222-2222-4222-8222-222222222222";
const changeHandle = "33333333-3333-4333-8333-333333333333";
const hostile = "</pre><script>steal()</script><img src=x onerror=steal()>";

const inspection = {
  snapshotHandle,
  backend: "firewalld",
  engine: "iptables",
  active: true,
  rules: `line one\n${hostile}\tcomment`,
  rulesTruncated: false,
  capturedAt: "2026-08-24T00:00:00Z",
  expiresInSeconds: 300,
} as const;

const entry = {
  changeHandle,
  backend: "firewalld",
  engine: "iptables",
  changeKind: "block-ipv4",
  label: hostile,
  state: "awaiting-keep",
  sshPort: 22,
  createdAt: "2026-08-24T00:00:00Z",
  deadmanDeadline: "2026-08-24T00:01:00Z",
  updatedAt: "2026-08-24T00:00:30Z",
  textTruncated: false,
} as const;

describe("firewall read strict boundary", () => {
  it("accepts bounded hostile multiline rules but no hidden inspection fields", () => {
    expect(isFirewallInspection(inspection)).toBe(true);
    expect(isFirewallInspection({ ...inspection, rules: "bad\0rule" })).toBe(false);
    expect(isFirewallInspection({ ...inspection, rules: "bad\rrule" })).toBe(false);
    expect(isFirewallInspection({ ...inspection, rules: "x".repeat(256 * 1_024 + 1) })).toBe(false);
    expect(isFirewallInspection({ ...inspection, rulesSha256: "ab".repeat(32) })).toBe(false);
    expect(isFirewallInspection({ ...inspection, target: "secret-target" })).toBe(false);
  });

  it("accepts only exact closed history projections", () => {
    expect(isFirewallHistoryEntry(entry)).toBe(true);
    expect(isFirewallHistoryEntry({ ...entry, state: "unknown" })).toBe(false);
    expect(isFirewallHistoryEntry({ ...entry, label: "line\nbreak" })).toBe(false);
    expect(isFirewallHistoryEntry({ ...entry, sshPort: 0 })).toBe(false);
    for (const forbidden of [
      "id", "operationId", "lastOperationId", "remoteRoot", "objectName", "preflightSha256",
    ]) expect(isFirewallHistoryEntry({ ...entry, [forbidden]: "secret" })).toBe(false);
  });

  it("requires a bounded unique-handle history envelope", () => {
    const history = {
      historyHandle,
      entries: [entry],
      displayed: 1,
      truncated: false,
      expiresInSeconds: 300,
    };
    expect(isFirewallHistory(history)).toBe(true);
    expect(isFirewallHistory({ ...history, displayed: 2 })).toBe(false);
    expect(isFirewallHistory({ ...history, entries: [entry, entry], displayed: 2 })).toBe(false);
    expect(isFirewallHistory({ ...history, path: "/tmp/firewall" })).toBe(false);
  });

  it("requires canonical opaque capabilities and valid timestamps", () => {
    expect(isFirewallInspection({ ...inspection, snapshotHandle: "snapshot" })).toBe(false);
    expect(isFirewallHistoryEntry({ ...entry, changeHandle: "RAW_CHANGE_ID" })).toBe(false);
    expect(isFirewallHistoryEntry({ ...entry, updatedAt: "not-a-time" })).toBe(false);
  });

  it("declares exactly two methods without remote or mutation primitives", () => {
    const source = readFileSync(new URL("./firewall-read-contract.ts", import.meta.url), "utf8");
    const api = source.slice(
      source.indexOf("export interface FirewallReadApi"),
      source.indexOf("type JsonRecord"),
    );
    expect((api.match(/Promise<Firewall(?:Inspection|History)>/gu) ?? [])).toHaveLength(2);
    expect(api).toContain("inspectFirewall");
    expect(api).toContain("listFirewallChangeHistory");
    for (const forbidden of [
      "session", "guard", "generation", "identity", "command", "path", "remoteRoot",
      "objectName", "operationId", "changeId", "digest", "plan", "confirm", "execute",
    ]) expect(api.toLocaleLowerCase()).not.toContain(forbidden.toLocaleLowerCase());
  });
});
