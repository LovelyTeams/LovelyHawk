import { describe, expect, it } from "vitest";

import {
  isSystemInfoCatalog,
  isSystemInfoDetail,
  isSystemInfoMaximumRows,
  isSystemInfoSummary,
  isSystemInfoTable,
  SYSTEM_INFO_CATALOG,
} from "./system-info-contract";

function catalogFixture(): unknown[] {
  return SYSTEM_INFO_CATALOG.map((entry) => ({ ...entry, columns: [...entry.columns] }));
}

function summaryFixture(): Record<string, unknown> {
  return {
    hostname: "server-1",
    operatingSystem: "Linux",
    kernel: "6.12",
    architecture: "x86_64",
    virtualization: "kvm",
    bootTime: "2026-08-24 00:00:00",
    timezone: "Asia/Taipei",
    locale: "zh_TW.UTF-8",
    initSystem: "systemd",
    packageManager: "apt",
    selinux: "disabled",
    apparmor: "enabled",
    uptimeSeconds: 7_200,
    loadAverage: ["0.1", "0.2", "0.3"],
    cpuModel: "Test CPU",
    cpuCores: 8,
    memoryTotalBytes: 16_000_000_000,
    memoryAvailableBytes: 8_000_000_000,
    swapTotalBytes: 2_000_000_000,
    swapFreeBytes: 1_000_000_000,
    rootDevice: "/dev/test",
    rootFilesystem: "ext4",
    rootTotalBytes: 100_000_000_000,
    rootAvailableBytes: 50_000_000_000,
    primaryIp: "192.0.2.10",
    defaultGateway: "192.0.2.1",
    dnsServers: "192.0.2.53",
    processCount: 120,
    loggedInUsers: 1,
    networkConnections: 42,
    receivedBytes: 1_024,
    transmittedBytes: 2_048,
  };
}

function tableFixture(): Record<string, unknown> {
  return {
    snapshotHandle: "42d64555-d01d-458a-9b27-4bb84f467135",
    tab: "users",
    columns: ["用户名", "UID", "GID", "主目录", "Shell"],
    rows: [{ id: "user:root", cells: ["root", "0", "0", "/root", "/bin/bash"], risk: "normal" }],
    truncated: false,
  };
}

describe("system-info process-boundary validators", () => {
  it("accepts only the fixed 25-tab, four-group catalog", () => {
    const catalog = catalogFixture();
    expect(isSystemInfoCatalog(catalog)).toBe(true);
    expect(new Set(SYSTEM_INFO_CATALOG.map((entry) => entry.group))).toEqual(
      new Set(["realtime", "persistence", "security", "workload"]),
    );

    expect(isSystemInfoCatalog(catalog.slice(0, 24))).toBe(false);
    expect(isSystemInfoCatalog([...catalog].reverse())).toBe(false);
    expect(isSystemInfoCatalog(catalog.map((entry, index) =>
      index === 0 ? { ...(entry as object), command: "uname -a" } : entry,
    ))).toBe(false);
  });

  it("requires the exact bounded summary shape", () => {
    const summary = summaryFixture();
    expect(isSystemInfoSummary(summary)).toBe(true);
    expect(isSystemInfoSummary({ ...summary, sessionId: "secret" })).toBe(false);
    expect(isSystemInfoSummary({ ...summary, targetGuard: { generation: 7 } })).toBe(false);
    expect(isSystemInfoSummary({ ...summary, hostname: "界".repeat(1_366) })).toBe(false);
    expect(isSystemInfoSummary({ ...summary, processCount: -1 })).toBe(false);
    expect(isSystemInfoSummary({ ...summary, receivedBytes: Number.MAX_SAFE_INTEGER + 1 })).toBe(false);
  });

  it("bounds rows and bytes and requires exact columns, cells, risks and opaque snapshots", () => {
    const table = tableFixture();
    expect(isSystemInfoTable(table)).toBe(true);
    expect(isSystemInfoMaximumRows(1)).toBe(true);
    expect(isSystemInfoMaximumRows(500)).toBe(true);
    expect(isSystemInfoMaximumRows(0)).toBe(false);
    expect(isSystemInfoMaximumRows(501)).toBe(false);

    expect(isSystemInfoTable({ ...table, snapshotHandle: "/tmp/snapshot" })).toBe(false);
    expect(isSystemInfoTable({ ...table, sessionId: "ssh-session" })).toBe(false);
    expect(isSystemInfoTable({ ...table, columns: ["用户名"] })).toBe(false);
    expect(isSystemInfoTable({
      ...table,
      rows: [{ id: "one", cells: ["root"], risk: "normal" }],
    })).toBe(false);
    expect(isSystemInfoTable({
      ...table,
      rows: [{ id: "one", cells: ["root", "0", "0", "/root", "/bin/bash"], risk: "critical" }],
    })).toBe(false);
    expect(isSystemInfoTable({
      ...table,
      rows: Array.from({ length: 501 }, (_, index) => ({
        id: `row-${index}`,
        cells: ["user", "1", "1", "/home/user", "/bin/sh"],
        risk: "normal",
      })),
    })).toBe(false);
  });

  it("keeps hostile text inert while rejecting leaked detail fields and UTF-8 overflow", () => {
    const hostile = "</script><img src=x onerror=steal()>";
    const detail = {
      tab: "users",
      rowId: "user:root",
      fields: [{ label: "说明", value: hostile }],
    };
    expect(isSystemInfoDetail(detail)).toBe(true);
    expect(detail.fields[0]?.value).toBe(hostile);
    expect(isSystemInfoDetail({ ...detail, command: "cat /etc/passwd" })).toBe(false);
    expect(isSystemInfoDetail({ ...detail, path: "/etc/passwd" })).toBe(false);
    expect(isSystemInfoDetail({ ...detail, rowId: "界".repeat(86) })).toBe(false);
    expect(isSystemInfoDetail({
      ...detail,
      fields: [{ label: "说明", value: "x".repeat(128 * 1_024 + 1) }],
    })).toBe(false);
  });
});
