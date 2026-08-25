import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type { SystemInfoApi, SystemInfoSummary, SystemInfoTable } from "../shared/system-info-contract";
import { SYSTEM_INFO_CATALOG } from "../shared/system-info-contract";
import {
  buildSystemInfoSummaryCopy,
  buildSystemInfoTableCopy,
  groupSystemInfoCatalog,
  nextModalFocusIndex,
} from "./system-info-helpers";
import { SystemInfoPage } from "./SystemInfoPage";

const api: SystemInfoApi = {
  getSystemInfoCatalog: vi.fn(async () => []),
  getSystemInfoSummary: vi.fn(async () => ({})),
  collectSystemInfo: vi.fn(async () => ({})),
  getSystemInfoDetail: vi.fn(async () => ({})),
};

describe("standalone SystemInfo page", () => {
  it("renders a connection prompt without a target", () => {
    const markup = renderToStaticMarkup(<SystemInfoPage connection={null} api={api} />);
    expect(markup).toContain("连接目标后查看系统信息");
    expect(markup).not.toContain("snapshotHandle");
  });

  it("renders target text inertly without exposing the binding handle", () => {
    const markup = renderToStaticMarkup(
      <SystemInfoPage
        connection={{
          bindingHandle: "opaque-binding-must-not-render",
          target: {
            connectionId: "server-1",
            host: "</p><script>steal()</script>",
            port: 22,
            username: "root",
            timestamp: "2026-08-24T00:00:00Z",
          },
        }}
        api={api}
      />,
    );
    // The page no longer echoes the target at all: the status bar owns it.
    expect(markup).not.toContain("steal()");
    expect(markup).not.toContain("<script>");
    expect(markup).not.toContain("opaque-binding-must-not-render");
    expect(markup).not.toContain("sessionId");
    expect(markup).not.toContain("TargetGuard");
  });
});

describe("system-info pure helpers", () => {
  it("groups the fixed catalog into four ordered groups", () => {
    const grouped = groupSystemInfoCatalog(SYSTEM_INFO_CATALOG.map((entry) => ({
      ...entry,
      columns: [...entry.columns],
    })));
    expect(grouped.map((group) => group.key)).toEqual([
      "realtime", "persistence", "security", "workload",
    ]);
    expect(grouped.reduce((total, group) => total + group.tabs.length, 0)).toBe(25);
  });

  it("copies bounded plain text without opaque row or snapshot handles", () => {
    const table: SystemInfoTable = {
      snapshotHandle: "opaque-snapshot",
      tab: "users",
      columns: ["用户名", "UID", "GID", "主目录", "Shell"],
      rows: [{
        id: "opaque-row-id",
        cells: ["root\tadmin", "0", "0", "/root", "/bin/bash\n--login"],
        risk: "normal",
      }],
      truncated: false,
    };
    const copied = buildSystemInfoTableCopy(table);
    expect(copied).toContain("root admin");
    expect(copied).toContain("/bin/bash --login");
    expect(copied).not.toContain("opaque-snapshot");
    expect(copied).not.toContain("opaque-row-id");
  });

  it("copies every summary field and wraps modal focus deterministically", () => {
    const summary = Object.fromEntries(
      [
        "hostname", "operatingSystem", "kernel", "architecture", "virtualization", "bootTime",
        "timezone", "locale", "initSystem", "packageManager", "selinux", "apparmor", "cpuModel",
        "rootDevice", "rootFilesystem", "primaryIp", "defaultGateway", "dnsServers",
      ].map((key) => [key, key]),
    ) as unknown as SystemInfoSummary;
    Object.assign(summary, {
      uptimeSeconds: 60,
      loadAverage: ["0", "0", "0"],
      cpuCores: 1,
      memoryTotalBytes: 1,
      memoryAvailableBytes: 1,
      swapTotalBytes: 1,
      swapFreeBytes: 1,
      rootTotalBytes: 1,
      rootAvailableBytes: 1,
      processCount: 1,
      loggedInUsers: 1,
      networkConnections: 1,
      receivedBytes: 1,
      transmittedBytes: 1,
    });
    const copied = buildSystemInfoSummaryCopy(summary);
    expect(copied).toContain("主机名\thostname");
    expect(copied).toContain("发送字节\t1 B");
    expect(nextModalFocusIndex(0, 3, true)).toBe(2);
    expect(nextModalFocusIndex(2, 3, false)).toBe(0);
    expect(nextModalFocusIndex(-1, 3, false)).toBe(0);
  });
});
