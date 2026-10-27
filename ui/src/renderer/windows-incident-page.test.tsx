import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { WINDOWS_STARTUP_CATEGORIES, type WindowsIncidentApi, type WindowsProcessEntry } from "../shared/windows-incident-contract";
import { WindowsIncidentPage } from "./WindowsIncidentPage";
import { DataTable } from "./WinIrKit";
import { buildWindowsTimeline, isRoutineSystemStart, WinIrTimeline } from "./WinIrEvents";
import { WinIrNetwork, WinIrProcesses } from "./WinIrActivity";
import { WinIrAccounts, WinIrBaseline, WinIrStartup } from "./WinIrChecks";
import { RELATED_ID, findRelated, isServiceAccount, normalizeWinPath } from "./win-ir-links";
import type { WinIrSnapshots } from "./win-ir-model";
import { buildProcessTree, decodeBase64, decodeTextPreview, isPublicAddress, parentPath, pathSegments, processAncestors, processChildren, toCsv } from "./win-ir-helpers";

describe("WindowsIncidentPage", () => {
  it("renders the DVC header, module tabs, and initial overview prompt", () => {
    const api: WindowsIncidentApi = {
      windowsIncident: async () => ({
        kind: "status",
        status: {
          registration: {
            registered: true,
            clsid: "{D9B80669-C06A-4BD1-9CB1-3B7168C9E3A3}",
            addinName: "SimpleRdpPlugin",
            localServerCommand: "lovelyhawk.exe -Embedding",
          },
          listenerRunning: true,
          rdpPluginInitialized: true,
          channelConnected: false,
          activeChannelName: null,
          connectedSince: null,
          sessionId: null,
          messagesSent: 0,
          messagesReceived: 0,
          recentLogs: [],
          receivedFiles: [],
        },
        filelessScript: "Add-Type ...",
      }),
    };

    const html = renderToStaticMarkup(<WindowsIncidentPage api={api} />);
    expect(html).toContain("Windows 应急响应工作台");
    expect(html).toContain("注册插件并启动监听");
    expect(html).toContain("复制免落地 PowerShell 脚本");
    // Before a session connects, the main column is the three-step guide.
    expect(html).toContain("三步连接被检 Windows 主机");
    expect(html).toContain('data-testid="windows-register-plugin"');
    expect(html).toContain('data-testid="windows-open-mstsc"');
    expect(html).toContain('data-testid="windows-reveal-agent"');
    expect(html).not.toContain("win-ir-target-card");
    expect(html).toContain("主机总览");
    expect(html).toContain("响应方案");
    expect(html).toContain("基线配置");
    expect(html).toContain("进程分析");
    expect(html).toContain("网络连接");
    expect(html).toContain("启动项");
    expect(html).toContain("本地账户");
    expect(html).toContain("事件日志");
    expect(html).toContain("文件排查");
    expect(html).toContain("注册表");
  });
});

function process(pid: number, ppid = 0): WindowsProcessEntry {
  return { pid, ppid, name: `process-${pid}`, executablePath: "", commandLine: "", user: "", sessionId: 0, workingSetMb: 1, startTime: "", riskLevel: "normal", riskReasons: [] };
}

describe("Windows investigation evidence helpers", () => {
  it("keeps orphan and cyclic processes visible without recursive stack overflow", () => {
    const rows = [process(1, 2), process(2, 1), process(3, 999)];
    expect(buildProcessTree(rows).map((row) => row.process.pid).sort()).toEqual([1, 2, 3]);
    expect(processAncestors(1, rows).map((row) => row.pid)).toEqual([2]);
    const deep = Array.from({ length: 12000 }, (_, index) => process(index + 1, index));
    expect(buildProcessTree(deep).at(-1)?.depth).toBe(11999);
  });

  it("links a parent only when it did not start after the child", () => {
    const at = (pid: number, ppid: number, startTime: string, riskLevel: WindowsProcessEntry["riskLevel"] = "normal") => ({ ...process(pid, ppid), startTime, riskLevel });
    const rows = [
      at(10, 4, "2026-10-24T08:00:00Z"),
      at(12, 10, "2026-10-24T09:30:00Z", "medium"),
      at(11, 10, "2026-10-24T09:00:00Z"),
      at(13, 11, "2026-10-24T09:10:00Z", "high"),
      at(20, 30, "2026-10-24T07:00:00Z"),
      at(30, 4, "2026-10-24T10:00:00Z"),
      at(40, 8196, "2026-10-24T08:00:00Z"),
      { ...process(50, 10) },
    ];
    const tree = buildProcessTree(rows);
    const row = (pid: number) => tree.find((candidate) => candidate.process.pid === pid)!;
    expect(row(20).link).toMatchObject({ parent: null, gap: "reused" });
    expect(row(20).depth).toBe(0);
    expect(row(40).link).toMatchObject({ parent: null, gap: "exited" });
    expect(row(50).link).toMatchObject({ verified: false, gap: null });
    expect(row(50).link.parent?.pid).toBe(10);
    expect(row(11).link).toMatchObject({ verified: true });
    // Siblings follow start time, missing times first.
    expect(tree.filter((candidate) => candidate.depth === 1 && candidate.link.parent?.pid === 10).map((candidate) => candidate.process.pid)).toEqual([50, 11, 12]);
    expect(row(10).descendantRisk).toEqual({ high: 1, medium: 1 });
    expect(row(10).childCount).toBe(3);
    expect(processAncestors(20, rows)).toEqual([]);
    expect(processAncestors(13, rows).map((entry) => entry.pid)).toEqual([11, 10]);
    expect(processChildren(30, rows)).toEqual([]);
    expect(processChildren(10, rows).map((entry) => entry.pid)).toEqual([50, 11, 12]);
  });

  it("shows processes as a tree with PID and PPID first and risk last", () => {
    const rows = [{ ...process(4, 0), name: "System" }, { ...process(628, 8196), name: "XWin_MobaX.exe", riskLevel: "high" as const }];
    const html = renderToStaticMarkup(<WinIrProcesses snapshot={{ totalCount: 2, suspiciousCount: 1, processes: rows }} network={null} focus={null} busy={false} connected onInspect={async () => { throw new Error("unused"); }} onCopy={() => undefined} onFile={() => undefined} onNetwork={() => undefined} />);
    const headers = [...html.matchAll(/<th[^>]*>(?:<button[^>]*>)?([^<]+)/gu)].map((match) => match[1]);
    expect(headers).toEqual(["PID", "PPID", "进程名称", "用户", "启动时间", "内存", "执行路径", "风险"]);
    expect(html).toContain('aria-pressed="true">进程树');
    expect(html).not.toContain("▣");
    expect(html).toContain("已退出");
    expect(html).toContain("←→ 折叠/展开");
  });

  it("relates records by path, account and address without treating names as identity", () => {
    const dropper = { ...process(900, 640), name: "powershell.exe", executablePath: "C:\\Users\\Public\\dropper.exe", user: "HOST\\alice", startTime: "2026-10-24T09:00:00Z" };
    const service = { ...process(700, 4), name: "svchost.exe", executablePath: "C:\\Windows\\System32\\svchost.exe", user: "NT AUTHORITY\\SYSTEM" };
    const snapshots = {
      processes: { totalCount: 2, suspiciousCount: 0, processes: [dropper, service] },
      startup: { observedAt:"2026-10-27T00:00:00Z", truncated:false, warnings:[], categories:WINDOWS_STARTUP_CATEGORIES.map(category=>({category,count:category==="logon"?1:0,status:"complete",message:"fixture"})), totalCount: 1, suspiciousCount: 1, entries: [{ category:"logon", sourceType: "registry", name: "Updater", location: "HKLM:\\Run", command: '"c:/users/public/DROPPER.exe" -silent', runAs: "", state: "", riskLevel: "high" as const, riskReason: "" }] },
      registry: { keyPath: "HKLM:\\IFEO", subkeys: [], warnings: [], values: [{ name: "Debugger", kind: "String", data: "%TEMP%\\dropper.exe", truncated: false, riskLevel: "high" as const, riskReason: "" }] },
      network: { totalCount: 1, suspiciousCount: 0, connections: [{ protocol: "TCP", localAddress: "10.0.0.5", localPort: 5000, remoteAddress: "203.0.113.7", remotePort: 443, state: "Established", pid: 1234, processName: "other.exe", processPath: "C:\\other.exe", riskLevel: "normal" as const, riskReason: "" }] },
      logs: { categoryFilter: "all", totalCount: 1, highRiskCount: 0, warnings: [], entries: [{ recordId: 7, timeCreated: "2026-10-24T09:01:00Z", channel: "Security", eventId: 4624, level: "Information", category: "Logon", summary: "登录成功", detail: "Account Name: alice\nSource Address: 203.0.113.7", detailTruncated: false, riskLevel: "normal" as const }] },
    } as Partial<WinIrSnapshots>;
    const hits = findRelated({ paths: [dropper.executablePath], accounts: [dropper.user], exclude: RELATED_ID.process(dropper) }, snapshots);
    expect(hits.find((hit) => hit.tab === "startup")?.match).toBe("path");
    expect(hits.find((hit) => hit.tab === "registry")?.match).toBe("name");
    expect(hits.find((hit) => hit.tab === "logs")?.match).toBe("mention");
    expect(hits.some((hit) => hit.tab === "processes")).toBe(false);
    expect(findRelated({ accounts: ["NT AUTHORITY\\SYSTEM"] }, snapshots)).toEqual([]);
    expect(isServiceAccount("NT AUTHORITY\\SYSTEM")).toBe(true);
    expect(findRelated({ addresses: ["203.0.113.7"] }, snapshots).map((hit) => hit.tab).sort()).toEqual(["logs", "network"]);
    expect(findRelated({ addresses: ["203.0.113.70"] }, snapshots)).toEqual([]);
    expect(normalizeWinPath('"C:/Users//Public/"')).toBe("c:\\users\\public");
  });

  it("orders the timeline by the moment each source time denotes", () => {
    const rows = buildWindowsTimeline({ processes: { totalCount: 2, suspiciousCount: 0, processes: [
      { ...process(1), startTime: "2026-10-24T09:00:00+08:00", executablePath: "C:\\Windows\\System32\\a.exe" },
      { ...process(2), startTime: "2026-10-24T02:00:00Z", executablePath: "C:\\Users\\Public\\b.exe" },
    ] } });
    const [early, late] = [rows.find((row) => row.title.endsWith("process-1"))!, rows.find((row) => row.title.endsWith("process-2"))!];
    expect(early.epoch).toBeLessThan(late.epoch);
    expect(early.time > late.time).toBe(true);
    expect(early.target).toEqual({ tab: "processes", pid: 1, startTime: "2026-10-24T09:00:00+08:00" });
    expect(isRoutineSystemStart(early)).toBe(true);
    expect(isRoutineSystemStart(late)).toBe(false);
  });

  it("keeps the risk column last in every evidence table", () => {
    const lastHeader = (html: string) => [...html.matchAll(/<th[^>]*>(?:<button[^>]*>)?([^<]+)/gu)].map((match) => match[1]).at(-1);
    const noop = () => undefined;
    expect(lastHeader(renderToStaticMarkup(<WinIrNetwork snapshot={{ totalCount: 1, suspiciousCount: 0, connections: [{ protocol: "TCP", localAddress: "0.0.0.0", localPort: 1, remoteAddress: "0.0.0.0", remotePort: 0, state: "Listen", pid: 4, processName: "System", processPath: "", riskLevel: "normal", riskReason: "" }] }} focus={null} onCopy={noop} onProcess={noop} onFile={noop} />))).toBe("风险");
    expect(lastHeader(renderToStaticMarkup(<WinIrStartup snapshot={{ observedAt:"2026-10-27T00:00:00Z", truncated:false, warnings:[], categories:WINDOWS_STARTUP_CATEGORIES.map(category=>({category,count:category==="services"?1:0,status:"complete",message:"fixture"})), totalCount: 1, suspiciousCount: 0, entries: [{ category:"services", sourceType: "service", name: "x", location: "", command: "", runAs: "", state: "", riskLevel: "normal", riskReason: "" }] }} onCopy={noop} onFile={noop} onRegistry={noop} />))).toBe("风险");
    expect(lastHeader(renderToStaticMarkup(<WinIrAccounts snapshot={{ totalCount: 1, adminCount: 0, suspiciousCount: 0, accounts: [{ name: "a", fullName: "", enabled: true, isAdmin: false, sid: "S-1", rid: 1, lastLogon: "", passwordRequired: true, passwordExpires: true, riskLevel: "normal", riskReasons: [] }] }} onCopy={noop} onLogs={noop} />))).toBe("风险");
    expect(lastHeader(renderToStaticMarkup(<WinIrBaseline snapshot={{ totalChecks: 1, passedCount: 1, failedCount: 0, warningCount: 0, unknownCount: 0, notApplicableCount: 0, items: [{ id: "a", remediationAvailable: false, category: "c", title: "t", currentValue: "", expectedValue: "", status: "pass", severity: "normal", description: "", recommendation: "" }] }} onCopy={noop} />))).toBe("结果");
    expect(lastHeader(renderToStaticMarkup(<WinIrTimeline snapshots={{ processes: { totalCount: 1, suspiciousCount: 0, processes: [{ ...process(1), startTime: "2026-10-24T09:00:00Z" }] } }} onCopy={noop} onGo={noop} />))).toBe("风险");
  });

  it("keeps drive roots and UNC share roots intact during navigation", () => {
    expect(parentPath("C:\\Windows\\System32\\")).toBe("C:\\Windows");
    expect(parentPath("C:\\file.txt")).toBe("C:\\");
    expect(parentPath("C:\\")).toBeNull();
    expect(parentPath("\\\\server\\share")).toBeNull();
    expect(pathSegments("\\\\server\\share\\folder")).toEqual([
      { label: "\\\\server\\share", path: "\\\\server\\share\\" },
      { label: "folder", path: "\\\\server\\share\\folder" },
    ]);
  });

  it("does not classify local, reserved, malformed or documentation addresses as public", () => {
    for (const address of ["127.0.0.1", "10.2.3.4", "169.254.2.2", "192.168.1.1", "100.64.1.1", "192.0.2.1", "203.0.113.9", "999.1.2.3", "::1", "fe80::1", "fd12::1", "2001:db8::4"]) expect(isPublicAddress(address), address).toBe(false);
    for (const address of ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"]) expect(isPublicAddress(address), address).toBe(true);
  });

  it("decodes a UTF-16 preview and never invents timestamps for missing evidence", () => {
    expect(decodeTextPreview(decodeBase64("//5BAEIA"))?.text).toBe("AB");
    expect(buildWindowsTimeline({ processes: { totalCount: 1, suspiciousCount: 0, processes: [process(1)] } })).toEqual([]);
    const entries = buildWindowsTimeline({ processes: { totalCount: 1, suspiciousCount: 0, processes: [{ ...process(1), startTime: "2026-10-24T09:00:00+08:00" }] } });
    expect(entries[0]?.time).toBe("2026-10-24T09:00:00+08:00");
    expect(toCsv(["value"], [["=HYPERLINK(\"evil\")"], ["@SUM(1,2)"]])).toContain("'@SUM");
  });

  it("bounds table rendering and escapes hostile evidence as text", () => {
    const rows = Array.from({ length: 250 }, (_, id) => ({ id, name: id === 0 ? "<script>bad()</script>" : `row-${id}` }));
    const html = renderToStaticMarkup(<DataTable label="evidence" rows={rows} columns={[{ key: "name", label: "名称", render: (row) => row.name }]} rowKey={(row) => String(row.id)} selectedKey={null} onSelect={() => undefined} empty="empty" />);
    expect(html).toContain("aria-rowcount=\"251\"");
    expect(html).toContain("下一页");
    expect(html).not.toContain("row-100");
    expect(html).toContain("&lt;script&gt;");
    expect(html).not.toContain("<script>bad()");
  });
});
