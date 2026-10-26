import type { WindowsRdpRequest, WindowsRdpStatus } from "../src/shared/windows-rdp-contract";
// Test-only entry, bundled by probe-windows-workspace.mjs and mounted through
// CDP in an isolated native window. It is never imported by the application.
import { createRoot } from "react-dom/client";
import { WindowsIncidentPage } from "../src/renderer/WindowsIncidentPage";
import { matchesWindowsIncidentResponse, type DvcRuntimeStatus, type WindowsIncidentApi, type WindowsIncidentRequest, type WindowsIncidentResponse, type WindowsProcessEntry } from "../src/shared/windows-incident-contract";
import type { WinIrSnapshots } from "../src/renderer/win-ir-model";

const firstSession = "00000000-0000-4000-8000-000000000001";
const secondSession = "00000000-0000-4000-8000-000000000002";
const receivedId = "00000000-0000-4000-8000-000000000099";
const stamp = "2026-10-24T09:30:00+08:00";
const digest = "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7";
const script = "Write-Output 'fixture only'";

export function mount() {
  const original = document.querySelector<HTMLElement>('[data-testid="windows-incident-page"]');
  if (!original) throw new Error("Open the actual Windows page before mounting the fixture.");
  original.style.display = "none";
  const container = document.createElement("div");
  container.id = "windows-fixture";
  container.style.cssText = "width:100%;height:100%;min-width:0;min-height:0";
  original.after(container);
  const status: DvcRuntimeStatus = {
    registration: { registered: true, clsid: "fixture", addinName: "fixture", localServerCommand: null },
    listenerRunning: true, rdpPluginInitialized: true, channelConnected: true,
    activeChannelName: "dvc::lovelyhawk::winir", connectedSince: stamp, sessionId: firstSession,
    messagesSent: 8, messagesReceived: 8,
    recentLogs: [{ timestamp: stamp, direction: "system", kind: "status", summary: "界面测试数据，未连接远程主机。" }],
    receivedFiles: [],
  };
  const sampleProcess = (pid: number, ppid: number, name: string): WindowsProcessEntry => ({
    pid, ppid, name, executablePath: `C:\\Windows\\System32\\${name}`, commandLine: `C:\\Windows\\System32\\${name}`,
    user: "NT AUTHORITY\\SYSTEM", sessionId: 0, workingSetMb: 12, startTime: stamp, riskLevel: "normal", riskReasons: [],
  });
  const processes: WindowsProcessEntry[] = [
    sampleProcess(4, 0, "System"), sampleProcess(468, 4, "services.exe"), sampleProcess(640, 468, "svchost.exe"),
    { ...sampleProcess(900, 640, "powershell.exe"), executablePath: "C:\\Users\\Public\\dropper.exe",
      commandLine: 'powershell.exe -EncodedCommand "VwByAGkAdABlAC0ASABvAHMAdAA=" <script>fixture()</script>',
      riskLevel: "high", riskReasons: ["编码 PowerShell 参数；需要核对父进程和启动来源。"] },
    ...Array.from({ length: 236 }, (_, index) => sampleProcess(1100 + index, 468, `worker-${String(index).padStart(3, "0")}.exe`)),
  ];
  const snapshots: Omit<WinIrSnapshots, "files" | "registry"> = {
    overview: {
      hostname: "UI-FIXTURE-01", osCaption: "Windows Server 2022 Datacenter", osVersion: "10.0.20348", architecture: "64-bit",
      domainOrWorkgroup: "IR-LAB", partOfDomain: true, currentUser: "IR-LAB\\Analyst", isElevated: true, sessionName: "RDP-Tcp#1",
      bootTime: stamp, uptimeHours: 36, cpuName: "Virtual CPU", cpuCores: 8, cpuLoadPercent: 12,
      memoryTotalMb: 16384, memoryUsedMb: 6144, memoryUsagePercent: 38, systemDriveFreeGb: 62, systemDriveTotalGb: 128,
      defenderEnabled: true, realtimeProtection: true, firewallDomainEnabled: true, firewallPrivateEnabled: true,
      firewallPublicEnabled: false, highRiskCount: 1, mediumRiskCount: 1, facts: [{ group: "网络", label: "Ethernet", value: "IP: 192.0.2.10 · DNS: 192.0.2.1" }], warnings: [], highlights: ["公用网络防火墙未报告为开启，请结合当前网络配置核实。"],
    },
    baseline: { totalChecks: 7, passedCount: 1, failedCount: 2, warningCount: 2, unknownCount: 1, notApplicableCount: 1, items: [
      { id: "wdigest", remediationAvailable: true, category: "凭据保护", title: "WDigest 凭据缓存", currentValue: "启用", expectedValue: "禁用", status: "fail", severity: "high", description: "可能增加凭据暴露风险。", recommendation: "核对业务依赖并制定修复计划。" },
      { id: "uac", remediationAvailable: false, category: "权限控制", title: "用户账户控制", currentValue: "启用", expectedValue: "启用", status: "pass", severity: "normal", description: "本次读取报告 UAC 已启用。", recommendation: "结合实际权限策略核实。" },
      { id: "log", remediationAvailable: false, category: "日志审计", title: "PowerShell 脚本块日志", currentValue: "未取得", expectedValue: "启用", status: "warn", severity: "medium", description: "采集权限不足。", recommendation: "由有权限的操作员核实。" },
      { id: "password-length", remediationAvailable: false, category: "口令与锁定", title: "本地账户最短口令长度", currentValue: "8 字符", expectedValue: "至少 14 字符", status: "fail", severity: "medium", description: "来源：NetUserModalsGet 的本地 SAM 策略；不代表域账户口令。", recommendation: "评估本地账户及业务依赖后制定计划。" },
      { id: "audit-logon", remediationAvailable: false, category: "高级审计", title: "登录成功与失败审计", currentValue: "当前账户缺少读取权限；未自动提权", expectedValue: "成功和失败", status: "unknown", severity: "low", description: "来源：AuditQuerySystemPolicy 的固定子类别 GUID。", recommendation: "由有读取权限的操作员重新核查。" },
      { id: "lockout-duration", remediationAvailable: false, category: "口令与锁定", title: "本地账户锁定持续时间", currentValue: "锁定阈值为 0，本项尚不生效", expectedValue: "至少 15 分钟，或仅由管理员解锁", status: "not-applicable", severity: "normal", description: "仅在锁定阈值大于 0 时适用。", recommendation: "先复核锁定阈值。" },
      { id: "security-log-size", remediationAvailable: false, category: "日志留存", title: "Security 日志容量", currentValue: "20971520 字节", expectedValue: "建议至少 192 MiB", status: "warn", severity: "medium", description: "来源：Get-WinEvent -ListLog Security 的 MaximumSizeInBytes。", recommendation: "容量不证明实际留存期；结合转发、覆盖速度核实。" },
    ] },
    processes: { totalCount: processes.length, suspiciousCount: 1, processes },
    network: { totalCount: 2, suspiciousCount: 1, connections: [
      { protocol: "TCP", localAddress: "10.10.0.5", localPort: 53432, remoteAddress: "1.1.1.1", remotePort: 443, state: "Established", pid: 900, processName: "powershell.exe", processPath: "C:\\Users\\Public\\dropper.exe", riskLevel: "high", riskReason: "需结合进程上下文核实外联。" },
      { protocol: "TCP", localAddress: "0.0.0.0", localPort: 3389, remoteAddress: "0.0.0.0", remotePort: 0, state: "Listen", pid: 640, processName: "svchost.exe", processPath: "C:\\Windows\\System32\\svchost.exe", riskLevel: "normal", riskReason: "" },
    ] },
    startup: { totalCount: 2, suspiciousCount: 1, entries: [
      { sourceType: "Registry Run", name: "System Update", location: "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", command: "C:\\Users\\Public\\dropper.exe", runAs: "", state: "启用", riskLevel: "high", riskReason: "启动路径位于用户可写目录，需核实来源。" },
      { sourceType: "Service", name: "WinDefend", location: "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\WinDefend", command: "C:\\Program Files\\Windows Defender\\MsMpEng.exe", runAs: "LocalSystem", state: "Running", riskLevel: "normal", riskReason: "" },
    ] },
    accounts: { totalCount: 2, adminCount: 1, suspiciousCount: 1, accounts: [
      { name: "support$", fullName: "", enabled: true, isAdmin: true, sid: "S-1-5-21-1001", rid: 1001, lastLogon: stamp, passwordRequired: true, passwordExpires: false, riskLevel: "high", riskReasons: ["名称带 $ 的本地管理员，需要核实创建来源。"] },
      { name: "Guest", fullName: "", enabled: false, isAdmin: false, sid: "S-1-5-21-501", rid: 501, lastLogon: "", passwordRequired: false, passwordExpires: false, riskLevel: "normal", riskReasons: [] },
    ] },
    logs: { categoryFilter: "all", totalCount: 2, highRiskCount: 1, warnings: ["测试样本：System 通道没有读取权限。"], entries: [
      { recordId: 983745, timeCreated: stamp, channel: "Security", eventId: 4625, level: "Information", category: "logon", summary: "账户登录失败", detail: "Subject: support$\nSource: 192.0.2.10\n<script>must remain text</script>", detailTruncated: false, riskLevel: "high" },
      { recordId: 983746, timeCreated: "2026-10-24T10:00:00+08:00", channel: "Security", eventId: 4624, level: "Information", category: "logon", summary: "账户登录成功", detail: "LogonType: 10", detailTruncated: false, riskLevel: "normal" },
    ] },
  };
  const files = (path: string): WinIrSnapshots["files"] => {
    const base = path.replace(/\\+$/u, "");
    const entry = (name: string, type = "file"): WinIrSnapshots["files"]["entries"][number] => ({
      name, fullPath: `${base}\\${name}`, entryType: type, sizeBytes: type === "dir" ? 0 : 4,
      lastWriteTime: stamp, sha256: type === "dir" ? "" : digest, hidden: false, system: false, riskLevel: "normal", riskReason: "",
    });
    return { currentPath: path, totalEntries: 4, truncated: false, entries: [
      entry("Logs", "dir"), entry("evidence.txt"), { ...entry("dropper.exe"), sizeBytes: 81920, hidden: true, riskLevel: "high", riskReason: "隐藏的可执行组件，需要进一步核实。" },
      entry(`very-long-${"中文文件名".repeat(12)}.txt`),
    ] };
  };
  const calls: WindowsIncidentRequest[] = [];
  const copies: string[] = [];
  const rdpCalls: WindowsRdpRequest[] = [];
  let rdpStatus: WindowsRdpStatus = { clientId: null, phase: "idle", server: "", message: "" };
  let failAction = "";
  let delayAction = "";
  let release: (() => void) | undefined;
  const api: WindowsIncidentApi = {
    async windowsIncident(request) {
      calls.push(structuredClone(request));
      if (request.action === failAction) { failAction = ""; throw new Error("测试中的权限不足；原有结果保留。"); }
      if ("sessionId" in request && (!status.channelConnected || request.sessionId !== status.sessionId)) throw new Error("会话已变化。");
      let response: WindowsIncidentResponse;
      switch (request.action) {
        case "status": response = { kind: "status", status: structuredClone(status), filelessScript: script }; break;
        case "collect-files":
          if (request.path.includes("denied")) throw new Error("访问被拒绝，原目录结果保留。");
          response = { kind: "files", snapshot: files(request.path) }; break;
        case "preview-file": {
          let bytes = new TextEncoder().encode("data");
          const executable = request.path.endsWith(".exe");
          if (executable) {
            bytes = new Uint8Array(512);
            const view = new DataView(bytes.buffer);
            view.setUint16(0, 0x5a4d, true); view.setUint32(0x3c, 0x80, true);
            view.setUint32(0x80, 0x4550, true); view.setUint16(0x84, 0x8664, true); view.setUint16(0x86, 3, true);
            view.setUint32(0x88, 1700000000, true); view.setUint16(0x94, 240, true); view.setUint16(0x98, 0x20b, true);
          }
          response = { kind: "file-preview", preview: { fullPath: request.path, sizeBytes: executable ? 81920 : bytes.length, lastWriteTime: stamp, previewB64: btoa(String.fromCharCode(...bytes)), previewBytes: bytes.length, truncated: executable } };
          break;
        }
        case "collect-registry": response = { kind: "registry", snapshot: {
          keyPath: request.keyPath, subkeys: ["Example", "Another"], warnings: [],
          values: [
            { name: "", kind: "String", data: "", truncated: false, riskLevel: "normal", riskReason: "" },
            { name: "Debugger", kind: "ExpandString", data: "%TEMP%\\dropper.exe", truncated: false, riskLevel: "high", riskReason: "应核对调试器配置是否由管理员设置。" },
          ],
        } }; break;
        case "collect-logs": {
          const entries = snapshots.logs.entries.filter((entry) => request.category === "all" || entry.category === request.category);
          response = { kind: "logs", snapshot: { ...snapshots.logs, categoryFilter: request.category, totalCount: entries.length, highRiskCount: entries.filter((entry) => entry.riskLevel === "high").length, entries } }; break;
        }
        case "collect-overview": response = { kind: "overview", snapshot: snapshots.overview }; break;
        case "collect-baseline": response = { kind: "baseline", snapshot: snapshots.baseline }; break;
        case "remediate-baseline":
          snapshots.baseline = {
            ...snapshots.baseline,
            items: snapshots.baseline.items.map((item) => item.id === request.ruleId ? { ...item, status: "pass", severity: "normal", currentValue: item.expectedValue, remediationAvailable: false } : item),
            passedCount: snapshots.baseline.passedCount + 1,
            failedCount: Math.max(0, snapshots.baseline.failedCount - 1),
          };
          response = { kind: "baseline", snapshot: snapshots.baseline }; break;
        case "inspect-process": response = { kind: "process-inspection", inspection: {
          pid: request.pid, startTime: request.startTime, observedAt: stamp, user: "fixture\\analyst",
          services: [{ name: "FixtureSvc", displayName: "Fixture service", state: "Running", startMode: "Auto", path: "C:\\fixture.exe", account: "LocalSystem" }],
          modules: [{ name: "fixture.dll", path: "C:\\Users\\Public\\fixture.dll", sizeBytes: 4096 }],
          network: snapshots.network.connections.filter(n => n.pid === request.pid), warnings: ["合成测试样本，不是实际主机采集。"],
        } }; break;
        case "collect-processes": response = { kind: "processes", snapshot: snapshots.processes }; break;
        case "kill-process":
          snapshots.processes = {
            ...snapshots.processes,
            processes: snapshots.processes.processes.filter((p) => p.pid !== request.pid),
            totalCount: Math.max(0, snapshots.processes.totalCount - 1),
          };
          response = { kind: "processes", snapshot: snapshots.processes }; break;
        case "collect-network": response = { kind: "network", snapshot: snapshots.network }; break;
        case "collect-startup": response = { kind: "startup", snapshot: snapshots.startup }; break;
        case "remove-startup":
          snapshots.startup = {
            ...snapshots.startup,
            entries: snapshots.startup.entries.filter((e) => !(e.name === request.name && e.location === request.location)),
            totalCount: Math.max(0, snapshots.startup.totalCount - 1),
          };
          response = { kind: "startup", snapshot: snapshots.startup }; break;
        case "collect-accounts": response = { kind: "accounts", snapshot: snapshots.accounts }; break;
        case "disable-account":
          snapshots.accounts = {
            ...snapshots.accounts,
            accounts: snapshots.accounts.accounts.map((a) => a.sid === request.sid ? { ...a, enabled: false } : a),
          };
          response = { kind: "accounts", snapshot: snapshots.accounts }; break;
        case "delete-file": {
          const listing = files(request.dirPath);
          const filtered = listing.entries.filter((e) => e.fullPath !== request.path);
          response = { kind: "files", snapshot: { ...listing, totalEntries: filtered.length, entries: filtered } };
          break;
        }
        case "delete-registry-value":
          response = { kind: "registry", snapshot: {
            keyPath: request.keyPath, subkeys: ["Example", "Another"], warnings: [],
            values: [{ name: "", kind: "String", data: "", truncated: false, riskLevel: "normal", riskReason: "" }],
          } }; break;
        case "pull-file":
          status.receivedFiles = [{ fileId: receivedId, name: "evidence.txt", sizeBytes: 4, sha256: digest, verified: true, receivedAt: stamp }];
          response = { kind: "status", status: structuredClone(status), filelessScript: script }; break;
        case "run-command": response = { kind: "command-output", output: "fixture\\analyst", status: structuredClone(status) }; break;
        default: response = { kind: "status", status: structuredClone(status), filelessScript: script };
      }
      response = structuredClone(response);
      if (!matchesWindowsIncidentResponse(request, response)) throw new Error(`Fixture response failed the real contract: ${request.action}`);
      if (delayAction === request.action) { delayAction = ""; await new Promise<void>((resolve) => { release = resolve; }); }
      return response;
    },
    async windowsRdp(request) {
      rdpCalls.push(structuredClone(request));
      if (request.action === "start") rdpStatus = { clientId: receivedId, phase: "waiting", server: request.server, message: "合成 UI 测试，没有发起实际连接。" };
      if (request.action === "disconnect") rdpStatus = { clientId: null, phase: "idle", server: "", message: "" };
      return structuredClone(rdpStatus);
    },
    async saveWindowsFile(fileId) {
      if (fileId !== receivedId) throw new Error("Unknown test receipt");
      if (failAction === "save-file") { failAction = ""; throw new Error("测试中的保存失败；接收缓存仍然保留。"); }
      if (failAction === "cancel-save") { failAction = ""; return { saved: false, fileName: null, sha256: null }; }
      return { saved: true, fileName: "evidence.txt", sha256: digest };
    },
  };
  const root = createRoot(container);
  root.render(<WindowsIncidentPage api={api} writeClipboard={async (text) => { copies.push(text); }} />);
  return {
    calls, copies, status, rdpCalls,
    failNext: (action: string) => { failAction = action; },
    pauseNext: (action: string) => { delayAction = action; },
    resume: () => { release?.(); release = undefined; },
    reconnect: (hostname = "UI-FIXTURE-02") => {
      status.sessionId = status.sessionId === firstSession ? secondSession : firstSession;
      status.channelConnected = true;
      snapshots.overview.hostname = hostname;
    },
    unmount: () => { root.unmount(); container.remove(); original.style.display = ""; },
  };
}
