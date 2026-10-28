import type { WindowsChannelView } from "../src/shared/windows-channel-contract";
import { useCallback, useEffect, useReducer, useState, type ReactNode } from "react";
import { NotificationCenter, NotificationContext, NotificationOpenContext } from "../src/renderer/NotificationCenter";
import { NotificationStack } from "../src/renderer/NotificationStack";
import { initialNotificationState, notificationReducer, type NotificationSeverity } from "../src/renderer/notification-state";
import type { WindowsRdpRequest, WindowsRdpStatus } from "../src/shared/windows-rdp-contract";
// Test-only entry, bundled by probe-windows-workspace.mjs and mounted through
// CDP in an isolated native window. It is never imported by the application.
import { createRoot } from "react-dom/client";
import { WindowsIncidentPage } from "../src/renderer/WindowsIncidentPage";
import { WINDOWS_STARTUP_CATEGORIES, type WindowsControlPlan, type WindowsControlReport, matchesWindowsIncidentResponse, type WindowsProcessPlan, type WindowsInventoryKind, type WindowsInventorySnapshot, type WindowsBaselineChangePlan, type WindowsBaselineChangeReport, type DvcRuntimeStatus, type WindowsIncidentApi, type WindowsIncidentRequest, type WindowsIncidentResponse, type WindowsProcessEntry } from "../src/shared/windows-incident-contract";
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
  const inventory = (kind: WindowsInventoryKind): WindowsInventorySnapshot => ({kind,observedAt:stamp,totalCount:2,truncated:false,warnings:[],entries:[{objectId:crypto.randomUUID(),name:`fixture-${kind}`,displayName:"Synthetic inventory",location:kind==="tasks"?"\\Fixture\\":`HKLM:\\SYSTEM\\CurrentControlSet\\Services\\fixture-${kind}`,command:"C:\\Users\\Public\\fixture.exe",account:"LocalSystem",state:"Running",startMode:"Auto",pid:kind==="services"?640:0,details:["Synthetic fixture only", "触发器：登录 · 操作：fixture.exe"],riskLevel:"medium",riskReason:"测试线索"},{objectId:crypto.randomUUID(),name:`disabled-${kind}`,displayName:"Disabled fixture",location:"fixture",command:"",account:"",state:"Disabled",startMode:"Disabled",pid:0,details:[],riskLevel:"normal",riskReason:""}]});
  let warningMode = false;
  const snapshots: Omit<WinIrSnapshots, "files" | "registry"> = {
    services:inventory("services"),drivers:inventory("drivers"),tasks:inventory("tasks"),
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
      { id: "ps-scriptblock-logging", remediationAvailable: true, category: "日志审计", title: "PowerShell 脚本块日志", currentValue: "未取得", expectedValue: "启用", status: "warn", severity: "medium", description: "采集权限不足。", recommendation: "由有权限的操作员核实。" },
      { id: "password-length", remediationAvailable: true, category: "口令与锁定", title: "本地账户最短口令长度", currentValue: "8 字符", expectedValue: "至少 14 字符", status: "fail", severity: "medium", description: "来源：NetUserModalsGet 的本地 SAM 策略；不代表域账户口令。", recommendation: "评估本地账户及业务依赖后制定计划。" },
      { id: "audit-logon", remediationAvailable: false, category: "高级审计", title: "登录成功与失败审计", currentValue: "当前账户缺少读取权限；未自动提权", expectedValue: "成功和失败", status: "unknown", severity: "low", description: "来源：AuditQuerySystemPolicy 的固定子类别 GUID。", recommendation: "由有读取权限的操作员重新核查。" },
      { id: "lockout-duration", remediationAvailable: false, category: "口令与锁定", title: "本地账户锁定持续时间", currentValue: "锁定阈值为 0，本项尚不生效", expectedValue: "至少 15 分钟，或仅由管理员解锁", status: "not-applicable", severity: "normal", description: "仅在锁定阈值大于 0 时适用。", recommendation: "先复核锁定阈值。" },
      { id: "security-log-size", remediationAvailable: true, category: "日志留存", title: "Security 日志容量", currentValue: "20971520 字节", expectedValue: "建议至少 192 MiB", status: "warn", severity: "medium", description: "来源：Get-WinEvent -ListLog Security 的 MaximumSizeInBytes。", recommendation: "容量不证明实际留存期；结合转发、覆盖速度核实。" },
    ] },
    processes: { totalCount: processes.length, suspiciousCount: 1, processes },
    commands: {
      observedAt: stamp, totalCount: 2, highRiskCount: 1, mediumRiskCount: 0,
      processCreationEventsEnabled: true, commandLineAuditEnabled: true, scriptBlockLoggingEnabled: false, sysmonInstalled: true,
      warnings: [],
      entries: [
        { id: "4688:1", timeCreated: stamp, source: "security-4688", pid: 900, ppid: 640, processName: "powershell.exe", executablePath: "C:\\Users\\Public\\dropper.exe", parentName: "C:\\Windows\\System32\\svchost.exe", user: "IR-LAB\\Analyst", commandLine: "powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAA=", riskLevel: "high", riskReasons: ["命令行包含编码载荷、隐蔽窗口或远程下载执行特征"] },
        { id: "hist:Analyst:1", timeCreated: stamp, source: "psreadline-history", pid: 0, ppid: 0, processName: "powershell.exe (PSReadLine)", executablePath: "C:\\Users\\Analyst\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt", parentName: "", user: "Analyst", commandLine: "Get-Service", riskLevel: "normal", riskReasons: [] },
      ],
    },
    defender: {
      observedAt: stamp, runningMode: "Normal", antivirusEnabled: true, realtimeProtection: true, behaviorMonitor: true,
      ioavProtection: true, onAccessProtection: true, tamperProtected: true, engineVersion: "1.1.24000.1", signatureVersion: "1.419.100.0",
      signatureLastUpdated: stamp, signatureAgeDays: 1, highRiskCount: 2, warnings: [],
      exclusions: [{ kind: "path", value: "C:\\Users\\Public", source: "Get-MpPreference", riskLevel: "high", riskReason: "排除项覆盖高危公共可写目录" }],
      detections: [{ recordId: 1001, timeCreated: stamp, eventId: 1116, threatName: "Backdoor:ASP/Webshell.A", severity: "严重", category: "后门", filePath: "C:\\Users\\Public\\dropper.exe", processName: "w3wp.exe", user: "NT AUTHORITY\\NETWORK SERVICE", action: "检出威胁", detail: "Windows Defender 检测到恶意软件。", riskLevel: "high" }],
      configChanges: [{ recordId: 1002, timeCreated: stamp, eventId: 5007, changeType: "Defender 配置变更 (5007)", oldValue: "", newValue: "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\Users\\Public = 0x0", detail: "Windows Defender 配置已更改。", riskLevel: "high" }],
    },
    webshell: {
      scannedPaths: ["C:\\inetpub\\wwwroot"], observedAt: stamp, scannedFiles: 128, scannedDirs: 14, elapsedMs: 16, workerThreads: 8,
      truncated: false, highRiskCount: 1, mediumRiskCount: 0, warnings: [],
      entries: [{ fullPath: "C:\\Users\\Public\\dropper.exe", name: "shell.aspx", extension: ".aspx", sizeBytes: 1024, lastWriteTime: stamp, sha256: digest, riskLevel: "high", confidenceLevel: 5, threatType: "ASP.NET 加密反射 Webshell", matchedRules: ["冰蝎/哥斯拉 ASP.NET 反射字节码内存加载后门特征"], lineSnippet: "L1: Assembly.Load( new RijndaelManaged().CreateDecryptor() )" }],
    },
    network: { totalCount: 2, suspiciousCount: 1, connections: [
      { protocol: "TCP", localAddress: "10.10.0.5", localPort: 53432, remoteAddress: "1.1.1.1", remotePort: 443, state: "Established", pid: 900, processName: "powershell.exe", processPath: "C:\\Users\\Public\\dropper.exe", riskLevel: "high", riskReason: "需结合进程上下文核实外联。" },
      { protocol: "TCP", localAddress: "0.0.0.0", localPort: 3389, remoteAddress: "0.0.0.0", remotePort: 0, state: "Listen", pid: 640, processName: "svchost.exe", processPath: "C:\\Windows\\System32\\svchost.exe", riskLevel: "normal", riskReason: "" },
    ] },
    startup: { observedAt:stamp,truncated:false,warnings:[],categories:WINDOWS_STARTUP_CATEGORIES.map(category=>({category,count:["logon","services"].includes(category)?1:0,status:"complete",message:"合成数据：只用于界面验证。"})),totalCount: 2, suspiciousCount: 1, entries: [
      { category:"logon", sourceType: "registry", name: "System Update", location: "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", command: "C:\\Users\\Public\\dropper.exe", runAs: "", state: "启用", riskLevel: "high", riskReason: "启动路径位于用户可写目录，需核实来源。" },
      { category:"services", sourceType: "service", name: "fixture-services", location: "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\fixture-services", command: "C:\\Program Files\\Windows Defender\\MsMpEng.exe", runAs: "LocalSystem", state: "Running", riskLevel: "normal", riskReason: "" },
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
  const controlPlans = new Map<string, WindowsControlPlan>();
  const controlHistory: WindowsControlReport[] = [];
  const processPlans = new Map<string, WindowsProcessPlan>();
  const baselinePlans = new Map<string, WindowsBaselineChangePlan>();
  const baselineHistory: WindowsBaselineChangeReport[] = [];
  const channel = window.lovelyhawk.windowsChannel!;
  let channelState: { owner: string; sessionId: string | null; view: WindowsChannelView } | null = null;
  let presentationOutput: { sessionId: string | null; output: WindowsChannelView["output"] } | null = null;
  const api: WindowsIncidentApi = {
    windowsChannel: { ...channel, async sync(owner, sessionId, view) {
      const presented = { ...view, output: presentationOutput?.sessionId === sessionId ? presentationOutput.output : view.output };
      channelState = { owner, sessionId, view: presented };
      await channel.sync(owner, sessionId, presented);
    } },
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
        case "inspect-file-access": response = { kind: "file-access", inspection: { path: request.path, observedAt: stamp, attributes: "ReadOnly", owner: "NT AUTHORITY\\SYSTEM", accessRules: [{ identity: "BUILTIN\\Users", rights: "ReadAndExecute", access: "Allow", inherited: true }], processes: [], services: [{ name: "FixtureDriver", displayName: "合成驱动关联", state: "Running", startMode: "Boot", path: request.path, kind: "driver" }], warnings: ["合成数据；不代表真实文件占用。"] } }; break;
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
        case "collect-inventory": response={kind:"inventory",snapshot:structuredClone(snapshots[request.kind])}; break;
        case "inspect-inventory": {
          const kind=(["services","drivers","tasks"] as const).find(k=>snapshots[k].entries.some(e=>e.objectId===request.objectId));
          if(!kind)throw new Error("对象已移除，请刷新清单");
          const entry=snapshots[kind].entries.find(e=>e.objectId===request.objectId)!;
          response={kind:"inventory-details",details:{objectId:request.objectId,target:snapshots.overview.hostname,kind,name:kind==="tasks"?entry.location+entry.name:entry.name,observedAt:"2026-10-27T02:00:00Z",fields:[{label:"执行配置",value:entry.command},{label:kind==="tasks"?"触发器 1":"依赖此对象的服务",value:kind==="tasks"?"每天 09:00 · 已启用":"无"},{label:"恶意长文本示例",value:"<img src=x onerror=alert(1)>"}],warnings:["合成数据，只读详情不执行修改。"]}};break;
        }
        case "plan-control": {
          const kind=(["services","drivers","tasks"] as const).find(k=>snapshots[k].entries.some(e=>e.objectId===request.objectId));
          if(!kind) throw new Error("对象过期");
          const entry=snapshots[kind].entries.find(e=>e.objectId===request.objectId)!;
          const plan:WindowsControlPlan={id:crypto.randomUUID(),target:snapshots.overview.hostname,kind,name:kind==="tasks"?entry.location+entry.name:entry.name,operation:request.operation,command:entry.command,currentState:entry.state,beforeSetting:"自动",afterSetting:request.operation,impact:["合成界面测试，不操作实际主机。","仅所选对象，不级联处置依赖项。",...(request.operation==="delete"?["删除注册定义，执行文件保留；没有完整备份，不能一键恢复。"]:[])],restoring:false,expiresAt:Math.floor(Date.now()/1000)+120};
          controlPlans.clear();controlPlans.set(plan.id,plan);response={kind:"control-plan",plan};break;
        }
        case "apply-control": {
          const plan=controlPlans.get(request.planId);if(!plan) throw new Error("计划已使用");controlPlans.delete(request.planId);
          const report:WindowsControlReport={id:plan.id,target:plan.target,kind:plan.kind,name:plan.name,operation:plan.operation,state:plan.operation==="run"?"submitted":"verified",message:plan.operation==="run"?"调度器已接受请求，仍需复查任务结果。":"合成测试：已核实操作结果。",canRestore:!plan.restoring&&["manual","automatic","disable","enable"].includes(plan.operation),createdAt:Math.floor(Date.now()/1000)};
          if(plan.operation==="delete"){snapshots[plan.kind].entries=snapshots[plan.kind].entries.filter(e=>(plan.kind==="tasks"?e.location+e.name:e.name)!==plan.name);snapshots[plan.kind].totalCount=snapshots[plan.kind].entries.length;}
          controlHistory.push(report);response={kind:"control-report",report};break;
        }
        case "discard-control-plan": controlPlans.delete(request.planId);response={kind:"baseline-acknowledged",accepted:true};break;
        case "control-history": response={kind:"control-history",records:controlHistory};break;
        case "plan-control-restore": {
          const record=controlHistory.find(r=>r.id===request.recordId);if(!record?.canRestore)throw new Error("不可恢复");
          const plan:WindowsControlPlan={id:crypto.randomUUID(),target:record.target,kind:record.kind,name:record.name,operation:record.kind==="tasks"?"enable":"automatic",command:"fixture",currentState:"Running",beforeSetting:"已修改",afterSetting:"原配置",impact:["恢复配置不等于业务恢复。"],restoring:true,expiresAt:Math.floor(Date.now()/1000)+120};
          controlPlans.set(plan.id,plan);response={kind:"control-plan",plan};break;
        }
        case "plan-process-change": {
          const process=snapshots.processes.processes.find((p)=>p.pid===request.pid && p.startTime===request.startTime); if(!process) throw new Error("进程已变化");
          const plan:WindowsProcessPlan={id:crypto.randomUUID(),target:snapshots.overview.hostname,tree:request.tree,expiresAt:Math.floor(Date.now()/1000)+120,items:[{pid:process.pid,ppid:process.ppid,name:process.name,startTime:process.startTime},...(request.tree?[{pid:999,ppid:process.pid,name:"fixture-child.exe",startTime:"2026-10-24T09:30:01+08:00"}]:[])]};
          processPlans.set(plan.id,plan);response={kind:"process-plan",plan};break;
        }
        case "discard-process-plan": processPlans.delete(request.planId);response={kind:"baseline-acknowledged",accepted:true};break;
        case "apply-process-plan": {
          const plan=processPlans.get(request.planId);if(!plan)throw new Error("计划已使用");processPlans.delete(request.planId);
          snapshots.processes.processes=snapshots.processes.processes.filter((p)=>!plan.items.some((item)=>item.pid===p.pid));snapshots.processes.totalCount=snapshots.processes.processes.length;
          response={kind:"process-change",report:{id:plan.id,items:plan.items.map((item)=>({pid:item.pid,state:"verified"})),message:"合成测试：已核实计划内进程退出，仍需复查新建进程。"}};break;
        }
        case "collect-overview": response = { kind: "overview", snapshot: snapshots.overview }; break;
        case "collect-baseline": response = { kind: "baseline", snapshot: snapshots.baseline }; break;
        case "plan-baseline": case "plan-baseline-restore": {
          const ids = request.action === "plan-baseline" ? request.ruleIds : baselineHistory.find((record) => record.id === request.recordId)?.items.map((item) => item.id) ?? [];
          const plan: WindowsBaselineChangePlan = { id: crypto.randomUUID(), target: "UI-FIXTURE", expiresAt: Math.floor(Date.now()/1000)+300, restoring: request.action === "plan-baseline-restore", notes: ["合成 UI 测试；执行前保存原值，失败停止并恢复已核实的修改，不修改实际主机。"], items: ids.map((id) => { const item = snapshots.baseline.items.find((value) => value.id === id)!; return { id, title: item.title, location: `HKLM\\Fixture\\${id}`, currentValue: item.currentValue, expectedValue: item.expectedValue, impact: "需重启与业务复核，当前仅验证配置回读。" }; }) };
          baselinePlans.set(plan.id, plan); response = { kind: "baseline-plan", plan }; break;
        }
        case "discard-baseline-plan": baselinePlans.delete(request.planId); response = { kind: "baseline-acknowledged", accepted: true }; break;
        case "cancel-baseline-plan": response = { kind: "baseline-acknowledged", accepted: true }; break;
        case "baseline-plan-progress": response = { kind: "baseline-progress", report: baselineHistory.find((record) => record.id === request.planId) ?? null }; break;
        case "baseline-history": response = { kind: "baseline-history", records: baselineHistory }; break;
        case "apply-baseline-plan": {
          const plan = baselinePlans.get(request.planId); if (!plan) throw new Error("测试计划已使用"); baselinePlans.delete(request.planId);
          const report: WindowsBaselineChangeReport = { id: plan.id, target: plan.target, createdAt: Math.floor(Date.now()/1000), restoring: plan.restoring, finished: true, recoveryAvailable: !plan.restoring, items: plan.items.map((item) => ({ id: item.id, title: item.title, state: plan.restoring ? "restored" : "verified" })), message: "所选配置已回读复核，仍需运行状态与业务验证。" };
          baselineHistory.push(report);
          if (!plan.restoring) { snapshots.baseline.items = snapshots.baseline.items.map((item) => plan.items.some((entry) => entry.id === item.id) ? { ...item, status: "pass", severity: "normal", remediationAvailable: false, currentValue: item.expectedValue } : item); snapshots.baseline.passedCount = snapshots.baseline.items.filter((i) => i.status === "pass").length; snapshots.baseline.failedCount = snapshots.baseline.items.filter((i) => i.status === "fail").length; }
          response = { kind: "baseline-change", report }; break;
        }
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
          snapshots.startup.categories=snapshots.startup.categories.map(c=>({...c,count:snapshots.startup.entries.filter(e=>e.category===c.category).length}));
          response = { kind: "startup", snapshot: snapshots.startup }; break;
        case "collect-accounts": response = { kind: "accounts", snapshot: snapshots.accounts }; break;
        case "disable-account":
          snapshots.accounts = {
            ...snapshots.accounts,
            accounts: snapshots.accounts.accounts.map((a) => a.sid === request.sid ? { ...a, enabled: false } : a),
          };
          response = { kind: "accounts", snapshot: snapshots.accounts }; break;
        case "delete-account": {
          const remaining = snapshots.accounts.accounts.filter((a) => a.sid !== request.sid);
          snapshots.accounts = {
            ...snapshots.accounts,
            totalCount: remaining.length,
            adminCount: remaining.filter((a) => a.isAdmin).length,
            suspiciousCount: remaining.filter((a) => a.riskLevel !== "normal").length,
            accounts: remaining,
          };
          response = { kind: "accounts", snapshot: snapshots.accounts }; break;
        }
        case "collect-commands": response = { kind: "commands", snapshot: snapshots.commands }; break;
        case "collect-defender": response = { kind: "defender", snapshot: snapshots.defender }; break;
        case "scan-webshells": response = { kind: "webshell", snapshot: { ...snapshots.webshell, scannedPaths: [request.path || "auto"] } }; break;
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
      if (warningMode && "snapshot" in response && "warnings" in response.snapshot) {
        response.snapshot.warnings = ["只读采集遇到权限缺口。".repeat(30), "<img src=x onerror=alert(1)> 按纯文本显示", ...Array.from({length:8},(_,i)=>`说明 ${i+1}：${"需核对当前采集范围。".repeat(30)}`), "最后一条说明：没有结果不能证明没有风险。"];
        if(response.kind === "startup") { response.snapshot.truncated = true; response.snapshot.categories[5]!.status = "partial"; response.snapshot.categories[5]!.message = "分类存在权限缺口；当前已返回超过 500 条。"; }
      }
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
  let enableNotices = () => {};
  let notificationState = initialNotificationState;
  function NotificationHarness({children}: {children:ReactNode}) {
    const [enabled,setEnabled] = useState(false);
    const [open,setOpen] = useState(false);
    const [state,dispatch] = useReducer(notificationReducer, initialNotificationState);
    notificationState = state;
    enableNotices = () => setEnabled(true);
    const publish = useCallback((source:string,message:string,severity:NotificationSeverity,key?:string) => dispatch({type:"message",source,message,severity,key,now:Date.now()}),[]);
    useEffect(()=>{if(open)dispatch({type:"read"});},[open,state.history]);
    return <NotificationContext.Provider value={enabled ? publish : null}><NotificationOpenContext.Provider value={enabled ? ()=>setOpen(true) : null}>
      {children}
      {enabled ? <><button type="button" data-testid="fixture-notifications" className="statusbar-button" style={{position:"fixed",bottom:0,left:10,zIndex:1400}} onClick={()=>setOpen(true)}>通知 {state.history.length}</button><NotificationStack notifications={state.notifications} modalOpen={open} onDismiss={id=>dispatch({type:"dismiss",id})} onExpire={now=>dispatch({type:"expire",now})}/>{open ? <NotificationCenter history={state.history} omitted={state.omitted} onClose={()=>setOpen(false)} onClear={()=>dispatch({type:"clear"})} onRemove={id=>dispatch({type:"remove",id})}/> : null}</> : null}
    </NotificationOpenContext.Provider></NotificationContext.Provider>;
  }
  const root = createRoot(container);
  root.render(<NotificationHarness><WindowsIncidentPage api={api} writeClipboard={async (text) => { copies.push(text); }} /></NotificationHarness>);
  return {
    calls, copies, status, rdpCalls,
    async showChannelOutput() {
      if (!channelState) throw new Error("Open the native channel first");
      const output = { command: "展示样例（未执行远程命令）", time: stamp, output: Array.from({length:600}, (_,i)=>`样例 ${i+1}  Service-${i+1}  Running  C:\\Windows\\System32\\fixture.exe`).join("\n") + "\n<script>hostile()</script>" };
      presentationOutput = { sessionId: channelState.sessionId, output };
      await channel.sync(channelState.owner, channelState.sessionId, { ...channelState.view, output });
    },
    notifications: () => notificationState,
    enableCollectionWarnings: () => {
      warningMode = true; enableNotices();
      const template = snapshots.startup.entries[0]!;
      snapshots.startup.entries.push(...Array.from({length:1200},(_,i)=>({...template,category:"codecs" as const,name:`codec-fixture-${i}`,riskLevel:"normal" as const,riskReason:""})));
      snapshots.startup.totalCount = snapshots.startup.entries.length;
      for(const c of snapshots.startup.categories) c.count = snapshots.startup.entries.filter(e=>e.category===c.category).length;
    },
    expandTasks:()=>{const template=snapshots.tasks.entries[0];snapshots.tasks.entries.push(...Array.from({length:120},(_,i)=>({...template,objectId:crypto.randomUUID(),name:`长列表任务-${i+1}`,displayName:"任务说明，需在详情中完整查看。".repeat(12)})));snapshots.tasks.totalCount=snapshots.tasks.entries.length;},
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
