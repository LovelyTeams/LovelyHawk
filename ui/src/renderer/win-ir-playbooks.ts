import type { LOG_CATEGORIES } from "./WinIrEvents";
import { WINDOWS_COMMAND_PRESETS } from "./win-ir-command-presets";
import { FILE_PLACES, REGISTRY_PLACES } from "./win-ir-presets";
import { moduleLabel } from "./win-ir-model";

export const PLAYBOOK_REVIEW_DATE = "2026-10-26";
export const PLAYBOOK_SOURCES = {
  nist: { title: "NIST SP 800-61 Rev. 3（2025）", url: "https://csrc.nist.gov/pubs/sp/800/61/r3/final" },
  microsoft: { title: "Microsoft 应急响应方案", url: "https://learn.microsoft.com/en-us/security/operations/incident-response-playbooks" },
  ransomware: { title: "Microsoft DART 勒索事件响应", url: "https://learn.microsoft.com/en-us/security/ransomware/incident-response-playbook-dart-ransomware-approach" },
  autoruns: { title: "Microsoft Sysinternals Autoruns", url: "https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns" },
  handle: { title: "Microsoft Sysinternals Handle", url: "https://learn.microsoft.com/en-us/sysinternals/downloads/handle" },
  drivers: { title: "Microsoft 易受攻击驱动阻止规则", url: "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules" },
  forest: { title: "Microsoft AD 林恢复指南", url: "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-guide" },
  events: { title: "Microsoft Windows 安全事件参考", url: "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor" },
  sysmon: { title: "Microsoft Sysinternals Sysmon", url: "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon" },
  miner: { title: "MITRE ATT&CK T1496 · 资源劫持", url: "https://attack.mitre.org/techniques/T1496/" },
  credentials: { title: "MITRE ATT&CK T1003.001 · LSASS 凭据访问", url: "https://attack.mitre.org/techniques/T1003/001/" },
  rdp: { title: "MITRE ATT&CK T1021.001 · RDP", url: "https://attack.mitre.org/techniques/T1021/001/" },
  smb: { title: "MITRE ATT&CK T1021.002 · SMB / 管理共享", url: "https://attack.mitre.org/techniques/T1021/002/" },
  tasks: { title: "MITRE ATT&CK T1053.005 · Windows 计划任务", url: "https://attack.mitre.org/techniques/T1053/005/" },
  wmi: { title: "MITRE ATT&CK T1546.003 · WMI 永久事件订阅", url: "https://attack.mitre.org/techniques/T1546/003/" },
  powershell: { title: "MITRE ATT&CK T1059.001 · PowerShell", url: "https://attack.mitre.org/techniques/T1059/001/" },
  webshell: { title: "MITRE ATT&CK T1505.003 · Web Shell", url: "https://attack.mitre.org/techniques/T1505/003/" },
  exfil: { title: "MITRE ATT&CK T1041 · 通过控制通道外传", url: "https://attack.mitre.org/techniques/T1041/" },
} as const;

/** These references select existing read-only entry points; they never contain executable commands. */
export type PlaybookAction =
  | { kind: "module"; tab: "overview" | "processes" | "network" | "startup" | "accounts" | "baseline" | "timeline" }
  | { kind: "files"; preset: (typeof FILE_PLACES)[number]["label"] }
  | { kind: "registry"; preset: (typeof REGISTRY_PLACES)[number]["label"] }
  | { kind: "logs"; category: (typeof LOG_CATEGORIES)[number]["value"]; label: string }
  | { kind: "command"; preset: string };

export interface PlaybookStep { title: string; text: string; actions: readonly PlaybookAction[] }
export interface WindowsPlaybook {
  id: string; title: string; group: string; summary: string; keywords: string;
  first: string; scope: string; evidence: readonly string[];
  steps: readonly [PlaybookStep, PlaybookStep, PlaybookStep, PlaybookStep];
  gaps: readonly string[]; sources: readonly (keyof typeof PLAYBOOK_SOURCES)[];
}
const module = (tab: Extract<PlaybookAction, { kind: "module" }>["tab"]): PlaybookAction => ({ kind: "module", tab });
const files = (preset: Extract<PlaybookAction, { kind: "files" }>["preset"]): PlaybookAction => ({ kind: "files", preset });
const registry = (preset: Extract<PlaybookAction, { kind: "registry" }>["preset"]): PlaybookAction => ({ kind: "registry", preset });
const logs = (category: Extract<PlaybookAction, { kind: "logs" }>["category"], label: string): PlaybookAction => ({ kind: "logs", category, label });
const command = (preset: string): PlaybookAction => ({ kind: "command", preset });

/** Original investigation workflows synthesized from the sources below, not automated verdicts. */
export const WINDOWS_PLAYBOOKS: readonly WindowsPlaybook[] = [
  {
    id: "triage", title: "初步排查与现场保全", group: "开始调查", summary: "接到告警后，确认目标、影响与证据缺口。", keywords: "首次 告警 取证 时间线 快照",
    first: "先记录告警时间、时区、主机和业务影响。若破坏仍在扩大，协调遏制与留证并行，避免为了完整采集而延误止损。",
    scope: "适用于尚未明确攻击类型的 Windows 主机。以当前采集账户的权限和可见范围为准。",
    evidence: ["主机名、系统版本、当前权限、时间与时区", "进程命令行、父子关系、连接、登录和启动项", "来源告警、原始文件及摘要、采集失败与截断情况"],
    steps: [
      { title: "确认目标和权限", text: "核对是否选中告警涉及的主机；区分普通用户、管理员和域成员。记录观察时间，先了解哪些证据能够读取。", actions: [module("overview"), command("identity"), command("os")] },
      { title: "保留易消失的线索", text: "先查看进程、连接和会话，再检查落地文件与持久化。用时间线关联不同采集时刻；快照不是同一时刻的完整现场。", actions: [module("processes"), module("network"), command("sessions"), module("timeline")] },
      { title: "按证据选择处置", text: "把可疑线索与正常运维活动核对。确定对象后进入相应页面留证，再审阅该对象的处置确认；不要将高风险标签直接当作删除依据。", actions: [module("startup"), module("accounts")] },
      { title: "形成可复核的结论", text: "重新采集受影响对象，与原始告警和业务方核对恢复情况。记录未解决事项；没有读到记录不能证明没有入侵。", actions: [module("timeline"), module("baseline")] },
    ],
    gaps: ["当前快照不能替代磁盘镜像、内存镜像与完整 EVTX 留证。", "跨主机证据关联、事件分派和业务恢复确认需在组织的应急流程中完成。"], sources: ["nist", "microsoft"],
  },
  {
    id: "ransomware", title: "勒索加密与恢复破坏", group: "恶意活动", summary: "文件批量变化、勒索提示、备份或防护异常。", keywords: "勒索病毒 ransomware 加密 备份 卷影",
    first: "若仍在加密或横向扩散，先通过组织认可的隔离方式限制影响，并保留必要的管理通道。不要默认重启、关机或删除勒索样本。",
    scope: "检查终端、共享存储、身份系统与备份的共同影响；单台主机停止加密不代表事件结束。",
    evidence: ["勒索提示、少量加密文件样本、文件时间与摘要", "异常进程、外连、登录来源和持久化", "备份访问、防护变更和恢复能力的独立记录"],
    steps: [
      { title: "确定破坏是否持续", text: "关联近期进程、连接与文件变化，记录已受影响业务和共享目录。不要为验证样本而运行可疑程序。", actions: [module("processes"), module("network"), files("公共目录")] },
      { title: "追查入口与扩散", text: "对照远程登录、服务安装与防护告警，检查是否使用受信任工具实施攻击。把账户和时间窗口交给其他主机的调查人员核查。", actions: [logs("rdp", "远程登录事件"), logs("defender", "防护告警"), logs("service", "服务事件"), module("startup")] },
      { title: "保全后遏制", text: "完成必要留证后，协调隔离、受影响账户处置与备份保护。远程结束进程前确认业务影响；不要清日志或批量删除加密文件。", actions: [files("用户临时目录"), module("accounts")] },
      { title: "验证可信恢复", text: "从已核实的备份或可信介质恢复，并处理入口与受影响凭据。检查任务、服务、登录和业务功能，持续观察是否再次出现加密。", actions: [module("startup"), module("baseline"), logs("logon", "登录审计")] },
    ],
    gaps: ["未接入 EDR 网络隔离、备份系统和解密服务。", "恢复文件不等于消除攻击者访问权限；域或备份受影响需升级联合响应。"], sources: ["ransomware", "microsoft"],
  },
  {
    id: "miner", title: "挖矿与资源异常", group: "恶意活动", summary: "持续资源占用，结合程序来源与外连判断。", keywords: "挖矿 miner CPU GPU 矿池 性能",
    first: "先区分业务负载、更新与未经授权的程序；单次高 CPU 或陌生进程名不足以判定挖矿。",
    scope: "当前进程与网络只是采集时刻的观察；需要持续性能记录和业务基准。",
    evidence: ["可疑进程的完整命令行、路径、父进程和启动时间", "外连地址、落地文件摘要及重复拉起来源"],
    steps: [
      { title: "锁定资源来源", text: "结合业务方的性能观察核对进程及父子关系；记录程序参数与所属账户。", actions: [module("processes"), command("processes")] },
      { title: "关联连接和驻留", text: "检查连接对端，并追查服务、任务和启动目录是否持续拉起相同程序。不要只按常见矿池端口筛选。", actions: [module("network"), module("startup"), command("tasks")] },
      { title: "留证并处理来源", text: "从进程定位文件后先取证拉取，再针对已核实对象审阅结束进程或启动项处置。同步修复最初入侵入口。", actions: [files("ProgramData"), files("用户临时目录"), command("services")] },
      { title: "复核复发与业务", text: "在约定观察期内复查进程、连接和任务触发，比较业务性能；资源恢复不能独立证明主机已安全。", actions: [module("processes"), module("network"), module("startup")] },
    ],
    gaps: ["未实现连续 CPU/GPU 监控、矿池信誉查询与自动挖矿判定。"], sources: ["miner", "autoruns"],
  },
  {
    id: "trojan", title: "木马外联与远控", group: "恶意活动", summary: "异常外连、陌生远控程序或可疑下载执行。", keywords: "木马 C2 RAT 远控 后门 反连 下载",
    first: "先记录连接对应的进程身份、路径和启动时间；不要访问可疑地址或运行下载文件来验证。",
    scope: "合法远控和代理也可能被滥用；需要对照安装来源、审批和正常使用时间。",
    evidence: ["连接两端、PID 与进程启动时间", "命令行、文件摘要、来源下载与启动项", "网关、DNS、代理或 EDR 的相关时间记录"],
    steps: [
      { title: "从连接定位进程", text: "对照网络页和进程页，区分监听与已建立连接。进程退出后 PID 可能复用，不用旧 PID 直接处置。", actions: [module("network"), module("processes"), command("dns")] },
      { title: "寻找落地和重启来源", text: "检查下载、公共目录、用户应用数据及启动项，核对与连接时间相关的程序和脚本。", actions: [files("下载"), files("漫游应用数据"), module("startup"), logs("sysmon", "Sysmon 线索")] },
      { title: "限制已确认的访问", text: "保存样本和连接记录后协调网络遏制，逐项核对结束进程和持久化处置。检查被使用的账户及远控授权。", actions: [module("accounts"), command("services")] },
      { title: "复查重新连接", text: "复查服务、任务与外连是否重现，并在网络侧核对后续通信。当前连接为空不能证明历史上未发生控制或外传。", actions: [module("network"), module("startup"), module("timeline")] },
    ],
    gaps: ["当前没有流量抓包、地址信誉查询或远控软件授权数据库。"], sources: ["exfil", "autoruns", "sysmon"],
  },
  {
    id: "rdp", title: "异常登录与暴力尝试", group: "身份与横向", summary: "登录失败激增、陌生来源或异常管理员会话。", keywords: "RDP 爆破 暴力破解 4624 4625 远程桌面 登录",
    first: "结合账户、来源地址、登录类型与时间核查；登录成功或失败事件本身都不能单独证明入侵。",
    scope: "本地账户页不包含域身份全貌；日志是否存在取决于事先配置的审计与留存。",
    evidence: ["失败与成功登录的账户、来源、登录类型和时间", "远程桌面连接/重连、会话与管理员组变化"],
    steps: [
      { title: "确定异常时间窗口", text: "先看失败与锁定，再对照同一账户或来源的成功登录。检查是否来自正常跳板机、扫描或运维。", actions: [logs("failed-logon", "失败与锁定事件"), logs("logon", "登录审计"), logs("rdp", "远程桌面事件")] },
      { title: "核查会话与权限", text: "核对当前会话、本地管理员和账户变更，追查异常登录之后的进程与服务活动。", actions: [command("sessions"), module("accounts"), logs("account", "账户变更"), module("timeline")] },
      { title: "控制受影响身份", text: "在可信管理终端协调账户禁用、凭据轮换和入口限制，保留应急管理账户。只修改 RDP 端口不能消除已泄露凭据的风险。", actions: [module("accounts"), registry("远程桌面 (RDP-Tcp)"), module("baseline")] },
      { title: "复核访问和业务", text: "重新检查登录来源与管理员成员，验证合法用户仍可访问；轮换口令后还需核查存量会话和其他访问路径。", actions: [logs("logon", "登录审计"), command("sessions"), module("accounts")] },
    ],
    gaps: ["未接入域控制器、身份提供商和远程网关的集中审计，不能自动终止所有域会话。"], sources: ["rdp", "events"],
  },
  {
    id: "persistence", title: "启动项、任务与 WMI 驻留", group: "持久化与系统", summary: "删后重现、周期拉起或登录后再次运行。", keywords: "持久化 自启动 Run IFEO 计划任务 TaskCache WMI WMIC 无文件",
    first: "先记录触发条件、执行内容、账户和来源，再判断用途。合法运维软件也会使用这些机制。",
    scope: "当前用户、全局与其他用户的启动位置不同；启动项列表和任务查询都不是全覆盖。",
    evidence: ["Run/服务/任务的原始定义、路径和账户", "WMI 过滤器、命令或脚本动作及其关联", "任务文件、TaskCache 和创建/执行事件"],
    steps: [
      { title: "检查常见启动位置", text: "从启动项按来源排查，再核对 Run、登录外壳与映像劫持。记录键值原文，不能仅凭位置判定恶意。", actions: [module("startup"), registry("本机 Run"), registry("当前用户 Run"), registry("映像劫持 (IFEO)")] },
      { title: "交叉核查任务与 WMI", text: "将任务清单与磁盘定义、任务缓存和日志交叉对照；隐藏任务可能不出现在常规查询中。WMI 需同时核对条件、动作和关联。", actions: [command("tasks"), files("计划任务文件"), registry("任务缓存"), command("wmi-filter"), command("wmi-command"), command("wmi-script"), command("wmi-binding")] },
      { title: "处理完整触发链", text: "先保存定义和落地文件，确认业务依赖后逐项处置。只删载荷可能被其他任务重新下载，WMI 对象不能仅按显示名称批量删除。", actions: [files("全局启动目录"), logs("tasks", "任务事件"), logs("wmi", "WMI 活动")] },
      { title: "跨触发时机验证", text: "在获批的登录、任务触发或维护窗口后重新检查，核对程序是否再次出现。不要为验证自动重启真实主机。", actions: [module("startup"), module("processes"), logs("tasks", "任务事件")] },
    ],
    gaps: ["WMI 目前提供只读定义查询，尚无带备份、对象核对和恢复的删除流程。", "未离线解析任务缓存、其他用户 hive 或完整 Autoruns 持久化范围。"], sources: ["autoruns", "tasks", "wmi"],
  },
  {
    id: "powershell", title: "无文件与脚本执行", group: "恶意活动", summary: "编码脚本、异常解释器链或内存驻留线索。", keywords: "PowerShell 无文件 4103 4104 AMSI EncodedCommand 脚本",
    first: "将命令和脚本当作证据文本保留；不要粘贴执行可疑脚本或把解码结果直接运行。",
    scope: "脚本日志和 Sysmon 需要事先启用；PowerShell 能由其他程序承载，不能只查 powershell.exe。",
    evidence: ["进程链、完整命令行和脚本块日志", "脚本来源、配置文件、历史与网络记录", "日志未启用、权限不足或记录超限的缺口"],
    steps: [
      { title: "关联执行链", text: "核对解释器的父进程、参数、路径与连接。编码参数可能有正常用途，需结合脚本内容和来源。", actions: [module("processes"), module("network"), logs("process", "进程创建事件")] },
      { title: "寻找脚本记录", text: "读取已有 PowerShell 和 Sysmon 事件，对照 Profile 与历史目录；历史可能包含秘密，按授权范围留证。", actions: [logs("powershell", "PowerShell 事件"), logs("sysmon", "Sysmon 线索"), files("PowerShell 历史"), files("PowerShell 配置目录")] },
      { title: "处理触发与权限", text: "关联任务、WMI 或启动脚本后审阅处置；只结束解释器不能移除触发来源。内存分析应在获批的专门取证环境完成。", actions: [module("startup"), command("wmi-binding"), registry("PowerShell 日志策略")] },
      { title: "验证不再触发", text: "复核相关进程、脚本事件和防护状态。事后启用日志不会补回历史，日志为空时仍需记录证据缺口。", actions: [logs("powershell", "PowerShell 事件"), logs("defender", "防护告警"), module("baseline")] },
    ],
    gaps: ["未接入内存采集、AMSI 遥测或脚本沙箱；不会自动安装 Sysmon 来伪补历史。"], sources: ["powershell", "sysmon"],
  },
  {
    id: "credentials", title: "凭据窃取与高权账户", group: "身份与横向", summary: "敏感进程访问、管理员变化或凭据泄露告警。", keywords: "LSASS 凭据 提权 管理员 口令 令牌 SAM",
    first: "从可信管理终端协调身份响应，避免在疑似失陷主机上输入新的高权限凭据。",
    scope: "本地账户状态与策略不是凭据未泄露的证明；域凭据和应用秘密需要单独核查。",
    evidence: ["防护告警、已有敏感进程访问遥测", "账户和管理员组变化、特权登录时间", "可疑进程与转储文件的元数据及授权留证记录"],
    steps: [
      { title: "核对告警和身份", text: "查看防护记录与已有 Sysmon 线索，关联进程路径和账户变化。缺少相应审计时不能排除凭据访问。", actions: [logs("defender", "防护告警"), logs("sysmon", "Sysmon 线索"), module("accounts")] },
      { title: "追查策略与后续访问", text: "检查认证相关策略和异常登录，区分当前观察值与事件发生时的设置。策略较弱不等于已发生窃取。", actions: [registry("WDigest"), registry("LSA / 认证包"), logs("account", "账户变更"), logs("logon", "登录审计")] },
      { title: "协调凭据处置", text: "按受影响范围轮换账户、服务和应用秘密，处理存量会话及持久化。不要通过自动转储 LSASS 或读取口令来验证告警。", actions: [module("accounts"), module("startup"), command("services")] },
      { title: "验证身份恢复", text: "核对管理员成员和新的登录活动，并由身份管理员确认凭据及会话处置结果；本机基线通过不替代这一步。", actions: [module("accounts"), logs("logon", "登录审计"), module("baseline")] },
    ],
    gaps: ["未实现凭据提取、域口令轮换、令牌撤销或敏感进程内存读取。"], sources: ["credentials", "events", "sysmon"],
  },
  {
    id: "lateral", title: "SMB、WinRM 与横向移动", group: "身份与横向", summary: "管理共享、远程服务和异常远程管理活动。", keywords: "横向 SMB WinRM WMI PsExec 管理共享 445 5985 5986",
    first: "把来源主机、目标主机、账户和时间一起核对；远程管理端口或工具的存在不能直接证明攻击。",
    scope: "需要来源和目标双方日志、身份系统及网络侧记录；当前工作台一次只观察一个 Windows 会话。",
    evidence: ["连接两端、账户与登录时间", "新建服务或任务的定义、路径和父子进程", "来源与目标主机各自的原始事件"],
    steps: [
      { title: "确认访问链路", text: "从当前连接和登录事件确定疑似来源，再检查相关服务进程。不能按端口号自动归因。", actions: [module("network"), logs("logon", "登录审计"), command("sessions")] },
      { title: "核查远程执行痕迹", text: "对照服务、计划任务和 WMI 活动，查找与登录时间相邻的执行记录；记录正常运维解释。", actions: [logs("service", "服务事件"), logs("tasks", "任务事件"), logs("wmi", "WMI 活动"), command("services")] },
      { title: "协调两端遏制", text: "由网络和身份管理员处理已确认的访问路径与账户。处置前保留管理恢复通道，勿自动关闭所有 SMB 或 WinRM 服务。", actions: [registry("WinRM 服务策略"), command("firewall"), module("accounts")] },
      { title: "复核整个范围", text: "同时验证来源、目标与可能继续访问的主机，确认远程执行不再重现且合法管理恢复。单端连接消失不能作为全网清除结论。", actions: [module("network"), module("startup"), module("timeline")] },
    ],
    gaps: ["未实现全网扫描、跨主机时间线和远程访问自动封锁。"], sources: ["smb", "rdp", "events"],
  },
  {
    id: "webshell", title: "IIS 后门与异常站点文件", group: "恶意活动", summary: "异常脚本、可疑请求或 Web 进程拉起命令。", keywords: "IIS WebShell web shell ASP ASPX web.config w3wp 网站后门",
    first: "先确定真实站点路径、应用池与业务负责人。默认 inetpub 目录不存在不代表未部署站点。",
    scope: "适用于 IIS 线索排查；需结合站点配置、部署记录和代理/访问日志，不靠扩展名判断。",
    evidence: ["站点配置与应用池对应关系、部署基准", "异常请求、响应与相邻文件修改时间", "脚本原始文件、摘要和 w3wp 子进程"],
    steps: [
      { title: "确认站点及进程", text: "从 IIS 配置和进程确认实际内容目录，再浏览目标路径。对照 Web 进程异常子进程与网络连接。", actions: [files("IIS 配置"), files("IIS 默认站点"), module("processes")] },
      { title: "关联请求与文件", text: "核对访问日志、上传入口和最近部署，保存可疑脚本的原始内容与摘要；不向后门发送测试指令。", actions: [files("IIS 日志"), logs("application", "应用事件"), module("timeline")] },
      { title: "处理入口和权限", text: "与业务方确定维护或隔离范围，留证后从可信版本恢复文件并修复入口、账户和可写权限。只删除一个脚本容易遗漏其他后门。", actions: [module("accounts"), module("startup"), command("services")] },
      { title: "验证站点恢复", text: "核对文件与发布基准，在业务方认可的范围检查页面和关键事务，并复查异常请求、进程及重新落地文件。", actions: [files("IIS 日志"), module("processes"), module("network")] },
    ],
    gaps: ["未实现 IIS 实例自动发现、全站扫描、发布基准比对和应用业务测试。"], sources: ["webshell", "sysmon"],
  },
  {
    id: "drivers", title: "驱动异常与删除受阻", group: "持久化与系统", summary: "拒绝访问、文件占用、异常驱动或过滤器。", keywords: "驱动 服务 文件删不掉 提权 SYSTEM TrustedInstaller ACL 占用 BYOVD rootkit",
    first: "在文件详情中先做权限与占用排查，区分 ACL、进程占用、服务和驱动。不要默认夺取系统目录所有权或关闭保护。",
    scope: "普通用户和管理员的可见范围不同；有效签名不能证明驱动无漏洞，也不能证明其加载用途可信。",
    evidence: ["文件所有者、ACL、属性、摘要和具体错误", "同路径进程/服务/驱动的定义与状态", "签名、版本、发布来源和已有安全告警"],
    steps: [
      { title: "确认拒绝原因", text: "从文件排查选择目标，使用「权限与占用排查」并保留错误原文。同路径关联只是线索，不能找出所有正在占用文件的程序。", actions: [files("驱动文件"), command("identity"), command("services")] },
      { title: "核对驱动与过滤器", text: "交叉检查驱动服务、路径与文件系统过滤器，结合厂商资料和已有防护记录判断；状态为运行不代表恶意。", actions: [command("drivers"), command("driverquery"), command("filters"), command("filter-instances"), registry("服务与驱动注册")] },
      { title: "选择可恢复的处置", text: "核实启动依赖和恢复介质后安排受控维护。强行解除文件占用或卸载驱动可能导致崩溃；删除磁盘文件不会卸载内存中的驱动。", actions: [command("service-drivers"), files("驱动包仓库"), logs("service", "服务与系统事件")] },
      { title: "独立验证加载状态", text: "在获批维护后重新检查驱动、服务、文件与业务设备状态。必要时用可信离线环境复核，并验证恢复路径。", actions: [command("drivers"), command("filters"), logs("system", "系统事件")] },
    ],
    gaps: ["没有绕过系统保护、自动提权、强行解除文件占用、卸载驱动或重启删除能力。", "未实现完整文件占用来源查询、驱动签名/漏洞库校验与离线内核取证。"], sources: ["handle", "drivers", "sysmon"],
  },
  {
    id: "evasion", title: "防护关闭与日志异常", group: "持久化与系统", summary: "防护变更、审计缺失、日志清除或采集失败。", keywords: "Defender 杀软 防护 日志清除 1102 104 auditpol 审计",
    first: "记录发生时间与权限错误，不把日志为空显示为无风险。先与正常维护、第三方防护及日志保留策略核对。",
    scope: "Defender 被动模式可能有正常原因；本机日志也可能已被攻击者改变，需要外部记录补证。",
    evidence: ["清除与配置变更事件、审计策略和防护状态", "日志读取错误、通道状态及可用时间范围", "集中日志或 EDR 中保留的独立记录"],
    steps: [
      { title: "核查异常和缺口", text: "查看清日志与防护事件，记录通道不可用、权限不足及截断。确定异常发生前后仍可获得哪些记录。", actions: [logs("clear-log", "日志清除事件"), logs("defender", "防护变更事件"), logs("security", "安全日志")] },
      { title: "比对当前配置", text: "查询审计、防护运行状态及策略，结合近期变更记录确认来源。当前配置正常不能说明过去一直正常。", actions: [command("audit"), command("defender"), registry("Defender 策略"), module("baseline")] },
      { title: "恢复经确认的防护", text: "与安全管理员核对策略管理来源和兼容性，再通过受控变更恢复防护与日志；不要反复覆盖由域策略管理的设置。", actions: [module("baseline"), command("services")] },
      { title: "验证生效与新日志", text: "检查运行状态，并以获批的无害事件验证日志链路和集中接收。历史被清除的缺口必须保留，不能靠重新启用消除。", actions: [command("defender"), command("audit"), logs("system", "系统事件")] },
    ],
    gaps: ["没有防篡改绕过、自动开启审计或 EDR/集中日志配置接口。"], sources: ["events", "ransomware", "sysmon"],
  },
  {
    id: "exfil", title: "数据外传与代理劫持", group: "恶意活动", summary: "异常传输、可疑归档文件、代理或转发变化。", keywords: "外传 泄露 exfil 代理 隧道 portproxy hosts DNS 压缩",
    first: "先记录连接与程序，保全网络侧日志。外连或压缩文件本身不足以证明敏感数据已泄露。",
    scope: "连接快照没有传输内容和累计字节；需要应用、代理、网关或流量证据共同确定范围。",
    evidence: ["异常连接、相关程序、代理与转发配置", "授权范围内的暂存文件元数据和访问记录", "网络侧传输时间、数据量及业务系统审计"],
    steps: [
      { title: "识别可疑通信", text: "核对进程、连接和 DNS 缓存，调查合法同步、备份或远控工具是否被滥用。缓存不是完整访问历史。", actions: [module("network"), module("processes"), command("dns")] },
      { title: "检查代理与暂存", text: "核对 WinHTTP、当前用户代理、端口转发和 hosts，调查临时目录中的异常归档；敏感内容按授权范围采集。", actions: [command("proxy"), command("portproxy"), registry("当前用户代理"), files("网络配置 / hosts"), files("用户临时目录")] },
      { title: "限制已确认的外传", text: "协调网络与身份管理员限制已确认的路径和账户，保留正常业务及管理恢复途径；同时查明数据来源和访问权限。", actions: [command("firewall"), module("accounts"), module("startup")] },
      { title: "核实范围和后续通信", text: "将主机观察与外部传输记录比对，记录已确认、可能涉及和无法判断的数据范围；重新采集不能替代网络侧复核。", actions: [module("network"), module("timeline"), command("proxy")] },
    ],
    gaps: ["未实现流量采集、DLP、数据内容识别或完整外传量统计。"], sources: ["exfil", "miner", "microsoft"],
  },
  {
    id: "domain", title: "域控影响与专项升级", group: "身份与横向", summary: "域管理员、域控制器或集中身份服务疑似失陷。", keywords: "AD Active Directory 域控 域管理员 林恢复 krbtgt DCSync",
    first: "启动域级响应，确认可信管理通道和恢复负责人。不要把单机清理流程直接套用于域控。",
    scope: "域、林、信任关系、复制与备份必须联合分析；本地账户列表无法代表域目录状态。",
    evidence: ["受影响域/林、域控与管理员范围、事件时间", "集中身份审计、复制/备份记录与可信恢复材料", "仍可信的管理路径及尚未核实的主机"],
    steps: [
      { title: "确认角色与影响", text: "核对主机系统信息与域归属，将域管理员异常和多主机相似事件升级给身份管理员；当前界面不能判断整个域是否可信。", actions: [module("overview"), logs("account", "账户事件"), logs("logon", "登录审计")] },
      { title: "保全并扩展调查", text: "保留现有安全日志、进程与网络线索，由域管理员补齐目录、复制及集中审计；标明每个来源和权限缺口。", actions: [logs("security", "安全日志"), module("processes"), module("network"), command("audit")] },
      { title: "按环境制定恢复", text: "根据域和林拓扑、备份及可信状态制定隔离与恢复计划。账户密钥轮换、域控恢复与重建应走专项确认和演练。", actions: [] },
      { title: "验证目录与业务", text: "由身份团队验证复制、认证、信任与应用依赖，并持续监测高权访问。单台域控启动或本机基线通过都不是林恢复完成。", actions: [logs("logon", "登录审计"), module("timeline")] },
    ],
    gaps: ["当前没有 AD 目录调查、域/林恢复、krbtgt 轮换与复制健康验证能力；本方案用于分流和保全。"], sources: ["forest", "credentials", "events"],
  },
];

export const PLAYBOOK_PHASES = ["发现与留证", "关联与定界", "遏制与修复", "复核与恢复"] as const;

export function playbookActionLabel(action: PlaybookAction): string {
  switch (action.kind) {
    case "module": return `打开${moduleLabel(action.tab)}`;
    case "files": return `目录 · ${action.preset}`;
    case "registry": return `注册表 · ${action.preset}`;
    case "logs": return `读取${action.label}`;
    case "command": return `准备查询 · ${WINDOWS_COMMAND_PRESETS.find((preset) => preset.id === action.preset)?.label ?? "预设不可用"}`;
  }
}

export function findPlaybooks(query: string): readonly WindowsPlaybook[] {
  const words = query.trim().toLocaleLowerCase().split(/\s+/u).filter(Boolean);
  return WINDOWS_PLAYBOOKS.filter((plan) => {
    const content = [plan.title, plan.group, plan.summary, plan.keywords, ...plan.steps.map((step) => step.text)].join(" ").toLocaleLowerCase();
    return words.every((word) => content.includes(word));
  });
}

export function playbookText(plan: WindowsPlaybook): string {
  return [
    `LovelyHawk Windows 响应方案 · ${plan.title}`, `资料整理日期：${PLAYBOOK_REVIEW_DATE}`,
    "此内容是调查指导，不是已采集证据或处置结果。", `适用范围：${plan.scope}`, `优先行动：${plan.first}`,
    "需要保留的证据：", ...plan.evidence.map((text) => `- ${text}`),
    ...plan.steps.flatMap((step, index) => [`\n${index + 1}. ${PLAYBOOK_PHASES[index]} · ${step.title}`, step.text, ...step.actions.map((action) => `  ${playbookActionLabel(action)}`)]),
    "\n当前能力缺口：", ...plan.gaps.map((text) => `- ${text}`),
    "\n日志查询默认最近 7 天、每通道最多 200 条；文件预设中的用户变量指采集账户。缺失、错误与截断须单独记录。",
    "真实目标上的变更须逐次核对具体对象、影响、备份和恢复条件后确认。处置后仍需独立复核和业务确认。",
    "\n参考资料（产品流程综合整理，并非原文转录）：", ...plan.sources.map((key) => `${PLAYBOOK_SOURCES[key].title}\n${PLAYBOOK_SOURCES[key].url}`),
  ].join("\n");
}
