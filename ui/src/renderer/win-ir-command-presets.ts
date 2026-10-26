export interface WindowsCommandPreset { id: string; group: string; label: string; hint: string; command: string }
const ps = (script: string) => `powershell.exe -NoLogo -NoProfile -NonInteractive -Command "${script}"`;
const cim = (name: string, fields: string, namespace = "root/cimv2") => ps(`$ErrorActionPreference='Stop'; Get-CimInstance -Namespace '${namespace}' -ClassName '${name}' -OperationTimeoutSec 15 | Select-Object -First 300 ${fields} | Format-List; Write-Output '仅显示前 300 项；无输出或拒绝访问不能证明不存在风险。'`);

/** Choosing a recipe only fills the editor. The existing target-bound confirmation still executes it. */
export const WINDOWS_COMMAND_PRESETS: readonly WindowsCommandPreset[] = [
  { id: "identity", group: "主机与账户", label: "当前权限与令牌", hint: "账户、组和特权状态；不会提权", command: "whoami /all" },
  { id: "os", group: "主机与账户", label: "系统版本与启动时间", hint: "CIM / Win32_OperatingSystem", command: cim("Win32_OperatingSystem", "Caption,Version,BuildNumber,OSArchitecture,LastBootUpTime") },
  { id: "users", group: "主机与账户", label: "本地账户", hint: "CIM；不读取口令", command: ps("Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' -OperationTimeoutSec 15 | Select-Object -First 300 Name,SID,Disabled,Lockout,PasswordRequired | Format-List") },
  { id: "sessions", group: "主机与账户", label: "登录会话", hint: "查询终端服务会话，可能需要额外权限", command: "quser" },
  { id: "processes", group: "进程与网络", label: "进程与完整命令行", hint: "CIM；命令行可能含敏感参数", command: cim("Win32_Process", "ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate") },
  { id: "connections", group: "进程与网络", label: "TCP/UDP 与 PID", hint: "包括监听与当前连接，需结合进程身份", command: "netstat -ano" },
  { id: "dns", group: "进程与网络", label: "DNS 缓存", hint: "只读缓存；不能作为完整访问历史", command: "ipconfig /displaydns" },
  { id: "routes", group: "进程与网络", label: "路由表", hint: "核查异常网关和路由", command: "route print" },
  { id: "proxy", group: "进程与网络", label: "WinHTTP 代理", hint: "不涵盖所有用户与应用代理", command: "netsh winhttp show proxy" },
  { id: "portproxy", group: "进程与网络", label: "端口转发", hint: "只读查询 portproxy 配置", command: "netsh interface portproxy show all" },
  { id: "services", group: "服务与驱动", label: "服务路径、权限账户与 PID", hint: "CIM；核对 StartName、PathName 和 ProcessId", command: cim("Win32_Service", "Name,DisplayName,State,StartMode,StartName,ProcessId,PathName") },
  { id: "drivers", group: "服务与驱动", label: "内核驱动服务", hint: "CIM；包含启动方式与路径，不停止或卸载", command: cim("Win32_SystemDriver", "Name,DisplayName,State,StartMode,ServiceType,PathName") },
  { id: "driverquery", group: "服务与驱动", label: "驱动清单", hint: "系统驱动查询；来源与签名需进一步核查", command: "driverquery /v /fo csv" },
  { id: "filters", group: "服务与驱动", label: "文件系统过滤驱动", hint: "fltmc filters；通常需要管理员权限，不自动提升", command: "fltmc filters" },
  { id: "filter-instances", group: "服务与驱动", label: "过滤驱动挂载实例", hint: "帮助判断过滤驱动与卷的关联，不卸载实例", command: "fltmc instances" },
  { id: "service-drivers", group: "服务与驱动", label: "服务管理器驱动状态", hint: "sc.exe query；输出不足时会给出续查索引", command: "sc.exe query type= driver state= all" },
  { id: "tasks", group: "持久化与 WMI", label: "计划任务清单", hint: "详细任务、触发方式与运行账户", command: "schtasks /query /fo csv /v" },
  { id: "wmi-filter", group: "持久化与 WMI", label: "WMI 永久事件过滤器", hint: "root/subscription；合法管理软件也会使用", command: cim("__EventFilter", "Name,EventNamespace,QueryLanguage,Query", "root/subscription") },
  { id: "wmi-command", group: "持久化与 WMI", label: "WMI 命令触发动作", hint: "只读取定义，不执行触发动作命令", command: cim("CommandLineEventConsumer", "Name,ExecutablePath,CommandLineTemplate", "root/subscription") },
  { id: "wmi-script", group: "持久化与 WMI", label: "WMI 脚本触发动作", hint: "仅查看脚本引擎与来源文件；不执行脚本", command: cim("ActiveScriptEventConsumer", "Name,ScriptingEngine,ScriptFileName", "root/subscription") },
  { id: "wmi-binding", group: "持久化与 WMI", label: "WMI 过滤器与动作关联", hint: "需结合事件条件、触发动作和授权用途判断", command: cim("__FilterToConsumerBinding", "Filter,Consumer", "root/subscription") },
  { id: "audit", group: "日志与防护", label: "审计子类别状态", hint: "auditpol，只读；可能需要管理员权限", command: "auditpol /get /category:* /r" },
  { id: "defender", group: "日志与防护", label: "Defender 运行状态", hint: "未安装、被动模式或权限不足分别核实", command: ps("Get-MpComputerStatus | Select-Object AMRunningMode,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated,IsTamperProtected | Format-List") },
  { id: "firewall", group: "日志与防护", label: "防火墙生效配置", hint: "ActiveStore，不修改防火墙", command: ps("Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,LogFileName | Format-List") },
  { id: "wmic-process", group: "旧版 WMIC", label: "WMIC 进程", hint: "仅供已安装 WMIC 的旧系统；新版使用 CIM 进程查询", command: "wmic process get ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine /format:csv" },
  { id: "wmic-service", group: "旧版 WMIC", label: "WMIC 服务", hint: "命令缺失请改用 CIM；不自动安装组件", command: "wmic service get Name,State,StartMode,StartName,ProcessId,PathName /format:csv" },
  { id: "wmic-driver", group: "旧版 WMIC", label: "WMIC 驱动", hint: "命令缺失请改用 CIM 内核驱动服务查询", command: "wmic sysdriver get Name,State,StartMode,ServiceType,PathName /format:csv" },
  { id: "wmic-startup", group: "旧版 WMIC", label: "WMIC 启动项", hint: "Win32_StartupCommand 不包含所有持久化机制", command: "wmic startup get Caption,Command,Location,User /format:csv" },
];
