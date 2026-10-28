# Windows 常见事件响应方案

资料整理日期：2026-10-26。当前实现是在 Windows 应急工作台新增“响应方案”入口，将常见事件的调查步骤连接到已有排查能力。页面可以离线查阅，内容随应用分发，不请求在线资源。

这些步骤是结合下列原始资料与 LovelyHawk 现有能力整理的产品流程，不是原文转录、合规认证或自动化恶意判定。NIST 使用 2025 年发布的 SP 800-61 Rev. 3；ATT&CK 用于解释线索，不能仅凭命中技术名称判定入侵。资料和具体 Windows 版本仍须持续复核。

## 已融合的 14 类方案

每个方案都有优先行动、适用范围、证据清单、四个阶段、实际入口、未实现能力及来源。四个阶段为发现与留证、关联与定界、遏制与修复、复核与恢复；阅读或执行某个查询不会被计为“事件已处置”。

| 场景 | 已连接的调查入口 | 关键复核与当前限制 |
| --- | --- | --- |
| 初步排查与现场保全 | 主机、权限、进程、网络、会话、时间线 | 记录采集来源、时间与缺口；不把分时快照当作完整现场 |
| 勒索加密与恢复破坏 | 进程/外连、RDP、防护、服务、落地文件、账户 | 联合检查入口、凭据、备份和复发；未接入 EDR 隔离或备份系统 |
| 挖矿与资源异常 | 进程参数、连接、任务、服务、ProgramData/临时目录 | 与业务性能及授权用途核对；未提供持续 CPU/GPU 监控或矿池判定 |
| 木马外联与远控 | 网络到进程、DNS、下载/用户数据、启动项、Sysmon | 查证软件来源与重新连接；未接入信誉库、流量或远控审批系统 |
| 异常登录与暴力尝试 | 登录失败/锁定、登录审计、RDP 会话、账户变更、基线 | 关联账户/来源/登录类型/时间；本地账户不能代表域身份与存量会话 |
| 启动项、任务与 WMI 驻留 | Run/IFEO、任务文件、TaskCache、WMI 条件/动作/关联、任务/WMI 日志 | 常规任务查询可能漏掉隐藏任务；WMI 删除和恢复尚未接通 |
| 无文件与脚本执行 | 进程链、PowerShell/Sysmon、历史/Profile、WMI | 保留原文且不执行可疑脚本；未接入内存、AMSI 或沙箱 |
| 凭据窃取与高权账户 | 防护/Sysmon、账户、WDigest/LSA、登录和服务 | 由可信管理终端协调凭据处置；不转储 LSASS，不读取口令 |
| SMB、WinRM 与横向移动 | 网络、登录、服务/任务/WMI、WinRM/防火墙 | 来源和目标双方核查；未提供全网扫描、跨主机时间线或自动封锁 |
| IIS 后门与异常站点文件 | IIS 配置/默认目录/日志、进程、应用事件、时间线 | 真实站点路径需核对；不向后门发送测试指令，不以默认目录代替实例发现 |
| 驱动异常与删除受阻 | 文件权限诊断、服务/驱动、过滤器、驱动目录、系统事件 | 签名不等于可信、删文件不等于卸载；完整占用、签名和离线内核核查待实现 |
| 防护关闭与日志异常 | 清日志事件、防护、审计状态、策略、基线 | 正常配置不能证明过去正常，事后开日志不能补回历史 |
| 数据外传与代理劫持 | 进程/网络/DNS、WinHTTP/用户代理、portproxy、hosts/暂存目录 | 网络侧与应用审计共同确认范围；无数据内容或累计外传量判定 |
| 域控影响与专项升级 | 主机/域信息、账户/登录/安全日志、进程、网络、审计 | 仅分流和保全；未实现 AD 调查、林恢复、密钥轮换或复制健康验证 |

## 操作接线与状态

- 左侧按症状、工具、事件 ID 和场景关键词搜索；右侧展示完整方案。跨模块返回保留方案和搜索，焦点返回当前场景。方案不包含目标结果，因此目标切换后仍可保留阅读位置与选择。
- 模块按钮打开现有结果，首次进入遵守已有自动采集规则。目录、注册表和日志按钮分别解析固定目录预设、固定注册表预设及固定日志类别，再调用现有目标绑定采集路径。目录和注册表引用有编译期类型检查，全部引用有回归检查。
- 只读命令推荐通过预设 ID 进入命令检查台，先显示建议，保留现有草稿。用户可保留草稿或明确替换；替换也不会执行。之后仍须确认具体目标与完整命令，原有会话变化拒绝规则不变。
- 断连或采集忙时禁用目标查询；离线仍能读方案、复制方案或准备命令。错误、旧快照、采集进度继续使用现有反馈，不被方案页面解释成安全结论。
- “复制当前方案”包含适用范围、四阶段步骤、证据清单、能力缺口和来源 URL，并标明这是指导材料，不是已经采集的证据或处置结果。
- 来源 URL 以文本展示并支持复制；不让页面任意打开外链，也没有在线脚本、图片或第三方运行依赖。

不新增远程 API、通用权限或自动处置入口。方案中的处置建议不会执行删除、停服务、隔离、修改策略、重启或提权。用户仍须进入相应功能审阅对象和本次操作；现有功能自身的备份、恢复及验证边界见 [排查预设](WINDOWS_IR_PRESETS.md) 与 [基线变更](WINDOWS_BASELINE_CHANGES.md)。

日志预设仍默认最近 7 天、每通道最多 200 条，受输出字节和权限限制；不代替完整 EVTX 导出。环境变量和 HKCU 指采集账户，默认站点/用户路径不代表已识别实际部署。采集也可能影响访问时间或资源占用，重要现场需另行制定采集顺序和授权范围。

实现：`ui/src/renderer/win-ir-playbooks.ts`（资料和固定入口）、`WinIrPlaybooks.tsx`（交互）、`WindowsIncidentPage.tsx`（现有模块接线）、`WinIrConsole.tsx`（保留草稿的查询推荐）。本轮没有改动 Windows core、后端方法表、宿主权限或基线规则。

## 原始资料

以下 18 个页面本轮通过网络读取。产品文案是综合整理及适配说明；未经测试的技术和操作不因被引用而成为已支持能力。

| 资料 | 用途 |
| --- | --- |
| [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) | 响应与恢复流程框架 |
| [Microsoft Incident response playbooks](https://learn.microsoft.com/en-us/security/operations/incident-response-playbooks) | 前提、调查步骤和验证思路 |
| [Microsoft DART 勒索响应](https://learn.microsoft.com/en-us/security/ransomware/incident-response-playbook-dart-ransomware-approach) | 人工操作勒索的身份、工具滥用与恢复破坏 |
| [Microsoft Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns) | 启动位置覆盖与多来源核查；未集成该工具 |
| [Microsoft Handle](https://learn.microsoft.com/en-us/sysinternals/downloads/handle) | 文件打开引用与强行关闭的影响；未集成该工具 |
| [Microsoft 驱动阻止规则](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules) | 易受攻击驱动、兼容影响与列表局限 |
| [Microsoft AD 林恢复](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-guide) | 域级专项响应与恢复前提 |
| [Microsoft Windows 安全事件参考](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor) | 登录、身份与审计变化的关联线索 |
| [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) | 既有进程/网络/驱动等遥测与配置前提；不自动安装 |
| [MITRE T1496](https://attack.mitre.org/techniques/T1496/) | 资源劫持 |
| [MITRE T1003.001](https://attack.mitre.org/techniques/T1003/001/) | LSASS 凭据访问的线索与身份影响 |
| [MITRE T1021.001](https://attack.mitre.org/techniques/T1021/001/) | 远程桌面访问 |
| [MITRE T1021.002](https://attack.mitre.org/techniques/T1021/002/) | SMB 与管理共享 |
| [MITRE T1053.005](https://attack.mitre.org/techniques/T1053/005/) | 任务持久化及隐藏任务线索 |
| [MITRE T1546.003](https://attack.mitre.org/techniques/T1546/003/) | WMI 永久事件条件、动作及关联 |
| [MITRE T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell 执行与非独立解释器承载 |
| [MITRE T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Web Shell 与站点调查 |
| [MITRE T1041](https://attack.mitre.org/techniques/T1041/) | 控制通道中的数据外传 |

也检索了 [CISA StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide)，本次直接读取网页及官方 PDF 均返回 HTTP 403。未把不可访问的完整内容作为已核对来源，也未计入以上 18 个已读取页面；保留为后续资料复核项。

## 后续能力按可验证流程补齐

1. 完整 EVTX 导出与分段留证：采集范围、读取失败、通道元数据、字节摘要与大文件保存，覆盖真实 Windows 目标。
2. 驱动与文件访问调查：签名链、文件版本、实际加载身份、完整占用来源，先只读，再设计带恢复条件的受控处置。
3. 任务/WMI 与多用户持久化：完整定义、对象并发核对、备份和恢复，补齐常规查询看不到的情况及其他用户 hive。
4. 独立的遏制与恢复：明确网络隔离后的管理恢复路径、对象身份、前后证据、业务复核；不通过关闭防护或危险通用命令绕过实现。
5. 内存/磁盘取证、EDR/备份及 AD：分别明确工具、许可、权限、敏感证据范围和真实环境验收，不以已有界面入口宣称完成。

这些是持续扩展目标，14 个方案不代表所有攻击场景、系统版本或自动处置能力已覆盖。

## 2026-10-26 验证记录

| 环境与检查 | 实际结果与证据 |
| --- | --- |
| UI 类型、单元测试和生产资源构建 | `pnpm ui:check` 通过，139 个测试文件 / 1,163 项；`target/windows-playbooks-ui-final.log` |
| Windows x64 调试宿主 | `cargo build --locked --package lovelyhawk-desktop --bin lovelyhawk` 通过；`target/windows-playbooks-build-final.log` |
| 原生 WebView2 Windows 工作区 | `node ui/scripts/probe-windows-workspace.mjs` **128/128**，控制台错误 0、正常退出；`target/desktop-debug/windows-workspace-6b871ef5-959d-4947-9e88-5c572a5e9fc9/evidence/` |
| 原生 WebView2 整应用回归 | `node ui/scripts/run-debug-smoke.mjs` **92/92**，控制台/网络错误 0、正常退出；`target/desktop-debug/8ae60df0-be1c-4c78-8a66-432d6ee648b9/evidence/` |
| 源码门禁 | `pnpm release:source-gate` 通过，221 个页面模块、37 个样式/资源文件；`target/windows-playbooks-source-gate-final.log` |

Windows 工作区验收包含原生宿主的未连接页面，以及明确标识的已连接合成数据。新断言核对离线可读、14 个场景、搜索/空结果、目录和 TaskCache 精确预设、WMI 远程日志类别、返回焦点与搜索保留、草稿保留/替换/执行确认、采集等待/失败、目标切换、断连、960 与 720 宽度及来源复制。保留此前全部 107 项断言，新增 21 项；修改导航数量断言反映新增入口，没有取消原有确认前零执行检查。

人工检查 `24-playbooks-iis-light.png`、`25-playbooks-drivers-narrow-dark.png` 和 `26-playbooks-small-dark.png`。初次 UI 检查的 2 项失败（界面用语和滚动列清单）保留在 `target/windows-playbooks-ui.log`，修正用户文案并为新滚动列增加防压缩规则与清单后通过。首次原生验收 **121/122** 的记录保留在 `target/desktop-debug/windows-workspace-236f20be-1f21-4789-b262-e0a424484af5/evidence/`；失败探针误选了隐藏基线页面的查询范围文字，改为核对可见日志页及请求类别。同时截图发现搜索框被纵向拉伸，修复后增加高度回归。后续 126/126 后补测 720 窗口与来源复制，最终 128/128。

最终调试程序 `target/debug/lovelyhawk.exe`，SHA256 `8edc82e1135c177cd22bd0e748da13a695da5d9983130669e34b98886500e18f`；汇总 `target/windows-playbooks-verification-20261026.json`。沿用原有大于 500 kB 共享资源块构建提示，没有调整阈值。

本轮没有向真实 Windows 目标执行处置，也没有新增远程采集协议。未重跑未修改的 Rust 全包测试或便携包发布链；未发布正式包。以上界面合成数据不能代替 Windows Server、RDP、域控、管理员正向修补或实际攻击样例的验证，相关矩阵继续待验证。
