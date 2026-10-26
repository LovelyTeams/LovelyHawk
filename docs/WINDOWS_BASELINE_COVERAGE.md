# Windows 基线覆盖与验证

后续增量（2026-10-26）：69 项检测数量不变，19 项既有注册表规则已接通带备份的一键配置，原有直接修复已移除；范围与未验证项见 [配置与恢复](WINDOWS_BASELINE_CHANGES.md)。本文下方测试计数为 `ffb5970` 的历史检测扩展记录。

更新：2026-10-26。目录由 32 项扩展到 **69 项、15 类**，本轮新增 37 项。它是按明确来源进行的只读核查目录，不是完整的等保、CIS 或微软安全基线认证。单项通过只适用于该项观察范围。

## 已接线的目录

| 类别 | 项数 | 当前范围 |
| --- | ---: | --- |
| 口令与锁定 | 6 | 本地 SAM 最短长度、历史、最短使用期、锁定次数、持续时间、计数重置窗口 |
| 高级审计 | 8 | 登录、锁定、特殊登录、进程创建、审计策略变更、用户管理、安全组管理、凭据验证 |
| 日志留存 | 6 | Security / System / Application / PowerShell Operational 通道开关，Security / System 容量 |
| 日志审计 | 4 | PowerShell 脚本块、模块、转录开关，4688 命令行策略 |
| 防火墙 | 4 | 三种配置文件的启用状态、有效默认入站动作、丢弃连接记录、日志容量 |
| 防病毒 | 6 | Defender 实时、防篡改、防病毒、行为、文件访问保护及安全情报时效 |
| 虚拟化保护 | 3 | VBS、Credential Guard、内存完整性的运行状态 |
| 权限控制 | 8 | UAC 主开关、提示和安全桌面、内置管理员、标准用户、远程令牌过滤、两处 Installer 策略 |
| 账户安全 | 6 | Guest、自动登录、空口令限制、匿名共享/SAM 枚举、Everyone 匿名权限 |
| 凭据保护 | 4 | WDigest、LSA 保护配置、LM/NTLM 级别、LM 哈希策略 |
| SMB | 4 | 服务端 SMBv1、客户端/服务端签名、不安全来宾 |
| 远程管理 | 5 | WinRM 服务端/客户端 Basic 与非加密策略、远程注册表启动方式 |
| 远程桌面 | 3 | NLA、加密级别、TLS 安全层配置 |
| 名称解析 | 1 | LLMNR 策略，不包含 mDNS、NetBIOS 或 DNS 服务配置 |
| 执行控制 | 1 | 驱动器自动运行策略 |

原有 32 项及此前验证记录保留在 [Windows 应急工作台](WINDOWS_INCIDENT_WORKBENCH.md)。规则定义在 `windows_incident.rs` 与其子模块 `windows_incident/baseline.rs`；采集脚本在 `lovelyhawk-win-dvc/src/queries/baseline*.ps1`，沿既有 core → backend → shared/host → 页面路径执行。

## 来源、判定和限制

### 本地口令和锁定

通过 `NetUserModalsGet(NULL, 0/3)` 读取固定字段，不解析本地化的 `net accounts` 文本，不导出口令或 SAM 秘密。使用操作系统 `ProductType` 核对角色：工作站和成员服务器适用于本地账户；域控制器的这六项显示“不适用”，域口令与细粒度策略须另外核查。角色不明显示“无法判断”。

本工具关注阈值为长度至少 14 字符、历史至少 24 次、最短使用期至少 1 天；锁定次数 1–10 次、持续时间及计数窗口至少 15 分钟。它们需要结合组织要求、紧急改密和锁定拒绝服务风险评估，不读取现有口令强度，也不强制改密。锁定次数为 0 时，持续时间和计数窗口不生效，显示“不适用”且不算通过。有限持续时间不能短于计数窗口；原生无限持续时间单独处理，不能混用策略界面的分钟数与 API 秒数。

### 高级审计与日志

按八个固定子类别 GUID 调用 `AuditQuerySystemPolicy`，核对返回 GUID 后读取成功/失败位，不调用设置 API、调整特权或自动提权。0/4 表示没有成功/失败审计，成功位不能代替失败位。权限拒绝、错误位组合和缺失均不算通过。系统审计策略不包含逐用户排除，也不能证明事件已写入或成功转发。

`Get-WinEvent -ListLog` 只读取四个固定通道的配置，不读取事件正文。Security 容量 192 MiB、System 32 MiB 是本工具的复核建议；容量不代表留存天数、覆盖模式或集中归档有效。4688 命令行策略和进程创建审计分别检查；开启命令行记录可能把秘密写入安全日志，须另行评估日志访问控制。

### 防火墙、防病毒与虚拟化保护

防火墙来源是 `Get-NetFirewallProfile -PolicyStore ActiveStore`，必须取得 Domain、Private、Public 三个不同对象及有效枚举。`NotConfigured`、重复或缺失不推断成默认安全值。默认入站 Block 不代表所有端口被阻止，日志容量至少 16384 KiB 也不代表已产生记录，启用状态及丢弃记录单独核对。

新增 Defender 检查同时观察 `AMRunningMode`：Normal 才按主防护评估，被动/辅助模式或未运行显示需复核，未知模式显示无法判断；不能由此否定其他防病毒产品。安全情报超过 7 天为本工具复核阈值；未知年龄不当作刚更新。仍需另行检查排除项、ASR、组织管理策略与实际防护。

VBS 使用 `Win32_DeviceGuard.VirtualizationBasedSecurityStatus`，Credential Guard / 内存完整性使用 `SecurityServicesRunning`，不以进程存在代替运行状态。未运行时提示复核版本、硬件和驱动条件；缺少类或权限时保留未知。本轮不更改启动配置、不重启。

### 页面和执行边界

- 五类结果分别统计和筛选：通过、不通过、需复核、无法判断、不适用；“检查目录”包含全部 69 项，不冒充实际成功执行的数量。
- 支持按类别、名称、配置值、规则编号和说明搜索；详情保留来源、适用条件及建议。不适用项不进入概况风险列表，未知结果不会让概况显示全绿。
- 新增 37 项均为只读核查，不提供未实现的快速修复按钮。已有修复只在 core 明确支持且结果为不通过/需复核时显示；未知和不适用不授予修复能力。
- 原生请求升级为 `baseline-v3`。旧采集端不识别时走已有完整 PowerShell 回退，不能把旧版 32 项响应冒充完成新采集。真实旧 Agent / RDP 回传尚未验证。
- DTO 对五种数量、总数、唯一规则编号及修复能力与状态组合进行一致性校验。目标会话、取消、输出上限和超时沿用现有边界。
- 查询不改写策略或读取口令，但 PowerShell/.NET 编译可能产生临时文件，执行可能产生系统审计记录；页面提供采集影响说明。受限语言、缺少编译能力或系统接口时保留未知，不调整目标环境。

## 验证与兼容记录

本轮证据目录：`target/windows-baseline-1793017646231/`。目录内 `environment.json` 记录采集时间、版本与权限结果，`local-read.json` 保存实际只读输出，`catalog.json` 保存本次规则目录。该目录是测试证据，不是产品案件归档。

| 环境 / 能力 | 日期 | 状态 | 证据与范围 |
| --- | --- | --- | --- |
| Windows 11 专业版 10.0.26200 / x64，本机 PowerShell 5.1，SAM 与系统配置只读查询 | 2026-10-26 | 已验证（本机范围） | `environment.json`、`local-read.json`；未修改策略、未连接 RDP |
| 同一主机，审计与 Security 日志读取权限缺口 | 2026-10-26 | 已验证（拒绝路径） | 两处均返回 permission-denied，核心结果保持 unknown；未提权 |
| 规则边界、审计位组合、域控制器不适用、锁定依赖、Defender 模式、数组及枚举异常 | 2026-10-26 | 已验证（合成输入） | `core-tests.log`；不代表相应操作系统实际读取成功 |
| Windows x64 Tauri 调试宿主，真实 WebView2 界面，已连接数据为合成输入 | 2026-10-26 | 已验证（界面范围） | 工作区 100/100、整应用 95/95，错误级控制台为 0；详细证据见 [本轮实际检查](WINDOWS_INCIDENT_WORKBENCH.md#本轮实际检查) |
| Windows 10、Windows Server、域控制器、ARM64，管理员审计正向读取、受限 PowerShell | 2026-10-26 | 待适配 / NOT_RUN | 当前未提供可确认归属的相应实验目标，不能由本机结果推断 |
| 两种采集端的真实 RDP 回传、多次连接与权限矩阵 | 2026-10-26 | 实验性 / NOT_RUN | 本机查询与桌面合成数据不能代替远程验收 |
| 新增规则的策略修改、备份恢复、业务独立复核 | 2026-10-26 | 待实现 | 本轮仅接线只读核查，不生成可回滚或已修复结论 |

复现命令（在仓库根运行，先确认本机只读采集影响）：

```powershell
pnpm ui:check
cargo test --locked --package lovelyhawk-core windows_incident --lib -- --nocapture
cargo test --locked --package lovelyhawk-win-dvc --package lovelyhawk-backend --package lovelyhawk-desktop --lib
cargo clippy --locked --package lovelyhawk-core --package lovelyhawk-win-dvc --package lovelyhawk-backend --package lovelyhawk-desktop --all-targets --no-deps -- -D warnings
pnpm ui:build
cargo build --locked --package lovelyhawk-desktop --package lovelyhawk-win-dvc --bin lovelyhawk --bin lovelyhawk-win-agent
node ui/scripts/probe-windows-workspace.mjs
node ui/scripts/run-debug-smoke.mjs
pnpm release:source-gate
pnpm release:dependency-gate
pnpm release:ledger-gate
```

## 后续缺口

优先继续补齐有效口令复杂度/可逆加密、用户权限分配、域策略来源与覆盖关系、ASR/应用控制、Secure Boot/BitLocker、TLS/Schannel、补丁时效与集中日志状态。每项均需独立来源、适用条件、权限/版本矩阵；不能只增加注册表开关计数。完整计划、一次确认、备份、独立复核、恢复及案件留证仍见 [未完成功能](UNWIRED_FEATURES.md)。

## 原始资料

资料用于核对 API 和策略语义；产品阈值不自动等于整个标准合规。核对日期：2026-10-26。

- [NetUserModalsGet 的本机/域与级别语义](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netusermodalsget)、[USER_MODALS_INFO_3 的单位与结构](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-user_modals_info_3)
- [AuditQuerySystemPolicy 的权限与返回缓冲区](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-auditquerysystempolicy)、[审计成功/失败标志](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-audit_policy_information)、[固定子类别](https://learn.microsoft.com/en-us/windows/win32/secauthz/auditing-constants)
- [微软账户锁定建议与拒绝服务权衡](https://techcommunity.microsoft.com/blog/microsoft-security-baselines/configuring-account-lockout/701040)、[SecCon 企业基础指导](https://github.com/microsoft/SecCon-Framework/blob/master/level-1-enterprise-basic-security.md)
- [Get-WinEvent 的日志配置读取](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.6)、[进程命令行审计及秘密风险](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-auditsettings)
- [防火墙配置字段与策略存储](https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile?view=windowsserver2025-ps)
- [Get-MpComputerStatus](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus?view=windowsserver2025-ps)、[Defender 与其他产品的模式差异](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility)
- [Credential Guard 运行状态](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure)、[VBS 与内存完整性](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity)
- [WinRM 客户端策略](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-remotemanagement)、[CISA 的 LLMNR 缓解说明](https://www.cisa.gov/eviction-strategies-tool/info-countermeasures/CM0053)
