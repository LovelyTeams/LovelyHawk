# Windows 应急响应工作台

Windows 工作区使用 LovelyHawk 的全局主题，初期参考 LovelySpark 的导航层级与 LovelyWinInspect 的排查分类，现按主机、调查列表、详情与任务面板组织。功能以 LovelyHawk 实际接入的采集接口为准，不代表这些产品能力等同。

## 已接线的流程

- 接入：注册本机当前用户插件并启动监听 → 在工作台内打开远程桌面（原生 mstsc 画面嵌入） → 在远程会话运行免落地 PowerShell 或复制采集端。首次未连接时显示三步向导；已有快照时断连保留当前调查页面，显示旧快照提示并提供重新接入入口。
- 总览与基线：主机、防护和资源概况，检查依据、当前/建议值、通过/警告/失败筛选与优先关注项。未核查不会显示为通过。
- 进程、网络、启动项、账户：搜索、风险/类别筛选、排序、分页、侧边详情与复制。进程支持列表/可折叠树；按 PID 关联网络，定位文件和注册表来源。列表间按 PID 跳转仍只是线索；新增的进程关联读取在前后核对 PID 与启动时间，读取账户、服务、TCP/UDP 与已加载 DLL。
- 日志与时间线：保留真实事件 RecordId、原始时间、详情和截断标记；权限与通道读取缺口单独显示。时间线汇总已取得且有时间的事件、进程、文件和账户记录，支持来源、日期筛选与 CSV 复制。
- 文件管理器：快速访问、地址栏、面包屑、前进/后退/上一级、目录优先排序、属性和 SHA256、文本/十六进制预览、PE 基本信息、文件拉取与另存。
- 注册表：常用位置、键路径、上一级、按需展开的注册表树、值筛选与详情，右侧集中常见排查位置。默认值保留空名称；环境变量保持原始内容；二进制按十六进制显示。
- 底部面板：任务、接收文件、命令检查台、通信日志。任务显示当前采集与模块读取结果；命令执行仍需确认目标和完整文本。

核心模块批量读取显示进度，可以停止后续采集；当前读取结束后才停止。切换模块保留查询、选择与编辑内容。失败保留上一份成功数据，并提供重试。

## 证据范围与限制

| 能力 | 当前边界 |
| --- | --- |
| 表格 | 每页最多渲染 100 行；筛选/排序针对已返回的记录 |
| 目录 | 单次返回最多 1,000 项；最多观察 10,001 项来报告截断，大目录数量可能只是下限 |
| 自动文件摘要 | 最多 24 个不超过 5 MiB 的特定可执行/脚本文件；空摘要不代表已校验 |
| 内容预览 | 文件开头最多 16 KiB；明确显示读取量、总大小与部分读取，PE 信息不是完整静态分析或签名鉴定 |
| 拉取及保存 | 单个文件最多 8 MiB；读入大小受限，读取期间大小变化则失败；接收和另存分别核对 SHA256 |
| 接收缓存 | 最多 32 个文件，关闭程序会丢失；应及时另存。缓存不是完整案件证据链，需同时保留来源主机、远程路径和采集时间 |
| 本机保存 | 系统文件对话框选择目的地，只创建新文件，不覆盖已有文件；取消保存保留缓存 |
| 注册表 | 最多 500 个子键、256 个值；单值文本最多 4,096 字符，二进制最多 1,024 字节，超限明确标记 |
| 事件日志 | 固定类别、时间与条数范围；失败/不可读与无匹配事件分别处理。详情有长度限制，不等于完整 EVTX 导出 |
| 时间线 | 仅当前会话已采集的数据；文件范围是当前目录。保留来源时间与时区，未校正源时钟误差 |

账户、事件日志、注册表的采集使用固定 PowerShell 只读查询。没有相应组件或读取权限时报告失败/缺口，不自动安装、提权或修改安全配置。账户不再从配置文件目录推断登录活动，日志不再用本地序号冒充 RecordId。

现有其他采集器仍有平台、权限与字段长度限制；当前检查不能证明所有 Windows 版本和字段均可取得。只维护一个活跃采集通道，多客户端并行处置、完整案件留证、EVTX/MFT/ADS/重解析点专项取证与系统修补恢复不属于本轮已验收能力。

## 会话与宿主边界

每次 DVC 通道建立生成独立会话标识。读取、预览、拉取、消息与命令都携带该标识；core 在队列执行、发送和接收时核对。旧通道的消息和关闭通知不能覆盖新通道，页面也拒绝旧请求的迟到结果。

短暂状态读取失败保留同一会话的快照与选择；真正的新会话清除旧结果与操作上下文。旧版采集端没有命令响应关联号，因此命令超时后暂停该通道，要求重新启动采集端，避免迟到结果被当成下一条命令输出。超时/停止后续采集不等于远程命令已经终止。

文件导出通过宿主专用 `windows_file_save` 命令。内部 `windows.evidence.part` 按 256 KiB 读取已校验缓存，不在主窗口方法白名单中。页面只持有文件标识、显示名称与摘要，得不到本机保存路径或导出字节。

发布构建和便携包脚本已加入 `lovelyhawk-win-agent.exe`，验证器拒绝缺少采集端的包。采集端不会随主程序自动运行。向导中的“打开 Agent 所在位置”是资源管理器定位，复制到服务器仍由操作员完成。

## 可复现验证

```powershell
pnpm ui:check
cargo test --locked --package lovelyhawk-core windows_incident --lib
cargo test --locked --package lovelyhawk-win-dvc --lib
cargo test --locked --package lovelyhawk-backend --package lovelyhawk-desktop --lib
cargo clippy --locked --package lovelyhawk-backend --package lovelyhawk-desktop --all-targets --no-deps -- -D warnings
cargo build --locked --package lovelyhawk-desktop --package lovelyhawk-win-dvc --bin lovelyhawk --bin lovelyhawk-win-agent
node ui/scripts/probe-windows-workspace.mjs
pnpm desktop:test:debug
pnpm release:source-gate
pnpm release:dependency-gate
pnpm release:ledger-gate
pwsh -NoProfile -File scripts/desktop-validate-package.ps1 -SelfTest
```

工作区探针使用隔离的数据根和真实 WebView2 主窗口、生产 origin、全局主题及原生宿主。未连接状态与缺失接收文件的拒绝走真实桥；**已连接场景使用显式测试数据**，不连接远程主机、不注册插件、不执行远程命令。它覆盖页面、筛选/详情、目录历史、预览竞态、会话切换、取消、键盘、窄窗口与主题，不能替代真实 RDP 验收。

截图、断言、控制台记录、宿主输出保存在 `target/desktop-debug/windows-workspace-*/evidence/`。失败运行保留其证据。真实 RDP 两种采集端、多版本/权限矩阵、大文件实际传输、mstsc/资源管理器操作和真实发布包运行仍需相应环境验证；打包脚本自测不等于已经生成并验收了发布包。

## 2026-10-24 使用反馈改进

- Agent：WTS 成功但返回零字节是空闲轮询，保持等待；真正断连后按 1–30 秒间隔重连，不重放旧命令。通道关闭与写入互斥，旧线程不能写到复用的句柄。只允许一条在途指令，异常捕获后返回错误。
- 查询进程：原生采集最多 35 秒、stdout/stderr 分别最多 2 MiB；自定义指令分别最多 512 KiB。管道非阻塞轮询并在退出时回收读取线程，派生进程持有管道不会无限拖住采集端。超时终止当前查询子进程，不宣称已终止它的全部派生进程。文件传输保持 8 MiB 上限和完整性核对。
- PowerShell 复制内容：一个可粘贴的 ASCII 命令，参数为完整脚本的 UTF-16LE Base64，避免交互窗口分段解释 here-string、花括号与换行。没有额外关闭安全机制或修改执行策略。免落地脚本仍需保持窗口运行；其进程内查询的取消能力不等同于原生 Agent 的子进程时限。
- 主机信息：补充 BIOS、系统安装时间、时区、硬件、磁盘、IP/网关/DNS/MAC、DHCP、最近 50 条系统更新、Defender 引擎与签名信息。Defender 与防火墙无法读取时为未知，采集缺口折叠显示。
- 进程与网络：移除原生进程前 80 项、网络前 65 项的静默截断。进程至多 32,768 条，网络 TCP/UDP 各至多 8,192 条，超限明确失败；整体字节上限也可能先达到。进程关联最多 256 个服务、512 个模块、TCP/UDP 各 1,024 条，部分失败和截断保留。系统模块枚举不覆盖隐藏/手工映射 DLL，不构成完整注入检测。
- 日志：16 种固定查询类别，覆盖登录、账户、服务、PowerShell、RDP、Defender、任务、Sysmon、清日志、进程、WMI 及常规通道；后端预写筛选条件查询最近 7 天、每通道 200 条，JSON 记录预算约 1.4 MB。常用日志目录可进入文件管理器；日志 ID 的风险解释同时匹配通道，避免把 Application 的同号事件误报为 Security 事件。EVTX 全量解析仍未提供。
- 基线：11 项扩展为 32 项，补充 LSA/NTLM、UAC、SMB 签名与来宾、PowerShell 日志、WinRM 策略、远程注册表、Installer 与自动运行等。缺失值列为“无法判断”，不假定系统默认值。该阶段只读配置观察不等于运行时安全证明；后续加入的部分处置入口及其验收边界见下文。
- 操作界面：文件目录树、地址栏快捷键、显式预览/路径复制/拉取按钮；注册表左树、中间键值、右侧排查位置。进程选中后可按需展开网络、服务、DLL 关联表。底部“通道与传输”打开日志抽屉，状态栏隐藏时侧栏保留入口。大块常驻黄色提示改为折叠摘要，实际错误、断连与读取缺口继续可见。
- 字体与动画：统一 Windows 系统字体与中文回退，等宽证据文本保留 Cascadia Mono；修复行内加载环不可变换的问题，保留减少动态效果设置。

### 内嵌 RDP 的实现与验收边界

桌面新增专用 `windows_rdp` 命令，只允许主窗口调用。页面提交地址、剪贴板选择和有界布局，不获得凭据、窗口句柄、PID、本机路径或通用进程权限。原生模块只操作本次启动且持有进程句柄的 mstsc，通过 PID 与 `TscShellContainerClass` 同时核对窗口；父窗口必须属于本宿主。关闭、页面切换和覆盖层分别处理断开或隐藏，切换模块保留会话。

凭据和证书提示由系统客户端处理：`.rdp` 使用 `authentication level:i:2`，证书无法验证（如工作组主机的自签名证书）时由 mstsc 显示证书并让操作者决定是否继续，既不像级别 1 那样直接拒绝，也不像级别 0 那样跳过检查；`/public` 模式不保存证书信任。分辨率默认按显示区域实际像素启动并开启动态分辨率；也可选预设或自定义（宽为 640–8192 的偶数、高 480–8192），固定分辨率关闭动态调整，按比例缩小或居中显示。嵌入时给宿主自身的子窗口加 `WS_CLIPSIBLINGS`，否则 WebView 会画在远程画面之上；mstsc 会在会话开始或重连时自行显示和调整窗口，因此会话期间宿主每 500 ms 在 GUI 线程重新套用页面要求的位置或隐藏状态，客户端退出后停止。默认不重定向剪贴板、磁盘、打印机和设备，不改变目标 RDP/防火墙配置。临时 `.rdp` 文件不含密码，独占创建，断开后删除。原生 `SetParent`、枚举和布局操作仅在既有 Windows 集成 crate 内；宿主保持 `forbid(unsafe_code)`。指针只在同步枚举期间指向有效栈变量，句柄每次使用前重核所有权，布局在 GUI 线程执行。

此路径为**实验性、已接线，尚未取得真实远端交互验收**。状态“画面已嵌入”仅表示已取得窗口，不能表示认证成功。不同 Windows/mstsc 版本、多屏 DPI、证书/凭据对话框、全屏快捷键、断开重连、键盘焦点、关闭流程仍需真实 RDP 目标复核。微软说明跨进程 SetParent 可能重置子进程 DPI，不能仅凭编译或合成 UI 测试宣称稳定。

### 规则与平台依据

- [WTSVirtualChannelRead：超时与返回字节](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsvirtualchannelread)
- [PowerShell.exe：EncodedCommand 使用 UTF-16LE](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1)
- [LSA 保护与 RunAsPPL 的版本条件](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [Installer 的用户和本机策略条件](https://learn.microsoft.com/en-us/windows/win32/msi/machine-policies)
- [WinRM 运行配置与认证选项](https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management)
- [SMB 签名的运行配置读取](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing)
- [PowerShell 日志策略与适用范围](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowspowershell)
- [跨进程父子窗口的 DPI 限制](https://learn.microsoft.com/en-us/windows/win32/hidpi/high-dpi-desktop-application-development-on-windows)

新增基线是产品只读检查目录，不宣称获得标准认证或覆盖所有 Windows 版本。当前只读采集验证环境为 Windows 11 专业版 10.0.26200 x64；其他版本、普通用户与域策略矩阵待验证。

## 本次实际验证结果（2026-10-24）

| 检查 | 结果 / 证据 |
| --- | --- |
| UI 类型、单测、构建 | 140 个测试文件，1,162 项通过；`target/windows-ir-verification-20261024/ui-final.log` |
| Windows core 专项 | 12 项通过，包括本机九模块采集、进程自身模块对应、PID 复用拒绝、基线未知与版本判断；`core-final.log` |
| DVC / 原生窗口边界 | 9 项通过，包括空闲读取、输出/时限、非法父窗口、配置注入与严格请求字段；`dvc-final.log` |
| backend / 宿主 | backend 全量 353 项、宿主 39 项通过；追加 Windows 严格请求回归 1 项通过；`native-tests.log`、`backend-final.log` |
| Clippy | backend、desktop、win-dvc 全目标无警告；`clippy-final2.log` |
| Windows 桌面工作区 | 49/49；`target/desktop-debug/windows-workspace-e8bd1436-dffb-4b40-a0af-f3aefce5bb48/evidence/` |
| 整应用桌面巡检 | 95/95；`target/desktop-debug/adad2ad5-23ac-4c04-9680-be00fc4db368/evidence/` |
| 仓库门禁 | source、dependency、普通 ledger 通过；ledger 仍为 24/53，未声称 strict 完成 |
| 打包验证脚本 | `desktop-validate-package.ps1 -SelfTest` 通过；未生成或验收正式便携发布包 |

表中未列目录的日志均在 `target/windows-ir-verification-20261024/`，另有 `verification.json` 和构建文件 SHA256。失败证据保留：第一次窄窗口检查发现 body 的固定最小宽度导致横向溢出，已修复，未放宽断言；原生 RDP 空参数操作的多余字段拒绝回归曾失败，已改为严格的空结构体请求并通过复测。

现有 `target/debug/lovelyhawk.exe` 正在运行，未终止或替换。此次独立调试构建为 `target/windows-ir-review/debug/lovelyhawk.exe`，采集端在同目录 `lovelyhawk-win-agent.exe`。真实桌面探针通过 `LOVELYHAWK_DESKTOP_BIN` 指向它，并各自使用独立的 `LOVELYHAWK_ARCHIVE_ROOT`；全应用巡检直接运行 `node ui/scripts/run-debug-smoke.mjs`。这是调试构建，不是已通过严格发布验收的便携包。

## 2026-10-26 工作区布局改造

开发前已保存 Git 快照 `6eba3d5`。本轮按照已确认的效果图调整真实 Tauri 页面，继续使用全局主题 token 与现有采集接口。

- 顶部固定主机栏呈现名称、系统、权限与采集通道状态，保留远程桌面入口。状态查询失败显示待核实，断连后明确标记旧快照；有未保存接收文件时提供直接入口。
- 左侧按调查、取证、配置分组，所有模块直接可见；底部保留接入、通道、设置和切换工作台。窄窗口自动收为图标栏，仍有可访问名称与展开按钮。
- 进程列表与调查详情分别滚动。详情先解释风险线索，随后列出进程关系、命令行和网络/服务/DLL 入口；原始字段、完整进程链及已有跨模块定位仍可使用。没有取得关联数据时显示“未读取”，风险线索不表述为已确认恶意行为。
- 任务、接收文件、命令与通信日志使用底部分页面板，占用明确的布局空间。切换页签保留输入草稿；方向键切换页签，Escape 收起并返回页签焦点。
- 文件拉取完成自动打开接收文件。完整性校验与是否另存分别显示，取消或保存失败保留待保存状态，只有另存成功才清除提醒。
- 日志页明确远端查询的类别、最近 7 天、每通道最多 200 条，以及搜索只过滤已返回记录的范围。
- 窄窗口选中进程后详情占用列表区域，关闭后返回列表与键盘焦点。表格选中行仅滚动自身，模块标题、主机栏与底栏保持可达。

已有的基线快速修复、结束进程、文件/注册表删除等入口保留原有确认和执行路径。本轮桌面合成数据只验证确认前不执行、取消、参数绑定与重新读取，不证明真实目标上的计划、备份、恢复和独立复核已经完成。完整案件链路、真实 RDP 与 Windows 修补恢复继续保留在 [未完成功能](UNWIRED_FEATURES.md) 中。

### 本轮验证结果

| 检查 | 结果 / 证据 |
| --- | --- |
| `pnpm ui:check` | 类型检查、140 个测试文件 / 1,167 项测试与构建通过；保留已有共享 chunk 超过 500 kB 的构建提示 |
| `cargo build --locked --package lovelyhawk-desktop --bin lovelyhawk` | 通过；本轮未修改 Rust、远程命令或接口契约 |
| `node ui/scripts/probe-windows-workspace.mjs` | 95/95；`target/desktop-debug/windows-workspace-b14add0c-7b14-4f76-b4d5-5ee51dff531a/evidence/` |
| `node ui/scripts/run-debug-smoke.mjs` | 95/95；`target/desktop-debug/400b481f-356b-41d4-93b2-a77b8a8cc567/evidence/` |
| `pnpm release:source-gate`、`pnpm release:dependency-gate`、`pnpm release:ledger-gate` | 通过；普通账本仍为 24/53，未执行或宣称 strict 完成 |
| `git diff --check` | 通过 |

Windows 桌面探针核对 1440×960、1280×800、960×780 布局、浅色/深色主题、详情与焦点、任务停止、命令草稿、接收文件取消/失败/成功、断连与会话切换；无运行时或错误级控制台记录。截图包括 `10a-process-investigation.png`、`10b-process-laptop.png`、`14-transfers.png` 与 `22a-process-narrow-inspector.png`。已连接数据为显式合成数据；截图中的应用底部全局连接状态仍来自真实未连接的外壳，不能把合成主机栏计作真实连接。

初次运行 91/92，发现窄窗口关闭详情后焦点未返回已恢复的表格，失败证据保留在 `target/desktop-debug/windows-workspace-8d91db5c-48cc-4201-92ab-b871c0373126/evidence/`。修复为等待视图提交后返回焦点，保留原失败断言并通过复测；随后补充笔记本布局、底栏键盘和未知连接状态检查。

当前调试程序为 `target/debug/lovelyhawk.exe`，SHA256 为 `7444b0e61ff08ec6e2fe16c202e223851f4cf4c83cda72aa91e4ea77f52daf69`。构建前确认该程序未运行，两个探针均使用独立数据根并正常退出。本轮没有生成正式便携包，也没有连接真实 RDP 目标。
