# Windows 进程、清单与全局通知

2026-10-27。本轮范围是进程树处置、远程桌面复制采集命令、通知中心，以及服务 / 驱动 / 计划任务入口。

## 进程处置

进程详情分别提供“结束进程”和“结束进程树”。先只读预览，显示目标、名称、PID、父 PID、启动时间及完整影响范围，再由用户点击明确的确认按钮。计划限当前 DVC 会话，120 秒失效，只能使用一次；每次最多 64 个进程。计划由 core 保存，页面执行时只能提交计划编号。

执行前重新检查整个范围，核对 PID 和启动时间、父子关系及采集端祖先；拒绝系统核心进程和关键进程。所有对象先取得固定的进程引用并核对创建时间、终止权限，再次比较范围，最后从后代到根进程依次终止。CIM 时间精度按微秒比较；后续不重新按 PID 打开进程。使用退出等待独立核实终止，失败、超时和结果未知均逐项展示，停止后续操作。操作前与返回结果写入便携数据的 `LovelyHawk-windows-process-history.json`，最多 100 次，达到容量拒绝新增，不覆盖旧记录。

终止没有恢复运行状态的备份，确认界面明确提示数据丢失和服务中断。此流程不自动提权，不绕过保护，不保证阻止处置期间新建、逃逸或被持久化机制重新拉起的进程；需要重新采集与独立调查。该计划日志目前没有专用浏览 / 导出页面，旧单进程 API 为兼容仍保留，但桌面单进程和进程树入口都使用新计划。

依据：Microsoft 说明 [PID / 父 PID 会复用](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-process)，[TerminateProcess 后需等待才能确认退出](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess)。当前策略避免用 `taskkill /T` 扩大已确认的范围。

## 服务、驱动、计划任务

三个独立入口调用固定枚举的只读清单 API；不是启动项中前 15 个非系统任务的过滤视图。服务来自 `Win32_Service`，驱动来自 `Win32_SystemDriver`，任务来自 `Get-ScheduledTask`，包括系统任务与已禁用任务。

列表支持搜索、状态和线索筛选、排序、详情、复制、服务配置注册表定位、运行服务的进程定位，以及现有只读命令预设。计划任务展示最多 10 个操作和 10 个触发器摘要；不把摘要当作完整 XML / 执行历史。最多读取 2001 条以识别超限，显示最多 2000 条，响应预算 2 MiB，字段与结果截断均可见。权限或工具缺失保留缺口，不显示合规结论。驱动清单是驱动服务观察，不是完整内核模块、隐藏驱动或 rootkit 检测；本轮未增加驱动强制卸载、服务修补和任务删除权限。

## 通知与复制

2026-10-27 后续采集警告的紧凑入口、完整通知和分段传输，见 [Windows 采集提示与分段结果](WINDOWS_COLLECTION_NOTIFICATIONS.md)。

主窗口状态栏最左侧提供通知中心；隐藏状态栏时保留侧栏入口。既有固定通知和主窗口各页面的操作反馈汇入同一中心。只显示最新一条短提示，从左下侧滑入，普通 3 秒、错误 5 秒后消失，历史仍可查看。打开中心标为已读，支持逐条移除和清空；只保留本次运行最近 64 条，超出时显示丢弃的较早通知数量。通知不是取证或操作日志，不持久化到浏览器存储。

通知入口显式接收原本用于公开展示的操作文案，不扫描 DOM，也不接收命令输出、脚本、证据或凭据。既有固定 intent 仍拒绝附带自定义正文；公开文案限制长度、移除控制字符、遮蔽常见标记的秘密，并按纯文本渲染。进行中的任务、断连、采集不完整、输入校验以及操作对话框里的必要错误仍留在相关位置；独立文件编辑子窗口的保存结果保留在子窗口，不假称已接入跨窗口通知转发。

通知抽屉支持 Escape、焦点限制和返回，尊重降低动画设置。弹窗期间短提示暂存，关闭后再计时；RDP 原生视图在通知覆盖期间隐藏，避免遮住通知和弹窗，随后恢复原会话。

远程桌面页标题区域增加“复制免落地 PowerShell”。复制经过宿主提供的完整采集脚本到本机剪贴板，不自动执行远端命令；无脚本或剪贴板能力时按钮禁用。

## 验证与边界

- UI 类型、单测与构建：`target/ui-check-process-notifications.log`，141 个文件 / 1169 项通过，包含隐藏状态栏的 Windows 侧栏入口修正。
- Core Windows 相关测试：`target/core-windows-changes-test-final.log`，36 项通过，包括单次计划、会话 / 过期拒绝、父子关系、64 个身份的命令行预算与清单缺口。
- Backend 请求边界：`target/backend-windows-changes-test.log`，3 项通过；backend / desktop 全目标 Clippy（`-D warnings`）通过，见 `target/clippy-process-notifications.log`。
- 实际 PowerShell 5.1 进程脚本：`scripts/test-windows-process-tree.ps1`，只创建并终止自己的休眠进程及其 console host，保留 PID / 启动时间对应。预览零效果、身份变化整批拒绝、未批准子进程拒绝、退出验证共 5 项通过，证据 `target/process-tree-lab-836733f2-d327-40fe-bcd9-e07466dc5d2e/`。这是脚本层验证，不能替代真实 RDP / core / 宿主全链路验收。
- 本机只读清单：`target/windows-inventory-readonly-validation.json`，服务 330、驱动 493、任务 194 条；任务存在字段截断并正确报告。没有进行服务 / 驱动 / 任务变更，未保存原始敏感命令行到报告。
- Source gate：`target/source-gate-process-notifications.log`，通过。
- 调试宿主构建：`target/desktop-build-process-notifications-final.log`，生成 `target/debug/lovelyhawk.exe`。本轮未重新打 release 包，不能用旧包验证本轮功能。
- 原生主窗口巡检：92/92，`target/desktop-debug/5e1fe186-6706-4d1e-8ae1-c575f1646520/evidence/`；无 console / Runtime / Log 错误。
- 通知中心原生验收：17/17，`target/desktop-debug/notifications-0de81f61-ac0c-4271-9f8a-dfeaff640704/evidence/`。覆盖自动消失、保留历史、标为已读、重复事件、弹窗暂停、焦点返回、Windows 实际宿主剪贴板测试钩子、隐藏状态栏及 640 像素窗口；无 console / Runtime / Log 错误。首轮发现保存进度误入通知已修复，失败报告仍保留在 `target/desktop-debug/notifications-126eb6eb-3105-47d1-bbd3-fba874abe8d6/evidence/`。
- Windows 工作台原生合成数据验收：137/137，`target/desktop-debug/windows-workspace-d2be847c-9762-4ee7-ac5b-97e62d93ff8d/evidence/`。覆盖独立清单请求与详情、系统 / 禁用条目、进程单项与树预览、取消和明确确认、回车不误触、只传计划编号、逐项结果、远程桌面复制、断连 / 换目标及窄窗口。无 console / Runtime / Log 错误；数据和执行端为合成 fixture，不是实际 RDP 上的处置证据。

真实 RDP 上的计划处置、权限不足 / PPL / 恶意持续拉起、多 Windows 版本和 Windows Server 矩阵仍待验证。独立子窗口的跨窗口通知汇总和进程操作日志浏览 / 归档入口仍待接通。不能据本轮宣称 Windows 应急能力全覆盖。
