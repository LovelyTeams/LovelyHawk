# Windows 服务、驱动与任务：可见详情和删除

2026-10-27，在 [启动项分类与快捷处置](WINDOWS_STARTUP_CONTROLS.md) 基础上的增量。

## 界面与详情

之前列表只突出一个启动 / 停止 / 运行按钮，选中后的详情位于长列表底部，不容易发现。本次每行提供「详情」「主要操作」「操作 ▾」，原来的底部详情仍可用。Enter 打开所选对象详情；描述在列表限制为两行，详情窗口展示完整已取得文本。操作选择、详情、确认窗口分别管理焦点，危险操作不会成为打开窗口后的默认焦点。

详情先保留清单字段，再按当前会话和 core 缓存的对象编号只读查询。页面不能指定服务名、任务路径或命令进行查询与删除。新 `inspect-inventory` 意图经过 backend、共享契约及现有 `windows.incident` 固定宿主桥；响应校验对象编号、种类、名称、字段数与长度。旧会话结果不能替换当前详情，关闭后迟到结果不再展示；请求有 45 秒上限，关闭详情并不等于远端查询已被取消。

- 计划任务：完整路径、注册说明、账户与权限、启用状态、最近运行时间、下次计划时间、返回代码、操作、触发器及常见设置。调度时间按目标本地时区报告；下次时间可能仍受禁用触发器影响，返回代码也不能证明业务成功。
- 服务 / 驱动：名称、说明、命令、账户、状态、启动方式、服务类型、退出代码、PID（适用时）、前后依赖与常见注册表配置。关键对象即使不能修改，也可以只读查看。
- 最多 96 个字段，每项最多 2000 个 UTF-16 字符，core 与页面另限制为 8192 字节；操作和触发器各最多 32 项，依赖最多 64 项。超限、权限不足或字段读取失败保留缺口。不会返回原始任务 XML、口令、组件私有 Data 或完整安全描述符。触发器只展示固定字段，不承诺还原每种第三方配置。

详情内容及复制均为纯文本。详情读取不生成处置授权，实际操作仍需独立规划及确认。

## 删除注册项

服务、驱动、任务均有「删除注册项」入口，复用已有一次性计划、会话约束、执行前记录及结果保存。预览完整目标、任务文件夹路径、配置、影响与恢复条件；确认删除还须主动勾选“没有完整备份、不能一键恢复，执行文件保留”。关闭或过期计划不可执行。

删除任务须先禁用、没有可见运行实例、状态为已禁用；`\Microsoft\Windows\` 下的系统任务拒绝此处删除。服务 / 驱动须先禁用、已停止，没有任何依赖它的服务（包括当前停止的依赖者），继续拒绝核心 / 连接、引导 / 系统及严重错误控制对象。不隐式停止、禁用、强制卸载、提权或重启；条件不符时说明先停止、禁用并刷新后再试。

实际删除使用 Scheduler `DeleteTask` 或 SCM `DeleteService`；只删除注册定义，不删除执行文件、驱动文件或驱动安装包。SCM 句柄在删除后释放，再重新查询：1060 才是不存在；1072 是仍等待其他程序释放，报告待核实。任务重新查询仅将明确的“文件不存在”错误当作缺失；权限拒绝和其他错误不能冒充删除成功。core 同时核对删除观察中的原主机、对象种类与完整名称，正常状态回读不能冒充删除证明。

这不是配置备份或卸载产品功能。处置历史只保留操作结果、原设置与配置摘要，不保留可完整恢复任务 / 服务所需的定义、账户口令、依赖、安装包及设备信息。删除没有恢复按钮；用户应先自行保留适当的定义或安装材料和凭据，再按系统工具或安装程序恢复。删除或停止驱动不能证明设备或业务恢复。

计划与执行之间及 Windows API 核对与效果之间仍有竞态窗口；状态、权限、完整配置或依赖发生变化时拒绝旧计划，但两次读取不是 Windows 原子事务。另一管理工具删除后同名重建的极短竞争不能完全排除。生产目标仍要求用户对本次具体计划明确确认。

## 验证与尚未覆盖

本轮使用 Windows 11 专业版 10.0.26200、x64、Windows PowerShell 5.1.26100.9711、非提升账户。脚本探针只创建当前任务拥有的唯一隐藏休眠任务，检查归属并清理该任务及空文件夹；没有修改真实服务 / 驱动或提权。

- `node tools/lab/probe-windows-control.mjs`：25 项通过、1 项 NOT_RUN（服务 / 驱动变更），证据 `target/windows-control/8519bb89-3dee-4038-8f0a-a8856d0fbcb3/results.json`。含只读服务 / 驱动详情、任务详情、拒绝运行中或启用的任务删除、配置变化后的旧计划拒绝、禁用后删除及独立缺失复核、文件保留。该脚本测试不代表真实 RDP 和 core 记录写入的端到端验证。
- `pnpm ui:check`：141 个文件、1172 项测试、类型检查及构建通过；`target/windows-delete-ui-check.log`。原有大于 500 kB 的打包警告保留。
- `cargo test --locked -p lovelyhawk-core windows_incident::control::tests`：7 项通过；`target/windows-delete-core-tests.log`，包含删除缺失证明、不同对象 / 主机拒绝、普通状态回读不能充当删除证明、详情字段边界、一次性计划及传输上限。
- `cargo test --locked -p lovelyhawk-backend --lib windows_incident_api::tests`：4 项通过；`target/windows-delete-backend-tests.log`，只读详情与删除不接受页面传入的名称、路径、命令或强制参数。
- 三个 crate 的 `cargo clippy --locked --all-targets --no-deps -- -D warnings` 通过，见 `target/windows-delete-clippy.log`；源码门禁通过，见 `target/windows-delete-source-gate.log`。
- 调试宿主：`cargo build --locked -p lovelyhawk-desktop --profile windows-preview --config 'profile.windows-preview.inherits="dev"'`，成功输出 `target/windows-preview/lovelyhawk.exe`；日志 `target/windows-delete-preview-build.log`。继承 dev、保留调试断言及受限调试入口；未修改仓库的 profile、依赖或锁定文件。
- `node ui/scripts/probe-windows-workspace.mjs` 使用新调试宿主和独立数据目录，经 WebView2 CDP 验收 **182/182**，无运行时、console 或 Log 错误，窗口正常退出。覆盖服务 / 驱动 / 任务的直接详情、复制、纯文本、读取失败、关闭后的迟到响应、断连、全部操作、删除确认与刷新、100 行分页长列表及窄窗口。证据：`target/desktop-debug/windows-workspace-ae0524d5-464c-46b3-8ebf-8a566b53bbb7/evidence/`；日志 `target/windows-delete-desktop-probe-passed.log`。截图 `31-task-details-narrow.png`、`32-tasks-details.png`、`33-tasks-delete-preview.png`、`34-tasks-long-list-actions.png`。
- 前三次桌面运行的失败证据保留在 `windows-workspace-314b9c75-a0ab-400a-8f2b-feccd9520307`、`windows-workspace-abf852c6-152a-408b-a0f6-b99a375d9531` 和 `windows-workspace-d93f9570-ada7-45c7-b4cb-a11d982ee945` 目录。原因是新增合成数据超出契约长度、选择器误选隐藏页、合成响应未模拟序列化复制，以及把浏览器返回的 normal 行高当作数字。用例改为合规长文本、可见表格、独立快照和实际单行高度测量，保留原来的两行限制与无额外执行断言；没有删除失败检查或过滤运行时错误。
- 服务 / 驱动真实删除、SCM 外部引用导致的延迟删除、其他 Windows / Server / 域控及真实 RDP 全链路仍为 **NOT_RUN**。它们不能由脚本任务测试、只读服务查询或合成桌面数据代替。
- 没有制作新的 release 包。构建期间保留了用户原 dev 会话，使用单独的输出目录，仍是同一个 Tauri 宿主。检测到原窗口关闭后，将已验收的程序同步到 `target/debug/lovelyhawk.exe`，核对 SHA-256 一致并启动，新窗口标题与响应状态正常。

## 原始资料

- [DeleteService：注册删除及引用释放条件](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-deleteservice)
- [TaskFolder.DeleteTask](https://learn.microsoft.com/en-us/windows/win32/taskschd/taskfolder-deletetask)
- [IRegisteredTask 只读详情接口](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nn-taskschd-iregisteredtask)
- [NextRunTime 的触发器限制](https://learn.microsoft.com/en-us/windows/win32/taskschd/registeredtask-nextruntime)、[LastTaskResult](https://learn.microsoft.com/en-us/windows/win32/taskschd/registeredtask-lasttaskresult)
