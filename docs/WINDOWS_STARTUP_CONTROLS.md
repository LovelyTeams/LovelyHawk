# Windows 启动项分类与快捷处置

2026-10-27。服务、驱动和计划任务已接通操作按钮、只读计划、明确确认、结果回读、处置历史，以及配置原值恢复。启动项使用 19 类固定采集目录。此项是 Windows 应急工作台的增量，不代表 Autoruns 全量能力或全部 Windows 版本已经验证。

后续已补充可见详情、全部操作及注册项删除，见 [对象详情与删除](WINDOWS_INVENTORY_ACTIONS.md)。下文保留本轮初次分类接线的验收记录。

## 用户入口

| 页面 | 操作 |
| --- | --- |
| 服务 | 列表快捷启动 / 停止；详情启动、停止、重启、自动、手动、禁用；定位文件、注册表、所属进程 |
| 驱动 | 同样的受控服务操作；拒绝引导 / 系统启动、严重错误控制与不接受停止的驱动，不强制卸载 |
| 计划任务 | 立即运行、停止当前确认的实例、启用、禁用；复制和详情保留 |
| 处置与恢复记录 | 记录目标、对象、操作及已核实 / 已提交 / 未执行 / 待核实结果；符合条件时预览恢复原配置 |
| 启动项 | 全部及 19 类导航、数量、搜索、筛选、底部详情；服务 / 驱动 / 任务跳到独立处置页面 |

点击快捷操作直接只读预览；不会在打开弹窗或阅读区域按回车时执行。确认展示目标、对象、执行配置、当前状态、原值、预期变化、依赖及影响。未执行的计划关闭即丢弃，120 秒失效，仅能用一次。断连或会话变化后不能确认。结果汇入现有通知中心，同时保留对话框内的必要反馈。

## 启动项采集

19 类为登录、资源管理器、Internet Explorer、系统服务、驱动服务、编解码器、Winsock、打印、LSA 提供者、网络、启动执行、映像劫持、程序初始化、KnownDlls、Winlogon、输入法、计划任务、小工具、Folder Extensions。

采集机器及当前采集账户的固定注册表位置，包括适用位置的 32 位物理分支、常见 Run / RunOnce / Active Setup、Shell 扩展及 COM 注册、AppInit、IFEO / SilentProcessExit、KnownDLLs、BootExecute、LSA、打印与网络提供者、Winsock 目录、IME / TSF、Sidebar 历史配置，以及启动目录、服务 / 驱动 / 任务。只读取，不激活 COM 组件、不执行快捷方式、不加载 DLL。Sidebar 文件读取有上限；注册表、CIM 和任务查询可能产生系统审计记录。Add-Type 的系统编译过程也可能产生临时文件，不能称整个操作绝对无磁盘痕迹。

每类返回 `complete / partial / unavailable` 和计数；complete 仅表示本版本列出的固定位置已检查。后续容量与传输已更新为每类 5000 条、合计 20000 条，JSON 预算约 4.5 MB，见 [采集提示与分段结果](WINDOWS_COLLECTION_NOTIFICATIONS.md)；COM 服务器解析、注册表子项、字段和时间均有界限，超限显示缺口。其他账户、离线 hive、任意 Shell ProgID、所有 TSF 语言配置、WMI 订阅、隐藏内核对象及全部第三方加载点不在此目录的完整覆盖承诺内。小工具 / IE 分类也可能包含历史残留，安装或配置记录不等于正在执行。

新增关键系统类别不会继承通用“清理启动项”按钮。原有 Logon Run / RunOnce 清理入口保留；新的服务与任务入口走上述计划链路。其他注册表记录可定位查看，由相应模块另行确认操作。本轮没有增加批量删除或自动修复系统加载键。

## 执行与恢复边界

core 为采集条目生成当前会话的短期对象编号；页面不传可执行服务名、任务路径、命令或“强制”参数。计划保留目标 MachineGuid 的摘要、完整配置 / 权限摘要、状态、进程 / 任务实例及依赖观察。执行在消费计划、写入操作前记录之后进行，再次核对目标和配置。

服务使用保留的 SCM 服务引用，检查启动类型、错误控制、停止支持、活动依赖和采集端祖先。拒绝关键系统 / 连接服务。启动与重启核对传递依赖当前均运行，并完整展示这些依赖；Windows 原生启动会处理依赖，核对后依赖退出仍可能被 Windows 拉起。Windows 未提供这组检查与效果的原子事务，不以两次读取承诺绝无竞态。停止不会主动连带停止其他服务。

任务经 Scheduler COM 读取定义和权限，按任务路径和实例 GUID 操作，包含当前权限可见的隐藏任务实例。停止只针对确认的实例；新建或无权限读取的实例不在已确认集合内。运行只报告调度器提交结果，不把接受请求当作任务成功。不能枚举实例时拒绝停止，不把空枚举当作已经结束。

服务启动 / 停止有有限等待，配置及运行状态另行回读。返回不完整、超时或保存失败显示待核实，不重复旧计划，也不自动重新拉起已经停止的对象。停止 / 重启 / 运行不能恢复原进程数据，不声称有运行状态备份。

启动方式与任务启用状态的原值记录在便携数据 `LovelyHawk-windows-control-history.json`。只保留必要原值和私有配置摘要，不保存任务 XML、完整服务注册表内容或命令参数。恢复要求同一主机、其他配置及权限未变、当前值仍为修改后值；用新计划再次确认，只恢复设置，不自动启动对象。保存回读后的结果失败时不提供虚假的恢复按钮。记录最多 100 次 / 4 MiB，达到容量拒绝新增，保留旧记录；归档 / 导出专用入口仍待实现。

## 验证

- `pnpm ui:check`：141 个文件、1171 项测试通过；`target/startup-control-ui-check-final.log`。覆盖精确分类计数、作用域、额外字段拒绝和任务结果语义，类型检查与 UI 构建通过。已有大于 500 kB 的打包体积警告保留。
- `cargo test --locked -p lovelyhawk-core windows_incident::`：43 项通过，含 Windows 本机只读采集；`target/startup-control-core-tests-final.log`。最后补充完整任务路径、恢复主机名校验及中文状态后，5 项处置测试再次通过，见 `target/startup-control-core-control-tests-final.log`。
- `cargo test --locked -p lovelyhawk-backend --lib windows_incident_api::tests`：4 项通过，见 `target/startup-control-backend-lib-tests.log`。最初未限制 `--lib` 的命令在这 4 项通过后，因无关的 `emergency_command_api_standalone` 测试程序无法启动（os error 2）退出；保留 `target/startup-control-backend-tests.log`，不记为整个 backend 测试套件通过。
- `cargo clippy --locked -p lovelyhawk-core -p lovelyhawk-backend -p lovelyhawk-desktop --all-targets --no-deps -- -D warnings`：通过；`target/startup-control-clippy-final.log`。
- `node tools/lab/probe-windows-control.mjs`：Windows 11 专业版 10.0.26200、x64、Windows PowerShell 5.1.26100.9711、非提升账户，12 项通过、1 项 NOT_RUN。创建唯一当前用户隐藏休眠任务，验证原值预览、禁用回读、旧配置拒绝、启用恢复及定义不变、运行提交、实例停止、按已确认归属清理；也只读检查服务配置和关键服务拒绝。证据：`target/windows-control/e16a8a7f-4ea7-49cf-a9ed-465713a2a9af/results.json`。报告只保留计数与结果，原始命令 / 注册表内容不写入报告。该探针验证脚本，不代表 core 历史写入或真实 RDP 链路已实测。
- 本机普通账户缺少创建测试服务和加载驱动的条件；服务 / 驱动真实变更为 **NOT_RUN**，没有修改已有业务服务或提权。
- `node ui/scripts/probe-windows-workspace.mjs`：真实调试宿主、独立数据目录、WebView2 CDP 合成数据验收 151/151 通过，未发现运行时、console 或 Log 错误，退出正常。覆盖 19 类、空结果、快捷预览、阅读焦点、取消、执行、恢复、失败、任务提交、断连、定位和窄窗口。日志：`target/startup-control-desktop-probe-final.log`；截图与结果：`target/desktop-debug/windows-workspace-f7da13c8-216a-4086-9f45-7ebc304de9d0/evidence/`。截图使用合成状态文案，最后的“预期变化”标签和 core 中文状态由之后的构建与类型检查验证；不替代真实 RDP 的端到端处置。
- `pnpm release:source-gate`、`pnpm release:dependency-gate`：通过；`target/startup-control-source-gate-final.log`、`target/startup-control-dependency-gate.log`。
- `cargo build --locked -p lovelyhawk-desktop`：调试版宿主，输出 `target/debug/lovelyhawk.exe`，日志 `target/startup-control-desktop-build-final.log`。

实际 RDP、管理员服务 / 驱动变更、Windows Server / 域控 / 其他版本、删除与完整恢复、系统组件业务健康仍需独立验证。本轮没有制作新的 release 便携包。

## 原始资料

- [Autoruns 范围](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns)
- [SCM 停止控制](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-controlservice)、[启动及依赖](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew)、[修改服务配置](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfiga)
- [Scheduler 注册任务接口](https://learn.microsoft.com/en-us/windows/win32/taskschd/registeredtask)、[实例的权限可见范围](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-iregisteredtask-getinstances)、[运行任务与隐藏任务枚举](https://learn.microsoft.com/en-us/windows/win32/taskschd/enumerating-tasks-and-displaying-task-information)
- [WOW64 注册表映射](https://learn.microsoft.com/en-us/windows/win32/winprog64/shared-registry-keys)、[64 位输入法注册](https://learn.microsoft.com/en-gb/windows/win32/tsf/64-bit-platform-considerations)
