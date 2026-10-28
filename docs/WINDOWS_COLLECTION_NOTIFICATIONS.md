# Windows 采集提示与分段结果

2026-10-27。本轮针对启动项、服务、驱动、计划任务、日志、注册表及关联详情里的重复警告占高，以及大清单被单次输出限制挡住的问题。

## 交互

- 采集警告和覆盖范围收进已有全局通知中心。页面保留简短入口与“部分读取 / 未能读取”状态；启动项分类计数旁的缺口标记继续存在。
- 批量采集的结果在主页面统一发布，未打开或暂时隐藏的模块也会保留采集警告。每条通知带当时的目标与采集时间；切换页面或短提示到期不重复发布同一份结果。
- 多条长警告分成多个有界通知，保留后面的原因；侧边短提示只展示前三行，完整内容在通知中查看。通知中心仍只保留本次运行最近 64 条，超过后显示已移出的数量；它不代替证据与处置记录。
- 从页面入口可打开通知，关闭后焦点返回入口。详情和确认对话框里的错误也进入通知，并在当前对话框保留紧凑的可展开原因，避免叠加两个焦点捕获层。
- 风险证据、操作影响、确认内容、断连状态和重试按钮继续与对应对象一起显示，样式改为紧凑文本。没有通过隐藏警告把部分清单标成完整，也没有放宽删除/处置条件。

## 有界分段回传

`lovelyhawk-win-dvc` 增加 `result_start / result_chunk / result_end`。工作台给命令附加随机请求编号，接收时同时绑定原会话与当前请求。每段最多 48 KiB 原始字节，采用 Base64 传输；起始帧声明总字节数，分段声明偏移，结束帧校验总量与 SHA256，再统一解码 UTF-8。单次合并最多 16 MiB，未完成的内容不交给业务解析器。

丢段、重复、错序、无效 Base64、总量超限、非 UTF-8 或摘要不符均不产生成功结果；其他请求和旧会话的数据不能完成当前命令。断开、超时、重新连接清除未完成缓冲。原有超时关闭通道策略保留，旧采集端没有请求编号时的迟到结果不能被下一条命令消费。

免落地 PowerShell 和 Rust EXE 采集端都实现相同回传格式。PowerShell 按输出行累计字节，EXE 使用有界子进程管道；接收分段不会写临时结果文件。SHA256 仅用于传输完整性，不能证明目标可信。

兼容旧端的小结果：新版客户端仍接受旧 `result` 帧，新采集端遇到旧客户端的大输出明确要求更新。已经运行的旧采集程序不会自动升级；须重新复制新版免落地命令，或使用同目录新构建的 `lovelyhawk-win-agent.exe`。

## 启动项容量与剩余边界

启动项改为每类最多 5000 条、总共 20000 条，替代原每类 500 / 总共 4000 条。常规注册表值/子项遍历和服务/任务条目同步调整，COM 服务器路径解析最多 1000 项，特殊位置保留自己的遍历边界。每次扫描保留 30 秒预算。

在添加每行前计算 JSON 字节预算，原始结果最多约 4.5 MB；避免超限后反复序列化并逐行删除。Rust 解析后还检查现有 8 MiB 后端响应边界，未提高全局宿主响应权限或容量。超过条目、时间、字段或字节边界仍说明缺口。列表已有每页 100 条分页，搜索针对本次已取得的记录。

分段解决传输单条消息的限制，不等于无限采集，也不等于远程增量分页。日志时间窗、单目录/注册表查询边界和其他领域解析器的限制仍然适用；可恢复的远程分页、增量进度和逐段取消尚未实现。现有批量任务的“停止后续采集”不声称终止已经运行的远端命令。

## 验证记录

- UI：`pnpm ui:check`，141 个文件 / 1174 项通过，类型检查及构建通过。日志：`target/windows-notice-ui-check-final.log`。
- 传输：`cargo test --locked -p lovelyhawk-win-dvc`，15 项通过，大中文结果、错误分段、旧端兼容、请求及会话隔离；日志：`target/windows-notice-dvc-tests-final.log`。
- Core：`cargo test --locked -p lovelyhawk-core --lib windows_incident::startup_catalog`，超过旧 500 条限制的 1200 行样例、容量拒绝、19 分类覆盖及本机 PowerShell 只读目录；日志：`target/windows-notice-catalog-tests-final.log`。
- 免落地输出：`cargo test --locked -p lovelyhawk-core --lib windows_incident::tests::fileless`，命令长度和本机 Windows PowerShell 900000 字节中文输出分段、偏移及摘要回读通过。日志：`target/windows-notice-fileless-tests.log`。
- 桌面：真实调试 WebView2 CDP 的 193 / 193 项通过，无 Runtime / console / Log 错误，窗口正常退出。日志：`target/windows-notice-desktop-probe-final.log`；证据：`target/desktop-debug/windows-workspace-438ba29f-cb7d-4f56-b114-ffad05dd8a1b/evidence/`，其中 `35-startup-compact-notices.png`、`36-collection-notification-center.png`、`37-startup-compact-narrow.png`、`38-registry-compact-notices.png` 展示本轮效果。启动项提示实际高度 20px；同一启动项快照切页前后均为 1 条通知。
- 首轮桌面探针 192 / 193，失败断言误把首次访问服务页的新采集通知计为启动项重复通知。保留证据 `target/desktop-debug/windows-workspace-250d8bd4-295f-4a6e-829f-e5b243f78db3/evidence/` 和 `target/windows-notice-desktop-probe.log`；修正为按启动项来源计数，并打印前后数量及全部来源，原“不重复发布”预期保留。
- Core / win-dvc / backend / desktop 全目标 Clippy（`--no-deps -- -D warnings`）通过：`target/windows-notice-clippy.log`。源码门禁通过，228 页面模块、37 样式/资源：`target/windows-notice-source-gate.log`。
- 调试构建：`cargo build --locked -p lovelyhawk-desktop -p lovelyhawk-win-dvc --bins --profile windows-preview --config 'profile.windows-preview.inherits="dev"'` 通过。日志：`target/windows-notice-preview-build-final.log`。仅命令行增加继承 dev 的构建目录，没有增加第二套 UI / 发布路径或修改 Cargo 配置、lockfile。
- 为保留正在运行的旧 dev 窗口，将已验证的宿主复制到 `target/debug/lovelyhawk-notices-dev.exe`，同目录 `lovelyhawk-win-agent.exe` 更新并逐一校验 SHA256 相同。关闭旧窗口后启动该 dev 可沿用同目录的现有便携数据；没有自动切断现有连接。

真实 RDP 的高延迟/中途断链分段传输、旧 EXE 与不同 Windows / Server 版本组合仍为 **NOT_RUN**，不能由本机编码器、模拟通道和合成 UI 验收替代。本轮没有连接或修改用户真实远端目标，没有强制退出用户已打开的工作台，也未生成 release 发布包。
