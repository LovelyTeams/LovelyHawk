# Windows 通道与传输独立窗口

2026-10-27。本轮把 Windows 工作台底部的通道抽屉迁到 Tauri 原生窗口，保留现有采集与执行路径。

## 用户入口与布局

- 侧栏、状态栏的「通道与传输」打开同一窗口；响应方案和对象详情里的查询入口打开命令标签，取证拉取和「接收与保存」打开文件标签。
- 默认 1240 × 840，可调整大小、最小化和最大化，最小 800 × 600。四个标签为任务、接收文件、命令检查台、通信日志。主页面底部不再留抽屉空间。
- 宽窗口将命令预设和草稿放在左侧，完整输出放在右侧，输出使用剩余高度滚动。窄窗口改为上下排列；长文本按纯文本显示。
- 关闭窗口仅收起，当前工作台中的草稿和输出继续保留，已提交任务继续。离开 Windows 工作台或退出应用才释放窗口；未保存文件和草稿参与确认，未完成任务阻止离开。确认期间草稿版本或任务变化时拒绝旧决定。
- 操作使用现有确认框、采集锁、文件缓存和另存链路。另存对话框按已领取的文件请求绑定到通道窗口，子窗口仍不获得本机文件权限。新窗口的小提示约 5.5 秒消失，反馈同时送入主窗口通知中心。

## 接线与边界

`WindowsIncidentPage` 保持唯一的 `useWindowsIncident`。`useWindowsChannel` 发布专用视图并接收有限操作；第二个页面不创建第二套采集器或命令执行器。

宿主窗口名固定为 `windows-channel`，只加载 `terminal.html?window=windows-channel`。独立 capability 只授予窗口控件和 `windows_channel_child`；没有通用后端、SSH、插件、文件系统权限。`windows_channel_owner` 仅主窗口可调用。请求、响应在 Rust 和 shared/host 两侧校验，视图不传本机插件程序路径。

子窗口提交运行、发送、保存、核心模块重试、停止后续采集、移除插件注册等闭合意图；不提交目标身份。宿主绑定主窗口持有的会话，对远程操作再次只读核对实际 DVC 状态；主工作台按原会话和操作锁执行。连接变化使旧确认和等待请求失效；任务只领取一次，不自动重放。最多一项等待操作，未领取超过 5 秒失效。窗口的通知队列最多 16 条；主窗口通知保留原有容量与省略提示。

视图限制为 256 条日志、32 个文件、7 个核心模块记录；命令输出保持现有 16 MiB 上限，复制仍为 128 KiB。不对大输出逐次轮询重复回传；内容没有变化时只查询版本和完成状态。窗口缩放不改变采集上限或分段协议。

## 验证

使用 `pnpm ui:check`、宿主单元测试、宿主 clippy 和源码门禁检查契约、单次领取、过期拒绝、断连隔离、权限和视图边界。

`ui/scripts/probe-windows-workspace.mjs` 在独立数据目录运行真实调试宿主，经 WebView2 CDP 连接主窗口和通道窗口。探针覆盖入口、最大化、复用、隐藏后的草稿、离开确认、确认期间草稿变化、文件另存成功/取消/失败、键盘标签切换、推荐查询、长输出、窄窗口和错误收集。数据为明确标记的合成样例，不执行真实目标命令，不替代 RDP 目标验收。

本轮最终记录：

| 检查 | 结果与证据 |
| --- | --- |
| `pnpm ui:check` | 143 个文件 / 1181 项通过，类型检查与构建通过；`target/windows-channel-ui-check-final.log`。主 API 的类型声明补齐后再次单独运行类型检查通过。 |
| `cargo test --locked -p lovelyhawk-desktop --lib` | 48 项通过；`target/windows-channel-host-tests-final.log`。 |
| 宿主 clippy `--all-targets --no-deps -- -D warnings` | 通过；`target/windows-channel-clippy-final.log`。 |
| `pnpm release:source-gate` | 231 个页面模块 / 38 个样式资源通过，三类窗口权限严格分开；`target/windows-channel-source-gate-final.log`。 |
| WebView2 CDP | 206 / 206 通过，观察期间 Runtime / console / Log 错误为零，正常退出；`target/windows-channel-desktop-probe-delivery.log`。 |

最终桌面证据目录：`target/desktop-debug/windows-workspace-1a5973ad-24bd-4b58-95a7-40f6fd9ae13a/evidence/`。已目视检查宽、窄、深色布局，代表截图为 `17a-command-output-wide.png`、`17b-command-output-narrow.png` 和 `17c-command-output-dark.png`。截图中的输出是合成展示样例，未执行远程命令。

未删除失败记录：第一次探针发现重入工作台会重放旧打开请求；第三次发现通用提示覆盖了独立页面中的具体保存错误，均已修复。第二次未在期限内取得调试页面（0 / 1），原因未确认，不计通过；第四次的窄窗断言使用了不适用于实际字号的 100 px 下限，改为同时核对预设内容无裁切、无横向溢出和输出高度，最终整轮重新通过。这些记录分别保留在 `target/windows-channel-desktop-probe.log`、`-2.log`、`-3.log`、`-final.log` 和各自独立的证据目录中。

调试构建使用现有 dev 配置继承的 `windows-preview` profile，命令为 `cargo build --locked -p lovelyhawk-desktop --bin lovelyhawk --profile windows-preview --config 'profile.windows-preview.inherits="dev"'`，未修改 Cargo 工具链或依赖。已把经过上述桌面验证的程序复制到 `target/debug/lovelyhawk-channel-dev.exe`，沿用该目录的便携数据和采集程序。大小 52,591,616 字节，SHA256 为 `629B86B40D95435FCDAE476EC044EE6ED8901395C8926499C6178A291F59A7FD`，与验证构建相同；不是 release 发布包。

## 仍待验证

真实远程目标上的命令、传输、长任务与 RDP 客户端并行交互继续列为待验证。没有据此扩大此前 Windows 采集、处置、恢复或分段传输的验证矩阵。窗口草稿仅保留在当前工作台运行期，未新增跨应用重启持久化。
