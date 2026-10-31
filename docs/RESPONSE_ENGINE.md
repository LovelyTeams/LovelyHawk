# PR #5 收敛到命令工作台

2026-10-30。原 PR 的独立“应急处置引擎”页面、复选框扫描目录、`response.engine` 方法和批量修复逻辑均不保留。用户入口仍为“命令工作台”，复用现有分类、单项执行、分组执行、容器/Pod 运行位置、历史定位和受控文件操作。

原目录 146 项全部保留，只增加 1 项至 147 项。整合没有新增桌面桥方法、DTO、依赖、Python 脚本或需要分发的采集文件。固定只读采集逻辑编译在 `command_workbench.rs` 中，经已有 SSH 通道执行；开发用 Node/CDP 探针不进入便携包。这些改动纳入 0.0.3，下面保留整合期间各轮验证的实际范围。

2026-10-31 后续四项已接入原页面：进程/会话/映射关联、认证文件属性修补与撤销、固定 auditd 监控、完整性认证文件预设。基线与完整性沿用原 API 和确认链路，扩大既有预设枚举；没有恢复独立应急引擎。当前实现与验收限制见 [专项说明](AUTHENTICATION_BASELINE_VERIFICATION.md)，下文较早结果保留为历次记录。

## 去重与归类

| 原 PR 内容 | 本轮归属与处理 |
| --- | --- |
| 普通高 UID 账号、UID 0、空口令、sudo | 复用“账户与认证”“权限安全”；删除把普通账号当后门并删除的逻辑，不新增账号检查入口 |
| cron、启动脚本、PATH 注入 | 复用“持久化检查”的任务与登录脚本；原规则继续标记临时/可写路径 |
| 命令包装器过滤输出 | 唯一新增目录项“持久化检查 → 排查命令包装器”，检查 `/usr/local/bin` 的固定常用命令 |
| LD_PRELOAD、会话环境变量 | 增强现有 `process-preload`，名称改为“进程与内存 → 预加载与会话环境”；增加 LD_AUDIT、PROMPT_COMMAND 名称观察，不输出变量值 |
| 已删除的预加载库驻留 | 增强现有 `process-deleted`，名称改为“已删除文件与映射”；同一入口检查 FD 和 maps，正常升级/日志轮转也可能命中 |
| PAM 直接放行 | 增强现有 `persistence-pam`，名称改为“PAM 认证规则与变更”；检查 `auth sufficient pam_permit.so`，保留配置/常见模块文件属性，不再只按近期修改时间筛选 |
| 命令记录、会话启动钩子 | 原全局/用户登录脚本规则增加 PROMPT_COMMAND 中 history/tee/logger/script 的记录特征；普通提示命令与注释不因此命中 |
| 进程、监听端口 | 复用“进程与内存”“网络排查”；不复制新的监听扫描，也不根据显示路径/PID 自动结束进程 |
| SSH 授权公钥 | 复用原账号检查，逐把核对归属；合法 `command=` 限制不是自动删除依据 |
| 隐藏目录、站点可疑代码、凭据文件 | 复用“文件线索”的对应入口；不引入递归删除站点或目录的动作 |
| 历史命令中的凭据 | 2026-10-31 增强原“命令历史文件”：只返回文件、行号与特征，不输出历史命令或口令原文；保留文件属性、空文件、下载管道和清理历史线索 |
| 站点备份、数据库导出 | 2026-10-31 将原“凭据类文件位置”增强为“凭据与站点备份文件”，保留凭据权限标记，增加常见站点内 `.env.*`、数据库文件、`.bak` 及带 backup/dump/bak 名称的压缩包；只读属性，不验证网络可访问性 |
| 更具体的站点代码特征 | 2026-10-31 增强原“站点可疑代码特征”：匹配请求参数直接进入执行函数、解码结果进入 eval/assert，以及 JSP/ASP 请求执行调用；常见注释、字符串示例、普通解码与固定命令保持中性 |
| 加固、完整性清单、修复/恢复队列 | 原 PR 的重复 API 和隐藏逻辑一并移除；已有基线、完整性、受控文件处置链路继续承担对应流程 |

分类由 core 的固定目录控制。后续扩展先对照已有条目与规则；可以补充已有检查时不另建扫描器、任务注册表或第二个页面。

## 工作台交互

- 左侧仍为原分类树和检查条目，右侧显示说明、运行入口与结果。没有顶部项目复选框，也没有“自动/命令”两套标签页。
- 分类“快速执行”只执行当前筛选下按钮标明的项目，开始时固定该集合。修复了原来显示筛选数量、实际运行整个分类的问题。
- 执行期间锁定条目、搜索、目录刷新与主机/容器/Pod 运行位置；执行后更换运行位置清除旧结果，目标切换后的迟到结果被丢弃。
- 分组提供“停止后续检查”。当前命令返回或超时后停止安排下一项，保留结果并列明未执行数量。此按钮不承诺立即终止远端进程。
- 分组显示已返回数量、关注项和未完成项，输出按检查折叠；关注、失败和截断结果默认展开。
- 结果支持“全部输出 / 关注与缺口”。筛选保留原始行号、后端提供的文件操作位置以及读取缺口。执行成功只表示命令返回，不代表主机安全；空输出也明确说明边界。
- 使用现有主题 token，结果工具条可换行。修复欢迎页在窄窗口误占侧栏列宽的问题。

## 采集边界

七个增强/新增检查最多处理 2048 个对象，每个文件/进程内容最多 64 KiB，保留前 256 条关注线索；一般读取缺口最多逐条展示 12 条并保留总数，目录列表截断和总对象上限始终显示。工具缺失、读取失败、符号链接跳过、数量或字节超限均保留提示并返回非零状态，不解释成没有风险。目录和 `/proc` 的可见性受当前账号、命名空间和挂载约束。

依赖目标既有的 POSIX sh、head、tr、wc、awk、readlink、ls，两个站点/文件检查还需 find（`-xdev -maxdepth -print0`）；工具/参数不可用明确保留缺口。不自动安装、不提权、不执行被检查脚本，也不落地采集程序。固定 PATH 可以避开常见用户目录中的包装器，但无法证明目标上的工具、动态加载器或内核可信。文件检查和读取不是原子快照，进程退出/PID 重用也使这些观察不能授权后续处置。

新增历史检查只覆盖 `/root` 与 `/home` 第一层账号的 Bash/Zsh 文件、常见单行口令调用；复杂 Shell 语法、自定义历史路径与未落盘的会话记录不在覆盖范围。原 root 最近命令原文展示改为位置/特征摘要，避免再次传播口令；原始文件须通过既有明确的查看/留证操作处理。读取可能更新访问时间。

两个文件检查在固定目录内最多遍历 6 层且不跨文件系统，每个目录列表最多 2048 项/256 KiB，总量仍受 2048 对象约束（目录也计入）。目录不存在明确说明；不可读、符号链接、路径过长/控制字符、深度和容量上限保留缺口。不使用不完整的 NUL 路径记录，也不把文本文件中的 NUL 转换成额外行号；文本截断时丢弃末尾不完整行。Web 检查是有限的单行静态特征，不是完整语法、变量传播或业务安全分析；自定义站点、跨行代码、复杂混淆和网络暴露仍待核实。

PAM 不解析 include/substack 或完整认证链；预加载检查只给出位置和变量名；包装器只覆盖指定目录/命令；maps/FD 观察不证明二进制来源。业务健康、根除入侵、内核隐藏、完整站点暴露和生产处置/恢复均不在本轮验收结论中。

## 验证

开发命令：

```powershell
pnpm ui:check
cargo test --locked --package lovelyhawk-core --lib
cargo test --locked --package lovelyhawk-backend --package lovelyhawk-desktop -- --quiet
node tools/lab/probe-command-observations.mjs
cargo build --locked --package lovelyhawk-desktop
node ui/scripts/probe-command-workbench.mjs
```

2026-10-30 实际结果：

| 验证 | 结果与证据 |
| --- | --- |
| UI 类型、测试、构建 | 143 文件 / 1186 测试通过；既有大于 500 KiB 的公共分块构建提示仍保留 |
| Core 库测试 | 1278 通过，11 忽略；最后的环境记录边界调整后再跑 `command_` 相关 90 项通过 |
| Backend 与宿主测试 | Backend 库与独立 API 测试合计 778 通过；宿主 53 通过、1 忽略。忽略项主要需要专用目标或在线发布下载，不计通过 |
| 只读命令实际执行 | Ubuntu 24.04.1 / x86_64 / WSL / `/bin/sh` / GNU coreutils 9.4 的自有文件夹具，17/17。包括正常/异常 PAM、正常/过滤包装器、环境值不外泄、值内换行不伪造变量、FD/maps、字节/条目上限、六种工具逐一缺失及读失败。见 [report.json](../target/lab-command-observations/9449a3a1-08ca-4220-bd1f-d3f898f76277/report.json)，自有目录 `/tmp/lovelyhawk-command-checks-JdIvHMAx` 保留用于复查 |
| 工作台桌面交互 | 真实调试 WebView2、合成 API 数据，18/18，无 Runtime/console/Log 错误。见 [report.json](../target/desktop-debug/command-workbench-33b14cf1-fc77-4048-968a-84b8be7c5084/evidence/report.json)、[分类与详情截图](../target/desktop-debug/command-workbench-33b14cf1-fc77-4048-968a-84b8be7c5084/evidence/00-workbench-overview.png)、[结果截图](../target/desktop-debug/command-workbench-33b14cf1-fc77-4048-968a-84b8be7c5084/evidence/01-integrated-results.png) |
| 全桌面离线巡检 | 92/92：14 个页面、172 个现有主窗口 API、弹层/键盘/焦点、CSP、本地资源和干净退出。见 [report.json](../target/desktop-debug/ff7d2800-3fe1-4886-a6b2-a84e821f8d96/evidence/report.json) |
| 格式与仓库门禁 | Rust fmt、core/backend/desktop clippy、source/dependency/ledger 普通门禁通过。ledger 仍是 24/53 Completed，不是严格发布验收 |

本机 Node 为 24.13.0，未满足仓库指定的 26.13.x；本轮 UI 验证通过不能替代指定 Node 版本的发布门禁。未制作/发布新的 release 便携包。未执行、忽略和兼容性待验证项不计为通过。WSL 文件夹具不替代真实 SSH、容器、Pod、VM 或实机矩阵；桌面合成 API 测试不替代远端执行与修补验收。

## 2026-10-31 补充验证

- UI 类型检查、143 文件 / 1186 测试及构建通过，保留既有公共分块大小提示。Core `command_` 相关 92 项通过；backend `emergency_` 相关库/独立测试合计 68 项通过；core 全目标 clippy `-D warnings` 通过。新摘要/文件属性行复用原受控路径操作；路径测试验证完整空格路径、管道分隔符、穿越和多路径歧义，拒绝将文件名的一部分当作操作对象。
- 同一 Ubuntu 24.04.1 / x86_64 / WSL 文件夹具扩展至 31/31：新检查的正常/异常样例、秘密值不输出、源行号、截断行、链接及上级链接、深度/数量/字节上限、目录读取失败、原文件字节未变。见 [采集报告](../target/lab-command-observations/8bcba504-0e1f-432c-8779-ff4653e66eaf/report.json)，保留目录 `/tmp/lovelyhawk-command-checks-uN0ePOF3`。报告源摘要与最终 `command_workbench.rs` 一致。
- 最终源码的标准调试宿主 `target/debug/lovelyhawk.exe`，经真实 WebView2 CDP 验证 24/24，无 Runtime/console/Log 错误。使用合成 API 回放上项实际采集输出，检查三个原入口、脱敏结果和关注/缺口筛选；不是实时 SSH 验收。见 [桌面报告](../target/desktop-debug/command-workbench-262e573f-8522-4a6d-bdbf-a13db269e651/evidence/report.json)、[历史检查截图](../target/desktop-debug/command-workbench-262e573f-8522-4a6d-bdbf-a13db269e651/evidence/04-history-observations.png)、[文件检查截图](../target/desktop-debug/command-workbench-262e573f-8522-4a6d-bdbf-a13db269e651/evidence/04-credential-observations.png)、[代码检查截图](../target/desktop-debug/command-workbench-262e573f-8522-4a6d-bdbf-a13db269e651/evidence/04-web-observations.png)。`cargo build --locked --package lovelyhawk-desktop` 通过。
- 初次目录容量回归暴露截断提示被普通缺口上限隐藏，修正为总量/列表上限始终显示；初次桌面回放夹具的末尾换行造成行数契约拒绝，修正夹具以符合现有响应规则。失败证据分别保留在 `target/lab-command-observations/4294a60a-dfe1-40f9-9a65-ead798e1bdd3` 和 `target/desktop-debug/command-workbench-07eaf57a-d857-40e6-bbbd-2d5812706b18/evidence`，没有放宽生产校验或过滤桌面错误。

本轮仍使用 Node 24.13.0，未补真实 SSH/容器/Pod、其他发行版/架构、BusyBox 或 release 包矩阵；上一轮全桌面 92/92 不作为本轮重跑记录。会话关联、认证文件修补和 auditd 监控继续保留待办，本轮只完成前三项增量。
