# 认证文件、进程关联与审计监控

2026-10-31。PR #5 剩余四项按已有职责接入，纳入 0.0.3；以下验证按实际环境与范围分别记录。

| 能力 | 现有入口 | 当前范围 |
| --- | --- | --- |
| 进程、会话与映射关联 | 主机全景 → 进程 → 预加载、会话与映射关联；命令工作台 → 进程与内存 → 预加载与会话环境 | 共用同一个内嵌采集器，关联 PID、PPID、SID、启动时钟、可执行路径与最多 32 个映射文件。只输出环境变量名称 |
| 认证文件权限 | 配置 → 检查这台主机 → 文件权限 | passwd、group、shadow、gshadow 的属性检查、单项计划、确认、执行、独立复核及历史撤销 |
| auditd 监控 | 配置 → 检查这台主机 → 审计日志 | 四个认证文件的固定写入/属性监控。增量添加缺失规则，撤销只移除本次新增规则；真实内核功能仍为实验性 |
| 完整性预设 | 文件完整性 → 关键认证文件（可选） | 四项折叠预设，沿用现有创建、比较、取消及结果处置；与 /etc 的重复范围自动合并 |

命令目录保持 147 项，基线目录从 108 增至 113 项，完整性预设从 6 增至 10 项。没有增加页面、通用命令 API 或独立执行服务。固定 POSIX shell 逻辑编译进主程序，通过现有 SSH 通道执行；没有 Python、远端采集脚本或新增分发依赖。开发探针不进入便携包。规则片段、备份和完整性清单是明确计划中的目标数据，不是另外分发的程序。

## 权限策略与恢复

这是一项有限的本机权限策略，不声明 CIS 或其他标准的完整合规。passwd/group 保留现有模式与 0644 的交集、属主 UID 0，属组采用本机 root 组；shadow/gshadow 原属 root 组时上限为 0600，原属 shadow 组时上限为 0640。不会扩大原有权限。未知口令文件属组须人工核实，不能一律改成 root:root。Debian 的 shadow 组用途见 [UserAccounts](https://wiki.debian.org/UserAccounts)。

检测读取完整文件摘要、属性和 ACL，不向页面返回账号/口令正文或内部摘要。要求普通文件、单硬链接、无路径符号链接、最多 1 MiB；getfacl 缺失、读取失败、扩展 ACL、重复/缺失 root/shadow 组信息均不能算通过。工具来自目标现有环境，不自动安装或提权。修改只支持当前 UID 0；扫描和生成计划不产生变更。

计划绑定目标及会话、完整内容摘要、设备/inode/硬链接数、原属性、组文件摘要和确切新属性。确认后先在既有 root 私有备份目录保存原件，再只修改属主/属组/模式；不重写账号文件。失败只在当前状态仍属于本次已知中间状态时尝试撤销，独立回读失败则明确保留未解决状态及日志。历史恢复核对全部证据，只恢复属性，不覆盖正文。后来改动文件内容、属性、身份或组定义会拒绝旧操作。

这些 Shell 检查不是原子事务，也不能防御拥有 root 权限的主动并发篡改。读取可能更新 atime；权限收紧可能影响原来依赖多余权限的程序。文件属性复核不是登录/业务恢复验收。

## auditd 的有限管理

只接受明确可用且未锁定的主机审计：auditctl 状态 enabled=1、daemon PID 非零、可读启动编号和受监控文件身份。要求现有 systemd-detect-virt 明确返回非容器结果，同时检查容器标记和 WSL 内核；工具缺失或无法判断环境也拒绝执行。容器、WSL、权限不足、停止或 immutable 状态保留缺口，不提供修改。这仍依赖目标本机工具与内核可信。

固定规则为四条 `-w /etc/<文件> -p wa -k lovelyhawk_auth`，保存于 `/etc/audit/rules.d/70-lovelyhawk-auth.rules`，root:root / 0600。同名非受管文件、其他 key 的重叠监控、目录级重叠、排除/never/task 规则及重复规则拒绝自动合并。规则较少不等于完整覆盖；现有规则复杂时保守留给人工核对。

计划绑定启动编号、daemon PID、四个文件的设备/inode、受管片段以及整个运行规则集。执行不使用 `-D`，不全量 reload、不重启或启动服务，仅增加缺失条目。保存片段不证明本机启动流程会读取它；读取到内核规则不证明审计事件成功落盘。规则语义和加载边界依据 [Linux Audit auditctl 手册](https://github.com/linux-audit/audit-userspace/blob/master/docs/auditctl.8) 与 [auditd 手册](https://github.com/linux-audit/audit-userspace/blob/master/docs/auditd.8)。

恢复只删除本计划新增条目；原先已有的本工具规则和所有其他规则保留。只在当时新建且内容/身份不变时移除本工具片段。失败恢复也核对当前规则是原集合与计划集合之间的已知状态；遇到无关变更、文件替换或无法读取则停止并报告。尚需专用 Linux VM/实机验证真实 auditctl 返回格式、内核接受、事件落盘、重启加载、磁盘/队列故障和不同版本组合。

## 进程观察与完整性边界

进程观察在读取环境、maps 前后比对 PPID、SID、启动时钟、exe 和 mount namespace；退出或变化丢弃关联。单进程即使没有预加载变量也展示映射上下文。全局入口只展开有变量线索的进程，保留原全局预加载文件检查。LD_PRELOAD、LD_AUDIT、LD_LIBRARY_PATH、PROMPT_COMMAND 只返回名称，不返回值；同一进程中同时出现变量和映射不证明加载因果，不能据此授权结束进程。一般采集字节/对象上限与缺口规则继续见 [工作台整合](RESPONSE_ENGINE.md)。

完整性只记录内容摘要与路径；选中缺失/不可读文件或 find/sha256sum 失败时整次采集失败，不保存不完整清单。选择 /etc 后再选其中认证文件会合并范围。其余既有完整性上限、取消及目标生命周期保持原行为，不将内容相同解释为权限安全或没有入侵。

## 实际验证与待验范围

开发入口（均无 Python）：

```powershell
pnpm ui:check
cargo test --locked -p lovelyhawk-core --lib
cargo test --locked -p lovelyhawk-backend -p lovelyhawk-desktop -- --quiet
cargo build --locked -p lovelyhawk-backend -p lovelyhawk-desktop
node tools/lab/probe-command-observations.mjs
node tools/lab/probe-auth-audit-fixture.mjs
node tools/lab/probe-auth-baseline.mjs
```

- 只读采集：Ubuntu 24.04.1、x86_64、WSL、POSIX sh 文件夹具 **35/35**，含启动时钟字段、无变量的单进程、已退出进程、采集期间 exe 改变。见 [采集报告](../target/lab-command-observations/2b5b0568-738c-423a-8c40-586f580202eb/report.json)。这不是 VM/实机兼容矩阵。
- 审计脚本：同环境的私有 chroot，模拟 auditctl，执行生产生成的脚本 **15/15**，覆盖增删、幂等拒绝、无关规则保留、片段变化、文件替换、部分失败恢复、锁定、读取失败与无法识别主机/容器。见 [规则报告](../target/lab-auth-audit-fixture/6e368e7d-deb6-48df-9e32-a45cdc73bcf8/report.json)。未操作真实内核规则；不得计作 auditd 实机通过。
- 权限与完整性：Debian 12 / x86_64 自建普通 Docker 容器，实际 SSH 首轮 **22/22**；容器 ID、镜像、标签、网络、零挂载及资源限制均先核实，结束只删除该 ID。见 [SSH 报告](../target/lab-auth-baseline/19fedb16-2c00-4292-923e-0db540a40ffe/report.json)。ACL 工具只在这个独有测试容器中显式安装；生产检测仍不安装工具。
- 最后一次实际 SSH / 调试 WebView2 联验 **34/34**（24 项 SSH/API 与 10 项桌面检查），观察起点 `2026-10-31T00:48:55.431Z`：权限计划、确认、修补、撤销、后续正文变化拒绝；扩展 ACL/缺工具拒绝；完整性四文件创建与比较、缺失文件拒绝；桌面完整流程、折叠预设与键盘、通知中心回执和 900px 窄窗口。Runtime/console/Log 错误 0，使用独立数据根，未修改用户连接库。见 [联验报告](../target/lab-auth-baseline/a8a4f9f3-fecf-4e76-af8d-1c306e9b5b02/report.json)、[权限界面](../target/lab-auth-baseline/a8a4f9f3-fecf-4e76-af8d-1c306e9b5b02/01-permission-panel.png)、[完整性窄窗口](../target/lab-auth-baseline/a8a4f9f3-fecf-4e76-af8d-1c306e9b5b02/07-auth-integrity-narrow.png)。最终调试宿主已重新构建。

UI 类型检查、143 文件 / **1189** 测试及构建通过；Core 库 **1286** 通过、12 忽略（[日志](../target/pr5-core-tests.log)）；Backend 库及独立 API 测试合计 **778** 通过，桌面宿主 **53** 通过、1 忽略（[日志](../target/pr5-backend-desktop-tests.log)）。补充 `baseline` 相关 104 通过、3 忽略，审计旧片段被替换后拒绝失败恢复也有独立回归。忽略项不计通过。Rust fmt、core/backend/desktop 全目标 clippy、source/dependency/ledger 普通门禁通过；没有放宽门禁。

失败证据保留：`target/lab-auth-baseline/14b5b23f-1b30-40de-b399-838939683df5` 的探针误点了上层“检查这台主机”，改用准确的“基线检查”标签；`2b593f7b-f9b9-424f-bee6-4f0cfbd203ec` 观察期发生页面切换及 DevTools CSP 错误，整轮失败；`8520da92-04ad-44c6-9c60-b759b706a243` 在 React 挂载前访问最小化按钮，改为等待现有连接卡片；`5f3cf884-f2a0-4df9-934f-66732ff25e88` 等待了已统一迁入通知中心的页面内提示，改为同时断言新增基线和通知中保留的成功回执。没有过滤控制台错误或恢复重复的局部提示来让探针通过。

其他发行版、BusyBox/musl、rootless、ACL/SELinux 组合、非 root 扫描以及真实 auditd VM/实机矩阵为待验证。Node 当前为 24.13.0，不满足指定 26.13.x；不能据此宣称 release 门禁完成。本轮不制作发布包，不改变长期 ledger 的 Pending 状态。
