# PostgreSQL 与 SSH 主机进程对应

数据库页在原生连接仍存活时核对 Linux 进程。新手先看是否已对应，以及数据目录是否一致；专家可展开 PID、启动 ticks、主机启动标识、socket inode、命名空间及可执行文件路径/摘要。不能对应时参数仍可读取，并显示具体缺口。此步骤提供采集时的实例线索，后续配置采集、修补和恢复仍须独立核对目标与状态。

## 对应依据

1. 从同一 PostgreSQL 原生连接取得后端 PID、服务端和客户端地址/端口，以及有权限时的数据目录；不接受页面传入任意 PID、路径或程序。
2. 通过该 SSH 连接发送内嵌的固定 Python 检查程序。先以 pidfd 持有会话进程和 `/proc/<pid>/stat` 报告的父进程，确认存活。
3. 要求会话、父进程和检查程序处于相同 PID、网络及挂载命名空间。按数据库报告的完整连接两端，在 procfs TCP/TCP6 中找到唯一 ESTABLISHED 项，并核对它的 inode 确实出现在该会话进程的 fd 中。只有数字 PID 或端口相同不能通过。
4. 核对父子进程使用同一个可执行文件设备号/inode，从父进程的 `/proc/<pid>/exe` 读取并计算 SHA-256；不执行该程序，不读取 argv、环境变量或配置内容。检查前后核对文件属性、进程启动 ticks、命名空间、工作目录和 socket，确认 pidfd 未报告退出。
5. 记录父进程工作目录，并与数据库报告的数据目录作明确比较。数据库未提供目录时记为未知；不同路径或符号链接别名不能因推测而变成一致。未跟随数据库报告的任意路径去读取主机文件。
6. 主机检查后再次读取 SQL 会话/来源，与检查前及运行参数交叉核对；身份或配置来源变化使整次参数结果失效。

依据：[Linux procfs 文件描述符](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)、[进程 stat 字段](https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html)、[内核 TCP procfs 格式](https://www.kernel.org/doc/Documentation/networking/proc_net_tcp.txt)、[PostgreSQL 16 进程架构](https://www.postgresql.org/docs/16/tutorial-arch.html)。这些资料解释读取格式和关联方法，不代表每个 Linux 环境已实测。

## 边界与用户反馈

- 要求目标已有 Python 3.9+、Linux pidfd 与必要的 procfs 读取权限。产品不安装 Python、不改变 capabilities、不提权。无工具、无权限、进程退出、namespace/socket 不匹配、可执行文件异常、超限或非法输出分别保留为未完成原因。
- 内嵌程序以 `python3 -I` 运行；输入最多 8 KiB，输出最多 12 KiB，错误流最多 4 KiB。每份 TCP 表最多 2 MiB，总计最多 16,384 项；会话最多 4,096 个 fd；可执行文件最多 64 MiB。程序自身六秒期限、SSH 八秒期限，整体原生读取仍受四十秒限制与目标/配置取消约束。
- 读取可执行文件可能影响访问时间与目标负载；数据库连接可能产生审计日志。命令、口令、环境和完整配置不会进入此观察或页面。错误使用有限原因，不回显目标程序的错误正文。
- 数据库地址可能位于其他主机、代理或容器中。只有本次确实满足对应条件时才展示已对应；失败不能证明数据库不存在或没有风险。跨命名空间映射、代理连接复用及其他平台仍需独立适配和验收。
- 对应结果是历史观察。进程可能随后退出、PID 可能复用、文件可能替换；不能将它直接变成重启、结束进程、文件写入或回滚权限。目录一致也不能证明完整 include 图、HBA/ident、启动参数、配置生效或业务健康。
- “读取并留证”的新记录使用 `postgresql-runtime-summary/v2`：增加主机对应状态、采集时间、启动标识、父子进程及可执行文件 SHA-256，仍不包含来源路径或配置正文。旧 v1 记录保留原文。保存失败、原案件补存、幂等、过期和退出保护继续沿用 [检查摘要约定](POSTGRESQL_NATIVE_RUNTIME.md)。

## 验证

```powershell
python -B tools/lab/test_postgresql_process.py
cargo test --locked --package lovelyhawk-core --package lovelyhawk-backend
cargo build --locked --package lovelyhawk-backend --bin lovelyhawk-backend
pnpm ui:check
pnpm desktop:build
node tools/lab/probe-postgresql-native.mjs --desktop
```

桌面实验只在新建并核实归属的 PostgreSQL 容器中安装 Python，并赋予同容器进程读取所需的 `SYS_PTRACE`；无宿主 PID/网络空间、无宿主目录挂载、非 privileged。这些夹具准备不计产品安装或提权能力，也不代表普通/rootless 容器默认拥有相同权限。探针比较独立读取的主进程、二进制摘要与 namespace，另用单独保持的 TCP 会话验证正确对应、错误端口、错误 PID 和受限账号；临时缺少工具时通过正常桌面页面验证参数仍可读取。

以下结果为 Electron 时期记录。最终原生桌面 **69/69**，启动、preload 和页面控制台错误 **0**，见 [验收报告](../target/lab-postgresql-desktop/6c681078-9238-4fcf-a0ea-3882b449b4e2/report.json)。实测 PostgreSQL 16.15 / Debian 13 / x86_64、Python 3.13.5；同一次主机启动的 WSL2 内核为 `5.15.167.4-microsoft-standard-WSL2`。Rust core/sidecar **1,772 通过、10 忽略**，Electron **133 文件 / 932 测试**，procfs Python 测试 **6/6**；类型、构建、Clippy、源码门禁和格式检查通过。其他 PostgreSQL、Python、内核版本与 rootless/跨命名空间组合未因此算作通过。

[独立证据复核](../target/goal-20260907/postgresql-process-verification.json)记录 28 个源码摘要全部匹配、九张原生截图、未检出转义或明文测试口令，以及本轮三次容器的清理。初次 Docker capability 名称差异与补充测试账号被 HBA 拒绝的失败均保留，详见 [长期进度](PRODUCT_ROADMAP.md)。
