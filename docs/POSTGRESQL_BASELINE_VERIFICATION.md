# PostgreSQL 基线检测与运行状态边界

“配置 → 基线检测”中的 7 个 PostgreSQL 项目读取常见路径内的候选配置。它们尚未关联实际实例、配置包含顺序、启动参数、数据库/角色/会话覆盖及当前连接，因此只报告风险线索或待复核，不将文件中的安全值显示为运行状态已符合。按实例修补与恢复仍待接通。

core 的 [PostgreSQL 原生连接](POSTGRESQL_NATIVE_RUNTIME.md) 已开始补齐真实认证与运行参数读取，并已接入桌面“数据库”页的参数检查（见该文），但尚未与本页的候选来源和修补流程接线。该连接的 `pg_settings` 观察不能改变本页候选检测的判断边界。

## 当前判断

| 项目 | 候选判断 | 后续必须核对 |
| --- | --- | --- |
| 监听范围 | 地址列表中的 `*`、`0.0.0.0`、`::` 和完整零 IPv6 地址保留为通配监听线索 | 实际监听、网络命名空间、业务网段和 HBA；远程业务不能一律改为 localhost |
| 口令存放 | 显式 `md5` 为线索；建议拼写为 `scram-sha-256` | 已有账号的口令类型、客户端兼容性和 HBA；修改默认算法不会转换已有口令 |
| 连接建立与断开日志 | 明确的 false 值及无歧义前缀归一为 `off` 线索 | 新会话的实际设置、日志内容与完整收集链路 |
| 语句日志 | 显式 `none` 为线索；`mod` 和 `all` 不因不同于 `ddl` 被直接判错 | 所需审计范围、扩展审计、性能和敏感内容处理；单个参数不能证明完整审计 |
| 日志持久留存 | `logging_collector` 的 on/off 均待复核 | `log_destination`、标准错误、syslog、容器日志驱动、轮转、容量与保留策略 |
| TLS | 显式 false 值保留为线索；`ssl = on` 仍待复核 | 证书与私钥、HBA、客户端验证及实际连接；提供 TLS 不等于所有连接必须加密 |

读取常见 `/etc/postgresql`、`/var/lib/postgresql` 和 `/var/lib/pgsql` 路径，包括 Debian 的 `main/conf.d/*.conf` 及常见数据目录中的 `postgresql.auto.conf`。各候选文件分别判断，不把路径排列当成实例配置的包含顺序，也不根据另一份安全配置清除已有风险。查看文件重新定位当前来源，所有候选行均不标为唯一生效项。

读取器按文件内最后一个标量处理大小写、可选等号、单引号、成对单引号与行尾注释；引号内的 `#` 是数据。结果只输出有限风险标记，不输出任意配置值。需要原生解析的转义、破损语法、超过 16 KiB 的物理行或超过 512 KiB 的文件保持待复核，不输出之前读到的部分结论。值和来源读取都使用 `LC_ALL=C`，使 GNU awk 在中文环境中同样按字节实施上限。没有候选文件也不套用某版本的默认值。

长操作建议自动换行，文件区保留最小阅读高度并可独立滚动；完整配置不会因说明较长而缩成一条滚动条。配置中的 HTML 字样只按文本呈现。

## 修改与恢复

core 拒绝新的 PostgreSQL 通用写入请求。通用写入器不能证明实例身份、真实主配置、include、`postgresql.auto.conf` 和启动参数的关系，也没有数据库运行值与业务连接复核；不能用它猜测写入位置或统一重启服务。

修改前应核对实际实例的 `pg_settings`、`pg_file_settings` 及来源；`postgresql.auto.conf` 由 `ALTER SYSTEM` 管理，不直接覆写。`listen_addresses` 和 `logging_collector` 需要实例重启，其他项目也必须按实际上下文重载并用新会话独立检查。计划必须包含精确目标、差异、业务影响、完整备份、确认、原生验证、运行值与业务检查、失败恢复。历史文件恢复的已实现条件和限制见 [基线历史恢复](BASELINE_RESTORE_VERIFICATION.md)。

修正目录语义时保留旧审计记录：历史 `logging_collector` 的 `on/off` 和旧目录接受过的 `scram_sha_256` 按原值、原摘要读取，不静默更正。兼容规则仅用于历史校验，新的写入请求仍被拒绝；缺少修改后完整文件证据的旧记录也不能授权覆盖恢复。

## 复现与证据

```powershell
cargo test --locked --package lovelyhawk-core --package lovelyhawk-backend
cargo build --locked --package lovelyhawk-backend --bin lovelyhawk-backend
pnpm ui:check
pnpm desktop:build
node tools/lab/probe-postgresql-baseline.mjs
```

探针复用本地 `lovelyres-svc:postgres` 镜像，新建唯一容器和临时应用数据目录。逐次核对 ID、名称、镜像、运行标签、网络和挂载；限制为 512 MiB、1 CPU、128 个进程，数据目录使用 256 MiB tmpfs，无宿主挂载或特权。只将 SSH 发布到 WSL 私有地址的随机端口，不导入用户连接库。

原生 `postgres -C` 对照候选读取器；真实 `pg_settings` 对照文件已改但未重载、`ALTER SYSTEM` 覆盖主配置等情况。探针还使用 WSL 已安装的 GNU awk 检查短中文注释、超长中文行及文件字节上限，不向目标安装软件。后续通过真实 SSH/RPC 和正常桌面入口验证来源、待复核说明、日志建议、最小窗口和断连清理；观察到的启动和运行时错误均算失败。Electron 时期的探针从 inspector 连接时开始观察 main 控制台，实际主文档加载后再连接 renderer CDP。

容器内写文件、调用 SQL 和 `ALTER SYSTEM` 用于构造独立测试输入，不能计为应用已完成数据库修补。报告保存原生结果、实际版本、镜像摘要、截图和失败材料；已记录的执行结果（Electron 时期）见 [长期进度](PRODUCT_ROADMAP.md)。其他 PostgreSQL 版本、架构、集群/容器部署、完整 HBA 与账号迁移，以及 openGauss 等衍生产品均需独立适配和验证。

## 官方依据

文件语法、包含关系、覆盖顺序及运行时配置见 [PostgreSQL 16 参数设置](https://www.postgresql.org/docs/16/config-setting.html)；日志去向、收集器与语句日志见 [PostgreSQL 16 日志配置](https://www.postgresql.org/docs/16/runtime-config-logging.html)。监听、TLS 与重启条件见 [PostgreSQL 16 连接配置](https://www.postgresql.org/docs/16/runtime-config-connection.html)，口令算法与迁移见 [PostgreSQL 16 口令认证](https://www.postgresql.org/docs/16/auth-password.html)。这些依据不替代目标版本和实例的实际检查。

GNU awk 在多字节字符环境中按字符处理字符串，见 [GNU awk 的字节与字符说明](https://www.gnu.org/software/gawk/manual/html_node/Bytes-vs_002e-Characters.html)。本次同时用 GNU Awk 5.2.1 的中文输入对照实际字节上限，具体结果保留在探针报告中。
