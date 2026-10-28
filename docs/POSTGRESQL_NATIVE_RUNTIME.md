# PostgreSQL 原生运行检查连接

`DatabaseService::read_runtime_parameters` 的 PostgreSQL 分支通过已确认的 SSH 连接打开 `direct-tcpip` 通道，在 core 内使用 PostgreSQL 协议完成认证和读取。身份查询、`pg_settings`、会话/来源及访问诊断查询来自闭合计划，并在同一个数据库连接中执行。目标不需要安装 `psql`，数据库密码不进入远端命令、环境变量或临时客户端配置。

桌面应用的“数据库”页现已接入 PostgreSQL 原生参数检查：连接配置编辑、只读任务、取消、分页、新手观察说明、服务端报告的会话/配置来源，以及检查摘要留证；当前文件 HBA/ident、角色直接属性和口令标识诊断现也接入同一任务，详见 [访问诊断](POSTGRESQL_ACCESS_DIAGNOSTICS.md)。具体实测记录（Electron 时期）见文末桌面验收。通用 SQL、账号管理、插件清单、配置写入和恢复未开放；整个数据库迁移项继续保持 Pending。候选基线仍遵守 [PostgreSQL 基线边界](POSTGRESQL_BASELINE_VERIFICATION.md)。

## 连接和凭据

- 连接复用 core 加密的数据库配置库；新 PostgreSQL 配置默认用户名为 `postgres`。旧配置缺少 `postgresql_tls` 时仍可反序列化，序列化时不增加空字段，从而保留旧摘要比较语义。
- 默认 `verify-full`，验证服务器证书链与所填主机名/IP，最低 TLS 1.2。系统信任库之外可以明确添加一份不超过 64 KiB 的公开 CA PEM；不接受私钥、多个 PEM 块或跳过验证的标志。TLS 主机名同时交给 `Config` 和 TLS connector；`connect_raw` 仅使用已打开的 SSH 流。
- 显式 `ssh-loopback` 模式只接受 SSH 目标后方的字面回环 IP，例如 `127.0.0.1` 或 `::1`，不能以 `localhost` 或其他 DNS 名称扩大此范围。此模式仅有 SSH 链路保护，数据库 TCP 段不启用 TLS；不会因证书失败自动切换模式。
- 本次密码认证支持 SCRAM-SHA-256 与 MD5 挑战；服务端要求明文密码、GSSAPI 等其他认证方式时，在驱动发送凭据前拒绝。不会为了连接成功而修改真实目标的 HBA 或账号。
- 自有秘密类型、协议帧缓存和解析用 TSV 使用清零包装。原生认证库仍会复制密码，不能宣称第三方内部缓冲都已清零。公开错误不包含数据库错误详情、认证载荷或服务器自选通知；未知运行值继续使用现有受限解析与脱敏。

## 生命周期和读取范围

连接、认证、查询和驱动均由同一个 SSH actor 任务持有，没有游离的数据库驱动任务。操作继承该 actor 的并发、排队、会话身份和取消机制。数据库服务在等待中每 100 ms 核对目标代次与配置摘要，完成和展示前再次核对；断连、丢弃请求、目标切换和配置编辑后的旧结果均不能接受。

| 边界 | 当前值 |
| --- | --- |
| actor 操作总期限 | 40 秒，沿用既有排队/取消行为 |
| 连接和认证 | 12 秒 |
| 会话默认只读 / SQL 搜索路径 | `default_transaction_read_only=on` / `pg_catalog` |
| 单条语句 / 锁等待 / 空闲事务 | 20 秒 / 3 秒 / 5 秒 |
| 成功后的连接关闭确认 | 2 秒 |
| 传输累计读 / 写 | 16 MiB / 256 KiB，包含 TLS 流量 |
| 单协议帧 / 认证帧 | 1 MiB / 16 KiB |
| SCRAM 迭代次数 | 1–1,000,000，交给驱动计算前核对 |
| 额外通知 | 最多 64 条，计数并丢弃正文 |
| 身份 / 运行结果 | 1 行、4 KiB / 最多 16,384 行、4 MiB 的受限 hex-TSV |
| 每次会话/来源结果 | 1 行、128 KiB hex-JSON；参数读取前后各一次，有权限时各增加一次 41 字节以内的集群标识查询 |
| 来源路径 / 来源类别 | 每项最多 2,048 / 128 UTF-8 字节，超限拒绝整个观察 |

丢弃流会关闭 SSH 通道，当前没有另发 PostgreSQL `CancelRequest`。服务端正在等待或执行的 SQL 可能持续到其锁/语句时限，所以不能把本机取消完成说成数据库语句立即退出。独立实验使用实际锁等待并从 `pg_stat_activity` 确认连接退出。超时依赖正常 PostgreSQL 遵守会话设置；不可信服务端仍受本机传输、帧和总期限限制。

运行行包括设置、作用域、来源类别、上下限、枚举及 `pending_restart`。它们反映当前服务器/会话观察，可补充下述服务端集群标识和会话诊断，但尚未构成 SSH 主机上实际进程身份、完整配置图和业务健康证明。现有身份解析只拒绝已知不兼容签名并核对版本；可伪装版本的服务器不能被称为已证明“非 fork”。当前不能用这些行自动授权修补或覆盖 `postgresql.auto.conf`。

真实 Debian 软件包的版本包含发行版标签，解析器接受受限的 Debian/Ubuntu 包格式并核对其中的上游版本；这不扩大版本注册表。PostgreSQL 的 `ssl_max_protocol_version` 枚举包含合法的空字符串，表示不限制最高协议版本，解析时保留该选项并与空值/缺失区分。MariaDB 逗号清单中的空洞仍拒绝，控制字符和元数据上限也保持不变，参见 [PostgreSQL 16 SSL 参数](https://www.postgresql.org/docs/16/runtime-config-connection.html#GUC-SSL-MAX-PROTOCOL-VERSION)。

原生 PostgreSQL 路径只允许展示已审查的有限标量：SSL/日志布尔开关、口令算法名、语句日志级别、TLS 协议名和少数明确监听形式。名字与值都必须精确匹配，不能使用服务端自报的类型或枚举来授权任意文本；其他值保留脱敏和存在状态。原有远端客户端 TSV 入口仍保持全部值脱敏。`default_transaction_read_only` 是本次检查会话设置，不能据此推断其他业务连接只读。

## 复现与验收

```powershell
cargo test --locked --package lovelyhawk-core postgresql_ --lib
node tools/lab/probe-postgresql-native.mjs
```

探针先检查 WSL Ubuntu 和缓存的 `lovelyres-svc:postgres` 镜像，只创建带本次 UUID 标签的独立容器与临时数据根。512 MiB 内存、1 CPU、128 进程、256 MiB 数据 tmpfs，无宿主目录挂载；只向 WSL 私有地址发布两种 SSH 测试端口。第二个 sshd 禁止 TCP 转发。测试自行签发证书，但不写入操作系统信任库。

如果 WSL 与 Windows 时钟存在偏差，探针记录证书 `notBefore` 与客户端时间，等待新证书在 Windows 客户端生效后再开始连接；不修改系统时钟或关闭有效期校验。

真实 core 用例在默认单测中明确忽略，只有探针通过独有 SSH 配置和运行标记后才显式执行；缺少环境不会以成功退出代替测试。夹具创建 SCRAM/MD5 账号、改变权限、临时锁住目录视图和关闭 SSL，均只用于构造测试条件，不能算产品数据库写入能力。

报告位于 `target/lab-postgresql-native/<run-id>/report.json`，附代码/依赖摘要、实际版本、服务日志和 core 输出；具体通过数量及失败记录见 [长期进度](PRODUCT_ROADMAP.md)。其他 PostgreSQL 版本、Windows 之外的 TLS 实现、客户端证书、GSSAPI、多级 CA、代理/高可用切换和衍生数据库均仍需独立验证。

## 桌面边界

链路为 `database.rs` / `postgresql_native.rs` → `postgresql_runtime_api.rs` → 单个 `postgresql.runtime` RPC / `postgresqlRuntime` API → `DatabasePage`。页面桥接层（`ui/src/host/main-api.ts` 与 `backend-client.ts`）直接使用 shared 契约校验请求和响应的精确字段与字节数，宿主只把白名单内的 `postgresql.runtime` 交给进程内后端；过期、并发冲突、容量或配置错误以有限 `rejected` 结果返回并显示给用户，不把正常业务拒绝变成宿主调用异常。

- 每个新连接显式关联当前 SSH 连接。旧配置缺少关联时可查看和编辑，保存关联前不能开始读取。地址从 SSH 主机访问，界面说明回环地址的含义；不会自动把另一台主机的连接移过来。
- 保存使用 core 不可变配置版本，在同一后端配置库锁内做比较和写入，包含加密口令变更；删除准备本机配置的不可变计划，两分钟内逐次确认，执行后 journal 和回读核实。删除状态未知时要求刷新，不宣称“未删除”。新建响应不确定时应先刷新确认是否已保存，不能盲目重复创建。
- 口令仅保留、替换或移除，不回传。CA 是公开证书文本，页面不经手本机路径。保存/离开后清除输入；脏编辑参与导航、连接管理、断连和关闭握手，等待正在保存的结果。
- core 配置库最多 256 个连接、8 MiB 文档、16 KiB 单个口令；文件过大、重复身份和并发变化均拒绝，保留原有字节。此上限覆盖配置库中的所有数据库类型。
- 后端最多保留四个 SSH 目标条目，每个目标一个读取任务和一个待删除计划。参数结果只存内存，十分钟内按原目标和配置版本取用；切换、断连、旧句柄或版本变化后失效。尚未保存的摘要在参数过期后继续保留，需重试或明确放弃；案件中的已保存记录不受参数过期影响。任务总期限和语句时限沿用上文核心边界。
- 新手视图解释十种有限观察值及局限；专家视图按参数名搜索，每页最多 50 行、总数最多 16,384。来源、生效范围和待重启状态可见。长元数据截断时标明；空枚举仍显示“（空值）”。输出最多 512 KiB，不回传秘密值、凭据摘要或内部参数指纹；已保存案件记录可展示其 SHA-256 及摘要范围。
- 数据库页面已接线不代表实例配置图、已加载 HBA、业务认证和完整基线通过。检查摘要已接入案件；其他数据库原生认证、完整配置取证、按实例修补、恢复与业务复检继续在长期任务中推进。

## 服务端会话与配置来源

闭合查询读取当前数据库与 OID、登录/执行身份、会话 PID、服务端/客户端地址和端口、服务启动时间、会话报告的配置加载时间、恢复模式及服务端观察时间（UTC）。有 `pg_control_system()` 执行权限时才发送独立查询读取集群标识；无权限时只发送不调用该函数的基础查询，避免 PostgreSQL 初始化未选中 CASE 分支时仍检查函数权限；保留明确缺口，不通过提权补读。函数含义见 [PostgreSQL 16 会话与控制数据函数](https://www.postgresql.org/docs/16/functions-info.html)。这些信息不是 SSH 主机上的进程授权；代理、端口转发、容器 PID 命名空间和复制集群还需另行关联，会话连接结束后 PID 也不能用作处置依据。

页面展示服务端报告的 `config_file`、`data_directory`、`hba_file`、`ident_file`，及十项重点参数的 `sourcefile`、`sourceline` 和待重启状态。路径来自数据库的观察，不读取路径指向的文件、不生成通用路径操作。`pg_settings` 的来源字段会因权限不足或值来自其他来源而为空；`pg_read_all_settings` 可补充来源可见性，但不等于获得集群控制函数权限，见 [PostgreSQL 16 pg_settings](https://www.postgresql.org/docs/16/view-pg-settings.html)。

参数读取前后分别读取会话/来源，比较身份、地址、启动/加载时间、路径及重点参数来源，并与参数结果交叉核对来源和 `pending_restart`。`pg_settings` 对当前账号隐藏的参数在来源查询中保留完整空值，仅当两次来源与参数结果都一致缺失时接受，并在新手页面、专家表格及留证摘要中明确标记未取得；不能把未知状态写成“否”或合规。变化、观察与参数结果不一致、缺少必需字段、越界、非法编码或不完整结果均拒绝；时间回拨本身不作为实例变化。本检查不声称数据库或磁盘的原子快照，也不把未经重载的磁盘修改当作运行值。这些来源观察不代表完整 include 图、命令行或 `pg_file_settings`。当前文件 HBA/ident 与角色直接属性诊断另见 [访问诊断边界](POSTGRESQL_ACCESS_DIAGNOSTICS.md)；成员授权与静态角色路径已接入；实际已加载策略和具体对象授权仍未取得，不能凭这里的路径进入修补。

主机进程对应现也接入同一读取流程，见 [对应依据与边界](POSTGRESQL_PROCESS_CORRELATION.md)：在 SQL 连接存活时核对完整 socket、父子进程、pidfd、可执行文件和相同命名空间，之后再核对 SQL 身份。对应失败保留参数及明确原因；成功也不授权后续文件/进程操作。该只读检查要求目标已有相应工具与权限，产品不自动安装或提权。

## 检查摘要留证

- 普通“读取生效参数”仅观察；“读取并留证”在开始时取得当前采集案件（未选择时创建），持有案件采集占用直到结束和保存。检查成功、失败或用户取消都会生成对应结果记录。数据库只读查询仍可能产生连接/审计日志。
- 新摘要使用 `postgresql-runtime-summary/v4`，包含观察编号、开始/结束 UTC、实际 SSH 来源、请求数据库、结果；完成时增加数据库会话身份、传输方式、主机进程对应状态及可执行文件摘要、参数/通知数量、十项有限公开参数和访问诊断数量/提示代码、成员授权数量和静态角色路径分析状态。旧 v1 / v2 / v3 记录保持原文。**不包含全部参数、配置内容、来源路径、完整 HBA/ident、角色明细或秘密值**。不以摘要代替完整配置取证。
- 案件记录上限沿用 4,096 字符；无法在限额内完整生成摘要时明确显示未留证，不能截断后宣称保存完整。案件 SHA-256 校验保存记录及其元数据，不是原始 PostgreSQL 流量或远端文件摘要；案件入库时间与正文中的观察时间分开。
- 本机写入、案件容量或状态失败时保留同一摘要、观察编号和已取得的归属案件。重试只补存原记录，幂等返回相同证据编号，不重新连接数据库，也不随当前采集案件变化迁移旧观察。如果开始时未能取得案件，则明确告知重试采用届时的采集案件。
- 未保存摘要阻止新的数据库读取和配置替换，提供展开/全选复制、重试与明确放弃。导航、断连和真实窗口关闭先处理正在进行的操作，再确认未保存摘要；取消离开保留页面。参数过期或本机连接被外部编辑后，历史摘要仍可补存；新的远端读取仍要核对当前配置版本。
- 保存成功的摘要可在案件工作台、时间线与固定快照报告中查看，既有本机案件库负责离线持久记录。未保存摘要仍属于当前进程内存；意外退出、强制终止或失去目标后的恢复还未实现。

复现桌面验收前构建当前代码：

```powershell
cargo build --locked --package lovelyhawk-backend --bin lovelyhawk-backend
pnpm desktop:build
node tools/lab/probe-postgresql-native.mjs --desktop
```

以下桌面验收均在 Electron 时期完成，不能直接当作 Tauri 桌面壳的验收结果。主机进程阶段的桌面实测为 PostgreSQL 16.15 / Debian 13 / x86_64，**69/69**，启动、preload 和页面控制台错误 **0**，见 [进程阶段报告](../target/lab-postgresql-desktop/6c681078-9238-4fcf-a0ea-3882b449b4e2/report.json)。包括服务端会话/参数来源、受限角色、保存与退出保护，以及新增的同命名空间主机进程对应。28 个源码摘要在验收复核时全部匹配；测试口令检查覆盖 JSON 引号与 Unicode 转义，独立查询确认本轮容器无残留，见 [证据复核](../target/goal-20260907/postgresql-process-verification.json)。早期 39 项和 62 项桌面验收作为各阶段历史证据保留。

桌面模式复用同一受限容器准备，启动正常桌面入口（Electron 时期为 Electron `.` 入口，先从 main 观察启动错误，真实主文档就绪后才连接 renderer）。探针只观察数据库 IPC 的动作名称与目标句柄，不记录口令、不替换产品处理器结果；本机调试器用于输入、截图和隔离窗口关闭。报告保存在 `target/lab-postgresql-desktop/<run-id>/report.json`，失败记录与最终验收见 [长期进度](PRODUCT_ROADMAP.md)。

## 原始依据

证书链与主机名验证语义参考 [PostgreSQL 16 SSL 文档](https://www.postgresql.org/docs/16/libpq-ssl.html)；本模块使用 `native-tls` 而非 libpq，系统信任与验证实现见 [native-tls](https://github.com/rust-native-tls/rust-native-tls)。认证方法见 [PostgreSQL 16 口令认证](https://www.postgresql.org/docs/16/auth-password.html)，语句和锁时限见 [PostgreSQL 16 客户端会话默认值](https://www.postgresql.org/docs/16/runtime-config-client.html)。原生流接口与 TLS 包装见 [tokio-postgres](https://docs.rs/tokio-postgres/0.7.18/tokio_postgres/config/struct.Config.html#method.connect_raw) 和 [postgres-native-tls](https://docs.rs/postgres-native-tls/0.5.3/postgres_native_tls/)。


访问诊断与详情焦点完善后的最终桌面验收（Electron 时期）为 **94/94**，同为 PostgreSQL 16.15 / Debian 13 / x86_64，控制台 0 错误。见 [访问诊断报告](../target/lab-postgresql-desktop/6be33e26-486f-4d98-8ebd-663f209a465c/report.json) 和 [访问诊断边界](POSTGRESQL_ACCESS_DIAGNOSTICS.md)。37 个关键源码摘要匹配，原有连接、参数、进程与留证回归继续通过；其他版本和完整修补恢复仍待实测与实现。

后续成员授权与静态角色路径扩展在 Electron 时期的完整桌面验收为 **110/110**，见 [最终报告](../target/lab-postgresql-desktop/bbaa35ba-b046-4345-be1d-93e080868e95/report.json) 和 [独立复核](../target/goal-20260907/postgresql-membership-verification.json)；现行新增留证为 v4，原有 v1/v2/v3 保持原文。角色路径、超级用户区别与所有者上下文的范围见 [访问诊断](POSTGRESQL_ACCESS_DIAGNOSTICS.md)。
