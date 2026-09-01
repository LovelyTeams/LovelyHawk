# 原生功能接线与限制清单

本清单记录 Electron 迁移中尚未中央接线的模块，以及虽已中央接线但因安全契约、完整 parity 或实机证据不足而继续保持 Pending 的能力。

新增实现如果不能在同一变更中完成 UI 接线，必须登记：crate 路径、领域 owner、缺少的 entity/lifecycle/render 或窗口接线、目标绑定要求，以及可验证的完成条件。

## 已实现但未接线

- Linux 安全基线的 mutation/recovery Phase 2（领域 owner：`lovelyres-core::baseline`）仍未接线；只读
  Phase 1 已经进入中央 `BackendState`、固定 RPC/IPC、frozen preload、`App` registry 与 `BaselinePage`。
  当前公开面精确为 `getBaselineCatalog()`、`scanBaseline(bindingHandle)`、
  `listBaselineHistory(bindingHandle)` 三个 typed 方法；页面只接收 opaque `bindingHandle`，不接收 target
  summary、session、guard 或 generation。Rust adapter 只调用 `BaselineService::catalog/scan/list_history`，
  扫描使用共享的真实 `BoundSshSession`，请求前后复核完整 target scope；统一 SSH disconnect 在真实断开前
  调用 `close_binding`，只清该 binding 的 scan/history capabilities，迟到结果失败关闭。
  公开 DTO 只含 opaque item/snapshot handles、安全目录元数据、观察值/合规结果及历史摘要；raw record、
  operation、backup、digest、file/remote path、target/session/guard/generation 和 check/apply/verify shell
  均不进入 renderer。portable history 在 serde 前有 4 MiB encoded-byte cap，exact 257 records 硬拒绝、
  exact 256 合法，list/insert/lookup/transition 统一使用 fail-closed loader。目录、状态、历史分别最多
  64/64/256 项，响应最多 256/256/512 KiB；registry 最多 12 项/4 MiB、TTL 五分钟，并限制全局 4 个和
  每 binding 1 个并发读取。credential-like 值整字段遮蔽，hostile 文本只作为 React text node 渲染。
  Renderer 已覆盖分类、筛选/搜索、history、loading/error/empty/truncated、activate/deactivate、scope change
  与 late-result cleanup，且没有 plan/confirm/execute/restore/reload/file/terminal/export/AI 入口。
  当前 Electron-native CDP PASS 证据为
  `target/electron-debug/526e344c-a5f5-499d-9a17-ab4c0bf4defe/evidence`：该运行早于 Log Analysis 中央接线，本地目录 38 项、
  forged/unknown scan/history 拒绝且不回显、断连页/重挂载空态、本地资源、`capturePage` 和 0 console
  errors 均已验证。此前 `c7f9b277-006c-4f00-9fb1-7c503928d857` 运行是 `FAIL`，不可引用为通过证据。
  Phase 2 immutable plan/exact confirm/verify/restore 仍为 `UNWIRED`；真实 Linux/OpenSSH、实际 scan/history、
  权限/取消/断连竞态与 target-switch 成功矩阵仍为 `NOT_RUN`，因此页面整体 ledger 状态继续为 Pending。

- `lovelyres-core::apache_runtime` 与 `lovelyres-core::apache_capability`（领域 owner：
  `lovelyres-core`）已经完成 Apache Evidence Seal Phase A。运行时证据合同以完整 `TargetGuard`、
  systemd unit/InvocationID、MainPID、进程 starttime、规范化可执行文件路径与 SHA-256、ExecStart、
  NUL argv、effective environment 和按顺序读取的 EnvironmentFile 内容摘要为绑定，并保留重复且有序的
  `-d/-f/-D/-C/-c` 参数种类。原始 argv、环境和 EnvironmentFile 内容只进入 core 的有界
  `Zeroizing` 构造边界；`Debug`、错误和公开 getter 不返回原文。该构造器以及裸运行时/图 SHA-256
  构造器均为 crate-private/test fixture，外部调用方不能再用任意 64 位十六进制字符串铸造 capability
  绑定。构造器只校验形状、边界与摘要绑定，本身不证明采集来源；未来 provider 还必须证明 ExecStart
  executable 与 MainPID 的 `/proc/<pid>/exe` 指向同一个规范化可执行文件并绑定其摘要，wrapper 或任意
  不匹配必须成为 typed `UnsupportedWrapper/Unavailable`，不得降级猜测。
  `ApacheConfigGraphEvidence` 使用版本化、长度前缀编码绑定 core 持有的文件、include 解析结果及目录
  清单；`ApacheStableConfigGraphEvidence::seal` 只接受 invocation、guard 与全部图 item 完全相同的
  before/after 端点。它只证明两个采集端点相同，不宣称远端文件系统在区间内原子不变。
  `httpd -M` 已加载模块和 `httpd -L` 静态指令证据解析仍保持有界；`-L` 仍明确为 `StaticOnly`，缺失
  项不能显示成“不支持”。快照现在只能从同一 runtime evidence、matching stable graph evidence 和
  有界输出构造。
  当前没有 systemd/`/proc`/EnvironmentFile provider，没有分离 stdout/stderr、exit=0、超时/取消/截断
  完整状态的精确 `httpd -M/-L/-t` transport，也没有 Electron 页面 capability 接线。普通合并 stderr、lossy
  UTF-8 或字符串 shell 重放（尤其任意 `-C/-c`）不得作为替代。真实 Linux 的 Debian/Ubuntu
  apachectl+envvars+symlink、RHEL/Rocky direct-httpd、自定义 wrapper/drop-in、PID/restart/权限竞态和
  include/glob 组合均为 `NOT_RUN`。
  远程 middleware 已有实例发现、有界 `Include`/`IncludeOptional` 图、原生 `-t`、逐文件及目录清单
  CAS、备份、验证和恢复；但旧运行时字符串指纹及重建的 `-t -d -f` 尚不能证明与服务的真实有序调用
  上下文等价。因此 Phase A 明确关闭 Apache 远程 plan/execution，只读发现和候选配置图不受影响，
  Nginx 变更路径不受影响。完成接线前 capability 与 Apache mutation 都不得显示为已运行或已验证。

- `lovelyres-core::database_config_sources`（领域 owner：`lovelyres-core`）已经提供目标绑定、产品/
  组件/工件精确绑定的配置来源与优先级图，覆盖文件、include、命令行、环境变量、服务管理器、
  运行时 SQL、自动生成态、厂商工具、云 API 与内建默认值；未知/冲突/未解析来源会阻止生成
  effective view，绝不默认文件最高优先级。该模块尚未接目标发现 provider、页面或实际来源回读。
  完成条件是逐产品从同一 `TargetGuard` 构建完整来源图，回读每个来源摘要/版本，展示 unresolved
  barrier，并覆盖 include 环、并发变化、迟到结果、命令行/环境覆盖与秘密不进入 UI/日志。

- `lovelyres-core::postgres_auth_schema`（领域 owner：`lovelyres-core`）已经提供原生 PostgreSQL
  16/17/18 的静态 HBA/ident 方法、选项和交叉字段语义；未知方法保持可见未知，未知选项保持目标
  依赖。它尚未接入 line parser、配置生成器、目标 capability 回读，也没有用目标端
  `pg_hba_file_rules`/`pg_ident_file_mappings` 校验。完成条件包括绑定 `TargetGuard`、读取目标能力与
  诊断视图、运行目标端验证，并拒绝目标切换后的迟到结果。

- 配置生成器与远程 middleware 树（领域 owner：Electron config-generator 页面）已经接入只使用安全名称/静态说明
  的本地搜索、父链过滤和逐项说明；配置生成器还展示完整已审 schema 参数目录，包括文件中未出现项。
  统一目标入口现已覆盖 4 个 middleware 和 33 个数据库产品：Nginx 有静态站点、反向代理与路径 403 三个
  typed 本地配方；Apache 2.4 有路径及子路径 `Require all denied`、禁用 TRACE（405）和减少版本信息暴露三个
  本地配方，后两项仍未运行目标 `httpd -t`、模块能力或真实请求验证。18 个版本化数据库 schema 的参数可按
  canonical 名称、已审说明及闭合中英文意图搜索，并有远程访问、慢查询、TLS、审计、连接容量、查询超时、
  事务持久性、密码存储、连接准入、空闲会话保护与连接事件日志十一组多步骤检查清单。只有 `Public`、无
  capability、允许本地草稿且通过 typed validator
  的参数能显式加入本地草稿；其余只显示 `CatalogGuidance`。闭合的一行赋值语法支持产品、版本、可选
  `@artifact-key`、可选 `[container]`、canonical/精确别名与 typed 值；711 个可写 locator 全部解析为唯一目标或
  明确候选。赋值式失败不会回退普通搜索，候选和值编辑都保持 exact target，确认使用页面/查询/文档 revision
  租约，并通过临时文档写入与 exact 回读后一次性提交；跨工件脏草稿、重复参数、敏感值、未证 capability 与
  只读工件均失败关闭。产品/目标评分和数据库版本筛选相互隔离，未登记
  的精确版本不会借用相邻 schema；每个失败结果会返回 MissingIntent/Recipe/Schema/Version/Validator/Artifact/
  Runtime/Evidence/Sensitive 中的 typed 原因、当前已有证据和开放条件，绝不降级为猜测生成。
  Nginx、Apache、unknown 和无逐项权威 schema 的 structured 行仍是 `SyntaxOnlyUnknown`。此外，156 个数据库
  配置工件可按稳定 key/default filename 搜索；该入口只导航到既有 source-backed 工作区。有 parser 时可选择
  对应只读/草稿视图，无 parser 时显示 typed 缺口；所有工件结果均为 `CatalogGuidance`，绝不冒充目标配方、
  当前配置、验证或部署，也不会自动导入文件或绕过脏草稿保护。
  `VerifiedForTarget` 证据链尚未接线：完成条件至少包括把 exact
  `TargetGuard`、产品/版本/edition/组件与文档/schema 摘要绑定到同一快照，证明所需 target
  capability，执行目标厂商校验/readback，并在结果应用前复核目标、能力和快照均未变化。Nginx 与
  Apache 还缺 directive-specific、按产品版本隔离且带官方 reference/rationale/type/scope/activation/
  risk 的 metadata registry；第三方或未登记 directive 必须继续失败关闭为 `SyntaxOnlyUnknown`。
  搜索不得索引 value、preview、arguments、comment、raw、default 或 secret；只读目录选择不得修改文件，
  目标动作也不得从 documented default、现值或搜索原文自动填值。上述数据库 bundle 目前是有界的分步导航，
  仍没有访问控制文件、证书链、审计插件、网络/重载及真实 readback 的自动执行，因此不能宣称完整达成目标。
  `lovelyres-core::redis_config`（领域 owner：`lovelyres-core`）现已提供 Redis Open Source 6.2、7.2、7.4
  与 8.0/8.2/8.4/8.6/8.8/8.10 的类型化“新建空实例”本地 Baseline，并已接入
  原三栏快捷配置器（原 GPUI `config_generator`，源码归档于 docs/legacy/config-generator-baseline.rs.txt，Electron 页面替代进行中）。页面保持 Baseline 不可移除，支持按静态元数据
  搜索、配置叠加、逐行下方类型化编辑、真实移除、仅重置 Redis、独立滚动预览、复制和 `create_new`
  非覆盖另存；版本、数据目录、端口、连接/超时、内存/淘汰、AOF/RDB、slowlog 与 latency monitor 均展示
  含义及风险，并强制 maxmemory 不可移除及 AOF/RDB 至少保留一种。Redis 高级语义编辑器没有安全加载器，
  因而在界面与程序入口均明确禁用，不会显示成加载成功。该流程只适用于新建空实例，明确不承担既有含数据
  实例的 AOF/RDB 迁移，也不生成认证/ACL、远程监听或任意指令。任何目标校验或部署还必须绑定完整
  `TargetGuard`，使用同版本隔离验证、CAS、备份、重启后持久化与数据回读，并拒绝迟到结果；真实 Redis
  解析、启动、迁移与部署矩阵仍为 `NOT_RUN`。
  `lovelyres-core::postgresql_config`（领域 owner：`lovelyres-core`）现已提供 PostgreSQL 14–18
  的类型化“新建空集群”本地 include 片段：固定回环监听、端口、SCRAM 新密码存储、WAL 耐久性、
  统计与 autovacuum Baseline，并可叠加 13 项配置：版本化连接容量、认证超时、事务内/事务外空闲保护、
  单进程临时文件上限、连接生命周期日志、带明确 `deadlock_timeout` 的锁等待日志、checkpoint、autovacuum
  与临时文件阈值日志、数据/WAL I/O 计时、内建 pglz WAL 全页镜像压缩和 query ID。该模块只使用闭合
  有界值，以 `PostgresConf` 无损解析器完成
  生成后 allowlist 与逐字节 round-trip 校验，并只允许 `create_new` 另存；它不会生成 include 指令，
  也不初始化、部署、覆盖、重载或重启 PostgreSQL。HBA/ident、`postgresql.auto.conf`、TLS/秘密/角色、
  archive/restore 命令、preload、目标资源 sizing、全局 statement timeout、SQL/参数文本日志、远程监听
  和既有集群迁移继续 typed deferred。该模块尚未接入配置生成器 entity/state/render；完成条件是原生
  页面显式选择精确 major（后续 UI 可默认推荐 18）、展示 immutable Baseline、全部 feature/字段说明与
  风险，支持叠加/移除/重置、滚动预览及本地不覆盖另存。任何目标校验或部署还必须绑定完整
  `TargetGuard`，盘点全部配置来源与优先级，在同 major 隔离目标上验证启动/行为、CAS、备份、恢复与
  effective readback，并拒绝迟到结果；真实 PostgreSQL 14–18 矩阵仍为 `NOT_RUN`。
  `lovelyres-core::mongodb_config`（领域 owner：`lovelyres-core`）现已提供 MongoDB 7.0、8.0 与 8.3
  的类型化“新建空本地 standalone”`mongod.conf` 草稿：Baseline 固定回环监听、开启 authorization、
  关闭服务端 JavaScript 并使用 WiredTiger；可叠加连接上限、慢操作阈值与采样、`slowOp` profiler、
  8.3 专属的运行中慢查询日志、显式绝对路径日志轮转、WiredTiger cache 以及新集合与 journal 压缩。
  生成器只接受闭合有界值和严格 YAML 映射子集，拒绝 anchor、alias、tag、include、sequence、未知键、
  重复键与多行值，并只允许 `create_new` 另存。它不生成首个用户或任何凭据，不开放远程监听，不猜测
  `dbPath`/PID/service 布局，也不生成 TLS/私钥、Enterprise `auditLog`/LDAP/KMIP、复制集、分片或部署命令；
  MongoDB 8.2 已于 2026-07-31 结束支持，因而不会作为可选版本。该模块尚未接入配置生成器与数据库产品
  目录；完成条件是登记独立 MongoDB 产品/工件并接入版本选择、immutable Baseline、全部功能及字段说明、
  叠加/移除/重置、独立滚动预览和本地非覆盖另存。任何目标动作仍需完整 `TargetGuard`、同系列隔离验证、
  备份/恢复和行为回读；真实 MongoDB 7.0/8.0/8.3 启动与客户端矩阵仍为 `NOT_RUN`。
  `lovelyres-core::haproxy_config`（领域 owner：`lovelyres-core`）现已提供 HAProxy 3.4 LTS、3.3 stable、
  3.2/3.0 LTS 与 2.8/2.6 compatibility 分支的类型化 HTTP 反向代理本地草稿。Baseline 固定闭合监听与
  单一上游、HTTP mode、必需连接/客户端/服务端超时和零重试，并默认叠加请求/队列超时、安全响应头、
  上游 `Server` 头移除及直接边界转发头；另有健康检查、stdout 访问日志、Gzip、路径 403、直接来源
  IP、GET/HEAD、WebSocket tunnel、连接/队列上限、仅连接失败重试、请求 ID、直接来源限速等共 16 项。
  所有名称、地址、端口、path/CIDR、超时和上限均使用闭合 typed value；生成后由专用 allowlist parser
  逐项复核，并只允许 `create_new` 另存。TLS 前端虽作为可搜索能力显示，但在没有证书资产、权限与目标
  capability 闭环时明确拒绝启用，不会输出 `crt`/`ssl` 占位；本模块也不部署、reload、覆盖或声称已经
  运行 `haproxy -c -f`。该模块尚未登记到 middleware 产品树或配置生成器；完成条件是接入版本选择、
  immutable Baseline、全部功能/字段说明、叠加/移除/重置、独立预览与非覆盖另存，并在精确版本目标上
  绑定 `TargetGuard` 执行配置检查、HTTP/WebSocket 行为、CAS、备份与恢复。真实 HAProxy 2.6–3.4
  二进制与行为矩阵仍为 `NOT_RUN`。
  `lovelyres-core::tomcat_config`（领域 owner：`lovelyres-core`）现已提供当前受支持的 Tomcat 9.0、10.1、
  11.0 三个精确版本族的类型化“全新/空白安装 + 新 ROOT 应用”配置审阅 bundle，并已接入
  原三栏快捷配置器（原 GPUI `config_generator`，源码归档于 docs/legacy/config-generator-baseline.rs.txt，Electron 页面替代进行中）。页面默认 Tomcat 11，显示 Servlet/Java namespace、
  immutable Baseline、全部 feature/字段说明与 deferred 边界，支持按静态元数据搜索、配置叠加、逐行下方
  类型化编辑、真实移除、仅重置 Tomcat、独立滚动三工件组合预览、复制和全新目录非覆盖另存；GET/HEAD
  allow-list 与全应用 403 原子互斥。它始终同时生成 `conf/server.xml`、
  `webapps/ROOT/META-INF/context.xml`、`webapps/ROOT/WEB-INF/web.xml`，且 `maxPostSize` 与
  `maxSwallowSize` 的说明不冒充通用请求体或上传上限。三工件高级语义编辑与导入没有安全加载器，因而在
  界面与程序入口均明确禁用，不会显示成加载成功。该 bundle 不是完整 Tomcat 安装包、不可直接部署，也绝不
  覆盖/迁移现有应用、Realm、Valve、Listener 或账户；TLS、Manager/HostManager、Realm 秘密、任意 XML、
  既有应用部署与非回环暴露继续 typed deferred。任何目标校验或部署还必须绑定完整 `TargetGuard`，在匹配
  版本的隔离 Tomcat 上验证 schema、启动、HTTP 行为、CAS、备份与恢复并拒绝迟到结果；真实 Tomcat
  9.0/10.1/11.0 与 Java 8/11/17 启动及 HTTP 矩阵仍为 `NOT_RUN`。
  真实 Nginx/Apache 与数据库目标的 capability/readback 矩阵仍为 `NOT_RUN`。

- `lovelyres-core::line_config_visual::LineConfigTargetPolicy`（领域 owner：`lovelyres-core`）已经为
  MariaDB option file 提供字段私有、由产品与完整四段版本推导的 `?includedir` 语法门禁。当前
  allowlist 只包含官方源码逐个审校的 11.4.10、11.8.6 与 12.2.2；默认 parse/read、MySQL、相邻或
  未知补丁全部保持 opaque，且 document 在 replace/add/update/reparse 后保留同一 policy。前端
  尚无可信的完整 patch 版本输入，因此没有接入 `*_with_target_policy` API，也不会从 MariaDB 11.4
  minor schema 或 MySQL wire compatibility 推断该能力。完成条件是增加明确标为“本地语法选择、
  非目标证明”的产品+四段版本控件，切换时重新解析并使旧 NodeId 失效，同时覆盖导入、更新、
  `#` 歧义、末行 LF、错误产品/补丁和权限不升级；真实 Linux/Windows MariaDB 版本矩阵仍为
  `NOT_RUN`。
- MySQL/MariaDB Batch A 已将无版本 `mysql-option-file`/`mariadb-option-file` catalog validator
  统一失败关闭为 `SyntaxOnly`，但原生 validator 尚未接线：MySQL 8.0.11–8.0.15 没有
  `--validate-config`；MySQL `>=8.0.16`（含 8.4）只能在隔离环境调用
  `mysqld --validate-config`，且不会初始化 storage engines、plugins、components；MariaDB
  10.11/11.4 没有专用 `--validate-config`（13.0 才引入），`--print-defaults` 与
  `my_print_defaults` 只发现并展开选项，不构成 validator。默认名 `my.cnf` 仅是 Unix 常见建议；
  真实路径和 Windows `my.ini`/`my.cnf` 必须按实例发现。include graph、suffix、platform
  组合以及 MySQL/MariaDB 真实 VM 矩阵仍为 `UNWIRED`/`NOT_RUN`。
- MySQL `auto.cnf` 与 `mysqld-auto.cnf` 是不同来源：前者由服务端生成并保存只读
  `server_uuid`，本轮只把它登记为 `SourceBacked` + `ReadOnly` 的 ReplicationIdentity，
  明确禁止编辑。文件读取、权限/拒绝访问呈现、provider 接线、与运行时 `@@server_uuid`
  的 source correlation、请求和结果两端的完整 `TargetGuard` 校验以及真实 MySQL 验证均仍为
  `UNWIRED`/`NOT_RUN`，不得把 scope 行解释为已能发现、回读或验证该身份。依据：
  [MySQL replication options and `auto.cnf`](https://dev.mysql.com/doc/refman/8.4/en/replication-options.html)。
- `mysql-plugin-registry`、`mysql-component-registry`、`mariadb-plugin-registry` 已接入 core 的闭合只读 SQL、
  有界 typed parser、同连接身份绑定与数据库页面的 `Inventory` 页签。页面只渲染 core 公开的安全值或统一
  脱敏占位，并复用完整 `TargetGuard`、连接配置摘要、取消和迟到结果拒绝；MariaDB component 在发起 SSH 前
  静态拒绝。它们仍不等价于 option-file、命令行、manifest 等 startup 来源。真实数据库/SSH、最小权限与拒绝
  访问语义、registry/runtime/startup source correlation 和原生数据库协议仍为 `NOT_RUN`/`UNWIRED`。因此不得声称 plugin/component
  inventory comprehensive，也不得开放或暗示支持 `INSTALL`/`UNINSTALL PLUGIN`、
  `INSTALL`/`UNINSTALL COMPONENT` 或 MariaDB 对应 mutation。依据：
  [MySQL plugin loading](https://dev.mysql.com/doc/refman/8.4/en/plugin-loading.html)、
  [MySQL component loading](https://dev.mysql.com/doc/refman/8.4/en/component-loading.html)、
  [MariaDB plugin overview](https://mariadb.com/docs/server/reference/plugins/plugin-overview)。

新增页面至少要同时完成：

1. 在 `PageId` 与集中 descriptor registry 中注册；
2. 由应用组合根创建并复用 entity；
3. 接入 activate/deactivate、render 和目标切换失效逻辑；
4. 增加页面唯一性、导航、迟到结果拒绝和攻击者文本只作纯文本的测试。

原生辅助窗口还必须使用共享 typed entity 或 intent，并覆盖关闭后重开、目标切换和 stale session 行为。

## 刻意保持关闭的高风险能力

以下项目不是遗漏的按钮。它们缺少足够窄的计划、快照、CAS、审计或恢复保证，在契约补齐并通过真实 Linux VM 故障注入前不得开放：

- 任意改写 sudoers、`authorized_keys` 或 SSH 认证设置；当前仅提供受限只读调查。
- 软件包真实卸载；当前只提供本地包数据库调查和卸载影响预览。
- 用户删除、强制清退用户全部会话等不可精确恢复的账户操作；当前只开放可验证恢复的锁定/解锁。
- 卸载当前已加载的内核模块；当前只允许创建或移除 LovelyRes 自有的自动加载黑名单。
- 执行 Cron 行中的远端命令。Cron 命令始终作为攻击者可控文本，只允许查看、解析和指标检查。

已经开放的 Cron 独立文件删除、Shell 精确行注释、SUID/SGID 位移除或隔离，都必须继续绑定内容 SHA-256 和文件身份，先写入 `.lovelyres-backups` 受管命名空间，再经过 exact confirm → journal → verify/restore。

内核模块黑名单路径固定为 `/etc/modprobe.d/lovelyres-blacklist-<module>.conf`。新文件必须独占创建并使用 `0644`；移除只接受逐字节匹配的 LovelyRes 管理内容。黑名单只影响未来自动加载，不能把它展示为当前模块已经卸载。

## 尚未完成的实机验收

- 数据库页面已接入 MySQL 8.0.11–8.0.x/8.4.x、MariaDB 10.11.x/11.4.x 与 PostgreSQL
  16/17/18 community 的“运行时参数（只读）”页签：只选择 core 内闭合身份/查询计划，使用同一
  `TargetGuard` 与连接配置摘要拒绝迟到结果，解析有界 headerless hex-TSV，未知值默认脱敏，
  页面初始状态明确显示 `NOT_RUN`。当前只允许无已保存密码的连接；带密码连接在 core 与 UI
  两层失败关闭，因为把数据库密码交给目标机上的外部 `mysql`/`psql` 后，无法同时把该二进制视为
  可能恶意又证明它不会借 name/source/min/max/enum 输出通道回显凭据。完成密码认证支持的条件是
  通过 SSH forwarding 使用 core 直接控制的原生数据库协议，让凭据不进入远端 shell、环境变量或
  client 进程，并覆盖目标切换、取消、超时、非零退出和秘密不进入日志/快照。PostgreSQL 当前只
  拒绝已知不兼容厂商签名并要求三处版本一致；服务器可伪装上游签名，因此不能声称已密码学证明
  “非 fork”。真实 OpenSSH 与三类真实数据库查询均仍是 `NOT_RUN`，取消后的远端进程退出也必须
  在真实 Linux 环境验证。

- Nginx 全面可视化当前只编辑和安全另存单个本地文档；目标机 `nginx -V/-t/-T`、
  include 文件图、候选文件远端暂存、CAS 部署与恢复仍未接线。界面必须持续显示
  “尚未运行 nginx -t”，不得把通用语法树或静态提示当成目标二进制验证结果。
- Apache 全面可视化已接入本地配置生成器；远程 middleware 已具备独立的实例发现、有界
  `Include`/`IncludeOptional` 候选图、原生 `httpd -t`、全图/目录 CAS、备份验证与恢复流程，不能再
  记为这些能力全部缺失。但远程树仍是 `MiddlewareDocument`，没有与本地 `ApacheVisualDocument`
  合并为同一模型；更重要的是，当前 validator 没有绑定 MainPID 的精确 invocation、EnvironmentFile
  内容及原始有序 `-D/-C/-c` 上下文。Phase A 只落地 typed evidence 与 matching-endpoint graph seal
  合同，provider/transport 尚未接线，所以 Apache 远程 plan/execution 明确失败关闭；本地生成器和
  远程只读候选图只能显示“尚未运行目标校验”，不能显示为已部署。目标模块/静态指令 capability
  解析器也仍未接远端 transport 或 Electron 页面。
- MySQL option file、PostgreSQL conf/HBA/ident、通用 INI、TOML、Java properties、
  flat/whitespace 配置已经具备本地无损可视化；JSON 以及 YAML/XML 的可证明安全子集已接入
  source-backed 有序只读树。YAML 的 anchor/alias/tag/merge/flow/block scalar/directive/complex
  key 等高级构造，以及 XML 的 DTD/CDATA/PI/namespace/entity 等高风险边界，仍按最小可证明
  区域原子不透明保留；不透明区域默认遮罩且禁止普通复制，解析器不展开实体或访问外部资源。
  18 个经官方资料审校的版本化参数 schema 已接入配置生成器，但全部仍为 `Partial`，只提供
  精确路径元数据、风险/生效提示和提前脱敏；页面尚未通过目标实例回读证明版本、edition、
  capability 或参数值有效，因此这些 schema 不授予额外修改或部署权限。JSON/YAML/XML 结构
  变更、数据库运行时 SQL 修改/应用 UI、云参数 API、完整闭源厂商 schema 与目标回读 provider
  仍未接线；现有 RuntimeSql transport 与页面仅执行经过身份校验的闭合只读计划，尚无真实数据库
  验收。
  生成态 `mysqld-auto.cnf`、`postgresql.auto.conf`、Kingbase auto conf、OBD 注册状态与
  OceanBase 内部二进制始终只读。
- OceanBase P0 inventory catalog 已登记四个只读键：`oceanbase-observer-runtime` 通过
  `SHOW PARAMETERS` / `GV$OB_PARAMETERS` 盘点 observer 参数，`oceanbase-obproxy-runtime`
  通过 `root@proxysys` 的 `SHOW PROXYCONFIG` 盘点 ODP 参数；
  `oceanbase-tenant-variables` 限 CE 4.x MySQL-mode，通过 `SHOW GLOBAL VARIABLES` /
  `SHOW SESSION VARIABLES` 盘点租户变量，global 值仅影响新连接；
  `oceanbase-backup-archive-state` 只读 `DBA_OB_BACKUP_PARAMETER`、
  `DBA_OB_ARCHIVE_DEST`、`DBA_OB_BACKUP_JOBS` 与 `DBA_OB_BACKUP_JOB_HISTORY`。
  四项均声明 RuntimeSql+RuntimeReadBack+VendorSchemaRequired，不提供 mutation/activation；
  `observer.conf.bin` 继续为 GeneratedReadOnly。这仅完成 catalog rows；P0 provider、
  TargetGuard 前后校验接线与真实 readback 仍为 UNWIRED，真实 OceanBase / ODP 环境验收为
  NOT_RUN。
- TiDB 的 `tiflash.toml`、`tiflash-learner.toml`、`tiproxy.toml`、`ticdc.toml`、
  `changefeed.toml` 与 `tidb-lightning.toml` 已按六个独立组件登记并接入配置生成器的本地 TOML
  只读视图；TiCDC server 不再使用旧的泛化 `config.toml` 名称。它们保持
  `VendorSchemaRequired + VendorProcedure`，不会继承 TiDB Server 8.5.7 schema；TiProxy 版本必须
  独立匹配。当前只允许导入、逐字节预览和另存本地只读副本，starter、本地草稿、增删改移、应用
  与部署均关闭。精确组件版本 schema、目标路径/进程发现、厂商校验、健康回读、恢复演练和真实
  TiFlash/TiProxy/TiCDC/Lightning 集群验收均为 `NOT_RUN`。
- GBase 8a `gcware.conf` 的专用 source-backed 嵌套解析器已接入配置生成器目录与本地只读树，
  可逐字节展示官方风格的块与 `key: value` 项；未知边界失败关闭为不透明内容。它仍没有目标精确
  版本 schema、厂商校验、远端回读或部署链路，所以本地只允许导入、预览和另存只读副本；新建
  骨架、增删改移、应用及把副本标记为可部署配置均保持关闭，真实 GBase 8a/gcware 验收为
  `NOT_RUN`。
- GBase 8a 的 GNode/GCluster option 工件已按真实组件拆分；两份组件目录中的同名
  `cluster_common.cnf` 已登记为独立 `GeneratedReadOnly + JSON` 工件，不会继承 MySQL schema。
  它们当前仅供本地只读结构展示；目标路径发现、组件版本核验、厂商工具回读及集群级恢复仍为
  `NOT_RUN`。
- GBase 8s 已登记 `cmsm.cfg`、`concsm.cfg`、`gbasedbt.rc`、`~/.gbasedbt`、`ac_config.std`、
  `sm_versions`、`plconfig` 与 `IMCconfig` 的精确文件/角色身份，但这些复杂 VendorText 还没有
  专用 parser，因此仅 catalog 可见并不进入配置生成器 selector；不得用通用空白键值解析
  连接管理器块/宏、通信安全模块或工具专用参数。目前只有既有 `onconfig` 与五列 `sqlhosts`
  具备已证明的本地语法视图。`ac_config.std` 只是可发现的只读模板；PSM 目录、
  `ixbar.<servernum>` 与 `oncfg_<servername>.<servernum>` 恢复状态没有被误登记为文本配置。
  [GBase 8s 连接管理器](https://docs.gbasedbt.com/gbase8s/admin/ids_admin_1415.html)、
  [sqlhosts/通信支持](https://docs.gbasedbt.com/gbase8s/admin/ids_admin_0175.html)、
  [UNIX 环境文件](https://docs.gbasedbt.com/gbase8s/admin/ids_admin_0024.html) 与
  [ON-Bar/存储管理器文件](https://docs.gbasedbt.com/gbase8s/bar/ids_bar_288.html) 是当前官方工件身份依据；
  目标实例/路径发现、精确版本 schema、厂商 validator、部署、健康回读及恢复演练均为
  `NOT_RUN`。
- 神通产品目录已拆成 `ShenTongNative`、`ShenTongMpp` 和 `ShenTongOpenGauss`，三者都只声明
  `VendorNative`，当前零 artifact、零 parser、零 schema。虚构的 `shentong-server-config` 已删除；
  在没有现行交付证据前不写入 `oscar.conf` 或 `OSRDB.conf`。[官方产品中心](https://shentongdata.com/index.php/product/list-4)
  分开列出[自研内核](https://shentongdata.com/index.php/product/view-37)、
  [MPP](https://shentongdata.com/index.php/product/view-106) 与
  [openGauss 版](https://shentongdata.com/index.php/product/view-355)；
  [openGauss 发行版认证](https://opengauss.org/zh/certification/) 又显示同一神通 V7.0.21 产品版本名同时对应
  openGauss 3 与 openGauss 6 底座，因此不得按版本名猜测继承 openGauss 工件或 schema。完成条件是从
  [厂商文档下载](https://shentongdata.com/index.php/download/list-26) 与真实交付包取得 edition/版本/文件身份、
  建立专用 parser 与 schema，再运行厂商校验、部署及恢复矩阵；真实交付验收为 `NOT_RUN`。
- SequoiaDB quickDeploy 的 `sequoiadb.conf`、`mysql.conf`、`mariadb.conf`、`postgresql.conf`
  已作为四个独立 catalog 工件接入配置生成器；cluster 与 SQL instance 分别绑定专用 bracket-aware
  source-backed 只读方言，四份官方默认注释可见，`[host:port,host:port]` 不会被通用 CSV 逗号
  拆列。跨角色表头整份失败关闭为敏感 opaque；odd/even quote、坏方括号和未知记录布局只使当前
  物理行敏感 opaque，后续安全 sibling 仍可见。MariaDB 证据来自 SequoiaDB 官方仓库 `master`
  commit `6d49550`，尚未绑定 released version。四个工件继续保持 `VendorSchemaRequired`；当前没有
  匹配产品/精确版本 schema、可调用的厂商 validator、目标回读或远端 deploy 链路，因此 starter、
  全部结构 mutation、应用和部署均保持关闭，只允许导入、预览与另存本地只读副本；真实
  SequoiaDB/SequoiaSQL quickDeploy 验证为 `NOT_RUN`。
- YashanDB 23.5 的 `yasdb.ini` 已作为精确 `KeyValue` 工件接入本地只读可视化；exact
  v23.5.4.100 + `official-doc-family-23.5.4.100` 现在提供 15 项 root uppercase `Partial` 只读
  元数据与官方文档默认。该 guard 是文档证据族，不代表 Enterprise/AI edition 猜测；lowercase、
  未列和复杂但未审校参数保持 `VisibleUnvalidated`。选择 schema 不改变 `VendorSchemaRequired`：
  默认值不进入输入、原文、复制或另存，草稿、骨架、增删改移、应用和部署仍关闭。`yasdb.spfile`
  与 `yasdb.pwd` 继续作为不可文本读取的厂商二进制生成态。目标身份/路径发现、真实
  `ALTER SYSTEM`、实际值回读、厂商过程、恢复及真实 YashanDB 验证仍为 `NOT_RUN`。
- 分布式数据库的远端变更仍缺目标拓扑发现、逐工件 SHA/CAS、同版本厂商校验、灰度激活、
  集群健康回读和恢复演练，因此本地“安全另存”不得解释为 TiDB/OceanBase/DM 等产品已生效。
- DM8 的 `dm-thread` catalog 与 `dmthrd.ini` source-backed INI parser 已接入配置生成器，可提供
  本地无损草稿；`dmtimer.ini` 的 `REPEAT_INTERVAL` 分号值也已有回归覆盖。`dmthrd.ini` 仅在
  `dm.ini` 的 `DMTHRD_INI=1` 时使用；其参数 schema、目标 exact build 与 CPU 上下文、匹配 build
  的厂商工具校验、远端部署/激活及真实 DM8 验收均为 `NOT_RUN`。
- DM8 的 `dm-dcr-config`（`dmdcr_cfg.ini`）与 `dm-dcr-node`（`dmdcr.ini`）已失败关闭为
  `VendorText` + `VendorSchemaRequired`：前者的 `//` 注释、重复 `[GRP]` 及其 `[CSS]`/`[ASM]`
  成员必须作为有序原子结构处理，后者的 `DMDCR_*_STARTUP_CMD` 必须永久按命令载荷处理；当前仅保留
  catalog 与有界原始文本可读性，不进入结构化 selector，也不提供骨架、本地草稿或增删改移。专用 DCR
  parser/schema、匹配 exact build 的厂商校验、目标发现与 TargetGuard、部署/激活、恢复以及真实 DM8
  验收仍为 `UNWIRED` / `NOT_RUN`。
- 数据库 core 已有命令行、环境变量、systemd/service manager、厂商工具托管状态和 include 的
  有界来源/优先级图模型，但尚未接任何目标发现 provider，因此当前不能构建目标实例的完整图；
  `LosslessLocalDraft` 只表示本地无损草稿权限，不能把单个文件的内容显示为目标当前 effective
  state，更不能据此开放生成、应用或部署。
- Windows 10/11、混合 DPI、中文 IME、RDP、虚拟机、集显和完全离线启动必须使用同一二进制摘要采集真实证据；缺失项保持 `NOT_RUN`。
- OpenSSH/Dropbear、MFA、Agent、跳板机、SFTP 降级和网络故障矩阵必须在适用的 Linux/SSH 实验环境执行；被忽略的自动化测试不等于通过。
- 破坏性远端操作必须验证成功、非零退出、断连、并发变化、验证失败和恢复失败路径，不能只用 mock 结果作为发布依据。

相关验收契约见 [终端可行性门禁](../crates/lovelyres-terminal/FEASIBILITY_GATES.md) 与 [SSH 兼容性与安全策略](SSH_COMPATIBILITY.md)。

- `lovelyres-core::database_config_inventory`（owner：database core）已实现 MySQL/MariaDB plugin 与 MySQL component 的闭合只读 SQL plan、typed bounded snapshot、带唯一末行 `complete_v1` 的 headerless hex-TSV parser，以及共享 `DatabaseService` 的无密码 profile 只读路径。服务保存精确 runtime identity、完整 `TargetGuard` 与 profile digest，并在两阶段查询之间、返回前和消费前提供复核；密码 profile 在第一次 SSH 前失败关闭。尚未接入 Electron 页面或 core-owned native database protocol；完成条件是把 snapshot 接到 Electron 页面且页面只能读取 `public_value()`，并覆盖 MySQL 8.0/8.4、MariaDB 10.11/11.4 的真实权限、空表、重复行、超限、取消与目标切换矩阵。`complete_v1` 只用于发现普通截断，不能把恶意服务端变成可信来源。真实数据库验收仍为 `NOT_RUN`，且本模块不授权任何安装、卸载或其他 mutation。

## Electron 迁移期切片接线状态

### 2026-08-27 移除的四个切片

边界隔离（firewall）、取证快照（snapshot）、中间件（middleware）、多机批量（batch-servers）
按需求整体移除。下文里凡是描述这四个切片的段落只保留历史记录，**不再对应任何现存代码**：
它们的页面、契约、preload 方法、主进程 IPC、后端 RPC 与 `lovelyres-core` 里只被它们用到的
`firewall.rs`/`snapshot.rs`/`batch.rs` 都已删除。它们提到的"仍待实机验收"因此一并作废，
不需要再排期。`middleware.rs` 与 `middleware_document.rs` 保留——那是配置生成器的产品路径
知识，跟中间件页面无关。

### 已中央接线但仍为 Pending

- SSH terminal 已不再是 `UNWIRED`。`crates/lovelyres-electron-backend/src/terminal_api.rs` 的七个固定
  内部 RPC 已实例化到 `BackendState`；main LovelyRes preload 只新增零参数 `openSshTerminal()`，当前总公开面
  精确为 81 个方法，而独立 `terminal.html` renderer 只得到 `open/poll/input/resize/search/copySelection/close`
  七个无 handle 方法。binding、session、guard、host、command、launch token 与 backend terminal handle
  始终由 main/Rust 持有，不进入 URL、argv、window.name、DOM 或 renderer state。main 以 binding + window kind
  为 key 创建 hardened `BrowserWindow`，重复入口聚焦现有窗口；新 binding、disconnect、窗口关闭、backend
  shutdown 和打开失败都会先使上下文失效并 best-effort 关闭 terminal，迟到结果失败关闭。
  选区复制只在已打开 terminal handle 上接受非空、最多 128 KiB UTF-8 纯文本并调用 main
  `clipboard.writeText`；按钮和有选区的原生 copy 事件共用同一个有界 helper，无选区 Ctrl+C 不被 copy
  边界吞掉。没有 navigator clipboard、renderer fallback、readClipboard 或新增 paste preload。
  exact `lovelyres://app/?window=terminal` 映射到独立本地 entry；xterm DOM renderer 所需的动态尺寸/主题 CSS
  仅在该文档允许 inline style，main App CSP 和 terminal script CSP 均未放宽，全部资源仍为
  `lovelyres://app`。当前 Electron-native CDP 证据位于
  `target/electron-debug/526e344c-a5f5-499d-9a17-ab4c0bf4defe/evidence`，验证当时的 pre-LogAnalysis main API、terminal exact7、
  未授权真实窗口全方法失败关闭、零泄漏、local-only resource tree、零 console error、capturePage 和销毁。
  条目仍为 `Pending`：真实 SSH/PTY 的成功 resize/input/poll/search/copy/close、生产 keyed reuse/focus/disconnect、
  OpenSSH/Dropbear/auth/MFA、IME/CJK、网络故障及 packaged Windows/macOS/Linux 生命周期矩阵均为 `NOT_RUN`，
  tabs、completion、directory launch 和 AI parity 也尚未达成，不能据此宣布 SSH terminal 完成。

- Middleware 只读调查 Phase 1 已不再是 `UNWIRED`。`middleware.discover`、
  `middleware.configuration.load` 与 `middleware.history.list` 三个固定 RPC 已进入中央 `BackendState`、main、
  frozen preload、aggregate `LovelyResApi` 与 `App` registry；renderer 页面只接收 opaque `bindingHandle`，
  discovery/instance 继续使用 target-scoped opaque handles，不接收 target/session/guard/generation、远端路径、
  摘要、shell 或命令。adapter 仅调用 core `MiddlewareService::discover/load_configuration/history`，并在
  请求前后复核完整 target scope；SSH disconnect 会先 `close_binding`，迟到结果失败关闭。当前公开 API
  仅为 `discoverMiddleware`、`loadMiddlewareConfiguration`、`listMiddlewareHistory`。Electron-native CDP
  的 pre-LogAnalysis 证据 `target/electron-debug/526e344c-a5f5-499d-9a17-ab4c0bf4defe/evidence` 已验证伪造/unknown
  参数拒绝且不回显、断连页无实例/历史、refresh 禁用、本地资源、卸载重挂载后仍无远端行、capturePage 与
  0 console errors。页面仍为 `Pending`：真实 Linux/OpenSSH/systemd/SFTP 多实例、权限/include/断连/目标切换
  矩阵为 `NOT_RUN`，plan/confirm/execute/verify/restore/draft/file/terminal/export/AI 仍是后续独立安全设计。

- 命令审计 / Check Audit 只读 Phase 1 已不再是 `UNWIRED`。`check-audit.catalog.get`、
  `check-audit.status.collect` 与 `check-audit.log.read` 三个固定 RPC 已进入中央 `BackendState`、main、frozen
  preload、aggregate `LovelyResApi` 与 `App` registry；renderer 页面只接收 opaque `bindingHandle`，日志读取
  继续使用 target-scoped opaque snapshot capability，不接收 session/guard/generation/identity、shell、远端路径、
  摘要或备份位置。adapter 只调用 core `AuditService` 的固定目录/status/log/analyze 路径，并在请求前后复核
  完整 target scope；SSH disconnect 会先 `close_binding`，迟到结果失败关闭。当前公开 API 仅为
  `getCheckAuditCatalog`、`collectCheckAuditStatus`、`readCheckAuditLog`。同一 pre-LogAnalysis CDP 证据已验证伪造/
  unknown 参数拒绝且不回显、断连页无命令/日志行、本地资源、卸载重挂载后仍无远端行、capturePage 与
  0 console errors。页面仍为 `Pending`：真实 Linux/SSH/auditd 未安装、权限拒绝、日志缺失/畸形、断连与
  target-switch 矩阵为 `NOT_RUN`，deploy/restore/clear-log、plan/confirm/execute、file/terminal/export 仍待迁移。

### 尚未中央接线或仍待完整验收

以下条目同时记录仍为 `UNWIRED` 的入口，以及已经中央接线但因实机、mutation/remediation、持久化或
packaged 验收不足而继续为 `Pending` 的切片。每一条都必须按其明确状态解读，不能因为源码、测试或
某一阶段接线存在就把整个页面或 overlay 标记为完成：

- **容器运行时不再写死成 Docker（2026-08-27）。** 后端原来在六处硬编码
  `ContainerRuntime::Docker`，核心声明支持 Podman 却没有任何地方会选它——**在只装 Podman
  的机器上，Docker 页的每个问题都返回空**，读起来像"这台机器没有容器"，是最坏的一种错答案。
  国产发行版与 RHEL 系（openEuler、Anolis、AlmaLinux、Rocky）默认就是这个形状。
  现在开快照时探测一次（`DockerService::detect_runtime`），把结果随快照带下去，之后每次
  调用都用它；"没装任何运行时" 与 "装了但不响应" 分成 `docker-runtime-absent` 与
  `docker-runtime-not-running` 两个答复。容器动作也跟着走对——身份里带着运行时，所以
  Podman 主机上生成的是 `podman stop`。

  同轮修掉解析层的一串 Docker 形状假设：`Id`/`ID`、`Names` 数组、`Status` 空而值在
  `State`、`CreatedAt` 空而值在 `Created`、`Ports` 结构化数组、`Command` 数组、网络清单
  的全小写下划线键。另外 SSH 层把 stderr 并进 stdout，Podman 在 cgroups-v1 主机上每条
  命令先打一句弃用告警，三处解析器（逐行 JSON、整体 JSON 数组、`id<TAB>状态`）都因此
  全盘失败；规则改成"不以 `{` 开头的行跳过，以 `{` 开头却解析不了的仍然报错"。
  验收靶机 `svc-podman`（AlmaLinux 9 + Podman，构建时断言机器上没有 `docker`）与
  `tools/lab/probe-podman.mjs`。**未覆盖**：`podman stats` 在这台嵌套 cgroups-v1 靶机上
  读不到 cgroup，探针明确标注不覆盖，真实主机上没有这一层。

- **Kubernetes 工作负载动作（2026-08-27）已中央接线**，preload 从 113 变 117：
  `planKubernetesWorkloadAction` 等四个方法。渲染层只发行句柄与三种闭合形状之一
  （`scale-deployment` 带副本数、`cordon`、`uncordon`），namespace、名称、UID 都到不了它
  手上；核心的比较-并-设置补丁、日志、回读复核与按精确 revision 回滚原样复用。
  同轮修掉一个**做成了却报没做成**的问题：`kubectl patch` 少了 `-o json`，kubectl 打印
  一行 `deployment.apps/ledger patched`，调用方按 JSON 解析失败，于是整个流程报错——而
  补丁其实已经生效。操作员看到失败会再做一次。验收见
  `tools/lab/probe-kubernetes-action.mjs`。

- **Kubernetes 只读路径（2026-08-27）第一次对着真集群跑过**，并查出一个从这个页面存在起就有的问题：
  `crates/lovelyres-core/src/kubernetes.rs` 的 `RawPodStatus` 用 `rename_all = "camelCase"` 把
  `pod_ip` 变成 `podIp`，而 Kubernetes 发的是 `podIP`——**Pod 列表的地址列在任何真实集群上都是空的**。
  原解析测试的 fixture 里写了 `podIP`，但只断言行数和 id，所以一直没抓到；现在补了逐列断言的
  `a_populated_pod_row_carries_every_column_it_was_given`。靶机与探针见
  `tools/lab/orchestration/`、`tools/lab/probe-kubernetes.mjs`。Kubernetes 的写路径
  （Deployment 扩缩容、节点 cordon/uncordon）核心里有，仍未接线。

- 全局取消按内容遮蔽（2026-08-25）：sidecar 与渲染层契约里按 credential 词形（`password=`、`token=`、
  `bearer `、URL userinfo 等）遮蔽或拒绝的实现已全部移除，涉及 baseline、check-audit、docker、integrity、
  kubernetes、middleware、packet-capture、snapshot、log-analysis 九处。取证快照原先有七个采集器整段只返回
  marker——进程、登录历史、计划任务、authorized_keys、sudoers、最近修改文件、环境变量——正好是事后第一批要
  看的东西，现在按采集内容原样返回。渲染层契约那份过滤比 sidecar 更糟：它拒绝整个响应而不是一行，一条
  credential 形状的日志就能让整页读不出来。
  保留的仍是能力擦除：DTO 里绝不出现 binding/session/connection handle、target identity、快照 id 与
  host key fingerprint；控制字符净化与体积上限也保留。应用日志（`diagnostic_log_api`）是 LovelyRes 自己的
  tracing 环，不是目标采集输出，其遮蔽保留，避免把操作者自己的口令写进本地日志。
- 快速检测（Quick Detection）已整体移除：sidecar 的 `quick_detection_api.rs`、七个 RPC、
  main/preload 的七个方法、`quick-detection-contract.ts`、`QuickDetectionPage.tsx` 与其状态/助手/
  样式文件、以及对应的门禁与 CDP 场景都已删除。主窗口 preload 面因此从 118 收到 111，页面注册表
  从 20 收到 19。core 的 `detection.rs` 保留：baseline、compliance、report 与 services 仍在用它。
  该切片在 ledger 的 `pages` 中不再存在；`verificationRuns` 里的历史记录按原样保留，因为那些运行
  当时确实发生过。
- **Docker 容器动作（2026-08-27）已中央接线，并且是第一条在真 daemon 上跑通的写路径。**
  `crates/lovelyres-electron-backend/src/docker_write_api.rs` 新增，preload 从 109 变 113：
  `planDockerContainerAction`、`confirmDockerContainerAction`、`executeDockerContainerAction`、
  `cancelDockerContainerAction`。渲染层只发容器句柄（由自己那份快照发出、由只读侧在同一套
  scope/token/过期规则下解回身份）和一个闭集里的动作词；容器 id、运行时动词、命令都到不了它手上。
  计划有 5 分钟 TTL，确认与执行是两次调用，执行时计划先离开 registry 再 await，所以一个计划最多跑一次。
  核心的 plan→confirm→execute→journal→verify→restore 原样复用，回执给的是**复核读回的状态**，
  不是命令的退出码。

  同轮改掉三处只有对着真机才会暴露的问题：`probe_state` 的 `--format` 里写了裸 `\t`，Go 模板原样
  打印成反斜杠加 t，解析器按真 tab 切分——**任何容器动作在真 Docker 上从来没能通过状态探测**；
  计划摘要与回滚说明是英文且带 64 位全长容器 id，现在是中文短 id；验证回执 `observed container
  state: ...` 也改成中文。验收证据是 `tools/lab/probe-docker-action.mjs`，在 `svc-docker` 上覆盖
  计划→未确认拒绝→确认→执行→主机侧独立复核、同计划不能跑第二次、状态不符时计划阶段就拒、伪造句柄
  解不到东西、达不到目标状态时验证判失败并回滚、取消。

- **系统信息表格的右键菜单（2026-09-02）已接线：核心里按行的排查与处置动作，界面上终于能点到。**
  `lovelyres-core::system_info` 早就有一整套按标签划分的按行动作——进程 40 项排查加
  SIGTERM/SIGKILL、服务 19 项排查加启停/启用/禁用、用户与登录历史的账户锁定/解锁、
  网络/外连/开放端口 19 项排查加断开 TCP 连接、计划任务/定时器/SSH 密钥/SUID/
  sudoers/内核模块/环境变量/软件包/Shell 配置各自的排查，以及删除独立 cron 文件、
  注释 Shell 行、去 SUID 位/权限隔离、内核模块黑名单这几项改动——request builder、
  plan/execute、journal、verify、restore 全写完测完了，但没有任何调用方。现在后端多一个
  `system_info_action_api.rs`：动作用闭集 key 寻址（`process.open-files`、
  `process.signal.kill`、`network.disconnect`……），key 直接由核心枚举的 serde 名生成，
  解析不回来的就是不存在；**哪些动作对这一行可用，由后端拿它自己保存的快照按行算出来**
  （request builder 是纯函数，不碰目标机），所以 UDP 行没有"断开连接"，已经是注释的
  Shell 行没有"注释此行"，用户名不合法的行什么都没有。6 个 RPC / IPC / preload 方法：
  `listSystemInfoRowActions`、`inspectSystemInfoRow`、`planSystemInfoRowAction`、
  `confirmSystemInfoRowAction`、`executeSystemInfoRowAction`、`cancelSystemInfoRowAction`，
  preload 从 118 变 124。渲染层只会说"这个快照的这一行、这个 key"——没有 PID、
  单元名、路径、命令穿过边界；改动类动作走 plan → confirm → execute 三步、计划句柄
  一次性、5 分钟过期、断开连接时连同快照一起清掉。右键菜单本身还带三个本地项：
  复制这一格、复制整行、查看详情；Shell 配置那种按文件显示的标签，每一行也能右键。
  真实靶机上的执行路径（尤其是 SIGKILL、断连、锁账户、去 SUID 位）仍待实机验收；
  当前证据是后端 6 个模块测试 + 1 个 RPC 级拒绝测试、渲染层契约/菜单/对话框测试、
  主进程边界测试和源码门禁。

- **Docker 容器终端（2026-08-27）已接线，是核心早就写好、界面上一直没有的第一件。**
  核心的 `DockerService::open_terminal` 与 `TerminalLaunch::ContainerExec` 存在已久，
  但从来没有任何调用方——一整条 PTY 路径写完了、测过了、没接过。现在
  `docker.container.terminal.open` 一个 RPC 打通：只读侧把容器句柄解回身份，核心探出这个
  镜像里真有的 shell，终端 registry 照常开一个槽。preload 从 117 变 118，只多
  `openDockerContainerTerminal` 一个方法——**渲染层给不出 shell，也给不出容器 id**，
  它只能开一个窗口。终端窗口自己的那套 API 一个字没改：窗口是什么类型在创建时就定死了，
  窗口里的渲染层只会说"给我开个终端"。窗口按 binding + 容器句柄分别记名，所以宿主 shell
  和容器 shell 可以并排开着；断开连接照旧把这个 binding 上的窗口全带走。

  新增 `DockerService::detect_shell`：按 `bash → ash → sh` 探一次。写死 bash 在
  busybox 镜像上必挂，一律用 sh 又白扔掉有 bash 那些镜像上的行编辑与历史。

  同轮查出三个只有真开一个 shell 才会暴露的问题，都记在
  `tools/lab/orchestration/README.md`：**终端 id 由核心自己造，而调用方拿自己登记的 id
  核对每条事件——开得起来，第一次 poll 就报协议违规，窗口当场死**；**停着的容器被答成
  "这个镜像里没有 shell"**，把人打发去重建镜像；**靶机十六个容器全是 alpine，"优先挑 bash"
  这条分支在真机上从没走过**（现在加了 `app-shell`，Debian 的）。验收证据是
  `pnpm lab:docker-terminal`：挑对 shell、敲进去的命令回显得出来、确认人真在容器里而不是
  宿主机上、停着的容器给的是"没在跑"、伪造句柄解不到东西——在 `svc-docker`、`svc-arena`
  与只有 Podman 的 `svc-podman` 上都跑通。

  仍缺：网络/卷删除、Compose 动作（Compose 项目目前没有句柄）、容器内文件读写。

- **镜像详情（2026-09-02）已接线，是当初点名的三件事里的最后一件。**
  镜像页原本只有一张卡片，列仓库、标签、摘要、大小、创建时间——全是清单里已有的字段，
  点不开也问不出任何清单答不了的问题。现在核心新增 `DockerService::inspect_image`，
  镜像行拿到自己的句柄（和网络/卷一样是 opaque 的，全长 id 留在后端），
  `docker.resource.inspect` 多认一种 `kind: "image"`。

  读的是两条命令而不是一条，因为它们答的是两个问题，只有凑齐才有用：
  `image inspect` 说这个镜像**起来之后会做什么**——以谁的身份跑、入口点是什么、
  烤进去了哪些环境变量、暴露了哪些端口；`image history` 说它**是怎么变成这样的**，
  别人往里加的那一层就在这里露出来。history 读不到不算失败：按 digest 拉下来的镜像
  本地就没有构建记录，配置照样值得看。

  「运行身份」这一栏会把空值直接写成「root（镜像没有指定用户）」——镜像没设 user 就是 root，
  而运行时表达这件事的方式是把字段留空，照原样显示等于把最该看见的答案藏起来。
  内置环境变量一律原样显示，理由和别处一样：烤进镜像里的凭据是**要找的东西**，
  不是要遮的东西。

  同轮查出两个只有真读一台主机才会暴露的问题：**`image ls` 是一个 tag 一行，
  同一个镜像挂两个 tag 就是两行同 id**（走镜像源的主机上必然如此），按 id 去重会把
  整个标签页判成快照失效；**Podman 的字段名和 Docker 不一样，而且 size 和创建时间给的是数字**
  ——照 Docker 的形状读，这两列一个空一个是一串秒数。两者都补了断言。
  验收证据是 `pnpm lab:docker-image`（自建镜像、拉下来的镜像、伪造句柄，启动命令与
  运行身份都和主机侧独立复核对齐）与 `pnpm lab:podman` 里新增的镜像段。

- Docker 只读调查 phase 1 已中央接线：`crates/lovelyres-electron-backend/src/docker_read_api.rs`、
  `electron/src/shared/docker-read-contract.ts`、`docker-read-state.ts`、`docker-read-helpers.ts` 与
  `DockerPage.tsx` 已实现真实 opaque SSH binding、完整 `TargetGuard` 前后验证、固定 Docker runtime、
  有界容器快照，以及 stats/images/networks/volumes/Compose 项目、容器/镜像/网络/卷详情、安全审计和日志读取。
  Renderer 只持有 5 分钟 TTL 的 opaque snapshot/resource handles，不发送 session、guard、generation、
  identity、命令或远端路径；后端 registry 限 8 个快照、每快照 3 个并发读取和 2 个并发刷新，并限制全部
  行数、UTF-8 文本、日志、registry 字节与事件结果应用。网络或卷清单刷新会作废其旧资源 handle；容器
  快照刷新或目标切换会作废该目标的全部旧 handle，晚到结果失败关闭。BackendState 单例、exact5 RPC、
  main/preload exact96、aggregate contract、App binding-only page registry 与 SSH disconnect 前 eager
  `close_binding` 均已接线；phase 1 不暴露 start/stop/restart/remove/exec/file/terminal/export/mutation/generic
  surface。当前代码面验证包括 backend library 206 tests、standalone 35 tests、Electron 99 files/542 tests、
  source gate/fixture self-test，以及 `target/electron-debug/b3e44b7a-7a8f-481d-be9d-26521d5cbfea/evidence`：
  真实 Electron `webContents.debugger`/CDP 证明五个方法的直接和 unknown-field forged 请求共 10 项全部拒绝且
  不回显；断连页的 table/resource/card/finding/inspection/log/tab rows 全为 0、local-only、无内部身份，卸载重挂载
  仍为空，Docker/全局 console error 为 0，并由 `capturePage` 生成截图；标题/提示对比度为 15.05:1/6.37:1。
  仍缺真实 Linux/OpenSSH/Docker 的空清单、权限拒绝、超限、超时、断连和目标切换矩阵。容器 action、资源/
  Compose mutation、文件读写/复制和 container terminal 属于 phase 2，必须另行建立不可变计划、确认、审计、
  验证/恢复及窗口生命周期闭环；整个 Docker 页面因此继续为 `Pending`，但只读 phase 1 不再计为 `UNWIRED`。
- 日志分析只读调查 phase 1 已中央接线：`crates/lovelyres-electron-backend/src/log_analysis_read_api.rs`、
  `electron/src/shared/log-analysis-read-contract.ts`、`log-analysis-read-state.ts`、
  `log-analysis-read-helpers.ts` 与 `LogAnalysisPage.tsx` 已实现真实 opaque SSH binding、完整
  `BoundSshSession`/`TargetGuard` 前后验证，并且只调用 core `LogAnalysisService` 的日志源发现、文件/
  journal 分页读取、威胁汇总、多源关联与 IOC 搜索。Renderer 仅发送 binding、snapshot/source capability
  及有界 typed query；远端位置只能作为 hostile plain text 展示，后续读取不接收 path，也不发送
  session、guard、generation、identity 或命令。快照 TTL 为 5 分钟，registry 限 8 个快照、每快照 1 MiB、
  总量 4 MiB、每快照 3 个并发读取，发现限全局 2 个且每 binding 1 个；文件源限 100 个并可附加 1 个
  journal capability。单页限 200 行/512 KiB；关联限 2–8 个文件源、每源 200 行、观察 1,600 行、返回
  1,000 行/1 MiB；IOC 限 1–8 个文件源、16 个 indicator、64 个 source/indicator 组合、64 个结果、
  每结果 3 个样本且总文本 512 KiB。过期、淘汰、目标切换及晚到结果均失败关闭。按“可信条件下不做主动隐藏”
  的约定，日志行一律原样返回，只保留控制字符净化与体积截断：原先按 credential 形态整行遮蔽的实现
  会吞掉 auth.log 里正要看的证据，已移除。页面已按命令工作台改造为工具栏 + 日志源树 + 详情三段式，
  行号沟槽与命令输出同构。BackendState 已注册 exact4 固定 RPC，main/preload/aggregate contract 只公开
  `discoverLogSources`、`readLogSource`、`correlateLogSources`、`searchLogIocs`；main 对请求与响应作严格
  exact-object 验证，unknown/forged 参数固定失败且不回显。`App`/`LogAnalysisPage` 只接收 opaque
  `bindingHandle`，不接 target identity、connection/session metadata；SSH disconnect 在实际断连前 eager
  `close_binding`，取消、过期、目标切换及晚到结果均失败关闭。owner 为 Electron log analysis migration；
  验收测试为
  `log_analysis_read_api_standalone.rs`、`log-analysis-read-contract.test.ts`、
  `log-analysis-read-state.test.ts`、`log-analysis-page.test.tsx` 与 `log-analysis-read-boundary.test.ts`。
  source gate 与 fixture self-test 已接受当前 main exact89、Log Analysis exact4、strict validators、backend
  guard/bounds、opaque-only App、forbidden surfaces 及 eager close-before-disconnect；最近完整 Electron check 为
  96 files / 509 tests，sidecar aggregate 为 583 passed、0 failed、0 ignored，standalone 为 29/29。新的
  Electron-native CDP 证据 `target/electron-debug/c7b33682-bc4d-4f91-bd63-8990152a2987/evidence` 已通过：
  该 pre-Kubernetes main exact85 运行中，forged/unknown discover/read/correlate/IOC search 均 reject-no-echo，forbidden
  mutation/rules/AI/file/terminal/export/generic 为 `undefined`，断连页无 rows、local-only、无 internal identity，
  `log-analysis-disconnected.png` capturePage 成功，unmount/remount 后仍为空，console error 为 0。真实 Linux/OpenSSH/journal 的权限拒绝、不可用、
  populated/空集、超限、超时、断连及 target-switch 矩阵同样 `NOT_RUN`。AI 分析、规则 mutation、导出、
  任意文件入口与终端属于 phase 2 独立安全设计，仍为 `UNWIRED`；因此页面整体保持 `mixed`/`Pending`，
  不把 phase 1 的代码面接线误报为完整 parity。
- Snapshot 只读调查 phase 1：`crates/lovelyres-electron-backend/src/snapshot_read_api.rs`、
  `electron/src/shared/snapshot-read-contract.ts`、`snapshot-read-state.ts`、`snapshot-read-helpers.ts` 与
  `SnapshotPage.tsx` 已实现真实 opaque SSH binding、完整 `BoundSshSession`/`TargetGuard` 前后验证，并且
  只调用 core `SnapshotService` 的 `list_directory`、`list_forensic` 与 `diff_forensic`。Renderer 仅发送
  binding 和 opaque snapshot handles，不发送 core snapshot id、target/session/generation、host/fingerprint、
  命令、远端路径或摘要。目录响应最多 64 份、每份 8 个固定 preset，`bytes` 使用精确 u64 十进制字符串；
  `source`、`remote_root`、archive path、全部 SHA/digest 和 target identity 均不出 sidecar。每个目录项的
  `archiveAvailability` 固定为 `not-checked`，页面明确便携索引可读不表示远端归档仍存在、不可变或已重新
  验证。
  取证索引最多 10 份；详情固定 12 个 collector、最多 2,048 行/512 KiB、每字段 512 行、单行 4 KiB，
  serialized 响应限 768 KiB。差异固定 12 个 collector、每字段每方向 200 行、总计 1,000 行/512 KiB，
  serialized 响应限 768 KiB，并强制 baseline 时间严格早于 newer。公开投影按 collector 固定为 7/5：
  `processes`、`loginHistory`、`cronJobs`、`authorizedKeys`、`sudoers`、`recentModifiedFiles`、`envVariables` 的 detail 整段只返回
  `[SENSITIVE SNAPSHOT TEXT REDACTED]` 或 `[FORENSIC COLLECTOR FAILED]`，diff 的 added/removed 每方向也最多
  只返回一个相同固定 marker，旧内容不会进入 renderer。`networkConnections`、`listeningPorts`、
  `startupServices`、`runningUsers`、`loadedModules` 才允许有界、控制字符归一化的
  plain text，并继续对已知 credential marker 与当前 target/session literal 失败关闭；这只是闭合公开面，
  不宣称能够从任意文本识别所有秘密。Core portable snapshot/export 仍可能持有原始采集文本，必须继续作为
  core-owned 敏感数据保护。opaque catalog TTL 为 5 分钟，限 8 个 catalog、每个 128 KiB、registry 总量
  1 MiB；list 限全局 2 个且每 binding 1 个，详情/差异限全局 8 个且每 catalog 3 个。同 scope 刷新可为
  未变化记录复用 opaque handle 以保持选择，但会轮换内部 token；目标切换、断连、TTL、淘汰和晚到结果均
  失败关闭。
  Snapshot 只读 phase 1 已不再是 `UNWIRED`：`BackendState`、三个固定 RPC、main exact IPC、frozen preload、
  aggregate `LovelyResApi` 与 App page registry 已中央接线，main 公开 API 从 67 精确增加到 70。App 只把当前
  opaque `bindingHandle` 交给 `SnapshotPage`，不传 `ActiveSshTarget`、connection/host/port/username/timestamp
  或其他公开目标摘要；断连会清理该 binding 的 catalog，页面卸载和晚到结果继续失败关闭。
  Core 预投影 hardening gap 同轮关闭：portable snapshot document 在反序列化前受 128 MiB encoded-size
  上限约束，目录/取证索引在 deserializer 中分别硬限 64/10，forensic diff 在建立集合前同时执行每字段
  2,048 行与总计 8,192 行上限。篡改的 oversized/count 文档与过量 diff 输入均有 fail-closed 测试。
  已观察证据包括 `snapshot_read_api_standalone.rs`、central backend RPC、core all-targets、Electron 89 个
  Vitest 文件/460 项、exact70 source gate，以及
  `target/electron-debug/7078e63f-be4f-47be-a3bf-6d50df216d1a/evidence` 的断连/伪造 capability/CDP/
  capturePage。真实 Linux/SSH 的 populated index、权限拒绝、断连、TTL、目标切换与 corrupted-store 实机
  矩阵仍为 `NOT_RUN`。create/capture/export/restore/delete/journal mutation、文件、terminal 和 AI 属于后续
  独立安全设计，phase 1 不提供 API 或按钮；因此页面仍为 `Pending`，不得标记 Completed。
- Emergency Commands / command workbench phase 1：
  `crates/lovelyres-electron-backend/src/emergency_command_api.rs`、
  `electron/src/shared/emergency-command-contract.ts`、`emergency-command-state.ts`、
  `emergency-command-helpers.ts` 与 `EmergencyCommandsPage.tsx` 已建立独立的固定目录执行边界。Sidecar
  load 时从真实 opaque SSH binding 捕获 `BoundSshSession` 与完整 `TargetGuard`，只调用 core
  `CommandWorkbenchService::catalog`、`detect_system`、`execute`；系统 family、raw catalog id 和固定 shell
  文本仅保存在按 binding/snapshot 隔离的 registry。中央 public API 固定且仅为
  `loadEmergencyCommandCatalog(bindingHandle)` 与
  `runEmergencyCommand(bindingHandle,snapshotHandle,commandHandle)`；renderer 只发送 opaque handles，不发送
  family、command、target/session/generation、host、path 或任意用户输入。
  Catalog 最多 64 项，title 128 bytes、description 512 bytes、timeout 1..=60 秒；registry 最多 8 份、
  每份 64 KiB、总计 512 KiB、TTL 5 分钟。系统识别 sidecar deadline 为 15 秒；执行依赖 core 固定
  30 秒 timeout 并另有 40 秒 sidecar deadline。load 全局并发 2 且同 binding 1，execute 全局并发 4 且
  同 binding 1；刷新、TTL、淘汰、断连、完整 target epoch 变化和晚到结果均失败关闭。即时执行 DTO 最多
  2,000 行/256 KiB、单行 4 KiB、serialized 384 KiB；credential-like 行、binding/session/connection/
  target identity literal 和 raw catalog id 逐行替换为固定 marker，hostile 文本只进入 React text node/`pre`。
  即时 DTO 与 portable history 是两条独立边界：core `command_workbench.rs` producer 已最小加固为 history
  只保存固定不可执行 identity、固定有界 result/exit 摘要与安全 title，不保存 raw catalog id、shell 文本或
  即时输出；现有 history schema/detail/search 保持兼容，保守 `mutating` 风险使 Electron replay consumer
  明确返回 blocked。测试直接读取 portable history 文件并证明 shell、credential marker 与 hostile output
  不落盘。
  BackendState 单例、exact2 RPC、main/preload exact91、aggregate contract 与 App binding-only page registry
  已中央接线；SSH disconnect 会在真实断连前 eager 清理 Emergency registry。当前代码面验证包括 backend
  library 190/190、standalone 31/31、Electron 98 files/532 tests、source gate/fixture self-test，以及
  `target/electron-debug/38fc68d4-41d7-43fc-ace8-ef4afdf08da5/evidence`：真实 Electron
  `webContents.debugger`/CDP 证明 catalog/run 的直接与 unknown-field 请求均拒绝且不回显，禁用的
  custom/shell/file/terminal/export/mutation/generic surface 均为 `undefined`；断连页零远端 rows、
  local-only、无内部身份，卸载重挂载仍为空，console error 为 0，并由 `capturePage` 生成截图；标题与提示
  对比度为 14.15:1/4.77:1。较早的 `136bb2ce` 报告因探针仍期待旧 API 排序而为 `FAIL`，不得引用为通过。
  仍缺 Debian/Red Hat/Alpine/SUSE/Arch/Other 的真实命令存在性、权限拒绝、timeout、取消、断连竞态和
  目标切换矩阵。
  phase 1 不提供 arbitrary command、terminal、file、export、AI、mutation plan 或邻接动作；真实 SSH/Linux
  验收继续为 `NOT_RUN`，危险 mutation/审计/验证/恢复 parity 尚未迁移，因此页面继续计为 `Pending`。
- SFTP 文件管理（已并入 SSH 窗口，写操作走计划链）：
  `crates/lovelyres-electron-backend/src/sftp_browser_api.rs` 已在 lib.rs 注册，对外是九个固定 RPC：
  `sftp-browser.open`、`.directory.list`、`.text.read`、`.download`、`.operation.plan`、
  `.operation.confirm`、`.operation.execute`、`.operation.cancel`、`.upload.stage`。SSH 窗口的 preload
  面固定为 18 个方法（主窗口仍是 118），由 gate 与 CDP probe 双向钉住。renderer 全程只拿 opaque
  handle：binding 由 main 依据发起窗口反查，终端 renderer 从不持有 binding handle，远端路径、raw
  session/guard/generation/identity、host/fingerprint、本地路径都不进 DTO。
  读取仍只调用 core `SftpService::bind_session`、`list`、`read_text`，固定从 `RemotePath("/")` 打开；
  目录压到 128 项/128 KiB、名称 256 bytes，文本压到 2,000 行/256 KiB、单行 4 KiB、序列化 384 KiB。
  下载由 main 打开系统保存对话框、再走 core `download_new(&session, &self.paths, …)`，本地目标由
  `PathGuard::ensure_safe_download_target` 校验；上传先由 main 打开系统打开对话框，sidecar 以
  `stage_upload` 把字节落到受管目录（单文件上限 64 MiB），renderer 始终不说出任何本地路径。
  一切改动目标的操作只有一条路径：plan → confirm → execute_and_verify → 失败时 restore。计划单次
  可用（取出即消费）、TTL 120 秒、同 target 最多 8 个、执行上限 90 秒；支持新建目录、重命名、
  设置权限、删除、打包（tar / tar-gzip / tar-zstd）与上传。名称是唯一的自由输入，拒绝分隔符、
  控制字符、`.`/`..` 与超长值。按“可信条件下不做主动隐藏”的约定，名称与预览一律原样呈现，只保留
  控制字符净化与体积截断。
  本地一侧由 `electron/src/main/local-browser.ts` 提供，同样只发 handle，`lstat` 描述软链接而不跟随。
  验收测试为 `sftp_browser_api.rs` 内联测试（含 closed-core-surface、名称校验、格式白名单、计划作用域）、
  core `sftp::tests::directory_list_refuses_files_symlinks_and_stale_targets_before_read_dir`、
  `sftp-browser-contract.test.ts`、`sftp-browser-state.test.ts`、`sftp-browser-page.test.tsx` 与
  `ssh-window.test.tsx`。仍缺真实 OpenSSH/Dropbear 的不可读根目录、空目录、50k/64 MiB core 上限、
  非 UTF-8/2 MiB 文件、权限拒绝、慢请求、断连、目标切换、symlink 与 swap race 矩阵，以及上传/打包/
  删除在真机上的验证与回滚证据；这些真实 SFTP 验收继续为 `NOT_RUN`，页面因此仍计为 `Pending`。
  本切片不提供解压、就地编辑、终端跳转、导出与 AI 的 API/按钮。
- Notification stack：`notification-state.ts` 与 `NotificationStack.tsx` 已实现去重、3/5 秒超时、64 项
  上限、持久项、手动关闭和 hostile plain-text。仍缺 App-level host、所有生产调用点、overlay stacking
  以及 Electron CDP timer/accessibility 证据。
- Dialog host：`dialog-state.ts` 与 `DialogHost.tsx` 已实现 alert、非秘密 prompt 和 opaque-handle-bound
  dangerous confirmation，含 UTF-8 边界、action/id 匹配、focus trap/restore、Escape 取消和危险操作
  不响应 Enter。仍缺 App-level controller、所有生产调用点、与各领域 plan/cancel 方法的 typed 绑定及
  Electron CDP；generic host 不能成为任意 backend action 或通用确认能力。
- Application log：`crates/lovelyres-electron-backend/src/diagnostic_log_api.rs`、
  `electron/src/shared/application-log-contract.ts`、`ApplicationLogOverlay.tsx` 与 main-only export helper
  已实现 500 条结构化 `tracing` ring、动态级别、有界筛选/预览、敏感字段与任意 Debug/Error 脱敏、
  volatile-only clear，以及 `wx` + fsync 的非覆盖导出。该切片不从 backend stderr 反向读取或转发内容到 renderer，renderer
  export 结果只有 basename/count/truncated，不能取得路径或正文。唯一 sidecar subscriber 现同时挂标准 fmt
  stderr layer（独立 per-layer `EnvFilter`）与 Application Log capture layer；BackendState 单例、exact5
  list/level/volatile-clear/preview/export-prepare RPC、strict main/preload、native save dialog、frozen exact112 API 与
  App-level overlay host 均已中央接线。内部 export payload 只到 main，renderer 不取得路径、正文、stderr、
  arbitrary file 或 generic invoke surface；关闭、Escape、导航、断连和卸载都会先作废 overlay 的迟到结果，
  但 SSH disconnect 不清除 process-local ring。当前 aggregate evidence 为 backend library 248/248、16 个
  standalone targets 共 451/451（总计 699 tests）、Application Log standalone 11/11、Electron full
  102 files/594 tests、typecheck/build、workspace check/Clippy/rustfmt，以及 exact112 source gate/fixture self-test。
  Electron-native CDP 证据 `target/electron-debug/19adbfae-598c-4eee-b7f1-cc2a666e3ac7/evidence` 已验证 exact5
  surface：list/level/preview/export unknown-field 请求 reject-no-echo，stderr/file/path/internal-payload/generic
  均为 `undefined`；overlay 显示 0/500 ring、无 entry/detail/error rows 或内部 payload，focus/inert/Escape restore、
  unmount/remount 清理、local-only resources、`application-log-overlay.png` capturePage 与 0 console errors 均通过。
  便携 rolling-file writer 与 packaged native save-dialog/实际落盘 smoke 仍为 `NOT_RUN`，因此 exact5 不再计为
  `UNWIRED`，但 overlay 整体仍为 `mixed`/`Pending`，不得标记 Completed。
- File Integrity：`crates/lovelyres-electron-backend/src/integrity_api.rs`、
  `electron/src/shared/integrity-contract.ts`、`integrity-state.ts`、`integrity-helpers.ts` 与
  `IntegrityPage.tsx` 已把 Phase 0 收窄为 exact5 只读 surface：preset、目标作用域 baseline 列表、comparison
  start/poll/cancel。Backend 在 dispatch 前后及结果 apply 前验证完整 `TargetGuard`，并限制 opaque handles、TTL、
  registry bytes、单 binding 并发、事件 cursor 和响应字节；`close_binding` 会中止任务并回收 handles/bytes/
  permits，晚到结果不能复活。credential、URI userinfo、binding/session/connection/target literals 与 C0 在 renderer
  前按固定规则脱敏或投影。Renderer 仅持 binding 与 opaque capabilities；切换、卸载和错配响应会主动取消并
  失败关闭，hostile text 只进入 React 文本节点。当前 evidence 为 standalone 29 tests（Integrity 专项 7）、
  contract/state/helpers/page 4 files/18 tests，以及 Electron 100 files/563 tests、typecheck/build、Clippy 与 workspace
  rustfmt。基线创建与 quarantine 明确属于远端 mutation，本 phase 不提供 API 或按钮；后续必须恢复 immutable
  plan、exact confirmation、journal、独立验证和失败恢复。仍缺 BackendState/RPC、main/preload exact5、App page
  registry、source gate、Electron CDP/capturePage 与真实 Linux/SSH 比较/取消/断连/目标切换证据。SFTP 定位也
  必须等待 keyed SFTP window 安全绑定同一 TargetGuard；在中央接线前继续计为 `UNWIRED`/`Pending`。
- Kubernetes 只读调查 phase 1 已中央接线：`crates/lovelyres-electron-backend/src/kubernetes_read_api.rs`、
  `electron/src/shared/kubernetes-read-contract.ts`、`kubernetes-read-state.ts`、
  `kubernetes-read-helpers.ts` 与 `KubernetesPage.tsx` 已实现真实 opaque SSH binding、完整
  `TargetGuard` 前后验证，以及只调用 core `KubernetesService` 的 availability、namespaces、pods、
  deployments、nodes、有界详情和最近 Pod 日志。Renderer 只发送 binding/snapshot/row capability；
  namespace scope 也由目标绑定的 Namespace 行 capability 表达，不发送 session、guard、generation、
  identity、资源 UID/名称/namespace、命令、日志参数或远端路径。快照为 5 分钟 sliding TTL，registry
  限 24 个/32 MiB，每快照限 4 MiB，列表限 500 行/2 MiB，详情 256 KiB、日志 512 KiB，并限制全局与
  逐 binding 并发；过期、淘汰、目标切换及晚到结果均失败关闭。owner 为 Electron Kubernetes read
  migration。BackendState 已注册 exact4 固定 RPC，main/preload/aggregate contract 只公开
  `getKubernetesAvailability`、`listKubernetesResources`、`getKubernetesResourceDetail`、
  `getKubernetesPodLogs`；main 对请求与响应作严格 exact-object 验证，unknown/forged 参数固定失败且不回显。
  `App`/`KubernetesPage` 只接收 opaque `bindingHandle`，不接 target identity、connection/session metadata；
  SSH disconnect 在实际断连前 eager `close_binding`，过期、淘汰、目标切换及晚到结果均失败关闭。验收测试为
  `kubernetes_read_api_standalone.rs`、`kubernetes-read-contract.test.ts`、`kubernetes-read-state.test.ts`、
  `kubernetes-read-helpers.test.ts`、`kubernetes-page.test.tsx` 与 `kubernetes-read-boundary.test.ts`。
  source gate 与 fixture self-test 已接受 main exact89、Kubernetes exact4、strict validators、backend
  redaction/guard/bounds、opaque-only App、forbidden surfaces 及 eager close-before-disconnect；最近完整 Electron
  check 为 97 files / 522 tests，backend library 为 177/177，standalone 为 38/38。Electron-native CDP 证据
  `target/electron-debug/0ad5379b-1186-4f2c-892e-0b54a87cd4d1/evidence` 已验证 main exact89、forged/unknown
  reject-no-echo、forbidden scale/restart/delete/cordon/drain/exec/file/terminal/export/generic `undefined`、断连
  title/prompt/零 rows/local-only/no internal identity、`kubernetes-disconnected.png` capturePage、unmount/remount
  clear、Kubernetes/全局 console error 0，以及标题/提示 14.02:1/4.73:1 对比度。真实 Linux/SSH/
  Kubernetes 的权限拒绝、空集/populated、超限、日志截断、取消、断连及 target-switch 同样 `NOT_RUN`。
  SFTP 定位在 keyed SFTP window 能安全绑定同一 TargetGuard 前不提供入口；scale/restart/delete/cordon/drain、
  exec、文件、终端、导出及任何 generic mutation 均属于后续独立安全设计，仍为 `UNWIRED`。因此页面整体
  保持 `mixed`/`Pending`，不把 phase 1 的代码面接线误报为完整 parity。
- 网络抓包 live phase 1 已中央接线：`crates/lovelyres-electron-backend/src/packet_capture_live_api.rs`、
  `electron/src/shared/packet-capture-live-contract.ts`、`packet-capture-live-state.ts`、
  `packet-capture-live-helpers.ts` 与 `PacketCapturePage.tsx` 已实现真实 opaque SSH binding、完整
  `BoundSshSession`/`TargetGuard` 前后验证，并且只调用 core `PacketCaptureService::list_interfaces` 与
  `start_live`；远端命令、tcpdump 参数 quoting、PTY 与 `LivePacketCapture` 生命周期仍由 core 持有。
  Renderer 只发送 binding/interface/capture capability 和严格的 filter/packetLimit/durationSeconds，
  不发送 interface 名、session、guard、generation、identity、命令、远端路径或 core capture id。
  interface capability 为 5 分钟 TTL，限 256 项/2 MiB；capture 限全局 8 个、每 binding 1 个，最多保留
  512 个事件/400 个数据包/4 MiB，每次 poll 限 100 个事件/512 KiB，单事件 64 KiB，并限制全局 12 个、
  每 binding 3 个并发操作。重复 start、过期/淘汰、断连、目标切换、artifact 事件、cursor reset 和晚到
  结果均失败关闭；失活、切换、卸载、poll 失败和终态都会真实调用 `request_stop`/`stop`，公开失败不回显
  attacker-controlled tcpdump stderr。BackendState 单例、exact4 RPC、main/preload exact100、aggregate contract、
  App binding-only page registry 与 SSH disconnect 前 awaited `close_binding` 均已接线。当前代码面验证包括
  backend library 221/221、standalone 33/33、Electron 100 files/562 tests、all-target check/Clippy、workspace
  rustfmt，以及 source gate/fixture self-test。`target/electron-debug/2d9db536-7817-4047-9c41-87e90a2e48d9/evidence`
  的真实 Electron `webContents.debugger`/CDP 已验证 main exact100、8 个 direct/unknown-field 请求拒绝且不回显、
  command/file/terminal/download/export/AI/mutation/generic surface 均为 `undefined`、断连页零远端 rows、local-only、
  无内部身份、卸载重挂载清空、Packet Capture/全局 console error 为 0，并由 `capturePage` 生成截图；标题与提示
  对比度均为 11.10:1。仍缺真实 Linux/SSH 的 tcpdump 缺失、root/non-interactive sudo、
  `CAP_NET_RAW`/`CAP_NET_ADMIN`、权限拒绝、空接口、超限、超时、PTY backpressure、断连、目标切换和
  取消矩阵。PCAP evidence/download/export/cleanup、案件持久化、任意文件/终端和 AI 属于后续独立安全链，
  phase 1 不提供 API 或按钮；整个页面继续为 `Pending`，但 live phase 1 不再计为 `UNWIRED`。
- Firewall 只读调查 phase 1：`crates/lovelyres-electron-backend/src/firewall_read_api.rs`、
  `electron/src/shared/firewall-read-contract.ts`、`firewall-read-state.ts`、
  `firewall-read-helpers.ts` 与 `FirewallPage.tsx` 已实现真实 opaque SSH binding、完整
  `BoundSshSession`/`TargetGuard` 前后验证，并且只调用 core `FirewallService::inspect` 与当前目标
  `list_changes`。规则在 sidecar 再限制为 256 KiB 并清理非换行/Tab 控制字符；history 最多 256 条，
  只返回 opaque change handle、闭合 backend/engine/kind/state、512-byte 标签、SSH 端口和时间戳，绝不返回
  raw change id、operation ids、remote root、object name、preflight digest、路径、session、guard、generation、
  identity 或命令。快照为 5 分钟 TTL，registry 限 12 个、每个 768 KiB、总量 4 MiB，history 响应限
  512 KiB，并限制全局 8 个、每 binding 2 个并发读取；同一目标刷新复用稳定 change handle，过期、淘汰、
  断连、目标切换及晚到结果均失败关闭。页面只有“当前规则/变更历史”、手动刷新、规则搜索和通过 injected
  clipboard callback 的有界纯文本复制；不会回退到 renderer `window` clipboard API。owner 为 Electron
  Firewall read migration。中央 `BackendState` 现已共享同一套 core services/SSH registry，并且只注册
  `firewall.inspect` 与 `firewall.change-history.list` 两个 strict params RPC；main/preload/LovelyResApi 也只增加
  arity-1 的 `inspectFirewall` 与 `listFirewallChangeHistory`，使 main frozen preload 从 exact70 变为 exact72。
  SSH disconnect 在真实断开前 eager 清理该 binding 的 Firewall capabilities，App 只把当前 opaque
  `bindingHandle`、固定 API 与既有 128 KiB main-owned clipboard callback 交给页面；UTF-8 截断不会切开
  scalar，并显示明确截断提示。固定错误不回显 hostile params，页面失活、断连与 scope 切换拒绝晚到结果。
  验收测试为 `firewall_read_api_standalone.rs`、中央 RPC/IPC/preload exact tests、
  `firewall-read-contract.test.ts`、`firewall-read-helpers.test.ts`、`firewall-read-state.test.ts`、
  `firewall-page.test.tsx` 和 Electron `webContents.debugger`/`capturePage`；CDP 证据包含 exact72、两次伪造
  capability 拒绝且不回显、无 Firewall mutation/generic/file/terminal/export surface、断连空态、导航重挂载、
  本地资源、对比度、零 console error 与 `firewall-disconnected.png`。仍缺真实 Linux/SSH 的
  iptables/nftables/UFW/firewalld 缺失、active/empty 组合、root/non-root、非交互 sudo、超限、断连和目标切换
  成功矩阵，全部保持 `NOT_RUN`。本阶段明确不调用 `reconcile`，所以过期的
  `awaiting-keep` 记录不会被只读层擅自解释为已经自动恢复。任何 block/allow/isolate/keep/restore/reconcile
  必须在后续 phase 2 重新建立 core-owned immutable plan、exact dangerous confirmation、journal、远端
  dead-man、独立 verify 和 restore 闭环，并完成真实自锁/自动恢复矩阵；phase 1 不提供 mutation API、按钮、
  generic execute、terminal/file/export；由于 phase 2 与真实 Linux 矩阵尚未完成，页面继续计为
  `Pending`，不得据此宣称 Firewall 完整迁移。
