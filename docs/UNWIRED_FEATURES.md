# 原生功能接线与限制清单

本清单只记录当前 Rust/GPUI 主线中已经实现但尚未接入原生页面或窗口的模块，以及因安全契约或实机证据不足而刻意保持关闭的能力。

新增实现如果不能在同一变更中完成 UI 接线，必须登记：crate 路径、领域 owner、缺少的 entity/lifecycle/render 或窗口接线、目标绑定要求，以及可验证的完成条件。

## 已实现但未接线

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
  完整状态的精确 `httpd -M/-L/-t` transport，也没有 GPUI capability 接线。普通合并 stderr、lossy
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

- 配置生成器与远程 middleware 树（领域 owner：`lovelyres-gpui`）已经接入只使用安全名称/静态说明
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
  Redis 和 Tomcat 仍只有只读结构解析，没有 directive/attribute 值模型、按工件/版本隔离的 schema 或配置生成器
  写回视图，查询会明确返回 `MissingReviewedRecipe`；不能因为 parser 能切分文本/XML 就生成原始配置字符串。
  真实 Nginx/Apache 与数据库目标的 capability/readback 矩阵仍为 `NOT_RUN`。

- `lovelyres-core::line_config_visual::LineConfigTargetPolicy`（领域 owner：`lovelyres-core`）已经为
  MariaDB option file 提供字段私有、由产品与完整四段版本推导的 `?includedir` 语法门禁。当前
  allowlist 只包含官方源码逐个审校的 11.4.10、11.8.6 与 12.2.2；默认 parse/read、MySQL、相邻或
  未知补丁全部保持 opaque，且 document 在 replace/add/update/reparse 后保留同一 policy。GPUI
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
  解析器也仍未接远端 transport 或 GPUI。
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

相关验收契约见 [GPUI Windows 可行性门禁](GPUI_FEASIBILITY_GATE.md) 与 [SSH 兼容性与安全策略](SSH_COMPATIBILITY.md)。

- `lovelyres-core::database_config_inventory`（owner：database core）已实现 MySQL/MariaDB plugin 与 MySQL component 的闭合只读 SQL plan、typed bounded snapshot、带唯一末行 `complete_v1` 的 headerless hex-TSV parser，以及共享 `DatabaseService` 的无密码 profile 只读路径。服务保存精确 runtime identity、完整 `TargetGuard` 与 profile digest，并在两阶段查询之间、返回前和消费前提供复核；密码 profile 在第一次 SSH 前失败关闭。尚未接入 GPUI 或 core-owned native database protocol；完成条件是把 snapshot 接到 GPUI 且页面只能读取 `public_value()`，并覆盖 MySQL 8.0/8.4、MariaDB 10.11/11.4 的真实权限、空表、重复行、超限、取消与目标切换矩阵。`complete_v1` 只用于发现普通截断，不能把恶意服务端变成可信来源。真实数据库验收仍为 `NOT_RUN`，且本模块不授权任何安装、卸载或其他 mutation。
