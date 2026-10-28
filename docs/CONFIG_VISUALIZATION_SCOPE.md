# 全面配置可视化范围与验收边界

LovelyHawk 面向应急响应比赛，配置中心不能依赖一个封闭的“常用参数表”。本项目所说的“全面可视化”分成两层：

1. **语法全面**：目标配置文件中的已知、未知、重复和第三方节点都必须可见；未修改内容逐字节保真；无法安全理解的区域作为不透明原文保留，绝不猜测重排。
2. **语义可证明**：参数是否合法、是否生效以及应 reload 还是 restart，必须由精确的产品、版本、edition、组件角色、目标机能力和厂商校验结果证明。本地解析成功不等于目标配置有效。

“可以看见”与“获准修改”是两条独立能力。目录允许一个工件进入无损只读视图，
不代表页面可以新增、修改、移动、删除或把它标记为已验证。当前目录唯一可变更策略名为
`LosslessLocalDraft`：它只授权本地有界、无损草稿编辑和另存，不授权“已验证生成”、远端应用、
激活或部署；后续能力仍必须重新检查目标产品/版本 schema、capability 和实际校验器。

## 三轴模型

数据库连接协议、数据库产品和配置语法是三件不同的事：

- `DatabaseProtocol`：MySQL、PostgreSQL、Redis、MongoDB、DM 等客户端协议。
- `DatabaseProduct`：TiDB、OceanBase、openGauss、KingbaseES、DM、GBase 等具体产品。
- `ConfigArtifactDialect`：MySQL option file、INI、PostgreSQL conf、HBA、TOML、YAML、Properties、Flat KV、XML、JSON、运行时 SQL、云 API 或生成态二进制。

例如 TiDB 使用 MySQL wire protocol，但服务组件配置是 TOML；OceanBase 兼容 MySQL 协议，但 `observer.conf.bin` 是内部生成态，配置入口是运行时参数或 OBD YAML。不能因为协议兼容就复用错误的文件格式。

## 配置表面

每个配置工件必须明确属于以下一种表面：

| 表面 | 行为 |
| --- | --- |
| File | 可导入、无损可视化、安全另存；部署必须走 CAS、备份、验证和恢复链路 |
| RuntimeSql | 通过厂商规定的查询/修改语句读取和变更；不得伪造成文件 |
| CloudApi | 由托管平台 API/参数模板管理；无主机文件权限时不显示本地写入 |
| GeneratedReadOnly | 服务器或工具生成的 JSON/二进制/状态文件，只读展示，禁止普通文本编辑 |

这四类是“配置工件表面”，还不是完整的生效来源图。命令行参数、环境变量、systemd/service
manager、厂商运维工具、include 搜索顺序和运行时持久化层可能覆盖文件。当前版本尚未把这些来源
及其优先级串成 target-bound effective view，因此本地文件草稿绝不能显示成“目标当前有效配置”。

## 产品与语法族

| 产品/家族 | 主要配置工件 | 语法族 | 当前落地方向 |
| --- | --- | --- | --- |
| Nginx | `nginx.conf`、include 文件 | Nginx statements/blocks | 通用无损树；目标机 `nginx -t/-T` 另行验证 |
| Apache HTTPD | `httpd.conf`、`apache2.conf`、include 文件、`.htaccess` | directives/sections/logical lines | 本地通用无损树与远程只读候选图；远程 middleware 已有有界 Include 图、原生 `httpd -t`、全图/目录 CAS 及恢复，但 exact runtime invocation provider 与 matching-endpoint graph/capability 事务仍未接线，Phase A 对 Apache plan/execution 失败关闭 |
| MySQL/MariaDB/GreatSQL | `my.cnf`、`my.ini`、included `.cnf`、MySQL `mysqld-auto.cnf`、MySQL `auto.cnf` | MySQL/MariaDB option file；MySQL ReplicationIdentity | section、重复项、大小写敏感的 `!include`/`!includedir`；MariaDB `?includedir` 只在已审校的 11.4.10/11.8.6/12.2.2 target policy 下结构化，默认及未知补丁继续 opaque；`mysqld-auto.cnf` 只读；MySQL `auto.cnf`（不是 `mysqld-auto.cnf`）是服务端生成的 ReplicationIdentity 来源，仅按 `SourceBacked` + `ReadOnly` 展示，禁止修改，未来须与运行时 `@@server_uuid` 回读做 source correlation；MySQL 8.4 静态 schema 仅覆盖 `>=8.4.0,<8.5.0`，8.5+ 不得继承；无版本 `mysql-option-file`/`mariadb-option-file` catalog validator 统一为 `SyntaxOnly` |
| MySQL plugin registry | `mysql.plugin` 与运行时 plugin inventory | `mysql-plugin-registry` | P0-C 只读 catalog：`RuntimeSql` + `RuntimeReadBack` + `VendorSchemaRequired`；不进入配置 selector，不提供 mutation，也不等价于 option-file/命令行的 startup 来源或 comprehensive plugin inventory |
| MySQL component registry | `mysql.component` 与运行时 component inventory | `mysql-component-registry` | P0-C 只读 catalog：`RuntimeSql` + `RuntimeReadBack` + `VendorSchemaRequired`；不进入配置 selector，不提供 mutation，也不等价于 option-file/manifest 的 startup 来源或 comprehensive component inventory |
| MariaDB plugin registry | `mysql.plugin` 与运行时 plugin inventory | `mariadb-plugin-registry` | P0-C 只读 catalog：`RuntimeSql` + `RuntimeReadBack` + `VendorSchemaRequired`；不进入配置 selector，不提供 mutation，也不等价于 option-file/命令行的 startup 来源或 comprehensive plugin inventory |
| PostgreSQL | `postgresql.conf`、`pg_hba.conf`、`pg_ident.conf` | PG conf、顺序敏感 HBA/ident | 分别建模，不能把 HBA 当普通 key/value |
| openGauss/MogDB/Vastbase/KingbaseES/GBase 8c/AntDB/HighGo/OpenTenBase | 产品 conf、HBA、ident | PostgreSQL 家族 | 语法复用，语义 schema 按产品版本隔离 |
| DM（达梦） | `dm.ini`、`dmap.ini`、`dminit.ini`、`dmthrd.ini`、DCR/CSS/ASM、归档/MAL/Watcher/Monitor/Timer、`sqllog.ini` 等 | INI/section/flat KV/vendor | 已按角色登记 16 个文件工件；`dmthrd.ini` 已用 source-backed INI 接入本地无损草稿，仅在 `dm.ini` 的 `DMTHRD_INI=1` 时使用。`dmdcr_cfg.ini` 的 `//` 注释及重复 `[GRP]` + `[CSS]`/`[ASM]` 成员是有序原子结构，`dmdcr.ini` 的 `DMDCR_*_STARTUP_CMD` 是命令载荷；两项现均以 `VendorText` + `VendorSchemaRequired` 仅登记 catalog 和原始文本可读性，不进入结构化 selector，也不授权本地草稿或增删改移。除 `dm.ini`/`sqllog.ini` 的检查型 Partial schema 外，其余工件的精确 build 语义与厂商 provider 仍待补，`dmthrd.ini` 的参数 schema、目标 exact build/CPU 上下文、匹配 build 的厂商工具校验及部署/激活均未验证 |
| TiDB/TiKV/PD/TiFlash/TiProxy/TiCDC/Lightning | 各组件 TOML、TiUP/Operator YAML、运行时变量 | TOML、YAML、RuntimeSql | TiDB/TiKV/PD 8.5.7 有 Partial schema；TiFlash、TiFlash learner、TiProxy、TiCDC server/changefeed、Lightning 六个精确 TOML 工件已登记并接入只读视图，各组件自身版本 schema、命令行/环境覆盖、etcd effective state 与运行时 provider 待补 |
| OceanBase/OBProxy/OBD | 运行时参数、OBD YAML、内部 `observer.conf.bin` | RuntimeSql、YAML、GeneratedReadOnly | `oceanbase-observer-runtime` 仅以 `SHOW PARAMETERS` / `GV$OB_PARAMETERS` 盘点 observer 参数；`oceanbase-obproxy-runtime` 仅以 `root@proxysys` 执行 `SHOW PROXYCONFIG`；`oceanbase-tenant-variables` 限 CE 4.x MySQL-mode，以 `SHOW GLOBAL VARIABLES` / `SHOW SESSION VARIABLES` 盘点租户变量，global 值仅影响新连接；`oceanbase-backup-archive-state` 只读 `DBA_OB_BACKUP_PARAMETER`、`DBA_OB_ARCHIVE_DEST`、`DBA_OB_BACKUP_JOBS` 与 `DBA_OB_BACKUP_JOB_HISTORY`。四者均为 RuntimeSql+RuntimeReadBack+VendorSchemaRequired，不提供 mutation/activation；OBD 部署入口另行建模，内部 `observer.conf.bin` 继续为 GeneratedReadOnly。 |
| GBase 8a | GNode/GCluster option `.cnf`、两份 `cluster_common.cnf`、distribution XML、`gcware.conf` | MySQL option、generated JSON、XML、custom nested | GNode/GCluster 角色已精确拆分；两份同名厂商生成 JSON 按组件隔离只读；`gcware.conf` 用专用 source-backed 嵌套树；尚无目标精确版本 schema、厂商校验或远端部署 |
| GBase 8s | `onconfig`、`sqlhosts[.<instance>]`、`cmsm.cfg`、`concsm.cfg`、`gbasedbt.rc`、`~/.gbasedbt`、`ac_config.std`、`sm_versions`、`plconfig`、`IMCconfig`、OM XML | whitespace/custom flat/XML/vendor text | 只有 `onconfig` 与五列 `sqlhosts` 已有证明的本地语法视图；新增复杂 VendorText 工件只做 catalog 登记且不进入 selector，`ac_config.std` 只读发现；精确版本 schema、厂商校验与实机待补 |
| TDSQL MySQL / TDSQL PostgreSQL | 参数模板、API、私有化组件工件 | MySQL/PG/CloudApi/vendor | 协议族与托管/私有化四类分开；托管实例不得伪装成本地文件 |
| GoldenDB | 计算节点 `proxy.ini`、运行时参数及私有化集群配置 | INI/MySQL protocol/vendor | `proxy.ini` 已无损只读；v6.1.03.10 的 5 个精确枚举项已有 Partial 元数据，未知集群文件仍为 `VendorSchemaRequired` 且不映射通用解析器 |
| PolarDB-X | CN properties、DN option file、Operator YAML | Properties、MySQL option、YAML | 与托管 PolarDB 分开 |
| SequoiaDB | standalone/coord/catalog/data 的 `sdb.conf`；quickDeploy 的 `sequoiadb.conf`、`mysql.conf`、`mariadb.conf`、`postgresql.conf` | Flat KV、角色绑定的 quickDeploy vendor CSV | 四种节点角色与四种 quickDeploy 文件独立登记；cluster/SQL instance 使用各自的 bracket-aware source-backed 只读方言，快照 JSON 不是配置文件 |
| YashanDB | `yasdb.ini`、`yasdb.spfile`、`yasdb.pwd`、yasboot TOML | flat KV、generated binary、TOML | `yasdb.ini` 已按官方禁改要求只读可视；v23.5.4.100 + `official-doc-family-23.5.4.100` 有 15 项 Partial 只读元数据；spfile/口令文件仅登记为厂商二进制，禁止文本读取；yasboot 继续 schema-gated |
| 神通数据库 | `ShenTongNative` / `ShenTongMpp` / `ShenTongOpenGauss` 当前均为零配置工件 | VendorNative（产品身份）；零 parser | 已拆成自研内核、MPP 和 openGauss 版三个产品；不虚构 `shentong-server-config`，不猜测 `oscar.conf`/`OSRDB.conf`，获得精确交付证据前不开放导入、解析或 schema |

## 当前结构化格式状态

- JSON 已使用 source-backed 的有序只读树：保留重复键、原始字符串、原始数值和成员顺序；
  JSON5、畸形输入、非 UTF-8 和超出资源边界的输入降级为整段不透明字节。
- YAML 的可证明安全子集已使用 source-backed 的有序只读树：保留缩进映射、序列、重复键、
  注释、多文档边界和原始字节。anchor、alias、tag、merge、flow collection、block scalar、
  directive、complex key、未证明的转义或缩进只作为所属的最小原子不透明区域；边界无法证明时
  才降级整份文档，绝不让一个高级构造吞掉前后可证明安全的文档。
- XML 的可证明安全子集已使用 source-backed 的有序只读树：保留元素、属性顺序与引号、文本、
  注释和 mixed content。DTD、CDATA、自定义 PI、命名空间上下文歧义及含实体引用的值作为原子
  不透明区域；解析器不展开实体、不读取外部资源，也不执行 XInclude。
- GBase 8a `gcware.conf` 已使用专用 source-backed 嵌套只读树：保留原始字节、块层级、重复项、
  `key: value` 项和局部未知语法；无法证明结构边界时整份降级为不透明字节。当前没有目标精确版本
  schema、厂商校验器或远端部署链路，因此不能新建骨架、增删改移或另存为可部署配置，只能导入、
  预览并另存本地只读副本。
- GBase 8a 的 `gbase_8a_gbase.cnf` 与 `gbase_8a_gcluster.cnf` 已分别绑定 GNode/GCluster，避免把
  GNode 误标成泛化 Server。`$GBASE_BASE/config/cluster_common.cnf` 与
  `$GCLUSTER_BASE/config/cluster_common.cnf` 是两个同名但组件隔离的厂商生成 JSON，只读结构可视，
  绝不生成不存在的 `gnode.cnf`，也不继承 MySQL 参数 schema。
- GBase 8s 已按实际角色登记 `cmsm.cfg`、`concsm.cfg`、`gbasedbt.rc`、`~/.gbasedbt`、
  `ac_config.std`、`sm_versions`、`plconfig` 和 `IMCconfig`。它们的块、宏、安全模块、环境覆盖及
  工具专用字段还没有专用 source-backed parser，因此保持 catalog-only，不经通用 VendorText
  方言进入配置生成器 selector；只有早已证明的 `onconfig` 与五列 `sqlhosts` 可进入本地语法
  视图。`ac_config.std` 是复制后再修改的厂商模板，目录中只标记为只读发现；PSM 目录以及
  `ixbar.<servernum>` / `oncfg_<servername>.<servernum>` 恢复状态不是普通文本配置，未误登记为
  可视或可编辑工件。精确实例路径发现、厂商 validator、部署与恢复演练均为 `NOT_RUN`。
- 神通已拆成 `ShenTongNative`、`ShenTongMpp` 与 `ShenTongOpenGauss` 三个产品身份，三者均只声明
  `VendorNative`，当前零 artifact、零 parser、零生产 schema。openGauss 发行版认证中同一神通
  V7.0.21 产品版本名同时出现在 openGauss 3 与 openGauss 6 底座记录，所以不得仅根据产品版本名
  继承 openGauss 的 `postgresql.conf`/HBA/ident 工件或参数 schema。已删除虚构的
  `shentong-server-config`，也不登记未由现行官方交付证据确认的 `oscar.conf`/`OSRDB.conf`；
  真实交付包、edition、配置路径、语法、厂商校验与部署验证全部为 `NOT_RUN`。
- TiDB 辅助组件的 `tiflash.toml`、`tiflash-learner.toml`、`tiproxy.toml`、`ticdc.toml`、
  `changefeed.toml` 与 `tidb-lightning.toml` 已作为六个组件隔离的精确工件接入 source-backed TOML
  只读视图；TiCDC server 文件名是 `ticdc.toml`，不是旧的泛化 `config.toml`。六者只允许导入、
  逐字节预览和另存本地只读副本，不提供 starter、本地草稿、增删改移、应用或部署。它们没有匹配
  的生产 schema，绝不继承 TiDB Server 8.5.7 参数包；TiProxy 必须按自身组件版本独立匹配，不能用
  TiDB Server 版本推断。真实 TiFlash/TiProxy/TiCDC/Lightning 集群验证仍为 `NOT_RUN`。
- SequoiaDB quickDeploy 的 `sequoiadb.conf`、`mysql.conf`、`mariadb.conf`、`postgresql.conf`
  已使用两个角色绑定的 bracket-aware source-backed 只读方言：cluster 只接受精确五列表头，三个
  SQL instance 工件只接受精确四列表头；跨角色导入会整份失败关闭为敏感不透明字节，并仍使用所选
  catalog 工件的文件名。物理行首字节为 `#` 的官方默认注释可见，未加引号的
  `[host:port,host:port]` 保持为一个 `coordAddr` 字段；odd/even quote、歧义方括号、未知列布局和
  其他未证明行只把该物理行标为敏感 opaque，后续可证明安全的 sibling 仍可见。`mariadb.conf`
  的证据来自 SequoiaDB 官方仓库 `master` commit `6d49550`，尚未绑定任何 released version，不能
  推导版本语义。四个工件继续保持 `VendorSchemaRequired`：当前无匹配产品/精确版本 schema、可调用
  的厂商 validator 或远端 deploy 链路，只能导入、预览并另存本地只读副本；真实
  SequoiaDB/SequoiaSQL 验证仍为 `NOT_RUN`。
- YashanDB 23.5 的 `yasdb.ini` 已作为精确文件工件进入 flat key/value 只读视图；生产 registry 仅在
  exact v23.5.4.100 与证据族 guard `official-doc-family-23.5.4.100` 同时匹配时提供 15 项 root
  uppercase `Partial` 元数据及官方文档默认。该 guard 表示审校文档族，不是 Enterprise/AI 商业
  edition 推断；lowercase、复杂但未审校及未列参数继续保持 `VisibleUnvalidated`。选择 schema 只
  增加只读状态说明，不会把默认值写入输入、原文、复制或另存，也不会开放本地草稿、starter、
  增删改移、应用或部署。`yasdb.spfile` 和 `yasdb.pwd` 分别由 `ALTER SYSTEM` 与 `yaspwd` 管理，
  只登记为不可文本读取的 `GeneratedReadOnly` 厂商二进制；真实目标发现、`ALTER SYSTEM`、实际值
  回读、厂商过程和恢复验证仍为 `NOT_RUN`。
- MariaDB 的权限错误容忍型目录指令没有被建成一个宽泛新方言：前缀 `?` 只使服务端忽略
  `includedir` 的目录权限错误，并不使不存在目录等其他失败自动可选。core 的
  `LineConfigTargetPolicy` 只对官方源码
  已逐个审校的 MariaDB 11.4.10、11.8.6 与 12.2.2（revision 0）识别精确小写
  `?includedir`；相邻补丁、其他 minor、MySQL/兼容产品和无版本文档全部失败关闭。`?include`、
  大小写变体、含 `#` 的歧义行及无终止换行的末行仍作为 opaque 保真。前端尚无完整 patch
  版本选择器，因此默认导入路径不会启用该策略；真实 MariaDB 各版本与 Windows 末行行为仍为
  `NOT_RUN`。
- MySQL/MariaDB Batch A 已把静态 schema 与 catalog validator 的证明边界锁定：MySQL 8.4
  静态 schema 仅覆盖 `>=8.4.0,<8.5.0`，8.5+ 不得继承；无版本的 `mysql-option-file` 与
  `mariadb-option-file` catalog validator 统一为 `SyntaxOnly`。MySQL 8.0.11–8.0.15 没有
  `--validate-config`；MySQL `>=8.0.16`（含 8.4）虽可在隔离环境运行
  `mysqld --validate-config`，但它不初始化 storage engines、plugins、components，不能作为完整
  validator。MariaDB 10.11/11.4 没有专用 `--validate-config`，该选项到 MariaDB 13.0 才引入；
  `--print-defaults`/`my_print_defaults` 只发现并展开选项，不是 validator。默认名 `my.cnf`
  只是 Unix 常见建议；实际路径以及 Windows 的 `my.ini`/`my.cnf` 必须按目标实例发现。include
  graph、suffix、platform 组合与真实 VM 矩阵仍为 `UNWIRED`/`NOT_RUN`。
- 所有不透明结构化区域默认按敏感内容处理：页面不显示正文预览，也不开放普通复制；
  原字节只保留在 core 文档与显式安全另存边界。
- `mysqld-auto.cnf`、`postgresql.auto.conf`、Kingbase auto conf、OBD 注册状态等生成态
  工件始终只读。当前 JSON/YAML/XML 树均为只读；TiUP/Operator/OBD 输入 YAML 和部署 XML
  即使语法可视，也必须等匹配产品与版本的 schema 后才允许变更。

## 当前版本化参数 Schema

当前生产 registry 已接入 18 个经官方资料审校的 `Partial` 参数包：MySQL 8.0.11–8.0.x、
MySQL 8.4.x（<8.5.0）、MariaDB 10.11/11.4、PostgreSQL 16/17/18、TiDB/TiKV/PD 8.5.7、
openGauss 5.0 enterprise/6.0 lite、KingbaseES V8.6.7.12/V9.3.11，以及两个 DM8
仅检查包、GoldenDB v6.1.03.10 `proxy.ini` 和 YashanDB v23.5.4.100 `yasdb.ini`。匹配同时要求产品、组件、工件、精确 edition/证据族和有类型的版本区间；别名与 TOML/INI
容器路径只做白名单精确匹配，绝不按兼容协议或相似名称猜测。

TiDB 8.5.7 的三个参数包只绑定 TiDB Server、TiKV 与 PD；TiFlash、TiFlash learner、TiProxy、
TiCDC server/changefeed 和 TiDB Lightning 没有生产 schema。尤其 TiProxy 的版本线独立，不能因
同属一个部署拓扑就继承 TiDB Server 的版本或字段语义。

所有这些包仍是 `Partial`：已列参数可显示作用域、生效方式、风险、竞赛依据、敏感级别、
所需 capability 和官方参考；未列参数保持 `VisibleUnvalidated`。选择静态 schema 只启用本地
元数据与提前脱敏，不证明当前目标确实属于该版本/edition、不读取原值做验证，也不改变工件
原有编辑策略。DM8 文档未锁定补丁版本，因此所有 DM 参数还要求目标回读
`dm8.exact-build-schema-confirmed`，未满足时不得自动应用。

固定默认值使用独立的 typed `documented_default` 元数据，不从枚举顺序、文案或 starter 反推。
当前 GoldenDB 精确版本的 5 个公开枚举项与 YashanDB 精确版本/证据族的 15 项参数具备此证据，
合计 20 项；页面只读显示并明确标注它不是目标当前值、推荐值或自动填充值，也不会进入输入框、
草稿、预览、复制、另存或部署权限判断。

目前只有原生 MySQL、MariaDB 与 PostgreSQL 的起始草稿含经审查的常见默认项；兼容协议产品、
国产数据库和分布式组件只提供说明性空骨架或要求导入目标原文件，避免把 3306、5432、
SCRAM 等上游默认值错误套给 KingbaseES、openGauss、GBase、TiDB 等产品。

## 搜索、逐项说明与证据等级

配置生成器现在提供有界的本地搜索与逐项说明。文档树只按安全节点名称和静态结构类型匹配，
命中时保留原始顺序及其父链；选择精确的已审 schema 后，参数目录会列出该 schema 的完整参数集，
包括当前文件中尚未出现的参数，并仅按 canonical 安全名称和已审静态说明搜索。每项展示静态含义、
类型、作用域、生效方式、风险、参考资料和允许的枚举/范围值域。目录选择和搜索都只是只读导航：
不会插入缺失参数，不会把 documented default 写入输入框、文档、草稿或另存内容，也不会修改原文件。

同一页面现在另有统一的“我想实现什么”入口，覆盖 4 个 middleware 产品和 33 个数据库产品，并明确区分
`LocalDraftRecipe`、`CatalogGuidance` 与 `Unavailable`，绝不把空结果伪装成支持。首批闭合配方包括 Nginx
静态站点、反向代理、指定路径返回 HTTP 403，以及 Apache 2.4 的指定路径及子路径 `Require all denied`、
禁用 TRACE（返回 405）和减少版本信息暴露三个本地草稿。Apache 的后两项只使用闭合的 core 指令，仍未
运行目标端 `httpd -t`、模块能力检查或真实请求验证；`ServerTokens Prod` 仍会标识 Apache。

数据库侧把上述 18 个版本化 schema 的全部参数懒投影为可搜索目标，并提供远程访问、慢查询、TLS、审计、
连接容量、查询超时、事务持久性、密码存储、连接准入、空闲会话保护和连接事件日志十一组多步骤检查清单；
清单会分别列出已经定位的精确参数和仍缺少的访问控制、连接池预算、证书、网络、重载、日志落盘或回读步骤，
不把“找到一个参数”显示成目标已经完成。搜索不要求操作者先记住厂商参数名。

156 个数据库配置工件也可以按稳定 key 或默认文件名搜索。该结果只导航到现有 source-backed 工作区：有 parser
时可打开对应本地只读/草稿视图，无 parser 时显示精确 typed 缺口；它始终是 `CatalogGuidance`，不是运维目标
配方、目标当前配置、厂商验证或部署授权。选择工件不会自动导入文件，也不会绕过脏草稿保护。

产品名只限定搜索范围，目标词必须命中同产品的受审意图；例如 `Apache TLS` 不会误用 Apache 403 配方，
`PostgreSQL TLS` 也不会返回无关的 `max_connections`。数据库版本只在识别产品后解析：指定
`PostgreSQL 16` 时仅返回 16 的 schema；请求未登记的 15 时显示 `MissingVersion` 和当前登记的 16/17/18，
绝不借用相邻版本。所有 catalogued 产品都会返回可执行配方、参数依据或一个 typed 缺口；缺口区分
未收录意图、缺配方、缺精确 schema/版本、缺值校验器、缺可编辑工件、缺运行时能力和缺外部验证证据。
Redis 当前只有 `redis.conf` 只读结构，Tomcat 当前只有 `server.xml`/`web.xml`/`context.xml` 只读结构；
两者缺少值模型和安全写回时明确显示 `MissingReviewedRecipe`，不会拼接模板字符串冒充支持。（桌面端
“可视化编辑”已能逐行编辑本机的 `redis.conf` 草稿，但这不是按目标写回的配方，上述缺口不变。）

桌面端可视化编辑为 Nginx、Apache、Redis 与 HAProxy 的常用指令内置了中文说明（作用、常见写法、注意），并可
把说明作为注释写在新项上方。这些说明是固定的通用解释，等级低于 `CatalogGuidance`：不按产品版本区分
（个别条目注明了起始版本），不证明目标支持该项、含义已按目标核验或允许修改，逐项语义状态仍是
`SyntaxOnlyUnknown`；中文搜索只匹配说明文字本身，从不索引文件中的值、参数或注释。

数据库目标只有在参数为 `Public`、没有未证明 capability、工件允许本地无损草稿、方言具备闭合写入器，
且用户输入通过现有 typed schema validator 后，才显示“校验并加入本地草稿”。写入只使用 schema 的
canonical key、精确容器和归一化公开值；现有同名项只更新唯一命中，重复项失败关闭，缺失容器仅通过
结构化 API 创建。敏感、能力依赖、只读、未知或 `VisibleUnvalidated` 参数仍只显示说明。这个显式目标动作
与上面的只读参数目录不同，且其结果仍只是 `SyntaxValid` 本地草稿，不是推荐值、目标当前值或部署授权。

统一目标入口还接受闭合的数据库参数赋值语法：
`产品 [版本] [@精确工件key] [[精确容器]] canonical或精确别名 (设置为|设为|=) 值`。赋值运算符右侧只进入
已选参数的 typed validator，不参与产品、版本、工件、容器或参数选择；值中允许的第二个 `=` 因而不能改变
目标身份。只要出现赋值或常见赋值式措辞，解析失败就保持 typed `Blocked`，不会回退到普通模糊搜索。
同名参数跨版本、工件或容器不唯一时只列出有界的精确候选；也可用 `@artifact-key` 与 `[container]` 消歧。
预览阶段不修改文档，独立值输入只重新校验原 exact target；点击“确认写入本地草稿”后，写入器先在临时
文档上完成 exact 回读验证，再一次性替换当前本地草稿。查询、页面激活状态或文档 revision 变化都会使旧确认
租约失效；另一工件存在未另存修改时拒绝切换。当前 18 个 schema 中 711 个 `LocalDraftRecipe` locator 均由
该闭合解析器覆盖为唯一目标或明确候选；这仍不证明任何真实目标的版本、能力、现值或激活结果。

远程 middleware 配置树同样支持安全节点名称/静态类型搜索、父链过滤和逐项结构说明；说明只覆盖
结构类型、层级、直接子项数、敏感/截断状态及现有操作策略。Nginx 与 Apache 的通用语法树没有
directive-specific 的版本化权威 metadata，因此其逐项语义状态一律是 `SyntaxOnlyUnknown`，不能因
解析器识别出 directive 或 section 名称就宣称目标支持、含义已核验或允许修改。

当前页面使用的语义证据等级边界如下：

- `CatalogGuidance`：精确静态目录/schema 匹配后提供的已审说明，只证明目录证据匹配，不证明当前
  目标的产品身份、版本、edition、组件、capability、实际值或生效状态。
- `SyntaxOnlyUnknown`：Nginx、Apache、未知节点，以及没有逐项权威 schema 的通用 JSON/YAML/XML/
  line/structured 行；仅证明有界语法结构可见，不授权语义推断。
- `VerifiedForTarget`：当前配置生成器与 middleware 树均未产生该状态；它必须等待 exact target、
  capability 与目标 readback 的完整绑定和最终复核。

所有搜索索引永久排除 value、preview、arguments、comment、raw/source text、documented default 和
secret；敏感 schema 行只可按静态类型或已审 canonical 名称命中，opaque 行只可按静态类型命中，
绝不因正文启发式未报警就索引其内容。真实目标的 schema/capability/readback 验收仍为 `NOT_RUN`。

## 当前 RuntimeSql 状态

core 已实现闭合的服务端身份计划、只读发现计划和敌意输出解析边界：MySQL 8.0.11–8.0.x/8.4.x 使用
`performance_schema`，MariaDB 10.11.x/11.4.x 使用 `information_schema.SYSTEM_VARIABLES`，
PostgreSQL 16/17/18 使用 `pg_catalog.pg_settings`。查询计划只能由精确 provider、产品、组件、
工件、typed version 和 `community` edition 共同选中；Enterprise、托管版、未知 fork 与兼容协议
不会继承原生产品计划。身份查询同样是静态闭合 SELECT，要求单行、精确列数的 4 KiB 有界
hex-TSV，并由 core 推导 runtime provider 与工件。解析器只接收可清零的
有界 hex-TSV 缓冲区，保留顺序和重复项，并在构造文档前丢弃凭据、连接串和私钥相关明文。

该只读链路已经接入数据库页面，并复用组合根的 SSH 会话、完整 `TargetGuard`、请求取消、连接
配置摘要和迟到结果拒绝。页面只调用 core 的闭合身份/查询计划，且对未知值默认脱敏；它不包含
`SET`、`ALTER SYSTEM` 或任何修改语句。当前带已保存密码的连接在 core 与 UI 两层失败关闭，
因为外部远端 `mysql`/`psql` 进程无法同时作为潜在恶意目标程序又被证明不会回显凭据。完成该
能力需要通过 SSH forwarding 使用 core 直接控制的原生数据库协议。真实 MySQL、MariaDB、
PostgreSQL 与 OpenSSH 组合尚未执行，因此页面初始和未取证状态仍必须显示 `NOT_RUN`，不能显示成
“已读取目标”或“已验证”。

## 无损与安全规则

- 单文件默认上限 4 MiB、65,536 个节点、深度 128；攻击者可控预览必须进一步截断并虚拟化。
- BOM、LF/CRLF、无末尾换行、缩进、注释、重复键、未知键和原始大小写必须保留。
- 每次结构修改都产生新 revision；旧节点 ID 必须失败关闭，防止异步操作改错节点。
- 节点名称、参数或注释不得通过换行、结束标签、引号或注释边界注入第二个节点。
- 密码、token、私钥、连接串等节点在树行和 `Debug` 中必须掩码，普通编辑流不得接收敏感节点；完整原文字节只留在 core 文档/显式导出边界，可清零的临时字符串应使用可清零缓冲区，且不得进入通知、日志或状态快照。
- 不透明区域允许逐字节另存；结构操作禁用。禁止为了“格式化”未知厂商语法而改写内容。

## 目标验证与部署

结构解析仅证明编辑器没有破坏自己理解的语法边界。发布“目标验证通过”至少要绑定：

- 页面 activation generation 和请求 ID；
- `TargetGuard { identity, generation }`；
- 产品、版本、edition、组件角色和工件 ID；
- 文档 revision 与完整内容哈希；
- 实际执行的闭合校验器及有界输出。

编辑、目标切换或晚到结果会让验证状态失效。远端部署还需要逐文件 SHA/CAS、不可变计划、危险确认、备份、厂商校验、灰度激活、健康回读和恢复路径；“安全另存成功”不能显示成“已经部署”。

## 官方语法依据

下列 PingCAP `/stable/` 链接只是当前官方文档入口与工件命名证据，不代表同一字段 schema 对所有
历史或未来版本稳定；开放语义校验前仍须绑定每个组件自身的精确版本。

- [Apache HTTP Server configuration files](https://httpd.apache.org/docs/current/en/configuring.html)
- [Apache configuration sections](https://httpd.apache.org/docs/2.4/sections.html)
- [MySQL option files](https://dev.mysql.com/doc/refman/8.4/en/option-files.html)
- [MySQL 8.0 server configuration validation（8.0.16 起）](https://dev.mysql.com/doc/refman/8.0/en/server-configuration-validation.html)
- [MySQL 8.4 server configuration validation](https://dev.mysql.com/doc/refman/8.4/en/server-configuration-validation.html)
- [MariaDB option files](https://mariadb.com/docs/server/server-management/install-and-upgrade-mariadb/configuring-mariadb/configuring-mariadb-with-option-files)
- [MariaDB `validate_config`（13.0 引入）](https://mariadb.com/docs/server/server-management/variables-and-modes/server-system-variables#validate_config)
- [MariaDB 11.4.10 option-file scanner source](https://github.com/MariaDB/server/blob/mariadb-11.4.10/mysys/my_default.c)
- [MariaDB 11.8.6 option-file scanner source](https://github.com/MariaDB/server/blob/mariadb-11.8.6/mysys/my_default.c)
- [MariaDB 12.2.2 option-file scanner source](https://github.com/MariaDB/server/blob/mariadb-12.2.2/mysys/my_default.c)
- [TiDB configuration file](https://docs.pingcap.com/tidb/stable/tidb-configuration-file/)
- [TiFlash and TiFlash learner configuration](https://docs.pingcap.com/tidb/stable/tiflash-configuration/)
- [TiProxy configuration file](https://docs.pingcap.com/tidb/stable/tiproxy-configuration/)
- [TiCDC server configuration](https://docs.pingcap.com/tidb/stable/ticdc-server-config/)
- [TiCDC changefeed configuration](https://docs.pingcap.com/tidb/stable/ticdc-changefeed-config/)
- [TiDB Lightning configuration](https://docs.pingcap.com/tidb/stable/tidb-lightning-configuration/)
- [OceanBase configuration files and runtime parameters](https://en.oceanbase.com/docs/common-oceanbase-database-10000000001103733)
- [OceanBase tenant system variables](https://en.oceanbase.com/docs/common-oceanbase-database-10000000003450816)
- [OceanBase `ALTER SYSTEM PARAMETER`](https://en.oceanbase.com/docs/common-oceanbase-database-10000000001379319)
- [OceanBase Database Proxy parameters](https://en.oceanbase.com/docs/common-odp-doc-en-10000000002135917)
- [OceanBase physical backup and restore views](https://en.oceanbase.com/docs/common-oceanbase-database-10000000001885377)
- [openGauss client access configuration](https://docs.opengauss.org/en/docs/latest/database_administration_guide/configuring_client_access_authentication.html)
- [DM configuration file family](https://eco.dameng.com/document/dm/zh-cn/pm/configuration-description.html)
- [DM physical storage and `dmthrd.ini`](https://eco.dameng.com/document/dm/zh-cn/pm/physical-storage)
- [GBase 8a MPP Cluster V9.5.3 product manual](https://cdn.gbase.cn/products/30/WYp0qy85K9ciqDMnYt463/GBase%208a%20MPP%20Cluster%E4%BA%A7%E5%93%81%E6%89%8B%E5%86%8C_V953.pdf)
- [GBase 8s Connection Manager configuration](https://docs.gbasedbt.com/gbase8s/admin/ids_admin_1415.html)
- [GBase 8s sqlhosts and communication support](https://docs.gbasedbt.com/gbase8s/admin/ids_admin_0175.html)
- [GBase 8s UNIX environment files](https://docs.gbasedbt.com/gbase8s/admin/ids_admin_0024.html)
- [GBase 8s ON-Bar and storage-manager files](https://docs.gbasedbt.com/gbase8s/bar/ids_bar_288.html)
- [GBase 8s Primary Storage Manager](https://docs.gbasedbt.com/gbase8s/bar/ids_bar_526.html)
- [GBase 8s V8.8 SQL reference](https://gbase8s-document.pek3b.qingstor.com/GBase%208s%20V8.8%20SQL%20%E6%8C%87%E5%8D%97%EF%BC%9A%E5%8F%82%E8%80%83.pdf)
- [GoldenDB v6.1.03.10 SQL configuration evidence](https://www.goldendb.com/docsCenter/GoldenDB/61310/html/FAQ_SQL.html)
- [SequoiaDB quickDeploy configuration](https://raw.githubusercontent.com/SequoiaDB/SequoiaDB/master/doc/src/manual/Distributed_Engine/Maintainance/Mgmt_Tools/quickdeploy.md)
- [ShenTong product center](https://shentongdata.com/index.php/product/list-4)
- [ShenTong native database product](https://shentongdata.com/index.php/product/view-37)
- [ShenTong MPP database product](https://shentongdata.com/index.php/product/view-106)
- [ShenTong openGauss database product](https://shentongdata.com/index.php/product/view-355)
- [openGauss distribution certification](https://opengauss.org/zh/certification/)
- [ShenTong official documentation downloads](https://shentongdata.com/index.php/download/list-26)
- [YashanDB 23.5 configuration and password files](https://doc.yashandb.com/yashandb/23.5/zh/All-Manuals/Database-Administration/Storage-Management/Database-File-Management/Configuration-Parameter-File-and-Password-File-Management.html)
- [YashanDB 23.5.4 configuration parameters](https://doc.yashandb.com/yashandb/23.5.4/zh/All-Manuals/Reference-Manual/Configuration-Parameters.html)
- [YashanDB v23.5.4.100 release evidence](https://doc.yashandb.com/yashandb/23.5/zh/All-Manuals/Product-Overview/Release-Notes/23.5.4.html)
- [YashanDB 23.5 ALTER SYSTEM](https://doc.yashandb.com/yashandb/23.5/zh/SQL-Guide/SQL-Statements/ALTER-SYSTEM.html)
