# PostgreSQL 访问规则与角色诊断

## 用户流程与能力范围

数据库页的「读取数据库状态」经当前 SSH 连接和原生 PostgreSQL 协议读取参数、会话、主机进程对应，以及访问诊断。「读取并留证」还把开始时归属案件、检查状态与有限摘要保存到案件库。每项诊断独立报告可用、权限不足、查询失败、输出无法核对、超限或读取期间变化；一项不可用不抹去已完成的参数读取。

新手先看到 HBA、ident、角色、成员授权四类数量、需要复核的项数和原因，查看按钮可以直接展开详情并移动键盘焦点；搜索和翻页后自动定位到新结果。专家详情提供来源文件和行号、规则顺序、搜索与每页 50 项的结果。提示以条件、用途和下一步为主；没有触发提示不等于合规。

| 数据 | 当前含义 | 尚不能证明 |
| --- | --- | --- |
| `pg_hba_file_rules` | 当前文件及 include 展开的连接规则、认证方法、选项名称、是否有解析问题 | 上次加载内容、实际匹配规则、网络可达性、任意用户可访问 |
| `pg_ident_file_mappings` | 当前文件展开后的用户映射和问题状态 | 上次加载映射、某次身份映射成功 |
| `pg_roles` / `pg_authid` | 角色直接属性、LOGIN、连接限制、服务器显示格式的口令到期时间 | 成员关系、SET ROLE、对象 ACL、实际业务权限、账号已完全停用 |
| `pg_auth_members` + 当前数据库所有者 | 逐条成员、目标角色、授权者、INHERIT / SET / ADMIN，以及静态权限来源路径 | 完整对象 ACL、实际登录、任意成员管理或可直接处置 |
| 数据库端口令标识分类 | 无存储口令、MD5、SCRAM 标识、未知；权限不足时明确未取得 | 口令强度、有效 SCRAM 校验值、登录成功或实际协商算法 |

HBA / ident 视图丢失部分原始引号信息。LDAP 的 `ldapscope` 等名称由视图派生，不能当作可写入 HBA 的配置选项；本次仅在 LDAP 诊断上下文识别它，原始配置 schema 不放宽。不得把其数组拼接回配置文本或交给需要完整词法输入的规则验证器。`all`、正则、角色选择项只显示文本；宽来源提示仅依据数值 IP 和零掩码。拒绝规则不因此报宽来源风险。匹配到 `trust` 无需口令证明；`password` 的传输风险按连接类型区分；`md5` 规则仍可能对 SCRAM 存储值协商 SCRAM。

角色提示针对直接可登录的高权限属性，以及已观察到的旧口令标识、未知标识和口令过期。没有口令仍可能使用 peer、cert、trust 或外部认证。到期时间只约束口令认证，采用服务器的时间判断，不把服务器显示格式重新标为 UTC。修改 `password_encryption` 不会转换现存口令。

## 读取边界

- 固定 SQL 在 core 内选择，renderer 没有 SQL、路径读取或角色写入权限。先查询表与函数权限，只请求已报告可读的受保护视图；缺少口令目录权限时仅查询 `pg_roles`。
- 每类视图读取两次，并复核前后权限。视图完整行摘要在数据库端生成，包含未公开认证选项和口令状态，仅在 core 短期比较，清零后丢弃。公开字段也比较，捕捉跨越口令到期时间的变化。
- 全部认证选项值、原始解析错误、口令校验值、角色秘密配置均不进入公共 DTO。错误可能回显秘密，因此只保留问题布尔值与闭合原因。内部摘要不进入 Debug、页面、案件或导出。
- 每次 HBA / ident 各限 512 行，角色限 1024 行、成员授权限 2048 行，各类公开行 JSON 限 384 KiB。超限返回空公共行和明确不可用状态，不当作成功空表。分页查询限 128 UTF-8 字节，页长 50，精确校验任务、类别、数量和配置版本。
- 仍使用整个原生任务 40 秒、单语句 20 秒和锁等待 3 秒的期限与累计协议字节限制。取消、断连、目标切换、配置变更和十分钟结果过期使后续访问页失效。
- 视图比较不是原子文件快照，不能检查被视图丢失的引号或原始字节，也不能证明采集期间没有短暂变化。访问诊断结束后还复核原有会话身份、加载时间和重点参数来源。
- 不自动安装工具、提权、重载、写 HBA、改角色或关闭服务端日志。读视图仍可能引起服务器审计、解析日志和访问时间变化。

## 角色成员关系与权限来源

角色行提供「查看权限来源」，不用开启专家模式。四类路径分别显示全部成员关系、自动继承的普通权限、允许切换到的角色、切换后新增普通权限来源。每页 20 项，搜索限 128 UTF-8 字节；每项展示一条可行路径和授权 OID。超过 32 个角色时明确显示路径截断和完整步数，目标角色仍单独展示，不展开所有路径。

- 普通权限逐条检查 `inherit_option`；SET 路径逐条检查 `set_option`。PostgreSQL 16+ 的角色 `INHERIT` 属性是新授权的默认值，修改它不会倒改既有成员授权。
- 自动继承不传递 SUPERUSER、CREATEDB、CREATEROLE、REPLICATION、BYPASSRLS 属性。页面展示目标属性时说明适用条件。仅有某超级用户角色的可继承授权不能得到超级用户的全局权限。
- 原始会话身份决定 SET ROLE；从它切换到超级用户可以得到普通对象的广泛权限，但不据此虚构其可继续切换到所有角色。先 SET 再 INHERIT 的路径独立呈现，不能声称切换后同时保留原来的全部权限。
- 当前数据库所有者隐式属于 `pg_database_owner`，不是 `pg_auth_members` 中的人工授权。单独读取并前后核对数据库 OID、名称和所有者，再关联既有会话；路径明确标记隐式关系。未知数据库上下文时禁用图分析。
- 同一成员/角色可以存在不同授权者的多条记录。保留各条 OID 与选项；缺失引用、重复同一授权、显式循环和不合法内建角色关系不进入图。原始角色和授权可分别保持可见。
- ADMIN 仅提供有条件的复核提示，没有推导一个脱离执行角色、授权者、继承和版本规则的通用账号管理能力。产品不执行 GRANT、REVOKE、SET ROLE 或 SET SESSION AUTHORIZATION。
- 角色与成员数据均完整且前后稳定后才分析。角色、授权或当前数据库缺失分别说明；过期、目标/配置变化和迟到响应仍按原任务失效。Debug 和案件只保留数量与闭合原因，不包含路径、角色明细或私有指纹。

分析是以所选角色作为会话身份的静态图。未涵盖 PUBLIC、表/函数等对象权限、SECURITY DEFINER 间接执行、实际认证与网络可达性。没有额外管理属性提示不等于安全。算法使用有界广度遍历，不枚举所有路径；普通权限和成员管理语义依据 [角色成员关系](https://www.postgresql.org/docs/16/role-membership.html)、[成员目录](https://www.postgresql.org/docs/16/catalog-pg-auth-members.html)、[SET ROLE](https://www.postgresql.org/docs/16/sql-set-role.html) 和 [GRANT](https://www.postgresql.org/docs/16/sql-grant.html)。隐式所有者及超级用户分支已核对 [16](https://github.com/postgres/postgres/blob/REL_16_STABLE/src/backend/utils/adt/acl.c)、[17](https://github.com/postgres/postgres/blob/REL_17_STABLE/src/backend/utils/adt/acl.c)、[18](https://github.com/postgres/postgres/blob/REL_18_STABLE/src/backend/utils/adt/acl.c) 官方源码；版本实测仍分别记录。

## 案件摘要

新记录为 `postgresql-runtime-summary/v4`，增加成员授权、角色路径分析状态及可切换取得额外管理属性的登录角色数；同时保留各类总数、需复核数、闭合提示代码数量与缺口原因。保留原有会话、进程对应和十项参数摘要；不保存规则正文、来源路径、角色明细、认证选项值、校验值或内部视图摘要。

既有 v1 / v2 / v3 记录不重写。写入失败保留同一摘要与原案件，重试只补存；未保存结果仍参与导航、关闭、重新读取和过期处理。案件 SHA-256 校验保存记录，不是原始认证文件或协议取证摘要。

## 验证入口与待完成项

```powershell
cargo test --locked --package lovelyhawk-core --package lovelyhawk-backend
pnpm ui:check
cargo build --locked --package lovelyhawk-backend --bin lovelyhawk-backend
pnpm desktop:build
node tools/lab/probe-postgresql-native.mjs --desktop
```

以下验收均在 Electron 时期完成，不能直接当作 Tauri 桌面壳的验收结果。

访问规则阶段于 2026-09-08 完成正常 Electron → WSL2 Ubuntu → 独有 PostgreSQL 16.15 / Debian 13 / x86_64 容器验收，最终 **94/94**，启动、preload 与 renderer 控制台 **0 错误**。见 [最终报告](../target/lab-postgresql-desktop/6be33e26-486f-4d98-8ebd-663f209a465c/report.json) 和 [独立复核](../target/goal-20260907/postgresql-access-verification.json)。其 37 个关键源码摘要在该阶段验收时一致；后续角色扩展的当前证据见下文。

真实场景包括：独立视图数量、SCRAM/MD5 标识、未重载的首条拒绝规则与仍成功的原认证、HBA/ident include 来源行、带引号的 `all`、LDAP/RADIUS 秘密选项、派生 `ldapscope`、角色高权限及口令过期、实际口令变化、搜索与分页、详情焦点、错误字段隐藏、v3 留证、受限账号，以及三类行数和 HBA 公开字节超限。原来的 TLS、取消、配置冲突、保存失败补存、案件归属和导航/关闭保护继续通过。

完整 Rust core / sidecar **1,776 通过、10 忽略**；Electron **134 文件 / 937 测试**，类型检查与构建通过。全部目标 Clippy、格式、源码门禁（171 个 renderer 可达源码 / 6 个固定资源）与 diff 检查通过。忽略项不计通过。

原生截图已核对概览、HBA 表格、角色分页、问题状态和最小支持窗口 1080×700。HBA 查看、搜索与翻页完成后，键盘焦点和页面位置回到结果标题。当前没有宣称更小窗口的整应用验收。

原生探针使用单次 UUID 对应的 PostgreSQL 容器、完整 ID 与镜像归属检查，所有故障配置、角色创建与口令更换仅用于此测试容器。资源限 512 MiB / 1 CPU / 128 PID，仅本次 tmpfs；基础镜像 `sha256:e00728409e510ae569d85927d0067046b9b09f9206c0b99f9e69c74d74c6d7d6`。Python 与 SYS_PTRACE 仅为该容器的进程验证准备，不改变产品权限策略。

访问规则阶段七次运行的容器和临时应用数据均记录清理，并独立核实无本轮标签残留。主连接口令的明文与 JSON 转义检查没有命中报告或文本日志；最终运行另在应用退出后扫描全部临时本机数据，确认认证选项/错误标记未落盘。失败记录保留，具体原因与修正见 [长期进度](PRODUCT_ROADMAP.md)。

完整认证文件词法与字节证据、已加载规则匹配、具体对象授权、跨命名空间实例归属、配置修补与恢复仍待实现。PG 16–18 的版本语义并不等于三个版本均完成部署验证，商业兼容产品不能借用社区 PostgreSQL 的结果。

参考：[HBA 文件视图](https://www.postgresql.org/docs/16/view-pg-hba-file-rules.html)、[ident 文件视图](https://www.postgresql.org/docs/16/view-pg-ident-file-mappings.html)、[角色目录](https://www.postgresql.org/docs/16/catalog-pg-authid.html)、[口令认证](https://www.postgresql.org/docs/16/auth-password.html)、[PostgreSQL 16 视图实现](https://github.com/postgres/postgres/blob/REL_16_STABLE/src/backend/utils/adt/hbafuncs.c)。其他原生连接、实例与留证边界见 [原生运行检查](POSTGRESQL_NATIVE_RUNTIME.md) 和 [主机进程对应](POSTGRESQL_PROCESS_CORRELATION.md)。


### 成员授权与角色路径实测

2026-09-08，Windows Electron → WSL2 Ubuntu → 独有 PostgreSQL **16.15 / Debian 13.6 / x86_64** 容器完整 **110/110**，启动/preload/renderer **0 错误**。见 [角色扩展最终报告](../target/lab-postgresql-desktop/bbaa35ba-b046-4345-be1d-93e080868e95/report.json) 与 [独立复核](../target/goal-20260907/postgresql-membership-verification.json)。43 个关键源码摘要与当前实现一致。Rust **1,781 通过 / 10 忽略**，Electron **135 文件 / 941 测试**；类型、构建、Clippy 全部目标、格式及源码门禁（173 个 renderer 可达源码 / 6 个资源）通过。

真实 PostgreSQL 的 6 组角色 × MEMBER / USAGE / SET 共 **18 组比较**全部相同。独立 SQL 会话复核先切换再继承以及失去原有部分权限；另覆盖继承超级用户与切换超级用户的差别、当前数据库所有者隐式关系、两名授权者、改 NOINHERIT 默认值后保留既有授权、ADMIN、44 步路径截断、成员授权超过 2048 项、受限账号失去成员目录权限、v4 留证以及实际页面选角色、切换类型与焦点返回。原有 94 项认证、参数、进程、秘密和案件回归继续通过。

已查看 [角色路径截图](../target/lab-postgresql-desktop/bbaa35ba-b046-4345-be1d-93e080868e95/role-mixed-path-1080x700.png) 和 [成员授权截图](../target/lab-postgresql-desktop/bbaa35ba-b046-4345-be1d-93e080868e95/role-memberships-1080x700.png)，均为 1080×700 的真实窗口。

首轮 [8d3701b7](../target/lab-postgresql-desktop/8d3701b7-3087-4e98-8e3e-aa9ecc228ae5/report.json) 在夹具角色 OID 使用 PostgreSQL JSON 字符串后被请求边界拒绝，整轮不计通过；夹具显式转为 bigint，产品校验没有放宽。第二轮完整通过。两轮均记录清理且独立确认对应 UUID 标签无容器残留；报告、文本日志未检出主连接口令的明文或 JSON 转义，最后一轮在 Electron 退出后扫描全部临时本机文件，认证选项/错误秘密标记未落盘。PG 17/18、其他架构/部署和兼容数据库仍无本次实测证据。
