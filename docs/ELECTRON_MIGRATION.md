# LovelyRes Electron 前端迁移

## 决策

LovelyRes 的受支持桌面前端将从 GPUI 完整迁移到 Electron。最终状态不是双前端，也不是长期兼容层：

- Electron main、preload、React renderer 是唯一桌面 UI。
- lovelyres-core 继续拥有业务规则、SSH/SFTP、目标守卫、计划、确认、审计、验证、恢复、便携存储和秘密数据。
- lovelyres-electron-backend 是 Electron 与 Rust core 之间唯一受支持的进程边界。
- 最终删除 crates/lovelyres-gpui、全部 GPUI 依赖、GPUI 启动/打包/发布路径，以及 lovelyres-terminal 中的 GPUI view/runtime 依赖。

> **状态（2026-08-25）**：crates/lovelyres-gpui、GPUI workspace 依赖、`gpui-ui` feature、`gpui-*` 脚本与 GPUI release workflow 已全部移除；`electron-dependency-gate.ps1 -RequireGpuiRetired` 通过。后续条目中的 Pending 状态仍指验收证据尚未记录，不代表 GPUI 仍存在。
- 不使用 computer-use 做 Electron 调试或迁移验收。UI 自动验证使用 Electron 的 webContents.debugger/CDP、webContents.capturePage、main/renderer 单元测试和打包后 smoke。

机器可读的条目、owner、源文件、替代目标、状态、验收条件和测试证据以 [ELECTRON_UI_LEDGER.json](./ELECTRON_UI_LEDGER.json) 为准。该文件使用稳定的 lovelyres-electron-ui-ledger/v1 格式。

## 当前事实

本迁移快照最初建立于 2026-08-24 Asia/Taipei（Git HEAD `fb3ac95577d244cbf505ddfadc3ccdc503111adf`，工作树有未提交修改），并按 2026-08-25 的已观察验证持续更新。

| 项目 | 当前状态 | 已观察证据 |
| --- | --- | --- |
| Electron secure shell | Completed | sandbox、context isolation、自定义 lovelyres://app origin、严格 main CSP、导航/新窗口/权限拒绝、单实例和便携 Electron 路径已经实现；独立 terminal entry 只为 xterm 动态 CSS 保留 style-only 例外，script CSP 不放宽；Electron check 与 CDP smoke 通过 |
| Electron ↔ Rust backend boundary | Completed | 版本化、换行分帧、有大小上限、main frozen preload 当前精确 112 方法、terminal frozen preload 独立精确 7 方法、typed params、无通用 shell.execute；当前代码面的边界测试、typecheck、source gate 与 exact112 Electron-native CDP smoke 均通过 |
| security-reference 页面 | Completed | 107 条/13 语言离线目录、搜索/筛选/收藏/复制、纯文本边界、可访问性和 CDP smoke 已验证 |
| 已中央接线但仍待最终实机验收的切片 | Pending | 连接、Notes、配置快速生成、System Info、AI History、Command History、Disposal Report、Settings secret lifecycle、Snapshot、Firewall、Baseline、Middleware、Check Audit、Log Analysis、Kubernetes 只读、Docker 只读、Packet Capture live phase 1、Emergency Commands 固定目录 phase 1、Quick Detection read-only phase 1、Application Log exact5，以及 SSH terminal 已进入中央 main/preload/App、overlay host 或 keyed window；缺少的真实 SSH/PTY/Linux/OpenSSH/systemd/auditd/journal/Kubernetes/Docker/tcpdump、remediation/恢复/导出、rolling writer、packaged native dialog、完整 parity 或最终候选证据仍按各 ledger 条目保持 Pending |
| 已实现但尚未中央暴露的切片 | Pending | File Integrity、Dialog 与 Notification 仍记录在 UNWIRED/ledger 中；Quick Detection phase 1 与 Application Log exact5 已不属于此行 |
| 其余页面、连接完整工作流、四类窗口、全局 overlays、最终资产/打包与发布 gates | Pending | 文件或脚手架存在不等于完成；没有最终候选构建的通过证据就不得改为 Completed |

已实际运行：

- 最新 TypeScript 与定向 main/preload/contract/renderer 边界验证通过；Middleware 与 Check Audit 均固定为 exact3 方法，Log Analysis、Kubernetes 与 Packet Capture live 均固定为 exact4，Emergency Commands 固定为 exact2，Docker 只读与 Application Log 均固定为 exact5，Quick Detection 固定为 exact7。各远端切片使用严格 DTO、opaque binding-only `App` composition、deactivation/scope cleanup 与 late-result 拒绝；Application Log 是 process-local overlay，不接收 target/binding/session。最近一次完整 Electron check 为 102 files / 594 tests，并完成 typecheck 与 production build；最终候选仍须重新记录。
- Rust sidecar 当前 all-target 结果为 backend library 248/248，加 16 个 standalone targets 共 451/451，总计 699 tests、0 failed、0 ignored。Quick Detection exact7 的完整 TargetGuard/cancel/late-result/close-binding 边界与 Application Log exact5 的唯一 subscriber、独立 per-layer stderr filter、500-record ring、严格参数/响应、volatile clear 和 main-only export 均有通过测试；这些自动化结果不替代真实 Linux/OpenSSH 扫描或 rolling-file/packaged native-dialog 验收。
- `pwsh -NoProfile -File ./scripts/electron-source-gate.ps1 -RepositoryRoot .` 及 fixture self-test 已接受 main 精确 112-method preload、terminal 独立精确 7-method preload、Quick Detection exact7 与 Application Log exact5 的固定 RPC/IPC/preload/main validators、单 subscriber、bounded/redacted DTO、opaque-only 页面/overlay 接线、lifecycle cleanup，以及禁止 remediation/shell/path/target/session/mutation/generic/file/terminal/internal-export-payload 越过 renderer 边界的约束。
- 最新 PASS CDP 证据为 `target/electron-debug/19adbfae-598c-4eee-b7f1-cc2a666e3ac7/evidence`：真实 Electron 进程通过 `webContents.debugger`/CDP 验证 main exact112。Quick Detection 的 plan/start/poll/cancel/history/report direct 与 unknown-field forged 请求均拒绝且不回显，catalog 仍为封闭 13-module/2-profile 目录；remediation/auto-fix/command/file/terminal/export/mutation/generic 均为 `undefined`。断连页零 module/profile/progress/history/report/action rows、local-only、无内部身份，卸载重挂载仍为空，并生成 `quick-detection-disconnected.png`；console error 为 0。Application Log 的 list/level/preview/export unknown-field 请求均拒绝且不回显，stderr/file/path/internal-payload/generic surface 为 `undefined`；overlay 只有 bounded empty ring，内部 payload 不可见，focus/inert/Escape restore 与重挂载清理通过，并生成 `application-log-overlay.png`；console error 为 0。真实 Linux/OpenSSH connected scan、remediation parity、rolling writer 与 packaged native save dialog 均为 `NOT_RUN`/Pending，因此两项仍不得标为 Completed。

这些结果只证明 ledger 引用的当前代码面，以及 Baseline、Middleware、Check Audit、Log Analysis、Kubernetes、Docker 等只读 Phase 1 的中央接线；不证明真实 Linux/SSH、中间件、auditd、journal、Kubernetes 或 Docker 行为、任何 mutation/恢复/导出、原生保存或跨平台打包已经完成。

## 不可丢失的 dirty config-generator 基线

crates/lovelyres-gpui/src/config_generator.rs 曾是一个巨大的未提交工作树成果。GPUI crate 已于 2026-08-25 移除；该脏基线在删除前逐字归档到 docs/legacy/config-generator-baseline.rs.txt（SHA-256 与账本 snapshot 一致），剩余替代测试见 docs/CONFIG_GENERATOR_TEST_BACKLOG.md。原保全要求如下：

| 属性 | 快照值 |
| --- | --- |
| SHA-256 | 7d66302eb9d58a09b09cc95f7b074057357d11c1f1f158ec37a6de56d37ac19e |
| Git worktree blob | 28fa3179c28423fab0d4dd67ce0c61489881279b |
| HEAD blob | 8820497114d4390439da11aa93baadaaf0e960f0 |
| 大小 | 866,081 bytes / 19,991 行 |
| 相对 HEAD | 11,229 insertions / 2,743 deletions |
| 测试清单 | 90 项：60 个普通 Rust test，30 个 gpui::test |
| 测试 ID 顺序摘要 | 058ec2ed7386b2c0bff39cd1b225d4179263853ee42b94c0e6fecaa5f96b6214 |

此前 ledger 冻结值为 `c7c9a2625344476c94c038f7d6c7aa7ea7f5eb689763f8aa8260fba98b206639`
（865,992 bytes / 19,996 行）。复核时工作树已是上表所列当前内容；没有对该文件执行 reset、checkout、
format 或覆盖。重新扫描确认 90 个测试 ID、60/30 分类和顺序摘要完全不变，并对当前内容重新运行了全部
90 项测试，结果仍为 88 passed / 2 failed，因此 ledger 更新为当前可验证快照，同时保留旧哈希作为审计线索。

Electron 替代测试台账当前已独立验证 39/90 Passed、51 Pending；这些替代项包含产品目录/默认值边界、typed assignment 的等号保真、Nginx 403 意图/安全路径搜索、Nginx typed feature remove click 的 preview/row/revision 一致性、六类 core-owned database starters、兼容与国产工件不猜测上游默认值、受管运行时/云/二进制/未解析工件的本地可视选择隔离、未解析 vendor raw text 不进入 visual rows 或 copy/export/save 边界、DM DCR array/startup command 不进入通用 INI 编辑器、DM init password 脱敏/不可复制/拒绝普通更新、structured secret redaction/whole-text copy boundary、MariaDB 容器参数标签、目标产品匹配/唯一 subject 推断、Apache competition skeleton、跨 document node ID mutation fail-closed、request/unmount lifecycle lease、generated/vendor-schema 只读工件的闭合 core→sidecar→renderer contract、GBase 8s byte-exact read-only grammars、GBase 8s visual text AUTHKEY 固定脱敏/whole-document copy capability 隔离、GBase 8a gcware nested/read-only 与 cluster JSON AUTHKEY boundaries、YashanDB vendor-binary exclusion、YashanDB exact metadata/nonserialization、schema 不改变 local-draft authority、SequoiaDB quick-deploy catalog/parser boundaries、移除旧筛选徽章，以及跨产品移除和重置隔离。Preview 的 hostile-text/Unicode SSR 与 lifecycle 单测只是 partial evidence，Electron CDP 仍为 Pending。该进度不改变下面对原 GPUI 测试快照 88/2 的事实记录。

Apache quick configuration 已记录 typed stack/remove/dependency cascade/reset、revision preview、stale/late/unmount 与 hostile plain-text 的四层 partial evidence；它仍计入 51 个 Pending。Core 的 byte-exact `ApacheVisualDocument` round-trip 只是前置条件，当前尚无 sidecar `ApacheVisualDocument` capability → typed aggregate → renderer structured visual editor 的生产 wiring，也没有 legacy `load_quick_into_visual` 的 byte-exact open 语义；纯文本 `<pre>` 预览不作为该能力的替代证据。

另有 MySQL auto.cnf、TiDB auxiliary TOML 与 YashanDB yasdb.ini 三项已经登记通过的 core fixture/identity/schema 子证据，但映射仍为 Pending：Electron 尚未完成 artifact-bound selector、copy/save filename、read-only notice 与 mutation enforcement，不能用低层 parser 测试替代这些前端边界。

90 个测试 ID 已完整冻结在 JSON ledger 中。当前定向运行不是全绿：

- 88 passed
- 2 failed
- 0 ignored

失败项为：

1. config_generator::tests::postgresql_and_mariadb_catalogs_render_versions_search_and_inline_editors  
   快照行 15234：config-generator-postgresql-version-V14 must be explicitly selectable
2. config_generator::tests::unified_goal_search_opens_database_guidance_and_explains_unavailable_products  
   快照行 16374：catalogued configuration artifacts must be discoverable by product

因此不能声称“90 项测试通过”。迁移规则是：

1. 不得 reset、checkout、覆盖或删除该 dirty 文件及 ledger 中列出的耦合 core 修改。
2. 删除源文件前，90 个测试 ID 必须逐项映射到 core、backend contract、renderer component 或 Electron CDP 替代测试。
3. 两个现存失败必须被修复，或得到明确、审阅过的迁移处置；不能通过删除测试让它们消失。
4. 90 个替代测试处置必须齐全且最终通过，才能删除 GPUI config-generator UI。

## 页面映射

页面 ID 以 20 项中央 registry 为准。Security Reference 是唯一 Completed 页面。

| 页面 ID | GPUI 源 | Electron 替代 | 状态 |
| --- | --- | --- | --- |
| system-info | system_info.rs | SystemInfoPage + typed backend methods | Pending |
| docker | docker.rs、container_terminal.rs | DockerPage + exact5 只读 refresh/collection/inspect/security/log methods；actions、资源/Compose mutation、file 与 container terminal 待 phase 2 | Pending |
| kubernetes | kubernetes.rs | KubernetesPage + exact4 availability/resource list/detail/Pod logs 只读方法；scale/restart/delete/cordon/drain/exec 等 mutation 待独立迁移 | Pending |
| quick-detection | quick_detection.rs | QuickDetectionPage + exact7 catalog/plan/start/poll/cancel/history/report；真实 Linux/OpenSSH 与 remediation phase 仍待验收 | Pending |
| security-reference | security_reference.rs、security_reference.json | SecurityReference.tsx、catalog.ts、favorites/clipboard boundary | Completed |
| emergency-commands | command_workbench.rs | EmergencyCommandsPage + exact2 closed catalog/run methods；危险 mutation/审计/验证/恢复与实机矩阵待迁移 | Pending |
| log-analysis | log_analysis.rs | LogAnalysisPage + exact4 sources discover/source read/correlate/IOC search 只读方法；phase 2 rules/AI/export 待迁移 | Pending |
| packet-capture | packet_capture.rs | PacketCapturePage + exact4 live interface/start/poll/stop methods；PCAP evidence/download/export 与真实 tcpdump 矩阵待迁移 | Pending |
| check-audit | check_audit.rs | CheckAuditPage + exact3 catalog/status/log 只读方法；phase 2 mutation/restore/export 待迁移 | Pending |
| integrity | integrity.rs | IntegrityPage + typed methods | Pending |
| notes | notes.rs | NotesPage + finite notes methods | Pending |
| firewall | firewall.rs | FirewallPage + exact2 read-only methods；phase 2 plan/confirm/verify/restore 待迁移 | Pending |
| snapshot | snapshot.rs | SnapshotPage + typed methods | Pending |
| baseline-quick-edit | baseline.rs | BaselinePage + exact3 read-only methods；phase 2 plan/confirm/verify/restore 待迁移 | Pending |
| database | database.rs | DatabasePage + typed query/config methods | Pending |
| middleware | middleware.rs | MiddlewarePage + exact3 discover/configuration/history 只读方法；phase 2 plan/confirm/verify/restore 待迁移 | Pending |
| java-hot-update | java.rs | JavaHotUpdatePage + typed plan methods | Pending |
| batch-servers | batch_servers.rs | BatchServersPage + bounded multi-target methods | Pending |
| ai-history | ai_history.rs | AiHistoryPage + typed history/stream methods | Pending |
| config-generator | dirty config_generator.rs | ConfigGeneratorPage + core rules + typed methods | Pending |

每页只有在完整交互、loading/empty/error、hostile plain text、bounds、cancellation、page lifecycle、TargetGuard、accessibility 和 Electron CDP smoke 都有通过证据后才能变为 Completed。

## 连接映射

连接不是只有 connections.list。以下六个工作流全部 Pending：

| 工作流 | GPUI/Core 源 | Electron 替代 |
| --- | --- | --- |
| 列表与 disconnected landing | connection_ui.rs、connections.rs | 有界无凭据 summaries + list/detail/filter/refresh UI |
| 新建、编辑、保存 | connection_ui.rs、connections.rs、crypto.rs | typed get/upsert、write-only secret changes、native credential path dialog |
| 测试、host key、MFA | connection_ui.rs、connections.rs、ssh.rs | snapshot-bound probe、独立指纹确认、bounded keyboard-interactive |
| 连接、断开、目标激活 | connection_ui.rs、ssh.rs、target.rs | session API、TargetGuard、generation/cancel/stale cleanup |
| 导入、导出 | connection_ui.rs、connections.rs | Electron native dialog + bounded/atomic typed methods |
| 危险删除 | connection_ui.rs、connections.rs、operations.rs | immutable plan、single-use confirmation handle、journal、verification |

任何 preload/API 只实现了其中一个子集，都不能把“连接迁移”标为完成。renderer 不得收到密码、密钥口令、密文、data root 或任意文件/命令能力。

## 四类窗口

| Window kind | 键/生命周期要求 | Electron 替代 | 状态 |
| --- | --- | --- | --- |
| Main | 单实例、main lifecycle、backend shutdown | 已有 secure BrowserWindow shell，仍需完整页面/overlay/发布 parity | Pending |
| SSH terminal | 每目标会话窗口、tabs、resize/input/search/backpressure/cancel | 中央 keyed BrowserWindow + main-owned binding/token/handle + bundled offline xterm + main exact118/terminal exact18 typed API 已接线；真实 SSH/PTY、tabs/IME/CJK/package 矩阵仍 NOT_RUN | Pending |
| SFTP | 每目标唯一窗口、transfer cancel、remote path safety | 并入 SSH 窗口的文件面板：terminal exact18 内的九个方法、main 拥有保存/打开对话框、写操作一律 plan/confirm/execute/verify/restore；真实 OpenSSH/Dropbear 传输与回滚矩阵仍 NOT_RUN | Pending |
| Container terminal | target identity + generation + container identity | 精确 key 的 BrowserWindow + typed container stream API | Pending |

当前 secure main shell 已完成，但“Main 窗口完整迁移”仍 Pending，因为导航、状态栏、全部页面/overlay、packaged platform 行为尚未完成。

## Overlays

以下 app-level surfaces 必须迁移，页面内部确认/编辑器还要在各页面条目中单独覆盖：

| Overlay | GPUI 源 | 状态 |
| --- | --- | --- |
| Settings panel | settings_panel.rs、interaction.rs | Pending |
| Command history | command_history.rs | Pending |
| Disposal report | disposal_report.rs | Pending |
| Application log / diagnostics | app.rs、logging.rs、diagnostics.rs | exact5 process-local overlay、唯一 subscriber 与 main-owned export 已中央接线；rolling writer 与 packaged native dialog 仍 NOT_RUN，保持 Pending |
| Alert / prompt / dangerous confirm host | interaction.rs、app.rs | Pending |
| Notification/toast stack | interaction.rs、app.rs | Pending |

验收必须覆盖 focus trap/restore、Escape/Enter、stacking、typed outcomes、capacity/timeouts、危险确认绑定、accessibility 和 hostile plain text。

## Assets

electron/assets 中的 app.ico、logo.png、security_reference.json 和三份字体目前与 GPUI 资产 SHA-256 相同，且开发构建可从自定义本地 origin 加载。资产条目仍为 Pending，因为最终还需要：

- 建立删除 GPUI 后的单一维护源。
- 在 Windows/macOS/Linux packaged artifacts 中验证 icon、logo、字体、目录和 license/notices。
- 将 gpui-component-assets 图标注册表替换为本地 bundled、可访问、有限的 Electron 图标注册表。
- source/resource gate 证明没有 CDN、remote image/font/style/script、remote SVG 或在线-only UI 依赖。

## Gates 映射

| Gate | GPUI 现有来源 | Electron 最终替代 | 状态 |
| --- | --- | --- | --- |
| Source/dependency | gpui-source-gate、gpui-dependency-gate | electron-source-gate + electron-dependency-gate（strict no-GPUI） | Pending |
| Quality | gpui-quality-gates | electron-quality-gates：Rust fmt/clippy/test + Electron type/test/build + all gates | Pending |
| Debug smoke | gpui portable/manual smoke | webContents.debugger/CDP + capturePage，覆盖全部 UI | Pending |
| Test ledger | GPUI_TEST_MIGRATION_LEDGER、validator | electron-ui-ledger-gate + config ledger gate + legacy/replacement IDs | Pending |
| Portable release | GPUI_PORTABLE_RELEASE、portable smoke | packaged Electron/backend data-root and clean-machine smoke | Pending |
| Platform package | 三个平台 GPUI package scripts | locked Electron Windows/macOS/Linux package/verify | Pending |
| SBOM/notices | GPUI SBOM/notices scripts | Cargo + pnpm/Electron/resource reconciliation | Pending |
| Real environment | SSH compatibility matrix | Electron-driven SSH/SFTP/terminal + destructive/recovery VM matrix | Pending |
| GPUI retirement | GPUI crate/deps/scripts/docs | Electron-only repo/build/release audit | Pending |

Ignored、skipped、NOT_RUN、Pending 或失败场景一律不能计为通过。

## 最终验收

只有同时满足以下条件，才能宣布“前端已完全迁移到 Electron”：

1. crates/lovelyres-gpui 已从磁盘和 Cargo workspace 删除。
2. active Cargo manifests 与 Cargo.lock 不再包含 gpui、gpui-component、gpui-component-assets，以及仅用于 GPUI UI 的平台依赖。
3. lovelyres-terminal 已删除或重构，不再含 GPUI view/runtime；仍保留的协议/model 必须由 Electron backend/renderer 实际使用并通过 conformance tests。
4. README、AGENTS.md、CI、scripts、docs、package commands、release artifacts 都只指向 Electron；没有 GPUI launcher、package 或 release gate。
5. 20 页面、6 个连接工作流、4 类窗口、6 个 overlays、4 组 assets 和 9 个 gates 在 JSON ledger 中全部为 Completed，并且各自引用最终候选构建的通过证据。
6. typed finite IPC/RPC、sandbox、CSP、secret isolation、hostile plain text、validated paths、command closure、TargetGuard、bounds、backpressure、cancellation、dangerous plan/confirmation、audit、verification 和 restore 路径没有因 Electron 迁移而弱化。
7. dirty config-generator 的 90 项测试全部有审阅后的替代映射；当前两个失败已经明确解决；该工作树成果可恢复、已保全，不因删除 GPUI 而丢失。
8. Windows、macOS、Linux portable packages 均在 clean environment 通过 offline launch、executable-adjacent data、backend/assets/licenses、window/overlay/page、SSH/SFTP/terminal 和 shutdown smoke。
9. 最终 UI 调试/验收只依赖 Electron-native test/CDP 机制，不依赖 computer-use。

在以上条件全部满足前，项目状态是“Electron 迁移进行中”，不是“已完全移除 GPUI”。
