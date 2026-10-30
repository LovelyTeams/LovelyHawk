# LovelyHawk v0.0.4 版本说明（修改文件与新增功能）

发布日期：2026-10-30。本轮以 ghost-range v2「深度失陷」应急响应靶场（nc1.ctfplus.cn:16050 共享实例 + 本地容器）为需求来源，完成应急处置引擎的第二次扩展与首个处置后加固模块，并交付 Windows 便携发布包。

- 需求背景与设计取舍详见 [RESPONSE_ENGINE.md](RESPONSE_ENGINE.md)；
- 用户可见变更见 [CHANGELOG.md](../CHANGELOG.md) 的 v0.0.4 小节；
- 本文给出完整的新增功能清单与逐文件修改说明。

---

## 一、新增功能

### 1. 应急检测 17 → 19 类：补齐「信息不可信」闭环

上轮 17 类已覆盖靶场评分判定的全部后门，但闭环还缺两块——这道题的考点恰恰在此：

| 新类别 | 严重度 | 解决的问题 | 检测与修复方式 |
| --- | --- | --- | --- |
| `session-env-hook` 会话驻留钩子 | critical | PROMPT_COMMAND 录音 / PATH 注入 / LD_PRELOAD 驻留在**已登录会话的内存环境**里；删启动文件清不掉，录音文件会不断"长回来"（靶场关 5 最大坑） | 直读 `/proc/*/environ`（root），三种闭合签名（`PROMPT_COMMAND` 含 `>>`、PATH 含隐藏/可写目录、`LD_PRELOAD` 指向已删或攻击者目录）；**不按进程名过滤**（shell 可能已 exec 成子进程，钩子环境随子进程存活），相同钩子环境聚为一个会话簇；修复=逐 PID 复核 `/proc/<pid>/exe` 身份后 TERM→KILL 整簇（不删文件），复验=全机 `/proc/*/environ` 无签名残留 |
| `preload-residue` 恶意库驻留进程 | high（指导型） | 已删除的恶意 `.so`（如 libsyslog.so）仍被 nginx/sshd 等常驻进程映射在内存，钩子副本要等进程重启才消失 | `/proc/*/maps` 引用可疑前缀（/usr/local/lib、/usr/local/libexec、/opt、/var/tmp、/tmp、/dev/shm）下已删除或磁盘不存在的 `.so`；发行版升级的正常 `(deleted)` 残留因 `/usr/lib`、`/lib` 前缀排除不误报；**不提供自动 kill**（会打断业务，本题 kill nginx 直接判 FAIL），报告并给出按业务窗口重启的指引 |

### 2. 处置后加固模块（全新能力）

应急页新增「处置后加固」区块，两个新动作 `hardening-scan` / `plan-hardening`，**复用与应急修复完全相同的 方案 → 确认 → 执行 → 自动复验 链路与句柄注册表**（confirm/execute/poll 无改动直接复用）：

| 加固项 | 检查 | 动作与复验 |
| --- | --- | --- |
| 认证文件权限（hardening-auth-permissions） | 闭合目标集 stat 比对基线 mode/owner/group：shadow、gshadow、sudoers、sudoers.d、root 与各用户 `.ssh` 与 authorized_keys、crontab spool 目录、SSH 主机密钥；固定目标用基线三元组，用户级路径只收紧 mode 保留属主 | 原始权限写入归档目录后逐项 chmod/chown；复验逐项重 stat 等于基线；撤销按归档记录逐项恢复 |
| 防复发监控（hardening-audit-watch） | auditctl 存在性 + 10 个篡改热点（passwd/shadow/sudoers、cron、profile.d、pam.d、/var/tmp、root/.ssh）是否已有 `lovelyhawk-tamper` watch | auditctl 逐点 `-w … -p wa -k lovelyhawk-tamper`（运行时规则、重启失效已在方案中注明）；撤销逐点 `-W`；**无 auditd 的容器如实报「不适用」而非假装覆盖** |
| 完整性基线（hardening-integrity-snapshot） | `/var/case/hardening/integrity-manifest.txt` 是否存在；存在时抽查最近 64 项重算 sha256 比对漂移 | 对认证与后门高发位置（上限 256 项）生成 0600 清单；漂移后可重建收编当前状态，重建后回到已达标 |

每项带三态展示：待加固（可出方案）/ 已达标（附说明）/ 不适用（附原因）。凭据轮换属人工步骤不自动执行：发现过泄露时报告文案提示「删文件≠追回密码」。

### 3. 顺带修复的三个既有缺陷（全流程实测暴露）

| 缺陷 | 后果 | 修复 |
| --- | --- | --- |
| PAM 后门误报 | 发行版原生 `required pam_permit.so`（common-auth/account 等的合法栈终结规则）被当后门删除 → sudo/PAM 全链路损坏 | 检测收紧为只匹配 `auth sufficient pam_permit.so`（万能密码后门形态）+ 回归测试 |
| 监听修复端口被抢回 | 后门脚本 boot 竞态产生多实例（一个持 socket、其余自旋等 bind），只杀持有者后端口立即被自旋实例重新监听 → 复验失败 | listener 修复并入**同一本体的全部 PID**（含未持 socket 实例）+ 回归测试 |
| 业务站点误报 | 绑回环 `127.0.0.1:80/443` 的业务 Web（本靶场 nginx 即此部署）被报可疑监听 | 80/443 加入合理回环端口表 + 回归测试 |

### 4. 其他

- 扫描超时 90s → 240s（core）、页面侧 scan/hardening-scan 120s → 300s：扫描新增两段 /proc 全量遍历，慢速共享靶机需要分钟级。
- 扫描脚本 ENVIRON/MAPS 段采用 grep 预过滤 + 单次 awk（早期版本逐行起管道，万级进程派生拖垮共享靶机）。

---

## 二、修改与新增文件清单

### Rust 后端

| 文件 | 类型 | 修改内容 |
| --- | --- | --- |
| `crates/lovelyhawk-core/src/response_engine.rs` | 修改（7.3k → 8.6k 行） | 核心：5 个新 `ResponseIssueKind`（session-env-hook、preload-residue、3 个 hardening）与 slug/label/排序；5 个新 `IssueObject` 变体（`SessionEnv`、`ResidentLib`、`HardeningPermissions`、`HardeningAuditWatch`、`HardeningSnapshot`）及闭合校验（PID/exe/签名码/权限路径/审计点位/去重）；扫描脚本新增 ENVIRON 与 MAPS 两段（含 dash 兼容与低开销实现）；会话簇与驻留库聚类解析；`plan_fix` 新增 4 个臂（会话整簇 kill、权限收紧、审计 watch、清单生成，均带 TOCTOU 复核脚本）；`hardening_scan` + `plan_hardening` 两个新服务方法与 `HardeningItem/HardeningStatus/HardeningScan` 类型；三对加固修复/复验/恢复脚本；PAM 分类器收紧；listener 并入同本体进程；BENIGN_LOOPBACK_PORTS +80/443；SCAN_TIMEOUT 240s；新增/更新约 30 个引擎单测 |
| `crates/lovelyhawk-backend/src/response_engine_api.rs` | 修改（1.0k → 1.3k 行） | 请求枚举新增 `hardening-scan` / `plan-hardening` 两个 action（deny_unknown_fields 闭合）；`HardeningItemDto` 与 `HardeningScan` 响应；注册表新增 hardening 句柄表（TTL/容量/按 binding 回收与 prune）；`plan_hardening` 处理器（复用同一 plan 注册表，confirm/execute/poll 零改动）；请求校验与 kebab 序列化测试扩展 |
| `Cargo.toml` / `Cargo.lock` | 修改 | 工作区版本 0.0.3 → 0.0.4（五个 crate 同步） |

### 前端（Tauri UI）

| 文件 | 类型 | 修改内容 |
| --- | --- | --- |
| `ui/src/shared/response-engine-contract.ts` | 修改（332 → 419 行） | actions 数组 +2；`ResponseIssueKind` +2（session-env-hook、preload-residue）；新类型 `ResponseHardeningKind` / `ResponseHardeningStatus` / `HardeningItem` / `ResponseEngineHardeningScan`；请求/响应双侧运行时校验（含加固项三态、去重句柄、上限 8 项）；加固 kind 不得混入入侵问题列表的负向校验 |
| `ui/src/shared/response-engine-contract.test.ts` | 修改 | 新 action 闭合形状、伪造字段拒绝、加固扫描校验（未知 kind/状态、重复句柄拒绝）、请求-响应配对扩展 |
| `ui/src/renderer/ResponseEnginePage.tsx` | 修改（568 → 723 行） | 新「处置后加固」区块（独立扫描状态、三态徽章行、缺口区）；`KIND_META` +2 类；修复弹层泛化为 `FixSubject`（入侵问题 / 加固项共用确认-执行-轮询链路与行内进度）；空态文案 17 → 19 类 |
| `ui/src/renderer/response-engine-page.test.tsx` | 修改 | 加固区块渲染（三态、仅待加固可执行）、扫描前可达性、新文案断言 |
| `ui/src/renderer/response-engine.css` | 修改（+~90 行） | 加固区块/徽章/说明样式，全部走主题 token（含深浅色变量核对） |
| `ui/src/host/backend-client.ts` | 修改 | scan / hardening-scan 超时 120s → 300s，其余 60s → 120s |
| `ui/package.json` | 修改 | 版本 0.0.4 |
| `crates/lovelyhawk-desktop/tauri.conf.json` | 修改 | 版本 0.0.4 |

说明：`lovelyhawk-desktop` 宿主代码**零改动**——新 action 走已白名单的 `response.engine` 方法，lane 语义不变（仅 poll/cancel 走 Control 通道）。

### 实验探针与文档

| 文件 | 类型 | 修改内容 |
| --- | --- | --- |
| `tools/lab/probe-response-hardening.mjs` | **新增**（199 行） | 加固端到端探针：植入权限偏离 → 扫描 pending → 收紧复验 → auditd 不适用判定 → 清单建立 → 漂移注入 → 重建回达标；远程模式只检查不加固 |
| `tools/lab/probe-response-engine-v2.mjs` | 修改（269 → 330 行） | 植入 `bash -l` 钩子会话并断言 session-env-hook 修复；修复队列纳入新类并只收可修复项（listener 吸收同本体后门项）；复扫断言允许 preload-residue 指导项残留；归档计数扣除无删除类；业务就绪等待；远程模式新增 `PROBE_REMOTE_FIX=1` 完整修复开关；`lineOf` 正则修复（history 证据无尾冒号导致升序删行错位） |
| `docs/RESPONSE_ENGINE.md` | 修改 | 本轮扩展全记录：19 类表、加固章节、三项缺陷修复、验证证据（本地/远程）、0.0.4 发布包与复现参数 |
| `CHANGELOG.md` | 修改 | v0.0.4 用户可见变更（新能力 + 三项缺陷修复） |
| `docs/RELEASE_0.0.4.md` | **新增** | 本文 |

### 发布产物

| 文件 | 说明 |
| --- | --- |
| `artifacts/LovelyHawk-0.0.4-windows-x64.zip` | Windows 便携包 18.1 MB（LovelyHawk.exe 43.3MB + lovelyhawk-win-agent.exe + 许可/清单/SBOM 共 8 文件） |
| `artifacts/LovelyHawk-0.0.4-windows-x64.zip.sha256` | `e81ee00f1b289364d91d174d87b18943409656bff399d100ccec5a188bab4106` |

---

## 三、验证证据摘要

- 单测/门禁：core **1332** 过、backend **365** 过、ui **1205** 过（145 文件）；clippy 零警告、fmt 干净、`pnpm ui:check` 全绿。
- 本地 v2 全流程探针 **ALL CHECKS PASSED（137 断言）**：17 类 25 项全命中 → 全部修复复验通过 → 容器内评分 **5/5** → 70s 跨周期复评 5/5 → 业务 200 → 独立证据归档。
- 本地加固探针 **ALL CHECKS PASSED**（权限/监控/清单全链路）。
- 真实靶场（nc1.ctfplus.cn:16050）：只读扫描 25 项全命中 → 完整修复 → `sudo python3 /opt/check.py` **5/5，flag{ghost-range-deep-cleaned}** → 跨周期复验 5/5 → 远程加固检查全过。
- 发布包：source-gate（235 页面模块）、双二进制静态 CRT/PE 门禁、第三方清单 443 crates、版本一致性、便携包结构校验全部通过；`release:smoke` 运行态冒烟需真实 Windows，仍未执行（登记于 [UNWIRED_FEATURES.md](UNWIRED_FEATURES.md)）。
