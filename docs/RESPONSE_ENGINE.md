# Linux 应急处置引擎（response.engine）

2026-10-29 新增。本文记录本次二次开发的全部变动、新增能力、验证证据与剩余限制。

2026-10-30 扩展：检测/修复从 7 类扩到 **17 类**（新增严重级 `critical`），覆盖 ghost-range-v2 深度失陷靶场（LD_PRELOAD readdir 劫持、PATH 注入、SSH 密钥后门、PAM 万能密码、回环可疑监听、隐藏藏匿目录、Web 敏感文件、WebShell、命令录音钩子、历史命令明文密码），并在该靶场完成端到端验收（容器内评分 5/5）。

2026-10-30 第二次扩展（本次，逐文件清单见 [RELEASE_0.0.4.md](RELEASE_0.0.4.md)）：
- 应急检测 17 → **19 类**，补上「信息不可信」闭环的最后两块：
  - `session-env-hook`（critical）：PROMPT_COMMAND 录音 / PATH 注入 / LD_PRELOAD 驻留在**已登录会话的内存环境**里——删启动文件清不掉，录音文件会不断"长回来"。检测直读 `/proc/*/environ`（不按 exe 过滤：shell 可能已 `exec` 成子进程），按相同钩子环境聚类成会话簇；修复=逐 PID 复核 exe 身份后 TERM→KILL 整簇，复验为全机环境扫描无签名残留。
  - `preload-residue`（high，指导型不自动修）：`/proc/*/maps` 中仍映射着已删除恶意 `.so`（`(deleted)` 或文件已不存在，仅限 /usr/local/lib、/opt、/var/tmp、/tmp、/dev/shm、/usr/local/libexec 前缀，规避发行版升级误报）的常驻进程；盲目 kill 会打死业务，只报告并给出重启指引。
- **处置后加固模块**（新 action：`hardening-scan` / `plan-hardening`，复用同一 plan→confirm→execute→poll 链路与句柄注册表）：三项闭合检查（认证关键文件权限、auditd 防复发监控、关键文件 sha256 完整性清单 + 漂移比对），待加固/已达标/不适用三态展示。
- 修复既有缺陷：PAM 检测曾把发行版原生 `required pam_permit`（common-auth/account 的栈终结规则）当后门删除导致 sudo 全挂——收紧为只认 `auth sufficient pam_permit`；bind-listener 修复曾只杀持 socket 的进程，boot 竞态产生的同名自旋实例会立刻抢回端口——现并入同本体全部 PID。
- 扫描超时 90s → 240s（扫描新增两段 /proc 全量遍历，慢速共享靶机需要分钟级），页面侧 scan/hardening-scan 超时 120s → 300s。

2026-10-30 第三次迭代（v0.0.5，按用户反馈）：
- **修复顺序死锁**：先修藏匿目录再修后门进程时，本体文件已被删而进程仍从已删文件运行，旧版 plan 以「本体已被移除」拒绝修复，进程永远清不掉。现在 `ensure_process_unchanged` 把 BODY_GONE 作为可继续状态返回，plan 降级为「级联 cron（如有）+ 仅按 /proc 复核终止进程」，无归档删除步骤；绑定监听走同一路径。真实靶机（36250）死锁态实测：降级计划执行并跨周期复验通过。
- **扫描异步化 + 真实阶段进度**：`scan` 动作改为后台执行（返回 `scan-started`，新动作 `poll-scan` 轮询，`poll-scan` 走 Control lane 不排队）；core `scan_with` 提供 kinds 闭合过滤与阶段回调（privilege→collect→linked→accounts），后端映射为中文阶段与百分比，页面进度条只显示真实到达的阶段。同一 binding 同时只允许一个扫描；扫描完成后仍原子替换 issue 句柄表。
- **扫描项可选**：`scan` 请求接受 `kinds`（闭合 19 类、去重、非空），页面提供默认全选的勾选面板与「全选 / 仅眼睛三项」快捷方式。
- **移除「处置后加固」页面区块**（按用户要求）：`hardening-scan` / `plan-hardening` 后端能力、注册表与 `probe-response-hardening.mjs` 探针保留并通过验收，恢复入口只需把页面区块与契约类型加回（登记于 UNWIRED_FEATURES.md）。

## 目标与来源

给 LovelyHawk 增加「Linux 主机应急响应自动化处置」能力：对 SSH 目标一键扫描入侵痕迹，**每个问题项行内一个「修复」按钮**，点击后经 确认 → 取证归档 → 执行 → 自动复验 的完整链路处置该项。检测/修复规则集以 ghost-range（v1，三关）与 ghost-range-v2（深度失陷五关）应急响应靶场的全部考点为基线设计，并在两个靶场上完成端到端验收。

## 用户流程

1. 侧栏「应急处置」页 →「开始扫描」（需已连接目标）。
2. 结果列表逐行展示：类别、严重度、摘要、证据（可展开）、修复方式说明；权限不足的项目按钮置灰并说明原因，采集盲区在页面顶部缺口区列出。
3. 点「修复」→ 弹层展示处置计划（步骤、影响、归档位置、回滚说明、有效期）→ 确认后执行。
4. 行内实时状态：执行中 →（后门项）「等待跨周期复验（约 70 秒）」→ 已修复并复验通过 / 执行完成但复验未通过 / 失败原因。
5. 「重新扫描」复验全局；有修复进行中时先提示（新扫描会吊销旧问题句柄）。

空口令账户在确认弹层可选「锁定账户（默认）/ 删除账户」两种修复方式；其余类别为单一修复动作。

## 检测与修复能力（17 类）

| 类别（kind） | 检测方法 | 修复动作 | 复验 |
| --- | --- | --- | --- |
| ld-preload-hijack 动态链接库劫持（critical） | 直读 `/etc/ld.so.preload` 非空行，逐库取 sha256+stat 指纹 | 归档后删 preload 文件与全部白名单内引用库（先删 preload 即时解除 readdir 钩子） | preload 无有效行且引用库全部不存在 |
| path-injection PATH 注入（critical） | 启动文件（profile/bashrc/environment/profile.d）中含 PATH= 且引用隐藏目录或 world-writable 目录（标准 PATH 目录闭合集不误报） | 归档后按行号+行 sha256 双复核删行（profile.d 整文件可疑删整文件），连带删除注入目录内的伪命令 | 全文件行摘要搜索确认注入行消失 + 伪命令全部不存在 |
| hijacked-command 伪命令劫持（critical） | `command -v` 多副本 + 吞行特征双信号（文件含 `grep -E` 过滤且回调真身绝对路径） | 归档后 `rm` | PATH 解析回到 `/usr/bin` + 文件不存在 |
| ssh-key-backdoor SSH 密钥后门（critical） | authorized_keys 有效行的选项段含 `command=`（选项在密钥类型 token 之前，密钥材料里的 command= 不误报） | 归档后删条目（整文件均恶意删整文件），并删除 command= 指向的脚本本体 | 行摘要全文件搜索 + 脚本本体不存在 |
| pam-backdoor PAM 认证后门（critical） | `/etc/pam.d/*` 有效行含 `pam_permit` | 归档后按行号+行 sha256 双复核删行 | 该文件不再有任何有效 pam_permit 行 |
| webshell WebShell（critical） | getdents64 直扫遍历 `/var/www`，脚本扩展名 + 危险函数特征（`eval($_POST` 等闭合特征集） | 归档后删文件；所在隐藏目录经 getdents64 复核「纯恶意」（仅有该文件）则整目录删除 | 文件（目录）不存在 + 业务首页保持 plan 时冻结的 200 |
| bind-listener 可疑监听 | 直读 `/proc/net/tcp(6)` 取 LISTEN（st=0A），按 inode 反查进程；回环非常规端口或进程本体可疑即命中 | 走后门进程处置链（断 cron 保活 → 删本体 → 杀进程） | 本体灭 + 无进程引用 + 端口不再 LISTEN；70 秒跨周期复验 |
| backdoor-process 后门进程 | 直读 `/proc/[0-9]*/cmdline` + `readlink exe`（不信任可能被劫持的 ps/PATH） | **锁死顺序**：级联断 cron 通道 → 删本体 → 按 `/proc/<pid>/cmdline` 复核后 TERM→KILL | 异步等待 70 秒跨过一个 cron 保活周期后重扫，确认不复活 |
| uid-zero-account UID=0 影子账户 | `awk $3==0 && !=root` 读 `/etc/passwd` | 归档账户四件套后 `userdel -f`；家目录仅 `/home/<x>` 才 `-r`（系统目录不连带删） | 双库无条目 |
| empty-password 空口令账户 | `awk $2==""` 读 `/etc/shadow` | 默认 `passwd -l` 锁定；可选删除（同上的家目录判定） | shadow 字段以 `!` 开头 / 双库无条目 |
| malicious-sudoers 恶意提权授权 | 扫描 `/etc/sudoers` 与 `/etc/sudoers.d/*`（NOPASSWD 等） | 按 行号+行 sha256 双复核删行/整文件删 → `visudo -c`，失败自动从归档恢复并复检 | 重跑检测 + `visudo -c` 通过 |
| cron-persistence 计划任务持久化 | 枚举 `/etc/crontab`、`/etc/cron.d/*`、`/var/spool/cron/crontabs/*`、`cron.daily` 等全点位，Rust 侧闭合规则判定可疑行 | 按行号+行 sha256 双复核删行/整文件删 | 重跑检测 |
| stash-dir 后门藏匿目录 | 从可疑 cron 行与可疑进程命令行/ exe 中的路径 token 向上归约出隐藏目录（/var/tmp//tmp//dev/shm//opt/ 下 `.x` 形态，系统隐藏目录 denylist 除外）；无引用不单独报 | 归档整个目录后递归删除 | 目录不存在 |
| web-sensitive-file Web 敏感文件泄露 | getdents64 遍历 `/var/www`，`.env*` 与 backup/dump/bak 语义的压缩包/数据库扩展名 | 归档后删文件 | 文件不存在 + 业务首页保持 200 |
| command-recorder 命令录音钩子 | 启动文件有效行含 PROMPT_COMMAND 且 `>>` 追加到文件，解析录音文件路径并取指纹 | 归档后删钩子行（profile.d 整文件可疑删整文件）+ 删录音文件 | 行摘要全文件搜索 + 录音文件不存在 |
| session-env-hook 会话驻留钩子（critical） | 直读 `/proc/*/environ`（root），PROMPT_COMMAND 含 `>>`、PATH 含隐藏/可写目录、LD_PRELOAD 指向已删或攻击者目录三种闭合签名；相同钩子环境聚类为一个会话簇 | 逐 PID 复核 `/proc/<pid>/exe` 身份后 TERM→KILL 整簇（不删任何文件，无归档） | 簇内 PID 全灭 + 全机 `/proc/*/environ` 无签名残留 |
| preload-residue 恶意库驻留进程（high） | `/proc/*/maps` 引用可疑前缀下已删除/不存在的 `.so`（发行版升级残留因 `/usr/lib` 前缀排除不误报） | **不自动修复**（kill 常驻服务会打断业务）：给出按业务窗口重启对应服务的指引 | ——（指导型，重新扫描观察） |
| suspicious-account 可疑登录账户 | uid≥1000 + 交互 shell（bash/sh/zsh/dash/ash 闭合集）+ 非会话登录用户 + 未被 uid-zero/空口令覆盖（去重） | 同 uid-zero 删除路径 | 双库无条目 |
| history-credential-leak 历史命令明文密码 | `/root/.bash_history`、`/home/*/.bash_history` 逐行闭合特征判定（`mysql -p` 内联、chpasswd 管道、`password=` 赋值；`nmap -p-`/`ssh -p22`/注释不误报） | 归档整个历史文件后按行号+行 sha256 双复核删行（不清空文件） | 全文件行摘要搜索确认该行消失 |

所有删除类动作执行前强制取证归档：远端 `install -d -m700 /var/case/bak/<UTC时间戳>-<类别>/` + `cp -rp --parents` + `MANIFEST.sha256`。例外：session-env-hook 只终结进程不删文件，无归档。

## 处置后加固（hardening-scan / plan-hardening）

清掉入侵痕迹后的一键加固检查，三项闭合条目，各带「待加固 / 已达标 / 不适用（含原因）」三态；待加固项走与应急修复完全相同的 plan→confirm→execute→poll 链路（同一张 plan 注册表，confirm/execute/poll 复用，修复确认弹层共用）：

| 加固项 | 检查 | 动作 | 复验 |
| --- | --- | --- | --- |
| 认证文件权限（hardening-auth-permissions） | `stat` 闭合目标集（shadow/gshadow/sudoers/sudoers.d、root 与各用户 .ssh 与 authorized_keys、crontab spool 目录、SSH 主机密钥）比对基线 mode/owner/group；固定目标用基线三元组，用户级路径只收紧 mode 保留属主 | 原始权限记录进归档后逐项 chmod/chown | 逐项重 stat 等于基线；撤销按归档记录恢复 |
| 防复发监控（hardening-audit-watch） | auditctl 是否存在、10 个篡改热点（passwd/shadow/sudoers、cron、profile.d、pam.d、/var/tmp、root/.ssh）是否已有 `lovelyhawk-tamper` watch | auditctl 逐点 `-w … -p wa -k lovelyhawk-tamper`（运行时规则，重启失效已在方案中注明）；撤销逐点 `-W` | `auditctl -l` 含全部点位与键；无 auditd 的容器报「不适用」而非假装覆盖 |
| 完整性基线（hardening-integrity-snapshot） | `/var/case/hardening/integrity-manifest.txt` 是否存在；存在时抽查最近 64 项重算 sha256 比对漂移 | 对认证与后门高发位置（上限 256 项）生成 0600 清单；漂移后可重建收编当前状态 | 清单非空且抽查一致；漂移态重新扫描回到已达标 |

凭据轮换属人工步骤，不在自动加固内：扫描发现过 `.env` 明文口令、history 明文密码时，报告文案提示「删文件≠追回密码」，由操作员确认轮换。


扫描排序固定「先修眼睛」：先按严重度（critical > high > medium），同级按类别固定序（ld-preload → path-injection → hijacked-command → …），因为 ld.so.preload / PATH / 伪命令不除，其余所有观测都不可信。

v2 靶场的 libsyslog.so 会钩住 readdir 隐藏 `.sysd`/`.ghost` 条目：扫描与目录复核内嵌 python3 ctypes 直调 `getdents64`（syscall 217，`lstat` 不跟符号链接）的 `hawk_walk`，钩子对枚举无效；目标无 python3 时降级 find 并在缺口区明示。

## 安全设计

- **句柄隔离**：修复只接受扫描时后端签发的 opaque handle（UUID），页面拿不到任何可执行语义；对象身份由 core 校验过的 `IssueObject` 承载。
- **闭合校验**：路径前缀白名单（`/usr/local/bin/`、`/etc/sudoers*`、`/etc/cron*`、`/var/spool/cron/`、`/usr/local/libexec/`、`/usr/local/lib/`、`/etc/profile*`、`/etc/pam.d/`、`/var/www/`、`ld.so.preload`、authorized_keys 与 .bash_history 的限定形态，外加 `/var/tmp//tmp//dev/shm//opt/` 下的隐藏目录（denylist 系统隐藏目录）），拒绝 `..` 与符号链接逃逸；用户名、PID、行号、sha256 各自格式校验；命令模板静态化，拼接值一律 `shell_escape`。
- **TOCTOU 防护**：plan 阶段与执行脚本内双重复核（文件 sha256+stat 指纹、行 sha256、`/proc/<pid>/exe` 身份），不符即拒绝；扫描时消失的次级本体（伪命令、录音文件、强制命令脚本）容忍跳过，内容变化的直接中止整计划。
- **提权**：探测 `id -u` → `sudo -n` → 会话存密走 `sudo -S -p ''`（经 `execute_bound_sensitive`，密码 Zeroizing 留在 core，不进命令行/DTO/日志/journal）；三者皆不可时降级扫描、缺口可见、修复置灰。
- **污染环境自检**：检测/修复命令全部绝对路径调用系统工具，进程检测直读 `/proc`。
- **生命周期**：plan/confirm/execute/journal/verify 全部走 `operations.rs` 既有状态机，journal 落盘；文件类支持从归档恢复，删号类不提供自动恢复（归档保留）。
- **并发与失效**：同一目标同时只允许一个修复（busy）；新扫描吊销旧句柄；plan TTL 5 分钟；断连/切目标后迟到结果失效（scope 绑定 + close_binding 回收）。

## 架构接线（六层）

```
core  crates/lovelyhawk-core/src/response_engine.rs   ResponseEngineService::{scan, plan_fix, execute_fix, verify_fix}
 ↓    （挂入 BackendServices；audit.rs 的 privileged_script 提为 pub(crate) 共享）
backend crates/lovelyhawk-backend/src/response_engine_api.rs
      RpcMethod::ResponseEngine（"response.engine"），action: scan/plan-fix/confirm-fix/cancel-fix/execute-fix/poll-fix
      三张句柄注册表（Mutex<HashMap> + TTL + scope 绑定）；execute-fix spawn：execute →（70s）→ verify → 回写 stage
 ↓
desktop crates/lovelyhawk-desktop/src/backend_bridge.rs   MAIN_WINDOW_METHODS 加白；poll-fix/cancel-fix 走 Control lane
 ↓
UI    ui/src/shared/response-engine-contract.ts（双侧运行时校验）
      ui/src/host/main-api.ts + backend-client.ts（scan 超时 120s、其余 60s）
      ui/src/renderer/ResponseEnginePage.tsx（+ response-engine.css，色值全走 theme token）
```

页面 descriptor 已注册（id `response-engine`，group triage，「开始扫描」，migration_state=Ready）。

## 文件清单

**新建**
- `crates/lovelyhawk-core/src/response_engine.rs`（约 7.3k 行，含引擎单测）
- `crates/lovelyhawk-backend/src/response_engine_api.rs`（约 1.2k 行）
- `ui/src/shared/response-engine-contract.ts`（+ `.test.ts`）
- `ui/src/renderer/ResponseEnginePage.tsx`（+ `response-engine.css`、`response-engine-page.test.tsx`）
- `tools/lab/probe-response-engine.mjs`（v1 端到端探针；支持 `PROBE_HOST/PROBE_PORT/PROBE_USER/PROBE_PASS` 覆盖目标，远程模式跳过本地容器重置与评分段）
- `tools/lab/probe-response-engine-v2.mjs`（v2 深度失陷端到端探针：容器 `ghost-range-v2-lab`，端口 2322/8081，含跨周期复评与业务 200 断言；2026-10-30 第二次扩展后另需植入一个 `bash -l` 钩子会话并断言 session-env-hook 修复；远程模式 `PROBE_REMOTE_FIX=1` 可执行完整修复队列）
- `tools/lab/probe-response-hardening.mjs`（加固端到端探针：植入权限偏离→收紧→auditd 不适用判定→清单建立→漂移→重建全链路；远程模式只检查不加固）

**修改**
- `crates/lovelyhawk-core/src/lib.rs`、`services.rs`（挂服务）、`audit.rs`（`privileged_script` → `pub(crate)`）
- `crates/lovelyhawk-backend/src/lib.rs`（RpcMethod、dispatch、错误映射、BackendState、close_binding、page_descriptors）
- `crates/lovelyhawk-desktop/src/backend_bridge.rs`（白名单 + lane）
- `ui/src/shared/contract.ts`、`ui/src/host/main-api.ts`、`ui/src/host/backend-client.ts`、`ui/src/renderer/App.tsx`、`nav-icons.tsx` 及若干页面清单/计数断言测试

## 验证证据

2026-10-30 第二次扩展后（本轮全部重跑）：

- 单测：`cargo test --locked -p lovelyhawk-core` **1332 passed**；`-p lovelyhawk-backend` 全绿（含新 action 的闭合请求校验与 kebab 序列化断言）；三包 clippy `--all-targets --no-deps -- -D warnings` 零警告（`lovelyhawk-desktop` 在本 Linux 环境因缺 GTK/pkg-config 系统库无法编译，为预存环境限制，本轮未改 desktop 代码——新 action 走已白名单的 `response.engine` 方法，lane 语义不变）；`cargo fmt --check` 通过；`pnpm ui:check`（145 测试文件 / 1205 用例 + typecheck + build）全绿。
- 本地 v2 深度失陷探针（容器重置后全流程）：扫描 **17 类 25 项全命中**（含植入的 `bash -l` 钩子会话 → session-env-hook 1 项；boot 竞态的 netmon 双实例由 listener 一并收编）→ 逐项 plan/confirm/execute/poll 全部 `completed + verifyPassed`（session-env-hook 修复后全机环境扫描无签名）→ 复扫仅剩 preload-residue 指导项（不可自动修复为设计内，给出重启指引）→ 容器内 `python3 /opt/check.py` **5/5 通过（exit 0）** → 70 秒跨周期复评仍 5/5 → 业务首页保持 200 → 每项删除类修复独立证据归档（MANIFEST.sha256）。**ALL CHECKS PASSED（137 项断言）**。
- 本地加固探针：植入 shadow/authorized_keys 666 偏离 → 扫描 pending 且证据点名 → 收紧 640/600 并复验 → 归档含原始权限记录；无 auditd 的容器正确报告「不适用」而非假装覆盖；完整性清单建立（>10 项）→ 追加 `/etc/crontab` 漂移被点名 → 重建后回到已达标。**ALL CHECKS PASSED**。
- 真实远程靶场（nc1.ctfplus.cn:16050，共享实例）**端到端通关**：
  - 只读扫描 25 项 16 类全命中（远程无挂起钩子会话、恶意库未删故无这两类，符合预期）；
  - `PROBE_REMOTE_FIX=1` 分两轮执行完整修复队列（第一轮被业务 nginx 绑 127.0.0.1:80 的误报中断——该误报即本轮修复项之一；第二轮在收紧后重跑），全部 `completed + verifyPassed`，复扫仅剩 preload-residue 指导项；
  - 目标上 `sudo python3 /opt/check.py` **5/5 全部通过，flag{ghost-range-deep-cleaned}**，且 70 秒跨周期复评仍 5/5（无复活）；
  - 远程加固检查（只读）：权限项 compliant（8 个文件达标）、audit 项如实报 not-applicable（容器无 auditd）、清单项 pending 待建。ALL CHECKS PASSED。
- 本轮顺带修复并回归的既有缺陷：PAM 误报（发行版原生 `required pam_permit` 被当后门删除导致 sudo 全挂——v2 探针全流程实测暴露，已收紧为 `auth sufficient` 并补回归测试）；bind-listener 只杀 socket 持有者导致自旋实例抢回端口（已并入同本体全部 PID）；探针 history 行号排序正则失配导致升序删行错位；业务 nginx 绑 `127.0.0.1:80` 被误报可疑监听（80/443 已入合理回环端口表并补回归测试）。
- 端到端探针（本地 ghost-range 容器，失陷态重置后跑）：扫描命中 9 项 / 6 类全覆盖 → 逐条 plan/confirm/execute/poll 全部 `completed + verifyPassed` → 复扫 0 → 容器内 `python3 /opt/check.py` 3/3 通过（exit 0）→ 每项修复均有独立证据归档（MANIFEST.sha256）。连续多轮 ALL CHECKS PASSED，幂等。
- 真实靶场实测（nc1.ctfplus.cn，共享实例）：仅剩锁定态 watcher 残留的场景下，扫描命中 `suspicious-account × 1` → 修复 → 复扫 0 → check.py 3/3 通过。此前完整失陷实例亦已全程走通并拿到通关 flag。

## Windows 便携发布包

当前产物：`artifacts/LovelyHawk-0.0.5-windows-x64.zip`（18.1 MB，sha256 `e81ee00f1b289364d91d174d87b18943409656bff399d100ccec5a188bab4106`）+ `.sha256`，含本轮全部应急 19 类与处置后加固能力（版本一致性：Cargo 工作区 / tauri.conf.json / ui/package.json 均 0.0.4，CHANGELOG 已定版 v0.0.4）。上一版 0.0.3 的产物与校验值保留在 artifacts/ 供对照。

在 Linux 上经 cargo-xwin 交叉构建（`x86_64-pc-windows-msvc`，`-C target-feature=+crt-static`，`CARGO_BUILD_JOBS=2`），打包与校验走项目原生 `scripts/desktop-package-windows.ps1` / `desktop-validate-package.ps1`（Linux pwsh 7.6.2 零修改跑通）：source-gate、PE/静态 CRT 门禁（无 VCRUNTIME/MSVCP/MSVCR，仅系统 DLL + UCRT）、第三方清单（443 crates，CycloneDX 1.5 SBOM）、版本一致性全部通过。

复现注意：cargo-xwin 默认强制静态 UCRT（链接参数 `-nodefaultlib:ucrt -defaultlib:libucrt`）与项目 `static_vcruntime` 的动态 UCRT 设计冲突；构建用 lld-link 参数过滤包装，已持久化到 `~/.local/lld-filter/lld-link`（过滤上述两项后转发 rustc 自带的 `rust-lld`——本机未装 lld 包；`llvm-rc`/`llvm-objdump` 来自系统 llvm-21，`/usr/lib/llvm-21/bin` 入 PATH；xwin SDK 缓存在 `~/.cache/xwin`）。本机 8G 内存跑该构建需 `CARGO_BUILD_JOBS=1`（jobs=2 曾两次触发整机卡死）。

## 剩余限制

- 便携冒烟（`release:smoke`）与 CDP 逐页桌面巡检需要真实 Windows + WebView2，未执行——ZIP 的结构/清单/二进制校验全过，但运行态未实测（已登记 `docs/UNWIRED_FEATURES.md`）。
- `release:quality-gate` 中 `lovelyhawk-win-dvc` 在 Linux 上的 clippy/test 失败为预存平台问题（Windows 专用 crate 缺 cfg 门控），与本次改动无关。
- 检测面目前覆盖上述 17 类；systemd timer、内核级 rootkit 等更深层持久化/隐藏手段未覆盖，扩类只需在 `response_engine.rs` 加 detector/fixer 与枚举值。
- 密码 sudo 复用 SSH 会话登录密码；无密码 sudo、密钥-only 登录且非 root 的场景下修复不可用（降级扫描 + 缺口提示）。
