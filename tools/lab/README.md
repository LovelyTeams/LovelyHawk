# 靶机与实机验证工具

用 WSL 里的 Docker 起两批靶机，再拿真实 sidecar 连上去跑检测，用已知的问题核对
检出结果。自动化测试证明代码按写的方式运行；这里证明它在真实主机上找得到东西。

**先看这台**：[综合靶机](arena/README.md) —— 一台 Ubuntu 上跑齐 nginx / MariaDB / Redis / PostgreSQL，
六个基线文件全是错的，还带几处入侵痕迹。一台机器覆盖到基线、中间件、数据库、命令工作台，
也只有一台要养。`pnpm lab:arena`，端口 2250。

下面两批是按产品/发行版分开的细活：

| 批次 | 端口 | 是什么 | 用来验 |
|------|------|--------|--------|
| 被入侵主机（9 台） | 2222–2230 | 九种发行版，各种下 30 项植入物 | 命令工作台、日志分析、文件处置、跨发行版适配 |
| 配置不合规主机（12 台） | 2231–2242 | 每台一个真实产品，配置留成没加固的样子 | 配置核查、中间件发现、数据库巡检、安全基线 |

第二批见 [`services/README.md`](services/README.md)。下面讲第一批。

Nginx 精确修补与恢复的独立验收见 [`NGINX_PROCESS_REPAIR.md`](../../docs/NGINX_PROCESS_REPAIR.md)：先构建最新后端（`pnpm backend:harness`）和桌面应用（`pnpm desktop:build`），再运行 `node tools/lab/probe-nginx-repair.mjs`。该探针基于本地缓存镜像新建唯一容器与临时连接库，走真实 RPC 和桌面应用的原生 CDP（见下文[桌面界面探针](#桌面界面探针)），由 HTTP 独立核对产品修补效果；结束时只清理本次资源，不运行批量靶机重建或连接库导入。

同一探针还验证 [Nginx TLS/HTTP 连接复核与案件留证](../../docs/NGINX_CONNECTIVITY.md)。它检查真实协议/证书/HEAD 结果逐次入案，在自己的临时数据目录中模拟案件存储不可用，核对等待复核后的离开保护、取消保留、原记录重试且不增加目标 HEAD 请求、打开案件、Markdown/HTML 报告及断连后的完整 JSON 导出。保存对话框的返回值和剪贴板只在本次调试版应用的宿主边界由测试接管，避免操作用户剪贴板；其他链路使用真实产品实现。失败注入保留并恢复原案件文件，只移除经过校验的空占位目录；完整记录和截图位于该次报告目录。

应急文件留证的独立验收见 [`FILE_EVIDENCE_COLLECTION.md`](../../docs/FILE_EVIDENCE_COLLECTION.md)：`node tools/lab/probe-file-evidence.mjs` 自动创建独立 Ubuntu 容器，验证二进制原件、清单、案件/报告与桌面应用用户流程；设置 `EVIDENCE_LAB=alpine` 验证 Alpine SFTP/RPC。目录选择器的返回值由测试控制，其他环节运行真实实现，不触碰既有靶机。

基线历史恢复的独立 core 实验见 [恢复验证边界](../../docs/BASELINE_RESTORE_VERIFICATION.md)：执行 `node tools/lab/probe-baseline-restore.mjs` 创建独有 Redis / SSH 容器，通过实际计划、确认、写入和独立回读验证恢复；覆盖后续内容、权限和 inode 变化、完整备份预检、符号链接、原先缺失文件及复核期间干预。报告保留版本、镜像、结果和失败材料，仅回收本次容器与临时应用数据。此探针不计桌面应用修补入口验收，Redis 历史样例由测试明确构造，不启用产品通用 Redis 写入器。

Redis 候选基线的独立验收见 [`REDIS_BASELINE_VERIFICATION.md`](../../docs/REDIS_BASELINE_VERIFICATION.md)：构建最新后端与桌面应用后执行 `node tools/lab/probe-redis-baseline.mjs`。它创建独立 Redis 容器和临时连接库，核对通配监听、认证/ACL、日志与命令权限、真实 Redis 语法，以及原生界面中的风险来源和待复核状态；`REDIS_UI=0` 仅做 RPC 检查。实验夹具修改不计为应用自动修补或恢复证据。

PostgreSQL 候选基线的独立验收见 [`POSTGRESQL_BASELINE_VERIFICATION.md`](../../docs/POSTGRESQL_BASELINE_VERIFICATION.md)：构建最新后端与桌面应用后执行 `node tools/lab/probe-postgresql-baseline.mjs`。它新建独有 PostgreSQL/SSH 容器和临时连接库，用原生解析器与实际运行值核对注释、重复项、候选来源、未重载文件和 `ALTER SYSTEM` 覆盖，并验证正常桌面应用中的待复核、日志与来源说明。数据目录仅使用本次 tmpfs，结束后核对并清理本次资源；夹具 SQL 和配置修改不计产品数据库修补验收。

PostgreSQL 原生认证与运行参数 core 验收执行 `node tools/lab/probe-postgresql-native.mjs`，见 [`POSTGRESQL_NATIVE_RUNTIME.md`](../../docs/POSTGRESQL_NATIVE_RUNTIME.md)。它复用缓存镜像，新建独有容器、证书和临时连接库，验证真实 SCRAM/MD5、TLS、权限失败、取消、目标/配置变化与 SSH 断开；读取 `pg_stat_activity` 独立确认清理。该探针会串行执行 Cargo 测试，不能和其他 Cargo 命令同时运行。不加参数时只做核心验证。完成后端和桌面应用构建后，加 `--desktop` 可运行新数据库页的正常桌面验收，覆盖连接编辑、TLS/SCRAM/MD5、分页、冲突、取消、旧配置关联、脏编辑、删除确认与断连，并验证会话标识、include/auto.conf 来源、未重载文件、受限角色、案件摘要及保存失败后的重试/导航保护；报告分别写入 `target/lab-postgresql-native/` 与 `target/lab-postgresql-desktop/`。桌面模式不执行 Cargo，不能把核心模式的通过数量当作桌面证据。 桌面夹具还会在本次容器中准备 Python 和 `SYS_PTRACE`，验证相同命名空间的进程/socket 对应、错误 PID/端口、权限不足与缺工具时的真实页面；不修改缓存基础镜像或产品权限策略，详见 [进程对应验收](../../docs/POSTGRESQL_PROCESS_CORRELATION.md)。 当前桌面探针还验证 HBA/ident 当前文件与 include 来源、LDAP/RADIUS 秘密值隐藏、角色标识与口令到期、受限账号、数量/字节超限、访问分页与 v3 案件摘要；夹具 SQL 经标准输入传递，避免 WSL 解释 SQL 的美元引号。所有角色创建、口令更换及不重载的认证文件修改均只用于这个归属已核实的容器，不是产品修补能力，见 [访问诊断验收](../../docs/POSTGRESQL_ACCESS_DIAGNOSTICS.md)。

案件工作台的独立验收见 [`CASE_WORKSPACE.md`](../../docs/CASE_WORKSPACE.md)：`node tools/lab/probe-case-workspace.mjs` 验证创建重试、固定案件视图、分页、笔记版本、案件切换时的文件归属，以及真实桌面应用的创建/记录/检索/报告保存、长结案结论的完整核对与键盘滚动、防回车误确认、取消保留输入、重新调查保留历史、Markdown / HTML 中的完整结论及来源、断连后的完整 JSON 导出、归档/恢复与覆盖拒绝；设置 `CASE_LAB=alpine` 验证 Alpine RPC/SFTP。探针只创建并清理本次资源，只有报告与案件 JSON 的系统保存对话框返回值由测试控制。

登录一律 `root` / `LabRoot#2026`。WSL 的 localhost 转发会间歇性断开，所以探针走 WSL
虚机自己的地址（`lab-target.mjs` 自动取）。容器 PID 1 是 `sleep infinity` 加 sshd
看门狗，否则 sshd 一退出整台靶机就没了。

## 一键起环境

```bash
pnpm lab:up
```

一条命令：检查 WSL 里的 docker、同步靶机定义、把九台都拉起来，再把它们连同口令写进
LovelyHawk 的连接库。打开应用就能在连接管理里直接点，不用输任何东西。

WSL 重启后虚机会换地址，再跑一次 `pnpm lab:up` 就把九条连接的地址都刷新了（原地更新，
不会产生重复条目）。

### 靶机集体挂掉，先别查靶机

表现是**所有靶机的退出码相同、退出时间也相同**（`Exited (255)` 或 `Exited (128)`）。
判据：靶机的 PID 1 是 `exec sleep infinity`（见 `services/entrypoint.sh`），它自己不会退出，
所以非零退出码一定来自外面；`docker inspect` 里 `OOMKilled=false` 可以排除内存不够。

**直接原因是虚机里的 docker 守护进程停过一次又起来了**，不是靶机自己的问题。查证：

```bash
wsl -d Ubuntu -u root -- journalctl -u docker --no-pager | grep 'systemd\[1\]'
```

看 `Started docker.service` 的时间，和靶机的退出时间对得上就是它。

触发条件是**机器上一个 `wsl.exe` 进程都不剩**：最后一个退出后几秒，虚机里的 docker
守护进程和所有容器就没了；下一次 `wsl.exe` 进来时 `docker.service` 被重新拉起来，
但容器不会跟着回来。

这不是「发行版重启了」——`journalctl --list-boots` 显示 boot id 自始至终没变、uptime
连续。所以 `/etc/wsl.conf` 里的 `systemd=true` 帮不上忙，`systemctl is-enabled docker`
显示 enabled 也帮不上忙。2026-09-02 记到三次，都是同一个 boot 里发生的：

| 最后一个 wsl.exe 退出 | `Starting docker.service` | 容器退出 |
| --- | --- | --- |
| ~00:29 | 00:30:17 | 同一窗口 |
| ~02:10 | 02:10:58 | 02:10:55 |
| ~03:51 | 03:51:39 | 同一窗口 |

反过来也成立：中间用一个长命令占着的那 97 分钟，靶机一台没掉。所以要长时间跑测试，
先开个后台进程占住，再起靶机：

```bash
wsl -d Ubuntu -e sleep 5400 &
```

守护进程刚起来的那十几秒里**别急着起靶机**：`--privileged` 的那两台会撞上
`devices.allow: invalid argument`（cgroup 还没就绪），`docker start` 直接失败，
但过一会儿重试就好了。`restart.sh` 报告「已启动」而靶机其实没起来，多半就是这个——
所以起完要复查一次 `docker ps -a --filter status=exited`。

被这样杀掉之后，跑着守护进程的那两台靶机自己起不来，各有各的理由，两条都已经在
entrypoint 里处理了：`svc-docker` 的 `/var/run/docker.pid` 留在可写层，下次启动时那个
pid 号**要是**正好被新命名空间里的别的进程占着，dockerd 就拒绝启动（占没占上看运气，
所以这个故障是时灵时不灵的）；`svc-podman` 缓存了上次的 boot id，对不上就拒绝执行任何
命令（这条是必现的）。`svc-arena` 用的是 `--tmpfs /var/run`，pid 文件活不过进程，所以不需要。

**改的是 entrypoint，所以镜像不重建就还是老样子。** 2026-09-02 验过：两台各重建一次，
再 `docker kill` 硬杀、`docker start` 起回来，内层守护进程都自己活了，内层容器也跟着回来。
只要内层守护进程起得来，`plant.sh` 会在 entrypoint 里重跑一遍，把内层容器恢复成预期状态
（它们自己没有 restart 策略——「停着的容器」也是靶机的一部分）。守护进程要是没起来，
`plant.sh` 的等待循环会超时退出，那时内层就一个都不会回来，得手工补：

```bash
wsl -d Ubuntu -u root -- docker exec svc-docker sh -c 'docker ps -a --format "{{.Names}}" | grep -vE "^(stopped-worker|stopped-batch)$" | xargs -r docker start'
```

`/var/lib/docker` 那个卷要是被写坏了（dockerd 启动时 panic），修不回来，删掉卷重建靶机。

| 命令 | 作用 |
| --- | --- |
| `pnpm lab:up` | 起容器 + 写连接库 |
| `pnpm lab:up -- -Rebuild` | 改过 `tools/lab/matrix/` 里的脚本后重建镜像 |
| `pnpm lab:up -- -SkipImport` | 只起容器，不动连接库 |
| `pnpm lab:import` | 只刷新连接库（换地址后最常用） |
| `pnpm lab:remove` | 把九条实验靶机连接从库里删掉 |
| `pnpm lab:down` | 停掉容器，连接条目保留 |

连接名统一是「实验靶机 xxx」、分组「实验靶机」、标签 `lab`，和真实目标一眼可分。
写入的是应用自己的连接库（调试版 `target/debug/lovelyhawk.exe` 的数据在 `D:\LovelyRes\data`，
`pnpm desktop:dev` 打开的就是它）；要写到别处就设 `LOVELYHAWK_ARCHIVE_ROOT`。
**应用运行时不要跑导入**，应用内的后端和导入脚本的后端同时写同一个库会打架。

## 九台靶机（tools/lab/matrix/）

`build.sh` 按发行版逐台构建并启动，植入物用同一份 `compromise.sh`，所以任何检出差异
都来自发行版本身而不是靶机。

| 名称 | 镜像 | 端口 | 包管理 |
| --- | --- | --- | --- |
| ubuntu | ubuntu:22.04 | 2222 | apt |
| alpine | alpine:3.20 | 2223 | apk / busybox |
| debian | debian:12 | 2224 | apt |
| rocky | rockylinux/rockylinux:9 | 2225 | dnf |
| alma | almalinux:9 | 2226 | dnf |
| openeuler | openeuler/openeuler:22.03-lts | 2227 | dnf（国产） |
| anolis | openanolis/anolisos:8.8 | 2228 | dnf（国产/龙蜥） |
| deepin | linuxdeepin/deepin:beige | 2229 | apt（国产/深度） |
| suse | opensuse/leap:15.5 | 2230 | zypper |

麒麟（Kylin）和统信（UOS）是商业镜像，Docker Hub 上没有公开 tag，暂时缺席。

```bash
wsl -d Ubuntu -u root -e bash -lc 'cp /mnt/d/LovelyRes/tools/lab/matrix/* /opt/lab-matrix/ && sed -i "s/
$//" /opt/lab-matrix/*.sh && bash /opt/lab-matrix/build.sh'
```

单独重建一台：`bash /opt/lab-matrix/build.sh ubuntu`。

## 植入了什么（约 30 项）

- **账号**：第二个 UID 0、空口令账号、系统账号被给了 shell、两条 NOPASSWD sudo 规则
  （一条通配、一条指向能拿 shell 的工具）、用户被塞进特权组
- **登录脚本链**：`/etc/profile`、`/etc/profile.d/00-locale-fix.sh`、`/etc/bash.bashrc`、
  `~/.bashrc`、`~/.bash_logout`、`/etc/environment` 里的 LD_PRELOAD、`~/.ssh/rc`、`/etc/ssh/sshrc`
- **SSH**：允许 root 登录与口令认证、`sshd_config.d` 里额外的 AuthorizedKeysFile 与
  PermitEmptyPasswords、root 与普通用户各一把攻击者公钥、一把带 `command=` 强制命令的公钥
- **计划任务**：`/etc/cron.d`、`/etc/cron.daily`、用户 crontab（两种路径）、systemd timer
- **服务/持久化**：systemd unit（带 LD_PRELOAD）、`rc.local`、`init.d` 脚本、`update-motd.d`、
  `pam.d/sshd` 里的 pam_exec 钩子、`/etc/ld.so.preload`
- **权限**：SUID 后门、标准工具被加 SUID、python3 被赋 `cap_setuid`、全局可写库目录
- **文件**：隐藏目录 `/tmp/.X11-unix/.cache`、带空格的 `/var/tmp/... `、`.bash_history` 指向
  `/dev/null`、关键文件时间戳被回填到 2024-01-01
- **网络**：4444 监听（进程名伪装成 `[kworker/1:2-events]`）、`/etc/hosts` 劫持三个更新源
- **Web**：明文 webshell、base64+assert 混淆 webshell、JSP webshell、`.htaccess` 放开执行
- **日志**：爆破 20 次后成功登录、nginx 的 webshell POST、wtmp/btmp 被清空
- **进程**：可执行文件已被删除但仍在运行的进程

攻击者 IP 统一 `198.51.100.7`，方便当 IOC 用。回连都加了 1 秒连接超时并脱离会话，
否则不可达的 C2 会把每次登录拖到 20 秒。

## 检出率（2026-08-26）

`probe-groundtruth.mjs` 逐条断言 30 项植入物：

| 靶机 | 结果 | 说明 |
| --- | --- | --- |
| ubuntu / debian / deepin | 30/30 | |
| rocky / alma / anolis / openeuler | 30/30 | 修复前 RPM 系连命令目录都出不来 |
| suse | 28/30 | 两项靶机没种上：SUSE 的 `daemon` 行与特权组名不同 |
| alpine | 28/30 | 两项在 Alpine 上不存在：`/usr/bin/find` 是 busybox 符号链接（加 SUID 无效）、系统无 PAM |

余下的差额都是**靶机在该发行版上没种上**，不是漏检。改降噪规则后如果某台掉到 30 以下，
先用 `probe-one.mjs` 看那条命令的原始输出，确认是规则问题还是植入没成功。

## 探针

```bash
node tools/lab/probe-groundtruth.mjs   # 回归闸门：30 项植入物逐条断言仍被命中
node tools/lab/probe-matrix.mjs        # 九台一起跑，输出跨发行版差异表
node tools/lab/probe-commands.mjs      # 单台跑完 146 条目录，列出命中与失败
node tools/lab/probe-one.mjs "SUID 可执行" ...   # 逐行看某条命令命中了什么
node tools/lab/probe-logs.mjs          # 日志源发现、auth.log 解析、IOC 关联
node tools/lab/probe-sftp.mjs          # 浏览 + plan/confirm/execute/verify 全链路
node tools/lab/probe-upload.mjs        # 上传字节到真机再清理
node tools/lab/probe-system.mjs        # 系统信息摘要与 25 个标签页、命令审计
LAB=rocky node tools/lab/probe-check-audit.mjs  # 命令审计真窗口：脚本/程序/缺失与各种日志状态，自建一次性容器
node tools/lab/probe-java-hot-update.mjs        # Java 热更新真窗口：替换、恢复、属主权限，自建一次性 JDK 容器
node tools/lab/probe-switch.mjs        # 切换目标后旧能力必须全部失效
node tools/lab/probe-markers.mjs       # 全量扫一遍，确认没有任何遮蔽 marker
node tools/lab/probe-baseline.mjs      # 基线读值：先问 sshd -T，再看扫描读到的是不是同一个
node tools/lab/probe-paths.mjs         # 输出行右键处置：属性 / 去执行位 / 隔离，逐步核对靶机
node tools/lab/probe-ui.mjs            # 起真窗口连真靶机，走完右键到执行的全过程并截图
```

单台探针用 `LAB=alpine` 之类切换（见 `lab-target.mjs`）。

**降噪改动之后一定要跑 `probe-groundtruth.mjs`**，它证明去掉的是噪声不是信号；
`probe-matrix.mjs` 只打印各发行版行为不一致的命令——一台失败其余成功是移植缺口，
一台不报其余都报是检测缺口。

`probe-one.mjs` 会用 `!!` 标出被规则命中的行，是判断误报最快的方式。

**改了输出行右键处置就跑 `probe-paths.mjs` 和 `probe-ui.mjs`**：前者走 RPC，
每一步都回到容器里 `stat` 一次，所以"验证通过"是真的改到了靶机；后者起真窗口
连真靶机，把右键、计划、确认、回执整条路走完，截图落在 `target/lab-ui/`。
两者都会先种一个 4755 的假后门，结束时删掉。

## 桌面界面探针

`probe-ui*.mjs`、`probe-case-workspace.mjs`、`probe-file-evidence.mjs`、`probe-*-baseline.mjs`、
`probe-nginx-repair.mjs` 和 `probe-postgresql-native.mjs --desktop` 驱动的是真实桌面应用
（Tauri 2 + WebView2），共用 `tools/lab/desktop.mjs`：

```bash
pnpm backend:harness   # target/debug/lovelyhawk-backend.exe：探针先用它记下连接、确认主机密钥
pnpm desktop:build     # vite build + cargo build --package lovelyhawk-desktop → target/debug/lovelyhawk.exe
node tools/lab/probe-ui.mjs
```

- 每次运行用自己的临时数据根启动调试版 `target/debug/lovelyhawk.exe`：`LOVELYHAWK_ARCHIVE_ROOT`
  指向它（应用数据在其中的 `data/`，WebView2 的数据在 `data/webview2/`），`LOVELYHAWK_DEBUG_PORT`
  只在调试版打开 127.0.0.1 上的 WebView2 远程调试。探针经 CDP 附加主窗口
  `https://tauri.localhost/`；终端和文件编辑器窗口是 `terminal.html?window=terminal|file-editor`。
- 系统文件对话框和剪贴板由两个**只在调试版生效**的变量接管：`LOVELYHAWK_TEST_DIALOG_ANSWERS`
  指向一个 JSON 数组，每弹一次对话框消费一条（绝对路径，或 `null` 表示取消）；用完后会弹出真实
  对话框等人，所以每次会弹框的点击前都要先写好应答。`LOVELYHAWK_TEST_CLIPBOARD_FILE` 接收复制的
  文本，不碰用户剪贴板。发布版不读取这两个变量；对话框之后的计划、确认、执行和复核照常走产品实现。
- 控制台错误：附加后立即启用 Runtime / Log，页面在附加前记下的错误也会补报（标为 `startup`），
  之后的为 `running`；`Log` 里的错误级条目也算。
- 关闭先点窗口自己的关闭按钮走关闭握手，超时才结束进程树，并等 WebView2 放开数据目录后再清理。
- 和以前的不同：导出的 HTML 报告不再放进隐藏窗口渲染截图（新宿主不开新窗口），改为在页面里用
  HTML 解析器做结构与活动内容检查，不再核对横向溢出；需要观察宿主调用时（PostgreSQL 桌面场景），
  记录点在页面 IPC 的 `fetch` 上，只记方法、动作、绑定句柄和响应类型。窗口最小尺寸用 CDP 的
  设备尺寸模拟固定在 1080 × 700。

想自己点着看：`pnpm desktop:dev` 构建并打开调试版，连接库就是 `pnpm lab:import` 写入的那个。

`probe-nginx-repair.mjs` 现包含 TLS 负例：只在独有容器内生成临时证书并允许旧协议，使用实际桌面应用确认修补和恢复；以 OpenSSL 指定协议、CA 与主机名校验的连接及 HTTP 响应验证前后变化。较低的密码安全级别仅为实验设置，产品操作只修改选定的协议列表。报告包含 OpenSSL 客户端版本、系统、镜像、四种协议和另一个 SNI 的观察；不计为产品已自动验证全部 TLS/业务健康。

同一 Nginx 探针现还测试产品“TLS 连接复核”：自签证书拒绝后，仅向本次隔离容器添加临时 CA；通过实际页面检查可信/错误域名、HEAD 404、IPv6、非 TLS 端口、修补/恢复及陈旧监听。服务端低安全级别与 CA 修改均为夹具准备；产品只在旧协议客户端探测中放宽本次上下文，不修改目标安全设置。结果分别记录 `tlsObservations` 与 `nativeTlsObservations`，详见 [连接复核](../../docs/NGINX_CONNECTIVITY.md)。


PostgreSQL 原生桌面探针现包含 `postgresql-role-scenario.mjs`：只在已核实 ID、镜像、资源、网络和挂载的本次容器中构造成员授权、修改测试数据库所有者、切换独立 SQL 会话并生成超限样例。产品结果沿正常页面/宿主/core 路径取得，与 `pg_has_role` 的 MEMBER/USAGE/SET 以及独立会话结果比较；覆盖多个授权者、NOINHERIT 默认值、隐式所有者、管理属性、长路径、页面焦点、权限缺口和 v4 数量摘要。夹具 SQL 走带引号 heredoc 的标准输入，避免 WSL 命令行展开；这不是产品开放 GRANT/SET ROLE 的证据。旧参数、进程、秘密标记和留证回归继续执行。
