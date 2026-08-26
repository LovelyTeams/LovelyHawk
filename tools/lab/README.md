# 靶机与实机验证工具

用 WSL 里的 Docker 起两批靶机，再拿真实 sidecar 连上去跑检测，用已知的问题核对
检出结果。自动化测试证明代码按写的方式运行；这里证明它在真实主机上找得到东西。

**两批靶机解决的是不同的问题：**

| 批次 | 端口 | 是什么 | 用来验 |
|------|------|--------|--------|
| 被入侵主机（9 台） | 2222–2230 | 九种发行版，各种下 30 项植入物 | 命令工作台、日志分析、文件处置、跨发行版适配 |
| 配置不合规主机（12 台） | 2231–2242 | 每台一个真实产品，配置留成没加固的样子 | 配置核查、中间件发现、数据库巡检、安全基线 |

第二批见 [`services/README.md`](services/README.md)。下面讲第一批。

登录一律 `root` / `LabRoot#2026`。WSL 的 localhost 转发会间歇性断开，所以探针走 WSL
虚机自己的地址（`lab-target.mjs` 自动取）。容器 PID 1 是 `sleep infinity` 加 sshd
看门狗，否则 sshd 一退出整台靶机就没了。

## 一键起环境

```bash
pnpm lab:up
```

一条命令：检查 WSL 里的 docker、同步靶机定义、把九台都拉起来，再把它们连同口令写进
LovelyRes 的连接库。打开应用就能在连接管理里直接点，不用输任何东西。

WSL 重启后虚机会换地址，再跑一次 `pnpm lab:up` 就把九条连接的地址都刷新了（原地更新，
不会产生重复条目）。

| 命令 | 作用 |
| --- | --- |
| `pnpm lab:up` | 起容器 + 写连接库 |
| `pnpm lab:up -- -Rebuild` | 改过 `tools/lab/matrix/` 里的脚本后重建镜像 |
| `pnpm lab:up -- -SkipImport` | 只起容器，不动连接库 |
| `pnpm lab:import` | 只刷新连接库（换地址后最常用） |
| `pnpm lab:remove` | 把九条实验靶机连接从库里删掉 |
| `pnpm lab:down` | 停掉容器，连接条目保留 |

连接名统一是「实验靶机 xxx」、分组「实验靶机」、标签 `lab`，和真实目标一眼可分。
写入的是应用自己的连接库（开发模式下在 `D:\LovelyRes\data`）；要写到别处就设
`LOVELYRES_ARCHIVE_ROOT`。**应用运行时不要跑导入**，两个 sidecar 同时写同一个库会打架。

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
node tools/lab/probe-system.mjs        # 系统信息摘要与 25 个标签页、核查审计
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
