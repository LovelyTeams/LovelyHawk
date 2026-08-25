# 靶机与实机验证工具

用 WSL 里的 Docker 起一台"被入侵"的 Linux 主机，再拿真实 sidecar 连上去跑检测，
用已知的植入物核对检出结果。自动化测试证明代码按写的方式运行；这里证明它在真实
主机上找得到东西。

## 起靶机

镜像定义在 WSL 的 `/opt/lovelyres-lab/`（`Dockerfile`、`compromise.sh`、
`entrypoint.sh`）。

```bash
wsl -d Ubuntu -u root -e bash -lc 'systemctl start docker; cd /opt/lovelyres-lab && docker build -t lovelyres-lab:compromised . && docker rm -f lab-web; docker run -d --restart unless-stopped --name lab-web -p 2222:22 lovelyres-lab:compromised'
```

登录：`root` / `LabRoot#2026`，端口 2222。WSL 的 localhost 转发会间歇性断开，
所以探针走 WSL 虚机自己的地址（`lab-target.mjs` 自动取）。

## 植入了什么

| 类别 | 植入物 |
| --- | --- |
| 权限 | `/usr/local/bin/.sysd`（SUID bash）、`/usr/local/lib/pyshared` 777、`loader.so` 666 |
| 账号 | `svcadm` UID 0、`backup2` 空口令、`/etc/sudoers.d/99-web` NOPASSWD |
| 持久化 | `/etc/cron.d/sysupdate`（curl\|sh）、`/etc/rc.local` 反弹 shell、`/etc/ld.so.preload`、`.bashrc` 后门 |
| 网络 | 4444 监听，进程名伪装成 `[kworker/1:2-events]` |
| 文件 | `/var/www/html/.well-known/upload.php` webshell、`/tmp/.X11-unix/.cache/nc` |
| 日志 | auth.log 爆破 20 次后成功登录、nginx webshell POST、syslog cron 回连 |
| 公钥 | root 的 `authorized_keys` 里一把 `attacker@kali` |

攻击者 IP 固定为 `198.51.100.7`，方便当 IOC 用。

## 第二台靶机：Alpine

`/opt/lovelyres-lab-alpine/` 里是同一套植入物的 Alpine（busybox）版本，端口 2223：

```bash
wsl -d Ubuntu -u root -e bash -lc 'cd /opt/lovelyres-lab-alpine && docker build -t lovelyres-lab:alpine . && docker rm -f lab-alpine; docker run -d --restart unless-stopped --name lab-alpine -p 2223:22 lovelyres-lab:alpine'
```

探针用 `LAB=alpine` 切换。busybox 的行为和 GNU 差别很大，这台机器专门用来撞这些差异
（`find -ls` 静默返回空就是这么发现的）。

## 探针

```bash
node tools/lab/probe-commands.mjs   # 跑完 146 条命令目录，列出所有命中与失败
node tools/lab/probe-logs.mjs       # 日志源发现、auth.log 解析、IOC 关联
node tools/lab/probe-one.mjs "SUID 可执行" ...   # 逐行看某条命令命中了什么
```

```bash
node tools/lab/probe-sftp.mjs      # 浏览 + plan/confirm/execute/verify 全链路
node tools/lab/probe-system.mjs    # 系统信息摘要与 25 个标签页、核查审计
node tools/lab/probe-switch.mjs    # 切换目标后旧能力必须全部失效
node tools/lab/probe-markers.mjs   # 全量扫一遍，确认没有任何遮蔽 marker
LAB=alpine node tools/lab/probe-commands.mjs   # 同样的命令跑 busybox 靶机
```

`probe-groundtruth.mjs` 是回归闸门：14 条植入物逐条断言仍被命中。降噪改动之后一定要跑它，
证明去掉的是噪声不是信号。

`probe-one.mjs` 会用 `!!` 标出被规则命中的行，是判断误报最快的方式。
