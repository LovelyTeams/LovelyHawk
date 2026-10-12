# 超级靶机（一台把每个页面都点亮）

一台 Ubuntu 22.04，把综合靶机（`lab-arena`）的所有问题都搬过来，再加码一层。目标是
**一台 SSH 主机就能喂饱 LovelyHawk 的每一个页面**：主机全景、六个系统基线、中间件与数据库
基线、命令审计、文件完整性、日志分析、网络抓包、账号与持久化。

端口 **2251**，`root` / `LabRoot#2026`。

```bash
# 构建并启动（第一次要装一批服务，几分钟）
wsl -d Ubuntu -u root -e sh /mnt/d/LovelyRes/tools/lab/super/up.sh
REBUILD=1 wsl -d Ubuntu -u root -e sh /mnt/d/LovelyRes/tools/lab/super/up.sh   # 重建镜像

# 把它写进软件的连接库（和其它靶机一起）
node tools/lab/import-labs.mjs
```

它复用 `arena/misconfigure.sh` 原样不动，再叠一层 `misconfigure-super.sh`。每一项都是日常
能见到的错配，或"有人先来过"的痕迹；所有外连地址都指向 TEST-NET（198.51.100.0/24，不可路由），
机器实际上连不出去，也没有开真正可用的后门。

## 在 arena 的基础上多了什么

| 方向 | 新增的问题 |
|------|-----------|
| Web（第二个） | apache 监听 :8080，版本号与签名外露、全站目录列表、`/server-status` 开放、世界可读的 `.htpasswd` |
| FTP | vsftpd 匿名登录、匿名可写、不 chroot、不加密、不记传输日志（:21） |
| 账号 | `deploy`（弱口令，进 sudo 组）、`guest`（空口令）、`monitor`（uid 480 的服务账号却给了交互 shell） |
| sudo | `deploy` 可免密以 root 跑 vim / awk / find（都能直接提权拿 shell） |
| 文件 capability | `/usr/local/bin/.netcheck` 带 `cap_setuid+ep`（包管理器之外设的权限边界） |
| SUID / PATH | `/usr/local/bin/.awk`（SUID）；`/usr/local/bin` 整个目录世界可写，还躺着一个世界可写脚本 |
| 计划任务 | `/etc/crontab` 与 `/etc/cron.d` 世界可写、多一个 `cron.hourly` 钩子、一个开机 `at` 任务 |
| 明文口令 | `/opt/app/.env`（DB 口令、API token、AWS key）、世界可读的 `/root/.my.cnf` 与 `/root/.pgpass`、`/etc/environment` 里的 token |
| Web 上传 | 世界可写的上传目录里放了一个 `.php`（本不该在那） |
| 日志 | `auth.log` 指向 `/dev/null`、`syslog` / `wtmp` / `btmp` / `lastlog` 被清空 |
| 进程 / 端口 | 一个从 `/tmp` 跑、伪装成内核线程名 `[kworker/1:0]` 的闲置进程；:8081 上一个只回 banner 的监听器（不是 shell） |
| 持久化 | `/usr/local/lib/pyshared/.cache.bin`：一个加了不可变位（`chattr +i`）、删不掉的投放物副本 |

arena 原有的：错到底的 sshd / nginx / MariaDB / Redis / PostgreSQL 配置、六个基线文件、
`operator`/`backupsvc` 账号、SUID 后门、cron/rc.local/init.d/profile.d/ld.so.preload 等多路
持久化、`authorized_keys` 里不是你的公钥、被 `history -c` 清过的历史——全部照旧。

## 停掉 / 重建

```bash
wsl -d Ubuntu -u root -e sh -c 'docker rm -f lab-super'
REBUILD=1 wsl -d Ubuntu -u root -e sh /mnt/d/LovelyRes/tools/lab/super/up.sh
```
