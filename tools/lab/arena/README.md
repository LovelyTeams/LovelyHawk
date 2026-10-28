# 综合靶机（一台就够）

一台 Ubuntu 22.04，上面同时跑 nginx、MariaDB、Redis、PostgreSQL，六个基线文件全是错的，
再加上几处"有人先来过"的痕迹。**这是日常调试首选的那一台**——一台机器覆盖到基线、中间件、
数据库、命令工作台，而不是开 21 个容器各管一摊。

```bash
pnpm lab:arena          # 构建、启动，并写进连接库
pnpm lab:verify-import  # 核对连接库里 22 台一台不少
```

端口 2250，`root` / `LabRoot#2026`。

## 为什么会有这台

之前的靶机"好容易断"。查下来**不是容器的问题**：WSL 2 在最后一个 shell 退出后会把整个
虚机关掉（`vmIdleTimeout` 默认约 60 秒），里面的容器一起没。程序那边看到的就是
`Channel send error`，而且当时每个功能各报各的错。

两件事一起做掉了：

1. 写了 `%USERPROFILE%\.wslconfig`，把 `vmIdleTimeout` 设成 `-1`，虚机不再自己关机。
   **要 `wsl --shutdown` 一次才生效。** 不想要就删掉这个文件。
2. 所有靶机容器加了 `--restart unless-stopped`，虚机万一还是重启，Docker 起来它们自己回来。

减少活动部件是第三件：一台比十二台好养。

## 这台机器上有什么

| 服务 | 端口 | 留的问题 |
|------|------|----------|
| sshd | 22 | 放行 root、允许空口令、`MaxAuthTries 10`、关掉 PAM 和公钥认证 |
| nginx | 80 | 版本号外露、全站目录列表、SSLv3/TLS1.0、上传无上限、`/nginx_status` 和 `/.git` 直接可访问 |
| MariaDB | 3306 | 监听 0.0.0.0、`local_infile=1`、`secure_file_priv` 为空、日志全关、不加密 |
| Redis | 6379 | 无口令、`bind 0.0.0.0`、`protected-mode no` |
| PostgreSQL | 5432 | `listen_addresses='*'`、pg_hba 全 `trust`、不记连接与语句、md5 口令、`fsync=off` |

基线那六个文件（sshd_config、login.defs、faillock.conf、pwquality.conf、auditd.conf、
sysctl.d）全写成不合规，其中 sshd_config 里刻意留了这个形状：

```
PermitRootLogin yes
#PermitRootLogin prohibit-password
```

生效的是上面那条。**把注释当设置读的扫描会报"合规"，而这台机器正放着 root 进来。**
这是基线扫描曾经犯过的错，这台机器是它的常驻回归。

账号方面：`operator`/`123456` 且口令永不过期、`NOPASSWD:ALL` 的 sudo，外加一个 uid 为 0 的
`backupsvc`——换了个名字的 root。

## 有人先来过的痕迹

- `/usr/local/lib/pyshared/.helper`、`/usr/local/bin/.sysd`：4755 的 SUID 后门
- `/etc/cron.d/sysupdate`、`/etc/cron.daily/logrotate-helper`：定时拉起
- `/etc/profile` 末尾追加的外连（连不通的地址，带 2 秒超时，不会拖慢登录）
- `/root/.ssh/authorized_keys` 里一把不是你的公钥
- `/root/.bash_history` 记着干了什么，然后 `history -c`；`operator` 的历史被清空

## 停掉

```bash
wsl -d Ubuntu -u root -e bash -lc 'docker rm -f lab-arena'
```

重建加 `REBUILD=1`。
