# 配置不合规靶机

十二台可 SSH 登录的主机，每台跑一个真实产品，配置故意留成典型的"没人加固过"的样子。
跟 `tools/lab/matrix` 那九台不一样：那九台是**被入侵**的现场，这十二台是**配置本身有问题**，
用来验配置生成、中间件发现、数据库巡检和安全基线。

镜像用产品官方镜像做基底，只加一个 sshd。这样每个配置文件都在产品真正放它的位置——
LovelyRes 得在 `/etc/nginx/nginx.conf` 找到 nginx，而不是在实验室自己定的路径。

## 起来

```bash
node tools/lab/services/pull.sh   # 只需第一次；见下面"镜像从哪来"
pnpm lab:services                 # 构建并启动全部十二台
pnpm lab:import                   # 写进连接库，打开程序就能看到
```

`build.sh` 可以反复跑：镜像有缓存，容器会重建，某一台失败不影响其余，最后会列出哪些起来了。

口令统一是 `LabRoot#2026`，用户 `root`。

## 有哪些

| 端口 | 名字 | 产品 | 主要留了什么问题 |
|------|------|------|------------------|
| 2231 | svc-nginx | Nginx 1.27 | 版本号外露、目录列表打开、SSLv3/TLS1.0、上传无上限、`/nginx_status` 与 `/.git` 可直接访问 |
| 2232 | svc-httpd | Apache 2.4 | `ServerTokens Full`、`TraceEnable On`、`Options Indexes ExecCGI`、server-status 不限来源 |
| 2233 | svc-tomcat | Tomcat 10.1 | manager 应用可达且口令是 `tomcat`/`admin123`、去掉地址过滤、autoDeploy 打开 |
| 2234 | svc-mysql | MySQL 8.0 | 监听 0.0.0.0、`local_infile=ON`、`secure_file_priv` 为空、日志全关、不加密、空口令账号 |
| 2235 | svc-mariadb | MariaDB 11 | 同上，写在 MariaDB 实际读取的位置 |
| 2236 | svc-postgres | PostgreSQL 16 | `listen_addresses='*'`、pg_hba 全 `trust`、不记连接与语句、md5 口令、`fsync=off` |
| 2237 | svc-redis | Redis 7 | 无口令、`bind 0.0.0.0`、`protected-mode no`、危险命令未改名 |
| 2238 | svc-mongo | MongoDB 7 | `authorization: disabled`、监听 0.0.0.0、TLS 关闭、无审计 |
| 2239 | svc-opengauss | openGauss 5.0 | 同 PostgreSQL 那套，加上审计关闭、登录失败不锁定 |
| 2240 | svc-tidb | TiDB 7.5 | 集群与客户端 TLS 全空、`skip-grant-table`、status 端口不限来源 |
| 2241 | svc-baseline-deb | Debian 12 | 不装中间件，只把六个基线文件改成不合规 |
| 2242 | svc-baseline-el | AlmaLinux 9 | 同上，RPM 系 |

达梦和人大金仓没有可公开拉取的镜像，所以不在这里；配置生成那边的 schema 仍然覆盖它们。

## 两台纯基线主机为什么值得单独存在

`misconfigure/baseline.sh` 把 sshd_config、login.defs、faillock.conf、pwquality.conf、
auditd.conf 和 sysctl 全写成不合规的样子，其中两处是刻意的形状：

```
PermitRootLogin yes
#PermitRootLogin prohibit-password
```

生效的是上面那条，下面那条是发行版自带的注释默认值。**把注释当成设置读的扫描会报"合规"，
而这台机器正放着 root 进来。** 基线扫描曾经就是这么错的，这两台是那个错误的常驻回归。
`tools/lab/probe-baseline.mjs` 拿 `sshd -T` 的答案跟扫描结果对，不一致就失败。

## 镜像从哪来

这台机器上 Docker Hub 连不通，但发行版源和 daocloud 镜像站通。`pull.sh` 因此按
`docker.m.daocloud.io/library/nginx:1.27` 这样的全名拉，再 `docker tag` 成短名给 Dockerfile 用。
**不改 docker 守护进程的配置**——镜像站只是镜像名的一部分。

换别的镜像站：`LAB_MIRROR=xxx bash pull.sh`。Hub 能直连的话把它设成 `docker.io`。

## 验一遍

```bash
node tools/lab/verify-services.mjs
```

每台检查四件事：容器在跑、sshd 在跑、故意留的那行配置确实在文件里、LovelyRes 自己的
sidecar 连得上。四项全过才算就绪。

## WSL 重启之后

WSL 虚机一重启，所有容器都会以 exit 255 停掉，虚机地址也换了，连接库里那 21 条就指向
不存在的地址。

```bash
pnpm lab:restart
```

把已有容器原样启回来（不重建），再把新地址刷进连接库。**exit 255 是虚机下线，不是容器出问题**，
不用去查日志。

## 停掉和清理

```bash
wsl -d Ubuntu -u root -e bash -lc 'docker stop $(docker ps -q --filter name=svc-)'
wsl -d Ubuntu -u root -e bash -lc 'docker rm -f $(docker ps -aq --filter name=svc-)'
pnpm lab:remove   # 从连接库里去掉
```
