# 容器编排靶机

Docker 页和 Kubernetes 页在这之前**从来没有对着真的 daemon 或真的集群跑过**——
留档的验收证据全是断开连接时的那张截图。这两台靶机就是为了把那句话改掉。

```bash
pnpm lab:orchestration                          # 建并起 5 个容器，并写进连接库
pnpm lab:container-arena                        # 综合靶机：一台机器，两个页面都有数据
pnpm lab:docker                                 # Docker 只读 RPC，对着种下的东西核
pnpm lab:kubernetes                             # Kubernetes 只读 RPC
pnpm lab:podman                                 # 同一个页面，指向只有 Podman 的主机
pnpm lab:docker-terminal                        # 容器终端：真进去敲命令、看回显
node tools/lab/probe-docker-action.mjs          # 容器动作：计划→确认→执行→复核
node tools/lab/probe-kubernetes-action.mjs      # 工作负载动作：扩缩容、节点隔离
```

起完要等一到两分钟：内层 daemon 要拉镜像，集群要调度工作负载。看进度：

```bash
wsl -d Ubuntu -u root -- docker exec svc-docker cat /var/log/lab-plant.log
```

## 五个容器

| 容器 | SSH | 是什么 |
| --- | --- | --- |
| **`svc-arena`** | **2247** | **一台机器上同时有 Docker 和 k3s —— 日常调试首选这台** |
| `svc-docker` | 2244 | Ubuntu，**跑自己的 Docker daemon**（不是借靶机那台） |
| `lab-k3s` | — | 真的单节点 k3s 集群，不开放 SSH |
| `svc-kubernetes` | 2245 | Ubuntu + kubectl，指向 `lab-k3s` |
| `svc-podman` | 2246 | AlmaLinux 9 + Podman，**故意一个 `docker` 都没有** |

`svc-arena` 是真实赛场机器的样子：没人会给你一台只跑容器的机器和另一台只跑 Kubernetes 的。
单一用途那三台各自证明一件事，但它们合起来也不覆盖"两个页面看的是同一个 SSH 目标"这种情况。

口令都是 `LabRoot#2026`。

四台带 SSH 的都会进 LovelyRes 的连接库，打开应用直接点就能连；分组写的是
「实验靶机 · 容器编排」，在连接管理的搜索框里打「容器编排」就只剩这四台。
`lab-k3s` 不开 SSH，也就不在里面。WSL 重启换了地址之后跑一次 `pnpm lab:import` 刷新即可。

`svc-podman` 是这套靶机里最关键的一台。国产发行版与 RHEL 系（openEuler、Anolis、
AlmaLinux、Rocky）默认装的都是 Podman，很多机器上根本没有 `docker`——而工具原来把
运行时写死成 `docker`，在这类机器上每个问题都返回空，读起来像"这台机器没有容器"。
所以镜像用 AlmaLinux 而不是 Ubuntu，并且 Dockerfile 里有一条
`RUN test ! -e /usr/bin/docker`：真要是哪天混进来一个 docker 的软链，构建就该失败，
否则这台靶机证明的就是另一件事了。

## svc-docker 上种了什么

16 个容器，其中 9 个各自对应安全审计的一条分支——审计代码里每个 `if` 都有东西可以命中，
否则那条分支只证明它会跑，不证明它会说"有"：

| 容器 | 对应发现 |
| --- | --- |
| `legacy-agent` | `--privileged` |
| `monitor-sidecar` | `--pid=host` |
| `shm-worker` | `--ipc=host` |
| `net-tuner` | `NET_ADMIN` / `SYS_ADMIN` / `SYS_PTRACE` |
| `ci-runner` | 挂了 `/var/run/docker.sock` |
| `config-sync` | 读写挂载宿主 `/etc` |
| `edge-proxy` | `--net=host` |
| `open-admin` | 端口发布到 `0.0.0.0` |
| `drifted-tool` | `latest` 标签 |

再加一台 `app-shell`：整套靶机里唯一用 Debian 而不是 Alpine 的容器。别的全是 busybox，
根本没有 bash——只用 Alpine 建的靶机永远只能证明"没有 bash 时会退到 sh"，证明不了
"有 bash 时会挑 bash"。半条分支跑通了，读起来和整条一模一样，直到某天不是。

外加：`incident-collector`（持续写 stdout，日志面板要读得到东西）、一个叫 `incident` 的
Compose 项目（里面 `shipper` 同时是特权 + 挂 sock，审计要能穿过项目边界看见）、两个网络、两个卷。

再加两个停着的容器，给「容器动作」那条路各一种结局：

| 容器 | 为什么是它 |
| --- | --- |
| `stopped-worker` | 启动后一直跑 —— 动作的正常路径，验证应该通过 |
| `stopped-batch` | 启动后立刻退出 —— 命令返回 0 但状态没到，验证要判失败并回滚 |

第二个是关键：「命令成功了」和「主机真的到了那个状态」是两回事，而这条差别光靠单测
证明不了——单测里主机说什么都是编的。

## svc-kubernetes 上种了什么

| 工作负载 | 为什么是它 |
| --- | --- |
| `payments/ledger` (3 副本) | 健康的多副本 Deployment，扩缩容计划就是对它做的 |
| `frontend/storefront` (2 副本) | 第二个命名空间，证明分组不是全落在 default |
| `jobs/nightly-report` | 镜像故意拉不到 → `ImagePullBackOff` |
| `jobs/flapping-worker` | 起来就退 → `CrashLoopBackOff`，重启次数不为 0 |
| `frontend/access-logger` | 持续写 stdout，Pod 日志要读得到 |

一列清一色 `Running`、一列恒为 0 的重启次数，都证明不了那一列真的解析出来了。

## 建这两台时踩到的四个坑

都写进脚本注释了，这里留个索引：

1. **overlay 套 overlay**：内层 `/var/lib/docker` 落在容器自己的 overlayfs 上，
   内核直接拒绝挂载。症状很迷惑——拉镜像、建网络、建卷全都正常，只有 `docker run`
   在 mount 那一步失败。解法是给它一个真的卷。
2. **k3s 的证书里没有 `k3s` 这个名字**：客户端按容器别名连，TLS 校验不过。
   加 `--tls-san=k3s`。
3. **k3s 自己的 containerd 不看 Docker 的镜像加速**：它有独立的
   `/etc/rancher/k3s/registries.yaml`，不配的话连 pause 镜像都拉不下来，
   所有 Pod 卡在 `ContainerCreating`。
4. **叫 `kubectl` 的 k3s 二进制会优先读 `/etc/rancher/k3s/k3s.yaml`**，
   压过 `~/.kube/config`。而那份配置里服务器写的是 `127.0.0.1`，在客户端这边连不通。
   所以集群的 kubeconfig 挂在 `/mnt/k3s`，客户端自己抄一份改好放进 `~/.kube/config`。

## 这轮查出来的真问题

**一、Pod 的地址列一直是空的。** `crates/lovelyres-core/src/kubernetes.rs` 的 `RawPodStatus`
用 `rename_all = "camelCase"` 把 `pod_ip` 变成 `podIp`，而 Kubernetes 发出来的是 `podIP`——
两个字母都大写。字段永远匹配不上，从这个页面存在起，任何真实集群上那一列都是空的。

原来的解析测试 fixture 里其实写了 `"podIP"`，但只断言了行数和 id，没有断言这个值，
所以一直没抓到。现在补了 `a_populated_pod_row_carries_every_column_it_was_given`，
逐列断言；把 `rename` 去掉那条测试就红。

**二、容器动作在真 Docker 上从来没能通过状态探测。** `probe_state` 的
`docker inspect --format '{{.Id}}\t{{.State.Status}}'` 里写的是裸 `\t`，而这串格式串交给的是
Go 模板——它把没加引号的 `\t` 原样打成反斜杠加 `t` 两个字符。解析器按真 tab 切分，于是
每个存在的容器都返回「状态记录无效」，任何动作连计划都建不出来。正确写法是
`{{"\t"}}`，Go 会把引号里的转义真的解释掉。

同样地，所有围绕它的单测都是直接喂给解析器一个已经带真 tab 的字符串，所以一个都没发现。
现在 `the_state_probe_asks_for_a_separator_the_runtime_will_really_print` 同时钉住格式串的写法
和「运行时真打出来的那种字符串解析要失败」。

**三、Kubernetes 的补丁做成了却报没做成。** `kubectl patch` 后面没有 `-o json`，
kubectl 于是打印一行 `deployment.apps/ledger patched`，而调用方要把这段输出解析回一个
快照来核对是否到了目标状态。解析失败 → 整个流程返回错误——**但补丁已经生效了**。
把"做成了"报成"没做成"，比报错更糟：操作员会照着错误信息再做一次。

**四、整个 Docker 页在只有 Podman 的机器上什么都读不到。** 后端把
`ContainerRuntime::Docker` 写死在六处，核心声明支持 Podman 却从来没人选它。改成开
快照时探测一次、之后每一次调用都用探到的那个，并且把 "没装" 与 "装了但不响应" 分成
两个不同的答复——前者让操作员别再找了，后者让他去把服务起起来。

**五、Podman 的输出形状与 Docker 不一样，解析器全是 Docker 形状的。** 对着真机逐项发现：

| 字段 | Docker | Podman |
| --- | --- | --- |
| 容器 id | `ID` | `Id` |
| 名称 | `Names` 字符串 | `Names` 数组 |
| 状态文本 | `Status` 有值 | `Status` 空，值在 `State` |
| 创建时间 | `CreatedAt` | `CreatedAt` 空，值在 `Created` |
| 端口 | 已渲染的字符串 | 结构化数组或 null |
| 命令 | 字符串 | 数组 |
| 网络清单 | `Name`/`ID`/`Internal` | `name`/`id`/`internal`（全小写下划线） |

**六、运行时自己的告警会把整份输出弄废。** SSH 层把 stderr 并进 stdout，而 Podman 在
cgroups-v1 主机上每条命令都先打一句弃用告警。逐行 JSON 的解析器、整体 JSON 数组的
解析器、以及 `id<TAB>状态` 的状态探测，三处都因为多了这一行而全盘失败。

规则定成：**不以 `{` 开头的行不是数据，跳过；以 `{` 开头却解析不了的行是被截断的数据，
仍然报错。** 后者要是也跳过，一份被截断的清单就会悄悄变短——那才是真正危险的。

## 接容器终端时查出来的三个问题

**一、终端开得起来，但第一次读就废。** 核心的 `open_terminal` 自己造了个
`container-<uuid>` 当终端 id，而调用方（`terminal_api`）是拿自己登记的那个 id 去核对
每一条事件的。两边各自的单测都过，因为两边各自都是对的——只有真开一个 shell、
真敲一个字符，才会看到第一次 `terminal.poll` 直接报协议违规、窗口当场变死。
现在 id 由调用方给，核心不再自己造；`container_terminal_answers_to_the_id_its_caller_gave_it`
钉住这件事。

**二、停着的容器被说成"这个镜像里没有 shell"。** 探 shell 的办法是往容器里 exec 一句
`command -v`，而对一个停着的容器 exec 什么都不会输出——和"镜像里真没有 shell"长得
一模一样。于是操作员会被打发去重建镜像，实际上只要把容器启动起来。现在探 shell 之前
先读状态，两种情况分成 `docker-container-not-running` 与 `docker-container-shell-missing`
两个答复。

**三、靶机里一个带 bash 的容器都没有。** 十六个容器全是 alpine，所以"优先挑 bash"
这条分支在真机上从来没被走过——第一次跑探针时它在 nginx 名字的容器上挑了 ash，
我以为是 bug，其实那台本来就是 alpine。加了 `app-shell`（Debian）之后才真的覆盖到。

## 建综合靶机踩到的四个坑

一台机器上同时跑 dockerd 和 k3s，比想象的难：

1. **k3s 的 containerd 也是 overlay 套 overlay**：跟 Docker 那台一样的病，
   `/var/lib/rancher` 也得给真卷，否则 API server 起得来、节点永远注册不上。
2. **纯 Ubuntu 没有 CNI 插件**：官方 k3s 镜像的 `/bin` 里带着，普通发行版没有。
   而且它们**不是一个**——`bandwidth bridge firewall flannel host-local loopback portmap`
   七个名字全是同一个 `cni` 二进制的软链。我一个一个猜着补，返工了三次：
   补完 host-local 才暴露缺 flannel，补完 flannel 才暴露缺 bandwidth。缺插件不会响亮地失败，
   kubelet 注册正常、API 应答正常，只是每个 Pod 永远停在 `ContainerCreating`。
   正确做法是把镜像里所有指向 `cni` 的软链一次列全。
3. **`--tmpfs /run` 把 sshd 的目录冲掉了**：k3s 需要这个 tmpfs，而它盖在镜像建好的
   `/run/sshd` 上面，sshd 直接以 "Missing privilege separation directory" 退出。
   目录要在 entrypoint 里建，不是在 Dockerfile 里。
4. **看门狗用 `kill -0` 判活，对僵尸进程恒为真**：上面那个 sshd 死成僵尸之后，
   看门狗在旁边守了九分钟一次都没重启它，容器 `Up`、端口 published、连接全部拒绝。
   改成 `pgrep -x sshd`，四台靶机的 entrypoint 都同样修了。
