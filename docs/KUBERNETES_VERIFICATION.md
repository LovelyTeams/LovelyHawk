# Kubernetes 操作验证与恢复

2026-09-07：在 Linux amd64、k3s v1.31.4+k3s1 单节点实验环境验证。实现位于 `crates/lovelyhawk-core/src/kubernetes.rs`；本文不表示其他集群版本、CRI、CNI、存储或业务应用已通过验收。

## 扩缩容完成条件

确认提交的仍是用户审阅的不可变计划；执行前核对对象 UID、resourceVersion 和原副本数，写入使用比较并交换的 JSON Patch。写入成功后独立读取同一对象，最多等待 45 秒：

- 期望副本数等于计划中的值，UID 和配置 generation 仍对应本次写入。
- 控制器已经处理本次配置，`status.observedGeneration` 不落后于 `metadata.generation`。
- 当前、已更新、就绪、可用副本数都等于期望值；不能只核对 `spec.replicas` 或 Ready 数量。
- 已知的进展超时或副本创建失败报告为未达到预期；缺少版本或副本信息、读取失败和超时不能算成功。

就绪条件参考 [Kubernetes Deployment 状态定义](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#complete-deployment) 与 [kubectl v1.31.4 的状态判断](https://github.com/kubernetes/kubectl/blob/v0.31.4/pkg/polymorphichelpers/rollout_status.go#L68)。LovelyHawk 对本次扩缩容进一步核对精确目标数与对象身份，并明确提示：副本可用不等于业务接口已经恢复。

缩到 0 是特殊的运维/应急意图：读取到控制器已处理配置且相关计数为 0 后报告结果，但不称应用可用，也不承诺终止中的 Pod 已完全退出。旧 rollout 故障不应触发重新启动副本；验证超时或失败时也不会自动恢复成非零值。这是 LovelyHawk 的处置策略，用户在确认计划前能看到说明。

## 恢复与并发保护

非零扩缩容验证失败后，尝试恢复操作前的副本数，并独立回读。恢复配置成功与业务健康分别表述；读取验证失败但配置恢复成功时，也会如实返回恢复结果。

Deployment 控制器更新 status 会改变 resourceVersion，因此不能仅因状态刷新而拒绝所有恢复。v2 回执同时保存 UID、写入版本和 generation：配置 generation 未变化时，可使用最新 resourceVersion 执行受保护的恢复 Patch；配置、模板或 annotations 再次变化时拒绝覆盖。[Kubernetes v1.31.4 的 Deployment 更新策略](https://github.com/kubernetes/kubernetes/blob/v1.31.4/pkg/registry/apps/deployment/strategy.go#L101) 是该区分的依据。

Node 和旧 v1 回执继续要求完全相同的 resourceVersion。节点动作只修改调度标记，不迁移已有 Pod、不实施网络隔离；界面使用“已暂停调度”。恢复被并发变更、连接或权限等原因阻止时，回执显示未恢复，保留原验证结果并引导刷新检查。

45 秒就绪期限包含在计划正文；后端总执行期限为 180 秒，桌面页面桥接层（`ui/src/host/backend-client.ts`）等待期限为 210 秒，为回读和可能的恢复留出时间。失败计划不能重新执行，必须从当前状态重新规划和确认。

## 实验与证据

探针先核对实验客户端/服务端的镜像、容器 ID、挂载和唯一节点身份，再创建带本次标签的独立命名空间。样例使用缓存 Alpine 镜像、有限 CPU/内存与无害的成功/失败 readinessProbe。结束时核对命名空间 UID 和本次标签，只删除自己的资源。

```powershell
# 正常、故障、并发变更与停止工作负载的真实 RPC 验证
node tools/lab/probe-kubernetes-health.mjs
# 加上真实桌面界面的失败提示、恢复说明、取消和断连检查
$env:HEALTH_UI = '1'
node tools/lab/probe-kubernetes-health.mjs
# 仅复查桌面故障恢复界面
$env:HEALTH_UI_ONLY = '1'
node tools/lab/probe-kubernetes-health.mjs
```

下表为 2026-09-07 Electron 时期的记录，界面结果不能直接当作 Tauri 桌面壳的验收。

| 验证 | 结果与证据 |
| --- | --- |
| 核心回归 | Kubernetes 21 项通过，包含等待新状态、状态更新后恢复、配置变更拒绝恢复、读取失败与停止后不重启；core 全量 1038 通过、7 个实机测试忽略 |
| 真实就绪与恢复 | `target/lab-kubernetes-health/982eb826-5159-486c-b770-b75b9e25dc58/report.json`；正常扩容、未就绪超时恢复、并发配置保护、缩到 0，以及 Electron 子探针通过 |
| 最终 Electron 故障恢复 UI | `target/lab-ui/orchestration-kubernetes-6b0adcf0-6655-42c1-89de-a8362126a422/report.json`；包含 0 副本的明确状态，截图已经检查 |
| Electron 正常扩缩容 UI | `target/lab-ui/orchestration-kubernetes-b0613c3c-a3f0-4c42-b810-54df7b25a7c4/report.json` |
| 原有动作与拒绝回归 | `target/goal-20260907/orchestration/kubernetes-actions-with-health.log`；扩缩容、节点暂停/恢复调度、取消、重放和伪造对象拒绝 |

### Tauri 桌面壳重新验收（2026-10-11）

同一 k3s v1.31.4 单节点实验环境（启动前核对了 `lab-k3s`、`svc-kubernetes` 的镜像、共享的 `lab-k3s-config` 卷和实验 registry 挂载），在 Tauri 桌面壳下重跑：

| 验证 | 结果 |
| --- | --- |
| 只读 RPC（`probe-kubernetes.mjs`） | 24/24 |
| 动作（`probe-kubernetes-action.mjs`） | 30/30，结束时集群复原 |
| 就绪与恢复，含桌面界面（`HEALTH_UI=1 probe-kubernetes-health.mjs`） | 35/35；`target/lab-kubernetes-health/5f60d68c-9398-4379-a24b-5ce3a6111e26/report.json`（mode `rpc-and-ui`） |
| 桌面界面正常扩缩容（`LAB=kubernetes probe-ui-orchestration.mjs`） | 10/10，无控制台错误 |

结束后 `payments/ledger` 为 3 副本、节点可调度、本次的 `lr-health-*` 命名空间已删除。上表 Electron 时期的界面记录由此被 Tauri 证据取代；下方“尚未完成的范围”不变。

### Pod 终端、文件与上次日志（2026-10-11）

这三项都是只读或交互入口，不改动集群对象，因此不走扩缩容那样的计划与确认；它们共同的约束是“只对列表里那个 Pod 动手”：

- 每次打开终端、列目录、读文件之前，core 都重新读取 Pod 的 UID、阶段和删除时间；UID 变了（同名重建）、正在删除或不在 `Running` 一律拒绝，页面提示刷新列表。
- 终端用 `kubectl exec -it` 进默认容器，shell 带会话标记；关闭窗口或断开连接后，按标记结束它启动的进程。
- 文件只读：读取前后各核对一次长度和 SHA-256，符号链接、目录、设备和超过 1 MiB 的文件拒绝；改动应回到部署清单。
- 上次日志是 `kubectl logs --previous`；kubelet 暂时交不出日志时会以 0 退出并输出一句固定的报错，core 认出这一句并报告“稍后再读”，不把它当成 Pod 输出。

| 验证 | 结果 |
| --- | --- |
| 只读 RPC，含上次日志（`pnpm lab:kubernetes`） | 通过；`flapping-worker` 上一次运行留下的原因被读到，从没重启过的 Pod 读上次日志明确失败 |
| Pod 终端 RPC（`pnpm lab:kubernetes-terminal`） | 通过；shell 的主机名就是 Pod 名，关闭后后台 `sleep` 从外部看已结束；Pending、无 shell 的 coredns、列表后被重建的 Pod、伪造句柄各自被拒绝 |
| Pod 目录与文件 RPC（`pnpm lab:container-files` 的 Kubernetes 部分） | 通过；`/etc/hostname` 内容与摘要一致，目录、符号链接、缺失文件、无 shell 镜像、未运行 Pod 各自被拒绝 |
| 桌面界面（`pnpm lab:ui-kubernetes-tools`） | 13/13；行操作、上次日志、文件浏览与读取、Pod 终端窗口与断开后清理，无控制台错误 |

为让“上次日志”有可核对的内容，实验种子里的 `jobs/flapping-worker` 改为退出前先输出一行带 `lab-marker` 的原因（`tools/lab/orchestration/*/plant*.sh`）；已运行的实验集群只替换了这一个 Pod。

### 多容器 Pod：按容器读日志、开终端、看文件（2026-10-12）

一个 Pod 有几个容器时，行操作旁多出“容器”选择，日志、上次日志、终端和文件都对所选容器；没有选择时用 Pod 的默认容器（`kubectl.kubernetes.io/default-container` 注解指定的那个，注解没有指向本 Pod 的容器时取第一个），单容器 Pod 不显示选择、不点名，由 kubectl 自己选：

- 列表随 Pod 一起读出各容器的名称、镜像、是否就绪、是否在运行和重启次数（只取应用容器，不含 init 与临时容器）。
- 请求只能点名列表里这个 Pod 的容器；名称先按 DNS 标签校验，再与快照里的容器名比对，不符的连 `kubectl` 都不调用。
- 开终端、列目录、读文件前的重读除 UID、阶段和删除时间外，还核对所选容器此刻在运行；重启中或已退出的容器拒绝，页面在按钮上说明原因，日志仍可读。
- 终端、文件和关闭时的清理都带同一个 `-c <容器>`：清理只在 shell 所在的容器里找它启动的进程；同一 Pod 的不同容器各开一个窗口，窗口标题写明容器。
- 读日志的结果标题写明来自哪个容器。

| 验证 | 结果 |
| --- | --- |
| 多容器 RPC（`pnpm lab:kubernetes-containers`） | 通过；本次自建命名空间里的三容器 Pod（app、sidecar、反复退出的 crasher，注解默认 sidecar）：列表顺序与默认容器正确，crasher 标为未运行；app 与 sidecar 的日志、/tmp 标记文件各是各的，不点名读到的是 sidecar；crasher 自己的日志可读，上次运行的日志在 kubelet 交出后可读（期间“暂时交不出”与 kubectl 直接读的结果一致）；在 app 里开的 shell 只在 app 里留下后台进程，关闭后它结束，sidecar 里从未出现；未运行、不存在、写法不对的容器名都被拒绝；命名空间按本次标记删除 |
| 桌面界面（`pnpm lab:ui-kubernetes-containers`） | 9/9，无控制台错误；选择框按顺序列出容器、默认选中 sidecar、标出未运行；日志标题写明容器且内容是该容器的；选中 crasher 时终端和文件不可用并说明原因、日志仍可读；文件对话框与 Pod 终端窗口都在所选容器 app 里，标题写明容器 |
| 回归 | `pnpm lab:kubernetes`、`pnpm lab:kubernetes-terminal`、`pnpm lab:container-files` 仍全部通过 |

### 只能看一个命名空间的账号（2026-10-12）

比赛环境和跳板机常发这种 kubeconfig：一个服务账号，只在一个命名空间里有只读 Role。以前这种账号在页面上什么都看不到：命名空间列不出来，“全部”又被拒绝，错误只说“读取没有完成”。现在：

- 集群以 `Error from server (Forbidden)` 拒绝时（kubectl 失败且最后一行是这句），core 报告“权限不足”，后端返回 `kubernetes-forbidden`，页面说是哪一页被拒绝、可以怎么办，不显示成空列表，统计卡显示“—”而不是 0。只看最后一行，日志正文里碰巧有同样的话不算；集群原话里的用户名和资源不回传页面。
- 可用性检查一并读出 kubeconfig 当前上下文的命名空间（上下文没写就是 kubectl 默认的 `default`，不是命名空间名的值丢弃）。命名空间列表被拒、且上下文给了命名空间时，页面加一个“当前上下文 · 名称”的范围并默认选中，按它读取 Pod 与 Deployment；页面只发 `{ context: true }`，不传命名空间名，kubectl 不加 `-n` 按上下文读取，每行仍显示集群给出的命名空间。
- 列目录和读文件会丢掉 kubectl 的 stderr（它的提示会弄乱记录），拒绝原因也跟着丢了。失败之后再用 `kubectl auth can-i create pods/<名称> --subresource=exec` 问一次 API server：明确回答 no 才报“没有 pods/exec 权限”，其他回答保留原来的失败，不猜。终端探测本来就保留 kubectl 的原话。终端窗口、文件对话框都显示这条原因。
- 扩缩容计划只读，受限账号也能生成；执行时集群拒绝修改，回执写“集群拒绝了这次修改：当前账号没有这个权限，资源没有被改动”。RBAC 判定在写入之前，所以只有这种失败能这样说。计划阶段的读取被拒同样报 `kubernetes-forbidden`。

| 验证 | 结果 |
| --- | --- |
| RPC（`pnpm lab:kubernetes-rbac`） | 21 项全部通过。本次建立命名空间、只读 Role 的服务账号和 svc-kubernetes 上的登录账号（`kubectl auth can-i` 独立核对：exec no、列命名空间 no、本命名空间列 Pod yes、全部命名空间 no）。命名空间、全部命名空间的 Pod、节点三处被拒且报权限；上下文命名空间读出 Pod、Deployment 与日志；终端、列目录、读文件都报缺 pods/exec；扩缩容 1 → 2 被拒、回执如上、集群里仍是 1 副本。结束后命名空间与登录账号按本次标记删除 |
| 桌面界面（`pnpm lab:ui-kubernetes-rbac`） | 10/10，无控制台错误；“当前上下文”范围默认选中且说明原因；选“全部”显示被拒与改选建议，表格不显示“没有 Pods”；命名空间页说明不能列出；文件对话框与终端窗口说明缺 pods/exec。截图在 `target/desktop-debug/kubernetes-rbac-*/evidence` |
| 回归 | core、后端 Kubernetes 单元测试，页面、状态、契约与终端提示测试 |

### Pod 文件留证（2026-10-12）

Pod 文件对话框里每个普通文件都有“留证”：原始字节经 SSH 主机 `/tmp` 的临时副本复制回本机所选文件夹，存成 `pod-file.bin`，清单 `pod` 一节写明 Pod、UID、容器与路径，并登记到开始时的案件。方法、校验与限制见 [应急文件下载留证](FILE_EVIDENCE_COLLECTION.md#pod-文件留证)。

| 验证 | 结果 |
| --- | --- |
| RPC（`pnpm lab:kubernetes-pod-evidence`） | 30 项全部通过。本次命名空间里的双容器 Pod：3 MiB 随机文件的本地字节、页面摘要、清单和案件记录都等于 kubectl 在容器里独立算出的 SHA-256，清单写明 Pod、UID 与路径，主机上不留副本；选 sidecar 时从 sidecar 复制；符号链接、缺失、正在写入、600 MB 稀疏文件各自拒绝且主机不留东西；不属于这个 Pod 的容器不开始；450 MiB 复制途中取消，带标记的 kubectl 结束、主机文件删除、目录里没有清单 |
| 桌面界面（`pnpm lab:ui-kubernetes-pod-evidence`） | 10/10，无控制台错误；文件行的“留证”、面板跟到“已保存为证据”且摘要等于容器里的、所选文件夹里的字节一致、主机副本已删除、关掉目录选择器什么都不开始、案件工作台列出这条证据 |

这一轮第一遍跑探针时有四项失败，原因在实验环境：WSL 保活进程到期，Docker 重启了靶机（所有 Pod 在 95 分钟前重启过，`payments/ledger` 带着一次重启，与工具探针的前提不符），同时有库测试在编译。重新保活、对 `payments/ledger` 做一次 rollout restart、不再并行编译后，用同一批二进制重跑全部通过；Pod 留证探针的取消步骤改为先在主机上开始观察再发起复制，复制先完成时换新任务重试（这次第一次就落在复制途中）。

### 导出 YAML 清单（2026-10-12）

Pod、Deployment、Node 的详情里有“导出 YAML…”：在 SSH 主机上执行 `kubectl get <类型> <名称> [-n <命名空间>] -o yaml`，把集群返回的原文写进本机保存对话框选的新文件，只读，不改动集群。

- 对象只按列表的句柄指定，页面不传类型、命名空间或名称；文件内容由后端直接交给宿主写入，不经过页面。
- 清单里的类型、名称、命名空间和 UID 必须仍是列表里那一行的；列表之后被删除并以同名重建的对象拒绝导出，并说明原因。权限不足单独报告。
- kubectl 的 stderr 不进入文件（SSH 传输会把 stderr 接在输出后面，弃用警告会混进 YAML）；清单超过 1 MB 拒绝，不截断。
- 文件开头是 YAML 注释：来源 SSH 主机、kubeconfig 上下文、对象、UID 与 resourceVersion、读取时间（本机时钟，UTC；集群时钟可能差几秒）、所用命令，以及原文可能含有明文口令或令牌的提示。之后是 kubectl 输出的原文，不做任何改写或遮蔽。
- 只创建新文件，已存在的文件不覆盖。

| 验证 | 结果 |
| --- | --- |
| RPC（`pnpm lab:kubernetes-manifest`） | 15/15。本次命名空间里的 Pod：YAML 的类型、名称、命名空间与 UID 等于 kubectl 独立读到的，环境变量里的明文值原样保留，文件头写明对象、UID、来源主机与上下文；Deployment 与 Node 同样导出，Node 没有命名空间；命名空间行、伪造句柄被拒；Pod 删除后同名重建，按旧行导出被拒并给出专门原因；导出前后 Deployment 的 generation 不变 |
| 桌面界面（`pnpm lab:ui-kubernetes-manifest`） | 8/8，无控制台错误；Pod 详情里有“导出 YAML…”且说明只读；保存后页面写明文件名并提醒可能含明文口令，文件内容是该 Pod 的清单（UID 与 kubectl 一致）；关掉保存对话框什么都不写、不提示；选已存在的文件不覆盖，页面说明没有导出 |

## 尚未完成的范围

受限账号只验证了单命名空间只读 Role 这一种形态；集群级只读、只有 exec 没有 get 等其他组合，以及准入 webhook 拒绝 exec，仍未实测。

固定 45 秒可能不适合启动或 minReadySeconds 较长的业务；后续需要把可配置的就绪期限和恢复策略纳入不可变计划与确认。业务 HTTP/TCP/数据库连通性检查、恢复后的业务验证、HPA/暂停 rollout、多节点故障及不同版本矩阵仍需补齐。副本状态验证不得作为这些能力已完成的证据。
