# 原生功能接线与限制清单

本清单记录尚未中央接线的模块，以及虽已中央接线但因安全契约、完整 parity 或实机证据不足而继续保持 Pending 的能力。清单建立于 Electron 迁移期。

桌面壳现已从 Electron 换成 Tauri 2：后端 `crates/lovelyhawk-backend` 以库的形式链接进桌面进程；原 Electron main/preload 的职责由 `crates/lovelyhawk-desktop` 宿主（窗口、系统对话框、剪贴板、导出、主窗口方法白名单与子窗口目标绑定）和 `ui/src/host` 页面桥接层（`window.lovelyhawk` / `window.lovelyhawkTerminal`，用 shared 契约校验请求与响应）承担；页面与契约位于 `ui/src/renderer`、`ui/src/shared`。下文带日期的接线记录、API 计数（如 `exact112`）、测试计数、`target/electron-debug/...` 证据，以及其中的 main/preload/IPC、sidecar、`LovelyResApi` 描述都是 Electron 时期的事实，保留为历史；代码路径已改为当前位置，已删除模块的路径保持原样。

新增实现如果不能在同一变更中完成 UI 接线，必须登记：crate 路径、领域 owner、缺少的 entity/lifecycle/render 或窗口接线、目标绑定要求，以及可验证的完成条件。

- 应急文件下载留证已完成中央接线，不能再列为只有 SFTP 下载而无应急入口：`file_evidence.rs` → `file_evidence_api.rs` → 有限 RPC → 宿主 `file_evidence_begin`（系统目录选择）与页面桥接层 → 命令工作台文件菜单与进度对话框 → 案件 → 处置报告。Ubuntu / Alpine 的实际证据和 512 MiB / 15 分钟等边界见 `FILE_EVIDENCE_COLLECTION.md` 与 `PRODUCT_ROADMAP.md`。案件工作台的创建、浏览/归档选择、手工记录、笔记快照、检索与所选案件报告现已接线，见 `CASE_WORKSPACE.md`。离线案件库、完整 JSON 导出、归档释放活动名额和保留原件的恢复已接线。结案与重新调查已接通完整结论核对、时间线历史保留及报告；结案不代表主机已通过修复或安全复核。归档永久移除、孤立副本修复、目录批量取证、外部证据重新导入及跨案件转交仍待接线；普通文件采集通过不等于整个应急闭环或严格发布验收通过。

- Nginx 可视化编辑已接线（2026-10-11）：`nginx_visual.rs` → `config_visual_api.rs`（方法 `config.visual`：new / open-quick / view / add / update / remove / move / close；import 与 export 只由宿主命令 `config_visual_import`、`config_visual_copy`、`config_visual_save` 发出）→ `ui/src/shared/config-visual-contract.ts` → 配置页第四种模式“可视化编辑”（`ConfigVisualEditor.tsx`）。文档放在后端，页面只拿句柄、修订号和当前修订的行；每次修改由 core 重建文本并重新解析，字段不能变成两条语句，旧修订号或旧节点编号一律拒绝且不改文档；未改动的导入文件另存逐字节一致（含 CRLF、无结尾换行）。含疑似口令、令牌或带账号地址的行隐藏、不能改删移、不能往里添加，整份文件不复制、不显示全文，另存时原样保留；core 补上了 Nginx 删除/移动/作为父块添加时的同样检查（Apache 原本就有）。搜索只看名称和类型，被搜索隐藏的选中项自动取消。快速生成的 Nginx 草稿可“在可视化编辑中打开”，先建好树再释放快速草稿。另存为新文件不覆盖已有文件；有未另存修改时切换模式、新建、导入、关闭会先询问。Apache httpd 随后接入（同一方法，`product: apache`）：区段显示为“区段”，改开头一行会同时改写结束标签，&lt;Perl&gt; 等非 Apache 内容标为“原文”原样保留（`partlyOpaque`），SSLPassPhraseDialog 等口令设置隐藏并锁定，快速生成的 Apache 草稿也可打开；新建与导入前在工具栏选 Nginx 或 Apache httpd，提示里的检查命令随产品改为 apachectl -t。Redis 随后接入（`product: redis`）：core `line_config_visual` 的 Redis 方言按 Redis 自己的参数拆分规则读写，一行一项、没有块；引号没闭合等 Redis 不会照样拆分的行标为“原文”原样保留；requirepass、masterauth、user 以及改成新名字的 rename-command（改成 `""` 只是禁用，照常显示）隐藏并锁定；比赛模板带中文注释、不含示例口令；快速生成的 Redis 草稿也可打开；Redis 没有单独检查配置文件的命令，提示改为先在测试环境用 redis-server 加载。中文说明：页面内置 Nginx、Apache、Redis 常用指令与配置项的中文说明（`ui/src/renderer/config-visual-glossary.ts`，固定文字，不来自文件），树的每一行、所选项（作用、常见写法、注意）和添加面板（按所在块筛选的常用项、输入名称时的说明）都会显示；添加指令或块时默认在上方加一行中文注释（可改写或关掉），注释和新项在后端同一次修改里加入，其中一步被拒绝就都不加；中文搜索词也按说明查找；Nginx 与 Apache 比赛模板每一段上方都有中文注释；“生成新配置”里这三种产品的草稿预览下面列出用到的配置项及说明，不改动草稿内容。HAProxy 随后接入（`product: haproxy`）：core `line_config_visual` 新增 HAProxy 方言，`global`、`frontend web` 这类区段关键字开始一个区段并拥有其后各行，直到下一个区段；写在所有区段之外的设置、`.if` 这类条件行、引号没闭合或有未知转义的行标为“原文”原样保留；读不懂的区段头仍会结束上一个区段，不把它的行算到别的区段；写在第一列、紧挨着区段的注释算作介绍下一个区段；行尾 `# 注释` 不计入值，改值时原样保留；`stats auth` 以及整行（含行尾注释）出现口令类字样的行隐藏并锁定。新区段只加在文件末尾、不能嵌套，设置只能加在区段里（选中区段里任意一行即代表该区段），缩进跟随区段已有的行；比赛模板每一段上方都有中文注释；快速生成的 HAProxy 草稿可打开且没有“原文”行；内置约 60 项 HAProxy 中文说明，按所在区段筛选常用项；部署前提示用同一版本的 `haproxy -c -f` 检查。另修正：Redis 的 `rename-command` 隐藏规则此前误作用于所有行格式方言，现只对 Redis 生效。MySQL 与 MariaDB 选项文件随后接入（2026-10-12，`product: mysql` / `mariadb`，同用 core `line_config_visual` 的 MySqlOption 方言）：`[mysqld]` 这类选项组显示为“选项组”、只在最外层、不能嵌套，选项必须写在组里（core 拒绝组外选项），`skip-name-resolve` 这类开关可以没有值，`!include`/`!includedir` 引用行可写在文件开头（加在第一个组之前，因为组头之后的每一行都属于该组）或组里；组头只有组名，改名只改 `[组名]` 一行；`password` 等行隐藏并锁定；组外选项、带引号或转义的引用路径、BOM 等标为“原文”。比赛模板（core `MYSQL_COMPETITION_SKELETON` / `MARIADB_COMPETITION_SKELETON`）只监听本机、不解析主机名、`local_infile=0`、`secure_file_priv` 限定目录、开错误与慢查询日志、不含口令，每个组的第一行是中文说明。快速生成的 MySQL、MariaDB 草稿可直接打开（MariaDB 草稿头部原句含 passwords 字样被整份隐藏，已改写为不含凭据词的同义表述）。内置约 70 项 MySQL/MariaDB 中文说明，按选项组筛选（服务端各种组名都算 `[mysqld]`），名称不分大小写、`-` 与 `_` 视为相同；生成器写出的每个选项都有说明（单元测试列出全部名称）。部署前提示：MySQL 用同版本 `mysqld --defaults-file=… --validate-config`（8.0.16 起），MariaDB 没有只检查文件的命令，提示用 `my_print_defaults` 核对生效选项后在测试环境启动（不把它说成校验）。生成器的数据库草稿文件名改为 `lovelyhawk-` 前缀。验收：`tools/lab/probe-ui-config-visual.mjs` 真实窗口 60/60（系统文件对话框与剪贴板由调试构建的测试钩子代答），`tools/lab/probe-ui-config-interactions.mjs` 11/11。目录里的数据库配置文件随后接入（2026-10-12，产品选“数据库配置文件”）：core `visual_document` 把 Nginx、Apache、行格式与结构化数据库文件及 schema 规则收在一处（GPUI 页面模型里的 21 条规则连同测试移入 core），后端 `config.visual` 新增 database-catalog、new-database、select-schema、set-parameter，读本机文件只由宿主命令 `config_visual_import_database` 发出。按数据库和文件从内置目录选择（PostgreSQL 的 postgresql.conf、pg_hba.conf 等）：可编辑的文件打开经审查的起始内容（起始内容不含任何凭据字样，否则整份会被隐藏）；服务器或工具生成的文件（如 postgresql.auto.conf）和要求厂商完整说明的文件只读，只能导入查看、逐字节另存副本，所选项与添加面板都说明只读。选择“对照的版本”后，目录描述过的行标出“目录说明”，所选项显示取值、作用范围、生效方式、风险、敏感级别和文档默认值，并注明来自内置目录、没有核对过任何服务器；版本名由后端按版本选择器生成中文（如“PostgreSQL 16.x（16.0.0 及以上、低于 17.0.0）”），不把目录里的英文标签带到页面。“目录里的参数”可按名称、中文作用或风险筛选；公开且不需要额外能力的参数可以“写入草稿”：先按所选版本的取值规则检查，文件里没有就新加一行（缺少的分组会先建好），只有一处就原位替换，写后读回核对；同一参数写了多处、所在行被隐藏或太长、值不符合规则时拒绝且文档不变。树的搜索只用 core 给出的名称与目录词，不按值命中。验收：同一探针新增第 19、20 节，共 62/62（target/lab-config-visual/3b7b53c9-dc19-486e-b9f6-f423fc670d68）。生成器的目标搜索随后接入（2026-10-12，同一 `config.visual` 方法的 goal-search / goal-choose / goal-confirm，core `configuration_goal` 已有的检索与赋值规则，后端 `config_goal_api.rs`）：“生成新配置”的搜索框在本地特性匹配之外，还按目标给出可生成的做法（点“在快速生成里设置”选好产品、模式、特性与句子里的路径）、按版本的数据库目标（列出各步骤用到的参数，并标出必须在配置文件之外完成的步骤）、数据库参数（可“在可视化编辑中查看”，或填入一条赋值句子）、数据库配置文件（可直接打开）以及“暂时做不到”的产品与原因；原因由后端给出代号、页面写成中文，不出现目录内部的英文用语。形如 `PostgreSQL 16 @postgresql-main max_connections = 300` 的句子只按 core 的闭合语法当作赋值，不做模糊匹配：唯一时出现确认卡片（版本、取值范围、生效方式、风险、可改的值、会写进哪里），多个候选时先选再显示值，拒绝时只说原因、不回显所写的值；后端以只对最新一次搜索有效的租约持有赋值，并记下预览所依据的文档与修订号，确认时值再按目录检查一次，写进当前打开的同一文件同一版本（原位替换或新加一行，写后读回），否则新建一份只含这一项的草稿；预览之后文档有任何修改、或另一文件/另一版本有未另存修改、或参数写了多处，都拒绝且不改任何文档。可视化编辑里的数据库文件另有“用一句话写入参数”，同样先预览后确认。验收：`tools/lab/probe-ui-config-goals.mjs`（`pnpm lab:ui-config-goals`）4/4，config-generator 遗留 90 个测试 ID 全部有通过的替代。仍未接线：Tomcat 的可视化编辑（core 只有只读 XML 结构）、按产品与补丁版本选择 `LineConfigTargetPolicy`（例如 MariaDB `?includedir`）；也不能从目标主机读取或写回配置。
- Docker / Kubernetes 应急工具（2026-10-11 接通）：
  - **Pod 的行操作**：Kubernetes 页面每个 Pod 行上有 日志 · 详情 · 终端 · 文件 · 排查，重启过的 Pod 另有“上次日志”（放在最后，其他按钮逐行对齐）。不在运行的 Pod 不提供终端和文件。
  - **上次日志**：`kubernetes.pod.logs.get` 新增 `previous`，结果单独标为 `pod-previous-logs`，不会当成当前日志显示。实测发现 kubelet 在容器刚被替换、状态还没跟上时，`kubectl logs` 以 0 退出并把 “unable to retrieve container logs for …” 当日志输出；core 识别整段只有这一句的情况（`KubernetesText::is_kubelet_log_refusal`），报告 `kubernetes-logs-not-ready`，页面说明稍后再读，不再把这句话当成 Pod 的输出。
  - **Pod 终端**：core `KubernetesService::detect_shell` / `open_terminal` 每一步之前都重新读取 Pod，UID 变了（被删除重建）、正在删除或不在运行就拒绝；`kubectl exec -it` 进默认容器，shell 先给自己设置会话标记再成为交互 shell，关闭时按标记结束它留下的进程（`kubectl exec` 断开后不会自己结束）。后端 `kubernetes.pod.terminal.open` 只由终端子窗口的宿主命令调用，不在主窗口白名单里；宿主新增 `pod_terminal_open` 与 `ChildKind::Pod`（`terminal.html?window=pod`，窗口按行句柄去重）。打不开时窗口留着并说明原因：没有 pods/exec 权限、镜像里没有 shell、Pod 已不是列表里那个、kubectl 失败，各有独立代码。
  - **容器与 Pod 的文件浏览**：core `exec_directory` 用一段固定的 POSIX sh 列目录（BusyBox 与 GNU 通用；有 `stat` 时给出大小、修改时间、权限，没有就显示“—”），每条记录以 `/` 加换行结束，名字里可以有换行但不会有 `/`，所以不会被拆错；最多 1000 项，传到一半断掉的半条丢弃并标为不完整。名字作数据显示（控制字符转义显示），含控制字符、反斜杠或非 UTF-8 字节的名字可以看到但不能打开。方法 `docker.container.directory.list`、`kubernetes.pod.directory.list`，路径由页面给出、后端按绝对路径规则复核，容器或 Pod 由列表句柄决定；带路径的请求结构与容器文件参数放在一起，受同一测试约束，不混进只带句柄的 Docker 参数区。Docker 的文件对话框改为默认“浏览”，选中的文件可“打开”进原有编辑器或“复制出来”到连接的主机；Kubernetes 行上的“文件”打开只读的 Pod 文件对话框，`kubernetes.pod.file.read` 读取前后两次核对长度和 SHA-256（1 MiB 上限，符号链接、目录、设备拒绝），页面显示摘要。setuid、setgid、所有人可写（带粘滞位的目录除外）的权限标出提示。
  - **Docker 快速排查**：容器详情顶部新增“快速排查”，按需读取 `docker.container.changes.get`（`docker diff`，与镜像相比的新增、修改、删除；说明不含卷和绑定目录）和 `docker.container.processes.get`（`docker top`，从宿主机一侧读取，不依赖容器里的 ps）。临时目录、计划任务、账号与 sudo、SSH 密钥、登录与启动脚本、可执行程序目录、动态链接预加载、被删除的日志等改动，以及交互 shell 接网络、网络工具带执行参数、下载即执行、挖矿程序名、从临时目录运行等进程特征标为“值得先看”并写明原因，只是提示，不是结论。实测发现 Podman 在 cgroups v1 主机上每条命令都往 stderr 写弃用警告，传输把 stderr 接在输出后面，曾被读成一个进程和一条读不懂的改动；diff 与 top 现在丢弃 stderr（真正的失败仍由退出码判断）。容器日志不能丢 stderr（那是容器自己的），改为只对 Podman 设置它自己的 `PODMAN_IGNORE_CGROUPSV1_WARNING=1`；此前每个 Podman 容器的日志最后一行都是这条警告。
  - **界面**：Docker 容器状态和运行时长显示为中文（无法识别的原样保留）；Kubernetes 的“要看的”只算没就绪或状态异常的 Pod，重启次数单独标色；命名空间与资源类型改为紧凑样式；Pod 与容器可一键带到命令工作台。
  - **验收**：RPC 探针 `pnpm lab:kubernetes`（含上次日志）、`pnpm lab:kubernetes-terminal`（shell 的主机名就是 Pod 名；关闭后后台进程结束；Pending、distroless、重建、伪造句柄四种拒绝）、`pnpm lab:container-files`（Docker BusyBox 与 GNU、Podman、k3s Pod；临时种下的换行名、setuid、所有人可写、符号链接，以及 docker diff/top 的标记，结束后按确切路径清除）；真实窗口 `ui/scripts/probe-docker.mjs` 36/36、`pnpm lab:ui-kubernetes-tools` 13/13。
  - **多容器 Pod 选择容器（2026-10-12 接通）**：行操作旁的“容器”选择决定日志、上次日志、终端和文件对哪个容器，默认是注解指定的默认容器；只能点名列表里这个 Pod 的容器，打开前核对所选容器在运行，终端清理在同一容器里进行，同一 Pod 的不同容器各开一个终端窗口（`pnpm lab:kubernetes-containers`、`pnpm lab:ui-kubernetes-containers`，见 `docs/KUBERNETES_VERIFICATION.md`）。
  - **只能看一个命名空间的账号（2026-10-12 接通）**：集群的权限拒绝报 `kubernetes-forbidden` 并说明可以怎么办，不再显示成“读取没有完成”或空列表；命名空间列不出来时按 kubeconfig 当前上下文的命名空间读取（页面只发 `{ context: true }`）；列目录、读文件失败后用 `kubectl auth can-i` 确认是否缺 pods/exec；扩缩容执行被拒时回执说明资源没有被改动；Pod 终端窗口显示后端给出的具体原因（`pnpm lab:kubernetes-rbac`、`pnpm lab:ui-kubernetes-rbac`，见 `docs/KUBERNETES_VERIFICATION.md`）。
  - **Pod 文件留证（2026-10-12 接通）**：Pod 文件对话框的“留证”把原始字节经 SSH 主机 `/tmp` 的独占临时副本复制回本机所选文件夹，容器内复制前后、主机副本、两次读取与本地回读的摘要一致才写清单并登记案件，取消时结束这次复制的 kubectl 并删除副本；抓包留证与 Pod 留证改用同一个留证任务控制器（`pnpm lab:kubernetes-pod-evidence`、`pnpm lab:ui-kubernetes-pod-evidence`，见 `docs/FILE_EVIDENCE_COLLECTION.md`）。
  - **导出 YAML 清单**（2026-10-12）：Pod、Deployment、Node 详情里的“导出 YAML…”经宿主专用命令 `kubernetes_manifest_export` → 后端 `kubernetes.manifest.export`（不在主窗口白名单）→ core `KubernetesService::object_manifest`，对象只按列表句柄指定，UID 等身份不符拒绝，原文写入保存对话框选的新文件、带来源说明的注释头，内容不经过页面。实测与范围见 `KUBERNETES_VERIFICATION.md`。
  - **仍未做**：其他 RBAC 形态（集群级只读、准入 webhook 拒绝 exec）的实机验证；无 shell 镜像的文件留证；容器文件的批量留证；Kubernetes 事件的单独视图（详情里的 describe 已含 Events）；容器网络隔离、暂停等处置动作（需走计划、确认、回读链路）。

## 已实现但未接线

- PostgreSQL 的 7 项候选基线已接入现有只读 API 和页面：`baseline.rs` / `baseline_postgresql.awk` → `baseline_read_api.rs` → `BaselinePage` / `BaselineFilePane`。各文件独立保留风险，常见 `postgresql.auto.conf` 来源可查看，没有实例证据的安全值不标为符合；具体范围和验证见 `POSTGRESQL_BASELINE_VERIFICATION.md`。core 拒绝新的通用 PostgreSQL 写入。实际实例身份、主配置/include/启动与会话覆盖、HBA/账号/TLS/日志完整检查，以及精确变更、运行值与业务连接验证、恢复仍待接通；探针中的 SQL、`ALTER SYSTEM` 与文件修改仅构造实验输入，不计产品修补或数据库配置部署矩阵验收。

- Redis 候选基线已接入现有四个只读 API 和基线页面：`baseline.rs` / `baseline_redis.awk` → `baseline_read_api.rs` → `BaselinePage` / `BaselineFilePane`。通配 bind、原生 yes/no 建议、ACL 与运行时待复核、独立候选来源及恶意纯文本已做实际验证，见 `REDIS_BASELINE_VERIFICATION.md`。core 禁止新的 Redis 通用写入；实例身份、认证、配置包含关系、精确修改/恢复计划、原生验证和业务连接检查尚未接通，实验夹具修改不算应用修补。core 历史恢复已完成完整文件回读、后续内容/身份保护和失败不重新应用的实验验证，见 `BASELINE_RESTORE_VERIFICATION.md`；缺少修改后证据的旧记录拒绝自动覆盖，桌面预览/确认和生产并发恢复边界仍待接通。

- Nginx 普通进程的 TLS 协议修补已复用现有 `nginx.repair` 接入桌面：只从明确位置移除旧版协议，保留原现代协议集合，差异、旧客户端影响、默认服务器影响及恢复提示均可见。Electron 时期的真实桌面与独立 TLS/HTTP 验证见 `NGINX_PROCESS_REPAIR.md`，不再列为没有任何 TLS 修补入口；目标本机监听/SNI/证书/HEAD、连接观察入案、保存重试和离线报告已接通，具体范围见 `NGINX_CONNECTIVITY.md`。前后观察与处置计划的自动关联、外部业务复核、仅旧协议实例的升级及跨版本矩阵仍待完成。

- Linux 安全基线的单项修改与历史放回（领域 owner：`lovelyhawk-core::baseline`）已于 2026-10-12 接入桌面：
  `baseline.action.plan/confirm/execute/cancel` 只接受句柄，计划经应用内确认执行一次，写入前完整备份、
  程序检查、按计划重载并独立读回，失败时放回；可放回的历史记录在文件未被后续改动时才放回。同时修正了
  sshd 附加文件在主文件没有 Include 时仍被当成生效位置、以及 sshd 写入删除/误入 Match 块的问题。
  范围、容器验证与剩余缺口见 `BASELINE_CHANGE_VERIFICATION.md`；Nginx、Redis、PostgreSQL 与存在性检查仍只读，
  systemd 主机、虚拟机与实机矩阵未验证，页面 ledger 状态继续为 Pending。以下为只读部分的原记录。只读
  Phase 1 已经进入中央 `BackendState`、固定 RPC、宿主主窗口方法白名单与 `ui/src/host` 页面桥接层
  （Electron 时期为固定 IPC 与 frozen preload）、`App` registry 与 `BaselinePage`。
  当前公开面精确为 `getBaselineCatalog()`、`scanBaseline(bindingHandle)`、
  `listBaselineHistory(bindingHandle)`、`readBaselineFile(bindingHandle, itemHandle)` 四个 typed 方法；
  页面只接收 opaque `bindingHandle`，不接收 target summary、session、guard 或 generation。
  Rust adapter 调用 `BaselineService::catalog/scan/list_history/read_setting_file`，
  扫描使用共享的真实 `BoundSshSession`，请求前后复核完整 target scope；统一 SSH disconnect 在真实断开前
  调用 `close_binding`，只清该 binding 的 scan/history capabilities，迟到结果失败关闭。
  公开 DTO 包含 opaque item/snapshot handles、目录元数据、观察结果、历史摘要与受限的配置文件查看。
  文件路径是显示标签，由 core 的目录或经校验的扫描来源选择；renderer 不接受任意读取路径。
  raw record、operation、backup、digest、target/session/guard/generation 和 check/apply/verify shell
  不进入 renderer。portable history 在 serde 前有 4 MiB encoded-byte cap，exact 257 records 硬拒绝、
  exact 256 合法，list/insert/lookup/transition 统一使用 fail-closed loader。目录、状态、历史分别最多
  160/160/256 项，当前目录 108 项，响应最多 256/256/512 KiB；registry 最多 12 项/4 MiB、TTL 五分钟，并限制全局 4 个和
  每 binding 1 个并发读取。credential-like 值整字段遮蔽，hostile 文本只作为 React text node 渲染。
  Renderer 已覆盖分类、筛选/搜索、history、loading/error/empty/truncated、activate/deactivate、scope change
  与 late-result cleanup，且没有 plan/confirm/execute/restore/reload/terminal/export/AI 入口。
  早期 Electron-native CDP PASS 证据为
  `target/electron-debug/526e344c-a5f5-499d-9a17-ab4c0bf4defe/evidence`：该运行早于 Log Analysis 中央接线，本地目录 38 项、
  forged/unknown scan/history 拒绝且不回显、断连页/重挂载空态、本地资源、`capturePage` 和 0 console
  errors 均已验证。此前 `c7f9b277-006c-4f00-9fb1-7c503928d857` 运行是 `FAIL`，不可引用为通过证据。
  2026-09-07 已补 Nginx 1.27.5 隔离容器的真实 SSH/RPC 与 Electron 检测验证，详见
  `NGINX_BASELINE_VERIFICATION.md`。Nginx 现在输出候选文件风险线索或待复核，不以最后一个同名指令
  判断全部站点合规；通用基线写入器拒绝 Nginx 配置，不能删除其他 server/location 的同名项。
  解析工具失败返回 `unverified`；缺工具、未安装、条件配置等不能生成通用写入计划。配置读取按请求序号、
  API、目标和生命周期失效；刷新扫描会重新读取当前项。Nginx 文件查看跟随新的风险来源且不标记唯一生效行。
  可写单项的计划/确认/检查/放回已接通（见上）；Nginx、Redis、PostgreSQL 的完整运行实例、include/继承解析、
  实际修补/重载/健康验证/恢复，以及跨产品和权限矩阵仍未完成，页面整体 ledger 状态继续为 Pending。

- `lovelyhawk-core::apache_runtime` 与 `lovelyhawk-core::apache_capability`（领域 owner：
  `lovelyhawk-core`）已经完成 Apache Evidence Seal Phase A。运行时证据合同以完整 `TargetGuard`、
  systemd unit/InvocationID、MainPID、进程 starttime、规范化可执行文件路径与 SHA-256、ExecStart、
  NUL argv、effective environment 和按顺序读取的 EnvironmentFile 内容摘要为绑定，并保留重复且有序的
  `-d/-f/-D/-C/-c` 参数种类。原始 argv、环境和 EnvironmentFile 内容只进入 core 的有界
  `Zeroizing` 构造边界；`Debug`、错误和公开 getter 不返回原文。该构造器以及裸运行时/图 SHA-256
  构造器均为 crate-private/test fixture，外部调用方不能再用任意 64 位十六进制字符串铸造 capability
  绑定。构造器只校验形状、边界与摘要绑定，本身不证明采集来源；未来 provider 还必须证明 ExecStart
  executable 与 MainPID 的 `/proc/<pid>/exe` 指向同一个规范化可执行文件并绑定其摘要，wrapper 或任意
  不匹配必须成为 typed `UnsupportedWrapper/Unavailable`，不得降级猜测。
  `ApacheConfigGraphEvidence` 使用版本化、长度前缀编码绑定 core 持有的文件、include 解析结果及目录
  清单；`ApacheStableConfigGraphEvidence::seal` 只接受 invocation、guard 与全部图 item 完全相同的
  before/after 端点。它只证明两个采集端点相同，不宣称远端文件系统在区间内原子不变。
  `httpd -M` 已加载模块和 `httpd -L` 静态指令证据解析仍保持有界；`-L` 仍明确为 `StaticOnly`，缺失
  项不能显示成“不支持”。快照现在只能从同一 runtime evidence、matching stable graph evidence 和
  有界输出构造。
  当前没有 systemd/`/proc`/EnvironmentFile provider，没有分离 stdout/stderr、exit=0、超时/取消/截断
  完整状态的精确 `httpd -M/-L/-t` transport，也没有桌面页面 capability 接线。普通合并 stderr、lossy
  UTF-8 或字符串 shell 重放（尤其任意 `-C/-c`）不得作为替代。真实 Linux 的 Debian/Ubuntu
  apachectl+envvars+symlink、RHEL/Rocky direct-httpd、自定义 wrapper/drop-in、PID/restart/权限竞态和
  include/glob 组合均为 `NOT_RUN`。
  远程 middleware 已有实例发现、有界 `Include`/`IncludeOptional` 图、原生 `-t`、逐文件及目录清单
  CAS、备份、验证和恢复；但旧运行时字符串指纹及重建的 `-t -d -f` 尚不能证明与服务的真实有序调用
  上下文等价。因此 Phase A 明确关闭 Apache 远程 plan/execution，只读发现和候选配置图不受影响，
  Nginx 变更路径不受影响。完成接线前 capability 与 Apache mutation 都不得显示为已运行或已验证。

- `lovelyhawk-core::database_config_sources`（领域 owner：`lovelyhawk-core`）已经提供目标绑定、产品/
  组件/工件精确绑定的配置来源与优先级图，覆盖文件、include、命令行、环境变量、服务管理器、
  运行时 SQL、自动生成态、厂商工具、云 API 与内建默认值；未知/冲突/未解析来源会阻止生成
  effective view，绝不默认文件最高优先级。该模块尚未接目标发现 provider、页面或实际来源回读。
  完成条件是逐产品从同一 `TargetGuard` 构建完整来源图，回读每个来源摘要/版本，展示 unresolved
  barrier，并覆盖 include 环、并发变化、迟到结果、命令行/环境覆盖与秘密不进入 UI/日志。

- `lovelyhawk-core::postgres_auth_schema`（领域 owner：`lovelyhawk-core`）已经提供原生 PostgreSQL
  16/17/18 的静态 HBA/ident 方法、选项和交叉字段语义；未知方法保持可见未知，未知选项保持目标
  依赖。它尚未接入 line parser、配置生成器、目标 capability 回读，也没有用目标端
  `pg_hba_file_rules`/`pg_ident_file_mappings` 校验。完成条件包括绑定 `TargetGuard`、读取目标能力与
  诊断视图、运行目标端验证，并拒绝目标切换后的迟到结果。

- 配置生成器与远程 middleware 树（领域 owner：桌面 config-generator 页面）已经接入只使用安全名称/静态说明
  的本地搜索、父链过滤和逐项说明；配置生成器还展示完整已审 schema 参数目录，包括文件中未出现项。
  统一目标入口现已覆盖 4 个 middleware 和 33 个数据库产品：Nginx 有静态站点、反向代理与路径 403 三个
  typed 本地配方；Apache 2.4 有路径及子路径 `Require all denied`、禁用 TRACE（405）和减少版本信息暴露三个
  本地配方，后两项仍未运行目标 `httpd -t`、模块能力或真实请求验证。18 个版本化数据库 schema 的参数可按
  canonical 名称、已审说明及闭合中英文意图搜索，并有远程访问、慢查询、TLS、审计、连接容量、查询超时、
  事务持久性、密码存储、连接准入、空闲会话保护与连接事件日志十一组多步骤检查清单。只有 `Public`、无
  capability、允许本地草稿且通过 typed validator
  的参数能显式加入本地草稿；其余只显示 `CatalogGuidance`。闭合的一行赋值语法支持产品、版本、可选
  `@artifact-key`、可选 `[container]`、canonical/精确别名与 typed 值；711 个可写 locator 全部解析为唯一目标或
  明确候选。赋值式失败不会回退普通搜索，候选和值编辑都保持 exact target，确认使用页面/查询/文档 revision
  租约，并通过临时文档写入与 exact 回读后一次性提交；跨工件脏草稿、重复参数、敏感值、未证 capability 与
  只读工件均失败关闭。产品/目标评分和数据库版本筛选相互隔离，未登记
  的精确版本不会借用相邻 schema；每个失败结果会返回 MissingIntent/Recipe/Schema/Version/Validator/Artifact/
  Runtime/Evidence/Sensitive 中的 typed 原因、当前已有证据和开放条件，绝不降级为猜测生成。
  Nginx、Apache、unknown 和无逐项权威 schema 的 structured 行仍是 `SyntaxOnlyUnknown`。此外，156 个数据库
  配置工件可按稳定 key/default filename 搜索；该入口只导航到既有 source-backed 工作区。有 parser 时可选择
  对应只读/草稿视图，无 parser 时显示 typed 缺口；所有工件结果均为 `CatalogGuidance`，绝不冒充目标配方、
  当前配置、验证或部署，也不会自动导入文件或绕过脏草稿保护。
  `VerifiedForTarget` 证据链尚未接线：完成条件至少包括把 exact
  `TargetGuard`、产品/版本/edition/组件与文档/schema 摘要绑定到同一快照，证明所需 target
  capability，执行目标厂商校验/readback，并在结果应用前复核目标、能力和快照均未变化。Nginx 与
  Apache 还缺 directive-specific、按产品版本隔离且带官方 reference/rationale/type/scope/activation/
  risk 的 metadata registry；第三方或未登记 directive 必须继续失败关闭为 `SyntaxOnlyUnknown`。
  搜索不得索引 value、preview、arguments、comment、raw、default 或 secret；只读目录选择不得修改文件，
  目标动作也不得从 documented default、现值或搜索原文自动填值。上述数据库 bundle 目前是有界的分步导航，
  仍没有访问控制文件、证书链、审计插件、网络/重载及真实 readback 的自动执行，因此不能宣称完整达成目标。
  `lovelyhawk-core::redis_config`（领域 owner：`lovelyhawk-core`）现已提供 Redis Open Source 6.2、7.2、7.4
  与 8.0/8.2/8.4/8.6/8.8/8.10 的类型化“新建空实例”本地 Baseline，并已接入
  原三栏快捷配置器（原 GPUI `config_generator`，源码归档于 docs/legacy/config-generator-baseline.rs.txt，桌面页面替代进行中）。页面保持 Baseline 不可移除，支持按静态元数据
  搜索、配置叠加、逐行下方类型化编辑、真实移除、仅重置 Redis、独立滚动预览、复制和 `create_new`
  非覆盖另存；版本、数据目录、端口、连接/超时、内存/淘汰、AOF/RDB、slowlog 与 latency monitor 均展示
  含义及风险，并强制 maxmemory 不可移除及 AOF/RDB 至少保留一种。Redis 高级语义编辑器没有安全加载器，
  因而在界面与程序入口均明确禁用，不会显示成加载成功。该流程只适用于新建空实例，明确不承担既有含数据
  实例的 AOF/RDB 迁移，也不生成认证/ACL、远程监听或任意指令。任何目标校验或部署还必须绑定完整
  `TargetGuard`，使用同版本隔离验证、CAS、备份、重启后持久化与数据回读，并拒绝迟到结果；真实 Redis
  解析、启动、迁移与部署矩阵仍为 `NOT_RUN`。
  `lovelyhawk-core::postgresql_config`（领域 owner：`lovelyhawk-core`）现已提供 PostgreSQL 14–18
  的类型化“新建空集群”本地 include 片段：固定回环监听、端口、SCRAM 新密码存储、WAL 耐久性、
  统计与 autovacuum Baseline，并可叠加 13 项配置：版本化连接容量、认证超时、事务内/事务外空闲保护、
  单进程临时文件上限、连接生命周期日志、带明确 `deadlock_timeout` 的锁等待日志、checkpoint、autovacuum
  与临时文件阈值日志、数据/WAL I/O 计时、内建 pglz WAL 全页镜像压缩和 query ID。该模块只使用闭合
  有界值，以 `PostgresConf` 无损解析器完成
  生成后 allowlist 与逐字节 round-trip 校验，并只允许 `create_new` 另存；它不会生成 include 指令，
  也不初始化、部署、覆盖、重载或重启 PostgreSQL。HBA/ident、`postgresql.auto.conf`、TLS/秘密/角色、
  archive/restore 命令、preload、目标资源 sizing、全局 statement timeout、SQL/参数文本日志、远程监听
  和既有集群迁移继续 typed deferred。该模块尚未接入配置生成器 entity/state/render；完成条件是原生
  页面显式选择精确 major（后续 UI 可默认推荐 18）、展示 immutable Baseline、全部 feature/字段说明与
  风险，支持叠加/移除/重置、滚动预览及本地不覆盖另存。任何目标校验或部署还必须绑定完整
  `TargetGuard`，盘点全部配置来源与优先级，在同 major 隔离目标上验证启动/行为、CAS、备份、恢复与
  effective readback，并拒绝迟到结果；真实 PostgreSQL 14–18 矩阵仍为 `NOT_RUN`。
  `lovelyhawk-core::mongodb_config`（领域 owner：`lovelyhawk-core`）现已提供 MongoDB 7.0、8.0 与 8.3
  的类型化“新建空本地 standalone”`mongod.conf` 草稿：Baseline 固定回环监听、开启 authorization、
  关闭服务端 JavaScript 并使用 WiredTiger；可叠加连接上限、慢操作阈值与采样、`slowOp` profiler、
  8.3 专属的运行中慢查询日志、显式绝对路径日志轮转、WiredTiger cache 以及新集合与 journal 压缩。
  生成器只接受闭合有界值和严格 YAML 映射子集，拒绝 anchor、alias、tag、include、sequence、未知键、
  重复键与多行值，并只允许 `create_new` 另存。它不生成首个用户或任何凭据，不开放远程监听，不猜测
  `dbPath`/PID/service 布局，也不生成 TLS/私钥、Enterprise `auditLog`/LDAP/KMIP、复制集、分片或部署命令；
  MongoDB 8.2 已于 2026-07-31 结束支持，因而不会作为可选版本。该模块尚未接入配置生成器与数据库产品
  目录；完成条件是登记独立 MongoDB 产品/工件并接入版本选择、immutable Baseline、全部功能及字段说明、
  叠加/移除/重置、独立滚动预览和本地非覆盖另存。任何目标动作仍需完整 `TargetGuard`、同系列隔离验证、
  备份/恢复和行为回读；真实 MongoDB 7.0/8.0/8.3 启动与客户端矩阵仍为 `NOT_RUN`。
  `lovelyhawk-core::haproxy_config`（领域 owner：`lovelyhawk-core`）现已提供 HAProxy 3.4 LTS、3.3 stable、
  3.2/3.0 LTS 与 2.8/2.6 compatibility 分支的类型化 HTTP 反向代理本地草稿。Baseline 固定闭合监听与
  单一上游、HTTP mode、必需连接/客户端/服务端超时和零重试，并默认叠加请求/队列超时、安全响应头、
  上游 `Server` 头移除及直接边界转发头；另有健康检查、stdout 访问日志、Gzip、路径 403、直接来源
  IP、GET/HEAD、WebSocket tunnel、连接/队列上限、仅连接失败重试、请求 ID、直接来源限速等共 16 项。
  所有名称、地址、端口、path/CIDR、超时和上限均使用闭合 typed value；生成后由专用 allowlist parser
  逐项复核，并只允许 `create_new` 另存。TLS 前端虽作为可搜索能力显示，但在没有证书资产、权限与目标
  capability 闭环时明确拒绝启用，不会输出 `crt`/`ssl` 占位；本模块也不部署、reload、覆盖或声称已经
  运行 `haproxy -c -f`。该模块尚未登记到 middleware 产品树或配置生成器；完成条件是接入版本选择、
  immutable Baseline、全部功能/字段说明、叠加/移除/重置、独立预览与非覆盖另存，并在精确版本目标上
  绑定 `TargetGuard` 执行配置检查、HTTP/WebSocket 行为、CAS、备份与恢复。真实 HAProxy 2.6–3.4
  二进制与行为矩阵仍为 `NOT_RUN`。
  `lovelyhawk-core::tomcat_config`（领域 owner：`lovelyhawk-core`）现已提供当前受支持的 Tomcat 9.0、10.1、
  11.0 三个精确版本族的类型化“全新/空白安装 + 新 ROOT 应用”配置审阅 bundle，并已接入
  原三栏快捷配置器（原 GPUI `config_generator`，源码归档于 docs/legacy/config-generator-baseline.rs.txt，桌面页面替代进行中）。页面默认 Tomcat 11，显示 Servlet/Java namespace、
  immutable Baseline、全部 feature/字段说明与 deferred 边界，支持按静态元数据搜索、配置叠加、逐行下方
  类型化编辑、真实移除、仅重置 Tomcat、独立滚动三工件组合预览、复制和全新目录非覆盖另存；GET/HEAD
  allow-list 与全应用 403 原子互斥。Tauri 页面（2026-10-12）已补齐这两项：“复制全部”按
  `===== BEGIN/END <路径> =====` 标注每个文件，“导出全部 3 个文件…”在所选位置新建
  `lovelyhawk-tomcat-new-empty-review-bundle` 并经 core `write_new` 逐个 create_new 写入、已存在即拒绝
  （宿主 `config_bundle_export`，路径不经过页面；真实窗口验收 `desktop-config-generator-quick-flows-2026-10-12`）。
  它始终同时生成 `conf/server.xml`、
  `webapps/ROOT/META-INF/context.xml`、`webapps/ROOT/WEB-INF/web.xml`，且 `maxPostSize` 与
  `maxSwallowSize` 的说明不冒充通用请求体或上传上限。三工件高级语义编辑与导入没有安全加载器，因而在
  界面与程序入口均明确禁用，不会显示成加载成功。该 bundle 不是完整 Tomcat 安装包、不可直接部署，也绝不
  覆盖/迁移现有应用、Realm、Valve、Listener 或账户；TLS、Manager/HostManager、Realm 秘密、任意 XML、
  既有应用部署与非回环暴露继续 typed deferred。任何目标校验或部署还必须绑定完整 `TargetGuard`，在匹配
  版本的隔离 Tomcat 上验证 schema、启动、HTTP 行为、CAS、备份与恢复并拒绝迟到结果；真实 Tomcat
  9.0/10.1/11.0 与 Java 8/11/17 启动及 HTTP 矩阵仍为 `NOT_RUN`。
  真实 Nginx/Apache 与数据库目标的 capability/readback 矩阵仍为 `NOT_RUN`。

- `lovelyhawk-core::line_config_visual::LineConfigTargetPolicy`（领域 owner：`lovelyhawk-core`）已经为
  MariaDB option file 提供字段私有、由产品与完整四段版本推导的 `?includedir` 语法门禁。当前
  allowlist 只包含官方源码逐个审校的 11.4.10、11.8.6 与 12.2.2；默认 parse/read、MySQL、相邻或
  未知补丁全部保持 opaque，且 document 在 replace/add/update/reparse 后保留同一 policy。前端
  尚无可信的完整 patch 版本输入，因此没有接入 `*_with_target_policy` API，也不会从 MariaDB 11.4
  minor schema 或 MySQL wire compatibility 推断该能力。完成条件是增加明确标为“本地语法选择、
  非目标证明”的产品+四段版本控件，切换时重新解析并使旧 NodeId 失效，同时覆盖导入、更新、
  `#` 歧义、末行 LF、错误产品/补丁和权限不升级；真实 Linux/Windows MariaDB 版本矩阵仍为
  `NOT_RUN`。
- MySQL/MariaDB Batch A 已将无版本 `mysql-option-file`/`mariadb-option-file` catalog validator
  统一失败关闭为 `SyntaxOnly`，但原生 validator 尚未接线：MySQL 8.0.11–8.0.15 没有
  `--validate-config`；MySQL `>=8.0.16`（含 8.4）只能在隔离环境调用
  `mysqld --validate-config`，且不会初始化 storage engines、plugins、components；MariaDB
  10.11/11.4 没有专用 `--validate-config`（13.0 才引入），`--print-defaults` 与
  `my_print_defaults` 只发现并展开选项，不构成 validator。默认名 `my.cnf` 仅是 Unix 常见建议；
  真实路径和 Windows `my.ini`/`my.cnf` 必须按实例发现。include graph、suffix、platform
  组合以及 MySQL/MariaDB 真实 VM 矩阵仍为 `UNWIRED`/`NOT_RUN`。
- MySQL `auto.cnf` 与 `mysqld-auto.cnf` 是不同来源：前者由服务端生成并保存只读
  `server_uuid`，本轮只把它登记为 `SourceBacked` + `ReadOnly` 的 ReplicationIdentity，
  明确禁止编辑。文件读取、权限/拒绝访问呈现、provider 接线、与运行时 `@@server_uuid`
  的 source correlation、请求和结果两端的完整 `TargetGuard` 校验以及真实 MySQL 验证均仍为
  `UNWIRED`/`NOT_RUN`，不得把 scope 行解释为已能发现、回读或验证该身份。依据：
  [MySQL replication options and `auto.cnf`](https://dev.mysql.com/doc/refman/8.4/en/replication-options.html)。
- `mysql-plugin-registry`、`mysql-component-registry`、`mariadb-plugin-registry` 已接入 core 的闭合只读 SQL、
  有界 typed parser、同连接身份绑定与数据库页面的 `Inventory` 页签。页面只渲染 core 公开的安全值或统一
  脱敏占位，并复用完整 `TargetGuard`、连接配置摘要、取消和迟到结果拒绝；MariaDB component 在发起 SSH 前
  静态拒绝。它们仍不等价于 option-file、命令行、manifest 等 startup 来源。真实数据库/SSH、最小权限与拒绝
  访问语义、registry/runtime/startup source correlation 和原生数据库协议仍为 `NOT_RUN`/`UNWIRED`。因此不得声称 plugin/component
  inventory comprehensive，也不得开放或暗示支持 `INSTALL`/`UNINSTALL PLUGIN`、
  `INSTALL`/`UNINSTALL COMPONENT` 或 MariaDB 对应 mutation。依据：
  [MySQL plugin loading](https://dev.mysql.com/doc/refman/8.4/en/plugin-loading.html)、
  [MySQL component loading](https://dev.mysql.com/doc/refman/8.4/en/component-loading.html)、
  [MariaDB plugin overview](https://mariadb.com/docs/server/reference/plugins/plugin-overview)。

新增页面至少要同时完成：

1. 在 `PageId` 与集中 descriptor registry 中注册；
2. 由应用组合根创建并复用 entity；
3. 接入 activate/deactivate、render 和目标切换失效逻辑；
4. 增加页面唯一性、导航、迟到结果拒绝和攻击者文本只作纯文本的测试。

原生辅助窗口还必须使用共享 typed entity 或 intent，并覆盖关闭后重开、目标切换和 stale session 行为。

## 刻意保持关闭的高风险能力

以下项目不是遗漏的按钮。它们缺少足够窄的计划、快照、CAS、审计或恢复保证，在契约补齐并通过真实 Linux VM 故障注入前不得开放：

- 任意改写 sudoers、`authorized_keys` 或 SSH 认证设置；当前仅提供受限只读调查。
- 软件包真实卸载；当前只提供本地包数据库调查和卸载影响预览。
- 用户删除、强制清退用户全部会话等不可精确恢复的账户操作；当前只开放可验证恢复的锁定/解锁。
- 卸载当前已加载的内核模块；当前只允许创建或移除 LovelyHawk 自有的自动加载黑名单。
- 执行 Cron 行中的远端命令。Cron 命令始终作为攻击者可控文本，只允许查看、解析和指标检查。

已经开放的 Cron 独立文件删除、Shell 精确行注释、SUID/SGID 位移除或隔离，都必须继续绑定内容 SHA-256 和文件身份，先写入 `.lovelyres-backups` 受管命名空间（目录名改名后沿用，以兼容目标机上已有备份），再经过 exact confirm → journal → verify/restore。

内核模块黑名单路径固定为 `/etc/modprobe.d/lovelyres-blacklist-<module>.conf`。新文件必须独占创建并使用 `0644`；移除只接受逐字节匹配的管理内容。文件名前缀与其中的 `# Managed by LovelyRes; …` 管理标记行在改名后保留不变，以兼容目标机上早期版本写入的黑名单。黑名单只影响未来自动加载，不能把它展示为当前模块已经卸载。

## 尚未完成的实机验收

- **Tauri 2 外壳**（2026-10-10）：Windows x64 已通过以下验证：
  - 调试构建 CDP 冒烟（逐页、逐浮层、明暗主题、全局 API 形态）；
  - 实验室靶机终端子窗口场景（连接、输入回显、文件编辑窗口的打开与未保存修改询问、复用、断开即回收）；
  - 主窗口关闭握手（未保存设置的询问超过 15 秒后，回答仍然有效）；
  - 安全速查页在新外壳下重新验收，账本恢复为 Completed（`ui/scripts/probe-security-reference.mjs`）；
  - 笔记、连接导入导出、连接删除逐项验收（`probe-notes.mjs`、`probe-connections.mjs`）；
  - 完整质量门禁，以及源码与依赖门禁的正反例自检；
  - release 便携包的校验与冒烟（含空格和中文的路径、重定向用户目录、正常关闭）。

  账本现为 22/53 Completed（2026-10-11 新增连接编辑与保存、处置报告、容器终端、Docker、命令工作台、命令历史、文件完整性）。应用日志浮层的探针已通过，日志现在同时写入程序旁的 `data/logs/lovelyhawk.log`（每个约 2 MB，连同较早的一共保留 3 个；写入的是与浮层相同的已遮蔽内容，清空浮层不动文件；文件写不进去时浮层用警示说明）。顺带修正改名后的遗漏：采集仍只把以 lovelyres 开头的模块当作本程序，程序自己的 INFO/DEBUG 记录因此一直被丢掉。条目仍为 Pending：还没有在打包版本中用真实保存对话框验证导出（release 版没有对话框测试钩子也没有调试端口，需要人工操作）。

  终端窗口里的文件管理（2026-10-11）：下载、上传、编辑器写回和“主机改过就拒绝保存”已在九台靶机上通过（`probe-sftp-transfers.mjs`），条目仍为 Pending，因为还缺 SSH/SFTP 兼容矩阵在虚拟机或实机上的运行（目前只有容器靶机）。

  在文件夹里打开终端（2026-10-11 接通）：文件管理里文件夹的右键菜单、空白处右键和工具栏都有“在这里打开终端”，每次打开一个新的终端窗口，shell 从那个文件夹开始。窗口只拿到文件管理已有的两个句柄和用于标题的名字；后端把句柄换回列出过的路径（必须是同一目标、同一次连接、未过期、确实是文件夹），core 再核对一次并把路径加引号交给 shell，页面始终不经手路径或命令。打不开时窗口留着说明原因（文件夹已被删除、本机上的终端已满 4 个等），不会一闪就没。九台靶机各 16/16（`probe-directory-terminal.mjs`，含名字是 `it's a dir; touch PWNED` 的文件夹：shell 在里面，名字里的命令没有执行）。仍有的限制：靶机都以 root 登录，“能列出但进不去”的文件夹没有覆盖到。

  同时修正两处：
  - 容器终端窗口原来也带着主机的文件管理，看起来像容器里的文件；而且后端每个连接只保留一个文件浏览器，容器窗口一开，SSH 窗口和它打开的编辑窗口手里的条目就全部过期。现在只有 SSH 窗口有文件管理，宿主拒绝其他窗口打开；容器和文件夹窗口里写明“主机文件在 SSH 终端窗口的文件管理中”。
  - 连接与主机密钥（2026-10-11）：主机密钥首次确认、密钥变化拒绝连接、取消尝试原来就有，此前只验收过“信任”这一条路。现在用 `probe-host-key.mjs` 在不改动任何主机的前提下补齐：导入一个带错误指纹的连接验证拒绝且保留原指纹，首次连接验证拒绝后不记录、不留会话。顺带修正两处：确认主机密钥时焦点原来停在“信任此指纹”，误按回车就信任了未核实的密钥，现在焦点在“取消尝试”；连接失败原来一律显示同一句英文，现在按失败环节（主机名解析、端口不通、经堡垒机、认证、私钥或证书、SSH Agent）给出中文说明和下一步，主机返回的原文只进应用日志。交互认证 / MFA 已在真实服务器上验证（`probe-mfa.mjs` 8/8）：探针只在本次运行期间给 lab-rocky 加一个 sshd 配置片段开启键盘交互认证，结束后删除并确认恢复为关闭；服务器的提示原样显示、输入框隐藏输入并获得焦点，答错拒绝并说明，答对连上，任何回答都没有写进数据目录。首次运行发现：在回答框里输入就会让整个窗口变成空白（状态更新函数在 React 清空事件之后才读取它），已修正并加了全页面检查。尚未覆盖：真正的多因素服务器、堡垒机指纹。
  - 日志留证（2026-10-11）：日志分析里打开的日志文件可以直接“留存这个日志文件”，复用命令工作台的下载留证（原始字节、来源主机、时间、SHA-256、关联案件）；只对显示路径完整的文件提供，journal 不提供。九台靶机各 28/28。顺带修正：这个留证对话框以及文件操作菜单的样式原来放在命令工作台页面的样式表里，在日志页（以及先打开的文件完整性页）显示成页面下方的散文字，现在随组件一起加载。
  - 终端的中文输入法与显示尺寸（2026-10-11）：用 WebView2 的输入法通道（组字后上屏）验证了中文输入，ubuntu、alpine、rocky 各 12/12（`probe-terminal-ime.mjs`）。同时修掉三处所有终端窗口都有的显示问题：组字时终端框横向滚动、首列被遮住；网格按带内边距的外框和字体还没加载时的字宽计算，右侧约 5 列、底部几行一直被裁掉，长命令看起来像少了字符；修好后又露出 xterm 自带的黑色底条。现在终端挂在没有内边距的内层元素上、等字体加载后再渲染窗口、外框不滚动、底色跟随主题。
  - Java 热更新（2026-10-11 接通）：扫描 Java 进程、找到它们用的 JAR、选择本机 `.class`、出计划、确认替换、核对，并可从记录恢复原 JAR；只改磁盘上的 JAR，不重启进程。在本次运行创建的 Temurin 17 容器里 29/29（`probe-java-hot-update.mjs`），范围与边界见 `docs/JAVA_HOT_UPDATE_VERIFICATION.md`。验收中修正：替换后的 JAR 原来会变成 root 所有、权限 600（`jar uf` 写出的是新文件），以自己账号运行的应用重启后就读不了；现在换入前恢复原属主与权限，做不到就不换，两次回读都核对。2026-10-12 补上普通账号登录（同一探针 34/34）：首次实测发现普通账号的替换必然失败（备份目录固定在只有 root 能建的 /var/lib 下），现改为普通账号备份到自己主目录的 `~/.lovelyhawk-java-updates`；主目录是 `/` 的账号不生成计划并说明原因；属于其他账号的 JAR 不换入，回执写明原因、删掉为这次准备的备份。尚未实测：只装 JRE、Alpine/BusyBox、RPM 系、JDK 8/11/21、其他架构，以及真实应用服务器（Tomcat 何时关闭 `WEB-INF/lib` JAR、热部署是否自动重载）。
  - 终端窗口底部原来从第一帧起就写着“已连接”，打不开也一样；现在按会话实际状态显示“正在连接 / 已连接 / 未连接”，会话时间只在连接期间计时。打开文件或终端窗口失败的提示原来只在操作对话框里，没打开对话框时看不到，现在在文件管理里直接显示。

  取消正在进行的传输已在 2026-10-11 接上：下载时文件管理底部显示“正在下载 <文件名>…”和“取消下载”，上传执行中对话框左下角是“取消上传”。复制循环每一块之间、以及等待网络读写时都会检查取消开关（`SftpTransferCancel`），停下后先删掉写到一半的文件再回答：下载删本机文件，上传删服务器上的文件。下载的本机文件还有一层保护：请求在复制中途被丢弃（调用方不再等待）时，文件也会被删掉。后端到时限时改为先取消、给 15 秒清理，而不是直接丢弃复制。取消请求走单独的队列，不会排在它要取消的传输后面。仍有的限制：传输进行中连接断开时，服务器上写了一半的上传文件无法清理（连接已经没了）。九台靶机各下载一个 6 GB 文件并在 3～7 MB 时取消、上传 60 MB 并取消，均没有留下文件（`probe-sftp-transfers.mjs`）。文件列表里的大小也改为“6.0 GB”这种写法，精确字节数放在悬停提示和属性里。

  由操作员发起的撤销已在 2026-10-11 接上：删除、设置权限、重命名、新建文件夹核对通过后，回执上有“撤销这次操作”，10 分钟内可用一次，先问再做、焦点在“不撤销”；之后又有变化（比如原来的名字被别的文件占了）就拒绝。上传和打包不提供撤销：它们的核对只看存在或大小，同样大小的后续修改察觉不到，再删掉可能连带丢掉那次修改。编辑器保存和解压暂不提供，因为恢复之后还没有独立回读（`confirm_restored` 对这两类只报告“已按备份恢复”）。九台靶机见 `probe-sftp-transfers.mjs`。

  命令工作台的右键文件操作（2026-10-11）：“去掉执行权限”和“隔离”核对通过后，回执上多了“撤销这次操作”，完成后 10 分钟内可以用一次。撤销会先问一遍，说明文件会重新可以执行或回到原路径，焦点停在“不撤销”。撤销前 core 先重新核对文件：如果那次操作之后文件又被改过（权限变了，或原路径又出现了文件），就拒绝，不覆盖之后的修改；放回去之后再独立回读一次。验收见 `tools/lab/probe-emergency-path.mjs`（RPC）和 `tools/lab/probe-ui.mjs`（桌面窗口）。

  命令历史（2026-10-11）：用真实运行产生的记录验收通过（`probe-command-history.mjs`）。再次运行已接上，但不是“重放保存的命令”：新记录在占位串里记下是清单的哪一项检查（`# lovelyres emergency catalog entry: <检查>`，不保存命令全文和输出），详情里的“到命令工作台再次运行”会关闭面板、切到命令工作台，由后端在当前清单里找到这一项（`emergency-command.history.locate`，页面拿到的只是这份清单里的句柄，检查的标识不进页面），选中它并把焦点放在运行按钮上，由操作员按下运行。较早的记录没有记下是哪一项，界面会如实说明；当前目标的清单里没有这一项（比如给的是通用命令集）时也会说明。core 原有的 `plan_replay`（为只读命令生成重放计划）仍没有执行方，界面不提供。

  仍待完成：
  - macOS 的构建、打包与冒烟；Linux 页面、子窗口、对话框与剪贴板的实测（Linux 目前只在 Debian 12 容器中做过启动级冒烟）；
  - 干净 Windows 10/11 虚拟机上的便携包冒烟；
  - 缺少 WebView2 Runtime 时的表现；
  - 任务栏与 Alt+Tab 图标的截图核对（exe 内嵌图标已逐像素核对，见 `OPEN_ITEMS.md` 第 4 条）。

  Docker 页（2026-10-11）：容器内文件的编辑与复制已接线。core 原有的 `DockerFileWritePlan`/`DockerFileCopyPlan`（有上限的读取、写入前状态核对、备份与回读）现在有三个后端方法（`docker.container.file.read`、`plan-write`、`plan-copy`，确认与执行沿用容器动作的那两步），运行中容器的行上有“文件”入口。对着真实守护进程验收见 `probe-docker.mjs`。

  已在 2026-10-11 补上：编辑窗口的关闭握手（`OPEN_ITEMS.md` 第 19 条，`probe-editor-close.mjs`）；主窗口长命令期间终端不再卡住（第 18 条，`probe-terminal-during-long-task.mjs`）。

  Electron 时期的证据不能计入这些条目。架构见 [DESKTOP_ARCHITECTURE.md](DESKTOP_ARCHITECTURE.md)，发布流程见 [DESKTOP_PORTABLE_RELEASE.md](DESKTOP_PORTABLE_RELEASE.md)。
- 桌面数据库页已接入 PostgreSQL 原生参数读取及本机连接编辑；其余数据库工作流和完整
  迁移项仍 Pending。旧 GPUI 接线不能作为现行桌面证据。core 保留 MySQL 8.0.11–8.0.x/8.4.x、MariaDB
  10.11.x/11.4.x 与 PostgreSQL 16/17/18 community 的闭合身份/参数计划、有界 hex-TSV
  解析、未知值脱敏，以及目标和配置摘要校验。MySQL/MariaDB 的远端客户端路径继续拒绝密码配置。
- PostgreSQL 运行参数分支已改为 core 原生协议，经已绑定的 SSH `direct-tcpip` 通道完成认证，
  默认验证 TLS 证书链和主机名；明确选择 SSH 回环保护时只接受字面回环 IP。完整连接、查询和
  驱动共同受 actor 生命周期限制，等待中校验目标代次与配置摘要。当前没有独立的 PostgreSQL
  `CancelRequest`，流关闭后的服务端工作仍需受锁/语句时限约束并独立复核。实现与复现见
  [原生连接边界](POSTGRESQL_NATIVE_RUNTIME.md)，实际通过/失败记录见 [长期进度](PRODUCT_ROADMAP.md)。
  本机连接的版本比较、主机关联、宿主白名单/页面桥接层/renderer 有限契约和可取消任务已接线。服务端会话、
  十项参数来源及检查摘要留证继续由同一有限入口承载；摘要不包括全部参数、文件内容和来源路径。
  案件失败保留原记录并补存。相同 PID/网络/挂载命名空间中的 socket、父子进程与二进制对应现已接通，
  见 [主机进程对应](POSTGRESQL_PROCESS_CORRELATION.md)，缺工具/权限时仍保留参数和对应缺口。
  当前文件 HBA/ident 与角色直接属性诊断已接入同一原生任务及分页 API，见
  [访问诊断边界与实测进度](POSTGRESQL_ACCESS_DIAGNOSTICS.md)。缺权限、读取变化和超限单独展示，
  选项值、原始报错与口令校验值不进 DTO；v4 留证仅补充数量和提示代码；成员授权及静态继承/切换路径已接线。仍未实现原始认证文件词法、
  已加载策略匹配与具体对象授权，不能把现有直接属性当作完整权限检测。
  该历史观察不能直接授权后续处置；跨命名空间/代理适配、完整文件图与按实例修补仍待完成。
  通用 SQL、插件清单、账号与数据库管理、配置写入/恢复没有因此开放；旧密码 CLI 路径不能混入
  这个新入口。身份解析允许受限 Debian/Ubuntu 包标签并核对三处版本，但不能密码学证明“非 fork”。

- Nginx 全面可视化当前只编辑和安全另存单个本地文档；目标机 `nginx -V/-t/-T`、
  include 文件图、候选文件远端暂存、CAS 部署与恢复仍未接线。界面必须持续显示
  “尚未运行 nginx -t”，不得把通用语法树或静态提示当成目标二进制验证结果。
- Apache 全面可视化已接入本地配置生成器；远程 middleware 已具备独立的实例发现、有界
  `Include`/`IncludeOptional` 候选图、原生 `httpd -t`、全图/目录 CAS、备份验证与恢复流程，不能再
  记为这些能力全部缺失。但远程树仍是 `MiddlewareDocument`，没有与本地 `ApacheVisualDocument`
  合并为同一模型；更重要的是，当前 validator 没有绑定 MainPID 的精确 invocation、EnvironmentFile
  内容及原始有序 `-D/-C/-c` 上下文。Phase A 只落地 typed evidence 与 matching-endpoint graph seal
  合同，provider/transport 尚未接线，所以 Apache 远程 plan/execution 明确失败关闭；本地生成器和
  远程只读候选图只能显示“尚未运行目标校验”，不能显示为已部署。目标模块/静态指令 capability
  解析器也仍未接远端 transport 或桌面页面。
- MySQL option file、PostgreSQL conf/HBA/ident、通用 INI、TOML、Java properties、
  flat/whitespace 配置已经具备本地无损可视化；JSON 以及 YAML/XML 的可证明安全子集已接入
  source-backed 有序只读树。YAML 的 anchor/alias/tag/merge/flow/block scalar/directive/complex
  key 等高级构造，以及 XML 的 DTD/CDATA/PI/namespace/entity 等高风险边界，仍按最小可证明
  区域原子不透明保留；不透明区域默认遮罩且禁止普通复制，解析器不展开实体或访问外部资源。
  18 个经官方资料审校的版本化参数 schema 已接入配置生成器，但全部仍为 `Partial`，只提供
  精确路径元数据、风险/生效提示和提前脱敏；页面尚未通过目标实例回读证明版本、edition、
  capability 或参数值有效，因此这些 schema 不授予额外修改或部署权限。JSON/YAML/XML 结构
  变更、数据库运行时 SQL 修改/应用 UI、云参数 API、完整闭源厂商 schema 与目标回读 provider
  仍未接线；现有 RuntimeSql transport 与页面仅执行经过身份校验的闭合只读计划，尚无真实数据库
  验收。
  生成态 `mysqld-auto.cnf`、`postgresql.auto.conf`、Kingbase auto conf、OBD 注册状态与
  OceanBase 内部二进制始终只读。
- OceanBase P0 inventory catalog 已登记四个只读键：`oceanbase-observer-runtime` 通过
  `SHOW PARAMETERS` / `GV$OB_PARAMETERS` 盘点 observer 参数，`oceanbase-obproxy-runtime`
  通过 `root@proxysys` 的 `SHOW PROXYCONFIG` 盘点 ODP 参数；
  `oceanbase-tenant-variables` 限 CE 4.x MySQL-mode，通过 `SHOW GLOBAL VARIABLES` /
  `SHOW SESSION VARIABLES` 盘点租户变量，global 值仅影响新连接；
  `oceanbase-backup-archive-state` 只读 `DBA_OB_BACKUP_PARAMETER`、
  `DBA_OB_ARCHIVE_DEST`、`DBA_OB_BACKUP_JOBS` 与 `DBA_OB_BACKUP_JOB_HISTORY`。
  四项均声明 RuntimeSql+RuntimeReadBack+VendorSchemaRequired，不提供 mutation/activation；
  `observer.conf.bin` 继续为 GeneratedReadOnly。这仅完成 catalog rows；P0 provider、
  TargetGuard 前后校验接线与真实 readback 仍为 UNWIRED，真实 OceanBase / ODP 环境验收为
  NOT_RUN。
- TiDB 的 `tiflash.toml`、`tiflash-learner.toml`、`tiproxy.toml`、`ticdc.toml`、
  `changefeed.toml` 与 `tidb-lightning.toml` 已按六个独立组件登记并接入配置生成器的本地 TOML
  只读视图；TiCDC server 不再使用旧的泛化 `config.toml` 名称。它们保持
  `VendorSchemaRequired + VendorProcedure`，不会继承 TiDB Server 8.5.7 schema；TiProxy 版本必须
  独立匹配。当前只允许导入、逐字节预览和另存本地只读副本，starter、本地草稿、增删改移、应用
  与部署均关闭。精确组件版本 schema、目标路径/进程发现、厂商校验、健康回读、恢复演练和真实
  TiFlash/TiProxy/TiCDC/Lightning 集群验收均为 `NOT_RUN`。
- GBase 8a `gcware.conf` 的专用 source-backed 嵌套解析器已接入配置生成器目录与本地只读树，
  可逐字节展示官方风格的块与 `key: value` 项；未知边界失败关闭为不透明内容。它仍没有目标精确
  版本 schema、厂商校验、远端回读或部署链路，所以本地只允许导入、预览和另存只读副本；新建
  骨架、增删改移、应用及把副本标记为可部署配置均保持关闭，真实 GBase 8a/gcware 验收为
  `NOT_RUN`。
- GBase 8a 的 GNode/GCluster option 工件已按真实组件拆分；两份组件目录中的同名
  `cluster_common.cnf` 已登记为独立 `GeneratedReadOnly + JSON` 工件，不会继承 MySQL schema。
  它们当前仅供本地只读结构展示；目标路径发现、组件版本核验、厂商工具回读及集群级恢复仍为
  `NOT_RUN`。
- GBase 8s 已登记 `cmsm.cfg`、`concsm.cfg`、`gbasedbt.rc`、`~/.gbasedbt`、`ac_config.std`、
  `sm_versions`、`plconfig` 与 `IMCconfig` 的精确文件/角色身份，但这些复杂 VendorText 还没有
  专用 parser，因此仅 catalog 可见并不进入配置生成器 selector；不得用通用空白键值解析
  连接管理器块/宏、通信安全模块或工具专用参数。目前只有既有 `onconfig` 与五列 `sqlhosts`
  具备已证明的本地语法视图。`ac_config.std` 只是可发现的只读模板；PSM 目录、
  `ixbar.<servernum>` 与 `oncfg_<servername>.<servernum>` 恢复状态没有被误登记为文本配置。
  [GBase 8s 连接管理器](https://docs.gbasedbt.com/gbase8s/admin/ids_admin_1415.html)、
  [sqlhosts/通信支持](https://docs.gbasedbt.com/gbase8s/admin/ids_admin_0175.html)、
  [UNIX 环境文件](https://docs.gbasedbt.com/gbase8s/admin/ids_admin_0024.html) 与
  [ON-Bar/存储管理器文件](https://docs.gbasedbt.com/gbase8s/bar/ids_bar_288.html) 是当前官方工件身份依据；
  目标实例/路径发现、精确版本 schema、厂商 validator、部署、健康回读及恢复演练均为
  `NOT_RUN`。
- 神通产品目录已拆成 `ShenTongNative`、`ShenTongMpp` 和 `ShenTongOpenGauss`，三者都只声明
  `VendorNative`，当前零 artifact、零 parser、零 schema。虚构的 `shentong-server-config` 已删除；
  在没有现行交付证据前不写入 `oscar.conf` 或 `OSRDB.conf`。[官方产品中心](https://shentongdata.com/index.php/product/list-4)
  分开列出[自研内核](https://shentongdata.com/index.php/product/view-37)、
  [MPP](https://shentongdata.com/index.php/product/view-106) 与
  [openGauss 版](https://shentongdata.com/index.php/product/view-355)；
  [openGauss 发行版认证](https://opengauss.org/zh/certification/) 又显示同一神通 V7.0.21 产品版本名同时对应
  openGauss 3 与 openGauss 6 底座，因此不得按版本名猜测继承 openGauss 工件或 schema。完成条件是从
  [厂商文档下载](https://shentongdata.com/index.php/download/list-26) 与真实交付包取得 edition/版本/文件身份、
  建立专用 parser 与 schema，再运行厂商校验、部署及恢复矩阵；真实交付验收为 `NOT_RUN`。
- SequoiaDB quickDeploy 的 `sequoiadb.conf`、`mysql.conf`、`mariadb.conf`、`postgresql.conf`
  已作为四个独立 catalog 工件接入配置生成器；cluster 与 SQL instance 分别绑定专用 bracket-aware
  source-backed 只读方言，四份官方默认注释可见，`[host:port,host:port]` 不会被通用 CSV 逗号
  拆列。跨角色表头整份失败关闭为敏感 opaque；odd/even quote、坏方括号和未知记录布局只使当前
  物理行敏感 opaque，后续安全 sibling 仍可见。MariaDB 证据来自 SequoiaDB 官方仓库 `master`
  commit `6d49550`，尚未绑定 released version。四个工件继续保持 `VendorSchemaRequired`；当前没有
  匹配产品/精确版本 schema、可调用的厂商 validator、目标回读或远端 deploy 链路，因此 starter、
  全部结构 mutation、应用和部署均保持关闭，只允许导入、预览与另存本地只读副本；真实
  SequoiaDB/SequoiaSQL quickDeploy 验证为 `NOT_RUN`。
- YashanDB 23.5 的 `yasdb.ini` 已作为精确 `KeyValue` 工件接入本地只读可视化；exact
  v23.5.4.100 + `official-doc-family-23.5.4.100` 现在提供 15 项 root uppercase `Partial` 只读
  元数据与官方文档默认。该 guard 是文档证据族，不代表 Enterprise/AI edition 猜测；lowercase、
  未列和复杂但未审校参数保持 `VisibleUnvalidated`。选择 schema 不改变 `VendorSchemaRequired`：
  默认值不进入输入、原文、复制或另存，草稿、骨架、增删改移、应用和部署仍关闭。`yasdb.spfile`
  与 `yasdb.pwd` 继续作为不可文本读取的厂商二进制生成态。目标身份/路径发现、真实
  `ALTER SYSTEM`、实际值回读、厂商过程、恢复及真实 YashanDB 验证仍为 `NOT_RUN`。
- 分布式数据库的远端变更仍缺目标拓扑发现、逐工件 SHA/CAS、同版本厂商校验、灰度激活、
  集群健康回读和恢复演练，因此本地“安全另存”不得解释为 TiDB/OceanBase/DM 等产品已生效。
- DM8 的 `dm-thread` catalog 与 `dmthrd.ini` source-backed INI parser 已接入配置生成器，可提供
  本地无损草稿；`dmtimer.ini` 的 `REPEAT_INTERVAL` 分号值也已有回归覆盖。`dmthrd.ini` 仅在
  `dm.ini` 的 `DMTHRD_INI=1` 时使用；其参数 schema、目标 exact build 与 CPU 上下文、匹配 build
  的厂商工具校验、远端部署/激活及真实 DM8 验收均为 `NOT_RUN`。
- DM8 的 `dm-dcr-config`（`dmdcr_cfg.ini`）与 `dm-dcr-node`（`dmdcr.ini`）已失败关闭为
  `VendorText` + `VendorSchemaRequired`：前者的 `//` 注释、重复 `[GRP]` 及其 `[CSS]`/`[ASM]`
  成员必须作为有序原子结构处理，后者的 `DMDCR_*_STARTUP_CMD` 必须永久按命令载荷处理；当前仅保留
  catalog 与有界原始文本可读性，不进入结构化 selector，也不提供骨架、本地草稿或增删改移。专用 DCR
  parser/schema、匹配 exact build 的厂商校验、目标发现与 TargetGuard、部署/激活、恢复以及真实 DM8
  验收仍为 `UNWIRED` / `NOT_RUN`。
- 数据库 core 已有命令行、环境变量、systemd/service manager、厂商工具托管状态和 include 的
  有界来源/优先级图模型，但尚未接任何目标发现 provider，因此当前不能构建目标实例的完整图；
  `LosslessLocalDraft` 只表示本地无损草稿权限，不能把单个文件的内容显示为目标当前 effective
  state，更不能据此开放生成、应用或部署。
- Windows 10/11、混合 DPI、中文 IME、RDP、虚拟机、集显和完全离线启动必须使用同一二进制摘要采集真实证据；缺失项保持 `NOT_RUN`。
- OpenSSH/Dropbear、MFA、Agent、跳板机、SFTP 降级和网络故障矩阵必须在适用的 Linux/SSH 实验环境执行；被忽略的自动化测试不等于通过。
- 破坏性远端操作必须验证成功、非零退出、断连、并发变化、验证失败和恢复失败路径，不能只用 mock 结果作为发布依据。

相关验收契约见 [终端可行性门禁](../crates/lovelyhawk-terminal/FEASIBILITY_GATES.md) 与 [SSH 兼容性与安全策略](SSH_COMPATIBILITY.md)。

- `lovelyhawk-core::database_config_inventory`（owner：database core）已实现 MySQL/MariaDB plugin 与 MySQL component 的闭合只读 SQL plan、typed bounded snapshot、带唯一末行 `complete_v1` 的 headerless hex-TSV parser，以及共享 `DatabaseService` 的无密码 profile 只读路径。服务保存精确 runtime identity、完整 `TargetGuard` 与 profile digest，并在两阶段查询之间、返回前和消费前提供复核；密码 profile 在第一次 SSH 前失败关闭。尚未接入桌面页面或 core-owned native database protocol；完成条件是把 snapshot 接到桌面页面且页面只能读取 `public_value()`，并覆盖 MySQL 8.0/8.4、MariaDB 10.11/11.4 的真实权限、空表、重复行、超限、取消与目标切换矩阵。`complete_v1` 只用于发现普通截断，不能把恶意服务端变成可信来源。真实数据库验收仍为 `NOT_RUN`，且本模块不授权任何安装、卸载或其他 mutation。

## Electron 迁移期切片接线状态

### 2026-08-27 移除的四个切片

边界隔离（firewall）、取证快照（snapshot）、中间件（middleware）、多机批量（batch-servers）
按需求整体移除。下文里凡是描述这四个切片的段落只保留历史记录，**不再对应任何现存代码**：
它们的页面、契约、preload 方法、主进程 IPC、后端 RPC 与 `lovelyhawk-core` 里只被它们用到的
`firewall.rs`/`snapshot.rs`/`batch.rs` 都已删除。它们提到的"仍待实机验收"因此一并作废，
不需要再排期。`middleware.rs` 与 `middleware_document.rs` 保留——那是配置生成器的产品路径
知识，跟中间件页面无关。

### 已中央接线但仍为 Pending

- SSH terminal 已不再是 `UNWIRED`。（以下窗口、main/preload 与 CSP 描述为 Electron 时期的接线；现由
  `crates/lovelyhawk-desktop` 的子窗口与终端命令、`ui/src/host/terminal-api.ts` 承担同样职责。）
  `crates/lovelyhawk-backend/src/terminal_api.rs` 的七个固定
  内部 RPC 已实例化到 `BackendState`；main LovelyRes preload 只新增零参数 `openSshTerminal()`，当前总公开面
  精确为 81 个方法，而独立 `terminal.html` renderer 只得到 `open/poll/input/resize/search/copySelection/close`
  七个无 handle 方法。binding、session、guard、host、command、launch token 与 backend terminal handle
  始终由 main/Rust 持有，不进入 URL、argv、window.name、DOM 或 renderer state。main 以 binding + window kind
  为 key 创建 hardened `BrowserWindow`，重复入口聚焦现有窗口；新 binding、disconnect、窗口关闭、backend
  shutdown 和打开失败都会先使上下文失效并 best-effort 关闭 terminal，迟到结果失败关闭。
  选区复制只在已打开 terminal handle 上接受非空、最多 128 KiB UTF-8 纯文本并调用 main
  `clipboard.writeText`；按钮和有选区的原生 copy 事件共用同一个有界 helper，无选区 Ctrl+C 不被 copy
  边界吞掉。没有 navigator clipboard、renderer fallback、readClipboard 或新增 paste preload。
  exact `lovelyres://app/?window=terminal` 映射到独立本地 entry；xterm DOM renderer 所需的动态尺寸/主题 CSS
  仅在该文档允许 inline style，main App CSP 和 terminal script CSP 均未放宽，全部资源仍为
  `lovelyres://app`。当时的 Electron-native CDP 证据位于
  `target/electron-debug/526e344c-a5f5-499d-9a17-ab4c0bf4defe/evidence`，验证当时的 pre-LogAnalysis main API、terminal exact7、
  未授权真实窗口全方法失败关闭、零泄漏、local-only resource tree、零 console error、capturePage 和销毁。
  条目仍为 `Pending`：真实 SSH/PTY 的成功 resize/input/poll/search/copy/close、生产 keyed reuse/focus/disconnect、
  OpenSSH/Dropbear/auth/MFA、IME/CJK、网络故障及 packaged Windows/macOS/Linux 生命周期矩阵均为 `NOT_RUN`，
  tabs、completion、directory launch 和 AI parity 也尚未达成，不能据此宣布 SSH terminal 完成。
  （2026-10-13 补记，Tauri 外壳）多标签页（`desktop-terminal-tabs-2026-10-13`）、文件夹终端和终端里的
  “AI 解释选中内容”（`desktop-terminal-ai-2026-10-13`）已接线，并在 lab-super 的真实窗口里实测；命令补全仍未做，
  SSH 兼容矩阵、打包生命周期以及容器/Pod/文件夹窗口里的 AI 控件仍为 `NOT_RUN`，条目仍为 `Pending`。

- 通用 Middleware 远程编辑器仍为 `UNWIRED`；普通 Nginx 进程的三项有限修补已接线（2026-09-08）。本目录历史上记载的
  `middleware.discover`、`middleware.configuration.load`、`middleware.history.list` 及对应三个 preload
  方法在 Electron 时期的 `crates/lovelyres-electron-backend`、`electron/src` 中已不存在，在当前
  `crates/lovelyhawk-backend`、`ui/src` 中同样不存在，旧 CDP 路径不能证明当前接线。
  当前实际入口是“配置 → 修补已有配置”，经 `nginx.repair` 闭合 RPC 接入实例发现、配置图中的
  `autoindex`/`server_tokens`/`ssl_protocols` 指定节点、精确差异与逐次确认、原子写入、原生检查、进程切换、历史和恢复。
  原生 CDP 与独立 HTTP 实验（Electron 时期）已覆盖真实修补、取消、恢复、并发文件保护和断连，证据见
  `NGINX_PROCESS_REPAIR.md` / `PRODUCT_ROADMAP.md`。该入口不接受任意配置文本、路径或命令。
  目标本机监听的 TLS/证书/HEAD 复核及完整案件留证现已接通，含保存失败保留、只补存原记录、案件入口、报告和离线 JSON，见 `NGINX_CONNECTIVITY.md`。
  Apache/Tomcat 等其他产品的远程编辑入口、多发行版/版本/架构、systemd 定制启动、rootless、只读容器、
  业务客户端路径、前后观察与处置计划的自动关联及业务恢复判定仍待完成，不能由本次有限 Nginx 能力推断为已接通或已验证。

- 命令审计 / Check Audit 只读 Phase 1 已不再是 `UNWIRED`。`check-audit.catalog.get`、
  `check-audit.status.collect` 与 `check-audit.log.read` 三个固定 RPC 已进入中央 `BackendState`、main、frozen
  preload、aggregate `LovelyResApi` 与 `App` registry；renderer 页面只接收 opaque `bindingHandle`，日志读取
  继续使用 target-scoped opaque snapshot capability，不接收 session/guard/generation/identity、shell、远端路径、
  摘要或备份位置。adapter 只调用 core `AuditService` 的固定目录/status/log/analyze 路径，并在请求前后复核
  完整 target scope；SSH disconnect 会先 `close_binding`，迟到结果失败关闭。当前公开 API 仅为
  `getCheckAuditCatalog`、`collectCheckAuditStatus`、`readCheckAuditLog`。同一 pre-LogAnalysis CDP 证据已验证伪造/
  unknown 参数拒绝且不回显、断连页无命令/日志行、本地资源、卸载重挂载后仍无远端行、capturePage 与
  0 console errors。页面仍为 `Pending`：真实 Linux/SSH/auditd 未安装、权限拒绝、日志缺失/畸形、断连与
  target-switch 矩阵为 `NOT_RUN`，deploy/restore/clear-log、plan/confirm/execute、file/terminal/export 仍待迁移。

  2026-10-11 在 Tauri 外壳下用真实主机重新验收（`tools/lab/probe-check-audit.mjs`，九个发行版各自新建一次性容器，root 与普通账号 deploy 各连一次），并修正了几处会误导判断的地方：
  - 日志原来只要不是可读的普通文件就当作空日志，“没有日志”“日志位置被换成指向 /etc/shadow 的符号链接”“当前账号读不了”和“日志是空的”在页面上都是同一句“没有匹配日志”。现在 core 先报告日志位置的实际状态，页面在日志、周期分析和建议三个标签页都说明原因，并写明没有读到不代表没有记录；符号链接不跟随，/etc/shadow 的内容不会出现在页面上。
  - 日志里不是审计记录的行原来要么被静默丢掉，要么显示成英文的解析错误。现在按原样列出、标为可疑并计数，不计入命令统计和周期分析。
  - 命令状态原来把“没有本工具的采集包装的程序文件”叫做“原始二进制”，被替换过的程序也会这样显示。现在叫“未加采集”，并写明这不代表文件没被篡改；执行的是脚本的命令单独点名。
  - EL9 及其衍生发行版（Rocky、Alma、Anolis 镜像）的 cat、head、tail 是单文件 coreutils 的一行转接，原来被当作“未知脚本”。现在只认发行版写的那一行，而且 /usr/bin/coreutils 本身必须是非脚本的普通文件，单独标为“转到 coreutils”。判断脚本时 `file` 的输出原来带着文件名，名字里含 text 的程序也会被当成脚本，已改用 `file -b`。
  - 侧栏原来叫“核查审计”，说明写的是“核查账号、服务、网络与安全配置”，与页面实际内容不符，已改为“命令审计”。
  - 补回旧页面的“复制 TSV”：日志标签页可以把显示的记录按制表符分隔复制到剪贴板（字段里的制表符、换行写成 `\t`、`\n`，不丢内容；超过 128 KB 时说明原因、不复制；只复制显示的部分时写明还有多少条没复制）。
  2026-10-12 第二阶段接通：加采集、移除采集、清空日志。
  - 后端 `check-audit.action.plan/confirm/execute/cancel`（`crates/lovelyhawk-backend/src/check_audit_write_api.rs`），页面只按命令列表的句柄点名命令，计划由 core `AuditService` 生成（只接受“未加采集”的程序加采集、只接受本工具加的采集移除），确认绑定这一个计划、执行一次、读回核对，失败按计划换回；断开连接时丢弃未执行的计划。非 root 且不能免密码 sudo 的账号在生成计划前就被告知，什么都不做。
  - 页面“命令”标签选中命令后有“加采集… / 移除采集…”，“日志”标签有“清空日志…”；确认框列出计划全文、涉及的命令、对目标的影响和失败时怎么换回，默认焦点在“取消”。回执说明是否已读回核对。
  - 实机首次运行发现并修正三处：部署脚本对没有 SELinux 标签的主机也调用 `chcon`（Ubuntu 上因此永远加不上采集，已改为只在 SELinux 启用时调用）；`chmod/chown --reference` 与 `cp --preserve=all` 是 GNU 才有的写法（Alpine/BusyBox 上失败，已改为 `stat -c` 取值与 `cp -p` 兜底）；BusyBox 主机上 `ls`、`cat`、`sh` 都解析到同一个 `/bin/busybox`，原来被当作普通程序，加采集会把整个 BusyBox（连同 sh）换成记录脚本——现在单独标为“BusyBox 等多合一程序”，不提供加采集，计划阶段也拒绝。
  - 验收：`LAB=<发行版> pnpm lab:check-audit-actions` 九个发行版全部通过（每台 26 项，Alpine 另有 BusyBox 两项共 28 项）：计划不改动主机、未确认不执行、同一计划不能执行两次、加采集后原程序按字节留作备份、普通账号运行命令被记录且页面读回、再加采集被拒、移除后原字节回来且备份删除、清空日志后旧日志改名保留、伪造句柄与路径被拒；`LAB=ubuntu|alpine pnpm lab:ui-check-audit-actions` 真实窗口 14/14。
  仍未完成：一次选多个命令批量加采集的页面入口；SELinux enforcing 主机上的实测（容器靶机没有 SELinux）；页面只读本工具包装写的日志，不读系统 auditd。

### 尚未中央接线或仍待完整验收

以下条目同时记录仍为 `UNWIRED` 的入口，以及已经中央接线但因实机、mutation/remediation、持久化或
packaged 验收不足而继续为 `Pending` 的切片。每一条都必须按其明确状态解读，不能因为源码、测试或
某一阶段接线存在就把整个页面或 overlay 标记为完成：

- **容器运行时不再写死成 Docker（2026-08-27）。** 后端原来在六处硬编码
  `ContainerRuntime::Docker`，核心声明支持 Podman 却没有任何地方会选它——**在只装 Podman
  的机器上，Docker 页的每个问题都返回空**，读起来像"这台机器没有容器"，是最坏的一种错答案。
  国产发行版与 RHEL 系（openEuler、Anolis、AlmaLinux、Rocky）默认就是这个形状。
  现在开快照时探测一次（`DockerService::detect_runtime`），把结果随快照带下去，之后每次
  调用都用它；"没装任何运行时" 与 "装了但不响应" 分成 `docker-runtime-absent` 与
  `docker-runtime-not-running` 两个答复。容器动作也跟着走对——身份里带着运行时，所以
  Podman 主机上生成的是 `podman stop`。

  同轮修掉解析层的一串 Docker 形状假设：`Id`/`ID`、`Names` 数组、`Status` 空而值在
  `State`、`CreatedAt` 空而值在 `Created`、`Ports` 结构化数组、`Command` 数组、网络清单
  的全小写下划线键。另外 SSH 层把 stderr 并进 stdout，Podman 在 cgroups-v1 主机上每条
  命令先打一句弃用告警，三处解析器（逐行 JSON、整体 JSON 数组、`id<TAB>状态`）都因此
  全盘失败；规则改成"不以 `{` 开头的行跳过，以 `{` 开头却解析不了的仍然报错"。
  验收靶机 `svc-podman`（AlmaLinux 9 + Podman，构建时断言机器上没有 `docker`）与
  `tools/lab/probe-podman.mjs`。**未覆盖**：`podman stats` 在这台嵌套 cgroups-v1 靶机上
  读不到 cgroup，探针明确标注不覆盖，真实主机上没有这一层。

- **Kubernetes 工作负载动作（2026-08-27）已中央接线**，preload 从 113 变 117：
  `planKubernetesWorkloadAction` 等四个方法。渲染层只发行句柄与三种闭合形状之一
  （`scale-deployment` 带副本数、`cordon`、`uncordon`），namespace、名称、UID 都到不了它
  手上；核心的比较-并-设置补丁、日志、回读复核与按精确 revision 回滚原样复用。
  同轮修掉一个**做成了却报没做成**的问题：`kubectl patch` 少了 `-o json`，kubectl 打印
  一行 `deployment.apps/ledger patched`，调用方按 JSON 解析失败，于是整个流程报错——而
  补丁其实已经生效。操作员看到失败会再做一次。验收见
  `tools/lab/probe-kubernetes-action.mjs`。

- **Kubernetes 只读路径（2026-08-27）第一次对着真集群跑过**，并查出一个从这个页面存在起就有的问题：
  `crates/lovelyhawk-core/src/kubernetes.rs` 的 `RawPodStatus` 用 `rename_all = "camelCase"` 把
  `pod_ip` 变成 `podIp`，而 Kubernetes 发的是 `podIP`——**Pod 列表的地址列在任何真实集群上都是空的**。
  原解析测试的 fixture 里写了 `podIP`，但只断言行数和 id，所以一直没抓到；现在补了逐列断言的
  `a_populated_pod_row_carries_every_column_it_was_given`。靶机与探针见
  `tools/lab/orchestration/`、`tools/lab/probe-kubernetes.mjs`。Kubernetes 的写路径
  （Deployment 扩缩容、节点 cordon/uncordon）核心里有，仍未接线。

- 全局取消按内容遮蔽（2026-08-25）：sidecar 与渲染层契约里按 credential 词形（`password=`、`token=`、
  `bearer `、URL userinfo 等）遮蔽或拒绝的实现已全部移除，涉及 baseline、check-audit、docker、integrity、
  kubernetes、middleware、packet-capture、snapshot、log-analysis 九处。取证快照原先有七个采集器整段只返回
  marker——进程、登录历史、计划任务、authorized_keys、sudoers、最近修改文件、环境变量——正好是事后第一批要
  看的东西，现在按采集内容原样返回。渲染层契约那份过滤比 sidecar 更糟：它拒绝整个响应而不是一行，一条
  credential 形状的日志就能让整页读不出来。
  保留的仍是能力擦除：DTO 里绝不出现 binding/session/connection handle、target identity、快照 id 与
  host key fingerprint；控制字符净化与体积上限也保留。应用日志（`diagnostic_log_api`）是 LovelyHawk 自己的
  tracing 环，不是目标采集输出，其遮蔽保留，避免把操作者自己的口令写进本地日志。
- 快速检测（Quick Detection）已整体移除：sidecar 的 `quick_detection_api.rs`、七个 RPC、
  main/preload 的七个方法、`quick-detection-contract.ts`、`QuickDetectionPage.tsx` 与其状态/助手/
  样式文件、以及对应的门禁与 CDP 场景都已删除。主窗口 preload 面因此从 118 收到 111，页面注册表
  从 20 收到 19。core 的 `detection.rs` 保留：baseline、compliance、report 与 services 仍在用它。
  该切片在 ledger 的 `pages` 中不再存在；`verificationRuns` 里的历史记录按原样保留，因为那些运行
  当时确实发生过。
- **Docker 容器动作（2026-08-27）已中央接线，并且是第一条在真 daemon 上跑通的写路径。**
  `crates/lovelyhawk-backend/src/docker_write_api.rs` 新增，preload 从 109 变 113：
  `planDockerContainerAction`、`confirmDockerContainerAction`、`executeDockerContainerAction`、
  `cancelDockerContainerAction`。渲染层只发容器句柄（由自己那份快照发出、由只读侧在同一套
  scope/token/过期规则下解回身份）和一个闭集里的动作词；容器 id、运行时动词、命令都到不了它手上。
  计划有 5 分钟 TTL，确认与执行是两次调用，执行时计划先离开 registry 再 await，所以一个计划最多跑一次。
  核心的 plan→confirm→execute→journal→verify→restore 原样复用，回执给的是**复核读回的状态**，
  不是命令的退出码。

  同轮改掉三处只有对着真机才会暴露的问题：`probe_state` 的 `--format` 里写了裸 `\t`，Go 模板原样
  打印成反斜杠加 t，解析器按真 tab 切分——**任何容器动作在真 Docker 上从来没能通过状态探测**；
  计划摘要与回滚说明是英文且带 64 位全长容器 id，现在是中文短 id；验证回执 `observed container
  state: ...` 也改成中文。验收证据是 `tools/lab/probe-docker-action.mjs`，在 `svc-docker` 上覆盖
  计划→未确认拒绝→确认→执行→主机侧独立复核、同计划不能跑第二次、状态不符时计划阶段就拒、伪造句柄
  解不到东西、达不到目标状态时验证判失败并回滚、取消。

- **系统信息表格的右键菜单（2026-09-02）已接线：核心里按行的排查与处置动作，界面上终于能点到。**
  `lovelyhawk-core::system_info` 早就有一整套按标签划分的按行动作——进程 40 项排查加
  SIGTERM/SIGKILL、服务 19 项排查加启停/启用/禁用、用户与登录历史的账户锁定/解锁、
  网络/外连/开放端口 19 项排查加断开 TCP 连接、计划任务/定时器/SSH 密钥/SUID/
  sudoers/内核模块/环境变量/软件包/Shell 配置各自的排查，以及删除独立 cron 文件、
  注释 Shell 行、去 SUID 位/权限隔离、内核模块黑名单这几项改动——request builder、
  plan/execute、journal、verify、restore 全写完测完了，但没有任何调用方。现在后端多一个
  `system_info_action_api.rs`：动作用闭集 key 寻址（`process.open-files`、
  `process.signal.kill`、`network.disconnect`……），key 直接由核心枚举的 serde 名生成，
  解析不回来的就是不存在；**哪些动作对这一行可用，由后端拿它自己保存的快照按行算出来**
  （request builder 是纯函数，不碰目标机），所以 UDP 行没有"断开连接"，已经是注释的
  Shell 行没有"注释此行"，用户名不合法的行什么都没有。6 个 RPC / IPC / preload 方法：
  `listSystemInfoRowActions`、`inspectSystemInfoRow`、`planSystemInfoRowAction`、
  `confirmSystemInfoRowAction`、`executeSystemInfoRowAction`、`cancelSystemInfoRowAction`，
  preload 从 118 变 124。渲染层只会说"这个快照的这一行、这个 key"——没有 PID、
  单元名、路径、命令穿过边界；改动类动作走 plan → confirm → execute 三步、计划句柄
  一次性、5 分钟过期、断开连接时连同快照一起清掉。右键菜单本身还带三个本地项：
  复制这一格、复制整行、查看详情；Shell 配置那种按文件显示的标签，每一行也能右键。
  真实靶机上的执行路径（尤其是断连、锁账户、去 SUID 位）仍待实机验收；
  当前证据是后端 6 个模块测试 + 1 个 RPC 级拒绝测试、渲染层契约/菜单/对话框测试、
  主进程边界测试和源码门禁。

  **删除用户账户（2026-10-12 接线，实机待验收）**：用户标签的"处置"里在锁定/解锁之后多了
  "删除用户账户"（`account.delete`），沿用同一条 plan → confirm → execute → journal → 回读链路。
  只删账户记录：有 `userdel` 用 `userdel`，否则用 BusyBox `deluser`，都不带删除主目录的参数。
  普通账户从不用 `userdel -f`——还有进程时 userdel 拒绝，回执说明"仍然存在，没有改动"和原因
  （退出码 8 = 有进程，77 = 无 root/免密 sudo，78 = 两个工具都没有，79 = root 已不是 UID 0）。
  root 本身不提供删除；**除 root 外的 UID 0 账户（最常见的后门）可以删除**：它与 root 共用
  身份，userdel 会把 root 的进程算成它的而永远拒绝，所以只对这种账户用 `userdel -f`（只跳过
  进程检查，不带 `-r`，不删文件；计划里说明部分旧版会一并删除 /var/mail 下同名邮件文件）。
  每次删除下发前先确认 root 仍是 UID 0，删除 UID 0 账户后再回读 root，不是 UID 0 就判失败并
  提示保留现有连接人工检查。当前 SSH 登录账户在计划时拒绝，按 sshd 设置的
  `LOGNAME`/`USER` 判断（两个 UID 0 账户时 `id -un` 分不清是谁）；登录历史不提供删除。
  同日起用户表里除 root 外 UID 为 0 的行标为"高危"（仅 GID 0 不标，部分发行版的
  sync/shutdown/halt 本就在 0 组）。计划不声称可恢复（无恢复描述，
  确认框显示"无备份，执行后不可自动还原"）：口令哈希不保存，UID/GID/主目录/Shell/所属组记入
  操作日志供手工重建。UID < 1000 时计划提示"通常是系统或服务账户"。删除后只回读一次：
  userdel 返回即已完成，RPM 系每条命令约 11 秒，轮询会越过 120 秒执行时限。
  证据：core 15 个账户测试（含 shell 注入、普通账户不带 -r/-f、UID 0 账户只加 -f 且前后核对 root、root/登录历史/会话账户拒绝、UID 0 行标高危、
  不可恢复与回读不存在、未删成时如实说明且不再执行任何命令）。
  **桌面实测（2026-10-12，alpine 3.20 + shadow 的 userdel，以带免密 sudo 的普通账户登录）**：
  经真实窗口右键 → 处置 → 删除用户账户，删掉植入的 UID 0 账户 `sys-update`：计划写明
  `userdel -f` 与不可恢复，回执"已不存在（已回读核实）"，目标机上 root 仍为 UID 0、主目录保留；
  删除当前登录账户被拒绝并说明原因；锁定普通账户经 sudo 完成并回读核实。同轮修掉两个只在
  非 root 会话出现的缺陷：账户快照里的 `passwd -S` 读别人账户需要 root，原先不经 sudo，
  锁定/解锁/删除对普通 sudoer 一律在计划阶段失败；拒绝原因（当前登录账户、root、已是该状态）
  原先都显示成"状态或可用工具不满足前提，见应用日志"，现在各有代码与说明。
  **仍缺**：BusyBox `deluser`、有进程的普通账户（userdel 退出码 8）、无 sudo、NSS（LDAP）账户、
  RPM 系（11 秒/条）与 Debian 系 shadow-utils 未实测，不能计为通过。

- **主机全景的搜索与筛选（2026-10-12）**：每个表格标签（含按文件显示的 Shell 配置）都有
  搜索框（不分大小写，空格分隔的多个词须全部命中，可在"在"里限定某一列）、级别筛选
  （全部 / 注意及以上 / 只看高风险，带各自计数）、"显示 n / 共 m 行"、无结果时的说明与
  "清除筛选"，Esc 清空搜索；筛选按标签分别保留、换目标清空；"复制表格"复制当前显示的行并
  注明是筛选后的。只在已读到的行里找，超过 500 行截断时照样提示。用户表里除 root 外 UID 为 0
  的行标"高风险"。实测：上面的 alpine 靶机上真实窗口 22 项 CDP 检查全过（用户表、进程表、
  列限定、空结果、按标签保留、筛选后复制、删除流程中页面最长无响应 481ms）。
  同轮发现并修复：BusyBox `ps` 不支持 `pcpu/pmem/etimes/--no-headers`，进程表在
  Alpine 等精简系统上整表为空并显示"没有这类条目"，现在退回直接读 /proc（同样的列，%CPU 按
  procps 的定义）。同一靶机上系统服务、自启动、计划任务、登录历史、Sudoers、内核模块仍显示
  "没有这类条目"，其中 Sudoers（非 root 读不到）与计划任务（未读 /etc/crontabs）可以确定是
  把缺口说成了没有，已另立任务处理，不能计为通过。

  **九发行版实测（2026-09-02）暴露了三个真问题，都已修：**

  1. **RPM 系四台（Rocky/Alma/openEuler/Anolis）的处置动作 100% 失败。** 这四台镜像
     **每条 SSH exec 固定 ~11 秒**（Debian 系/SUSE/Alpine 只要 50–95ms，容器新起也一样，
     是 sshd/PAM 自身开销），而 `lovelyhawk-core` 里六处前置快照与一次性下发——进程身份、
     服务状态、账户状态、网络连接快照，以及 `kill -s` 与断连的下发——预算写死 10 秒，
     全部超时。九台里四台的**每一个**处置动作都不可能成功。六处改用 `PRECONDITION_TIMEOUT`
     （20 秒，与只读排查的 15–30 秒对齐）。这个耙子踩过第二次了：2026-08-26 命令目录
     也是被同一个 10 秒预算卡空的。
  2. **超时被说成"这个操作已经不适用于这一行了"。** 核心的 `command_failed` 把"目标机没回话"
     和"目标机拒绝了"折叠成同一个 Validation 错误，sidecar 一律映射成 action-unavailable。
     结果是：主机只是慢，界面却告诉运维"行的状态变了，刷新后再看"——指挥人去查一个根本没
     发生的变化。核心导出 `COMMAND_TIMEOUT_MARKER`，sidecar 把带该标记的失败映射成超时文案。
  3. **主机全景一打开就在后台采集"进程详情"，点开该标签又采一次。** 用户还停在摘要页，
     500 行进程扫描已经发出去了；随后点开标签触发第二次采集，两次并发。后落地的那次
     （不一定是新的那次）会替换快照，静默关掉已打开的行菜单——在进程多的主机上必然发生。
     改：摘要页激活时不采集；每次采集编号，被取代的响应不再落地（`tableRequest`）。

  修完之后九台全绿：`pnpm lab:ui-system-info`（`LAB=<发行版>`）在
  ubuntu/alpine/debian/deepin/suse/rocky/alma/openeuler/anolis 上各 26 项断言全过，
  含在每台上真实执行并核对 SIGKILL。截图落在 `target/lab-ui-system-info/<发行版>/`。

  **非 systemd 主机的"自启动"曾经一个动作都给不出，已补上排查词汇（2026-09-02）。**
  `pnpm lab:row-actions` 逐台问后端"每个标签的行能拿到哪些动作"时发现：RHEL 四台与 SUSE 的
  自启动行是 systemd 单元，各 21 个动作；而 Ubuntu/Debian/deepin/Alpine 的行来自 `/etc/init.d`
  或 `/etc/runlevels`，核心的启动项排查（18 项）与服务运行时动作都要求行的类型是 `systemd`，
  于是这四台上自启动标签**列得出行、右键一个动作也没有**。

  核心新增 `ArtifactIdentity::StartupScript`（脚本名 + 引导目录实际指向的路径）与
  `startup_script_investigation_command`：18 个问题里 16 个用读脚本、读引导链接、读设置文件、
  读日志的方式回答；开机耗时与资源占用只有 systemd 的记账答得出，由
  `StartupInvestigationAction::applies_to_script` 在**请求构建阶段**就拒掉——放到命令阶段拒
  会让菜单先给出再失败，比不给更糟。引导链接指向 `/etc/init.d` 之外时不隐藏，反而明说
  "OUTSIDE the standard boot script directories"，那正是值得点开的一行。

  写这段时踩到两个通用坑，都已在代码注释里写明原因：**`stat -c` 不解释 `\t`、`%n` 是文件名不是
  换行**（原样式输出会变成 `Owner\troot:root/etc/init.d/cron...`），改用一个分隔符加一次 awk；
  以及**管道后面的 `|| printf` 永远不触发**（管道退出码是 `head` 的，空输入也成功），12 处
  "没匹配到"提示全部不可达，改成先把输出收进变量再判空。第二个坑与 2026-08-26 记录的
  journalctl 空输出是同一类。命令在 dash、bash、busybox ash 三种 shell 下 `sh -n` 全过。

  **处置那一半也补上了：非 systemd 主机的自启动行现在能"禁用开机自启"（2026-09-02 同日）。**
  核心新增 `BootScriptRuntimeRequest/Plan/Outcome` 与 `BootScriptRuntimeExecutor`，走的是
  systemd 那条一模一样的 plan → confirm → execute → journal → verify → restore 流水线，
  但读的东西不同：systemd 问 `systemctl show`，脚本这边读**引导目录里的启动链接**。
  `SystemInfoTable::runtime_change_request` 按行的类型把同一个菜单项分给两条路，
  渲染层与 preload 一个字没改（动作 key 仍是 `service.runtime.disable`）。

  三个设计判断，每个都有实测支撑：
  - **只做"禁用"，不做"启用"，也不做"启动"。** 自启动标签是用"已经会开机启动的东西"建出来的
    （systemd 取 `--state=enabled`，脚本取启动链接），所以每一行天然都是启用状态，
    "启用开机自启"必然是空操作。`ServiceRuntimeAction::AUTOSTART` 因此从
    `[Start, Enable, Disable]` 收成 `[Start, Disable]`——**这条同时修正了 systemd 那半边**，
    以前它也在给一个只会被拒的选项。启动一个脚本需要有个正在跑的服务管理器接手、
    事后还要有东西能回读是否生效，脚本两样都没有，直接拒。
  - **"在开机序列里"的判据是有没有启动链接（S 链接）**，而不是有没有任何链接。
    `update-rc.d x disable` 会把 S 链接改成 K 链接而不是删掉，只看"有没有链接"会判错。
  - **没有引导链接工具的主机，拒绝而不是猜。** Alpine 那台的链接是手工建的，
    `rc-update`/`update-rc.d`/`chkconfig` 一个都没有；核心如实拒绝，主机一个字节没动。

  顺带修了一条文案：这类前置条件拒绝以前一律说"目标机上的状态可能变了，刷新后再看"，
  但"这台机器没有可用工具"也是这条路径，说"状态变了"是在撒谎。现在说
  "状态或可用工具不满足前提，具体原因见应用日志"——真正的原因已经进了诊断日志。

  实测（`pnpm lab:boot-script-runtime`，自己种一个 `lovelyres-probe` 引导脚本，
  全程不碰靶机上任何真服务）：**Ubuntu / Debian / deepin 三台用 update-rc.d 完整跑通**——
  计划里列出四条 S 链接、确认、执行、回读核对、靶机上链接确实消失、该行随即离开自启动标签、
  用过的计划句柄不能再执行一次；**Alpine 正确拒绝且主机未变**；RHEL 四台与 SUSE 的自启动表
  走 systemd 分支、根本不列引导脚本，探针如实跳过。
  **chkconfig 与 rc-update 两条分支写了但没有实机验证**：靶机里有 chkconfig 的那几台
  自启动表都走 systemd，而没有任何一台跑 OpenRC。上赛场前这两条仍须按铁律在 VM 实测。

  同类观察：服务标签在这些主机上照常给 25 个动作，但容器里没有 systemctl，真正执行的行为未验证。

  另外记录两条环境事实，不是产品问题：容器 PID 1 是 `sleep infinity` 不回收子进程，
  反复测试会攒出几百个僵尸（Rocky 一度 557 进程里 545 个僵尸），把 500 行上限撑爆；
  以及一个 wsl.exe 都不剩时 docker 守护进程和容器几秒内就没，表现为绑定随机失效。

- **Docker 容器终端（2026-08-27）已接线，是核心早就写好、界面上一直没有的第一件。**
  核心的 `DockerService::open_terminal` 与 `TerminalLaunch::ContainerExec` 存在已久，
  但从来没有任何调用方——一整条 PTY 路径写完了、测过了、没接过。现在
  `docker.container.terminal.open` 一个 RPC 打通：只读侧把容器句柄解回身份，核心探出这个
  镜像里真有的 shell，终端 registry 照常开一个槽。preload 从 117 变 118，只多
  `openDockerContainerTerminal` 一个方法——**渲染层给不出 shell，也给不出容器 id**，
  它只能开一个窗口。终端窗口自己的那套 API 一个字没改：窗口是什么类型在创建时就定死了，
  窗口里的渲染层只会说"给我开个终端"。窗口按 binding + 容器句柄分别记名，所以宿主 shell
  和容器 shell 可以并排开着；断开连接照旧把这个 binding 上的窗口全带走。

  新增 `DockerService::detect_shell`：按 `bash → ash → sh` 探一次。写死 bash 在
  busybox 镜像上必挂，一律用 sh 又白扔掉有 bash 那些镜像上的行编辑与历史。

  同轮查出三个只有真开一个 shell 才会暴露的问题，都记在
  `tools/lab/orchestration/README.md`：**终端 id 由核心自己造，而调用方拿自己登记的 id
  核对每条事件——开得起来，第一次 poll 就报协议违规，窗口当场死**；**停着的容器被答成
  "这个镜像里没有 shell"**，把人打发去重建镜像；**靶机十六个容器全是 alpine，"优先挑 bash"
  这条分支在真机上从没走过**（现在加了 `app-shell`，Debian 的）。验收证据是
  `pnpm lab:docker-terminal`：挑对 shell、敲进去的命令回显得出来、确认人真在容器里而不是
  宿主机上、停着的容器给的是"没在跑"、伪造句柄解不到东西——在 `svc-docker`、`svc-arena`
  与只有 Podman 的 `svc-podman` 上都跑通。

  仍缺：网络/卷删除、Compose 动作（Compose 项目目前没有句柄）、容器内文件读写。

- **镜像详情（2026-09-02）已接线，是当初点名的三件事里的最后一件。**
  镜像页原本只有一张卡片，列仓库、标签、摘要、大小、创建时间——全是清单里已有的字段，
  点不开也问不出任何清单答不了的问题。现在核心新增 `DockerService::inspect_image`，
  镜像行拿到自己的句柄（和网络/卷一样是 opaque 的，全长 id 留在后端），
  `docker.resource.inspect` 多认一种 `kind: "image"`。

  读的是两条命令而不是一条，因为它们答的是两个问题，只有凑齐才有用：
  `image inspect` 说这个镜像**起来之后会做什么**——以谁的身份跑、入口点是什么、
  烤进去了哪些环境变量、暴露了哪些端口；`image history` 说它**是怎么变成这样的**，
  别人往里加的那一层就在这里露出来。history 读不到不算失败：按 digest 拉下来的镜像
  本地就没有构建记录，配置照样值得看。

  「运行身份」这一栏会把空值直接写成「root（镜像没有指定用户）」——镜像没设 user 就是 root，
  而运行时表达这件事的方式是把字段留空，照原样显示等于把最该看见的答案藏起来。
  内置环境变量一律原样显示，理由和别处一样：烤进镜像里的凭据是**要找的东西**，
  不是要遮的东西。

  同轮查出两个只有真读一台主机才会暴露的问题：**`image ls` 是一个 tag 一行，
  同一个镜像挂两个 tag 就是两行同 id**（走镜像源的主机上必然如此），按 id 去重会把
  整个标签页判成快照失效；**Podman 的字段名和 Docker 不一样，而且 size 和创建时间给的是数字**
  ——照 Docker 的形状读，这两列一个空一个是一串秒数。两者都补了断言。
  验收证据是 `pnpm lab:docker-image`（自建镜像、拉下来的镜像、伪造句柄，启动命令与
  运行身份都和主机侧独立复核对齐）与 `pnpm lab:podman` 里新增的镜像段。

- Docker 只读调查 phase 1 已中央接线：`crates/lovelyhawk-backend/src/docker_read_api.rs`、
  `ui/src/shared/docker-read-contract.ts`、`docker-read-state.ts`、`docker-read-helpers.ts` 与
  `DockerPage.tsx` 已实现真实 opaque SSH binding、完整 `TargetGuard` 前后验证、固定 Docker runtime、
  有界容器快照，以及 stats/images/networks/volumes/Compose 项目、容器/镜像/网络/卷详情、安全审计和日志读取。
  Renderer 只持有 5 分钟 TTL 的 opaque snapshot/resource handles，不发送 session、guard、generation、
  identity、命令或远端路径；后端 registry 限 8 个快照、每快照 3 个并发读取和 2 个并发刷新，并限制全部
  行数、UTF-8 文本、日志、registry 字节与事件结果应用。网络或卷清单刷新会作废其旧资源 handle；容器
  快照刷新或目标切换会作废该目标的全部旧 handle，晚到结果失败关闭。BackendState 单例、exact5 RPC、
  main/preload exact96、aggregate contract、App binding-only page registry 与 SSH disconnect 前 eager
  `close_binding` 均已接线；phase 1 不暴露 start/stop/restart/remove/exec/file/terminal/export/mutation/generic
  surface。当前代码面验证包括 backend library 206 tests、standalone 35 tests、Electron 99 files/542 tests、
  source gate/fixture self-test，以及 `target/electron-debug/b3e44b7a-7a8f-481d-be9d-26521d5cbfea/evidence`：
  真实 Electron `webContents.debugger`/CDP 证明五个方法的直接和 unknown-field forged 请求共 10 项全部拒绝且
  不回显；断连页的 table/resource/card/finding/inspection/log/tab rows 全为 0、local-only、无内部身份，卸载重挂载
  仍为空，Docker/全局 console error 为 0，并由 `capturePage` 生成截图；标题/提示对比度为 15.05:1/6.37:1。
  仍缺真实 Linux/OpenSSH/Docker 的空清单、权限拒绝、超限、超时、断连和目标切换矩阵。容器 action、资源/
  Compose mutation、文件读写/复制和 container terminal 属于 phase 2，必须另行建立不可变计划、确认、审计、
  验证/恢复及窗口生命周期闭环；整个 Docker 页面因此继续为 `Pending`，但只读 phase 1 不再计为 `UNWIRED`。
- 日志分析只读调查 phase 1 已中央接线：`crates/lovelyhawk-backend/src/log_analysis_read_api.rs`、
  `ui/src/shared/log-analysis-read-contract.ts`、`log-analysis-read-state.ts`、
  `log-analysis-read-helpers.ts` 与 `LogAnalysisPage.tsx` 已实现真实 opaque SSH binding、完整
  `BoundSshSession`/`TargetGuard` 前后验证，并且只调用 core `LogAnalysisService` 的日志源发现、文件/
  journal 分页读取、威胁汇总、多源关联与 IOC 搜索。Renderer 仅发送 binding、snapshot/source capability
  及有界 typed query；远端位置只能作为 hostile plain text 展示，后续读取不接收 path，也不发送
  session、guard、generation、identity 或命令。快照 TTL 为 5 分钟，registry 限 8 个快照、每快照 1 MiB、
  总量 4 MiB、每快照 3 个并发读取，发现限全局 2 个且每 binding 1 个；文件源限 100 个并可附加 1 个
  journal capability。单页限 200 行/512 KiB；关联限 2–8 个文件源、每源 200 行、观察 1,600 行、返回
  1,000 行/1 MiB；IOC 限 1–8 个文件源、16 个 indicator、64 个 source/indicator 组合、64 个结果、
  每结果 3 个样本且总文本 512 KiB。过期、淘汰、目标切换及晚到结果均失败关闭。按“可信条件下不做主动隐藏”
  的约定，日志行一律原样返回，只保留控制字符净化与体积截断：原先按 credential 形态整行遮蔽的实现
  会吞掉 auth.log 里正要看的证据，已移除。页面已按命令工作台改造为工具栏 + 日志源树 + 详情三段式，
  行号沟槽与命令输出同构。BackendState 已注册 exact4 固定 RPC，main/preload/aggregate contract 只公开
  `discoverLogSources`、`readLogSource`、`correlateLogSources`、`searchLogIocs`；main 对请求与响应作严格
  exact-object 验证，unknown/forged 参数固定失败且不回显。`App`/`LogAnalysisPage` 只接收 opaque
  `bindingHandle`，不接 target identity、connection/session metadata；SSH disconnect 在实际断连前 eager
  `close_binding`，取消、过期、目标切换及晚到结果均失败关闭。owner 为 Electron log analysis migration；
  验收测试为
  `log_analysis_read_api_standalone.rs`、`log-analysis-read-contract.test.ts`、
  `log-analysis-read-state.test.ts`、`log-analysis-page.test.tsx` 与 `log-analysis-read-boundary.test.ts`。
  source gate 与 fixture self-test 已接受当前 main exact89、Log Analysis exact4、strict validators、backend
  guard/bounds、opaque-only App、forbidden surfaces 及 eager close-before-disconnect；最近完整 Electron check 为
  96 files / 509 tests，sidecar aggregate 为 583 passed、0 failed、0 ignored，standalone 为 29/29。新的
  Electron-native CDP 证据 `target/electron-debug/c7b33682-bc4d-4f91-bd63-8990152a2987/evidence` 已通过：
  该 pre-Kubernetes main exact85 运行中，forged/unknown discover/read/correlate/IOC search 均 reject-no-echo，forbidden
  mutation/rules/AI/file/terminal/export/generic 为 `undefined`，断连页无 rows、local-only、无 internal identity，
  `log-analysis-disconnected.png` capturePage 成功，unmount/remount 后仍为空，console error 为 0。真实 Linux/OpenSSH/journal 的权限拒绝、不可用、
  populated/空集、超限、超时、断连及 target-switch 矩阵同样 `NOT_RUN`。AI 分析、规则 mutation、导出、
  任意文件入口与终端属于 phase 2 独立安全设计，仍为 `UNWIRED`；因此页面整体保持 `mixed`/`Pending`，
  不把 phase 1 的代码面接线误报为完整 parity。
- 2026-09-03 日志分析与 SFTP 的五项使用性修复：
  1. SFTP 打不开的真因是目标机 `sshd_config` 缺 `Subsystem sftp`，握手在子系统请求处失败，而旧提示
     等约十秒后只报三条与实际无关的原因。core 新增 `SFTP_HANDSHAKE_OPERATION` 标记握手失败，
     sidecar 映射为 `sftp-browser-subsystem-unavailable`，页面由 `sftpOpenFailureMessage` 直接说出
     是哪一行配置缺失、终端仍可用。九台靶机里只有 lab-ubuntu 缺该行，补上后立即列出 22 个条目。
  2. journal 源的搜索此前只搜当前页：`generate_journalctl_command` 把 `-n`/`head` 排在 `grep` 之前，
     等于先截断再搜。现在改为先 `-n JOURNAL_FILTER_SCAN_LINES` 再 `grep`，最后才 `tail`/`head` 分页。
     扫描深度按实测定为 5 万行：在一份真实 journal 上 journalctl 每条约 80 微秒，20 万行要 16 秒，
     对 60 秒的 `REMOTE_TIMEOUT` 余量太小——慢一点的机器就会整条超时、什么都拿不到；5 万行约 3.6 秒，
     仍有 500 页深。要看更早的，用日期把 `--since`/`--until` 加上，那是在源头裁剪，比往回多扫便宜。
     文件源本就是整文件搜索，已复测确认。
  3. 分页新增 `LogPagination`：首页/上一页/下一页之外提供页码直达输入框，并给出
     `data-testid="log-pagination-summary"` 的条目数说明。总数是从分页推导的下界，最后一页才转为精确，
     文案自身说明是哪一种，避免为算总数把整份日志重扫一遍。
  4. “选择日志目录”按边界改为扩大发现范围而非接收 renderer 传入的路径：`LOG_ROOTS` 由
     `/var/log` 扩到十处——`/var/log`、`/opt`、`/srv`、`/usr/local`、`/var/www`、`/www`、`/wwwroot`、
     `/home`、`/data`、`/app`。`generate_list_log_files_command` 同时修掉四个真实缺陷：
     嵌套 `-exec find … -exec … \;` 会被外层 find 吞掉第一个 `\;`；`-readable` 是 GNU 专有，
     busybox find 会整条失败，Alpine 的日志页因此一直是空的（0 → 3 个源）；名字只认 `*.log`，
     于是**没有一个 web 应用的日志能被发现**——RPM 系 Apache 写的是无扩展名的 `access_log`/
     `error_log`，Tomcat 写的是 `catalina.out` 与 `localhost_access_log.<日期>.txt`，nohup 起的服务
     写 `.out`；以及第二段 find 要求路径里必须有 `log/` 或 `logs/`，把站点直接写在自己目录下的
     `access.log` 和面板的 `/www/wwwlogs/`（目录名是 `wwwlogs`，不匹配 `*/logs/*`）全部挡在外面，
     而这个过滤根本不省遍历成本，只是把结果藏起来。现在名字集合为 `*.log`、`*.log.[0-9]`、`*_log`、
     `*.out`、`localhost_access_log*` 加四个系统名，第二段不再有路径过滤，`/var/log` 深度由 2 提到 3。
     让操作员自己输入任意目录仍需 renderer 侧传路径，与 source gate 明令禁止的 `remotePath` 相冲突，
     属于需要用户拍板的边界变更，本次不做，记为 `UNWIRED`。
  5. 敏感内容改为“就地标注”而不是遮蔽：`splitSensitiveSegments` 把一行拆成普通段与标注段，
     标注三类 network/secret/payload，单行最多 24 处、超过 4,096 字符的行不扫描，切分结果始终能原样
     拼回原文。凭据的值一并标注而绝不打码——日志是证据，遮蔽会把要看的东西吞掉，与既有约定一致。
  实机验收为 `tools/lab/probe-ui-log-analysis.mjs`（`pnpm lab:ui-log-analysis`）在 lab-ubuntu 真实窗口
  跑通：`/opt` 下的日志被列为源、Apache `access_log`/Tomcat `catalina.out`/面板 `/www/wwwlogs` 三类
  web 日志都出现在列表里且无扩展名的那个真的能打开并显示内容（8 → 12 个源）、页码直达落到第 3 页、
  搜索命中第 250 行中的第 240 行并回到第 1 页、
  只返回匹配行、标注计数非零，证据在 `target/lab-ui-log-analysis/ubuntu/`。journal 分支另在 WSL Ubuntu
  的真实 journal（20 万行以上）上对跑新旧两种命令形态：取一个在最新 100 行里出现 0 次的词，旧形态返回
  0 条即"查无此项"，新形态返回满满一页 100 条，第二页另有 100 条且与第一页不同，用时 3.6 秒。
  journal 在真实 Linux 上的权限拒绝、单元过滤与日期过滤组合矩阵仍为 `NOT_RUN`。
- 2026-09-04 归档日志：昨天的日志现在读得出来了。轮转过的日志才是入侵痕迹最常在的地方，
  而此前它们既发现不了也读不了——上一轮我自己把这条记为遗留缺口，这轮补上：
  1. 发现：名字集合补 `*.gz`（排除 `*.tar.gz`/`*.tgz` 两种"源码包"后缀）、`messages-[0-9]*`、
     `secure-[0-9]*`、`*_log-[0-9]*`、`syslog.[0-9]*`，覆盖 Debian 的 `syslog.1`/`access.log.2.gz`
     与 RPM 系的 `secure-20260901`/`access_log-20260901.gz` 两套轮转命名。
  2. 读取：`generate_log_read_command` 对 `.gz` 走 `gzip -dc` 而不是 `tail`——压缩流没法 seek，
     所以归档分支不用 tail 的定位形式，明文分支保留（一份 2 GB 的明文日志不该被拉过管道）。
     `gzip -dc` 是三个家族都认的拼法，busybox 与 RPM 系实测通过，`zcat`/`gunzip` 并非处处一致。
  3. IOC 搜索同样解压后再 grep。之前用明文 grep 搜归档会对每个 indicator 回答"没有"——
     把唯一存着昨日证据的文件报成干净的，是最坏的一种错。多源关联复用同一个读取函数，自动继承。
  4. 界面把归档说清楚：`isArchivedLog` 从已经在屏幕上的位置文本判断（不新增跨边界字段），
     体积标为"压缩后大小"，读取方式标为"只读，解压后按页读取"。
  5. 目标机没有 gzip 时不再返回空白页。核心以稳定的 `ARCHIVE_TOOL_SUBJECT` 报错，sidecar 映射为
     `log-analysis-archive-tool-missing`，界面由 `logReadFailureMessage` 告诉操作员装 gzip 或去
     命令工作台解压，并说明"这个文件本身是好的"。九台靶机里 lab-suse 就没有 gzip，这条是实测出来的。
  顺带修掉一个真实的操作体验缺陷：读取进行中整棵日志源树是 `disabled` 的，也就是说在 RPM 系
  （每条命令固定 11 秒）上，操作员点错一个日志就得干等十几秒才能换，界面上还没有任何解释。
  reducer 本来就按 scope/request 丢弃晚到结果，这层锁是多余的防御，已去掉；忙闲状态留在"读取日志"
  按钮上，那才是它该待的地方。这个缺陷正是靶机验证逼出来的——探针在 Rocky 上点不动源树才暴露。
  实机验收：`pnpm lab:ui-log-analysis` 在**九台靶机全部通过**（ubuntu/alpine/debian/rocky/alma/
  openeuler/anolis/deepin/suse）。探针本身也修了两处会掩盖问题的写法：选中源之后不再靠固定 sleep
  就按"读取"（点到 disabled 按钮会静默失败，读的还是上一个源），搜索改为等状态变化而不是固定 4 秒
  （RPM 机器上不够，会把好功能报成坏的）；失败时打印选中源、状态与错误并截图。
  仍未覆盖：`.bz2`/`.xz`/`.zst` 归档，以及解压炸弹只靠 60 秒命令期限兜底，均记为 `UNWIRED`。
- 2026-09-04 基线：sshd 的 `Match` 条件块不再被当成全局配置（关闭 OPEN_ITEMS 第 9 条）。
  `Match` 之后的一切到下一个 `Match` 或文件结束为止只对部分连接生效，此前扫描把它们读成
  这台机器的设置，两个方向都会错：把全局 `PermitRootLogin no` 的机器报成 `yes`；更要命的是
  反过来——攻击者在 `Match Address` 里给某个地址留门，全局段看着规规矩矩，扫描就把后门读成了合规。
  新增观察状态 `BaselineObservedValue::Conditional`（sidecar `"conditional"`，界面"写在 Match
  条件块里，只对部分连接生效"），`compliance_of` 对它一律返回 false，contract 校验也钉死
  "conditional 不能同时 compliant"。读取程序按 `FNR==1{m=0}` 逐文件重置条件状态，
  `reads_conditional_blocks()` 限定只有 sshd 走这条分支，witness（只负责给出文件名）不受影响。
  文件视图里 `Match` 之后的行照常列出，但不再被标成"这台机器实际生效的那一行"。
  验收：`tools/lab/probe-baseline.mjs` 的每个用例都先问 `sshd -T` 再比对扫描，新增 F（全局 no +
  Match 里 yes）、G（只在 Match 里放行）、H（Match 被注释掉）三例，**九台靶机全部通过**。
  顺带修掉探针自身两个既有缺陷：其一，每个用例是从上一个用例装好的文件继续改的，于是写过
  `Match` 的用例会污染它后面所有用例——现在每个用例都从一份开机时留存的原始配置出发；
  其二，`sed` 的大小写无关标志 `I` 是 GNU 专有，busybox 直接报 `unsupported command I`，
  所以这个探针在 Alpine 上从来没跑通过，改成逐字母字符类后 Alpine 首次通过。
  另外发现 Alma 镜像自带 `/etc/ssh/sshd_config.d/25-permitrootlogin.conf` 强制 `yes`，
  drop-in 会盖住主文件，探针运行期间把该目录暂时移开、结束后原样放回。
  仍未覆盖：`Match` 块**内部**取值本身的正确性（这轮只判定"有条件"，不解析条件表达式），记为 `UNWIRED`。
- 2026-09-04 命令工作台：打开变快，并且会说清楚给的是哪一套命令（关闭 OPEN_ITEMS 第 10 条）。
  实测 `pnpm lab:catalog-latency`：改前 Rocky 每次打开都要 31.9 秒（第二次一样），因为系统家族、
  容器、Pod 三个互不依赖的探测是串行等的，而 RPM 系每条命令固定约 11 秒。改成 `tokio::join!`
  并发后降到 11.0 秒。更要紧的是识别一直在失败：`detect_system` 内层预算 10 秒卡在 11 秒地板之下，
  rocky/alma/openeuler/anolis **四台全都在静默使用通用命令集**——这正是本项目最在意的国产/RPM 系。
  `DETECTION_TIMEOUT` 提到 20 秒、`DETECTION_DEADLINE` 提到 25 秒（源码门禁的固定值同步更新）后，
  九台全部报 `detected`。**这是 11 秒地板第三次咬人**，已在常量注释里写死缘由。
  目录新增闭合字段 `commandSet`（`detected` / `portable`，绝不回传发行版本身——那是目标机的事，
  操作员要知道的只是"接下来这些答案够不够好"），contract 侧钉死只接受这两个词且必须存在；
  页面只在是通用集时显示一行说明并提示可以重新加载再试。这个词由**结果**决定而不是由"探测有没有报错"
  决定：机器答得上但报了个没听过的系统，同样只能给通用集，此时说"为你这台机器挑的"就是撒谎。
  新探针 `tools/lab/probe-catalog-latency.mjs`（`pnpm lab:catalog-latency`）除了计时，还会临时把
  `/etc/os-release` 改成一个认不出的系统、验证界面如实报 `portable`，然后原样还原。
  **九台靶机全部通过**。未做缓存：并发之后 family 不再是长杆，容器/Pod 列表又必须每次刷新，
  缓存它省不到墙钟时间。仍未覆盖：容器内 family 探测（`detect_container_system`）的同类计时，记为 `NOT_RUN`。
- 2026-09-04 界面不再声称"有内容被藏起来了"（关闭 OPEN_ITEMS 第 5 条）。在一个用来读证据的
  工具里，这句话是最坏的方向——它让操作员不再往下看——而它当时还不是真的。清理分两类处理：
  1. 基线与核查审计：`redacted` 是硬编码 false（`take_public` 里 `let redacted = false;` 后面跟
     一条永远走不到的分支，`bounded_public_text` 收一个用 `_` 忽略掉的 `redacted_text` 参数），
     所以那个"0 遮蔽字段"计数块、"credential-like 字段已遮蔽"以及五处"已遮蔽或截断"全是废话。
     计数块删掉；文案改成只说截断这件真事，并明说"内容本身没有做过删改"；死分支与被忽略的参数
     一并清掉；`REDACTED_TEXT` 两个常量保留但标注为"冻结标志的配对值"，因为契约仍然要求
     "若 redacted 为真则文本必须正好是这个串"，两边不能各走各的。
  2. 文件完整性页**不能一刀切**：它的遮蔽是活的——`project_path` 会把混进本机连接口令的路径、
     以及畸形/穿越路径整条替换掉，这是正确保护。问题在于三件完全不同的事（按上限截断 /
     控制字符净化 / 真的整条替换）被同一个"已遮蔽"混着说。现在分开讲：截断说截断，净化说
     "控制字符已替换成可见符号，文字本身没有删改"，只有真的替换才说"这条路径含本机连接口令，已整条替换"。
  验收：先在两台真机上实测确认标志确实从不为真（baseline 108 项 0 处 redacted，审计各计数全 0），
  再给 `tools/lab/probe-ui-baseline.mjs` 加了一段在真实窗口里逐页断言（配置 / 核查审计 / 文件完整性
  三页都不得出现"已遮蔽"、不得出现恒为 0 的遮蔽计数），**ubuntu/rocky/alpine 三台通过**；
  另加一条渲染层断言，禁止任何页面再读 `.redacted`/`redactedFieldCount`/`locationRedacted`。
  仍未做：DTO 里这些字段本身没删（契约冻结，涉及两个 API 的 exact 键集、门禁与大量测试），记为 `UNWIRED`。
- 2026-09-04 主机全景的表不再"声称完整而其实不完整"（关闭 OPEN_ITEMS 第 11 条）。
  几乎每个标签页的远端命令都写死了 `| head -n 500`；核心的 `parse_table` 只有在自己碰到行数
  上限时才置 `truncated`，而它永远看不到第 501 行，于是这个标志对整个页面结构性恒假——
  一台进程很多的被入侵主机上，要找的进程完全可能排在第 501 位，它不显示，界面还说什么都没少。
  `SystemInfoTab::command` 改为按调用方要的行数重写命令上限、永远多取一行（`ROW_LIMIT_MARKER`
  集中替换，不手改二十条字符串），多出的那行被解析掉不进表，但足以让"还有没有更多"可回答。
  过程中另发现两个上限**低于该页能显示的行数**、连表都填不满的：登录历史 200、Web 应用 100，
  一并对齐；Shell 配置（1000，高于调用方上限）与 Rootcheck（目标机不设上限）本来就正确，
  测试里点名放行，新增标签页若两者都不满足会直接失败。界面文案从"结果已在 500 行边界截断"
  改成说清楚还有更多并给出下一步（用筛选缩小范围）。
  验收：新探针 `tools/lab/probe-table-truncation.mjs`（`pnpm lab:table-truncation`）**九台靶机
  全部通过**——干净机器 13 个进程时如实报未截断，种到 576 个进程后报截断且正好 500 行，
  只要 10 行时同样如实报截断，多取的那行从不混进表里。探针自身用记录 PID 的方式清理种下的进程，
  因为 `exec -a` 是 bash 内置、容器的 `sh` 没有，而按名字模糊匹配去 kill 又可能误杀别的东西。
  其余标签页的逐个复测已于同日补齐，见下一条。
- 2026-09-04 主机全景二十五个标签页的截断行为逐页实测（补齐上一条的 `NOT_RUN`）。
  给每个标签页造五百行做不到，所以反过来把窗口调小：要 3 行。这样任何在这台机器上有 4 行以上的
  标签页都必须只回 3 行并如实说被截断，3 行以内的必须说没截断——同一段代码路径，二十五个页面
  在真机上全走一遍。再用 500 行的那次采集得出"到底有多少行"，两次结果必须自洽。
  新探针 `tools/lab/probe-table-limits.mjs`（`pnpm lab:table-limits`）。
  结果：**九台靶机、二十五个标签页全部通过**，各机真正越过小窗口的标签页数为
  ubuntu 13、alpine 8、debian 14、rocky 13、alma 13、suse 13、openeuler 13、anolis 13、deepin 14
  （探针会断言至少 5 个真的走到超限分支，否则这一轮什么也没证明）。
  代价说明：RPM 系每条命令固定约 11 秒，一台机器 50 次采集要跑九分钟左右，这是那类机器的地板。
- 2026-09-04 空表现在会说清楚是哪一种空（关闭 OPEN_ITEMS 第 12 条）。主机全景每条命令都写着
  `2>/dev/null`，工具不在时输出为空，页面统一显示"当前目标没有返回条目"。可"防火墙一条规则都没有"
  和"这台机器没装 iptables、我看不了"是**完全相反的结论**：前者意味着门户大开要立刻处置，
  后者意味着得换个办法去看。核心新增 `SystemInfoTable::missing_tool`，由 `SystemInfoTab::command`
  统一加壳（不逐条改命令，那样总有一条会忘）——工具不在时只打印 `NO_TOOL_MARKER`。
  **名字由核心侧固定表提供，绝不读机器写的字**：否则被入侵的主机可以自己打印一行假标记，
  用"这里没有 iptables"把自己的规则藏起来。标记只有在**独占整份输出**时才算数，机器若既打标记
  又打规则则规则说了算，所以它最多只能做到"什么都不显示"，而那是它本来就能做到的。
  `required_tool`/`tool_probe` 两张表由测试强制一一对应，新增标签页对不上直接失败；
  contract 侧把可说出口的工具名钉成闭集（`SYSTEM_INFO_TOOLS`），伪造的名字一律拒收。
  界面据此分别说"这台机器上没有这类条目。"和"这台机器上没有 X，所以这项查不了——空白不代表没有。"
  验收：新探针 `tools/lab/probe-missing-tools.mjs`（`pnpm lab:missing-tools`）**九台靶机全部通过**。
  容器天然缺 iptables/docker/kubectl/nginx，每台各缺 4–5 个，两种情况都验到：缺时点名且不编条目，
  有时（`last`、`ss`）即使 0 行也不甩锅给工具，读文件的页面从不甩锅。
  "有工具"那一面已于同日补齐，见下一条。
- 2026-09-04 "有工具"那一面在真机上补齐（关掉上一条的 `NOT_RUN`）。九台被入侵靶机是容器，
  几乎不带 iptables/docker/kubectl/nginx，只能验"缺工具"那半边。编排靶机的镜像其实早就建好、
  只是停着，启动很便宜（`svc-kubernetes` 依赖 `lab-k3s`，要先起 k3s 再起它）。
  `probe-missing-tools.mjs` 现在也能指向 `svc-*` 主机，四条分支全部验到：
  `svc-docker` 上 iptables 在、防火墙读出 **44 条真实规则**且不甩锅，docker 在、读出 **17 个容器**；
  `svc-kubernetes` 上 kubectl 在、读出 **10 个 Pod**；`lab-arena` 上 nginx 在、web 应用读出 4 行。
  加上原有的九台，`pnpm lab:missing-tools` 现在十三台通过。
  **顺带查清一件事并记为下一步**：工具装了但"答不上来"（docker 守护进程死了、kubectl 没有集群）
  仍然会显示成空表。根因是 shell 管道的退出码取的是**最后一级**——`docker ps … | head | awk` 里
  docker 失败了 awk 照样退 0，所以核心那句"故意不看退出码"其实也没机会看到失败。
  要分清得让每条命令自己上报主工具的状态，是二十五条一起改的事，已在 `collect_table` 的注释里写明
  代价与原因，记为 `UNWIRED`。（另：实验中我 `pkill -STOP` 过 svc-docker 的 dockerd，
  发现 `docker ps` 会**阻塞**而不是快速失败；已恢复并复测该主机健康。）
- 2026-09-04 空表的第三种含义："工具装着，但这次没答上来"（关闭 OPEN_ITEMS 第 13 条）。
  第 12 条解决了"没装"，但装了却失败——docker 守护进程死了、kubectl 连不上集群——仍显示成空表，
  而且是三种空里最安静的一种：机器上什么都不像坏了。原以为要改 25 条命令去救管道退出码
  （`docker ps … | head | awk` 退的是 awk 的码），实际不用：在已有外壳里多加一层健康探测即可，
  两问同在一条命令里，不多一次往返。`tool_health` 只配给真要和别的东西说话的工具
  （`docker version`、`kubectl version`、`systemctl list-units --type=timer`）；
  `iptables-save`/`ss`/`last` 读内核或文件，没有可断开的对象，留空。新增 `failed_tool`，
  与 `missing_tool` 互斥，contract 侧钉死这条互斥并把名字限在同一个闭集里。
  timers 特意不用 `systemctl is-system-running`：`degraded` 的机器照样答得出 timer，
  而那种机器恰恰最可能正被调查。界面三种空各说各话。
  验收：`pnpm lab:missing-tools` **十三台全部通过**，其中在 `svc-docker` 上真的把 dockerd 杀掉，
  验到"工具还在、说它这次没答上来、不编条目"，跑完自动 `docker restart` 恢复并复验。
  意外收获：RPM 系容器有 `systemctl` 却没有 systemd 在跑，`list-units` 确实失败——
  一开始看着像产品错了，查下去**是探针的预期错了**；探针已改成到机器上问同一个健康问题再比对，
  而不是无条件放行"工具在就不该报失败"。
  仍未覆盖：健康探测本身被挂起的情形（`pkill -STOP` 会让 `docker version` 阻塞而非快速失败，
  此时只能由该标签页的 SSH 超时兜底，页面显示的是超时错误而不是这条说明），记为 `UNWIRED`。
- 2026-09-04 抓包页：抓不了的时候会说为什么，而不是伪装成一个数据包。实测发现在没有 tcpdump 的
  机器上，`start` 照样返回 `status: "running"`，而"tcpdump unavailable"这句话被当成**一个数据包**
  塞进包列表（协议 OTHER、源和目的为空）。原因是实时命令末尾 `2>&1`，预检的抱怨和包走同一条流。
  核心把这几句预检诊断收进 `CAPTURE_PREFLIGHT_REASONS`（tcpdump 缺失 / timeout 缺失 / 需要 root 或
  免密码 sudo / sudo 要输密码），命中就发 `Failed` 事件并结束抓包，不再当包解析。
  边界原本规定不回显抓包失败文本——这是对的，其余内容是目标机上 tcpdump 自己的 stderr——
  所以新增 `known_capture_failure`：sidecar 拿收到的 message 去核心的固定表里**反查**，
  过界的是那张表里的字符串而不是手上的 message；contract 侧同样把这几句钉成闭集。
  界面因此能说"这台机器上没有 tcpdump，抓不了包"，而不是"远端错误详情未跨越安全边界"。
  验收：新探针 `tools/lab/probe-packet-capture.mjs`（`pnpm lab:packet-capture`）**九台靶机全部通过**，
  两面都验：没有 tcpdump 时说清原因、状态标失败、不伪装成包也不进包计数；临时装上 tcpdump 后
  正常跑完并**真的抓到 10 个包**（探针用自己的 SSH 轮询当流量——这些镜像连 `ping` 都没有，
  第一版检查因此把"零个包"当成了成功），验完把 tcpdump 卸回去。
  顺带修掉仓库里最后一处不可见字节：`packet-capture-live-contract.ts` 第 131 行的 `\u0000`/`\u001f`
  被某次脚本改动写成了**真实的 NUL 与 0x1F**（字符类恰好等价所以校验一直是对的，但 git 把整个文件
  当二进制，diff 没法看）。已还原成转义并全仓扫描确认再无此类字节。
  仍未覆盖：`CAP_NET_RAW`/`CAP_NET_ADMIN` 被剥夺、PTY backpressure、超限、抓包中途断连与目标切换，
  以及非 root 账号下的 sudo 分支（靶机都以 root 连），仍记为 `NOT_RUN`。
- 2026-10-11 抓包在 Tauri 外壳下用真实 tcpdump 重新验收（`tools/lab/probe-ui-packet-capture.mjs`）：九个发行版各自新建一次性容器，经用户同意从各自的官方源装上 tcpdump，结束后按核实的 ID 删除。每台都验证：列出真实网卡并默认选中它（不是 lo）；向网关发三个 ping，页面上恰好是六个包、地址正确；数据包上限到了主机上的 tcpdump 就结束；“停止抓包”和离开页面之后主机上没有在跑的 tcpdump（这些容器的 PID 1 不回收进程，探针按状态排除已退出的僵尸）；带 `; touch …` 的过滤条件什么都没执行，页面说明 tcpdump 拒绝了它并原样给出 tcpdump 自己那一行。验收中发现并修正：
  - 实时命令带 `-e -v`，每个 IPv4 包被 tcpdump 拆成两行，页面上一个包变成两行乱码（协议列是 MAC 地址）。改为一行输出 `-nn -l -tttt`，协议按摘要识别 ICMP/UDP/TCP。
  - Alpine 的 BusyBox `timeout` 不认 `--signal=`、`--kill-after=`，那里的抓包一律失败。实时抓包改由 POSIX shell 自己计时（tcpdump 作为后台作业，HUP/INT/TERM 由 trap 收尾），不再依赖 `timeout`；留证命令改用两边都认的短选项 `-s INT -k 5`。“停止抓包”先经 PTY 发 Ctrl-C 再关闭通道，由包装脚本的 trap 收尾，不只指望关闭通道带来的挂断（关闭和 Ctrl-C 各自是否单独够用，本轮没有分开测）。
  - 终端通道读到 EOF 就停，丢掉了随后才到的退出码，过滤条件写错的抓包显示成“已停止”。现在读到退出码或通道关闭为止。
  - 一次抓包到上限自己结束后，“开始抓包”一直是灰的、“停止抓包”点了也没用（结束的那次轮询让自己的收尾被当成过期而跳过）。
  - tcpdump 在 RHEL 系上打印的 “dropped privs to tcpdump”、在 4.99 上不带前缀的 “listening on …” 被当成数据包。
  - 失败原因会消失：tcpdump 的那一行和失败往往分两次轮询到达，而之后的网卡列表重新读取又清掉了错误提示。
  - 浅色主题下“累计数据包”等数字几乎看不见（用了按钮用的文字色）；时间列只显示时分秒毫秒，完整时间在提示和详情里；重新读取网卡后不再跳回 lo。
  仍未覆盖：非 root 账号的 sudo 分支、`CAP_NET_RAW` 被剥夺、真实网络中断仍为 `NOT_RUN`；只在容器上跑过。
- 2026-10-11 抓包留证接通：抓包页的“抓包并保存…”按所选网卡和参数在目标上运行 tcpdump，把 `/tmp/lovelyres-pcap-<UUID>.pcap` 经两次 SFTP 读取与本地回读存成 `capture.pcap`，三个摘要须与目标上算出的 SHA-256 一致才写清单并登记为案件证据（类型：抓包），随后删除目标上的临时文件并报告是否删除。新方法 `packet-capture.evidence`（begin/poll/cancel）走 core → backend → 宿主命令 `packet_capture_evidence_begin`（目录选择器）→ 页面桥接；页面只交网卡句柄与有界参数，开始动作和本机目录不能经通用调用发送。取消会中断命令行里带这次临时路径的进程再删除文件；tcpdump 拒绝时页面引用它自己的最后一行，目标上不留文件。方法与限制见 [文件留证](FILE_EVIDENCE_COLLECTION.md)“抓包留证”一节。仍未覆盖：非 root 的 sudo 分支、中途断连（临时文件会留在目标上，已在页面说明）、超过 512 MiB 的抓包、真实 VM/实机。
- 2026-09-04 抓包的收尾：断连不会在被查主机上留下进程，自然结束的抓包也不再挡住下一次。
  应急现场最怕的是"走的时候留了个东西在人家机器上"，所以先验清理：正常停止、主动断开、
  以及**应用直接消失**（相当于崩溃或强杀）三种走法，远端 tcpdump 都在数秒内归零。
  还单独验了没人能发信号的那一路——网断了、机器听不到任何指令——靠的是命令自带的
  `timeout {duration}s`：不去碰它，到点自己就停。三条都不是代码看出来的，是真起了抓包再走掉量出来的。
  **发现并修掉一个真缺陷**：一次带时限的抓包自然结束后，它的槽位仍被计入"每个绑定最多 1 个"，
  于是第二次抓包被拒，公开文案是"已达上限"——可一个都没在跑，而唯一的出路是去点一个**已经停了**的
  抓包的"停止"。`CaptureRegistry::reserve` 现在在计数前先把该绑定下已终止（stopped/failed）的槽位摘掉。
  排查时另有一处容易误判：单次 poll 最多回 100 个事件，终止事件可能还排在后面，
  所以只轮询一次会看到"状态还是 running"——那是客户端没读完，不是产品说谎；探针改成读到 `hasMore`
  为假再判断。验收：`pnpm lab:packet-capture` **九台靶机全部通过**，共 12 项检查。
  仍未覆盖：`CAP_NET_RAW`/`CAP_NET_ADMIN` 被剥夺、PTY backpressure、真实网络分区（本轮用的是
  应用侧消失来近似）、以及非 root 账号的 sudo 分支，仍记为 `NOT_RUN`。
- 2026-09-04 抓包的三种拒绝各说各话。`CaptureAlreadyActive`/`RegistryCapacity`/`ConcurrencyLimit`
  原本合并成一句"已达上限"，可它们对应的下一步完全不同：把自己这台上正在跑的停掉 / 去别的目标上
  关一个 / 单纯等一下。上一轮排查时我本人就被这句话误导过，先怀疑是产品坏了。
  现在拆成 `packet-capture-already-running`、`packet-capture-too-many`、`packet-capture-busy` 三个 code，
  页面各给一句带下一步的话。顺带修掉页面上那个 `catch {}`：它把错误码整个吞掉，还在**猜原因**
  （"目标可能缺少 tcpdump，或没有 root/sudo 权限"）——而 tcpdump 缺失现在走事件流，
  根本不是启动失败，这句话指的是错的方向。
  验收：`pnpm lab:packet-capture` 在真机上制造"已经在抓"的场景并断言拒绝理由说的是这件事、
  且不再出现 `packet-capture-capacity`，**九台靶机全部通过**。
  另：扫了一遍 sidecar 的错误映射，还有三处同类合并值得拆（已记入 OPEN_ITEMS 第 14 条），
  而七处 `invalid-params` 的合并是**故意的**，不该拆——伪造请求不能被告知是哪个校验器跳了。
- 2026-09-04 主机全景的三种"问不到详情"各说各话（关掉 OPEN_ITEMS 第 14 条的第一项）。
  `InvalidSnapshot`/`InvalidRow`/`DetailUnavailable` 原本合并成一句"这份表格已经过期，请刷新后再试"。
  前两个刷新确实有用，第三个**永远不会变**——那一行本来就没有更多内容可看，于是操作员被指使着
  去做一件不可能成功的事，而且没有任何线索告诉他该停。现在拆成 `system-info-snapshot-stale`、
  `system-info-row-gone`、`system-info-detail-none` 三个 code，各给一句带下一步的话，
  第三句明说"不是出错，刷新也不会变出来"。
  页面上原来那句"当前行没有可用详情，**或**快照已失效"也一并去掉——那个"或"是把判断推给操作员；
  详情失败现在和右键动作走同一张映射表，说的是同一件事。
  验收：新探针 `tools/lab/probe-system-info-refusals.mjs`（`pnpm lab:system-info-refusals`）在真机上
  分别造出三种情况（正常行 / 表里没有的行 / 旧快照句柄 / 一个本来就没详情的行），
  断言每种都回自己的 code、且都不再回退到旧的笼统码，**九台靶机全部通过**。
  剩下两处同类合并（日志分析四合一、终端三个 limit 加协议违规）仍在 OPEN_ITEMS 第 14 条里。
- 2026-09-04 日志分析：查完之后**没有**拆那个四合一，改掉的是别的东西。
  原计划是把 `InvalidSource`/`InvalidSourceKind`/`InvalidSnapshot`/`SnapshotStale` 拆开，
  理由是"这个源不支持这种操作"和"快照过期"处置不同。查下去发现前提是错的：界面把 journal 的
  按钮 disable 了，reducer 里 `analysis-source-toggled` 也直接拒绝非文件源，所以
  `InvalidSourceKind` **操作员根本碰不到**，它只是对伪造请求的防御。给它单独造一句话，
  等于加一条永远显示不出来的文案——那比合并更糟。四个变体对操作员只对应一个动作：刷新源清单。
  真正该修的是页面上那两句"多源关联已取消、快照已过期**或**返回内容无效"（IOC 那句同理）——
  那个"或"是页面把自己的不确定推给操作员。三个视图现在共用 `logAnalysisFailureMessage`，
  连接断了 / 清单旧了 / 同时读得太多各说各的下一步，其余情况保留各视图自己的兜底句。
  验收：`tools/lab/probe-refusals.mjs`（`pnpm lab:refusals`，由 `probe-system-info-refusals.mjs`
  改名而来，现在覆盖两个页面）在真机上用过期句柄跑读取、多源关联、IOC 三条路，
  断言都回同一个码，**九台靶机全部通过**。
  留下的判断：合并本身不是缺陷，**判据是操作员的下一步是否不同**；相同就该合，不同才该拆。
- 2026-09-04 终端：按判据拆了一半（关闭 OPEN_ITEMS 第 14 条）。四个原因里只有两个对操作员
  有不同的下一步：`SearchLimit`（匹配太多——缩小关键词）和 `OutputLimit`（这个会话的输出量
  用满了——另开一个终端）。`SnapshotLimit` 与 `ProtocolViolation` 都是"这个终端出问题了、重开一个"，
  继续共用一个 code。原来这两条的文案是"终端搜索失败"和"终端输出读取失败"：前者没告诉任何人
  该缩小什么，后者听起来像一次值得重试的小故障，可那个会话**再也不会产出一个字节**。
  新增 `terminal-output-limit`、`terminal-search-limit` 两个 code 与 `terminalFailureMessage`，
  两处 `catch {}`（搜索与轮询）原本把错误整个丢掉，现在把它传进来。
  验收：`pnpm lab:refusals` 用 `yes` 把真实终端灌到 64 MiB 上限，确认回的是 `terminal-output-limit`
  且不再是笼统的协议越界，**九台靶机全部通过**。
  过程中三次被参数上限挡住（终端最大 160×60、搜索结果最多 256、单次轮询最多 64 个事件），
  都是边界在正常工作；另外第一版轮询循环按次数写，400 次空转在输出还没开始时就跑完了，
  改成按时间轮询才真正灌满——这类"测试自己没跑到点上"的写法，本轮已第三次遇到。
  仍未覆盖：`SearchLimit` 的真机触发（需要终端缓冲里留住 128 KiB 以上的匹配文本，本轮没造出来），
  记为 `NOT_RUN`；该分支由单元测试与映射断言覆盖。
- 2026-09-04 SFTP 删除在真机上跑通了（补上"删除的验证与回滚证据"这条 `NOT_RUN` 的一半）。
  新探针 `tools/lab/probe-sftp-remove.mjs`（`pnpm lab:sftp-remove`）按窗口的走法——只用句柄、
  一层层 list 进去，绝不拼路径——种一个 webshell 再删掉，然后**去机器上核对而不是信回执**：
  计划阶段文件还在、执行后真的没了、复核回的是"原路径不在且存在可恢复的备份"、
  按 sha256 在机器上找得到那份一字不差的副本、同一个计划不能跑第二次。**九台靶机全部通过**。
  **但这次运行同时暴露了一个严重问题，已记入 OPEN_ITEMS 第 15 条**：备份落在被删文件的同一个目录下
  （`.lovelyres-backups/<uuid>-<原名>`），保留原扩展名、0644 全局可读。在 lab-arena 上实测，
  删掉 `/var/www/html/evil.php` 之后 `curl` 那份备份仍返回 **200**——对防御赛场景，这等于删除没生效。
  这是"备份该放哪"的设计取舍，留给用户拍板，不在本轮顺手改。**已于当天修掉，见下条。**
  仍未覆盖：上传与打包（`CreateArchive`）在真机上的验证与回滚——**已于当天补齐，见下下条**；
  以及不可读根目录、非 UTF-8、50k/64 MiB 上限、symlink swap race 等矩阵，继续 `NOT_RUN`。
- 2026-09-04 删掉的东西真的删掉了（关闭 OPEN_ITEMS 第 15 条）。上一条实测发现：被删的 webshell
  会以原名、0644、留在同一个 web 根目录里，`curl` 返回 200，PHP 照样执行——操作员被告知"已完成
  并核对过"，而那个后门只是换了个 URL。
  我上轮倾向"把备份挪出 web 根"，想透之后没那么做：备份是靠 `rename` 挪的，跨文件系统必然失败，
  而复核要求备份存在，所以在 `/var` 与 `/var/tmp` 分属不同挂载点的机器上**删除会直接失败**，
  那是更糟的一种。改成就地留底但让它失效：`crates/lovelyhawk-core/src/sftp.rs` 的 `backup_location`
  在名字后面加 `BACKUP_SUFFIX`（`.removed`）——web 服务器按**最后一个**扩展名挑处理器，
  `.php` 不再是最后一个；`ssh.rs` 的 `MoveToBackup` 在建目录和搬完文件之后分别收到
  `BACKUP_DIRECTORY_MODE` 0700 与 `BACKUP_FILE_MODE` 0600，收权限是尽力而为（SFTP 服务端不给改
  也不该让删除失败，能不能删由复核说了算）。计划文案同时改成把落点说出来：
  "把 /var/www/html/evil.php 挪进同目录下的 `.lovelyres-backups/` 留底：名字后面加 .removed、
  权限收成只有你能读，网站再也跑不动它（不是直接抹掉）"——原文案只说"移进可恢复的备份区"，
  从没说过副本就在同一个目录里，而那正是 web 根时最该说的一句。
  **顺带修的两处**：撤销删除现在把权限也还原（`RestoreToken::RemovedToBackup` 多带 `previous_mode`），
  不然回滚会把文件放回来但变成 0600，那是没人要求也没人被告知的改动；以及测试替身里的 `rename`
  原本是空实现，"撤销删除"的测试怎么写都会过，一并补上。
  **靶机验证**（扩写后的 `pnpm lab:sftp-remove`，十台全过）：探针先问机器"你有没有真在对外提供某个
  目录"，有就把 webshell 种在那儿。lab-arena 上 nginx 确实在服务 `/var/www/html`——删之前 `curl`
  拿得到 `<?php ... ?>` 原文，删之后同一个副本 URL 返回 **403**，正文里既没有 `system($_GET`
  也没有执行标记 `SHELL-RAN`，原路径也不再是 200。九台标准靶机上断言副本以 `.removed` 结尾、
  权限 600、备份目录 700、内容与原文件逐字节一致（还能还原）。
  **残余风险**：web 服务器若以 root 跑，0700 挡不住它读，知道那串 uuid 的人仍可能把副本下载下来；
  但 `.removed` 让它不会被执行。要根治得让操作员选落点，成本远超一轮，见 OPEN_ITEMS 第 15 条。
- 2026-09-04 上传与打包在真机上验完了（补齐上上条剩的那半个 `NOT_RUN`），顺手把"操作失败了但不说
  为什么"改掉。新探针 `tools/lab/probe-sftp-upload-archive.mjs`（`pnpm lab:sftp-upload-archive`），
  仍然只用句柄一层层走进去。
  **上传**：暂存 → 计划 → 确认 → 执行，然后**在机器上重新算 sha256** 比对（300 040 字节，跨块），
  大小与内容都一字不差；同名再传一次会被拒绝、原来那份内容不变。
  **打包**：tar / tar-gzip / tar-zstd 三种格式，用机器自己的 `tar tf` 打开来看——包里装的正是选中的
  `evidence/one.log`、`evidence/two.log`，没把同目录下没选的 `unrelated.txt` 装进去。
  **这次跑出来的两件事**：
  1. lab-suse（openSUSE Leap 15.5 精简镜像）**根本没有 tar**，openEuler 反而有 zstd。
     探针最初写死"打包应该成功"，在 suse 上挂了四条——**是探针错，不是产品错**，
     和 RPM 那次一样：改成先问机器 `command -v tar/gzip/zstd`，有什么就验什么，没有就验它是否
     老实说了自己做不到。
  2. 说不出为什么失败。`sftp_browser_api.rs` 与 `emergency_path_api.rs` 的 `Ok(Err(_))` 分支
     **把 core 的错误整个丢掉**，一律回一句"操作未能完成。"——缺工具、磁盘满、没权限、
     文件被改过，四个字一模一样，而这四种的下一步完全不同。
     按抓包那次立的规矩（core 出句子、机器的话不过边界）在 `crates/lovelyhawk-core/src/sftp.rs`
     加了 `OPERATION_FAILURE_ADVICE` 表和 `operation_failure_advice()`：读机器说了什么、就地扔掉，
     只放行这边写好的句子，认不出来就还用调用方原来那句。现在没有 zstd 的机器会说
     "这台机器的 tar 打不出 zstd 包（没装 zstd，或者这个 tar 不支持）。改用 tar 或 tar.gz 再打一次。"
     needle 是从真机抄的：Debian 系报 `zstd: not found`，Alpine 的 busybox tar 报
     `unrecognized option: zstd`——两句话不同、下一步相同，所以映射到同一句。
  **九台靶机全部通过**（openEuler 连 zstd 的成功路径也真跑过，不只是失败路径）。
  仍未覆盖：不可读根目录、非 UTF-8 文件名、50k 条目 / 64 MiB 上限、symlink swap race，继续 `NOT_RUN`。
- 2026-09-04 从检查结果那一行直接处置，在真机上验完了。这是整个工具里"发现"到"它跑不起来了"
  之间最短的一条路：跑一条检查、看见一行点名了某个文件、就在那一行上选 去掉执行权限 或 隔离，
  全程不用打路径。它和文件管理器共用计划/确认/执行，但**路径句柄是从某一次运行的输出里现铸的**，
  这套从没在真机上跑过。新探针 `tools/lab/probe-emergency-path.mjs`（`pnpm lab:emergency-path`）：
  在 `/usr/local/bin` 下种两个 `chmod 4755` 的 `/bin/sh` 副本（名字取成 `.systemd-helper`
  这种像是本来就该在那儿的），跑 SUID 那条检查，然后：
  **句柄不串行** —— 每个 `pathHandle` 对应的文件都必须就是它那一行显示的那个（逐行核对，不是抽查）。
  **去掉执行权限** —— `EXECUTE_BITS = 0o6111`，setuid、setgid、三个执行位一起清掉，4755 → 0644；
  然后**问机器**：setuid 没了、执行位没了、`find -perm -4000` 找不到它了、直接执行它会被拒，
  但文件还在、还读得了（它还是证据）。同一个计划不能跑第二次。
  **变了就不动** —— 确认之后、执行之前把文件 `chmod 4700`，执行被拒、主机上一位都没改。
  **隔离** —— 走的是文件管理器同一条可恢复删除，所以副本同样以 `.removed` 结尾、600 权限、
  setuid 位也没了。
  **顺手修的一处文案错**：隔离 `/usr/local/bin/.dbus-helper` 时，计划却说"**网站**再也跑不动它"——
  那是上一条为 webshell 写的句子，套在一个 bin 目录下的 setuid 后门上就是假话，而这句文案
  根本无从知道文件在哪儿。改成描述它实际做的事："改名加 .removed、权限收成只有你能读，
  **原先靠这个名字把它调起来的东西（比如网站）**就找不到它了"，并加了断言防止它再退回去。
  **九台靶机全部通过**（每台真机上的 setuid 文件 13～20 个不等，全部认出来并给出了句柄）。
  另外注意到：上一条加的 `operation_failure_advice` 在这条路径上**没改一行代码就生效了**——
  "文件在计划之后被改过"现在会说"权限位在你做计划之后被改过了，所以没动它。重新看一眼再操作。"
- 2026-09-04 主机全景那四个会动手的行内操作，在真机上验完了——**并且发现其中两个从来就没能在任何
  真机上跑起来过**。新探针 `tools/lab/probe-system-info-mutations.mjs`
  （`pnpm lab:system-info-mutations`）：种一条 cron 后门、往 `/etc/profile` 里塞一行反弹 shell、
  在 `/usr/local/bin` 放一个 4755 的 `/bin/sh` 副本，然后从表格的那一行下手，再回机器上核对。
  **注释掉启动文件里的那一行**（`shell.comment-line`）：真机上是对的。改完之后逐行比对整个文件——
  只有那一行前面多了 `# LovelyRes disabled:`（当时的标记；改名后新注释的行使用 `# LovelyHawk disabled:`），行数一行不多不少，旁边的行一个字节没动，
  结尾换行还在，文件权限没被顺手改掉。
  **删掉独立 cron 文件**（`cron.delete-file`）：走的是文件管理器同一条可恢复删除，副本 `.removed`
  结尾、600 权限、备份目录 700（`/etc/cron.d` 是 cron 逐个读的目录，它进不去正是重点）。
  **两个真 bug**：
  1. `移除 SUID/SGID 位` 与 `权限隔离（000）` **在任何真机上都跑不起来**。前置快照命令写的是
     `stat -Lc "$sha\t%a\t..."`——可 `stat -c` **不解释反斜杠转义**（只有 `--printf` 解释，
     而 busybox 连 `--printf` 都没有），于是机器回的是字面量 `\t`，七个字段变成一个，
     一律报"remote output did not contain the exact snapshot schema"。
     内存测试之所以一直绿，是因为断言里写的 `"{sha}\t4755\t..."` 在 Rust 里是**真的制表符**，
     测试替身照着回，双方一起错开了真机。改成空格分隔（七个值都不含空格，GNU 与 busybox 都行），
     并加了断言禁止格式串里再出现 `\t`。
  2. 去掉 SUID 位的时候，**留底那份仍然是 setuid root 的**。备份是 `cp -aL` 做的，`-a` 把权限
     原样带过去了：操作员让工具把 setuid 拿掉，工具转手又造了一个还带着 setuid 的同样文件。
     0700 的目录挡住了别的账号，但 `find / -perm -4000` 照样列出它——在防御赛里等于工具自己
     制造了操作员来清的那条发现。改成 `cp -L` 加 `chmod 600`（`MANAGED_BACKUP_MODE`），
     复核也跟着改成核对 0600 而不是"和原文件权限一致"。还原不受影响：还原只核对副本的内容哈希，
     权限是从计划里记的原始模式恢复的。
  **顺带硬化的一处**：快照解析原本要求**整段输出**正好七个字段，于是机器的 shell 一开口报错
  （半截的 `.bashrc`、登录横幅、入侵者自己加的坏行）就会让处置被拒。在一台有人住过的机器上，
  shell 启动时吵是常态而不是意外，因为入侵者自己的 `.bashrc` 报了个错就不给拆后门，方向正好反了。
  改成在输出里找**最后一行**符合"七个空格分隔字段、第一个是 64 位十六进制"的行。
  这条是我自己在靶机上留了脏东西才撞出来的，正好变成了一条真的回归检查。
  **九台靶机全部通过**：ubuntu/debian/openeuler/deepin 上连"shell 一启动就报错"的场景也真造出来
  并通过了；rocky/alma/anolis/suse 的 bash 不读 `~/.bashrc`，造不出来就明说 SKIP；
  alpine 的 SUID 那张表根本列不出东西（见 OPEN_ITEMS 第 16 条），也明说 SKIP，不假装验过。
  **（后一条已于当天修掉，alpine 的 SUID 行内处置现在也真跑通了，见下条。）**
- 2026-09-04 busybox 机器上那三张表不再假装"什么都没发现"（关闭 OPEN_ITEMS 第 16 条）。
  setuid 文件、敏感文件、最近改动文件都靠 `find -printf` 采集，而 busybox 的 find 没有这个开关；
  错误被 `2>/dev/null` 吞掉，管道又以 `head` 结尾（退出码是 head 的 0），于是 sidecar 看到
  "命令成功、输出为空"，三张表一律按"确实没有"渲染。**一台装着 setuid 后门的 Alpine，工具会告诉
  操作员这台机器一个 setuid 文件都没有**——不是漏一行，是整张表的假放行。
  换成 `find … -exec stat -c '%a|%U|%s|%y|%n' {} +` 再交给 awk 拼列（`file_facts_awk!` 宏）。
  三处细节都有原因：`stat -c` 是可移植的那一半（busybox 没有 `--printf`）；`-exec … {} +` 成批
  调用；**路径放最后一个字段**，名字里带竖线也不会被切开；制表符由 awk 的 printf 生成，因为
  `stat -c` 不解释转义（上一条刚在这上面栽过）。同一个毛病的六处明细命令一并换掉。
  新测试 `no_command_asks_a_machine_for_find_printf` 逐行扫整个文件禁止这个开关再出现，
  当场抓出我自己漏掉的两处。
  **靶机验证**（新探针 `pnpm lab:file-tables`，九台全过）：不是"表非空"这种弱断言，而是
  **先问机器再问工具、两边数目必须一致**——alpine 从 **0 行变成 11 行**（机器上确实 11 个），
  ubuntu 18/18、suse 21/21，其余六台也全部一一对上；每一列都断言是真值（权限 `4755`、
  属主有名字、大小是数、时间是 `2026-09-04T16:18:57` 这种格式），并专门验了名字里带竖线的文件
  整条还在。上一条因表空而 SKIP 的 alpine SUID 行内处置，现在端到端跑通。
- 2026-09-04 把"假放行"这类问题在二十五张表上扫了一遍，又抓出四个。新探针
  `tools/lab/probe-tab-coverage.mjs`（`pnpm lab:tab-coverage`）在一台机器上把二十五张表全采一遍，
  报出每张表的行数、以及空表是哪一种空。**判据**：一张表在这台机器上满、在那台机器上空、
  且**没说为什么**，就是可移植性缺口的签名。拿 ubuntu 和 alpine 对着跑，四个当场现形：
  1. **软件包清单在 Alpine 上是空的**。命令只认 `dpkg-query` 和 `rpm`，Alpine 用 apk，
     整条 if/elif 落空、退出码 0、输出为空 → 表按"确实没有"渲染。
     **工具会告诉操作员这台机器一个软件包都没装**，而操作员正是来找那个不该装的包的。
     补了 apk（直接读 `/lib/apk/db/installed` 的 `P:`/`V:` 字段，不用 `apk info`——它把名字和版本
     用同一个减号粘在一起）和 pacman；并给这张表加了 `required_tool`，四个都没有的机器现在会说
     "这台机器没有 dpkg、rpm、apk 或 pacman"，而不是给一张空清单。**alpine：0 行 → 71 行**。
  2. **登录历史在 busybox 上是空的**。`last -Faiw` 是 GNU 的写法，busybox 整组拒绝、退出 1、
     stdout 什么都没有；而这张表的工具检查只问"有没有 last"，于是显示空的登录记录。
     改成 `{ last -Faiw || last; }`，并把 busybox 的表头行 `USER` 加进"永远不是用户名"的名单。
     **说明**：靶机里没有一台 busybox 机器有登录记录（alpine 的 `/var/log/wtmp` 是 0 字节），
     所以这条只机械验证了回退链会触发，没能端到端验出行来——如实记下。
  3. **防火墙表在七台机器上都是空的，而且没说为什么**。`iptables-save` 装着，但容器没有
     CAP_NET_ADMIN，它打印 "you must be root" 就停了。原来的注释写着"装了就够了"，
     实测每一台都推翻了这句。加了健康检查 `iptables-save 2>/dev/null | grep -q '^[*:]'`——
     真的规则集总会开一个表（`*filter`）或一条链（`:INPUT`）。deepin 现在说"iptables 没答上来"，
     ubuntu 仍然说"这台机器没有 iptables"，两种不再混为一谈。旧测试里断言
     `Firewall.tool_health().is_none()` 的那一行，是被真机推翻的，已连同证据改掉。
  4. **web 应用表在 Alpine 上空得没有理由**。工具检查认 `httpd`，Alpine 的 httpd 是 busybox 的，
     没有配置可导；采集器只会读 `nginx -T` 和 `apachectl -S`。改成按**采集器读得懂的东西**来检查
     （nginx / apachectl / apache2ctl），Alpine 现在说"这台机器没有 nginx 或 apache"（属实），
     lab-arena 上真有 nginx 的仍然是 4 行。
  **扫完之后九台上只剩两处空表，而且都是实话**：`kernel-modules`（容器里 `/proc/modules` 确实是空的）
  和 alpine 的 `login-history`（wtmp 确实 0 字节）。
- Snapshot 只读调查 phase 1：`crates/lovelyres-electron-backend/src/snapshot_read_api.rs`、
  `electron/src/shared/snapshot-read-contract.ts`、`snapshot-read-state.ts`、`snapshot-read-helpers.ts` 与
  `SnapshotPage.tsx` 已实现真实 opaque SSH binding、完整 `BoundSshSession`/`TargetGuard` 前后验证，并且
  只调用 core `SnapshotService` 的 `list_directory`、`list_forensic` 与 `diff_forensic`。Renderer 仅发送
  binding 和 opaque snapshot handles，不发送 core snapshot id、target/session/generation、host/fingerprint、
  命令、远端路径或摘要。目录响应最多 64 份、每份 8 个固定 preset，`bytes` 使用精确 u64 十进制字符串；
  `source`、`remote_root`、archive path、全部 SHA/digest 和 target identity 均不出 sidecar。每个目录项的
  `archiveAvailability` 固定为 `not-checked`，页面明确便携索引可读不表示远端归档仍存在、不可变或已重新
  验证。
  取证索引最多 10 份；详情固定 12 个 collector、最多 2,048 行/512 KiB、每字段 512 行、单行 4 KiB，
  serialized 响应限 768 KiB。差异固定 12 个 collector、每字段每方向 200 行、总计 1,000 行/512 KiB，
  serialized 响应限 768 KiB，并强制 baseline 时间严格早于 newer。公开投影按 collector 固定为 7/5：
  `processes`、`loginHistory`、`cronJobs`、`authorizedKeys`、`sudoers`、`recentModifiedFiles`、`envVariables` 的 detail 整段只返回
  `[SENSITIVE SNAPSHOT TEXT REDACTED]` 或 `[FORENSIC COLLECTOR FAILED]`，diff 的 added/removed 每方向也最多
  只返回一个相同固定 marker，旧内容不会进入 renderer。`networkConnections`、`listeningPorts`、
  `startupServices`、`runningUsers`、`loadedModules` 才允许有界、控制字符归一化的
  plain text，并继续对已知 credential marker 与当前 target/session literal 失败关闭；这只是闭合公开面，
  不宣称能够从任意文本识别所有秘密。Core portable snapshot/export 仍可能持有原始采集文本，必须继续作为
  core-owned 敏感数据保护。opaque catalog TTL 为 5 分钟，限 8 个 catalog、每个 128 KiB、registry 总量
  1 MiB；list 限全局 2 个且每 binding 1 个，详情/差异限全局 8 个且每 catalog 3 个。同 scope 刷新可为
  未变化记录复用 opaque handle 以保持选择，但会轮换内部 token；目标切换、断连、TTL、淘汰和晚到结果均
  失败关闭。
  Snapshot 只读 phase 1 已不再是 `UNWIRED`：`BackendState`、三个固定 RPC、main exact IPC、frozen preload、
  aggregate `LovelyResApi` 与 App page registry 已中央接线，main 公开 API 从 67 精确增加到 70。App 只把当前
  opaque `bindingHandle` 交给 `SnapshotPage`，不传 `ActiveSshTarget`、connection/host/port/username/timestamp
  或其他公开目标摘要；断连会清理该 binding 的 catalog，页面卸载和晚到结果继续失败关闭。
  Core 预投影 hardening gap 同轮关闭：portable snapshot document 在反序列化前受 128 MiB encoded-size
  上限约束，目录/取证索引在 deserializer 中分别硬限 64/10，forensic diff 在建立集合前同时执行每字段
  2,048 行与总计 8,192 行上限。篡改的 oversized/count 文档与过量 diff 输入均有 fail-closed 测试。
  已观察证据包括 `snapshot_read_api_standalone.rs`、central backend RPC、core all-targets、Electron 89 个
  Vitest 文件/460 项、exact70 source gate，以及
  `target/electron-debug/7078e63f-be4f-47be-a3bf-6d50df216d1a/evidence` 的断连/伪造 capability/CDP/
  capturePage。真实 Linux/SSH 的 populated index、权限拒绝、断连、TTL、目标切换与 corrupted-store 实机
  矩阵仍为 `NOT_RUN`。create/capture/export/restore/delete/journal mutation、文件、terminal 和 AI 属于后续
  独立安全设计，phase 1 不提供 API 或按钮；因此页面仍为 `Pending`，不得标记 Completed。
- Emergency Commands / command workbench phase 1：
  `crates/lovelyhawk-backend/src/emergency_command_api.rs`、
  `ui/src/shared/emergency-command-contract.ts`、`emergency-command-state.ts`、
  `emergency-command-helpers.ts` 与 `EmergencyCommandsPage.tsx` 已建立独立的固定目录执行边界。Sidecar
  load 时从真实 opaque SSH binding 捕获 `BoundSshSession` 与完整 `TargetGuard`，只调用 core
  `CommandWorkbenchService::catalog`、`detect_system`、`execute`；系统 family、raw catalog id 和固定 shell
  文本仅保存在按 binding/snapshot 隔离的 registry。中央 public API 固定且仅为
  `loadEmergencyCommandCatalog(bindingHandle)` 与
  `runEmergencyCommand(bindingHandle,snapshotHandle,commandHandle)`；renderer 只发送 opaque handles，不发送
  family、command、target/session/generation、host、path 或任意用户输入。
  Catalog 最多 64 项，title 128 bytes、description 512 bytes、timeout 1..=60 秒；registry 最多 8 份、
  每份 64 KiB、总计 512 KiB、TTL 5 分钟。系统识别 sidecar deadline 为 15 秒；执行依赖 core 固定
  30 秒 timeout 并另有 40 秒 sidecar deadline。load 全局并发 2 且同 binding 1，execute 全局并发 4 且
  同 binding 1；刷新、TTL、淘汰、断连、完整 target epoch 变化和晚到结果均失败关闭。即时执行 DTO 最多
  2,000 行/256 KiB、单行 4 KiB、serialized 384 KiB；credential-like 行、binding/session/connection/
  target identity literal 和 raw catalog id 逐行替换为固定 marker，hostile 文本只进入 React text node/`pre`。
  即时 DTO 与 portable history 是两条独立边界：core `command_workbench.rs` producer 已最小加固为 history
  只保存固定不可执行 identity、固定有界 result/exit 摘要与安全 title，不保存 raw catalog id、shell 文本或
  即时输出；现有 history schema/detail/search 保持兼容，保守 `mutating` 风险使 Electron replay consumer
  明确返回 blocked。测试直接读取 portable history 文件并证明 shell、credential marker 与 hostile output
  不落盘。
  BackendState 单例、exact2 RPC、main/preload exact91、aggregate contract 与 App binding-only page registry
  已中央接线；SSH disconnect 会在真实断连前 eager 清理 Emergency registry。当前代码面验证包括 backend
  library 190/190、standalone 31/31、Electron 98 files/532 tests、source gate/fixture self-test，以及
  `target/electron-debug/38fc68d4-41d7-43fc-ace8-ef4afdf08da5/evidence`：真实 Electron
  `webContents.debugger`/CDP 证明 catalog/run 的直接与 unknown-field 请求均拒绝且不回显，禁用的
  custom/shell/file/terminal/export/mutation/generic surface 均为 `undefined`；断连页零远端 rows、
  local-only、无内部身份，卸载重挂载仍为空，console error 为 0，并由 `capturePage` 生成截图；标题与提示
  对比度为 14.15:1/4.77:1。较早的 `136bb2ce` 报告因探针仍期待旧 API 排序而为 `FAIL`，不得引用为通过。
  仍缺 Debian/Red Hat/Alpine/SUSE/Arch/Other 的真实命令存在性、权限拒绝、timeout、取消、断连竞态和
  目标切换矩阵。
  phase 1 不提供 arbitrary command、terminal、file、export、AI、mutation plan 或邻接动作；真实 SSH/Linux
  验收继续为 `NOT_RUN`，危险 mutation/审计/验证/恢复 parity 尚未迁移，因此页面继续计为 `Pending`。
- SFTP 文件管理（已并入 SSH 窗口，写操作走计划链）：
  `crates/lovelyhawk-backend/src/sftp_browser_api.rs` 已在 lib.rs 注册，对外是九个固定 RPC：
  `sftp-browser.open`、`.directory.list`、`.text.read`、`.download`、`.operation.plan`、
  `.operation.confirm`、`.operation.execute`、`.operation.cancel`、`.upload.stage`。Electron 时期 SSH 窗口的 preload
  面固定为 18 个方法（主窗口当时是 118），由 gate 与 CDP probe 双向钉住；现由宿主
  `crates/lovelyhawk-desktop/src/child_commands.rs` 的 `sftp_*`/`local_*` 命令与子窗口 capability 提供。renderer 全程只拿 opaque
  handle：binding 由宿主依据发起窗口反查，终端 renderer 从不持有 binding handle，远端路径、raw
  session/guard/generation/identity、host/fingerprint、本地路径都不进 DTO。
  读取仍只调用 core `SftpService::bind_session`、`list`、`read_text`，固定从 `RemotePath("/")` 打开；
  目录压到 128 项/128 KiB、名称 256 bytes，文本压到 2,000 行/256 KiB、单行 4 KiB、序列化 384 KiB。
  下载由宿主打开系统保存对话框、再走 core `download_new(&session, &self.paths, …)`，本地目标由
  `PathGuard::ensure_safe_download_target` 校验；上传先由宿主打开系统打开对话框，后端以
  `stage_upload` 把字节落到受管目录（单文件上限 64 MiB），renderer 始终不说出任何本地路径。
  一切改动目标的操作只有一条路径：plan → confirm → execute_and_verify → 失败时 restore。计划单次
  可用（取出即消费）、TTL 120 秒、同 target 最多 8 个、执行上限 90 秒；支持新建目录、重命名、
  设置权限、删除、打包（tar / tar-gzip / tar-zstd）与上传。名称是唯一的自由输入，拒绝分隔符、
  控制字符、`.`/`..` 与超长值。按“可信条件下不做主动隐藏”的约定，名称与预览一律原样呈现，只保留
  控制字符净化与体积截断。
  本地一侧由宿主 `crates/lovelyhawk-desktop/src/local_browser.rs` 提供（Electron 时期为
  `electron/src/main/local-browser.ts`），同样只发 handle，`lstat` 描述软链接而不跟随。
  验收测试为 `sftp_browser_api.rs` 内联测试（含 closed-core-surface、名称校验、格式白名单、计划作用域）、
  core `sftp::tests::directory_list_refuses_files_symlinks_and_stale_targets_before_read_dir`、
  `sftp-browser-contract.test.ts`、`sftp-browser-state.test.ts`、`sftp-browser-page.test.tsx` 与
  `ssh-window.test.tsx`。仍缺真实 OpenSSH/Dropbear 的不可读根目录、空目录、50k/64 MiB core 上限、
  非 UTF-8/2 MiB 文件、权限拒绝、慢请求、断连、目标切换、symlink 与 swap race 矩阵，以及上传/打包/
  删除在真机上的验证与回滚证据；这些真实 SFTP 验收继续为 `NOT_RUN`，页面因此仍计为 `Pending`。
  本切片不提供解压、就地编辑、终端跳转、导出与 AI 的 API/按钮。
- Notification stack：`notification-state.ts` 与 `NotificationStack.tsx` 已实现去重、3/5 秒超时、64 项
  上限、持久项、手动关闭和 hostile plain-text。仍缺 App-level host、所有生产调用点、overlay stacking
  以及桌面 CDP timer/accessibility 证据。
- Dialog host：`dialog-state.ts` 与 `DialogHost.tsx` 已实现 alert、非秘密 prompt 和 opaque-handle-bound
  dangerous confirmation，含 UTF-8 边界、action/id 匹配、focus trap/restore、Escape 取消和危险操作
  不响应 Enter。仍缺 App-level controller、所有生产调用点、与各领域 plan/cancel 方法的 typed 绑定及
  桌面 CDP；generic host 不能成为任意 backend action 或通用确认能力。
- Application log：`crates/lovelyhawk-backend/src/diagnostic_log_api.rs`、
  `ui/src/shared/application-log-contract.ts`、`ApplicationLogOverlay.tsx` 与 main-only export helper
  已实现 500 条结构化 `tracing` ring、动态级别、有界筛选/预览、敏感字段与任意 Debug/Error 脱敏、
  volatile-only clear，以及 `wx` + fsync 的非覆盖导出。该切片不从 backend stderr 反向读取或转发内容到 renderer，renderer
  export 结果只有 basename/count/truncated，不能取得路径或正文。唯一 sidecar subscriber 现同时挂标准 fmt
  stderr layer（独立 per-layer `EnvFilter`）与 Application Log capture layer；BackendState 单例、exact5
  list/level/volatile-clear/preview/export-prepare RPC、strict main/preload、native save dialog、frozen exact112 API 与
  App-level overlay host 均已中央接线。内部 export payload 只到 main，renderer 不取得路径、正文、stderr、
  arbitrary file 或 generic invoke surface；关闭、Escape、导航、断连和卸载都会先作废 overlay 的迟到结果，
  但 SSH disconnect 不清除 process-local ring。当前 aggregate evidence 为 backend library 248/248、16 个
  standalone targets 共 451/451（总计 699 tests）、Application Log standalone 11/11、Electron full
  102 files/594 tests、typecheck/build、workspace check/Clippy/rustfmt，以及 exact112 source gate/fixture self-test。
  Electron-native CDP 证据 `target/electron-debug/19adbfae-598c-4eee-b7f1-cc2a666e3ac7/evidence` 已验证 exact5
  surface：list/level/preview/export unknown-field 请求 reject-no-echo，stderr/file/path/internal-payload/generic
  均为 `undefined`；overlay 显示 0/500 ring、无 entry/detail/error rows 或内部 payload，focus/inert/Escape restore、
  unmount/remount 清理、local-only resources、`application-log-overlay.png` capturePage 与 0 console errors 均通过。
  便携 rolling-file writer 与 packaged native save-dialog/实际落盘 smoke 仍为 `NOT_RUN`，因此 exact5 不再计为
  `UNWIRED`，但 overlay 整体仍为 `mixed`/`Pending`，不得标记 Completed。
  2026-10-11 更新：滚动日志文件已接通（`DiagnosticLogCapture::persist_to`，宿主在取得实例锁后传入 `data/logs`），
  桌面探针 21/21（`probe-application-log.mjs`，含程序退出后文件仍在、整行带时间、记录了被拒的保存、
  没有口令）；剩下的只是打包版本里真实保存对话框的导出验证。
- File Integrity：`crates/lovelyhawk-backend/src/integrity_api.rs`、
  `ui/src/shared/integrity-contract.ts`、`integrity-state.ts`、`integrity-helpers.ts` 与
  `IntegrityPage.tsx` 已把 Phase 0 收窄为 exact5 只读 surface：preset、目标作用域 baseline 列表、comparison
  start/poll/cancel。Backend 在 dispatch 前后及结果 apply 前验证完整 `TargetGuard`，并限制 opaque handles、TTL、
  registry bytes、单 binding 并发、事件 cursor 和响应字节；`close_binding` 会中止任务并回收 handles/bytes/
  permits，晚到结果不能复活。credential、URI userinfo、binding/session/connection/target literals 与 C0 在 renderer
  前按固定规则脱敏或投影。Renderer 仅持 binding 与 opaque capabilities；切换、卸载和错配响应会主动取消并
  失败关闭，hostile text 只进入 React 文本节点。当前 evidence 为 standalone 29 tests（Integrity 专项 7）、
  contract/state/helpers/page 4 files/18 tests，以及 Electron 100 files/563 tests、typecheck/build、Clippy 与 workspace
  rustfmt。（以上为 2026-08 的只读阶段记录。）

  2026-10-11 起已接上新建基线和对发现的处置，并在 Tauri 桌面窗口里验收：
  - 新建基线放在单独的 `integrity_write_api.rs`（只读的 `integrity_api.rs` 仍不含任何写操作，其测试照旧）。
    页面只能勾选预设位置（后端只收预设编号，不收路径）。点“新建基线”先弹出确认，说明会读取哪些位置、清单写在目标机的
    `/tmp/.lovelyres_fim`、被记录的文件不会被改动；确认后按开始 / 轮询 / 取消运行（`integrity.baseline.create.*`），
    显示已用时间，可以取消；取消后远端的临时文件由 core 的 trap 清掉，不会留下没登记的清单。
  - 待决定：自定义位置。core 本身接受任意绝对路径，很多主机的网站目录不在预设里（例如宝塔的 `/www/wwwroot`、
    `/usr/share/nginx/html`），但源码门禁明确不许完整性页接收自行输入的路径（`customPath|pathInput`），所以目前不提供。
    要放开需要先改这条门禁规则并说明理由，或者把常见网站目录加进预设清单。
  - 比较结果里新增或改动、且路径完整显示的文件带“文件操作”（也可右键），用的就是命令工作台那套：查看属性、
    下载留证、去掉执行权限、隔离，先出计划再执行，完成后 10 分钟内可撤销。路径登记分来源存放
    （`PathOfferSource`），比较页和命令工作台互不覆盖对方的入口。被脱敏、截断或改写过的路径和已删除的文件不提供操作。
  - 页面上原来的“Phase 0 仅列出并比较已有基线……”这类实现说法已改成人话。
  - 九台靶机 `tools/lab/probe-ui-integrity.mjs` 各 19/19：相对路径被点名拒绝、只写入一个清单、比较找出新增和改动、
    隔离后原位置消失并留副本、撤销恢复 4755、改动文件去掉执行权限、第二次新建在中途取消且不留清单。
  - 仍有的限制：core 自带的 `plan_quarantine`/`execute_quarantine`（移到 `/tmp/.lovelyres_fim/quarantine`，不绑定内容哈希）
    没有接线，页面用的是绑定内容和身份、放在同目录 `.lovelyres-backups` 的那套。
- Kubernetes 只读调查 phase 1 已中央接线：`crates/lovelyhawk-backend/src/kubernetes_read_api.rs`、
  `ui/src/shared/kubernetes-read-contract.ts`、`kubernetes-read-state.ts`、
  `kubernetes-read-helpers.ts` 与 `KubernetesPage.tsx` 已实现真实 opaque SSH binding、完整
  `TargetGuard` 前后验证，以及只调用 core `KubernetesService` 的 availability、namespaces、pods、
  deployments、nodes、有界详情和最近 Pod 日志。Renderer 只发送 binding/snapshot/row capability；
  namespace scope 也由目标绑定的 Namespace 行 capability 表达，不发送 session、guard、generation、
  identity、资源 UID/名称/namespace、命令、日志参数或远端路径。快照为 5 分钟 sliding TTL，registry
  限 24 个/32 MiB，每快照限 4 MiB，列表限 500 行/2 MiB，详情 256 KiB、日志 512 KiB，并限制全局与
  逐 binding 并发；过期、淘汰、目标切换及晚到结果均失败关闭。owner 为 Electron Kubernetes read
  migration。BackendState 已注册 exact4 固定 RPC，main/preload/aggregate contract 只公开
  `getKubernetesAvailability`、`listKubernetesResources`、`getKubernetesResourceDetail`、
  `getKubernetesPodLogs`；main 对请求与响应作严格 exact-object 验证，unknown/forged 参数固定失败且不回显。
  `App`/`KubernetesPage` 只接收 opaque `bindingHandle`，不接 target identity、connection/session metadata；
  SSH disconnect 在实际断连前 eager `close_binding`，过期、淘汰、目标切换及晚到结果均失败关闭。验收测试为
  `kubernetes_read_api_standalone.rs`、`kubernetes-read-contract.test.ts`、`kubernetes-read-state.test.ts`、
  `kubernetes-read-helpers.test.ts`、`kubernetes-page.test.tsx` 与 `kubernetes-read-boundary.test.ts`。
  source gate 与 fixture self-test 已接受 main exact89、Kubernetes exact4、strict validators、backend
  redaction/guard/bounds、opaque-only App、forbidden surfaces 及 eager close-before-disconnect；最近完整 Electron
  check 为 97 files / 522 tests，backend library 为 177/177，standalone 为 38/38。Electron-native CDP 证据
  `target/electron-debug/0ad5379b-1186-4f2c-892e-0b54a87cd4d1/evidence` 已验证 main exact89、forged/unknown
  reject-no-echo、forbidden scale/restart/delete/cordon/drain/exec/file/terminal/export/generic `undefined`、断连
  title/prompt/零 rows/local-only/no internal identity、`kubernetes-disconnected.png` capturePage、unmount/remount
  clear、Kubernetes/全局 console error 0，以及标题/提示 14.02:1/4.73:1 对比度。真实 Linux/SSH/
  Kubernetes 的权限拒绝、空集/populated、超限、日志截断、取消、断连及 target-switch 同样 `NOT_RUN`。
  SFTP 定位在 keyed SFTP window 能安全绑定同一 TargetGuard 前不提供入口；scale/restart/delete/cordon/drain、
  exec、文件、终端、导出及任何 generic mutation 均属于后续独立安全设计，仍为 `UNWIRED`。因此页面整体
  保持 `mixed`/`Pending`，不把 phase 1 的代码面接线误报为完整 parity。
- 网络抓包 live phase 1 已中央接线：`crates/lovelyhawk-backend/src/packet_capture_live_api.rs`、
  `ui/src/shared/packet-capture-live-contract.ts`、`packet-capture-live-state.ts`、
  `packet-capture-live-helpers.ts` 与 `PacketCapturePage.tsx` 已实现真实 opaque SSH binding、完整
  `BoundSshSession`/`TargetGuard` 前后验证，并且只调用 core `PacketCaptureService::list_interfaces` 与
  `start_live`；远端命令、tcpdump 参数 quoting、PTY 与 `LivePacketCapture` 生命周期仍由 core 持有。
  Renderer 只发送 binding/interface/capture capability 和严格的 filter/packetLimit/durationSeconds，
  不发送 interface 名、session、guard、generation、identity、命令、远端路径或 core capture id。
  interface capability 为 5 分钟 TTL，限 256 项/2 MiB；capture 限全局 8 个、每 binding 1 个，最多保留
  512 个事件/400 个数据包/4 MiB，每次 poll 限 100 个事件/512 KiB，单事件 64 KiB，并限制全局 12 个、
  每 binding 3 个并发操作。重复 start、过期/淘汰、断连、目标切换、artifact 事件、cursor reset 和晚到
  结果均失败关闭；失活、切换、卸载、poll 失败和终态都会真实调用 `request_stop`/`stop`，公开失败不回显
  attacker-controlled tcpdump stderr。BackendState 单例、exact4 RPC、main/preload exact100、aggregate contract、
  App binding-only page registry 与 SSH disconnect 前 awaited `close_binding` 均已接线。当前代码面验证包括
  backend library 221/221、standalone 33/33、Electron 100 files/562 tests、all-target check/Clippy、workspace
  rustfmt，以及 source gate/fixture self-test。`target/electron-debug/2d9db536-7817-4047-9c41-87e90a2e48d9/evidence`
  的真实 Electron `webContents.debugger`/CDP 已验证 main exact100、8 个 direct/unknown-field 请求拒绝且不回显、
  command/file/terminal/download/export/AI/mutation/generic surface 均为 `undefined`、断连页零远端 rows、local-only、
  无内部身份、卸载重挂载清空、Packet Capture/全局 console error 为 0，并由 `capturePage` 生成截图；标题与提示
  对比度均为 11.10:1。仍缺真实 Linux/SSH 的 tcpdump 缺失、root/non-interactive sudo、
  `CAP_NET_RAW`/`CAP_NET_ADMIN`、权限拒绝、空接口、超限、超时、PTY backpressure、断连、目标切换和
  取消矩阵——**其中 tcpdump 缺失、root/非交互 sudo 与"能抓到真流量"三项已于 2026-09-04 补齐，见下条**。
  PCAP evidence/download/export/cleanup、案件持久化、任意文件/终端和 AI 属于后续独立安全链，
  phase 1 不提供 API 或按钮；整个页面继续为 `Pending`，但 live phase 1 不再计为 `UNWIRED`。
- Firewall 只读调查 phase 1：`crates/lovelyres-electron-backend/src/firewall_read_api.rs`、
  `electron/src/shared/firewall-read-contract.ts`、`firewall-read-state.ts`、
  `firewall-read-helpers.ts` 与 `FirewallPage.tsx` 已实现真实 opaque SSH binding、完整
  `BoundSshSession`/`TargetGuard` 前后验证，并且只调用 core `FirewallService::inspect` 与当前目标
  `list_changes`。规则在 sidecar 再限制为 256 KiB 并清理非换行/Tab 控制字符；history 最多 256 条，
  只返回 opaque change handle、闭合 backend/engine/kind/state、512-byte 标签、SSH 端口和时间戳，绝不返回
  raw change id、operation ids、remote root、object name、preflight digest、路径、session、guard、generation、
  identity 或命令。快照为 5 分钟 TTL，registry 限 12 个、每个 768 KiB、总量 4 MiB，history 响应限
  512 KiB，并限制全局 8 个、每 binding 2 个并发读取；同一目标刷新复用稳定 change handle，过期、淘汰、
  断连、目标切换及晚到结果均失败关闭。页面只有“当前规则/变更历史”、手动刷新、规则搜索和通过 injected
  clipboard callback 的有界纯文本复制；不会回退到 renderer `window` clipboard API。owner 为 Electron
  Firewall read migration。中央 `BackendState` 现已共享同一套 core services/SSH registry，并且只注册
  `firewall.inspect` 与 `firewall.change-history.list` 两个 strict params RPC；main/preload/LovelyResApi 也只增加
  arity-1 的 `inspectFirewall` 与 `listFirewallChangeHistory`，使 main frozen preload 从 exact70 变为 exact72。
  SSH disconnect 在真实断开前 eager 清理该 binding 的 Firewall capabilities，App 只把当前 opaque
  `bindingHandle`、固定 API 与既有 128 KiB main-owned clipboard callback 交给页面；UTF-8 截断不会切开
  scalar，并显示明确截断提示。固定错误不回显 hostile params，页面失活、断连与 scope 切换拒绝晚到结果。
  验收测试为 `firewall_read_api_standalone.rs`、中央 RPC/IPC/preload exact tests、
  `firewall-read-contract.test.ts`、`firewall-read-helpers.test.ts`、`firewall-read-state.test.ts`、
  `firewall-page.test.tsx` 和 Electron `webContents.debugger`/`capturePage`；CDP 证据包含 exact72、两次伪造
  capability 拒绝且不回显、无 Firewall mutation/generic/file/terminal/export surface、断连空态、导航重挂载、
  本地资源、对比度、零 console error 与 `firewall-disconnected.png`。仍缺真实 Linux/SSH 的
  iptables/nftables/UFW/firewalld 缺失、active/empty 组合、root/non-root、非交互 sudo、超限、断连和目标切换
  成功矩阵，全部保持 `NOT_RUN`。本阶段明确不调用 `reconcile`，所以过期的
  `awaiting-keep` 记录不会被只读层擅自解释为已经自动恢复。任何 block/allow/isolate/keep/restore/reconcile
  必须在后续 phase 2 重新建立 core-owned immutable plan、exact dangerous confirmation、journal、远端
  dead-man、独立 verify 和 restore 闭环，并完成真实自锁/自动恢复矩阵；phase 1 不提供 mutation API、按钮、
  generic execute、terminal/file/export；由于 phase 2 与真实 Linux 矩阵尚未完成，页面继续计为
  `Pending`，不得据此宣称 Firewall 完整迁移。

## Windows 应急响应补充（2026-10-24）

工作台的树形文件/注册表、进程关联查询、日志类别和扩展基线已沿 core → backend → shared/host → 页面接线。内嵌 RDP 沿专用主窗口命令接入原生客户端显示区域，保持宿主禁止 unsafe；属于实验性能力，尚缺真实远端登录、鼠标键盘、DPI、焦点和重连证据。详见 [Windows 工作台](WINDOWS_INCIDENT_WORKBENCH.md)。仍缺完整 EVTX 解析、案件链路、经过确认和独立复核的 Windows 自动修补与恢复，不能因本轮 UI 完成关闭这些待办。
