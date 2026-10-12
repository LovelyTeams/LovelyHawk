# Nginx 普通进程模式的修补与恢复

更新日期：2026-09-08。此能力属于 `MiddlewareService`，覆盖满足下述条件的普通 Linux / Docker Nginx 进程。桌面入口位于“配置 → 修补已有配置”，已接通目录列表、版本显示与 TLS 协议的有限修补、历史与恢复；不代表通用中间件编辑器或全部 Nginx 基线均已完成。

## 当前范围

- 默认启动 `nginx` / 实际可执行文件绝对路径，以及后接 `-g 'daemon off;'` 的前台启动。Nginx 会改写进程标题，其他启动参数不能从被压平的标题中无歧义还原，因此明确拒绝；不猜测 `-c`、`-p`、任意 `-g` 或包装脚本。
- 目标需预先具备 Python 3.9+、Linux `pidfd_open` / `pidfd_send_signal`，以及读取该 master 的 procfs、可执行文件、环境和配置的权限。缺少能力时返回具体限制，产品不会安装工具或提权。进程必须与 SSH 执行环境共享根目录和挂载命名空间。
- 主配置与 prefix 来自该 master 所用二进制的 `nginx -V`，不是任选一个存在的候选文件。配置必须在已有 Nginx 白名单根内且路径规范、文件常规；原生验证保留默认启动方式及 master 环境，环境内容留在目标。
- 发现记录 PID、启动时钟、boot ID、可执行文件/进程标题/环境摘要及命名空间。配置图仍使用已有有界 include 解析、文件摘要和目录清单；保留按文件、按节点的无损修改。
- 同一主配置由多个 master 使用时拒绝发现；生成计划后新增共享该配置的 master，也会使原来的验证和重载权限失效。

## 桌面操作流程

1. 连接目标，进入“配置 → 修补已有配置”，点击“识别 Nginx 实例”，选择运行实例后只读加载配置图。
2. 搜索并选择具体文件、具体行号的目录列表、版本显示或旧 TLS/SSL 协议位置。`autoindex on` 与 `server_tokens on/build` 只将所选节点改为 `off`；TLS 规则按下节移除旧协议，保留其他作用域和格式。未解析引用会阻止修补，空列表不表示整个实例合规。
3. 预览操作目标、配置差异、重载影响和备份条件，再逐次确认。目标地址与进程来自已经绑定的真实 SSH 会话和 core 实例，修补请求不能传入命令、文件路径、任意内容或确认材料。
4. 执行后显示已核实、已自动还原或尚未核实的状态。正在写入时等待验证；响应丢失不自动重试写入，后续通过修补历史检查。用户取消尚未执行的计划、切换目标或关闭旧页面后，迟到的准备/确认结果不能继续执行。
5. 从当前目标历史选择“准备恢复”，检查实际备份差异并再次确认。恢复预览独立检查当前文件和备份中的敏感值；含秘密的正文保持隐藏。文件、配置图、实例或备份变化时拒绝覆盖后续业务修改。

实现使用一个闭合的 `nginx.repair` RPC，动作含发现、读取、计划、确认、执行、查询结果、取消、历史和恢复，以及只读监听与连接复核。每个计划最长 5 分钟且只能执行一次。有限结果、身份和缓存均有上限；客户端不持有目标命令或备份正文。页面桥接层 `ui/src/host/main-api.ts` 直接使用 shared 契约校验请求，再经宿主的方法白名单交给后端。

## TLS 协议修补

`ssl_protocols` 中明确出现 `SSLv2`、`SSLv3`、`TLSv1` 或 `TLSv1.1`，并同时保留至少一种 `TLSv1.2` / `TLSv1.3` 时，可准备“移除旧版 TLS/SSL 协议”。规则只删除已知旧协议，保留原现代协议组合与顺序，不自动添加 TLS 1.3，也不改证书、私钥、密码套件或 OpenSSL 安全级别。独立指令、注释和其他 server 作用域保持原样；引号内的单个已知协议可识别，未知值、变量、无法解析的转义或仅旧版协议需另外规划升级。

确认页展示准确差异，并说明仅支持旧版协议的客户端可能无法连接。协议协商还受监听地址的默认服务器、继承及 OpenSSL 设置影响；即使修改的是某个具名 server，也不能据此推断对应域名已经禁用旧协议。配置原生检查和工作进程切换通过后，仍需对实际地址与 SNI 进行连接、证书及业务检查。恢复完整备份会撤销该修补，确认页明确提示旧协议可能重新启用。

旧协议的安全依据为 [RFC 9325 §3.1.1](https://www.rfc-editor.org/rfc/rfc9325.html#section-3.1.1)；此有限配方不代表完成整份 TLS 安全规范。指令语义依据为 [Nginx HTTP SSL 模块](https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_protocols) 与 [Stream SSL 模块](https://nginx.org/en/docs/stream/ngx_stream_ssl_module.html#ssl_protocols) 的协议参数和默认服务器说明；实际可用版本以目标 Nginx/OpenSSL 为准，文档不替代目标验证。

## 执行与恢复

写入走原有不可变计划、逐次确认、原子比较写入、远端备份、journal 和恢复记录。执行与验证期间反复核对目标、进程身份和整个配置图；配置或实例变化后不能重放旧计划。未确认、过期或已执行的计划在写恢复记录前拒绝，重复执行不能把 `Applied` 误写回 `RecoveryPending`。

配置检查通过固定的、保持打开的可执行文件执行 `nginx -t`，不会把远端进程标题当作 shell 程序。验证实际构建配置，避免恢复记录被篡改后把另一个文件冒充实例主配置。

重载先取得指向该 master 的 pidfd，再核对身份并发送 HUP；不依赖可能陈旧的 PID 文件，不向重新使用该 PID 的其他进程发信号。15 秒内检查新工作进程出现并稳定、旧工作进程不再以接收新请求的状态出现；无法证明切换时不能报告成功。旧进程处理已有长连接的退出时间不强制设为零。

失败恢复要求当前文件、配置图、目标和 master 身份仍符合原计划。恢复原始字节后再执行原生配置检查、重载与进程验证；若并发变更或实例消失使恢复不安全，保留备份和恢复失败记录，不覆盖新业务状态。持久记录新增运行时种类和有界进程证据，旧记录默认保持 systemd 语义，不能通过丢失证据降级为无保护的进程操作。

工作进程切换是服务运行层面的证据，**不等于业务接口、TLS、全部站点或全部长连接已经恢复**。界面明确提示继续检查业务；自动业务健康验证仍待按具体目标接入。实验另用真实 HTTP 请求独立检查目录暴露和版本响应头，并用指定协议、CA 与主机名校验的 TLS 连接检查协议变化。桌面已接通目标本机的监听、SNI、证书与 HEAD 观察，见 [连接复核](NGINX_CONNECTIVITY.md)；这不自动改变修补结果或触发恢复，也不代替外部业务客户端验证。

## 可重复实验

```powershell
# helper 拒绝路径：无需第三方 Python 包
wsl -d Ubuntu -e python3 /mnt/d/LovelyRes/tools/lab/test_nginx_process_helper.py
# 独立容器 + SSH + 实际 core 计划/确认/写入/验证/恢复
node tools/lab/probe-nginx-process.mjs
# 先构建最新后端和桌面应用，再测试真实 RPC 与原生窗口
cargo build --locked --package lovelyhawk-backend --bin lovelyhawk-backend
pnpm desktop:build
node tools/lab/probe-nginx-repair.mjs
```

探针使用本地 `lovelyres-svc:nginx` 镜像（实验镜像名沿用旧前缀）创建唯一容器，核对完整 ID、摘要、标签、网络、挂载和非特权状态，限制 384 MiB / 1 CPU / 128 PID，SSH 仅绑定 WSL 私有地址。Python 只安装在本次新建的实验容器中。测试临时连接库与用户数据分开，结束时按身份回收容器和临时数据，报告留在 `target/lab-nginx-process/<runId>/`。

验证范围包括无 systemd 的发现、默认与相对 include 配置、伪造启动时间/配置来源拒绝、前台运行、复杂启动参数拒绝、原生配置检查、工作进程切换，以及 core 的未确认拒绝、坏配置自动恢复、端口占用导致重载失败后的恢复、目录与版本修补、幂等/重放拒绝、持久恢复、并发修改保护与 master 重启后的旧计划拒绝。僵尸进程不会被误认作可服务的 worker，也不会阻断其他 worker 的调查。Cargo 必须实际选择并完成指定测试；零项测试和缺少完成标记均算失败。早期无效/编译失败报告保留，不计为通过。最新结果见 [产品进度](PRODUCT_ROADMAP.md)。

桌面探针在同样的唯一容器与独立应用数据目录上使用真实后端、桌面应用原生 CDP（Electron 时期为 sidecar 与 Electron CDP）、HTTP 请求与 OpenSSL 客户端；覆盖计划取消、未确认/重放拒绝、目录、版本及 TLS 协议修补、恢复预览与执行、外部配置修改保护、键盘焦点、最小窗口 1080×700、断连清空和控制台异常。报告与截图保留在 `target/lab-nginx-repair/<runId>/`。准备实验状态的文件写入不计为产品修补；产品效果必须由实际确认/执行路径触发后再独立核对。

尚未验收：rootless/只读/ARM、其他发行版和 Nginx 版本、OpenResty/Tengine、复杂启动参数、多 master 共享配置的安全修补、商业 Nginx、跨证书/默认服务器/协议覆盖的完整 TLS 矩阵、自动业务健康和跨重启恢复。共享配置当前验证的是拒绝路径，不能登记为修补兼容。

依据：[Nginx 命令参数](https://nginx.org/en/docs/switches.html)、[HUP 与工作进程切换](https://nginx.org/en/docs/control.html)、[Nginx 1.27.5 include 路径源码](https://github.com/nginx/nginx/blob/release-1.27.5/src/core/ngx_conf_file.c)、[Python pidfd 信号接口](https://docs.python.org/3/library/signal.html#signal.pidfd_send_signal)。

前一轮 TLS 配方实验（Electron 时期记录）在 Nginx 1.27.5、Debian 12 / x86_64 和 OpenSSL 客户端 3.0.20 上完成 **64/64** 条综合检查，报告 `target/lab-nginx-repair/8d65c59c-bdb8-4007-a413-aacb124ae993/report.json`。所用站点在修补前实际接受 TLS 1.0/1.1/1.2/1.3；经桌面确认修补后拒绝前两种，后两种继续通过证书验证和 HTTP 请求；经再次确认恢复后，原先四种协议的行为恢复。另一个 SNI 名称验证了默认服务器策略的实际影响。`nginx-tls-review-minimum.png` 与 `nginx-tls-restore-review.png` 已检查，最小窗口可完整显示差异、影响和按钮。

为构造真实旧协议负例，探针仅在自己创建的容器站点与客户端设置了较低 OpenSSL 安全级别；这是显式实验输入，产品修补不会降低密码套件安全级别或修改证书。客户端参数见 [OpenSSL s_client](https://docs.openssl.org/3.0/man1/openssl-s_client/)。报告保留各协议的实际握手结果，容器和独立应用数据已清理；该结果不外推为其他版本、Stream/TLS 代理、所有站点或业务均已验证。

目标本机连接复核的最新能力、原生验证与剩余范围见 [Nginx TLS 与 HTTP 连接复核](NGINX_CONNECTIVITY.md)。
