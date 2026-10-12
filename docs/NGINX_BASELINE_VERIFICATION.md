# Nginx 基线检测与修补边界

记录日期：2026-09-07。当前完成的是候选配置检测、风险定位与复核提示，自动修补界面仍未接线。

## 已修正的行为

- `server_tokens`、`autoindex` 不再用最后出现的值代表整台机器。任何候选文件中的显式 `on` 都保留为风险线索；`server_tokens build` 同样报告。
- `ssl_protocols` 不再因为“写过配置”而显示符合。显式 SSLv2、SSLv3、TLSv1、TLSv1.1 保留为线索，建议结合该实例能力选择 TLS 1.2/1.3。
- `access_log off` 不再被当作已启用日志；`error_log /dev/null` 保留为日志丢弃线索。`error_log off` 是文件名，不冒充 Nginx 的禁用开关。
- 解析按指令分隔，区分注释、引号、跨行与同一行里的多条指令。结果与来源文件由同一遍历规则选择，后面的安全值不会擦掉前面的风险。
- 安全候选值、没有显式设置或尚未核实的范围显示“待复核”，不采用猜测的默认值显示符合。解析工具缺失或读取失败同样返回无法判断；状态沿 core、RPC、共享契约和页面传递。
- Nginx 文件查看重新确定候选来源，打开发现风险的文件；不再标记“唯一生效行”。页面可搜索产品名、单独筛选待复核，刷新扫描后重新读取已选项。旧请求、同一项重开、切换目标/API、断连和卸载后的结果失效。
- Nginx 的目录 `writable` 为 false。构造请求、直接构造请求后规划、底层通用编辑入口都拒绝进入普通合并同名键的写入流程。未核实、未安装、符号链接/特殊文件和条件配置同样不能生成通用写入计划。

这些是静态配置线索：当前扫描仍检查固定候选路径，未解析完整 include 图、指令继承、实际 master 的启动参数、运行实例或已加载配置。每个候选文件最多解析 524288 个字符，单行最多 16384 个字符；超出的部分不能证明没有其他风险。一次只展示该规则遇到的首个显式风险值与来源，不能作为风险数量清单。不存在显式风险也不构成通过。

## 真实环境证据

入口：`node tools/lab/probe-nginx-baseline.mjs`。设置 `NGINX_UI=0` 只运行 RPC；报告明确标识模式，跳过 UI 不算 UI 通过。

以下是 2026-09-07 Electron 时期的运行记录，不能直接当作 Tauri 桌面壳的界面验收。

- 使用本地缓存的 `lovelyres-svc:nginx`（Nginx 1.27.5、Debian bookworm、Linux amd64）创建本次唯一容器。核对完整 ID、镜像摘要、归属标签、bridge 网络、无挂载和非特权，限制 384 MiB、1 CPU、128 PID；SSH 端口仅绑定 WSL 私有地址。
- 创建两个站点，一处暴露版本和目录列表，一处关闭。用 Nginx 自身 `-t` 与实际 HTTP 请求核对独立预期，再经真实 SSH/sidecar 扫描；覆盖后续安全站点掩盖前面风险、嵌套 location、跨行/带引号指令、注释与普通字符串、日志关闭、旧 TLS 配置和缺少 awk。
- 测试修改配置后通过 `nginx -t`、reload 与实际请求确认实验配置已改变，再检查页面仍如实显示待复核。此处修改是探针创建的实验状态，**不是 LovelyHawk 自动修补执行的验收证据**；没有验证真实 TLS 握手。
- Electron 通过原生 CDP 操作实际应用：连接、配置页、产品搜索、选择风险项、打开源文件、重新扫描、最小支持窗口 1080×700、断连与控制台异常检查。850 像素的早期探针低于 BrowserWindow 最小宽度，其失败报告保留，不当作通过。
- 每次报告与截图位于 `target/lab-nginx-baseline/<runId>/`。探针只移除已核实身份的自建容器，并校验临时路径后清理自己的应用数据目录；原有服务容器不受修改。

最后完成的报告与全套检查汇总见 [产品进度](PRODUCT_ROADMAP.md)。测试只覆盖以上具体版本与部署方式，尚不覆盖多实例、OpenResty/Tengine、ARM、rootless/只读容器或其他 Linux 产品组合。

## 自动修补后续验收

“配置 → 修补已有配置”现已接通有条件支持的普通 Nginx 进程路径；对配置图中具体文件、具体节点的 `autoindex on` 与 `server_tokens on/build` 提供差异、逐次确认、原子比较写入、备份、原生检查、重载、进程验证与恢复。范围、前提及 Electron 时期的真实桌面/HTTP 证据见 [普通进程修补与恢复](NGINX_PROCESS_REPAIR.md)。业务请求由实验独立核对；产品尚未自动完成全部 HTTP/TLS 健康验证。不能把这一有限路径混同于本页的候选基线扫描，也不能重新启用合并同名指令的通用写入器。

资料依据：Nginx 的[配置结构与重载行为](https://nginx.org/en/docs/beginners_guide.html#conf_structure)、[版本标记](https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens)、[目录索引](https://nginx.org/en/docs/http/ngx_http_autoindex_module.html#autoindex)、[协议设置与 TLS 1.3 前提](https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_protocols)、[访问日志](https://nginx.org/en/docs/http/ngx_http_log_module.html#access_log)。这些资料说明配置语义；本项目的静态检查不等同于生效配置或业务健康证明。
