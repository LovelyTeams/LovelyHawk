# Redis 基线检测与修补边界

“配置 → 基线检测”中的 Redis 项目目前检查常见路径内的**候选配置线索**。它尚未证明某个文件属于哪个运行实例，也没有取得实际 ACL、启动参数或 `CONFIG SET` 后的运行状态。因此只展示风险线索或待复核，不能据此报告 Redis 已安全生效。基线页面仍是只读检查与建议入口；按实例执行的 Redis 修补和恢复链路尚未接通。

## 当前判断

| 项目 | 已实现的判断 | 仍需核对 |
| --- | --- | --- |
| 监听地址 | 显式 `0.0.0.0`、有效的 IPv6 未指定地址、`*` 和 `::*` 保留为通配监听线索；支持可选地址的 `-` 前缀 | 运行实例的全部监听、网络命名空间、启动参数和业务访问范围；存在 `bind` 不等于受限 |
| 保护模式 | 候选文件中的 `protected-mode no` 为线索，建议使用 Redis 的 `yes` 语法 | 实际默认用户认证、监听及运行时设置；安全文件值不能证明实例已采用 |
| 访问认证 | 候选文件没有声明口令或 ACL 时明确提示；空引号口令不算已配置 | 遇到 `user`、`aclfile` 或未解析的 `include` 时待复核；缺少 `requirepass` 不能否定 ACL 认证 |
| DEBUG / MODULE | 显式 `yes` 或 `local` 保留为可用命令线索；关闭建议使用 `no` | 产品版本、指令支持和实际用户权限；未出现指令不套用某一版本的默认值 |
| 危险命令权限 | 不再把任意 `rename-command` 当作通过，也不因缺少改名而直接判错 | 使用适用版本的 ACL 核对用户权限；改名不能替代授权 |
| 日志 | `/dev/null` 为丢弃日志线索；其他情况待复核 | `logfile ""` 使用标准输出，需核对容器或服务管理器的收集与保留策略，不能直接认定日志丢失 |

读取 `/etc/redis/redis.conf`、`/etc/redis.conf`、`/etc/redis/6379.conf` 与 `/usr/local/etc/redis/redis.conf`，各文件独立判断，不把它们当作一个实例的包含顺序。单个文件内同名标量按最后一条处理，注释不会覆盖前面的值；另一个安全文件不能抹去已有风险来源。文件查看重新定位来源，不标记所谓唯一生效行。

读取器只输出固定的风险标记、地址或开关值；扫描不回传口令、口令摘要或 ACL 规则正文。无法解析的转义、引号、过长行或超过 512 KiB 的候选内容保持待复核。Redis 的整行注释与引号按独立规则处理，不套用通用 shell 行尾注释。已发现 Redis 但没有候选文件时仍是待复核，不认定默认合规。

## 修补与恢复

旧通用写入器没有实例、包含关系、ACL 和运行时验证，却会生成 `protected-mode on`、`enable-debug-command off` 等不适用于 Redis 的建议。建议已改用原生语法；core 拒绝新的 Redis 通用修改请求，包括绕过构造函数提交的请求。不会根据一个候选文件猜测该重启哪个服务。

后续必须接通真实实例身份与配置来源、认证与权限能力、完整变化预览、备份、明确确认、原生验证、运行时及业务连接复核、失败恢复和幂等性。不能仅执行 `CONFIG SET` 或写入文件就声称持久修复。core 历史恢复已改为独立核对完整文件，不再因候选状态变化而比较失败后重新应用。新记录保存修改后的完整摘要与身份属性；缺少这些证据的旧记录仍可读取，但拒绝自动覆盖。真实 core 恢复及限制见 [基线历史恢复](BASELINE_RESTORE_VERIFICATION.md)，该链路仍未接入桌面，也不能计为 Redis 按实例自动修补。

## 复现

```powershell
cargo test --locked --package lovelyhawk-core --package lovelyhawk-backend
cargo build --locked --package lovelyhawk-backend --bin lovelyhawk-backend
pnpm ui:check
pnpm desktop:build
node tools/lab/probe-redis-baseline.mjs
```

探针创建并逐次核对本次 Redis 容器 ID、镜像、标签、网络与存储，限制为 256 MiB、1 CPU、128 个进程，无宿主挂载或特权；镜像的 `/data` 使用本次容器的受限 tmpfs。SSH 仅映射到 WSL 私有地址的随机端口，不导入用户连接库。设置 `REDIS_UI=0` 可仅运行 RPC 检查；不会把它计为桌面界面验收。

运行真实 Redis、SSH、基线 RPC 和正常桌面入口；覆盖候选来源、ACL、空口令、重复项、IPv6、无法解析的内容、未发现配置及最小窗口的实际反馈。实验中写配置和调用 `CONFIG SET` 用于构造对照样例，**不是应用已完成自动修补的证据**。已记录的结果（Electron 时期）、镜像摘要、截图和失败材料见 [长期进度](PRODUCT_ROADMAP.md)。Redis Sentinel、Cluster、Valkey、其他版本和架构，以及完整修补/恢复矩阵仍需分别适配与验证。

## 原始依据

Redis 文件语法、`bind` 地址、`yes/no/local`、包含顺序和日志说明以适用版本的 [Redis 7.4 官方配置](https://raw.githubusercontent.com/redis/redis/7.4/redis.conf) 为依据；实际默认用户和命令权限按 [Redis ACL 文档](https://redis.io/docs/latest/operate/oss_and_stack/management/security/acl/) 核对。持久文件与运行时配置的区别见 [Redis 配置文档](https://redis.io/docs/latest/operate/oss_and_stack/management/config/)，危险命令改名的限制见 [Redis 安全文档](https://redis.io/docs/latest/operate/oss_and_stack/management/security/)。资料仅作为对应规则的依据，不替代实际版本与实例验证。
