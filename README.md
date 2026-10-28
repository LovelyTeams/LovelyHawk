<div align="center">
  <img src="ui/assets/logo.png" alt="LovelyHawk Logo" width="220" height="220">

  # LovelyHawk

  **面向 Linux 与 Windows 的应急响应与安全运维桌面工作台**

  基于 Rust 与 Tauri 2 构建的离线便携桌面工具（原名 LovelyRes / LovelyERes）。<br/>
  通过原生 **SSH / SFTP** 与 **Windows RDP 动态虚拟通道（DVC，仅需 TCP 3389）**，提供从环境识别、证据采集、关联排查、受控遏制到独立复核与恢复的完整工作流。

  [![Rust](https://img.shields.io/badge/Rust-1.93.1-000000?style=flat-square&logo=rust&logoColor=white)](https://www.rust-lang.org)
  [![Tauri](https://img.shields.io/badge/Tauri-2.12.1-24C8DB?style=flat-square&logo=tauri&logoColor=white)](https://tauri.app/)
  [![React](https://img.shields.io/badge/React-19.2.8-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev/)
  [![TypeScript](https://img.shields.io/badge/TypeScript-7.0.2-3178C6?style=flat-square&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
  [![License](https://img.shields.io/badge/License-AGPLv3-yellow.svg?style=flat-square)](LICENSE)
</div>

---

## 项目简介

**LovelyHawk** 旨在同时服务一线应急响应人员与日常系统运维工程师：

- **对新手友好**：无需死记复杂命令或底层参数。界面直接呈现当前目标状态、风险线索、关注原因、推荐排查步骤与处置影响，对关键术语原位解释。
- **对专家高效**：支持全局与表内搜索、多维筛选、排序、原始证据复制、CSV / Markdown / HTML 导出、键盘快捷键、右键上下文处置菜单，以及带完整差异预览的计划执行。
- **安全与留证优先**：所有远端操作绑定目标身份与会话代次（`TargetGuard`）；高风险变更强制经过“不可变计划 → 明确确认 → 单次执行 → 审计记录（Journal）→ 独立回读验证（Verify）→ 可恢复回滚（Restore）”闭环。
- **开箱即用的便携设计**：单目录离线分发，所有字体、图标与规则库均内嵌于可执行文件中，运行时零外部 CDN 请求；运行数据统一保存在程序同级的 `data/` 目录下，不污染系统用户目录。

---

## 核心能力矩阵

### 1. Linux 应急响应与系统运维（SSH / SFTP）

| 模块 | 主要能力 |
| --- | --- |
| **连接与认证** | 支持密码、私钥（含口令）、OpenSSH 证书、键盘交互 MFA、SSH Agent 与跳板机（Bastion）；首次连接强校验主机指纹，按错误类型提供清晰中文诊断 |
| **终端与文件子窗口** | 独立多标签 SSH 终端窗口（内置选中输出 AI 解释）、双栏 SFTP 与本机文件浏览器、支持单次撤销的文件删除/改名/改权限、独立文件编辑器（含远端并发修改检测）、任意文件夹一键打开独立终端 |
| **主机全景** | 26 个细分视图覆盖主机概况、进程、网络连接、用户与组、登录历史、系统服务、定时任务、启动项、内核模块等，支持表格行右键直接排查或遏制 |
| **应急命令工作台** | 分类只读排查目录；针对可疑 SUID / 可执行文件支持右键去执行位、同目录权限隔离与一键撤销；支持远端文件 SHA-256 留证下载并自动登记清单 |
| **日志分析与留证** | 自动发现常规与非标日志路径，支持 `.gz` 及 RPM 式轮转日志在线解压分页阅读、敏感信息原位标注、自定义匹配规则、AI 辅助日志研判及原文件留证 |
| **网络抓包** | 网卡识别、BPF 过滤表达式安全校验、实时数据包解析，以及远端 `.pcap` 抓包留证下载（双重 SHA-256 核验与中断自动清理） |
| **命令审计与完整性** | 命令审计包装器部署、移除与周期统计（自动识别 BusyBox / coreutils 多合一程序并拒绝误替换）；文件完整性基线创建、差异比对、一键隔离与恢复 |
| **Java 热更新** | 扫描运行中 Java 进程与关联 JAR（含 `/proc/<pid>/fd` 打开的通配类路径 JAR），在保持原属主与权限的前提下替换 `.class` 并支持逐字节恢复 |

### 2. 容器与云原生排查（Docker / Podman / Kubernetes）

| 模块 | 主要能力 |
| --- | --- |
| **Docker / Podman** | 容器、镜像、网络、存储卷清单；特权容器、Docker Socket 挂载、宿主网络/PID 命名空间等安全审计；容器启停复核與异常回滚；容器内目录浏览、`docker diff` 文件改动与宿主侧 `docker top` 快速排查；容器内文件编辑、导出与独立容器终端窗口；自动兼容 Podman（含 cgroups v1 警告过滤） |
| **Kubernetes** | 支持集群级与单命名空间受限 RBAC 账号；Deployment 扩缩容、并发版本（`UID` / `resourceVersion`）保护与就绪超时恢复；Pod 多容器选择、当前日志与崩溃重启前日志（`previous`）、独立 Pod 终端窗口（关闭自动清理遗留进程）、只读 Pod 文件浏览、Pod 文件留证下载，以及 Pod / Deployment / Node 的原始 YAML 清单导出 |

### 3. 基线核查、中间件与数据库配置

| 模块 | 主要能力 |
| --- | --- |
| **Linux 系统基线** | 覆盖认证、SSH、账号口令、权限与日志审计检测；支持可写单项的计划、确认、语法检查、服务重载、独立回读与历史放回（精确识别 `sshd` 的 `Include` 生效位置并保护 `Match` 块） |
| **Nginx 专项修补** | 候选配置风险检测；针对运行中普通 Nginx 进程（绑定 `pidfd` 身份）提供目录列表关闭、版本隐藏与旧版 TLS 协议移除修补，内置对具体监听地址和 SNI 的四协议连接复核与入案留存 |
| **PostgreSQL 诊断** | 基于 SSH 隧道与原生数据库协议读取运行参数、配置来源、HBA / ident 规则视图、角色继承图、库/表/列/函数权限，以及 SQL 会话与宿主机操作系统进程的交叉核验 |
| **配置工作台** | 支持 Nginx、Apache httpd、Redis、HAProxy、MySQL、MariaDB 及内置数据库目录的**可视化树形编辑**（敏感行自动遮蔽锁定、未识别语法无损保留）；提供类型化**快速配置生成器**（含 Tomcat 三文件审阅包导出）、**自然语言目标搜索**与**闭合单行赋值预览** |

### 4. Windows 应急响应工作台（RDP DVC · 仅需 TCP 3389）

针对防火墙仅放行 `TCP 3389`、不通 WinRM / SSH / SMB 且不挂载本地磁盘的严苛内网现场，LovelyHawk 通过 `crates/lovelyhawk-win-dvc` 实现了**进程内 Rust COM LocalServer 插件**与动态虚拟通道（`DRDYNVC` / `dvc::lovelyhawk::winir`）：

- **三步向导与内嵌远程桌面**：在工作台内直接注册当前用户插件并内嵌原生 `mstsc.exe` 远程桌面画面（支持自适应或固定预设分辨率，默认关闭磁盘/打印机重定向以防反向污染）。
- **免落地脚本 / 独立 Agent 双模式**：支持一键复制 UTF-16LE Base64 编码的免落地 PowerShell 采集命令到远程会话运行，或手动复制独立采集端 `lovelyhawk-win-agent.exe` 运行。
- **19 个排查、取证与处置模块**：
  - **主机与方案**：主机总览（BIOS、补丁、网卡、Defender 与防火墙概况）、**14 类常见应急响应方案（Playbooks）**（覆盖初查、勒索、挖矿、木马、异常登录、计划任务/WMI 驻留、脚本、凭据转储、横向移动、IIS、驱动、防护异常、外传与域控分流，可直接联动对应采集入口）。
  - **活动与持久化调查**：进程分析（进程树/列表切换、PID 关联网络/服务/DLL、单进程与进程树固定计划终止及退出复核）、**命令监控**（汇总并实时监控 4688 / Sysmon 1 / PowerShell 4104 / PSReadLine 命令活动）、网络连接、启动项（19 类持久化位置分类统计）、服务、驱动、计划任务（按对象查看运行/触发器/依赖详情，支持快捷启停、禁用、受保护删除与配置恢复）、本地账户。
  - **取证分析**：调查时间线（事件、进程、文件、账户多源聚合与 CSV 导出）、事件日志（16 类快速查询预设与 6 个常见日志目录联动）、**Defender 解析**（威胁检出、处置状态、排除项与防篡改变更）、文件排查（32 个常用目录预设、目录树、SHA-256、文本/Hex/PE 预览、ACL 与进程/服务/驱动占用诊断、单文件 8 MiB 完整性校验拉取）、**Webshell 查杀**（多线程扫描 Web 目录，检测 PHP/ASP/ASPX/JSP 一句话后门、冰蝎/哥斯拉特征与高熵混淆脚本）、注册表（37 个常用位置预设与完整键树）。
  - **基线配置与独立通道窗口**：**69 项（15 类）安全基线检测**，其中 19 项注册表策略支持原值备份、差异预览、逐项回读与并发保护恢复；专用 **`windows-channel` 独立窗口**管理采集任务、已接收文件另存、命令检查台（含 28 个只读命令预设）与通信日志。

### 5. 支撑工具与全局体验

- **安全速查、笔记、命令历史、AI 历史、应用日志、处置报告**（支持纯文本、Markdown、HTML 预览与安全导出）。
- **16 套内置主题配色**：内置 10 套浅色主题（月白、樱花、桃夭、庭芜绿、东方既白、春辰、挼蓝、林野脉冲、珊瑚警报、霓虹频谱、小小火花）与 6 套深色主题（玄青、事件画布、深海薄荷绿、午夜蓝紫、咖棕焦糖、墨绿玫瑰）。宿主在窗口首帧绘制前注入原生底色，杜绝启动闪白。

---

## 架构设计与安全边界

LovelyHawk 桌面端采用 **Tauri 2 + Rust 进程内后端 + React 19** 架构：

```text
LovelyHawk/
├── Cargo.toml / Cargo.lock          # Rust Workspace 根配置与依赖锁定
├── package.json / pnpm-lock.yaml    # 前端与自动化脚本入口
├── crates/
│   ├── lovelyhawk-core/             # UI 无关的领域规则、SSH/SFTP、Windows 应急编排、基线/中间件/数据库引擎与便携存储
│   ├── lovelyhawk-terminal/         # Headless 终端模型、ANSI 解析、传输、搜索与背压控制
│   ├── lovelyhawk-win-dvc/          # Windows RDP DVC COM 插件宿主、mstsc 画面嵌入与远程采集端 (lovelyhawk-win-agent)
│   ├── lovelyhawk-backend/          # 有限且版本化的后端方法表（lovelyhawk-backend/v1），由桌面宿主进程内直接链接调用
│   └── lovelyhawk-desktop/          # Tauri 2 宿主：窗口加固、按窗口授权命令、主窗口方法白名单、系统对话框/剪贴板/导出、单实例锁
├── ui/
│   ├── assets/                      # 随可执行文件嵌入的离线字体（Inter / Cascadia Mono）、图标与安全速查数据
│   ├── scripts/                     # WebView2 CDP 真实桌面自动化巡检与场景探针
│   └── src/
│       ├── host/                    # 页面侧唯一宿主桥（冻结的 window.lovelyhawk* 对象，按共享契约双向校验）
│       ├── renderer/                # React 19 视图组件、显式状态机与主题样式
│       └── shared/                  # 前后端共享 DTO 与运行时请求/响应校验器
├── docs/                            # 架构说明、各模块验证边界、UI 验收账本与路线图
├── scripts/                         # 源码门禁、依赖门禁、账本门禁、Windows/Linux 便携打包与冒烟脚本
└── tools/lab/                       # 多发行版 Linux、数据库/中间件服务与 Docker/Podman/k3s 靶机实验室
```

### 核心安全约束

1. **严格的页面与宿主信任边界**：
   - 窗口禁用全局 Tauri 对象（`withGlobalTauri: false`），页面不持有 Node.js 权限或任何 Tauri 插件权限，禁止直接导入 `@tauri-apps/plugin-*`。
   - 宿主按窗口标签（`main`、`child-*`、`windows-channel`）分别授予最小命令集合；主窗口 `backend_call` 仅允许调用 `MAIN_WINDOW_METHODS` 白名单内的方法。
   - 涉及本机文件路径、系统文件对话框、剪贴板和导出文件写入的操作全部在 Rust 宿主内完成（导出強制使用 `create_new` 拒绝覆盖已有文件），页面无法读取本机绝对路径。
2. **三通道并发隔离**：
   - 宿主内的 `BackendBridge` 将调用分为“终端 Shell”、“SFTP 文件管理”与“常规后端任务”三条独立通道，主窗口执行耗时排查任务时不会阻塞终端按键回显或文件浏览刷新。
3. **关闭握手与防丢失保护**：
   - 主窗口、独立文件编辑窗口与 Windows 通道窗口均接入异步关闭握手（`before-close`），存在未保存修改、未另存接收文件或运行中任务时自动拦截关闭、断连或切换目标操作并弹窗确认。
4. **纯文本渲染与防注入**：
   - 所有来自远端主机、日志、进程名、容器、数据库、AI 响应与导入文件的数据均按纯文本处理，源码门禁强制禁止 `innerHTML`、`dangerouslySetInnerHTML`、`eval` 等危险接收点。
   - 远端命令优先使用闭合枚举与独立参数；确需通过 Shell 传输时统一经过 `lovelyhawk-core` 的转义与边界校验。

---

## 快速开始

### 环境要求

- **操作系统**：Windows 10 / 11 x64（自带 Microsoft Edge WebView2 Runtime）
- **Rust 工具链**：`1.93.1`（含 `rustfmt`、`clippy`）与 MSVC 构建工具（Visual Studio C++ Build Tools）
- **Node.js 与包管理**：Node.js `24.x` 与 `pnpm@10.28.2`（可通过 `corepack enable` 启用）
- **PowerShell**：PowerShell `7.2+`（`pwsh`，用于执行仓库质量门禁与便携打包脚本）

### 安装依赖与启动

```powershell
# 启用固定版本的 pnpm 并安装锁定依赖
corepack enable
pnpm install --frozen-lockfile

# 构建前端与调试版宿主并启动桌面端
pnpm desktop:dev
```

### 界面热更新开发（HMR）

修改 `ui/src/` 下的前端代码时，可使用热更新模式以获得即时反馈：

```powershell
pnpm desktop:hot
```

> **说明**：`desktop:hot` 仅在调试构建（`debug_assertions`）中生效，宿主只接受本机回环地址 `http://127.0.0.1:<端口>/`。调试构建默认将数据写入仓库根目录的 `data/`（可通过 `LOVELYHAWK_ARCHIVE_ROOT` 指定隔离目录），支持按 `F12` 或 `Ctrl+Shift+I` 打开 DevTools。

---

## 质量门禁与测试验证

项目配备了从单元测试、静态门禁到 WebView2 CDP 真实窗口巡检与实验室靶机探针的多层验证体系：

```powershell
# 1. 前端类型检查、Vitest 单元测试与构建
pnpm ui:check

# 2. Rust 核心、DVC、后端与桌面宿主单元测试
cargo test --locked --package lovelyhawk-core
cargo test --locked --package lovelyhawk-win-dvc
cargo test --locked --package lovelyhawk-backend
cargo test --locked --package lovelyhawk-desktop

# 3. 仓库安全与架构门禁（源码安全门禁、依赖锁定门禁、UI 账本门禁）
pnpm release:source-gate
pnpm release:dependency-gate
pnpm release:ledger-gate

# 4. 一键运行完整质量门禁（包含 fmt、clippy、全量单测、UI 构建与三大门禁）
pnpm release:quality-gate
```

### 真实桌面端（WebView2 CDP）自动化探针

```powershell
# 逐页、逐浮层、明暗主题与无障碍巡检并生成截图证据
pnpm desktop:test:debug

# Windows 应急响应工作台全模块桌面巡检（需先编译调试版宿主）
node ui/scripts/probe-windows-workspace.mjs
```

更多针对多发行版 Linux、Docker/Podman、k3s、PostgreSQL、Nginx 与 SFTP 的真实环境探针详见 `ui/scripts/` 与 [`tools/lab/README.md`](tools/lab/README.md)。

---

## 构建 Windows 便携发布包

```powershell
# 编译 UI、以静态 CRT 编译 Release 宿主与 Windows 采集端、生成 SBOM 与第三方许可证并打包校验
pnpm release:package -Build

# 在含空格与中文的隔离目录中执行便携包启动、渲染、数据目录隔离与退出冒烟测试
pnpm release:smoke -ArchivePath artifacts/LovelyHawk-0.0.1-windows-x64.zip
```

生成的 `LovelyHawk-<版本>-windows-x64.zip` 解压后为单一目录，包含以下 8 个文件（详见 [`docs/DESKTOP_PORTABLE_RELEASE.md`](docs/DESKTOP_PORTABLE_RELEASE.md)）：

- `LovelyHawk.exe`：主程序（已内嵌全部前端与离线资源，静态链接 CRT，无需安装 VC++ 运行库）
- `lovelyhawk-win-agent.exe`：Windows 远程桌面会话采集端（按需复制到远程会话使用，不随主程序自动运行）
- `LICENSE`：AGPL-3.0 许可证全文
- `THIRD_PARTY_NOTICES.md`：前端、Tauri/WebView2 与内嵌字体许可声明
- `THIRD_PARTY_LICENSES_RUST.txt`：构建中链接的全部 Rust 依赖 crate 许可证全文
- `SBOM.cdx.json`：CycloneDX 1.5 软件物料清单（含组件与内嵌资源 SHA-256）
- `README.txt`：便携版使用说明
- `PACKAGE_MANIFEST.json`：包内所有文件的大小与 SHA-256 校验清单

---

## 文档导航与真实验收边界

LovelyHawk 坚持**按真实环境证据记录完成度**，不以静态 Schema、合成 UI 测试或单一发行版结果宣称全环境兼容。各模块的详细设计与当前已知边界请参阅：

| 文档 | 内容说明 |
| --- | --- |
| [`AGENTS.md`](AGENTS.md) | 开发规范、用户体验准则、安全红线与验收纪律 |
| [`docs/DESKTOP_ARCHITECTURE.md`](docs/DESKTOP_ARCHITECTURE.md) | Tauri 2 宿主架构、窗口权限划分、三通道桥接与关闭握手协议 |
| [`docs/DESKTOP_PORTABLE_RELEASE.md`](docs/DESKTOP_PORTABLE_RELEASE.md) | Windows / Linux 便携包构建、SBOM 生成、二进制校验与冒烟规范 |
| [`docs/WINDOWS_INCIDENT_WORKBENCH.md`](docs/WINDOWS_INCIDENT_WORKBENCH.md) | Windows RDP DVC 应急响应工作台架构、证据上限与已验证范围 |
| [`docs/WINDOWS_RESPONSE_PLAYBOOKS.md`](docs/WINDOWS_RESPONSE_PLAYBOOKS.md) | 14 类 Windows 应急响应方案（Playbooks）依据、四阶段流程与联动映射 |
| [`docs/WINDOWS_BASELINE_COVERAGE.md`](docs/WINDOWS_BASELINE_COVERAGE.md) | Windows 69 项安全基线目录、采集来源与 [`WINDOWS_BASELINE_CHANGES.md`](docs/WINDOWS_BASELINE_CHANGES.md) 变更恢复边界 |
| [`docs/SSH_COMPATIBILITY.md`](docs/SSH_COMPATIBILITY.md) | SSH 算法、认证方式与国内外 Linux 发行版兼容矩阵 |
| [`docs/KUBERNETES_VERIFICATION.md`](docs/KUBERNETES_VERIFICATION.md) | Kubernetes 就绪核验、并发保护、RBAC 降级与 Pod 取证边界 |
| [`docs/NGINX_BASELINE_VERIFICATION.md`](docs/NGINX_BASELINE_VERIFICATION.md) | Nginx 基线检测、[`NGINX_PROCESS_REPAIR.md`](docs/NGINX_PROCESS_REPAIR.md) 进程修补与 [`NGINX_CONNECTIVITY.md`](docs/NGINX_CONNECTIVITY.md) 连接复核 |
| [`docs/POSTGRESQL_NATIVE_RUNTIME.md`](docs/POSTGRESQL_NATIVE_RUNTIME.md) | PostgreSQL 原生连接、[`POSTGRESQL_PROCESS_CORRELATION.md`](docs/POSTGRESQL_PROCESS_CORRELATION.md) 进程对应与 [`POSTGRESQL_ACCESS_DIAGNOSTICS.md`](docs/POSTGRESQL_ACCESS_DIAGNOSTICS.md) 访问诊断 |
| [`docs/DESKTOP_UI_LEDGER.json`](docs/DESKTOP_UI_LEDGER.json) | 桌面端各页面、子窗口、浮层与发布门禁的精确验收账本 |
| [`docs/UNWIRED_FEATURES.md`](docs/UNWIRED_FEATURES.md) | 尚未完全接线或仍处于待实机验证（Pending）状态的功能与限制清单 |
| [`docs/PRODUCT_ROADMAP.md`](docs/PRODUCT_ROADMAP.md) | 长期产品路线图与历次实验室/桌面端实测记录 |

---

## 贡献指南

欢迎提交 Issue 与 Pull Request！在提交代码前请务必：

1. 阅读并遵守 [`AGENTS.md`](AGENTS.md) 中的架构边界、安全规则与中文界面文案规范（不向用户暴露内部实现术语）。
2. 新增功能必须打通 `lovelyhawk-core` → `lovelyhawk-backend` → `ui/src/shared` → `lovelyhawk-desktop` → `ui/src/host` → `ui/src/renderer` 完整链路，未完成接线或缺少实机验证的部分需如实登记至 [`docs/UNWIRED_FEATURES.md`](docs/UNWIRED_FEATURES.md)。
3. 运行 `pnpm release:quality-gate` 确保代码格式、Clippy、TypeScript 类型、单元测试及源码/依赖/账本门禁全部通过。

---

## 开源协议

本项目基于 [GNU Affero General Public License v3.0 (AGPL-3.0-only)](LICENSE) 协议开源。

---

<div align="center">
  <sub>Built with ❤️ by Tokeii</sub>
</div>
