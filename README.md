<div align="center">
  <img src="ui/assets/logo.png" alt="LovelyHawk Logo" width="250" height="250">

  # LovelyHawk

  **Linux 应急响应工作台**

  基于 Rust 与 Tauri 2 的便携 SSH / SFTP 诊断、调查和处置工具（原名 LovelyRes / LovelyERes）。

  [![Rust](https://img.shields.io/badge/Rust-1.93.1-000000?style=flat-square&logo=rust&logoColor=white)](https://www.rust-lang.org)
  [![Tauri](https://img.shields.io/badge/Tauri-2.12.1-24C8DB?style=flat-square&logo=tauri&logoColor=white)](https://tauri.app/)
  [![License](https://img.shields.io/badge/License-AGPLv3-yellow.svg?style=flat-square)](LICENSE)
</div>

---

## 当前状态

LovelyHawk 的桌面端已从 Electron 迁移到 **Tauri 2**：

- Rust 宿主 `crates/lovelyhawk-desktop` 与 `ui/` 页面是唯一受支持的界面；Electron 与更早的 GPUI 前端都已退役。
- 后端 `lovelyhawk-backend` 直接链接进宿主进程，沿用原来的方法表、参数解析、错误码与大小上限；终端 shell、终端窗口的文件管理与其余调用各走一条通道，通道内按到达顺序逐个执行。
- `lovelyhawk-core` 继续负责 SSH/SFTP、便携存储、目标代际、危险计划、审计、验证与恢复。
- 本机路径、导出内容、系统对话框与剪贴板只在宿主里处理；页面只能调用按窗口授权的固定命令。

各页面、窗口、浮层与发布门禁的真实完成情况以 [桌面 UI 账本](docs/DESKTOP_UI_LEDGER.json)、[桌面架构说明](docs/DESKTOP_ARCHITECTURE.md) 与 [未接线功能清单](docs/UNWIRED_FEATURES.md) 为准。Electron 时期的账本与验证记录保留为历史，不能当作 Tauri 外壳的证据。存在文件或脚手架不代表功能已经完成。

## 目标能力

- SSH 连接、主机密钥 / MFA、目标连接与断开；
- SSH 终端、SFTP（含本机文件栏）、容器终端与文件编辑独立窗口；
- 主机全景（表格行可右键排查与处置）、Docker、Kubernetes、命令工作台、日志、抓包、命令审计和文件完整性；
- 基线检查与配置生成、数据库（PostgreSQL）、案件工作台、笔记；
- 安全速查、命令历史、AI 历史、设置、应用日志和处置报告；
- 目标绑定、不可变危险计划、精确确认、journal、执行后独立验证与可恢复流程。

## 技术栈

| 层 | 技术 | 职责 |
|---|---|---|
| 桌面宿主 | Tauri 2.12、WebView2 | 无边框窗口、按窗口授权的命令、方法白名单、本机对话框 / 剪贴板 / 导出、子窗口与目标绑定 |
| 页面 | React 19、TypeScript 7、Vite 8 | 页面、浮层、可访问交互；`ui/src/host` 校验每个请求与响应 |
| 后端 | Rust 2024、Tokio | 有限的后端方法表，组合 core 服务并管理敏感状态 |
| 核心服务 | `lovelyhawk-core` | SSH/SFTP、诊断、存储、审计、验证和恢复 |
| 终端 | `lovelyhawk-terminal` + xterm.js | ANSI 模型、传输、输入、搜索、背压与取消 |

依赖由根目录 `Cargo.toml`、`Cargo.lock`、`ui/package.json` 与 `pnpm-lock.yaml` 锁定。

## 项目结构

~~~text
LovelyHawk/
├── Cargo.toml / Cargo.lock
├── package.json / pnpm-lock.yaml
├── crates/
│   ├── lovelyhawk-core/         # UI 无关的领域服务与安全契约
│   ├── lovelyhawk-backend/      # 有限的后端方法表（宿主进程内调用；另有供实验室探针用的 stdio 入口）
│   ├── lovelyhawk-terminal/     # headless 终端基础
│   └── lovelyhawk-desktop/      # Tauri 2 宿主、tauri.conf.json、capabilities/、icons/
├── ui/
│   ├── assets/                  # 随程序嵌入的字体、图标与离线数据
│   ├── scripts/                 # CDP 冒烟与场景探针
│   └── src/{host,renderer,shared}/
├── docs/
├── scripts/                     # 门禁、打包、校验与便携冒烟
└── tools/lab/                   # 实验室靶机与真实环境探针
~~~

## 快速开始

### 环境要求

- Rust 1.93.1（含 rustfmt、clippy）与 MSVC 构建工具；
- Node.js 24 与 Corepack/pnpm 10.28.2；
- Windows 10/11 自带的 Microsoft Edge WebView2 Runtime；
- PowerShell 7.2+（打包与仓库门禁）。

### 构建与运行

~~~powershell
corepack enable
pnpm install --frozen-lockfile
pnpm desktop:dev        # 构建 UI 与调试版宿主并启动
~~~

改界面时用热更新启动：

~~~powershell
pnpm desktop:hot        # 编译调试版宿主，页面改由本机 Vite 提供，改动 ui/src 立即生效
~~~

`desktop:hot` 只在调试构建里生效：宿主读取 `LOVELYHAWK_DEV_SERVER`，只接受 `http://127.0.0.1:<端口>/` 这类本机回环地址，并给它一份与两个 capability 文件相同的命令权限。Vite 提供的页面在 CSP 中额外放行它注入的内联脚本（按哈希）、内联样式与本机 WebSocket；构建产物、release 程序、`desktop:dev` 与 CDP 验收仍加载嵌入页面，不受影响。只导出 React 组件的文件会原地替换并保留页面状态；同时导出普通函数或常量的文件（如 `App.tsx`、`WelcomeView.tsx`）会整页重新加载。Rust 改动仍需重新运行命令。

调试构建会把数据写到仓库根目录的 `data/`；可用 `LOVELYHAWK_ARCHIVE_ROOT` 指向别处（仅调试构建生效），自动化就是这样与正在使用的应用隔离的。

### Debug 模式

调试构建默认可用 `F12` / `Ctrl+Shift+I` 打开 DevTools。便携 release 版默认关闭，需要临时排障时设置 `LOVELYHAWK_DEBUG=1` 再启动。调试构建设置 `LOVELYHAWK_DEBUG_PORT=<端口>` 时开放 WebView2 远程调试端口，供 CDP 自动化连接；release 版不包含这一能力。

### 主题与界面设置

设计语言为中性 slate 底 + 蓝色强调；浅色主题全部区域为浅色，深色主题全部为深色，不混用。`ui/src/renderer/theme/themes.css` 是唯一取色来源，内置浅色、深色、樱花、事件画布四套配色。标题栏的太阳/月亮按钮循环切换并持久化；宿主按 `crates/lovelyhawk-desktop/src/theme.rs` 的原生配色表在窗口首次绘制前设置底色，子窗口的主题与目标标签也在首帧前注入。

设置面板中的侧栏宽度、紧凑模式、界面动画（同时尊重系统的“减少动态效果”）与状态栏开关会实时应用；隐藏状态栏时，“应用日志”“处置报告”入口与目标错误提示移到侧栏。

新增配色：在 `themes.css` 复制一个 `:root[data-theme="…"]` 块改值 → 在 `shared/settings-contract.ts` 的 `SettingsTheme` 登记 → 在 `shared/theme-contract.ts` 的 `THEMES` 与宿主 `theme.rs` 各加一行。`theme.test.ts` 会检查 token 完整性、WCAG 对比度、明暗一致性，以及注册表、CSS token 与宿主原生配色完全一致。

### 检查

~~~powershell
pnpm ui:check                                   # 类型检查、单测与构建
cargo test --locked --package lovelyhawk-backend
cargo test --locked --package lovelyhawk-desktop
pnpm release:source-gate
pnpm release:dependency-gate
pnpm release:ledger-gate
pnpm release:quality-gate                       # 以上全部，失败即阻断
~~~

桌面端回归使用真实调试构建与 WebView2 CDP：

~~~powershell
pnpm desktop:test:debug                         # 逐页、逐浮层巡检并截图
node ui/scripts/probe-terminal-window.mjs       # 实验室靶机：连接、终端与文件编辑子窗口、断开回收
node ui/scripts/probe-close-handshake.mjs       # 未保存设置时关闭主窗口的询问与迟到回答
node ui/scripts/probe-sftp-transfers.mjs        # 实验室靶机：下载、上传、编辑器写回、改过就拒绝保存（LAB=靶机名）
node ui/scripts/probe-command-history.mjs       # 实验室靶机：真实运行产生的命令历史，搜索、复制、删除与换主机
node ui/scripts/probe-disposal-report.mjs       # 实验室靶机：真实处置操作生成报告，预览、复制、另存与换主机
node ui/scripts/probe-connection-editor.mjs     # 实验室靶机：选私钥文件并真实登录、堡垒机、秘密的保存与删除
node ui/scripts/probe-terminal-during-long-task.mjs  # 实验室靶机：主窗口长命令期间终端照常回显、文件列表照常刷新
node ui/scripts/probe-editor-close.mjs          # 实验室靶机：编辑窗口有未保存修改时，各种关闭方式都先询问
node ui/scripts/probe-docker.mjs                # 容器编排靶机 svc-docker：容器、审计、日志、启停复核与回滚、容器终端
~~~

`ui/scripts/` 下还有设置、连接、笔记、对话框等页面各自的探针，均自带截图与 `report.json` 证据。

完整验收使用 `pnpm release:quality-gate:strict`：它要求桌面 UI 账本全部有通过证据并执行最终 workspace 检查，验收完成前失败是预期阻断，不得绕过。

### Windows 便携包

~~~powershell
pnpm release:package -Build      # 构建 UI 与静态 CRT 的 release 宿主，打包并校验
pnpm release:smoke -ArchivePath artifacts/LovelyHawk-1.0.0-windows-x64.zip
~~~

便携包只有一个 `LovelyHawk.exe`（页面资源已嵌入）、许可文件、Rust 依赖许可证全文、SBOM 与清单，详见 [便携发布说明](docs/DESKTOP_PORTABLE_RELEASE.md)。首次启动在程序旁创建 `data/`，不写用户配置目录；同一数据目录同时只允许运行一份。Linux x64 包（`scripts/desktop-package-linux.sh`）目前只在 Debian 12 容器中做过启动级冒烟；macOS 包与干净环境冒烟尚未完成，不得宣称三平台发布已经通过。SSH 实机覆盖见 [SSH 兼容性与安全策略](docs/SSH_COMPATIBILITY.md)。

## 离线与安全约束

- UI 字体、图标、Logo 和目录数据嵌入程序；运行时不加载 CDN、远程字体、图片、脚本、样式或 SVG。
- 页面没有 Node、没有全局 Tauri API、没有任何插件权限；宿主拒绝导航、新窗口、下载与权限请求，关闭拖放路径与自动填充。
- 主窗口只能调用白名单里的后端方法；带本机路径或返回导出内容的操作只能由宿主命令完成，子窗口不传目标身份。
- 运行数据写入可执行文件同级的 `data/`（含 WebView2 数据），不使用浏览器持久化，也不静默回退到用户配置目录。
- 每个远端请求都绑定 core 管理的目标身份与代次；切换或断开后，迟到结果失败关闭。
- 用户、远端、AI、日志和导入文本始终作为纯文本，不解释为 HTML、资源、路径、动作或 shell 程序。
- 危险写操作使用不可变 core 计划、精确确认、单次能力、journal、独立 verify，并在可恢复时提供 restore。
- 密钥、口令、密文和秘密配置不得进入日志、页面 DTO、截图、导出或浏览器状态。
- 旧版本写在本机或目标主机上的格式与托管标识保留 `lovelyres` 前缀以保持兼容（例如 `.lovelyres-backups` 与各 `lovelyres-*/vN` schema）。

## 贡献

提交前请阅读 [AGENTS.md](AGENTS.md)，运行与改动风险相称的 Rust、UI、门禁和 CDP 检查。新增模块如果尚未接入页面、窗口或宿主命令，必须登记到 [docs/UNWIRED_FEATURES.md](docs/UNWIRED_FEATURES.md)，并保持 Pending。

## 开源协议

本项目基于 AGPLv3 协议开源，详情见 [LICENSE](LICENSE)。

---

<div align="center">
  <sub>Built with ❤️ by the Tokeii</sub>
</div>
