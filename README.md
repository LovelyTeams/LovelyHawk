<div align="center">
  <img src="electron/assets/logo.png" alt="LovelyRes Logo" width="250" height="250">

  # LovelyERes

  **Linux 应急响应工具**

  基于 Electron 与 Rust 的便携 SSH / SFTP 诊断、调查和处置工作台。

  [![Rust](https://img.shields.io/badge/Rust-1.93.1-000000?style=flat-square&logo=rust&logoColor=white)](https://www.rust-lang.org)
  [![Electron](https://img.shields.io/badge/Electron-43.4.1-47848F?style=flat-square&logo=electron&logoColor=white)](https://www.electronjs.org/)
  [![License](https://img.shields.io/badge/License-AGPLv3-yellow.svg?style=flat-square)](LICENSE)
</div>

---

## 当前状态

LovelyERes 的桌面前端已 **完全迁移到 Electron**，GPUI crate、依赖与发布路径已于 2026-08-25 移除：

- Electron main、冻结的 preload API 和 React renderer 是唯一受支持的 UI。
- Rust lovelyres-core 继续负责 SSH/SFTP、便携存储、目标代际、危险计划、审计、验证和恢复。
- lovelyres-electron-backend 是 Electron 与 Rust core 之间唯一受支持的进程边界。
- 原受保护的 GPUI config-generator 脏基线已逐字归档到 docs/legacy/config-generator-baseline.rs.txt，剩余测试替代工作见 [Config-generator 测试迁移待办](docs/CONFIG_GENERATOR_TEST_BACKLOG.md)。

页面、窗口、overlay、测试替代和发布 gate 的真实完成情况以 [Electron 迁移说明](docs/ELECTRON_MIGRATION.md)、[机器可读 UI ledger](docs/ELECTRON_UI_LEDGER.json) 与 [未接线功能清单](docs/UNWIRED_FEATURES.md) 为准。存在文件或脚手架不代表功能已经完成。

## 目标能力

- SSH 连接、host-key/MFA、目标激活与断开；
- SSH 终端、SFTP 和容器终端独立窗口；
- 系统信息、Docker、Kubernetes、快速检测、安全速查、日志、抓包和完整性检查；
- 防火墙、快照、基线、数据库、中间件、Java 更新和多机批量工作流；
- 调查笔记、命令历史、AI 历史、设置、诊断和处置报告；
- TargetGuard、不可变危险计划、精确确认、journal、执行后验证与可恢复流程。

## 技术栈

| 层 | 技术 | 职责 |
|---|---|---|
| 桌面界面 | Electron 43、React 19、TypeScript 7 | 主/次窗口、页面、overlay、本机对话框与可访问交互 |
| 进程边界 | Electron main/preload + Rust sidecar | 固定 IPC/RPC 白名单、严格 DTO、秘密和路径隔离 |
| 核心服务 | Rust 2024、Tokio | SSH/SFTP、诊断、存储、审计、验证和恢复 |
| 终端 | headless lovelyres-terminal + Electron renderer | ANSI 模型、传输、输入、搜索、选择、背压与取消 |
| SSH/SFTP | russh、russh-sftp | 目标绑定的远程会话与文件传输 |

依赖由根目录 Cargo.toml、Cargo.lock、electron/package.json 与 pnpm-lock.yaml 锁定。

## 项目结构

~~~text
LovelyRes/
├── Cargo.toml
├── Cargo.lock
├── package.json
├── pnpm-lock.yaml
├── crates/
│   ├── lovelyres-core/                 # UI 无关的领域服务与安全契约
│   ├── lovelyres-electron-backend/     # 有限、版本化的 Rust sidecar
│   └── lovelyres-terminal/             # headless 终端基础
├── electron/
│   ├── assets/                         # 唯一本地 Electron UI 资源
│   └── src/{main,preload,renderer,shared}/
├── docs/
└── scripts/
~~~

## 快速开始

### 环境要求

- Rust 1.93.1，包含 rustfmt 与 clippy；
- Node.js 与 Corepack/pnpm 10.28.2；
- 对应平台的原生 Rust 构建工具链；
- PowerShell 7.2+（Windows 打包与仓库 gate）。

### 安装与运行 Electron

~~~powershell
corepack enable
pnpm install --frozen-lockfile
pnpm electron:dev
~~~

### Debug 模式

开发运行（未打包）默认开启 debug 模式：主窗口与 SSH 终端窗口均可用 `F12` 或 `Ctrl+Shift+I` 切换独立 DevTools。打包后的便携版默认关闭 DevTools（`webPreferences.devTools: false`）；如需临时在打包版排障，设置环境变量 `LOVELYRES_DEBUG=1` 再启动。

### 主题配色

设计语言为中性 slate 底 + 蓝色强调：浅色主题**全部区域都是浅色**（含侧栏、标题栏、日志/代码面板与 SSH 终端窗口），深色主题全部为深色，不混用。

主题以全局设计 token 驱动（`electron/src/renderer/theme/themes.css` 是唯一取色来源），内置四套配色：浅色（默认）、深色、樱花、事件画布。标题栏右侧的太阳/月亮图标按钮循环切换并经设置后端持久化；设置面板「通用设置 → 主题」可直接选择。主进程按 `shared/theme-contract.ts` 的注册表同步原生标题栏配色与新窗口底色；SSH 终端窗口保持 invoke-only 边界，主题通过启动参数在首帧前落位（已开启的终端窗口保留打开时的主题，重开即跟随）。

新增配色三步：在 `themes.css` 复制一个 `:root[data-theme="…"]` 块改值 → 在 `shared/settings-contract.ts` 的 `SettingsTheme` 枚举登记 → 在 `shared/theme-contract.ts` 的 `THEMES` 注册表加一行。`theme.test.ts` 会自动强制：token 集完整、关键前景/背景对满足 WCAG 对比度、浅色主题不出现深色表面（反之亦然）、注册表原生色与 CSS token 一致，并禁止组件 CSS 出现硬编码色值或把表面 token 当文字色用。

### 检查

~~~powershell
pnpm electron:check
cargo test --locked --package lovelyres-electron-backend
cargo clippy --locked --package lovelyres-electron-backend --all-targets -- -D warnings
pwsh -NoProfile -File ./scripts/electron-source-gate.ps1 -RepositoryRoot .
pnpm electron:release:dependency-gate
pnpm electron:release:ledger-gate
~~~

迁移收口时使用 `pnpm electron:release:quality-gate:strict`。它会额外要求 GPUI crate、依赖和 lockfile 条目保持退役状态（负向检查，已通过），58 项 UI ledger 全部有通过证据，并执行最终 workspace 检查；验收完成前失败是预期阻断，不得绕过。config-generator 的 90 项测试替代进度另见 docs/CONFIG_GENERATOR_TEST_BACKLOG.md。

Electron UI 回归使用自身的 CDP/debugger 与截图机制：

~~~powershell
pnpm --filter @lovelyres/electron test:debug
~~~

该调试链检查自定义本地 origin、CSP、精确 preload API、Node 隔离、本地资源、页面交互、可访问性、hostile plain text、截图和控制台错误。迁移验收不使用 computer-use。

### Windows 便携包

~~~powershell
pnpm electron:release:package
pnpm electron:release:validate
pnpm electron:release:smoke
~~~

Windows 流程见 [Electron 便携发布](docs/ELECTRON_PORTABLE_RELEASE.md)。macOS/Linux Electron package 与 clean-environment smoke 尚未完成时，不得宣称三平台发布已经通过。SSH 实机覆盖见 [SSH 兼容性与安全策略](docs/SSH_COMPATIBILITY.md)。

## 离线与安全约束

- UI 字体、图标、Logo 和目录数据从 electron/assets/ 随包分发；运行时不加载 CDN、远程字体、图片、脚本、样式或 SVG。
- BrowserWindow 启用 sandbox、context isolation 与 web security，关闭 renderer Node，并只加载 lovelyres://app。
- preload 只暴露固定、有界、强类型的方法；renderer 不接收任意 IPC、文件系统、进程、绝对路径、data root 或通用命令能力。
- 运行数据写入可执行文件同级的 data/，不写浏览器存储，也不静默回退到用户配置目录。
- 每个远端请求都绑定 core 管理的目标身份与代次；切换或断开后，迟到结果失败关闭。
- 用户、远端、AI、日志和导入文本始终作为纯文本。不得把它们解释为 HTML、资源、路径、动作或 shell 程序。
- 危险写操作使用不可变 core 计划、精确确认、单次能力、journal、独立 verify，并在可恢复时提供 restore。
- 密钥、口令、密文和秘密配置不得进入日志、renderer DTO、截图、导出或浏览器状态。

## 贡献

提交前请阅读 [AGENTS.md](AGENTS.md)，运行与改动风险相称的 Rust、Electron、source gate 和 CDP 检查。新增模块如果尚未接入页面、窗口或 preload，必须登记到 [docs/UNWIRED_FEATURES.md](docs/UNWIRED_FEATURES.md)，并保持 Pending。

## 开源协议

本项目基于 AGPLv3 协议开源，详情见 [LICENSE](LICENSE)。

---

<div align="center">
  <sub>Built with ❤️ by the Tokeii</sub>
</div>
