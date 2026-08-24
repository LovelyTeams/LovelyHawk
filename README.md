<div align="center">
  <img src="crates/lovelyres-gpui/assets/logo.png" alt="LovelyRes Logo" width="250" height="250">

  # LovelyERes

  **Linux 应急响应工具**

  面向应急响应、攻防演练与日常运维的原生 SSH / SFTP 诊断工作台。

  [![Rust](https://img.shields.io/badge/Rust-1.93.1-000000?style=flat-square&logo=rust&logoColor=white)](https://www.rust-lang.org)
  [![GPUI](https://img.shields.io/badge/GPUI-0.2.2-6B5BFF?style=flat-square)](https://www.gpui.rs/)
  [![License](https://img.shields.io/badge/License-AGPLv3-yellow.svg?style=flat-square)](LICENSE)
</div>

---

## 简介

LovelyERes（Lovely Emergency Response）是一个以 Rust 和 GPUI 构建的跨平台原生桌面应用。当前主线只有 Cargo workspace，不依赖浏览器内核或前端运行时。应用把 SSH、SFTP、终端、诊断与处置能力组织在同一套目标绑定模型中，适合在离线比赛环境中携带和启动。

主要能力包括：

- 原生多窗口 SSH 终端、SFTP 文件管理和容器终端；
- 系统信息、Docker、Kubernetes、快速检测、安全速查、日志分析、抓包与完整性检查；
- 防火墙、快照、基线加固、数据库、Java 更新与多机批量工作流；
- 调查笔记、命令历史、AI 历史和处置报告；
- 目标代际校验、危险操作确认、操作日志、执行后验证与可恢复流程。

尚未开放或仍需实机验收的能力记录在 [未接线功能清单](docs/UNWIRED_FEATURES.md)。

## 技术栈

| 层 | 技术 | 职责 |
|---|---|---|
| 原生界面 | GPUI 0.2.2、gpui-component 0.5.1 | 主窗口、原生窗口、实体、视图和交互 |
| 核心服务 | Rust 2024、Tokio | SSH/SFTP、诊断、存储、审计和强类型安全边界 |
| 终端 | alacritty_terminal、GPUI | 终端模型、传输、输入、搜索、选择和渲染 |
| SSH/SFTP | russh、russh-sftp | 目标绑定的远程会话与文件传输 |
| 本地资源 | rust-embed | 字体、图标、Logo 与安全速查数据随二进制分发 |

依赖版本由根目录 `Cargo.toml` 与已提交的 `Cargo.lock` 固定。发布工具链固定为 Rust 1.93.1。

## 项目结构

```text
LovelyRes/
├── Cargo.toml                    # Cargo workspace 与统一依赖版本
├── Cargo.lock                    # 锁定的可复现依赖图
├── crates/
│   ├── lovelyres-core/           # 与 UI 无关的领域服务、安全契约和便携存储
│   ├── lovelyres-terminal/       # 原生终端模型、传输、视图与一致性测试
│   └── lovelyres-gpui/           # GPUI 应用壳、页面、窗口和内嵌资源
│       └── assets/               # 本地字体、Logo、图标和安全速查数据
├── docs/                         # 原生应用、兼容性与发布文档
└── scripts/                      # 源码、依赖、质量与便携发布门禁
```

开发入口是 `crates/lovelyres-gpui/src/main.rs`，应用组合根位于 `crates/lovelyres-gpui/src/app.rs`。业务规则应进入 `lovelyres-core`；终端协议和渲染基础应进入 `lovelyres-terminal`；窗口与页面交互留在 `lovelyres-gpui`。

## 快速开始

### 环境要求

- Rust 1.93.1，包含 `rustfmt` 与 `clippy`；
- 对应平台的原生 Rust 构建工具链；
- PowerShell 7.2+（仅运行仓库内的 PowerShell 门禁与 Windows 打包脚本时需要）。

### 开发运行

```powershell
cargo run --locked --package lovelyres-gpui --bin lovelyres
```

### 构建

```powershell
cargo build --locked --package lovelyres-gpui --bin lovelyres
cargo build --release --locked --package lovelyres-gpui --bin lovelyres
```

### 测试与质量检查

```powershell
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
pwsh -File ./scripts/gpui-source-gate.ps1 -ManifestPath ./Cargo.toml
pwsh -File ./scripts/gpui-dependency-gate.ps1 -ManifestPath ./Cargo.toml
```

完整发布门禁与便携包格式见 [GPUI 便携发布与门禁](docs/GPUI_PORTABLE_RELEASE.md)，SSH 实机覆盖要求见 [SSH 兼容性与安全策略](docs/SSH_COMPATIBILITY.md)。

## 离线与安全约束

- UI 字体、图标、Logo 和速查数据全部位于 `crates/lovelyres-gpui/assets/` 并嵌入程序；不从 CDN、网络字体或远程 UI 资源加载。
- 运行数据写入可执行文件同级的 `data/`，便携包不依赖用户配置目录。
- 所有远端操作都必须绑定目标身份与代次；切换目标后，迟到结果不得应用。
- 用户输入或远端返回值不得直接形成 shell 命令。固定形状输入使用白名单类型，必要参数由核心层统一转义。
- 危险写操作必须使用不可变计划、精确确认、journal、verify，并在可恢复时提供 restore。
- 密钥与凭据不得进入日志、UI 状态快照或导出文件。

## 贡献

提交修改前请阅读 [AGENTS.md](AGENTS.md)，并至少运行与修改范围相称的格式检查、Clippy 和测试。新增功能若尚未挂入页面或窗口，必须登记到 [docs/UNWIRED_FEATURES.md](docs/UNWIRED_FEATURES.md)。

## 开源协议

本项目基于 AGPLv3 协议开源，详情见 [LICENSE](LICENSE)。

---

<div align="center">
  <sub>Built with ❤️ by the Tokeii</sub>
</div>
