<div align="center">
  <img src="public/logo.png" alt="LovelyERes Logo" width="250" height="250">

  # LovelyERes
  
  **Linux 应急响应工具**
  
  一款专为快速服务器管理和应急响应设计的现代化、高性能 SSH 终端及诊断工具箱。

  [![Tauri](https://img.shields.io/badge/Tauri-v2.0-24C8DB?style=flat-square&logo=tauri&logoColor=white)](https://tauri.app)
  [![Vue](https://img.shields.io/badge/Vue.js-v3.5-4FC08D?style=flat-square&logo=vue.js&logoColor=white)](https://vuejs.org)
  [![Rust](https://img.shields.io/badge/Rust-Backend-000000?style=flat-square&logo=rust&logoColor=white)](https://www.rust-lang.org)
  [![TypeScript](https://img.shields.io/badge/TypeScript-5.0-3178C6?style=flat-square&logo=typescript&logoColor=white)](https://www.typescriptlang.org)
  [![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)

  [功能特性](#-功能特性) • [技术栈](#-技术栈) • [快速开始](#-快速开始) • [开发计划](#-开发计划)
</div>

---

## 📖 简介

**LovelyERes** (Lovely Emergency Response) 是一款专为应急响应、CTF 比赛和日常运维设计的多功能桌面应用。与标准的 SSH 客户端不同，LovelyERes 专为 **应急响应场景和攻防演练** 优化，提供了一个稳健、安全且高效的环境，用于快速诊断、修复 Linux 服务器问题，同时也能胜任日常运维管理工作。

基于 **Tauri v2** 框架构建，它结合了轻量级的原生占用和 **Vue 3** 带来的现代化 UI 体验。

## 支持


## ✨ 功能截图

### 仪表盘界面
<img width="1498" height="1014" alt="image" src="https://github.com/user-attachments/assets/b787eca7-37dc-4494-bf10-9becb811c176" />

### 系统信息
<img width="1312" height="928" alt="image" src="https://github.com/user-attachments/assets/180f5f83-0561-4b55-86d8-64cb52b4d48d" />
<img width="1312" height="928" alt="image" src="https://github.com/user-attachments/assets/b101b779-f4b2-4ffb-9110-eb6db33dd6d2" />

### SFTP管理
<img width="1312" height="928" alt="image" src="https://github.com/user-attachments/assets/dbd1fc4f-f053-44f5-bfa3-97bb5284e701" />

### Docker容器管理
<img width="1312" height="928" alt="image" src="https://github.com/user-attachments/assets/d179cc53-bcee-43a1-8c2e-56e23b9130a4" />

### 常用命令快速执行
<img width="1312" height="928" alt="image" src="https://github.com/user-attachments/assets/2d38d720-b1b2-476d-92ed-a994cf8ca40d" />
<img width="1312" height="928" alt="image" src="https://github.com/user-attachments/assets/5c61e064-43ec-4f9e-8673-782936bd85d8" />

### 快速检测
<img width="1312" height="928" alt="image" src="https://github.com/user-attachments/assets/9d6e238a-52fd-40d4-9de9-891edcaa6d86" />

### AI分析功能
<img width="1312" height="928" alt="image" src="https://github.com/user-attachments/assets/1650a489-252e-4f0a-9bb3-25e4aad38a21" />

### SSH终端
<img width="1002" height="702" alt="image" src="https://github.com/user-attachments/assets/3f34bb35-67f5-4179-828b-ade436ffcc7f" />

<img width="1002" height="702" alt="image" src="https://github.com/user-attachments/assets/55178d80-74ae-4427-a26c-acf27205d165" />

<img width="1002" height="702" alt="image" src="https://github.com/user-attachments/assets/6bc24c96-b3f5-4109-802b-158f0bef3534" />





## 🛠 技术栈

| 组件 | 技术 | 说明 |
|-----------|------------|-------------|
| **核心框架** | [Tauri v2](https://tauri.app) | 构建轻量级、快速的二进制应用框架 |
| **前端框架** | [Vue 3](https://vuejs.org) | 响应式 UI 框架 |
| **构建工具** | [Vite](https://vitejs.dev) | 下一代前端构建工具 |
| **开发语言** | [TypeScript](https://www.typescriptlang.org) | 类型安全的 JavaScript |
| **后端逻辑** | [Rust](https://www.rust-lang.org) | 用于核心逻辑的系统级编程语言 |
| **终端组件** | [xterm.js](https://xtermjs.org) | 全功能终端组件 |
| **图标库** | [IconPark](https://iconpark.bytedance.com) | 丰富的图标资源库 |

## 📂 项目结构

```bash
LovelyRes/
├── index.html                # 唯一的 HTML 入口（辅助窗口用 ?window=xxx 复用）
├── src/                      # 前端源码 (TypeScript + Vite)
│   ├── main.ts               # 入口：引导主应用 / 分流辅助窗口
│   ├── entries/              # SSH 终端、容器终端等独立窗口入口
│   ├── modules/              # 业务逻辑（按领域分目录）
│   │   ├── core/             # 状态、日志、操作日志、转义等基础设施
│   │   ├── ui/               # 渲染器、右键菜单、模态框
│   │   ├── detection/        # 快速检测与一键修复
│   │   ├── emergency/        # 应急命令库
│   │   ├── secfix/           # 安全速查（离线修复片段库）
│   │   └── ...               # docker / kubernetes / baseline / firewall / snapshot 等
│   ├── components/           # Vue SFC（仅终端窗口使用）
│   └── css/                  # main.css → tokens → themes → base → components → layout → pages
├── src-tauri/                # 后端源码 (Rust)
│   ├── src/
│   │   ├── ssh_manager_russh.rs   # SSH / SFTP（russh 实现）
│   │   ├── detection_manager.rs   # 检测逻辑
│   │   ├── commands/              # Tauri command 分组
│   │   └── ...
│   ├── capabilities/         # Tauri 权限配置
│   └── tauri.conf.json
├── public/                   # 静态资源 (Logos, Icons)
└── docs/                     # 开发文档
```

> 说明：项目虽然依赖 Vue 3，但 UI **不是** Vue 应用——绝大部分界面由
> `src/modules/ui/modernUIRenderer.ts` 生成 HTML 字符串并配合事件委托驱动，
> 只有终端窗口使用了 Vue SFC。参与开发前请先读 [AGENTS.md](AGENTS.md)。

## 🚀 快速开始

### 环境要求

- **Node.js** (v18+)
- **Rust** (最新稳定版)
- **Visual Studio Code** (推荐) 配合 Rust Analyzer & Volar 插件

### 安装步骤

1. **克隆仓库**
   ```bash
   git clone https://github.com/Tokeii0/LovelyERes.git
   cd lovelyres
   ```

2. **安装依赖**
   ```bash
   npm install
   ```

3. **运行开发模式**
   该命令将启动前端开发服务器和 Tauri Rust 后端。
   ```bash
   npm run tauri dev
   ```

4. **构建生产版本**
   ```bash
   npm run tauri build
   ```

## 🤝 贡献指南

欢迎提交 Pull Request 来参与贡献！

1. Fork 本项目
2. 创建您的特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交您的更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启一个 Pull Request

## 📜 开源协议

本项目基于 AGPLv3 协议开源。详情请参阅 `LICENSE` 文件。

---

<div align="center">
  <sub>Built with ❤️ by the Tokeii</sub>
</div>
