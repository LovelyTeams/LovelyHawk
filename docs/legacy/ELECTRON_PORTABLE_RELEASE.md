# Electron Windows x64 便携发布

第一版 Windows 产物是目录型 ZIP，不使用 `electron-builder`、NSIS、MSI、单文件自解压或在线安装器。打包链只复制 `pnpm-lock.yaml` 所对应、当前已安装且与 `electron/package.json` 精确版本一致的 Electron runtime；当前锁定版本为 `43.4.1`。

## 固定产物与目录

```text
artifacts/
  LovelyRes-1.0.0-windows-x64.zip
  LovelyRes-1.0.0-windows-x64.zip.sha256
```

ZIP 只有一个顶层目录：

```text
LovelyRes-1.0.0-windows-x64/
  LovelyRes.exe
  *.dll, *.pak, locales/, resources.pak, snapshots...  # 完整 Electron runtime
  resources/
    app/
      package.json
      dist-electron/                                   # 仅生产 JS
      dist-renderer/                                   # Vite 生产产物
    bin/lovelyres-backend.exe                          # 静态 CRT Rust sidecar
  licenses/
    ELECTRON_LICENSE
    LICENSES.chromium.html
  LICENSE
  THIRD_PARTY_NOTICES.md
  RUNTIME_MANIFEST.json
  PACKAGE_MANIFEST.json
  data/README.txt
```

`resources/app` 明确排除 `node_modules`、`src`、TypeScript、测试和 source maps。Electron 的 `LICENSE` 与 `LICENSES.chromium.html` 不会被项目许可证覆盖，而是原样保存在 `licenses/`；`THIRD_PARTY_NOTICES.md` 同时覆盖 React、React DOM、Scheduler 与本地字体。`RUNTIME_MANIFEST.json` 冻结经过重命名后的完整 Electron runtime 文件集、字节数和 SHA-256。`PACKAGE_MANIFEST.json` 为除自身外的每个文件记录相对路径、字节数与 SHA-256；相邻 `.zip.sha256` 绑定最终 ZIP。

运行时状态只能写入 ZIP 顶层的 `data/`。禁止生成 `data/data`，移动应用时应把 `LovelyRes.exe`、`resources/` 和 `data/` 作为整体移动。

## 本地发布顺序

要求 Windows x64、Rust 1.93.1、锁定 pnpm 依赖和 `llvm-objdump`。先执行常规 Electron 检查，然后构建静态 CRT sidecar：

```powershell
pnpm electron:check
pnpm electron:release:source-gate
pnpm electron:release:sidecar
```

sidecar 命令等价于：

```powershell
$env:RUSTFLAGS = '-C target-feature=+crt-static'
cargo build --release --locked `
  --package lovelyres-electron-backend `
  --bin lovelyres-backend `
  --target x86_64-pc-windows-msvc
./scripts/electron-verify-windows-sidecar.ps1 `
  -BinaryPath ./target/x86_64-pc-windows-msvc/release/lovelyres-backend.exe
```

PE gate 必须识别 x86-64 PE/COFF，并拒绝 `VCRUNTIME*`、`MSVCP*`、`MSVCR*`、`ucrtbase.dll` 和 `api-ms-win-crt-*` 动态 imports。找不到 `llvm-objdump` 时硬失败，不把仅设置 `RUSTFLAGS` 当成验证。

构建生产前端、打包并验证：

```powershell
pnpm electron:build
pnpm electron:release:package

pnpm electron:release:validate -- `
  -ArchivePath ./artifacts/LovelyRes-1.0.0-windows-x64.zip `
  -Version 1.0.0
```

打包命令自身会再次强制运行 source gate 和 sidecar 静态 CRT/import gate，复制 sidecar 后复核 SHA-256 并再次检查 imports，不能靠跳过前置命令生成产物。验证器会先限制 ZIP entry 数、名称长度、单文件大小、总展开大小与压缩比，拒绝 traversal、ADS、DOS device、尾随点/空格及 Windows 规范化冲突，再解压到唯一临时目录。build-provenance 模式逐文件双向比对锁定的本机 Electron runtime；clean-artifact 模式只依赖 ZIP、checksum 和内置 runtime inventory，因此 clean smoke 不需要源码或 `node_modules`。两个模式都检查 Electron 与 sidecar 的 x64 PE 头、runtime/package manifest，并拒绝：

- workspace 绝对路径泄漏；
- 文件名或生产文本中的 GPUI 残留；
- HTML/CSS/JS 中的远程资源加载；
- Electron runtime、应用入口、sidecar、许可证、notices、manifest 或 `data/README.txt` 缺漏；
- `resources/app` 下的源码、测试、source maps 或 `node_modules`；
- ZIP traversal、重复路径、额外顶层目录和 `data/data`。

验证器的十六项故障注入自测会重新生成 manifest 与 ZIP checksum，避免仅因哈希失配而“假拒绝”：

```powershell
pnpm electron:release:selftest -- `
  -ArchivePath ./artifacts/LovelyRes-1.0.0-windows-x64.zip `
  -Version 1.0.0
```

它必须分别命中缺文件、GPUI 残留、workspace 路径、远程资源、`data/data`、许可证缺项、未声明 runtime、traversal、ADS、尾随点、DOS device、entry 数、路径长度、单文件、总展开量和压缩比上限拒绝分支。

## Electron 原生便携 smoke

```powershell
pnpm electron:release:smoke -- `
  -ArchivePath ./artifacts/LovelyRes-1.0.0-windows-x64.zip `
  -Version 1.0.0 `
  -TimeoutSeconds 60
```

Smoke 解压到同时含中文和空格的唯一目录，从其中启动 `LovelyRes.exe`。启动前必须用 GUID 名称为 Electron EXE 和 sidecar 建立临时 Windows 防火墙出站阻断规则；权限不足、规则建立失败或规则中途消失都会写 `NOT_RUN` 并返回失败，不能降级为联网 smoke。规则在所有退出路径的 `finally` 中删除并复核不存在。随后同时等待：

1. 主进程原子写出的 `lovelyres-smoke-ready/v1` marker；
2. Electron/Chromium remote-debugging 暴露的 `lovelyres://app/` 页面；
3. CDP `Runtime.evaluate` 确认标题、20 个导航项、Rust 后端握手、renderer 中没有 `process`/`require`，且所有实际资源 URL 都来自 `lovelyres://app/`；
4. 唯一的 `lovelyres-backend.exe` 子进程仍然存活。

CDP connect/send/receive/close 全部受同一个全局截止时间约束。进程关闭时脚本跟踪 Electron、Chromium 与 sidecar 的完整后代树；只有主窗口握手后整棵树优雅退出才通过，任何强杀都只用于清理并把 smoke 判为失败。随后比较整个解压树，任何 `data/` 外写入都失败；隔离后的 `APPDATA`/`LOCALAPPDATA` 也必须保持不变。Smoke marker 只能写入系统临时目录下带随机 nonce 的新目录和新文件，生产进程不会删除或覆盖任意 marker 目标。Smoke 使用 Electron 自带的 marker、CDP 和进程信息，不使用屏幕自动化或 `computer-use`。

失败时保留唯一 smoke 目录、stdout/stderr 与 `smoke-control/report.json`（只有完整通过时才写 PASS report）。超时、未运行和 `NOT_RUN` 都不是通过。

## 发布前证据

发布记录必须逐项保存真实输出：Electron typecheck/tests/build、release sidecar build、静态 CRT/PE import gate、package validator、portable smoke、最终 ZIP SHA-256。任何一项未执行都要明确标为未运行，不能用其他平台或 debug 构建替代。

### 当前工作树观察（2026-08-24）

- 新生成的验证用 ZIP 已通过 clean-artifact validator、workspace provenance validator、两次 static CRT/import gate，以及 16/16 validator 故障注入。
- 当前会话没有 Windows 防火墙管理权限；portable smoke 在启动应用前以 `status: NOT_RUN` 和非零退出拒绝继续，检查确认没有遗留 `LovelyResSmoke-*` 规则或 smoke 进程。
- 随后的全工作树 `pnpm electron:check` 被并行新增的 `electron/src/shared/config-contract.ts` TypeScript 错误阻断。因此上述 ZIP 只是打包链验证产物，不是发布候选；修复当前检查、重新构建并在具备防火墙能力的环境取得完整 smoke `PASS` 前不得发布。
