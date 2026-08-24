# GPUI 便携发布与门禁

GPUI 发布使用 `.github/workflows/gpui-release.yml`。v1 的必交付物是 Windows 10/11 x64 便携包：

```text
LovelyRes-1.0.0-windows-x64.zip
LovelyRes-1.0.0-windows-x64.zip.sha256
LovelyRes-1.0.0-windows-x64.cdx.json
```

ZIP 内固定包含 `LovelyRes.exe`、`LICENSE`、`THIRD_PARTY_NOTICES.txt`、`SBOM.cdx.json` 和 `data/README.txt`。不生成 MSI、NSIS，也不包含浏览器运行时。

## 工作流顺序

1. `quality` 在 Rust 1.93.1 上校验冻结测试基线，再运行 GPUI source/resource gate、`cargo fmt --all --check`、workspace clippy `-D warnings`、workspace tests，以及 Cargo dependency tree gate。
2. `windows-portable` 仅在 quality 成功后运行。它以 `x86_64-pc-windows-msvc` 和 `-C target-feature=+crt-static` 构建、检查 PE imports、生成 notices 与 CycloneDX SBOM、打包、执行便携 smoke、生成 SHA-256，并用 GitHub artifact attestations 分别记录 build provenance 和 archive→SBOM 绑定。
3. Windows 全部通过后，文件上传为 workflow artifact，并附加到 `gpui-v1.0.0` 的 draft release。
4. `linux-x64-preview` 与 `macos-universal-preview` 都显式 `needs: windows-portable`。默认不运行；从 `workflow_dispatch` 勾选 `build_preview_platforms` 后才生成 provisional `tar.zst` / universal `.app.zip`。它们不是 v1 Windows 验收的替代品。

推送 `gpui-v1.0.0` tag 或手动 dispatch 均会执行 Windows gate。后续版本必须同时更新 workflow 的 `RELEASE_VERSION`、`RELEASE_TAG` 和所有确定性产物名，不能只改其中一处。

## 本地质量门禁

安装 Rust 1.93.1、rustfmt 和 clippy 后运行：

```powershell
./scripts/gpui-quality-gates.ps1 -ManifestPath ./Cargo.toml
```

依赖门禁也可单独运行：

```powershell
./scripts/gpui-dependency-gate.ps1 -ManifestPath ./Cargo.toml
```

源码/资源门禁也可单独运行：

```powershell
./scripts/gpui-source-gate.ps1 -ManifestPath ./Cargo.toml
./scripts/gpui-source-gate.ps1 -SelfTest
```

dependency gate 对 locked workspace 的全部 target/feature 执行 `cargo tree`，并拒绝浏览器 UI 运行时依赖。source gate 扫描三个 crate 的 Rust source 与四份 Cargo manifest，确认 `gpui-component = 0.5.1` 保持 `default-features = false`，拒绝外部终端服务器入口、Web runtime 文件、CDN/远程字体和远程 UI 资源，并核对 18 页、四类原生窗口、action registry 以及本地 Inter/Cascadia/Logo/app icon。Inter、Cascadia Mono、透明 Logo PNG 和 Windows app icon 都必须匹配固定 SHA-256，且 Logo 由内嵌字节同步解码，不依赖远程或异步路径资源。

## Windows 静态 CRT 与打包

CI 安装 `llvm-tools-preview`，release build 使用：

```powershell
$env:RUSTFLAGS = '-C target-feature=+crt-static'
cargo build --release --locked --package lovelyres-gpui --bin lovelyres --target x86_64-pc-windows-msvc
./scripts/gpui-verify-windows-binary.ps1 `
  -BinaryPath ./target/x86_64-pc-windows-msvc/release/lovelyres.exe
```

验证脚本同时确认目标启用了 `crt-static`、产物是 x86-64 PE/COFF，并拒绝 `VCRUNTIME*`、`MSVCP*`、`MSVCR*`、`ucrtbase.dll` 和 `api-ms-win-crt-*` 动态 imports。缺少 llvm-objdump 会硬失败，不会降级为仅相信 `RUSTFLAGS`。

notices 由 locked Cargo metadata 生成，并收录每个依赖随 crate 发布的 LICENSE/COPYING/NOTICE 文本，以及 `lovelyres-terminal` 的 gpui-terminal/alacritty attribution：

```powershell
New-Item -ItemType Directory -Path ./artifacts -Force | Out-Null
./scripts/gpui-third-party-notices.ps1 `
  -ManifestPath ./Cargo.toml `
  -ProjectNoticePath ./crates/lovelyres-terminal/THIRD_PARTY_NOTICES.md `
  -GpuiNoticePath ./crates/lovelyres-gpui/THIRD_PARTY_NOTICES.md `
  -OutputPath ./artifacts/THIRD_PARTY_NOTICES.txt
```

已有 CycloneDX JSON 后，确定性命名的 Windows 包由下列命令生成：

```powershell
./scripts/gpui-package-windows.ps1 `
  -Version 1.0.0 `
  -BinaryPath ./target/x86_64-pc-windows-msvc/release/lovelyres.exe `
  -OutputDirectory ./artifacts `
  -LicensePath ./LICENSE `
  -NoticesPath ./artifacts/THIRD_PARTY_NOTICES.txt `
  -SbomPath ./artifacts/LovelyRes-1.0.0-windows-x64.cdx.json
```

## 便携 smoke 契约

应用只有在 GPUI root window 初始化完成、便携数据根可写且必要服务就绪后，才能原子写入 `LOVELYRES_SMOKE_READY_FILE`：

```json
{"schema":"lovelyres-smoke-ready/v1","status":"ready"}
```

不得在窗口创建前、错误页显示时或仅 Tokio runtime 启动后写 marker。生产正常启动未设置该环境变量时，不创建 marker。

Smoke 脚本会：

- 先核对相邻 `.sha256` 的文件名和 archive digest，再解压到同时包含空格和中文的唯一临时路径；
- 从解压目录启动 `LovelyRes.exe`，等待最多 30 秒并确认进程仍存活；
- 严格解析上述 schema/status；
- 将 APPDATA/LOCALAPPDATA 指向隔离审计目录，同时监测真实 profile 下常见 LovelyRes 目录；
- 对启动前后的解压树逐项比较，任何 `data/` 以外的新建、修改或删除都失败；
- 关闭进程后确认外部 profile 未发生持久化变化。

本地执行：

```powershell
./scripts/gpui-portable-smoke.ps1 `
  -Version 1.0.0 `
  -ArchivePath ./artifacts/LovelyRes-1.0.0-windows-x64.zip `
  -ScratchDirectory $env:TEMP `
  -TimeoutSeconds 30
```

脚本保留唯一 smoke 临时目录和日志，便于失败后取证；CI runner 结束时自动清理临时盘。它不会递归删除调用者提供的目录。

## 校验下载产物

Windows PowerShell：

```powershell
$expected = (Get-Content ./LovelyRes-1.0.0-windows-x64.zip.sha256).Split(' ')[0]
$actual = (Get-FileHash ./LovelyRes-1.0.0-windows-x64.zip -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw 'SHA-256 mismatch' }
```

安装 GitHub CLI 后验证仓库保存的 Sigstore build provenance attestation：

```powershell
gh attestation verify ./LovelyRes-1.0.0-windows-x64.zip --repo Tokeii0/LovelyERes
```

CycloneDX 文件既作为独立 release asset，也以 `SBOM.cdx.json` 放入便携包。SBOM 扫描输入由 locked 根 `Cargo.toml`、`Cargo.lock` 和三个 crate manifests 组成；`gpui-validate-sbom.ps1` 还会验证格式、非空 components，并拒绝浏览器 UI 运行时依赖。GitHub attestation 的 subject 是最终 ZIP 的 SHA-256 digest，因此重新压缩或修改 ZIP 会使验证失败。

## 预留平台产物

手动启用 preview jobs 后生成：

```text
LovelyRes-1.0.0-linux-x64.tar.zst
LovelyRes-1.0.0-linux-x64.tar.zst.sha256
LovelyRes-1.0.0-macos-universal.app.zip
LovelyRes-1.0.0-macos-universal.app.zip.sha256
```

Linux archive 含可执行文件、许可证、notices、SBOM 和 `data/`。macOS job 分别构建 arm64/x86_64，再以 `lipo` 生成 universal binary；许可证、notices 与 SBOM 位于 app Resources。macOS 运行时数据必须创建在 `.app` 同级 `data/`，不得写入已签名 bundle。两个 preview job 在获得各自的启动 smoke、签名/公证策略和平台验收前不得改名为正式 release gate。
