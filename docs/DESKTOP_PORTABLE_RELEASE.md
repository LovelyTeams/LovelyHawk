# Windows x64 便携发布（Tauri 2）

便携包是一个 ZIP，不使用安装器、MSI 或在线下载器。Electron 时期的发布说明见 [legacy/ELECTRON_PORTABLE_RELEASE.md](legacy/ELECTRON_PORTABLE_RELEASE.md)，仅作历史参考。

## 产物

```text
artifacts/
  LovelyHawk-<版本>-windows-x64.zip
  LovelyHawk-<版本>-windows-x64.zip.sha256
```

ZIP 只有一个顶层目录，里面恰好八个文件：

```text
LovelyHawk-<版本>-windows-x64/
  LovelyHawk.exe                  # Tauri 宿主 + 进程内后端；页面资源已嵌入
  lovelyhawk-win-agent.exe        # Windows 远程桌面会话采集端（不随主程序自动运行）
  LICENSE
  THIRD_PARTY_NOTICES.md          # 来自 ui/THIRD_PARTY_NOTICES.md：界面依赖、Tauri/WebView2、字体
  THIRD_PARTY_LICENSES_RUST.txt   # 链接进可执行文件的每个 Rust crate 及其自带的许可证全文
  SBOM.cdx.json                   # CycloneDX 1.5 物料清单：crate、界面依赖与嵌入资源（含 SHA-256）
  README.txt                      # 面向使用者的简短说明
  PACKAGE_MANIFEST.json           # schema lovelyhawk-portable-package/v1，记录其余文件的路径、字节数与 SHA-256
```

`THIRD_PARTY_LICENSES_RUST.txt` 与 `SBOM.cdx.json` 由 `scripts/desktop-third-party.mjs` 按目标平台生成：

- 依赖范围是桌面 crate 在该目标上的普通依赖闭包；
- 许可证全文按内容去重；
- 没有自带许可证文件的少数 crate 单独列出，并要求其许可证的标准全文已由其他 crate 提供，否则生成失败；
- 出现 GPUI crate，或任何组件没有声明许可证时，生成失败。

包内不带 `data/`。首次启动时在 `LovelyHawk.exe` 旁创建 `data/`，连接库、历史、案件、证据与 WebView2 数据都在其中。迁移时把整个文件夹一起移动。

程序日志写在 `data/logs/lovelyhawk.log`，满约 2 MB 时改名为 `lovelyhawk.1.log`、`lovelyhawk.2.log`，最多保留三个。内容与“应用日志”浮层相同，口令、令牌等已遮蔽；排障时可直接附上这个文件。写不进去时程序照常运行，浮层会说明日志只在内存中。

页面由系统自带的 Microsoft Edge WebView2 Runtime 渲染（Windows 11 与已更新的 Windows 10 默认具备）。包内不附带固定版本的 WebView2，这一点记录在 [OPEN_ITEMS.md](OPEN_ITEMS.md)。

## 构建与打包

前提：Windows x64、Rust 1.93.1、`pnpm install --frozen-lockfile` 之后的依赖、可用的 `llvm-objdump`。

```powershell
pnpm release:package -Build
```

打包脚本 `scripts/desktop-package-windows.ps1` 依次执行：

1. 源码门禁的自检与正式检查（`desktop-source-gate.ps1`）；
2. 使用 `-Build` 时由 `desktop-build-windows.ps1` 先构建 UI，再以 `-C target-feature=+crt-static` 构建 release 宿主与 `lovelyhawk-win-agent.exe`；
3. 用 `desktop-verify-windows-binary.ps1` 检查两个可执行文件：必须是 x86-64 PE，不得动态导入 `VCRUNTIME*`、`MSVCP*` 或 `MSVCR*`；
4. 核对第三方声明中的必需条目，并核对版本号与 `tauri.conf.json` 一致；
5. 在 `artifacts/` 下的临时目录组装、写清单、压缩并写校验和。已有同名产物时拒绝覆盖；
6. 调用校验器检查刚生成的 ZIP。

**为什么允许 UCRT**：即使以静态 CRT 构建，当前 release 宿主仍导入 `api-ms-win-crt-*`，这一点已在本仓库的构建中实际观察到。通用 C 运行库（UCRT）是 WebView2 支持的所有 Windows 版本都自带的系统组件，因此二进制检查以 `-AllowSystemUcrt` 放行 UCRT。VC++ 可再发行组件仍然禁止，因为干净的机器上没有它。

## 校验

```powershell
pnpm release:validate -ArchivePath artifacts/LovelyHawk-1.0.0-windows-x64.zip
```

`scripts/desktop-validate-package.ps1` 不运行程序，只检查：

- 相邻 `.sha256` 与 ZIP 一致；
- 只有一个 `LovelyHawk-<版本>-windows-x64` 目录，文件集合恰好是上面八个，没有 `data/` 或其他运行状态；
- `SBOM.cdx.json` 是 CycloneDX 1.5，每个组件都有许可证、没有 GPUI，SBOM 中的每个 crate 都能在 `THIRD_PARTY_LICENSES_RUST.txt` 中找到对应条目；
- 清单的 schema、版本与目录名一致，并逐个列出、逐个核对其余文件的大小与 SHA-256；
- `LovelyHawk.exe` 是 PE 文件，且不包含仅调试构建才读取的变量名（`LOVELYHAWK_DEBUG_PORT`、`LOVELYHAWK_TEST_DIALOG_ANSWERS`、`LOVELYHAWK_TEST_CLIPBOARD_FILE`、`LOVELYHAWK_ARCHIVE_ROOT`、`LOVELYHAWK_DEV_SERVER`）。

`-SelfTest` 用构造的合格包、带运行数据的包与被篡改的包验证校验器本身。

## 便携冒烟

```powershell
pnpm release:smoke -ArchivePath artifacts/LovelyHawk-1.0.0-windows-x64.zip
```

`scripts/desktop-portable-smoke.ps1` 按使用者的方式运行一次：

- 先校验 ZIP，再解压到路径中同时含空格与中文的新目录；
- 把 `APPDATA`、`LOCALAPPDATA` 重定向到临时目录，不带参数启动；
- 等待页面完成首次渲染（宿主把就绪标记写到系统临时目录下固定格式的目录中），再通过窗口正常关闭；
- 要求进程正常退出、WebView2 辅助进程全部结束、新增文件只出现在程序旁的 `data/` 下，且重定向的用户目录中没有任何写入。

## Linux x64 便携包（实验性）

`scripts/desktop-package-linux.sh <可执行文件> <输出目录> <清单目录> [版本]` 生成 `LovelyHawk-<版本>-linux-x64.tar.gz` 与相邻的 `.sha256`。

- 包内的七个文件与 Windows 包对应，可执行文件名为 `lovelyhawk`；
- 清单目录需事先在构建机上生成：`node scripts/desktop-third-party.mjs --target x86_64-unknown-linux-gnu --out <目录> --version <版本>`。这个脚本需要界面的 `node_modules`。

打包规则与 Windows 包相同：

- 已有同名产物时拒绝覆盖；
- 可执行文件中不得含仅调试构建读取的变量名；
- 第三方声明必须包含必需条目；
- 版本号须与 `tauri.conf.json` 一致。

页面由系统的 WebKitGTK 4.1 渲染，包内不附带。

`scripts/desktop-portable-smoke-linux.sh <tar.gz>` 按使用者的方式运行一次：

- 先核对校验和、文件集合与清单；
- 解压到路径中同时含空格与中文的新目录；
- 用空的家目录、Xvfb 与 openbox 启动程序，等待页面就绪标记；
- 通过窗口管理器关闭窗口；
- 要求正常退出、新增文件只出现在 `data/` 下、家目录中没有任何写入。

构建与冒烟目前在一次性的 Debian 12 容器中进行（WSL 中的 Docker，源码只读挂载后复制，安装 `libwebkit2gtk-4.1-dev` 等构建依赖与 Rust 1.93.1）。

### Linux 实测记录（2026-10-11）

环境：Debian 12（bookworm）容器、WebKitGTK 2.50.6、x86_64，Xvfb 加 openbox。

- `cargo build --release --locked -p lovelyhawk-desktop --bin lovelyhawk` 无警告通过，产出 27 MB 的 stripped ELF，动态链接系统的 WebKitGTK 4.1 与 GTK 3；
- 第一次冒烟失败：窗口始终没有出现。原因是 WebKitGTK 首次导航到的 `tauri://localhost` 没有路径，宿主的导航守卫只接受 `/` 与 `/index.html`，于是拒绝了自己的主页。修正守卫并补上回归测试后，打包与冒烟通过：
  - 页面 1 秒内就绪；
  - 通过窗口管理器关闭后正常退出（0）；
  - 新增文件全部在 `data/` 下，家目录中没有写入；
  - 解压路径含空格与中文。
- 这一结果只说明 Debian 12 容器中的启动、渲染与关闭可用。功能页面、终端子窗口、文件对话框、剪贴板，以及其他发行版与桌面环境（Wayland、GNOME/KDE）都还没有在 Linux 上验证。

## 尚未完成

- macOS 的构建、打包与冒烟没有做（需要 macOS 机器）；Linux 只在 Debian 12 容器中做了启动级冒烟，不得宣称三平台发布已经通过；
- 干净虚拟机（无开发工具、刚安装的 Windows 10/11）上的冒烟没有记录；
- 包内不附带固定版本的 WebView2，缺少系统 WebView2 的环境无法运行；
- 程序没有代码签名。
