# GPUI 0.2.2 Windows 可行性门禁

本门禁是页面重写和 Windows 便携版发布的硬前置条件。它只接受同一 `LovelyRes.exe` SHA-256 上采集的真实实验室结果；未实际执行的项目必须写成 `NOT_RUN`。`NOT_RUN` 不等于通过，六组 OS/DPI 基础矩阵或任一专项环境缺证据时，最终 release acceptance 必须失败。

门禁固定面向 `gpui = 0.2.2`、Windows x64。脚本只读取系统信息、枚举显示器/GPU、发起两个短时 TCP 连通性探针，并启动其复制出的 LovelyRes 进程；不更改 DPI、网络、防火墙、RDP 或驱动设置，也不递归删除任何用户路径。

采集、合并和 selftest 明确要求 **PowerShell 7.2+ (`pwsh`)**。它们使用 JSON Schema 2020-12、`$IsWindows` 和现代 .NET 文件 API，不能由 Windows PowerShell 5.1 可靠执行。

## 固定版本局部补丁账

- GPUI 0.2.2 的 Windows `Window::zoom_window()` 实际只执行最大化，不能按其 API 注释恢复；父标题栏的 drag hitbox 还会覆盖子按钮的 control hitbox。LovelyRes 的 Windows UI adapter 从 GPUI 暴露的 raw HWND 精确调用 `SW_MAXIMIZE`/`SW_RESTORE`，并以 `SC_MOVE | HTCAPTION` 启动拖动；其他平台继续走 GPUI API。`app::tests::windows_maximize_button_uses_explicit_restore_workaround` 固定这些命令边界。
- 隐藏创建的 GPUI 0.2.2 Win32 窗口不会触发首帧回调，因此无人值守采集仍短暂呈现窗口。smoke marker 继续只在真实首帧后写入，不能提前到进程入口。

上述都是精确锁定 `gpui = 0.2.2` 的局部兼容措施；升级 GPUI 时必须先移除或重验，不能静默长期携带。

## 结果契约

机器可读契约位于：

- `scripts/gpui-feasibility-manual.schema.json`：可选的人工证据输入，schema 为 `lovelyres-feasibility-manual/v1`。
- `scripts/gpui-feasibility-result.schema.json`：单场景采集结果，schema 为 `lovelyres-feasibility-result/v1`。
- `scripts/gpui-feasibility-summary.schema.json`：发布验收汇总，schema 为 `lovelyres-feasibility-summary/v1`。

应用诊断模式由以下进程环境变量启用：

| 变量 | 值 |
|---|---|
| `LOVELYRES_FEASIBILITY_MODE` | `windows-v1` |
| `LOVELYRES_FEASIBILITY_RESULT_FILE` | harness 指定的绝对 JSON 路径 |
| `LOVELYRES_TERMINAL_STRESS_BYTES` | 默认 `16777216` |
| `LOVELYRES_SMOKE_READY_FILE` | harness 指定的绝对 marker 路径 |

应用结果 schema 必须是 `lovelyres-gpui-feasibility/v1`。自动 IDs 固定为 `root_window`、`portable_store`、`page_registry`、`theme_registry`、`embedded_assets`、`font_assets`、`terminal_no_loss`；人工 IDs 固定为 `d3d11_gpu_driver`、`custom_titlebar`、`native_multi_window`、`chinese_ime`、`clipboard`、`file_dialog`、`folder_dialog`、`theme_switch`、`virtual_large_table`、`mixed_dpi`、`rdp`、`virtual_machine`、`integrated_gpu`、`offline_startup`。

应用初始人工结果必须是 `NOT_RUN`。只有 operator evidence 可以把对应项目改成 `PASS`/`FAIL`；harness 不从硬件名称、环境变量或“窗口能启动”推断人工交互通过，也不会用人工 `PASS` 覆盖应用产生的 `FAIL`。

自动验收还要求：

- marker 精确为 `{"schema":"lovelyres-smoke-ready/v1","status":"ready"}`；
- marker 与 app result 出现后进程仍存活，并一直存活到人工采集结束；
- 非交互采集在两个 readiness 文件出现后还会观察 exact PID 至少 3 秒，避免“写完 marker 立即崩溃”被判为存活；
- `requested_bytes` 等于请求值、`processed_bytes == requested_bytes`、`elapsed_ms >= 1`、`no_loss == true`；
- terminal throughput 不低于 `10 MiB/s`；
- app 报告的便携根等于复制出的可执行文件旁 `data`；进程退出后，harness 会递归比较 portable root、隔离的 Roaming/Local profile 及已存在的 LovelyRes AppData 根，`LovelyRes.exe` 也不得被修改，只有 `data/` 子树可以变化。

`terminal_no_loss` 只证明本地 `TerminalModel` parser 对请求字节计数无损并达到阈值，不证明 D3D 呈现、PTY、SSH 背压、IME 候选窗或高吞吐滚动的视觉正确性；这些仍必须由真实交互和发布前 OpenSSH/Windows 验收覆盖。目录快照也不能证明注册表、任意 `%TEMP%` 路径或其他未监控位置绝无写入；发布前应保留一次 Process Monitor（按 exact PID/子进程过滤）的人工证据。

## 单场景采集

每次使用新的输出文件名。harness 会在输出目录建立 `<name>-run` 与隔离的 `<name>-profile`，复制二进制后从 run directory 启动，并保留 run directory、隔离 profile、原始 app result、marker 和 stdout/stderr 作为证据；不会清理它们。

交互采集示例：

```powershell
pwsh -NoProfile -File ./scripts/gpui-feasibility-collect.ps1 `
  -BinaryPath ./target/x86_64-pc-windows-msvc/release/lovelyres.exe `
  -OutputPath D:/gpui-lab/win11-150.json `
  -ScenarioId win11-150-physical `
  -ExpectedOperatingSystem Windows11 `
  -ExpectedDpiPercent 150 `
  -InteractiveManual
```

在对应实验环境追加开关：`-RequireMixedDpi`、`-RequireRdp`、`-RequireVm`、`-RequireIntegratedGpu`、`-RequireOffline`。这些开关表达“本场景必须观察到该环境”，未指定不代表观察结果为 false。

如实验室先独立记录人工证据，可改用 `-ManualEvidencePath D:/gpui-lab/win11-150.manual.json`。文件可只列本场景需执行的人工项；公共人工项缺失会保留 `NOT_RUN` 并令该场景失败。`-Headless -ReportOnly` 仅表示无人值守地采集自动基线，仍会短暂显示真实 GPUI 窗口以等待首帧；GPUI 0.2.2 的隐藏 Win32 窗口不会触发首帧回调。该模式必然保留人工 `NOT_RUN`，不能作为发布通过证据。

预录人工证据必须包含本次二进制的 `binary_sha256`（64 位十六进制），采集器会与 `-BinaryPath` 的实际哈希比较；因此旧二进制或另一构建记录的 PASS 不能复用。

人工检查至少记录以下实际观察；证据文本应包含输入、观察结果及截图/录像/hash 路径（若有）：

| ID | 必须实际验证的行为 |
|---|---|
| `d3d11_gpu_driver` | D3D11 renderer 初始化、GPU/驱动无 fallback/崩溃/设备丢失 |
| `custom_titlebar` | 无边框标题栏拖动、最大化、恢复、最小化、关闭 |
| `native_multi_window` | Main、SshTerminal、Sftp、ContainerTerminal 四类窗口的创建、聚焦、关闭 |
| `chinese_ime` | 中文组合、候选窗、提交、退格，在普通输入框与 terminal 中都正确 |
| `clipboard` | Unicode 文本复制/粘贴；terminal bracketed paste 行为正确 |
| `file_dialog` / `folder_dialog` | 原生选择、取消、中文和空格路径 |
| `theme_switch` | light、dark、sakura、incident-canvas 即时切换且跨窗口一致 |
| `virtual_large_table` | 大数据表快速滚动、选择、焦点，无明显卡顿或错误复用 |
| `mixed_dpi` | 窗口跨不同 DPI 显示器后尺寸、文字、命中区域和重绘正确 |
| `rdp` | RDP 连接、重连、剪贴板/IME/窗口渲染路径实际可用 |
| `virtual_machine` | 受测 VM 中启动、交互和 terminal 压力实际通过 |
| `integrated_gpu` | 受测集显及其驱动上 D3D11/多窗/terminal 实际通过 |
| `offline_startup` | 网络已由实验环境外部断开，完整启动且所有字体、图标、帮助和主题可用 |

## 必须覆盖的实验矩阵

基础矩阵要求六个单元各至少一个完整 `PASS` 场景：

| OS | 100% | 150% | 200% |
|---|---:|---:|---:|
| Windows 10 22H2（build 19045） | 必须 | 必须 | 必须 |
| Windows 11（build 22000+） | 必须 | 必须 | 必须 |

此外，同一批、同一二进制 SHA-256 的结果中必须分别存在符合真实环境探针且人工检查为 `PASS` 的 `mixed_dpi`、`rdp`、`virtual_machine`、`integrated_gpu`、`offline_startup` 场景。专项场景可以同时满足一个 OS/DPI 基础单元。

Win10/Win11、各 DPI、RDP、VM、集显或离线环境不在当前机器上时，正确动作是提交带 `NOT_RUN` 的 report-only 结果或不提交该单元，随后由汇总明确失败；禁止复制、改写或将 fixture 当成实验室证据。

## 合并与发布验收

```powershell
$results = Get-ChildItem -LiteralPath D:/gpui-lab/results -Filter '*.json' |
  Where-Object { $_.Name -notlike '*summary*' }

pwsh -NoProfile -File ./scripts/gpui-feasibility-merge.ps1 `
  -ResultPath $results.FullName `
  -SummaryJsonPath D:/gpui-lab/acceptance/summary.json `
  -SummaryMarkdownPath D:/gpui-lab/acceptance/summary.md
```

正常命令在任一场景为 `FAIL`/必需 `NOT_RUN`、六格矩阵不全、专项覆盖缺失、GPUI 不是精确 `0.2.2`、app 版本不同或二进制 SHA-256 不同时返回非零。`-ReportOnly` 只允许生成失败报告，不改变 `acceptance.status=FAILED`。输出默认不可覆盖；只有明确的 `-Force` 才替换两个精确指定的汇总文件。

`fixture: true` 的结果在正式合并中无条件拒绝。`-AllowFixture` 是 `gpui-feasibility-selftest.ps1` 的测试专用开关，任何使用它生成的 summary 都带 `fixture_evidence_allowed: true`，不得进入 release acceptance。

## Harness 自测

```powershell
pwsh -NoProfile -File ./scripts/gpui-feasibility-selftest.ps1
```

自测使用 JSON Schema 2020-12 实际验证 fixture，核对 terminal 与 GPUI 字体 notice，验证完整的合成六格矩阵可通过、缺格矩阵会失败、预期/实测 OS 不一致不能占据矩阵单元，并验证正常合并拒绝 fixture。它还会确认缺失 operator evidence、应用预填人工 PASS、operator SHA 与二进制不一致三类篡改证据都被拒绝。合成结果只写入新的 `target/gpui-feasibility-selftest/<guid>` 目录并保留，不会删除真实证据。
