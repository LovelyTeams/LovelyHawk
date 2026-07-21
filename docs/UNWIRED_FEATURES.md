# 已实现但未接线的功能清单

本仓库反复出现同一类问题：功能写完了，UI 入口却没接上（或在重构中被顺手删掉），
于是代码一直躺在仓库里，既不产生价值也没人敢删。最严重的一次是**整个快速检测子系统**
——约 6000 行前端 + 37 个 Rust command 在 commit `04f6819` 的侧边栏重构中丢了入口，
三个月无人发现（已于本轮修复）。

这份清单就是为了不再发生这种事。**新增功能后如果暂时不接 UI，请登记在这里。**

> 判断标准：`grep -rn "<模块名>" src --include=*.ts --include=*.vue` 只匹配到它自己，
> 即为未接线。

---

## 前端模块

| 模块 | 规模 | 是什么 | 接线还缺什么 |
|---|---|---|---|
| `src/modules/detection/complianceRules.ts` | 217 行 | 等保 2.0 / CIS Benchmark 合规检查框架，把检测项 ID 映射到合规条款 | 已有 `detectionItemId` 字段对接 `quickDetectionManager`。缺一个合规视图（按标准分组展示达标情况）与导出。快速检测已于本轮恢复，可以接了 |
| `src/modules/ui/kubernetesContextMenu.ts` | 375 行 | K8s 资源右键菜单，已 `extends BaseContextMenu` 并导出单例 | K8s 页面当前完全没有右键菜单。参照 `tableUpdateManager` 里其他表格的 `addContextMenuListener` 用法接入 `kubernetesRenderer` 的 Pod/Deployment 表格 |
| `src/modules/sftp/sftpEnhanced.ts` | 249 行 | 远程文件搜索、批量操作进度追踪 | 与现有 `remote/sftpManager.ts` 的职责边界需要先厘清（是增强还是重复实现），再决定合并还是接独立入口 |
| `src/modules/ai/commandExplainer.ts` | 146 行 | 对应急命令给 AI 自然语言解释，带本地缓存 | 缺调用点。适合接在命令执行页/右键菜单的「解释这条命令」。注意赛场离线时 AI 不可用，需要降级（参考 `aiService.toFriendlyError`） |
| `src/modules/monitoring/liveMonitor.ts` | 206 行 | CPU/内存/磁盘/网络定时轮询 + 数据缓存，通过 eventBus 广播 | 原本唯一的消费方 `composables/useManagers.ts` 已随本轮清理删除（Vue composable，但本项目不是 Vue 架构）。**接线前先确认**它与系统信息页现有的「实时状态」Tab 是否重复 |
| `src/modules/utils/listenerManager.ts` | 155 行 | `ListenerScope`：统一管理 addEventListener / setInterval 的生命周期 | 全项目 198 处 addEventListener 对 19 处 removeEventListener。目前靠各页面管理器的 `eventsBound` 标志 + `outerHTML` 整体替换兜底，尚未出现实际泄漏。要推广的话建议从模态框和右键菜单开始 |

## 后端命令（已在 `lib.rs` 的 `invoke_handler!` 注册，前端零调用）

| 命令 | 说明 |
|---|---|
| `get_app_settings` / `save_app_settings` | 结构化的设置读写 API。前端目前走 `read_settings_file` / `write_settings_file` + localStorage，绕过了这对命令 |
| `get_rsa_public_key` | `crypto_keys.rs` 整个模块闲置。而 AI 的 API Key 目前是明文存 localStorage，这是可以配上的 |
| `db_get_stats` | `db_manager.rs:850` 已实现，数据库页没有入口 |
| `get_log_file_info` | 日志页未使用 |
| `sftp_file_analysis` | 前端只用 `sftp_file_analysis_independent` 变体，此命令冗余，可考虑删除 |
| `get_command_completion` | 本轮 Tab 补全选用了功能更全的 `ssh_get_completion`（同时补路径）。此命令只做 `compgen -c`，保留作备选 |

---

## 本轮（2026-07）已接线的

作为参照，以下几项此前也在本清单同类状态，现已接上：

- `server/batchServerManager.ts` → 新增「多机批量」页（`server/batchServerPageManager.ts`）
- `ssh_get_completion` → 终端 Tab 补全（`remote/terminalManager.ts`）
- `test_ssh_performance` / `diagnose_shell_performance` → 设置 → 工具 → 连接诊断
- 快速检测全子系统 → 恢复侧边栏入口与 `renderWorkspaceContent` 分支

## 本轮已删除的（确认为被取代，非未接线）

- `src/css/base.css`（3461 行）——被模块化的 `src/css/base/` 目录取代
- `src/styles/sftp-context-menu.css`（90 行）——被 `css/components/` 下的样式取代
- `src/modules/composables/useManagers.ts`（148 行）——Vue composable，但本项目 95% 是手写 DOM
- `src/components/IconParkIcon.vue`（106 行）——被 `ui/iconMapping.ts` 取代
- `src/modules/utils/uiHelpers.ts`（70 行）——其自述目标（取代 `window.showNotification?.()`）
  已由 `ui/notificationManager.ts` + `utils/errorHandler.ts` 达成
- 空目录 `src/modules/{api,auth,crypto,user}`——已移除的授权系统残留
