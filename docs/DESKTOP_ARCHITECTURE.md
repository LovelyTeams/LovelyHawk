# LovelyHawk 桌面架构（Tauri 2）

本文说明 Tauri 2 桌面端的进程、窗口、权限与生命周期约定。Electron 时期的迁移记录与发布说明已移到 [legacy/](legacy/)，只作历史参考，不能当作当前外壳的证据。各条目的验收状态以 [DESKTOP_UI_LEDGER.json](DESKTOP_UI_LEDGER.json) 为准。

## 组成

| 部分 | 位置 | 职责 |
| --- | --- | --- |
| 宿主 | `crates/lovelyhawk-desktop/` | 进程入口、窗口创建与加固、按窗口授权的命令、本机对话框/剪贴板/导出、子窗口与目标绑定、关闭握手、单实例 |
| 后端方法表 | `crates/lovelyhawk-backend/` | 有限、版本化的方法表（`lovelyhawk-backend/v1`），组合 core 服务并持有敏感状态；宿主进程内调用，另保留 stdio 入口供实验室探针使用 |
| 核心服务 | `crates/lovelyhawk-core/` | SSH/SFTP、目标身份与代次、计划、凭据、审计、验证、恢复、便携存储 |
| 终端模型 | `crates/lovelyhawk-terminal/` | headless 终端、传输、输入、搜索、背压与取消 |
| 页面 | `ui/src/renderer/` | React 页面与浮层；只通过 `window.lovelyhawk*` 三个冻结对象与宿主交互 |
| 页面桥 | `ui/src/host/` | 把固定命令包装成冻结、强类型的 API；用 `ui/src/shared/` 的契约校验每个请求与响应 |

一个进程、一个可执行文件：页面资源在编译时嵌入，后端直接链接进宿主。Windows 上由系统 WebView2 Runtime 渲染页面，WebView2 自身的辅助进程由宿主退出时一并结束。

## 页面与宿主的边界

- 页面没有 Node、没有全局 Tauri 对象（`withGlobalTauri: false`），也没有任何插件权限。`@tauri-apps/api` 只在 `ui/src/host` 中使用。
- `ui/src/host/install.ts` 在首次渲染前把 API 定义为不可写、不可配置的全局属性：主窗口是 `window.lovelyhawk` 与 `window.lovelyhawkWindow`，终端类窗口是 `window.lovelyhawkTerminal` 与 `window.lovelyhawkWindow`。
- 宿主命令登记在 `build.rs` 的 `COMMANDS` 中，每个命令都成为必须由 capability 文件授予的权限：
  - `capabilities/main-window.json` 只授予窗口标签为 `main` 的主窗口，包括 `backend_call`、导出与导入、剪贴板、主题、打开子窗口与关闭决定；
  - `capabilities/child-windows.json` 只授予 `child-*` 子窗口，包括终端、SFTP、本机文件栏与文件编辑器命令。
- `backend_call` 只接受 `backend_bridge.rs` 中 `MAIN_WINDOW_METHODS` 白名单里的方法。带本机路径或返回导出内容的方法（如案件库导出、文件留证开始）不能从页面调用，必须走对应宿主命令，由宿主打开系统对话框、在 Rust 中写文件。页面拿不到本机绝对路径。
- 子窗口命令从不接收目标身份。宿主按窗口标签在子窗口登记表中查找它创建时绑定的目标与代次，每次调用前都核对绑定仍然有效。
- 导出命令只创建新文件（`create_new` + `sync_all`），不覆盖已有文件。导出内容在宿主中用会清零的类型保存。

## 后端调用

`BackendState::call(method, params)` 与 stdio 协议共用同一张方法表、同一套参数解析、错误码和大小上限。宿主中的 `BackendBridge` 把调用分成三条通道：终端窗口的 shell（`terminal.*` 与容器终端打开）、终端窗口的文件管理（`sftp-browser.*`）、其余全部。每条通道内按到达顺序逐个执行，通道之间互不等待，所以主窗口一次 30 秒的检查不会再卡住终端的按键和输出（`ui/scripts/probe-terminal-during-long-task.mjs`）。终端与文件接口在每次等待之后都重新核对连接与目标，主窗口在此期间断开连接时，它们以“连接已断开”结束，不会交回过期结果。每次调用都在独立任务中运行，调用方超时或窗口关闭不会把一个执行到一半的远端操作取消掉。

由此带来的限制：长时间运行的后端调用会让后续调用排队，包括终端窗口的输出轮询。见 [OPEN_ITEMS.md](OPEN_ITEMS.md)。

## 窗口

| 窗口 | 标签 | 页面 | 说明 |
| --- | --- | --- | --- |
| 主窗口 | `main` | `index.html` | 欢迎页、侧栏导航、各工作页与浮层 |
| SSH 终端 | `child-N` | `terminal.html` | 绑定打开时的目标与代次；同一目标重复打开时复用窗口 |
| 容器终端 | `child-N` | `terminal.html` | 绑定目标与 core 校验过的容器身份 |
| 文件编辑 | `child-N` | `terminal.html` | 绑定目标与 SFTP 文件；保存经过 SFTP 计划、确认与执行 |

- 所有窗口都没有系统边框（`decorations(false)`），标题栏由页面绘制，使用 `data-tauri-drag-region="deep"` 拖动；最小化、最大化与关闭按钮通过 `window.lovelyhawkWindow` 调用。
- 主题在窗口首帧前设置：宿主按 `theme.rs` 的原生配色表设置窗口底色，并在页面脚本运行前注入主题与目标标签。`theme.test.ts` 检查这张表与 `themes.css`、`theme-contract.ts` 完全一致。
- 创建窗口的命令必须是 `async`：在 Windows 上，同步命令里创建窗口会死锁。源码门禁会检查这一点。

## 加固

每个窗口在创建时调用 `host.rs` 的 `harden()`：

- 使用无痕会话与可执行文件旁 `data/webview2` 作为 WebView2 数据目录；关闭拖放路径与自动填充；
- 只允许导航到本窗口的固定页面（`Page::allows`），拒绝新窗口、下载与权限请求；
- 页面来源为 `https://tauri.localhost`。`tauri.conf.json` 给出整体 CSP，每个页面另有更严格的 meta CSP：主窗口不允许内联样式，终端页只为 xterm 的动态样式放开 `style-src 'unsafe-inline'`，脚本始终只允许 `'self'`；
- `ui/src/host/window-chrome.ts` 的 `hardenPage` 屏蔽浏览器自带快捷键、右键菜单、鼠标侧键导航与拖放，只在冒泡阶段拦截，因此 xterm 仍能收到 Ctrl+R、Ctrl+U、Ctrl+W 等终端按键。

## 目标绑定与子窗口回收

`binding_state.rs` 跟踪 SSH 连接尝试与已接受的绑定：

- 页面开始连接时记下待定尝试；查询尝试状态、主机密钥与 MFA 时，宿主核对尝试仍是当前这一次，否则返回过期错误；
- 绑定变化或断开连接时，宿主先关闭属于旧绑定的全部子窗口，再把断开请求交给后端；
- 子窗口关闭时释放对应的终端、SFTP 与编辑会话。

迟到的结果由 core 的目标代次拒绝；宿主这一层只保证窗口与绑定一一对应。

## 关闭与退出

1. 主窗口收到关闭请求时，宿主阻止关闭，并向页面发送带编号的 `lovelyhawk://before-close`，其中带上有未保存修改的文件编辑窗口数量。
2. 页面检查脏编辑与进行中的任务（包括这些编辑窗口），必要时用应用内对话框询问，再带着同一编号调用 `close_decision`。
3. 页面 15 秒内没有回应时，窗口保持打开，下一次点击关闭会重新询问。在那之前，迟到的回答仍然有效：在“未保存修改”对话框上考虑得久一些，不会让选择失效。新的关闭请求发出后，旧请求的回答不再生效；每个请求只接受一次回答。
4. 主窗口销毁后，宿主关闭全部子窗口并退出；退出时最多等待 3 秒，让后端收尾。
5. 文件编辑窗口有未保存修改时会告诉宿主（`file_editor_unsaved`）。此时来自页面以外的关闭（Alt+F4、任务栏）同样被拦下，宿主按上面的编号规则问这个窗口，窗口用 `child_close_decision` 回答。断开连接、连接新目标会回收这个连接的子窗口，主窗口在此之前用 `unsaved_editor_count` 查询并先确认。

## 数据与单实例

- 运行数据写入可执行文件旁的 `data/`，WebView2 数据在 `data/webview2/`。不使用浏览器持久化，也不回退到用户配置目录。
- 单实例锁是 `data/.lovelyhawk-instance.lock`，按数据目录区分：同一份数据目录同时只能运行一个程序，另一份解压目录可以独立运行。
- 调试构建把数据写到仓库根目录的 `data/`，可以用 `LOVELYHAWK_ARCHIVE_ROOT` 指向别处。

## 仅调试构建可用的能力

以下能力都在 `#[cfg(debug_assertions)]` 之下，release 可执行文件中不包含这些变量名，便携包校验器会检查这一点：

| 变量 | 作用 |
| --- | --- |
| `LOVELYHAWK_ARCHIVE_ROOT` | 改变数据根目录，自动化用它与正在使用的应用隔离 |
| `LOVELYHAWK_DEBUG_PORT` | 开放 WebView2 远程调试端口，供 CDP 自动化连接 |
| `LOVELYHAWK_TEST_DIALOG_ANSWERS` | 按顺序给出系统对话框的回答，用于导出/导入自动化 |
| `LOVELYHAWK_TEST_CLIPBOARD_FILE` | 把剪贴板写入重定向到文件，避免自动化改动系统剪贴板 |

`LOVELYHAWK_DEBUG=1` 在 release 中打开 DevTools，用于临时排障。便携冒烟使用 `LOVELYHAWK_SMOKE_READY_ROOT` 与 `LOVELYHAWK_SMOKE_READY_NONCE`：宿主只把就绪标记写到系统临时目录下名称格式固定的目录中。

## 旧标识

产品名、界面文字与本机环境变量使用 LovelyHawk。已经写在本机或目标主机上的格式与托管标识保留 `lovelyres` 前缀，以便读取旧数据、识别旧备份并清理旧版本创建的对象，例如 `.lovelyres-backups`、各种 `lovelyres-*/vN` schema 与目标侧的 `LOVELYRES_*` 输出标记。改名不能导致旧证据、旧备份或旧计划无法识别。

## 验证

| 层 | 命令 | 覆盖 |
| --- | --- | --- |
| 宿主 | `cargo test --locked --package lovelyhawk-desktop` | 方法白名单、绑定状态机、子窗口登记、本机目录浏览、导出写入、主题表 |
| 后端 | `cargo test --locked --package lovelyhawk-backend` | 方法表、参数与响应边界、进程内调用 |
| 页面 | `pnpm ui:check` | 类型检查、单元测试（含 `ui/src/host` 的请求/响应校验）与构建 |
| 桌面冒烟 | `pnpm desktop:test:debug` | 真实调试构建 + WebView2 CDP：逐页、逐浮层、明暗主题、全局 API 形态与截图 |
| 终端场景 | `node ui/scripts/probe-terminal-window.mjs` | 实验室靶机：连接、终端子窗口、输入回显、文件编辑窗口与未保存修改的询问、复用、断开即回收 |
| 关闭握手 | `node ui/scripts/probe-close-handshake.mjs` | 未保存设置时关闭主窗口：询问出现，超过 15 秒后回答仍然有效 |
| 编辑窗口关闭握手 | `node ui/scripts/probe-editor-close.mjs` | 有未保存修改的编辑窗口：页面外关闭、主窗口关闭、连接新目标、断开连接都先询问；没有修改时直接关闭 |
| 长命令期间的终端 | `node ui/scripts/probe-terminal-during-long-task.mjs` | 主窗口命令卡满 30 秒期间，终端回显与文件列表刷新不受影响 |
| Docker 与容器终端 | `node ui/scripts/probe-docker.mjs` | 容器编排靶机 svc-docker：清单、审计、详情、日志、启停复核与回滚、每个容器一个终端窗口、关窗结束容器内遗留命令 |
| 安全速查 | `node ui/scripts/probe-security-reference.mjs` | 目录完整、搜索与筛选、展开为纯文本、经宿主复制、收藏跨重启保留、可访问名称 |
| 笔记 | `node ui/scripts/probe-notes.mjs` | 空状态、恶意标记按纯文本、标签上限的错误状态、置顶、导出、删除确认与结果提示、离开页面自动保存、跨重启保留 |
| 连接管理 | `node ui/scripts/probe-connections.mjs` | 新建、搜索、导出（取消 / 不含秘密 / 不覆盖）、删除确认、导入（重复提示、四类坏文件整体拒绝）、跨重启保留 |
| 应用日志 | `node ui/scripts/probe-application-log.mjs` | 有界记录、级别筛选与采集级别、复制、导出（取消 / 写入 / 不覆盖）、清空、Escape 与焦点返回、口令不入日志 |
| 确认对话框 | `node ui/scripts/probe-dialogs.mjs` | 初始焦点在“取消”、Tab / Shift+Tab 只在对话框内循环、背后内容不可操作、Escape 与在“取消”上按回车都退出并返回焦点 |
| 通知 | `node ui/scripts/probe-notifications.mjs` | 有浮层时暂缓显示、关闭后出现并礼貌播报、约 3 秒自动消失、手动关闭、重复事件只续期一条 |
| 设置 | `node ui/scripts/probe-settings.mjs` | 取消不留痕、越界值拒绝保存、各分组保存并立即生效、API Key 只写且不落明文、清除需单独确认、焦点返回、跨重启保留 |
| 无障碍与资源 | `node ui/scripts/probe-accessibility.mjs`（加 `LAB=ubuntu` 再连接靶机巡检一遍） | 用浏览器自身的无障碍树检查每个页面与浮层：每个可操作控件都有能读出的名称（只有符号不算），图标与资源都来自程序本身 |
| 主机全景（靶机） | `LAB=ubuntu node ui/scripts/probe-system-info.mjs` | 摘要数字、每个标签页有数据或说明原因、刷新、复制表格、预置的恶意命名进程按纯文本显示、断开后不留旧数据 |

连接文件损坏时程序仍可启动：欢迎页和连接管理都会说明“连接文件读不出来”，而不是显示为空列表；程序不会改动这个文件，其他不需要连接的工具照常可用（`probe-connections.mjs` 的第三次启动）。

后端错误码在 `ui/src/host/error-messages.ts` 中换成面向操作员的中文句子，末尾保留错误码，供页面判断与排障使用。`error-messages.test.ts` 会从后端源码中找出所有仍以英文回答的错误码，缺少译文时测试失败。
| 门禁 | `pnpm release:quality-gate` | 源码、依赖、账本门禁与以上检查 |
| 便携包 | `pnpm release:package -Build`、`pnpm release:smoke` | 见 [DESKTOP_PORTABLE_RELEASE.md](DESKTOP_PORTABLE_RELEASE.md) |
