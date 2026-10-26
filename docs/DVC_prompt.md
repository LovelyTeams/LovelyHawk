# LovelyHawk — Windows RDP Dynamic Virtual Channel 取证模块开发任务

## 一、项目目标

请基于当前 LovelyHawk 项目的现有代码和架构，新增 Windows 远程取证功能，核心通信技术使用 **Remote Desktop Protocol Dynamic Virtual Channel（RDP DVC）**。

目标场景：

- 远程 Windows 仅开放 TCP 3389（RDP）。
- 不依赖 WinRM、SSH、SMB 或额外开放的 TCP 端口。
- 不要求目标系统预先安装常驻 Agent。
- 不需要用户持续通过 RDP 图形界面操作。
- 允许首次通过已授权的 RDP 会话引导运行临时 Collector。
- Collector 启动后，通过 DVC 完成双向通信、任务调度、实时数据返回和证据文件传输。
- 保留 LovelyHawk 现有 Linux SSH 功能，不破坏已有业务逻辑。

**禁止只实现一个独立 Demo。必须评估现有项目结构，并把功能真正集成到 LovelyHawk。**

## 二、技术栈

优先沿用项目现有技术栈：

- 桌面端：Tauri v2 + Rust
- 前端：沿用当前项目框架、组件和 UI 风格
- Windows 原生 API：windows-rs
- RDP DVC：微软官方 DVC COM 接口
- 通信协议：初期使用 JSON + 二进制帧，后续可扩展 Protobuf
- Windows Collector：优先 Rust，遗留系统兼容层可使用 C/C++
- 异步 I/O：根据现有运行时选择 Tokio 或 Windows Overlapped I/O

参考项目：

https://github.com/microsoft/rdp-dvc-plugin-samples

Rust 示例：

https://github.com/microsoft/rdp-dvc-plugin-samples/tree/main/Simple/rust

优先研究微软官方实现，不要凭空设计无法验证的 DVC 接口。

## 三、Windows 版本兼容要求

目标版本：

- Windows 7 SP1
- Windows 8 / 8.1
- Windows 10
- Windows 11
- Windows Server 2008 R2
- Windows Server 2012 / 2012 R2
- Windows Server 2016
- Windows Server 2019
- Windows Server 2022
- Windows Server 2025

要求：

1. 桌面端继续采用最新可用的 Tauri 和 Rust。
2. Windows 10/11 与现代 Windows Server 优先使用 Rust Collector。
3. Windows 7、Server 2008 R2 等老系统采用独立兼容构建，可使用 C/C++ Win32 Collector。
4. 不允许为兼容旧系统而强制整个 LovelyHawk 降级。
5. 所有 Collector 共享统一通信协议和证据数据结构。
6. 通过构建目标及运行时能力检测选择 Collector，不能仅根据系统版本字符串判断。
7. 老系统支持必须以实际运行测试为准，不得把 DVC API 存在直接等同于完整功能可用。
8. 不要求远程 Windows 安装 WebView2、.NET Runtime 或其他大型依赖。

## 四、DVC 客户端实现

优先使用系统自带的 mstsc.exe + 独立 DVC 插件，避免重新实现完整的 RDP 协议。

实现 Rust COM LocalServer 插件，至少包括：

- IWTSPlugin
- IWTSListenerCallback
- IWTSVirtualChannelCallback
- IWTSVirtualChannel

支持：

1. 插件注册和注销。
2. RDP 会话建立后的通道初始化。
3. 双向二进制数据通信。
4. DVC 消息分帧与重组。
5. 多会话隔离。
6. 心跳检测。
7. 错误处理与日志输出。
8. RDP 断线后的通道重建。
9. 与 LovelyHawk Rust 后端通过本地 IPC 交换消息。
10. 同一台客户端同时连接多个 Windows 目标。

创建两条逻辑通道：

**LH_CONTROL**

用于发送取证任务、返回 JSON 结果、查询任务状态、取消任务和心跳检测。

**LH_EVIDENCE**

用于传输 EVTX、注册表 Hive、文件系统证据和其他二进制数据。

通道建立由双方协商，控制与文件传输必须相互隔离。禁止将 GB 级文件作为单个内存消息处理。

插件必须具有明确的注册、加载、卸载和清理流程，并验证 mstsc.exe 对插件的实际支持情况。

## 五、Windows Collector 实现

开发独立的 LovelyHawkCollector.exe。

Collector 应满足：

- 无 GUI。
- 不需要长期安装。
- 不自动注册系统服务。
- 尽量减少第三方依赖。
- 支持普通权限和管理员权限分级运行。
- 可在交互式 RDP 会话中启动。
- 使用 WTSVirtualChannelOpenEx 打开 DVC。
- 支持 WTS_CURRENT_SESSION。
- 正确处理 WTSVirtualChannelRead、WTSVirtualChannelWrite 和通道关闭。
- 支持连接超时、重试、心跳及断线状态恢复。

Collector 需要实现通用任务接口：

```json
{
  "version": 1,
  "request_id": "req-001",
  "action": "collect.processes",
  "parameters": {},
  "timeout_ms": 30000
}
```

第一阶段至少实现：

- collect.system_info
- collect.processes
- collect.network_connections
- collect.services
- collect.scheduled_tasks
- collect.autoruns
- collect.event_logs
- collect.registry
- collect.logged_on_users

后续预留：

- collect.ntfs_mft
- collect.usn_journal
- collect.prefetch
- collect.amcache
- collect.memory

这些操作必须通过白名单任务接口调用，不允许把任意 Shell 命令执行作为默认的 DVC 控制能力。

所有采集模块独立封装，失败时返回明确的权限、API 或系统兼容性错误。

## 六、首次启动引导

DVC 不具备独立执行远程程序的能力，因此必须设计 Collector Bootstrap 机制。

按优先级研究：

**方式 A：RDP Initial Program**

验证远程会话配置是否允许通过 Initial Program 启动指定采集器，并处理重定向资源尚未准备好的情况。

**方式 B：RDP 文件夹重定向 + 一次性启动**

通过授权的 RDP 会话映射 LovelyHawk 专用目录，在目标桌面会话就绪后，使用有限的键盘自动化启动签名的 Collector。

**方式 C：人工辅助启动**

前两种不可用时，引导用户在可见 RDP 窗口中手动启动一次 Collector。

不得绕过 UAC、WDAC、AppLocker、EDR 或组策略限制。

如果管理员权限采集器无法访问当前 RDP 用户的重定向目录，应将本机证据采集和会话用户身份下的文件传输分离。

## 七、通信协议设计

建立独立的协议模块，支持：

- HELLO / HELLO_ACK
- AUTH / AUTH_ACK
- TASK_REQUEST
- TASK_RESPONSE
- TASK_PROGRESS
- TASK_CANCEL
- ERROR
- HEARTBEAT
- FILE_BEGIN
- FILE_CHUNK
- FILE_ACK
- FILE_END
- RESUME_REQUEST

必须具备：

1. 协议版本协商。
2. 会话及请求唯一 ID。
3. 应用层任务认证与会话绑定。
4. 长度前缀、消息大小上限及输入校验。
5. 大文件分块传输。
6. 块序号和偏移量验证。
7. SHA-256 完整性校验。
8. 断点续传与重传。
9. 传输限速及背压控制。
10. 消息超时、取消与错误码。
11. 应用日志脱敏。

不得将 RDP 已完成身份认证视为任意 Collector 指令都天然可信。跨会话消息必须隔离，避免把一个 RDP 会话的证据发给另一个连接。

## 八、证据固定和安全要求

所有采集活动必须产生审计记录。

至少保存：

- 目标主机信息
- RDP 会话标识
- Collector 版本及程序哈希
- 采集开始与结束时间
- 采集任务参数
- 原始证据来源路径
- 原始文件大小及 SHA-256
- 传输后的 SHA-256
- 采集错误及未完成项目
- 采集行为可能引入的系统变化

证据暂存目录必须限制访问权限。

不保存明文 RDP 密码，不关闭系统审计，不修改防火墙策略，不通过隐藏持久化机制维持 Collector。

仅在用户明确授权的主机和证据范围内执行任务。

## 九、集成 LovelyHawk 现有界面

保留现有 Linux 模块与操作方式，新增 Windows 系统适配层。

统一抽象：

- ConnectionProvider
- EvidenceCollector
- TaskDispatcher
- EvidenceTransport
- ForensicParser

目标效果：

用户通过 RDP 连接 Windows 后，可以直接点击 LovelyHawk 现有的：

- 系统信息
- 进程详情
- 网络详情
- 服务详情
- 持久化检查
- 日志分析
- 案件工作台

由后端自动选择对应 Windows Collector 任务并返回结果。

对于 Windows 不支持的 Linux 特有功能，明确显示“不适用”，不能返回虚假的空结果或错误的正常状态。

前端展示连接状态、Collector 状态、权限等级、任务进度、证据传输速度和失败原因。

## 十、实施步骤

请按以下顺序执行，逐阶段验证：

**阶段 1：项目分析**

检查现有 LovelyHawk 的目录结构、连接管理、Rust 命令接口、状态管理和证据模块，提出最小侵入式改造方案。

**阶段 2：DVC 通信验证**

基于微软 Rust 示例，实现 mstsc 客户端插件与远程 Collector 之间的 Ping/Pong，完成双向 JSON 数据传输。

**阶段 3：Bootstrap**

实现首次 Collector 启动引导，验证 RDP 专用目录映射、启动成功率和失败回退。

**阶段 4：基础 Windows 取证**

接入系统信息、进程、网络、服务、启动项和事件日志。

**阶段 5：证据传输**

实现证据文件分块传输、哈希校验、断线恢复和文件回收。

**阶段 6：多版本适配**

建立 Windows 7 至 Windows 11、Server 2008 R2 至 Server 2025 的测试矩阵，记录各平台能力差异。

**阶段 7：现有 UI 集成**

统一 Linux SSH 和 Windows RDP 的连接体验，完成案件工作台证据导入。

## 十一、验收标准

必须至少完成以下验证：

1. Windows 仅开放 3389 时可完成 RDP 登录和 DVC 建立。
2. Collector 经授权启动后可接收任务并返回真实进程数据。
3. 不依赖 WinRM、SSH、SMB 或额外开放服务端口。
4. 能传输 100 MB 文件并通过 SHA-256 校验。
5. 支持 RDP 断开后重新建立通道。
6. 可以检测 Collector 无法启动、权限不足、策略阻止等状态。
7. Linux SSH 原有功能不受影响。
8. 所有新增模块能够实际编译，运行测试和自动化测试通过。
9. 对未测试的旧版 Windows 明确标为未验证。
10. 不使用模拟数据冒充真实采集结果。

## 十二、最终交付要求

请直接在现有项目中进行开发，交付：

- 完整 Rust DVC 客户端插件源码。
- Windows Collector 源码。
- 通信协议模块。
- LovelyHawk 连接管理集成。
- Windows 基础取证模块。
- Collector 引导模块。
- 编译和部署脚本。
- 版本兼容性说明。
- 实际验证结果与已知限制。

**不要一次性凭空实现所有模块。先检查项目，再建立最小可运行闭环，完成一次真实 RDP DVC 通信，确认可行后逐步扩展。**

对于无法确认的 Windows API、RDP 插件接口或系统行为，应优先验证微软官方文档和示例源码，不允许编造不存在的 API。

最终目标是让 LovelyHawk 成为同时支持 Linux SSH 与 Windows RDP DVC 的统一远程主机取证平台。
