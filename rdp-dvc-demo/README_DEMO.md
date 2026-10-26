# RDP DVC Python Demo 验证步骤

来源：`microsoft/rdp-dvc-plugin-samples` 的 `Simple/python` 示例（win32more 实现 COM LocalServer），协议为 ping/echo：服务端每秒发 5120 字节 ping，客户端插件原样回显，服务端测 RTT。

本目录相对官方示例只多了两个文件：

- `client_host.py` — 让 COM 能直接用 `python.exe <脚本> -Embedding` 拉起插件的宿主入口
- `register_dev.py` — 修复官方注册器的缺陷：官方 `/register` 会把 `LocalServer32` 写成 `"python.exe" -Embedding`（不带脚本/模块，插件不会被加载）；本脚本写入完整命令行

## 前置条件

- 客户端机（发起 mstsc 的机器）：Windows + Python 3.12+，`pip install -r requirements.txt`（即 `win32more`）
- 服务端机（被 RDP 连接的机器）：需要能被 RDP 连接的 Windows（Pro/Server，Home 不行）；同样装 Python + win32more
- 没有第二台机器时，可在支持环回 RDP 的版本上 `mstsc /v localhost` 自连验证

## 步骤

### 1. 客户端机：注册插件（HKCU，无需管理员）

```powershell
cd D:\LovelyRes\rdp-dvc-demo
python register_dev.py
```

### 2. 客户端机：手动跑起插件进程（便于看日志）

```powershell
python client_host.py
```

看到 `Class factory registered` 和 `Entering message loop` 即正常，保持窗口开着。

### 3. 服务端机：在 RDP 会话内启动服务端

把本目录拷到服务端机器，在 **RDP 会话里** 执行：

```powershell
python -m rdp_simple_plugin_server
```

注意必须已经是 RDP 会话（先连上再跑）。不在会话内会报 `WTSVirtualChannelOpenEx failed: 1722`。

### 4. 建立 RDP 连接

客户端机 `mstsc /v <服务端>` 连接（如果服务端程序已在会话里跑着，断开重连一次也会重建通道）。

### 5. 预期现象

- 客户端窗口：`Initialize` → `CreateListener` → `OnNewChannelConnection` → 每秒 `OnDataReceived` + `Echoed xxxx bytes`
- 服务端窗口：每个 ping 的 RTT 日志

## 自定义 demo：双向聊天（demo_client_host.py / demo_server.py）

在原 ping/echo 基础上加的自定义协议 demo：两端都能主动发消息。

- 通道名：`dvc::demo::chat`（和 ping 示例不同，互不干扰）
- 协议：`[u32 len][JSON]`，JSON 为 `{"from","seq","text"}`
- `demo_protocol.py` 含流式重组（DVC 是字节流，一次 Write 可能分多次到达）

用法：

1. 客户端机（本目录）：`python demo_client_host.py`，等 `Class factory registered`
2. mstsc 连接服务端 → 客户端窗口出现 `Initialize` / `CreateListener`
3. 服务端 RDP 会话里：`python demo_server.py` → 客户端出现 `OnNewChannelConnection`
4. 之后两边窗口打字回车即互发，消息以 `<-`（收）/ `->`（发）打印
5. 输入 `/cmd <命令>` 让**对端**执行 shell 命令，输出以 `result` 消息回传（30s 超时，输出截断到 8000 字符）

协议字段：`type` = `chat`（聊天）/ `cmd`（命令请求）/ `result`（命令输出）

服务端机器需要的文件：`demo_server.py`、`demo_protocol.py`、`rdp_simple_plugin_server/`（用到其中的 `dvc_reassembler.py`）+ `pip install win32more`。Python 3.11 可跑（`ping_message_codec.py` 的 `Buffer` 已做兼容，本 demo 不依赖它）。

## 卸载

```powershell
python register_dev.py --unregister
```

## 排错速查

- mstsc 连接后客户端窗口没有任何 `Initialize` 输出 → 检查注册表 `HKCU\Software\Microsoft\Terminal Server Client\Default\AddIns\SimpleRdpPlugin` 是否存在；确认 `client_host.py` 是在连接前启动的
- SCM 自动拉起模式下日志不可见，验证阶段建议先手动跑 `client_host.py`
- 服务端 `1722` 错误 = 不在 RDP 会话内
