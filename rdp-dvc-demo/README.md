---
languages:
- python
products:
- windows
description: "Minimal RDP Dynamic Virtual Channel (DVC) plugin sample using Python with COM LocalServer activation and a ping/echo protocol."
urlFragment: rdp-dvc-simple-plugin-python
page_type: sample
name: "RDP DVC simple plugin – Python"
---

# RDP DVC Simple Plugin - Python Implementation

The Python Simple implementation demonstrates a complete RDP DVC plugin system using the `win32more` package for COM and WTS APIs:
- **Client Plugin**: Out-of-process COM LocalServer implemented in Python using `win32more` for COM interface implementation and registry management
- **Server Application**: Server-side DVC host running inside RDP sessions, with WTS API (synchronous) and File Handle (async overlapped) I/O modes
- **Shared Protocol**: A minimal binary ping/echo protocol, wire-compatible with all other Simple samples

The server sends ping messages with a 5120-byte payload every second. The client plugin echoes them back. The server measures and logs round-trip time (RTT) for each ping.

## Quick Facts

- Channel: `dvc::sample::simpleplugin`
- CLSID: `{D9B80669-C06A-4BD1-9CB1-3B7168C9E3A3}`
- Client output: `bin/<Platform>/<Configuration>/rdp-simple-plugin-client-python.exe`
- Server output: `bin/<Platform>/<Configuration>/rdp-simple-plugin-server-python.exe`
- Register: client EXE `/register` (per-user); add `/machine` for machine-wide; `/unregister` to remove; also supports `python -m rdp_simple_plugin_client`
- Server modes: WTS API (default) or `--filehandle`
- Interop: protocol compatible with all other Simple implementations

## Contents

| File/folder | Description |
|---|---|
| [`rdp_simple_plugin_protocol/`](https://github.com/microsoft/rdp-dvc-plugin-samples/tree/main/Simple/python/rdp_simple_plugin_protocol) | Protocol definitions (Python package). |
| [`rdp_simple_plugin_client/`](https://github.com/microsoft/rdp-dvc-plugin-samples/tree/main/Simple/python/rdp_simple_plugin_client) | Client-side DVC plugin (COM LocalServer). |
| [`rdp_simple_plugin_server/`](https://github.com/microsoft/rdp-dvc-plugin-samples/tree/main/Simple/python/rdp_simple_plugin_server) | Server-side application. |
| [`pyproject.toml`](https://github.com/microsoft/rdp-dvc-plugin-samples/blob/main/Simple/python/pyproject.toml) | Project metadata and build config. |
| [`requirements.txt`](https://github.com/microsoft/rdp-dvc-plugin-samples/blob/main/Simple/python/requirements.txt) | Python dependencies. |
| [`build.ps1`](https://github.com/microsoft/rdp-dvc-plugin-samples/blob/main/Simple/python/build.ps1) | PowerShell build script. |
| [`README.md`](https://github.com/microsoft/rdp-dvc-plugin-samples/blob/main/Simple/python/README.md) | This README file. |

## Key Implementation Details

### COM Implementation via win32more

The client plugin uses `win32more` to implement COM interfaces in Python:
- `simple_plugin.py` subclasses `IWTSPlugin`, `IWTSListenerCallback`, and `IWTSVirtualChannelCallback` from `win32more`
- `win32more` handles vtable layout and COM marshaling automatically
- `registry_helper.py` writes `LocalServer32` and AddIns registry entries using `winreg`

### Server I/O Modes

**WTS API Mode (Default):**
- Synchronous reads via `WTSVirtualChannelRead` (ctypes)
- Single-threaded send-receive loop
- Simpler implementation; good for testing

**File Handle Mode (`--filehandle`):**
- Asynchronous overlapped I/O using Windows `ReadFile`/`WriteFile` with OVERLAPPED via ctypes
- `DvcReassembler` in `dvc_reassembler.py` handles PDU fragment reassembly

### Running as a Module vs Executable

The client and server can be run either as standalone executables (built with PyInstaller) or directly as Python modules:
```powershell
# As executable (after build):
.\bin\x64\Debug\rdp-simple-plugin-client-python.exe /register

# As Python module (development):
python -m rdp_simple_plugin_client /register
python -m rdp_simple_plugin_server
```

## Wire Protocol

Messages use a simple binary format (little-endian):

```
Frame: [frameLen:u32][sequenceNumber:u32][utcTicks:i64][payloadLen:u32][payload...]

Where:
- frameLen: Total size of the message (excluding this field)
- sequenceNumber: Incrementing sequence number for tracking
- utcTicks: UTC timestamp in 100ns ticks (Windows FILETIME)
- payloadLen: Size of the payload in bytes
- payload: Deterministic test pattern (0..255 repeating)
```

### PDU Fragmentation

The default payload size is **5120 bytes**, which exceeds the typical RDP channel chunk size (~1600 bytes). This demonstrates PDU fragmentation and reassembly:

- Large messages are automatically fragmented by the RDP stack
- Fragments are marked with `CHANNEL_FLAG_FIRST` and `CHANNEL_FLAG_LAST` flags
- The `DvcReassembler` class handles reassembly for file-handle mode
- WTS API mode (`WTSVirtualChannelRead`) handles reassembly automatically

See [CHANNEL_PDU_HEADER](https://learn.microsoft.com/en-us/windows/win32/api/pchannel/ns-pchannel-channel_pdu_header) for details on the fragmentation protocol.

## Architecture

### Client Plugin Flow

```
RDP Client
    │
    ├─> Reads AddIns registry for plugin CLSID {D9B80669-C06A-4BD1-9CB1-3B7168C9E3A3}
    │       └─> HKCU\Software\Microsoft\Terminal Server Client\Default\AddIns\SimpleRdpPlugin\Name
    │
    ├─> Calls CoCreateInstance with CLSID
    │       └─> COM looks up LocalServer32 registry path
    │           └─> HKCU\Software\Classes\CLSID\{...}\LocalServer32
    │
    ├─> COM SCM either:
    │       ├─> Connects to existing rdp-simple-plugin-client-python.exe process, OR
    │       └─> Launches new process with registered executable path
    │
    ├─> Process registers IClassFactory via CoRegisterClassObject (win32more)
    │
    ├─> COM calls IClassFactory::CreateInstance → returns IWTSPlugin
    │
    ├─> RDP client calls IWTSPlugin::Initialize
    │       └─> CreateListener("dvc::sample::simpleplugin")
    │
    ├─> Server opens channel from remote session
    │
    ├─> IWTSListenerCallback::OnNewChannelConnection
    │       └─> Creates per-channel callback instance
    │
    ├─> Server sends data via DVC
    │
    ├─> IWTSVirtualChannelCallback::OnDataReceived
    │       └─> Parse framed ping message
    │           └─> Echo all bytes back via IWTSVirtualChannel::Write
    │
    └─> IWTSPlugin::Terminated → cleanup
```

### Server Application Flow

```
RDP Session (remote machine)
    │
    ├─> OpenChannel("dvc::sample::simpleplugin")
    │       └─> WTSVirtualChannelOpenEx with WTS_CHANNEL_OPTION_DYNAMIC (ctypes)
    │
    ├─> Send ping messages every 1 second
    │       └─> Build frame: [frameLen][seqNum][utcTicks][payloadLen][payload]
    │
    ├─> Receive echo responses
    │       └─> DvcReassembler handles PDU fragmentation
    │           └─> Parse complete message once reassembled
    │
    ├─> Calculate and log RTT
    │
    └─> Ctrl+C → CloseChannel, cleanup, exit
```

### Protocol Message Flow

```
Server                                         Client Plugin
  │                                                 │
  ├─ BuildPingFrame(seq=1, payload=5120 bytes)      │
  ├─ WTSVirtualChannelWrite ──────────────────────> │
  │                                                 ├─ OnDataReceived
  │                                                 ├─ Parse PingMessage
  │                                                 └─ Echo bytes back
  │ <────────────────────────────────────────────── │
  ├─ Parse echo response                            │
  ├─ Calculate RTT                                  │
  └─ Log "Ping#1 payload=5120 rttMs=12.34"          │
```

## Prerequisites

- **Python 3.10 or later**
- **Windows 10/11 or Windows Server 2019+**
- **win32more >= 0.6.9** (for client plugin COM support)
- **PyInstaller** (for building standalone executables)

## Setup

### Using PowerShell Script

```powershell
# Install dependencies and build executables
.\build.ps1 -Install

# Build all executables (auto-detects platform)
.\build.ps1

# Build specific configuration/platform
.\build.ps1 -Configuration Release -Platform x64

# Build only client or server
.\build.ps1 -Project client
.\build.ps1 -Project server

# Force rebuild (clean first)
.\build.ps1 -Force

# Clean all build outputs
.\build.ps1 -Clean
```

### Development Mode

```powershell
# Create virtual environment (recommended)
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

## Running the sample

### 1. Register the Client Plugin

Run on the **RDP client machine** (where the RDP client runs):

```powershell
# Using built executable:
.\bin\x64\Debug\rdp-simple-plugin-client-python.exe /register

# Using Python module:
python -m rdp_simple_plugin_client /register

# Register (machine-wide, requires admin)
.\bin\x64\Debug\rdp-simple-plugin-client-python.exe /register /machine

# Unregister
.\bin\x64\Debug\rdp-simple-plugin-client-python.exe /unregister
```

### 2. Start the Server

Run **inside the RDP session** (on the remote server):

```powershell
# Using built executable:
.\bin\x64\Debug\rdp-simple-plugin-server-python.exe

# Using Python module:
python -m rdp_simple_plugin_server

# File handle mode (overlapped I/O)
.\bin\x64\Debug\rdp-simple-plugin-server-python.exe --filehandle
```

### 3. Connect via RDP

After registration, launch the RDP client and connect to the remote session. The DVC channel will be established automatically, and you'll see ping/echo messages in both console windows.

## Interoperability

All language implementations use the same:
- Channel name: `dvc::sample::simpleplugin`
- Wire protocol format
- COM CLSID: `{D9B80669-C06A-4BD1-9CB1-3B7168C9E3A3}`

This means you can mix and match client and server implementations across languages.

## Debugging

### Client Plugin

1. Start the RDP client and connect to the remote server
2. Run the client as a Python module (not packaged EXE) so you can add `print` statements:
   ```powershell
   python -m rdp_simple_plugin_client
   ```
3. Add logging in `simple_plugin.py` → `OnDataReceived` to observe echo logic
4. Use [DebugView](https://learn.microsoft.com/sysinternals/downloads/debugview) if the plugin writes via `OutputDebugString` (through win32more)

### Server Application

1. Run the server as a Python module for live output:
   ```powershell
   python -m rdp_simple_plugin_server
   ```
2. Add `print` or `logging` statements in `simple_server.py` for detailed tracing
3. Connect with the RDP client and observe ping/echo messages

### Common Issues

**Plugin not loaded:**
- Verify `HKCU\Software\Classes\CLSID\{D9B80669-C06A-4BD1-9CB1-3B7168C9E3A3}\LocalServer32` points to the correct EXE or Python script
- Check Windows Event Viewer → Application for COM activation errors

**Channel not opening:**
- Must run inside an active RDP session, not the local console
- Confirm the RDP client has established the connection before starting the server

## Troubleshooting

### Client plugin not loading
- Verify the plugin is registered in the registry
- Check if the RDP client is loading the plugin (use Process Monitor)
- Ensure win32more package is installed (`pip install win32more`)

### Server fails to open channel
- Must run inside an RDP session (not local console)
- Check WTSVirtualChannelOpenEx error code
- Ensure a client plugin is registered and the RDP client has loaded it

### Import errors
- Ensure you're running from the `Simple/python` directory
- Or install as a package: `pip install -e .`

## Next steps

### RDP Virtual Channels
- [Terminal Services Virtual Channels](https://learn.microsoft.com/windows/win32/termserv/terminal-services-virtual-channels)
- [IWTSPlugin Interface](https://learn.microsoft.com/windows/win32/api/tsvirtualchannels/nn-tsvirtualchannels-iwtsplugin)
- [IWTSListenerCallback Interface](https://learn.microsoft.com/windows/win32/api/tsvirtualchannels/nn-tsvirtualchannels-iwtslistenercallback)
- [IWTSVirtualChannelCallback Interface](https://learn.microsoft.com/windows/win32/api/tsvirtualchannels/nn-tsvirtualchannels-iwtsvirtualchannelcallback)
- [IWTSVirtualChannel Interface](https://learn.microsoft.com/windows/win32/api/tsvirtualchannels/nn-tsvirtualchannels-iwtsvirtualchannel)
- [WTSVirtualChannelOpenEx](https://learn.microsoft.com/windows/win32/api/wtsapi32/nf-wtsapi32-wtsvirtualchannelopenex)
- [WTSVirtualChannelRead](https://learn.microsoft.com/windows/win32/api/wtsapi32/nf-wtsapi32-wtsvirtualchannelread)
- [WTSVirtualChannelWrite](https://learn.microsoft.com/windows/win32/api/wtsapi32/nf-wtsapi32-wtsvirtualchannelwrite)
- [DVC Plug-in Registration](https://learn.microsoft.com/windows/win32/termserv/dvc-plug-in-registration)

### COM Development
- [Component Object Model (COM)](https://learn.microsoft.com/windows/win32/com/component-object-model--com--portal)
- [Out-of-Process Servers](https://learn.microsoft.com/windows/win32/com/out-of-process-server-implementation-helpers)
- [Registering COM Servers](https://learn.microsoft.com/windows/win32/com/registering-com-servers)

### Python on Windows
- [win32more](https://github.com/ynkdir/py-win32more) - Python COM and Windows API bindings
- [ctypes](https://docs.python.org/3/library/ctypes.html) - C foreign function interface for Python
- [PyInstaller](https://pyinstaller.org/) - Package Python apps as standalone executables

### Debugging
- [DebugView](https://learn.microsoft.com/sysinternals/downloads/debugview) - Capture OutputDebugString output
- [Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon) - Trace registry and file I/O

## License

See repository root for license information.
