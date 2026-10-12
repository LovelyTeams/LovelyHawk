# LovelyHawk workspace crates

- `lovelyhawk-core`: UI-framework-independent services and safety contracts.
- `lovelyhawk-terminal`: headless terminal model, protocol, transport, search, and layout code used by the backend.
- `lovelyhawk-backend`: the bounded, versioned backend boundary and the only supported path from the desktop UI to core. The desktop application links it in-process; the headless stdio binary `lovelyhawk-backend` (protocol `lovelyhawk-backend/v1`) is kept only for lab RPC harnesses.
- `lovelyhawk-desktop`: the Tauri 2 desktop application (`lovelyhawk.exe`). It links the backend in-process and owns windows, system file dialogs, clipboard, exports, the terminal/container-terminal/file-editor child windows and their binding to the current SSH target, the close handshake, the portable data directory, and the single-instance lock. Its permission split lives in `capabilities/` and `tauri.conf.json`.

The Tauri 2 host (`lovelyhawk-desktop`) and the React UI in `ui/` are the supported desktop application and release target. The earlier Electron shell has been retired, and the legacy GPUI frontend was removed on 2026-08-25; do not reintroduce Electron or GPUI UI or release paths.
