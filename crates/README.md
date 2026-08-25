# Electron workspace crates

- `lovelyres-core`: UI-framework-independent services and safety contracts.
- `lovelyres-terminal`: headless terminal model, protocol, transport, search, and layout code used by the Electron sidecar.
- `lovelyres-electron-backend`: the bounded Rust sidecar and the only supported Electron-to-core process boundary.

Electron main, preload, and the React renderer are the supported desktop application and release target. The legacy GPUI frontend was removed on 2026-08-25; do not reintroduce GPUI UI or release paths.
