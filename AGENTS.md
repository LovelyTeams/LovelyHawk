# LovelyRes Electron Development Guide

LovelyRes has completed its frontend migration from GPUI to Electron; the `crates/lovelyres-gpui` tree, GPUI dependencies, and GPUI release paths were removed on 2026-08-25. Electron main, preload, and the React renderer are the only supported desktop frontend target. Do not reintroduce GPUI or add a second frontend. The retired dirty config-generator baseline is archived verbatim at `docs/legacy/config-generator-baseline.rs.txt` as the behavior reference for the outstanding test replacements in `docs/CONFIG_GENERATOR_TEST_BACKLOG.md`.

## Workspace

- `crates/lovelyres-core`: UI-independent domain services, SSH/SFTP actors, portable stores, target guards, operation planning, audit, verification, and recovery contracts.
- `crates/lovelyres-electron-backend`: the finite, versioned Rust sidecar boundary used by Electron. It composes shared core services once and must not expose generic shell, filesystem, process, or core-call primitives.
- `crates/lovelyres-terminal`: headless terminal model, protocol, transport, search, and layout code consumed by the Electron sidecar.
- `electron/`: Electron main, frozen preload API, React renderer, local assets, tests, and Electron-native CDP/capture debugging.
- `docs/`: migration ledgers, compatibility, release, validation, and unresolved-feature documentation.
- `scripts/`: Electron source, dependency, quality, package, smoke, migration-ledger, and portable-release gates.

Rust uses edition 2024 and Rust 1.93.1. Keep Rust dependency versions centralized in the root `Cargo.toml`, JavaScript versions pinned in `electron/package.json`, and both `Cargo.lock` and `pnpm-lock.yaml` committed.

## Commands

```powershell
# Electron development and verification
pnpm --filter @lovelyres/electron dev
pnpm --filter @lovelyres/electron check
pnpm --filter @lovelyres/electron test:debug
pwsh -NoProfile -File ./scripts/electron-source-gate.ps1 -RepositoryRoot .

# Rust sidecar and core
cargo build --locked --package lovelyres-electron-backend --bin lovelyres-backend
cargo test --locked --package lovelyres-electron-backend
cargo clippy --locked --package lovelyres-electron-backend --all-targets -- -D warnings
cargo test --locked --package lovelyres-core

# Windows portable release chain
pwsh -NoProfile -File ./scripts/electron-package-windows.ps1
pwsh -NoProfile -File ./scripts/electron-validate-package.ps1
pwsh -NoProfile -File ./scripts/electron-portable-smoke.ps1
```

Use `#[cfg(test)]` unit tests near domain rules and integration tests for process/protocol boundaries. Tests requiring a real Linux/SSH target stay `#[ignore]` until the applicable release gate actually runs them. Never report ignored, skipped, Pending, or `NOT_RUN` scenarios as passing.

## Electron architecture rules

- Browser windows use `sandbox: true`, `contextIsolation: true`, `nodeIntegration: false`, `webSecurity: true`, a packaged local `lovelyres://app` origin, and a strict CSP. Deny unapproved navigation, new windows, downloads, permissions, and remote resources.
- The renderer receives one frozen, finite preload API. Every method has an exact IPC channel, arity, bounded input validator, fixed sidecar method, exact response validator, and negative tests. Do not expose `ipcRenderer`, arbitrary channel invocation, absolute data roots, raw filesystem access, process spawning, or generic command execution.
- Electron main owns native dialogs, clipboard operations, keyed secondary-window lifecycle, and create-only file exports. Renderer calls do not supply or receive absolute paths or exported file contents.
- The Rust sidecar owns shared core services, target/session capabilities, mutation registries, and sensitive state. Public DTOs contain only bounded display data and opaque handles.
- Keep business rules and remote effects in `lovelyres-core`. Core APIs accept typed values and return bounded typed results; they do not depend on Electron or GPUI.
- Every remote async request captures the complete target identity/generation through a core-bound capability and validates it before dispatch and before applying results. Late or stale results fail closed.
- Pages and overlays support explicit activation/deactivation. Dirty editors participate in navigation and application-close handshakes. Keyed terminal/SFTP/container windows close their remote work when the window or binding closes.
- The custom title bar draws only the fixed, named app actions (SSH terminal, command history, theme, settings) as labelled icon buttons that opt out of the drag region; window controls stay native. The app opens on the welcome landing view (`WELCOME_PAGE_ID`) until a target binds, and only that editor-free view may be left without the dirty-navigation handshake.
- User-visible copy is written for the operator, not the architect. Never surface implementation vocabulary (`renderer`, `sidecar`, `core`, `opaque`, `binding`, `capability`, `handle`, 有界, 代际, 投影, 字节预算, `Phase N`) or uppercase English eyebrow labels; state what the page does, what it will not touch, and what to do when it fails. Changing copy also breaks the SSR test assertions, the CDP probe's `includes(...)` checks, and the source-gate markers — update all three.
- The renderer never opens a system-level dialog. `window.alert/confirm/prompt` are blocked by the source gate; ask through `useConfirmDialog` + `DialogHost`, which fail closed on cancel, supersession, or a malformed request. Native OS dialogs stay in main and only for file selection, where the picker is the user's consent boundary and keeps absolute paths out of the renderer.
- Treat all remote, imported, AI, command, log, and configuration text as hostile plain text. Never reinterpret it as markup, a URL, a local resource, a path, an action identifier, or a command.

## Electron-native debugging

Unpackaged development builds run in debug mode: F12 / Ctrl+Shift+I toggles detached DevTools on the main and terminal windows, and `LOVELYRES_DEBUG=1` forces the same for a packaged build (see `electron/src/main/debug-mode.ts`). Packaged builds otherwise ship with `devTools: false`.

Do not use `computer-use` for Electron development or migration acceptance. Automated UI debugging and visual evidence use Electron's own `webContents.debugger`/CDP integration, `webContents.capturePage`, main/preload/renderer tests, and packaged smoke tests. CDP probes must enforce the exact preload API, local-only resources, zero unexpected console errors, accessibility, focus behavior, hostile-text rendering, cancellation, and bounded evidence output.

## Safety rules

- No CDN, remote image/font/style/script, remote SVG, or online-only UI dependency. Bundle distributable assets under `electron/assets/`, keep licenses/notices, and load them only from the local application origin.
- Never interpolate user or remote data into a shell program. Prefer closed enums and validated value types; otherwise use the core shell-escaping boundary.
- Dangerous mutations require an immutable core plan, exact dangerous confirmation, single-use bounded capability, journal entry, independent verification, and a restore path when reversible.
- Remote paths use validated path types and managed namespaces. Uploads, downloads, backups, restores, imports, and exports reject traversal, overwrite races, stale target/session state, and renderer-selected arbitrary paths.
- Secrets stay in core-owned credential/settings types, are encrypted at rest, zeroized where practical, and never appear in logs, debug output, renderer DTOs, snapshots, exports, or persisted browser state. Secret changes are write-only.
- Bound output bytes, text length, item count, concurrency, snapshot registries, pending capabilities, and event queues for attacker-controlled targets. Long-running work is cancellable; close/shutdown must interrupt backpressure waits.
- Log through the native tracing setup. Public failures are fixed and redacted; do not swallow production errors or echo attacker-controlled parameters.
- Destructive remote one-liners, SSH/SFTP/terminal compatibility, and recovery flows require actual Linux VM validation before release.

## Code and change discipline

- Use four-space Rust indentation, `snake_case` modules/functions, `PascalCase` types, strict TypeScript, and focused React components with explicit state transitions.
- Renderer CSS takes every color from the global tokens in `electron/src/renderer/theme/themes.css` via `var(--token)`; never write color literals in component CSS, and never use a surface token as a foreground (or a text token as a background). `theme/theme.test.ts` blocks both, enforces per-theme WCAG contrast, and requires light themes to stay light everywhere (sidebar, log panels, terminal) while dark themes stay dark. New themes are one `:root[data-theme="…"]` block plus a `shared/theme-contract.ts` `THEMES` entry plus the `SettingsTheme` enum value; native colors main paints must match the CSS tokens.
- The terminal preload is sandboxed and cannot require sibling modules, so it repeats the theme ids inline; `terminal-preload-theme.test.ts` keeps that copy in sync with the shared registry.
- Prefer small, explicit changes. Reuse existing typed core services, repositories, target capabilities, and shared entities before adding abstractions.
- Document why a safety boundary exists; avoid comments that merely restate code.
- Do not use `unsafe` unless a narrow platform integration requires it, its invariant is documented, and a focused test or gate covers it.
- Add tests for security-sensitive parsing, exact IPC/RPC shapes, shell/path construction, target lifecycle, attacker-controlled text, persistence, backpressure, cancellation, and recovery behavior.
- If a module cannot be wired into its Electron page/window in the same change, record its path, owner, missing wiring, and acceptance test in `docs/UNWIRED_FEATURES.md`. Presence alone is never completion evidence.
- Preserve the archived config-generator baseline (`docs/legacy/config-generator-baseline.rs.txt`, SHA-256 recorded in `docs/ELECTRON_UI_LEDGER.json`) and work down `docs/CONFIG_GENERATOR_TEST_BACKLOG.md`: every remaining legacy test ID needs a reviewed, passing Electron/core replacement. Pending or merely-present tests never count as done.

## Portable data and releases

Runtime state belongs under the executable-adjacent `data/` root through the versioned portable stores. Set Electron paths before the single-instance lock. Do not use browser storage or silently fall back to a user-profile directory.

Releases are Electron-only: no `lovelyres-gpui` crate, GPUI dependency, GPUI launcher, GPUI CI/release job, or GPUI runtime artifact may return. Historical/legal migration references and negative gates may retain the word “GPUI,” but active manifests, dependency trees, supported commands, and production packages must not contain the runtime — `scripts/electron-dependency-gate.ps1 -RequireGpuiRetired` enforces this. Windows, macOS, and Linux candidates must pass their clean offline package, asset/license, portable-path, shutdown, and real-environment matrices before the migration is declared complete.
