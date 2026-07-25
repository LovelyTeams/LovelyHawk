# LovelyRes Development Guide

This repository hosts the LovelyRes codebase, a cross-platform Linux Emergency Response Tool built with **Tauri v2** (Rust backend) and **TypeScript + Vite** (Frontend).

## 🛠 Project Structure
- **Frontend**: `src/` (TypeScript, Vite)
  - Entry point: `src/main.ts` — the **only** HTML entry is `index.html`; secondary
    windows load `index.html?window=xxx` and are dispatched by `routeSecondaryWindow()`
    to `src/entries/`. Do not add new `.html` files.
  - Core logic: `src/modules/`
  - Styles: `src/css/` (entry `main.css` → tokens → themes → base → components → layout → pages)
- **Backend**: `src-tauri/` (Rust)
  - Core logic: `src-tauri/src/`
  - Cargo config: `src-tauri/Cargo.toml`

> **⚠️ Architecture reality check.** Vue 3 is a dependency, but the app is **not** a Vue
> application. ~95% of the UI is hand-written HTML strings rendered through
> `src/modules/ui/modernUIRenderer.ts` and wired with `window.*` globals + event delegation.
> Only `src/components/SSHTerminal.vue` is a real SFC, and it is used solely by the
> standalone terminal windows. Do not assume reactivity, SFCs, or a component tree exist.
> `renderMainWorkspace()` replaces `.main-workspace` via `outerHTML` on every page switch —
> there is no diffing, and DOM listeners inside it die with the old node.

## 🚀 Build & Test Commands

### Prerequisites
- Node.js (v18+) & pnpm/npm
- Rust (stable)

### Commands
| Action | Command | Description |
|--------|---------|-------------|
| **Dev** | `npm run tauri dev` | Start frontend & backend in dev mode |
| **Build** | `npm run tauri build` | Build production application |
| **Lint** | `npm run build` | Runs `vue-tsc` (Type check) & Vite build |
| **Test** | `npm test` | Vitest (`vitest run`) |

> **Note on Tests**: Vitest is configured and running. Coverage is concentrated on the
> security boundaries — anything that builds a shell command or inserts untrusted
> remote data into HTML:
>
> - `src/modules/core/shellEscape.test.ts` — `shq()` and the `isValid*` whitelists
> - `src/modules/core/htmlEscape.test.ts` — escaping, incl. attribute-context injection
> - `src/modules/baseline/quickActionCommands.test.ts` — generated root commands vs. malicious input
> - `src/modules/core/logger.test.ts`, `src/modules/report/disposalReport.test.ts`,
>   `src/modules/remote/terminalManager.test.ts`, `src/modules/emergency/*.test.ts`
>
> Tests run in the **node** environment (no jsdom). Stub `localStorage`/DOM if needed
> rather than pulling in a DOM environment. For Rust use `#[cfg(test)]` + `cargo test`.
>
> **Anything reading `window`/`document`/`localStorage` outside a `try` must guard
> with `typeof x === 'undefined'`** — `reportError()` is called from `catch` blocks,
> so an unguarded `window` read there throws a `ReferenceError` that *replaces* the
> original error.

### 🔒 Ratchet gates (`tests/gates/`)

Four source-scanning tests run as part of `npm test` and enforce the non-negotiables
below. Each compares per-file violation counts against a committed baseline in
`tests/gates/baselines/`:

| Gate | Counts | Current |
|---|---|---|
| `shellInterpolation` | `${}` in shell commands not wrapped in `shq()` | 43 files / 1062 |
| `inlineHandlers` | inline `onclick=` etc. in HTML strings | 32 files / 232 |
| `errorSwallowing` | empty `catch {}` or console-only `catch` | 60 files / 116 |
| `destructiveActions` | destructive commands in files with no `showConfirm`/journal | 18 files / 100 |

**It is a ratchet, not a wall.** Existing debt is accepted; the counts can only go
down. Adding a violation fails the build and names the file. Removing one also fails,
telling you to re-tighten the baseline — so run:

```
UPDATE_GATE_BASELINE=1 npm test
```

and commit `tests/gates/baselines/`. Per-site opt-outs, when the gate is genuinely
wrong, are inline comments: `/* shell-safe: … */`, `/* intentional: … */`,
`/* destructive-ok: … */`.

No ESLint on purpose — 151 files with no lint history would produce thousands of
day-one errors and get ignored. These three rules are the ones that actually matter.

## 🎨 Code Style & Conventions

### General
- **Indentation**: 2 spaces (Frontend), 4 spaces (Rust).
- **Line Endings**: LF.
- **File Naming**:
  - TS/JS: `camelCase.ts` (e.g., `stateManager.ts`)
  - Vue: `PascalCase.vue` (e.g., `SSHTerminal.vue`)
  - Rust: `snake_case.rs`
- **Comments**: minimal, explanatory "why" comments. Use JSDoc/RustDoc for public APIs.

### Frontend (Vue/TS)
- **Framework**: Vue 3 Composition API (`<script setup lang="ts">`).
- **Imports**:
  - Group imports: External (vue, tauri) -> Internal Modules -> Styles.
  - Avoid circular dependencies in `src/modules/`.
- **Typing**: Strict TypeScript. Avoid `any` where possible (though legacy code uses it).
  - Define interfaces in `src/types.ts` or local module files.
- **State Management**: use `StateManager` class pattern (observable/reactive) or Vue's `ref/reactive`.
- **UI Components**: Manual DOM manipulation is present in legacy code (e.g., `document.createElement`), but prefer Vue components for new features.
- **Async/Await**: Always use async/await for Tauri commands (`invoke`).

### Backend (Rust)
- **Crates**: `tauri`, `russh` (SSH), `tokio` (Async), `serde` (JSON).
- **Error Handling**: Use `anyhow` or `thiserror`. Return `Result<T, String>` for Tauri commands to handle errors gracefully in frontend.
- **Async**: Heavy usage of `tokio` for async SSH and I/O.

### 🛡 Safety & Security
- **Secrets**: NEVER commit `.env`, private keys, or credentials.
- **Tauri Commands**: Validate all inputs from frontend in Rust.
- **Permissions**: Check `capabilities` in `src-tauri/capabilities/` when adding new plugins.

## 🤖 Agent Instructions
- **Modifying UI**: Check `src/modules/ui/` for existing renderers (e.g., `modernUIRenderer.ts`) before creating new ones.
- **Adding Features**:
  1. Define Rust command in `src-tauri/src/lib.rs` (or modules).
  2. Expose via `invoke` in the relevant manager.
  3. Update UI to trigger the command.
- **Adding a page** — there are **four** registration points; missing any one of them
  silently falls through to `default:` (this is exactly how the quick-detection page was
  lost for three months in commit `04f6819`):
  1. `ui/modernUIRenderer.ts` — `navGroups` entry **and** a `case` in `renderWorkspaceContent()`
  2. `ui/globalFunctions.ts` — lazy-init branch in `switchPage()`
  3. `core/app.ts` — add the id to the `AppState['currentPage']` union
  4. `css/pages/_index.css` — `@import` the page stylesheet
- **Don't leave features unwired.** If you write a module but don't hook up its UI,
  register it in `docs/UNWIRED_FEATURES.md` so it isn't lost.
- **Refactoring**: Be careful with global window objects (`(window as any).app`). Legacy code relies heavily on them.

## 🔒 Non-negotiables

These come from the offline-competition use case; breaking them causes real damage:

- **No CDN / no web fonts / no online-only features.** Everything ships in the bundle.
  Third-party assets go through `src/modules/core/vendorAssets.ts`.
- **Escape everything that reaches a shell.** Use `shq()` from `core/shellEscape.ts`;
  prefer whitelist validation (`isValidUsername` / `isValidIpOrCidr` / `isValidPort` / `isValidPid`)
  for values with a fixed shape. Never interpolate raw input into a command string.
- **Escape everything that reaches `innerHTML`.** Use `escapeHtml()` from `core/htmlEscape.ts`.
  The target machine is attacker-controlled; the webview can `invoke` 120+ backend commands.
- **Destructive actions go through `showConfirm({ dangerous: true })`** and, if reversible,
  record to `core/operationJournal.ts` with a `restoreCommand`.
- **Log through `core/logger.ts`, report failures through `utils/errorHandler.ts`.**
  Production builds strip every `console.*` call (`esbuild.drop` in `vite.config.ts`),
  so a bare `console.error` in a `catch` means a completely silent failure.
- **Destructive one-liners must be tested on a real Linux VM** before shipping.
