# LovelyRes Native Development Guide

LovelyRes is a native Rust desktop application built with GPUI. The supported application is the root Cargo workspace; do not add an HTML, JavaScript, WebView, CDN, or web-font runtime.

## Workspace

- `crates/lovelyres-core`: UI-independent domain services, SSH/SFTP actors, portable stores, target guards, operation planning, audit, and recovery contracts.
- `crates/lovelyres-terminal`: terminal model, transport adapter, input, selection, search, layout, and GPUI terminal view.
- `crates/lovelyres-gpui`: application composition root, GPUI entities/views, native windows, page lifecycle, dialogs, themes, and embedded assets.
- `docs/`: current compatibility, release, validation, and unresolved-feature documentation.
- `scripts/`: source, dependency, quality, feasibility, and portable-release gates.

The workspace uses Rust 2024 and Rust 1.93.1. Keep dependency versions centralized in the root `Cargo.toml` and keep `Cargo.lock` committed.

## Commands

```powershell
# Run and build
cargo run --locked --package lovelyres-gpui --bin lovelyres
cargo build --locked --package lovelyres-gpui --bin lovelyres
cargo build --release --locked --package lovelyres-gpui --bin lovelyres

# Required checks
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
pwsh -File ./scripts/gpui-source-gate.ps1 -ManifestPath ./Cargo.toml
pwsh -File ./scripts/gpui-dependency-gate.ps1 -ManifestPath ./Cargo.toml
```

Use `#[cfg(test)]` unit tests near domain rules and integration tests for cross-crate or protocol behavior. Tests requiring a real Linux/SSH target stay `#[ignore]` until run by the applicable release gate; never report an ignored or `NOT_RUN` scenario as passing.

## Architecture rules

- Put business rules and remote effects in `lovelyres-core`. Core APIs should accept typed values and return bounded typed results; they must not depend on GPUI.
- Put terminal protocol/model behavior in `lovelyres-terminal`. Keep transport events bounded and preserve cancellation, resize, backpressure, and stale-session behavior.
- Keep `lovelyres-gpui` focused on entities, views, native dialogs/windows, and translating user intent into typed core calls.
- The composition root creates shared services and state once. Do not create parallel stores, SSH actors, Tokio runtimes, or target state inside individual pages.
- Every remote async request captures a complete `TargetGuard { identity, generation }` and validates it before dispatch and before applying results.
- Page state must support explicit activation/deactivation. Register a new page in the centralized `PageId`/descriptor registry and wire its entity, lifecycle, render branch, and tests together.
- Native secondary windows share typed entities or intents with the main window. Do not introduce stringly-typed event buses or hidden persistence as a navigation channel.
- Treat all remote text as hostile plain text. Do not reinterpret it as markup, a resource path, an action identifier, or a command.

## Safety rules

- No CDN, remote image/font/style/script, or online-only UI dependency. Add distributable assets under `crates/lovelyres-gpui/assets/` and load them through the embedded asset source.
- Never interpolate user or remote data into a shell program. Prefer closed enums and validated value types; otherwise use the core shell-escaping boundary.
- Dangerous mutations require an immutable plan, exact dangerous confirmation, journal entry, independent verification, and a restore path when the action is reversible.
- Remote paths must use validated path types and managed namespaces. Uploads, downloads, backups, and restores must reject traversal, overwrite races, and stale target/session state.
- Secrets remain in core-owned credential types, are encrypted at rest, zeroized where practical, and never appear in logs, debug output, exports, or GPUI state snapshots.
- Bound output size, item count, concurrency, and event queues for attacker-controlled targets. Long-running work must be cancellable and late results must fail closed.
- Log through the native tracing setup. Do not swallow errors or reduce a production failure to debug-only output.
- Destructive remote one-liners and recovery flows require real Linux VM validation before release.

## Code style and change discipline

- Use four-space Rust indentation, `snake_case` modules/functions, and `PascalCase` types.
- Prefer small, explicit changes. Reuse existing typed services and shared entities before adding abstractions.
- Document why a safety boundary exists; avoid comments that only restate code.
- Do not use `unsafe` unless the platform integration requires it, its invariant is documented, and a narrow test or gate covers the boundary.
- Add tests for security-sensitive parsing, shell/path construction, target lifecycle, attacker-controlled text, persistence, and recovery behavior.
- If an implemented module cannot be wired into its page or native window in the same change, record its crate path, owner, missing wiring, and acceptance test in `docs/UNWIRED_FEATURES.md`.

## Portable data and releases

Runtime state belongs under the executable-adjacent `data/` root via the versioned portable stores. Do not write application state to browser storage or silently fall back to a user profile directory. Release artifacts must pass the source/resource gate, dependency gate, platform smoke checks, and the real-environment matrices described in `docs/`.
