//! Commands a terminal-family window may call.
//!
//! The window never sends target identity. The host resolves its binding, its
//! container and its file from what it recorded when it created the window,
//! and every answer is checked against that record again before it is handed
//! back, so a window whose binding changed meanwhile gets an error instead of
//! another target's output.

use serde_json::{Value, json};
use tauri::{AppHandle, Manager, Runtime, State, WebviewWindow};

use crate::{
    backend_bridge::REFUSED_METHOD,
    child_windows::{ChildKind, DirectoryScope, EditorScope},
    host::{Host, WindowLaunch, is_child_label},
    local_files::{self, DialogKind},
};

type CommandResult<T> = Result<T, String>;

// Mirrors TERMINAL_LIMITS in ui/src/shared/terminal-contract.ts.
const MAXIMUM_COLUMNS: u32 = 160;
const MAXIMUM_ROWS: u32 = 60;
const MAXIMUM_INPUT_BYTES: usize = 64 * 1024;
const MAXIMUM_POLL_EVENTS: u32 = 64;
const MAXIMUM_POLL_BYTES: u32 = 256 * 1024;
const MAXIMUM_SEARCH_QUERY_BYTES: usize = 1024;
const MAXIMUM_SEARCH_RESULTS: u32 = 256;
const MAXIMUM_SELECTION_COPY_BYTES: usize = 128 * 1024;

const UNAVAILABLE: &str = "这个窗口所属的连接已经断开或关闭。";
const TERMINAL_OPEN_FAILURE: &str = "Unable to open the bound SSH terminal.";
const NO_TERMINAL: &str = "这个窗口还没有打开终端。";

/// What a window is for, read under the lock and copied out.
struct Scope {
    label: String,
    binding_handle: String,
    kind: ChildKind,
    terminal_handle: Option<String>,
}

fn scope<R: Runtime>(window: &WebviewWindow<R>, host: &Host) -> CommandResult<Scope> {
    let label = window.label();
    if !is_child_label(label) {
        return Err(REFUSED_METHOD.to_owned());
    }
    let current = host.current_binding();
    let mut children = host.children.lock();
    let context = children
        .current(label, current.as_deref())
        .ok_or_else(|| UNAVAILABLE.to_owned())?;
    Ok(Scope {
        label: label.to_owned(),
        binding_handle: context.binding_handle.clone(),
        kind: context.kind.clone(),
        terminal_handle: context.terminal_handle.clone(),
    })
}

/// Whether the window still belongs to the same binding and still holds the
/// same terminal as when the call started.
fn still_current(host: &Host, scope: &Scope) -> bool {
    let current = host.current_binding();
    let mut children = host.children.lock();
    children
        .current(&scope.label, current.as_deref())
        .is_some_and(|context| {
            context.binding_handle == scope.binding_handle
                && context.terminal_handle == scope.terminal_handle
        })
}

fn require_terminal(scope: &Scope) -> CommandResult<String> {
    scope
        .terminal_handle
        .clone()
        .ok_or_else(|| NO_TERMINAL.to_owned())
}

fn valid_size(columns: u32, rows: u32) -> bool {
    (1..=MAXIMUM_COLUMNS).contains(&columns) && (1..=MAXIMUM_ROWS).contains(&rows)
}

fn opaque(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}

/// Decoded length of canonical, non-empty base64 within the input bound.
pub fn base64_decoded_length(value: &str, maximum: usize) -> Option<usize> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = value.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) || bytes.len() > maximum.div_ceil(3) * 4 {
        return None;
    }
    let padding = bytes.iter().rev().take_while(|byte| **byte == b'=').count();
    if padding > 2 {
        return None;
    }
    let body = &bytes[..bytes.len() - padding];
    if !body.iter().all(|byte| ALPHABET.contains(byte)) {
        return None;
    }
    let last = ALPHABET.iter().position(|byte| Some(byte) == body.last())?;
    if (padding == 2 && last & 0b1111 != 0) || (padding == 1 && last & 0b11 != 0) {
        return None;
    }
    let decoded = bytes.len() / 4 * 3 - padding;
    (decoded <= maximum).then_some(decoded)
}

#[tauri::command]
pub async fn terminal_open<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    columns: u32,
    rows: u32,
) -> CommandResult<Value> {
    let scope = scope(&window, &host)?;
    if !valid_size(columns, rows) || scope.terminal_handle.is_some() {
        return Err("Invalid terminal open request.".to_owned());
    }
    {
        let current = host.current_binding();
        let mut children = host.children.lock();
        let context = children
            .current(&scope.label, current.as_deref())
            .ok_or_else(|| UNAVAILABLE.to_owned())?;
        if !context.launch_available {
            return Err("Invalid terminal open request.".to_owned());
        }
        context.launch_available = false;
    }
    let request = match &scope.kind {
        ChildKind::Terminal => (
            "terminal.open",
            json!({ "bindingHandle": scope.binding_handle, "columns": columns, "rows": rows }),
        ),
        ChildKind::Container(container) => (
            "docker.container.terminal.open",
            json!({
                "bindingHandle": scope.binding_handle,
                "snapshotHandle": container.snapshot_handle,
                "containerHandle": container.container_handle,
                "columns": columns,
                "rows": rows,
            }),
        ),
        ChildKind::Pod(pod) => (
            "kubernetes.pod.terminal.open",
            json!({
                "bindingHandle": scope.binding_handle,
                "snapshotHandle": pod.snapshot_handle,
                "rowHandle": pod.row_handle,
                "container": pod.container,
                "columns": columns,
                "rows": rows,
            }),
        ),
        ChildKind::Directory(directory) => (
            "terminal.open-directory",
            json!({
                "bindingHandle": scope.binding_handle,
                "browserHandle": directory.browser_handle,
                "directoryHandle": directory.directory_handle,
                "columns": columns,
                "rows": rows,
            }),
        ),
        ChildKind::Editor(_) => return Err("Invalid terminal open request.".to_owned()),
    };
    let opened = match host.bridge.call(request.0, request.1).await {
        Ok(opened) => opened,
        // A folder window stays open and says why: the folder may have gone
        // stale in the file browser, or too many terminals are open. The page
        // maps the code to plain words; nothing from the target is in it.
        Err(error) if matches!(scope.kind, ChildKind::Directory(_)) => {
            tracing::warn!(%error, "directory terminal open failed");
            return Err(error);
        }
        // So does a pod's: kubectl exec is refused for reasons the operator
        // can act on — no exec permission, no shell in the image, the pod
        // replaced since the list was read — and a window that vanished would
        // say none of them. The backend's sentences are fixed text.
        Err(error) if matches!(scope.kind, ChildKind::Pod(_)) => {
            tracing::warn!(%error, "pod terminal open failed");
            return Err(error);
        }
        Err(error) => {
            tracing::warn!(%error, "terminal open failed");
            host.release_child(&app, &scope.label, true).await;
            return Err(TERMINAL_OPEN_FAILURE.to_owned());
        }
    };
    let Some(handle) = opened
        .get("handle")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        host.release_child(&app, &scope.label, true).await;
        return Err(TERMINAL_OPEN_FAILURE.to_owned());
    };
    let accepted = {
        let current = host.current_binding();
        let mut children = host.children.lock();
        match children.current(&scope.label, current.as_deref()) {
            Some(context) if context.terminal_handle.is_none() => {
                context.terminal_handle = Some(handle.clone());
                true
            }
            _ => false,
        }
    };
    if !accepted {
        let _ = host
            .bridge
            .call("terminal.close", json!({ "handle": handle }))
            .await;
        return Err("The terminal launch context is no longer current.".to_owned());
    }
    Ok(json!({
        "columns": opened.get("columns").cloned().unwrap_or(Value::from(columns)),
        "rows": opened.get("rows").cloned().unwrap_or(Value::from(rows)),
    }))
}

#[tauri::command]
pub async fn terminal_poll<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    maximum_events: u32,
    maximum_bytes: u32,
) -> CommandResult<Value> {
    let scope = scope(&window, &host)?;
    let handle = require_terminal(&scope)?;
    if !(1..=MAXIMUM_POLL_EVENTS).contains(&maximum_events)
        || !(1..=MAXIMUM_POLL_BYTES).contains(&maximum_bytes)
    {
        return Err("Invalid terminal poll request.".to_owned());
    }
    let result = host
        .bridge
        .call(
            "terminal.poll",
            json!({ "handle": handle, "maximumEvents": maximum_events, "maximumBytes": maximum_bytes }),
        )
        .await?;
    if !still_current(&host, &scope) {
        return Err("The terminal poll context is no longer current.".to_owned());
    }
    Ok(result)
}

#[tauri::command]
pub async fn terminal_input<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    bytes_base64: String,
) -> CommandResult<Value> {
    let scope = scope(&window, &host)?;
    let handle = require_terminal(&scope)?;
    let decoded = base64_decoded_length(&bytes_base64, MAXIMUM_INPUT_BYTES)
        .ok_or_else(|| "Invalid terminal input request.".to_owned())?;
    let result = host
        .bridge
        .call(
            "terminal.input",
            json!({ "handle": handle, "bytesBase64": bytes_base64 }),
        )
        .await?;
    let accepted = result.get("acceptedBytes").and_then(Value::as_u64);
    if !still_current(&host, &scope) || accepted != Some(decoded as u64) {
        return Err("The terminal input response is no longer current.".to_owned());
    }
    Ok(result)
}

#[tauri::command]
pub async fn terminal_resize<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    columns: u32,
    rows: u32,
) -> CommandResult<Value> {
    let scope = scope(&window, &host)?;
    let handle = require_terminal(&scope)?;
    if !valid_size(columns, rows) {
        return Err("Invalid terminal resize request.".to_owned());
    }
    let result = host
        .bridge
        .call(
            "terminal.resize",
            json!({ "handle": handle, "columns": columns, "rows": rows }),
        )
        .await?;
    if !still_current(&host, &scope) {
        return Err("The terminal resize context is no longer current.".to_owned());
    }
    Ok(result)
}

#[tauri::command]
pub async fn terminal_search<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    query: String,
    case_sensitive: bool,
    regex: bool,
    maximum_results: u32,
) -> CommandResult<Value> {
    let scope = scope(&window, &host)?;
    let handle = require_terminal(&scope)?;
    if query.is_empty()
        || query.len() > MAXIMUM_SEARCH_QUERY_BYTES
        || query.chars().any(char::is_control)
        || !(1..=MAXIMUM_SEARCH_RESULTS).contains(&maximum_results)
    {
        return Err("Invalid terminal search request.".to_owned());
    }
    let result = host
        .bridge
        .call(
            "terminal.search",
            json!({
                "handle": handle,
                "query": query,
                "caseSensitive": case_sensitive,
                "regex": regex,
                "maximumResults": maximum_results,
            }),
        )
        .await?;
    if !still_current(&host, &scope) {
        return Err("The terminal search context is no longer current.".to_owned());
    }
    Ok(result)
}

#[tauri::command]
pub fn terminal_copy_selection<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    text: String,
) -> CommandResult<()> {
    let scope = scope(&window, &host)?;
    require_terminal(&scope)?;
    if text.is_empty() || text.len() > MAXIMUM_SELECTION_COPY_BYTES {
        return Err("Invalid terminal selection copy request.".to_owned());
    }
    crate::host::write_clipboard(&app, &text)
}

#[tauri::command]
pub async fn terminal_close<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    host: State<'_, Host>,
) -> CommandResult<Value> {
    let scope = scope(&window, &host)?;
    host.release_child(&app, &scope.label, false).await;
    // Destroyed after this answer is on its way, so the page hears it.
    let window = window.clone();
    tauri::async_runtime::spawn(async move {
        let _ = window.destroy();
    });
    Ok(json!({ "closed": true }))
}

#[tauri::command]
pub async fn sftp_open<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
) -> CommandResult<Value> {
    let scope = scope(&window, &host)?;
    // The backend keeps one file browser per connection, and it belongs to the
    // SSH window. Another window opening one would quietly invalidate every
    // entry that window and its editors hold; a container window showing the
    // host's files would also read as the container's.
    if !matches!(scope.kind, ChildKind::Terminal) {
        return Err(REFUSED_METHOD.to_owned());
    }
    host.bridge
        .call(
            "sftp-browser.open",
            json!({ "bindingHandle": scope.binding_handle }),
        )
        .await
}

#[tauri::command]
pub async fn sftp_list<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    browser_handle: String,
    directory_handle: String,
) -> CommandResult<Value> {
    let scope = scope(&window, &host)?;
    if !opaque(&browser_handle) || !opaque(&directory_handle) {
        return Err("Invalid SFTP directory request.".to_owned());
    }
    host.bridge
        .call(
            "sftp-browser.directory.list",
            json!({
                "bindingHandle": scope.binding_handle,
                "browserHandle": browser_handle,
                "directoryHandle": directory_handle,
            }),
        )
        .await
}

#[tauri::command]
pub async fn sftp_read_text<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    browser_handle: String,
    file_handle: String,
) -> CommandResult<Value> {
    let scope = scope(&window, &host)?;
    if !opaque(&browser_handle) || !opaque(&file_handle) {
        return Err("Invalid SFTP preview request.".to_owned());
    }
    host.bridge
        .call(
            "sftp-browser.text.read",
            json!({
                "bindingHandle": scope.binding_handle,
                "browserHandle": browser_handle,
                "fileHandle": file_handle,
            }),
        )
        .await
}

/// The operator picks where the bytes land; the page never names a path.
#[tauri::command]
pub async fn sftp_download<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    browser_handle: String,
    file_handle: String,
) -> CommandResult<Value> {
    let scope = scope(&window, &host)?;
    if !opaque(&browser_handle) || !opaque(&file_handle) {
        return Err("Invalid SFTP download request.".to_owned());
    }
    let kind = DialogKind::Save { default_name: "" };
    let Some(path) = local_files::choose(&window, "保存远程文件", kind, None).await else {
        return Ok(json!({ "saved": false, "fileName": null, "bytes": null }));
    };
    let transfer = host
        .bridge
        .call(
            "sftp-browser.download",
            json!({
                "bindingHandle": scope.binding_handle,
                "browserHandle": browser_handle,
                "fileHandle": file_handle,
                "localPath": path.to_string_lossy(),
            }),
        )
        .await?;
    Ok(json!({
        "saved": true,
        "fileName": local_files::display_name(&path, "download"),
        "bytes": transfer.get("bytes").cloned().unwrap_or(Value::Null),
    }))
}

/// One SFTP change as the browser pane describes it. The backend takes the
/// fields flat beside the handles, with absent options as nulls.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SftpOperationInput {
    kind: String,
    entry_handles: Vec<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    mode: Option<u32>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    staged_handle: Option<String>,
    /// `write-text` only: the edited content and the hash it was read at.
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    expected_sha256: Option<String>,
}

#[tauri::command]
pub async fn sftp_plan<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    browser_handle: String,
    input: SftpOperationInput,
) -> CommandResult<Value> {
    let scope = scope(&window, &host)?;
    if !opaque(&browser_handle)
        || input.entry_handles.len() > 1024
        || !input.entry_handles.iter().all(|handle| opaque(handle))
    {
        return Err("Invalid SFTP operation request.".to_owned());
    }
    host.bridge
        .call(
            "sftp-browser.operation.plan",
            json!({
                "bindingHandle": scope.binding_handle,
                "browserHandle": browser_handle,
                "kind": input.kind,
                "entryHandles": input.entry_handles,
                "name": input.name,
                "mode": input.mode,
                "format": input.format,
                "stagedHandle": input.staged_handle,
                "text": input.text,
                "expectedSha256": input.expected_sha256,
            }),
        )
        .await
}

async fn sftp_plan_step<R: Runtime>(
    window: &WebviewWindow<R>,
    host: &Host,
    method: &str,
    plan_handle: String,
) -> CommandResult<Value> {
    let scope = scope(window, host)?;
    if !opaque(&plan_handle) {
        return Err("Invalid SFTP plan request.".to_owned());
    }
    host.bridge
        .call(
            method,
            json!({ "bindingHandle": scope.binding_handle, "planHandle": plan_handle }),
        )
        .await
}

#[tauri::command]
pub async fn sftp_confirm<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    plan_handle: String,
) -> CommandResult<Value> {
    sftp_plan_step(
        &window,
        &host,
        "sftp-browser.operation.confirm",
        plan_handle,
    )
    .await
}

#[tauri::command]
pub async fn sftp_execute<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    plan_handle: String,
) -> CommandResult<Value> {
    sftp_plan_step(
        &window,
        &host,
        "sftp-browser.operation.execute",
        plan_handle,
    )
    .await
}

#[tauri::command]
pub async fn sftp_cancel<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    plan_handle: String,
) -> CommandResult<Value> {
    sftp_plan_step(&window, &host, "sftp-browser.operation.cancel", plan_handle).await?;
    Ok(json!({ "cancelled": true }))
}

/// Stops this window's running upload or download. The transfer removes what
/// it wrote and answers its own caller; this says how many it reached.
#[tauri::command]
pub async fn sftp_cancel_transfer<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    browser_handle: String,
) -> CommandResult<Value> {
    let scope = scope(&window, &host)?;
    if !opaque(&browser_handle) {
        return Err("Invalid SFTP transfer cancellation.".to_owned());
    }
    host.bridge
        .call(
            "sftp-browser.transfer.cancel",
            json!({ "bindingHandle": scope.binding_handle, "browserHandle": browser_handle }),
        )
        .await
}

/// Puts a finished operation back once; the backend holds which ones may be.
#[tauri::command]
pub async fn sftp_undo<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    plan_handle: String,
) -> CommandResult<Value> {
    sftp_plan_step(&window, &host, "sftp-browser.operation.undo", plan_handle).await
}

/// Stages a local file for upload: one the local pane listed, or one picked
/// in the system dialog. Either way the host resolves the path.
#[tauri::command]
pub async fn sftp_stage_upload<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    local_file_handle: Option<String>,
) -> CommandResult<Value> {
    let scope = scope(&window, &host)?;
    let chosen = match local_file_handle {
        Some(handle) => host
            .local
            .lock()
            .resolve_file(&handle)
            .ok_or_else(|| "所选本机文件已不在列表中，请刷新后重试。".to_owned())?,
        None => match local_files::choose(&window, "选择要上传的文件", DialogKind::OpenFile, None)
            .await
        {
            Some(path) => path,
            None => return Ok(json!({ "staged": false, "upload": null })),
        },
    };
    let name = chosen
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "所选文件名无法识别。".to_owned())?
        .to_owned();
    let upload = host
        .bridge
        .call(
            "sftp-browser.upload.stage",
            json!({ "bindingHandle": scope.binding_handle, "localPath": chosen.to_string_lossy(), "name": name }),
        )
        .await?;
    Ok(json!({ "staged": true, "upload": upload }))
}

#[tauri::command]
pub fn local_open<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    host: State<'_, Host>,
) -> CommandResult<Value> {
    scope(&window, &host)?;
    let home = app
        .path()
        .home_dir()
        .map_err(|_| "无法定位本机用户目录。".to_owned())?;
    let snapshot = host.local.lock().open(&home).map_err(str::to_owned)?;
    serde_json::to_value(snapshot).map_err(|_| "本机目录读取失败。".to_owned())
}

#[tauri::command]
pub fn local_list<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    directory_handle: String,
) -> CommandResult<Value> {
    scope(&window, &host)?;
    if !opaque(&directory_handle) {
        return Err("Invalid local directory request.".to_owned());
    }
    let snapshot = host
        .local
        .lock()
        .list(&directory_handle)
        .map_err(str::to_owned)?;
    serde_json::to_value(snapshot).map_err(|_| "本机目录读取失败。".to_owned())
}

/// Asked by the browser pane, which already holds both handles. The window it
/// opens gets them from the host, not from its own page. Async because it
/// creates a window (see `terminal_window_open`).
#[tauri::command]
pub async fn file_editor_open<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    browser_handle: String,
    entry_handle: String,
    name: String,
    editable: bool,
) -> CommandResult<WindowLaunch> {
    let scope = scope(&window, &host)?;
    if !opaque(&browser_handle)
        || !opaque(&entry_handle)
        || name.is_empty()
        || name.chars().count() > 255
    {
        return Err("Invalid file editor launch request.".to_owned());
    }
    host.open_child(
        &app,
        &scope.binding_handle,
        ChildKind::Editor(EditorScope {
            browser_handle,
            entry_handle,
            name,
            editable,
        }),
    )
}

/// Opens a new terminal window that starts in a folder the SSH window's file
/// browser listed; each request is another shell, like a new tab. Only the SSH
/// window has that browser. The shell is opened by the new window itself, at
/// its own size; whether the handle still names a folder is checked then, by
/// the backend, and a refusal stays on screen in that window.
#[tauri::command]
pub async fn directory_terminal_open<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    browser_handle: String,
    directory_handle: String,
    name: String,
) -> CommandResult<WindowLaunch> {
    let scope = scope(&window, &host)?;
    if !matches!(scope.kind, ChildKind::Terminal)
        || !opaque(&browser_handle)
        || !opaque(&directory_handle)
        || name.is_empty()
        || name.chars().count() > 255
    {
        return Err("Invalid directory terminal request.".to_owned());
    }
    host.open_child(
        &app,
        &scope.binding_handle,
        ChildKind::Directory(DirectoryScope {
            browser_handle,
            directory_handle,
            name,
        }),
    )
}

/// The editor window asking what it was opened for; the answer comes from the
/// record the host made when it created the window.
#[tauri::command]
pub fn file_editor_target<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
) -> CommandResult<EditorScope> {
    match scope(&window, &host)?.kind {
        ChildKind::Editor(editor) => Ok(editor),
        _ => Err("This window is not a file editor.".to_owned()),
    }
}

/// The editor window saying whether it holds text that is not on the server.
/// While it does, closing it from outside the page (Alt+F4, the taskbar) asks
/// the page first.
#[tauri::command]
pub fn file_editor_unsaved<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    unsaved: bool,
) -> CommandResult<()> {
    let scope = scope(&window, &host)?;
    if !matches!(scope.kind, ChildKind::Editor(_)) {
        return Err("This window is not a file editor.".to_owned());
    }
    host.children.lock().set_unsaved(&scope.label, unsaved);
    Ok(())
}

/// The answer to a close question the host put to this window. Async because
/// closing a window from a command that runs on the main thread can stall it.
#[tauri::command]
pub async fn child_close_decision<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    request: u64,
    allowed: bool,
) -> CommandResult<()> {
    // A window whose connection is gone is being closed by the host anyway.
    let scope = scope(&window, &host)?;
    if host
        .children
        .lock()
        .resolve_close(&scope.label, request, allowed)
    {
        let _ = window.close();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_lengths_match_the_shared_contract() {
        assert_eq!(base64_decoded_length("", 10), None);
        assert_eq!(base64_decoded_length("YQ==", 10), Some(1));
        assert_eq!(base64_decoded_length("YWI=", 10), Some(2));
        assert_eq!(base64_decoded_length("YWJj", 10), Some(3));
        assert_eq!(base64_decoded_length("YR==", 10), None);
        assert_eq!(base64_decoded_length("YW=j", 10), None);
        assert_eq!(base64_decoded_length("YWJj", 2), None);
        assert_eq!(base64_decoded_length("Y===", 10), None);
    }
}
