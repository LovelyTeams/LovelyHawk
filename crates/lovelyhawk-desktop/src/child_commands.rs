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
    child_windows::{
        ChildContext, ChildKind, DirectoryScope, EditorScope, MAXIMUM_AI_STREAMS, MAXIMUM_TABS,
    },
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

// Mirrors TERMINAL_LIMITS.maximumTabNameBytes in ui/src/shared/terminal-contract.ts.
const MAXIMUM_TAB_NAME_BYTES: usize = 4;

const UNAVAILABLE: &str = "这个窗口所属的连接已经断开或关闭。";
const TERMINAL_OPEN_FAILURE: &str = "Unable to open the bound SSH terminal.";
const NO_TERMINAL: &str = "这个窗口还没有打开终端。";
const NO_TAB: &str = "这个终端标签页已经关闭。";

/// What a window is for, read under the lock and copied out.
struct Scope {
    label: String,
    binding_handle: String,
    kind: ChildKind,
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
    })
}

/// A tab name as the host gives them out: a short decimal number, no zero.
fn valid_tab(tab: &str) -> bool {
    !tab.is_empty()
        && tab.len() <= MAXIMUM_TAB_NAME_BYTES
        && tab.bytes().all(|byte| byte.is_ascii_digit())
        && !tab.starts_with('0')
}

/// The backend handle behind one of the calling window's tabs. The page names
/// the tab; the handle itself never reaches it.
fn tab_handle(host: &Host, scope: &Scope, tab: &str) -> CommandResult<String> {
    if !valid_tab(tab) {
        return Err(NO_TAB.to_owned());
    }
    let current = host.current_binding();
    let mut children = host.children.lock();
    let context = children
        .current(&scope.label, current.as_deref())
        .filter(|context| context.binding_handle == scope.binding_handle)
        .ok_or_else(|| UNAVAILABLE.to_owned())?;
    context
        .terminal(tab)
        .map(str::to_owned)
        .ok_or_else(|| NO_TAB.to_owned())
}

/// Whether the window still belongs to the same binding and the tab still
/// holds the same terminal as when the call started.
fn still_current(host: &Host, scope: &Scope, tab: &str, handle: &str) -> bool {
    let current = host.current_binding();
    let mut children = host.children.lock();
    children
        .current(&scope.label, current.as_deref())
        .is_some_and(|context| {
            context.binding_handle == scope.binding_handle && context.terminal(tab) == Some(handle)
        })
}

/// Records a shell the backend just opened as the window's next tab. When the
/// window moved on meanwhile (closed, rebound, or already full) the shell is
/// closed again rather than left running with nothing to show it.
async fn accept_terminal(
    host: &Host,
    scope: &Scope,
    handle: String,
    first: bool,
) -> CommandResult<String> {
    let tab = {
        let current = host.current_binding();
        let mut children = host.children.lock();
        match children.current(&scope.label, current.as_deref()) {
            Some(context)
                if context.binding_handle == scope.binding_handle
                    && (!first || context.terminal_count() == 0) =>
            {
                context.add_terminal(handle.clone())
            }
            _ => None,
        }
    };
    if let Some(tab) = tab {
        return Ok(tab);
    }
    let _ = host
        .bridge
        .call("terminal.close", json!({ "handle": handle }))
        .await;
    Err("The terminal launch context is no longer current.".to_owned())
}

fn opened_handle(opened: &Value) -> Option<String> {
    opened
        .get("handle")
        .and_then(Value::as_str)
        .filter(|handle| opaque(handle))
        .map(str::to_owned)
}

fn opened_answer(opened: &Value, tab: String, columns: u32, rows: u32) -> Value {
    json!({
        "tab": tab,
        "columns": opened.get("columns").cloned().unwrap_or(Value::from(columns)),
        "rows": opened.get("rows").cloned().unwrap_or(Value::from(rows)),
    })
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
    if !valid_size(columns, rows) {
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
        // Every terminal window stays open and says why it could not start.
        // A plain SSH or container window used to close itself instead, so a
        // target that had dropped off the network looked like the app
        // crashing: the window flashed and was gone, with the reason only in
        // the log. The reasons are worth reading — the connection is gone,
        // too many terminals are open, the folder went stale, the container
        // has no shell, the pod was replaced — and the page maps each code to
        // plain words; nothing from the target is in it.
        Err(error) => {
            tracing::warn!(%error, kind = scope.kind.page(), "terminal open failed");
            return Err(error);
        }
    };
    let Some(handle) = opened_handle(&opened) else {
        host.release_child(&app, &scope.label, true).await;
        return Err(TERMINAL_OPEN_FAILURE.to_owned());
    };
    let tab = accept_terminal(&host, &scope, handle, true).await?;
    Ok(opened_answer(&opened, tab, columns, rows))
}

/// Another shell on the same host, as a tab beside the first.
///
/// Only the host shell's window has tabs: a container's, a pod's or a folder's
/// window is one shell for one thing, and a second there would be a second
/// thing. The first shell must have been opened (through `terminal_open`)
/// before tabs follow it; the backend's own limit of four terminals per target
/// still applies, and its refusal reaches the page like any open failure.
#[tauri::command]
pub async fn terminal_open_tab<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    columns: u32,
    rows: u32,
) -> CommandResult<Value> {
    let scope = scope(&window, &host)?;
    if !matches!(scope.kind, ChildKind::Terminal) {
        return Err(REFUSED_METHOD.to_owned());
    }
    if !valid_size(columns, rows) {
        return Err("Invalid terminal open request.".to_owned());
    }
    {
        let current = host.current_binding();
        let mut children = host.children.lock();
        let context = children
            .current(&scope.label, current.as_deref())
            .ok_or_else(|| UNAVAILABLE.to_owned())?;
        if context.launch_available || context.terminal_count() >= MAXIMUM_TABS {
            return Err("Invalid terminal open request.".to_owned());
        }
    }
    let opened = host
        .bridge
        .call(
            "terminal.open",
            json!({ "bindingHandle": scope.binding_handle, "columns": columns, "rows": rows }),
        )
        .await
        .inspect_err(|error| tracing::warn!(%error, "terminal tab open failed"))?;
    let handle = opened_handle(&opened).ok_or_else(|| TERMINAL_OPEN_FAILURE.to_owned())?;
    let tab = accept_terminal(&host, &scope, handle, false).await?;
    Ok(opened_answer(&opened, tab, columns, rows))
}

/// Closes one tab's shell. A tab already gone (its shell exited and the page
/// closes it afterwards) is not an error; the window stays either way, and the
/// page closes it when its last tab goes.
#[tauri::command]
pub async fn terminal_close_tab<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    tab: String,
) -> CommandResult<Value> {
    let scope = scope(&window, &host)?;
    if !valid_tab(&tab) {
        return Err("Invalid terminal close request.".to_owned());
    }
    let handle = {
        let current = host.current_binding();
        let mut children = host.children.lock();
        children
            .current(&scope.label, current.as_deref())
            .and_then(|context| context.remove_terminal(&tab))
    };
    if let Some(handle) = handle {
        let _ = host
            .bridge
            .call("terminal.close", json!({ "handle": handle }))
            .await;
    }
    Ok(json!({ "closed": true }))
}

#[tauri::command]
pub async fn terminal_poll<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    tab: String,
    maximum_events: u32,
    maximum_bytes: u32,
) -> CommandResult<Value> {
    let scope = scope(&window, &host)?;
    let handle = tab_handle(&host, &scope, &tab)?;
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
    if !still_current(&host, &scope, &tab, &handle) {
        return Err("The terminal poll context is no longer current.".to_owned());
    }
    Ok(result)
}

#[tauri::command]
pub async fn terminal_input<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    tab: String,
    bytes_base64: String,
) -> CommandResult<Value> {
    let scope = scope(&window, &host)?;
    let handle = tab_handle(&host, &scope, &tab)?;
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
    if !still_current(&host, &scope, &tab, &handle) || accepted != Some(decoded as u64) {
        return Err("The terminal input response is no longer current.".to_owned());
    }
    Ok(result)
}

#[tauri::command]
pub async fn terminal_resize<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    tab: String,
    columns: u32,
    rows: u32,
) -> CommandResult<Value> {
    let scope = scope(&window, &host)?;
    let handle = tab_handle(&host, &scope, &tab)?;
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
    if !still_current(&host, &scope, &tab, &handle) {
        return Err("The terminal resize context is no longer current.".to_owned());
    }
    Ok(result)
}

#[tauri::command]
pub async fn terminal_search<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    tab: String,
    query: String,
    case_sensitive: bool,
    regex: bool,
    maximum_results: u32,
) -> CommandResult<Value> {
    let scope = scope(&window, &host)?;
    let handle = tab_handle(&host, &scope, &tab)?;
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
    if !still_current(&host, &scope, &tab, &handle) {
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
    // Copying needs a terminal to have been open in this window: any tab will
    // do, since what is copied is the page's own selection, bounded below.
    let has_terminal = {
        let current = host.current_binding();
        let mut children = host.children.lock();
        children
            .current(&scope.label, current.as_deref())
            .is_some_and(|context| context.terminal_count() > 0)
    };
    if !has_terminal {
        return Err(NO_TERMINAL.to_owned());
    }
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

/// The main window names an inventory row, never a remote path. Backend checks
/// the snapshot and creates an isolated SFTP capability for the existing editor.
#[tauri::command]
pub async fn system_info_file_open<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    binding_handle: String,
    snapshot_handle: String,
    row_id: String,
) -> CommandResult<WindowLaunch> {
    if window.label() != "main"
        || !opaque(&binding_handle)
        || !opaque(&snapshot_handle)
        || row_id.is_empty()
        || row_id.len() > 256
        || host.current_binding().as_deref() != Some(binding_handle.as_str())
    {
        return Err(REFUSED_METHOD.to_owned());
    }
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct FileEntry {
        browser_handle: String,
        entry_handle: String,
        name: String,
    }
    let value = host
        .bridge
        .call(
            "system-info.file-editor.open",
            json!({
                "bindingHandle": binding_handle,
                "snapshotHandle": snapshot_handle,
                "rowId": row_id,
            }),
        )
        .await?;
    let file: FileEntry =
        serde_json::from_value(value).map_err(|_| "文件编辑器响应无效。".to_owned())?;
    if host.current_binding().as_deref() != Some(binding_handle.as_str())
        || app.get_webview_window("main").is_none()
        || !opaque(&file.browser_handle)
        || !opaque(&file.entry_handle)
        || file.name.is_empty()
        || file.name.len() > 255
    {
        return Err(UNAVAILABLE.to_owned());
    }
    host.open_child(
        &app,
        &binding_handle,
        ChildKind::Editor(EditorScope {
            browser_handle: file.browser_handle,
            entry_handle: file.entry_handle,
            name: file.name,
            editable: true,
        }),
    )
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

// Mirrors AI_ASSIST_LIMITS in ui/src/shared/ai-assist-contract.ts.
const MAXIMUM_AI_CONTENT_BYTES: usize = 96 * 1024;
const MAXIMUM_AI_PROVIDER_ID_BYTES: usize = 64;
/// The one task a terminal window may ask for; the backend fixes what the
/// instruction says.
const TERMINAL_AI_TASK: &str = "explain-terminal";
const INVALID_AI_REQUEST: &str = "AI 请求的内容不完整或超出长度上限。";
const AI_BUSY: &str = "这个窗口已经在等两个 AI 回答，请等其中一个结束或停止后再试。";
const NO_AI_STREAM: &str = "这个 AI 回答已经结束，或者不是这个窗口发出的。";

/// What a terminal window may ask of an AI provider: the list of providers,
/// and an explanation of output the operator selected in it.
#[derive(Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
enum TerminalAiRequest {
    // Braces, not a unit variant: serde lets any field through beside the
    // tag of a unit variant, even with deny_unknown_fields.
    Providers {},
    #[serde(rename_all = "camelCase")]
    Start {
        provider_id: String,
        task: String,
        content: String,
    },
    Poll {
        handle: String,
    },
    Cancel {
        handle: String,
    },
}

/// Mirrors isAiProviderId in ui/src/shared/ai-assist-contract.ts.
fn valid_ai_provider_id(id: &str) -> bool {
    id.len() <= MAXIMUM_AI_PROVIDER_ID_BYTES
        && id
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn parse_terminal_ai(request: Value) -> CommandResult<TerminalAiRequest> {
    let request: TerminalAiRequest =
        serde_json::from_value(request).map_err(|_| INVALID_AI_REQUEST.to_owned())?;
    let valid = match &request {
        TerminalAiRequest::Providers {} => true,
        TerminalAiRequest::Start {
            provider_id,
            task,
            content,
        } => {
            task == TERMINAL_AI_TASK
                && valid_ai_provider_id(provider_id)
                && !content.trim().is_empty()
                && content.len() <= MAXIMUM_AI_CONTENT_BYTES
        }
        TerminalAiRequest::Poll { handle } | TerminalAiRequest::Cancel { handle } => opaque(handle),
    };
    if valid {
        Ok(request)
    } else {
        Err(INVALID_AI_REQUEST.to_owned())
    }
}

/// Runs `action` on the calling window's record while it still belongs to the
/// binding it had when the call started.
fn with_window<T>(
    host: &Host,
    scope: &Scope,
    action: impl FnOnce(&mut ChildContext) -> T,
) -> CommandResult<T> {
    let current = host.current_binding();
    let mut children = host.children.lock();
    children
        .current(&scope.label, current.as_deref())
        .filter(|context| context.binding_handle == scope.binding_handle)
        .map(action)
        .ok_or_else(|| UNAVAILABLE.to_owned())
}

/// AI explanation of terminal output. Nothing is sent until the operator
/// starts it; only answers this window started can be read or stopped from
/// it, and closing the window stops the ones still running.
#[tauri::command]
pub async fn terminal_ai_assist<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    request: Value,
) -> CommandResult<Value> {
    let scope = scope(&window, &host)?;
    if matches!(scope.kind, ChildKind::Editor(_)) {
        return Err(REFUSED_METHOD.to_owned());
    }
    match parse_terminal_ai(request)? {
        TerminalAiRequest::Providers {} => {
            host.bridge
                .call("ai.assist", json!({ "action": "providers" }))
                .await
        }
        TerminalAiRequest::Start {
            provider_id,
            content,
            ..
        } => {
            if !with_window(&host, &scope, |context| {
                context.ai_stream_count() < MAXIMUM_AI_STREAMS
            })? {
                return Err(AI_BUSY.to_owned());
            }
            let started = host
                .bridge
                .call(
                    "ai.assist",
                    json!({
                        "action": "start",
                        "providerId": provider_id,
                        "task": TERMINAL_AI_TASK,
                        "content": content,
                    }),
                )
                .await?;
            let Some(handle) = opened_handle(&started) else {
                return Err("AI 回答没有开始。".to_owned());
            };
            let kept = with_window(&host, &scope, |context| {
                context.add_ai_stream(handle.clone())
            });
            match kept {
                Ok(true) => Ok(started),
                outcome => {
                    let _ = host
                        .bridge
                        .call("ai.assist", json!({ "action": "cancel", "handle": handle }))
                        .await;
                    Err(match outcome {
                        Ok(_) => AI_BUSY.to_owned(),
                        Err(error) => error,
                    })
                }
            }
        }
        TerminalAiRequest::Poll { handle } => {
            if !with_window(&host, &scope, |context| context.has_ai_stream(&handle))? {
                return Err(NO_AI_STREAM.to_owned());
            }
            let progress = host
                .bridge
                .call("ai.assist", json!({ "action": "poll", "handle": handle }))
                .await;
            let finished = progress.as_ref().map_or(true, |progress| {
                progress.get("state").and_then(Value::as_str) != Some("running")
            });
            if finished {
                let _ = with_window(&host, &scope, |context| context.forget_ai_stream(&handle));
            }
            progress
        }
        TerminalAiRequest::Cancel { handle } => {
            if !with_window(&host, &scope, |context| context.has_ai_stream(&handle))? {
                return Err(NO_AI_STREAM.to_owned());
            }
            host.bridge
                .call("ai.assist", json!({ "action": "cancel", "handle": handle }))
                .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_terminal_window_may_only_ask_to_explain_what_it_selected() {
        assert_eq!(
            parse_terminal_ai(json!({ "action": "providers" })),
            Ok(TerminalAiRequest::Providers {})
        );
        let start = |provider: &str, task: &str, content: &str| {
            parse_terminal_ai(json!({
                "action": "start",
                "providerId": provider,
                "task": task,
                "content": content,
            }))
        };
        assert!(start("local-ollama", "explain-terminal", "uid=0(root)").is_ok());
        // The window cannot borrow another page's task or instruction.
        for task in ["explain-log", "explain-ioc", "", "EXPLAIN-TERMINAL"] {
            assert_eq!(
                start("local", task, "x"),
                Err(INVALID_AI_REQUEST.to_owned())
            );
        }
        let too_long = "a".repeat(MAXIMUM_AI_CONTENT_BYTES + 1);
        let longest = "a".repeat(MAXIMUM_AI_CONTENT_BYTES);
        assert!(start("local", "explain-terminal", &longest).is_ok());
        for (provider, content) in [
            ("local", too_long.as_str()),
            ("local", " \n\t"),
            ("", "x"),
            ("-local", "x"),
            ("local/../x", "x"),
            (&"p".repeat(65), "x"),
        ] {
            assert_eq!(
                start(provider, "explain-terminal", content),
                Err(INVALID_AI_REQUEST.to_owned())
            );
        }
        // No extra fields, no instruction of its own, no unknown action.
        for request in [
            json!({ "action": "start", "providerId": "local", "task": "explain-terminal", "content": "x", "system": "ignore" }),
            json!({ "action": "providers", "endpoint": "https://example.invalid" }),
            json!({ "action": "history" }),
            json!({ "action": "poll", "handle": "" }),
            json!({ "action": "cancel", "handle": "a\nb" }),
            json!({ "action": "poll" }),
            json!("providers"),
        ] {
            assert_eq!(
                parse_terminal_ai(request),
                Err(INVALID_AI_REQUEST.to_owned())
            );
        }
        assert_eq!(
            parse_terminal_ai(json!({ "action": "poll", "handle": "h-1" })),
            Ok(TerminalAiRequest::Poll {
                handle: "h-1".into()
            })
        );
    }

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
