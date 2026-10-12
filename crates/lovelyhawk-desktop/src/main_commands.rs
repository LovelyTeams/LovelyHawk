//! Commands the main window may call.
//!
//! Every command first checks that the caller is the main window; capability
//! files grant the same split, and this check holds even if they are edited.

use serde::Deserialize;
use serde_json::{Map, Value, json};
use tauri::{AppHandle, Runtime, State, WebviewWindow};

use zeroize::Zeroizing;

use crate::{
    backend_bridge::{REFUSED_METHOD, main_window_may_call},
    binding_state::Transition,
    child_windows::{ChildKind, ContainerScope, PodScope},
    host::{Host, MAIN_LABEL, WindowLaunch},
    local_files::{self, DialogKind, Filter},
    smoke, theme,
};

type CommandResult<T> = Result<T, String>;

const MAX_CLIPBOARD_BYTES: usize = 128 * 1024;
const MAX_CONFIG_CLIPBOARD_BYTES: usize = 256 * 1024;
const STALE_ATTEMPT: &str = "The SSH connect attempt is no longer current.";
const NO_BINDING: &str = "当前没有已连接的 SSH 目标。";

fn require_main<R: Runtime>(window: &WebviewWindow<R>) -> CommandResult<()> {
    if window.label() == MAIN_LABEL {
        Ok(())
    } else {
        Err(REFUSED_METHOD.to_owned())
    }
}

fn text_field<'a>(params: &'a Value, key: &str) -> Option<&'a str> {
    params.get(key).and_then(Value::as_str)
}

/// The generic call: one backend method from the main window's list, with the
/// host watching connect attempts so terminal windows follow the binding.
#[tauri::command]
pub async fn backend_call<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    method: String,
    params: Value,
) -> CommandResult<Value> {
    require_main(&window)?;
    if !main_window_may_call(&method, &params) {
        return Err(REFUSED_METHOD.to_owned());
    }
    match method.as_str() {
        "ssh.binding.disconnect" => {
            let binding = text_field(&params, "bindingHandle")
                .unwrap_or_default()
                .to_owned();
            host.binding.lock().disconnect(&binding);
            host.close_children_for_binding(&app, &binding).await;
            host.bridge.call(&method, params).await
        }
        "ssh.connect.start" => {
            let started = host.bridge.call(&method, params).await?;
            if let Some(attempt) = text_field(&started, "attemptHandle") {
                host.binding.lock().start_connect(attempt);
            }
            Ok(started)
        }
        "ssh.attempt.cancel" => {
            let attempt = text_field(&params, "attemptHandle")
                .unwrap_or_default()
                .to_owned();
            let result = host.bridge.call(&method, params).await?;
            host.binding.lock().cancel_attempt(&attempt);
            Ok(result)
        }
        "ssh.attempt.get" | "ssh.host-key.confirm" | "ssh.mfa.respond" => {
            let attempt = text_field(&params, "attemptHandle")
                .unwrap_or_default()
                .to_owned();
            let status = host.bridge.call(&method, params).await?;
            let transition = host.binding.lock().observe(&attempt, &status);
            match transition {
                Transition::Stale => Err(STALE_ATTEMPT.to_owned()),
                Transition::Accepted {
                    binding_handle,
                    previous_binding_handle: Some(previous),
                } if previous != binding_handle => {
                    host.close_children_for_binding(&app, &previous).await;
                    Ok(status)
                }
                _ => Ok(status),
            }
        }
        _ => host.bridge.call(&method, params).await,
    }
}

#[tauri::command]
pub async fn connections_import<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
) -> CommandResult<Value> {
    require_main(&window)?;
    let filter = Filter {
        name: "LovelyHawk 连接 JSON",
        extensions: &["json"],
    };
    let Some(path) = local_files::choose(
        &window,
        "导入 LovelyHawk 连接",
        DialogKind::OpenFile,
        Some(filter),
    )
    .await
    else {
        return Ok(
            json!({ "cancelled": true, "imported": 0, "skippedExisting": 0, "skippedDuplicate": 0 }),
        );
    };
    if !local_files::has_extension(&path, "json") {
        return Err("请选择 .json 连接文件。".to_owned());
    }
    let result = host
        .bridge
        .call_with_code(
            "connections.import-file",
            json!({ "path": path.to_string_lossy() }),
        )
        .await
        .map_err(|(code, _)| connection_import_failure(code).to_owned())?;
    let mut merged = Map::new();
    merged.insert("cancelled".to_owned(), Value::Bool(false));
    if let Value::Object(fields) = result {
        merged.extend(fields);
    }
    Ok(Value::Object(merged))
}

#[tauri::command]
pub async fn connections_export<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
) -> CommandResult<Value> {
    require_main(&window)?;
    let filter = Filter {
        name: "LovelyHawk 连接 JSON",
        extensions: &["json"],
    };
    let kind = DialogKind::Save {
        default_name: "lovelyhawk-connections.json",
    };
    let Some(path) = local_files::choose(&window, "导出 LovelyHawk 连接", kind, Some(filter)).await
    else {
        return Ok(json!({ "cancelled": true, "count": 0, "fileName": null }));
    };
    if !local_files::has_extension(&path, "json") {
        return Err("连接文件必须使用 .json 扩展名。".to_owned());
    }
    // The save dialog may already have asked "replace?"; exports still only
    // create new files. The backend refuses too, without saying why.
    if std::fs::symlink_metadata(&path).is_ok() {
        return Err(local_files::FILE_EXISTS.to_owned());
    }
    let result = host
        .bridge
        .call_with_code(
            "connections.export-file",
            json!({ "path": path.to_string_lossy() }),
        )
        .await
        .map_err(|_| CONNECTION_EXPORT_FAILED.to_owned())?;
    Ok(json!({
        "cancelled": false,
        "count": result.get("count").cloned().unwrap_or(Value::from(0)),
        "fileName": local_files::display_name(&path, "lovelyhawk-connections.json"),
    }))
}

const CONNECTION_EXPORT_FAILED: &str =
    "连接导出没有完成。请确认目标目录可写且没有同名文件；详细原因见应用日志。";

/// The backend answers import failures in English with a code; the operator
/// gets what the code means. A refused file is never partly imported.
fn connection_import_failure(code: &str) -> &'static str {
    match code {
        "connection-invalid" => {
            "这个文件不是有效的连接导出，或超出上限（2 MiB、1000 个连接）。没有导入任何连接。"
        }
        "connections-store-unreadable" => {
            "本机保存的连接文件（data 中的 connections.json）读不出来，没有导入任何连接。程序没有改动它；data/backups 中可能有之前的备份。"
        }
        _ => "连接导入没有完成。请刷新连接列表核对结果；详细原因见应用日志。",
    }
}

/// How many editor windows hold unsaved text. Disconnecting or switching the
/// target closes them, so the main page asks before it does either.
#[tauri::command]
pub fn unsaved_editor_count<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
) -> CommandResult<Value> {
    require_main(&window)?;
    Ok(json!({ "count": host.children.lock().unsaved_count() }))
}

/// The editor's limit for a key or certificate path.
const MAX_CREDENTIAL_PATH_BYTES: usize = 4_096;

/// Fills a key or certificate path from the system's own file dialog, so the
/// operator does not have to type an absolute path. Only the chosen path
/// leaves: the file is not read here, and the connection keeps a path exactly
/// as it would if it had been typed.
#[tauri::command]
pub async fn connection_credential_file<R: Runtime>(
    window: WebviewWindow<R>,
    kind: String,
) -> CommandResult<Value> {
    require_main(&window)?;
    let (title, private_key) = match kind.as_str() {
        "private-key" => ("选择 SSH 私钥文件", true),
        "certificate" => ("选择 OpenSSH 用户证书", false),
        _ => return Err("文件类型无效。".to_owned()),
    };
    let Some(path) = local_files::choose(&window, title, DialogKind::OpenFile, None).await else {
        return Ok(json!({ "path": null }));
    };
    credential_path_text(&path, private_key).map(|text| json!({ "path": text }))
}

fn credential_path_text(path: &std::path::Path, private_key: bool) -> Result<String, String> {
    let metadata = std::fs::metadata(path).map_err(|_| "读不到所选文件。".to_owned())?;
    if !metadata.is_file() {
        return Err("请选择一个文件，而不是文件夹。".to_owned());
    }
    // The commonest mistake: the public half sits right next to the key.
    if private_key && local_files::has_extension(path, "pub") {
        return Err("这是公钥文件（.pub）。请选择同名但不带 .pub 的私钥文件。".to_owned());
    }
    let text = path
        .to_str()
        .ok_or_else(|| "文件路径里有无法保存的字符，请把文件放到别的位置再选。".to_owned())?;
    if text.len() > MAX_CREDENTIAL_PATH_BYTES {
        return Err("文件路径太长，请把文件放到更短的路径下再选。".to_owned());
    }
    Ok(text.to_owned())
}

/// Picking the replacement class for Java hot update. The file comes from the
/// open dialog and goes straight into core's staging area; the page learns its
/// name, size and hash, never where it was.
#[tauri::command]
pub async fn java_class_stage<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    binding_handle: String,
) -> CommandResult<Value> {
    require_main(&window)?;
    if !opaque_handle(&binding_handle) {
        return Err("类文件请求无效。".to_owned());
    }
    if host.current_binding().as_deref() != Some(binding_handle.as_str()) {
        return Err(NO_BINDING.to_owned());
    }
    let Some(path) = local_files::choose(
        &window,
        "选择替换用的 .class 文件",
        DialogKind::OpenFile,
        Some(Filter {
            name: "Java 类文件",
            extensions: &["class"],
        }),
    )
    .await
    else {
        return Ok(json!({ "staged": false, "class": null }));
    };
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "所选文件名无法识别。".to_owned())?
        .to_owned();
    let staged = host
        .bridge
        .call(
            "java.hot-update.class.stage",
            json!({ "bindingHandle": binding_handle, "localPath": path.to_string_lossy(), "name": name }),
        )
        .await?;
    Ok(json!({ "staged": true, "class": staged }))
}

/// Exporting the case being viewed: the destination comes from the dialog.
#[tauri::command]
pub async fn case_library_export<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    request: Value,
) -> CommandResult<Value> {
    require_main(&window)?;
    let valid = request.as_object().is_some_and(|fields| {
        fields.len() == 2
            && text_field(&request, "action") == Some("export")
            && fields
                .get("snapshotHandle")
                .and_then(Value::as_str)
                .is_some()
    });
    if !valid {
        return Err("案件库请求无效。".to_owned());
    }
    let filter = Filter {
        name: "案件 JSON",
        extensions: &["json"],
    };
    let name = format!("LovelyHawk-case-{}.json", unix_millis());
    let kind = DialogKind::Save {
        default_name: &name,
    };
    let Some(path) = local_files::choose(
        &window,
        "导出当前查看的完整案件 · 请选择新文件名",
        kind,
        Some(filter),
    )
    .await
    else {
        return Ok(Value::Null);
    };
    let mut params = request;
    params["selectedDestination"] = Value::String(path.to_string_lossy().into_owned());
    host.bridge.call("case.library", params).await
}

/// Starting file evidence: the folder comes from the dialog.
#[tauri::command]
pub async fn file_evidence_begin<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    request: Value,
) -> CommandResult<Value> {
    require_main(&window)?;
    let valid = request.as_object().is_some_and(|fields| {
        fields.len() == 3
            && text_field(&request, "action") == Some("begin")
            && ["bindingHandle", "pathHandle"]
                .iter()
                .all(|key| fields.get(*key).and_then(Value::as_str).is_some())
    });
    if !valid {
        return Err("留证请求无效。".to_owned());
    }
    let Some(path) = local_files::choose(
        &window,
        "选择留证目录 · 将创建独立证据文件夹",
        DialogKind::PickFolder,
        None,
    )
    .await
    else {
        return Ok(Value::Null);
    };
    let mut params = request;
    params["selectedDirectory"] = Value::String(path.to_string_lossy().into_owned());
    host.bridge.call("emergency.file-evidence", params).await
}

/// Starting a packet capture kept as evidence: the folder comes from the dialog.
#[tauri::command]
pub async fn packet_capture_evidence_begin<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    request: Value,
) -> CommandResult<Value> {
    require_main(&window)?;
    let valid = request.as_object().is_some_and(|fields| {
        fields.len() == 4
            && text_field(&request, "action") == Some("begin")
            && ["bindingHandle", "interfaceHandle"]
                .iter()
                .all(|key| fields.get(*key).and_then(Value::as_str).is_some())
            && fields.get("input").is_some_and(Value::is_object)
    });
    if !valid {
        return Err("抓包留证请求无效。".to_owned());
    }
    let Some(path) = local_files::choose(
        &window,
        "选择留证目录 · 抓包文件将存进独立证据文件夹",
        DialogKind::PickFolder,
        None,
    )
    .await
    else {
        return Ok(Value::Null);
    };
    let mut params = request;
    params["selectedDirectory"] = Value::String(path.to_string_lossy().into_owned());
    host.bridge.call("packet-capture.evidence", params).await
}

/// Keeping a pod file as evidence: the folder comes from the dialog. The pod
/// is the list's handles and the path the page's, both checked by the backend.
#[tauri::command]
pub async fn pod_file_evidence_begin<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    request: Value,
) -> CommandResult<Value> {
    require_main(&window)?;
    let valid = request.as_object().is_some_and(|fields| {
        fields.len() == 6
            && text_field(&request, "action") == Some("begin")
            && ["bindingHandle", "snapshotHandle", "rowHandle", "path"]
                .iter()
                .all(|key| fields.get(*key).and_then(Value::as_str).is_some())
            && fields
                .get("container")
                .is_some_and(|value| value.is_null() || value.is_string())
    });
    if !valid {
        return Err("Pod 文件留证请求无效。".to_owned());
    }
    let Some(path) = local_files::choose(
        &window,
        "选择留证目录 · Pod 里的文件将存进独立证据文件夹",
        DialogKind::PickFolder,
        None,
    )
    .await
    else {
        return Ok(Value::Null);
    };
    let mut params = request;
    params["selectedDirectory"] = Value::String(path.to_string_lossy().into_owned());
    host.bridge
        .call("kubernetes.pod.file-evidence", params)
        .await
}

/// Export contents are wiped when the host is done writing them.
fn zeroizing_string<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

/// An export payload the backend prepared for the host only.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExportPayload {
    suggested_name: String,
    #[serde(deserialize_with = "zeroizing_string")]
    contents: Zeroizing<String>,
    #[serde(flatten)]
    rest: Map<String, Value>,
}

impl ExportPayload {
    fn parse(value: Value, maximum_bytes: usize) -> CommandResult<Self> {
        let payload: Self =
            serde_json::from_value(value).map_err(|_| "导出内容未通过校验。".to_owned())?;
        if !local_files::is_safe_file_name(&payload.suggested_name)
            || payload.contents.len() > maximum_bytes
        {
            return Err("导出内容未通过校验。".to_owned());
        }
        Ok(payload)
    }

    fn count(&self, key: &str) -> Value {
        self.rest.get(key).cloned().unwrap_or(Value::from(0))
    }
}

#[tauri::command]
pub async fn application_log_export<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    filter: Value,
) -> CommandResult<Value> {
    require_main(&window)?;
    let prepared = host
        .bridge
        .call(
            "application-log.export.prepare",
            json!({ "filter": filter }),
        )
        .await?;
    let payload = ExportPayload::parse(prepared, 256 * 1024)?;
    if !local_files::has_extension(std::path::Path::new(&payload.suggested_name), "log") {
        return Err("导出内容未通过校验。".to_owned());
    }
    let kind = DialogKind::Save {
        default_name: &payload.suggested_name,
    };
    let filter = Filter {
        name: "应用日志",
        extensions: &["log"],
    };
    let Some(path) = local_files::choose(&window, "导出应用日志", kind, Some(filter)).await
    else {
        return Ok(
            json!({ "saved": false, "fileName": null, "entryCount": 0, "truncated": false }),
        );
    };
    if !local_files::has_extension(&path, "log") {
        return Err("诊断日志必须使用 .log 扩展名。".to_owned());
    }
    local_files::write_new_file(&path, payload.contents.as_bytes()).map_err(str::to_owned)?;
    Ok(json!({
        "saved": true,
        "fileName": local_files::display_name(&path, &payload.suggested_name),
        "entryCount": payload.count("entryCount"),
        "truncated": payload.rest.get("truncated").cloned().unwrap_or(Value::Bool(false)),
    }))
}

#[tauri::command]
pub async fn disposal_report_export<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    binding_handle: String,
    report_handle: String,
    format: String,
) -> CommandResult<Value> {
    require_main(&window)?;
    let extension = match format.as_str() {
        "markdown" => "md",
        "html" => "html",
        _ => return Err("报告格式无效。".to_owned()),
    };
    let prepared = host
        .bridge
        .call(
            "disposal-report.export",
            json!({ "bindingHandle": binding_handle, "reportHandle": report_handle, "format": format }),
        )
        .await?;
    let payload = ExportPayload::parse(prepared, 512 * 1024)?;
    if payload.rest.get("format").and_then(Value::as_str) != Some(format.as_str())
        || !local_files::has_extension(std::path::Path::new(&payload.suggested_name), extension)
    {
        return Err("导出内容未通过校验。".to_owned());
    }
    let kind = DialogKind::Save {
        default_name: &payload.suggested_name,
    };
    let filter = Filter {
        name: if extension == "md" {
            "Markdown"
        } else {
            "HTML"
        },
        extensions: &[extension],
    };
    let Some(path) = local_files::choose(&window, "导出处置交付报告", kind, Some(filter)).await
    else {
        return Ok(json!({ "saved": false, "fileName": null, "operationCount": 0 }));
    };
    if !local_files::has_extension(&path, extension) {
        return Err("报告扩展名与所选格式不一致。".to_owned());
    }
    local_files::write_new_file(&path, payload.contents.as_bytes()).map_err(str::to_owned)?;
    Ok(json!({
        "saved": true,
        "fileName": local_files::display_name(&path, &payload.suggested_name),
        "operationCount": payload.count("operationCount"),
    }))
}

/// A listed Pod, Deployment or Node's manifest, written to a new file the
/// operator chooses. The object is named by the list's handles alone; the
/// contents go from the backend to the file and never to the page.
#[tauri::command]
pub async fn kubernetes_manifest_export<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    binding_handle: String,
    snapshot_handle: String,
    row_handle: String,
) -> CommandResult<Value> {
    require_main(&window)?;
    let prepared = host
        .bridge
        .call(
            "kubernetes.manifest.export",
            json!({
                "bindingHandle": binding_handle,
                "snapshotHandle": snapshot_handle,
                "rowHandle": row_handle,
            }),
        )
        .await?;
    // A Node with every image it has pulled is the largest; the core keeps
    // at most 1 MB of YAML, and the header is a few hundred bytes.
    let payload = ExportPayload::parse(prepared, 2 * 1024 * 1024)?;
    if !local_files::has_extension(std::path::Path::new(&payload.suggested_name), "yaml") {
        return Err("导出内容未通过校验。".to_owned());
    }
    let kind = DialogKind::Save {
        default_name: &payload.suggested_name,
    };
    let filter = Filter {
        name: "YAML",
        extensions: &["yaml", "yml"],
    };
    let Some(path) = local_files::choose(&window, "导出 Kubernetes 清单", kind, Some(filter)).await
    else {
        return Ok(json!({ "saved": false, "fileName": null }));
    };
    if !local_files::has_extension(&path, "yaml") && !local_files::has_extension(&path, "yml") {
        return Err("清单文件必须使用 .yaml 或 .yml 扩展名。".to_owned());
    }
    local_files::write_new_file(&path, payload.contents.as_bytes()).map_err(str::to_owned)?;
    Ok(json!({
        "saved": true,
        "fileName": local_files::display_name(&path, &payload.suggested_name),
    }))
}

#[tauri::command]
pub async fn ai_history_export<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    format: String,
) -> CommandResult<Value> {
    require_main(&window)?;
    let extension = match format.as_str() {
        "text" => "txt",
        "json" => "json",
        _ => return Err("导出格式无效。".to_owned()),
    };
    let prepared = host
        .bridge
        .call("ai-history.export", json!({ "format": format }))
        .await?;
    let payload = ExportPayload::parse(prepared, 8 * 1024 * 1024)?;
    let kind = DialogKind::Save {
        default_name: &payload.suggested_name,
    };
    let filter = Filter {
        name: if extension == "txt" {
            "纯文本"
        } else {
            "JSON"
        },
        extensions: &[extension],
    };
    let Some(path) = local_files::choose(&window, "导出 AI 历史", kind, Some(filter)).await
    else {
        return Ok(json!({ "saved": false, "fileName": null, "recordCount": 0 }));
    };
    let chosen = local_files::display_name(&path, "");
    if !local_files::is_safe_file_name(&chosen) {
        return Err("所选文件名不可用。".to_owned());
    }
    local_files::write_new_file(&path, payload.contents.as_bytes()).map_err(str::to_owned)?;
    Ok(json!({ "saved": true, "fileName": chosen, "recordCount": payload.count("recordCount") }))
}

fn config_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConfigArtifact {
    #[serde(default)]
    suggested_name: Option<String>,
    #[serde(deserialize_with = "zeroizing_string")]
    contents: Zeroizing<String>,
}

#[derive(Deserialize)]
struct ConfigCopy {
    artifacts: Vec<ConfigArtifact>,
    /// The backend's copy text: one file as is, several each labelled with
    /// its path, so pasted text still says which file each part belongs to.
    #[serde(deserialize_with = "zeroizing_string")]
    text: Zeroizing<String>,
}

#[tauri::command]
pub async fn config_copy<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    handle: String,
    revision: u64,
) -> CommandResult<Value> {
    require_main(&window)?;
    if !config_identifier(&handle) || revision == 0 {
        return Err("配置复制请求无效。".to_owned());
    }
    let payload = host
        .bridge
        .call(
            "config.quick.copy",
            json!({ "handle": handle, "revision": revision }),
        )
        .await?;
    let copy: ConfigCopy =
        serde_json::from_value(payload).map_err(|_| "配置内容未通过校验。".to_owned())?;
    let text = &copy.text;
    if copy.artifacts.is_empty() || text.is_empty() {
        return Err("配置内容未通过校验。".to_owned());
    }
    if text.len() > MAX_CONFIG_CLIPBOARD_BYTES {
        return Err("配置内容过大，无法复制到剪贴板。".to_owned());
    }
    crate::host::write_clipboard(&app, text)?;
    Ok(json!({ "artifactCount": copy.artifacts.len(), "byteLength": text.len() }))
}

#[tauri::command]
pub async fn config_artifact_export<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    handle: String,
    revision: u64,
    artifact_key: String,
) -> CommandResult<Value> {
    require_main(&window)?;
    if !config_identifier(&handle) || !config_identifier(&artifact_key) || revision == 0 {
        return Err("配置导出请求无效。".to_owned());
    }
    let payload = host
        .bridge
        .call(
            "config.quick.artifact",
            json!({ "handle": handle, "revision": revision, "artifactKey": artifact_key }),
        )
        .await?;
    let artifact: ConfigArtifact =
        serde_json::from_value(payload).map_err(|_| "配置内容未通过校验。".to_owned())?;
    if artifact.contents.len() > 512 * 1024 {
        return Err("配置内容未通过校验。".to_owned());
    }
    let suggested = artifact
        .suggested_name
        .as_deref()
        .map(|name| name.rsplit(['/', '\\']).next().unwrap_or(name))
        .filter(|name| local_files::is_safe_file_name(name))
        .unwrap_or("lovelyhawk-config.txt")
        .to_owned();
    let kind = DialogKind::Save {
        default_name: &suggested,
    };
    let Some(path) = local_files::choose(&window, "导出配置文件", kind, None).await else {
        return Ok(json!({ "saved": false, "fileName": null }));
    };
    local_files::write_new_file(&path, artifact.contents.as_bytes()).map_err(str::to_owned)?;
    Ok(json!({ "saved": true, "fileName": local_files::display_name(&path, &suggested) }))
}

/// Saving every file of a multi-file draft at once: the operator picks a
/// folder, and the backend creates a new directory inside it, named by the
/// generator, holding each file at its relative path. Nothing that exists is
/// ever overwritten.
#[tauri::command]
pub async fn config_bundle_export<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    handle: String,
    revision: u64,
) -> CommandResult<Value> {
    require_main(&window)?;
    if !config_identifier(&handle) || revision == 0 {
        return Err("配置导出请求无效。".to_owned());
    }
    let Some(parent) = local_files::choose(
        &window,
        "选择存放草稿文件夹的位置",
        DialogKind::PickFolder,
        None,
    )
    .await
    else {
        return Ok(json!({ "saved": false, "directoryName": null, "fileCount": null }));
    };
    let result = host
        .bridge
        .call_with_code(
            "config.quick.bundle.export",
            json!({ "handle": handle, "revision": revision, "parentDirectory": parent }),
        )
        .await;
    match result {
        Ok(value) => {
            let directory = value
                .get("directoryName")
                .and_then(Value::as_str)
                .filter(|name| local_files::is_safe_file_name(name));
            let count = value
                .get("fileCount")
                .and_then(Value::as_u64)
                .filter(|count| (2..=3).contains(count));
            match (directory, count) {
                (Some(directory), Some(count)) => {
                    Ok(json!({ "saved": true, "directoryName": directory, "fileCount": count }))
                }
                _ => Err("配置导出结果未通过校验。".to_owned()),
            }
        }
        Err(("configuration-destination-exists", _)) => Err(
            "所选位置已有同名的草稿文件夹。导出只新建、不覆盖；请换一个位置，或先把旧文件夹移走。"
                .to_owned(),
        ),
        Err((code, message)) => Err(format!("{message} ({code})")),
    }
}

/// Opening a local configuration file as a tree: the file comes from the dialog.
#[tauri::command]
pub async fn config_visual_import<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    product: String,
) -> CommandResult<Value> {
    require_main(&window)?;
    let title = match product.as_str() {
        "nginx" => "导入 Nginx 配置文件",
        "apache" => "导入 Apache httpd 配置文件",
        "redis" => "导入 Redis 配置文件",
        "haproxy" => "导入 HAProxy 配置文件",
        "mysql" => "导入 MySQL 选项文件",
        "mariadb" => "导入 MariaDB 选项文件",
        _ => return Err("导入请求无效。".to_owned()),
    };
    let Some(path) = local_files::choose(&window, title, DialogKind::OpenFile, None).await else {
        return Ok(Value::Null);
    };
    host.bridge
        .call(
            "config.visual",
            json!({ "action": "import", "product": product, "selectedPath": path.to_string_lossy() }),
        )
        .await
}

/// Opening a local copy of a catalogued database file: the page names the
/// catalogue entry, the file comes from the dialog.
#[tauri::command]
pub async fn config_visual_import_database<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    artifact_key: String,
) -> CommandResult<Value> {
    require_main(&window)?;
    if !config_identifier(&artifact_key) {
        return Err("导入请求无效。".to_owned());
    }
    let Some(path) =
        local_files::choose(&window, "导入数据库配置文件", DialogKind::OpenFile, None).await
    else {
        return Ok(Value::Null);
    };
    host.bridge
        .call(
            "config.visual",
            json!({ "action": "import-database", "artifactKey": artifact_key, "selectedPath": path.to_string_lossy() }),
        )
        .await
}

/// The whole text of a visual document, to the clipboard. The backend refuses
/// one that holds hidden values.
#[tauri::command]
pub async fn config_visual_copy<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    document_handle: String,
    revision: u64,
) -> CommandResult<Value> {
    require_main(&window)?;
    if !config_identifier(&document_handle) || revision == 0 {
        return Err("配置复制请求无效。".to_owned());
    }
    let payload = host
        .bridge
        .call(
            "config.visual",
            json!({ "action": "export", "documentHandle": document_handle, "revision": revision, "purpose": "copy" }),
        )
        .await?;
    let artifact: ConfigArtifact =
        serde_json::from_value(payload).map_err(|_| "配置内容未通过校验。".to_owned())?;
    if artifact.contents.len() > MAX_CONFIG_CLIPBOARD_BYTES {
        return Err("配置内容过大，无法复制到剪贴板。".to_owned());
    }
    crate::host::write_clipboard(&app, &artifact.contents)?;
    Ok(json!({ "byteLength": artifact.contents.len() }))
}

/// Saving a visual document to a new file the operator names; an existing
/// file is never replaced.
#[tauri::command]
pub async fn config_visual_save<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    document_handle: String,
    revision: u64,
) -> CommandResult<Value> {
    require_main(&window)?;
    if !config_identifier(&document_handle) || revision == 0 {
        return Err("配置保存请求无效。".to_owned());
    }
    let payload = host
        .bridge
        .call(
            "config.visual",
            json!({ "action": "export", "documentHandle": document_handle, "revision": revision, "purpose": "save" }),
        )
        .await?;
    let artifact: ConfigArtifact =
        serde_json::from_value(payload).map_err(|_| "配置内容未通过校验。".to_owned())?;
    if artifact.contents.len() > 4 * 1024 * 1024 {
        return Err("配置内容未通过校验。".to_owned());
    }
    let suggested = artifact
        .suggested_name
        .as_deref()
        .filter(|name| local_files::is_safe_file_name(name))
        .unwrap_or("visual.conf")
        .to_owned();
    let kind = DialogKind::Save {
        default_name: &suggested,
    };
    let Some(path) = local_files::choose(&window, "另存配置文件", kind, None).await else {
        return Ok(json!({ "saved": false, "fileName": null }));
    };
    local_files::write_new_file(&path, artifact.contents.as_bytes()).map_err(str::to_owned)?;
    Ok(json!({ "saved": true, "fileName": local_files::display_name(&path, &suggested) }))
}

#[tauri::command]
pub fn clipboard_write<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    text: String,
) -> CommandResult<()> {
    require_main(&window)?;
    if text.len() > MAX_CLIPBOARD_BYTES {
        return Err("复制内容过大。".to_owned());
    }
    crate::host::write_clipboard(&app, &text)
}

#[tauri::command]
pub fn window_theme<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    theme: String,
    scrim: bool,
) -> CommandResult<theme::WindowTheme> {
    require_main(&window)?;
    let Some(native) = theme::find(&theme) else {
        return Err("主题无效。".to_owned());
    };
    let applied = theme::WindowTheme { theme, scrim };
    *host.theme.lock() = applied.clone();
    let _ = window.set_background_color(Some(theme::color(native.window_background)));
    Ok(applied)
}

// Every command that creates a window is async: a synchronous command runs on
// the main thread, and creating a window there deadlocks on Windows.
#[tauri::command]
pub async fn terminal_window_open<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    host: State<'_, Host>,
) -> CommandResult<WindowLaunch> {
    require_main(&window)?;
    let binding = host
        .current_binding()
        .ok_or_else(|| NO_BINDING.to_owned())?;
    host.open_child(&app, &binding, ChildKind::Terminal)
}

fn opaque_handle(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}

#[tauri::command]
pub async fn container_terminal_open<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    snapshot_handle: String,
    container_handle: String,
    container_name: String,
) -> CommandResult<WindowLaunch> {
    require_main(&window)?;
    if !opaque_handle(&snapshot_handle)
        || !opaque_handle(&container_handle)
        || container_name.is_empty()
        || container_name.len() > 256
        || container_name.chars().any(char::is_control)
    {
        return Err("容器终端请求无效。".to_owned());
    }
    let binding = host
        .current_binding()
        .ok_or_else(|| NO_BINDING.to_owned())?;
    host.open_child(
        &app,
        &binding,
        ChildKind::Container(ContainerScope {
            snapshot_handle,
            container_handle,
            container_name,
        }),
    )
}

#[tauri::command]
pub async fn pod_terminal_open<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    snapshot_handle: String,
    row_handle: String,
    pod_name: String,
    container: Option<String>,
) -> CommandResult<WindowLaunch> {
    require_main(&window)?;
    if !opaque_handle(&snapshot_handle)
        || !opaque_handle(&row_handle)
        || pod_name.is_empty()
        || pod_name.len() > 512
        || pod_name.chars().any(char::is_control)
        || container
            .as_deref()
            .is_some_and(|name| !container_label(name))
    {
        return Err("Pod 终端请求无效。".to_owned());
    }
    let binding = host
        .current_binding()
        .ok_or_else(|| NO_BINDING.to_owned())?;
    host.open_child(
        &app,
        &binding,
        ChildKind::Pod(PodScope {
            snapshot_handle,
            row_handle,
            pod_name,
            container,
        }),
    )
}

/// A Kubernetes container name: a DNS label. Whether it is one of the pod's
/// containers is the backend's to check against the list it made.
fn container_label(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-')
}

/// The page's answer to "may the window close?".
#[tauri::command]
pub async fn close_decision<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    request: u64,
    allowed: bool,
) -> CommandResult<()> {
    require_main(&window)?;
    if host.close.resolve(request, allowed) {
        host.close_all_children(&app).await;
        let _ = window.close();
    }
    Ok(())
}

#[tauri::command]
pub fn renderer_ready<R: Runtime>(
    window: WebviewWindow<R>,
    host: State<'_, Host>,
) -> CommandResult<()> {
    require_main(&window)?;
    if host
        .renderer_ready
        .swap(true, std::sync::atomic::Ordering::SeqCst)
    {
        return Ok(());
    }
    smoke::write_requested_marker().map_err(|error| {
        tracing::error!(%error, "smoke marker request refused");
        "就绪标记写入失败。".to_owned()
    })
}

fn unix_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_failures_are_told_in_plain_chinese() {
        let refused = connection_import_failure("connection-invalid");
        assert!(refused.contains("没有导入任何连接"));
        // Only a refused file is known to have changed nothing.
        let other = connection_import_failure("connections-operation-failed");
        assert!(!other.contains("没有导入任何连接"));
        assert!(other.contains("刷新"));
        for message in [refused, other, CONNECTION_EXPORT_FAILED] {
            assert!(!message.is_ascii());
            assert!(!message.contains("connection"));
        }
    }

    #[test]
    fn a_chosen_credential_must_be_a_file_and_not_the_public_half() {
        let root =
            std::env::temp_dir().join(format!("lovelyhawk-credential-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let key = root.join("id_ed25519");
        let public = root.join("id_ed25519.pub");
        std::fs::write(&key, b"key").unwrap();
        std::fs::write(&public, b"public").unwrap();

        assert_eq!(
            credential_path_text(&key, true).unwrap(),
            key.to_str().unwrap()
        );
        assert!(
            credential_path_text(&public, true)
                .unwrap_err()
                .contains(".pub")
        );
        // A certificate is itself a .pub file.
        assert_eq!(
            credential_path_text(&public, false).unwrap(),
            public.to_str().unwrap()
        );
        assert!(
            credential_path_text(&root, true)
                .unwrap_err()
                .contains("文件夹")
        );
        assert!(credential_path_text(&root.join("missing"), true).is_err());
        std::fs::remove_dir_all(&root).unwrap();
    }
}
