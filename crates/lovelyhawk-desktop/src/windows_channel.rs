//! A presentation window for the main Windows workspace. It receives a bounded
//! view and submits closed intents to the workspace's existing operation gate.
//! It has no backend, SSH, filesystem or target-selection permission.
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tauri::{AppHandle, Manager, Runtime, State, WebviewWindow};

use crate::host::{Host, MAIN_LABEL};

pub const LABEL: &str = "windows-channel";
const UNAVAILABLE: &str = "通道窗口所属的工作台已关闭，请从主窗口重新打开。";
const CHANGED: &str = "连接或操作状态已变化，请核对目标后重新操作。";

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tab {
    #[default]
    Tasks,
    Files,
    Command,
    Logs,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Collection {
    Overview,
    Baseline,
    Processes,
    Network,
    Startup,
    Accounts,
    Logs,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Action {
    Run {
        command: String,
    },
    Send {
        text: String,
    },
    Save {
        #[serde(rename = "fileId")]
        file_id: String,
    },
    Collect {
        key: Collection,
    },
    CancelBatch,
    Unregister,
}
impl Action {
    fn valid(&self) -> bool {
        match self {
            Self::Run { command } => {
                text(command, 16_384) && !command.trim().is_empty() && !command.contains('\0')
            }
            Self::Send { text: message } => {
                text(message, 8192) && !message.trim().is_empty() && !message.contains('\0')
            }
            Self::Save { file_id } => uuid(file_id),
            _ => true,
        }
    }
    fn remote(&self) -> bool {
        matches!(
            self,
            Self::Run { .. } | Self::Send { .. } | Self::Collect { .. }
        )
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct View {
    hostname: String,
    connected: bool,
    #[serde(deserialize_with = "required_option")]
    busy: Option<String>,
    #[serde(deserialize_with = "required_option")]
    batch: Option<Batch>,
    history: Vec<History>,
    registered: bool,
    messages_sent: u64,
    messages_received: u64,
    logs: Vec<Log>,
    files: Vec<File>,
    saved_files: Vec<String>,
    can_save: bool,
    #[serde(deserialize_with = "required_option")]
    output: Option<Output>,
    #[serde(deserialize_with = "required_option")]
    suggestion: Option<Suggestion>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Batch {
    done: u32,
    total: u32,
    stopping: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct History {
    key: Collection,
    #[serde(deserialize_with = "required_option")]
    time: Option<String>,
    #[serde(deserialize_with = "required_option")]
    error: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Log {
    timestamp: String,
    direction: String,
    kind: String,
    summary: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct File {
    file_id: String,
    name: String,
    size_bytes: u64,
    sha256: String,
    verified: bool,
    received_at: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Output {
    command: String,
    output: String,
    time: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Suggestion {
    id: String,
    request: u64,
}
fn text(v: &str, max: usize) -> bool {
    v.len() <= max
}
fn optional(v: &Option<String>, max: usize) -> bool {
    v.as_deref().is_none_or(|v| text(v, max))
}
fn uuid(v: &str) -> bool {
    v.len() == 36 && uuid::Uuid::parse_str(v).is_ok()
}
fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Notification {
    message: String,
    severity: Severity,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum Severity {
    Info,
    Error,
}
impl View {
    fn valid(&self) -> bool {
        text(&self.hostname, 1024)
            && optional(&self.busy, 4096)
            && self
                .batch
                .as_ref()
                .is_none_or(|v| v.done <= v.total && v.total <= 32)
            && self.history.len() <= 7
            && self
                .history
                .iter()
                .all(|v| optional(&v.time, 128) && optional(&v.error, 16_384))
            && self.messages_sent <= 9_007_199_254_740_991
            && self.messages_received <= 9_007_199_254_740_991
            && self.logs.len() <= 256
            && self.logs.iter().all(|v| {
                text(&v.timestamp, 128)
                    && text(&v.direction, 128)
                    && text(&v.kind, 128)
                    && text(&v.summary, 16_384)
            })
            && self.files.len() <= 32
            && self.files.iter().all(|v| {
                uuid(&v.file_id)
                    && text(&v.name, 4096)
                    && v.size_bytes <= 9_007_199_254_740_991
                    && v.sha256.len() == 64
                    && v.sha256.bytes().all(|b| b.is_ascii_hexdigit())
                    && text(&v.received_at, 128)
            })
            && self.saved_files.len() <= 32
            && self.saved_files.iter().all(|v| uuid(v))
            && self.output.as_ref().is_none_or(|v| {
                text(&v.command, 16_384) && text(&v.output, 16 * 1024 * 1024) && text(&v.time, 128)
            })
            && self
                .suggestion
                .as_ref()
                .is_none_or(|v| text(&v.id, 128) && v.request <= 9_007_199_254_740_991)
    }
}

#[derive(Debug, Default)]
pub struct ChannelState {
    owner: Option<String>,
    session: Option<String>,
    view: Option<View>,
    revision: u64,
    binding: u64,
    tab: Tab,
    open_request: u64,
    next_id: u64,
    dirty: bool,
    draft_revision: u64,
    pending: Option<Pending>,
    completion: Option<(u64, bool)>,
    notifications: Vec<Notification>,
}
#[derive(Debug)]
struct Pending {
    id: u64,
    session: Option<String>,
    action: Action,
    taken: bool,
    created: Instant,
}
impl ChannelState {
    /// A native save dialog belongs to this window only for the receipt it
    /// actually submitted and the workspace has already claimed.
    pub fn owns_save(&self, file_id: &str) -> bool {
        self.owner.is_some() && self.pending.as_ref().is_some_and(|pending| {
            pending.taken && matches!(&pending.action, Action::Save { file_id: requested } if requested == file_id)
        })
    }
    fn owner(&self, owner: &str) -> Result<(), String> {
        if self.owner.as_deref() == Some(owner) {
            Ok(())
        } else {
            Err(UNAVAILABLE.into())
        }
    }
    fn attach(&mut self) -> Result<String, String> {
        if self.owner.is_some() {
            return Err("通道工作台仍在使用，请先关闭原工作台。".into());
        }
        let owner = uuid::Uuid::new_v4().to_string();
        self.owner = Some(owner.clone());
        self.binding += 1;
        Ok(owner)
    }
    fn sync(&mut self, session: Option<String>, view: View) -> Result<(), String> {
        if !view.valid()
            || session.as_ref().is_some_and(|s| !uuid(s))
            || view.connected != session.is_some()
        {
            return Err("通道视图无效或超过大小限制。".into());
        }
        if self.session != session {
            self.binding += 1;
            if let Some(pending) = self.pending.take() {
                self.completion = Some((pending.id, false));
            }
        }
        self.session = session;
        self.view = Some(view);
        self.revision += 1;
        Ok(())
    }
    fn enqueue(&mut self, binding: u64, action: Action) -> Result<u64, String> {
        let view = self.view.as_ref().ok_or(UNAVAILABLE)?;
        if self.owner.is_none() || self.binding != binding || !action.valid() {
            return Err(CHANGED.into());
        }
        if self.pending.is_some() || (view.busy.is_some() && !matches!(action, Action::CancelBatch))
        {
            return Err("当前任务尚未结束，请稍后再试。".into());
        }
        if action.remote() && !view.connected {
            return Err("远程通道尚未连接。".into());
        }
        if let Action::Save { file_id } = &action
            && (!view.can_save
                || !view
                    .files
                    .iter()
                    .any(|f| f.file_id == *file_id && f.verified))
        {
            return Err("文件已过期或尚未通过校验，请重新查看接收文件。".into());
        }
        self.next_id += 1;
        self.pending = Some(Pending {
            id: self.next_id,
            session: self.session.clone(),
            action,
            taken: false,
            created: Instant::now(),
        });
        Ok(self.next_id)
    }
    fn poll(&mut self, take: bool) -> Value {
        if self
            .pending
            .as_ref()
            .is_some_and(|p| !p.taken && p.created.elapsed() > Duration::from_secs(5))
        {
            let p = self.pending.take().expect("pending checked");
            self.completion = Some((p.id, false));
        }
        let work = self.pending.as_mut().filter(|p| take && !p.taken).map(|p| {
            p.taken = true;
            json!({ "id": p.id, "sessionId": p.session, "action": p.action })
        });
        let notifications = if take {
            std::mem::take(&mut self.notifications)
        } else {
            Vec::new()
        };
        json!({ "dirty": self.dirty, "draftRevision": self.draft_revision, "pending": self.pending.is_some(), "work": work, "notifications": notifications })
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum OwnerRequest {
    Attach,
    Sync {
        owner: String,
        #[serde(rename = "sessionId", deserialize_with = "required_option")]
        session_id: Option<String>,
        view: Box<View>,
    },
    Open {
        owner: String,
        tab: Tab,
    },
    Poll {
        owner: String,
        take: bool,
    },
    Finish {
        owner: String,
        id: u64,
        ok: bool,
    },
    Release {
        owner: String,
        #[serde(rename = "expectedDraft", deserialize_with = "required_option")]
        expected_draft: Option<u64>,
    },
}

// Async because Open creates a WebView2 window.
#[tauri::command]
pub async fn windows_channel_owner<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    request: OwnerRequest,
) -> Result<Value, String> {
    if window.label() != MAIN_LABEL {
        return Err(crate::backend_bridge::REFUSED_METHOD.into());
    }
    match request {
        OwnerRequest::Attach => Ok(json!(host.channel.lock().attach()?)),
        OwnerRequest::Sync {
            owner,
            session_id,
            view,
        } => {
            let mut channel = host.channel.lock();
            channel.owner(&owner)?;
            channel.sync(session_id, *view)?;
            Ok(Value::Null)
        }
        OwnerRequest::Open { owner, tab } => {
            {
                let mut channel = host.channel.lock();
                channel.owner(&owner)?;
                channel.tab = tab;
                channel.open_request += 1;
            }
            host.open_channel(&app)?;
            Ok(Value::Null)
        }
        OwnerRequest::Poll { owner, take } => {
            let mut channel = host.channel.lock();
            channel.owner(&owner)?;
            Ok(channel.poll(take))
        }
        OwnerRequest::Finish { owner, id, ok } => {
            let mut channel = host.channel.lock();
            channel.owner(&owner)?;
            if channel
                .pending
                .as_ref()
                .is_some_and(|p| p.id == id && p.taken)
            {
                channel.pending = None;
                channel.completion = Some((id, ok));
            }
            Ok(Value::Null)
        }
        OwnerRequest::Release {
            owner,
            expected_draft,
        } => {
            {
                let mut channel = host.channel.lock();
                channel.owner(&owner)?;
                if channel.pending.is_some()
                    || expected_draft.is_some_and(|revision| channel.draft_revision != revision)
                {
                    return Err("确认期间草稿或任务状态已变化，请重新核对后再离开。".into());
                }
                channel.owner = None;
                channel.view = None;
                channel.session = None;
                channel.pending = None;
                channel.completion = None;
                channel.dirty = false;
                channel.notifications.clear();
            }
            if let Some(child) = app.get_webview_window(LABEL) {
                let _ = child.destroy();
            }
            Ok(Value::Null)
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ChildRequest {
    Read { after: u64 },
    Act { binding: u64, action: Action },
    Dirty { dirty: bool },
    Copy { text: String },
    Notify { notification: Notification },
}

#[tauri::command]
pub async fn windows_channel_child<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    host: State<'_, Host>,
    request: ChildRequest,
) -> Result<Value, String> {
    if window.label() != LABEL {
        return Err(crate::backend_bridge::REFUSED_METHOD.into());
    }
    if host.channel.lock().owner.is_none() {
        return Err(UNAVAILABLE.into());
    }
    match request {
        ChildRequest::Notify { notification } => {
            let mut channel = host.channel.lock();
            if notification.message.len() > 4096 || channel.notifications.len() >= 16 {
                return Err("通知内容过长或正在等待主窗口接收。".into());
            }
            channel.notifications.push(notification);
            Ok(Value::Null)
        }
        ChildRequest::Read { after } => {
            let channel = host.channel.lock();
            Ok(
                json!({ "revision": channel.revision, "binding": channel.binding,
                "theme": host.theme.lock().theme, "tab": channel.tab, "openRequest": channel.open_request,
                "view": if after == channel.revision { None } else { channel.view.as_ref() },
                "completion": channel.completion.map(|(id, ok)| json!({ "id": id, "ok": ok })) }),
            )
        }
        ChildRequest::Act { binding, action } => {
            // Check the live channel as well as the displayed state. The child
            // never supplies a target; its confirmation only names this view.
            if action.remote() {
                let session = host.channel.lock().session.clone();
                let result = host
                    .bridge
                    .call("windows.incident", json!({ "action": "status" }))
                    .await
                    .map_err(|_| CHANGED)?;
                if session.is_none()
                    || result["status"]["channelConnected"] != true
                    || result["status"]["sessionId"].as_str() != session.as_deref()
                {
                    return Err(CHANGED.into());
                }
            }
            Ok(json!(host.channel.lock().enqueue(binding, action)?))
        }
        ChildRequest::Dirty { dirty } => {
            let mut channel = host.channel.lock();
            channel.dirty = dirty;
            channel.draft_revision += 1;
            Ok(Value::Null)
        }
        ChildRequest::Copy { text } => {
            if text.len() > 128 * 1024 {
                return Err("内容超过 128 KB 剪贴板上限，请缩小选择范围。".into());
            }
            crate::host::write_clipboard(&app, &text)?;
            Ok(Value::Null)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const SESSION: &str = "00000000-0000-4000-8000-000000000001";
    fn view(connected: bool) -> View {
        serde_json::from_value(json!({ "hostname": "fixture", "connected": connected, "busy": null, "batch": null, "history": [], "registered": false,
            "messagesSent": 0, "messagesReceived": 0, "logs": [], "files": [], "savedFiles": [], "canSave": true, "output": null, "suggestion": null })).unwrap()
    }
    fn state() -> ChannelState {
        let mut state = ChannelState::default();
        state.attach().unwrap();
        state.sync(Some(SESSION.into()), view(true)).unwrap();
        state
    }
    #[test]
    fn old_confirmations_and_queued_actions_do_not_survive_a_session_change() {
        let mut state = state();
        let binding = state.binding;
        let id = state
            .enqueue(
                binding,
                Action::Run {
                    command: "whoami".into(),
                },
            )
            .unwrap();
        state.sync(None, view(false)).unwrap();
        assert!(state.pending.is_none());
        assert_eq!(state.completion, Some((id, false)));
        state.sync(Some(SESSION.into()), view(true)).unwrap();
        assert!(
            state
                .enqueue(
                    binding,
                    Action::Run {
                        command: "whoami".into()
                    }
                )
                .is_err()
        );
    }
    #[test]
    fn one_action_is_taken_once_and_duplicate_clicks_are_refused() {
        let mut state = state();
        state
            .enqueue(
                state.binding,
                Action::Send {
                    text: "test".into(),
                },
            )
            .unwrap();
        assert!(
            state
                .enqueue(
                    state.binding,
                    Action::Send {
                        text: "test".into()
                    }
                )
                .is_err()
        );
        assert!(!state.poll(true)["work"].is_null());
        assert!(state.poll(true)["work"].is_null());
        assert_eq!(state.poll(false)["pending"], true);
    }
    #[test]
    fn stale_unclaimed_action_is_never_executed() {
        let mut state = state();
        let id = state.enqueue(state.binding, Action::Unregister).unwrap();
        state.pending.as_mut().unwrap().created = Instant::now() - Duration::from_secs(6);
        assert!(state.poll(true)["work"].is_null());
        assert_eq!(state.completion, Some((id, false)));
    }
    #[test]
    fn busy_work_can_only_stop_subsequent_batch_items() {
        let mut state = state();
        let mut busy = view(true);
        busy.busy = Some("collecting".into());
        state.sync(Some(SESSION.into()), busy).unwrap();
        assert!(state.enqueue(state.binding, Action::Unregister).is_err());
        assert!(state.enqueue(state.binding, Action::CancelBatch).is_ok());
    }
    #[test]
    fn exact_requests_refuse_arbitrary_paths_targets_and_methods() {
        for value in [
            json!({ "kind": "run", "command": "whoami", "sessionId": SESSION }),
            json!({ "kind": "collect", "key": "delete-file" }),
            json!({ "kind": "backend-call", "method": "anything" }),
        ] {
            assert!(serde_json::from_value::<Action>(value).is_err());
        }
        assert!(
            !Action::Save {
                file_id: "C:\\secret".into()
            }
            .valid()
        );
        assert!(
            !Action::Run {
                command: "汉".repeat(6000)
            }
            .valid()
        );
        assert!(
            serde_json::from_value::<ChildRequest>(
                json!({ "kind": "read", "after": 0, "owner": SESSION })
            )
            .is_err()
        );
    }
    #[test]
    fn snapshot_and_receipt_boundaries_are_enforced() {
        let mut state = state();
        let mut excessive = view(true);
        excessive.output = Some(Output {
            command: "query".into(),
            output: "x".repeat(16 * 1024 * 1024 + 1),
            time: "now".into(),
        });
        assert!(state.sync(Some(SESSION.into()), excessive).is_err());
        assert!(state.sync(None, view(true)).is_err());
        assert!(
            state
                .enqueue(
                    state.binding,
                    Action::Save {
                        file_id: SESSION.into()
                    }
                )
                .is_err()
        );
        assert!(state.owner("not-the-owner").is_err());
        assert!(state.attach().is_err());
        let mut incomplete = serde_json::to_value(view(true)).unwrap();
        incomplete.as_object_mut().unwrap().remove("output");
        assert!(serde_json::from_value::<View>(incomplete).is_err());
        assert!(
            serde_json::from_value::<OwnerRequest>(json!({ "kind": "release", "owner": SESSION }))
                .is_err()
        );
    }
    #[test]
    fn observing_close_state_does_not_consume_global_notifications() {
        let mut state = state();
        state.notifications.push(Notification {
            message: "copied".into(),
            severity: Severity::Info,
        });
        assert_eq!(state.poll(false)["notifications"], json!([]));
        assert_eq!(state.poll(true)["notifications"][0]["message"], "copied");
        assert_eq!(state.poll(true)["notifications"], json!([]));
    }
    #[test]
    fn a_save_dialog_is_owned_only_by_the_claimed_receipt_request() {
        let mut state = state();
        let mut snapshot = view(true);
        snapshot.files.push(File {
            file_id: SESSION.into(),
            name: "evidence.txt".into(),
            size_bytes: 4,
            sha256: "a".repeat(64),
            verified: true,
            received_at: "now".into(),
        });
        state.sync(Some(SESSION.into()), snapshot).unwrap();
        state
            .enqueue(
                state.binding,
                Action::Save {
                    file_id: SESSION.into(),
                },
            )
            .unwrap();
        assert!(!state.owns_save(SESSION));
        state.poll(true);
        assert!(state.owns_save(SESSION));
        assert!(!state.owns_save("00000000-0000-4000-8000-000000000002"));
        state.owner = None;
        assert!(!state.owns_save(SESSION));
    }
    #[test]
    fn channel_page_and_permissions_are_separate_from_ssh_and_main_windows() {
        use crate::host::Page;
        let url = tauri::Url::parse("https://tauri.localhost/terminal.html?window=windows-channel")
            .unwrap();
        assert!(Page::Channel.allows(&url));
        assert!(!Page::Child.allows(&url));
        assert!(!Page::Main.allows(&url));
        assert!(
            !Page::Channel.allows(
                &tauri::Url::parse(
                    "https://tauri.localhost/terminal.html?window=windows-channel&target=other"
                )
                .unwrap()
            )
        );
        let capability: Value =
            serde_json::from_str(include_str!("../capabilities/windows-channel.json")).unwrap();
        assert_eq!(capability["windows"], json!([LABEL]));
        let permissions = capability["permissions"].as_array().unwrap();
        assert!(permissions.contains(&json!("allow-windows-channel-child")));
        for denied in [
            "allow-backend-call",
            "allow-windows-channel-owner",
            "allow-terminal-open",
            "allow-windows-file-save",
        ] {
            assert!(!permissions.contains(&json!(denied)));
        }
    }
}
