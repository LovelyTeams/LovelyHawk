//! The one path from a window to the backend.
//!
//! The backend links into this process, but it keeps the exact contract the
//! stdio boundary had: the same method table, parameter parsing, error codes
//! and size bounds. What changes is who may ask for what: the main window
//! reaches a fixed list of methods, and nothing that names a local path or
//! returns an export payload is on it. Those go through host commands that open
//! the system dialog and write the file here, so no page ever holds a local
//! path or a full export.
//!
//! Calls run one at a time in arrival order within each of four lanes: the
//! terminal windows' shells, their file manager, bounded task controls, and everything else. With a
//! single queue, a 30-second scan in the main window held back every keystroke
//! and output poll of an open terminal until the page gave up on them. The
//! terminal and file APIs re-check their binding and target after every await,
//! so a disconnect from the main lane while one of them waits ends it with
//! "connection gone" instead of a stale result.

use std::sync::Arc;

use lovelyhawk_backend::BackendState;
use serde_json::Value;

/// Methods the main window may call directly.
const MAIN_WINDOW_METHODS: &[&str] = &[
    "app.bootstrap",
    "connections.list",
    "connections.get",
    "connections.create",
    "connections.update",
    "connections.delete.plan",
    "connections.delete.confirm",
    "connections.delete.cancel",
    "ssh.connect.start",
    "ssh.probe.start",
    "ssh.attempt.get",
    "ssh.host-key.confirm",
    "ssh.mfa.respond",
    "ssh.attempt.cancel",
    "ssh.binding.disconnect",
    "system-info.catalog.get",
    "system-info.summary.get",
    "system-info.table.collect",
    "system-info.detail.get",
    "system-info.row.actions.list",
    "system-info.row.inspect",
    "system-info.row.action.plan",
    "system-info.row.action.confirm",
    "system-info.row.action.execute",
    "system-info.row.action.cancel",
    "baseline.catalog.get",
    "baseline.scan",
    "baseline.history.list",
    "baseline.file.read",
    "baseline.action.plan",
    "baseline.action.confirm",
    "baseline.action.execute",
    "baseline.action.cancel",
    "nginx.repair",
    "response.engine",
    "log.rules",
    "ai.assist",
    "java.hot-update",
    "windows.incident",
    "postgresql.runtime",
    "emergency.file-evidence",
    "case.workspace",
    "case.library",
    "check-audit.catalog.get",
    "check-audit.status.collect",
    "check-audit.log.read",
    "check-audit.action.plan",
    "check-audit.action.confirm",
    "check-audit.action.execute",
    "check-audit.action.cancel",
    "log-analysis.sources.discover",
    "log-analysis.source.read",
    "log-analysis.sources.correlate",
    "log-analysis.iocs.search",
    "kubernetes.availability.get",
    "kubernetes.resources.list",
    "kubernetes.resource.detail.get",
    "kubernetes.pod.logs.get",
    "kubernetes.pod.directory.list",
    "kubernetes.pod.file.read",
    "kubernetes.pod.file-evidence",
    "kubernetes.workload.action.plan",
    "kubernetes.workload.action.confirm",
    "kubernetes.workload.action.execute",
    "kubernetes.workload.action.cancel",
    "docker.containers.refresh",
    "docker.collection.get",
    "docker.resource.inspect",
    "docker.security.audit.get",
    "docker.container.logs.get",
    "docker.container.changes.get",
    "docker.container.processes.get",
    "docker.container.action.plan",
    "docker.container.action.confirm",
    "docker.container.action.execute",
    "docker.container.action.cancel",
    "docker.container.file.read",
    "docker.container.directory.list",
    "docker.container.file.plan-write",
    "docker.container.file.plan-copy",
    "emergency-command.catalog.load",
    "emergency-command.run",
    "emergency-command.history.locate",
    "emergency-command.path.inspect",
    "emergency-command.path.plan",
    "emergency-command.path.confirm",
    "emergency-command.path.execute",
    "emergency-command.path.cancel",
    "emergency-command.path.undo",
    "packet-capture.interfaces.list",
    "packet-capture.start",
    "packet-capture.poll",
    "packet-capture.stop",
    "packet-capture.evidence",
    "application-log.list",
    "application-log.level.set",
    "application-log.buffer.clear",
    "application-log.preview.get",
    "integrity.presets.get",
    "integrity.baselines.list",
    "integrity.comparison.start",
    "integrity.comparison.poll",
    "integrity.comparison.cancel",
    "integrity.baseline.create.start",
    "integrity.baseline.create.poll",
    "integrity.baseline.create.cancel",
    "settings.get",
    "settings.save",
    "settings.ai-api-key.replace",
    "settings.ai-api-key.clear.plan",
    "settings.ai-provider.remove.plan",
    "settings.mutation.confirm",
    "settings.mutation.cancel",
    "ai-history.list",
    "ai-history.get",
    "ai-history.remove.plan",
    "ai-history.clear.plan",
    "ai-history.mutation.confirm",
    "ai-history.mutation.cancel",
    "command-history.list",
    "command-history.get",
    "command-history.replay.plan",
    "command-history.remove.plan",
    "command-history.clear.plan",
    "command-history.mutation.confirm",
    "command-history.mutation.cancel",
    "disposal-report.generate",
    "disposal-report.content.get",
    "config.catalog.get",
    "config.quick.generate",
    "config.quick.revise",
    "config.quick.close",
    "config.visual",
    "security-reference.set-favorites",
    "notes.list",
    "notes.get",
    "notes.create",
    "notes.update",
    "notes.set-pinned",
    "notes.add-tag",
    "notes.remove-tag",
    "notes.delete.plan",
    "notes.delete.confirm",
    "notes.delete.cancel",
    "notes.export",
];

/// Why the host refused a call before it reached the backend.
pub const REFUSED_METHOD: &str = "这个窗口不能执行该操作。";

/// Whether the main window may send `method` with `params` as written.
///
/// Three methods carry a local path only for one action each; for those the
/// host fills the path itself after the system dialog, so a page sending that
/// action, or the path field on any action, is refused here.
pub fn main_window_may_call(method: &str, params: &Value) -> bool {
    if !MAIN_WINDOW_METHODS.contains(&method) {
        return false;
    }
    let action = params.get("action").and_then(Value::as_str);
    match method {
        "case.library" => action != Some("export") && params.get("selectedDestination").is_none(),
        "emergency.file-evidence" | "packet-capture.evidence" | "kubernetes.pod.file-evidence" => {
            action != Some("begin") && params.get("selectedDirectory").is_none()
        }
        // Reading a local file and handing out the whole text are the host's:
        // one carries a path, the other the contents.
        "config.visual" => {
            !matches!(action, Some("import" | "import-database" | "export"))
                && params.get("selectedPath").is_none()
                && params.get("purpose").is_none()
        }
        _ => true,
    }
}

/// Which queue a call waits in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lane {
    Main = 0,
    Terminal = 1,
    Files = 2,
    /// Task status and cancellation must not wait behind the operation they control.
    Control = 3,
}

fn lane_for(method: &str) -> Lane {
    if method.starts_with("terminal.")
        || method == "docker.container.terminal.open"
        || method == "kubernetes.pod.terminal.open"
    {
        Lane::Terminal
    } else if method == "sftp-browser.transfer.cancel" {
        Lane::Control
    } else if method.starts_with("sftp-browser.") {
        Lane::Files
    } else {
        Lane::Main
    }
}

fn lane_for_request(method: &str, params: &Value) -> Lane {
    // Only in-memory status/cancel actions bypass the main queue. The backend
    // still validates the complete request and its session; writes stay queued.
    if method == "windows.incident"
        && matches!(
            params.get("action").and_then(Value::as_str),
            Some("status" | "baseline-plan-progress" | "cancel-baseline-plan")
        )
    {
        Lane::Control
    } else if method == "response.engine"
        && matches!(
            params.get("action").and_then(Value::as_str),
            Some("poll-fix" | "cancel-fix" | "poll-scan")
        )
    {
        // A poll or cancel must not queue behind the work it follows.
        Lane::Control
    } else {
        lane_for(method)
    }
}

/// The backend plus one single-file queue per lane.
#[derive(Debug, Clone)]
pub struct BackendBridge {
    state: Arc<BackendState>,
    lanes: [Arc<tokio::sync::Mutex<()>>; 4],
}

impl BackendBridge {
    pub fn new(state: Arc<BackendState>) -> Self {
        Self {
            state,
            lanes: std::array::from_fn(|_| Arc::new(tokio::sync::Mutex::new(()))),
        }
    }

    /// Runs one call after every call in its lane that arrived before it.
    ///
    /// The work runs on its own task, so a window that stops waiting — closed,
    /// navigated or timed out — does not cancel a change halfway through; the
    /// backend finishes it and its journal stays whole, as it did when a
    /// separate process kept running after Electron stopped listening.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        self.call_with_code(method, params)
            .await
            .map_err(|(code, message)| format!("{message} ({code})"))
    }

    /// The same call, keeping the backend's error code apart from its message
    /// so a host command can turn a known failure into a sentence for the
    /// operator.
    pub async fn call_with_code(
        &self,
        method: &str,
        params: Value,
    ) -> Result<Value, (&'static str, &'static str)> {
        let state = Arc::clone(&self.state);
        let queue = Arc::clone(&self.lanes[lane_for_request(method, &params) as usize]);
        let method = method.to_owned();
        let task = tokio::spawn(async move {
            let _turn = queue.lock().await;
            state.call(&method, params).await
        });
        match task.await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err((error.code, error.message)),
            Err(_) => Err(("backend-task-failed", "LovelyHawk 后端操作意外中止。")),
        }
    }

    /// Waits for every lane to drain, always in the same order, then stops.
    pub async fn shutdown(&self) {
        let _main = self.lanes[Lane::Main as usize].lock().await;
        let _terminal = self.lanes[Lane::Terminal as usize].lock().await;
        let _files = self.lanes[Lane::Files as usize].lock().await;
        let _control = self.lanes[Lane::Control as usize].lock().await;
        self.state.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn path_and_export_methods_are_not_reachable_from_a_page() {
        for method in [
            "connections.import-file",
            "connections.export-file",
            "windows.evidence.part",
            "sftp-browser.download",
            "sftp-browser.upload.stage",
            "java.hot-update.class.stage",
            "application-log.export.prepare",
            "ai-history.export",
            "disposal-report.export",
            "kubernetes.manifest.export",
            "config.quick.copy",
            "config.quick.artifact",
            "config.quick.bundle.export",
            "terminal.open",
            "terminal.open-directory",
            "terminal.render-snapshot",
            "docker.container.terminal.open",
            "kubernetes.pod.terminal.open",
            "shell.execute",
        ] {
            assert!(!main_window_may_call(method, &json!({})), "{method}");
        }
    }

    #[test]
    fn actions_that_carry_a_local_path_are_refused() {
        assert!(main_window_may_call(
            "case.library",
            &json!({ "action": "list" })
        ));
        assert!(!main_window_may_call(
            "case.library",
            &json!({ "action": "export" })
        ));
        assert!(!main_window_may_call(
            "case.library",
            &json!({ "action": "list", "selectedDestination": "C:\\x.json" })
        ));
        assert!(main_window_may_call(
            "emergency.file-evidence",
            &json!({ "action": "poll" })
        ));
        assert!(!main_window_may_call(
            "emergency.file-evidence",
            &json!({ "action": "begin" })
        ));
        assert!(!main_window_may_call(
            "emergency.file-evidence",
            &json!({ "action": "poll", "selectedDirectory": "C:\\" })
        ));
        assert!(main_window_may_call(
            "packet-capture.evidence",
            &json!({ "action": "poll" })
        ));
        assert!(main_window_may_call(
            "packet-capture.evidence",
            &json!({ "action": "cancel" })
        ));
        assert!(!main_window_may_call(
            "packet-capture.evidence",
            &json!({ "action": "begin" })
        ));
        assert!(!main_window_may_call(
            "packet-capture.evidence",
            &json!({ "action": "cancel", "selectedDirectory": "C:\\" })
        ));
        // A pod file kept as evidence: the folder is the host's, from its dialog.
        for action in ["poll", "cancel"] {
            assert!(main_window_may_call(
                "kubernetes.pod.file-evidence",
                &json!({ "action": action })
            ));
        }
        assert!(!main_window_may_call(
            "kubernetes.pod.file-evidence",
            &json!({ "action": "begin" })
        ));
        assert!(!main_window_may_call(
            "kubernetes.pod.file-evidence",
            &json!({ "action": "poll", "selectedDirectory": "C:\\" })
        ));
        for action in [
            "new",
            "open-quick",
            "view",
            "add",
            "update",
            "remove",
            "move",
            "close",
            "database-catalog",
            "new-database",
            "select-schema",
            "set-parameter",
            "goal-search",
            "goal-choose",
            "goal-confirm",
        ] {
            assert!(main_window_may_call(
                "config.visual",
                &json!({ "action": action })
            ));
        }
        for refused in [
            json!({ "action": "import-database", "artifactKey": "postgresql-main" }),
            json!({ "action": "new-database", "selectedPath": "C:\\postgresql.conf" }),
            json!({ "action": "import", "product": "nginx" }),
            json!({ "action": "export", "purpose": "copy" }),
            json!({ "action": "view", "selectedPath": "C:\\nginx.conf" }),
            json!({ "action": "view", "purpose": "save" }),
            json!({ "action": "goal-confirm", "selectedPath": "C:\\postgresql.conf" }),
        ] {
            assert!(
                !main_window_may_call("config.visual", &refused),
                "{refused}"
            );
        }
    }

    #[test]
    fn terminal_and_file_calls_have_lanes_of_their_own() {
        for method in [
            "terminal.open",
            "terminal.open-directory",
            "terminal.poll",
            "terminal.input",
            "terminal.close",
            "docker.container.terminal.open",
            "kubernetes.pod.terminal.open",
        ] {
            assert_eq!(lane_for(method), Lane::Terminal, "{method}");
        }
        for method in [
            "sftp-browser.open",
            "sftp-browser.directory.list",
            "sftp-browser.operation.execute",
        ] {
            assert_eq!(lane_for(method), Lane::Files, "{method}");
        }
        // A cancel cannot queue behind the transfer it is meant to stop.
        assert_eq!(lane_for("sftp-browser.transfer.cancel"), Lane::Control);
        for action in ["status", "baseline-plan-progress", "cancel-baseline-plan"] {
            assert_eq!(
                lane_for_request("windows.incident", &json!({"action":action})),
                Lane::Control
            );
        }
        for action in [
            "apply-baseline-plan",
            "plan-baseline",
            "run-command",
            "baseline-history",
            "cancel-everything",
        ] {
            assert_eq!(
                lane_for_request("windows.incident", &json!({"action":action})),
                Lane::Main
            );
        }
        for action in ["poll-fix", "cancel-fix", "poll-scan"] {
            assert_eq!(
                lane_for_request("response.engine", &json!({"action":action})),
                Lane::Control
            );
        }
        for action in ["scan", "plan-fix", "confirm-fix", "execute-fix"] {
            // poll-scan 走 Control
            assert_eq!(
                lane_for_request("response.engine", &json!({"action":action})),
                Lane::Main
            );
        }
        for method in [
            "emergency-command.run",
            "ssh.binding.disconnect",
            "docker.container.list",
            "terminal",
            "sftp-browserx",
        ] {
            assert_eq!(lane_for(method), Lane::Main, "{method}");
        }
    }

    /// A long main-window call must not hold back a terminal call.
    #[test]
    fn a_busy_main_lane_does_not_hold_back_the_terminal_lane() {
        let root = std::env::temp_dir().join(format!("lovelyhawk-lanes-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let bridge = BackendBridge::new(Arc::new(BackendState::open(root.clone()).unwrap()));
            let busy = bridge.lanes[Lane::Main as usize].lock().await;
            let deadline = std::time::Duration::from_secs(5);
            // An unknown handle: the terminal API answers at once, with an error.
            let terminal = tokio::time::timeout(
                deadline,
                bridge.call(
                    "terminal.poll",
                    json!({ "handle": "missing", "maximumEvents": 1, "maximumBytes": 1024 }),
                ),
            )
            .await;
            assert!(matches!(terminal, Ok(Err(_))), "{terminal:?}");
            for action in ["status", "baseline-plan-progress", "cancel-baseline-plan"] {
                let params = if action == "status" { json!({"action":action}) } else {
                    json!({"action":action,"planId":"00000000-0000-4000-8000-000000000001","sessionId":"00000000-0000-4000-8000-000000000002"})
                };
                let response = tokio::time::timeout(deadline, bridge.call("windows.incident", params)).await;
                assert!(matches!(response, Ok(Ok(_))), "{action}: {response:?}");
            }
            // The main lane really is held: its own call waits.
            let main = tokio::time::timeout(
                std::time::Duration::from_millis(300),
                bridge.call("app.bootstrap", json!({})),
            )
            .await;
            assert!(
                main.is_err(),
                "a main-lane call ran while the lane was held"
            );
            drop(busy);
            bridge.shutdown().await;
        });
        drop(runtime);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_list_has_no_duplicates() {
        let mut methods = MAIN_WINDOW_METHODS.to_vec();
        methods.sort_unstable();
        methods.dedup();
        assert_eq!(methods.len(), MAIN_WINDOW_METHODS.len());
    }
}
