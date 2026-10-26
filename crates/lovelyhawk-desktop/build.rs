/// Commands the pages may call. Listing them here makes each one a permission
/// a capability file must grant, so the main window and the terminal-family
/// windows each reach only their own set (see `capabilities/`).
const COMMANDS: &[&str] = &[
    // Main window.
    "backend_call",
    "connections_import",
    "connections_export",
    "connection_credential_file",
    "unsaved_editor_count",
    "case_library_export",
    "java_class_stage",
    "file_evidence_begin",
    "packet_capture_evidence_begin",
    "pod_file_evidence_begin",
    "kubernetes_manifest_export",
    "application_log_export",
    "disposal_report_export",
    "ai_history_export",
    "config_copy",
    "config_artifact_export",
    "config_bundle_export",
    "config_visual_import",
    "config_visual_import_database",
    "config_visual_copy",
    "config_visual_save",
    "windows_file_save",
    "windows_rdp",
    "clipboard_write",
    "window_theme",
    "terminal_window_open",
    "container_terminal_open",
    "pod_terminal_open",
    "close_decision",
    "renderer_ready",
    // Terminal, container-terminal and file-editor windows.
    "terminal_open",
    "terminal_open_tab",
    "terminal_poll",
    "terminal_input",
    "terminal_resize",
    "terminal_search",
    "terminal_copy_selection",
    "terminal_ai_assist",
    "terminal_close_tab",
    "terminal_close",
    "sftp_open",
    "sftp_list",
    "sftp_read_text",
    "sftp_download",
    "sftp_plan",
    "sftp_confirm",
    "sftp_execute",
    "sftp_cancel",
    "sftp_undo",
    "sftp_cancel_transfer",
    "sftp_stage_upload",
    "local_open",
    "local_list",
    "file_editor_open",
    "directory_terminal_open",
    "file_editor_target",
    "file_editor_unsaved",
    "child_close_decision",
];

fn main() {
    // tauri-build embeds icons/icon.ico as the executable's icon but only asks
    // to rerun when tauri.conf.json or the capabilities change, so a new icon
    // would otherwise never reach a build whose script already ran.
    println!("cargo:rerun-if-changed=icons");
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("failed to prepare the Tauri context");
}
