#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
//! LovelyHawk desktop application: a Tauri 2 host around the backend.
//!
//! The host owns what the pages must never hold: local paths, export payloads,
//! the system dialogs and clipboard, the windows and which target each belongs
//! to. Pages reach the backend only through the commands registered here.

mod archive_root;
mod backend_bridge;
mod binding_state;
mod child_commands;
mod child_windows;
#[cfg(debug_assertions)]
mod dev_server;
mod host;
mod instance_lock;
mod local_browser;
mod local_files;
mod main_commands;
mod smoke;
mod test_hooks;
mod theme;

use std::{
    path::PathBuf,
    process::ExitCode,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

use lovelyhawk_backend::{BackendState, DiagnosticLogCapture, DiagnosticLogLevel};
use parking_lot::Mutex;
use tauri::{AppHandle, Manager, RunEvent, Runtime, WindowEvent};
use tracing_subscriber::prelude::*;

use crate::{
    backend_bridge::BackendBridge,
    binding_state::BindingState,
    child_windows::ChildWindows,
    host::{CloseGate, Host, MAIN_LABEL, is_child_label},
    local_browser::LocalBrowser,
    theme::WindowTheme,
};

const BACKEND_STOP_GRACE: Duration = Duration::from_secs(3);
/// How long a restored window gets to notice it is no longer minimised.
const SHOW_SETTLE: Duration = Duration::from_millis(150);
/// DevTools for a portable build someone has to debug in the field.
const DEBUG_MODE_VARIABLE: &str = "LOVELYHAWK_DEBUG";

/// What only a debug build lets its environment change.
#[derive(Debug, Default)]
struct DevelopmentOverrides {
    /// Where the data lives.
    archive_root: Option<std::ffi::OsString>,
    /// Whether automation may attach to WebView2 over CDP.
    browser_args: Option<String>,
    /// Whether the pages load from a local Vite server instead of the
    /// embedded assets.
    dev_server: Option<tauri::Url>,
}

/// A release build does not contain these variable names at all.
#[cfg(debug_assertions)]
fn development_overrides() -> DevelopmentOverrides {
    const DEBUG_PORT_VARIABLE: &str = "LOVELYHAWK_DEBUG_PORT";
    /// Tauri's own WebView2 defaults, kept when the debug port is added.
    const DEFAULT_BROWSER_ARGS: &str =
        "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection";
    let browser_args = std::env::var(DEBUG_PORT_VARIABLE)
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| *port >= 1024)
        .map(|port| format!("{DEFAULT_BROWSER_ARGS} --remote-debugging-port={port}"));
    DevelopmentOverrides {
        archive_root: std::env::var_os(archive_root::ARCHIVE_ROOT_VARIABLE),
        browser_args,
        dev_server: dev_server::from_env(),
    }
}

#[cfg(not(debug_assertions))]
fn development_overrides() -> DevelopmentOverrides {
    DevelopmentOverrides::default()
}

pub fn run() -> ExitCode {
    let development = cfg!(debug_assertions);
    let capture = DiagnosticLogCapture::new(DiagnosticLogLevel::Info);
    let stderr_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let subscriber = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_filter(stderr_filter),
        )
        .with(capture.layer());
    if subscriber.try_init().is_err() {
        return ExitCode::FAILURE;
    }

    let executable = match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => {
            tracing::error!(%error, "cannot resolve the executable");
            return ExitCode::FAILURE;
        }
    };
    let DevelopmentOverrides {
        archive_root: archive_override,
        browser_args,
        dev_server,
    } = development_overrides();
    let archive_root =
        match archive_root::resolve(development, &executable, archive_override.as_deref()) {
            Ok(root) => root,
            Err(error) => {
                tracing::error!(%error, "invalid archive root");
                return ExitCode::from(2);
            }
        };
    let data_directory = archive_root.join("data");
    let webview_data = data_directory.join("webview2");
    if let Err(error) = std::fs::create_dir_all(&webview_data) {
        tracing::error!(%error, "cannot prepare the portable data directory");
        return ExitCode::FAILURE;
    }
    let _instance = match instance_lock::acquire(&data_directory) {
        Ok(lock) => lock,
        Err(instance_lock::InstanceLockError::AlreadyRunning) => {
            // The running copy brings its window forward; only when it does
            // not answer is the operator told to find it themselves.
            if !instance_lock::request_show(&data_directory, instance_lock::SHOW_WAIT) {
                already_running();
            }
            return ExitCode::SUCCESS;
        }
        Err(instance_lock::InstanceLockError::Io(error)) => {
            tracing::error!(%error, "cannot lock the portable data directory");
            return ExitCode::FAILURE;
        }
    };
    // Only the process holding the lock writes the log file. Without it the program
    // still runs; the application log overlay says the log is in memory only.
    if let Err(error) = capture.persist_to(&data_directory.join("logs")) {
        tracing::warn!(%error, "cannot open the log file; logs stay in memory");
    }

    let debug_mode = development || std::env::var(DEBUG_MODE_VARIABLE).as_deref() == Ok("1");
    let show_requests = data_directory.clone();

    let built = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(move |app| {
            let state = tauri::async_runtime::block_on(async {
                BackendState::open_with_diagnostic_capture(archive_root, capture)
            })?;
            #[cfg(debug_assertions)]
            if let Some(origin) = &dev_server {
                dev_server::grant(app.handle(), origin)?;
            }
            app.manage(Host {
                bridge: BackendBridge::new(Arc::new(state)),
                binding: Mutex::new(BindingState::default()),
                children: Mutex::new(ChildWindows::default()),
                local: Mutex::new(LocalBrowser::default()),
                theme: Mutex::new(WindowTheme::default()),
                webview_data,
                debug_mode,
                browser_args,
                dev_server,
                renderer_ready: AtomicBool::new(false),
                close: CloseGate::default(),
            });
            app.state::<Host>().build_main_window(app.handle())?;
            watch_show_requests(app.handle().clone(), show_requests);
            Ok(())
        })
        .on_window_event(|window, event| {
            let label = window.label().to_owned();
            match event {
                WindowEvent::CloseRequested { api, .. } if label == MAIN_LABEL => {
                    let host = window.state::<Host>();
                    if !host.close.is_allowed() {
                        api.prevent_close();
                        host.request_close(window);
                    }
                }
                // Alt+F4 or the taskbar on an editor with unsaved text: the
                // window asks first, as its own close button does.
                WindowEvent::CloseRequested { api, .. } if is_child_label(&label) => {
                    let host = window.state::<Host>();
                    if host.children.lock().is_unsaved(&label) {
                        api.prevent_close();
                        host.request_child_close(window);
                    }
                }
                WindowEvent::Destroyed if label == MAIN_LABEL => {
                    let app = window.app_handle().clone();
                    tauri::async_runtime::spawn(async move {
                        app.state::<Host>().close_all_children(&app).await;
                        app.exit(0);
                    });
                }
                WindowEvent::Destroyed if is_child_label(&label) => {
                    let app = window.app_handle().clone();
                    tauri::async_runtime::spawn(async move {
                        app.state::<Host>().release_child(&app, &label, false).await;
                    });
                }
                _ => {}
            }
        })
        .invoke_handler(tauri::generate_handler![
            main_commands::backend_call,
            main_commands::connections_import,
            main_commands::connections_export,
            main_commands::connection_credential_file,
            main_commands::unsaved_editor_count,
            main_commands::case_library_export,
            main_commands::java_class_stage,
            main_commands::file_evidence_begin,
            main_commands::packet_capture_evidence_begin,
            main_commands::pod_file_evidence_begin,
            main_commands::kubernetes_manifest_export,
            main_commands::application_log_export,
            main_commands::disposal_report_export,
            main_commands::ai_history_export,
            main_commands::config_copy,
            main_commands::config_artifact_export,
            main_commands::config_bundle_export,
            main_commands::config_visual_import,
            main_commands::config_visual_import_database,
            main_commands::config_visual_copy,
            main_commands::config_visual_save,
            main_commands::clipboard_write,
            main_commands::window_theme,
            main_commands::terminal_window_open,
            main_commands::container_terminal_open,
            main_commands::pod_terminal_open,
            main_commands::close_decision,
            main_commands::renderer_ready,
            child_commands::terminal_open,
            child_commands::terminal_open_tab,
            child_commands::terminal_poll,
            child_commands::terminal_input,
            child_commands::terminal_resize,
            child_commands::terminal_search,
            child_commands::terminal_copy_selection,
            child_commands::terminal_ai_assist,
            child_commands::terminal_close_tab,
            child_commands::terminal_close,
            child_commands::sftp_open,
            child_commands::sftp_list,
            child_commands::sftp_read_text,
            child_commands::sftp_download,
            child_commands::sftp_plan,
            child_commands::sftp_confirm,
            child_commands::sftp_execute,
            child_commands::sftp_cancel,
            child_commands::sftp_undo,
            child_commands::sftp_cancel_transfer,
            child_commands::sftp_stage_upload,
            child_commands::local_open,
            child_commands::local_list,
            child_commands::file_editor_open,
            child_commands::directory_terminal_open,
            child_commands::file_editor_target,
            child_commands::file_editor_unsaved,
            child_commands::child_close_decision,
        ])
        .build(tauri::generate_context!());

    let app = match built {
        Ok(app) => app,
        Err(error) => {
            tracing::error!(%error, "failed to start LovelyHawk");
            return ExitCode::FAILURE;
        }
    };
    app.run(|app, event| {
        if let RunEvent::Exit = event
            && let Some(host) = app.try_state::<Host>()
        {
            let bridge = host.bridge.clone();
            let stopped = tauri::async_runtime::block_on(async move {
                tokio::time::timeout(BACKEND_STOP_GRACE, bridge.shutdown()).await
            });
            if stopped.is_err() {
                tracing::warn!("backend did not stop within its grace period");
            }
        }
    });
    ExitCode::SUCCESS
}

/// A second launch of the same copy asks for the window instead of opening
/// another: the main window is restored, shown and focused.
fn watch_show_requests<R: Runtime>(app: AppHandle<R>, data_directory: PathBuf) {
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(instance_lock::SHOW_POLL).await;
            if !instance_lock::take_show_request(&data_directory) {
                continue;
            }
            tracing::info!("a second launch asked for the window");
            if let Some(window) = app.get_webview_window(MAIN_LABEL) {
                // Each step only when needed, and the restore given a moment:
                // show() issued before the window has noticed the restore put
                // it straight back to the taskbar.
                if window.is_minimized().unwrap_or(false) {
                    let _ = window.unminimize();
                    tokio::time::sleep(SHOW_SETTLE).await;
                }
                if !window.is_visible().unwrap_or(true) {
                    let _ = window.show();
                }
                let _ = window.set_focus();
                // The window in front is not enough: the page inside it needs
                // the keyboard too, or typing goes nowhere.
                let webview: &tauri::Webview<R> = window.as_ref();
                let _ = webview.set_focus();
            }
        }
    });
}

#[cfg(windows)]
fn already_running() {
    rfd::MessageDialog::new()
        .set_level(rfd::MessageLevel::Info)
        .set_title("LovelyHawk")
        .set_description(
            "LovelyHawk 已经在运行，并正在使用这个目录中的数据。请切换到已打开的窗口。",
        )
        .set_buttons(rfd::MessageButtons::Ok)
        .show();
}

#[cfg(not(windows))]
fn already_running() {
    eprintln!("LovelyHawk is already running with this data directory.");
}
