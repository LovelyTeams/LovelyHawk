//! Everything the host keeps for the life of the process, and the windows it
//! creates.

use std::{
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use parking_lot::Mutex;
use serde::Serialize;
use serde_json::{Value, json};
use tauri::{
    AppHandle, Manager, Runtime, WebviewUrl, WebviewWindow, WebviewWindowBuilder,
    webview::{NewWindowResponse, PageLoadEvent, PermissionResponse},
};

use crate::{
    backend_bridge::BackendBridge,
    binding_state::{BindingState, sanitize_label},
    child_windows::{ChildKind, ChildWindows, LABEL_PREFIX, window_key},
    local_browser::LocalBrowser,
    theme::{self, WindowTheme},
};

pub const MAIN_LABEL: &str = "main";
/// The floor every window shares, and the floor the stylesheet assumes.
pub const MIN_WINDOW_WIDTH: f64 = 1_080.0;
pub const MIN_WINDOW_HEIGHT: f64 = 700.0;
const CLOSE_GATE_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug)]
pub struct Host {
    pub bridge: BackendBridge,
    pub rdp: Mutex<crate::windows_rdp::RdpState>,
    pub channel: Mutex<crate::windows_channel::ChannelState>,
    pub binding: Mutex<BindingState>,
    pub children: Mutex<ChildWindows>,
    pub local: Mutex<LocalBrowser>,
    pub theme: Mutex<WindowTheme>,
    pub webview_data: PathBuf,
    pub debug_mode: bool,
    pub browser_args: Option<String>,
    /// Debug builds only: the loopback Vite origin the pages load from instead
    /// of the embedded assets. Always `None` in a release build.
    pub dev_server: Option<tauri::Url>,
    pub renderer_ready: AtomicBool,
    pub close: CloseGate,
}

/// The main window asks the page before it closes, so unsaved edits and
/// running work get a chance to say no.
#[derive(Debug, Default)]
pub struct CloseGate {
    allowed: AtomicBool,
    requests: Mutex<CloseRequests>,
}

#[derive(Debug, Default)]
struct CloseRequests {
    latest: u64,
    unanswered: Option<u64>,
    waiting: bool,
}

impl CloseGate {
    pub fn is_allowed(&self) -> bool {
        self.allowed.load(Ordering::SeqCst)
    }

    /// Starts a request unless one is still waiting for its answer. Returns
    /// the request number the page must echo back.
    pub fn begin(&self) -> Option<u64> {
        let mut requests = self.requests.lock();
        if requests.waiting {
            return None;
        }
        requests.latest += 1;
        requests.unanswered = Some(requests.latest);
        requests.waiting = true;
        Some(requests.latest)
    }

    /// Lets the next close click ask again, for a page that never answered.
    /// The request stays answerable: someone reading an unsaved-changes dialog
    /// for longer than the timeout still gets their choice honoured, unless a
    /// newer close request has replaced it.
    pub fn expire(&self, request: u64) {
        let mut requests = self.requests.lock();
        if requests.unanswered == Some(request) {
            requests.waiting = false;
        }
    }

    /// The page's answer. Only the first answer to the latest request counts.
    pub fn resolve(&self, request: u64, allowed: bool) -> bool {
        let mut requests = self.requests.lock();
        if requests.unanswered != Some(request) {
            return false;
        }
        requests.unanswered = None;
        requests.waiting = false;
        if allowed {
            self.allowed.store(true, Ordering::SeqCst);
        }
        allowed
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowLaunch {
    pub opened: bool,
    pub reused: bool,
}

impl Host {
    pub fn current_binding(&self) -> Option<String> {
        self.binding
            .lock()
            .current_binding_handle()
            .map(str::to_owned)
    }

    /// The embedded page, or the same page on the development server when a
    /// debug build was started with one.
    fn page_url(&self, page: WebviewUrl) -> WebviewUrl {
        match (&self.dev_server, page) {
            (Some(origin), WebviewUrl::App(path)) => match origin.join(&path.to_string_lossy()) {
                Ok(url) => WebviewUrl::External(url),
                Err(_) => WebviewUrl::App(path),
            },
            (_, page) => page,
        }
    }

    /// Applies the window-wide settings every LovelyHawk webview shares.
    fn harden<'a, R: Runtime, M: Manager<R>>(
        &self,
        builder: WebviewWindowBuilder<'a, R, M>,
        page: Page,
    ) -> WebviewWindowBuilder<'a, R, M> {
        let page = NavigationRule {
            page,
            dev_server: self.dev_server.clone(),
        };
        let mut builder = builder
            .decorations(false)
            .resizable(true)
            .visible(false)
            .min_inner_size(MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT)
            .data_directory(self.webview_data.clone())
            .incognito(true)
            .use_https_scheme(true)
            .disable_drag_drop_handler()
            .general_autofill_enabled(false)
            .zoom_hotkeys_enabled(false)
            .devtools(self.debug_mode)
            .on_navigation(move |url| page.allows(url))
            .on_new_window(|_, _| NewWindowResponse::Deny)
            .on_download(|_, _| false)
            .on_permission_request(|_, _| PermissionResponse::Deny)
            .on_page_load(|window, payload| {
                if payload.event() == PageLoadEvent::Finished {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            });
        if let Some(arguments) = &self.browser_args {
            builder = builder.additional_browser_args(arguments);
        }
        builder
    }

    pub fn build_main_window<R: Runtime>(
        &self,
        app: &AppHandle<R>,
    ) -> tauri::Result<WebviewWindow<R>> {
        let native = theme::resolve(&self.theme.lock().theme);
        let (width, height) = preferred_window_size(app);
        let url = self.page_url(WebviewUrl::App("index.html".into()));
        let builder = WebviewWindowBuilder::new(app, MAIN_LABEL, url)
            .title("LovelyHawk")
            .inner_size(width, height)
            .center()
            .background_color(theme::color(native.window_background));
        self.harden(builder, Page::Main).build()
    }

    pub fn open_channel<R: Runtime>(&self, app: &AppHandle<R>) -> Result<(), String> {
        if let Some(window) = app.get_webview_window(crate::windows_channel::LABEL) {
            window
                .unminimize()
                .and_then(|_| window.show())
                .and_then(|_| window.set_focus())
                .map_err(|_| "无法显示通道窗口。".to_owned())?;
            return Ok(());
        }
        let native = theme::resolve(&self.theme.lock().theme);
        let builder = WebviewWindowBuilder::new(
            app,
            crate::windows_channel::LABEL,
            self.page_url(WebviewUrl::App(
                "terminal.html?window=windows-channel".into(),
            )),
        )
        .title("LovelyHawk · 通道与传输")
        .inner_size(1_240.0, 840.0)
        .center()
        .background_color(theme::color(native.window_background))
        .initialization_script(launch_script(native.id, "通道与传输"));
        self.harden(builder, Page::Channel)
            .min_inner_size(800.0, 600.0)
            .build()
            .map_err(|error| {
                tracing::error!(%error, "failed to open Windows channel window");
                "无法打开通道与传输窗口。".to_owned()
            })?;
        Ok(())
    }

    /// Opens, or raises, the window for `kind` on `binding_handle`.
    pub fn open_child<R: Runtime>(
        &self,
        app: &AppHandle<R>,
        binding_handle: &str,
        kind: ChildKind,
    ) -> Result<WindowLaunch, String> {
        let key = window_key(binding_handle, &kind);
        let existing = self.children.lock().existing_label(&key).map(str::to_owned);
        if let Some(label) = existing
            && let Some(window) = app.get_webview_window(&label)
        {
            let _ = window.unminimize();
            let _ = window.show();
            let _ = window.set_focus();
            return Ok(WindowLaunch {
                opened: true,
                reused: true,
            });
        }

        let target = self.binding.lock().current_target_label().to_owned();
        let (title, label_text) = match &kind {
            ChildKind::Terminal => ("LovelyHawk SSH 终端".to_owned(), target),
            ChildKind::Container(scope) => (
                "LovelyHawk 容器终端".to_owned(),
                format!("{target} · 容器 {}", scope.container_name),
            ),
            ChildKind::Pod(scope) => (
                "LovelyHawk Pod 终端".to_owned(),
                match &scope.container {
                    Some(container) => {
                        format!("{target} · Pod {} · 容器 {container}", scope.pod_name)
                    }
                    None => format!("{target} · Pod {}", scope.pod_name),
                },
            ),
            ChildKind::Directory(scope) => (
                "LovelyHawk SSH 终端".to_owned(),
                format!("{target} · 文件夹 {}", scope.name),
            ),
            ChildKind::Editor(scope) => (
                "LovelyHawk 文件".to_owned(),
                format!("{target} · {}", scope.name),
            ),
        };
        let page = kind.page();
        let label = self.children.lock().register(binding_handle, kind);
        let native = theme::resolve(&self.theme.lock().theme);
        let script = launch_script(native.id, &sanitize_label(&label_text));
        let url = WebviewUrl::App(format!("terminal.html?window={page}").into());
        let builder = WebviewWindowBuilder::new(app, &label, self.page_url(url))
            .title(title)
            .inner_size(1_120.0, 760.0)
            .center()
            .background_color(theme::color(native.terminal_background))
            .initialization_script(script);
        match self.harden(builder, Page::Child).build() {
            Ok(_) => Ok(WindowLaunch {
                opened: true,
                reused: false,
            }),
            Err(error) => {
                tracing::error!(%error, "failed to create a terminal-family window");
                self.children.lock().remove(&label);
                Err("无法打开新窗口。".to_owned())
            }
        }
    }

    /// Forgets a child window and closes every terminal it held, one per tab.
    pub async fn release_child<R: Runtime>(&self, app: &AppHandle<R>, label: &str, destroy: bool) {
        let (handles, ai_streams) = {
            let mut children = self.children.lock();
            let ai_streams = children.take_ai_streams(label);
            (children.remove(label).unwrap_or_default(), ai_streams)
        };
        if destroy && let Some(window) = app.get_webview_window(label) {
            let _ = window.destroy();
        }
        for terminal_handle in handles {
            let _ = self
                .bridge
                .call("terminal.close", json!({ "handle": terminal_handle }))
                .await;
        }
        // An answer nobody will read stops costing the provider anything.
        for stream in ai_streams {
            let _ = self
                .bridge
                .call("ai.assist", json!({ "action": "cancel", "handle": stream }))
                .await;
        }
    }

    pub async fn close_children_for_binding<R: Runtime>(
        &self,
        app: &AppHandle<R>,
        binding_handle: &str,
    ) {
        let labels = self.children.lock().labels_for_binding(binding_handle);
        for label in labels {
            self.release_child(app, &label, true).await;
        }
    }

    pub async fn close_all_children<R: Runtime>(&self, app: &AppHandle<R>) {
        let labels = self.children.lock().labels();
        for label in labels {
            self.release_child(app, &label, true).await;
        }
    }

    /// Asks an editor window holding unsaved text whether it may close, once
    /// per pending request. The window answers with `child_close_decision`.
    pub fn request_child_close<R: Runtime>(&self, window: &tauri::Window<R>) {
        let label = window.label().to_owned();
        let Some(request) = self.children.lock().begin_close(&label) else {
            return;
        };
        let _ = tauri::Emitter::emit_to(
            window,
            label.as_str(),
            "lovelyhawk://before-close",
            serde_json::json!({ "request": request }),
        );
        let app = window.app_handle().clone();
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(CLOSE_GATE_TIMEOUT).await;
            app.state::<Host>()
                .children
                .lock()
                .expire_close(&label, request);
        });
    }

    /// Asks the main page whether it may close, once per pending request.
    /// Closing it closes every editor window, so the page is told how many
    /// of them still hold unsaved text.
    pub fn request_close<R: Runtime>(&self, window: &tauri::Window<R>) {
        let Some(request) = self.close.begin() else {
            return;
        };
        let unsaved_editors = self.children.lock().unsaved_count();
        let _ = tauri::Emitter::emit_to(
            window,
            MAIN_LABEL,
            "lovelyhawk://before-close",
            serde_json::json!({ "request": request, "unsavedEditors": unsaved_editors }),
        );
        let app = window.app_handle().clone();
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(CLOSE_GATE_TIMEOUT).await;
            app.state::<Host>().close.expire(request);
        });
    }
}

/// Which page a window may show. Anything else is a navigation away from the
/// application and is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page {
    Main,
    Child,
    Channel,
}

impl Page {
    #[cfg(test)]
    pub fn allows(self, url: &tauri::Url) -> bool {
        self.allows_from(url, None)
    }

    /// As [`Page::allows`], also accepting the same page on `dev_server`.
    pub fn allows_from(self, url: &tauri::Url, dev_server: Option<&tauri::Url>) -> bool {
        let embedded = match url.scheme() {
            "https" | "http" => url.host_str() == Some("tauri.localhost"),
            "tauri" => url.host_str() == Some("localhost"),
            _ => false,
        };
        let development = dev_server.is_some_and(|origin| {
            url.scheme() == origin.scheme()
                && url.host_str() == origin.host_str()
                && url.port() == origin.port()
                && url.username().is_empty()
                && url.password().is_none()
        });
        let local_origin = embedded || development;
        if !local_origin || url.fragment().is_some() {
            return false;
        }
        match self {
            Self::Channel => {
                url.path() == "/terminal.html" && url.query() == Some("window=windows-channel")
            }
            // Linux and macOS load the app root as `tauri://localhost`, whose
            // path is empty rather than "/".
            Self::Main => matches!(url.path(), "" | "/" | "/index.html") && url.query().is_none(),
            Self::Child => {
                url.path() == "/terminal.html"
                    && matches!(
                        url.query(),
                        Some(
                            "window=terminal"
                                | "window=container"
                                | "window=pod"
                                | "window=directory"
                                | "window=file-editor"
                        )
                    )
            }
        }
    }
}

/// The page a window may show, and the development origin a debug build may
/// also show it from.
#[derive(Clone, Debug)]
struct NavigationRule {
    page: Page,
    dev_server: Option<tauri::Url>,
}

impl NavigationRule {
    fn allows(&self, url: &tauri::Url) -> bool {
        self.page.allows_from(url, self.dev_server.as_ref())
    }
}

/// Stamps the theme and the display label before the page's own scripts run,
/// so a dark terminal never flashes light. Presentation only: the label is
/// never a capability.
fn launch_script(theme_id: &str, target_label: &str) -> String {
    let theme = Value::String(theme_id.to_owned()).to_string();
    let label = Value::String(target_label.to_owned()).to_string();
    format!(
        "(function(){{var t={theme},l={label};function a(){{var r=document.documentElement;if(!r)return false;r.dataset.theme=t;r.dataset.targetLabel=l;return true}}if(!a()){{var o=new MutationObserver(function(){{if(a())o.disconnect()}});o.observe(document,{{childList:true}})}}}})();"
    )
}

/// 1920×1080 is the size the pages are laid out for, clamped to the work area
/// so the status bar along the bottom edge never ends up under the taskbar.
fn preferred_window_size<R: Runtime>(app: &AppHandle<R>) -> (f64, f64) {
    let work = app
        .primary_monitor()
        .ok()
        .flatten()
        .map(|monitor| {
            let area = monitor.work_area();
            let scale = monitor.scale_factor();
            (
                area.size.width as f64 / scale,
                area.size.height as f64 / scale,
            )
        })
        .unwrap_or((1_920.0, 1_080.0));
    (
        MIN_WINDOW_WIDTH.max(work.0.min(1_920.0)),
        MIN_WINDOW_HEIGHT.max(work.1.min(1_080.0)),
    )
}

pub fn is_child_label(label: &str) -> bool {
    label.starts_with(LABEL_PREFIX)
}

/// Every copy a page asks for goes through here.
pub fn write_clipboard<R: Runtime>(app: &AppHandle<R>, text: &str) -> Result<(), String> {
    use tauri_plugin_clipboard_manager::ClipboardExt;
    if crate::test_hooks::capture_clipboard(text) {
        return Ok(());
    }
    app.clipboard()
        .write_text(text)
        .map_err(|_| "无法写入剪贴板。".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(value: &str) -> tauri::Url {
        value.parse().unwrap()
    }

    #[test]
    fn windows_stay_on_their_own_page() {
        assert!(Page::Main.allows(&url("https://tauri.localhost/")));
        assert!(Page::Main.allows(&url("http://tauri.localhost/index.html")));
        assert!(Page::Main.allows(&url("tauri://localhost/index.html")));
        assert!(!Page::Main.allows(&url(
            "https://tauri.localhost/terminal.html?window=terminal"
        )));
        assert!(!Page::Main.allows(&url("https://example.com/")));
        assert!(!Page::Main.allows(&url("https://tauri.localhost/#x")));
        assert!(Page::Child.allows(&url(
            "https://tauri.localhost/terminal.html?window=terminal"
        )));
        assert!(Page::Child.allows(&url(
            "https://tauri.localhost/terminal.html?window=file-editor"
        )));
        for kind in ["container", "pod", "directory"] {
            assert!(Page::Child.allows(&url(&format!(
                "https://tauri.localhost/terminal.html?window={kind}"
            ))));
        }
        assert!(!Page::Child.allows(&url("https://tauri.localhost/terminal.html?window=other")));
        assert!(!Page::Child.allows(&url(
            "https://tauri.localhost/terminal.html?window=directory&path=/etc"
        )));
        assert!(!Page::Child.allows(&url("https://tauri.localhost/index.html")));
        assert!(!Page::Child.allows(&url("file:///C:/terminal.html?window=terminal")));
    }

    #[test]
    fn a_development_server_serves_the_same_pages_and_nothing_else() {
        let dev = url("http://127.0.0.1:5173/");
        let rule = |page| NavigationRule {
            page,
            dev_server: Some(dev.clone()),
        };
        assert!(rule(Page::Main).allows(&url("http://127.0.0.1:5173/index.html")));
        assert!(rule(Page::Main).allows(&url("http://127.0.0.1:5173/")));
        assert!(rule(Page::Main).allows(&url("https://tauri.localhost/")));
        assert!(
            rule(Page::Child).allows(&url("http://127.0.0.1:5173/terminal.html?window=terminal"))
        );
        // Same page rules as the embedded origin.
        assert!(!rule(Page::Main).allows(&url("http://127.0.0.1:5173/other.html")));
        assert!(!rule(Page::Child).allows(&url("http://127.0.0.1:5173/index.html")));
        assert!(!rule(Page::Main).allows(&url("http://127.0.0.1:5173/#x")));
        // Only that origin: not another port, host or scheme.
        assert!(!rule(Page::Main).allows(&url("http://127.0.0.1:5174/index.html")));
        assert!(!rule(Page::Main).allows(&url("http://localhost:5173/index.html")));
        assert!(!rule(Page::Main).allows(&url("https://127.0.0.1:5173/index.html")));
        assert!(!rule(Page::Main).allows(&url("http://user@127.0.0.1:5173/index.html")));
        // Without a development server the origin is just another site.
        assert!(!Page::Main.allows(&url("http://127.0.0.1:5173/index.html")));
    }

    #[test]
    fn the_app_root_without_a_path_is_the_main_page_on_linux() {
        // WebKitGTK's first navigation is the bare custom-scheme root; refusing
        // it left the Linux window blank and never shown.
        let root = url("tauri://localhost");
        assert_eq!(root.path(), "");
        assert!(Page::Main.allows(&root));
        assert!(!Page::Child.allows(&root));
        assert!(!Page::Main.allows(&url("tauri://localhost?x=1")));
        assert!(!Page::Main.allows(&url("tauri://localhost.example")));
        assert!(!Page::Main.allows(&url("tauri://localhost/other.html")));
    }

    #[test]
    fn launch_script_encodes_untrusted_labels_as_string_literals() {
        let script = launch_script("dark", "root@h\"});alert(1);//");
        assert!(script.contains(r#"l="root@h\"});alert(1);//""#));
        assert!(script.contains(r#"t="dark""#));
    }

    #[test]
    fn the_close_gate_answers_only_a_waiting_request() {
        let gate = CloseGate::default();
        assert!(!gate.resolve(1, true));
        let first = gate.begin().unwrap();
        assert!(gate.begin().is_none());
        assert!(!gate.resolve(first + 1, true));
        assert!(!gate.resolve(first, false));
        assert!(!gate.resolve(first, true), "a request is answered once");
        assert!(!gate.is_allowed());
        let second = gate.begin().unwrap();
        gate.expire(first);
        assert!(
            gate.begin().is_none(),
            "expiring an older request frees nothing"
        );
        assert!(gate.resolve(second, true));
        assert!(gate.is_allowed());
        gate.expire(second);
    }

    #[test]
    fn a_late_answer_counts_until_a_newer_close_request_replaces_it() {
        let gate = CloseGate::default();
        let slow = gate.begin().unwrap();
        gate.expire(slow);
        assert!(
            gate.resolve(slow, true),
            "the operator took longer than the timeout"
        );
        assert!(gate.is_allowed());

        let gate = CloseGate::default();
        let stale = gate.begin().unwrap();
        gate.expire(stale);
        let fresh = gate
            .begin()
            .expect("an expired request lets the next click ask again");
        assert!(
            !gate.resolve(stale, true),
            "the replaced request no longer decides"
        );
        assert!(!gate.is_allowed());
        assert!(gate.resolve(fresh, true));
    }
}
