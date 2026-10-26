//! Native RDP viewport. Only the mstsc process launched here may be embedded.
//! No credentials, HWNDs, local paths or arbitrary process controls cross IPC.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Bounds {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

impl Bounds {
    pub fn valid(&self) -> bool {
        [self.x, self.y, self.width, self.height]
            .iter()
            .all(|n| n.is_finite() && *n >= 0.0 && *n <= 16384.0)
            && self.width >= 160.0
            && self.height >= 120.0
            && self.y >= 40.0
    }
}

/// A fixed remote desktop size chosen by the operator.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Resolution {
    pub width: u32,
    pub height: u32,
}

impl Resolution {
    /// The sizes mstsc accepts: even widths, 640×480 up to 8192×8192.
    pub fn valid(&self) -> bool {
        self.width.is_multiple_of(2)
            && (640..=8192).contains(&self.width)
            && (480..=8192).contains(&self.height)
    }

    /// The viewport's physical size, kept within the accepted range.
    fn fitting(bounds: &Bounds, scale: f64) -> Self {
        let width = ((bounds.width * scale).floor() as u32).clamp(640, 8192) & !1;
        let height = ((bounds.height * scale).floor() as u32).clamp(480, 8192);
        Self { width, height }
    }
}

#[derive(Debug, Deserialize)]
#[serde(
    tag = "action",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Request {
    Status {},
    Start {
        server: String,
        clipboard: bool,
        bounds: Bounds,
        /// None fits the session to the viewport and follows its size.
        resolution: Option<Resolution>,
    },
    Place {
        client_id: String,
        bounds: Bounds,
    },
    Hide {
        client_id: String,
    },
    Disconnect {
        client_id: String,
    },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub client_id: Option<String>,
    pub server: String,
    pub phase: &'static str,
    pub message: String,
}

pub fn valid_server(server: &str) -> bool {
    !server.is_empty()
        && server.len() <= 253
        && server
            .bytes()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == b'[')
        && server
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b".-:[]".contains(&c))
}

/// Native viewport supplied only by the desktop host, never by IPC callers.
#[derive(Debug)]
pub struct Viewport {
    pub parent: usize,
    pub scale: f64,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Default)]
pub struct RdpState {
    #[cfg(windows)]
    client: Option<native::Client>,
}

impl RdpState {
    pub fn stop(&mut self) {
        #[cfg(windows)]
        {
            self.client.take();
        }
    }

    pub fn apply(
        &mut self,
        window: &Viewport,
        data_root: &std::path::Path,
        request: Request,
    ) -> Result<Status, String> {
        #[cfg(windows)]
        {
            native::apply(self, window, data_root, request)
        }
        #[cfg(not(windows))]
        {
            let _ = (window, data_root, request);
            Err("内嵌远程桌面仅适用于 Windows".to_owned())
        }
    }

    /// Re-applies the requested placement or hiding, since mstsc may show or
    /// resize its own window. Returns false once no client remains.
    pub fn enforce(&mut self, window: &Viewport) -> bool {
        #[cfg(windows)]
        {
            native::enforce(self, window)
        }
        #[cfg(not(windows))]
        {
            let _ = window;
            false
        }
    }
}

#[cfg(windows)]
mod native {
    use super::*;
    use std::{
        io::Write,
        path::PathBuf,
        process::{Child, Command, Stdio},
    };
    use windows::Win32::{
        Foundation::{HWND, LPARAM, RECT},
        UI::WindowsAndMessaging::*,
    };

    #[derive(Debug)]
    pub(super) struct Client {
        id: String,
        server: String,
        child: Child,
        file: PathBuf,
        window: Option<usize>,
        visible: bool,
        bounds: Bounds,
        /// The largest size mstsc accepted (it caps its window at the session size).
        cap: Option<(i32, i32)>,
    }
    impl Drop for Client {
        fn drop(&mut self) {
            // The retained Child owns the process handle: PID reuse cannot
            // redirect this termination to a different mstsc instance.
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = std::fs::remove_file(&self.file);
        }
    }

    struct Search {
        pid: u32,
        hwnd: Option<HWND>,
    }
    unsafe extern "system" fn find_window(hwnd: HWND, context: LPARAM) -> windows::core::BOOL {
        // SAFETY: EnumWindows is synchronous; context points to the stack
        // Search for this enumeration, and all buffers are locally bounded.
        unsafe {
            let search = &mut *(context.0 as *mut Search);
            let mut pid = 0;
            GetWindowThreadProcessId(hwnd, Some(&mut pid));
            if pid == search.pid {
                let mut name = [0u16; 128];
                let length = GetClassNameW(hwnd, &mut name);
                if String::from_utf16_lossy(&name[..length.max(0) as usize])
                    == "TscShellContainerClass"
                {
                    search.hwnd = Some(hwnd);
                }
            }
        }
        true.into()
    }

    fn owned_window(client: &Client) -> Option<HWND> {
        let hwnd = HWND(client.window? as *mut _);
        // SAFETY: HWND is never trusted from the page; ownership is checked
        // on every use, in addition to the retained process handle.
        unsafe {
            let mut pid = 0;
            GetWindowThreadProcessId(hwnd, Some(&mut pid));
            let mut name = [0u16; 128];
            let length = GetClassNameW(hwnd, &mut name);
            (IsWindow(Some(hwnd)).as_bool()
                && pid == client.child.id()
                && String::from_utf16_lossy(&name[..length.max(0) as usize])
                    == "TscShellContainerClass")
                .then_some(hwnd)
        }
    }

    /// The window's rectangle in its parent's client coordinates.
    fn rect_in_parent(hwnd: HWND, parent: HWND) -> Option<(i32, i32, i32, i32)> {
        // SAFETY: reads geometry of verified windows into a local rectangle.
        unsafe {
            let mut rect = RECT::default();
            GetWindowRect(hwnd, &mut rect).ok()?;
            let mut info = WINDOWINFO {
                cbSize: std::mem::size_of::<WINDOWINFO>() as u32,
                ..Default::default()
            };
            GetWindowInfo(parent, &mut info).ok()?;
            Some((
                rect.left - info.rcClient.left,
                rect.top - info.rcClient.top,
                rect.right - rect.left,
                rect.bottom - rect.top,
            ))
        }
    }

    /// Puts the client where the page asked, clamped to the host window, and
    /// does nothing when it is already there: repeated moves make it flicker.
    fn place(client: &mut Client, window: &Viewport) -> Result<(), String> {
        let Some(hwnd) = owned_window(client) else {
            return Ok(());
        };
        let parent = HWND(window.parent as *mut _);
        let scale = window.scale;
        let b = &client.bounds;
        // Bounds from before a resize or scaling change are clamped to the
        // current client area instead of hiding the session.
        let (max_w, max_h) = (window.width as i32, window.height as i32);
        let x = ((b.x * scale).round() as i32).clamp(0, max_w);
        let y = ((b.y * scale).round() as i32).clamp(0, max_h);
        let width = (((b.x + b.width) * scale).round() as i32).min(max_w) - x;
        let height = (((b.y + b.height) * scale).round() as i32).min(max_h) - y;
        // SAFETY: bounded dimensions of our process-owned child window. No
        // focus is stolen during status polls or resize notifications.
        unsafe {
            let shown = IsWindowVisible(hwnd).as_bool();
            if !client.visible || !b.valid() || width < 160 || height < 120 {
                if shown {
                    let _ = ShowWindow(hwnd, SW_HIDE);
                }
                return Ok(());
            }
            let current = rect_in_parent(hwnd, parent);
            // mstsc caps its window at the session size; when it changes that
            // size itself (a new remote resolution), the old cap no longer holds.
            if let (Some(cap), Some((_, _, w, h))) = (client.cap, current)
                && shown
                && (w, h) != (width.min(cap.0), height.min(cap.1))
            {
                client.cap = None;
            }
            let (tw, th) = client
                .cap
                .map_or((width, height), |(cw, ch)| (width.min(cw), height.min(ch)));
            let target = (x + (width - tw) / 2, y + (height - th) / 2, tw, th);
            let on_top = GetWindow(parent, GW_CHILD).ok() == Some(hwnd);
            if shown && on_top && current == Some(target) {
                return Ok(());
            }
            SetWindowPos(
                hwnd,
                Some(HWND_TOP),
                target.0,
                target.1,
                tw,
                th,
                SWP_NOACTIVATE | SWP_SHOWWINDOW,
            )
            .map_err(|_| "远程桌面画面布局失败")?;
            // A smaller session sits centred; its size is remembered so the
            // next pass does not ask for the larger size again.
            if let Some((_, _, w, h)) = rect_in_parent(hwnd, parent)
                && w > 0
                && h > 0
                && (w < tw || h < th)
            {
                client.cap = Some((w, h));
                let _ = SetWindowPos(
                    hwnd,
                    Some(HWND_TOP),
                    x + (width - w.min(width)) / 2,
                    y + (height - h.min(height)) / 2,
                    0,
                    0,
                    SWP_NOACTIVATE | SWP_NOSIZE,
                );
            }
        }
        Ok(())
    }

    /// The host's other children (the web view) must not paint over the
    /// embedded client; only windows of this process are changed.
    fn clip_host_siblings(parent: HWND, embedded: HWND) {
        // SAFETY: walks the direct children of our own top-level window and
        // only adds WS_CLIPSIBLINGS to windows owned by this process.
        unsafe {
            let mut child = GetWindow(parent, GW_CHILD).ok();
            while let Some(hwnd) = child {
                let mut pid = 0;
                GetWindowThreadProcessId(hwnd, Some(&mut pid));
                if hwnd == embedded || pid == std::process::id() {
                    let style = GetWindowLongW(hwnd, GWL_STYLE) as u32;
                    if style & WS_CLIPSIBLINGS.0 == 0 {
                        SetWindowLongW(hwnd, GWL_STYLE, (style | WS_CLIPSIBLINGS.0) as i32);
                        let _ = SetWindowPos(
                            hwnd,
                            None,
                            0,
                            0,
                            0,
                            0,
                            SWP_NOMOVE
                                | SWP_NOSIZE
                                | SWP_NOZORDER
                                | SWP_NOACTIVATE
                                | SWP_FRAMECHANGED,
                        );
                    }
                }
                child = GetWindow(hwnd, GW_HWNDNEXT).ok();
            }
        }
    }

    pub(super) fn enforce(state: &mut RdpState, window: &Viewport) -> bool {
        let Some(client) = state.client.as_mut() else {
            return false;
        };
        if client
            .child
            .try_wait()
            .map_or(true, |status| status.is_some())
        {
            state.client.take();
            return false;
        }
        let _ = place(client, window);
        true
    }

    pub(super) fn apply(
        state: &mut RdpState,
        window: &Viewport,
        data_root: &std::path::Path,
        request: Request,
    ) -> Result<Status, String> {
        // SAFETY: querying an arbitrary HWND is supported by Win32. Only a
        // live window owned by this host may become the parent, and geometry is
        // finite and bounded before any native window mutation.
        let parent = HWND(window.parent as *mut _);
        let valid_parent = unsafe {
            let mut pid = 0;
            GetWindowThreadProcessId(parent, Some(&mut pid));
            IsWindow(Some(parent)).as_bool() && pid == std::process::id()
        };
        if !valid_parent || !window.scale.is_finite() || !(0.5..=8.0).contains(&window.scale) {
            return Err("远程桌面宿主窗口无效".to_owned());
        }
        if let Some(client) = state.client.as_mut()
            && client
                .child
                .try_wait()
                .map_err(|_| "无法核实远程桌面进程")?
                .is_some()
        {
            state.client.take();
        }
        match request {
            Request::Start {
                server,
                clipboard,
                bounds,
                resolution,
            } => {
                if !valid_server(&server)
                    || !bounds.valid()
                    || resolution.is_some_and(|size| !size.valid())
                    || (bounds.x + bounds.width) * window.scale > window.width as f64 + 2.0
                    || (bounds.y + bounds.height) * window.scale > window.height as f64 + 2.0
                {
                    return Err("远程桌面地址或显示区域无效".to_owned());
                }
                if state.client.is_some() {
                    return Err("已有远程桌面，请先断开当前会话".to_owned());
                }
                let exe = std::env::var_os("SystemRoot")
                    .map(PathBuf::from)
                    .map(|p| p.join("System32\\mstsc.exe"))
                    .filter(|p| p.is_absolute() && p.is_file())
                    .ok_or("系统远程桌面客户端不可用")?;
                let id = uuid::Uuid::new_v4().to_string();
                let file = data_root.join(format!("rdp-{id}.rdp"));
                let mut config = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&file)
                    .map_err(|_| "无法创建本次连接配置")?;
                // No saved credentials or automatic drive/device forwarding.
                // Authentication level 2 lets mstsc show the server certificate and ask the
                // operator; level 1 refuses self-signed hosts outright and 0 would skip the check.
                // Without a chosen size the session starts at the viewport's size and follows it.
                let size = resolution.unwrap_or_else(|| Resolution::fitting(&bounds, window.scale));
                let dynamic = u8::from(resolution.is_none());
                let (desktop_width, desktop_height) = (size.width, size.height);
                let text = format!(
                    "full address:s:{server}\r\nscreen mode id:i:1\r\nuse multimon:i:0\r\nsmart sizing:i:1\r\ndynamic resolution:i:{dynamic}\r\ndesktopwidth:i:{desktop_width}\r\ndesktopheight:i:{desktop_height}\r\nauthentication level:i:2\r\nenablecredsspsupport:i:1\r\nprompt for credentials:i:1\r\nredirectclipboard:i:{}\r\nredirectprinters:i:0\r\nredirectcomports:i:0\r\nredirectsmartcards:i:0\r\nredirectwebauthn:i:0\r\ndrivestoredirect:s:\r\ndevicestoredirect:s:\r\naudiomode:i:2\r\naudiocapturemode:i:0\r\nkeyboardhook:i:1\r\n",
                    u8::from(clipboard)
                );
                if config
                    .write_all(text.as_bytes())
                    .and_then(|_| config.sync_all())
                    .is_err()
                {
                    drop(config);
                    let _ = std::fs::remove_file(&file);
                    return Err("无法保存本次连接配置".to_owned());
                }
                drop(config);
                let child = match Command::new(exe)
                    .arg(&file)
                    .arg("/public")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                {
                    Ok(child) => child,
                    Err(_) => {
                        let _ = std::fs::remove_file(&file);
                        return Err("无法启动系统远程桌面".to_owned());
                    }
                };
                state.client = Some(Client {
                    id,
                    server,
                    child,
                    file,
                    window: None,
                    visible: true,
                    bounds,
                    cap: None,
                });
            }
            Request::Place { client_id, bounds } => {
                let client = state
                    .client
                    .as_mut()
                    .filter(|c| c.id == client_id)
                    .ok_or("远程桌面已变化")?;
                if !bounds.valid() {
                    return Err("远程桌面显示区域无效".to_owned());
                }
                client.bounds = bounds;
                client.visible = true;
            }
            Request::Hide { client_id } => {
                if let Some(client) = state.client.as_mut().filter(|c| c.id == client_id) {
                    client.visible = false;
                }
            }
            Request::Disconnect { client_id } => {
                if state.client.as_ref().is_none_or(|c| c.id != client_id) {
                    return Err("远程桌面已变化，请重新核实".to_owned());
                }
                state.stop();
            }
            Request::Status {} => {}
        }
        let Some(client) = state.client.as_mut() else {
            return Ok(Status {
                client_id: None,
                server: String::new(),
                phase: "idle",
                message: String::new(),
            });
        };
        if owned_window(client).is_none() {
            client.window = None;
            let mut search = Search {
                pid: client.child.id(),
                hwnd: None,
            };
            // SAFETY: synchronous enumeration with a valid stack context.
            unsafe {
                EnumWindows(
                    Some(find_window),
                    LPARAM(&mut search as *mut Search as isize),
                )
                .map_err(|_| "无法定位远程桌面画面")?;
            }
            if let Some(hwnd) = search.hwnd {
                let parent = HWND(window.parent as *mut _);
                // SAFETY: only the class and process matched above are changed.
                // No other mstsc window is adopted. SetParent and positioning
                // execute on Tauri's main thread; credentials remain in mstsc.
                unsafe {
                    let style = GetWindowLongW(hwnd, GWL_STYLE);
                    SetWindowLongW(
                        hwnd,
                        GWL_STYLE,
                        (style as u32 & !(WS_POPUP.0 | WS_CAPTION.0 | WS_THICKFRAME.0)) as i32
                            | WS_CHILD.0 as i32,
                    );
                    let _ = SetParent(hwnd, Some(parent));
                    if GetParent(hwnd).ok() != Some(parent) {
                        SetWindowLongW(hwnd, GWL_STYLE, style);
                        return Err("当前客户端无法嵌入，请在系统远程桌面窗口操作".to_owned());
                    }
                }
                clip_host_siblings(parent, hwnd);
                // SAFETY: applies the style change above once, on our verified child.
                unsafe {
                    let _ = SetWindowPos(
                        hwnd,
                        None,
                        0,
                        0,
                        0,
                        0,
                        SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED,
                    );
                }
                client.window = Some(hwnd.0 as usize);
            }
        }
        place(client, window)?;
        Ok(Status {
            client_id: Some(client.id.clone()),
            server: client.server.clone(),
            phase: if client.window.is_some() {
                "embedded"
            } else {
                "waiting"
            },
            message: if client.window.is_some() {
                "画面已嵌入；实际连接状态以远程桌面画面为准"
            } else {
                "正在等待远程桌面画面，请完成系统凭据或证书提示"
            }
            .to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    #[test]
    fn unowned_parent_is_rejected_before_any_client_or_file_is_created() {
        let directory =
            std::env::temp_dir().join(format!("lovelyhawk-rdp-{}", uuid::Uuid::new_v4()));
        let viewport = Viewport {
            parent: 0,
            scale: 1.0,
            width: 1000,
            height: 800,
        };
        let mut state = RdpState::default();
        let request = Request::Start {
            server: "192.0.2.1".to_owned(),
            clipboard: false,
            bounds: Bounds {
                x: 100.0,
                y: 100.0,
                width: 700.0,
                height: 500.0,
            },
            resolution: None,
        };
        assert!(
            state
                .apply(&viewport, &directory, request)
                .unwrap_err()
                .contains("宿主窗口")
        );
        assert!(!directory.exists());
        assert!(state.client.is_none());
    }
    #[test]
    fn rejects_config_injection_and_unbounded_geometry() {
        assert!(valid_server("server.example:3389"));
        assert!(valid_server("[::1]:3389"));
        for input in [
            "host\r\nredirectdrives:i:1",
            "/admin",
            "host /f",
            "file://host",
            "",
        ] {
            assert!(!valid_server(input));
        }
        assert!(
            !Bounds {
                x: 0.0,
                y: 0.0,
                width: 100.0,
                height: f64::NAN
            }
            .valid()
        );
        assert!(serde_json::from_str::<Request>(r#"{"action":"status","pid":123}"#).is_err());
    }
    #[test]
    fn resolutions_stay_within_what_mstsc_accepts() {
        assert!(
            Resolution {
                width: 1920,
                height: 1080
            }
            .valid()
        );
        for (width, height) in [(1921, 1080), (320, 240), (9000, 1080), (1920, 9000)] {
            assert!(!Resolution { width, height }.valid());
        }
        let bounds = Bounds {
            x: 100.0,
            y: 100.0,
            width: 901.3,
            height: 473.0,
        };
        let fit = Resolution::fitting(&bounds, 2.0);
        assert_eq!((fit.width, fit.height), (1802, 946));
        assert!(fit.valid());
        let tiny = Resolution::fitting(
            &Bounds {
                width: 200.0,
                height: 130.0,
                ..bounds
            },
            1.0,
        );
        assert!(tiny.valid());
        let parsed: Request = serde_json::from_str(
            r#"{"action":"start","server":"h","clipboard":false,"bounds":{"x":0,"y":40,"width":800,"height":600},"resolution":{"width":1600,"height":900}}"#,
        )
        .unwrap();
        assert!(matches!(
            parsed,
            Request::Start {
                resolution: Some(Resolution {
                    width: 1600,
                    height: 900
                }),
                ..
            }
        ));
        assert!(serde_json::from_str::<Request>(
            r#"{"action":"start","server":"h","clipboard":false,"bounds":{"x":0,"y":40,"width":800,"height":600},"resolution":{"width":1600,"height":900,"bpp":32}}"#,
        )
        .is_err());
    }
}
