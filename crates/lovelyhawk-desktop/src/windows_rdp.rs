//! Main-window adapter for the bounded native RDP viewport.
pub use lovelyhawk_win_dvc::rdp_viewport::{Request, Status};

#[derive(Debug, Default)]
pub struct RdpState {
    inner: lovelyhawk_win_dvc::rdp_viewport::RdpState,
    /// A watcher re-applies placement while a client exists.
    pub watching: bool,
}

impl RdpState {
    pub fn stop(&mut self) {
        self.inner.stop();
    }

    pub fn apply<R: tauri::Runtime>(
        &mut self,
        window: &tauri::WebviewWindow<R>,
        data_root: &std::path::Path,
        request: Request,
    ) -> Result<Status, String> {
        #[cfg(windows)]
        {
            self.inner.apply(&viewport(window)?, data_root, request)
        }
        #[cfg(not(windows))]
        {
            let _ = (window, data_root, request);
            Err("内嵌远程桌面仅适用于 Windows".to_owned())
        }
    }

    /// Keeps the embedded client where the page last put it, or hidden;
    /// false once no client remains.
    pub fn enforce<R: tauri::Runtime>(&mut self, window: &tauri::WebviewWindow<R>) -> bool {
        #[cfg(windows)]
        {
            viewport(window).is_ok_and(|viewport| self.inner.enforce(&viewport))
        }
        #[cfg(not(windows))]
        {
            let _ = window;
            false
        }
    }
}

#[cfg(windows)]
fn viewport<R: tauri::Runtime>(
    window: &tauri::WebviewWindow<R>,
) -> Result<lovelyhawk_win_dvc::rdp_viewport::Viewport, String> {
    let size = window.inner_size().map_err(|_| "无法读取窗口尺寸")?;
    Ok(lovelyhawk_win_dvc::rdp_viewport::Viewport {
        parent: window.hwnd().map_err(|_| "无法读取宿主窗口")?.0 as usize,
        scale: window.scale_factor().map_err(|_| "无法读取窗口缩放")?,
        width: size.width,
        height: size.height,
    })
}
