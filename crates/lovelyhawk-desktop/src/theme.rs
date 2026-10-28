//! Native colors a window needs before the page paints.
//!
//! These mirror `ui/src/shared/theme-contract.ts`; `theme-contract.test.ts`
//! reads this file and fails if a value drifts, so a new theme must be added
//! in both places.

use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeTheme {
    pub id: &'static str,
    pub window_background: &'static str,
    pub terminal_background: &'static str,
}

pub const THEMES: [NativeTheme; 17] = [
    NativeTheme {
        id: "light",
        window_background: "#f5f7fa",
        terminal_background: "#eef1f6",
    },
    NativeTheme {
        id: "dark",
        window_background: "#0c1119",
        terminal_background: "#0a1017",
    },
    NativeTheme {
        id: "sakura",
        window_background: "#fbf6f8",
        terminal_background: "#f7eaef",
    },
    NativeTheme {
        id: "pink",
        window_background: "#fef7fb",
        terminal_background: "#fbeaf2",
    },
    NativeTheme {
        id: "tingwu",
        window_background: "#f5f6ec",
        terminal_background: "#eaeed8",
    },
    NativeTheme {
        id: "dongfang",
        window_background: "#eef4fa",
        terminal_background: "#e2ebf5",
    },
    NativeTheme {
        id: "chunchen",
        window_background: "#f0f1ed",
        terminal_background: "#e5e7e0",
    },
    NativeTheme {
        id: "ruolan",
        window_background: "#faf4e9",
        terminal_background: "#f3e9d8",
    },
    NativeTheme {
        id: "linye",
        window_background: "#f2f7e4",
        terminal_background: "#e6eec9",
    },
    NativeTheme {
        id: "shanhu",
        window_background: "#fdfaf0",
        terminal_background: "#faf5e4",
    },
    NativeTheme {
        id: "nihong",
        window_background: "#f8f5ff",
        terminal_background: "#efe8ff",
    },
    NativeTheme {
        id: "spark",
        window_background: "#f5f8ff",
        terminal_background: "#eaf1ff",
    },
    NativeTheme {
        id: "incident-canvas",
        window_background: "#05080c",
        terminal_background: "#04070a",
    },
    NativeTheme {
        id: "shenhai",
        window_background: "#0a1e21",
        terminal_background: "#071619",
    },
    NativeTheme {
        id: "wuye",
        window_background: "#14152e",
        terminal_background: "#0e0f22",
    },
    NativeTheme {
        id: "jiaotang",
        window_background: "#191007",
        terminal_background: "#120b04",
    },
    NativeTheme {
        id: "molv",
        window_background: "#0d1f19",
        terminal_background: "#091712",
    },
];

pub const DEFAULT_THEME_ID: &str = "light";

pub fn find(id: &str) -> Option<NativeTheme> {
    THEMES.iter().copied().find(|theme| theme.id == id)
}

pub fn resolve(id: &str) -> NativeTheme {
    find(id).unwrap_or(THEMES[0])
}

pub fn color(hex: &str) -> tauri::window::Color {
    let value = u32::from_str_radix(hex.trim_start_matches('#'), 16).unwrap_or(0xffffff);
    tauri::window::Color(
        ((value >> 16) & 0xff) as u8,
        ((value >> 8) & 0xff) as u8,
        (value & 0xff) as u8,
        0xff,
    )
}

/// What the page last asked for, applied to every window created after it.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WindowTheme {
    pub theme: String,
    pub scrim: bool,
}

impl Default for WindowTheme {
    fn default() -> Self {
        Self {
            theme: DEFAULT_THEME_ID.to_owned(),
            scrim: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_theme_color_is_a_six_digit_hex_value() {
        for theme in THEMES {
            for value in [theme.window_background, theme.terminal_background] {
                assert!(value.len() == 7 && value.starts_with('#'), "{}", theme.id);
                assert!(u32::from_str_radix(&value[1..], 16).is_ok(), "{}", theme.id);
            }
        }
        assert_eq!(resolve("unknown").id, DEFAULT_THEME_ID);
        assert_eq!(
            color("#0c1119"),
            tauri::window::Color(0x0c, 0x11, 0x19, 0xff)
        );
    }
}
