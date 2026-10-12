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

pub const THEMES: [NativeTheme; 4] = [
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
        id: "incident-canvas",
        window_background: "#05080c",
        terminal_background: "#04070a",
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
