use gpui::{App, Hsla, Rgba, px, rgb};
use lovelyres_core::settings::Theme as CoreTheme;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ThemeId {
    Light,
    #[default]
    Dark,
    Sakura,
    IncidentCanvas,
}

impl ThemeId {
    pub const ALL: [Self; 4] = [Self::Light, Self::Dark, Self::Sakura, Self::IncidentCanvas];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Light => "Light",
            Self::Dark => "Dark",
            Self::Sakura => "Sakura",
            Self::IncidentCanvas => "Incident Canvas",
        }
    }

    pub const fn next(self) -> Self {
        match self {
            Self::Light => Self::Dark,
            Self::Dark => Self::Sakura,
            Self::Sakura => Self::IncidentCanvas,
            Self::IncidentCanvas => Self::Light,
        }
    }

    pub fn tokens(self) -> ThemeTokens {
        match self {
            Self::Light => ThemeTokens::new(
                0xf6f8fb, 0xffffff, 0xf2f5f9, 0x172033, 0x68758a, 0xe3e8ef, 0x2563eb, 0x16885b,
                0xc17b00, 0xc43b46, 0x0f1724,
            ),
            Self::Dark => ThemeTokens::new(
                0x0c111b, 0x141b28, 0x1b2535, 0xe6ecf5, 0x91a0b6, 0x2a3547, 0x5b8cff, 0x43c59e,
                0xf0b35b, 0xff6874, 0x090d14,
            ),
            Self::Sakura => ThemeTokens::new(
                0x1d141b, 0x291c27, 0x382532, 0xffedf6, 0xcba8ba, 0x523648, 0xf187b5, 0x76c7aa,
                0xf1b86b, 0xff718c, 0x140e13,
            ),
            Self::IncidentCanvas => ThemeTokens::new(
                0x12120f, 0x1d1c17, 0x28261e, 0xf3ecd2, 0xaaa184, 0x454130, 0xd9a441, 0x84b66a,
                0xd69045, 0xd65c4d, 0x0c0c0a,
            ),
        }
    }
}

pub fn apply_component_theme(theme_id: ThemeId, cx: &mut App) {
    let tokens = theme_id.tokens();
    let background: Hsla = tokens.background.into();
    let surface: Hsla = tokens.surface.into();
    let surface_alt: Hsla = tokens.surface_alt.into();
    let text: Hsla = tokens.text.into();
    let muted: Hsla = tokens.muted.into();
    let border: Hsla = tokens.border.into();
    let accent: Hsla = tokens.accent.into();
    let success: Hsla = tokens.success.into();
    let warning: Hsla = tokens.warning.into();
    let danger: Hsla = tokens.danger.into();
    let white: Hsla = rgb(0xffffff).into();
    let component = gpui_component::Theme::global_mut(cx);

    component.font_family = "Inter".into();
    component.font_size = px(14.0);
    component.mono_font_family = "Cascadia Mono".into();
    component.mono_font_size = px(13.0);
    component.radius = px(7.0);
    component.radius_lg = px(10.0);

    component.background = background;
    component.foreground = text;
    component.border = border;
    component.input = border;
    component.muted = surface_alt;
    component.muted_foreground = muted;
    component.primary = accent;
    component.primary_active = adjust_lightness(accent, -0.08);
    component.primary_hover = adjust_lightness(accent, -0.04);
    component.primary_foreground = white;
    component.secondary = surface_alt;
    component.secondary_active = border;
    component.secondary_hover = adjust_lightness(
        surface_alt,
        if theme_id == ThemeId::Light {
            -0.03
        } else {
            0.04
        },
    );
    component.secondary_foreground = text;
    component.accent = accent.opacity(0.10);
    component.accent_foreground = accent;
    component.selection = accent.opacity(0.22);
    component.ring = accent;
    component.caret = accent;
    component.link = accent;
    component.link_active = adjust_lightness(accent, -0.08);
    component.link_hover = adjust_lightness(accent, -0.04);

    component.sidebar = surface;
    component.sidebar_foreground = text;
    component.sidebar_border = border;
    component.sidebar_accent = accent.opacity(0.10);
    component.sidebar_accent_foreground = accent;
    component.sidebar_primary = accent;
    component.sidebar_primary_foreground = white;
    component.title_bar = surface;
    component.title_bar_border = border;

    component.table = surface;
    component.table_even = surface_alt.opacity(if theme_id == ThemeId::Light {
        0.55
    } else {
        0.35
    });
    component.table_head = surface_alt;
    component.table_head_foreground = muted;
    component.table_hover = accent.opacity(0.07);
    component.table_active = accent.opacity(0.12);
    component.table_active_border = accent;
    component.table_row_border = border;
    component.list = surface;
    component.list_even = surface_alt;
    component.list_head = surface_alt;
    component.list_hover = accent.opacity(0.07);
    component.list_active = accent.opacity(0.12);
    component.list_active_border = accent;

    component.success = success;
    component.success_foreground = white;
    component.warning = warning;
    component.warning_foreground = white;
    component.danger = danger;
    component.danger_foreground = white;
    component.popover = surface;
    component.popover_foreground = text;
    component.overlay = background.opacity(0.72);
}

fn adjust_lightness(mut color: Hsla, delta: f32) -> Hsla {
    color.l = (color.l + delta).clamp(0.0, 1.0);
    color
}

impl From<CoreTheme> for ThemeId {
    fn from(theme: CoreTheme) -> Self {
        match theme {
            CoreTheme::Light => Self::Light,
            CoreTheme::Dark => Self::Dark,
            CoreTheme::Sakura => Self::Sakura,
            CoreTheme::IncidentCanvas => Self::IncidentCanvas,
        }
    }
}

impl From<ThemeId> for CoreTheme {
    fn from(theme: ThemeId) -> Self {
        match theme {
            ThemeId::Light => Self::Light,
            ThemeId::Dark => Self::Dark,
            ThemeId::Sakura => Self::Sakura,
            ThemeId::IncidentCanvas => Self::IncidentCanvas,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ThemeTokens {
    pub background: Rgba,
    pub surface: Rgba,
    pub surface_alt: Rgba,
    pub text: Rgba,
    pub muted: Rgba,
    pub border: Rgba,
    pub accent: Rgba,
    pub success: Rgba,
    pub warning: Rgba,
    pub danger: Rgba,
    pub terminal_background: Rgba,
}

impl ThemeTokens {
    #[allow(clippy::too_many_arguments)]
    fn new(
        background: u32,
        surface: u32,
        surface_alt: u32,
        text: u32,
        muted: u32,
        border: u32,
        accent: u32,
        success: u32,
        warning: u32,
        danger: u32,
        terminal_background: u32,
    ) -> Self {
        Self {
            background: rgb(background),
            surface: rgb(surface),
            surface_alt: rgb(surface_alt),
            text: rgb(text),
            muted: rgb(muted),
            border: rgb(border),
            accent: rgb(accent),
            success: rgb(success),
            warning: rgb(warning),
            danger: rgb(danger),
            terminal_background: rgb(terminal_background),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn theme_cycle_is_closed() {
        let start = ThemeId::Dark;
        let end = (0..ThemeId::ALL.len()).fold(start, |theme, _| theme.next());
        assert_eq!(start, end);
    }
}
