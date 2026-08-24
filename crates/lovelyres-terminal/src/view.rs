use std::sync::Arc;

use gpui::{Context, IntoElement, Render, Window, div, prelude::*, px, rgb};
use parking_lot::Mutex;

use crate::{CellColor, TerminalModel};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalPalette {
    pub background: u32,
    pub foreground: u32,
    pub selection: u32,
    pub cursor: u32,
    pub ansi: [u32; 16],
}

impl Default for TerminalPalette {
    fn default() -> Self {
        Self {
            background: 0x0b1020,
            foreground: 0xdbe7ff,
            selection: 0x24446f,
            cursor: 0x79c0ff,
            ansi: [
                0x0b1020, 0xff6b7a, 0x63d297, 0xf2c86b, 0x70a5ff, 0xc792ea, 0x67d4e8, 0xdbe7ff,
                0x5d6785, 0xff8a96, 0x83e6ae, 0xffdc8a, 0x91bdff, 0xdaa8f5, 0x8be7f5, 0xffffff,
            ],
        }
    }
}

impl TerminalPalette {
    pub fn resolve(&self, color: &CellColor, foreground: bool, bold: bool, dim: bool) -> u32 {
        let resolved = match color {
            CellColor::Rgb(red, green, blue) => {
                (u32::from(*red) << 16) | (u32::from(*green) << 8) | u32::from(*blue)
            }
            CellColor::Indexed(index) => self.resolve_indexed(*index),
            CellColor::Named(name) => self.resolve_named(name, foreground, bold),
        };
        if dim { dim_color(resolved) } else { resolved }
    }

    fn resolve_named(&self, name: &str, foreground: bool, bold: bool) -> u32 {
        let normal = match name {
            "Black" | "DimBlack" => Some(0),
            "Red" | "DimRed" => Some(1),
            "Green" | "DimGreen" => Some(2),
            "Yellow" | "DimYellow" => Some(3),
            "Blue" | "DimBlue" => Some(4),
            "Magenta" | "DimMagenta" => Some(5),
            "Cyan" | "DimCyan" => Some(6),
            "White" | "DimWhite" => Some(7),
            "BrightBlack" => Some(8),
            "BrightRed" => Some(9),
            "BrightGreen" => Some(10),
            "BrightYellow" => Some(11),
            "BrightBlue" => Some(12),
            "BrightMagenta" => Some(13),
            "BrightCyan" => Some(14),
            "BrightWhite" => Some(15),
            _ => None,
        };
        if let Some(mut index) = normal {
            if bold && index < 8 {
                index += 8;
            }
            let color = self.ansi[index];
            return if name.starts_with("Dim") {
                dim_color(color)
            } else {
                color
            };
        }
        match name {
            "Background" => self.background,
            "Cursor" => self.cursor,
            "BrightForeground" => self.ansi[15],
            "DimForeground" => dim_color(self.foreground),
            _ if foreground => self.foreground,
            _ => self.background,
        }
    }

    fn resolve_indexed(&self, index: u8) -> u32 {
        match index {
            0..=15 => self.ansi[index as usize],
            16..=231 => {
                let value = index - 16;
                let red = value / 36;
                let green = (value % 36) / 6;
                let blue = value % 6;
                let component = |component: u8| {
                    if component == 0 {
                        0
                    } else {
                        55 + u32::from(component) * 40
                    }
                };
                (component(red) << 16) | (component(green) << 8) | component(blue)
            }
            232..=255 => {
                let gray = 8 + u32::from(index - 232) * 10;
                (gray << 16) | (gray << 8) | gray
            }
        }
    }
}

fn dim_color(color: u32) -> u32 {
    let red = ((color >> 16) & 0xff) * 2 / 3;
    let green = ((color >> 8) & 0xff) * 2 / 3;
    let blue = (color & 0xff) * 2 / 3;
    (red << 16) | (green << 8) | blue
}

/// Native GPUI entry point for the terminal surface.
///
/// It deliberately renders text nodes only. Cell-level color batching, input,
/// IME, and selection painting remain feasibility-gate work rather than being
/// represented as complete here.
pub struct TerminalView {
    model: Arc<Mutex<TerminalModel>>,
    palette: TerminalPalette,
}

impl TerminalView {
    pub fn new(model: Arc<Mutex<TerminalModel>>) -> Self {
        Self {
            model,
            palette: TerminalPalette::default(),
        }
    }

    pub fn with_palette(mut self, palette: TerminalPalette) -> Self {
        self.palette = palette;
        self
    }

    pub fn model(&self) -> Arc<Mutex<TerminalModel>> {
        self.model.clone()
    }
}

impl Render for TerminalView {
    fn render(&mut self, _window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        let model = self.model.lock();
        let lines = model.viewport_lines();
        let font_family = model.config().font_family.clone();
        let font_size = model.config().font_size;
        let line_height = font_size * model.config().line_height;
        drop(model);

        div()
            .id("lovelyres-native-terminal")
            .flex()
            .flex_col()
            .size_full()
            .overflow_hidden()
            .bg(rgb(self.palette.background))
            .text_color(rgb(self.palette.foreground))
            .font_family(font_family)
            .text_size(px(font_size))
            .children(lines.into_iter().map(|line| {
                div()
                    .h(px(line_height))
                    .flex_none()
                    .overflow_hidden()
                    .child(if line.is_empty() {
                        " ".to_owned()
                    } else {
                        line
                    })
            }))
    }
}
