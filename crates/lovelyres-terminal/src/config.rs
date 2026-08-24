use alacritty_terminal::grid::Dimensions;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Character-cell and pixel dimensions advertised to the remote PTY.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalSize {
    pub columns: u16,
    pub rows: u16,
    pub cell_width: u16,
    pub cell_height: u16,
}

impl TerminalSize {
    pub fn new(columns: u16, rows: u16) -> Result<Self, TerminalConfigError> {
        let size = Self {
            columns,
            rows,
            cell_width: 0,
            cell_height: 0,
        };
        size.validate()?;
        Ok(size)
    }

    pub fn with_cell_pixels(mut self, width: u16, height: u16) -> Self {
        self.cell_width = width;
        self.cell_height = height;
        self
    }

    pub fn validate(self) -> Result<(), TerminalConfigError> {
        if self.columns < 2 {
            return Err(TerminalConfigError::Columns(self.columns));
        }
        if self.rows == 0 {
            return Err(TerminalConfigError::Rows(self.rows));
        }
        Ok(())
    }
}

impl Default for TerminalSize {
    fn default() -> Self {
        Self {
            columns: 120,
            rows: 36,
            cell_width: 0,
            cell_height: 0,
        }
    }
}

impl Dimensions for TerminalSize {
    fn total_lines(&self) -> usize {
        self.rows as usize
    }

    fn screen_lines(&self) -> usize {
        self.rows as usize
    }

    fn columns(&self) -> usize {
        self.columns as usize
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TerminalConfig {
    pub size: TerminalSize,
    pub scrollback_limit: usize,
    pub event_capacity: usize,
    pub font_family: String,
    pub font_size: f32,
    pub line_height: f32,
}

impl TerminalConfig {
    pub fn validate(&self) -> Result<(), TerminalConfigError> {
        self.size.validate()?;
        if self.event_capacity == 0 {
            return Err(TerminalConfigError::EventCapacity);
        }
        if !self.font_size.is_finite() || self.font_size <= 0.0 {
            return Err(TerminalConfigError::FontSize(self.font_size));
        }
        if !self.line_height.is_finite() || self.line_height < 1.0 {
            return Err(TerminalConfigError::LineHeight(self.line_height));
        }
        if self.font_family.trim().is_empty() {
            return Err(TerminalConfigError::FontFamily);
        }
        Ok(())
    }
}

impl Default for TerminalConfig {
    fn default() -> Self {
        Self {
            size: TerminalSize::default(),
            scrollback_limit: 10_000,
            event_capacity: 256,
            font_family: "monospace".to_owned(),
            font_size: 14.0,
            line_height: 1.2,
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq)]
pub enum TerminalConfigError {
    #[error("terminal requires at least two columns, got {0}")]
    Columns(u16),
    #[error("terminal requires at least one row, got {0}")]
    Rows(u16),
    #[error("terminal event capacity must be non-zero")]
    EventCapacity,
    #[error("terminal font size must be finite and positive, got {0}")]
    FontSize(f32),
    #[error("terminal line height must be finite and at least 1.0, got {0}")]
    LineHeight(f32),
    #[error("terminal font family must not be empty")]
    FontFamily,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_dimensions_that_alacritty_cannot_represent() {
        assert_eq!(
            TerminalSize::new(1, 24),
            Err(TerminalConfigError::Columns(1))
        );
        assert_eq!(TerminalSize::new(80, 0), Err(TerminalConfigError::Rows(0)));
    }
}
