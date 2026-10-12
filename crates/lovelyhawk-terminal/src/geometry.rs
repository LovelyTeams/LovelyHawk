use crate::{CellPosition, TerminalModel, TerminalModelError, TerminalSize};

/// Logical terminal layout plus the physical-pixel scale advertised to the PTY.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TerminalGeometry {
    pub font_size: f32,
    pub line_height_multiplier: f32,
    pub cell_width: f32,
    pub cell_height: f32,
    pub padding: f32,
    pub dpi_scale: f32,
}

impl TerminalGeometry {
    pub fn from_font(font_size: f32, line_height_multiplier: f32) -> Self {
        let font_size = finite_positive(font_size, 14.0);
        let line_height_multiplier = finite_positive(line_height_multiplier, 1.2).max(1.0);
        Self {
            font_size,
            line_height_multiplier,
            cell_width: font_size * 0.6,
            cell_height: font_size * line_height_multiplier,
            padding: 8.0,
            dpi_scale: 1.0,
        }
    }

    pub fn with_measured_cell(mut self, width: f32, height: f32) -> Self {
        self.cell_width = finite_positive(width, self.cell_width);
        self.cell_height = finite_positive(height, self.cell_height);
        self
    }

    pub fn with_dpi_scale(mut self, dpi_scale: f32) -> Self {
        self.dpi_scale = finite_positive(dpi_scale, 1.0);
        self
    }

    pub fn with_padding(mut self, padding: f32) -> Self {
        self.padding = padding.max(0.0);
        self
    }

    pub fn terminal_size(&self, width: f32, height: f32) -> TerminalSize {
        let content_width = (width - self.padding * 2.0).max(self.cell_width * 2.0);
        let content_height = (height - self.padding * 2.0).max(self.cell_height);
        let columns = (content_width / self.cell_width)
            .floor()
            .clamp(2.0, u16::MAX as f32) as u16;
        let rows = (content_height / self.cell_height)
            .floor()
            .clamp(1.0, u16::MAX as f32) as u16;
        let physical_width = (self.cell_width * self.dpi_scale)
            .round()
            .clamp(0.0, u16::MAX as f32) as u16;
        let physical_height = (self.cell_height * self.dpi_scale)
            .round()
            .clamp(0.0, u16::MAX as f32) as u16;
        TerminalSize {
            columns,
            rows,
            cell_width: physical_width,
            cell_height: physical_height,
        }
    }

    pub fn cell_at_local_point(&self, x: f32, y: f32, size: TerminalSize) -> CellPosition {
        let column = ((x - self.padding).max(0.0) / self.cell_width).floor() as u16;
        let row = ((y - self.padding).max(0.0) / self.cell_height).floor() as u16;
        CellPosition::new(
            row.min(size.rows.saturating_sub(1)),
            column.min(size.columns.saturating_sub(1)),
        )
    }

    pub fn cell_origin(&self, position: CellPosition) -> (f32, f32) {
        (
            self.padding + position.column as f32 * self.cell_width,
            self.padding + position.row as f32 * self.cell_height,
        )
    }

    pub fn wheel_lines(&self, pixel_delta_y: f32) -> i32 {
        if pixel_delta_y == 0.0 {
            return 0;
        }
        let lines = (pixel_delta_y / self.cell_height).round() as i32;
        if lines == 0 {
            pixel_delta_y.signum() as i32
        } else {
            lines
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PointerSelection {
    anchor: Option<CellPosition>,
}

impl PointerSelection {
    pub fn begin(
        &mut self,
        model: &mut TerminalModel,
        position: CellPosition,
    ) -> Result<(), TerminalModelError> {
        self.anchor = Some(position);
        model.select(position, position)
    }

    pub fn drag(
        &self,
        model: &mut TerminalModel,
        position: CellPosition,
    ) -> Result<(), TerminalModelError> {
        if let Some(anchor) = self.anchor {
            model.select(anchor, position)?;
        }
        Ok(())
    }

    pub fn end(&mut self) {
        self.anchor = None;
    }

    pub fn is_selecting(&self) -> bool {
        self.anchor.is_some()
    }
}

fn finite_positive(value: f32, fallback: f32) -> f32 {
    if value.is_finite() && value > 0.0 {
        value
    } else {
        fallback
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TerminalConfig;

    #[test]
    fn resize_calculation_accounts_for_dpi_and_padding() {
        let geometry = TerminalGeometry::from_font(10.0, 1.2)
            .with_measured_cell(6.0, 12.0)
            .with_padding(6.0)
            .with_dpi_scale(1.5);
        let size = geometry.terminal_size(612.0, 372.0);
        assert_eq!(size.columns, 100);
        assert_eq!(size.rows, 30);
        assert_eq!(size.cell_width, 9);
        assert_eq!(size.cell_height, 18);
    }

    #[test]
    fn pointer_drag_selects_clamped_cells() {
        let config = TerminalConfig {
            size: TerminalSize::new(20, 2).unwrap(),
            ..Default::default()
        };
        let mut model = TerminalModel::new(config).unwrap();
        model.feed_output(b"mouse selection");
        let geometry = TerminalGeometry::from_font(10.0, 1.2)
            .with_measured_cell(5.0, 10.0)
            .with_padding(0.0);
        let mut pointer = PointerSelection::default();
        let start = geometry.cell_at_local_point(0.0, 0.0, model.size());
        let end = geometry.cell_at_local_point(24.9, 0.0, model.size());
        pointer.begin(&mut model, start).unwrap();
        pointer.drag(&mut model, end).unwrap();
        pointer.end();
        assert_eq!(model.selected_text().as_deref(), Some("mouse"));
    }
}
