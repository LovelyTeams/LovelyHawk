use crate::CellPosition;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseTrackingMode {
    Off,
    Click,
    ButtonMotion,
    AnyMotion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseEncoding {
    Legacy,
    Sgr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MouseProtocol {
    pub tracking: MouseTrackingMode,
    pub encoding: MouseEncoding,
}

impl Default for MouseProtocol {
    fn default() -> Self {
        Self {
            tracking: MouseTrackingMode::Off,
            encoding: MouseEncoding::Legacy,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseButtonCode {
    Left,
    Middle,
    Right,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseEventKind {
    Press(MouseButtonCode),
    Release(MouseButtonCode),
    Move(Option<MouseButtonCode>),
    WheelUp,
    WheelDown,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MouseModifiers {
    pub shift: bool,
    pub alt: bool,
    pub control: bool,
}

impl MouseProtocol {
    pub fn enabled(self) -> bool {
        self.tracking != MouseTrackingMode::Off
    }

    pub fn encode(
        self,
        event: MouseEventKind,
        position: CellPosition,
        modifiers: MouseModifiers,
    ) -> Option<Vec<u8>> {
        if !self.should_report(event) {
            return None;
        }

        let mut code = match event {
            MouseEventKind::Press(button) | MouseEventKind::Release(button) => button_code(button),
            MouseEventKind::Move(button) => button.map(button_code).unwrap_or(3) + 32,
            MouseEventKind::WheelUp => 64,
            MouseEventKind::WheelDown => 65,
        };
        code += u8::from(modifiers.shift) * 4;
        code += u8::from(modifiers.alt) * 8;
        code += u8::from(modifiers.control) * 16;

        let column = position.column.saturating_add(1);
        let row = position.row.saturating_add(1);
        match self.encoding {
            MouseEncoding::Sgr => {
                let suffix = if matches!(event, MouseEventKind::Release(_)) {
                    'm'
                } else {
                    'M'
                };
                Some(format!("\x1b[<{code};{column};{row}{suffix}").into_bytes())
            }
            MouseEncoding::Legacy => {
                let legacy_code = if matches!(event, MouseEventKind::Release(_)) {
                    3 + u8::from(modifiers.shift) * 4
                        + u8::from(modifiers.alt) * 8
                        + u8::from(modifiers.control) * 16
                } else {
                    code
                };
                let column = u8::try_from(column.min(223)).ok()?;
                let row = u8::try_from(row.min(223)).ok()?;
                Some(vec![
                    0x1b,
                    b'[',
                    b'M',
                    legacy_code.saturating_add(32),
                    column.saturating_add(32),
                    row.saturating_add(32),
                ])
            }
        }
    }

    fn should_report(self, event: MouseEventKind) -> bool {
        match (self.tracking, event) {
            (MouseTrackingMode::Off, _) => false,
            (_, MouseEventKind::Press(_) | MouseEventKind::Release(_)) => true,
            (_, MouseEventKind::WheelUp | MouseEventKind::WheelDown) => true,
            (MouseTrackingMode::AnyMotion, MouseEventKind::Move(_)) => true,
            (MouseTrackingMode::ButtonMotion, MouseEventKind::Move(Some(_))) => true,
            _ => false,
        }
    }
}

fn button_code(button: MouseButtonCode) -> u8 {
    match button {
        MouseButtonCode::Left => 0,
        MouseButtonCode::Middle => 1,
        MouseButtonCode::Right => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sgr_mouse_encodes_press_release_motion_and_modifiers() {
        let protocol = MouseProtocol {
            tracking: MouseTrackingMode::AnyMotion,
            encoding: MouseEncoding::Sgr,
        };
        let position = CellPosition::new(4, 9);
        assert_eq!(
            protocol.encode(
                MouseEventKind::Press(MouseButtonCode::Left),
                position,
                MouseModifiers::default()
            ),
            Some(b"\x1b[<0;10;5M".to_vec())
        );
        assert_eq!(
            protocol.encode(
                MouseEventKind::Release(MouseButtonCode::Left),
                position,
                MouseModifiers::default()
            ),
            Some(b"\x1b[<0;10;5m".to_vec())
        );
        assert_eq!(
            protocol.encode(
                MouseEventKind::Move(None),
                position,
                MouseModifiers {
                    control: true,
                    ..Default::default()
                }
            ),
            Some(b"\x1b[<51;10;5M".to_vec())
        );
    }

    #[test]
    fn tracking_modes_filter_motion_and_legacy_coordinates_are_bounded() {
        let click = MouseProtocol {
            tracking: MouseTrackingMode::Click,
            encoding: MouseEncoding::Legacy,
        };
        assert_eq!(
            click.encode(
                MouseEventKind::Move(Some(MouseButtonCode::Left)),
                CellPosition::new(0, 0),
                MouseModifiers::default()
            ),
            None
        );
        let drag = MouseProtocol {
            tracking: MouseTrackingMode::ButtonMotion,
            encoding: MouseEncoding::Legacy,
        };
        let encoded = drag
            .encode(
                MouseEventKind::Move(Some(MouseButtonCode::Left)),
                CellPosition::new(u16::MAX, u16::MAX),
                MouseModifiers::default(),
            )
            .unwrap();
        assert_eq!(encoded.len(), 6);
        assert_eq!(encoded[4], 255);
        assert_eq!(encoded[5], 255);
    }
}
