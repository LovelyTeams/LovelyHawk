use gpui::Keystroke;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyAction {
    Send(Vec<u8>),
    Copy,
    Paste,
    Search,
    Workspace(TerminalShortcut),
    Ignore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalShortcut {
    NewTab,
    CloseTab,
    NextTab,
    PreviousTab,
    Reconnect,
    FontIncrease,
    FontDecrease,
    FontReset,
    ToggleAi,
    AcceptCompletion,
    ScrollPageUp,
    ScrollPageDown,
    ScrollToTop,
    ScrollToBottom,
}

pub struct TerminalKeyEncoder;

impl TerminalKeyEncoder {
    pub fn encode(keystroke: &Keystroke, application_cursor: bool) -> KeyAction {
        Self::encode_with_modes(keystroke, application_cursor, false)
    }

    pub fn encode_with_modes(
        keystroke: &Keystroke,
        application_cursor: bool,
        application_keypad: bool,
    ) -> KeyAction {
        let key = keystroke.key.to_ascii_lowercase();
        let modifiers = keystroke.modifiers;

        if modifiers.secondary() && modifiers.shift && key == "c" {
            return KeyAction::Copy;
        }
        if modifiers.secondary() && modifiers.shift && key == "v" {
            return KeyAction::Paste;
        }
        if modifiers.secondary() && !modifiers.shift && key == "f" {
            return KeyAction::Search;
        }
        if modifiers.secondary() && modifiers.shift && key == "t" {
            return KeyAction::Workspace(TerminalShortcut::NewTab);
        }
        if modifiers.secondary() && modifiers.shift && key == "w" {
            return KeyAction::Workspace(TerminalShortcut::CloseTab);
        }
        if modifiers.secondary() && key == "tab" {
            let shortcut = if modifiers.shift {
                TerminalShortcut::PreviousTab
            } else {
                TerminalShortcut::NextTab
            };
            return KeyAction::Workspace(shortcut);
        }
        if modifiers.secondary() && modifiers.shift && key == "r" {
            return KeyAction::Workspace(TerminalShortcut::Reconnect);
        }
        if modifiers.secondary() && matches!(key.as_str(), "+" | "=") {
            return KeyAction::Workspace(TerminalShortcut::FontIncrease);
        }
        if modifiers.secondary() && key == "-" {
            return KeyAction::Workspace(TerminalShortcut::FontDecrease);
        }
        if modifiers.secondary() && key == "0" {
            return KeyAction::Workspace(TerminalShortcut::FontReset);
        }
        if modifiers.secondary() && modifiers.shift && key == "a" {
            return KeyAction::Workspace(TerminalShortcut::ToggleAi);
        }
        if modifiers.secondary() && key == "space" {
            return KeyAction::Workspace(TerminalShortcut::AcceptCompletion);
        }
        if modifiers.shift && !modifiers.secondary() && key == "pageup" {
            return KeyAction::Workspace(TerminalShortcut::ScrollPageUp);
        }
        if modifiers.shift && !modifiers.secondary() && key == "pagedown" {
            return KeyAction::Workspace(TerminalShortcut::ScrollPageDown);
        }
        if modifiers.secondary() && modifiers.shift && key == "home" {
            return KeyAction::Workspace(TerminalShortcut::ScrollToTop);
        }
        if modifiers.secondary() && modifiers.shift && key == "end" {
            return KeyAction::Workspace(TerminalShortcut::ScrollToBottom);
        }
        if modifiers.platform {
            return KeyAction::Ignore;
        }

        let modifier = xterm_modifier(modifiers.shift, modifiers.alt, modifiers.control);
        if let Some((normal, application_final)) = keypad_key(&key) {
            let bytes = if application_keypad {
                cursor_key(application_final, true, modifier)
            } else {
                let mut bytes = normal.as_bytes().to_vec();
                if modifiers.alt {
                    bytes.insert(0, 0x1b);
                }
                bytes
            };
            return KeyAction::Send(bytes);
        }
        let special = match key.as_str() {
            "enter" | "return" => Some(vec![b'\r']),
            "escape" | "esc" => Some(vec![0x1b]),
            "backspace" => Some(vec![0x7f]),
            "tab" if modifiers.shift => Some(b"\x1b[Z".to_vec()),
            "tab" => Some(vec![b'\t']),
            "up" => Some(cursor_key(b'A', application_cursor, modifier)),
            "down" => Some(cursor_key(b'B', application_cursor, modifier)),
            "right" => Some(cursor_key(b'C', application_cursor, modifier)),
            "left" => Some(cursor_key(b'D', application_cursor, modifier)),
            "home" => Some(cursor_key(b'H', application_cursor, modifier)),
            "end" => Some(cursor_key(b'F', application_cursor, modifier)),
            "insert" => Some(tilde_key(2, modifier)),
            "delete" => Some(tilde_key(3, modifier)),
            "pageup" => Some(tilde_key(5, modifier)),
            "pagedown" => Some(tilde_key(6, modifier)),
            _ => function_number(&key).and_then(|number| function_key(number, modifier)),
        };
        if let Some(mut bytes) = special {
            if modifiers.alt && matches!(key.as_str(), "enter" | "return" | "backspace" | "tab") {
                bytes.insert(0, 0x1b);
            }
            return KeyAction::Send(bytes);
        }

        let Some(text) = keystroke
            .key_char
            .as_deref()
            .or_else(|| (keystroke.key.chars().count() == 1).then_some(keystroke.key.as_str()))
        else {
            return KeyAction::Ignore;
        };

        // Windows AltGr is represented as Ctrl+Alt but key_char contains the
        // already composed character. Treat it as text, not a control chord.
        if modifiers.control && modifiers.alt && text != keystroke.key {
            return KeyAction::Send(text.as_bytes().to_vec());
        }

        let mut bytes = if modifiers.control {
            control_character(text)
                .map(|byte| vec![byte])
                .unwrap_or_else(|| text.as_bytes().to_vec())
        } else {
            text.as_bytes().to_vec()
        };
        if modifiers.alt {
            bytes.insert(0, 0x1b);
        }
        KeyAction::Send(bytes)
    }

    /// Plain printable keys are delivered by `InputHandler`, preventing a
    /// keydown plus IME commit from sending the same character twice.
    pub fn is_plain_text(keystroke: &Keystroke) -> bool {
        let key = keystroke.key.to_ascii_lowercase();
        !keystroke.modifiers.control
            && !keystroke.modifiers.alt
            && !keystroke.modifiers.platform
            && !keystroke.modifiers.function
            && !matches!(
                key.as_str(),
                "enter"
                    | "return"
                    | "escape"
                    | "esc"
                    | "backspace"
                    | "tab"
                    | "up"
                    | "down"
                    | "left"
                    | "right"
                    | "home"
                    | "end"
                    | "insert"
                    | "delete"
                    | "pageup"
                    | "pagedown"
            )
            && function_number(&key).is_none()
            && keypad_key(&key).is_none()
            && keystroke
                .key_char
                .as_ref()
                .is_some_and(|text| !text.is_empty())
    }
}

fn keypad_key(key: &str) -> Option<(&'static str, u8)> {
    let normalized = key.replace(['-', '_', ' '], "");
    match normalized.as_str() {
        "numpad0" | "kp0" => Some(("0", b'p')),
        "numpad1" | "kp1" => Some(("1", b'q')),
        "numpad2" | "kp2" => Some(("2", b'r')),
        "numpad3" | "kp3" => Some(("3", b's')),
        "numpad4" | "kp4" => Some(("4", b't')),
        "numpad5" | "kp5" => Some(("5", b'u')),
        "numpad6" | "kp6" => Some(("6", b'v')),
        "numpad7" | "kp7" => Some(("7", b'w')),
        "numpad8" | "kp8" => Some(("8", b'x')),
        "numpad9" | "kp9" => Some(("9", b'y')),
        "numpaddecimal" | "kpdecimal" => Some((".", b'n')),
        "numpaddivide" | "kpdivide" => Some(("/", b'o')),
        "numpadmultiply" | "kpmultiply" => Some(("*", b'j')),
        "numpadsubtract" | "kpsubtract" => Some(("-", b'm')),
        "numpadadd" | "kpadd" => Some(("+", b'k')),
        "numpadenter" | "kpenter" => Some(("\r", b'M')),
        "numpadequal" | "kpequal" => Some(("=", b'X')),
        "numpadcomma" | "kpcomma" | "numpadseparator" => Some((",", b'l')),
        _ => None,
    }
}

fn xterm_modifier(shift: bool, alt: bool, control: bool) -> u8 {
    1 + u8::from(shift) + 2 * u8::from(alt) + 4 * u8::from(control)
}

fn cursor_key(final_byte: u8, application_cursor: bool, modifier: u8) -> Vec<u8> {
    if modifier == 1 {
        if application_cursor {
            vec![0x1b, b'O', final_byte]
        } else {
            vec![0x1b, b'[', final_byte]
        }
    } else {
        format!("\x1b[1;{modifier}{}", final_byte as char).into_bytes()
    }
}

fn tilde_key(code: u8, modifier: u8) -> Vec<u8> {
    if modifier == 1 {
        format!("\x1b[{code}~").into_bytes()
    } else {
        format!("\x1b[{code};{modifier}~").into_bytes()
    }
}

fn function_number(key: &str) -> Option<u8> {
    key.strip_prefix('f')?.parse().ok()
}

fn function_key(number: u8, modifier: u8) -> Option<Vec<u8>> {
    let bytes = match number {
        1..=4 => {
            let final_byte = b'P' + number - 1;
            if modifier == 1 {
                vec![0x1b, b'O', final_byte]
            } else {
                format!("\x1b[1;{modifier}{}", final_byte as char).into_bytes()
            }
        }
        5..=12 => {
            let code = [15, 17, 18, 19, 20, 21, 23, 24][(number - 5) as usize];
            if modifier == 1 {
                format!("\x1b[{code}~").into_bytes()
            } else {
                format!("\x1b[{code};{modifier}~").into_bytes()
            }
        }
        _ => return None,
    };
    Some(bytes)
}

fn control_character(text: &str) -> Option<u8> {
    let character = text.chars().next()?;
    if text.chars().count() != 1 {
        return None;
    }
    match character {
        'a'..='z' | 'A'..='Z' => Some(character.to_ascii_uppercase() as u8 & 0x1f),
        '@' | ' ' | '2' => Some(0x00),
        '[' | '3' => Some(0x1b),
        '\\' | '4' => Some(0x1c),
        ']' | '5' => Some(0x1d),
        '^' | '6' => Some(0x1e),
        '_' | '7' | '/' => Some(0x1f),
        '?' | '8' => Some(0x7f),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use gpui::{Keystroke, Modifiers};

    use super::*;

    fn key(key: &str, key_char: Option<&str>, modifiers: Modifiers) -> Keystroke {
        Keystroke {
            key: key.to_owned(),
            key_char: key_char.map(str::to_owned),
            modifiers,
        }
    }

    #[test]
    fn encodes_control_alt_cursor_and_function_keys() {
        assert_eq!(
            TerminalKeyEncoder::encode(
                &key(
                    "c",
                    Some("c"),
                    Modifiers {
                        control: true,
                        ..Default::default()
                    }
                ),
                false
            ),
            KeyAction::Send(vec![3])
        );
        assert_eq!(
            TerminalKeyEncoder::encode(
                &key(
                    "x",
                    Some("x"),
                    Modifiers {
                        alt: true,
                        ..Default::default()
                    }
                ),
                false
            ),
            KeyAction::Send(b"\x1bx".to_vec())
        );
        assert_eq!(
            TerminalKeyEncoder::encode(&key("up", None, Modifiers::default()), true),
            KeyAction::Send(b"\x1bOA".to_vec())
        );
        assert_eq!(
            TerminalKeyEncoder::encode(
                &key(
                    "left",
                    None,
                    Modifiers {
                        control: true,
                        shift: true,
                        ..Default::default()
                    }
                ),
                false
            ),
            KeyAction::Send(b"\x1b[1;6D".to_vec())
        );
        assert_eq!(
            TerminalKeyEncoder::encode(&key("f12", None, Modifiers::default()), false),
            KeyAction::Send(b"\x1b[24~".to_vec())
        );
    }

    #[test]
    fn recognizes_local_shortcuts_and_altgr_text() {
        let ctrl_shift = Modifiers {
            control: true,
            shift: true,
            ..Default::default()
        };
        assert_eq!(
            TerminalKeyEncoder::encode(&key("c", Some("C"), ctrl_shift), false),
            KeyAction::Copy
        );
        assert_eq!(
            TerminalKeyEncoder::encode(&key("v", Some("V"), ctrl_shift), false),
            KeyAction::Paste
        );
        assert_eq!(
            TerminalKeyEncoder::encode(&key("t", Some("T"), ctrl_shift), false),
            KeyAction::Workspace(TerminalShortcut::NewTab)
        );
        assert_eq!(
            TerminalKeyEncoder::encode(
                &key(
                    "tab",
                    None,
                    Modifiers {
                        control: true,
                        ..Default::default()
                    }
                ),
                false,
            ),
            KeyAction::Workspace(TerminalShortcut::NextTab)
        );
        assert_eq!(
            TerminalKeyEncoder::encode(
                &key(
                    "q",
                    Some("@"),
                    Modifiers {
                        control: true,
                        alt: true,
                        ..Default::default()
                    }
                ),
                false
            ),
            KeyAction::Send(b"@".to_vec())
        );
        assert!(TerminalKeyEncoder::is_plain_text(&key(
            "a",
            Some("A"),
            Modifiers {
                shift: true,
                ..Default::default()
            }
        )));
        assert!(!TerminalKeyEncoder::is_plain_text(&key(
            "enter",
            Some("\r"),
            Modifiers::default()
        )));
    }

    #[test]
    fn application_keypad_uses_dec_ss3_sequences() {
        let zero = key("numpad0", Some("0"), Modifiers::default());
        assert_eq!(
            TerminalKeyEncoder::encode_with_modes(&zero, false, false),
            KeyAction::Send(b"0".to_vec())
        );
        assert_eq!(
            TerminalKeyEncoder::encode_with_modes(&zero, false, true),
            KeyAction::Send(b"\x1bOp".to_vec())
        );
        assert_eq!(
            TerminalKeyEncoder::encode_with_modes(
                &key(
                    "kp-enter",
                    None,
                    Modifiers {
                        control: true,
                        ..Default::default()
                    }
                ),
                false,
                true,
            ),
            KeyAction::Send(b"\x1b[1;5M".to_vec())
        );
        assert!(!TerminalKeyEncoder::is_plain_text(&zero));
    }
}
