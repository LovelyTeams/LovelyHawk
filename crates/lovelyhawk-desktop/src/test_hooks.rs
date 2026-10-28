//! Automation hooks that exist only in debug builds.
//!
//! The lab probes drive the real application through CDP, which can click a
//! button but cannot click inside a system dialog or read what was copied. Two
//! environment variables stand in for the operator there, and only there:
//!
//! - `LOVELYHAWK_TEST_DIALOG_ANSWERS` names a JSON file holding an array of
//!   answers, consumed one per dialog: an absolute path, or `null` to cancel.
//! - `LOVELYHAWK_TEST_CLIPBOARD_FILE` names a file that receives copied text
//!   instead of the system clipboard.
//!
//! Release builds compile all of this out; nothing in a shipped executable
//! reads either variable. Everything after the dialog — the backend plan,
//! confirmation, execution and verification — runs exactly as it does for an
//! operator.

#[cfg(debug_assertions)]
use std::path::{Path, PathBuf};

#[cfg(debug_assertions)]
const DIALOG_ANSWERS: &str = "LOVELYHAWK_TEST_DIALOG_ANSWERS";
#[cfg(debug_assertions)]
const CLIPBOARD_FILE: &str = "LOVELYHAWK_TEST_CLIPBOARD_FILE";

/// `None`: no scripted answer, show the real dialog. `Some(None)`: the script
/// cancels this dialog. `Some(Some(path))`: the script chose `path`.
#[cfg(debug_assertions)]
pub fn scripted_dialog_answer() -> Option<Option<PathBuf>> {
    let file = std::env::var_os(DIALOG_ANSWERS)?;
    let file = Path::new(&file);
    let text = std::fs::read_to_string(file).ok()?;
    let mut answers: Vec<Option<String>> = serde_json::from_str(&text).ok()?;
    if answers.is_empty() {
        return None;
    }
    let answer = answers.remove(0);
    let _ = std::fs::write(file, serde_json::to_vec(&answers).unwrap_or_default());
    Some(answer.map(PathBuf::from).filter(|path| path.is_absolute()))
}

#[cfg(not(debug_assertions))]
pub fn scripted_dialog_answer() -> Option<Option<std::path::PathBuf>> {
    None
}

/// True when the copied text went to the automation file instead.
#[cfg(debug_assertions)]
pub fn capture_clipboard(text: &str) -> bool {
    let Some(file) = std::env::var_os(CLIPBOARD_FILE) else {
        return false;
    };
    std::fs::write(file, text).is_ok()
}

#[cfg(not(debug_assertions))]
pub fn capture_clipboard(_text: &str) -> bool {
    false
}
