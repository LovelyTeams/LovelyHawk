//! Local files the operator chose in a system dialog.
//!
//! Every path here comes from the dialog and goes straight to the backend or
//! to a new file; no page ever sees one. Exports always create a new file, so a
//! chosen name that already exists is refused rather than overwritten.

use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};

use tauri::{Runtime, WebviewWindow};
use tauri_plugin_dialog::DialogExt;

pub struct Filter<'a> {
    pub name: &'a str,
    pub extensions: &'a [&'a str],
}

pub enum DialogKind<'a> {
    Save { default_name: &'a str },
    OpenFile,
    PickFolder,
}

/// Shows one system dialog parented to `window` and waits for the choice.
pub async fn choose<R: Runtime>(
    window: &WebviewWindow<R>,
    title: &str,
    kind: DialogKind<'_>,
    filter: Option<Filter<'_>>,
) -> Option<PathBuf> {
    if let Some(answer) = crate::test_hooks::scripted_dialog_answer() {
        return answer;
    }
    let mut builder = window.dialog().file().set_parent(window).set_title(title);
    if let Some(filter) = filter {
        builder = builder.add_filter(filter.name, filter.extensions);
    }
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let deliver = move |picked: Option<tauri_plugin_dialog::FilePath>| {
        let _ = sender.send(picked.and_then(|path| path.into_path().ok()));
    };
    match kind {
        DialogKind::Save { default_name } => builder.set_file_name(default_name).save_file(deliver),
        DialogKind::OpenFile => builder.pick_file(deliver),
        DialogKind::PickFolder => builder
            .set_can_create_directories(true)
            .pick_folder(deliver),
    }
    receiver
        .await
        .ok()
        .flatten()
        .filter(|path| path.is_absolute())
}

pub const FILE_EXISTS: &str = "所选文件已存在。导出只创建新文件，请换一个文件名。";
pub const WRITE_FAILED: &str = "无法写入所选文件，请检查目录权限或磁盘空间。";

/// Creates `path` and writes `contents`, refusing an existing file.
pub fn write_new_file(path: &Path, contents: &[u8]) -> Result<(), &'static str> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            FILE_EXISTS
        } else {
            WRITE_FAILED
        }
    })?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|_| WRITE_FAILED)
}

/// The last path component, for telling the operator what was saved.
pub fn display_name(path: &Path, fallback: &str) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| {
            !name.is_empty()
                && name.len() <= 512
                && !name
                    .chars()
                    .any(|character| character.is_control() || matches!(character, '/' | '\\'))
        })
        .unwrap_or(fallback)
        .to_owned()
}

/// Whether a backend-suggested file name is a plain, portable base name.
pub fn is_safe_file_name(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value.len() <= 240
        && !value
            .chars()
            .any(|character| character.is_control() || "<>:\"/\\|?*".contains(character))
        && !value.ends_with(['.', ' '])
        && !is_reserved_windows_name(value)
}

fn is_reserved_windows_name(value: &str) -> bool {
    let stem = value
        .split('.')
        .next()
        .unwrap_or(value)
        .to_ascii_lowercase();
    matches!(stem.as_str(), "con" | "prn" | "aux" | "nul")
        || (stem.len() == 4
            && (stem.starts_with("com") || stem.starts_with("lpt"))
            && stem.as_bytes()[3].is_ascii_digit()
            && stem.as_bytes()[3] != b'0')
}

pub fn has_extension(path: &Path, extension: &str) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case(extension))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggested_names_must_be_plain_base_names() {
        for good in ["LovelyHawk-disposal-20261010.md", "notes.txt", "a b.json"] {
            assert!(is_safe_file_name(good), "{good}");
        }
        for bad in [
            "", ".", "..", "../x", "a/b", "a\\b", "con.txt", "COM1", "x.", "x ", "a\u{0}b", "a:b",
        ] {
            assert!(!is_safe_file_name(bad), "{bad:?}");
        }
        assert!(is_safe_file_name("com0.txt"));
    }

    #[test]
    fn exports_never_replace_an_existing_file() {
        let root = std::env::temp_dir().join(format!("lovelyhawk-export-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("report.md");
        write_new_file(&path, b"first").unwrap();
        assert_eq!(write_new_file(&path, b"second"), Err(FILE_EXISTS));
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        assert_eq!(display_name(&path, "fallback"), "report.md");
        assert!(has_extension(&path, "MD"));
        std::fs::remove_dir_all(&root).unwrap();
    }
}
