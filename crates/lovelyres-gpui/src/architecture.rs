#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    fn visit_rust_sources(root: &Path, callback: &mut impl FnMut(&Path, &str)) {
        let mut entries = fs::read_dir(root)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", root.display()))
            .map(|entry| entry.expect("workspace directory entry is readable"))
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            if path.is_dir() {
                visit_rust_sources(&path, callback);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let source = fs::read_to_string(&path)
                    .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
                callback(&path, &source);
            }
        }
    }

    fn contains_inline_handler(source: &str, event: &str) -> bool {
        let source = source.to_ascii_lowercase();
        let needle = ["on", event].concat();
        let bytes = source.as_bytes();
        let mut offset = 0;
        while let Some(relative) = source[offset..].find(&needle) {
            let start = offset + relative;
            let prefix_ok = start > 0
                && matches!(
                    bytes[start - 1],
                    b' ' | b'\t' | b'\r' | b'\n' | b'"' | b'\''
                );
            let mut cursor = start + needle.len();
            while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            if prefix_ok && bytes.get(cursor) == Some(&b'=') {
                cursor += 1;
                while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
                    cursor += 1;
                }
                if matches!(bytes.get(cursor), Some(b'"' | b'\'')) {
                    return true;
                }
            }
            offset = start + needle.len();
        }
        false
    }

    #[test]
    fn native_workspace_has_no_inline_html_event_handler_surface() {
        let malicious = ["<button ", "on", "click = \"run()\"", ">"].concat();
        assert!(contains_inline_handler(&malicious, "click"));
        assert!(!contains_inline_handler(
            "remote text: <img src=x onerror=alert(1)>",
            "error"
        ));
        let crates_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("GPUI crate lives below workspace crates directory");
        let event_names = [
            "click",
            "change",
            "input",
            "submit",
            "focus",
            "blur",
            "keydown",
            "keyup",
            "keypress",
            "mouseover",
            "mouseout",
            "mouseenter",
            "mouseleave",
            "mousedown",
            "mouseup",
            "dblclick",
            "contextmenu",
            "wheel",
            "scroll",
            "load",
            "error",
            "drag",
            "dragstart",
            "dragover",
            "drop",
            "paste",
            "copy",
            "cut",
            "toggle",
        ];
        let mut violations = Vec::new();
        visit_rust_sources(crates_root, &mut |path, source| {
            for event in event_names {
                if contains_inline_handler(source, event) {
                    let forbidden = ["on", event, "=<quoted value>"].concat();
                    violations.push(format!("{} contains {forbidden}", path.display()));
                }
            }
        });
        assert!(
            violations.is_empty(),
            "native workspace reintroduced an inline HTML event surface: {violations:?}"
        );
    }
}
