//! The windows that belong to one SSH binding: a login shell, a shell inside a
//! container, and a file editor.
//!
//! The host remembers what each window was opened for. A window asks for "a
//! terminal" or "my file" and gets the one its window is for; it never names a
//! binding, a container or a file, so it cannot be talked into naming a
//! different one. Every window closes with its binding.

use std::collections::HashMap;

use serde::Serialize;

pub const LABEL_PREFIX: &str = "child-";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerScope {
    pub snapshot_handle: String,
    pub container_handle: String,
    /// Display only, for the window's own title bar.
    pub container_name: String,
}

/// A shell in a pod a Kubernetes list showed. Like a container, the window
/// holds the list's own handles; the backend turns them back into the pod.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PodScope {
    pub snapshot_handle: String,
    pub row_handle: String,
    /// Display only, for the window's own title bar.
    pub pod_name: String,
    /// One of the pod's containers, or none for its default one. Each
    /// container of a pod gets a window of its own.
    pub container: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EditorScope {
    pub browser_handle: String,
    pub entry_handle: String,
    /// Display only, for the window's own title bar.
    pub name: String,
    /// False for 预览: the same window, with no way to write.
    pub editable: bool,
}

/// A shell started in a folder the SSH window's file browser listed. The
/// window names neither the folder nor the browser: the host hands the
/// browser's own handles to the backend, which turns them back into the path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryScope {
    pub browser_handle: String,
    pub directory_handle: String,
    /// Display only, for the window's own title bar.
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChildKind {
    Terminal,
    Container(ContainerScope),
    Pod(PodScope),
    Directory(DirectoryScope),
    Editor(EditorScope),
}

impl ChildKind {
    /// The page this window loads. The terminals share one page; the query
    /// tells it which, so only the SSH window shows the host's files.
    pub fn page(&self) -> &'static str {
        match self {
            Self::Terminal => "terminal",
            Self::Container(_) => "container",
            Self::Pod(_) => "pod",
            Self::Directory(_) => "directory",
            Self::Editor(_) => "file-editor",
        }
    }
}

#[derive(Debug)]
pub struct ChildContext {
    pub key: String,
    pub binding_handle: String,
    pub kind: ChildKind,
    /// Spent by the first terminal open; a window opens one terminal, once.
    pub launch_available: bool,
    pub terminal_handle: Option<String>,
    /// An editor window holding text that is not on the server yet.
    pub unsaved: bool,
    close: CloseRequests,
}

/// Numbered close questions to one window, as the main window has: only the
/// first answer to the latest question counts.
#[derive(Debug, Default)]
struct CloseRequests {
    latest: u64,
    unanswered: Option<u64>,
    waiting: bool,
}

#[derive(Debug, Default)]
pub struct ChildWindows {
    by_label: HashMap<String, ChildContext>,
    label_by_key: HashMap<String, String>,
    next_label: u64,
}

/// One window per binding for the host shell, one more per container, and one
/// per file, so a second request raises the window already showing it.
pub fn window_key(binding_handle: &str, kind: &ChildKind) -> String {
    match kind {
        ChildKind::Terminal => format!("ssh-terminal:{binding_handle}"),
        ChildKind::Container(scope) => {
            format!(
                "ssh-terminal:{binding_handle}:container:{}",
                scope.container_handle
            )
        }
        ChildKind::Pod(scope) => format!(
            "ssh-terminal:{binding_handle}:pod:{}:{}",
            scope.row_handle,
            scope.container.as_deref().unwrap_or("")
        ),
        // Never raised again: each request is a new shell, like a new tab. The
        // browser's handle for a folder changes as the folder is browsed, so it
        // could not name "the same folder" anyway. `register` makes the key unique.
        ChildKind::Directory(_) => format!("ssh-terminal:{binding_handle}:directory"),
        ChildKind::Editor(scope) => format!("file-editor:{binding_handle}:{}", scope.entry_handle),
    }
}

impl ChildWindows {
    pub fn existing_label(&self, key: &str) -> Option<&str> {
        self.label_by_key.get(key).map(String::as_str)
    }

    /// Reserves a label and records what the window is for, before it exists,
    /// so its first request already finds its context.
    pub fn register(&mut self, binding_handle: &str, kind: ChildKind) -> String {
        self.next_label += 1;
        let label = format!("{LABEL_PREFIX}{}", self.next_label);
        let key = match &kind {
            ChildKind::Directory(_) => format!("{}:{label}", window_key(binding_handle, &kind)),
            _ => window_key(binding_handle, &kind),
        };
        self.label_by_key.insert(key.clone(), label.clone());
        self.by_label.insert(
            label.clone(),
            ChildContext {
                key,
                binding_handle: binding_handle.to_owned(),
                launch_available: !matches!(kind, ChildKind::Editor(_)),
                kind,
                terminal_handle: None,
                unsaved: false,
                close: CloseRequests::default(),
            },
        );
        label
    }

    /// Records whether an editor window holds unsaved text. Only editors can.
    pub fn set_unsaved(&mut self, label: &str, unsaved: bool) -> bool {
        match self.by_label.get_mut(label) {
            Some(context) if matches!(context.kind, ChildKind::Editor(_)) => {
                context.unsaved = unsaved;
                true
            }
            _ => false,
        }
    }

    pub fn is_unsaved(&self, label: &str) -> bool {
        self.by_label
            .get(label)
            .is_some_and(|context| context.unsaved)
    }

    /// Editor windows holding unsaved text, for the main window to warn about.
    pub fn unsaved_count(&self) -> usize {
        self.by_label
            .values()
            .filter(|context| context.unsaved)
            .count()
    }

    /// Starts a close question unless one is still waiting for its answer.
    pub fn begin_close(&mut self, label: &str) -> Option<u64> {
        let close = &mut self.by_label.get_mut(label)?.close;
        if close.waiting {
            return None;
        }
        close.latest += 1;
        close.unanswered = Some(close.latest);
        close.waiting = true;
        Some(close.latest)
    }

    /// Lets the next close ask again; a late answer to this one still counts.
    pub fn expire_close(&mut self, label: &str, request: u64) {
        if let Some(context) = self.by_label.get_mut(label)
            && context.close.unanswered == Some(request)
        {
            context.close.waiting = false;
        }
    }

    /// The window's answer. Allowing the close drops the unsaved mark, so the
    /// close that follows is not asked about again.
    pub fn resolve_close(&mut self, label: &str, request: u64, allowed: bool) -> bool {
        let Some(context) = self.by_label.get_mut(label) else {
            return false;
        };
        if context.close.unanswered != Some(request) {
            return false;
        }
        context.close.unanswered = None;
        context.close.waiting = false;
        if allowed {
            context.unsaved = false;
        }
        allowed
    }

    /// The context for a calling window, only while it still belongs to the
    /// current binding.
    pub fn current(
        &mut self,
        label: &str,
        current_binding: Option<&str>,
    ) -> Option<&mut ChildContext> {
        let context = self.by_label.get_mut(label)?;
        if Some(context.binding_handle.as_str()) != current_binding {
            return None;
        }
        if self.label_by_key.get(&context.key).map(String::as_str) != Some(label) {
            return None;
        }
        Some(context)
    }

    /// Forgets a window and hands back the terminal it held, for closing.
    pub fn remove(&mut self, label: &str) -> Option<Option<String>> {
        let context = self.by_label.remove(label)?;
        if self.label_by_key.get(&context.key).map(String::as_str) == Some(label) {
            self.label_by_key.remove(&context.key);
        }
        Some(context.terminal_handle)
    }

    pub fn labels_for_binding(&self, binding_handle: &str) -> Vec<String> {
        self.by_label
            .iter()
            .filter(|(_, context)| context.binding_handle == binding_handle)
            .map(|(label, _)| label.clone())
            .collect()
    }

    pub fn labels(&self) -> Vec<String> {
        self.by_label.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn editor(entry: &str) -> ChildKind {
        ChildKind::Editor(EditorScope {
            browser_handle: "browser".into(),
            entry_handle: entry.into(),
            name: "a.conf".into(),
            editable: true,
        })
    }

    #[test]
    fn windows_resolve_only_for_their_own_binding() {
        let mut windows = ChildWindows::default();
        let label = windows.register("binding-a", ChildKind::Terminal);
        assert!(windows.current(&label, Some("binding-a")).is_some());
        assert!(windows.current(&label, Some("binding-b")).is_none());
        assert!(windows.current(&label, None).is_none());
        assert!(windows.current("child-999", Some("binding-a")).is_none());
    }

    #[test]
    fn keys_separate_host_shell_containers_and_files() {
        let mut windows = ChildWindows::default();
        let shell = windows.register("b", ChildKind::Terminal);
        let file = windows.register("b", editor("entry-1"));
        assert_ne!(shell, file);
        assert_eq!(
            windows.existing_label(&window_key("b", &ChildKind::Terminal)),
            Some(shell.as_str())
        );
        assert_eq!(
            windows.existing_label(&window_key("b", &editor("entry-1"))),
            Some(file.as_str())
        );
        assert!(
            windows
                .existing_label(&window_key("b", &editor("entry-2")))
                .is_none()
        );
        // An editor never opens a terminal of its own.
        assert!(!windows.current(&file, Some("b")).unwrap().launch_available);
    }

    #[test]
    fn only_editors_hold_unsaved_text_and_its_close_is_asked_once_per_request() {
        let mut windows = ChildWindows::default();
        let shell = windows.register("b", ChildKind::Terminal);
        let file = windows.register("b", editor("entry-1"));
        assert!(!windows.set_unsaved(&shell, true));
        assert!(windows.set_unsaved(&file, true));
        assert!(windows.is_unsaved(&file) && !windows.is_unsaved(&shell));
        assert_eq!(windows.unsaved_count(), 1);

        let first = windows.begin_close(&file).unwrap();
        // A second close while the first question is open does not ask again.
        assert!(windows.begin_close(&file).is_none());
        // A stale or foreign answer changes nothing.
        assert!(!windows.resolve_close(&file, first + 1, true));
        assert!(windows.is_unsaved(&file));
        // Keeping the edit leaves it unsaved and lets the next close ask.
        assert!(!windows.resolve_close(&file, first, false));
        assert!(windows.is_unsaved(&file));
        let second = windows.begin_close(&file).unwrap();
        assert!(second > first);
        // An answer that comes after the timeout still counts, until replaced.
        windows.expire_close(&file, second);
        assert!(windows.resolve_close(&file, second, true));
        assert!(!windows.is_unsaved(&file));
        assert_eq!(windows.unsaved_count(), 0);
        assert!(!windows.resolve_close(&file, second, true));
    }

    #[test]
    fn removal_returns_the_terminal_to_close_and_frees_the_key() {
        let mut windows = ChildWindows::default();
        let label = windows.register("b", ChildKind::Terminal);
        windows.current(&label, Some("b")).unwrap().terminal_handle = Some("terminal-1".into());
        assert_eq!(windows.labels_for_binding("b"), vec![label.clone()]);
        assert_eq!(windows.remove(&label), Some(Some("terminal-1".into())));
        assert_eq!(windows.remove(&label), None);
        assert!(
            windows
                .existing_label(&window_key("b", &ChildKind::Terminal))
                .is_none()
        );
    }

    fn directory(entry: &str) -> ChildKind {
        ChildKind::Directory(DirectoryScope {
            browser_handle: "browser".into(),
            directory_handle: entry.into(),
            name: "www".into(),
        })
    }

    #[test]
    fn every_folder_request_is_a_new_window_beside_the_host_shell() {
        let mut windows = ChildWindows::default();
        let shell = windows.register("b", ChildKind::Terminal);
        let first = windows.register("b", directory("entry-1"));
        // The same folder again is a second shell, not the first one raised.
        let again = windows.register("b", directory("entry-1"));
        assert!(first != shell && first != again);
        assert!(
            windows
                .existing_label(&window_key("b", &directory("entry-1")))
                .is_none()
        );
        // Neither replaced the host shell, nor each other.
        assert_eq!(
            windows.existing_label(&window_key("b", &ChildKind::Terminal)),
            Some(shell.as_str())
        );
        for label in [&shell, &first, &again] {
            let context = windows.current(label, Some("b")).unwrap();
            assert!(context.launch_available && context.terminal_handle.is_none());
        }
        assert!(windows.current(&again, Some("other")).is_none());
        // Closing one leaves the others current.
        assert_eq!(windows.remove(&first), Some(None));
        assert!(windows.current(&again, Some("b")).is_some());
        assert!(windows.current(&shell, Some("b")).is_some());
    }

    #[test]
    fn each_terminal_kind_loads_its_own_page() {
        assert_eq!(ChildKind::Terminal.page(), "terminal");
        assert_eq!(
            ChildKind::Container(ContainerScope {
                snapshot_handle: "s".into(),
                container_handle: "c".into(),
                container_name: "web".into(),
            })
            .page(),
            "container"
        );
        assert_eq!(pod("r").page(), "pod");
        assert_eq!(directory("t").page(), "directory");
        assert_eq!(editor("e").page(), "file-editor");
    }

    fn pod(row: &str) -> ChildKind {
        pod_in(row, None)
    }

    fn pod_in(row: &str, container: Option<&str>) -> ChildKind {
        ChildKind::Pod(PodScope {
            snapshot_handle: "s".into(),
            row_handle: row.into(),
            pod_name: "payments/ledger-7d9f".into(),
            container: container.map(str::to_owned),
        })
    }

    #[test]
    fn a_pod_shell_is_raised_again_for_the_same_row_and_is_its_own_window() {
        let mut windows = ChildWindows::default();
        let host = windows.register("b", ChildKind::Terminal);
        let first = windows.register("b", pod("row-1"));
        assert_eq!(
            windows.existing_label(&window_key("b", &pod("row-1"))),
            Some(first.as_str())
        );
        // Another container of the same pod is a shell of its own, raised
        // again only for that container.
        assert!(
            windows
                .existing_label(&window_key("b", &pod_in("row-1", Some("sidecar"))))
                .is_none()
        );
        let sidecar = windows.register("b", pod_in("row-1", Some("sidecar")));
        assert_ne!(sidecar, first);
        assert_eq!(
            windows.existing_label(&window_key("b", &pod_in("row-1", Some("sidecar")))),
            Some(sidecar.as_str())
        );
        assert!(
            windows
                .existing_label(&window_key("b", &pod("row-2")))
                .is_none()
        );
        // Same row handle under another binding is another window.
        assert!(
            windows
                .existing_label(&window_key("c", &pod("row-1")))
                .is_none()
        );
        assert_ne!(host, first);
        let context = windows.current(&first, Some("b")).unwrap();
        assert!(context.launch_available && context.terminal_handle.is_none());
        assert!(windows.current(&first, Some("c")).is_none());
    }
}
