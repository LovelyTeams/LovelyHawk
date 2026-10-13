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

/// Shells one window may hold as tabs. The backend allows four terminals per
/// target in all, so a window can never usefully hold more.
pub const MAXIMUM_TABS: usize = 4;

/// AI answers one window may be waiting for at once. The backend keeps four
/// in all, so one window cannot take every place.
pub const MAXIMUM_AI_STREAMS: usize = 2;

/// One shell in a terminal window. The page names it by `tab`, a number the
/// host gave it; the backend's handle never leaves the host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TerminalTab {
    pub tab: String,
    pub handle: String,
}

#[derive(Debug)]
pub struct ChildContext {
    pub key: String,
    pub binding_handle: String,
    pub kind: ChildKind,
    /// Spent by the first terminal open. Further shells are tabs, and only the
    /// host shell's window may open them (`add_terminal`'s callers check).
    pub launch_available: bool,
    /// The window's shells, in the order they were opened.
    terminals: Vec<TerminalTab>,
    /// Tab numbers are never reused within a window, so a late call naming a
    /// closed tab cannot reach the shell that replaced it.
    last_tab: u32,
    /// An editor window holding text that is not on the server yet.
    pub unsaved: bool,
    /// AI answers this window asked for and has not collected yet. Only these
    /// may be polled or cancelled from it, and closing it cancels them.
    ai_streams: Vec<String>,
    close: CloseRequests,
}

impl ChildContext {
    /// Records a newly opened shell as the next tab, or refuses when the
    /// window already holds as many as it may.
    pub fn add_terminal(&mut self, handle: String) -> Option<String> {
        if self.terminals.len() >= MAXIMUM_TABS {
            return None;
        }
        self.last_tab += 1;
        let tab = self.last_tab.to_string();
        self.terminals.push(TerminalTab {
            tab: tab.clone(),
            handle,
        });
        Some(tab)
    }

    /// The backend handle behind a tab the page named.
    pub fn terminal(&self, tab: &str) -> Option<&str> {
        self.terminals
            .iter()
            .find(|terminal| terminal.tab == tab)
            .map(|terminal| terminal.handle.as_str())
    }

    /// Forgets one tab and hands back its handle, for closing.
    pub fn remove_terminal(&mut self, tab: &str) -> Option<String> {
        let index = self
            .terminals
            .iter()
            .position(|terminal| terminal.tab == tab)?;
        Some(self.terminals.remove(index).handle)
    }

    pub fn terminal_count(&self) -> usize {
        self.terminals.len()
    }

    /// Records an AI answer the window started, or refuses when it already
    /// waits for as many as it may.
    pub fn add_ai_stream(&mut self, handle: String) -> bool {
        if self.ai_streams.len() >= MAXIMUM_AI_STREAMS {
            return false;
        }
        self.ai_streams.push(handle);
        true
    }

    pub fn has_ai_stream(&self, handle: &str) -> bool {
        self.ai_streams.iter().any(|stream| stream == handle)
    }

    /// Forgets an answer the window collected in full.
    pub fn forget_ai_stream(&mut self, handle: &str) {
        self.ai_streams.retain(|stream| stream != handle);
    }

    pub fn ai_stream_count(&self) -> usize {
        self.ai_streams.len()
    }
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
                terminals: Vec::new(),
                last_tab: 0,
                unsaved: false,
                ai_streams: Vec::new(),
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

    /// Forgets a window and hands back every terminal it held, for closing.
    /// The AI answers a closing window was still waiting for, to cancel.
    pub fn take_ai_streams(&mut self, label: &str) -> Vec<String> {
        self.by_label
            .get_mut(label)
            .map(|context| std::mem::take(&mut context.ai_streams))
            .unwrap_or_default()
    }

    pub fn remove(&mut self, label: &str) -> Option<Vec<String>> {
        let context = self.by_label.remove(label)?;
        if self.label_by_key.get(&context.key).map(String::as_str) == Some(label) {
            self.label_by_key.remove(&context.key);
        }
        Some(
            context
                .terminals
                .into_iter()
                .map(|terminal| terminal.handle)
                .collect(),
        )
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
    fn removal_returns_every_terminal_to_close_and_frees_the_key() {
        let mut windows = ChildWindows::default();
        let label = windows.register("b", ChildKind::Terminal);
        let context = windows.current(&label, Some("b")).unwrap();
        context.add_terminal("terminal-1".into());
        context.add_terminal("terminal-2".into());
        assert_eq!(windows.labels_for_binding("b"), vec![label.clone()]);
        assert_eq!(
            windows.remove(&label),
            Some(vec!["terminal-1".into(), "terminal-2".into()])
        );
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
            assert!(context.launch_available && context.terminal_count() == 0);
        }
        assert!(windows.current(&again, Some("other")).is_none());
        // Closing one leaves the others current.
        assert_eq!(windows.remove(&first), Some(Vec::new()));
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
        assert!(context.launch_available && context.terminal_count() == 0);
        assert!(windows.current(&first, Some("c")).is_none());
    }

    #[test]
    fn tabs_are_numbered_once_bounded_and_closed_one_at_a_time() {
        let mut windows = ChildWindows::default();
        let label = windows.register("b", ChildKind::Terminal);
        let context = windows.current(&label, Some("b")).unwrap();
        let tabs = (1..=MAXIMUM_TABS)
            .map(|index| context.add_terminal(format!("terminal-{index}")).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(tabs, ["1", "2", "3", "4"]);
        // A fifth is refused; the backend would refuse it too.
        assert_eq!(context.add_terminal("terminal-5".into()), None);
        assert_eq!(context.terminal("2"), Some("terminal-2"));

        // Closing one leaves the others, and its number is not given again:
        // a late call naming tab 2 must not reach the shell opened after it.
        assert_eq!(context.remove_terminal("2"), Some("terminal-2".into()));
        assert_eq!(context.remove_terminal("2"), None);
        assert_eq!(context.terminal("2"), None);
        assert_eq!(
            context.add_terminal("terminal-6".into()).as_deref(),
            Some("5")
        );
        assert_eq!(context.terminal("2"), None);
        assert_eq!(context.terminal("5"), Some("terminal-6"));
        assert_eq!(context.terminal_count(), MAXIMUM_TABS);
        // Names that are not a tab of this window resolve to nothing.
        for name in ["", "0", "9", "terminal-1", "1 "] {
            assert_eq!(context.terminal(name), None);
        }
    }

    #[test]
    fn ai_answers_belong_to_the_window_that_asked_and_close_with_it() {
        let mut windows = ChildWindows::default();
        let asking = windows.register("b", ChildKind::Terminal);
        let other = windows.register(
            "b",
            ChildKind::Container(ContainerScope {
                snapshot_handle: "s".into(),
                container_handle: "c".into(),
                container_name: "web".into(),
            }),
        );
        let context = windows.current(&asking, Some("b")).unwrap();
        assert!(context.add_ai_stream("stream-1".into()));
        assert!(context.add_ai_stream("stream-2".into()));
        // A third waits for one of these to finish.
        assert!(!context.add_ai_stream("stream-3".into()));
        assert_eq!(context.ai_stream_count(), MAXIMUM_AI_STREAMS);
        assert!(context.has_ai_stream("stream-1"));
        context.forget_ai_stream("stream-1");
        assert!(!context.has_ai_stream("stream-1"));
        assert!(context.add_ai_stream("stream-3".into()));

        // Another window of the same connection cannot reach them.
        let neighbour = windows.current(&other, Some("b")).unwrap();
        assert!(!neighbour.has_ai_stream("stream-2"));

        // Closing hands back what is still running, once.
        assert_eq!(
            windows.take_ai_streams(&asking),
            ["stream-2".to_owned(), "stream-3".to_owned()]
        );
        assert!(windows.take_ai_streams(&asking).is_empty());
        assert!(windows.take_ai_streams("child-unknown").is_empty());
    }
}
