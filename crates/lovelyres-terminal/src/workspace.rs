use std::fmt;

/// Stable identity for one native terminal tab.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TerminalTabId(u64);

impl TerminalTabId {
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for TerminalTabId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A tab identity plus its current async generation.
///
/// Every open/reconnect result must carry this token. A token stops matching as
/// soon as the tab reconnects or closes, so a late PTY result cannot replace a
/// newer session.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TerminalTabToken {
    pub id: TerminalTabId,
    pub generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TerminalTabState {
    Opening,
    Open,
    Reconnecting,
    Closed { exit_code: Option<i32> },
    Failed(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalTab {
    id: TerminalTabId,
    generation: u64,
    label: String,
    title: Option<String>,
    state: TerminalTabState,
}

impl TerminalTab {
    pub const fn id(&self) -> TerminalTabId {
        self.id
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn token(&self) -> TerminalTabToken {
        TerminalTabToken {
            id: self.id,
            generation: self.generation,
        }
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    pub fn display_title(&self) -> &str {
        self.title.as_deref().unwrap_or(&self.label)
    }

    pub fn state(&self) -> &TerminalTabState {
        &self.state
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TabDirection {
    Next,
    Previous,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TerminalSearchOverlay {
    pub visible: bool,
    pub query: String,
    pub current: Option<usize>,
    pub total: usize,
    pub error: Option<String>,
}

impl TerminalSearchOverlay {
    pub fn show(&mut self) {
        self.visible = true;
    }

    pub fn hide(&mut self) {
        self.visible = false;
        self.error = None;
    }

    pub fn set_result(&mut self, query: String, current: Option<usize>, total: usize) {
        self.query = query;
        self.current = current;
        self.total = total;
        self.error = None;
    }

    pub fn set_error(&mut self, query: String, error: impl Into<String>) {
        self.query = query;
        self.current = None;
        self.total = 0;
        self.error = Some(error.into());
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalAiState {
    Hidden,
    Ready,
    Streaming,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalAiToken {
    pub tab: TerminalTabToken,
    pub generation: u64,
    pub stream_id: String,
}

/// Text-only AI overlay state. Rendering code consumes `output` as a GPUI text
/// node; this model intentionally has no HTML or WebView representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalAiOverlay {
    pub visible: bool,
    pub state: TerminalAiState,
    pub prompt: String,
    pub output: String,
    pub error: Option<String>,
    active: Option<TerminalAiToken>,
}

impl Default for TerminalAiOverlay {
    fn default() -> Self {
        Self {
            visible: false,
            state: TerminalAiState::Hidden,
            prompt: String::new(),
            output: String::new(),
            error: None,
            active: None,
        }
    }
}

impl TerminalAiOverlay {
    pub fn show(&mut self) {
        self.visible = true;
        if self.state == TerminalAiState::Hidden {
            self.state = TerminalAiState::Ready;
        }
    }

    pub fn hide(&mut self) {
        self.visible = false;
    }

    pub fn active(&self) -> Option<&TerminalAiToken> {
        self.active.as_ref()
    }

    pub fn begin(&mut self, token: TerminalAiToken, prompt: String) {
        self.visible = true;
        self.state = TerminalAiState::Streaming;
        self.prompt = prompt;
        self.output.clear();
        self.error = None;
        self.active = Some(token);
    }

    pub fn apply_delta(&mut self, token: &TerminalAiToken, delta: &str) -> bool {
        if self.state != TerminalAiState::Streaming || self.active.as_ref() != Some(token) {
            return false;
        }
        self.output.push_str(delta);
        true
    }

    pub fn complete(&mut self, token: &TerminalAiToken) -> bool {
        if self.state != TerminalAiState::Streaming || self.active.as_ref() != Some(token) {
            return false;
        }
        self.state = TerminalAiState::Completed;
        self.active = None;
        true
    }

    pub fn fail(&mut self, token: &TerminalAiToken, error: impl Into<String>) -> bool {
        if self.state != TerminalAiState::Streaming || self.active.as_ref() != Some(token) {
            return false;
        }
        self.state = TerminalAiState::Failed;
        self.error = Some(error.into());
        self.active = None;
        true
    }

    pub fn cancel(&mut self) -> Option<TerminalAiToken> {
        let token = self.active.take()?;
        self.state = TerminalAiState::Cancelled;
        Some(token)
    }
}

/// Pure tab/overlay state used by the GPUI window and model tests.
#[derive(Clone, Debug)]
pub struct TerminalWorkspace {
    tabs: Vec<TerminalTab>,
    active: Option<TerminalTabId>,
    next_tab_id: u64,
    next_generation: u64,
    next_ai_generation: u64,
    font_size: f32,
    pub search: TerminalSearchOverlay,
    pub ai: TerminalAiOverlay,
}

impl TerminalWorkspace {
    pub fn new(font_size: f32) -> Self {
        Self {
            tabs: Vec::new(),
            active: None,
            next_tab_id: 0,
            next_generation: 0,
            next_ai_generation: 0,
            font_size: font_size.clamp(8.0, 72.0),
            search: TerminalSearchOverlay::default(),
            ai: TerminalAiOverlay::default(),
        }
    }

    pub fn tabs(&self) -> &[TerminalTab] {
        &self.tabs
    }

    /// Clears all visible state without reusing tab or async generations.
    /// This is required when an SSH binding is replaced under the same target
    /// guard: a late result from the old binding must not match the first tab
    /// created for the replacement binding.
    pub fn clear(&mut self) {
        self.tabs.clear();
        self.active = None;
        self.search = TerminalSearchOverlay::default();
        self.ai = TerminalAiOverlay::default();
    }

    pub fn tab(&self, id: TerminalTabId) -> Option<&TerminalTab> {
        self.tabs.iter().find(|tab| tab.id == id)
    }

    pub fn active_id(&self) -> Option<TerminalTabId> {
        self.active
    }

    pub fn active(&self) -> Option<&TerminalTab> {
        self.active.and_then(|id| self.tab(id))
    }

    pub fn active_token(&self) -> Option<TerminalTabToken> {
        self.active().map(TerminalTab::token)
    }

    pub fn contains(&self, token: TerminalTabToken) -> bool {
        self.tab(token.id)
            .is_some_and(|tab| tab.generation == token.generation)
    }

    pub fn open_tab(&mut self, label: impl Into<String>) -> TerminalTabToken {
        let id = TerminalTabId(self.bump_tab_id());
        let generation = self.bump_generation();
        let tab = TerminalTab {
            id,
            generation,
            label: label.into(),
            title: None,
            state: TerminalTabState::Opening,
        };
        let token = tab.token();
        self.tabs.push(tab);
        self.active = Some(id);
        token
    }

    pub fn activate(&mut self, id: TerminalTabId) -> bool {
        if self.tab(id).is_none() {
            return false;
        }
        self.active = Some(id);
        true
    }

    pub fn cycle(&mut self, direction: TabDirection) -> Option<TerminalTabId> {
        if self.tabs.is_empty() {
            self.active = None;
            return None;
        }
        let index = self
            .active
            .and_then(|id| self.tabs.iter().position(|tab| tab.id == id))
            .unwrap_or(0);
        let next = match direction {
            TabDirection::Next => (index + 1) % self.tabs.len(),
            TabDirection::Previous => (index + self.tabs.len() - 1) % self.tabs.len(),
        };
        let id = self.tabs[next].id;
        self.active = Some(id);
        Some(id)
    }

    /// Removes a tab and activates its right neighbor, or its left neighbor
    /// when the removed tab was last. Returns the exact generation that closed.
    pub fn close_tab(&mut self, id: TerminalTabId) -> Option<TerminalTabToken> {
        let index = self.tabs.iter().position(|tab| tab.id == id)?;
        let removed = self.tabs.remove(index);
        if self.active == Some(id) {
            self.active = self
                .tabs
                .get(index.min(self.tabs.len().saturating_sub(1)))
                .map(|tab| tab.id);
        }
        if self
            .ai
            .active()
            .is_some_and(|token| token.tab.id == removed.id)
        {
            let _ = self.ai.cancel();
        }
        Some(removed.token())
    }

    pub fn begin_reconnect(&mut self, id: TerminalTabId) -> Option<TerminalTabToken> {
        let generation = self.bump_generation();
        let tab = self.tabs.iter_mut().find(|tab| tab.id == id)?;
        tab.generation = generation;
        tab.state = TerminalTabState::Reconnecting;
        tab.title = None;
        Some(tab.token())
    }

    pub fn mark_open(&mut self, token: TerminalTabToken) -> bool {
        self.update_matching(token, |tab| tab.state = TerminalTabState::Open)
    }

    pub fn mark_closed(&mut self, token: TerminalTabToken, exit_code: Option<i32>) -> bool {
        self.update_matching(token, |tab| {
            tab.state = TerminalTabState::Closed { exit_code }
        })
    }

    pub fn mark_failed(&mut self, token: TerminalTabToken, error: impl Into<String>) -> bool {
        let error = error.into();
        self.update_matching(token, |tab| tab.state = TerminalTabState::Failed(error))
    }

    pub fn set_title(&mut self, token: TerminalTabToken, title: impl Into<String>) -> bool {
        let title = title.into();
        self.update_matching(token, |tab| tab.title = Some(title))
    }

    pub const fn font_size(&self) -> f32 {
        self.font_size
    }

    pub fn change_font_size(&mut self, delta: f32) -> f32 {
        self.font_size = (self.font_size + delta).clamp(8.0, 72.0);
        self.font_size
    }

    pub fn reset_font_size(&mut self, font_size: f32) -> f32 {
        self.font_size = font_size.clamp(8.0, 72.0);
        self.font_size
    }

    pub fn begin_ai(
        &mut self,
        tab: TerminalTabToken,
        stream_id: impl Into<String>,
        prompt: impl Into<String>,
    ) -> Option<TerminalAiToken> {
        if !self.contains(tab) {
            return None;
        }
        self.next_ai_generation = self.next_ai_generation.saturating_add(1);
        let token = TerminalAiToken {
            tab,
            generation: self.next_ai_generation,
            stream_id: stream_id.into(),
        };
        self.ai.begin(token.clone(), prompt.into());
        Some(token)
    }

    fn update_matching(
        &mut self,
        token: TerminalTabToken,
        update: impl FnOnce(&mut TerminalTab),
    ) -> bool {
        let Some(tab) = self
            .tabs
            .iter_mut()
            .find(|tab| tab.id == token.id && tab.generation == token.generation)
        else {
            return false;
        };
        update(tab);
        true
    }

    fn bump_tab_id(&mut self) -> u64 {
        self.next_tab_id = self.next_tab_id.saturating_add(1);
        self.next_tab_id
    }

    fn bump_generation(&mut self) -> u64 {
        self.next_generation = self.next_generation.saturating_add(1);
        self.next_generation
    }
}

impl Default for TerminalWorkspace {
    fn default() -> Self {
        Self::new(14.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tabs_keep_identity_and_close_selects_a_neighbor() {
        let mut workspace = TerminalWorkspace::default();
        let first = workspace.open_tab("shell 1");
        let second = workspace.open_tab("shell 2");
        let third = workspace.open_tab("shell 3");
        assert_eq!(workspace.active_id(), Some(third.id));

        assert_eq!(workspace.close_tab(second.id), Some(second));
        assert_eq!(workspace.active_id(), Some(third.id));
        assert_eq!(workspace.close_tab(third.id), Some(third));
        assert_eq!(workspace.active_id(), Some(first.id));
        assert_eq!(workspace.tabs().len(), 1);
    }

    #[test]
    fn reconnect_invalidates_late_open_and_output_tokens() {
        let mut workspace = TerminalWorkspace::default();
        let original = workspace.open_tab("shell");
        let reconnect = workspace.begin_reconnect(original.id).unwrap();
        assert_ne!(original.generation, reconnect.generation);
        assert!(!workspace.mark_open(original));
        assert!(!workspace.set_title(original, "stale"));
        assert!(workspace.mark_open(reconnect));
        assert!(workspace.set_title(reconnect, "current"));
        assert_eq!(workspace.tab(original.id).unwrap().title(), Some("current"));
    }

    #[test]
    fn clearing_a_binding_never_reuses_async_identity() {
        let mut workspace = TerminalWorkspace::default();
        let stale = workspace.open_tab("old binding");
        workspace.clear();
        let current = workspace.open_tab("new binding");
        assert_ne!(stale.id, current.id);
        assert_ne!(stale.generation, current.generation);
        assert!(!workspace.contains(stale));
        assert!(workspace.contains(current));
    }

    #[test]
    fn tab_cycle_wraps_in_both_directions() {
        let mut workspace = TerminalWorkspace::default();
        let first = workspace.open_tab("one");
        let second = workspace.open_tab("two");
        assert_eq!(
            workspace.cycle(TabDirection::Next),
            Some(first.id),
            "next wraps from the final tab"
        );
        assert_eq!(
            workspace.cycle(TabDirection::Previous),
            Some(second.id),
            "previous wraps from the first tab"
        );
    }

    #[test]
    fn ai_cancel_rejects_late_delta_and_completion() {
        let mut workspace = TerminalWorkspace::default();
        let tab = workspace.open_tab("shell");
        let token = workspace
            .begin_ai(tab, "terminal:1", "explain this")
            .unwrap();
        assert!(workspace.ai.apply_delta(&token, "safe "));
        assert_eq!(workspace.ai.cancel(), Some(token.clone()));
        assert!(!workspace.ai.apply_delta(&token, "late"));
        assert!(!workspace.ai.complete(&token));
        assert_eq!(workspace.ai.output, "safe ");
        assert_eq!(workspace.ai.state, TerminalAiState::Cancelled);
    }

    #[test]
    fn ai_is_bound_to_exact_tab_generation() {
        let mut workspace = TerminalWorkspace::default();
        let tab = workspace.open_tab("shell");
        let stale = workspace.begin_reconnect(tab.id).unwrap();
        let current = workspace.begin_reconnect(tab.id).unwrap();
        assert!(workspace.begin_ai(stale, "stale", "prompt").is_none());
        let token = workspace.begin_ai(current, "current", "prompt").unwrap();
        assert!(workspace.ai.apply_delta(&token, "<b>literal text</b>"));
        assert_eq!(workspace.ai.output, "<b>literal text</b>");
    }
}
