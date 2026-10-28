use crate::{SearchMatch, SearchOptions, TerminalModel, TerminalModelError};

/// Stateful terminal search cursor with deterministic wrap-around navigation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SearchState {
    query: String,
    options: SearchOptions,
    matches: Vec<SearchMatch>,
    current: Option<usize>,
}

impl SearchState {
    pub fn query(&self) -> &str {
        &self.query
    }

    pub fn options(&self) -> &SearchOptions {
        &self.options
    }

    pub fn matches(&self) -> &[SearchMatch] {
        &self.matches
    }

    pub fn current_index(&self) -> Option<usize> {
        self.current
    }

    pub fn current(&self) -> Option<&SearchMatch> {
        self.current.and_then(|index| self.matches.get(index))
    }

    pub fn is_empty(&self) -> bool {
        self.matches.is_empty()
    }

    pub fn len(&self) -> usize {
        self.matches.len()
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }

    pub fn update(
        &mut self,
        model: &TerminalModel,
        query: impl Into<String>,
        options: SearchOptions,
    ) -> Result<(), TerminalModelError> {
        let query = query.into();
        let matches = model.search(&query, &options)?;
        self.query = query;
        self.options = options;
        self.matches = matches;
        self.current = (!self.matches.is_empty()).then_some(0);
        Ok(())
    }

    pub fn next_match(&mut self) -> Option<&SearchMatch> {
        if self.matches.is_empty() {
            self.current = None;
            return None;
        }
        let index = self
            .current
            .map_or(0, |index| (index + 1) % self.matches.len());
        self.current = Some(index);
        self.matches.get(index)
    }

    pub fn previous_match(&mut self) -> Option<&SearchMatch> {
        if self.matches.is_empty() {
            self.current = None;
            return None;
        }
        let index = self.current.map_or(self.matches.len() - 1, |index| {
            (index + self.matches.len() - 1) % self.matches.len()
        });
        self.current = Some(index);
        self.matches.get(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TerminalConfig, TerminalSize};

    fn searchable_model() -> TerminalModel {
        let config = TerminalConfig {
            size: TerminalSize::new(32, 3).unwrap(),
            ..Default::default()
        };
        let mut model = TerminalModel::new(config).unwrap();
        model.feed_output(b"Alpha alpha\r\nbeta alpha");
        model
    }

    #[test]
    fn navigation_wraps_in_both_directions() {
        let model = searchable_model();
        let mut state = SearchState::default();
        state
            .update(&model, "alpha", SearchOptions::default())
            .unwrap();

        assert_eq!(state.len(), 3);
        assert_eq!(state.current().unwrap().text, "Alpha");
        assert_eq!(state.next_match().unwrap().text, "alpha");
        assert_eq!(state.next_match().unwrap().line, 1);
        assert_eq!(state.next_match().unwrap().text, "Alpha");
        assert_eq!(state.previous_match().unwrap().line, 1);
    }

    #[test]
    fn case_and_regex_options_are_applied() {
        let model = searchable_model();
        let mut state = SearchState::default();
        state
            .update(
                &model,
                r"^Alpha",
                SearchOptions {
                    case_sensitive: true,
                    regex: true,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(state.len(), 1);
        assert_eq!(state.current().unwrap().text, "Alpha");

        assert!(
            state
                .update(
                    &model,
                    "(",
                    SearchOptions {
                        regex: true,
                        ..Default::default()
                    },
                )
                .is_err()
        );
        assert_eq!(state.query(), r"^Alpha");
    }
}
