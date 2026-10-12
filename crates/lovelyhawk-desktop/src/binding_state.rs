//! Which SSH binding terminal windows may open against.
//!
//! The host watches the connect attempts the main window drives. Only the
//! attempt it saw start can become the current binding, so a late answer from
//! an abandoned attempt cannot quietly retarget the terminal windows. When the
//! binding changes, every window bound to the previous one is closed.

use serde_json::Value;

#[derive(Debug, PartialEq, Eq)]
pub enum Transition {
    Unchanged,
    Accepted {
        binding_handle: String,
        previous_binding_handle: Option<String>,
    },
    Stale,
}

#[derive(Debug, Default)]
pub struct BindingState {
    pending_attempt: Option<String>,
    accepted_attempt: Option<String>,
    active_binding: Option<String>,
    active_target_label: String,
}

impl BindingState {
    /// Display-only label for terminal title bars, `user@host:port`.
    pub fn current_target_label(&self) -> &str {
        &self.active_target_label
    }

    pub fn current_binding_handle(&self) -> Option<&str> {
        self.active_binding.as_deref()
    }

    pub fn start_connect(&mut self, attempt_handle: &str) {
        self.pending_attempt = Some(attempt_handle.to_owned());
    }

    pub fn cancel_attempt(&mut self, attempt_handle: &str) {
        if self.pending_attempt.as_deref() == Some(attempt_handle) {
            self.pending_attempt = None;
        }
    }

    /// Reads one attempt status as the backend returned it.
    pub fn observe(&mut self, attempt_handle: &str, status: &Value) -> Transition {
        let stage = status.get("stage").and_then(Value::as_str);
        match stage {
            Some("connected") => {
                let Some(binding) = status.get("bindingHandle").and_then(Value::as_str) else {
                    return Transition::Stale;
                };
                if self.accepted_attempt.as_deref() == Some(attempt_handle)
                    && self.active_binding.as_deref() == Some(binding)
                {
                    return Transition::Unchanged;
                }
                if self.pending_attempt.as_deref() != Some(attempt_handle) {
                    return Transition::Stale;
                }
                let previous = self.active_binding.take();
                self.pending_attempt = None;
                self.accepted_attempt = Some(attempt_handle.to_owned());
                self.active_binding = Some(binding.to_owned());
                self.active_target_label = target_label(status.get("target"));
                Transition::Accepted {
                    binding_handle: binding.to_owned(),
                    previous_binding_handle: previous,
                }
            }
            Some("failed" | "cancelled") => {
                if self.pending_attempt.as_deref() == Some(attempt_handle) {
                    self.pending_attempt = None;
                }
                Transition::Unchanged
            }
            _ => Transition::Unchanged,
        }
    }

    pub fn disconnect(&mut self, binding_handle: &str) -> bool {
        if self.active_binding.as_deref() != Some(binding_handle) {
            return false;
        }
        self.active_binding = None;
        self.accepted_attempt = None;
        true
    }
}

fn target_label(target: Option<&Value>) -> String {
    let field = |key: &str| {
        target
            .and_then(|value| value.get(key))
            .map(|value| match value {
                Value::String(text) => text.clone(),
                other => other.to_string(),
            })
            .unwrap_or_default()
    };
    sanitize_label(&format!(
        "{}@{}:{}",
        field("username"),
        field("host"),
        field("port")
    ))
}

pub const MAX_TARGET_LABEL_BYTES: usize = 128;

/// Single line, bounded, no control characters: the label is presentation.
pub fn sanitize_label(value: &str) -> String {
    let mut label = String::new();
    for character in value.chars().filter(|character| !character.is_control()) {
        if label.len() + character.len_utf8() > MAX_TARGET_LABEL_BYTES {
            break;
        }
        label.push(character);
    }
    label
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn connected(binding: &str) -> Value {
        json!({
            "stage": "connected",
            "bindingHandle": binding,
            "target": { "username": "root", "host": "10.0.0.9", "port": 22 }
        })
    }

    #[test]
    fn only_the_attempt_seen_starting_can_become_current() {
        let mut state = BindingState::default();
        assert_eq!(
            state.observe("attempt-a", &connected("binding-a")),
            Transition::Stale
        );
        state.start_connect("attempt-a");
        assert_eq!(
            state.observe("attempt-a", &connected("binding-a")),
            Transition::Accepted {
                binding_handle: "binding-a".into(),
                previous_binding_handle: None
            }
        );
        assert_eq!(state.current_target_label(), "root@10.0.0.9:22");
        assert_eq!(
            state.observe("attempt-a", &connected("binding-a")),
            Transition::Unchanged
        );
        state.start_connect("attempt-b");
        assert_eq!(
            state.observe("attempt-b", &connected("binding-b")),
            Transition::Accepted {
                binding_handle: "binding-b".into(),
                previous_binding_handle: Some("binding-a".into())
            }
        );
        // The first attempt answering late cannot take the binding back.
        assert_eq!(
            state.observe("attempt-a", &connected("binding-a")),
            Transition::Stale
        );
    }

    #[test]
    fn cancellation_and_disconnect_clear_their_own_state_only() {
        let mut state = BindingState::default();
        state.start_connect("attempt-a");
        state.cancel_attempt("attempt-other");
        state.cancel_attempt("attempt-a");
        assert_eq!(
            state.observe("attempt-a", &connected("binding-a")),
            Transition::Stale
        );
        state.start_connect("attempt-b");
        state.observe("attempt-b", &connected("binding-b"));
        assert!(!state.disconnect("binding-a"));
        assert!(state.disconnect("binding-b"));
        assert_eq!(state.current_binding_handle(), None);
    }

    #[test]
    fn labels_drop_control_characters_and_stay_bounded() {
        assert_eq!(sanitize_label("root\u{1b}[31m@host"), "root[31m@host");
        assert_eq!(sanitize_label(&"界".repeat(100)).len(), 126);
    }
}
