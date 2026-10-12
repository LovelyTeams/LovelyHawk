//! Generation-based target identity guards for asynchronous work.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::{CoreError, CoreResult};

/// Stable connection/host identity, separate from a display name or address.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TargetIdentity(String);

impl TargetIdentity {
    pub fn new(value: impl Into<String>) -> CoreResult<Self> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(CoreError::validation(
                "target identity",
                "must not be empty",
            ));
        }
        if value.len() > 256 || value.chars().any(char::is_control) {
            return Err(CoreError::validation(
                "target identity",
                "must be at most 256 bytes and contain no control characters",
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Snapshot captured when work is planned. Both fields must still match later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetGuard {
    pub identity: TargetIdentity,
    pub generation: u64,
}

#[derive(Debug, Clone)]
struct TargetState {
    identity: Option<TargetIdentity>,
    generation: u64,
}

/// The currently active target and its monotonically increasing activation epoch.
#[derive(Debug)]
pub struct TargetContext {
    state: RwLock<TargetState>,
}

impl Default for TargetContext {
    fn default() -> Self {
        Self::new()
    }
}

impl TargetContext {
    pub fn new() -> Self {
        Self {
            state: RwLock::new(TargetState {
                identity: None,
                generation: 0,
            }),
        }
    }

    /// Activate a target and invalidate every previously issued guard.
    /// Reconnecting the same identity intentionally creates a new generation.
    pub fn activate(&self, identity: TargetIdentity) -> CoreResult<TargetGuard> {
        let mut state = self.state.write();
        state.generation = next_generation(state.generation)?;
        state.identity = Some(identity.clone());
        Ok(TargetGuard {
            identity,
            generation: state.generation,
        })
    }

    /// Clear the active target and invalidate all in-flight work.
    pub fn clear(&self) -> CoreResult<()> {
        let mut state = self.state.write();
        state.generation = next_generation(state.generation)?;
        state.identity = None;
        Ok(())
    }

    /// Clear the active target only when the caller still owns its exact epoch.
    ///
    /// This lets an asynchronous connection failure clean up its own target
    /// without ever clearing a newer target that became active meanwhile.
    pub fn clear_if_current(&self, guard: &TargetGuard) -> CoreResult<bool> {
        let mut state = self.state.write();
        if state.identity.as_ref() != Some(&guard.identity) || state.generation != guard.generation
        {
            return Ok(false);
        }
        state.generation = next_generation(state.generation)?;
        state.identity = None;
        Ok(true)
    }

    pub fn current_guard(&self) -> CoreResult<TargetGuard> {
        let state = self.state.read();
        let identity = state.identity.clone().ok_or(CoreError::NoActiveTarget)?;
        Ok(TargetGuard {
            identity,
            generation: state.generation,
        })
    }

    /// Validate both identity and generation. Matching only the host id is unsafe
    /// because reconnecting it may have replaced the underlying SSH session.
    pub fn validate(&self, guard: &TargetGuard) -> CoreResult<()> {
        let state = self.state.read();
        validate_state(&state, guard)
    }
}

fn validate_state(state: &TargetState, guard: &TargetGuard) -> CoreResult<()> {
    if state.identity.as_ref() == Some(&guard.identity) && state.generation == guard.generation {
        return Ok(());
    }
    let current = state
        .identity
        .as_ref()
        .map(|identity| format!("{}@{}", identity.as_str(), state.generation))
        .unwrap_or_else(|| format!("<none>@{}", state.generation));
    Err(CoreError::TargetChanged {
        expected_identity: guard.identity.as_str().to_owned(),
        expected_generation: guard.generation,
        current,
    })
}

fn next_generation(current: u64) -> CoreResult<u64> {
    current
        .checked_add(1)
        .ok_or_else(|| CoreError::validation("target generation", "generation counter exhausted"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(value: &str) -> TargetIdentity {
        TargetIdentity::new(value).unwrap()
    }

    #[test]
    fn switch_invalidates_old_guard_even_for_same_identity() {
        let context = TargetContext::new();
        let first = context.activate(identity("host-a")).unwrap();
        context.validate(&first).unwrap();

        let second = context.activate(identity("host-a")).unwrap();
        assert_ne!(first.generation, second.generation);
        assert!(matches!(
            context.validate(&first),
            Err(CoreError::TargetChanged { .. })
        ));
        context.validate(&second).unwrap();
    }

    #[test]
    fn identity_and_generation_are_both_checked() {
        let context = TargetContext::new();
        let first = context.activate(identity("host-a")).unwrap();
        let second = context.activate(identity("host-b")).unwrap();
        assert!(context.validate(&first).is_err());
        context.validate(&second).unwrap();
        context.clear().unwrap();
        assert!(context.current_guard().is_err());
        assert!(context.validate(&second).is_err());
    }

    #[test]
    fn stale_guard_cannot_clear_a_newer_target() {
        let context = TargetContext::new();
        let stale = context.activate(identity("host-a")).unwrap();
        let current = context.activate(identity("host-b")).unwrap();

        assert!(!context.clear_if_current(&stale).unwrap());
        context.validate(&current).unwrap();
        assert!(context.clear_if_current(&current).unwrap());
        assert!(matches!(
            context.current_guard(),
            Err(CoreError::NoActiveTarget)
        ));
    }

    #[test]
    fn target_identity_rejects_ambiguous_values() {
        assert!(TargetIdentity::new("").is_err());
        assert!(TargetIdentity::new("host\nother").is_err());
        assert!(TargetIdentity::new("a".repeat(257)).is_err());
    }
}
