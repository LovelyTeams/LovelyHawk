use std::fmt;
use std::path::PathBuf;

/// Identifies which peer produced an SSH host-key verification error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SshHostRole {
    Target,
    JumpHost,
}

/// One bounded prompt returned by an SSH keyboard-interactive challenge.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshKeyboardInteractivePrompt {
    pub prompt: String,
    pub echo: bool,
}

/// A server-authored keyboard-interactive challenge safe for presentation by the UI.
///
/// Responses are deliberately absent: they remain short-lived secrets owned by the
/// connect authorization and are never serialized or included in an error value.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshKeyboardInteractiveChallenge {
    pub role: SshHostRole,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub name: String,
    pub instructions: String,
    pub prompts: Vec<SshKeyboardInteractivePrompt>,
    pub supplied_responses: usize,
}

impl fmt::Display for SshKeyboardInteractiveChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} prompt(s) for {}@{}:{}",
            self.prompts.len(),
            self.username,
            self.host,
            self.port
        )
    }
}

impl fmt::Display for SshHostRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Target => "target",
            Self::JumpHost => "jump host",
        })
    }
}

/// Errors that cross the core service boundary.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("{operation} failed for {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("{operation} failed for {path}: {primary}; cleanup also failed: {cleanup_failures}")]
    PartialCleanup {
        operation: &'static str,
        path: PathBuf,
        #[source]
        primary: Box<CoreError>,
        cleanup_failures: String,
    },

    #[error("invalid {subject}: {message}")]
    Validation {
        subject: &'static str,
        message: String,
    },

    #[error("failed to encode {subject}: {source}")]
    Encode {
        subject: &'static str,
        #[source]
        source: serde_json::Error,
    },

    #[error("failed to decode {subject}: {source}")]
    Decode {
        subject: &'static str,
        #[source]
        source: serde_json::Error,
    },

    #[error("unsupported schema version for {document}: expected {expected}, got {actual}")]
    UnsupportedSchema {
        document: &'static str,
        expected: u32,
        actual: u32,
    },

    #[error("unsupported feature: {feature}")]
    Unsupported { feature: &'static str },

    #[error("no target is active")]
    NoActiveTarget,

    #[error(
        "target changed while work was in flight (expected {expected_identity}@{expected_generation}, current {current})"
    )]
    TargetChanged {
        expected_identity: String,
        expected_generation: u64,
        current: String,
    },

    #[error("dangerous operation {operation_id} requires explicit confirmation")]
    ConfirmationRequired { operation_id: String },

    #[error("operation {operation_id} was cancelled")]
    OperationCancelled { operation_id: String },

    #[error("invalid operation transition from {state}: {action}")]
    InvalidOperationState {
        state: &'static str,
        action: &'static str,
    },

    #[error("cryptographic operation failed: {0}")]
    Crypto(String),

    #[error("{entity} not found: {id}")]
    NotFound { entity: &'static str, id: String },

    #[error("event channel capacity must be greater than zero")]
    InvalidChannelCapacity,

    #[error("{channel} event channel is closed")]
    ChannelClosed { channel: &'static str },

    #[error(
        "SSH {role} host key confirmation required for {username}@{host}:{port}: {fingerprint}"
    )]
    SshHostKeyConfirmationRequired {
        role: SshHostRole,
        host: String,
        port: u16,
        username: String,
        fingerprint: String,
    },

    #[error(
        "SSH {role} host key changed for {host}:{port}; recorded {expected}, observed {observed}"
    )]
    SshHostKeyChanged {
        role: SshHostRole,
        host: String,
        port: u16,
        expected: String,
        observed: String,
    },

    #[error("SSH keyboard-interactive authentication requires {challenge}")]
    SshKeyboardInteractiveRequired {
        challenge: Box<SshKeyboardInteractiveChallenge>,
    },

    #[error("SSH {operation} failed: {message}")]
    Ssh {
        operation: &'static str,
        message: String,
    },

    /// The connection to the target is gone.
    ///
    /// Separate from [`CoreError::Ssh`] because it is not a failure of the
    /// operation that reported it: a host that went away makes every feature
    /// fail at once, and each of them saying so in its own words reads as a
    /// dozen broken features rather than one lost connection.
    #[error("SSH connection to the target is gone: {message}")]
    SshDisconnected { message: String },
}

impl CoreError {
    pub(crate) fn io(
        operation: &'static str,
        path: impl Into<PathBuf>,
        source: std::io::Error,
    ) -> Self {
        Self::Io {
            operation,
            path: path.into(),
            source,
        }
    }

    pub(crate) fn validation(subject: &'static str, message: impl Into<String>) -> Self {
        Self::Validation {
            subject,
            message: message.into(),
        }
    }

    pub(crate) fn partial_cleanup(
        operation: &'static str,
        path: impl Into<PathBuf>,
        primary: CoreError,
        cleanup_failures: impl Into<String>,
    ) -> Self {
        Self::PartialCleanup {
            operation,
            path: path.into(),
            primary: Box::new(primary),
            cleanup_failures: cleanup_failures.into(),
        }
    }

    /// Classifies an SSH failure, so a lost connection is not reported as a
    /// failure of whatever happened to ask for it first.
    pub(crate) fn ssh(operation: &'static str, message: impl Into<String>) -> Self {
        let message = message.into();
        if transport_is_gone(&message) {
            return Self::SshDisconnected { message };
        }
        Self::Ssh { operation, message }
    }
}

/// Whether an SSH library error means the transport itself is gone.
///
/// The library reports this as ordinary errors on whatever call happened to be
/// made next, so the shapes are matched here rather than guessed at each call
/// site. Matching too little only leaves the old wording; matching too much
/// would report a live connection as lost, so every entry below is a message
/// the library only produces once the session task has ended.
fn transport_is_gone(message: &str) -> bool {
    const GONE: [&str; 6] = [
        // The session task is no longer receiving, so nothing can be opened.
        "Channel send error",
        "channel send error",
        // The peer closed, or the socket did.
        "Connection closed",
        "connection reset",
        "broken pipe",
        "Not connected",
    ];
    GONE.iter().any(|shape| message.contains(shape))
}

pub type CoreResult<T> = Result<T, CoreError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lost_transport_is_not_reported_as_a_failed_operation() {
        let lost = CoreError::ssh("open command channel", "Channel send error");
        assert!(matches!(lost, CoreError::SshDisconnected { .. }));
        assert!(
            lost.to_string()
                .contains("connection to the target is gone")
        );
    }

    #[test]
    fn an_ordinary_ssh_failure_keeps_saying_what_failed() {
        let refused = CoreError::ssh("execute command", "remote probe exited with Some(1)");
        assert!(matches!(refused, CoreError::Ssh { .. }));
        assert!(refused.to_string().contains("execute command"));
    }

    #[test]
    fn only_the_shapes_that_mean_the_session_ended_count_as_gone() {
        for message in [
            "Channel send error",
            "Connection closed by peer",
            "broken pipe",
        ] {
            assert!(transport_is_gone(message), "{message}");
        }
        // A refused channel, a timeout and a permission problem all happen on a
        // connection that is still there.
        for message in [
            "channel open failure: administratively prohibited",
            "command timed out",
            "Permission denied (publickey)",
            "host key confirmation required",
        ] {
            assert!(!transport_is_gone(message), "{message}");
        }
    }
}
