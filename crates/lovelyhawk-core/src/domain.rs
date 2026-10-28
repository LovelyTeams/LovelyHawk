//! Shared typed boundary for commands executed against a target session.

use serde::{Deserialize, Serialize};

use crate::{CoreError, CoreResult};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

impl CommandOutput {
    pub fn success(stdout: impl Into<String>) -> Self {
        Self {
            stdout: stdout.into(),
            stderr: String::new(),
            exit_code: 0,
        }
    }

    pub fn is_success(&self) -> bool {
        self.exit_code == 0
    }

    pub fn into_stdout(self, operation: &'static str) -> CoreResult<String> {
        if self.is_success() {
            return Ok(self.stdout);
        }
        let detail = if self.stderr.trim().is_empty() {
            self.stdout.trim()
        } else {
            self.stderr.trim()
        };
        Err(CoreError::validation(
            operation,
            format!("remote command exited {}: {detail}", self.exit_code),
        ))
    }
}

/// Injection seam implemented by the eventual russh session service and by tests.
pub trait CommandRunner: Send + Sync + std::fmt::Debug {
    fn run(&self, command: &str) -> CoreResult<CommandOutput>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceAction {
    Start,
    Stop,
    Restart,
    Status,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceActionResult {
    pub service: String,
    pub action: ServiceAction,
    pub succeeded: bool,
    pub message: String,
}

pub(crate) fn bounded_text(subject: &'static str, value: &str, maximum: usize) -> CoreResult<()> {
    if value.trim().is_empty() || value.len() > maximum || value.contains(['\0', '\n', '\r']) {
        return Err(CoreError::validation(
            subject,
            format!("must be non-empty, line-control-free, and at most {maximum} bytes"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_command_does_not_silently_return_stdout() {
        let output = CommandOutput {
            stdout: "partial".to_owned(),
            stderr: "permission denied".to_owned(),
            exit_code: 126,
        };
        let error = output.into_stdout("test operation").unwrap_err();
        assert!(error.to_string().contains("permission denied"));
    }
}
