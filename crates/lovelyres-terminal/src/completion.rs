const MAX_TRACKED_LINE_BYTES: usize = 4_096;

const OFFLINE_COMMANDS: &[&str] = &[
    "cat /etc/os-release",
    "df -h",
    "docker logs --tail 200 ",
    "docker ps --no-trunc",
    "free -h",
    "ip address show",
    "journalctl --no-pager -n 200",
    "last -n 50",
    "ls -al",
    "ps auxww",
    "ss -tulpn",
    "systemctl --failed --no-pager",
    "uname -a",
    "who -a",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteCompletion {
    source_line: String,
    candidates: Vec<String>,
    replacement_start: usize,
    replacement_end: usize,
}

impl RemoteCompletion {
    pub fn new(
        source_line: impl Into<String>,
        candidates: Vec<String>,
        replacement_start: usize,
        replacement_end: usize,
    ) -> Option<Self> {
        let source_line = source_line.into();
        if replacement_start > replacement_end
            || replacement_end > source_line.len()
            || !source_line.is_char_boundary(replacement_start)
            || !source_line.is_char_boundary(replacement_end)
        {
            return None;
        }
        let mut candidates = candidates
            .into_iter()
            .filter(|candidate| {
                !candidate.is_empty()
                    && candidate.len() <= 4_096
                    && !candidate.chars().any(char::is_control)
            })
            .take(100)
            .collect::<Vec<_>>();
        candidates.sort();
        candidates.dedup();
        if candidates.is_empty() {
            return None;
        }
        Some(Self {
            source_line,
            candidates,
            replacement_start,
            replacement_end,
        })
    }

    pub fn source_line(&self) -> &str {
        &self.source_line
    }

    pub fn candidates(&self) -> &[String] {
        &self.candidates
    }

    pub fn completion_suffix(&self, current_line: &str) -> Option<String> {
        if current_line != self.source_line || self.replacement_end != current_line.len() {
            return None;
        }
        let existing = current_line.get(self.replacement_start..self.replacement_end)?;
        let replacement = if self.candidates.len() == 1 {
            self.candidates.first()?.as_str()
        } else {
            longest_common_prefix(&self.candidates)?
        };
        let suffix = replacement.strip_prefix(existing)?;
        (!suffix.is_empty()).then(|| suffix.to_owned())
    }
}

fn longest_common_prefix(candidates: &[String]) -> Option<&str> {
    let first = candidates.first()?;
    let mut bytes = first.len();
    for candidate in &candidates[1..] {
        bytes = first
            .char_indices()
            .map(|(index, _)| index)
            .chain(std::iter::once(first.len()))
            .take_while(|end| *end <= bytes && candidate.get(..*end) == first.get(..*end))
            .last()
            .unwrap_or(0);
        if bytes == 0 {
            break;
        }
    }
    first.get(..bytes)
}

/// Conservative, offline command hints. It observes only a simple shell line;
/// cursor movement, alternate-screen input, and control sequences disable the
/// hint instead of guessing what the remote readline state contains.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandCompletion {
    line: String,
    reliable: bool,
}

impl Default for CommandCompletion {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandCompletion {
    pub fn new() -> Self {
        Self {
            line: String::new(),
            reliable: true,
        }
    }

    pub fn line(&self) -> &str {
        &self.line
    }

    pub const fn is_reliable(&self) -> bool {
        self.reliable
    }

    pub fn observe(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if bytes == b"\r" || bytes == b"\n" || bytes == b"\x03" {
            self.clear();
            return;
        }
        if bytes == [0x7f] || bytes == [0x08] {
            self.line.pop();
            return;
        }
        if bytes.contains(&0x1b) || bytes.contains(&b'\t') || bytes.contains(&b'\r') {
            self.reliable = false;
            return;
        }
        let Ok(text) = std::str::from_utf8(bytes) else {
            self.reliable = false;
            return;
        };
        if text.chars().any(char::is_control)
            || self.line.len().saturating_add(text.len()) > MAX_TRACKED_LINE_BYTES
        {
            self.reliable = false;
            return;
        }
        self.line.push_str(text);
    }

    pub fn hint(&self) -> Option<&'static str> {
        if !self.reliable || self.line.trim().is_empty() {
            return None;
        }
        OFFLINE_COMMANDS
            .iter()
            .copied()
            .find(|candidate| candidate.starts_with(&self.line) && *candidate != self.line)
    }

    pub fn completion_suffix(&self) -> Option<&'static str> {
        self.hint()?.strip_prefix(&self.line)
    }

    pub fn clear(&mut self) {
        self.line.clear();
        self.reliable = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cjk_ime_text_is_tracked_without_corrupting_utf8() {
        let mut completion = CommandCompletion::new();
        completion.observe("echo 中文".as_bytes());
        assert_eq!(completion.line(), "echo 中文");
        assert_eq!(completion.hint(), None);
        completion.observe(&[0x7f]);
        assert_eq!(completion.line(), "echo 中");
    }

    #[test]
    fn completes_known_commands_without_executing_them() {
        let mut completion = CommandCompletion::new();
        completion.observe(b"ss -tu");
        assert_eq!(completion.hint(), Some("ss -tulpn"));
        assert_eq!(completion.completion_suffix(), Some("lpn"));
        assert_eq!(completion.line(), "ss -tu");
    }

    #[test]
    fn cursor_control_disables_guessing_until_next_command() {
        let mut completion = CommandCompletion::new();
        completion.observe(b"ps a");
        assert!(completion.hint().is_some());
        completion.observe(b"\x1b[D");
        assert!(completion.hint().is_none());
        completion.observe(b"\r");
        completion.observe(b"df");
        assert_eq!(completion.hint(), Some("df -h"));
    }

    #[test]
    fn remote_candidates_complete_a_utf8_safe_common_prefix() {
        let completion = RemoteCompletion::new(
            "cat /tmp/证",
            vec!["/tmp/证据-a".to_owned(), "/tmp/证据-b".to_owned()],
            4,
            "cat /tmp/证".len(),
        )
        .unwrap();
        assert_eq!(
            completion.completion_suffix("cat /tmp/证").as_deref(),
            Some("据-")
        );
        assert_eq!(completion.completion_suffix("cat /tmp/证x"), None);
    }
}
