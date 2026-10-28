//! Correlation with procfs while the native database connection is still alive.
//! Historical observations do not authorize later filesystem or process actions.
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub(crate) const MAX_OUTPUT: usize = 12 * 1024;
pub(crate) const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProcessProbeInput {
    pub backend_pid: u32,
    pub server_address: std::net::IpAddr,
    pub server_port: u16,
    pub client_address: std::net::IpAddr,
    pub client_port: u16,
    pub data_directory: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProcessUnavailableReason {
    Unsupported,
    TransportUnavailable,
    NoTcpObservation,
    PermissionDenied,
    ProcessUnavailable,
    ProcessChanged,
    NamespaceUnmatched,
    SocketUnmatched,
    ExecutableUnmatched,
    ExecutableUnavailable,
    PathUnavailable,
    LimitExceeded,
    InvalidInput,
    InvalidProcfs,
    InvalidOutput,
    Timeout,
}
impl ProcessUnavailableReason {
    pub fn detail(self) -> &'static str {
        match self {
            Self::Unsupported => "未取得所需的 Python 3.9+ 或 Linux pidfd 能力；未自动安装。",
            Self::TransportUnavailable => "SSH 未能完成进程核对，请核实连接和执行权限。",
            Self::NoTcpObservation => "数据库未提供完整 TCP 连接两端，无法核对主机 socket。",
            Self::PermissionDenied => "当前 SSH 账号无法读取所需进程信息；未自动提权。",
            Self::ProcessUnavailable => {
                "当前 SSH 可见范围内未取得对应进程，可能涉及另一主机或容器。"
            }
            Self::ProcessChanged => "核对期间进程或可执行文件发生变化，请重新读取。",
            Self::NamespaceUnmatched => "数据库进程与 SSH 检查不在相同 PID、网络或挂载命名空间。",
            Self::SocketUnmatched => "数据库连接未对应到该进程持有的 socket，可能涉及代理或转发。",
            Self::ExecutableUnmatched => "会话与父进程的可执行文件不一致，仍需核实实例。",
            Self::ExecutableUnavailable => "进程可执行文件已删除或无法确认，仍需核实实例。",
            Self::PathUnavailable => "进程报告的路径无法完整展示，仍需核实实例。",
            Self::LimitExceeded => "所需进程信息超过检查上限，本次未完成对应。",
            Self::Timeout => "进程核对超时，请核实目标负载后重试。",
            Self::InvalidInput | Self::InvalidProcfs | Self::InvalidOutput => {
                "进程信息未通过完整性核对，请重新读取。"
            }
        }
    }
}

fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PostgresqlHostProcess {
    observed_at: String,
    boot_id: String,
    backend_pid: u32,
    backend_start_ticks: String,
    postmaster_pid: u32,
    postmaster_start_ticks: String,
    socket_inode: String,
    pid_namespace: String,
    network_namespace: String,
    mount_namespace: String,
    executable_path: String,
    executable_device: String,
    executable_inode: String,
    executable_sha256: String,
    data_directory: String,
    #[serde(deserialize_with = "required_option")]
    reported_directory_matches: Option<bool>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ProcessState {
    Matched,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PostgresqlHostInspection {
    state: ProcessState,
    #[serde(deserialize_with = "required_option")]
    reason: Option<ProcessUnavailableReason>,
    #[serde(deserialize_with = "required_option")]
    process: Option<PostgresqlHostProcess>,
}
impl PostgresqlHostInspection {
    pub(crate) fn unavailable(reason: ProcessUnavailableReason) -> Self {
        Self {
            state: ProcessState::Unavailable,
            reason: Some(reason),
            process: None,
        }
    }
    pub(crate) fn parse(bytes: Zeroizing<Vec<u8>>, input: &ProcessProbeInput) -> Self {
        if bytes.len() <= MAX_OUTPUT
            && let Ok(result) = serde_json::from_slice::<Self>(&bytes)
            && result.valid(input)
        {
            return result;
        }
        Self::unavailable(ProcessUnavailableReason::InvalidOutput)
    }
    fn valid(&self, input: &ProcessProbeInput) -> bool {
        if self.state == ProcessState::Unavailable {
            return self.reason.is_some() && self.process.is_none();
        }
        let Some(process) = &self.process else {
            return false;
        };
        let uint = |s: &str, zero: bool| {
            s.len() <= 20
                && !s.is_empty()
                && (s == "0" || !s.starts_with('0'))
                && s.bytes().all(|b| b.is_ascii_digit())
                && s.parse::<u64>().is_ok_and(|v| zero || v > 0)
        };
        let path =
            |s: &str| s.starts_with('/') && s.len() <= 2048 && !s.chars().any(char::is_control);
        self.reason.is_none()
            && process.observed_at.len() <= 40
            && process.observed_at.ends_with('Z')
            && chrono::DateTime::parse_from_rfc3339(&process.observed_at).is_ok()
            && uuid::Uuid::parse_str(&process.boot_id).is_ok()
            && process.boot_id.len() == 36
            && process.backend_pid == input.backend_pid
            && process.backend_pid > 0
            && process.backend_pid <= i32::MAX as u32
            && process.postmaster_pid > 0
            && process.postmaster_pid <= i32::MAX as u32
            && process.postmaster_pid != process.backend_pid
            && [
                &process.backend_start_ticks,
                &process.postmaster_start_ticks,
                &process.socket_inode,
                &process.pid_namespace,
                &process.network_namespace,
                &process.mount_namespace,
                &process.executable_inode,
            ]
            .iter()
            .all(|s| uint(s, false))
            && uint(&process.executable_device, true)
            && process.postmaster_start_ticks.parse::<u64>().ok()
                <= process.backend_start_ticks.parse::<u64>().ok()
            && path(&process.executable_path)
            && !process.executable_path.ends_with(" (deleted)")
            && path(&process.data_directory)
            && process.executable_sha256.len() == 64
            && process
                .executable_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && process.reported_directory_matches
                == input.data_directory.as_ref().map(|s| {
                    s.trim_end_matches('/') == process.data_directory.trim_end_matches('/')
                })
    }
    pub fn case_identity(&self) -> String {
        match &self.process {
            Some(p) => format!(
                "SSH 主机进程对应：采集时 socket 与会话/父进程一致\n主机进程观察时间（UTC）：{}\n主机启动标识：{}\n主进程 PID / 启动 ticks：{} / {}\n会话 PID / 启动 ticks：{} / {}\n可执行文件 SHA-256：{}\n数据库报告目录与主进程工作目录：{}\n",
                p.observed_at,
                p.boot_id,
                p.postmaster_pid,
                p.postmaster_start_ticks,
                p.backend_pid,
                p.backend_start_ticks,
                p.executable_sha256,
                match p.reported_directory_matches {
                    Some(true) => "一致",
                    Some(false) => "不一致，仍需核实",
                    None => "数据库未提供目录，仍需核实",
                }
            ),
            None => format!(
                "SSH 主机进程对应：未完成。{}\n",
                self.reason.expect("validated unavailable reason").detail()
            ),
        }
    }
}

pub(crate) fn command() -> Zeroizing<String> {
    Zeroizing::new(format!(
        "python3 -I -c {}",
        crate::shell_escape::shq(include_str!("postgresql_process.py"))
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    fn input() -> ProcessProbeInput {
        ProcessProbeInput {
            backend_pid: 42,
            server_address: "::1".parse().unwrap(),
            server_port: 5432,
            client_address: "::1".parse().unwrap(),
            client_port: 42000,
            data_directory: Some("/srv/pg".into()),
        }
    }
    fn fixture() -> Value {
        json!({"state":"matched","reason":null,"process":{"observedAt":"2026-09-08T08:00:00Z","bootId":"c1bf0d9c-bcbc-44e4-a3f5-52cc0857c4a7","backendPid":42,"backendStartTicks":"2000","postmasterPid":8,"postmasterStartTicks":"1000","socketInode":"121","pidNamespace":"4026531840","networkNamespace":"4026531841","mountNamespace":"4026531842","executablePath":"/usr/lib/postgresql/16/bin/postgres","executableDevice":"0","executableInode":"151","executableSha256":"a".repeat(64),"dataDirectory":"/srv/pg","reportedDirectoryMatches":true}})
    }
    fn parse(v: &Value, input: &ProcessProbeInput) -> PostgresqlHostInspection {
        PostgresqlHostInspection::parse(Zeroizing::new(serde_json::to_vec(v).unwrap()), input)
    }
    #[test]
    fn binds_process_to_sql_identity_and_keeps_missing_or_different_directories_explicit() {
        let full = parse(&fixture(), &input());
        assert!(full.process.is_some());
        assert!(full.case_identity().contains("42 / 2000"));
        assert!(!full.case_identity().contains("/srv/pg"));
        let mut limited = input();
        limited.data_directory = None;
        let mut value = fixture();
        value["process"]["reportedDirectoryMatches"] = Value::Null;
        assert!(parse(&value, &limited).process.is_some());
        assert!(parse(&value, &input()).process.is_none());
        value["process"]["reportedDirectoryMatches"] = json!(false);
        value["process"]["dataDirectory"] = json!("/srv/another");
        assert!(parse(&value, &input()).process.is_some());
    }
    #[test]
    fn rejects_partial_foreign_and_unbounded_observations_without_echoing_process_text() {
        for (key, replacement) in [
            ("backendPid", json!(43)),
            ("postmasterPid", json!(42)),
            ("socketInode", json!("18446744073709551616")),
            ("postmasterStartTicks", json!("2001")),
            ("executablePath", json!("/bin/x\nsecret-canary")),
            ("executableSha256", json!("bad")),
            ("reportedDirectoryMatches", Value::Null),
        ] {
            let mut value = fixture();
            value["process"][key] = replacement;
            let parsed = parse(&value, &input());
            assert!(parsed.process.is_none());
            assert!(!parsed.case_identity().contains("secret-canary"));
        }
        for key in fixture()["process"].as_object().unwrap().keys() {
            let mut value = fixture();
            value["process"].as_object_mut().unwrap().remove(key);
            assert!(parse(&value, &input()).process.is_none());
        }
        let mut value = fixture();
        value["process"]["command"] = json!("untrusted");
        assert!(parse(&value, &input()).process.is_none());
        value = fixture();
        value["reason"] = json!("permission-denied");
        assert!(parse(&value, &input()).process.is_none());
        let refused = json!({"state":"unavailable","reason":"permission-denied","process":null});
        assert_eq!(
            parse(&refused, &input()).reason,
            Some(ProcessUnavailableReason::PermissionDenied)
        );
        assert_eq!(
            PostgresqlHostInspection::parse(Zeroizing::new(vec![b' '; MAX_OUTPUT + 1]), &input())
                .reason,
            Some(ProcessUnavailableReason::InvalidOutput)
        );
    }
}
