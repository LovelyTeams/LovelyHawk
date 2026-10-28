//! Versioned target capability probing without distro assumptions.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::domain::CommandRunner;
use crate::{CoreError, CoreResult};

pub const CAPABILITY_PROBE_SCHEMA: &str = "lovelyres-target-capabilities/v1";
pub const SSH_COMPATIBILITY_CONTRACT_SCHEMA: &str = "lovelyres-ssh-compatibility/v1";

/// Release-gate contract for the heterogeneous Linux endpoints LovelyHawk must support.
///
/// This is an inventory, not proof that a laboratory run occurred. The ignored real-VM
/// tests and append-only release evidence remain responsible for proving each cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SshCompatibilityContract {
    pub schema: &'static str,
    pub server_families: &'static [&'static str],
    pub linux_families: &'static [&'static str],
    pub authentication: &'static [&'static str],
    pub fault_contracts: &'static [&'static str],
}

pub const SSH_COMPATIBILITY_CONTRACT: SshCompatibilityContract = SshCompatibilityContract {
    schema: SSH_COMPATIBILITY_CONTRACT_SCHEMA,
    server_families: &[
        "OpenSSH 7.x",
        "OpenSSH 8.x",
        "OpenSSH 9.x",
        "OpenSSH 10.x",
        "Dropbear",
    ],
    linux_families: &[
        "Ubuntu",
        "Debian",
        "Rocky Linux",
        "Alpine Linux",
        "openEuler",
        "Anolis OS",
        "openSUSE",
    ],
    authentication: &[
        "password",
        "public-key",
        "ecdsa-key",
        "certificate",
        "keyboard-interactive",
        "agent",
        "rsa-agent",
        "jump-host",
        "rsa-private-key",
        "rsa-certificate",
    ],
    fault_contracts: &[
        "raw-ipv6",
        "high-latency",
        "disconnect",
        "no-sftp",
        "no-pty",
        "host-key-change",
        "restricted-account",
    ],
};

/// Constant POSIX-sh probe. No target-controlled value is interpolated.
pub const CAPABILITY_PROBE_SCRIPT: &str = r#"
set +e
lr_value() { printf '%s' "$1" | tr '\r\n\t' '   ' | head -c 512; }
lr_os_value() {
  key="$1"
  if [ -r /etc/os-release ]; then
    value=$(sed -n "s/^${key}=//p" /etc/os-release 2>/dev/null | head -n 1)
    value=${value#\"}; value=${value%\"}; value=${value#\'}; value=${value%\'}
    lr_value "$value"
  fi
}
printf 'schema\t%s\n' 'lovelyres-target-capabilities/v1'
printf 'os_id\t%s\n' "$(lr_os_value ID)"
printf 'os_id_like\t%s\n' "$(lr_os_value ID_LIKE)"
printf 'os_version\t%s\n' "$(lr_os_value VERSION_ID)"
printf 'pretty_name\t%s\n' "$(lr_os_value PRETTY_NAME)"
printf 'kernel\t%s\n' "$(uname -srmo 2>/dev/null | head -c 512)"
printf 'shell\t%s\n' "$(lr_value "${SHELL:-unknown}")"
printf 'uid\t%s\n' "$(id -u 2>/dev/null || printf unknown)"
if [ -d /proc ] && [ -r /proc/1/status ]; then printf 'procfs\t1\n'; else printf 'procfs\t0\n'; fi
if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then printf 'sudo_non_interactive\t1\n'; else printf 'sudo_non_interactive\t0\n'; fi
if command -v doas >/dev/null 2>&1 && doas -n true >/dev/null 2>&1; then printf 'doas_non_interactive\t1\n'; else printf 'doas_non_interactive\t0\n'; fi
for tool in sh bash ash zsh busybox systemctl service rc-service journalctl dmesg ps ss netstat ip ifconfig lsof find grep sed awk sha256sum shasum stat timeout tcpdump dumpcap nft iptables firewall-cmd docker podman kubectl crictl ctr apt apt-get yum dnf rpm dpkg apk pacman zypper sudo doas; do
  if command -v "$tool" >/dev/null 2>&1; then printf 'tool:%s\t1\n' "$tool"; else printf 'tool:%s\t0\n' "$tool"; fi
done
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then printf 'init_system\tsystemd\n'
elif command -v rc-service >/dev/null 2>&1; then printf 'init_system\topenrc\n'
elif [ -x /sbin/init ]; then printf 'init_system\tsysvinit\n'
else printf 'init_system\tunknown\n'; fi
exit 0
"#;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TargetCapabilities {
    pub schema: String,
    pub os_id: String,
    pub os_id_like: String,
    pub os_version: String,
    pub pretty_name: String,
    pub kernel: String,
    pub shell: String,
    pub uid: Option<u32>,
    pub is_root: bool,
    pub sudo_non_interactive: bool,
    pub doas_non_interactive: bool,
    pub procfs: bool,
    pub exec: bool,
    pub sftp: bool,
    pub pty: bool,
    pub init_system: String,
    pub tools: BTreeMap<String, bool>,
    pub probe_error: Option<String>,
    pub probed_at: chrono::DateTime<chrono::Utc>,
}

impl Default for TargetCapabilities {
    fn default() -> Self {
        Self {
            schema: CAPABILITY_PROBE_SCHEMA.to_owned(),
            os_id: "unknown".to_owned(),
            os_id_like: String::new(),
            os_version: String::new(),
            pretty_name: "Unknown Linux".to_owned(),
            kernel: String::new(),
            shell: "unknown".to_owned(),
            uid: None,
            is_root: false,
            sudo_non_interactive: false,
            doas_non_interactive: false,
            procfs: false,
            exec: false,
            sftp: false,
            pty: false,
            init_system: "unknown".to_owned(),
            tools: BTreeMap::new(),
            probe_error: None,
            probed_at: chrono::Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FeatureCapability {
    pub feature: String,
    pub available: bool,
    pub reason: Option<String>,
    pub alternative: Option<String>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SshCompatibilityService;

impl SshCompatibilityService {
    pub fn probe(&self, runner: &dyn CommandRunner) -> CoreResult<TargetCapabilities> {
        let output = runner.run(CAPABILITY_PROBE_SCRIPT)?;
        let stdout = output.into_stdout("target capability probe")?;
        parse_capability_probe(&stdout)
    }
}

pub fn parse_capability_probe(output: &str) -> CoreResult<TargetCapabilities> {
    let mut result = TargetCapabilities::default();
    let mut observed_schema = None;
    for line in output.lines().take(256) {
        let Some((key, value)) = line.split_once('\t') else {
            continue;
        };
        let value = value.trim().chars().take(512).collect::<String>();
        match key {
            "schema" => observed_schema = Some(value),
            "os_id" => result.os_id = value,
            "os_id_like" => result.os_id_like = value,
            "os_version" => result.os_version = value,
            "pretty_name" => result.pretty_name = value,
            "kernel" => result.kernel = value,
            "shell" => result.shell = value,
            "uid" => result.uid = value.parse::<u32>().ok(),
            "procfs" => result.procfs = value == "1",
            "sudo_non_interactive" => result.sudo_non_interactive = value == "1",
            "doas_non_interactive" => result.doas_non_interactive = value == "1",
            "init_system" => result.init_system = value,
            _ if key.starts_with("tool:") => {
                let tool = key.trim_start_matches("tool:");
                if !tool.is_empty()
                    && tool.len() <= 64
                    && tool.chars().all(|character| {
                        character.is_ascii_alphanumeric() || "-_.".contains(character)
                    })
                {
                    result.tools.insert(tool.to_owned(), value == "1");
                }
            }
            _ => {}
        }
    }
    if observed_schema.as_deref() != Some(CAPABILITY_PROBE_SCHEMA) {
        return Err(CoreError::validation(
            "capability probe",
            "target returned an unknown or missing schema",
        ));
    }
    result.schema = CAPABILITY_PROBE_SCHEMA.to_owned();
    result.is_root = result.uid == Some(0);
    result.exec = true;
    Ok(result)
}

impl TargetCapabilities {
    pub fn has_tool(&self, name: &str) -> bool {
        self.tools.get(name).copied().unwrap_or(false)
    }

    pub fn evaluate_feature(&self, feature: &str) -> FeatureCapability {
        let (available, reason, alternative) = match feature {
            "terminal" => (
                self.exec && self.pty,
                "target does not accept a PTY",
                "use non-interactive emergency commands",
            ),
            "sftp" => (
                self.sftp,
                "target has no SFTP subsystem",
                "use escaped commands for small files",
            ),
            "system-info" => (
                self.procfs && self.has_tool("ps"),
                "target lacks readable /proc or ps",
                "use uname, id, and file checks",
            ),
            "log-analysis" => (
                self.has_tool("journalctl") || self.has_tool("find"),
                "target lacks journalctl and log discovery tools",
                "read a known log path manually",
            ),
            "packet-capture" => (
                self.has_tool("tcpdump") || self.has_tool("dumpcap"),
                "target lacks tcpdump/dumpcap",
                "collect an ss/netstat snapshot",
            ),
            "firewall" => (
                self.has_tool("nft") || self.has_tool("iptables") || self.has_tool("firewall-cmd"),
                "target lacks a supported firewall frontend",
                "generate isolation guidance only",
            ),
            "docker" => (
                self.has_tool("docker") || self.has_tool("podman"),
                "target lacks Docker/Podman",
                "continue host investigation",
            ),
            "kubernetes" => (
                self.has_tool("kubectl") || self.has_tool("crictl") || self.has_tool("ctr"),
                "target lacks Kubernetes/CRI tools",
                "mark Kubernetes checks N/A",
            ),
            "baseline-mutation" => (
                self.is_root || self.sudo_non_interactive || self.doas_non_interactive,
                "account has no non-interactive privilege escalation",
                "run read-only checks and export commands",
            ),
            _ => (
                self.exec,
                "target cannot execute commands",
                "retain connection metadata only",
            ),
        };
        FeatureCapability {
            feature: feature.to_owned(),
            available,
            reason: (!available).then(|| reason.to_owned()),
            alternative: (!available).then(|| alternative.to_owned()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_versioned_probe_and_feature_fallbacks() {
        let output = concat!(
            "schema\tlovelyres-target-capabilities/v1\n",
            "os_id\talpine\n",
            "os_version\t3.20\n",
            "pretty_name\tAlpine Linux 3.20\n",
            "shell\t/bin/ash\n",
            "uid\t1000\n",
            "procfs\t1\n",
            "init_system\topenrc\n",
            "tool:ps\t1\n",
            "tool:tcpdump\t0\n",
            "tool:ss\t1\n",
        );
        let mut capabilities = parse_capability_probe(output).unwrap();
        capabilities.sftp = true;
        capabilities.pty = true;
        assert_eq!(capabilities.os_id, "alpine");
        assert!(capabilities.evaluate_feature("terminal").available);
        assert!(!capabilities.evaluate_feature("packet-capture").available);
    }

    #[test]
    fn rejects_unversioned_and_attacker_shaped_tool_names() {
        assert!(parse_capability_probe("os_id\tubuntu\n").is_err());
        let capabilities = parse_capability_probe(concat!(
            "schema\tlovelyres-target-capabilities/v1\n",
            "tool:ok\t1\n",
            "tool:../../bad\t1\n",
        ))
        .unwrap();
        assert_eq!(capabilities.tools.get("ok"), Some(&true));
        assert!(!capabilities.tools.contains_key("../../bad"));
    }

    #[test]
    fn compatibility_contract_keeps_openssh_seven_through_ten_and_dropbear() {
        assert_eq!(
            SSH_COMPATIBILITY_CONTRACT.schema,
            SSH_COMPATIBILITY_CONTRACT_SCHEMA
        );
        for required in [
            "OpenSSH 7.x",
            "OpenSSH 8.x",
            "OpenSSH 9.x",
            "OpenSSH 10.x",
            "Dropbear",
        ] {
            assert!(
                SSH_COMPATIBILITY_CONTRACT
                    .server_families
                    .contains(&required),
                "missing server family {required}"
            );
        }
    }

    #[test]
    fn compatibility_contract_keeps_required_linux_families() {
        for required in [
            "Ubuntu",
            "Debian",
            "Rocky Linux",
            "Alpine Linux",
            "openEuler",
            "Anolis OS",
            "openSUSE",
        ] {
            assert!(
                SSH_COMPATIBILITY_CONTRACT
                    .linux_families
                    .contains(&required),
                "missing Linux family {required}"
            );
        }
    }

    #[test]
    fn compatibility_contract_keeps_advanced_authentication_and_faults() {
        for required in [
            "keyboard-interactive",
            "agent",
            "rsa-agent",
            "jump-host",
            "rsa-private-key",
            "rsa-certificate",
        ] {
            assert!(
                SSH_COMPATIBILITY_CONTRACT
                    .authentication
                    .contains(&required),
                "missing authentication contract {required}"
            );
        }
        for required in [
            "raw-ipv6",
            "high-latency",
            "disconnect",
            "no-sftp",
            "no-pty",
            "host-key-change",
            "restricted-account",
        ] {
            assert!(
                SSH_COMPATIBILITY_CONTRACT
                    .fault_contracts
                    .contains(&required),
                "missing fault contract {required}"
            );
        }
    }
}
