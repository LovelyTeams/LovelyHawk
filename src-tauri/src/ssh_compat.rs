use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const CAPABILITY_PROBE_SCHEMA: &str = "lovelyres-target-capabilities/v1";

/// Constant, POSIX-sh compatible probe. It never interpolates target-controlled data.
/// Missing commands are reported as capabilities instead of failing the connection.
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
            schema: CAPABILITY_PROBE_SCHEMA.to_string(),
            os_id: "unknown".to_string(),
            os_id_like: String::new(),
            os_version: String::new(),
            pretty_name: "Unknown Linux".to_string(),
            kernel: String::new(),
            shell: "unknown".to_string(),
            uid: None,
            is_root: false,
            sudo_non_interactive: false,
            doas_non_interactive: false,
            procfs: false,
            exec: false,
            sftp: false,
            pty: false,
            init_system: "unknown".to_string(),
            tools: BTreeMap::new(),
            probe_error: None,
            probed_at: chrono::Utc::now(),
        }
    }
}

fn parse_bool(value: &str) -> bool {
    value.trim() == "1"
}

pub fn parse_capability_probe(output: &str) -> Result<TargetCapabilities, String> {
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
            "procfs" => result.procfs = parse_bool(&value),
            "sudo_non_interactive" => result.sudo_non_interactive = parse_bool(&value),
            "doas_non_interactive" => result.doas_non_interactive = parse_bool(&value),
            "init_system" => result.init_system = value,
            _ if key.starts_with("tool:") => {
                let tool = key.trim_start_matches("tool:");
                if !tool.is_empty()
                    && tool.len() <= 64
                    && tool
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
                {
                    result.tools.insert(tool.to_string(), parse_bool(&value));
                }
            }
            _ => {}
        }
    }

    if observed_schema.as_deref() != Some(CAPABILITY_PROBE_SCHEMA) {
        return Err("目标能力探测返回了未知格式".to_string());
    }
    result.schema = CAPABILITY_PROBE_SCHEMA.to_string();
    result.is_root = result.uid == Some(0);
    result.exec = true;
    Ok(result)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FeatureCapability {
    pub feature: String,
    pub available: bool,
    pub reason: Option<String>,
    pub alternative: Option<String>,
}

impl TargetCapabilities {
    fn has_tool(&self, name: &str) -> bool {
        self.tools.get(name).copied().unwrap_or(false)
    }

    pub fn evaluate_feature(&self, feature: &str) -> FeatureCapability {
        let (available, reason, alternative) = match feature {
            "terminal" => (
                self.exec && self.pty,
                "目标不接受 PTY，会话只能使用非交互命令",
                "使用应急命令页的非交互执行",
            ),
            "sftp" => (
                self.sftp,
                "目标未启用 SFTP subsystem",
                "使用经过转义的 cat/base64 命令传输小文件",
            ),
            "system-info" => (
                self.procfs && self.has_tool("ps"),
                "目标缺少可读 /proc 或 ps",
                "使用通用 uname、id 和文件核查命令",
            ),
            "log-analysis" => (
                self.has_tool("journalctl") || self.has_tool("find"),
                "目标没有 journalctl，也缺少通用日志发现工具",
                "在应急命令页手动读取已知日志路径",
            ),
            "packet-capture" => (
                self.has_tool("tcpdump") || self.has_tool("dumpcap"),
                "目标没有 tcpdump/dumpcap",
                "使用 ss/netstat 收集连接快照",
            ),
            "firewall" => (
                self.has_tool("nft") || self.has_tool("iptables") || self.has_tool("firewall-cmd"),
                "目标未检测到受支持的防火墙前端",
                "仅生成隔离建议，不自动下发规则",
            ),
            "docker" => (
                self.has_tool("docker") || self.has_tool("podman"),
                "目标未检测到 Docker/Podman",
                "跳过容器处置，继续宿主机调查",
            ),
            "kubernetes" => (
                self.has_tool("kubectl") || self.has_tool("crictl") || self.has_tool("ctr"),
                "目标未检测到 Kubernetes/CRI 工具",
                "将 Kubernetes 检测标记为 N/A",
            ),
            "baseline-mutation" => (
                self.is_root || self.sudo_non_interactive || self.doas_non_interactive,
                "当前账户没有可用的非交互提权能力",
                "只运行只读核查并导出处置命令",
            ),
            _ => (self.exec, "目标不支持远程命令执行", "仅保留连接信息"),
        };

        FeatureCapability {
            feature: feature.to_string(),
            available,
            reason: (!available).then(|| reason.to_string()),
            alternative: (!available).then(|| alternative.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_capabilities_and_derives_feature_fallbacks() {
        let output = concat!(
            "schema\tlovelyres-target-capabilities/v1\n",
            "os_id\talpine\n",
            "os_version\t3.20\n",
            "pretty_name\tAlpine Linux 3.20\n",
            "shell\t/bin/ash\n",
            "uid\t1000\n",
            "procfs\t1\n",
            "sudo_non_interactive\t0\n",
            "doas_non_interactive\t0\n",
            "init_system\topenrc\n",
            "tool:ps\t1\n",
            "tool:tcpdump\t0\n",
            "tool:ss\t1\n",
        );
        let mut capabilities = parse_capability_probe(output).expect("valid probe");
        capabilities.sftp = true;
        capabilities.pty = true;

        assert_eq!(capabilities.os_id, "alpine");
        assert!(capabilities.evaluate_feature("terminal").available);
        let pcap = capabilities.evaluate_feature("packet-capture");
        assert!(!pcap.available);
        assert!(pcap
            .alternative
            .as_deref()
            .unwrap_or_default()
            .contains("ss/netstat"));
    }

    #[test]
    fn rejects_unversioned_or_attacker_controlled_output() {
        assert!(parse_capability_probe("os_id\tubuntu\n").is_err());
        let output = concat!(
            "schema\tlovelyres-target-capabilities/v1\n",
            "tool:ok\t1\n",
            "tool:../../bad\t1\n",
        );
        let capabilities = parse_capability_probe(output).expect("known schema");
        assert_eq!(capabilities.tools.get("ok"), Some(&true));
        assert!(!capabilities.tools.contains_key("../../bad"));
    }
}
