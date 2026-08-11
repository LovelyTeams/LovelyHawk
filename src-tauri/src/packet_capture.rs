use serde::{Deserialize, Serialize};

// 统一实现见 crate::shell_escape —— 此前本函数在 6 个文件里各存一份复制
use crate::shell_escape::shq as shell_quote;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketEntry {
    pub id: usize,
    pub timestamp: String,
    pub protocol: String,
    pub src: String,
    pub dst: String,
    pub length: String,
    pub info: String,
    pub raw: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub index: u32,
    pub mac: Option<String>,
    pub ips: Vec<String>,
}

pub const MAX_PCAP_CAPTURE_SECONDS: u32 = 300;
pub const MAX_PCAP_PACKET_COUNT: u32 = 100_000;
const PCAP_RESULT_MARKER: &str = "LOVELYRES_PCAP_V1";
const PCAP_REMOTE_PREFIX: &str = "/tmp/lovelyres-pcap-";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PcapEvidenceReceipt {
    pub cancelled: bool,
    pub local_path: Option<String>,
    pub sha256: Option<String>,
    pub size_bytes: Option<u64>,
    pub interface: String,
    pub filter: Option<String>,
    pub packet_limit: Option<u32>,
    pub duration_seconds: u32,
    pub captured_at: String,
    pub remote_cleanup_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemotePcapMetadata {
    pub size_bytes: u64,
    pub sha256: String,
}

fn validate_interface(interface: &str) -> Result<(), String> {
    if interface.is_empty()
        || interface.len() > 64
        || !interface
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:@-".contains(&byte))
    {
        return Err("网络接口名称格式无效".to_string());
    }
    Ok(())
}

fn validate_filter(filter: Option<&str>) -> Result<Option<String>, String> {
    let Some(filter) = filter.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if filter.len() > 2048 || filter.contains(['\0', '\n', '\r']) {
        return Err("BPF 过滤器过长或包含非法控制字符".to_string());
    }
    Ok(Some(filter.to_string()))
}

pub fn new_remote_pcap_path() -> String {
    format!("{}{}.pcap", PCAP_REMOTE_PREFIX, uuid::Uuid::new_v4())
}

pub fn is_managed_remote_pcap_path(path: &str) -> bool {
    let Some(id) = path
        .strip_prefix(PCAP_REMOTE_PREFIX)
        .and_then(|value| value.strip_suffix(".pcap"))
    else {
        return false;
    };
    uuid::Uuid::parse_str(id).is_ok()
}

pub fn generate_pcap_evidence_command(
    interface: &str,
    filter: Option<&str>,
    packet_limit: Option<u32>,
    duration_seconds: u32,
    remote_path: &str,
) -> Result<String, String> {
    validate_interface(interface)?;
    let filter = validate_filter(filter)?;
    if !(1..=MAX_PCAP_CAPTURE_SECONDS).contains(&duration_seconds) {
        return Err(format!("抓包时长必须为 1–{} 秒", MAX_PCAP_CAPTURE_SECONDS));
    }
    if packet_limit.is_some_and(|count| count == 0 || count > MAX_PCAP_PACKET_COUNT) {
        return Err(format!("抓包数量上限必须为 1–{}", MAX_PCAP_PACKET_COUNT));
    }
    if !is_managed_remote_pcap_path(remote_path) {
        return Err("远端 PCAP 路径不属于 LovelyRes 受管命名空间".to_string());
    }

    let remote = shell_quote(remote_path);
    let count_arg = packet_limit
        .map(|count| format!(" -c {}", count))
        .unwrap_or_default();
    let filter_arg = filter
        .as_deref()
        .map(|value| format!(" {}", shell_quote(value)))
        .unwrap_or_default();

    Ok(format!(
        "set -u\n\
umask 077\n\
command -v tcpdump >/dev/null 2>&1 || {{ echo 'tcpdump 不可用' >&2; exit 127; }}\n\
command -v timeout >/dev/null 2>&1 || {{ echo 'timeout 不可用' >&2; exit 127; }}\n\
command -v sha256sum >/dev/null 2>&1 || {{ echo 'sha256sum 不可用' >&2; exit 127; }}\n\
pcap_runner='tcpdump'\n\
pcap_needs_chown=0\n\
if [ \"$(id -u)\" -ne 0 ]; then\n\
  command -v sudo >/dev/null 2>&1 || {{ echo '当前账号无抓包权限且 sudo 不可用' >&2; exit 126; }}\n\
  sudo -n true >/dev/null 2>&1 || {{ echo '原始抓包需要 root 或免密 sudo' >&2; exit 126; }}\n\
  pcap_runner='sudo -n tcpdump'\n\
  pcap_needs_chown=1\n\
fi\n\
rm -f -- {remote}\n\
capture_rc=0\n\
timeout --signal=INT --kill-after=5s {duration_seconds}s $pcap_runner -nn -U -i {interface}{count_arg} -w {remote}{filter_arg} >/dev/null 2>&1 || capture_rc=$?\n\
case \"$capture_rc\" in\n\
  0|124|130) ;;\n\
  *) if [ \"$pcap_needs_chown\" -eq 1 ]; then sudo -n rm -f -- {remote}; else rm -f -- {remote}; fi; exit \"$capture_rc\" ;;\n\
esac\n\
if [ \"$pcap_needs_chown\" -eq 1 ]; then sudo -n chown -- \"$(id -u):$(id -g)\" {remote}; fi\n\
test -s {remote} || {{ rm -f -- {remote}; echo '未生成 PCAP 数据' >&2; exit 1; }}\n\
pcap_size=$(wc -c < {remote})\n\
pcap_hash=$(sha256sum {remote} | awk '{{print $1}}')\n\
printf '{marker}\\t%s\\t%s\\n' \"$pcap_size\" \"$pcap_hash\"",
        remote = remote,
        duration_seconds = duration_seconds,
        interface = shell_quote(interface),
        count_arg = count_arg,
        filter_arg = filter_arg,
        marker = PCAP_RESULT_MARKER,
    ))
}

pub fn parse_pcap_evidence_output(output: &str) -> Result<RemotePcapMetadata, String> {
    let line = output
        .lines()
        .rev()
        .find(|line| line.starts_with(PCAP_RESULT_MARKER))
        .ok_or_else(|| "抓包结果缺少可验证元数据".to_string())?;
    let mut parts = line.split('\t');
    if parts.next() != Some(PCAP_RESULT_MARKER) {
        return Err("抓包元数据版本无效".to_string());
    }
    let size_bytes = parts
        .next()
        .ok_or_else(|| "抓包元数据缺少文件大小".to_string())?
        .parse::<u64>()
        .map_err(|_| "抓包文件大小格式无效".to_string())?;
    let sha256 = parts
        .next()
        .map(str::trim)
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| "抓包 SHA-256 格式无效".to_string())?
        .to_ascii_lowercase();
    if parts.next().is_some() {
        return Err("抓包元数据字段数量无效".to_string());
    }
    Ok(RemotePcapMetadata { size_bytes, sha256 })
}

/// 从端口号推断应用层协议
fn infer_protocol_from_port(addr: &str) -> Option<&'static str> {
    // tcpdump 格式: 192.168.1.1.80 或 192.168.1.1.443
    if let Some(pos) = addr.rfind('.') {
        if let Ok(port) = addr[pos + 1..].parse::<u16>() {
            return match port {
                80 | 8080 | 8000 | 8888 => Some("HTTP"),
                443 | 8443 => Some("HTTPS"),
                53 => Some("DNS"),
                22 => Some("SSH"),
                21 => Some("FTP"),
                25 | 465 | 587 => Some("SMTP"),
                110 | 995 => Some("POP3"),
                143 | 993 => Some("IMAP"),
                3306 => Some("MySQL"),
                5432 => Some("PgSQL"),
                6379 => Some("Redis"),
                27017 => Some("MongoDB"),
                _ => None,
            };
        }
    }
    None
}

/// 从 info 字段提取 length
fn extract_length(info: &str) -> String {
    // 匹配 "length N" 或 "len N"
    for word_pair in info.split_whitespace().collect::<Vec<&str>>().windows(2) {
        if word_pair[0] == "length" || word_pair[0] == "len" {
            if let Some(num_str) = word_pair[1].strip_suffix(',').or(Some(word_pair[1])) {
                if num_str.parse::<u64>().is_ok() {
                    return num_str.to_string();
                }
            }
        }
    }
    String::new()
}

/// 解析 tcpdump 输出行（支持 -tttt -v 格式）
pub fn parse_tcpdump_line(line: &str, id: usize) -> PacketEntry {
    let parts: Vec<&str> = line.split_whitespace().collect();

    let mut entry = PacketEntry {
        id,
        timestamp: String::new(),
        protocol: "OTHER".to_string(),
        src: String::new(),
        dst: String::new(),
        length: String::new(),
        info: line.to_string(),
        raw: line.to_string(),
    };

    if parts.len() < 4 {
        return entry;
    }

    // 检测 -tttt 格式: "2024-01-15 19:43:01.123456 IP ..."
    // 或普通格式: "19:43:01.123456 IP ..."
    let (ts, offset) = if parts[0].contains('-') && parts.len() > 1 && parts[1].contains(':') {
        // -tttt 格式
        (format!("{} {}", parts[0], parts[1]), 2)
    } else {
        (parts[0].to_string(), 1)
    };
    entry.timestamp = ts;

    if parts.len() <= offset {
        return entry;
    }

    let proto_token = parts[offset];

    if proto_token == "IP" || proto_token == "IP6" {
        entry.protocol = proto_token.to_string();

        // 找 ">" 分隔 src > dst
        if let Some(arrow_idx) = parts[offset..].iter().position(|&x| x == ">") {
            let abs_arrow = offset + arrow_idx;

            // Source
            if abs_arrow > offset + 1 {
                entry.src = parts[offset + 1..abs_arrow].join(" ");
            }

            // Destination (去掉末尾冒号)
            if abs_arrow + 1 < parts.len() {
                entry.dst = parts[abs_arrow + 1].trim_end_matches(':').to_string();

                // Info
                let info_start = abs_arrow + 2;
                if info_start < parts.len() {
                    entry.info = parts[info_start..].join(" ");
                }
            }

            // 从端口推断应用层协议
            if let Some(app_proto) = infer_protocol_from_port(&entry.src)
                .or_else(|| infer_protocol_from_port(&entry.dst))
            {
                entry.protocol = app_proto.to_string();
            }
        }
    } else if proto_token.starts_with("ARP") || proto_token == "ARP," {
        entry.protocol = "ARP".to_string();
        entry.info = parts[offset..].join(" ");
    } else {
        entry.protocol = proto_token.trim_end_matches(',').to_string();
        entry.info = parts[offset..].join(" ");
    }

    // 提取 length
    entry.length = extract_length(&entry.info);

    entry
}

/// 生成 tcpdump 命令（增强版: -tttt 完整时间戳, -v 获取 length）
pub fn generate_tcpdump_command(
    interface: &str,
    filter: Option<&str>,
    count: Option<u32>,
) -> String {
    let mut cmd = format!("tcpdump -nne -l -tttt -v -i {}", shell_quote(interface));

    if let Some(c) = count {
        cmd.push_str(&format!(" -c {}", c));
    }

    if let Some(f) = filter {
        if !f.trim().is_empty() {
            cmd.push_str(&format!(" {}", shell_quote(f)));
        }
    }

    cmd
}

/// 生成获取网络接口的命令
pub fn generate_list_interfaces_command() -> String {
    "ip -o -4 addr show | awk '{print $2, $4}'".to_string()
}

#[cfg(test)]
mod command_tests {
    use super::*;

    #[test]
    fn tcpdump_arguments_are_shell_quoted() {
        let command = generate_tcpdump_command("eth0; id", Some("tcp'; id; echo '"), Some(5));
        assert!(command.contains("-i 'eth0; id'"));
        assert!(command.contains("'tcp'\\''; id; echo '\\'''"));
    }

    #[test]
    fn pcap_evidence_command_is_bounded_and_shell_quoted() {
        let path = "/tmp/lovelyres-pcap-123e4567-e89b-12d3-a456-426614174000.pcap";
        let command =
            generate_pcap_evidence_command("eth0", Some("tcp port 443; id"), Some(500), 15, path)
                .expect("valid evidence command");
        assert!(command.contains("timeout --signal=INT --kill-after=5s 15s"));
        assert!(command.contains("sudo -n true"));
        assert!(command.contains("-c 500"));
        assert!(command.contains("'tcp port 443; id'"));
        assert!(command.contains("LOVELYRES_PCAP_V1"));
        assert!(!command.contains("tcp port 443; id >/dev/null"));
    }

    #[test]
    fn pcap_evidence_rejects_unmanaged_paths_and_unbounded_inputs() {
        assert!(generate_pcap_evidence_command(
            "eth0; id",
            None,
            None,
            10,
            &new_remote_pcap_path()
        )
        .is_err());
        assert!(generate_pcap_evidence_command(
            "eth0",
            None,
            Some(MAX_PCAP_PACKET_COUNT + 1),
            10,
            &new_remote_pcap_path()
        )
        .is_err());
        assert!(generate_pcap_evidence_command(
            "eth0",
            None,
            None,
            MAX_PCAP_CAPTURE_SECONDS + 1,
            &new_remote_pcap_path()
        )
        .is_err());
        assert!(
            generate_pcap_evidence_command("eth0", None, None, 10, "/tmp/user-chosen.pcap")
                .is_err()
        );
    }

    #[test]
    fn pcap_evidence_metadata_requires_exact_marker_and_sha256() {
        let hash = "ab".repeat(32);
        let parsed =
            parse_pcap_evidence_output(&format!("noise\n{}\t24\t{}\n", PCAP_RESULT_MARKER, hash))
                .expect("valid marker");
        assert_eq!(parsed.size_bytes, 24);
        assert_eq!(parsed.sha256, hash);
        assert!(parse_pcap_evidence_output("LOVELYRES_PCAP_V1\t24\tnot-a-hash").is_err());
    }
}
