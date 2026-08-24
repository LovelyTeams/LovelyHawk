//! Closed, target-bound emergency command catalog.
//!
//! The native UI executes catalog identifiers, never caller supplied shell text.
//! This first slice intentionally contains read-only collection commands only.

use std::{sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};

use crate::{
    CoreError, CoreResult,
    investigation::{AddCommandHistory, CommandHistoryRepository},
    ssh::{BoundSshSession, SshCommandOutput, SshService},
    target::TargetContext,
};

const SYSTEM_PROBE: &str = "if [ -r /etc/os-release ]; then . /etc/os-release; printf '%s|%s\\n' \"${ID:-unknown}\" \"${ID_LIKE:-}\"; else printf 'unknown|\\n'; fi";
const MAX_COMMAND_OUTPUT_BYTES: usize = 2 * 1024 * 1024;
const DEFAULT_TIMEOUT_SECONDS: u64 = 30;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SystemFamily {
    Debian,
    RedHat,
    Alpine,
    Suse,
    Arch,
    Other,
}

impl SystemFamily {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Debian => "Debian 系",
            Self::RedHat => "Red Hat 系",
            Self::Alpine => "Alpine",
            Self::Suse => "SUSE 系",
            Self::Arch => "Arch 系",
            Self::Other => "通用 Linux",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CommandCategory {
    Permissions,
    Accounts,
    Network,
    Processes,
    Persistence,
    Logs,
    Files,
    Containers,
    System,
}

impl CommandCategory {
    pub const ALL: [Self; 9] = [
        Self::Permissions,
        Self::Accounts,
        Self::Network,
        Self::Processes,
        Self::Persistence,
        Self::Logs,
        Self::Files,
        Self::Containers,
        Self::System,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Permissions => "权限安全",
            Self::Accounts => "账户与认证",
            Self::Network => "网络排查",
            Self::Processes => "进程与内存",
            Self::Persistence => "持久化检查",
            Self::Logs => "日志线索",
            Self::Files => "文件线索",
            Self::Containers => "容器环境",
            Self::System => "系统状态",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandCatalogEntry {
    pub id: &'static str,
    pub category: CommandCategory,
    pub title: &'static str,
    pub description: &'static str,
    pub command_preview: &'static str,
    pub timeout_seconds: u64,
}

#[derive(Clone, Copy, Debug)]
struct CommandDefinition {
    entry: CommandCatalogEntry,
    default_command: &'static str,
    debian_command: Option<&'static str>,
    redhat_command: Option<&'static str>,
    alpine_command: Option<&'static str>,
}

#[derive(Clone, Copy, Debug)]
struct FamilyCommands {
    default: &'static str,
    debian: Option<&'static str>,
    redhat: Option<&'static str>,
    alpine: Option<&'static str>,
}

impl CommandDefinition {
    const fn portable(
        id: &'static str,
        category: CommandCategory,
        title: &'static str,
        description: &'static str,
        command: &'static str,
    ) -> Self {
        Self {
            entry: CommandCatalogEntry {
                id,
                category,
                title,
                description,
                command_preview: command,
                timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            },
            default_command: command,
            debian_command: None,
            redhat_command: None,
            alpine_command: None,
        }
    }

    const fn adapted(
        id: &'static str,
        category: CommandCategory,
        title: &'static str,
        description: &'static str,
        commands: FamilyCommands,
    ) -> Self {
        Self {
            entry: CommandCatalogEntry {
                id,
                category,
                title,
                description,
                command_preview: commands.default,
                timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            },
            default_command: commands.default,
            debian_command: commands.debian,
            redhat_command: commands.redhat,
            alpine_command: commands.alpine,
        }
    }

    fn command_for(self, family: SystemFamily) -> &'static str {
        match family {
            SystemFamily::Debian => self.debian_command,
            SystemFamily::RedHat => self.redhat_command,
            SystemFamily::Alpine => self.alpine_command,
            SystemFamily::Suse | SystemFamily::Arch | SystemFamily::Other => None,
        }
        .unwrap_or(self.default_command)
    }
}

macro_rules! portable {
    ($id:literal, $category:ident, $title:literal, $description:literal, $command:literal) => {
        CommandDefinition::portable(
            $id,
            CommandCategory::$category,
            $title,
            $description,
            $command,
        )
    };
}

static CATALOG: &[CommandDefinition] = &[
    portable!(
        "perm-suid",
        Permissions,
        "SUID 可执行",
        "列出当前文件系统内带 SUID 位的文件。",
        "find / -xdev -perm -4000 -type f 2>/dev/null | sort | head -n 300"
    ),
    portable!(
        "perm-sgid",
        Permissions,
        "SGID 可执行",
        "列出当前文件系统内带 SGID 位的文件。",
        "find / -xdev -perm -2000 -type f 2>/dev/null | sort | head -n 300"
    ),
    portable!(
        "perm-world-writable",
        Permissions,
        "全局可写文件",
        "定位可能被任意用户修改的普通文件。",
        "find / -xdev -type f -perm -0002 -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | sort | head -n 300"
    ),
    portable!(
        "perm-capabilities",
        Permissions,
        "文件 Capabilities",
        "收集 Linux 文件能力集。",
        "command -v getcap >/dev/null 2>&1 && getcap -r / 2>/dev/null | head -n 300 || echo 'getcap not available'"
    ),
    portable!(
        "account-users",
        Accounts,
        "用户与登录 Shell",
        "列出用户名、UID、GID、主目录和 Shell。",
        "getent passwd | awk -F: '{print $1 \"\\t\" $3 \"\\t\" $4 \"\\t\" $6 \"\\t\" $7}' | sort"
    ),
    portable!(
        "account-uid-zero",
        Accounts,
        "UID 0 账户",
        "检查所有拥有超级用户 UID 的账户。",
        "awk -F: '$3 == 0 {print $1 \"\\t\" $3 \"\\t\" $7}' /etc/passwd"
    ),
    portable!(
        "account-empty-password",
        Accounts,
        "空/锁定口令字段",
        "只读检查 shadow 中的空值和锁定标记；普通用户可能无权限。",
        "awk -F: '$2 == \"\" || $2 == \"!\" || $2 == \"*\" {print $1 \"\\t\" $2}' /etc/shadow 2>/dev/null | head -n 200"
    ),
    portable!(
        "account-sudoers",
        Accounts,
        "sudoers 有效配置",
        "收集非注释 sudoers 配置与片段目录。",
        "grep -vE '^[[:space:]]*(#|$)' /etc/sudoers 2>/dev/null; find /etc/sudoers.d -maxdepth 1 -type f -print 2>/dev/null | sort"
    ),
    portable!(
        "network-listen",
        Network,
        "监听端口",
        "列出 TCP/UDP 监听及其进程。",
        "ss -tulpen 2>/dev/null || netstat -tulpen 2>/dev/null || netstat -tuln 2>/dev/null || echo 'ss/netstat not available'"
    ),
    portable!(
        "network-established",
        Network,
        "活动连接",
        "列出已建立 TCP 连接及关联进程。",
        "ss -tanp 2>/dev/null | head -n 500 || netstat -tanp 2>/dev/null | head -n 500 || netstat -tan 2>/dev/null | head -n 500"
    ),
    portable!(
        "network-route",
        Network,
        "路由与策略",
        "收集路由表和策略路由。",
        "ip rule show 2>/dev/null; echo '--- routes ---'; ip route show table all 2>/dev/null || route -n 2>/dev/null"
    ),
    portable!(
        "network-firewall",
        Network,
        "防火墙规则",
        "只读收集 nftables、iptables 或 firewalld 规则。",
        "nft list ruleset 2>/dev/null || iptables-save 2>/dev/null || firewall-cmd --list-all-zones 2>/dev/null || echo 'firewall tooling not available'"
    ),
    portable!(
        "process-cpu",
        Processes,
        "CPU 占用进程",
        "按 CPU 使用率列出前 100 个进程。",
        "ps -eo pid,ppid,user,stat,pcpu,pmem,lstart,args --sort=-pcpu 2>/dev/null | head -n 101"
    ),
    portable!(
        "process-memory",
        Processes,
        "内存占用进程",
        "按内存使用率列出前 100 个进程。",
        "ps -eo pid,ppid,user,stat,pcpu,pmem,rss,vsz,args --sort=-pmem 2>/dev/null | head -n 101"
    ),
    portable!(
        "process-deleted",
        Processes,
        "已删除可执行映射",
        "定位仍由进程持有的 deleted 文件。",
        "find /proc/[0-9]*/fd -lname '* (deleted)' -exec ls -l {} + 2>/dev/null | head -n 300"
    ),
    portable!(
        "process-tree",
        Processes,
        "进程树",
        "展示进程父子关系与完整命令行。",
        "ps -eo pid,ppid,user,stat,lstart,args --forest 2>/dev/null | head -n 500"
    ),
    CommandDefinition::adapted(
        "persistence-services",
        CommandCategory::Persistence,
        "已启用服务",
        "按当前系统服务管理器列出启动项。",
        FamilyCommands {
            default: "systemctl list-unit-files --type=service --no-pager 2>/dev/null || service --status-all 2>/dev/null || find /etc/init.d -maxdepth 1 -type f -print 2>/dev/null",
            debian: Some(
                "systemctl list-unit-files --type=service --no-pager 2>/dev/null || service --status-all 2>/dev/null",
            ),
            redhat: Some(
                "systemctl list-unit-files --type=service --no-pager 2>/dev/null || chkconfig --list 2>/dev/null",
            ),
            alpine: Some(
                "rc-status -a 2>/dev/null || find /etc/init.d -maxdepth 1 -type f -print 2>/dev/null",
            ),
        },
    ),
    portable!(
        "persistence-cron",
        Persistence,
        "计划任务",
        "汇总系统 cron、anacron 与用户 crontab 文件。",
        "find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron -maxdepth 2 -type f -print 2>/dev/null | sort | head -n 500"
    ),
    portable!(
        "persistence-timers",
        Persistence,
        "systemd Timers",
        "列出所有 systemd timer。",
        "systemctl list-timers --all --no-pager 2>/dev/null || echo 'systemd timers not available'"
    ),
    portable!(
        "persistence-shell",
        Persistence,
        "Shell 启动脚本",
        "列出全局及用户 Shell 启动脚本元数据。",
        "find /etc/profile /etc/profile.d /etc/bashrc /etc/bash.bashrc /root /home -maxdepth 3 -type f \\( -name '.bashrc' -o -name '.profile' -o -name '*.sh' \\) -ls 2>/dev/null | head -n 500"
    ),
    portable!(
        "log-auth",
        Logs,
        "认证日志",
        "收集最近认证成功、失败和 sudo 线索。",
        "journalctl -n 500 --no-pager -u ssh -u sshd -t sudo 2>/dev/null || tail -n 500 /var/log/auth.log /var/log/secure 2>/dev/null"
    ),
    portable!(
        "log-errors",
        Logs,
        "系统错误",
        "收集本次启动的 error 级别日志。",
        "journalctl -b -p err..alert -n 500 --no-pager 2>/dev/null || tail -n 500 /var/log/messages /var/log/syslog 2>/dev/null"
    ),
    portable!(
        "log-kernel",
        Logs,
        "内核日志",
        "收集最近内核告警和驱动异常。",
        "journalctl -k -n 500 --no-pager 2>/dev/null || dmesg 2>/dev/null | tail -n 500"
    ),
    portable!(
        "file-recent-executable",
        Files,
        "近期可执行文件",
        "定位最近七天修改且带执行位的文件。",
        "find /tmp /var/tmp /dev/shm /usr/local/bin /opt -xdev -type f -mtime -7 -perm /111 -ls 2>/dev/null | head -n 500"
    ),
    portable!(
        "file-hidden",
        Files,
        "隐藏文件",
        "列出常见可写位置下的隐藏普通文件。",
        "find /tmp /var/tmp /dev/shm /home /root -xdev -type f -name '.*' -ls 2>/dev/null | head -n 500"
    ),
    portable!(
        "file-largest",
        Files,
        "大文件",
        "列出当前文件系统内最大的 100 个普通文件。",
        "find / -xdev -type f -size +10M -exec du -b {} + 2>/dev/null | sort -nr | head -n 100"
    ),
    portable!(
        "container-running",
        Containers,
        "运行中容器",
        "只读列出 Docker 或 Podman 容器。",
        "docker ps --no-trunc 2>/dev/null || podman ps --no-trunc 2>/dev/null || echo 'docker/podman not available'"
    ),
    portable!(
        "container-images",
        Containers,
        "容器镜像",
        "只读列出本地镜像及摘要。",
        "docker images --digests --no-trunc 2>/dev/null || podman images --digests --no-trunc 2>/dev/null || echo 'docker/podman not available'"
    ),
    portable!(
        "system-kernel",
        System,
        "系统与内核",
        "收集发行版、内核、架构和运行时间。",
        "cat /etc/os-release 2>/dev/null; echo '---'; uname -a; echo '---'; uptime"
    ),
    portable!(
        "system-resources",
        System,
        "资源使用",
        "收集 CPU、内存、文件系统和 inode 概览。",
        "nproc 2>/dev/null; free -h 2>/dev/null; echo '--- filesystems ---'; df -hT 2>/dev/null; echo '--- inodes ---'; df -hi 2>/dev/null"
    ),
    portable!(
        "system-mounts",
        System,
        "挂载与命名空间",
        "列出挂载点、文件系统和选项。",
        "findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS 2>/dev/null || mount 2>/dev/null"
    ),
    portable!(
        "system-modules",
        System,
        "内核模块",
        "列出已加载内核模块及签名状态线索。",
        "lsmod 2>/dev/null; echo '--- taint ---'; cat /proc/sys/kernel/tainted 2>/dev/null"
    ),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CommandResultKind {
    Success,
    Empty,
    NonZero,
    Timeout,
    MissingCommand,
    PermissionDenied,
    UnknownExit,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommandExecutionReceipt {
    pub command_id: String,
    pub title: String,
    pub output: String,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub timed_out: bool,
    pub kind: CommandResultKind,
    pub success: bool,
    pub message: String,
    pub truncated: bool,
    pub history_id: Option<String>,
    pub history_warning: Option<String>,
}

#[derive(Clone, Debug)]
pub struct CommandWorkbenchService {
    ssh: SshService,
    target: Arc<TargetContext>,
    history: CommandHistoryRepository,
}

impl CommandWorkbenchService {
    pub fn new(
        ssh: SshService,
        target: Arc<TargetContext>,
        history: CommandHistoryRepository,
    ) -> Self {
        Self {
            ssh,
            target,
            history,
        }
    }

    pub fn catalog(&self) -> Vec<CommandCatalogEntry> {
        CATALOG.iter().map(|definition| definition.entry).collect()
    }

    pub async fn detect_system(&self, session: &BoundSshSession) -> CoreResult<SystemFamily> {
        self.target.validate(session.target())?;
        let output = self
            .ssh
            .execute_bound(session, SYSTEM_PROBE.to_owned(), Duration::from_secs(10))
            .await?;
        self.target.validate(session.target())?;
        resolve_system_probe(&output)
    }

    pub async fn execute(
        &self,
        session: &BoundSshSession,
        command_id: &str,
        family: SystemFamily,
    ) -> CoreResult<CommandExecutionReceipt> {
        self.target.validate(session.target())?;
        let definition = lookup(command_id)?;
        let command = definition.command_for(family).to_owned();
        let output = self
            .ssh
            .execute_bound(
                session,
                command.clone(),
                Duration::from_secs(definition.entry.timeout_seconds),
            )
            .await?;
        self.target.validate(session.target())?;

        let (bounded_output, truncated) = truncate_utf8_bytes(&output.output);
        let (kind, success, message) = classify(&output, &bounded_output);
        let history = self.history.add(AddCommandHistory {
            command,
            title: definition.entry.title.to_owned(),
            output: bounded_output.clone(),
            exit_code: output.exit_code,
            target: session.target().identity.clone(),
            source: "native-command-workbench".to_owned(),
        });
        let (history_id, history_warning) = match history {
            Ok(record) => (Some(record.id), None),
            Err(error) => (None, Some(format!("命令已执行，但历史保存失败：{error}"))),
        };

        Ok(CommandExecutionReceipt {
            command_id: definition.entry.id.to_owned(),
            title: definition.entry.title.to_owned(),
            output: bounded_output,
            exit_code: output.exit_code,
            duration_ms: output.duration_ms,
            timed_out: output.timed_out,
            kind,
            success,
            message,
            truncated,
            history_id,
            history_warning,
        })
    }
}

fn lookup(command_id: &str) -> CoreResult<CommandDefinition> {
    if command_id.is_empty()
        || command_id.len() > 80
        || !command_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(CoreError::Validation {
            subject: "command catalog id",
            message: "must be 1..=80 lowercase ASCII letters, digits, or hyphens".to_owned(),
        });
    }
    CATALOG
        .iter()
        .copied()
        .find(|definition| definition.entry.id == command_id)
        .ok_or_else(|| CoreError::NotFound {
            entity: "command catalog entry",
            id: command_id.to_owned(),
        })
}

fn parse_system_family(output: &str) -> Option<SystemFamily> {
    let mut lines = output.lines();
    let first = lines.next()?.trim();
    if first.is_empty() || lines.any(|line| !line.trim().is_empty()) {
        return None;
    }
    let (id, id_like) = first.split_once('|')?;
    if id_like.contains('|')
        || !valid_os_release_id(id, false)
        || !valid_os_release_id(id_like, true)
    {
        return None;
    }
    let normalized = format!(
        "{} {}",
        id.to_ascii_lowercase(),
        id_like.to_ascii_lowercase()
    );
    let tokens = normalized.split_ascii_whitespace().collect::<Vec<_>>();
    if tokens
        .iter()
        .any(|value| matches!(*value, "debian" | "ubuntu" | "kylin" | "uos" | "deepin"))
    {
        Some(SystemFamily::Debian)
    } else if tokens.iter().any(|value| {
        matches!(
            *value,
            "rhel" | "centos" | "fedora" | "rocky" | "almalinux" | "openeuler" | "anolis"
        )
    }) {
        Some(SystemFamily::RedHat)
    } else if tokens.contains(&"alpine") {
        Some(SystemFamily::Alpine)
    } else if tokens
        .iter()
        .any(|value| matches!(*value, "suse" | "opensuse" | "sles"))
    {
        Some(SystemFamily::Suse)
    } else if tokens.contains(&"arch") {
        Some(SystemFamily::Arch)
    } else {
        Some(SystemFamily::Other)
    }
}

fn valid_os_release_id(value: &str, allow_empty: bool) -> bool {
    if value != value.trim()
        || (!allow_empty && value.bytes().any(|byte| byte.is_ascii_whitespace()))
    {
        return false;
    }
    if value.is_empty() {
        return allow_empty;
    }
    value.len() <= 256
        && value.split_ascii_whitespace().all(|token| {
            token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
}

fn resolve_system_probe(output: &SshCommandOutput) -> CoreResult<SystemFamily> {
    if output.timed_out {
        return Err(CoreError::ssh(
            "system family probe",
            "remote command timed out",
        ));
    }
    if let Some(code) = output.exit_code
        && code != 0
    {
        return Err(CoreError::ssh(
            "system family probe",
            format!("remote command exited with code {code}"),
        ));
    }
    // RFC 4254 permits servers to close an exec channel without sending the
    // optional exit-status request. The fixed probe's strictly validated output
    // is sufficient for this read-only classification; arbitrary command output
    // still treats a missing exit status as unknown failure.
    parse_system_family(&output.output).ok_or_else(|| {
        CoreError::ssh(
            "system family probe",
            "remote probe returned empty or malformed os-release data",
        )
    })
}

fn classify(output: &SshCommandOutput, bounded_output: &str) -> (CommandResultKind, bool, String) {
    let lower = bounded_output.to_ascii_lowercase();
    if output.timed_out {
        (CommandResultKind::Timeout, false, "命令执行超时".to_owned())
    } else if lower.contains("permission denied")
        || lower.contains("operation not permitted")
        || lower.contains("a password is required")
        || bounded_output.contains("权限不足")
    {
        (
            CommandResultKind::PermissionDenied,
            false,
            "权限不足或需要交互式认证".to_owned(),
        )
    } else if lower.contains("command not found")
        || lower.contains("not installed")
        || lower.contains("no such file or directory")
    {
        (
            CommandResultKind::MissingCommand,
            false,
            "目标系统缺少命令或文件".to_owned(),
        )
    } else if output.exit_code.is_some_and(|code| code != 0) {
        (
            CommandResultKind::NonZero,
            false,
            format!("命令返回非 0 退出码：{:?}", output.exit_code),
        )
    } else if output.exit_code.is_none() {
        (
            CommandResultKind::UnknownExit,
            false,
            "命令未返回退出状态，结果不可判定".to_owned(),
        )
    } else if bounded_output.trim().is_empty() {
        (
            CommandResultKind::Empty,
            true,
            "执行成功，无匹配结果".to_owned(),
        )
    } else {
        (CommandResultKind::Success, true, "执行完成".to_owned())
    }
}

fn truncate_utf8_bytes(value: &str) -> (String, bool) {
    if value.len() <= MAX_COMMAND_OUTPUT_BYTES {
        return (value.to_owned(), false);
    }
    let mut end = MAX_COMMAND_OUTPUT_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    (value[..end].to_owned(), true)
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, fs, path::PathBuf, sync::Arc};

    use chrono::Utc;
    use uuid::Uuid;

    use super::*;
    use crate::{
        BackendServices, PortableStore,
        ssh::{SshConnectionStatus, TestSessionHarness},
        target::TargetIdentity,
    };

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("lovelyres-commands-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    async fn bound_services(
        root: &TestRoot,
    ) -> (BackendServices, BoundSshSession, Arc<TestSessionHarness>) {
        let services =
            BackendServices::new(PortableStore::prepare(root.0.clone()).unwrap()).unwrap();
        let guard = services
            .activate_target(TargetIdentity::new("connection-a").unwrap())
            .unwrap();
        let status = SshConnectionStatus {
            session_id: "session-a".to_owned(),
            connection_id: "connection-a".to_owned(),
            host: "host-a.test".to_owned(),
            port: 22,
            username: "operator".to_owned(),
            host_key_fingerprint: "SHA256:test".to_owned(),
            connected_at: Utc::now(),
        };
        let session = BoundSshSession::from_status(guard, &status, "test session").unwrap();
        let harness = Arc::new(TestSessionHarness::default());
        services
            .ssh()
            .install_test_session(status, harness.clone())
            .await
            .unwrap();
        (services, session, harness)
    }

    #[test]
    fn catalog_is_closed_unique_and_read_only_by_construction() {
        assert!(CATALOG.len() >= 30);
        let ids = CATALOG
            .iter()
            .map(|definition| definition.entry.id)
            .collect::<BTreeSet<_>>();
        assert_eq!(ids.len(), CATALOG.len());
        for definition in CATALOG {
            assert_eq!(lookup(definition.entry.id).unwrap().entry, definition.entry);
            for command in [
                Some(definition.default_command),
                definition.debian_command,
                definition.redhat_command,
                definition.alpine_command,
            ]
            .into_iter()
            .flatten()
            {
                let lower = command.to_ascii_lowercase();
                assert!(!lower.contains("-printf"), "{command}");
                let interactive_sudo = lower.split([';', '&', '|', '(', ')']).any(|segment| {
                    let segment = segment.trim_start();
                    segment.starts_with("sudo ") && !segment.starts_with("sudo -n ")
                });
                assert!(!interactive_sudo, "{command}");
                for forbidden in [
                    " rm ",
                    "mv ",
                    "cp ",
                    "chmod ",
                    "chown ",
                    "kill ",
                    "reboot",
                    "shutdown",
                    "systemctl start",
                    "systemctl stop",
                    "systemctl restart",
                    "iptables -a",
                    "iptables -d",
                    "nft add",
                    "nft delete",
                ] {
                    assert!(!format!(" {lower} ").contains(forbidden), "{command}");
                }
            }
        }
        assert!(lookup("network-listen; id").is_err());
        assert!(lookup("unknown-id").is_err());
    }

    #[test]
    fn adapter_prefers_family_then_portable_fallback() {
        let services = *CATALOG
            .iter()
            .find(|definition| definition.entry.id == "persistence-services")
            .unwrap();
        assert!(
            services
                .command_for(SystemFamily::Debian)
                .contains("systemctl")
        );
        assert!(
            services
                .command_for(SystemFamily::RedHat)
                .contains("chkconfig")
        );
        assert!(
            services
                .command_for(SystemFamily::Alpine)
                .contains("rc-status")
        );
        assert_eq!(
            services.command_for(SystemFamily::Other),
            services.default_command
        );
        assert_eq!(
            parse_system_family("ubuntu|debian\n"),
            Some(SystemFamily::Debian)
        );
        assert_eq!(
            parse_system_family("rocky|rhel fedora\n"),
            Some(SystemFamily::RedHat)
        );
        assert_eq!(parse_system_family("alpine|\n"), Some(SystemFamily::Alpine));
    }

    #[test]
    fn result_classification_matches_legacy_failure_contract() {
        let output = SshCommandOutput {
            command: "static".to_owned(),
            output: "ss: command not found".to_owned(),
            exit_code: Some(127),
            duration_ms: 5,
            timed_out: false,
        };
        assert_eq!(
            classify(&output, &output.output).0,
            CommandResultKind::MissingCommand
        );
        let output = SshCommandOutput {
            output: String::new(),
            exit_code: Some(0),
            ..output
        };
        assert_eq!(classify(&output, "").0, CommandResultKind::Empty);
        let output = SshCommandOutput {
            output: "partial".to_owned(),
            exit_code: None,
            ..output
        };
        assert_eq!(
            classify(&output, "partial").0,
            CommandResultKind::UnknownExit
        );
        let output = SshCommandOutput {
            timed_out: true,
            ..output
        };
        assert_eq!(classify(&output, "partial").0, CommandResultKind::Timeout);
    }

    #[test]
    fn system_probe_accepts_valid_fixed_output_when_exit_status_is_omitted() {
        let output = SshCommandOutput {
            command: SYSTEM_PROBE.to_owned(),
            output: "ubuntu|debian\n".to_owned(),
            exit_code: None,
            duration_ms: 5,
            timed_out: false,
        };
        assert_eq!(resolve_system_probe(&output).unwrap(), SystemFamily::Debian);
    }

    #[test]
    fn system_probe_does_not_mask_real_failures_or_untrusted_output() {
        let valid = SshCommandOutput {
            command: SYSTEM_PROBE.to_owned(),
            output: "unknown|\n".to_owned(),
            exit_code: None,
            duration_ms: 5,
            timed_out: false,
        };
        assert_eq!(resolve_system_probe(&valid).unwrap(), SystemFamily::Other);

        for output in [
            SshCommandOutput {
                output: String::new(),
                ..valid.clone()
            },
            SshCommandOutput {
                output: "ubuntu\n".to_owned(),
                ..valid.clone()
            },
            SshCommandOutput {
                output: "ubuntu|debian\nuntrusted|rhel\n".to_owned(),
                ..valid.clone()
            },
            SshCommandOutput {
                output: "ubuntu|debian\n".to_owned(),
                exit_code: Some(7),
                ..valid.clone()
            },
            SshCommandOutput {
                output: "ubuntu|debian\n".to_owned(),
                timed_out: true,
                ..valid
            },
        ] {
            assert!(resolve_system_probe(&output).is_err(), "{output:?}");
        }
    }

    #[tokio::test]
    async fn execution_is_target_bound_and_persists_plain_bounded_history() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        harness.set_execute_output("<img src=x onerror=alert(1)>\nnormal evidence");
        let receipt = services
            .commands()
            .execute(&session, "network-listen", SystemFamily::Other)
            .await
            .unwrap();
        assert!(receipt.success);
        assert!(receipt.output.contains("<img src=x"));
        assert!(receipt.history_id.is_some());
        let history = services
            .investigation()
            .command_history()
            .list_for_target(&session.target().identity)
            .unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].title, "监听端口");

        services
            .activate_target(TargetIdentity::new("connection-b").unwrap())
            .unwrap();
        assert!(
            services
                .commands()
                .execute(&session, "network-listen", SystemFamily::Other)
                .await
                .is_err()
        );
        assert_eq!(
            services
                .investigation()
                .command_history()
                .list_for_target(&TargetIdentity::new("connection-a").unwrap())
                .unwrap()
                .len(),
            1
        );
    }
}
