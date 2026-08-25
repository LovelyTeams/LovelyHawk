//! Closed, target-bound emergency command catalog.
//!
//! The native UI executes catalog identifiers, never caller supplied shell text.
//! This first slice intentionally contains read-only collection commands only.

use std::{sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};

use crate::{
    CoreError, CoreResult,
    command_findings::{self, LineRule},
    investigation::{AddCommandHistory, CommandHistoryRepository},
    ssh::{BoundSshSession, SshCommandOutput, SshService},
    target::TargetContext,
};

const SYSTEM_PROBE: &str = "if [ -r /etc/os-release ]; then . /etc/os-release; printf '%s|%s\\n' \"${ID:-unknown}\" \"${ID_LIKE:-}\"; else printf 'unknown|\\n'; fi";
const MAX_COMMAND_OUTPUT_BYTES: usize = 2 * 1024 * 1024;
const DEFAULT_TIMEOUT_SECONDS: u64 = 30;
const HISTORY_COMMAND_IDENTITY: &str = "# lovelyres emergency catalog entry";

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
    /// Marks the output lines an operator should look at first.
    abnormal: Option<LineRule>,
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
            abnormal: None,
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
            abnormal: None,
        }
    }

    /// Attaches the rule that decides which output lines are abnormal.
    const fn flagging(mut self, rule: LineRule) -> Self {
        self.abnormal = Some(rule);
        self
    }

    const fn with_timeout(mut self, timeout_seconds: u64) -> Self {
        self.entry.timeout_seconds = timeout_seconds;
        self
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
    )
    .flagging(command_findings::suid_program),
    portable!(
        "perm-sgid",
        Permissions,
        "SGID 可执行",
        "列出当前文件系统内带 SGID 位的文件。",
        "find / -xdev -perm -2000 -type f 2>/dev/null | sort | head -n 300"
    )
    .flagging(command_findings::sgid_program),
    portable!(
        "perm-world-writable",
        Permissions,
        "全局可写文件",
        "定位可能被任意用户修改的普通文件。",
        "find / -xdev -type f -perm -0002 -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | sort | head -n 300"
    )
    .flagging(command_findings::world_writable_file),
    portable!(
        "perm-capabilities",
        Permissions,
        "文件 Capabilities",
        "收集 Linux 文件能力集。",
        "command -v getcap >/dev/null 2>&1 && getcap -r / 2>/dev/null | head -n 300 || echo 'getcap not available'"
    )
    .flagging(command_findings::file_capability),
    portable!(
        "account-users",
        Accounts,
        "用户与登录 Shell",
        "列出用户名、UID、GID、主目录和 Shell。",
        "getent passwd | awk -F: '{print $1 \"\\t\" $3 \"\\t\" $4 \"\\t\" $6 \"\\t\" $7}' | sort"
    )
    .flagging(command_findings::login_account),
    portable!(
        "account-uid-zero",
        Accounts,
        "UID 0 账户",
        "检查所有拥有超级用户 UID 的账户。",
        "awk -F: '$3 == 0 {print $1 \"\\t\" $3 \"\\t\" $7}' /etc/passwd"
    )
    .flagging(command_findings::extra_root_account),
    portable!(
        "account-empty-password",
        Accounts,
        "空/锁定口令字段",
        "只读检查 shadow 中的空值和锁定标记；普通用户可能无权限。",
        "awk -F: '$2 == \"\" || $2 == \"!\" || $2 == \"*\" {print $1 \"\\t\" $2}' /etc/shadow 2>/dev/null | head -n 200"
    )
    .flagging(command_findings::empty_password),
    portable!(
        "account-sudoers",
        Accounts,
        "sudoers 有效配置",
        "收集非注释 sudoers 配置与片段目录。",
        "grep -vE '^[[:space:]]*(#|$)' /etc/sudoers 2>/dev/null; find /etc/sudoers.d -maxdepth 1 -type f -print 2>/dev/null | sort"
    )
    .flagging(command_findings::sudo_grant),
    portable!(
        "network-listen",
        Network,
        "监听端口",
        "列出 TCP/UDP 监听及其进程。",
        "ss -tulpen 2>/dev/null || netstat -tulpen 2>/dev/null || netstat -tuln 2>/dev/null || echo 'ss/netstat not available'"
    )
    .flagging(command_findings::suspicious_socket),
    portable!(
        "network-established",
        Network,
        "活动连接",
        "列出已建立 TCP 连接及关联进程。",
        "ss -tanp 2>/dev/null | head -n 500 || netstat -tanp 2>/dev/null | head -n 500 || netstat -tan 2>/dev/null | head -n 500"
    )
    .flagging(command_findings::suspicious_socket),
    portable!(
        "network-route",
        Network,
        "路由与策略",
        "收集路由表和策略路由。",
        "ip rule show 2>/dev/null; echo '--- routes ---'; ip route show table all 2>/dev/null || route -n 2>/dev/null"
    )
    .flagging(command_findings::policy_route),
    portable!(
        "network-firewall",
        Network,
        "防火墙规则",
        "只读收集 nftables、iptables 或 firewalld 规则。",
        "nft list ruleset 2>/dev/null || iptables-save 2>/dev/null || firewall-cmd --list-all-zones 2>/dev/null || echo 'firewall tooling not available'"
    )
    .flagging(command_findings::permissive_firewall),
    portable!(
        "process-cpu",
        Processes,
        "CPU 占用进程",
        "按 CPU 使用率列出前 100 个进程。",
        "ps -eo pid,ppid,user,stat,pcpu,pmem,lstart,args --sort=-pcpu 2>/dev/null | head -n 101"
    )
    .flagging(command_findings::suspicious_process),
    portable!(
        "process-memory",
        Processes,
        "内存占用进程",
        "按内存使用率列出前 100 个进程。",
        "ps -eo pid,ppid,user,stat,pcpu,pmem,rss,vsz,args --sort=-pmem 2>/dev/null | head -n 101"
    )
    .flagging(command_findings::suspicious_process),
    portable!(
        "process-deleted",
        Processes,
        "已删除可执行映射",
        "定位仍由进程持有的 deleted 文件。",
        "find /proc/[0-9]*/fd -lname '* (deleted)' -exec ls -l {} + 2>/dev/null | head -n 300"
    )
    .flagging(command_findings::any_hit),
    portable!(
        "process-tree",
        Processes,
        "进程树",
        "展示进程父子关系与完整命令行。",
        "ps -eo pid,ppid,user,stat,lstart,args --forest 2>/dev/null | head -n 500"
    )
    .flagging(command_findings::suspicious_process),
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
    )
    .flagging(command_findings::service_anomaly),
    portable!(
        "persistence-cron",
        Persistence,
        "计划任务",
        "汇总系统 cron、anacron 与用户 crontab 文件。",
        "find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron -maxdepth 2 -type f -print 2>/dev/null | sort | head -n 500"
    )
    .flagging(command_findings::remote_execution_hint),
    portable!(
        "persistence-timers",
        Persistence,
        "systemd Timers",
        "列出所有 systemd timer。",
        "systemctl list-timers --all --no-pager 2>/dev/null || echo 'systemd timers not available'"
    )
    .flagging(command_findings::compromise_marker),
    portable!(
        "persistence-shell",
        Persistence,
        "Shell 启动脚本",
        "列出全局及用户 Shell 启动脚本元数据。",
        "find /etc/profile /etc/profile.d /etc/bashrc /etc/bash.bashrc /root /home -maxdepth 3 -type f \\( -name '.bashrc' -o -name '.profile' -o -name '*.sh' \\) -exec ls -ld -- {} + 2>/dev/null | head -n 500"
    )
    .flagging(command_findings::remote_execution_hint),
    portable!(
        "log-auth",
        Logs,
        "认证日志",
        "收集最近认证成功、失败和 sudo 线索。",
        "journalctl -n 500 --no-pager -u ssh -u sshd -t sudo 2>/dev/null || tail -n 500 /var/log/auth.log /var/log/secure 2>/dev/null"
    )
    .flagging(command_findings::authentication_alert),
    portable!(
        "log-errors",
        Logs,
        "系统错误",
        "收集本次启动的 error 级别日志。",
        "journalctl -b -p err..alert -n 500 --no-pager 2>/dev/null || tail -n 500 /var/log/messages /var/log/syslog 2>/dev/null"
    )
    .flagging(command_findings::system_alert),
    portable!(
        "log-kernel",
        Logs,
        "内核日志",
        "收集最近内核告警和驱动异常。",
        "journalctl -k -n 500 --no-pager 2>/dev/null || dmesg 2>/dev/null | tail -n 500"
    )
    .flagging(command_findings::system_alert),
    portable!(
        "file-recent-executable",
        Files,
        "近期可执行文件",
        "定位最近七天修改且带执行位的文件。",
        "find /tmp /var/tmp /dev/shm /usr/local/bin /opt -xdev -type f -mtime -7 -perm /111 -exec ls -ld -- {} + 2>/dev/null | head -n 500"
    )
    .flagging(command_findings::any_hit),
    portable!(
        "file-hidden",
        Files,
        "隐藏文件",
        "列出常见可写位置下的隐藏普通文件。",
        "find /tmp /var/tmp /dev/shm /home /root -xdev \\( -type f -o -type d \\) -name '.*' -not -name '.' -not -name '..' -exec ls -ld -- {} + 2>/dev/null | head -n 500"
    )
    .flagging(command_findings::planted_file),
    portable!(
        "file-largest",
        Files,
        "大文件",
        "列出当前文件系统内最大的 100 个普通文件。",
        "find / -xdev -type f -size +10M -exec du -b {} + 2>/dev/null | sort -nr | head -n 100"
    )
    .flagging(command_findings::compromise_marker),
    portable!(
        "container-running",
        Containers,
        "运行中容器",
        "只读列出 Docker 或 Podman 容器。",
        "docker ps --no-trunc 2>/dev/null || podman ps --no-trunc 2>/dev/null || echo 'docker/podman not available'"
    )
    .flagging(command_findings::container_workload),
    portable!(
        "container-images",
        Containers,
        "容器镜像",
        "只读列出本地镜像及摘要。",
        "docker images --digests --no-trunc 2>/dev/null || podman images --digests --no-trunc 2>/dev/null || echo 'docker/podman not available'"
    )
    .flagging(command_findings::dangling_image),
    portable!(
        "system-kernel",
        System,
        "系统与内核",
        "收集发行版、内核、架构和运行时间。",
        "cat /etc/os-release 2>/dev/null; echo '---'; uname -a; echo '---'; uptime"
    )
    .flagging(command_findings::compromise_marker),
    portable!(
        "system-resources",
        System,
        "资源使用",
        "收集 CPU、内存、文件系统和 inode 概览。",
        "nproc 2>/dev/null; free -h 2>/dev/null; echo '--- filesystems ---'; df -hT 2>/dev/null; echo '--- inodes ---'; df -hi 2>/dev/null"
    )
    .flagging(command_findings::high_utilisation),
    portable!(
        "system-mounts",
        System,
        "挂载与命名空间",
        "列出挂载点、文件系统和选项。",
        "findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS 2>/dev/null || mount 2>/dev/null"
    )
    .flagging(command_findings::insecure_mount),
    portable!(
        "system-modules",
        System,
        "内核模块",
        "列出已加载内核模块及签名状态线索。",
        "lsmod 2>/dev/null; echo '--- taint ---'; cat /proc/sys/kernel/tainted 2>/dev/null"
    )
    .flagging(command_findings::tainted_kernel),
    portable!(
        "perm-world-writable-dir",
        Permissions,
        "全局可写目录",
        "定位任意用户都能写入的目录，重点看缺少粘滞位的位置。",
        "find / -xdev -type d -perm -0002 -not -path '/proc/*' -not -path '/sys/*' -exec ls -ld -- {} + 2>/dev/null | head -n 300"
    )
    .with_timeout(60)
    .flagging(command_findings::world_writable_directory),
    portable!(
        "perm-no-owner",
        Permissions,
        "无属主文件",
        "查找已删除账号遗留或异常创建的文件。",
        "find / -xdev \\( -nouser -o -nogroup \\) -exec ls -ld -- {} + 2>/dev/null | head -n 300"
    )
    .with_timeout(60)
    .flagging(command_findings::unowned_path),
    portable!(
        "perm-key-files",
        Permissions,
        "关键文件权限",
        "检查账号、认证和 SSH 配置文件的属主与权限。",
        "ls -l /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/ssh/sshd_config /etc/crontab 2>/dev/null"
    )
    .flagging(command_findings::account_file_mode),
    portable!(
        "perm-path-writable",
        Permissions,
        "PATH 中的可写目录",
        "查找搜索路径里可被普通用户写入的目录，这类目录容易被投放同名程序。",
        "printf '%s\\n' \"$PATH\" | tr ':' '\\n' | while read -r dir; do [ -n \"$dir\" ] && [ -d \"$dir\" ] && [ -w \"$dir\" ] && ls -ld \"$dir\"; done 2>/dev/null"
    )
    .flagging(command_findings::shared_writable_directory),
    portable!(
        "perm-acl",
        Permissions,
        "扩展 ACL 授权",
        "列出在标准权限之外额外授权的文件。",
        "command -v getfacl >/dev/null 2>&1 && find /etc /root /home /var/www -maxdepth 3 -exec getfacl -s {} + 2>/dev/null | head -n 300 || echo 'getfacl 不可用'"
    )
    .with_timeout(60)
    .flagging(command_findings::acl_grant),
    portable!(
        "perm-immutable",
        Permissions,
        "受保护属性文件",
        "查找被加上不可修改或只可追加属性的文件，攻击者常用它锁住后门。",
        "command -v lsattr >/dev/null 2>&1 && lsattr -Ra /etc /root /var/spool/cron 2>/dev/null | awk 'NF==2 && substr($2,1,1)==\"/\" && $1 ~ /^[-a-zA-Z]+$/ && $1 ~ /[ai]/ {print}' | head -n 200 || echo 'lsattr 不可用'"
    )
    .with_timeout(60)
    .flagging(command_findings::locked_attribute),
    portable!(
        "perm-sudo-nopasswd",
        Permissions,
        "免密提权规则",
        "找出无需口令即可提权的 sudo 配置。",
        "grep -rnE 'NOPASSWD|!authenticate' /etc/sudoers /etc/sudoers.d 2>/dev/null | head -n 200"
    )
    .flagging(command_findings::passwordless_sudo),
    portable!(
        "perm-ssh-key-files",
        Permissions,
        "SSH 密钥文件",
        "列出各账号下的授权公钥与私钥文件位置和权限。",
        "ls -la /root/.ssh 2>/dev/null; echo '--- 用户密钥 ---'; find /home -maxdepth 3 -name 'authorized_keys*' -o -maxdepth 3 -name 'id_*' -exec ls -ld -- {} + 2>/dev/null | head -n 200"
    )
    .flagging(command_findings::ssh_key_exposure),
    portable!(
        "account-logged-in",
        Accounts,
        "当前登录会话",
        "查看此刻在线的账号、来源地址和正在执行的命令。",
        "w 2>/dev/null || who -a 2>/dev/null || echo 'w/who 不可用'"
    )
    .flagging(command_findings::remote_session),
    portable!(
        "account-last-login",
        Accounts,
        "最近登录记录",
        "按时间倒序列出最近的登录来源。",
        "last -n 200 -a 2>/dev/null | head -n 200 || echo 'last 不可用'"
    )
    .flagging(command_findings::remote_session),
    portable!(
        "account-failed-login",
        Accounts,
        "登录失败记录",
        "列出失败的登录尝试，用于判断是否存在爆破。",
        "lastb -n 200 2>/dev/null | head -n 200 || echo 'lastb 不可用或权限不足'"
    )
    .flagging(command_findings::any_hit),
    portable!(
        "account-groups",
        Accounts,
        "用户组清单",
        "列出全部用户组及其成员。",
        "getent group | sort"
    )
    .flagging(command_findings::privileged_group_listing),
    portable!(
        "account-privileged-groups",
        Accounts,
        "特权组成员",
        "检查 root、sudo、docker 等高权限组里多出来的成员。",
        "for g in root wheel sudo admin adm docker lxd disk shadow systemd-journal; do getent group \"$g\" 2>/dev/null; done"
    )
    .flagging(command_findings::privileged_group_member),
    portable!(
        "account-login-shells",
        Accounts,
        "可登录账号",
        "筛选出拥有可交互登录 Shell 的账号。",
        "getent passwd | awk -F: '$7 !~ /nologin|false|halt|sync/ {print $1 \"\\t\" $3 \"\\t\" $7}'"
    )
    .flagging(command_findings::login_account),
    portable!(
        "account-file-changes",
        Accounts,
        "账号文件变更时间",
        "查看账号相关文件的最后修改时间，判断是否被新增或改写。",
        "stat -c '%n mtime=%y uid=%U mode=%a' /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers 2>/dev/null || ls -l /etc/passwd /etc/shadow /etc/group /etc/sudoers 2>/dev/null; echo '--- 备份文件 ---'; ls -l /etc/passwd- /etc/shadow- /etc/group- 2>/dev/null"
    )
    .flagging(command_findings::account_file_exposure),
    portable!(
        "account-authorized-keys",
        Accounts,
        "SSH 授权公钥内容",
        "汇总各账号 authorized_keys 里的公钥，核对是否有陌生密钥。",
        "find /root /home -maxdepth 4 -name authorized_keys 2>/dev/null | while read -r f; do echo \"--- $f ---\"; cat \"$f\" 2>/dev/null; done | head -n 300"
    )
    .flagging(command_findings::authorized_key),
    portable!(
        "account-sshd-config",
        Accounts,
        "SSH 服务配置",
        "展开 SSH 服务的生效配置，关注 root 登录与认证方式。",
        "sshd -T 2>/dev/null | head -n 200 || grep -vE '^[[:space:]]*(#|$)' /etc/ssh/sshd_config 2>/dev/null | head -n 200"
    )
    .flagging(command_findings::risky_ssh_setting),
    portable!(
        "account-password-policy",
        Accounts,
        "口令策略",
        "收集口令长度、有效期与认证模块配置。",
        "grep -vE '^[[:space:]]*(#|$)' /etc/login.defs 2>/dev/null | head -n 80; echo '--- 认证模块 ---'; grep -rnE 'pam_(unix|pwquality|cracklib|faillock|tally)' /etc/pam.d 2>/dev/null | head -n 100"
    )
    .flagging(command_findings::weak_password_policy),
    portable!(
        "account-expiry",
        Accounts,
        "口令与账号有效期",
        "读取每个账号的口令最后修改时间与到期设置。",
        "awk -F: '{s=\"set\"; if ($2 == \"\") s=\"empty\"; else if ($2 ~ /^[!*]/) s=\"locked\"; printf \"%s state=%s last=%s min=%s max=%s warn=%s inactive=%s expire=%s\\n\", $1, s, $3, $4, $5, $6, $7, $8}' /etc/shadow 2>/dev/null | head -n 200 || echo '需要更高权限'"
    )
    .flagging(command_findings::password_never_set),
    portable!(
        "account-source",
        Accounts,
        "账号来源配置",
        "确认账号是否来自域控、LDAP 等外部目录服务。",
        "grep -vE '^[[:space:]]*(#|$)' /etc/nsswitch.conf 2>/dev/null; echo '--- 目录服务 ---'; ls -l /etc/sssd /etc/ldap /etc/openldap 2>/dev/null"
    )
    .flagging(command_findings::external_account_source),
    portable!(
        "account-privilege-history",
        Accounts,
        "提权命令记录",
        "从认证日志里提取 sudo 与切换用户的记录。",
        "grep -hE 'sudo:|su\\[|COMMAND=' /var/log/auth.log /var/log/secure 2>/dev/null | tail -n 300 || journalctl -t sudo -n 300 --no-pager 2>/dev/null"
    )
    .flagging(command_findings::privilege_command_record),
    portable!(
        "network-interfaces",
        Network,
        "网卡与地址",
        "列出全部网卡、IP 地址和状态。",
        "ip -o addr show 2>/dev/null; echo '--- 链路 ---'; ip -o link show 2>/dev/null || ifconfig -a 2>/dev/null || echo 'ip/ifconfig 不可用'"
    )
    .flagging(command_findings::promiscuous_link),
    portable!(
        "network-arp",
        Network,
        "ARP 邻居表",
        "查看同网段通信过的主机。",
        "ip neigh show 2>/dev/null || arp -an 2>/dev/null || cat /proc/net/arp 2>/dev/null"
    )
    .flagging(command_findings::static_arp),
    portable!(
        "network-dns",
        Network,
        "域名解析配置",
        "检查 DNS 服务器与 hosts 文件是否被篡改。",
        "cat /etc/resolv.conf 2>/dev/null; echo '--- hosts ---'; cat /etc/hosts 2>/dev/null; echo '--- 解析顺序 ---'; grep '^hosts' /etc/nsswitch.conf 2>/dev/null"
    )
    .flagging(command_findings::host_override),
    portable!(
        "network-socket-summary",
        Network,
        "连接数统计",
        "汇总各状态的连接数量，快速判断异常外联规模。",
        "ss -s 2>/dev/null || netstat -s 2>/dev/null | head -n 100 || echo 'ss/netstat 不可用'"
    )
    .flagging(command_findings::high_connection_count),
    portable!(
        "network-outbound",
        Network,
        "对外已建立连接",
        "只看非本机回环的已建立连接，用于发现反连和外传。",
        "ss -tanp state established 2>/dev/null | grep -vE '127\\.0\\.0\\.1|::1' | head -n 300 || netstat -anp 2>/dev/null | grep ESTABLISHED | head -n 300"
    )
    .flagging(command_findings::suspicious_socket),
    portable!(
        "network-top-remote",
        Network,
        "远端地址排名",
        "按连接数排列对端地址，定位集中通信的目标。",
        "ss -tan 2>/dev/null | awk 'NR>1 {print $5}' | sed 's/:[0-9]*$//' | sort | uniq -c | sort -nr | head -n 50"
    )
    .flagging(command_findings::frequent_source),
    portable!(
        "network-promisc",
        Network,
        "混杂模式网卡",
        "检查是否有网卡被置于抓包模式。",
        "ip -o link show 2>/dev/null | grep -i promisc; echo '--- 全部链路 ---'; ip -o link show 2>/dev/null | head -n 50"
    )
    .flagging(command_findings::promiscuous_link),
    portable!(
        "network-process-map",
        Network,
        "端口与进程对应",
        "把监听端口和外联连接映射到具体进程。",
        "command -v lsof >/dev/null 2>&1 && lsof -nPi 2>/dev/null | head -n 300 || ss -tulpna 2>/dev/null | head -n 300"
    )
    .with_timeout(60)
    .flagging(command_findings::suspicious_socket),
    portable!(
        "network-nat",
        Network,
        "转发与地址转换规则",
        "查看 NAT 表和转发链，判断是否被配置成跳板。",
        "iptables -t nat -L -n -v 2>/dev/null | head -n 200; echo '--- 转发链 ---'; iptables -L FORWARD -n -v 2>/dev/null | head -n 100 || echo 'iptables 不可用'"
    )
    .flagging(command_findings::traffic_redirection),
    portable!(
        "network-kernel-params",
        Network,
        "网络内核参数",
        "检查转发、重定向、源路由等与攻击面相关的开关。",
        "sysctl -a 2>/dev/null | grep -E 'ip_forward|rp_filter|accept_redirects|send_redirects|accept_source_route|syncookies' | head -n 60 || echo 'sysctl 不可用'"
    )
    .flagging(command_findings::risky_network_parameter),
    portable!(
        "network-namespaces",
        Network,
        "网络命名空间与网桥",
        "列出隔离的网络空间和网桥，容器环境常见。",
        "ip netns list 2>/dev/null; echo '--- 网桥 ---'; bridge link show 2>/dev/null; ls -l /var/run/netns 2>/dev/null"
    )
    .flagging(command_findings::compromise_marker),
    portable!(
        "network-proxy",
        Network,
        "代理配置",
        "查找系统与全局配置里设置的出网代理。",
        "env 2>/dev/null | grep -iE 'proxy'; echo '--- 全局配置 ---'; grep -rniE 'http_proxy|https_proxy|all_proxy' /etc/environment /etc/profile /etc/profile.d 2>/dev/null | head -n 50"
    )
    .flagging(command_findings::proxy_setting),
    portable!(
        "network-listen-summary",
        Network,
        "监听端口汇总",
        "按端口去重列出监听服务，便于和资产清单核对。",
        "ss -tulnp 2>/dev/null | awk 'NR>1 {print $1, $5, $7}' | sort -u | head -n 200 || netstat -tuln 2>/dev/null | head -n 200"
    )
    .flagging(command_findings::suspicious_socket),
    portable!(
        "process-all",
        Processes,
        "全量进程清单",
        "列出所有进程及完整命令行。",
        "ps -ef 2>/dev/null | head -n 500 || ps aux 2>/dev/null | head -n 500"
    )
    .flagging(command_findings::suspicious_process),
    portable!(
        "process-hidden",
        Processes,
        "隐藏进程比对",
        "比对 /proc 与进程列表，发现被工具隐藏的进程。",
        "for p in /proc/[0-9]*; do pid=${p#/proc/}; ps -p \"$pid\" >/dev/null 2>&1 || echo \"仅存在于 /proc 的进程: $pid $(cat \"$p/comm\" 2>/dev/null)\"; done 2>/dev/null | head -n 100"
    )
    .with_timeout(60)
    .flagging(command_findings::any_hit),
    portable!(
        "process-root-notty",
        Processes,
        "无终端的 root 进程",
        "筛选脱离终端运行的高权限进程。",
        "ps -eo pid,ppid,user,tty,stat,lstart,args 2>/dev/null | awk 'NR==1 || ($3==\"root\" && $4==\"?\")' | head -n 300"
    )
    .flagging(command_findings::suspicious_process),
    portable!(
        "process-recent",
        Processes,
        "最近启动的进程",
        "按运行时长升序排列，最新拉起的进程排在前面。",
        "ps -eo pid,ppid,user,etimes,lstart,args --sort=etimes 2>/dev/null | head -n 100 || ps -eo pid,ppid,user,lstart,args 2>/dev/null | head -n 100"
    )
    .flagging(command_findings::suspicious_process),
    portable!(
        "process-reparented",
        Processes,
        "被 init 收养的进程",
        "父进程为 1 的进程常见于脱离会话的后门。",
        "ps -eo pid,ppid,user,stat,etimes,args 2>/dev/null | awk 'NR==1 || $2==1' | head -n 300"
    )
    .flagging(command_findings::suspicious_process),
    portable!(
        "process-preload",
        Processes,
        "动态库注入痕迹",
        "检查全局预加载配置和带注入环境变量的进程。",
        "cat /etc/ld.so.preload 2>/dev/null; echo '--- 进程环境 ---'; grep -l 'LD_PRELOAD' /proc/[0-9]*/environ 2>/dev/null | head -n 100"
    )
    .flagging(command_findings::any_hit),
    portable!(
        "process-exe-path",
        Processes,
        "可疑映像路径",
        "找出可执行文件位于临时目录或已被删除的进程。",
        "ls -l /proc/[0-9]*/exe 2>/dev/null | grep -E 'deleted|/tmp/|/dev/shm|/var/tmp' | head -n 200"
    )
    .flagging(command_findings::any_hit),
    portable!(
        "process-interpreters",
        Processes,
        "解释器与工具进程",
        "列出脚本解释器和常见网络工具进程。",
        "ps -eo pid,ppid,user,args 2>/dev/null | grep -E '(python|perl|php|ruby|node|socat|ncat|nc -|bash -i|sh -i)' | grep -v grep | head -n 200"
    )
    .flagging(command_findings::suspicious_process),
    portable!(
        "process-threads",
        Processes,
        "线程数排行",
        "线程数异常的进程往往在做批量任务。",
        "ps -eo pid,user,nlwp,args --sort=-nlwp 2>/dev/null | head -n 50"
    )
    .flagging(command_findings::suspicious_process),
    portable!(
        "process-blocked",
        Processes,
        "阻塞状态进程",
        "列出处于不可中断状态的进程，多与磁盘或网络异常相关。",
        "ps -eo pid,ppid,stat,wchan,args 2>/dev/null | awk 'NR==1 || $3 ~ /^D/' | head -n 100"
    )
    .flagging(command_findings::any_hit),
    portable!(
        "process-open-files",
        Processes,
        "进程打开的文件",
        "查看进程持有的文件与工作目录。",
        "command -v lsof >/dev/null 2>&1 && lsof -n 2>/dev/null | head -n 500 || ls -l /proc/[0-9]*/cwd 2>/dev/null | head -n 300"
    )
    .with_timeout(60)
    .flagging(command_findings::suspicious_process),
    portable!(
        "process-cgroup",
        Processes,
        "进程归属关系",
        "按服务和容器分组查看进程归属。",
        "systemd-cgls --no-pager 2>/dev/null | head -n 200 || cat /proc/1/cgroup 2>/dev/null"
    )
    .flagging(command_findings::compromise_marker),
    portable!(
        "process-high-cpu",
        Processes,
        "持续高占用进程",
        "筛选 CPU 占用超过一半的进程，挖矿类程序特征明显。",
        "ps -eo pid,ppid,user,pcpu,pmem,etimes,args --sort=-pcpu 2>/dev/null | awk 'NR==1 || $4 > 50' | head -n 50"
    )
    .flagging(command_findings::suspicious_process),
    portable!(
        "persistence-user-crontab",
        Persistence,
        "用户计划任务内容",
        "读取每个账号的 crontab 内容。",
        "for f in /var/spool/cron/crontabs/* /var/spool/cron/*; do [ -f \"$f\" ] && { echo \"--- $f ---\"; cat \"$f\" 2>/dev/null; }; done 2>/dev/null | head -n 300"
    )
    .flagging(command_findings::remote_execution_hint),
    portable!(
        "persistence-system-crontab",
        Persistence,
        "系统计划任务内容",
        "读取 /etc/crontab 与 cron.d 下的任务内容。",
        "cat /etc/crontab 2>/dev/null; for f in /etc/cron.d/*; do [ -f \"$f\" ] && { echo \"--- $f ---\"; cat \"$f\" 2>/dev/null; }; done 2>/dev/null | head -n 300"
    )
    .flagging(command_findings::remote_execution_hint),
    portable!(
        "persistence-at",
        Persistence,
        "一次性定时任务",
        "查看 at 队列中的待执行任务。",
        "atq 2>/dev/null; ls -l /var/spool/at /var/spool/cron/atjobs 2>/dev/null | head -n 100"
    )
    .flagging(command_findings::any_hit),
    portable!(
        "persistence-recent-units",
        Persistence,
        "近期改动的服务单元",
        "列出最近三十天被创建或修改的服务文件。",
        "find /etc/systemd /lib/systemd /usr/lib/systemd -name '*.service' -mtime -30 -exec ls -ld -- {} + 2>/dev/null | head -n 200"
    )
    .with_timeout(60)
    .flagging(command_findings::any_hit),
    portable!(
        "persistence-user-units",
        Persistence,
        "用户级服务单元",
        "检查用户目录下的自启服务。",
        "find /home /root -maxdepth 5 -path '*/.config/systemd/*' -type f -exec ls -ld -- {} + 2>/dev/null | head -n 200; echo '--- 用户单元 ---'; systemctl --user list-unit-files --no-pager 2>/dev/null | head -n 100"
    )
    .with_timeout(60)
    .flagging(command_findings::any_hit),
    portable!(
        "persistence-rc",
        Persistence,
        "开机脚本与运行级",
        "查看 rc.local 与各运行级下的启动脚本。",
        "cat /etc/rc.local 2>/dev/null; echo '--- init 脚本 ---'; ls -l /etc/init.d 2>/dev/null | head -n 100; echo '--- 运行级目录 ---'; ls -l /etc/rc*.d 2>/dev/null | head -n 200"
    )
    .flagging(command_findings::remote_execution_hint),
    portable!(
        "persistence-ldso",
        Persistence,
        "动态链接配置",
        "检查预加载与库搜索路径是否被插入异常条目。",
        "cat /etc/ld.so.preload 2>/dev/null; echo '--- 搜索路径 ---'; cat /etc/ld.so.conf 2>/dev/null; ls -l /etc/ld.so.conf.d 2>/dev/null; cat /etc/ld.so.conf.d/*.conf 2>/dev/null | head -n 100"
    )
    .flagging(command_findings::remote_execution_hint),
    portable!(
        "persistence-profile-content",
        Persistence,
        "全局登录脚本内容",
        "读取全局 Shell 启动脚本，定位注入的命令。",
        "for f in /etc/profile /etc/bash.bashrc /etc/bashrc /etc/profile.d/*; do [ -f \"$f\" ] && { echo \"--- $f ---\"; cat \"$f\" 2>/dev/null; }; done 2>/dev/null | head -n 400"
    )
    .flagging(command_findings::remote_execution_hint),
    portable!(
        "persistence-user-rc",
        Persistence,
        "用户登录脚本内容",
        "读取各账号的 Shell 启动脚本。",
        "for f in /root/.bashrc /root/.bash_profile /root/.profile /home/*/.bashrc /home/*/.bash_profile /home/*/.profile; do [ -f \"$f\" ] && { echo \"--- $f ---\"; cat \"$f\" 2>/dev/null; }; done 2>/dev/null | head -n 400"
    )
    .flagging(command_findings::remote_execution_hint),
    portable!(
        "persistence-motd",
        Persistence,
        "登录横幅脚本",
        "登录时自动执行的横幅脚本也可被用作后门。",
        "ls -l /etc/update-motd.d /etc/motd /etc/issue /etc/issue.net 2>/dev/null; echo '--- 脚本内容 ---'; cat /etc/update-motd.d/* 2>/dev/null | head -n 200"
    )
    .flagging(command_findings::remote_execution_hint),
    portable!(
        "persistence-udev",
        Persistence,
        "设备触发规则",
        "检查设备事件触发执行的规则。",
        "find /etc/udev/rules.d /lib/udev/rules.d -type f -mtime -90 -exec ls -ld -- {} + 2>/dev/null | head -n 100; echo '--- 带执行动作 ---'; grep -rlE 'RUN\\+?=' /etc/udev/rules.d 2>/dev/null | head -n 50"
    )
    .flagging(command_findings::remote_execution_hint),
    portable!(
        "persistence-modules",
        Persistence,
        "开机加载的内核模块",
        "查看随系统启动自动加载的模块配置。",
        "cat /etc/modules 2>/dev/null; ls -l /etc/modules-load.d /etc/modprobe.d 2>/dev/null; cat /etc/modules-load.d/*.conf /etc/modprobe.d/*.conf 2>/dev/null | head -n 200"
    )
    .flagging(command_findings::remote_execution_hint),
    portable!(
        "persistence-inetd",
        Persistence,
        "超级守护进程服务",
        "检查 inetd 与 xinetd 中注册的服务。",
        "cat /etc/inetd.conf 2>/dev/null; ls -l /etc/xinetd.d 2>/dev/null; cat /etc/xinetd.d/* 2>/dev/null | head -n 200"
    )
    .flagging(command_findings::remote_execution_hint),
    portable!(
        "persistence-supervisor",
        Persistence,
        "进程守护配置",
        "查看 supervisor 等守护工具托管的程序。",
        "ls -l /etc/supervisor/conf.d /etc/supervisord.d 2>/dev/null; cat /etc/supervisor/conf.d/*.conf /etc/supervisord.d/*.ini 2>/dev/null | head -n 200"
    )
    .flagging(command_findings::remote_execution_hint),
    portable!(
        "persistence-pam",
        Persistence,
        "认证模块变更",
        "检查近期被改动的认证配置与模块文件。",
        "find /etc/pam.d -type f -mtime -60 -exec ls -ld -- {} + 2>/dev/null | head -n 100; echo '--- 模块文件 ---'; find /lib/security /lib64/security /usr/lib/security /usr/lib64/security -name '*.so' -mtime -60 -exec ls -ld -- {} + 2>/dev/null | head -n 100"
    )
    .with_timeout(60)
    .flagging(command_findings::any_hit),
    portable!(
        "persistence-alias",
        Persistence,
        "命令别名与函数",
        "别名和函数可以劫持常用命令的行为。",
        "grep -rnE '^[[:space:]]*(alias|function)[[:space:]]' /etc/profile /etc/profile.d /etc/bash.bashrc /etc/bashrc /root/.bashrc /home/*/.bashrc 2>/dev/null | head -n 200"
    )
    .flagging(command_findings::remote_execution_hint),
    portable!(
        "log-ssh-accepted",
        Logs,
        "SSH 登录成功记录",
        "提取认证日志中成功登录的来源与方式。",
        "grep -hE 'Accepted (password|publickey|keyboard)' /var/log/auth.log /var/log/secure 2>/dev/null | tail -n 300 || journalctl -u sshd -u ssh -n 500 --no-pager 2>/dev/null | grep Accepted | tail -n 300"
    )
    .flagging(command_findings::accepted_login),
    portable!(
        "log-ssh-failed",
        Logs,
        "登录爆破来源排名",
        "统计失败登录的来源地址，按次数排序。",
        "grep -hE 'Failed password|Invalid user' /var/log/auth.log /var/log/secure 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == \"from\") print $(i + 1)}' | sort | uniq -c | sort -nr | head -n 50"
    )
    .flagging(command_findings::frequent_source),
    portable!(
        "log-account-change",
        Logs,
        "账号变更日志",
        "查找新增账号、改口令、加组的日志痕迹。",
        "grep -hE 'useradd|usermod|groupadd|gpasswd|password changed|new user|new group' /var/log/auth.log /var/log/secure 2>/dev/null | tail -n 200"
    )
    .flagging(command_findings::any_hit),
    portable!(
        "log-tamper",
        Logs,
        "日志被清理迹象",
        "列出大小为零的日志和登录记录文件状态。",
        "ls -l /var/log/wtmp /var/log/btmp /var/log/lastlog /var/run/utmp 2>/dev/null; echo '--- 空日志文件 ---'; find /var/log -type f -size 0 -exec ls -ld -- {} + 2>/dev/null | head -n 200"
    )
    .flagging(command_findings::emptied_log),
    portable!(
        "log-journal",
        Logs,
        "日志占用与启动记录",
        "查看日志总量与可用的启动记录范围。",
        "journalctl --disk-usage 2>/dev/null; journalctl --list-boots --no-pager 2>/dev/null | tail -n 20; echo '--- 日志目录 ---'; du -sh /var/log 2>/dev/null"
    )
    .with_timeout(60)
    .flagging(command_findings::compromise_marker),
    portable!(
        "log-web-location",
        Logs,
        "Web 日志位置",
        "定位 Web 服务日志文件及其大小。",
        "ls -l /var/log/nginx /var/log/apache2 /var/log/httpd /usr/local/nginx/logs /usr/local/apache2/logs 2>/dev/null | head -n 100"
    )
    .flagging(command_findings::emptied_log),
    portable!(
        "log-web-suspicious",
        Logs,
        "Web 日志可疑请求",
        "在访问日志里筛选注入、遍历和命令执行特征。",
        "grep -hiE '(union[[:space:]]+select|\\.\\./|%2e%2e|eval\\(|base64_decode|/bin/sh|wget |curl )' /var/log/nginx/*access*.log /var/log/apache2/*access*.log /var/log/httpd/*access*.log 2>/dev/null | tail -n 200"
    )
    .with_timeout(60)
    .flagging(command_findings::any_hit),
    portable!(
        "log-cron-exec",
        Logs,
        "计划任务执行记录",
        "确认定时任务实际被执行的时间与内容。",
        "grep -hE 'CRON|cron' /var/log/syslog /var/log/cron /var/log/messages 2>/dev/null | tail -n 200 || journalctl -t CRON -n 200 --no-pager 2>/dev/null"
    )
    .flagging(command_findings::remote_execution_hint),
    portable!(
        "log-boot-history",
        Logs,
        "开机与运行时间",
        "查看本次启动时间和历史启动记录。",
        "who -b 2>/dev/null; uptime -s 2>/dev/null; echo '--- 历史 ---'; last -x -n 50 2>/dev/null | head -n 50"
    )
    .flagging(command_findings::boot_event),
    portable!(
        "log-audit",
        Logs,
        "审计日志",
        "读取审计子系统记录的登录与执行事件。",
        "command -v ausearch >/dev/null 2>&1 && ausearch -ts today -m USER_LOGIN,USER_AUTH,EXECVE 2>/dev/null | tail -n 200 || tail -n 200 /var/log/audit/audit.log 2>/dev/null || echo '审计日志不可用'"
    )
    .with_timeout(60)
    .flagging(command_findings::audit_failure),
    portable!(
        "log-rotate",
        Logs,
        "日志轮转配置",
        "确认日志保留策略，判断证据可追溯的时间范围。",
        "cat /etc/logrotate.conf 2>/dev/null | head -n 60; echo '--- 轮转配置 ---'; ls -l /etc/logrotate.d 2>/dev/null | head -n 100"
    )
    .flagging(command_findings::short_log_retention),
    portable!(
        "log-shell-history",
        Logs,
        "命令历史文件",
        "列出各账号的命令历史文件并读取 root 的最近记录。",
        "ls -l /root/.bash_history /home/*/.bash_history /root/.zsh_history /home/*/.zsh_history 2>/dev/null | head -n 100; echo '--- root 最近命令 ---'; tail -n 150 /root/.bash_history 2>/dev/null"
    )
    .flagging(command_findings::tampered_or_telling_history),
    portable!(
        "file-recent-modified",
        Files,
        "近一天改动的文件",
        "在配置、家目录和站点目录里找最近改动。",
        "find /etc /root /home /var/www /usr/local /opt -xdev -type f -mtime -1 -exec ls -ld -- {} + 2>/dev/null | head -n 400"
    )
    .with_timeout(60)
    .flagging(command_findings::planted_file),
    portable!(
        "file-temp-listing",
        Files,
        "临时目录清单",
        "完整列出临时目录内容，含权限与时间。",
        "ls -la /tmp /var/tmp /dev/shm 2>/dev/null | head -n 300"
    )
    .flagging(command_findings::planted_file),
    portable!(
        "file-etc-changed",
        Files,
        "配置目录近期变更",
        "列出 /etc 下最近七天被改动的文件。",
        "find /etc -xdev -type f -mtime -7 -exec ls -ld -- {} + 2>/dev/null | head -n 300"
    )
    .with_timeout(60)
    .flagging(command_findings::planted_file),
    portable!(
        "file-webshell-hint",
        Files,
        "站点可疑代码特征",
        "在站点目录里按危险函数特征筛选文件路径。",
        "grep -rlniE '(eval\\(|assert\\(|base64_decode|shell_exec|passthru\\(|system\\(|popen\\()' /var/www /usr/share/nginx /srv/www /home/*/public_html 2>/dev/null | head -n 200"
    )
    .with_timeout(60)
    .flagging(command_findings::any_hit),
    portable!(
        "file-web-recent",
        Files,
        "站点近期新增文件",
        "列出站点目录中最近七天出现的文件。",
        "find /var/www /usr/share/nginx /srv/www /home/*/public_html -xdev -type f -mtime -7 -exec ls -ld -- {} + 2>/dev/null | head -n 300"
    )
    .with_timeout(60)
    .flagging(command_findings::any_hit),
    portable!(
        "file-symlink",
        Files,
        "可疑软链接",
        "列出常见目录下的软链接及其指向。",
        "find /etc /root /home /tmp /var/tmp -xdev -type l -exec ls -ld -- {} + 2>/dev/null | head -n 300"
    )
    .flagging(command_findings::sensitive_symlink),
    portable!(
        "file-odd-name",
        Files,
        "异常文件名",
        "查找含空格或多重点号的文件名，常用于伪装。",
        "find /tmp /var/tmp /dev/shm /home /root -xdev \\( -name '* *' -o -name '.. *' -o -name '...*' \\) -exec ls -ld -- {} + 2>/dev/null | head -n 200"
    )
    .flagging(command_findings::any_hit),
    portable!(
        "file-binary-changed",
        Files,
        "系统命令近期改动",
        "检查系统命令目录中最近改动的文件。",
        "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -xdev -type f -mtime -30 -exec ls -ld -- {} + 2>/dev/null | head -n 200"
    )
    .with_timeout(60)
    .flagging(command_findings::any_hit),
    portable!(
        "file-dev-anomaly",
        Files,
        "设备目录中的普通文件",
        "/dev 下出现普通文件通常不正常。",
        "find /dev -xdev -type f -exec ls -ld -- {} + 2>/dev/null | head -n 100"
    )
    .flagging(command_findings::any_hit),
    portable!(
        "file-home-listing",
        Files,
        "家目录清单",
        "列出 root 与各用户家目录的内容。",
        "ls -la /root 2>/dev/null | head -n 200; echo '--- 用户家目录 ---'; ls -la /home/* 2>/dev/null | head -n 300"
    )
    .flagging(command_findings::shared_writable_directory),
    portable!(
        "file-credential",
        Files,
        "凭据类文件位置",
        "列出私钥、证书和环境变量文件的位置，不读取内容。",
        "find /etc /root /home /var/www /opt -xdev -type f \\( -name 'id_rsa*' -o -name 'id_ed25519*' -o -name '*.pem' -o -name '*.key' -o -name '.env' -o -name '*.p12' \\) -exec ls -ld -- {} + 2>/dev/null | head -n 200"
    )
    .with_timeout(60)
    .flagging(command_findings::ssh_key_exposure),
    portable!(
        "file-disk-usage",
        Files,
        "目录占用排行",
        "按占用空间排列一级目录，定位异常增长。",
        "du -x -h -d 1 / 2>/dev/null | sort -hr | head -n 40 || du -x -h --max-depth=1 / 2>/dev/null | sort -hr | head -n 40"
    )
    .with_timeout(60)
    .flagging(command_findings::compromise_marker),
    portable!(
        "container-all",
        Containers,
        "全部容器",
        "包含已退出的容器，便于回溯短暂运行过的实例。",
        "docker ps -a --no-trunc 2>/dev/null || podman ps -a --no-trunc 2>/dev/null || echo 'docker/podman 不可用'"
    )
    .flagging(command_findings::container_workload),
    portable!(
        "container-self",
        Containers,
        "当前主机是否在容器内",
        "判断这次连接进入的是宿主机还是容器。",
        "ls -l /.dockerenv /run/.containerenv 2>/dev/null; echo '--- 控制组 ---'; cat /proc/1/cgroup 2>/dev/null | head -n 20; echo '--- 虚拟化 ---'; systemd-detect-virt 2>/dev/null"
    )
    .flagging(command_findings::inside_container),
    portable!(
        "container-privileged",
        Containers,
        "特权容器检查",
        "列出以特权模式或共享宿主命名空间运行的容器。",
        "docker ps -q 2>/dev/null | while read -r c; do docker inspect --format '{{.Name}} privileged={{.HostConfig.Privileged}} pid={{.HostConfig.PidMode}} net={{.HostConfig.NetworkMode}}' \"$c\" 2>/dev/null; done | head -n 100"
    )
    .with_timeout(60)
    .flagging(command_findings::container_privilege),
    portable!(
        "container-mounts",
        Containers,
        "容器挂载的宿主目录",
        "检查容器是否挂载了宿主机敏感目录。",
        "docker ps -q 2>/dev/null | while read -r c; do docker inspect --format '{{.Name}}{{range .Mounts}} {{.Source}}:{{.Destination}}{{end}}' \"$c\" 2>/dev/null; done | head -n 100"
    )
    .with_timeout(60)
    .flagging(command_findings::host_mount),
    portable!(
        "container-network",
        Containers,
        "容器网络与端口",
        "列出容器网络和对外映射的端口。",
        "docker network ls 2>/dev/null; echo '--- 端口映射 ---'; docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null | head -n 100"
    )
    .flagging(command_findings::exposed_container_port),
    portable!(
        "container-volumes",
        Containers,
        "容器数据卷",
        "列出本地数据卷。",
        "docker volume ls 2>/dev/null | head -n 100; echo '--- podman ---'; podman volume ls 2>/dev/null | head -n 50"
    )
    .flagging(command_findings::compromise_marker),
    portable!(
        "container-runtime",
        Containers,
        "容器运行时信息",
        "收集运行时版本、存储驱动和安全选项。",
        "docker info 2>/dev/null | head -n 100 || podman info 2>/dev/null | head -n 100 || echo '容器运行时不可用'"
    )
    .flagging(command_findings::runtime_warning),
    portable!(
        "container-compose",
        Containers,
        "编排文件位置",
        "查找 compose 编排文件，了解服务组成。",
        "find /root /home /opt /srv /etc -maxdepth 4 \\( -name 'docker-compose*.yml' -o -name 'docker-compose*.yaml' -o -name 'compose.yml' -o -name 'compose.yaml' \\) -exec ls -ld -- {} + 2>/dev/null | head -n 100"
    )
    .with_timeout(60)
    .flagging(command_findings::compromise_marker),
    portable!(
        "container-orchestrator",
        Containers,
        "编排平台负载",
        "列出 Kubernetes 或 containerd 中运行的负载。",
        "command -v kubectl >/dev/null 2>&1 && kubectl get pods -A 2>/dev/null | head -n 200 || crictl ps 2>/dev/null | head -n 100 || echo '编排平台工具不可用'"
    )
    .with_timeout(60)
    .flagging(command_findings::unhealthy_workload),
    portable!(
        "container-daemon",
        Containers,
        "容器守护进程配置",
        "检查守护进程配置与可访问容器接口的账号。",
        "cat /etc/docker/daemon.json 2>/dev/null; echo '--- 接口权限 ---'; ls -l /var/run/docker.sock 2>/dev/null; getent group docker 2>/dev/null"
    )
    .flagging(command_findings::container_daemon_risk),
    portable!(
        "system-time",
        System,
        "时间与时钟同步",
        "确认系统时间和时区，日志比对前必须先核对。",
        "date 2>/dev/null; echo '--- 时区 ---'; timedatectl 2>/dev/null || cat /etc/timezone 2>/dev/null; echo '--- 时钟同步 ---'; chronyc sources 2>/dev/null || ntpq -p 2>/dev/null || echo '未发现时钟同步客户端'"
    )
    .flagging(command_findings::unsynchronised_clock),
    portable!(
        "system-identity",
        System,
        "主机标识",
        "收集主机名与机器标识。",
        "hostname 2>/dev/null; hostnamectl 2>/dev/null | head -n 20; cat /etc/hostname /etc/machine-id 2>/dev/null"
    )
    .flagging(command_findings::compromise_marker),
    portable!(
        "system-env",
        System,
        "环境变量",
        "查看当前会话与全局环境变量。",
        "env 2>/dev/null | sort | head -n 200; echo '--- 全局配置 ---'; cat /etc/environment 2>/dev/null"
    )
    .flagging(command_findings::injected_environment),
    portable!(
        "system-security-params",
        System,
        "安全内核参数",
        "检查地址随机化、内核指针保护等加固开关。",
        "sysctl -a 2>/dev/null | grep -E 'randomize_va_space|kptr_restrict|dmesg_restrict|yama|suid_dumpable|protected_' | head -n 60 || echo 'sysctl 不可用'"
    )
    .flagging(command_findings::weak_hardening),
    portable!(
        "system-limits",
        System,
        "资源限制",
        "查看进程与文件句柄的限制配置。",
        "ulimit -a 2>/dev/null; echo '--- 限制配置 ---'; grep -vE '^[[:space:]]*(#|$)' /etc/security/limits.conf 2>/dev/null | head -n 100"
    )
    .flagging(command_findings::core_dump_enabled),
    portable!(
        "system-disk",
        System,
        "磁盘与分区",
        "列出块设备、分区和交换空间。",
        "lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT 2>/dev/null || cat /proc/partitions 2>/dev/null; echo '--- 交换空间 ---'; cat /proc/swaps 2>/dev/null"
    )
    .flagging(command_findings::high_utilisation),
    portable!(
        "system-hardware",
        System,
        "处理器与内存",
        "收集处理器型号、核心数和内存明细。",
        "lscpu 2>/dev/null | head -n 40 || head -n 40 /proc/cpuinfo 2>/dev/null; echo '--- 内存 ---'; head -n 20 /proc/meminfo 2>/dev/null"
    )
    .flagging(command_findings::compromise_marker),
    portable!(
        "system-mac",
        System,
        "强制访问控制状态",
        "确认 SELinux 或 AppArmor 是否启用。",
        "sestatus 2>/dev/null || getenforce 2>/dev/null; echo '--- AppArmor ---'; aa-status 2>/dev/null | head -n 40 || cat /sys/kernel/security/apparmor/profiles 2>/dev/null | head -n 40 || echo '未检测到强制访问控制框架'"
    )
    .flagging(command_findings::disabled_mac),
    portable!(
        "system-boot",
        System,
        "启动参数与默认目标",
        "查看内核启动参数与默认启动目标。",
        "cat /proc/cmdline 2>/dev/null; echo '--- 默认目标 ---'; systemctl get-default 2>/dev/null || runlevel 2>/dev/null; echo '--- 引导目录 ---'; ls -l /boot 2>/dev/null | head -n 50"
    )
    .flagging(command_findings::risky_boot_parameter),
    portable!(
        "system-load",
        System,
        "负载与运行时间",
        "查看系统负载与最近的资源波动。",
        "uptime 2>/dev/null; cat /proc/loadavg 2>/dev/null; echo '--- 资源采样 ---'; vmstat 1 2 2>/dev/null | tail -n 3"
    )
    .flagging(command_findings::high_load),
    portable!(
        "system-kernel-integrity",
        System,
        "内核状态与 eBPF",
        "查看内核污染标记和已加载的 eBPF 程序。",
        "cat /proc/sys/kernel/tainted 2>/dev/null; echo '--- eBPF ---'; bpftool prog show 2>/dev/null | head -n 60 || echo 'bpftool 不可用'"
    )
    .flagging(command_findings::tainted_kernel),
    portable!(
        "system-virtualization",
        System,
        "虚拟化与云环境",
        "判断运行在物理机、虚拟机还是云主机上。",
        "systemd-detect-virt 2>/dev/null; cat /sys/class/dmi/id/product_name /sys/class/dmi/id/sys_vendor 2>/dev/null; echo '--- 云元数据接口 ---'; ls -l /sys/class/dmi/id 2>/dev/null | head -n 20"
    )
    .flagging(command_findings::inside_container),
    CommandDefinition::adapted(
        "system-packages",
        CommandCategory::System,
        "已安装软件包",
        "按当前发行版列出安装的软件包。",
        FamilyCommands {
            default: "dpkg -l 2>/dev/null | head -n 500 || rpm -qa 2>/dev/null | sort | head -n 500 || apk info -v 2>/dev/null | sort | head -n 500 || echo '未识别包管理器'",
            debian: Some("dpkg -l 2>/dev/null | head -n 500"),
            redhat: Some("rpm -qa 2>/dev/null | sort | head -n 500"),
            alpine: Some("apk info -v 2>/dev/null | sort | head -n 500"),
        },
    )
    .with_timeout(60)
    .flagging(command_findings::offensive_tool_package),
    CommandDefinition::adapted(
        "system-package-recent",
        CommandCategory::System,
        "最近安装的软件包",
        "按安装时间倒序，查看临时装上的工具。",
        FamilyCommands {
            default: "rpm -qa --last 2>/dev/null | head -n 100 || grep -hE ' install | upgrade ' /var/log/dpkg.log 2>/dev/null | tail -n 200 || tail -n 200 /var/log/apk.log 2>/dev/null || echo '无安装记录'",
            debian: Some("grep -hE ' install | upgrade ' /var/log/dpkg.log 2>/dev/null | tail -n 200 || echo '无安装记录'"),
            redhat: Some("rpm -qa --last 2>/dev/null | head -n 100"),
            alpine: Some("tail -n 200 /var/log/apk.log 2>/dev/null || echo '无安装记录'"),
        },
    )
    .with_timeout(60)
    .flagging(command_findings::offensive_tool_package),
    CommandDefinition::adapted(
        "system-updates",
        CommandCategory::System,
        "待更新与补丁状态",
        "只做模拟查询，不改动系统，用于判断补丁缺口。",
        FamilyCommands {
            default: "apt-get -s upgrade 2>/dev/null | tail -n 40 || yum check-update 2>/dev/null | head -n 100 || dnf check-update 2>/dev/null | head -n 100 || apk version -l '<' 2>/dev/null | head -n 100 || echo '未识别包管理器'",
            debian: Some("apt-get -s upgrade 2>/dev/null | tail -n 40"),
            redhat: Some("yum check-update 2>/dev/null | head -n 100 || dnf check-update 2>/dev/null | head -n 100"),
            alpine: Some("apk version -l '<' 2>/dev/null | head -n 100"),
        },
    )
    .with_timeout(60)
    .flagging(command_findings::pending_security_update),
    CommandDefinition::adapted(
        "file-package-verify",
        CommandCategory::Files,
        "软件包文件完整性",
        "比对系统命令与安装包记录，发现被替换的文件。",
        FamilyCommands {
            default: "rpm -Va --nomtime --nomode 2>/dev/null | head -n 300 || debsums -c 2>/dev/null | head -n 200 || echo '完整性校验工具不可用'",
            debian: Some("command -v debsums >/dev/null 2>&1 && debsums -c 2>/dev/null | head -n 200 || echo 'debsums 未安装'"),
            redhat: Some("rpm -Va --nomtime --nomode 2>/dev/null | head -n 300"),
            alpine: Some("apk audit --system 2>/dev/null | head -n 200 || echo 'apk audit 不可用'"),
        },
    )
    .with_timeout(60)
    .flagging(command_findings::any_hit),
    CommandDefinition::adapted(
        "persistence-user-services",
        CommandCategory::Persistence,
        "自启服务明细",
        "只列出处于启用状态的服务，比全量列表更聚焦。",
        FamilyCommands {
            default: "systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null | head -n 200 || rc-status -a 2>/dev/null | head -n 200 || ls -l /etc/rc*.d 2>/dev/null | head -n 200",
            debian: Some("systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null | head -n 200"),
            redhat: Some("systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null | head -n 200 || chkconfig --list 2>/dev/null | head -n 200"),
            alpine: Some("rc-update show 2>/dev/null | head -n 200 || rc-status -a 2>/dev/null | head -n 200"),
        },
    )
    .flagging(command_findings::service_anomaly),
];

/// The closed, read-only catalog every frontend runs from.
pub fn shipped_catalog() -> Vec<CommandCatalogEntry> {
    CATALOG.iter().map(|definition| definition.entry).collect()
}

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
    /// Zero-based indexes of output lines that look abnormal, ascending.
    #[serde(default)]
    pub finding_lines: Vec<u32>,
    /// Why those lines were marked, written for the operator.
    #[serde(default)]
    pub finding_reason: Option<String>,
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
        shipped_catalog()
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
            // The fixed shell program and its potentially sensitive output are
            // execution-only values. Portable history keeps a non-executable
            // producer identity plus a bounded classification summary.
            command: HISTORY_COMMAND_IDENTITY.to_owned(),
            title: definition.entry.title.to_owned(),
            output: command_history_summary(kind, output.exit_code, truncated),
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
            finding_lines: command_findings::finding_lines(&bounded_output, definition.abnormal),
            finding_reason: definition
                .abnormal
                .and_then(command_findings::reason_for)
                .map(str::to_owned),
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

fn command_history_summary(
    kind: CommandResultKind,
    exit_code: Option<i32>,
    truncated: bool,
) -> String {
    let kind = match kind {
        CommandResultKind::Success => "success",
        CommandResultKind::Empty => "empty",
        CommandResultKind::NonZero => "non-zero",
        CommandResultKind::Timeout => "timeout",
        CommandResultKind::MissingCommand => "missing-command",
        CommandResultKind::PermissionDenied => "permission-denied",
        CommandResultKind::UnknownExit => "unknown-exit",
    };
    let exit = exit_code.map_or_else(|| "unknown".to_owned(), |code| code.to_string());
    format!(
        "built-in emergency command result: {kind}; exit: {exit}; live output was not persisted{}",
        if truncated {
            "; live output was truncated"
        } else {
            ""
        }
    )
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
        store::StoreFile,
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
        assert!(CATALOG.len() >= 140);
        for category in CommandCategory::ALL {
            let count = CATALOG
                .iter()
                .filter(|definition| definition.entry.category == category)
                .count();
            assert!(count >= 8, "{category:?} only has {count} entries");
        }
        for definition in CATALOG {
            // The Electron boundary refuses anything outside this window.
            assert!(
                (1..=60).contains(&definition.entry.timeout_seconds),
                "{}",
                definition.entry.id
            );
            assert!(!definition.entry.title.is_empty());
            assert!(!definition.entry.description.is_empty());
        }
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

    /// A highlight the operator cannot explain is noise, so every rule the
    /// catalog uses has to carry its reason.
    #[test]
    fn every_command_explains_why_it_marks_a_line() {
        for definition in CATALOG {
            let rule = definition.abnormal.expect("every command has a rule");
            let reason = command_findings::reason_for(rule);
            assert!(
                reason.is_some_and(|text| text.len() > 20),
                "{} has no usable reason",
                definition.entry.id
            );
        }
    }

    /// Every catalog command decides which of its output lines are abnormal.
    /// Listing commands use the shared compromise markers rather than nothing,
    /// so a clean host stays quiet and a planted one still lights up.
    #[test]
    fn every_command_marks_its_abnormal_lines() {
        for definition in CATALOG {
            assert!(
                definition.abnormal.is_some(),
                "{} has no abnormal-line rule",
                definition.entry.id
            );
        }
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
    async fn execution_is_target_bound_and_history_omits_shell_and_live_output() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        harness.set_execute_output(
            "<img src=x onerror=alert(1)>\npassword=do-not-persist\nnormal evidence",
        );
        let receipt = services
            .commands()
            .execute(&session, "network-listen", SystemFamily::Other)
            .await
            .unwrap();
        assert!(receipt.success);
        assert!(receipt.output.contains("<img src=x"));
        assert!(receipt.output.contains("password=do-not-persist"));
        assert!(receipt.history_id.is_some());
        let history = services
            .investigation()
            .command_history()
            .list_for_target(&session.target().identity)
            .unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].title, "监听端口");
        assert_eq!(history[0].command, HISTORY_COMMAND_IDENTITY);
        assert!(history[0].output.contains("live output was not persisted"));
        assert!(!history[0].output.contains("normal evidence"));
        assert_eq!(history[0].risk, crate::investigation::CommandRisk::Mutating);
        assert_eq!(
            services
                .investigation()
                .command_history()
                .search(&session.target().identity, "live output was not persisted")
                .unwrap(),
            history
        );
        let replay = services
            .investigation()
            .command_history()
            .plan_replay(&session.target().identity, &history[0].id)
            .unwrap();
        let crate::investigation::CommandReplayPlan::Intent { intent } = replay else {
            panic!("fixed history identity must remain conservatively classified");
        };
        assert_eq!(intent.risk, crate::investigation::CommandRisk::Mutating);
        assert!(intent.requires_dangerous_confirmation);
        assert!(intent.command.starts_with("# "));
        let persisted = fs::read_to_string(services.store().path_for(StoreFile::History)).unwrap();
        for forbidden in [
            "network-listen",
            "ss -tulpen",
            "password=do-not-persist",
            "normal evidence",
            "<img src=x",
        ] {
            assert!(!persisted.contains(forbidden), "persisted {forbidden}");
        }

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
