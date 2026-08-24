//! Target-bound Linux configuration baselines with verified, reversible edits.
//!
//! The public boundary is deliberately closed: callers select a catalog item
//! and a typed value. Remote paths, shell snippets, regular expressions, and
//! service names never cross the UI/core boundary.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    CoreError, CoreResult, PortableStore,
    operations::{
        DangerousConfirmation, ExecutionReceipt, OperationExecutor, OperationJournal,
        OperationPlan, OperationState, PlannedOperation, PortableOperationJournal,
        VerificationResult,
    },
    shell_escape::shq,
    ssh::{BoundSshSession, SshCommandOutput, SshService},
    store::StoreFile,
    target::{TargetContext, TargetGuard, TargetIdentity},
};

const BASELINE_ROOT: &str = "/var/lib/lovelyres/managed-baseline";
const SCAN_MARKER: &str = "LR_BASELINE_SCAN_V1";
const APPLY_MARKER: &str = "LR_BASELINE_APPLY_V1";
const RESTORE_MARKER: &str = "LR_BASELINE_RESTORE_V1";
const REAPPLY_MARKER: &str = "LR_BASELINE_REAPPLY_V1";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(45);
const MAX_HISTORY: usize = 256;
const MAX_CHANGES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BaselineCategory {
    Ssh,
    Password,
    Kernel,
    Network,
    Authentication,
    Logging,
    FilePermissions,
}

impl BaselineCategory {
    pub const ALL: [Self; 7] = [
        Self::Ssh,
        Self::Authentication,
        Self::Password,
        Self::Kernel,
        Self::Network,
        Self::Logging,
        Self::FilePermissions,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Ssh => "SSH 安全",
            Self::Password => "密码策略",
            Self::Kernel => "内核加固",
            Self::Network => "网络参数",
            Self::Authentication => "认证防护",
            Self::Logging => "审计日志",
            Self::FilePermissions => "文件权限",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BaselineRisk {
    Critical,
    High,
    Medium,
    Low,
}

impl BaselineRisk {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Critical => "严重",
            Self::High => "高",
            Self::Medium => "中",
            Self::Low => "低",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineValueKind {
    Choice(&'static [&'static str]),
    Integer { minimum: u32, maximum: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileFormat {
    Whitespace,
    Equals,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ReloadGroup {
    None,
    Sshd,
    Sysctl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaselineDefinition {
    pub id: &'static str,
    pub category: BaselineCategory,
    pub title: &'static str,
    pub description: &'static str,
    pub recommendation: &'static str,
    pub risk: BaselineRisk,
    pub value_kind: BaselineValueKind,
    file: &'static str,
    key: &'static str,
    format: FileFormat,
    reload: ReloadGroup,
}

const YES_NO: &[&str] = &["yes", "no"];
const ROOT_LOGIN: &[&str] = &["yes", "no", "prohibit-password"];
const AUDIT_LOG_ACTION: &[&str] = &["ignore", "syslog", "suspend", "rotate", "keep_logs"];
const AUDIT_SPACE_ACTION: &[&str] = &["ignore", "syslog", "suspend", "single", "halt"];
const DEFAULT_UMASK: &[&str] = &["022", "027", "077"];

pub const BASELINE_CATALOG: &[BaselineDefinition] = &[
    BaselineDefinition {
        id: "ssh-permit-root-login",
        category: BaselineCategory::Ssh,
        title: "禁止 root 直接登录",
        description: "限制 root 通过 SSH 直接认证，优先使用普通账户与 sudo。",
        recommendation: "no",
        risk: BaselineRisk::Critical,
        value_kind: BaselineValueKind::Choice(ROOT_LOGIN),
        file: "/etc/ssh/sshd_config",
        key: "PermitRootLogin",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::Sshd,
    },
    BaselineDefinition {
        id: "ssh-password-authentication",
        category: BaselineCategory::Ssh,
        title: "关闭 SSH 密码认证",
        description: "仅在确认密钥认证可用后关闭密码认证。",
        recommendation: "no",
        risk: BaselineRisk::Critical,
        value_kind: BaselineValueKind::Choice(YES_NO),
        file: "/etc/ssh/sshd_config",
        key: "PasswordAuthentication",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::Sshd,
    },
    BaselineDefinition {
        id: "ssh-pubkey-authentication",
        category: BaselineCategory::Ssh,
        title: "启用 SSH 公钥认证",
        description: "允许使用受信任公钥登录。",
        recommendation: "yes",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Choice(YES_NO),
        file: "/etc/ssh/sshd_config",
        key: "PubkeyAuthentication",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::Sshd,
    },
    BaselineDefinition {
        id: "ssh-max-auth-tries",
        category: BaselineCategory::Ssh,
        title: "限制认证尝试次数",
        description: "降低单连接暴力猜测密码的次数。",
        recommendation: "4",
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Integer {
            minimum: 1,
            maximum: 10,
        },
        file: "/etc/ssh/sshd_config",
        key: "MaxAuthTries",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::Sshd,
    },
    BaselineDefinition {
        id: "ssh-login-grace-time",
        category: BaselineCategory::Ssh,
        title: "缩短登录宽限时间",
        description: "限制未完成认证的连接占用时长（秒）。",
        recommendation: "60",
        risk: BaselineRisk::Low,
        value_kind: BaselineValueKind::Integer {
            minimum: 10,
            maximum: 300,
        },
        file: "/etc/ssh/sshd_config",
        key: "LoginGraceTime",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::Sshd,
    },
    BaselineDefinition {
        id: "ssh-permit-empty-passwords",
        category: BaselineCategory::Ssh,
        title: "拒绝 SSH 空口令",
        description: "禁止空密码账户通过 SSH 完成认证。",
        recommendation: "no",
        risk: BaselineRisk::Critical,
        value_kind: BaselineValueKind::Choice(YES_NO),
        file: "/etc/ssh/sshd_config",
        key: "PermitEmptyPasswords",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::Sshd,
    },
    BaselineDefinition {
        id: "ssh-hostbased-authentication",
        category: BaselineCategory::Ssh,
        title: "关闭主机信任认证",
        description: "禁用依赖远端主机身份与信任文件的 HostbasedAuthentication。",
        recommendation: "no",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Choice(YES_NO),
        file: "/etc/ssh/sshd_config",
        key: "HostbasedAuthentication",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::Sshd,
    },
    BaselineDefinition {
        id: "ssh-ignore-rhosts",
        category: BaselineCategory::Ssh,
        title: "忽略 rhosts 信任文件",
        description: "避免 SSH 认证依赖用户或系统级 rhosts 信任关系。",
        recommendation: "yes",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Choice(YES_NO),
        file: "/etc/ssh/sshd_config",
        key: "IgnoreRhosts",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::Sshd,
    },
    BaselineDefinition {
        id: "ssh-x11-forwarding",
        category: BaselineCategory::Ssh,
        title: "关闭 X11 转发",
        description: "在服务器无需图形转发时减少 SSH 会话的额外攻击面。",
        recommendation: "no",
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Choice(YES_NO),
        file: "/etc/ssh/sshd_config",
        key: "X11Forwarding",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::Sshd,
    },
    BaselineDefinition {
        id: "ssh-tcp-forwarding",
        category: BaselineCategory::Ssh,
        title: "关闭 SSH TCP 转发",
        description: "在无需隧道能力时阻止 SSH 会话建立本地或远端 TCP 转发。",
        recommendation: "no",
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Choice(YES_NO),
        file: "/etc/ssh/sshd_config",
        key: "AllowTcpForwarding",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::Sshd,
    },
    BaselineDefinition {
        id: "authentication-login-fail-delay",
        category: BaselineCategory::Authentication,
        title: "延迟失败登录重试",
        description: "为支持 login.defs 的登录程序设置认证失败后的等待秒数。",
        recommendation: "4",
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Integer {
            minimum: 0,
            maximum: 60,
        },
        file: "/etc/login.defs",
        key: "FAIL_DELAY",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "authentication-faillock-deny",
        category: BaselineCategory::Authentication,
        title: "限制连续认证失败次数",
        description: "设置 pam_faillock 的失败阈值；仅在 PAM 栈已启用 pam_faillock 时生效。",
        recommendation: "5",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Integer {
            minimum: 1,
            maximum: 20,
        },
        file: "/etc/security/faillock.conf",
        key: "deny",
        format: FileFormat::Equals,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "authentication-faillock-window",
        category: BaselineCategory::Authentication,
        title: "限定失败统计窗口",
        description: "设置 pam_faillock 汇总连续失败的时间窗口（秒）。",
        recommendation: "900",
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Integer {
            minimum: 60,
            maximum: 86_400,
        },
        file: "/etc/security/faillock.conf",
        key: "fail_interval",
        format: FileFormat::Equals,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "authentication-faillock-unlock-time",
        category: BaselineCategory::Authentication,
        title: "设置认证锁定时长",
        description: "设置 pam_faillock 自动解除普通账户锁定的秒数，0 表示需人工解除。",
        recommendation: "900",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Integer {
            minimum: 0,
            maximum: 86_400,
        },
        file: "/etc/security/faillock.conf",
        key: "unlock_time",
        format: FileFormat::Equals,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "authentication-password-min-length",
        category: BaselineCategory::Authentication,
        title: "提高新密码最短长度",
        description: "设置 libpwquality 的最短密码长度；仅在认证栈使用 pwquality 时生效。",
        recommendation: "14",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Integer {
            minimum: 6,
            maximum: 128,
        },
        file: "/etc/security/pwquality.conf",
        key: "minlen",
        format: FileFormat::Equals,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "password-max-days",
        category: BaselineCategory::Password,
        title: "密码最长使用天数",
        description: "设置新账户密码的最长有效期。",
        recommendation: "90",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Integer {
            minimum: 1,
            maximum: 99_999,
        },
        file: "/etc/login.defs",
        key: "PASS_MAX_DAYS",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "password-min-days",
        category: BaselineCategory::Password,
        title: "密码最短使用天数",
        description: "防止用户快速循环密码绕过历史策略。",
        recommendation: "1",
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Integer {
            minimum: 0,
            maximum: 365,
        },
        file: "/etc/login.defs",
        key: "PASS_MIN_DAYS",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "password-warn-age",
        category: BaselineCategory::Password,
        title: "密码到期预警天数",
        description: "在密码到期前提示用户更新密码。",
        recommendation: "7",
        risk: BaselineRisk::Low,
        value_kind: BaselineValueKind::Integer {
            minimum: 0,
            maximum: 30,
        },
        file: "/etc/login.defs",
        key: "PASS_WARN_AGE",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "permissions-default-umask",
        category: BaselineCategory::FilePermissions,
        title: "收紧默认文件掩码",
        description: "设置新建文件与目录的系统默认 umask；不会追溯修改已有对象。",
        recommendation: "027",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Choice(DEFAULT_UMASK),
        file: "/etc/login.defs",
        key: "UMASK",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "permissions-ssh-strict-modes",
        category: BaselineCategory::FilePermissions,
        title: "启用 SSH 严格权限检查",
        description: "让 sshd 在认证前检查用户主目录及授权文件的属主和权限。",
        recommendation: "yes",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Choice(YES_NO),
        file: "/etc/ssh/sshd_config",
        key: "StrictModes",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::Sshd,
    },
    BaselineDefinition {
        id: "kernel-aslr",
        category: BaselineCategory::Kernel,
        title: "启用完整 ASLR",
        description: "随机化进程地址空间，增加内存利用难度。",
        recommendation: "2",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Integer {
            minimum: 0,
            maximum: 2,
        },
        file: "/etc/sysctl.d/99-lovelyres-baseline.conf",
        key: "kernel.randomize_va_space",
        format: FileFormat::Equals,
        reload: ReloadGroup::Sysctl,
    },
    BaselineDefinition {
        id: "kernel-kptr-restrict",
        category: BaselineCategory::Kernel,
        title: "限制内核指针暴露",
        description: "限制非特权用户读取内核地址。",
        recommendation: "2",
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Integer {
            minimum: 0,
            maximum: 2,
        },
        file: "/etc/sysctl.d/99-lovelyres-baseline.conf",
        key: "kernel.kptr_restrict",
        format: FileFormat::Equals,
        reload: ReloadGroup::Sysctl,
    },
    BaselineDefinition {
        id: "kernel-dmesg-restrict",
        category: BaselineCategory::Kernel,
        title: "限制 dmesg 读取",
        description: "防止非特权用户从内核日志获取敏感地址和设备信息。",
        recommendation: "1",
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Integer {
            minimum: 0,
            maximum: 1,
        },
        file: "/etc/sysctl.d/99-lovelyres-baseline.conf",
        key: "kernel.dmesg_restrict",
        format: FileFormat::Equals,
        reload: ReloadGroup::Sysctl,
    },
    BaselineDefinition {
        id: "kernel-suid-dumpable",
        category: BaselineCategory::Kernel,
        title: "禁止特权程序核心转储",
        description: "阻止 setuid 或其他提权程序生成可能包含敏感数据的 core dump。",
        recommendation: "0",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Integer {
            minimum: 0,
            maximum: 2,
        },
        file: "/etc/sysctl.d/99-lovelyres-baseline.conf",
        key: "fs.suid_dumpable",
        format: FileFormat::Equals,
        reload: ReloadGroup::Sysctl,
    },
    BaselineDefinition {
        id: "kernel-core-uses-pid",
        category: BaselineCategory::Kernel,
        title: "核心转储文件包含 PID",
        description: "为 core 文件名加入进程 PID，降低并发转储相互覆盖的风险。",
        recommendation: "1",
        risk: BaselineRisk::Low,
        value_kind: BaselineValueKind::Integer {
            minimum: 0,
            maximum: 1,
        },
        file: "/etc/sysctl.d/99-lovelyres-baseline.conf",
        key: "kernel.core_uses_pid",
        format: FileFormat::Equals,
        reload: ReloadGroup::Sysctl,
    },
    BaselineDefinition {
        id: "kernel-protected-hardlinks",
        category: BaselineCategory::Kernel,
        title: "保护硬链接创建",
        description: "限制普通用户为不受其控制的文件创建硬链接。",
        recommendation: "1",
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Integer {
            minimum: 0,
            maximum: 1,
        },
        file: "/etc/sysctl.d/99-lovelyres-baseline.conf",
        key: "fs.protected_hardlinks",
        format: FileFormat::Equals,
        reload: ReloadGroup::Sysctl,
    },
    BaselineDefinition {
        id: "kernel-protected-symlinks",
        category: BaselineCategory::Kernel,
        title: "保护符号链接跟随",
        description: "限制在粘滞位目录中跟随其他用户控制的符号链接。",
        recommendation: "1",
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Integer {
            minimum: 0,
            maximum: 1,
        },
        file: "/etc/sysctl.d/99-lovelyres-baseline.conf",
        key: "fs.protected_symlinks",
        format: FileFormat::Equals,
        reload: ReloadGroup::Sysctl,
    },
    BaselineDefinition {
        id: "network-accept-redirects",
        category: BaselineCategory::Network,
        title: "拒绝 IPv4 ICMP 重定向",
        description: "降低通过伪造 ICMP 重定向修改路由的风险。",
        recommendation: "0",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Integer {
            minimum: 0,
            maximum: 1,
        },
        file: "/etc/sysctl.d/99-lovelyres-baseline.conf",
        key: "net.ipv4.conf.all.accept_redirects",
        format: FileFormat::Equals,
        reload: ReloadGroup::Sysctl,
    },
    BaselineDefinition {
        id: "network-accept-source-route",
        category: BaselineCategory::Network,
        title: "拒绝 IPv4 源路由",
        description: "忽略由发送方指定路由路径的 IPv4 数据包。",
        recommendation: "0",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Integer {
            minimum: 0,
            maximum: 1,
        },
        file: "/etc/sysctl.d/99-lovelyres-baseline.conf",
        key: "net.ipv4.conf.all.accept_source_route",
        format: FileFormat::Equals,
        reload: ReloadGroup::Sysctl,
    },
    BaselineDefinition {
        id: "network-default-accept-redirects",
        category: BaselineCategory::Network,
        title: "新接口拒绝 IPv4 重定向",
        description: "确保之后创建的 IPv4 接口默认不接受 ICMP 重定向。",
        recommendation: "0",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Integer {
            minimum: 0,
            maximum: 1,
        },
        file: "/etc/sysctl.d/99-lovelyres-baseline.conf",
        key: "net.ipv4.conf.default.accept_redirects",
        format: FileFormat::Equals,
        reload: ReloadGroup::Sysctl,
    },
    BaselineDefinition {
        id: "network-secure-redirects",
        category: BaselineCategory::Network,
        title: "拒绝所谓安全 IPv4 重定向",
        description: "不信任来自当前网关列表的 ICMP 重定向消息。",
        recommendation: "0",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Integer {
            minimum: 0,
            maximum: 1,
        },
        file: "/etc/sysctl.d/99-lovelyres-baseline.conf",
        key: "net.ipv4.conf.all.secure_redirects",
        format: FileFormat::Equals,
        reload: ReloadGroup::Sysctl,
    },
    BaselineDefinition {
        id: "network-default-source-route",
        category: BaselineCategory::Network,
        title: "新接口拒绝 IPv4 源路由",
        description: "确保之后创建的 IPv4 接口默认忽略发送方指定的路由路径。",
        recommendation: "0",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Integer {
            minimum: 0,
            maximum: 1,
        },
        file: "/etc/sysctl.d/99-lovelyres-baseline.conf",
        key: "net.ipv4.conf.default.accept_source_route",
        format: FileFormat::Equals,
        reload: ReloadGroup::Sysctl,
    },
    BaselineDefinition {
        id: "network-log-martians",
        category: BaselineCategory::Network,
        title: "记录异常来源 IPv4 包",
        description: "记录来源地址不合理的 IPv4 数据包，为欺骗与路由异常提供线索。",
        recommendation: "1",
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Integer {
            minimum: 0,
            maximum: 1,
        },
        file: "/etc/sysctl.d/99-lovelyres-baseline.conf",
        key: "net.ipv4.conf.all.log_martians",
        format: FileFormat::Equals,
        reload: ReloadGroup::Sysctl,
    },
    BaselineDefinition {
        id: "network-tcp-syncookies",
        category: BaselineCategory::Network,
        title: "启用 TCP SYN Cookies",
        description: "在 SYN 队列溢出时使用 cookies 缓解连接洪泛造成的资源耗尽。",
        recommendation: "1",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Integer {
            minimum: 0,
            maximum: 1,
        },
        file: "/etc/sysctl.d/99-lovelyres-baseline.conf",
        key: "net.ipv4.tcp_syncookies",
        format: FileFormat::Equals,
        reload: ReloadGroup::Sysctl,
    },
    BaselineDefinition {
        id: "logging-audit-max-file-size",
        category: BaselineCategory::Logging,
        title: "限制单个审计日志大小",
        description: "设置 auditd 单个日志文件的 MiB 上限；仅在 auditd 已安装启用时生效。",
        recommendation: "100",
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Integer {
            minimum: 1,
            maximum: 65_535,
        },
        file: "/etc/audit/auditd.conf",
        key: "max_log_file",
        format: FileFormat::Equals,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "logging-audit-retained-files",
        category: BaselineCategory::Logging,
        title: "保留多份审计日志",
        description: "配置 auditd 轮转时保留的日志文件数量。",
        recommendation: "8",
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Integer {
            minimum: 1,
            maximum: 99,
        },
        file: "/etc/audit/auditd.conf",
        key: "num_logs",
        format: FileFormat::Equals,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "logging-audit-rotation-action",
        category: BaselineCategory::Logging,
        title: "启用审计日志轮转",
        description: "在单个审计日志达到上限时轮转，避免无界增长耗尽磁盘。",
        recommendation: "rotate",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Choice(AUDIT_LOG_ACTION),
        file: "/etc/audit/auditd.conf",
        key: "max_log_file_action",
        format: FileFormat::Equals,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "logging-audit-space-action",
        category: BaselineCategory::Logging,
        title: "记录审计磁盘空间告警",
        description: "当审计分区空间不足时将事件写入 syslog，避免静默失去审计能力。",
        recommendation: "syslog",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Choice(AUDIT_SPACE_ACTION),
        file: "/etc/audit/auditd.conf",
        key: "space_left_action",
        format: FileFormat::Equals,
        reload: ReloadGroup::None,
    },
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", content = "value", rename_all = "kebab-case")]
pub enum BaselineObservedValue {
    Missing,
    Unsupported,
    Value(String),
}

impl BaselineObservedValue {
    pub fn label(&self) -> &str {
        match self {
            Self::Missing => "未设置",
            Self::Unsupported => "不支持（符号链接或特殊文件）",
            Self::Value(value) => value,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineStatus {
    pub item_id: String,
    pub observed: BaselineObservedValue,
    pub compliant: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineScan {
    pub target: TargetGuard,
    pub statuses: Vec<BaselineStatus>,
    pub captured_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineChangeRequest {
    pub item_id: String,
    pub value: String,
}

impl BaselineChangeRequest {
    pub fn new(item_id: impl Into<String>, value: impl Into<String>) -> CoreResult<Self> {
        let item_id = item_id.into();
        let definition = definition(&item_id)?;
        let value = normalize_requested_value(definition, &value.into())?;
        Ok(Self { item_id, value })
    }

    pub fn recommended(item_id: impl Into<String>) -> CoreResult<Self> {
        let item_id = item_id.into();
        let definition = definition(&item_id)?;
        Self::new(item_id, definition.recommendation)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BaselineReloadPolicy {
    Defer,
    ApplyNow,
}

impl BaselineReloadPolicy {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Defer => "仅保存配置，稍后手动重载",
            Self::ApplyNow => "写入后立即校验并重载",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedBaselineChange {
    pub item_id: String,
    pub before: BaselineObservedValue,
    pub after: String,
}

#[derive(Debug, Clone)]
pub struct BaselineChangePlan {
    operation: OperationPlan,
    changes: Vec<PlannedBaselineChange>,
    files: Vec<String>,
    remote_root: String,
    reload_policy: BaselineReloadPolicy,
    digest: String,
}

impl BaselineChangePlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn changes(&self) -> &[PlannedBaselineChange] {
        &self.changes
    }

    pub const fn reload_policy(&self) -> BaselineReloadPolicy {
        self.reload_policy
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BaselineChangeState {
    Applied,
    Restored,
}

impl BaselineChangeState {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Applied => "已应用",
            Self::Restored => "已恢复",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineChangeRecord {
    pub id: String,
    pub operation_id: String,
    pub last_operation_id: String,
    pub target: TargetIdentity,
    pub changes: Vec<PlannedBaselineChange>,
    pub files: Vec<String>,
    pub backups: Vec<BaselineBackupEvidence>,
    pub remote_root: String,
    pub reload_policy: BaselineReloadPolicy,
    pub digest: String,
    pub state: BaselineChangeState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineBackupEvidence {
    pub file: String,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BaselineRestorePlan {
    operation: OperationPlan,
    record: BaselineChangeRecord,
}

impl BaselineRestorePlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn record(&self) -> &BaselineChangeRecord {
        &self.record
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineOperationOutcome {
    pub record: BaselineChangeRecord,
    pub verification: VerificationResult,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct StoredBaselineHistory {
    changes: Vec<BaselineChangeRecord>,
}

#[derive(Debug, Clone)]
pub struct BaselineService {
    ssh: SshService,
    target: Arc<TargetContext>,
    store: PortableStore,
    journal: PortableOperationJournal,
    lock: Arc<Mutex<()>>,
}

impl BaselineService {
    pub fn new(
        ssh: SshService,
        target: Arc<TargetContext>,
        store: PortableStore,
        journal: PortableOperationJournal,
    ) -> Self {
        Self {
            ssh,
            target,
            store,
            journal,
            lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn catalog(&self) -> &'static [BaselineDefinition] {
        BASELINE_CATALOG
    }

    pub async fn scan(&self, session: &BoundSshSession) -> CoreResult<BaselineScan> {
        self.target.validate(session.target())?;
        let output = successful_output(
            "scan baseline configuration",
            self.ssh
                .execute_bound(session, scan_command(), COMMAND_TIMEOUT)
                .await?,
        )?;
        let statuses = parse_scan(&output)?;
        self.target.validate(session.target())?;
        Ok(BaselineScan {
            target: session.target().clone(),
            statuses,
            captured_at: Utc::now(),
        })
    }

    pub async fn plan_changes(
        &self,
        session: &BoundSshSession,
        requests: Vec<BaselineChangeRequest>,
        reload_policy: BaselineReloadPolicy,
    ) -> CoreResult<BaselineChangePlan> {
        if requests.is_empty() || requests.len() > MAX_CHANGES {
            return Err(CoreError::validation(
                "baseline changes",
                format!("must contain 1..={MAX_CHANGES} items"),
            ));
        }
        let mut seen = BTreeSet::new();
        for request in &requests {
            if !seen.insert(request.item_id.clone()) {
                return Err(CoreError::validation(
                    "baseline changes",
                    "duplicate item id",
                ));
            }
            let definition = definition(&request.item_id)?;
            let normalized = normalize_requested_value(definition, &request.value)?;
            if normalized != request.value {
                return Err(CoreError::validation(
                    "baseline value",
                    "request value is not canonical",
                ));
            }
        }

        let scan = self.scan(session).await?;
        let by_id = scan
            .statuses
            .into_iter()
            .map(|status| (status.item_id.clone(), status))
            .collect::<BTreeMap<_, _>>();
        let mut changes = Vec::new();
        for request in requests {
            let status = by_id
                .get(&request.item_id)
                .ok_or_else(|| CoreError::NotFound {
                    entity: "baseline status",
                    id: request.item_id.clone(),
                })?;
            if status.observed == BaselineObservedValue::Unsupported {
                return Err(CoreError::validation(
                    "baseline file",
                    format!("{} is not a regular managed file", request.item_id),
                ));
            }
            if status.observed == BaselineObservedValue::Value(request.value.clone()) {
                continue;
            }
            changes.push(PlannedBaselineChange {
                item_id: request.item_id,
                before: status.observed.clone(),
                after: request.value,
            });
        }
        if changes.is_empty() {
            return Err(CoreError::validation(
                "baseline changes",
                "all requested values already match",
            ));
        }

        let files = files_for_changes(&changes)?;
        let change_id = Uuid::new_v4().to_string();
        let remote_root = expected_remote_root(&change_id)?;
        let digest = change_digest(&changes, &files, reload_policy)?;
        let mut operation = OperationPlan::new(
            session.target().clone(),
            format!(
                "应用 {} 项 Linux 安全基线（{}）",
                changes.len(),
                reload_policy.label()
            ),
            true,
            Some("从受管备份恢复全部配置文件并读回验证".to_owned()),
        )?;
        operation
            .metadata
            .insert("source".to_owned(), "baseline".to_owned());
        operation.metadata.insert("change_id".to_owned(), change_id);
        operation
            .metadata
            .insert("digest".to_owned(), digest.clone());
        Ok(BaselineChangePlan {
            operation,
            changes,
            files,
            remote_root,
            reload_policy,
            digest,
        })
    }

    pub async fn execute_changes(
        &self,
        session: &BoundSshSession,
        plan: BaselineChangePlan,
        confirmation: DangerousConfirmation,
    ) -> CoreResult<BaselineOperationOutcome> {
        validate_change_plan(session, &plan)?;
        let executor = ChangeExecutor {
            service: self,
            session,
            plan: &plan,
        };
        let verification = run_planned_operation(
            &self.target,
            &self.journal,
            plan.operation.clone(),
            confirmation,
            &executor,
        )
        .await?;
        if !verification.passed {
            return Err(CoreError::validation(
                "baseline verification",
                "remote readback differed; managed backups were restored",
            ));
        }
        let change_id = plan
            .operation
            .metadata
            .get("change_id")
            .ok_or_else(|| CoreError::validation("baseline plan", "missing change id"))?;
        Ok(BaselineOperationOutcome {
            record: self.record_by_id(session.target(), change_id)?,
            verification,
        })
    }

    pub fn list_history(&self, target: &TargetGuard) -> CoreResult<Vec<BaselineChangeRecord>> {
        self.target.validate(target)?;
        let _guard = self.lock.lock();
        let mut records = self
            .store
            .read_or_default::<StoredBaselineHistory>(StoreFile::Baseline)?
            .changes
            .into_iter()
            .filter(|record| record.target == target.identity)
            .collect::<Vec<_>>();
        for record in &records {
            validate_record(record)?;
        }
        records.sort_by(|left, right| right.created_at.cmp(&left.created_at));
        Ok(records)
    }

    pub fn plan_restore(
        &self,
        session: &BoundSshSession,
        record_id: &str,
    ) -> CoreResult<BaselineRestorePlan> {
        self.target.validate(session.target())?;
        let record = self.record_by_id(session.target(), record_id)?;
        if record.state != BaselineChangeState::Applied {
            return Err(CoreError::validation(
                "baseline restore",
                "only an applied change can be restored",
            ));
        }
        let mut operation = OperationPlan::new(
            session.target().clone(),
            format!("恢复基线变更 {}（{} 项）", record.id, record.changes.len()),
            true,
            Some("重新应用该记录中的基线值".to_owned()),
        )?;
        operation
            .metadata
            .insert("source".to_owned(), "baseline-restore".to_owned());
        operation
            .metadata
            .insert("record_id".to_owned(), record.id.clone());
        operation
            .metadata
            .insert("digest".to_owned(), record.digest.clone());
        Ok(BaselineRestorePlan { operation, record })
    }

    pub async fn execute_restore(
        &self,
        session: &BoundSshSession,
        plan: BaselineRestorePlan,
        confirmation: DangerousConfirmation,
    ) -> CoreResult<BaselineOperationOutcome> {
        validate_restore_plan(session, &plan)?;
        let executor = RestoreExecutor {
            service: self,
            session,
            plan: &plan,
        };
        let verification = run_planned_operation(
            &self.target,
            &self.journal,
            plan.operation.clone(),
            confirmation,
            &executor,
        )
        .await?;
        if !verification.passed {
            return Err(CoreError::validation(
                "baseline restore verification",
                "restored files did not match the recorded values",
            ));
        }
        Ok(BaselineOperationOutcome {
            record: self.record_by_id(session.target(), &plan.record.id)?,
            verification,
        })
    }

    fn insert_record(&self, record: BaselineChangeRecord) -> CoreResult<()> {
        validate_record(&record)?;
        let _guard = self.lock.lock();
        let mut stored = self
            .store
            .read_or_default::<StoredBaselineHistory>(StoreFile::Baseline)?;
        if stored.changes.iter().any(|item| item.id == record.id) {
            return Err(CoreError::validation(
                "baseline record",
                "record identity already exists",
            ));
        }
        stored.changes.push(record);
        if stored.changes.len() > MAX_HISTORY {
            stored.changes.sort_by_key(|item| item.created_at);
            stored.changes.drain(..stored.changes.len() - MAX_HISTORY);
        }
        self.store.write(StoreFile::Baseline, &stored)
    }

    fn record_by_id(
        &self,
        target: &TargetGuard,
        record_id: &str,
    ) -> CoreResult<BaselineChangeRecord> {
        validate_uuid("baseline record id", record_id)?;
        let _guard = self.lock.lock();
        let record = self
            .store
            .read_or_default::<StoredBaselineHistory>(StoreFile::Baseline)?
            .changes
            .into_iter()
            .find(|record| record.id == record_id && record.target == target.identity)
            .ok_or_else(|| CoreError::NotFound {
                entity: "baseline record",
                id: record_id.to_owned(),
            })?;
        validate_record(&record)?;
        Ok(record)
    }

    fn transition_record(
        &self,
        record_id: &str,
        target: &TargetIdentity,
        expected: BaselineChangeState,
        next: BaselineChangeState,
        operation_id: &str,
    ) -> CoreResult<BaselineChangeRecord> {
        validate_uuid("baseline operation id", operation_id)?;
        let _guard = self.lock.lock();
        let mut stored = self
            .store
            .read_or_default::<StoredBaselineHistory>(StoreFile::Baseline)?;
        let record = stored
            .changes
            .iter_mut()
            .find(|record| record.id == record_id && &record.target == target)
            .ok_or_else(|| CoreError::NotFound {
                entity: "baseline record",
                id: record_id.to_owned(),
            })?;
        validate_record(record)?;
        if record.state != expected {
            return Err(CoreError::validation(
                "baseline record state",
                format!(
                    "expected {}, found {}",
                    expected.label(),
                    record.state.label()
                ),
            ));
        }
        record.state = next;
        record.last_operation_id = operation_id.to_owned();
        record.updated_at = Utc::now();
        let result = record.clone();
        self.store.write(StoreFile::Baseline, &stored)?;
        Ok(result)
    }
}

#[derive(Debug)]
struct ChangeExecutor<'a> {
    service: &'a BaselineService,
    session: &'a BoundSshSession,
    plan: &'a BaselineChangePlan,
}

#[async_trait]
impl OperationExecutor for ChangeExecutor<'_> {
    async fn execute(&self, definition: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        ensure_same_plan(definition, &self.plan.operation, "baseline change")?;
        let output = successful_marker(
            "apply baseline changes",
            self.service
                .ssh
                .execute_bound(self.session, apply_command(self.plan)?, COMMAND_TIMEOUT)
                .await?,
            APPLY_MARKER,
        )?;
        let backups = parse_backup_evidence(&output, &self.plan.files)?;
        let change_id = self
            .plan
            .operation
            .metadata
            .get("change_id")
            .ok_or_else(|| CoreError::validation("baseline plan", "missing change id"))?;
        let now = Utc::now();
        let record = BaselineChangeRecord {
            id: change_id.clone(),
            operation_id: self.plan.operation.id.clone(),
            last_operation_id: self.plan.operation.id.clone(),
            target: self.session.target().identity.clone(),
            changes: self.plan.changes.clone(),
            files: self.plan.files.clone(),
            backups: backups.clone(),
            remote_root: self.plan.remote_root.clone(),
            reload_policy: self.plan.reload_policy,
            digest: record_digest(
                &self.plan.changes,
                &self.plan.files,
                &backups,
                self.plan.reload_policy,
            )?,
            state: BaselineChangeState::Applied,
            created_at: now,
            updated_at: now,
        };
        if let Err(error) = self.service.insert_record(record) {
            let _ = self
                .service
                .ssh
                .execute_bound(
                    self.session,
                    restore_command_for_change(self.plan, &backups)?,
                    COMMAND_TIMEOUT,
                )
                .await;
            return Err(error);
        }
        Ok(ExecutionReceipt {
            summary: format!(
                "applied {} typed baseline changes; backup {}",
                self.plan.changes.len(),
                self.plan.remote_root
            ),
            restore_token: Some(serde_json::to_string(&backups).map_err(|source| {
                CoreError::Encode {
                    subject: "baseline backup evidence",
                    source,
                }
            })?),
        })
    }

    async fn verify(
        &self,
        definition: &OperationPlan,
        _: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        ensure_same_plan(definition, &self.plan.operation, "baseline change")?;
        let scan = self.service.scan(self.session).await?;
        Ok(verify_expected(&scan.statuses, &self.plan.changes, false))
    }

    async fn restore(
        &self,
        definition: &OperationPlan,
        receipt: &ExecutionReceipt,
    ) -> CoreResult<()> {
        ensure_same_plan(definition, &self.plan.operation, "baseline change")?;
        let backups = serde_json::from_str::<Vec<BaselineBackupEvidence>>(
            receipt.restore_token.as_deref().ok_or_else(|| {
                CoreError::validation("baseline restore", "missing backup evidence")
            })?,
        )
        .map_err(|source| CoreError::Decode {
            subject: "baseline backup evidence",
            source,
        })?;
        validate_backups(&self.plan.files, &backups)?;
        successful_marker(
            "restore failed baseline changes",
            self.service
                .ssh
                .execute_bound(
                    self.session,
                    restore_command_for_change(self.plan, &backups)?,
                    COMMAND_TIMEOUT,
                )
                .await?,
            RESTORE_MARKER,
        )?;
        let change_id = self
            .plan
            .operation
            .metadata
            .get("change_id")
            .ok_or_else(|| CoreError::validation("baseline plan", "missing change id"))?;
        self.service.transition_record(
            change_id,
            &self.session.target().identity,
            BaselineChangeState::Applied,
            BaselineChangeState::Restored,
            &self.plan.operation.id,
        )?;
        Ok(())
    }
}

#[derive(Debug)]
struct RestoreExecutor<'a> {
    service: &'a BaselineService,
    session: &'a BoundSshSession,
    plan: &'a BaselineRestorePlan,
}

#[async_trait]
impl OperationExecutor for RestoreExecutor<'_> {
    async fn execute(&self, definition: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        ensure_same_plan(definition, &self.plan.operation, "baseline restore")?;
        successful_marker(
            "restore baseline history",
            self.service
                .ssh
                .execute_bound(
                    self.session,
                    restore_command_for_record(&self.plan.record)?,
                    COMMAND_TIMEOUT,
                )
                .await?,
            RESTORE_MARKER,
        )?;
        self.service.transition_record(
            &self.plan.record.id,
            &self.plan.record.target,
            BaselineChangeState::Applied,
            BaselineChangeState::Restored,
            &self.plan.operation.id,
        )?;
        Ok(ExecutionReceipt {
            summary: format!("restored baseline backup {}", self.plan.record.remote_root),
            restore_token: Some(self.plan.record.id.clone()),
        })
    }

    async fn verify(
        &self,
        definition: &OperationPlan,
        _: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        ensure_same_plan(definition, &self.plan.operation, "baseline restore")?;
        let scan = self.service.scan(self.session).await?;
        Ok(verify_expected(
            &scan.statuses,
            &self.plan.record.changes,
            true,
        ))
    }

    async fn restore(&self, definition: &OperationPlan, _: &ExecutionReceipt) -> CoreResult<()> {
        ensure_same_plan(definition, &self.plan.operation, "baseline restore")?;
        successful_marker(
            "reapply baseline after failed restore",
            self.service
                .ssh
                .execute_bound(
                    self.session,
                    reapply_command(&self.plan.record)?,
                    COMMAND_TIMEOUT,
                )
                .await?,
            REAPPLY_MARKER,
        )?;
        self.service.transition_record(
            &self.plan.record.id,
            &self.plan.record.target,
            BaselineChangeState::Restored,
            BaselineChangeState::Applied,
            &self.plan.operation.id,
        )?;
        Ok(())
    }
}

async fn run_planned_operation(
    target: &TargetContext,
    journal: &dyn OperationJournal,
    definition: OperationPlan,
    confirmation: DangerousConfirmation,
    executor: &dyn OperationExecutor,
) -> CoreResult<VerificationResult> {
    let mut operation = PlannedOperation::plan(definition);
    operation.confirm(confirmation)?;
    let execution = operation.execute(target, executor).await;
    if matches!(
        operation.state(),
        OperationState::Executed | OperationState::StaleAfterExecution
    ) {
        operation.journal(journal)?;
    }
    execution?;
    let verification = operation.verify(target, executor, journal).await;
    match verification {
        Ok(result) if result.passed => Ok(result),
        Ok(result) => {
            operation.restore(target, executor, journal).await?;
            Ok(result)
        }
        Err(error) => {
            if matches!(operation.state(), OperationState::VerificationFailed) {
                let _ = operation.restore(target, executor, journal).await;
            }
            Err(error)
        }
    }
}

pub fn definition(item_id: &str) -> CoreResult<&'static BaselineDefinition> {
    BASELINE_CATALOG
        .iter()
        .find(|definition| definition.id == item_id)
        .ok_or_else(|| CoreError::NotFound {
            entity: "baseline item",
            id: item_id.to_owned(),
        })
}

fn normalize_requested_value(definition: &BaselineDefinition, value: &str) -> CoreResult<String> {
    let value = value.trim();
    match definition.value_kind {
        BaselineValueKind::Choice(choices) => {
            let normalized = value.to_ascii_lowercase();
            if choices.contains(&normalized.as_str()) {
                Ok(normalized)
            } else {
                Err(CoreError::validation(
                    "baseline value",
                    format!("{} accepts only {}", definition.id, choices.join(", ")),
                ))
            }
        }
        BaselineValueKind::Integer { minimum, maximum } => {
            let number = value.parse::<u32>().map_err(|_| {
                CoreError::validation("baseline value", "must be a non-negative integer")
            })?;
            if !(minimum..=maximum).contains(&number) {
                return Err(CoreError::validation(
                    "baseline value",
                    format!("must be in {minimum}..={maximum}"),
                ));
            }
            Ok(number.to_string())
        }
    }
}

fn validate_observed(value: &BaselineObservedValue) -> CoreResult<()> {
    if let BaselineObservedValue::Value(value) = value
        && (value.is_empty()
            || value.len() > 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')))
    {
        return Err(CoreError::validation(
            "baseline observed value",
            "must be a bounded inert token",
        ));
    }
    Ok(())
}

fn scan_command() -> String {
    let mut command = format!("set -u; printf '%s\\n' {SCAN_MARKER}; ");
    for definition in BASELINE_CATALOG {
        command.push_str(&format!(
            "lr_file={file}; lr_key={key}; lr_value=__missing__; \
             if [ -L \"$lr_file\" ] || {{ [ -e \"$lr_file\" ] && [ ! -f \"$lr_file\" ]; }}; then \
               lr_value=__unsupported__; \
             elif [ -f \"$lr_file\" ]; then \
               lr_value=$(awk -v k=\"$lr_key\" 'BEGIN{{v=\"\"}} {{p=$0; sub(/^[[:space:]]*#[[:space:]]*/,\"\",p); t=p; sub(/[[:space:]=].*$/,\"\",t); if(tolower(t)==tolower(k)){{sub(/^[^[:space:]=]+[[:space:]=]+/,\"\",p); gsub(/^[[:space:]]+|[[:space:]]+$/,\"\",p); v=p}}}} END{{print v}}' \"$lr_file\" | tail -n 1); \
               lr_value=$(printf '%s' \"$lr_value\" | tr -cd 'A-Za-z0-9_-'); [ -n \"$lr_value\" ] || lr_value=__missing__; \
             fi; printf 'ITEM=%s\\t%s\\n' {id} \"$lr_value\"; ",
            file = shq(definition.file),
            key = shq(definition.key),
            id = shq(definition.id),
        ));
    }
    command
}

fn parse_scan(output: &str) -> CoreResult<Vec<BaselineStatus>> {
    if !output.lines().any(|line| line.trim() == SCAN_MARKER) {
        return Err(CoreError::validation(
            "baseline scan",
            "missing typed scan marker",
        ));
    }
    let mut values = BTreeMap::new();
    for line in output.lines().filter(|line| line.starts_with("ITEM=")) {
        let Some((item_id, value)) = line[5..].split_once('\t') else {
            return Err(CoreError::validation("baseline scan", "invalid item row"));
        };
        definition(item_id)?;
        let observed = match value {
            "__missing__" => BaselineObservedValue::Missing,
            "__unsupported__" => BaselineObservedValue::Unsupported,
            value => BaselineObservedValue::Value(value.to_owned()),
        };
        validate_observed(&observed)?;
        if values.insert(item_id.to_owned(), observed).is_some() {
            return Err(CoreError::validation("baseline scan", "duplicate item row"));
        }
    }
    if values.len() != BASELINE_CATALOG.len() {
        return Err(CoreError::validation(
            "baseline scan",
            "scan did not return the complete catalog",
        ));
    }
    BASELINE_CATALOG
        .iter()
        .map(|definition| {
            let observed = values
                .remove(definition.id)
                .ok_or_else(|| CoreError::validation("baseline scan", "missing item row"))?;
            let compliant = match &observed {
                BaselineObservedValue::Value(value) => normalize_requested_value(definition, value)
                    .is_ok_and(|value| value == definition.recommendation),
                BaselineObservedValue::Missing | BaselineObservedValue::Unsupported => false,
            };
            Ok(BaselineStatus {
                item_id: definition.id.to_owned(),
                observed,
                compliant,
            })
        })
        .collect()
}

fn parse_backup_evidence(
    output: &str,
    files: &[String],
) -> CoreResult<Vec<BaselineBackupEvidence>> {
    let mut evidence = BTreeMap::new();
    for line in output.lines().filter(|line| line.starts_with("BACKUP=")) {
        let Some((index, value)) = line[7..].split_once('\t') else {
            return Err(CoreError::validation(
                "baseline backup evidence",
                "invalid evidence row",
            ));
        };
        let index = index
            .parse::<usize>()
            .map_err(|_| CoreError::validation("baseline backup evidence", "invalid file index"))?;
        let file = files.get(index).ok_or_else(|| {
            CoreError::validation("baseline backup evidence", "file index is out of bounds")
        })?;
        let sha256 = if value == "__missing__" {
            None
        } else {
            let value = value.to_ascii_lowercase();
            if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(CoreError::validation(
                    "baseline backup evidence",
                    "invalid SHA-256 digest",
                ));
            }
            Some(value)
        };
        if evidence
            .insert(
                index,
                BaselineBackupEvidence {
                    file: file.clone(),
                    sha256,
                },
            )
            .is_some()
        {
            return Err(CoreError::validation(
                "baseline backup evidence",
                "duplicate file index",
            ));
        }
    }
    if evidence.len() != files.len() {
        return Err(CoreError::validation(
            "baseline backup evidence",
            "missing file evidence",
        ));
    }
    let backups = (0..files.len())
        .map(|index| {
            evidence.remove(&index).ok_or_else(|| {
                CoreError::validation("baseline backup evidence", "missing ordered evidence")
            })
        })
        .collect::<CoreResult<Vec<_>>>()?;
    validate_backups(files, &backups)?;
    Ok(backups)
}

fn files_for_changes(changes: &[PlannedBaselineChange]) -> CoreResult<Vec<String>> {
    let mut files = BTreeSet::new();
    for change in changes {
        files.insert(definition(&change.item_id)?.file.to_owned());
    }
    Ok(files.into_iter().collect())
}

fn change_digest(
    changes: &[PlannedBaselineChange],
    files: &[String],
    reload_policy: BaselineReloadPolicy,
) -> CoreResult<String> {
    let encoded = serde_json::to_vec(&(changes, files, reload_policy)).map_err(|source| {
        CoreError::Encode {
            subject: "baseline change digest",
            source,
        }
    })?;
    Ok(sha256_hex(encoded))
}

fn record_digest(
    changes: &[PlannedBaselineChange],
    files: &[String],
    backups: &[BaselineBackupEvidence],
    reload_policy: BaselineReloadPolicy,
) -> CoreResult<String> {
    let encoded =
        serde_json::to_vec(&(changes, files, backups, reload_policy)).map_err(|source| {
            CoreError::Encode {
                subject: "baseline record digest",
                source,
            }
        })?;
    Ok(sha256_hex(encoded))
}

fn sha256_hex(bytes: impl AsRef<[u8]>) -> String {
    format!("{:x}", Sha256::digest(bytes.as_ref()))
}

fn expected_remote_root(id: &str) -> CoreResult<String> {
    validate_uuid("baseline change id", id)?;
    Ok(format!("{BASELINE_ROOT}/{id}"))
}

fn validate_change_plan(session: &BoundSshSession, plan: &BaselineChangePlan) -> CoreResult<()> {
    if &plan.operation.target != session.target() {
        return Err(CoreError::validation(
            "baseline plan",
            "plan target does not match the bound SSH session",
        ));
    }
    let change_id = plan
        .operation
        .metadata
        .get("change_id")
        .ok_or_else(|| CoreError::validation("baseline plan", "missing change id"))?;
    if plan.remote_root != expected_remote_root(change_id)? {
        return Err(CoreError::validation(
            "baseline plan",
            "remote backup namespace is not canonical",
        ));
    }
    if plan.files != files_for_changes(&plan.changes)?
        || plan.digest != change_digest(&plan.changes, &plan.files, plan.reload_policy)?
        || plan.operation.metadata.get("digest") != Some(&plan.digest)
    {
        return Err(CoreError::validation(
            "baseline plan",
            "immutable plan digest mismatch",
        ));
    }
    validate_changes(&plan.changes)
}

fn validate_restore_plan(session: &BoundSshSession, plan: &BaselineRestorePlan) -> CoreResult<()> {
    if &plan.operation.target != session.target() || plan.record.target != session.target().identity
    {
        return Err(CoreError::validation(
            "baseline restore plan",
            "record target does not match the bound SSH session",
        ));
    }
    validate_record(&plan.record)?;
    if plan.record.state != BaselineChangeState::Applied
        || plan.operation.metadata.get("record_id") != Some(&plan.record.id)
        || plan.operation.metadata.get("digest") != Some(&plan.record.digest)
    {
        return Err(CoreError::validation(
            "baseline restore plan",
            "immutable record binding mismatch",
        ));
    }
    Ok(())
}

fn validate_record(record: &BaselineChangeRecord) -> CoreResult<()> {
    validate_uuid("baseline record id", &record.id)?;
    validate_uuid("baseline operation id", &record.operation_id)?;
    validate_uuid("baseline last operation id", &record.last_operation_id)?;
    if record.remote_root != expected_remote_root(&record.id)? {
        return Err(CoreError::validation(
            "baseline record",
            "remote backup namespace is not canonical",
        ));
    }
    validate_changes(&record.changes)?;
    validate_backups(&record.files, &record.backups)?;
    if record.files != files_for_changes(&record.changes)?
        || record.digest
            != record_digest(
                &record.changes,
                &record.files,
                &record.backups,
                record.reload_policy,
            )?
    {
        return Err(CoreError::validation(
            "baseline record",
            "record digest mismatch",
        ));
    }
    Ok(())
}

fn validate_changes(changes: &[PlannedBaselineChange]) -> CoreResult<()> {
    if changes.is_empty() || changes.len() > MAX_CHANGES {
        return Err(CoreError::validation(
            "baseline changes",
            "invalid change count",
        ));
    }
    let mut ids = BTreeSet::new();
    for change in changes {
        if !ids.insert(change.item_id.clone()) {
            return Err(CoreError::validation(
                "baseline changes",
                "duplicate item id",
            ));
        }
        let definition = definition(&change.item_id)?;
        if normalize_requested_value(definition, &change.after)? != change.after {
            return Err(CoreError::validation(
                "baseline changes",
                "non-canonical requested value",
            ));
        }
        validate_observed(&change.before)?;
    }
    Ok(())
}

fn validate_backups(files: &[String], backups: &[BaselineBackupEvidence]) -> CoreResult<()> {
    if files.len() != backups.len() {
        return Err(CoreError::validation(
            "baseline backups",
            "evidence count does not match file count",
        ));
    }
    for (file, backup) in files.iter().zip(backups) {
        validate_catalog_file(file)?;
        if &backup.file != file {
            return Err(CoreError::validation(
                "baseline backups",
                "evidence order does not match the immutable file list",
            ));
        }
        if let Some(sha256) = &backup.sha256
            && (sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return Err(CoreError::validation(
                "baseline backup hash",
                "must be a SHA-256 hex digest",
            ));
        }
    }
    Ok(())
}

fn apply_command(plan: &BaselineChangePlan) -> CoreResult<String> {
    validate_changes(&plan.changes)?;
    let mut command = backup_prelude(&plan.remote_root, &plan.files)?;
    command.push_str("lr_done=0; lr_restore() { ");
    command.push_str(&restore_body_unchecked(&plan.remote_root, &plan.files)?);
    command.push_str("; }; trap 'lr_status=$?; if [ \"$lr_done\" != 1 ]; then lr_restore; fi; exit \"$lr_status\"' 0; ");
    for (index, change) in plan.changes.iter().enumerate() {
        command.push_str(&edit_body(change, &plan.remote_root, index)?);
    }
    command.push_str(&configuration_validation(
        &plan.changes,
        plan.reload_policy,
    )?);
    command.push_str(&format!(
        "lr_done=1; trap - 0; printf '%s\\n' {APPLY_MARKER}"
    ));
    Ok(command)
}

fn backup_prelude(remote_root: &str, files: &[String]) -> CoreResult<String> {
    validate_remote_root(remote_root)?;
    let mut command = format!(
        "set -eu; umask 077; lr_parent={parent}; lr_root={root}; \
         if [ -L \"$lr_parent\" ] || {{ [ -e \"$lr_parent\" ] && [ ! -d \"$lr_parent\" ]; }}; then echo 'invalid baseline parent' >&2; exit 40; fi; \
         install -d -m 0700 -- \"$lr_parent\"; [ ! -e \"$lr_root\" ] || {{ echo 'baseline backup already exists' >&2; exit 40; }}; mkdir -- \"$lr_root\"; chmod 700 -- \"$lr_root\"; ",
        parent = shq(BASELINE_ROOT),
        root = shq(remote_root)
    );
    for (index, file) in files.iter().enumerate() {
        validate_catalog_file(file)?;
        command.push_str(&format!(
            "lr_file={file}; if [ -L \"$lr_file\" ] || {{ [ -e \"$lr_file\" ] && [ ! -f \"$lr_file\" ]; }}; then echo 'unsupported baseline file' >&2; exit 41; \
             elif [ -f \"$lr_file\" ]; then cp -p -- \"$lr_file\" {backup}; printf existing > {state}; \
               lr_hash=$(sha256sum -- {backup} 2>/dev/null | awk '{{print $1}}'); [ -n \"$lr_hash\" ] || lr_hash=$(busybox sha256sum {backup} 2>/dev/null | awk '{{print $1}}'); printf 'BACKUP=%s\\t%s\\n' {index} \"$lr_hash\"; \
             else printf missing > {state}; printf 'BACKUP=%s\\t%s\\n' {index} __missing__; fi; ",
            file = shq(file),
            backup = shq(&format!("{remote_root}/file-{index}.before")),
            state = shq(&format!("{remote_root}/file-{index}.state")),
            index = shq(&index.to_string()),
        ));
    }
    Ok(command)
}

fn edit_body(
    change: &PlannedBaselineChange,
    remote_root: &str,
    index: usize,
) -> CoreResult<String> {
    let definition = definition(&change.item_id)?;
    if normalize_requested_value(definition, &change.after)? != change.after {
        return Err(CoreError::validation(
            "baseline change",
            "non-canonical value reached command builder",
        ));
    }
    let separator = match definition.format {
        FileFormat::Whitespace => "space",
        FileFormat::Equals => "equals",
    };
    let temporary = format!("{remote_root}/edit-{index}.tmp");
    Ok(format!(
        "lr_file={file}; lr_key={key}; lr_value={value}; lr_sep={separator}; lr_tmp={temporary}; \
         lr_source=/dev/null; [ -f \"$lr_file\" ] && lr_source=\"$lr_file\"; \
         awk -v k=\"$lr_key\" -v v=\"$lr_value\" -v s=\"$lr_sep\" 'BEGIN{{done=0}} {{line=$0; p=$0; sub(/^[[:space:]]*#[[:space:]]*/,\"\",p); t=p; sub(/[[:space:]=].*$/,\"\",t); if(!done && tolower(t)==tolower(k)){{if(s==\"equals\") print k \" = \" v; else print k \" \" v; done=1}} else print line}} END{{if(!done){{if(s==\"equals\") print k \" = \" v; else print k \" \" v}}}}' \"$lr_source\" > \"$lr_tmp\"; \
         if [ -f \"$lr_file\" ]; then cat -- \"$lr_tmp\" > \"$lr_file\"; else mkdir -p -- \"$(dirname -- \"$lr_file\")\"; install -m 0644 -- \"$lr_tmp\" \"$lr_file\"; fi; rm -f -- \"$lr_tmp\"; ",
        file = shq(definition.file),
        key = shq(definition.key),
        value = shq(&change.after),
        separator = shq(separator),
        temporary = shq(&temporary),
    ))
}

fn configuration_validation(
    changes: &[PlannedBaselineChange],
    reload_policy: BaselineReloadPolicy,
) -> CoreResult<String> {
    let groups = changes
        .iter()
        .map(|change| definition(&change.item_id).map(|definition| definition.reload))
        .collect::<CoreResult<BTreeSet<_>>>()?;
    let mut command = String::new();
    if groups.contains(&ReloadGroup::Sshd) {
        command.push_str(
            "if command -v sshd >/dev/null 2>&1; then sshd -t -f /etc/ssh/sshd_config; fi; ",
        );
    }
    if reload_policy == BaselineReloadPolicy::ApplyNow {
        if groups.contains(&ReloadGroup::Sysctl) {
            command.push_str("sysctl -p /etc/sysctl.d/99-lovelyres-baseline.conf >/dev/null; ");
        }
        if groups.contains(&ReloadGroup::Sshd) {
            command.push_str("systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || service sshd reload 2>/dev/null || service ssh reload 2>/dev/null; ");
        }
    }
    Ok(command)
}

fn restore_body_unchecked(remote_root: &str, files: &[String]) -> CoreResult<String> {
    validate_remote_root(remote_root)?;
    let mut command = String::new();
    for (index, file) in files.iter().enumerate() {
        validate_catalog_file(file)?;
        command.push_str(&format!(
            "lr_state={state}; lr_backup={backup}; lr_file={file}; \
             if [ -f \"$lr_state\" ] && grep -qx existing \"$lr_state\"; then [ -f \"$lr_backup\" ] && cp -p -- \"$lr_backup\" \"$lr_file\"; \
             elif [ -f \"$lr_state\" ] && grep -qx missing \"$lr_state\"; then rm -f -- \"$lr_file\"; fi; ",
            state = shq(&format!("{remote_root}/file-{index}.state")),
            backup = shq(&format!("{remote_root}/file-{index}.before")),
            file = shq(file),
        ));
    }
    Ok(command)
}

fn restore_body_verified(
    remote_root: &str,
    backups: &[BaselineBackupEvidence],
) -> CoreResult<String> {
    validate_remote_root(remote_root)?;
    let files = backups
        .iter()
        .map(|backup| backup.file.clone())
        .collect::<Vec<_>>();
    validate_backups(&files, backups)?;
    let mut command = String::new();
    for (index, backup) in backups.iter().enumerate() {
        let state_path = format!("{remote_root}/file-{index}.state");
        let backup_path = format!("{remote_root}/file-{index}.before");
        match &backup.sha256 {
            Some(expected) => command.push_str(&format!(
                "lr_state={state}; lr_backup={backup}; lr_file={file}; [ -f \"$lr_state\" ] && grep -qx existing \"$lr_state\"; [ -f \"$lr_backup\" ] && [ ! -L \"$lr_backup\" ]; \
                 lr_hash=$(sha256sum -- \"$lr_backup\" 2>/dev/null | awk '{{print $1}}'); [ -n \"$lr_hash\" ] || lr_hash=$(busybox sha256sum \"$lr_backup\" 2>/dev/null | awk '{{print $1}}'); [ \"$lr_hash\" = {expected} ]; cp -p -- \"$lr_backup\" \"$lr_file\"; ",
                state = shq(&state_path),
                backup = shq(&backup_path),
                file = shq(&backup.file),
                expected = shq(expected),
            )),
            None => command.push_str(&format!(
                "lr_state={state}; lr_file={file}; [ -f \"$lr_state\" ] && grep -qx missing \"$lr_state\"; rm -f -- \"$lr_file\"; ",
                state = shq(&state_path),
                file = shq(&backup.file),
            )),
        }
    }
    Ok(command)
}

fn restore_command_for_change(
    plan: &BaselineChangePlan,
    backups: &[BaselineBackupEvidence],
) -> CoreResult<String> {
    let mut command = format!("set -eu; lr_root={}; ", shq(&plan.remote_root));
    validate_backups(&plan.files, backups)?;
    command.push_str(&restore_body_verified(&plan.remote_root, backups)?);
    command.push_str(&configuration_validation(
        &plan.changes,
        plan.reload_policy,
    )?);
    command.push_str(&format!("printf '%s\\n' {RESTORE_MARKER}"));
    Ok(command)
}

fn restore_command_for_record(record: &BaselineChangeRecord) -> CoreResult<String> {
    validate_record(record)?;
    let mut command = format!("set -eu; lr_root={}; ", shq(&record.remote_root));
    command.push_str(&restore_body_verified(
        &record.remote_root,
        &record.backups,
    )?);
    command.push_str(&configuration_validation(
        &record.changes,
        record.reload_policy,
    )?);
    command.push_str(&format!("printf '%s\\n' {RESTORE_MARKER}"));
    Ok(command)
}

fn reapply_command(record: &BaselineChangeRecord) -> CoreResult<String> {
    validate_record(record)?;
    let mut command = "set -eu; ".to_owned();
    for (index, change) in record.changes.iter().enumerate() {
        command.push_str(&edit_body(change, &record.remote_root, index)?);
    }
    command.push_str(&configuration_validation(
        &record.changes,
        record.reload_policy,
    )?);
    command.push_str(&format!("printf '%s\\n' {REAPPLY_MARKER}"));
    Ok(command)
}

fn verify_expected(
    statuses: &[BaselineStatus],
    changes: &[PlannedBaselineChange],
    before: bool,
) -> VerificationResult {
    let by_id = statuses
        .iter()
        .map(|status| (status.item_id.as_str(), &status.observed))
        .collect::<BTreeMap<_, _>>();
    let mismatches = changes
        .iter()
        .filter_map(|change| {
            let expected = if before {
                change.before.clone()
            } else {
                BaselineObservedValue::Value(change.after.clone())
            };
            (by_id.get(change.item_id.as_str()).copied() != Some(&expected)).then_some(format!(
                "{} expected {}, observed {}",
                change.item_id,
                expected.label(),
                by_id
                    .get(change.item_id.as_str())
                    .map_or("missing scan row", |value| value.label())
            ))
        })
        .collect::<Vec<_>>();
    VerificationResult {
        passed: mismatches.is_empty(),
        detail: if mismatches.is_empty() {
            format!(
                "verified {} baseline values by remote readback",
                changes.len()
            )
        } else {
            mismatches.join("; ")
        },
    }
}

fn validate_remote_root(remote_root: &str) -> CoreResult<()> {
    let id = remote_root
        .strip_prefix(&format!("{BASELINE_ROOT}/"))
        .ok_or_else(|| {
            CoreError::validation("baseline remote root", "outside managed namespace")
        })?;
    if remote_root != expected_remote_root(id)? {
        return Err(CoreError::validation(
            "baseline remote root",
            "non-canonical managed namespace",
        ));
    }
    Ok(())
}

fn validate_catalog_file(file: &str) -> CoreResult<()> {
    if BASELINE_CATALOG
        .iter()
        .any(|definition| definition.file == file)
    {
        Ok(())
    } else {
        Err(CoreError::validation(
            "baseline file",
            "path is not in the closed catalog",
        ))
    }
}

fn ensure_same_plan(
    actual: &OperationPlan,
    expected: &OperationPlan,
    subject: &'static str,
) -> CoreResult<()> {
    if actual.id != expected.id || actual.target != expected.target {
        return Err(CoreError::validation(
            subject,
            "executor received a different immutable plan",
        ));
    }
    Ok(())
}

fn validate_uuid(subject: &'static str, value: &str) -> CoreResult<Uuid> {
    Uuid::parse_str(value).map_err(|_| CoreError::validation(subject, "must be a canonical UUID"))
}

fn successful_output(subject: &'static str, output: SshCommandOutput) -> CoreResult<String> {
    if output.timed_out || output.exit_code != Some(0) {
        return Err(CoreError::ssh(
            subject,
            format!(
                "remote command failed (exit {:?}, timed_out={}): {}",
                output.exit_code,
                output.timed_out,
                compact_output(&output.output)
            ),
        ));
    }
    Ok(output.output)
}

fn successful_marker(
    subject: &'static str,
    output: SshCommandOutput,
    marker: &str,
) -> CoreResult<String> {
    let output = successful_output(subject, output)?;
    if !output.lines().any(|line| line.trim() == marker) {
        return Err(CoreError::validation(subject, "missing completion marker"));
    }
    Ok(output)
}

fn compact_output(output: &str) -> String {
    let mut output = output.replace(['\r', '\n'], " ");
    if output.len() > 512 {
        let mut end = 512;
        while !output.is_char_boundary(end) {
            end -= 1;
        }
        output.truncate(end);
        output.push('…');
    }
    output
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, sync::Arc};

    use super::*;
    use crate::{
        BackendServices,
        detection::DetectionRemediation,
        operations::JournalPhase,
        ssh::{SshConnectionStatus, TestSessionHarness},
    };

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("lovelyres-baseline-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    async fn fixture() -> (
        TestRoot,
        BackendServices,
        BoundSshSession,
        Arc<TestSessionHarness>,
    ) {
        let temp = TestRoot::new();
        let store = PortableStore::prepare(temp.0.clone()).unwrap();
        let services = BackendServices::new(store).unwrap();
        let identity = TargetIdentity::new("baseline-target").unwrap();
        let guard = services.activate_target(identity.clone()).unwrap();
        let status = SshConnectionStatus {
            session_id: "baseline-session".to_owned(),
            connection_id: identity.as_str().to_owned(),
            host: "192.0.2.20".to_owned(),
            port: 22,
            username: "root".to_owned(),
            host_key_fingerprint: "SHA256:baseline".to_owned(),
            connected_at: Utc::now(),
        };
        let harness = Arc::new(TestSessionHarness::default());
        services
            .ssh()
            .install_test_session(status, harness.clone())
            .await
            .unwrap();
        let session = services
            .ssh()
            .bind_session(guard, "baseline-session")
            .await
            .unwrap();
        (temp, services, session, harness)
    }

    fn scan_fixture(overrides: &[(&str, &str)], markers: &[&str]) -> String {
        let overrides = overrides.iter().copied().collect::<BTreeMap<_, _>>();
        let mut output = format!("{SCAN_MARKER}\n");
        for definition in BASELINE_CATALOG {
            let value = overrides
                .get(definition.id)
                .copied()
                .unwrap_or(definition.recommendation);
            output.push_str(&format!("ITEM={}\t{}\n", definition.id, value));
        }
        for marker in markers {
            output.push_str(marker);
            output.push('\n');
            if *marker == APPLY_MARKER {
                output.push_str(&format!("BACKUP=0\t{}\n", "00".repeat(32)));
            }
        }
        output
    }

    #[test]
    fn catalog_is_closed_unique_and_values_are_canonical() {
        let mut ids = BTreeSet::new();
        let mut file_keys = BTreeSet::new();
        for definition in BASELINE_CATALOG {
            assert!(ids.insert(definition.id));
            assert!(file_keys.insert((definition.file, definition.key)));
            assert!(definition.file.starts_with("/etc/"));
            assert!(BaselineCategory::ALL.contains(&definition.category));
            assert!(
                definition.key.len() <= 64
                    && definition.key.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    })
            );
            assert_eq!(
                normalize_requested_value(definition, definition.recommendation).unwrap(),
                definition.recommendation
            );
            match definition.value_kind {
                BaselineValueKind::Choice(choices) => {
                    let mut unique = BTreeSet::new();
                    assert!(!choices.is_empty());
                    for choice in choices {
                        assert!(unique.insert(*choice));
                        assert_eq!(
                            normalize_requested_value(definition, choice).unwrap(),
                            *choice
                        );
                    }
                }
                BaselineValueKind::Integer { minimum, maximum } => {
                    assert!(minimum <= maximum);
                }
            }
            match definition.format {
                FileFormat::Whitespace => assert!(matches!(
                    definition.file,
                    "/etc/ssh/sshd_config" | "/etc/login.defs"
                )),
                FileFormat::Equals => assert!(matches!(
                    definition.file,
                    "/etc/sysctl.d/99-lovelyres-baseline.conf"
                        | "/etc/security/faillock.conf"
                        | "/etc/security/pwquality.conf"
                        | "/etc/audit/auditd.conf"
                )),
            }
        }
        assert_eq!(BASELINE_CATALOG.len(), 38);
        assert!(BASELINE_CATALOG.len() <= MAX_CHANGES);
        for category in BaselineCategory::ALL {
            assert!(
                BASELINE_CATALOG
                    .iter()
                    .filter(|definition| definition.category == category)
                    .count()
                    >= 2,
                "category {category:?} must remain substantive"
            );
        }
        assert!(BaselineChangeRequest::new("ssh-max-auth-tries", "11").is_err());
        assert!(BaselineChangeRequest::new("ssh-permit-root-login", "no;id").is_err());
        assert!(BaselineChangeRequest::new("permissions-default-umask", "0027").is_err());
        assert!(BaselineChangeRequest::new("logging-audit-rotation-action", "exec").is_err());
        assert!(BaselineChangeRequest::new("authentication-password-min-length", "5").is_err());
        assert!(BaselineChangeRequest::new("../../etc/passwd", "x").is_err());
    }

    #[test]
    fn scan_parser_requires_complete_unique_typed_rows() {
        let parsed = parse_scan(&scan_fixture(&[("ssh-permit-root-login", "yes")], &[])).unwrap();
        assert_eq!(parsed.len(), BASELINE_CATALOG.len());
        assert!(!parsed[0].compliant);
        assert!(parse_scan("ITEM=ssh-permit-root-login\tno").is_err());
        let mut duplicate = scan_fixture(&[], &[]);
        duplicate.push_str("ITEM=ssh-permit-root-login\tno\n");
        assert!(parse_scan(&duplicate).is_err());
        let hostile = scan_fixture(&[("ssh-permit-root-login", "no;id")], &[]);
        assert!(parse_scan(&hostile).is_err());

        let normalized = parse_scan(&scan_fixture(
            &[("logging-audit-rotation-action", "ROTATE")],
            &[],
        ))
        .unwrap();
        assert!(
            normalized
                .iter()
                .find(|status| status.item_id == "logging-audit-rotation-action")
                .unwrap()
                .compliant,
            "closed choice values are compared by their canonical form"
        );
    }

    #[test]
    fn expanded_catalog_uses_only_supported_editor_formats() {
        let remote_root = expected_remote_root("6f03708a-40f4-486f-8bf1-ff08e7e25457").unwrap();
        for (item_id, separator) in [
            ("ssh-permit-empty-passwords", "space"),
            ("authentication-login-fail-delay", "space"),
            ("authentication-faillock-deny", "equals"),
            ("authentication-password-min-length", "equals"),
            ("permissions-default-umask", "space"),
            ("kernel-protected-hardlinks", "equals"),
            ("network-tcp-syncookies", "equals"),
            ("logging-audit-rotation-action", "equals"),
        ] {
            let definition = definition(item_id).unwrap();
            let command = edit_body(
                &PlannedBaselineChange {
                    item_id: item_id.to_owned(),
                    before: BaselineObservedValue::Missing,
                    after: definition.recommendation.to_owned(),
                },
                &remote_root,
                0,
            )
            .unwrap();
            assert!(command.contains(&format!("lr_file={}", shq(definition.file))));
            assert!(command.contains(&format!("lr_key={}", shq(definition.key))));
            assert!(command.contains(&format!("lr_sep={}", shq(separator))));
        }
    }

    #[tokio::test]
    async fn full_catalog_recommendation_batch_fits_the_bounded_plan() {
        let (_temp, services, session, harness) = fixture().await;
        let overrides = BASELINE_CATALOG
            .iter()
            .map(|definition| (definition.id, "__missing__"))
            .collect::<Vec<_>>();
        harness.set_execute_output(scan_fixture(&overrides, &[]));
        let requests = BASELINE_CATALOG
            .iter()
            .map(|definition| BaselineChangeRequest::recommended(definition.id).unwrap())
            .collect::<Vec<_>>();
        let plan = services
            .baseline()
            .plan_changes(&session, requests, BaselineReloadPolicy::Defer)
            .await
            .unwrap();

        assert_eq!(plan.changes.len(), BASELINE_CATALOG.len());
        assert_eq!(plan.files.len(), 6);
    }

    #[test]
    fn command_builders_use_only_catalog_paths_and_managed_backup_namespace() {
        let target = TargetGuard {
            identity: TargetIdentity::new("target").unwrap(),
            generation: 1,
        };
        let id = Uuid::new_v4().to_string();
        let changes = vec![PlannedBaselineChange {
            item_id: "ssh-max-auth-tries".to_owned(),
            before: BaselineObservedValue::Value("6".to_owned()),
            after: "4".to_owned(),
        }];
        let files = files_for_changes(&changes).unwrap();
        let digest = change_digest(&changes, &files, BaselineReloadPolicy::ApplyNow).unwrap();
        let mut operation =
            OperationPlan::new(target, "test", true, Some("restore".to_owned())).unwrap();
        operation
            .metadata
            .insert("change_id".to_owned(), id.clone());
        operation
            .metadata
            .insert("digest".to_owned(), digest.clone());
        let plan = BaselineChangePlan {
            operation,
            changes,
            files,
            remote_root: expected_remote_root(&id).unwrap(),
            reload_policy: BaselineReloadPolicy::ApplyNow,
            digest,
        };
        let command = apply_command(&plan).unwrap();
        assert!(command.contains(BASELINE_ROOT));
        assert!(command.contains("/etc/ssh/sshd_config"));
        assert!(command.contains("sshd -t"));
        assert!(command.contains("baseline backup already exists"));
        assert!(command.contains("BACKUP=%s"));
        assert!(!command.contains("rm -rf"));
        assert!(!command.contains("/tmp/"));
    }

    #[test]
    fn legacy_file_editor_is_replaced_by_closed_paths_exact_hashes_and_managed_backups() {
        assert_eq!(
            definition("ssh-permit-root-login").unwrap().file,
            "/etc/ssh/sshd_config"
        );
        for hostile in ["../../etc/passwd", "/etc/../tmp/x", "/etc/x\n/tmp/y", "/"] {
            assert!(validate_catalog_file(hostile).is_err(), "{hostile:?}");
        }

        let change_id = "6f03708a-40f4-486f-8bf1-ff08e7e25457";
        let remote_root = expected_remote_root(change_id).unwrap();
        let command = backup_prelude(&remote_root, &["/etc/ssh/sshd_config".to_owned()]).unwrap();
        assert!(command.contains(&shq(&remote_root)));
        assert!(command.contains(&shq(&format!("{remote_root}/file-0.before"))));
        assert!(command.contains("[ ! -e \"$lr_root\" ]"));
        assert!(command.contains("baseline backup already exists"));
        assert!(command.contains("sha256sum --"));
        assert_eq!(
            sha256_hex("hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[tokio::test]
    async fn scan_is_target_bound() {
        let (_temp, services, session, harness) = fixture().await;
        harness.set_execute_output(scan_fixture(&[], &[]));
        let scan = services.baseline().scan(&session).await.unwrap();
        assert_eq!(scan.statuses.len(), BASELINE_CATALOG.len());
        services
            .target()
            .activate(TargetIdentity::new("replacement").unwrap())
            .unwrap();
        assert!(services.baseline().scan(&session).await.is_err());
    }

    #[tokio::test]
    async fn wrong_confirmation_has_zero_side_effect_then_exact_plan_journals() {
        let (_temp, services, session, harness) = fixture().await;
        harness.set_execute_output(scan_fixture(&[("ssh-max-auth-tries", "6")], &[]));
        let request = BaselineChangeRequest::new("ssh-max-auth-tries", "4").unwrap();
        let wrong = services
            .baseline()
            .plan_changes(&session, vec![request.clone()], BaselineReloadPolicy::Defer)
            .await
            .unwrap();
        let plan = services
            .baseline()
            .plan_changes(&session, vec![request], BaselineReloadPolicy::Defer)
            .await
            .unwrap();
        let error = services
            .baseline()
            .execute_changes(
                &session,
                plan.clone(),
                DangerousConfirmation::approve(wrong.definition()),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("different operation"));
        assert!(
            services
                .baseline()
                .list_history(session.target())
                .unwrap()
                .is_empty()
        );

        harness.set_execute_output(scan_fixture(&[], &[APPLY_MARKER]));
        let outcome = services
            .baseline()
            .execute_changes(
                &session,
                plan.clone(),
                DangerousConfirmation::approve(plan.definition()),
            )
            .await
            .unwrap();
        assert_eq!(outcome.record.state, BaselineChangeState::Applied);
        assert!(outcome.verification.passed);
        assert!(
            services
                .operation_journal()
                .entries()
                .unwrap()
                .iter()
                .any(|entry| entry.operation_id == plan.definition().id)
        );
    }

    #[tokio::test]
    async fn detection_remediation_verification_mismatch_restores_and_stays_auditable() {
        let (_temp, services, session, harness) = fixture().await;
        let remediation = DetectionRemediation::LimitSshAuthenticationAttempts;
        harness.set_execute_output(scan_fixture(&[("ssh-max-auth-tries", "6")], &[]));
        let plan = services
            .baseline()
            .plan_changes(
                &session,
                vec![remediation.baseline_request().unwrap()],
                remediation.reload_policy(),
            )
            .await
            .unwrap();
        let operation_id = plan.definition().id.clone();

        harness.set_execute_outputs([
            scan_fixture(&[], &[APPLY_MARKER]),
            scan_fixture(&[("ssh-max-auth-tries", "6")], &[]),
            RESTORE_MARKER.to_owned(),
        ]);
        let error = services
            .baseline()
            .execute_changes(
                &session,
                plan.clone(),
                DangerousConfirmation::approve(plan.definition()),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("readback differed"));

        let history = services.baseline().list_history(session.target()).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].state, BaselineChangeState::Restored);
        let phases = services
            .operation_journal()
            .entries()
            .unwrap()
            .into_iter()
            .filter(|entry| entry.operation_id == operation_id)
            .map(|entry| entry.phase)
            .collect::<Vec<_>>();
        assert!(phases.contains(&JournalPhase::VerificationFailed));
        assert!(phases.contains(&JournalPhase::Restored));
    }

    #[tokio::test]
    async fn history_restore_is_a_second_exact_verified_operation() {
        let (_temp, services, session, harness) = fixture().await;
        harness.set_execute_output(scan_fixture(&[("ssh-max-auth-tries", "6")], &[]));
        let plan = services
            .baseline()
            .plan_changes(
                &session,
                vec![BaselineChangeRequest::new("ssh-max-auth-tries", "4").unwrap()],
                BaselineReloadPolicy::Defer,
            )
            .await
            .unwrap();
        harness.set_execute_output(scan_fixture(&[], &[APPLY_MARKER]));
        let applied = services
            .baseline()
            .execute_changes(
                &session,
                plan.clone(),
                DangerousConfirmation::approve(plan.definition()),
            )
            .await
            .unwrap();

        let restore = services
            .baseline()
            .plan_restore(&session, &applied.record.id)
            .unwrap();
        harness.set_execute_output(scan_fixture(
            &[("ssh-max-auth-tries", "6")],
            &[RESTORE_MARKER],
        ));
        let restored = services
            .baseline()
            .execute_restore(
                &session,
                restore.clone(),
                DangerousConfirmation::approve(restore.definition()),
            )
            .await
            .unwrap();
        assert_eq!(restored.record.state, BaselineChangeState::Restored);
        assert!(restored.verification.passed);
    }

    #[test]
    fn tampered_persisted_record_cannot_reach_a_shell_builder() {
        let id = Uuid::new_v4().to_string();
        let changes = vec![PlannedBaselineChange {
            item_id: "ssh-max-auth-tries".to_owned(),
            before: BaselineObservedValue::Value("6".to_owned()),
            after: "4".to_owned(),
        }];
        let files = files_for_changes(&changes).unwrap();
        let backups = vec![BaselineBackupEvidence {
            file: files[0].clone(),
            sha256: Some("00".repeat(32)),
        }];
        let record = BaselineChangeRecord {
            id: id.clone(),
            operation_id: Uuid::new_v4().to_string(),
            last_operation_id: Uuid::new_v4().to_string(),
            target: TargetIdentity::new("target").unwrap(),
            changes: changes.clone(),
            files: files.clone(),
            backups: backups.clone(),
            remote_root: format!("{BASELINE_ROOT}/{id};id"),
            reload_policy: BaselineReloadPolicy::Defer,
            digest: record_digest(&changes, &files, &backups, BaselineReloadPolicy::Defer).unwrap(),
            state: BaselineChangeState::Applied,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert!(restore_command_for_record(&record).is_err());

        let valid_root = expected_remote_root(&id).unwrap();
        let mut hostile_backup = record;
        hostile_backup.remote_root = valid_root;
        hostile_backup.backups[0].sha256 = Some("00; cp /etc/shadow /tmp/x".to_owned());
        assert!(restore_command_for_record(&hostile_backup).is_err());
    }

    #[test]
    fn baseline_history_has_a_dedicated_portable_store_file() {
        assert_eq!(StoreFile::Baseline.file_name(), "baseline-history.json");
    }
}
