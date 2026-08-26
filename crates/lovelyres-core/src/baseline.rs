//! Target-bound Linux configuration baselines with verified, reversible edits.
//!
//! The public boundary is deliberately closed: callers select a catalog item
//! and a typed value. Remote paths, shell snippets, regular expressions, and
//! service names never cross the UI/core boundary.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as _, IgnoredAny, SeqAccess, Visitor},
};
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
const MAX_BASELINE_HISTORY_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;
/// One plan may carry every check this tool can write, so "fix everything"
/// is one reviewable operation with one backup set rather than several.
const MAX_CHANGES: usize = 128;

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
    /// Who may reach the service at all: listen addresses, host rules.
    AccessControl,
    /// Whether what crosses the wire is encrypted.
    Transport,
    /// Turning off what the service does not need to be doing.
    ServiceHardening,
}

impl BaselineCategory {
    pub const ALL: [Self; 10] = [
        Self::Ssh,
        Self::Authentication,
        Self::Password,
        Self::Kernel,
        Self::Network,
        Self::Logging,
        Self::FilePermissions,
        Self::AccessControl,
        Self::Transport,
        Self::ServiceHardening,
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
            Self::AccessControl => "访问控制",
            Self::Transport => "传输加密",
            Self::ServiceHardening => "服务加固",
        }
    }
}

/// What a check is about, as opposed to what kind of hardening it is.
///
/// Two axes, because with eighty checks one is not enough: an operator asked
/// to harden the database wants the database's checks, and an operator asked
/// about logging wants logging across everything. Grouping by the software and
/// filtering by the kind answers both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BaselineComponent {
    System,
    Ssh,
    MySql,
    PostgreSql,
    Redis,
    MongoDb,
    Nginx,
    Apache,
    Tomcat,
    /// openGauss keeps a PostgreSQL-shaped file with directives of its own —
    /// `password_encryption_type`, `audit_enabled`, the login-lockout trio —
    /// so it is its own product rather than a path added to PostgreSQL's.
    OpenGauss,
    TiDb,
    HaProxy,
}

impl BaselineComponent {
    pub const ALL: [Self; 12] = [
        Self::System,
        Self::Ssh,
        Self::MySql,
        Self::PostgreSql,
        Self::Redis,
        Self::MongoDb,
        Self::Nginx,
        Self::Apache,
        Self::Tomcat,
        Self::OpenGauss,
        Self::TiDb,
        Self::HaProxy,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::System => "操作系统",
            Self::Ssh => "SSH 服务",
            Self::MySql => "MySQL / MariaDB",
            Self::PostgreSql => "PostgreSQL",
            Self::Redis => "Redis",
            Self::MongoDb => "MongoDB",
            Self::Nginx => "Nginx",
            Self::Apache => "Apache HTTP Server",
            Self::Tomcat => "Apache Tomcat",
            Self::OpenGauss => "openGauss",
            Self::TiDb => "TiDB",
            Self::HaProxy => "HAProxy",
        }
    }

    /// Whether a target without this software should be told it is missing
    /// checks. The operating system is always present; a database is not.
    pub const fn is_optional(self) -> bool {
        !matches!(self, Self::System | Self::Ssh)
    }

    /// A shell test for whether this software is on the target at all.
    ///
    /// Having no configuration file is not the same as not being installed,
    /// and treating it as the same was wrong on exactly the machines this tool
    /// is for: the official Redis image ships no `redis.conf` and runs on the
    /// built-in defaults, so every Redis check reported the software missing
    /// on a host that was running it — and `protected-mode` defaulting to yes
    /// is a real answer, not an absence.
    ///
    /// `None` for the things every Linux has.
    pub const fn presence_probe(self) -> Option<&'static str> {
        match self {
            Self::System | Self::Ssh => None,
            Self::MySql => Some(
                "command -v mysqld >/dev/null 2>&1 || command -v mariadbd >/dev/null 2>&1 \
                 || command -v mysqld_safe >/dev/null 2>&1 || [ -d /var/lib/mysql ]",
            ),
            Self::PostgreSql => Some(
                "command -v postgres >/dev/null 2>&1 || command -v postmaster >/dev/null 2>&1 \
                 || [ -d /var/lib/postgresql ] || [ -d /var/lib/pgsql ]",
            ),
            Self::Redis => Some(
                "command -v redis-server >/dev/null 2>&1 || command -v valkey-server >/dev/null 2>&1",
            ),
            Self::MongoDb => Some("command -v mongod >/dev/null 2>&1"),
            Self::Nginx => Some("command -v nginx >/dev/null 2>&1 || [ -d /etc/nginx ]"),
            Self::Apache => Some(
                "command -v httpd >/dev/null 2>&1 || command -v apache2 >/dev/null 2>&1 \
                 || [ -d /usr/local/apache2 ]",
            ),
            Self::Tomcat => Some(
                "[ -d /usr/local/tomcat ] || [ -d /opt/tomcat ] \
                 || ls -d /etc/tomcat* /usr/share/tomcat* /var/lib/tomcat* >/dev/null 2>&1",
            ),
            // openGauss ships `gaussdb`, not `postgres`, and keeps its cluster
            // under its own directory — so a host running it answers no to
            // PostgreSQL's probe and its PostgreSQL checks stay out of the way.
            Self::OpenGauss => Some(
                "command -v gaussdb >/dev/null 2>&1 || command -v gs_ctl >/dev/null 2>&1 \
                 || [ -d /var/lib/opengauss ] || [ -d /opt/opengauss ]",
            ),
            Self::TiDb => Some(
                "command -v tidb-server >/dev/null 2>&1 || [ -d /etc/tidb ] \
                 || [ -d /opt/tidb ]",
            ),
            Self::HaProxy => Some(
                "command -v haproxy >/dev/null 2>&1 || [ -d /etc/haproxy ] \
                 || [ -d /usr/local/etc/haproxy ]",
            ),
        }
    }

    /// The product's own check that the file it has just been handed is valid.
    ///
    /// Writing a file the program will refuse is worse than not writing it at
    /// all: the change reads as applied, and the next reload — which may be a
    /// reboot, in the middle of an incident — is where it fails. Every change
    /// this tool makes is now offered to the product's own parser first, and a
    /// refusal rolls the file back through the backup the operation already
    /// takes.
    ///
    /// `{file}` is replaced with the file the change was written to.
    ///
    /// Only validators proven on a real host to answer zero for a good file
    /// and non-zero for a broken one are here. `mariadbd --validate-config` is
    /// not one of them: it refuses to run as root, and as the mysql user it
    /// still answers non-zero on a file it accepts — encoding it would have
    /// rolled back every MariaDB change ever made. Redis and Tomcat have no
    /// offline validator at all, which is the same thing `MiddlewareValidator`
    /// records for them in `middleware.rs`.
    ///
    /// Each one skips silently when the program is not installed, so a check
    /// written on a host that does not run the product cannot fail on the
    /// absence of its validator.
    pub const fn validate_command(self) -> Option<&'static str> {
        match self {
            // login.defs, faillock, auditd and sysctl have no parser to ask.
            Self::System => None,
            Self::Ssh => Some("if command -v sshd >/dev/null 2>&1; then sshd -t; fi"),
            Self::Nginx => Some("if command -v nginx >/dev/null 2>&1; then nginx -t; fi"),
            Self::Apache => Some(
                "if command -v apachectl >/dev/null 2>&1; then apachectl configtest; \
                 elif command -v httpd >/dev/null 2>&1; then httpd -t; \
                 elif command -v apache2ctl >/dev/null 2>&1; then apache2ctl configtest; fi",
            ),
            // MySQL only. On a MariaDB host `mysqld` is absent and this skips.
            Self::MySql => {
                Some("if command -v mysqld >/dev/null 2>&1; then mysqld --validate-config; fi")
            }
            Self::MongoDb => Some(
                "if command -v mongod >/dev/null 2>&1; then \
                   mongod --config {file} --outputConfig >/dev/null; fi",
            ),
            // `postgres` is not on the path on Debian; it lives beside its own
            // version. The file's own directory is the configuration directory.
            Self::PostgreSql => Some(
                "for lr_pg in /usr/lib/postgresql/*/bin/postgres /usr/pgsql-*/bin/postgres \
                   /usr/local/pgsql/bin/postgres; do \
                   [ -x \"$lr_pg\" ] || continue; \
                   su postgres -s /bin/sh -c \"$lr_pg -C listen_addresses -D $(dirname {file})\" \
                     >/dev/null 2>&1 || exit 42; \
                   break; \
                 done",
            ),
            // openGauss ships `gs_guc check`, but it wants the cluster's data
            // directory and the omm account; TiDB has no offline check at all.
            // Neither is proven, so neither is claimed.
            Self::HaProxy => Some(
                "if command -v haproxy >/dev/null 2>&1; then haproxy -c -f {file} >/dev/null; fi",
            ),
            Self::Redis | Self::Tomcat | Self::OpenGauss | Self::TiDb => None,
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
    Integer {
        minimum: u32,
        maximum: u32,
    },
    /// Only whether the directive is set, never what it is set to.
    ///
    /// `requirepass` is the check that matters most on a Redis reachable from
    /// the network, and its value is the password. Carrying that back so it
    /// could be printed in a compliance table would make the check worse than
    /// not having it.
    Presence,
    /// A truth value, spelled however the software in question spells it.
    ///
    /// The same idea is written `0`, `off`, `false`, `no` and `disabled`
    /// across the files this reads, and comparing the spelling instead of the
    /// meaning reported a correctly hardened setting as a finding.
    Boolean,
}

impl BaselineValueKind {
    /// The canonical spelling of a truth value, or `None` if it is not one.
    fn as_boolean(value: &str) -> Option<&'static str> {
        match value.trim().to_ascii_lowercase().as_str() {
            "1" | "on" | "yes" | "true" | "enabled" | "enable" => Some("on"),
            "0" | "off" | "no" | "false" | "disabled" | "disable" => Some("off"),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileFormat {
    /// `Directive value` — sshd, redis, httpd, login.defs.
    Whitespace,
    /// `key = value` — sysctl, postgresql.conf, auditd.
    Equals,
    /// `key = value` under a `[section]` header — the my.cnf family.
    Ini(&'static str),
    /// `directive value;` — nginx.
    Semicolon,
    /// `parent:` then an indented `key: value` — mongod.conf.
    ///
    /// The key is written as the whole path, `security.authorization`, and the
    /// reader walks the indentation to find it.
    Yaml,
    /// `section` on its own line, then `key value` indented under it — which
    /// is how HAProxy writes `global` and `defaults`.
    ///
    /// There are no brackets to find the section by: a line that starts in
    /// column one *is* a header, and everything indented below it belongs to
    /// the one above.
    IndentSection(&'static str),
    /// An attribute on an XML element — Tomcat's `server.xml`. The key is the
    /// attribute name and this is the element it sits on.
    ///
    /// Three of the four `<Connector>` elements a stock Tomcat ships are
    /// inside `<!-- -->`, so anything reading this file without tracking
    /// comments reports the AJP connector as live. Both the reader and the
    /// editor walk the comments.
    ///
    /// Where several elements of the same name are live — Tomcat has more than
    /// one connector — the reader reports the worst of them, because the
    /// question a check asks is whether *every* connector is configured
    /// safely, and the editor fixes all of them.
    XmlAttribute(&'static str),
}

/// Where a check's observed value comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reading {
    /// The first of these paths that exists on the target. Distributions put
    /// the same file in different places, and a check that only knows one of
    /// them reports "not set" on all the others.
    Files(&'static [&'static str]),
    /// Ask the kernel what it is currently using.
    ///
    /// Reading the value out of a file says what someone wrote down; a kernel
    /// parameter can be set from `/etc/sysctl.conf`, from any file under
    /// `/etc/sysctl.d`, by a unit, or by hand, and only the running value says
    /// what the machine is doing right now.
    RunningSysctl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ReloadGroup {
    None,
    Sshd,
    Sysctl,
}

/// Which occurrence of a repeated directive the program on the host obeys.
///
/// This is not a stylistic choice: reading the wrong one reports a value the
/// host is not using. Both arms were settled by asking the real programs — see
/// [`reader_program`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Precedence {
    First,
    Last,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaselineDefinition {
    pub id: &'static str,
    pub category: BaselineCategory,
    pub component: BaselineComponent,
    pub title: &'static str,
    pub description: &'static str,
    pub recommendation: &'static str,
    pub risk: BaselineRisk,
    pub value_kind: BaselineValueKind,
    /// The file a change would be written to, and the file the operator is
    /// shown. Reading may find the value somewhere else — see [`Reading`].
    file: &'static str,
    reading: Reading,
    /// What the software uses when the directive is not written down.
    ///
    /// A setting left at a safe default is not a finding. Reporting every
    /// unwritten directive as non-compliant fills the table with rows that
    /// need no action, and a table like that stops being read.
    implicit: Option<&'static str>,
    key: &'static str,
    format: FileFormat,
    reload: ReloadGroup,
}

impl BaselineDefinition {
    /// The file this setting lives in on the host.
    ///
    /// Fixed at compile time and the same on every target, so it is safe to
    /// show; it is not a path a caller can choose.
    pub const fn file(&self) -> &'static str {
        self.file
    }

    /// Whether this tool will write the change as well as report it.
    ///
    /// Everything except a presence check, which has no value to write: what
    /// it reports is that a directive is set, and the directive's value is a
    /// credential. Setting one would mean this tool handling the credential,
    /// which it does not do — the operator is given the line to write instead.
    pub const fn is_writable(&self) -> bool {
        !matches!(self.value_kind, BaselineValueKind::Presence)
    }

    /// Every path the scan will look in, in order, for this setting.
    const fn candidates(&self) -> &'static [&'static str] {
        match self.reading {
            Reading::Files(paths) => paths,
            Reading::RunningSysctl => &[],
        }
    }

    /// The directive this setting is written as.
    pub const fn key(&self) -> &'static str {
        self.key
    }

    const fn precedence(&self) -> Precedence {
        // Only sshd reads top-down and keeps the first value it sees.
        match self.reload {
            ReloadGroup::Sshd => Precedence::First,
            ReloadGroup::None | ReloadGroup::Sysctl => Precedence::Last,
        }
    }
}

// Where each product keeps the file, on the distributions this tool meets.
// The scan reads the first of these that exists; a check that knows only one
// distribution's path reports "not set" on every other one.
// sshd keeps the first value it sees and its `Include` line sits at the top of
// the packaged file, so anything dropped into sshd_config.d wins — and so is
// read first here.
const SSHD_FILES: &[&str] = &["/etc/ssh/sshd_config.d/*.conf", "/etc/ssh/sshd_config"];
const LOGIN_DEFS_FILES: &[&str] = &["/etc/login.defs"];
const FAILLOCK_FILES: &[&str] = &["/etc/security/faillock.conf"];
const PWQUALITY_FILES: &[&str] = &["/etc/security/pwquality.conf"];
const AUDITD_FILES: &[&str] = &["/etc/audit/auditd.conf", "/etc/auditd.conf"];
// In the order the server reads them: the main file, then each include
// directory. The last value read is the one that takes effect.
const MYSQL_FILES: &[&str] = &[
    "/etc/my.cnf",
    "/etc/mysql/my.cnf",
    "/etc/my.cnf.d/*.cnf",
    "/etc/mysql/conf.d/*.cnf",
    "/etc/mysql/mysql.conf.d/*.cnf",
    "/etc/mysql/mariadb.conf.d/*.cnf",
];
const POSTGRESQL_FILES: &[&str] = &[
    "/etc/postgresql/*/main/postgresql.conf",
    "/var/lib/pgsql/data/postgresql.conf",
    "/var/lib/pgsql/*/data/postgresql.conf",
    "/var/lib/postgresql/data/postgresql.conf",
    "/etc/postgresql/postgresql.conf",
];
const REDIS_FILES: &[&str] = &[
    "/etc/redis/redis.conf",
    "/etc/redis.conf",
    "/etc/redis/6379.conf",
];
const MONGODB_FILES: &[&str] = &["/etc/mongod.conf", "/etc/mongodb.conf"];
// nginx includes conf.d and the enabled sites, and a directive set there
// overrides the one in the main file for that server.
const NGINX_FILES: &[&str] = &[
    "/etc/nginx/nginx.conf",
    "/usr/local/nginx/conf/nginx.conf",
    "/etc/nginx/conf.d/*.conf",
    "/etc/nginx/sites-enabled/*",
];
// openGauss keeps a PostgreSQL-shaped file under its own tree. Its own
// directives live in the same file, so one candidate list covers both.
const OPENGAUSS_FILES: &[&str] = &[
    "/var/lib/opengauss/data/postgresql.conf",
    "/var/lib/opengauss/*/data/postgresql.conf",
    "/opt/opengauss/data/postgresql.conf",
    "/gaussdb/data/*/postgresql.conf",
];

const TIDB_FILES: &[&str] = &[
    "/etc/tidb/tidb.toml",
    "/etc/tidb.toml",
    "/opt/tidb/conf/tidb.toml",
    "/tidb-deploy/*/conf/tidb.toml",
];

const HAPROXY_FILES: &[&str] = &[
    "/etc/haproxy/haproxy.cfg",
    "/usr/local/etc/haproxy/haproxy.cfg",
    "/etc/haproxy/conf.d/*.cfg",
];

const OPENGAUSS_PASSWORD_TYPE: &[&str] = &["0", "1", "2"];
const TIDB_LOG_LEVEL: &[&str] = &["debug", "info", "warn", "error", "fatal"];
const APACHE_LOG_LEVEL: &[&str] = &[
    "emerg", "alert", "crit", "error", "warn", "notice", "info", "debug",
];

// Tomcat is unpacked wherever whoever installed it decided; these are the
// places the packages and the official image put it.
const TOMCAT_SERVER_FILES: &[&str] = &[
    "/usr/local/tomcat/conf/server.xml",
    "/opt/tomcat/conf/server.xml",
    "/opt/tomcat*/conf/server.xml",
    "/etc/tomcat/server.xml",
    "/etc/tomcat*/server.xml",
    "/var/lib/tomcat*/conf/server.xml",
    "/usr/share/tomcat*/conf/server.xml",
];

const APACHE_FILES: &[&str] = &[
    "/etc/httpd/conf/httpd.conf",
    "/etc/apache2/apache2.conf",
    "/usr/local/apache2/conf/httpd.conf",
];

/// What a presence check reports instead of the value it found.
pub const PRESENCE_MARKER: &str = "configured";

const SSH_LOG_LEVEL: &[&str] = &["quiet", "fatal", "error", "info", "verbose", "debug"];
const ENCRYPT_METHOD: &[&str] = &["sha512", "sha256", "yescrypt", "md5", "des"];
const MYSQL_BIND: &[&str] = &["127.0.0.1", "::1", "localhost", "0.0.0.0", "*", "::"];
const PG_LISTEN: &[&str] = &["localhost", "127.0.0.1", "*", "0.0.0.0"];
const PG_PASSWORD_ENCRYPTION: &[&str] = &["scram-sha-256", "md5", "scram_sha_256"];
const PG_LOG_STATEMENT: &[&str] = &["none", "ddl", "mod", "all"];
const MONGO_AUTHORIZATION: &[&str] = &["enabled", "disabled"];
const MONGO_BIND: &[&str] = &["127.0.0.1", "::1", "localhost", "0.0.0.0"];
const MONGO_TLS_MODE: &[&str] = &["requiretls", "prefertls", "allowtls", "disabled"];
const APACHE_SERVER_TOKENS: &[&str] =
    &["prod", "productonly", "major", "minor", "min", "os", "full"];
const TOMCAT_SHUTDOWN_PORT: &[&str] = &["-1", "8005"];

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
        component: BaselineComponent::Ssh,
        reading: Reading::Files(SSHD_FILES),
        implicit: None,
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
        component: BaselineComponent::Ssh,
        reading: Reading::Files(SSHD_FILES),
        implicit: None,
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
        component: BaselineComponent::Ssh,
        reading: Reading::Files(SSHD_FILES),
        implicit: None,
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
        component: BaselineComponent::Ssh,
        reading: Reading::Files(SSHD_FILES),
        implicit: None,
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
        component: BaselineComponent::Ssh,
        reading: Reading::Files(SSHD_FILES),
        implicit: None,
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
        component: BaselineComponent::Ssh,
        reading: Reading::Files(SSHD_FILES),
        implicit: None,
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
        component: BaselineComponent::Ssh,
        reading: Reading::Files(SSHD_FILES),
        implicit: None,
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
        component: BaselineComponent::Ssh,
        reading: Reading::Files(SSHD_FILES),
        implicit: None,
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
        component: BaselineComponent::Ssh,
        reading: Reading::Files(SSHD_FILES),
        implicit: None,
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
        component: BaselineComponent::Ssh,
        reading: Reading::Files(SSHD_FILES),
        implicit: None,
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
        component: BaselineComponent::System,
        reading: Reading::Files(LOGIN_DEFS_FILES),
        implicit: None,
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
        component: BaselineComponent::System,
        reading: Reading::Files(FAILLOCK_FILES),
        implicit: None,
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
        component: BaselineComponent::System,
        reading: Reading::Files(FAILLOCK_FILES),
        implicit: None,
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
        component: BaselineComponent::System,
        reading: Reading::Files(FAILLOCK_FILES),
        implicit: None,
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
        component: BaselineComponent::System,
        reading: Reading::Files(PWQUALITY_FILES),
        implicit: None,
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
        component: BaselineComponent::System,
        reading: Reading::Files(LOGIN_DEFS_FILES),
        implicit: None,
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
        component: BaselineComponent::System,
        reading: Reading::Files(LOGIN_DEFS_FILES),
        implicit: None,
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
        component: BaselineComponent::System,
        reading: Reading::Files(LOGIN_DEFS_FILES),
        implicit: None,
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
        component: BaselineComponent::System,
        reading: Reading::Files(LOGIN_DEFS_FILES),
        implicit: None,
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
        component: BaselineComponent::Ssh,
        reading: Reading::Files(SSHD_FILES),
        implicit: None,
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
        component: BaselineComponent::System,
        reading: Reading::RunningSysctl,
        implicit: None,
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
        component: BaselineComponent::System,
        reading: Reading::RunningSysctl,
        implicit: None,
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
        component: BaselineComponent::System,
        reading: Reading::RunningSysctl,
        implicit: None,
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
        component: BaselineComponent::System,
        reading: Reading::RunningSysctl,
        implicit: None,
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
        component: BaselineComponent::System,
        reading: Reading::RunningSysctl,
        implicit: None,
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
        component: BaselineComponent::System,
        reading: Reading::RunningSysctl,
        implicit: None,
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
        component: BaselineComponent::System,
        reading: Reading::RunningSysctl,
        implicit: None,
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
        component: BaselineComponent::System,
        reading: Reading::RunningSysctl,
        implicit: None,
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
        component: BaselineComponent::System,
        reading: Reading::RunningSysctl,
        implicit: None,
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
        component: BaselineComponent::System,
        reading: Reading::RunningSysctl,
        implicit: None,
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
        component: BaselineComponent::System,
        reading: Reading::RunningSysctl,
        implicit: None,
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
        component: BaselineComponent::System,
        reading: Reading::RunningSysctl,
        implicit: None,
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
        component: BaselineComponent::System,
        reading: Reading::RunningSysctl,
        implicit: None,
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
        component: BaselineComponent::System,
        reading: Reading::RunningSysctl,
        implicit: None,
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
        component: BaselineComponent::System,
        reading: Reading::Files(AUDITD_FILES),
        implicit: None,
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
        component: BaselineComponent::System,
        reading: Reading::Files(AUDITD_FILES),
        implicit: None,
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
        component: BaselineComponent::System,
        reading: Reading::Files(AUDITD_FILES),
        implicit: None,
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
        component: BaselineComponent::System,
        reading: Reading::Files(AUDITD_FILES),
        implicit: None,
        file: "/etc/audit/auditd.conf",
        key: "space_left_action",
        format: FileFormat::Equals,
        reload: ReloadGroup::None,
    },
    // ---- SSH, the rest of what a session should be held to -----------------
    BaselineDefinition {
        id: "ssh-log-level",
        category: BaselineCategory::Logging,
        component: BaselineComponent::Ssh,
        title: "记录登录密钥指纹",
        description: "VERBOSE 会记录登录所用公钥的指纹，事后才能分辨是谁的密钥登进来的。",
        recommendation: "verbose",
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Choice(SSH_LOG_LEVEL),
        reading: Reading::Files(SSHD_FILES),
        implicit: Some("info"),
        file: "/etc/ssh/sshd_config",
        key: "LogLevel",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::Sshd,
    },
    BaselineDefinition {
        id: "ssh-client-alive-interval",
        category: BaselineCategory::Ssh,
        component: BaselineComponent::Ssh,
        title: "闲置会话自动断开",
        description: "无人操作的会话会一直留着；设定探测间隔后，掉线或被遗忘的终端会自行关闭。",
        recommendation: "300",
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Integer {
            minimum: 60,
            maximum: 900,
        },
        reading: Reading::Files(SSHD_FILES),
        implicit: None,
        file: "/etc/ssh/sshd_config",
        key: "ClientAliveInterval",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::Sshd,
    },
    BaselineDefinition {
        id: "ssh-client-alive-count",
        category: BaselineCategory::Ssh,
        component: BaselineComponent::Ssh,
        title: "探测无响应即断开",
        description: "配合探测间隔使用：连续几次无响应就结束会话。设为 0 表示第一次就断。",
        recommendation: "0",
        risk: BaselineRisk::Low,
        value_kind: BaselineValueKind::Integer {
            minimum: 0,
            maximum: 3,
        },
        reading: Reading::Files(SSHD_FILES),
        implicit: None,
        file: "/etc/ssh/sshd_config",
        key: "ClientAliveCountMax",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::Sshd,
    },
    BaselineDefinition {
        id: "ssh-use-pam",
        category: BaselineCategory::Authentication,
        component: BaselineComponent::Ssh,
        title: "登录走 PAM",
        description: "关掉 PAM，锁定策略、失败计数和会话限制就全部不生效了。",
        recommendation: "yes",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Choice(YES_NO),
        reading: Reading::Files(SSHD_FILES),
        // OpenSSH itself defaults this to no; the distributions ship it set to
        // yes. Assuming the distribution's habit would call a host built from
        // upstream compliant while its lockout policy did nothing.
        implicit: None,
        file: "/etc/ssh/sshd_config",
        key: "UsePAM",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::Sshd,
    },
    BaselineDefinition {
        id: "password-encrypt-method",
        category: BaselineCategory::Password,
        component: BaselineComponent::System,
        title: "口令哈希算法",
        description: "新建口令用哪种算法存放。MD5 与 DES 早已可以离线爆破。",
        recommendation: "sha512",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Choice(ENCRYPT_METHOD),
        reading: Reading::Files(LOGIN_DEFS_FILES),
        implicit: None,
        file: "/etc/login.defs",
        key: "ENCRYPT_METHOD",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::None,
    },
    // ---- More of what the kernel is actually doing -------------------------
    BaselineDefinition {
        id: "kernel-ptrace-scope",
        category: BaselineCategory::Kernel,
        component: BaselineComponent::System,
        title: "限制进程互相调试",
        description: "阻止一个普通进程附着到另一个进程上读它的内存，这是抓取内存中凭据的常用手法。",
        recommendation: "1",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Integer {
            minimum: 0,
            maximum: 3,
        },
        reading: Reading::RunningSysctl,
        implicit: None,
        file: "/etc/sysctl.d/99-lovelyres-baseline.conf",
        key: "kernel.yama.ptrace_scope",
        format: FileFormat::Equals,
        reload: ReloadGroup::Sysctl,
    },
    BaselineDefinition {
        id: "network-send-redirects",
        category: BaselineCategory::Network,
        component: BaselineComponent::System,
        title: "不发送 ICMP 重定向",
        description: "只有路由器需要告诉别人改走哪条路；一台服务器发这种包只会泄露网络结构。",
        recommendation: "0",
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Integer {
            minimum: 0,
            maximum: 1,
        },
        reading: Reading::RunningSysctl,
        implicit: None,
        file: "/etc/sysctl.d/99-lovelyres-baseline.conf",
        key: "net.ipv4.conf.all.send_redirects",
        format: FileFormat::Equals,
        reload: ReloadGroup::Sysctl,
    },
    BaselineDefinition {
        id: "network-ignore-broadcast-ping",
        category: BaselineCategory::Network,
        component: BaselineComponent::System,
        title: "忽略广播 ping",
        description: "回应广播 ICMP 会让这台机器成为放大攻击的帮凶，也会暴露自己存在。",
        recommendation: "1",
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Integer {
            minimum: 0,
            maximum: 1,
        },
        reading: Reading::RunningSysctl,
        implicit: None,
        file: "/etc/sysctl.d/99-lovelyres-baseline.conf",
        key: "net.ipv4.icmp_echo_ignore_broadcasts",
        format: FileFormat::Equals,
        reload: ReloadGroup::Sysctl,
    },
    BaselineDefinition {
        id: "network-reverse-path-filter",
        category: BaselineCategory::Network,
        component: BaselineComponent::System,
        title: "反向路径校验",
        description: "丢弃源地址不可能从该网卡进来的包，挡掉最简单的一类地址伪造。",
        recommendation: "1",
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Integer {
            minimum: 0,
            maximum: 2,
        },
        reading: Reading::RunningSysctl,
        implicit: None,
        file: "/etc/sysctl.d/99-lovelyres-baseline.conf",
        key: "net.ipv4.conf.all.rp_filter",
        format: FileFormat::Equals,
        reload: ReloadGroup::Sysctl,
    },
    // ---- MySQL and MariaDB -------------------------------------------------
    BaselineDefinition {
        id: "mysql-bind-address",
        category: BaselineCategory::AccessControl,
        component: BaselineComponent::MySql,
        title: "只监听本机",
        description: "数据库直接暴露在网络上，等于把认证当成唯一一道门。应用在本机时应只监听回环。",
        recommendation: "127.0.0.1",
        risk: BaselineRisk::Critical,
        value_kind: BaselineValueKind::Choice(MYSQL_BIND),
        reading: Reading::Files(MYSQL_FILES),
        implicit: None,
        file: "/etc/mysql/mariadb.conf.d/50-server.cnf",
        key: "bind-address",
        format: FileFormat::Ini("mysqld"),
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "mysql-local-infile",
        category: BaselineCategory::ServiceHardening,
        component: BaselineComponent::MySql,
        title: "关闭 LOAD DATA LOCAL",
        description: "开着它，一次 SQL 注入就能读走服务器上的任意文件。",
        recommendation: "off",
        risk: BaselineRisk::Critical,
        value_kind: BaselineValueKind::Boolean,
        reading: Reading::Files(MYSQL_FILES),
        // On by default in MySQL 5.7 and MariaDB, off in MySQL 8. Assuming
        // either one is wrong on the other, so this asks to see it written.
        implicit: None,
        file: "/etc/mysql/mariadb.conf.d/50-server.cnf",
        key: "local_infile",
        format: FileFormat::Ini("mysqld"),
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "mysql-skip-symbolic-links",
        category: BaselineCategory::ServiceHardening,
        component: BaselineComponent::MySql,
        title: "禁止表文件走符号链接",
        description: "允许符号链接时，一张表可以指到数据目录之外的任意路径。",
        recommendation: "on",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Boolean,
        reading: Reading::Files(MYSQL_FILES),
        implicit: None,
        file: "/etc/mysql/mariadb.conf.d/50-server.cnf",
        key: "skip-symbolic-links",
        format: FileFormat::Ini("mysqld"),
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "mysql-secure-file-priv",
        category: BaselineCategory::ServiceHardening,
        component: BaselineComponent::MySql,
        title: "限制导入导出目录",
        description: "限定 SELECT INTO OUTFILE 与 LOAD DATA 只能落在一个目录里。留空等于整个文件系统。",
        recommendation: PRESENCE_MARKER,
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Presence,
        reading: Reading::Files(MYSQL_FILES),
        implicit: None,
        file: "/etc/mysql/mariadb.conf.d/50-server.cnf",
        key: "secure_file_priv",
        format: FileFormat::Ini("mysqld"),
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "mysql-log-error",
        category: BaselineCategory::Logging,
        component: BaselineComponent::MySql,
        title: "错误日志写到文件",
        description: "没有错误日志，重启、崩溃和认证失败都不会留下任何可查的痕迹。",
        recommendation: PRESENCE_MARKER,
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Presence,
        reading: Reading::Files(MYSQL_FILES),
        implicit: None,
        file: "/etc/mysql/mariadb.conf.d/50-server.cnf",
        key: "log_error",
        format: FileFormat::Ini("mysqld"),
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "mysql-skip-name-resolve",
        category: BaselineCategory::AccessControl,
        component: BaselineComponent::MySql,
        title: "授权只按 IP 判定",
        description: "关掉反解后，授权表里的主机名不会被 DNS 影响，也就无法用 DNS 欺骗绕过。",
        recommendation: "on",
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Boolean,
        reading: Reading::Files(MYSQL_FILES),
        implicit: Some("off"),
        file: "/etc/mysql/mariadb.conf.d/50-server.cnf",
        key: "skip-name-resolve",
        format: FileFormat::Ini("mysqld"),
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "mysql-general-log",
        category: BaselineCategory::Logging,
        component: BaselineComponent::MySql,
        title: "关闭全量语句日志",
        description: "全量日志会把每条语句连同其中的口令一起写进文件，日常不应开着。",
        recommendation: "off",
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Boolean,
        reading: Reading::Files(MYSQL_FILES),
        implicit: Some("off"),
        file: "/etc/mysql/mariadb.conf.d/50-server.cnf",
        key: "general_log",
        format: FileFormat::Ini("mysqld"),
        reload: ReloadGroup::None,
    },
    // ---- PostgreSQL --------------------------------------------------------
    BaselineDefinition {
        id: "postgresql-listen-addresses",
        category: BaselineCategory::AccessControl,
        component: BaselineComponent::PostgreSql,
        title: "只监听本机",
        description: "监听 * 表示任何能到达这台机器的人都能尝试认证。",
        recommendation: "localhost",
        risk: BaselineRisk::Critical,
        value_kind: BaselineValueKind::Choice(PG_LISTEN),
        reading: Reading::Files(POSTGRESQL_FILES),
        implicit: Some("localhost"),
        file: "/etc/postgresql/postgresql.conf",
        key: "listen_addresses",
        format: FileFormat::Equals,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "postgresql-password-encryption",
        category: BaselineCategory::Password,
        component: BaselineComponent::PostgreSql,
        title: "口令用 SCRAM 存放",
        description: "md5 方式的口令散列可以直接拿来重放登录，SCRAM 不行。",
        recommendation: "scram-sha-256",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Choice(PG_PASSWORD_ENCRYPTION),
        reading: Reading::Files(POSTGRESQL_FILES),
        // No default is assumed: PostgreSQL 14 changed it from md5 to
        // scram-sha-256, and assuming the newer one called a 13 using md5
        // compliant. A setting whose meaning depends on the version is a
        // setting worth writing down.
        implicit: None,
        file: "/etc/postgresql/postgresql.conf",
        key: "password_encryption",
        format: FileFormat::Equals,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "postgresql-log-connections",
        category: BaselineCategory::Logging,
        component: BaselineComponent::PostgreSql,
        title: "记录连接建立",
        description: "不记录连接，就无从知道是谁在什么时候连过这个库。",
        recommendation: "on",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Boolean,
        reading: Reading::Files(POSTGRESQL_FILES),
        implicit: Some("off"),
        file: "/etc/postgresql/postgresql.conf",
        key: "log_connections",
        format: FileFormat::Equals,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "postgresql-log-disconnections",
        category: BaselineCategory::Logging,
        component: BaselineComponent::PostgreSql,
        title: "记录连接断开",
        description: "与连接记录成对使用，才能还原出每个会话持续了多久。",
        recommendation: "on",
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Boolean,
        reading: Reading::Files(POSTGRESQL_FILES),
        implicit: Some("off"),
        file: "/etc/postgresql/postgresql.conf",
        key: "log_disconnections",
        format: FileFormat::Equals,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "postgresql-log-statement",
        category: BaselineCategory::Logging,
        component: BaselineComponent::PostgreSql,
        title: "记录结构变更语句",
        description: "至少记下建表、改表、授权这类语句，事后才看得出库结构被谁动过。",
        recommendation: "ddl",
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Choice(PG_LOG_STATEMENT),
        reading: Reading::Files(POSTGRESQL_FILES),
        implicit: Some("none"),
        file: "/etc/postgresql/postgresql.conf",
        key: "log_statement",
        format: FileFormat::Equals,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "postgresql-logging-collector",
        category: BaselineCategory::Logging,
        component: BaselineComponent::PostgreSql,
        title: "日志落盘",
        description: "不开收集器时日志只写标准错误，容器里通常就等于没有留存。",
        recommendation: "on",
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Boolean,
        reading: Reading::Files(POSTGRESQL_FILES),
        implicit: Some("off"),
        file: "/etc/postgresql/postgresql.conf",
        key: "logging_collector",
        format: FileFormat::Equals,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "postgresql-ssl",
        category: BaselineCategory::Transport,
        component: BaselineComponent::PostgreSql,
        title: "启用传输加密",
        description: "不开 SSL 时，口令与查询结果在网络上是明文。",
        recommendation: "on",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Boolean,
        reading: Reading::Files(POSTGRESQL_FILES),
        implicit: Some("off"),
        file: "/etc/postgresql/postgresql.conf",
        key: "ssl",
        format: FileFormat::Equals,
        reload: ReloadGroup::None,
    },
    // ---- Redis -------------------------------------------------------------
    BaselineDefinition {
        id: "redis-protected-mode",
        category: BaselineCategory::AccessControl,
        component: BaselineComponent::Redis,
        title: "保持保护模式",
        description: "保护模式是没设口令时的最后一道拦阻；关掉它的无口令 Redis 是被利用最多的一种配置。",
        recommendation: "on",
        risk: BaselineRisk::Critical,
        value_kind: BaselineValueKind::Boolean,
        reading: Reading::Files(REDIS_FILES),
        implicit: Some("on"),
        file: "/etc/redis/redis.conf",
        key: "protected-mode",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "redis-requirepass",
        category: BaselineCategory::Authentication,
        component: BaselineComponent::Redis,
        title: "设置访问口令",
        description: "只检查有没有设置，不读取也不显示它的值。",
        recommendation: PRESENCE_MARKER,
        risk: BaselineRisk::Critical,
        value_kind: BaselineValueKind::Presence,
        reading: Reading::Files(REDIS_FILES),
        implicit: None,
        file: "/etc/redis/redis.conf",
        key: "requirepass",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "redis-bind",
        category: BaselineCategory::AccessControl,
        component: BaselineComponent::Redis,
        title: "限定监听地址",
        description: "没有 bind 行时 Redis 监听所有网卡。只检查是否显式限定过。",
        recommendation: PRESENCE_MARKER,
        risk: BaselineRisk::Critical,
        value_kind: BaselineValueKind::Presence,
        reading: Reading::Files(REDIS_FILES),
        implicit: None,
        file: "/etc/redis/redis.conf",
        key: "bind",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "redis-logfile",
        category: BaselineCategory::Logging,
        component: BaselineComponent::Redis,
        title: "日志写到文件",
        description: "logfile 为空时日志只写标准输出，重启后什么都不剩。",
        recommendation: PRESENCE_MARKER,
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Presence,
        reading: Reading::Files(REDIS_FILES),
        implicit: None,
        file: "/etc/redis/redis.conf",
        key: "logfile",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::None,
    },
    // ---- MongoDB -----------------------------------------------------------
    BaselineDefinition {
        id: "mongodb-authorization",
        category: BaselineCategory::Authentication,
        component: BaselineComponent::MongoDb,
        title: "开启鉴权",
        description: "默认不开鉴权，任何能连上的人都是管理员。",
        recommendation: "enabled",
        risk: BaselineRisk::Critical,
        value_kind: BaselineValueKind::Choice(MONGO_AUTHORIZATION),
        reading: Reading::Files(MONGODB_FILES),
        implicit: Some("disabled"),
        file: "/etc/mongod.conf",
        key: "security.authorization",
        format: FileFormat::Yaml,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "mongodb-bind-ip",
        category: BaselineCategory::AccessControl,
        component: BaselineComponent::MongoDb,
        title: "只监听本机",
        description: "绑定 0.0.0.0 会把整个库暴露到网络上。",
        recommendation: "127.0.0.1",
        risk: BaselineRisk::Critical,
        value_kind: BaselineValueKind::Choice(MONGO_BIND),
        reading: Reading::Files(MONGODB_FILES),
        implicit: Some("127.0.0.1"),
        file: "/etc/mongod.conf",
        key: "net.bindIp",
        format: FileFormat::Yaml,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "mongodb-javascript",
        category: BaselineCategory::ServiceHardening,
        component: BaselineComponent::MongoDb,
        title: "关闭服务端 JavaScript",
        description: "服务端 JavaScript 让一次注入可以直接在库里执行代码。",
        recommendation: "off",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Boolean,
        reading: Reading::Files(MONGODB_FILES),
        implicit: Some("on"),
        file: "/etc/mongod.conf",
        key: "security.javascriptEnabled",
        format: FileFormat::Yaml,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "mongodb-tls-mode",
        category: BaselineCategory::Transport,
        component: BaselineComponent::MongoDb,
        title: "强制传输加密",
        description: "不强制 TLS 时，认证与数据都以明文经过网络。",
        recommendation: "requiretls",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Choice(MONGO_TLS_MODE),
        reading: Reading::Files(MONGODB_FILES),
        implicit: Some("disabled"),
        file: "/etc/mongod.conf",
        key: "net.tls.mode",
        format: FileFormat::Yaml,
        reload: ReloadGroup::None,
    },
    // ---- Nginx -------------------------------------------------------------
    BaselineDefinition {
        id: "nginx-server-tokens",
        category: BaselineCategory::ServiceHardening,
        component: BaselineComponent::Nginx,
        title: "隐藏版本号",
        description: "响应头和错误页里的版本号，等于直接告诉对方该用哪个漏洞。",
        recommendation: "off",
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Boolean,
        reading: Reading::Files(NGINX_FILES),
        implicit: Some("on"),
        file: "/etc/nginx/nginx.conf",
        key: "server_tokens",
        format: FileFormat::Semicolon,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "nginx-autoindex",
        category: BaselineCategory::ServiceHardening,
        component: BaselineComponent::Nginx,
        title: "关闭目录浏览",
        description: "开着目录索引，没有首页的目录会把里面所有文件列出来。",
        recommendation: "off",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Boolean,
        reading: Reading::Files(NGINX_FILES),
        implicit: Some("off"),
        file: "/etc/nginx/nginx.conf",
        key: "autoindex",
        format: FileFormat::Semicolon,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "nginx-ssl-protocols",
        category: BaselineCategory::Transport,
        component: BaselineComponent::Nginx,
        title: "显式指定 TLS 版本",
        description: "只检查是否显式写过；没写就跟随编译默认，可能仍然接受已被淘汰的版本。",
        recommendation: PRESENCE_MARKER,
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Presence,
        reading: Reading::Files(NGINX_FILES),
        implicit: None,
        file: "/etc/nginx/nginx.conf",
        key: "ssl_protocols",
        format: FileFormat::Semicolon,
        reload: ReloadGroup::None,
    },
    // ---- Apache HTTP Server ------------------------------------------------
    BaselineDefinition {
        id: "apache-server-tokens",
        category: BaselineCategory::ServiceHardening,
        component: BaselineComponent::Apache,
        title: "隐藏版本与模块",
        description: "默认会连同版本号和已装模块一起报出去。Prod 只报产品名。",
        recommendation: "prod",
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Choice(APACHE_SERVER_TOKENS),
        reading: Reading::Files(APACHE_FILES),
        implicit: Some("full"),
        file: "/etc/httpd/conf/httpd.conf",
        key: "ServerTokens",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "apache-server-signature",
        category: BaselineCategory::ServiceHardening,
        component: BaselineComponent::Apache,
        title: "错误页不带签名",
        description: "错误页脚注里的版本与主机名会一并泄露。",
        recommendation: "off",
        risk: BaselineRisk::Low,
        value_kind: BaselineValueKind::Boolean,
        reading: Reading::Files(APACHE_FILES),
        implicit: Some("off"),
        file: "/etc/httpd/conf/httpd.conf",
        key: "ServerSignature",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "apache-trace-enable",
        category: BaselineCategory::ServiceHardening,
        component: BaselineComponent::Apache,
        title: "关闭 TRACE 方法",
        description: "TRACE 会把请求原样回显，可被用来读取本不该被脚本读到的头部。",
        recommendation: "off",
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Boolean,
        reading: Reading::Files(APACHE_FILES),
        implicit: Some("on"),
        file: "/etc/httpd/conf/httpd.conf",
        key: "TraceEnable",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "nginx-access-log",
        category: BaselineCategory::Logging,
        component: BaselineComponent::Nginx,
        title: "记录访问日志",
        description: "关掉访问日志之后，谁请求过什么就再也查不出来了。只检查是否显式配过。",
        recommendation: PRESENCE_MARKER,
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Presence,
        reading: Reading::Files(NGINX_FILES),
        implicit: None,
        file: "/etc/nginx/nginx.conf",
        key: "access_log",
        format: FileFormat::Semicolon,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "nginx-error-log",
        category: BaselineCategory::Logging,
        component: BaselineComponent::Nginx,
        title: "记录错误日志",
        description: "错误日志里是拒绝、超时和后端异常，排查入侵时先看的就是它。",
        recommendation: PRESENCE_MARKER,
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Presence,
        reading: Reading::Files(NGINX_FILES),
        implicit: None,
        file: "/etc/nginx/nginx.conf",
        key: "error_log",
        format: FileFormat::Semicolon,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "apache-error-log",
        category: BaselineCategory::Logging,
        component: BaselineComponent::Apache,
        title: "记录错误日志",
        description: "没有错误日志，拒绝与异常都不会留下痕迹。",
        recommendation: PRESENCE_MARKER,
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Presence,
        reading: Reading::Files(APACHE_FILES),
        implicit: None,
        file: "/etc/httpd/conf/httpd.conf",
        key: "ErrorLog",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "apache-custom-log",
        category: BaselineCategory::Logging,
        component: BaselineComponent::Apache,
        title: "记录访问日志",
        description: "关掉访问日志之后，谁请求过什么就再也查不出来了。",
        recommendation: PRESENCE_MARKER,
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Presence,
        reading: Reading::Files(APACHE_FILES),
        implicit: None,
        file: "/etc/httpd/conf/httpd.conf",
        key: "CustomLog",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "apache-log-level",
        category: BaselineCategory::Logging,
        component: BaselineComponent::Apache,
        title: "日志级别不要调得太高",
        description: "调到 crit 以上时，被拒绝的请求和模块报错都不会写进日志。",
        recommendation: "warn",
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Choice(APACHE_LOG_LEVEL),
        reading: Reading::Files(APACHE_FILES),
        implicit: Some("warn"),
        file: "/etc/httpd/conf/httpd.conf",
        key: "LogLevel",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "redis-rename-command",
        category: BaselineCategory::ServiceHardening,
        component: BaselineComponent::Redis,
        title: "危险命令改名",
        description: "CONFIG、FLUSHALL、KEYS 改名后，拿到未授权连接的人也用不了它们。只检查是否改过。",
        recommendation: PRESENCE_MARKER,
        risk: BaselineRisk::Low,
        value_kind: BaselineValueKind::Presence,
        reading: Reading::Files(REDIS_FILES),
        implicit: None,
        file: "/etc/redis/redis.conf",
        key: "rename-command",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "redis-debug-command",
        category: BaselineCategory::ServiceHardening,
        component: BaselineComponent::Redis,
        title: "关闭 DEBUG 命令",
        description: "DEBUG 能让服务器崩溃、也能读写内部结构。Redis 7 起默认关闭。",
        recommendation: "off",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Boolean,
        reading: Reading::Files(REDIS_FILES),
        implicit: Some("off"),
        file: "/etc/redis/redis.conf",
        key: "enable-debug-command",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "redis-module-command",
        category: BaselineCategory::ServiceHardening,
        component: BaselineComponent::Redis,
        title: "关闭 MODULE 命令",
        description: "MODULE LOAD 可以把任意 .so 加载进 Redis 进程，等于直接执行代码。",
        recommendation: "off",
        risk: BaselineRisk::Critical,
        value_kind: BaselineValueKind::Boolean,
        reading: Reading::Files(REDIS_FILES),
        implicit: Some("off"),
        file: "/etc/redis/redis.conf",
        key: "enable-module-command",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "mongodb-tls-require-client-cert",
        category: BaselineCategory::Transport,
        component: BaselineComponent::MongoDb,
        title: "不接受无证书连接",
        description: "开了 TLS 却允许无证书连接，等于只加密不认证。",
        recommendation: "off",
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Boolean,
        reading: Reading::Files(MONGODB_FILES),
        implicit: Some("off"),
        file: "/etc/mongod.conf",
        key: "net.tls.allowConnectionsWithoutCertificates",
        format: FileFormat::Yaml,
        reload: ReloadGroup::None,
    },
    // ---- Apache Tomcat -----------------------------------------------------
    BaselineDefinition {
        id: "tomcat-shutdown-port",
        category: BaselineCategory::AccessControl,
        component: BaselineComponent::Tomcat,
        title: "关闭关机端口",
        description: "8005 端口收到一个固定单词就会停掉整个服务；设为 -1 可以彻底不监听它。",
        recommendation: "-1",
        risk: BaselineRisk::Critical,
        value_kind: BaselineValueKind::Choice(TOMCAT_SHUTDOWN_PORT),
        reading: Reading::Files(TOMCAT_SERVER_FILES),
        implicit: None,
        file: "/usr/local/tomcat/conf/server.xml",
        key: "port",
        format: FileFormat::XmlAttribute("Server"),
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "tomcat-allow-trace",
        category: BaselineCategory::ServiceHardening,
        component: BaselineComponent::Tomcat,
        title: "关闭 TRACE 方法",
        description: "TRACE 会把请求连同头部一起回显。检查每一个未被注释掉的连接器。",
        recommendation: "off",
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Boolean,
        reading: Reading::Files(TOMCAT_SERVER_FILES),
        implicit: Some("off"),
        file: "/usr/local/tomcat/conf/server.xml",
        key: "allowTrace",
        format: FileFormat::XmlAttribute("Connector"),
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "tomcat-xpowered-by",
        category: BaselineCategory::ServiceHardening,
        component: BaselineComponent::Tomcat,
        title: "不发 X-Powered-By",
        description: "这个响应头会报出 Servlet 与 JSP 版本，等于告诉对方该找哪些漏洞。",
        recommendation: "off",
        risk: BaselineRisk::Low,
        value_kind: BaselineValueKind::Boolean,
        reading: Reading::Files(TOMCAT_SERVER_FILES),
        implicit: Some("off"),
        file: "/usr/local/tomcat/conf/server.xml",
        key: "xpoweredBy",
        format: FileFormat::XmlAttribute("Connector"),
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "tomcat-server-header",
        category: BaselineCategory::ServiceHardening,
        component: BaselineComponent::Tomcat,
        title: "改掉 Server 响应头",
        description: "不设置时响应头是 Apache-Coyote/1.1，一眼就能认出是 Tomcat。只检查是否设过。",
        recommendation: PRESENCE_MARKER,
        risk: BaselineRisk::Low,
        value_kind: BaselineValueKind::Presence,
        reading: Reading::Files(TOMCAT_SERVER_FILES),
        implicit: None,
        file: "/usr/local/tomcat/conf/server.xml",
        key: "server",
        format: FileFormat::XmlAttribute("Connector"),
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "tomcat-auto-deploy",
        category: BaselineCategory::ServiceHardening,
        component: BaselineComponent::Tomcat,
        title: "关闭自动部署",
        description: "开着自动部署时，往 webapps 里丢一个 war 就会被自动展开运行。",
        recommendation: "off",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Boolean,
        reading: Reading::Files(TOMCAT_SERVER_FILES),
        implicit: Some("on"),
        file: "/usr/local/tomcat/conf/server.xml",
        key: "autoDeploy",
        format: FileFormat::XmlAttribute("Host"),
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "tomcat-deploy-xml",
        category: BaselineCategory::ServiceHardening,
        component: BaselineComponent::Tomcat,
        title: "不读应用自带的 context.xml",
        description: "允许后，应用可以自己声明数据源、跨应用访问和特权配置。",
        recommendation: "off",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Boolean,
        reading: Reading::Files(TOMCAT_SERVER_FILES),
        implicit: Some("on"),
        file: "/usr/local/tomcat/conf/server.xml",
        key: "deployXML",
        format: FileFormat::XmlAttribute("Host"),
        reload: ReloadGroup::None,
    },
    // ---- HAProxy -----------------------------------------------------------
    BaselineDefinition {
        id: "haproxy-log",
        category: BaselineCategory::Logging,
        component: BaselineComponent::HaProxy,
        title: "把日志送出去",
        description: "没有 log 目标时，经过这台代理的请求一条都不会被记下来。",
        recommendation: PRESENCE_MARKER,
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Presence,
        reading: Reading::Files(HAPROXY_FILES),
        implicit: None,
        file: "/etc/haproxy/haproxy.cfg",
        key: "log",
        format: FileFormat::IndentSection("global"),
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "haproxy-user",
        category: BaselineCategory::ServiceHardening,
        component: BaselineComponent::HaProxy,
        title: "降权运行",
        description: "不指定 user 时进程留在 root 下，代理被打穿就直接是 root。",
        recommendation: PRESENCE_MARKER,
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Presence,
        reading: Reading::Files(HAPROXY_FILES),
        implicit: None,
        file: "/etc/haproxy/haproxy.cfg",
        key: "user",
        format: FileFormat::IndentSection("global"),
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "haproxy-chroot",
        category: BaselineCategory::ServiceHardening,
        component: BaselineComponent::HaProxy,
        title: "限制文件系统视野",
        description: "chroot 之后进程看不到自己目录以外的文件系统。",
        recommendation: PRESENCE_MARKER,
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Presence,
        reading: Reading::Files(HAPROXY_FILES),
        implicit: None,
        file: "/etc/haproxy/haproxy.cfg",
        key: "chroot",
        format: FileFormat::IndentSection("global"),
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "haproxy-ssl-bind-options",
        category: BaselineCategory::Transport,
        component: BaselineComponent::HaProxy,
        title: "显式指定 TLS 下限",
        description: "只检查是否写过；没写就跟随编译默认，可能仍然接受已被淘汰的版本。",
        recommendation: PRESENCE_MARKER,
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Presence,
        reading: Reading::Files(HAPROXY_FILES),
        implicit: None,
        file: "/etc/haproxy/haproxy.cfg",
        key: "ssl-default-bind-options",
        format: FileFormat::IndentSection("global"),
        reload: ReloadGroup::None,
    },
    // ---- openGauss ---------------------------------------------------------
    BaselineDefinition {
        id: "opengauss-listen-addresses",
        category: BaselineCategory::AccessControl,
        component: BaselineComponent::OpenGauss,
        title: "只监听本机",
        description: "监听 * 或 0.0.0.0 表示任何能到达这台机器的人都能尝试认证。",
        recommendation: "localhost",
        risk: BaselineRisk::Critical,
        value_kind: BaselineValueKind::Choice(PG_LISTEN),
        reading: Reading::Files(OPENGAUSS_FILES),
        implicit: Some("localhost"),
        file: "/var/lib/opengauss/data/postgresql.conf",
        key: "listen_addresses",
        format: FileFormat::Equals,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "opengauss-password-encryption-type",
        category: BaselineCategory::Password,
        component: BaselineComponent::OpenGauss,
        title: "口令只用 SHA-256 存放",
        description: "0 表示只存 MD5，1 表示同时存 MD5 与 SHA-256，两者都留下可离线爆破的散列。2 只存 SHA-256。",
        recommendation: "2",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Choice(OPENGAUSS_PASSWORD_TYPE),
        reading: Reading::Files(OPENGAUSS_FILES),
        implicit: None,
        file: "/var/lib/opengauss/data/postgresql.conf",
        key: "password_encryption_type",
        format: FileFormat::Equals,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "opengauss-ssl",
        category: BaselineCategory::Transport,
        component: BaselineComponent::OpenGauss,
        title: "启用传输加密",
        description: "不开 SSL 时，口令与查询结果在网络上是明文。",
        recommendation: "on",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Boolean,
        reading: Reading::Files(OPENGAUSS_FILES),
        implicit: Some("off"),
        file: "/var/lib/opengauss/data/postgresql.conf",
        key: "ssl",
        format: FileFormat::Equals,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "opengauss-audit-enabled",
        category: BaselineCategory::Logging,
        component: BaselineComponent::OpenGauss,
        title: "开启审计",
        description: "openGauss 自带审计，关掉之后登录、授权与结构变更都不会留下记录。",
        recommendation: "on",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Boolean,
        reading: Reading::Files(OPENGAUSS_FILES),
        implicit: Some("on"),
        file: "/var/lib/opengauss/data/postgresql.conf",
        key: "audit_enabled",
        format: FileFormat::Equals,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "opengauss-log-connections",
        category: BaselineCategory::Logging,
        component: BaselineComponent::OpenGauss,
        title: "记录连接建立",
        description: "不记录连接，就无从知道是谁在什么时候连过这个库。",
        recommendation: "on",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Boolean,
        reading: Reading::Files(OPENGAUSS_FILES),
        implicit: Some("off"),
        file: "/var/lib/opengauss/data/postgresql.conf",
        key: "log_connections",
        format: FileFormat::Equals,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "opengauss-failed-login-attempts",
        category: BaselineCategory::Authentication,
        component: BaselineComponent::OpenGauss,
        title: "限制连续认证失败次数",
        description: "设为 0 表示不锁定，账号可以被无限次尝试口令。",
        recommendation: "5",
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Integer {
            minimum: 1,
            maximum: 10,
        },
        reading: Reading::Files(OPENGAUSS_FILES),
        implicit: None,
        file: "/var/lib/opengauss/data/postgresql.conf",
        key: "failed_login_attempts",
        format: FileFormat::Equals,
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "opengauss-log-statement",
        category: BaselineCategory::Logging,
        component: BaselineComponent::OpenGauss,
        title: "记录结构变更语句",
        description: "至少记下建表、改表、授权这类语句，事后才看得出库结构被谁动过。",
        recommendation: "ddl",
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Choice(PG_LOG_STATEMENT),
        reading: Reading::Files(OPENGAUSS_FILES),
        implicit: Some("none"),
        file: "/var/lib/opengauss/data/postgresql.conf",
        key: "log_statement",
        format: FileFormat::Equals,
        reload: ReloadGroup::None,
    },
    // ---- TiDB --------------------------------------------------------------
    BaselineDefinition {
        id: "tidb-host",
        category: BaselineCategory::AccessControl,
        component: BaselineComponent::TiDb,
        title: "只监听本机",
        description: "绑定 0.0.0.0 会把 MySQL 协议端口暴露给整个网络。",
        recommendation: "127.0.0.1",
        risk: BaselineRisk::Critical,
        value_kind: BaselineValueKind::Choice(MYSQL_BIND),
        reading: Reading::Files(TIDB_FILES),
        implicit: Some("0.0.0.0"),
        file: "/etc/tidb/tidb.toml",
        key: "host",
        format: FileFormat::Ini(""),
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "tidb-status-host",
        category: BaselineCategory::AccessControl,
        component: BaselineComponent::TiDb,
        title: "状态端口只对本机开放",
        description: "状态端口会吐出完整配置与运行指标，不需要认证就能读。",
        recommendation: "127.0.0.1",
        risk: BaselineRisk::Critical,
        value_kind: BaselineValueKind::Choice(MYSQL_BIND),
        reading: Reading::Files(TIDB_FILES),
        implicit: Some("0.0.0.0"),
        file: "/etc/tidb/tidb.toml",
        key: "status-host",
        format: FileFormat::Ini(""),
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "tidb-skip-grant-table",
        category: BaselineCategory::Authentication,
        component: BaselineComponent::TiDb,
        title: "不要跳过权限表",
        description: "打开之后任何人不用口令就是管理员，并且可以读取服务器上的任意文件。",
        recommendation: "off",
        risk: BaselineRisk::Critical,
        value_kind: BaselineValueKind::Boolean,
        reading: Reading::Files(TIDB_FILES),
        implicit: Some("off"),
        file: "/etc/tidb/tidb.toml",
        key: "skip-grant-table",
        format: FileFormat::Ini("security"),
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "tidb-ssl-ca",
        category: BaselineCategory::Transport,
        component: BaselineComponent::TiDb,
        title: "客户端连接加密",
        description: "只检查是否配了 CA 证书；留空表示客户端与服务器之间是明文。",
        recommendation: PRESENCE_MARKER,
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Presence,
        reading: Reading::Files(TIDB_FILES),
        implicit: None,
        file: "/etc/tidb/tidb.toml",
        key: "ssl-ca",
        format: FileFormat::Ini("security"),
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "tidb-cluster-ssl-ca",
        category: BaselineCategory::Transport,
        component: BaselineComponent::TiDb,
        title: "集群内部通信加密",
        description: "TiDB 与 PD、TiKV 之间也要加密，否则内网抓包即可读到全部数据。",
        recommendation: PRESENCE_MARKER,
        risk: BaselineRisk::High,
        value_kind: BaselineValueKind::Presence,
        reading: Reading::Files(TIDB_FILES),
        implicit: None,
        file: "/etc/tidb/tidb.toml",
        key: "cluster-ssl-ca",
        format: FileFormat::Ini("security"),
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "tidb-log-level",
        category: BaselineCategory::Logging,
        component: BaselineComponent::TiDb,
        title: "日志级别不要调得太高",
        description: "只记 error 时，连接、认证与慢查询都不会写进日志，事后无从追查。",
        recommendation: "info",
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Choice(TIDB_LOG_LEVEL),
        reading: Reading::Files(TIDB_FILES),
        implicit: Some("info"),
        file: "/etc/tidb/tidb.toml",
        key: "level",
        format: FileFormat::Ini("log"),
        reload: ReloadGroup::None,
    },
    BaselineDefinition {
        id: "tidb-log-file",
        category: BaselineCategory::Logging,
        component: BaselineComponent::TiDb,
        title: "日志写到文件",
        description: "不指定文件时日志只写标准输出，容器里通常等于没有留存。",
        recommendation: PRESENCE_MARKER,
        risk: BaselineRisk::Medium,
        value_kind: BaselineValueKind::Presence,
        reading: Reading::Files(TIDB_FILES),
        implicit: None,
        file: "/etc/tidb/tidb.toml",
        key: "filename",
        format: FileFormat::Ini("log.file"),
        reload: ReloadGroup::None,
    },
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", content = "value", rename_all = "kebab-case")]
pub enum BaselineObservedValue {
    Missing,
    Unsupported,
    /// The software this check is about is not on this target: none of the
    /// paths it could keep its configuration in exists.
    ///
    /// This is not the same as "not set", and reporting it as such was the
    /// difference between a table of findings and a table where forty rows of
    /// absent software buried the four that mattered.
    NotInstalled,
    Value(String),
}

impl BaselineObservedValue {
    pub fn label(&self) -> &str {
        match self {
            Self::Missing => "未设置",
            Self::Unsupported => "不支持（符号链接或特殊文件）",
            Self::NotInstalled => "未安装",
            Self::Value(value) => value,
        }
    }

    /// Whether this check applies to the target at all. A check on software
    /// the target does not run is neither passed nor failed.
    pub fn applies(&self) -> bool {
        !matches!(self, Self::NotInstalled)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineStatus {
    pub item_id: String,
    pub observed: BaselineObservedValue,
    pub compliant: bool,
    /// The file on this target that decides this setting.
    ///
    /// Where the value was read from when it was found, and where a change
    /// would go when it was not. Empty only when the software is absent.
    pub source_file: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineScan {
    pub target: TargetGuard,
    pub statuses: Vec<BaselineStatus>,
    pub captured_at: DateTime<Utc>,
}

/// One of the six fixed configuration files, as it stands on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineFileView {
    /// The file the setting is read from. Fixed by the catalogue.
    pub path: &'static str,
    /// The directive this view was opened for.
    pub key: &'static str,
    pub exists: bool,
    /// The file as it is on the host, control characters aside.
    pub text: String,
    /// Every line that mentions the directive, in file order.
    pub mentions: Vec<BaselineFileMention>,
    /// True when the file was longer than the ceiling and was cut short.
    pub truncated: bool,
}

/// A line that mentions the directive this view was opened for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaselineFileMention {
    /// Zero-based index into the text that was returned.
    pub line: u32,
    /// Whether this line is commented out, and so sets nothing.
    pub commented: bool,
    /// Whether this is the line the program on the host actually obeys.
    ///
    /// At most one line is effective. A commented line never is, and when the
    /// directive appears more than once the answer depends on which end the
    /// reader starts from — see [`Precedence`].
    pub effective: bool,
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
    /// The file on this target the change is written to.
    ///
    /// Taken from the scan that found the current value, so the edit lands on
    /// the file the target is actually obeying rather than on the one path
    /// this tool was compiled knowing. It is backed up before it is touched
    /// and restored from that backup if anything downstream fails.
    ///
    /// Absent from records written before changes could target anything but
    /// the packaged path; those load with an empty string, which resolves back
    /// to that path.
    #[serde(default)]
    pub file: String,
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
    #[serde(deserialize_with = "deserialize_baseline_history_changes")]
    changes: Vec<BaselineChangeRecord>,
}

fn deserialize_baseline_history_changes<'de, D>(
    deserializer: D,
) -> Result<Vec<BaselineChangeRecord>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BaselineHistoryVisitor;

    impl<'de> Visitor<'de> for BaselineHistoryVisitor {
        type Value = Vec<BaselineChangeRecord>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAX_HISTORY} baseline history records")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut changes =
                Vec::with_capacity(sequence.size_hint().unwrap_or_default().min(MAX_HISTORY));
            while changes.len() < MAX_HISTORY {
                let Some(change) = sequence.next_element()? else {
                    return Ok(changes);
                };
                changes.push(change);
            }
            if sequence.next_element::<IgnoredAny>()?.is_some() {
                return Err(A::Error::custom(
                    "baseline history count exceeds its storage budget",
                ));
            }
            Ok(changes)
        }
    }

    deserializer.deserialize_seq(BaselineHistoryVisitor)
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

    /// Reads the file one setting lives in, and says which lines mention it.
    ///
    /// The caller names a setting, never a file: the path comes from the fixed
    /// catalogue, so this can only ever read one of six known configuration
    /// files. Reading is what makes a check answerable — a status of
    /// "不合规" is an assertion, and the operator has to be able to see the
    /// line it was made from.
    pub async fn read_setting_file(
        &self,
        session: &BoundSshSession,
        item_id: &str,
    ) -> CoreResult<BaselineFileView> {
        self.target.validate(session.target())?;
        let definition = definition(item_id)?;
        let output = successful_output(
            "read baseline configuration file",
            self.ssh
                .execute_bound(session, read_file_command(definition), COMMAND_TIMEOUT)
                .await?,
        )?;
        self.target.validate(session.target())?;
        parse_file_view(definition, &output)
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
                file: status.source_file.clone(),
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
            .load_stored_baseline_history()?
            .changes
            .into_iter()
            .filter(|record| record.target == target.identity)
            .collect::<Vec<_>>();
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
        let mut stored = self.load_stored_baseline_history()?;
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
        self.target.validate(target)?;
        let _guard = self.lock.lock();
        let record = self
            .load_stored_baseline_history()?
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
        let mut stored = self.load_stored_baseline_history()?;
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

    fn load_stored_baseline_history(&self) -> CoreResult<StoredBaselineHistory> {
        let stored = self
            .store
            .read_or_default_bounded::<StoredBaselineHistory>(
                StoreFile::Baseline,
                MAX_BASELINE_HISTORY_DOCUMENT_BYTES,
            )?;
        if stored.changes.len() > MAX_HISTORY {
            return Err(CoreError::validation(
                "baseline changes",
                "the stored history count exceeds its storage budget",
            ));
        }
        for record in &stored.changes {
            validate_record(record)?;
        }
        Ok(stored)
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

/// What to change, where, and what to run afterwards.
///
/// Derived from the check rather than written out beside it: a hand-written
/// instruction next to seventy-five checks is seventy-five chances for the
/// instruction and the check to say different things, and the one that goes
/// stale is always the prose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineRemediation {
    /// The file to edit on this target, as the scan found it.
    pub file: String,
    /// The exact lines to put in it.
    pub lines: Vec<String>,
    /// What makes the change take effect, if anything.
    pub reload: Option<String>,
    /// Set when this tool will not write the change itself.
    pub manual_reason: Option<&'static str>,
}

impl BaselineDefinition {
    /// The instruction for bringing one setting to its recommended value.
    ///
    /// `source_file` is where the scan found the setting on this target; pass
    /// an empty string before a scan and the packaged path is used.
    pub fn remediation(&self, source_file: &str) -> BaselineRemediation {
        let file = if source_file.trim().is_empty() {
            self.file.to_owned()
        } else {
            source_file.trim().to_owned()
        };
        let value = self.recommendation;
        let lines = match self.format {
            FileFormat::Whitespace => vec![format!("{} {value}", self.key)],
            FileFormat::Equals => vec![format!("{} = {value}", self.key)],
            FileFormat::Semicolon => vec![format!("{} {value};", self.key)],
            FileFormat::Ini(section) => {
                vec![format!("[{section}]"), format!("{} = {value}", self.key)]
            }
            FileFormat::IndentSection(section) => {
                vec![section.to_owned(), format!("    {} {value}", self.key)]
            }
            FileFormat::XmlAttribute(element) => vec![format!(
                "<{element} … {}=\"{value}\" …>（每一个未被注释掉的 {element}）",
                self.key
            )],
            FileFormat::Yaml => self
                .key
                .split('.')
                .enumerate()
                .map(|(level, part)| {
                    let indent = "  ".repeat(level);
                    if level + 1 == self.key.split('.').count() {
                        format!("{indent}{part}: {value}")
                    } else {
                        format!("{indent}{part}:")
                    }
                })
                .collect(),
        };
        let lines = if self.value_kind == BaselineValueKind::Presence {
            // There is no value to print: the operator chooses it, and this
            // tool must not see it.
            lines
                .iter()
                .map(|line| line.replace(PRESENCE_MARKER, "<自行设定>"))
                .collect()
        } else {
            lines
        };
        BaselineRemediation {
            file,
            lines,
            reload: self.reload_command().map(str::to_owned),
            manual_reason: if self.is_writable() {
                None
            } else {
                Some("这一项的值是凭据，请自行填写后再重载服务。")
            },
        }
    }

    /// What makes a change to this setting take effect.
    pub const fn reload_command(&self) -> Option<&'static str> {
        match self.reload {
            ReloadGroup::Sshd => Some("systemctl reload sshd（或 service ssh reload）"),
            ReloadGroup::Sysctl => Some("sysctl --system"),
            ReloadGroup::None => match self.component {
                BaselineComponent::System | BaselineComponent::Ssh => None,
                BaselineComponent::MySql => Some("systemctl restart mariadb（或 mysqld / mysql）"),
                BaselineComponent::PostgreSql => Some("systemctl reload postgresql"),
                BaselineComponent::Redis => Some("systemctl restart redis（或 redis-server）"),
                BaselineComponent::MongoDb => Some("systemctl restart mongod"),
                BaselineComponent::Nginx => Some("nginx -t && systemctl reload nginx"),
                BaselineComponent::Apache => {
                    Some("apachectl configtest && systemctl reload httpd（或 apache2）")
                }
                // Tomcat reads server.xml once at start; there is no reload.
                BaselineComponent::Tomcat => Some("systemctl restart tomcat（需要重启才生效）"),
                BaselineComponent::OpenGauss => Some("gs_ctl reload -D <数据目录>"),
                BaselineComponent::TiDb => Some("重启 tidb-server（配置只在启动时读取）"),
                BaselineComponent::HaProxy => {
                    Some("haproxy -c -f <配置文件> && systemctl reload haproxy")
                }
            },
        }
    }
}

/// Whether what the target is doing matches what the check asks for.
fn compliance_of(definition: &BaselineDefinition, observed: &BaselineObservedValue) -> bool {
    let effective = match observed {
        // A presence check has no value to compare: the marker is the whole
        // answer, and it only appears when the directive is set.
        BaselineObservedValue::Value(value)
            if definition.value_kind == BaselineValueKind::Presence =>
        {
            return value == PRESENCE_MARKER;
        }
        BaselineObservedValue::Value(value) => value.as_str(),
        // Nothing written down means the software uses its own default, and if
        // that default is what the check asks for then there is nothing wrong.
        BaselineObservedValue::Missing => match definition.implicit {
            Some(default) => default,
            None => return false,
        },
        // Software that is not installed cannot be out of compliance; callers
        // read `observed.applies()` before counting this either way.
        BaselineObservedValue::Unsupported | BaselineObservedValue::NotInstalled => return false,
    };
    normalize_requested_value(definition, effective)
        .is_ok_and(|value| value == definition.recommendation)
}

/// Refuses a change to a check this tool only knows how to read.
fn read_only_check(definition: &BaselineDefinition) -> CoreError {
    CoreError::validation(
        "baseline change",
        format!(
            "{} 是只读检查：请按建议手动修改 {}",
            definition.id, definition.file
        ),
    )
}

fn normalize_requested_value(definition: &BaselineDefinition, value: &str) -> CoreResult<String> {
    let value = value.trim();
    match definition.value_kind {
        // There is no value to write: the check reports only that a directive
        // is set, because its value is a credential.
        BaselineValueKind::Presence => Err(read_only_check(definition)),
        BaselineValueKind::Boolean => BaselineValueKind::as_boolean(value)
            .map(str::to_owned)
            .ok_or_else(|| {
                CoreError::validation("baseline value", format!("{} 只接受开关值", definition.id))
            }),
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

/// The characters an observed value may contain, on the target and again here.
///
/// It used to be letters, digits, underscore and hyphen, which was enough for
/// `yes`/`no` and a number and destroyed everything else: an address came back
/// as `127001`, a `*` came back empty and so read as "not set", and a log path
/// lost its slashes. Widened to what a configuration value is actually made
/// of, and no further — nothing here can start a command, close a quote or
/// carry a newline.
const OBSERVED_VALUE_CHARS: &str = "A-Za-z0-9_.:*/,+-";

/// The same set, written for an awk bracket expression: the slash is escaped
/// and the hyphen sits last so it is a character and not a range.
const PRESENCE_VALUE_CHARS: &str = "A-Za-z0-9_.:*\\/,+-";

fn validate_observed(value: &BaselineObservedValue) -> CoreResult<()> {
    if let BaselineObservedValue::Value(value) = value
        && (value.is_empty()
            || value.len() > 64
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'_' | b'-' | b'.' | b':' | b'*' | b'/' | b',' | b'+')
            }))
    {
        return Err(CoreError::validation(
            "baseline observed value",
            "must be a bounded inert token",
        ));
    }
    Ok(())
}

/// The distinct awk programs, written once and referred to by name.
///
/// Every check used to carry its own copy of the program that reads it, and at
/// eighty-one checks that came to 135 kB. A Linux kernel will not accept a
/// single argument longer than 128 kB, so the login shell rejected the whole
/// scan with "Argument list too long" before a single file was read — the
/// catalogue had quietly grown past what one command could carry. There are
/// only a handful of distinct programs; the repetition was all of the size.
#[derive(Default)]
struct ProgramTable {
    programs: Vec<String>,
}

impl ProgramTable {
    /// The shell expansion for this program, adding it if it is new.
    fn name(&mut self, program: &str) -> String {
        let index = self
            .programs
            .iter()
            .position(|existing| existing == program)
            .unwrap_or_else(|| {
                self.programs.push(program.to_owned());
                self.programs.len() - 1
            });
        format!("\"$LR_P{index}\"")
    }

    fn prelude(&self) -> String {
        self.programs
            .iter()
            .enumerate()
            .map(|(index, program)| format!("LR_P{index}={}; ", shq(program)))
            .collect()
    }
}

fn scan_command() -> String {
    let mut table = ProgramTable::default();
    let mut items = String::new();
    for definition in BASELINE_CATALOG {
        items.push_str(&item_command(definition, &mut table));
    }
    format!(
        "set -u; printf '%s\\n' {SCAN_MARKER}; {}{}{items}",
        table.prelude(),
        scan_functions(),
    )
}

/// The shell that reads one setting and prints one row.
///
/// Three answers have to be told apart and used to be two. "Not set" on a
/// machine that runs the software is a finding; the same word on a machine
/// that has never had that software installed is noise, and forty rows of it
/// is enough noise to hide the findings. A configuration file that is nowhere
/// to be found reports absent, and the check is not counted against the target.
/// The two shapes of read, written once as shell functions.
///
/// The rest of the size was here: the same forty lines of shell repeated once
/// per check. Each check is one call now.
fn scan_functions() -> String {
    format!(
        // lr_file id key want fallback reader witness installed candidates…
        "lr_file() {{ lr_id=$1; lr_key=$2; lr_want=$3; lr_where=$4; lr_fallback=$4; \
           lr_reader=$5; lr_witness=$6; lr_installed=$7; shift 7; \
           lr_files=; lr_odd=0; \
           for lr_candidate in \"$@\"; do \
             for lr_match in $lr_candidate; do \
               if [ -L \"$lr_match\" ] || {{ [ -e \"$lr_match\" ] && [ ! -f \"$lr_match\" ]; }}; then \
                 lr_odd=1; \
               elif [ -f \"$lr_match\" ]; then lr_files=\"$lr_files $lr_match\"; fi; \
             done; \
           done; \
           lr_seen=0; \
           for lr_candidate in $lr_files; do \
             [ \"$lr_candidate\" = \"$lr_fallback\" ] && lr_seen=1; \
           done; \
           if [ \"$lr_seen\" = 0 ] && [ -n \"$lr_files\" ]; then \
             for lr_candidate in $lr_files; do lr_where=$lr_candidate; done; \
           fi; \
           if [ -n \"$lr_files\" ]; then \
             lr_value=$(awk -v k=\"$lr_key\" -v r=\"$lr_want\" \"$lr_reader\" $lr_files | tail -n 1); \
             lr_value=$(printf '%s' \"$lr_value\" | tr -cd '{allowed}'); \
             [ -n \"$lr_value\" ] || lr_value=__missing__; \
             lr_found=$(awk -v k=\"$lr_key\" -v r=\"$lr_want\" \"$lr_witness\" $lr_files | tail -n 1); \
             [ -z \"$lr_found\" ] || lr_where=$lr_found; \
           elif [ \"$lr_odd\" = 1 ]; then lr_value=__unsupported__; \
           elif lr_present \"$lr_installed\"; then lr_value=__missing__; \
           else lr_value=__absent__; fi; \
           printf 'ITEM=%s\\t%s\\t%s\\n' \"$lr_id\" \"$lr_value\" \"$lr_where\"; }}; \
         lr_sysctl() {{ lr_id=$1; lr_key=$2; lr_where=$3; \
           if command -v sysctl >/dev/null 2>&1; then \
             lr_read=$(sysctl -n \"$lr_key\" 2>/dev/null || true); \
           else lr_read=$(cat /proc/sys/$(printf '%s' \"$lr_key\" | tr . /) 2>/dev/null || true); fi; \
           lr_read=$(printf '%s' \"$lr_read\" | tr -s '[:space:]' ' '); \
           lr_value=$(printf '%s' \"$lr_read\" | tr -cd '{allowed}'); \
           [ -n \"$lr_value\" ] || lr_value=__missing__; \
           printf 'ITEM=%s\\t%s\\t%s\\n' \"$lr_id\" \"$lr_value\" \"$lr_where\"; }}; \
         lr_present() {{ case $1 in {cases} *) return 1;; esac; }}; ",
        allowed = OBSERVED_VALUE_CHARS,
        cases = presence_cases(),
    )
}

/// Whether each optional product is on the target, as one `case` rather than
/// as a copy of the test beside every check that needs it.
fn presence_cases() -> String {
    let mut cases = String::new();
    for component in BaselineComponent::ALL {
        let Some(probe) = component.presence_probe() else {
            continue;
        };
        cases.push_str(&format!(
            "{key}) {probe};; ",
            key = shq(component_probe_key(component)),
        ));
    }
    // Anything with no probe of its own is part of every Linux.
    cases.push_str("'always') return 0;; ");
    cases
}

const fn component_probe_key(component: BaselineComponent) -> &'static str {
    match component {
        BaselineComponent::System | BaselineComponent::Ssh => "always",
        BaselineComponent::MySql => "mysql",
        BaselineComponent::PostgreSql => "postgresql",
        BaselineComponent::Redis => "redis",
        BaselineComponent::MongoDb => "mongodb",
        BaselineComponent::Nginx => "nginx",
        BaselineComponent::Apache => "apache",
        BaselineComponent::Tomcat => "tomcat",
        BaselineComponent::OpenGauss => "opengauss",
        BaselineComponent::TiDb => "tidb",
        BaselineComponent::HaProxy => "haproxy",
    }
}

/// One line per check: the call, and everything that differs between them.
///
/// Every file that exists is read, in the order the program reads them, with
/// the precedence rule applied across the whole set. Reading only the first
/// one found reported what the packaged default says — MySQL's `!includedir`
/// means a later file overrides an earlier one, and on a lab host with
/// `bind-address = 127.0.0.1` in the packaged file and an override elsewhere,
/// the check said the database was bound to the loopback while the server was
/// listening on every interface. sshd is the same shape read the other way
/// round: its `Include` sits at the top and it keeps the first value it sees,
/// so the dropped-in files win and are listed first.
fn item_command(definition: &BaselineDefinition, table: &mut ProgramTable) -> String {
    let id = shq(definition.id);
    match definition.reading {
        // A kernel parameter is read from the kernel, but it is written to a
        // file, and the operator is told which one.
        Reading::RunningSysctl => format!(
            "lr_sysctl {id} {key} {file}; ",
            key = shq(definition.key),
            file = shq(definition.file),
        ),
        Reading::Files(paths) => format!(
            "lr_file {id} {key} {want} {fallback} {program} {witness} {installed} {candidates}; ",
            key = shq(definition.key),
            program = table.name(&reader_program(definition)),
            witness = table.name(&witness_program(definition)),
            // Nothing on this target mentions the directive, so a change goes
            // where the distribution would expect to find it.
            fallback = shq(definition.file),
            // What the check wants, so a reader over several elements of the
            // same name can report the worst one rather than the first.
            want = shq(definition.recommendation),
            // Software with no configuration file is still software: its
            // settings are at their defaults, which is an answer.
            installed = shq(component_probe_key(definition.component)),
            // Quoted here and split by the function, so a `*` is a glob the
            // target's shell resolves and nothing else in the path can be.
            candidates = paths
                .iter()
                .map(|path| shq(path))
                .collect::<Vec<_>>()
                .join(" "),
        ),
    }
}

/// Reads the value a program on the host would actually obey for one key.
///
/// A commented line is not a setting. Reading through the comment marker made
/// `PermitRootLogin yes` followed by the distribution's own
/// `#PermitRootLogin no` report as compliant on a host that was letting root
/// straight in, which is the exact opposite of what the check exists for.
fn reader_program(definition: &BaselineDefinition) -> String {
    let body = match definition.format {
        FileFormat::Whitespace | FileFormat::Equals => flat_reader(definition.precedence(), ""),
        // Nginx writes `directive value;`, and the semicolon is punctuation
        // rather than part of the value.
        FileFormat::Semicolon => flat_reader(
            definition.precedence(),
            "sub(/[[:space:]]*;[[:space:]]*$/,\"\",v); ",
        ),
        FileFormat::Ini(section) => ini_reader(section),
        FileFormat::IndentSection(section) => {
            indent_section_reader(section, "v=(p==\"\" ? \"on\" : p)")
        }
        FileFormat::Yaml => YAML_READER.to_owned(),
        FileFormat::XmlAttribute(element) => xml_reader(element),
    };
    match definition.value_kind {
        // The value is the secret the check is about. Whether it is set is the
        // answer; what it is set to must not leave the target.
        // Matched on the print rather than on the whole END, because a format
        // that trims the value has already rewritten the END around it. That
        // replacement matched nothing for nginx, and a directive's value went
        // out through the one kind of check whose whole purpose is not to
        // carry values off the target.
        BaselineValueKind::Presence => {
            // The punctuation is dropped before the emptiness is judged, or a
            // directive set to a pair of quotes reads as set. `ssl-ca = ""` in
            // a TiDB config and `logfile ""` in a Redis one both mean "not
            // configured", and both were reported as configured — on the two
            // checks whose entire job is to notice that they are not.
            let strip = format!("gsub(/[^{}]/,\"\",v); ", PRESENCE_VALUE_CHARS);
            let replaced = body
                .replace(
                    "print v}",
                    &format!("{strip}print (v==\"\" ? \"\" : \"configured\")}}"),
                )
                // The XML reader ends on the worst-of-them choice instead.
                .replace(
                    "print (best != \"\" ? best : first)}",
                    &format!(
                        "{}print (first == \"\" ? \"\" : \"configured\")}}",
                        strip.replace(",\"\",v)", ",\"\",first)")
                    ),
                );
            debug_assert_ne!(replaced, body, "the presence reader did not take");
            replaced
        }
        BaselineValueKind::Choice(_)
        | BaselineValueKind::Integer { .. }
        | BaselineValueKind::Boolean => body,
    }
}

/// Which file the value that won came from.
///
/// The operator is not told "the setting is wrong" and left to find it: with
/// six candidate paths and include directories that override each other, the
/// file that actually decides the value is the one piece of information a fix
/// needs. It is also where this tool writes, so a change lands on the line the
/// target is obeying rather than on a file it ignores.
fn witness_program(definition: &BaselineDefinition) -> String {
    // The same walk as the reader, recording which file the winning line was
    // in instead of what it said.
    let program = match definition.format {
        FileFormat::Yaml => YAML_READER.replace("v=val}", "v=FILENAME}"),
        FileFormat::XmlAttribute(element) => xml_witness(element),
        FileFormat::IndentSection(section) => indent_section_reader(section, "v=FILENAME"),
        FileFormat::Ini(section) => {
            ini_reader(section).replace("v=(hasEq ? p : (p==\"\" ? \"on\" : p))", "v=FILENAME")
        }
        FileFormat::Whitespace | FileFormat::Equals | FileFormat::Semicolon => {
            flat_reader(definition.precedence(), "")
                .replace("v=p;", "v=FILENAME;")
                .replace("v=p}", "v=FILENAME}")
        }
    };
    debug_assert!(
        program.contains("FILENAME"),
        "the witness reads no filename"
    );
    program
}

/// A setting under a `[section]` header, which is how the my.cnf family works.
/// The same key means different things under `[mysqld]` and `[client]`, so
/// lines outside the section are not this setting at all.
fn ini_reader(section: &str) -> String {
    format!(
        "BEGIN{{v=\"\";inS={start}}} \
         /^[[:space:]]*[#;]/{{next}} \
         /^[[:space:]]*$/{{next}} \
         /^[[:space:]]*\\[/{{s=$0; \
           gsub(/^[[:space:]]*\\[|\\][[:space:]]*.*$/,\"\",s); \
           gsub(/^[[:space:]]+|[[:space:]]+$/,\"\",s); \
           inS=(tolower(s)==tolower(\"{section}\")); next}} \
         inS{{p=$0; sub(/^[[:space:]]+/,\"\",p); t=p; sub(/[[:space:]=].*$/,\"\",t); \
          tk=tolower(t); gsub(/-/,\"_\",tk); kk=tolower(k); gsub(/-/,\"_\",kk); \
          if(tk==kk){{hasEq=(p ~ /^[^[:space:]=]+[[:space:]]*=/); \
          sub(/^[^[:space:]=]+[[:space:]]*=?[[:space:]]*/,\"\",p); \
          sub(/[[:space:]]+[#;].*$/,\"\",p); \
          gsub(/^[[:space:]]+|[[:space:]]+$/,\"\",p); \
          v=(hasEq ? p : (p==\"\" ? \"on\" : p))}}}} \
         END{{print v}}",
        start = ini_section_start(section),
    )
}

/// A directive indented under an unbracketed section header.
///
/// HAProxy's `global` and `defaults` are named by a word in column one, and
/// everything indented under one belongs to it. `capture` is the awk that runs
/// once the value has been separated from the key.
fn indent_section_reader(section: &str, capture: &str) -> String {
    format!(
        "BEGIN{{v=\"\";inS=0}} \
         /^[[:space:]]*#/{{next}} \
         /^[[:space:]]*$/{{next}} \
         /^[^[:space:]]/{{s=$0; sub(/[[:space:]].*$/,\"\",s); \
           gsub(/[[:space:]]+$/,\"\",s); \
           inS=(tolower(s)==tolower(\"{section}\")); next}} \
         inS{{p=$0; sub(/^[[:space:]]+/,\"\",p); t=p; sub(/[[:space:]].*$/,\"\",t); \
          if(tolower(t)==tolower(k)){{sub(/^[^[:space:]]+[[:space:]]*/,\"\",p); \
          sub(/[[:space:]]+#.*$/,\"\",p); \
          gsub(/^[[:space:]]+|[[:space:]]+$/,\"\",p); {capture}}}}} \
         END{{print v}}"
    )
}

/// The same walk, replacing the first live line in the section rather than
/// reading it. Two passes, for the same reason every other editor needs them:
/// a second line in the same section would override the fix.
fn indent_section_writer(section: &str) -> String {
    format!(
        "BEGIN{{done=0;inS=0;seen=0;scanIn=0;active=0;firstActive=0;pad=\"    \"}} \
         NR==FNR{{if($0 ~ /^[^[:space:]]/){{s=$0; sub(/[[:space:]].*$/,\"\",s); \
            scanIn=(tolower(s)==tolower(\"{section}\")); if(scanIn) seen=1; next}} \
          if(!scanIn) next; \
          p=$0; sub(/^[[:space:]]+/,\"\",p); \
          if(p ~ /^#/) next; \
          t=p; sub(/[[:space:]].*$/,\"\",t); \
          if(tolower(t)==tolower(k)){{active++; \
            if(firstActive==0){{firstActive=FNR; \
              if(match($0,/[^ \\t]/)>1) pad=substr($0,1,RSTART-1)}}}} \
          next}} \
         /^[^[:space:]]/{{s=$0; sub(/[[:space:]].*$/,\"\",s); \
           if(inS && !done && active==0){{print pad k \" \" v; done=1}} \
           inS=(tolower(s)==tolower(\"{section}\")); print; next}} \
         {{if(inS && active>0){{ \
            if(FNR==firstActive){{print pad k \" \" v; done=1; next}} \
            p=$0; sub(/^[[:space:]]+/,\"\",p); \
            if(p !~ /^#/){{t=p; sub(/[[:space:]].*$/,\"\",t); \
              if(tolower(t)==tolower(k)) next}} \
          }} print}} \
         END{{if(!done){{if(!seen) print \"{section}\"; print pad k \" \" v}}}}"
    )
}

/// Whether a sectioned file is "inside the section" before it has seen one.
///
/// An empty section name means the keys above the first header — which is
/// where TOML puts a file's top-level settings, and where TiDB keeps the two
/// addresses it listens on. Everything else starts outside and waits for its
/// header.
const fn ini_section_start(section: &str) -> u8 {
    if section.is_empty() { 1 } else { 0 }
}

/// Walks an XML file past its comments, one element at a time.
///
/// Shared by the reader and the editor so there is one idea of where a comment
/// begins and ends. `handle` is the awk that runs for each live element, with
/// the tag in `tag`; `emit` decides whether the walked text is rebuilt.
fn xml_walk(element: &str, handle: &str, emit: bool) -> String {
    let keep = if emit { "out = out " } else { "skip = " };
    // The editor is handed the same file twice, because the line-based editors
    // need two passes; this one works on the whole text at once and would
    // otherwise write the file out doubled. The reader is handed every file
    // that exists and wants all of them.
    let accumulate = if emit {
        "NR==FNR{s = s $0 \"\\n\"; next} {next}"
    } else {
        "{s = s $0 \"\\n\"}"
    };
    format!(
        "{accumulate} \
         END{{rest = s; out = \"\"; \
          while (length(rest) > 0) {{ \
            ci = index(rest, \"<!--\"); ei = index(rest, \"<{element}\"); \
            if (ci > 0 && (ei == 0 || ci < ei)) {{ \
              r2 = substr(rest, ci + 4); j = index(r2, \"-->\"); \
              if (j == 0) {{ {keep}rest; rest = \"\"; break }} \
              {keep}substr(rest, 1, ci + 3 + j + 2); \
              rest = substr(r2, j + 3); continue }} \
            if (ei == 0) break; \
            tagrest = substr(rest, ei); gt = index(tagrest, \">\"); \
            if (gt == 0) break; \
            {keep}substr(rest, 1, ei - 1); \
            tag = substr(tagrest, 1, gt); rest = substr(tagrest, gt + 1); \
            after = substr(tag, {name_length} + 1, 1); \
            if (after != \" \" && after != \"\\t\" && after != \"\\n\" \
                && after != \"/\" && after != \">\") {{ {keep}tag; continue }} \
            {handle} }} \
          {finish}}}",
        name_length = element.len() + 1,
        finish = if emit {
            "out = out rest; printf \"%s\", out; if (!done) exit 3"
        } else {
            "print (best != \"\" ? best : first)"
        },
    )
}

/// The value an XML attribute has, or the worst of them when the file has
/// several live elements of the same name.
fn xml_reader(element: &str) -> String {
    xml_walk(
        element,
        "if (match(tag, \"[ \\t\\n]\" k \"[ \\t\\n]*=[ \\t\\n]*\\\"[^\\\"]*\\\"\")) { \
           piece = substr(tag, RSTART, RLENGTH); \
           sub(/^[^\"]*\"/, \"\", piece); sub(/\".*$/, \"\", piece); \
           if (first == \"\") first = piece; \
           if (piece != r && best == \"\") best = piece }",
        false,
    )
}

/// Sets the attribute on every live element of that name, adding it where the
/// element does not carry it yet.
fn xml_writer(element: &str) -> String {
    xml_walk(
        element,
        // The placeholder is bracketed so it cannot appear inside a name awk
        // already uses: substituting a bare `LEN` turned `RLENGTH` into
        // `R7GTH`, and every XML write would have failed on a syntax error.
        "if (match(tag, \"[ \\t\\n]\" k \"[ \\t\\n]*=[ \\t\\n]*\\\"[^\\\"]*\\\"\")) { \
           tag = substr(tag, 1, RSTART) k \"=\\\"\" v \"\\\"\" substr(tag, RSTART + RLENGTH) } \
         else { tag = substr(tag, 1, @NAME@) \" \" k \"=\\\"\" v \"\\\"\" substr(tag, @NAME@ + 1) } \
         done = 1; out = out tag"
            .replace("@NAME@", &(element.len() + 1).to_string())
            .as_str(),
        true,
    )
}

/// The file this element lives in, for the witness that names the file.
fn xml_witness(element: &str) -> String {
    xml_walk(
        element,
        "if (match(tag, \"[ \\t\\n]\" k \"[ \\t\\n]*=[ \\t\\n]*\\\"[^\\\"]*\\\"\") && first == \"\") \
           first = FILENAME;",
        false,
    )
}

/// A dotted path through indented YAML, which is how mongod.conf is written.
///
/// The key is given whole — `security.authorization` — and the reader rebuilds
/// each line's path from the indentation it sits at.
const YAML_READER: &str = "BEGIN{v=\"\";top=0} \
     /^[[:space:]]*#/{next} \
     /^[[:space:]]*$/{next} \
     {line=$0; sub(/#.*$/,\"\",line); \
      if(line ~ /^[[:space:]]*$/) next; \
      ind=match(line,/[^ ]/)-1; \
      name=line; sub(/^[[:space:]]*/,\"\",name); \
      p=index(name,\":\"); if(p==0) next; \
      val=substr(name,p+1); name=substr(name,1,p-1); \
      gsub(/^[[:space:]]+|[[:space:]]+$/,\"\",val); \
      gsub(/^[[:space:]]+|[[:space:]]+$/,\"\",name); \
      while(top>0 && ind_of[top]>=ind) top--; \
      top++; ind_of[top]=ind; name_of[top]=name; \
      path=name_of[1]; for(i=2;i<=top;i++) path=path \".\" name_of[i]; \
      if(tolower(path)==tolower(k) && val!=\"\") v=val} \
     END{print v}";

/// The two flat shapes differ only in which occurrence wins. Any trailing trim
/// is folded into the END, where the value is already whichever one won, so
/// the body stays exactly the program that was settled against real hosts.
fn flat_reader(precedence: Precedence, trim: &str) -> String {
    let program = flat_reader_body(precedence);
    if trim.is_empty() {
        program.to_owned()
    } else {
        program.replace("END{print v}", &format!("END{{{trim}print v}}"))
    }
}

fn flat_reader_body(precedence: Precedence) -> &'static str {
    match precedence {
        // `sshd -T` on a real host confirms sshd_config(5): "for each keyword,
        // the first obtained value will be used".
        Precedence::First => {
            "BEGIN{v=\"\";f=0} \
             /^[[:space:]]*#/{next} \
             /^[[:space:]]*$/{next} \
             {p=$0; sub(/^[[:space:]]+/,\"\",p); t=p; sub(/[[:space:]=].*$/,\"\",t); \
              if(f==0 && tolower(t)==tolower(k)){sub(/^[^[:space:]=]+[[:space:]=]+/,\"\",p); \
              sub(/[[:space:]]+#.*$/,\"\",p); \
              gsub(/^[[:space:]]+|[[:space:]]+$/,\"\",p); v=p; f=1}} \
             END{print v}"
        }
        // `sysctl -p` on a real host applies the later line; the parsers behind
        // the remaining files likewise overwrite as they read.
        Precedence::Last => {
            "BEGIN{v=\"\"} \
             /^[[:space:]]*#/{next} \
             /^[[:space:]]*$/{next} \
             {p=$0; sub(/^[[:space:]]+/,\"\",p); t=p; sub(/[[:space:]=].*$/,\"\",t); \
              if(tolower(t)==tolower(k)){sub(/^[^[:space:]=]+[[:space:]=]+/,\"\",p); \
              sub(/[[:space:]]+#.*$/,\"\",p); \
              gsub(/^[[:space:]]+|[[:space:]]+$/,\"\",p); v=p}} \
             END{print v}"
        }
    }
}

/// Longest configuration file this will carry back.
const MAX_FILE_BYTES: usize = 256 * 1024;
/// Most lines it will carry back, so a pathological file cannot fill a pane.
const MAX_FILE_LINES: usize = 4_000;
const FILE_MARKER: &str = "LR_BASELINE_FILE_V1";

fn read_file_command(definition: &BaselineDefinition) -> String {
    // `head -c` before `head -n` so a single enormous line cannot get through
    // either. The marker proves the command ran rather than the shell dying
    // half way and leaving a partial file that reads as a short one.
    format!(
        "set -u; lr_file={file}; \
         if [ -L \"$lr_file\" ] || {{ [ -e \"$lr_file\" ] && [ ! -f \"$lr_file\" ]; }}; then \
           printf '%s\\n' {marker}_UNSUPPORTED; \
         elif [ -f \"$lr_file\" ]; then \
           printf '%s\\n' {marker}_BEGIN; \
           head -c {bytes} \"$lr_file\" | head -n {lines}; \
           printf '\\n%s\\n' {marker}_END; \
         else \
           printf '%s\\n' {marker}_ABSENT; \
         fi",
        file = shq(definition.file),
        marker = FILE_MARKER,
        bytes = MAX_FILE_BYTES,
        lines = MAX_FILE_LINES,
    )
}

fn parse_file_view(definition: &BaselineDefinition, output: &str) -> CoreResult<BaselineFileView> {
    let absent = format!("{FILE_MARKER}_ABSENT");
    let unsupported = format!("{FILE_MARKER}_UNSUPPORTED");
    let begin = format!("{FILE_MARKER}_BEGIN");
    let end = format!("{FILE_MARKER}_END");

    if output.lines().any(|line| line.trim() == absent)
        || output.lines().any(|line| line.trim() == unsupported)
    {
        return Ok(BaselineFileView {
            path: definition.file,
            key: definition.key,
            exists: false,
            text: String::new(),
            mentions: Vec::new(),
            truncated: false,
        });
    }

    let (_, rest) = output
        .split_once(&begin)
        .ok_or_else(|| CoreError::validation("baseline file", "missing typed file marker"))?;
    let (body, _) = rest
        .rsplit_once(&end)
        .ok_or_else(|| CoreError::validation("baseline file", "missing typed file terminator"))?;
    // The command prints a newline before the terminator, and the marker sat
    // on its own line after the content.
    let body = body.strip_prefix('\n').unwrap_or(body);
    let body = body.strip_suffix('\n').unwrap_or(body);

    let mut lines = Vec::new();
    let mut truncated = false;
    for line in body.lines() {
        if lines.len() >= MAX_FILE_LINES {
            truncated = true;
            break;
        }
        // Only control characters are replaced. A configuration file is
        // evidence; what it says reaches the operator as written.
        lines.push(
            line.chars()
                .map(|character| {
                    if character == '\t' || !character.is_control() {
                        character
                    } else {
                        char::REPLACEMENT_CHARACTER
                    }
                })
                .collect::<String>(),
        );
    }

    let mentions = mentions_of(definition, &lines)?;
    let text = lines.join("\n");
    truncated |= text.len() >= MAX_FILE_BYTES;
    Ok(BaselineFileView {
        path: definition.file,
        key: definition.key,
        exists: true,
        text,
        mentions,
        truncated,
    })
}

/// Finds every line that names the directive, and marks the one that counts.
fn mentions_of(
    definition: &BaselineDefinition,
    lines: &[String],
) -> CoreResult<Vec<BaselineFileMention>> {
    let mut mentions = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        let commented = trimmed.starts_with('#');
        let bare = trimmed.trim_start_matches('#').trim_start();
        let Some(token) = bare.split([' ', '\t', '=']).next() else {
            continue;
        };
        if !token.eq_ignore_ascii_case(definition.key) {
            continue;
        }
        let Ok(line) = u32::try_from(index) else {
            break;
        };
        mentions.push(BaselineFileMention {
            line,
            commented,
            effective: false,
        });
    }
    // Exactly the rule the scan reads by, so the marked line and the reported
    // value can never disagree.
    let effective = match definition.precedence() {
        Precedence::First => mentions.iter().position(|mention| !mention.commented),
        Precedence::Last => mentions.iter().rposition(|mention| !mention.commented),
    };
    if let Some(index) = effective
        && let Some(mention) = mentions.get_mut(index)
    {
        mention.effective = true;
    }
    Ok(mentions)
}

/// The path the target says decides this setting, checked before it is kept.
///
/// The target is not trusted to name a file. A path only survives if this
/// check could legitimately have read it — one of its compile-time candidates,
/// with `*` matching within a single path segment — so a compromised host
/// cannot answer a scan with a path this tool would later write to.
fn resolved_source(definition: &BaselineDefinition, reported: &str) -> CoreResult<String> {
    let reported = reported.trim();
    if reported.is_empty() {
        return Ok(definition.file.to_owned());
    }
    if reported.len() > 4_096
        || !reported.starts_with('/')
        || reported.contains("..")
        || !reported.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-' | b'+' | b'@')
        })
    {
        return Err(CoreError::validation(
            "baseline scan",
            "the target named a configuration file this check cannot read",
        ));
    }
    if reported == definition.file
        || definition
            .candidates()
            .iter()
            .any(|pattern| path_matches(pattern, reported))
    {
        return Ok(reported.to_owned());
    }
    Err(CoreError::validation(
        "baseline scan",
        "the target named a configuration file outside this check's catalogue",
    ))
}

/// A path against one compile-time candidate. `*` matches within one segment.
fn path_matches(pattern: &str, path: &str) -> bool {
    let mut pattern_parts = pattern.split('/');
    let mut path_parts = path.split('/');
    loop {
        match (pattern_parts.next(), path_parts.next()) {
            (None, None) => return true,
            (Some(expected), Some(actual)) => {
                if !segment_matches(expected, actual) {
                    return false;
                }
            }
            _ => return false,
        }
    }
}

fn segment_matches(pattern: &str, segment: &str) -> bool {
    let Some((prefix, suffix)) = pattern.split_once('*') else {
        return pattern == segment;
    };
    // One star per segment is all the catalogue uses, and all this accepts.
    !suffix.contains('*')
        && segment.len() >= prefix.len() + suffix.len()
        && segment.starts_with(prefix)
        && segment.ends_with(suffix)
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
        let Some((item_id, rest)) = line[5..].split_once('\t') else {
            return Err(CoreError::validation("baseline scan", "invalid item row"));
        };
        let (value, source) = rest.split_once('\t').unwrap_or((rest, ""));
        let definition = definition(item_id)?;
        let observed = match value {
            "__missing__" => BaselineObservedValue::Missing,
            "__unsupported__" => BaselineObservedValue::Unsupported,
            "__absent__" => BaselineObservedValue::NotInstalled,
            value => BaselineObservedValue::Value(value.to_owned()),
        };
        validate_observed(&observed)?;
        let source = resolved_source(definition, source)?;
        if values
            .insert(item_id.to_owned(), (observed, source))
            .is_some()
        {
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
            let (observed, source_file) = values
                .remove(definition.id)
                .ok_or_else(|| CoreError::validation("baseline scan", "missing item row"))?;
            let compliant = compliance_of(definition, &observed);
            Ok(BaselineStatus {
                item_id: definition.id.to_owned(),
                observed,
                compliant,
                source_file,
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
        files.insert(change_file(change)?);
    }
    Ok(files.into_iter().collect())
}

/// The file one change writes to, re-checked against the catalogue.
///
/// The plan carries the path the scan resolved, and this asks the same
/// question again at the moment it is used: a path that is not one this check
/// could have read never reaches a command.
fn change_file(change: &PlannedBaselineChange) -> CoreResult<String> {
    let definition = definition(&change.item_id)?;
    resolved_source(definition, &change.file)
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
    if !definition.is_writable() {
        return Err(read_only_check(definition));
    }
    let file = change_file(change)?;
    let temporary = format!("{remote_root}/edit-{index}.tmp");
    Ok(format!(
        "lr_file={file}; lr_key={key}; lr_value={value}; lr_tmp={temporary}; \
         lr_source=/dev/null; [ -f \"$lr_file\" ] && lr_source=\"$lr_file\"; \
         awk -v k=\"$lr_key\" -v v=\"$lr_value\" '{program}' \"$lr_source\" \"$lr_source\" > \"$lr_tmp\"; \
         if [ -f \"$lr_file\" ]; then cat -- \"$lr_tmp\" > \"$lr_file\"; else mkdir -p -- \"$(dirname -- \"$lr_file\")\"; install -m 0644 -- \"$lr_tmp\" \"$lr_file\"; fi; rm -f -- \"$lr_tmp\"; ",
        file = shq(&file),
        key = shq(definition.key),
        value = shq(&change.after),
        program = writer_program(definition),
        temporary = shq(&temporary),
    ))
}

/// The awk that rewrites one directive, in the shape its file is written in.
///
/// Every one of them replaces the first line that already names the directive
/// — commented or not, so the fix lands where the operator will look for it —
/// and appends the line if the file never mentioned it.
fn writer_program(definition: &BaselineDefinition) -> String {
    match definition.format {
        FileFormat::Whitespace => flat_writer("k \" \" v"),
        FileFormat::Equals => flat_writer("k \" = \" v"),
        FileFormat::Semicolon => flat_writer("k \" \" v \";\""),
        FileFormat::Ini(section) => ini_writer(section),
        FileFormat::IndentSection(section) => indent_section_writer(section),
        FileFormat::Yaml => yaml_writer(definition.key),
        FileFormat::XmlAttribute(element) => xml_writer(element),
        // A presence check has nothing to write; `is_writable` refused it.
    }
}

/// One directive per line, in a file with no sections and no nesting.
///
/// Read twice, because writing it in one pass got it wrong twice over.
///
/// The line that matters is the one the program obeys, and a file usually
/// carries the packaged default commented out above the line someone actually
/// set. Replacing the first line that mentioned the directive put the fix in
/// the comment and left `log_connections = off` live underneath it — a change
/// that reads as applied and does nothing. And a second live line further down
/// would override the fix even once it landed in the right place, so the
/// duplicates go.
///
/// A directive is also allowed to be indented — nginx indents all of them —
/// and matching from the start of the line without stripping that whitespace
/// meant nothing inside a block was ever recognised, so every nginx fix was
/// appended to the end of the file instead of replacing the setting.
fn flat_writer(rendered: &str) -> String {
    format!(
        "{FLAT_WRITER_SCAN} \
         {{indent=\"\"; if(match($0,/[^ \\t]/)>1) indent=substr($0,1,RSTART-1); \
          if(active>0){{ \
            if(FNR==firstActive){{print indent {rendered}; done=1; next}} \
            p=$0; sub(/^[[:space:]]+/,\"\",p); \
            if(p !~ /^#/){{t=p; sub(/[[:space:]=].*$/,\"\",t); \
              if(tolower(t)==tolower(k)) next}} \
          }} else if(firstComment>0 && FNR==firstComment){{ \
            print indent {rendered}; done=1; next}} \
          print}} \
         END{{if(!done) print {rendered}}}"
    )
}

/// The counting pass shared by the flat writer: where the live occurrences of
/// the directive are, and where the first commented one is.
const FLAT_WRITER_SCAN: &str = "BEGIN{done=0;active=0;firstActive=0;firstComment=0} \
     NR==FNR{p=$0; sub(/^[[:space:]]+/,\"\",p); \
      if(p ~ /^#/){c=p; sub(/^#+[[:space:]]*/,\"\",c); t=c; \
        sub(/[[:space:]=].*$/,\"\",t); \
        if(tolower(t)==tolower(k) && firstComment==0) firstComment=FNR} \
      else {t=p; sub(/[[:space:]=].*$/,\"\",t); \
        if(tolower(t)==tolower(k)){active++; if(firstActive==0) firstActive=FNR}} \
      next} ";

/// A directive inside a `[section]`, which is how the my.cnf family works.
///
/// Writing it flat would have put `bind-address` under whatever section
/// happened to come first in the file — `[client]` on a stock Debian install —
/// where the server never reads it. The section is found first, the directive
/// replaced inside it, and if the file has no such section one is appended.
fn ini_writer(section: &str) -> String {
    // Two passes, for the same reason the flat writer needs them: the live
    // line wins over the commented default, and a second live line in the same
    // section would override the fix.
    // The top-level keys of a TOML file are "the section before the first
    // header", so both passes start inside it and the first header ends it.
    let start = ini_section_start(section);
    let scan = format!(
        "BEGIN{{done=0;inS={start};seen={start};scanIn={start};\
          active=0;firstActive=0;firstComment=0;endOfSection=0}} \
         NR==FNR{{p=$0; sub(/^[[:space:]]+/,\"\",p); \
          if(p ~ /^\\[/){{s=p; \
            gsub(/^\\[|\\].*$/,\"\",s); gsub(/^[[:space:]]+|[[:space:]]+$/,\"\",s); \
            if(scanIn) endOfSection=FNR; \
            scanIn=(tolower(s)==tolower(\"{section}\")); if(scanIn) seen=1; next}} \
          if(!scanIn) next; \
          if(p ~ /^[#;]/){{c=p; sub(/^[#;]+[[:space:]]*/,\"\",c); t=c; \
            sub(/[[:space:]=].*$/,\"\",t); tk=tolower(t); gsub(/-/,\"_\",tk); \
            kk=tolower(k); gsub(/-/,\"_\",kk); \
            if(tk==kk && firstComment==0) firstComment=FNR; next}} \
          t=p; sub(/[[:space:]=].*$/,\"\",t); tk=tolower(t); gsub(/-/,\"_\",tk); \
          kk=tolower(k); gsub(/-/,\"_\",kk); \
          if(tk==kk){{active++; if(firstActive==0) firstActive=FNR}} \
          next}} "
    );
    format!(
        "{scan}\
         /^[[:space:]]*\\[/{{s=$0; \
           gsub(/^[[:space:]]*\\[|\\][[:space:]]*.*$/,\"\",s); \
           gsub(/^[[:space:]]+|[[:space:]]+$/,\"\",s); \
           if(inS && !done && active==0 && firstComment==0){{print k \" = \" v; done=1}} \
           inS=(tolower(s)==tolower(\"{section}\")); print; next}} \
         {{if(inS && active>0){{ \
            if(FNR==firstActive){{print k \" = \" v; done=1; next}} \
            p=$0; sub(/^[[:space:]]+/,\"\",p); \
            if(p !~ /^[#;]/){{t=p; sub(/[[:space:]=].*$/,\"\",t); \
              tk=tolower(t); gsub(/-/,\"_\",tk); kk=tolower(k); gsub(/-/,\"_\",kk); \
              if(tk==kk) next}} \
          }} else if(inS && firstComment>0 && FNR==firstComment){{ \
            print k \" = \" v; done=1; next}} \
          print}} \
         END{{if(!done){{if(!seen) print \"[{section}]\"; print k \" = \" v}}}}"
    )
}

/// A dotted path through indented YAML, which is how mongod.conf is written.
///
/// The path is walked the way the reader walks it. A path whose parents are
/// already there has its leaf replaced in place at the indentation the file
/// uses; a path with no parents at all is appended as a fresh block, so
/// `security.authorization` becomes two lines rather than one wrong one.
fn yaml_writer(key: &str) -> String {
    let depth = key.split('.').count();
    let leaf = key.rsplit('.').next().unwrap_or(key);
    let mut block = String::new();
    for (level, part) in key.split('.').enumerate() {
        let indent = "  ".repeat(level);
        if level + 1 == depth {
            block.push_str(&format!("print \"{indent}{part}: \" v; "));
        } else {
            block.push_str(&format!("print \"{indent}{part}:\"; "));
        }
    }
    format!(
        "BEGIN{{done=0;top=0;at=0;pad=\"\"}} \
         NR==FNR{{probe=$0; sub(/#.*$/,\"\",probe); \
          if(probe ~ /^[[:space:]]*$/) next; \
          ind=match(probe,/[^ ]/)-1; \
          name=probe; sub(/^[[:space:]]*/,\"\",name); \
          p=index(name,\":\"); if(p==0) next; \
          name=substr(name,1,p-1); \
          gsub(/^[[:space:]]+|[[:space:]]+$/,\"\",name); \
          while(top>0 && ind_of[top]>=ind) top--; \
          top++; ind_of[top]=ind; name_of[top]=name; \
          path=name_of[1]; for(i=2;i<=top;i++) path=path \".\" name_of[i]; \
          if(at==0 && tolower(path)==tolower(k)){{at=FNR; \
            pad=\"\"; for(i=0;i<ind;i++) pad=pad \" \"}} \
          next}} \
         {{if(at>0 && FNR==at){{print pad \"{leaf}: \" v; done=1; next}} print}} \
         END{{if(!done){{{block}}}}}"
    )
}

/// Ask each product whether it accepts the file it was just given, then reload
/// what this tool is responsible for reloading.
///
/// Validation used to be one line, `sshd -t`, from when every check this tool
/// could write lived in `sshd_config` or a sysctl file. The catalogue grew to
/// databases and web servers without the validation growing with it, so a
/// change to `nginx.conf` or `my.cnf` was written and left: forty-eight of the
/// eighty-one checks were applied with nothing asked and nothing reloaded. A
/// file the program refuses is worse than no change at all, because it reads
/// as done and fails later, at a reload nobody chose the timing of.
///
/// Reloading is deliberately narrower than validating. This tool reloads what
/// it owns — sshd and the kernel parameters it writes — and does not restart
/// somebody's database because a directive changed. The remediation beside
/// each check already tells the operator what to run and when.
fn configuration_validation(
    changes: &[PlannedBaselineChange],
    reload_policy: BaselineReloadPolicy,
) -> CoreResult<String> {
    let mut command = String::new();
    // One validation per product, against a file that product actually owns.
    let mut validated = BTreeMap::new();
    for change in changes {
        let definition = definition(&change.item_id)?;
        let Some(validator) = definition.component.validate_command() else {
            continue;
        };
        validated
            .entry(validator)
            .or_insert_with(|| change_file(change));
    }
    for (validator, file) in validated {
        command.push_str(&validator.replace("{file}", &shq(&file?)));
        command.push_str("; ");
    }

    let groups = changes
        .iter()
        .map(|change| definition(&change.item_id).map(|definition| definition.reload))
        .collect::<CoreResult<BTreeSet<_>>>()?;
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

/// A path may be backed up, edited or restored only if some check in the
/// catalogue could have read it.
///
/// The set is still closed — every candidate is a compile-time constant — but
/// it is now the whole set rather than the one canonical path per check, since
/// a change is written to the file the target was actually obeying.
fn validate_catalog_file(file: &str) -> CoreResult<()> {
    if BASELINE_CATALOG.iter().any(|definition| {
        definition.file == file
            || definition
                .candidates()
                .iter()
                .any(|pattern| path_matches(pattern, file))
    }) {
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

    fn stored_record(
        index: usize,
        target: &TargetIdentity,
        state: BaselineChangeState,
    ) -> BaselineChangeRecord {
        let id = Uuid::from_u128(index as u128 + 1).to_string();
        let changes = vec![PlannedBaselineChange {
            item_id: "ssh-max-auth-tries".to_owned(),
            before: BaselineObservedValue::Value("6".to_owned()),
            after: "4".to_owned(),
            file: "/etc/ssh/sshd_config".to_owned(),
        }];
        let files = files_for_changes(&changes).unwrap();
        let backups = files
            .iter()
            .map(|file| BaselineBackupEvidence {
                file: file.clone(),
                sha256: Some("00".repeat(32)),
            })
            .collect::<Vec<_>>();
        let created_at = Utc::now() + chrono::TimeDelta::seconds(index as i64);
        BaselineChangeRecord {
            id: id.clone(),
            operation_id: Uuid::from_u128((1_u128 << 64) + index as u128 + 1).to_string(),
            last_operation_id: Uuid::from_u128((2_u128 << 64) + index as u128 + 1).to_string(),
            target: target.clone(),
            changes: changes.clone(),
            files: files.clone(),
            backups: backups.clone(),
            remote_root: expected_remote_root(&id).unwrap(),
            reload_policy: BaselineReloadPolicy::Defer,
            digest: record_digest(&changes, &files, &backups, BaselineReloadPolicy::Defer).unwrap(),
            state,
            created_at,
            updated_at: created_at,
        }
    }

    fn write_stored_history(services: &BackendServices, changes: Vec<BaselineChangeRecord>) {
        services
            .store()
            .write(StoreFile::Baseline, &StoredBaselineHistory { changes })
            .unwrap();
    }

    #[test]
    fn catalog_is_closed_unique_and_values_are_canonical() {
        let mut ids = BTreeSet::new();
        let mut file_keys = BTreeSet::new();
        for definition in BASELINE_CATALOG {
            assert!(ids.insert(definition.id));
            assert!(file_keys.insert((definition.file, definition.key)));
            // Most of these live under /etc; Tomcat lives wherever it was
            // unpacked. What has to hold is that the path is absolute, inert,
            // and one the check would also read.
            assert!(definition.file.starts_with('/'));
            assert!(resolved_source(definition, definition.file).is_ok());
            assert!(BaselineCategory::ALL.contains(&definition.category));
            assert!(
                definition.key.len() <= 64
                    && definition.key.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    })
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
                    assert_eq!(
                        normalize_requested_value(definition, definition.recommendation).unwrap(),
                        definition.recommendation
                    );
                }
                BaselineValueKind::Integer { minimum, maximum } => {
                    assert!(minimum <= maximum);
                    assert_eq!(
                        normalize_requested_value(definition, definition.recommendation).unwrap(),
                        definition.recommendation
                    );
                }
                BaselineValueKind::Boolean => {
                    assert!(matches!(definition.recommendation, "on" | "off"));
                }
                // A presence check has no value: what it reports is the marker,
                // and the marker is what it is compared against.
                BaselineValueKind::Presence => {
                    assert_eq!(definition.recommendation, PRESENCE_MARKER);
                    assert!(normalize_requested_value(definition, "anything").is_err());
                }
            }
            // A default has to be a value this check could actually read off a
            // target, or "nothing written down" would be judged against a
            // value the software never uses.
            if let Some(implicit) = definition.implicit {
                assert!(
                    normalize_requested_value(definition, implicit).is_ok(),
                    "{} has a default it could never observe: {implicit}",
                    definition.id
                );
                assert_eq!(
                    compliance_of(definition, &BaselineObservedValue::Missing),
                    compliance_of(
                        definition,
                        &BaselineObservedValue::Value(implicit.to_owned())
                    ),
                    "{} judges an unwritten directive differently from its own default",
                    definition.id
                );
            }
            // Only the flat formats can be written back; the rest are read-only
            // and must refuse a change rather than corrupt a sectioned file.
            if !definition.is_writable() {
                assert!(
                    edit_body(
                        &PlannedBaselineChange {
                            item_id: definition.id.to_owned(),
                            before: BaselineObservedValue::Missing,
                            after: definition.recommendation.to_owned(),
                            file: definition.file.to_owned(),
                        },
                        "/tmp",
                        0,
                    )
                    .is_err(),
                    "{} must refuse to be written",
                    definition.id
                );
            }
        }
        assert_eq!(BASELINE_CATALOG.len(), 108);
        // One plan carries every check this tool will write; the rest are read.
        assert!(
            BASELINE_CATALOG
                .iter()
                .filter(|definition| definition.is_writable())
                .count()
                <= MAX_CHANGES
        );
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

    /// Nothing this tool writes is left without asking the program about it.
    ///
    /// Validation was written when every writable check lived in sshd_config
    /// or a sysctl file, and the catalogue grew to databases and web servers
    /// without it: forty-eight of eighty-one checks were applied with nothing
    /// asked. Each product that has a validator must use it; each product that
    /// has none must be named here, so adding a product is a decision about
    /// validation rather than an omission.
    #[test]
    fn every_writable_product_is_asked_or_is_named_as_having_no_validator() {
        // Proven on a real host: zero for a file the product accepts, non-zero
        // for one it refuses. See the commit that added them.
        const NO_VALIDATOR: [BaselineComponent; 5] = [
            // login.defs, faillock, auditd and sysctl have no parser to ask.
            BaselineComponent::System,
            // `redis-server` has no offline check.
            BaselineComponent::Redis,
            // Tomcat parses server.xml only at start; `MiddlewareValidator`
            // records the same thing as `StructuralOnly`.
            BaselineComponent::Tomcat,
            // openGauss ships `gs_guc check`, but it wants the cluster data
            // directory and the omm account; TiDB has none at all.
            BaselineComponent::OpenGauss,
            BaselineComponent::TiDb,
        ];
        for component in BaselineComponent::ALL {
            let writable = BASELINE_CATALOG
                .iter()
                .any(|definition| definition.component == component && definition.is_writable());
            if !writable {
                continue;
            }
            assert_eq!(
                component.validate_command().is_none(),
                NO_VALIDATOR.contains(&component),
                "{} is neither validated nor named as unvalidatable",
                component.label()
            );
        }
        // Every validator has to survive a target that does not run the
        // product: an absent binary is a skip, never a failure.
        for component in BaselineComponent::ALL {
            let Some(validator) = component.validate_command() else {
                continue;
            };
            assert!(
                validator.contains("command -v") || validator.contains("[ -x"),
                "{} would fail on a host that does not run it",
                component.label()
            );
        }
    }

    /// The validation the apply step sends, for a change to each product.
    #[test]
    fn the_apply_step_asks_the_product_about_the_file_it_wrote() {
        for (item_id, expected) in [
            ("ssh-permit-root-login", "sshd -t"),
            ("nginx-server-tokens", "nginx -t"),
            ("apache-server-tokens", "apachectl configtest"),
            ("mysql-local-infile", "mysqld --validate-config"),
            ("mongodb-authorization", "mongod --config"),
            ("postgresql-ssl", "-C listen_addresses -D"),
        ] {
            let definition = definition(item_id).unwrap();
            let change = PlannedBaselineChange {
                item_id: item_id.to_owned(),
                before: BaselineObservedValue::Missing,
                after: definition.recommendation.to_owned(),
                file: definition.file.to_owned(),
            };
            let validation =
                configuration_validation(&[change], BaselineReloadPolicy::Defer).unwrap();
            assert!(
                validation.contains(expected),
                "{item_id} is applied without asking {expected}:\n{validation}"
            );
            // The file the change wrote, not a path compiled in beside it.
            if expected.contains("{file}") || expected.contains("-D") {
                assert!(validation.contains(definition.file));
            }
        }
        // A product with no validator sends nothing rather than something that
        // always succeeds — an empty check reads as a check that ran.
        let redis = definition("redis-protected-mode").unwrap();
        let validation = configuration_validation(
            &[PlannedBaselineChange {
                item_id: redis.id.to_owned(),
                before: BaselineObservedValue::Missing,
                after: redis.recommendation.to_owned(),
                file: redis.file.to_owned(),
            }],
            BaselineReloadPolicy::Defer,
        )
        .unwrap();
        assert_eq!(validation, "");
    }

    /// Each file shape is written the way that shape is written, and the line
    /// goes into the file the scan said the target was obeying.
    #[test]
    fn every_writable_check_edits_its_own_file_in_its_own_shape() {
        let remote_root = expected_remote_root("6f03708a-40f4-486f-8bf1-ff08e7e25457").unwrap();
        for (item_id, rendered) in [
            ("ssh-permit-empty-passwords", "k \" \" v"),
            ("authentication-login-fail-delay", "k \" \" v"),
            ("authentication-faillock-deny", "k \" = \" v"),
            ("permissions-default-umask", "k \" \" v"),
            ("network-tcp-syncookies", "k \" = \" v"),
            // The shapes the flat editor used to refuse outright.
            ("nginx-server-tokens", "k \" \" v \";\""),
            ("mysql-local-infile", "[mysqld]"),
            ("mongodb-authorization", "  authorization: "),
        ] {
            let definition = definition(item_id).unwrap();
            // The scan found it somewhere other than the compiled-in default.
            let found_at = definition
                .candidates()
                .last()
                .copied()
                .unwrap_or(definition.file);
            let elsewhere = found_at.replace('*', "written-here");
            let command = edit_body(
                &PlannedBaselineChange {
                    item_id: item_id.to_owned(),
                    before: BaselineObservedValue::Missing,
                    after: definition.recommendation.to_owned(),
                    file: elsewhere.clone(),
                },
                &remote_root,
                0,
            )
            .unwrap();
            assert!(
                command.contains(&format!("lr_file={}", shq(&elsewhere))),
                "{item_id} wrote somewhere other than where it read"
            );
            assert!(command.contains(&format!("lr_key={}", shq(definition.key))));
            assert!(
                command.contains(rendered),
                "{item_id} is not written in the shape its file uses"
            );
        }
    }

    /// A command the target's shell will refuse is not a command.
    ///
    /// Linux caps a single argument at 128 kB, and SSH hands the whole script
    /// to the login shell as one. At eighty-one checks, each carrying its own
    /// copy of the program that reads it, the scan reached 135 kB and bash
    /// answered "Argument list too long" — every check on every target,
    /// failing before a file was opened. The programs are written once now.
    #[test]
    fn the_scan_fits_in_one_argument_with_room_to_grow() {
        const KERNEL_LIMIT: usize = 128 * 1024;
        let scan = scan_command();
        assert!(
            scan.len() < KERNEL_LIMIT / 2,
            "the scan is {} bytes, over half of what a single argument may carry",
            scan.len()
        );
        // The saving is the deduplication, so it has to actually be happening.
        let distinct = scan.matches("LR_P").count();
        assert!(distinct > 0, "the programs are not written once");
        assert!(
            !scan.contains("BEGIN{v=\"\";f=0} /^[[:space:]]*#/{next} /^[[:space:]]*$/{next} {p=$0; sub(/^[[:space:]]+/,\"\",p); t=p; sub(/[[:space:]=].*$/,\"\",t); if(f==0 && tolower(t)==tolower(k)){sub(/^[^[:space:]=]+[[:space:]=]+/,\"\",p); gsub(/^[[:space:]]+|[[:space:]]+$/,\"\",p); v=p; f=1}} END{print v}' $lr_files"),
            "a program is still written out beside the check that uses it"
        );
    }

    /// Prints the whole scan, so a lab probe can run the exact script the tool
    /// sends inside an official image and see what this catalogue makes of a
    /// version nobody has tried it against. Not an assertion.
    const SCAN_DUMP_MARKER: &str = "----LOVELYRES-SCAN----";

    #[test]
    fn dump_scan_command_for_the_lab() {
        if std::env::var("LOVELYRES_DUMP_SCAN").is_err() {
            return;
        }
        println!("{SCAN_DUMP_MARKER}");
        println!("{}", scan_command());
        println!("{SCAN_DUMP_MARKER}");
    }

    /// Prints the readers a lab probe needs to run by hand. Not an assertion —
    /// it does nothing unless asked.
    #[test]
    fn dump_readers_for_the_lab() {
        if std::env::var("LOVELYRES_DUMP_READERS").is_err() {
            return;
        }
        for item_id in [
            "tomcat-allow-trace",
            "tomcat-shutdown-port",
            "haproxy-log",
            "haproxy-user",
        ] {
            let definition = definition(item_id).unwrap();
            println!("=== {item_id}\n{}", reader_program(definition));
        }
    }

    /// No editor may carry a name awk does not know.
    ///
    /// One did: a placeholder substitution meant to carry the element name's
    /// length rewrote `RLENGTH` into `R7GTH`, and every XML write would have
    /// died on a syntax error the moment it ran.
    #[test]
    fn no_editor_carries_a_mangled_awk_builtin() {
        for definition in BASELINE_CATALOG {
            if !definition.is_writable() {
                continue;
            }
            let program = writer_program(definition);
            for builtin in [
                "RSTART", "RLENGTH", "FILENAME", "FNR", "NR", "substr", "match",
            ] {
                let mangled = &builtin[1..];
                assert!(
                    !program.contains(&format!("R{mangled}")) || program.contains(builtin),
                    "{} carries a mangled {builtin}",
                    definition.id
                );
            }
            // The one that actually happened, named so it cannot come back.
            assert!(
                !program.contains("R7GTH"),
                "{} carries R7GTH",
                definition.id
            );
            assert!(
                !program.contains("@NAME@"),
                "{} left a placeholder unsubstituted",
                definition.id
            );
        }
    }

    /// The editor for every file shape is proved against real configuration
    /// files by `tools/lab/probe-baseline-write.mjs`, which runs the awk on a
    /// lab host and reads the result back with the real program. It can only
    /// prove what it carries, so what it carries has to be this.
    #[test]
    fn the_lab_probe_runs_the_editors_this_file_builds() {
        let probe = include_str!("../../../tools/lab/probe-baseline-write.mjs");
        let dump = std::env::var("LOVELYRES_DUMP_WRITERS").is_ok();
        for item_id in [
            "ssh-permit-root-login",
            "postgresql-log-connections",
            "nginx-server-tokens",
            "mysql-local-infile",
            "mongodb-authorization",
            "tomcat-shutdown-port",
        ] {
            let program = writer_program(definition(item_id).unwrap());
            if dump {
                println!("=== {item_id}\n{program}");
                continue;
            }
            // The probe carries each program as a JavaScript single-quoted
            // literal, where a backslash has to be doubled to survive.
            let embedded = program.replace('\\', "\\\\");
            assert!(
                probe.contains(&embedded),
                "the probe does not run the editor for {item_id}:\n{embedded}"
            );
        }
        // Two passes over the file, so the probe has to hand awk the file twice.
        assert!(probe.contains("/tmp/lr-write-test /tmp/lr-write-test"));
    }

    /// A path the target reports is only kept if this check could have read it.
    #[test]
    fn a_reported_configuration_file_is_checked_against_the_catalogue() {
        let mysql = definition("mysql-local-infile").unwrap();
        // A real include-directory match.
        assert_eq!(
            resolved_source(mysql, "/etc/mysql/mariadb.conf.d/99-override.cnf").unwrap(),
            "/etc/mysql/mariadb.conf.d/99-override.cnf"
        );
        // Nothing said means the place the distribution would put it.
        assert_eq!(resolved_source(mysql, "").unwrap(), mysql.file);
        for hostile in [
            "/etc/shadow",
            "/etc/mysql/mariadb.conf.d/../../shadow",
            "/etc/mysql/mariadb.conf.d/a/b.cnf",
            "etc/my.cnf",
            "/etc/mysql/mariadb.conf.d/x.cnf; rm -rf /",
        ] {
            assert!(
                resolved_source(mysql, hostile).is_err(),
                "{hostile} was accepted"
            );
            assert!(
                validate_catalog_file(hostile).is_err(),
                "{hostile} is backed up"
            );
        }
        // The star matches inside one segment and never across a slash.
        assert!(path_matches(
            "/etc/nginx/conf.d/*.conf",
            "/etc/nginx/conf.d/a.conf"
        ));
        assert!(!path_matches(
            "/etc/nginx/conf.d/*.conf",
            "/etc/nginx/conf.d/a/b.conf"
        ));
    }

    #[tokio::test]
    async fn full_catalog_recommendation_batch_fits_the_bounded_plan() {
        let (_temp, services, session, harness) = fixture().await;
        let overrides = BASELINE_CATALOG
            .iter()
            .map(|definition| (definition.id, "__missing__"))
            .collect::<Vec<_>>();
        harness.set_execute_output(scan_fixture(&overrides, &[]));
        // The checks this tool can write back. The rest are read: a sectioned
        // or nested file cannot be edited a line at a time without damage, and
        // a presence check has no value to write.
        let writable = BASELINE_CATALOG
            .iter()
            .filter(|definition| definition.is_writable())
            .collect::<Vec<_>>();
        let requests = writable
            .iter()
            .map(|definition| BaselineChangeRequest::recommended(definition.id).unwrap())
            .collect::<Vec<_>>();
        let plan = services
            .baseline()
            .plan_changes(&session, requests, BaselineReloadPolicy::Defer)
            .await
            .unwrap();

        assert_eq!(plan.changes.len(), writable.len());
        // One backup per distinct file, across everything the catalogue covers.
        assert_eq!(
            plan.files.len(),
            writable
                .iter()
                .map(|definition| definition.file)
                .collect::<BTreeSet<_>>()
                .len()
        );
        for file in &plan.files {
            assert!(
                validate_catalog_file(file).is_ok(),
                "{file} is not backed up"
            );
        }
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
            file: "/etc/ssh/sshd_config".to_owned(),
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

    #[tokio::test]
    async fn encoded_baseline_history_is_rejected_before_json_decode() {
        let (_temp, services, session, _harness) = fixture().await;
        let hostile = b"HOSTILE_BASELINE_DOCUMENT_MUST_NOT_ECHO";
        let mut encoded = vec![b'x'; MAX_BASELINE_HISTORY_DOCUMENT_BYTES + 1];
        encoded[..hostile.len()].copy_from_slice(hostile);
        fs::write(services.store().path_for(StoreFile::Baseline), encoded).unwrap();

        let error = services
            .baseline()
            .list_history(session.target())
            .unwrap_err();
        assert!(matches!(
            error,
            CoreError::Validation {
                subject: "baseline changes",
                ..
            }
        ));
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(std::str::from_utf8(hostile).unwrap()));
    }

    #[tokio::test]
    async fn stored_history_limit_rejects_257_on_every_load_path_without_echo() {
        let (_temp, services, session, _harness) = fixture().await;
        let target = session.target().identity.clone();
        let mut changes = (0..=MAX_HISTORY)
            .map(|index| stored_record(index, &target, BaselineChangeState::Applied))
            .collect::<Vec<_>>();
        let hostile = "HOSTILE_257TH_BASELINE_RECORD_MUST_NOT_ECHO";
        changes[MAX_HISTORY].operation_id = hostile.to_owned();
        let lookup_id = changes[0].id.clone();
        write_stored_history(&services, changes);

        let errors = [
            services
                .baseline()
                .list_history(session.target())
                .unwrap_err(),
            services
                .baseline()
                .record_by_id(session.target(), &lookup_id)
                .unwrap_err(),
            services
                .baseline()
                .transition_record(
                    &lookup_id,
                    &target,
                    BaselineChangeState::Applied,
                    BaselineChangeState::Restored,
                    &Uuid::new_v4().to_string(),
                )
                .unwrap_err(),
            services
                .baseline()
                .insert_record(stored_record(
                    MAX_HISTORY + 100,
                    &target,
                    BaselineChangeState::Applied,
                ))
                .unwrap_err(),
        ];
        for error in errors {
            let rendered = format!("{error:?} {error}");
            assert!(!rendered.contains(hostile));
            assert!(rendered.contains("baseline history count exceeds its storage budget"));
        }
    }

    #[tokio::test]
    async fn exactly_256_stored_history_records_are_valid_on_every_load_path() {
        let (_temp, services, session, _harness) = fixture().await;
        let target = session.target().identity.clone();
        let changes = (0..MAX_HISTORY)
            .map(|index| stored_record(index, &target, BaselineChangeState::Applied))
            .collect::<Vec<_>>();
        let lookup_id = changes[0].id.clone();
        write_stored_history(&services, changes);

        assert_eq!(
            services
                .baseline()
                .list_history(session.target())
                .unwrap()
                .len(),
            MAX_HISTORY
        );
        assert_eq!(
            services
                .baseline()
                .record_by_id(session.target(), &lookup_id)
                .unwrap()
                .id,
            lookup_id
        );
        let transitioned = services
            .baseline()
            .transition_record(
                &lookup_id,
                &target,
                BaselineChangeState::Applied,
                BaselineChangeState::Restored,
                &Uuid::new_v4().to_string(),
            )
            .unwrap();
        assert_eq!(transitioned.state, BaselineChangeState::Restored);

        let inserted = stored_record(MAX_HISTORY + 100, &target, BaselineChangeState::Applied);
        services.baseline().insert_record(inserted.clone()).unwrap();
        assert_eq!(
            services
                .baseline()
                .list_history(session.target())
                .unwrap()
                .len(),
            MAX_HISTORY
        );
        assert_eq!(
            services
                .baseline()
                .record_by_id(session.target(), &inserted.id)
                .unwrap()
                .id,
            inserted.id
        );
    }

    #[test]
    fn tampered_persisted_record_cannot_reach_a_shell_builder() {
        let id = Uuid::new_v4().to_string();
        let changes = vec![PlannedBaselineChange {
            item_id: "ssh-max-auth-tries".to_owned(),
            before: BaselineObservedValue::Value("6".to_owned()),
            after: "4".to_owned(),
            file: "/etc/ssh/sshd_config".to_owned(),
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

    #[test]
    fn every_setting_is_read_the_way_its_own_program_reads_it() {
        // sshd keeps the first value it is given; everything else is read by a
        // parser that overwrites as it goes.
        for definition in BASELINE_CATALOG {
            let expected = if definition.file() == "/etc/ssh/sshd_config" {
                Precedence::First
            } else {
                Precedence::Last
            };
            assert_eq!(
                definition.precedence(),
                expected,
                "{} reads {} the wrong way round",
                definition.id,
                definition.file(),
            );
        }
    }

    #[test]
    fn a_commented_line_is_never_read_as_a_setting() {
        // The bug this guards against reported a host that was letting root
        // log in as compliant, because the distribution's own commented
        // default sat below the active line.
        // Asked of every program rather than counted in the script, so the
        // property holds however the script is arranged.
        for definition in BASELINE_CATALOG {
            if !matches!(definition.reading, Reading::Files(_)) {
                continue;
            }
            for program in [reader_program(definition), witness_program(definition)] {
                let skips = match definition.format {
                    // An XML comment is a region, not a line: it is skipped by
                    // the walk that finds where it ends.
                    FileFormat::XmlAttribute(_) => program.contains("index(rest, \"<!--\")"),
                    _ => {
                        program.contains("/^[[:space:]]*#/{next}")
                            || program.contains("/^[[:space:]]*[#;]/{next}")
                            || program.contains("sub(/#.*$/,\"\",probe)")
                    }
                };
                assert!(skips, "{} reads commented lines as settings", definition.id);
                assert!(
                    !program.contains("sub(/^[[:space:]]*#[[:space:]]*/"),
                    "{} strips the comment marker before matching",
                    definition.id
                );
            }
        }
    }

    fn sshd_definition() -> &'static BaselineDefinition {
        definition("ssh-permit-root-login").unwrap()
    }

    fn sysctl_definition() -> &'static BaselineDefinition {
        BASELINE_CATALOG
            .iter()
            .find(|item| item.file() == "/etc/sysctl.d/99-lovelyres-baseline.conf")
            .unwrap()
    }

    fn view(definition: &BaselineDefinition, body: &str) -> BaselineFileView {
        let output = format!("{FILE_MARKER}_BEGIN\n{body}\n{FILE_MARKER}_END\n");
        parse_file_view(definition, &output).unwrap()
    }

    #[test]
    fn the_marked_line_is_the_line_the_host_obeys() {
        // sshd keeps the first value it is given, so the second active line is
        // present but not in force.
        let sshd = view(
            sshd_definition(),
            "#PermitRootLogin prohibit-password\nPermitRootLogin yes\nPermitRootLogin no",
        );
        assert_eq!(
            sshd.mentions,
            vec![
                BaselineFileMention {
                    line: 0,
                    commented: true,
                    effective: false
                },
                BaselineFileMention {
                    line: 1,
                    commented: false,
                    effective: true
                },
                BaselineFileMention {
                    line: 2,
                    commented: false,
                    effective: false
                },
            ],
        );

        // sysctl applies the later line.
        let sysctl = view(
            sysctl_definition(),
            &format!("{key} = 1\n{key} = 0", key = sysctl_definition().key()),
        );
        assert_eq!(
            sysctl.mentions,
            vec![
                BaselineFileMention {
                    line: 0,
                    commented: false,
                    effective: false
                },
                BaselineFileMention {
                    line: 1,
                    commented: false,
                    effective: true
                },
            ],
        );
    }

    #[test]
    fn a_file_that_only_comments_the_setting_has_nothing_in_force() {
        let view = view(
            sshd_definition(),
            "#PermitRootLogin no\n# PermitRootLogin yes",
        );
        assert_eq!(view.mentions.len(), 2);
        assert!(view.mentions.iter().all(|mention| mention.commented));
        assert!(view.mentions.iter().all(|mention| !mention.effective));
    }

    #[test]
    fn a_setting_is_matched_by_name_not_by_prefix() {
        // `PermitRootLoginX` and `NotPermitRootLogin` are different settings.
        let view = view(
            sshd_definition(),
            "PermitRootLoginX yes\nNotPermitRootLogin yes\npermitrootlogin no\nPermitRootLogin=yes",
        );
        assert_eq!(
            view.mentions
                .iter()
                .map(|mention| mention.line)
                .collect::<Vec<_>>(),
            vec![2, 3],
        );
        // The reader is case-insensitive, so the lower-case line is the first
        // one in force.
        assert!(view.mentions[0].effective);
    }

    #[test]
    fn the_file_reaches_the_caller_as_written() {
        let view = view(
            sshd_definition(),
            "Port 22\n\n  # spaced comment\nPermitRootLogin yes",
        );
        assert_eq!(
            view.text,
            "Port 22\n\n  # spaced comment\nPermitRootLogin yes"
        );
        assert_eq!(view.path, "/etc/ssh/sshd_config");
        assert_eq!(view.key, "PermitRootLogin");
        assert!(view.exists);
        assert!(!view.truncated);
    }

    #[test]
    fn only_control_characters_are_replaced() {
        let view = view(sshd_definition(), "PermitRootLogin yes\u{7}\tkeep\ttabs");
        assert!(view.text.contains('\u{fffd}'));
        assert!(view.text.contains("\tkeep\ttabs"));
    }

    #[test]
    fn a_file_that_is_not_there_says_so_rather_than_looking_empty() {
        for marker in ["ABSENT", "UNSUPPORTED"] {
            let output = format!("{FILE_MARKER}_{marker}\n");
            let view = parse_file_view(sshd_definition(), &output).unwrap();
            assert!(!view.exists, "{marker}");
            assert!(view.text.is_empty());
            assert!(view.mentions.is_empty());
        }
    }

    #[test]
    fn a_reply_without_the_marker_is_refused() {
        assert!(parse_file_view(sshd_definition(), "PermitRootLogin yes\n").is_err());
        let unterminated = format!("{FILE_MARKER}_BEGIN\nPermitRootLogin yes\n");
        assert!(parse_file_view(sshd_definition(), &unterminated).is_err());
    }

    #[test]
    fn the_read_command_names_only_a_catalogue_file() {
        for definition in BASELINE_CATALOG {
            let command = read_file_command(definition);
            assert!(command.contains(&format!("lr_file='{}'", definition.file())));
            assert!(command.contains(&format!("head -c {MAX_FILE_BYTES}")));
            assert!(command.contains(&format!("head -n {MAX_FILE_LINES}")));
            // Read-only: nothing here writes, moves or removes.
            for forbidden in ["rm ", "mv ", "tee ", "> \"$lr_file\"", "chmod", "chown"] {
                assert!(
                    !command.contains(forbidden),
                    "{} {forbidden}",
                    definition.id
                );
            }
        }
    }

    #[test]
    fn the_scan_asks_about_every_setting_exactly_once() {
        let command = scan_command();
        for definition in BASELINE_CATALOG {
            let call = match definition.reading {
                Reading::RunningSysctl => format!("lr_sysctl '{}'", definition.id),
                Reading::Files(_) => format!("lr_file '{}'", definition.id),
            };
            assert_eq!(
                command.matches(&call).count(),
                1,
                "{} is not asked about exactly once",
                definition.id,
            );
        }
        // Every row the scan prints, it prints the same way.
        assert_eq!(command.matches("printf 'ITEM=%s\\t%s\\t%s\\n'").count(), 2);
        // First-wins needs a found flag; last-wins must not have one, or it
        // would silently become first-wins too.
        for definition in BASELINE_CATALOG {
            if !matches!(definition.reading, Reading::Files(_)) {
                continue;
            }
            let first_wins = reader_program(definition).contains("BEGIN{v=\"\";f=0}");
            assert_eq!(
                first_wins,
                definition.reload == ReloadGroup::Sshd,
                "{} reads the wrong occurrence",
                definition.id
            );
        }
    }

    /// A kernel parameter can be set from any of half a dozen places, and a
    /// unit or an operator can set it from none of them. Reading the file this
    /// tool would write said what someone had written down; it said nothing
    /// about what the kernel was doing, and on a host where the file did not
    /// exist it said every one of these settings was missing.
    #[test]
    fn kernel_parameters_are_read_from_the_running_kernel() {
        let command = scan_command();
        let sysctl = BASELINE_CATALOG
            .iter()
            .filter(|definition| matches!(definition.reading, Reading::RunningSysctl))
            .collect::<Vec<_>>();
        assert!(sysctl.len() >= 18);
        // The reading is done once, in a function; each check names its own
        // parameter and is answered by that function rather than by a file.
        assert!(command.contains("lr_read=$(sysctl -n \"$lr_key\""));
        for definition in sysctl {
            assert!(
                command.contains(&format!(
                    "lr_sysctl '{}' '{}'",
                    definition.id, definition.key
                )),
                "{} is not read from the running kernel",
                definition.id
            );
        }
        // And when there is no sysctl binary, straight from /proc.
        assert!(command.contains("cat /proc/sys/$(printf '%s'"));
    }

    /// A comment after a value is a comment, not part of the value.
    ///
    /// `postgresql.conf` annotates almost every line it ships, and openGauss
    /// with it. Reading `log_connections = off  # log connection requirement`
    /// gave back the whole tail glued together once the punctuation had been
    /// filtered out, so a setting that was plainly `off` was reported as a
    /// value nothing could match and the check could only ever fail.
    #[test]
    fn a_comment_after_a_value_is_not_part_of_the_value() {
        for definition in BASELINE_CATALOG {
            let program = reader_program(definition);
            let strips = match definition.format {
                // nginx ends its values at the semicolon; the XML reader takes
                // an attribute out of quotes; YAML strips its own comments.
                FileFormat::Semicolon | FileFormat::XmlAttribute(_) | FileFormat::Yaml => true,
                FileFormat::Ini(_) => program.contains("sub(/[[:space:]]+[#;].*$/"),
                FileFormat::Whitespace | FileFormat::Equals | FileFormat::IndentSection(_) => {
                    program.contains("sub(/[[:space:]]+#.*$/")
                }
            };
            assert!(
                strips || !matches!(definition.reading, Reading::Files(_)),
                "{} would read a trailing comment as part of the value",
                definition.id
            );
        }
    }

    /// A presence check must never print what it found.
    ///
    /// One of them did: the nginx TLS check trims a trailing semicolon, and
    /// the rewrite that turns the value into a marker was looking for the
    /// exact END the trim had already replaced. It matched nothing, silently,
    /// and the directive's value came back instead of the word.
    #[test]
    fn a_presence_check_prints_a_marker_and_never_a_value() {
        let presence = BASELINE_CATALOG
            .iter()
            .filter(|definition| definition.value_kind == BaselineValueKind::Presence)
            .collect::<Vec<_>>();
        assert!(presence.len() >= 6);
        for definition in presence {
            let program = reader_program(definition);
            assert!(
                program.contains("\"configured\")"),
                "{} would print the value it read",
                definition.id
            );
            assert!(
                !program.contains("; print v}") && !program.contains("END{print v}"),
                "{} still has a path that prints the value",
                definition.id
            );
        }
    }

    /// Every candidate path is a compile-time constant that goes into the
    /// scan unquoted, so a `*` in it is a glob the target's shell resolves.
    /// Nothing else about them may be shell-significant.
    #[test]
    fn candidate_paths_are_inert_enough_to_go_unquoted() {
        for definition in BASELINE_CATALOG {
            for path in definition.candidates() {
                assert!(path.starts_with('/'), "{path} is not absolute");
                assert!(
                    path.bytes().all(|byte| byte.is_ascii_alphanumeric()
                        || matches!(byte, b'/' | b'.' | b'_' | b'-' | b'*')),
                    "{path} carries a shell-significant character"
                );
                assert!(!path.contains("..") && !path.contains("//"));
            }
        }
    }
}
