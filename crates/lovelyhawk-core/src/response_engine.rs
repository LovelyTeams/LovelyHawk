//! Incident response engine: one-shot scan, per-issue fix planning, confirmed
//! execution and independent re-verification, all over the bound SSH channel.
//!
//! Every detector is a static command template that calls system tools by
//! absolute path and reads `/proc` directly, so a target whose `ps`, `ls` or
//! `netstat` was replaced cannot hide evidence from the scan. Every value
//! interpolated into a fix script comes from a scan-time [`IssueObject`] that
//! passed closed validation (path whitelist, username and pid rules) and is
//! quoted with `shq`. Fix scripts re-check the sha256/stat fingerprint or the
//! line digest captured during the scan and abort before touching anything
//! when the object changed in between.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    CoreError, CoreResult,
    audit::privileged_script,
    crypto::SecretValue,
    operations::{
        DangerousConfirmation, ExecutionReceipt, OperationExecutor, OperationPlan,
        PlannedOperation, PortableOperationJournal, VerificationResult,
    },
    shell_escape::{is_valid_pid, is_valid_username, shq},
    ssh::{
        BoundSshSession, SshCommandOutput, SshSensitiveCommandLimits, SshSensitiveCommandOutput,
        SshService,
    },
    target::TargetContext,
};
use zeroize::Zeroizing;

/// The scan walks every /proc environ and maps file on top of the file
/// sections; a slow shared target legitimately needs minutes, not seconds.
const SCAN_TIMEOUT: Duration = Duration::from_secs(240);
const FIX_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_SCAN_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_SENSITIVE_STDERR_BYTES: usize = 64 * 1024;
const MAX_CONFIG_LINES: usize = 2_000;
const MAX_PROCESS_ROWS: usize = 4_096;
const MAX_EMPTY_PASSWORD_ACCOUNTS: usize = 32;
const MAX_PASSWD_LINES: usize = 2_000;
const MAX_EVIDENCE_CHARS: usize = 500;
const MAX_CASCADE_CRON_STEPS: usize = 16;
const MAX_LISTEN_ROWS: usize = 256;
const MAX_ENV_SESSIONS: usize = 64;
const MAX_RESIDUE_ROWS: usize = 256;
const MAX_WEB_ROWS: usize = 1_024;
const MAX_LINKED_PATHS: usize = 16;

/// Stable scan phase codes reported through [`ScanProgress`]; the backend
/// maps them to Chinese labels and a percent for the progress bar.
pub const SCAN_STAGE_PRIVILEGE: &str = "privilege";
pub const SCAN_STAGE_COLLECT: &str = "collect";
pub const SCAN_STAGE_LINKED: &str = "linked";
pub const SCAN_STAGE_ACCOUNTS: &str = "accounts";

/// Progress sink for [`ResponseEngineService::scan_with`]; fires on real
/// phase boundaries only.
pub type ScanProgress = dyn Fn(&str) + Send + Sync;

/// How long the caller must let pass between executing a backdoor-process fix
/// and calling [`ResponseEngineService::verify_fix`], so one full cron
/// keep-alive period (60 s on the standard `* * * * *` schedule) elapses and a
/// respawn would be visible. Core never sleeps; the backend schedules it.
pub const CROSS_PERIOD_VERIFY_DELAY: Duration = Duration::from_secs(70);

const ARCHIVE_ROOT: &str = "/var/case/bak";
const SELF_MARKER: &str = "LOVELYRES_RESPONSE";
const FIX_OK_MARKER: &str = "RESPONSE_FIX_OK";
const FIX_ROLLBACK_MARKER: &str = "RESPONSE_FIX_ROLLBACK";
const VERIFY_OK_MARKER: &str = "RESPONSE_VERIFY_OK";
const VERIFY_FAIL_MARKER: &str = "RESPONSE_VERIFY_FAIL";
const RESTORE_OK_MARKER: &str = "RESPONSE_RESTORE_OK";

const MARKER_HIJACK: &str = "LOVELYRES_RESPONSE_HIJACK_V1";
const MARKER_UID0: &str = "LOVELYRES_RESPONSE_UID0_V1";
const MARKER_SHADOW: &str = "LOVELYRES_RESPONSE_SHADOW_V1";
const MARKER_PASSWD: &str = "LOVELYRES_RESPONSE_PASSWD_V1";
const MARKER_SUDOERS: &str = "LOVELYRES_RESPONSE_SUDOERS_V1";
const MARKER_CRON: &str = "LOVELYRES_RESPONSE_CRON_V1";
const MARKER_PROC: &str = "LOVELYRES_RESPONSE_PROC_V1";
const MARKER_PRELOAD: &str = "LOVELYRES_RESPONSE_PRELOAD_V1";
const MARKER_PATHINJ: &str = "LOVELYRES_RESPONSE_PATHINJ_V1";
const MARKER_AUTHKEYS: &str = "LOVELYRES_RESPONSE_AUTHKEYS_V1";
const MARKER_PAM: &str = "LOVELYRES_RESPONSE_PAM_V1";
const MARKER_LISTEN: &str = "LOVELYRES_RESPONSE_LISTEN_V1";
const MARKER_WEB: &str = "LOVELYRES_RESPONSE_WEB_V1";
const MARKER_HOOK: &str = "LOVELYRES_RESPONSE_HOOK_V1";
const MARKER_HIST: &str = "LOVELYRES_RESPONSE_HISTORY_V1";
const MARKER_ENVIRON: &str = "LOVELYRES_RESPONSE_ENVIRON_V1";
const MARKER_MAPS: &str = "LOVELYRES_RESPONSE_MAPS_V1";
const MARKER_DONE: &str = "LOVELYRES_RESPONSE_DONE_V1";

/// Paths a fix may touch. Anything else parses as an issue with
/// `fixable: false` so the whitelist is enforced by construction.
const ALLOWED_PATH_EXACT: &[&str] = &[
    "/etc/sudoers",
    "/etc/crontab",
    "/etc/ld.so.preload",
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/environment",
    "/root/.bashrc",
    "/root/.bash_profile",
    "/root/.ssh/authorized_keys",
    "/root/.bash_history",
];
const ALLOWED_PATH_PREFIXES: &[&str] = &[
    "/usr/local/bin/",
    "/etc/sudoers.d/",
    "/etc/cron.d/",
    "/var/spool/cron/",
    "/usr/local/libexec/",
    "/usr/local/lib/",
    "/etc/profile.d/",
    "/etc/pam.d/",
    "/var/www/",
];

/// Prefixes under which only *hidden* directories (first component starts with
/// `.`) are writable by a fix: classic attacker stash locations such as
/// `/var/tmp/.sysd`. System hidden dirs in [`STASH_DIR_DENYLIST`] stay closed.
const HIDDEN_DIR_PREFIXES: &[&str] = &["/var/tmp/", "/tmp/", "/dev/shm/", "/opt/"];
const STASH_DIR_DENYLIST: &[&str] = &[
    "/tmp/.X11-unix",
    "/tmp/.ICE-unix",
    "/tmp/.font-unix",
    "/tmp/.Test-unix",
    "/tmp/.XIM-unix",
];

/// Signature codes a live session environment can be flagged with. Closed so
/// the kill re-check can look for the exact same evidence again.
const SESSION_SIGNATURE_CODES: &[&str] = &["prompt-recorder", "injected-path", "resident-preload"];

/// Library prefixes a legitimate distro package does not use: a mapped,
/// already-deleted `.so` under one of these is attacker residue. `/usr/lib`
/// and `/lib` are excluded on purpose — distro upgrades legitimately leave
/// `(deleted)` mappings there.
const RESIDENT_LIB_PREFIXES: &[&str] = &[
    "/usr/local/lib/",
    "/usr/local/libexec/",
    "/opt/",
    "/var/tmp/",
    "/tmp/",
    "/dev/shm/",
];

/// Auth-critical watch points for the auditd hardening item; the watch key
/// and permissions are fixed by the engine, only these paths are added.
const AUDIT_WATCH_POINTS: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/cron.d",
    "/var/spool/cron",
    "/etc/profile.d",
    "/etc/pam.d",
    "/var/tmp",
    "/root/.ssh",
];
const AUDIT_WATCH_KEY: &str = "lovelyhawk-tamper";

/// The hardening permission baseline: `(path, mode, owner, group)` in
/// `stat -c '%a|%U|%G'` terms. Only files that exist on the target are
/// checked; a missing file is not a deviation.
const HARDENING_PERMISSION_TARGETS: &[(&str, &str)] = &[
    ("/etc/shadow", "640|root|shadow"),
    ("/etc/gshadow", "640|root|shadow"),
    ("/etc/sudoers", "440|root|root"),
    ("/root/.ssh", "700|root|root"),
    ("/root/.ssh/authorized_keys", "600|root|root"),
    ("/var/spool/cron/crontabs", "1730|root|crontab"),
];

/// Remote location of the hardening integrity manifest.
const HARDENING_MANIFEST: &str = "/var/case/hardening/integrity-manifest.txt";
const HARDENING_MANIFEST_DIR: &str = "/var/case/hardening";
/// Glob shapes (expanded on the target) feeding the integrity manifest.
const HARDENING_SNAPSHOT_GLOBS: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/sudoers",
    "/etc/crontab",
    "/etc/ld.so.preload",
    "/etc/ssh/sshd_config",
    "/etc/pam.d/*",
    "/etc/profile.d/*.sh",
    "/etc/sudoers.d/*",
    "/etc/cron.d/*",
    "/var/spool/cron/crontabs/*",
    "/root/.ssh/authorized_keys",
    "/usr/local/bin/*",
    "/usr/local/libexec/*",
    "/usr/local/lib/*.so*",
    "/etc/ssh/ssh_host_*_key",
];
const MAX_SNAPSHOT_FILES: usize = 256;
/// How many manifest entries a drift re-check recomputes.
const MAX_SNAPSHOT_RECHECK: usize = 64;

/// Shell startup files scanned for PATH injections and recorder hooks.
const STARTUP_FILES_EXACT: &[&str] = &[
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/environment",
    "/root/.bashrc",
    "/root/.bash_profile",
];

/// Directory tokens that legitimately appear in PATH assignments; anything
/// hidden or under a world-writable prefix outside this set is an injection.
const STANDARD_PATH_DIRS: &[&str] = &[
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
    "/usr/games",
    "/usr/local/games",
    "/snap/bin",
];

/// Loopback listener ports that are plausibly legitimate services; any other
/// loopback LISTEN is reported as a suspicious bind listener.
const BENIGN_LOOPBACK_PORTS: &[u16] = &[25, 53, 80, 443, 587, 3306, 5432, 6379, 11211, 27017];

/// Locations a legitimately installed service binary or cron job should never
/// live in; their presence in a process command line or cron entry is the
/// signal itself.
const SUSPICIOUS_EXEC_PREFIXES: &[&str] =
    &["/usr/local/libexec/", "/tmp/", "/var/tmp/", "/dev/shm/"];

const CRON_SUSPICIOUS_TOKENS: &[&str] = &[
    "/dev/tcp",
    "/dev/shm/",
    "/var/tmp/",
    "/tmp/",
    "/usr/local/libexec/",
    "nohup",
    "pgrep -f",
    "base64",
    "bash -i",
    "sh -i",
    "nc -",
    "ncat",
    "curl ",
    "wget ",
    "python",
    "perl ",
];

/// Login shells an interactive account may legitimately use; accounts whose
/// shell is outside this closed set (nologin/false/sync/halt, ...) are system
/// accounts, not suspicious logins.
const INTERACTIVE_SHELLS: &[&str] = &["/bin/bash", "/bin/sh", "/bin/zsh", "/bin/dash", "/bin/ash"];

/// The incident shapes this engine detects and fixes. Closed on purpose:
/// the fixers only exist for these kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResponseIssueKind {
    HijackedCommand,
    UidZeroAccount,
    EmptyPassword,
    SuspiciousAccount,
    MaliciousSudoers,
    CronPersistence,
    BackdoorProcess,
    LdPreloadHijack,
    PathInjection,
    SshKeyBackdoor,
    PamBackdoor,
    BindListener,
    StashDir,
    WebSensitiveFile,
    Webshell,
    CommandRecorder,
    HistoryCredentialLeak,
    SessionEnvHook,
    PreloadResidue,
    HardeningAuthPermissions,
    HardeningAuditWatch,
    HardeningIntegritySnapshot,
}

impl ResponseIssueKind {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::HijackedCommand => "hijacked-command",
            Self::UidZeroAccount => "uid-zero-account",
            Self::EmptyPassword => "empty-password",
            Self::SuspiciousAccount => "suspicious-account",
            Self::MaliciousSudoers => "malicious-sudoers",
            Self::CronPersistence => "cron-persistence",
            Self::BackdoorProcess => "backdoor-process",
            Self::LdPreloadHijack => "ld-preload-hijack",
            Self::PathInjection => "path-injection",
            Self::SshKeyBackdoor => "ssh-key-backdoor",
            Self::PamBackdoor => "pam-backdoor",
            Self::BindListener => "bind-listener",
            Self::StashDir => "stash-dir",
            Self::WebSensitiveFile => "web-sensitive-file",
            Self::Webshell => "webshell",
            Self::CommandRecorder => "command-recorder",
            Self::HistoryCredentialLeak => "history-credential-leak",
            Self::SessionEnvHook => "session-env-hook",
            Self::PreloadResidue => "preload-residue",
            Self::HardeningAuthPermissions => "hardening-auth-permissions",
            Self::HardeningAuditWatch => "hardening-audit-watch",
            Self::HardeningIntegritySnapshot => "hardening-integrity-snapshot",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::HijackedCommand => "命令劫持",
            Self::UidZeroAccount => "UID 为 0 的影子账户",
            Self::EmptyPassword => "空口令账户",
            Self::SuspiciousAccount => "可疑登录账户",
            Self::MaliciousSudoers => "恶意 sudoers 授权",
            Self::CronPersistence => "cron 持久化",
            Self::BackdoorProcess => "后门进程",
            Self::LdPreloadHijack => "动态链接库劫持",
            Self::PathInjection => "PATH 注入",
            Self::SshKeyBackdoor => "SSH 密钥后门",
            Self::PamBackdoor => "PAM 认证后门",
            Self::BindListener => "可疑监听",
            Self::StashDir => "后门藏匿目录",
            Self::WebSensitiveFile => "Web 敏感文件泄露",
            Self::Webshell => "WebShell",
            Self::CommandRecorder => "命令录音钩子",
            Self::HistoryCredentialLeak => "历史命令明文密码",
            Self::SessionEnvHook => "会话驻留钩子",
            Self::PreloadResidue => "恶意库驻留进程",
            Self::HardeningAuthPermissions => "认证文件权限加固",
            Self::HardeningAuditWatch => "防复发监控加固",
            Self::HardeningIntegritySnapshot => "关键文件基线加固",
        }
    }

    /// The hardening kinds only appear on items from
    /// [`ResponseEngineService::hardening_scan`]; the incident scan never
    /// reports them and `plan_fix` routes them through the same plan
    /// machinery the backend keeps in a separate handle registry.
    pub const fn is_hardening(self) -> bool {
        matches!(
            self,
            Self::HardeningAuthPermissions
                | Self::HardeningAuditWatch
                | Self::HardeningIntegritySnapshot
        )
    }

    /// Fixed display order inside one severity: the "eyes" of the target
    /// (ld.so.preload, PATH injection, hijacked commands) come first because
    /// every later finding is only trustworthy once they are fixed.
    const fn sort_rank(self) -> u8 {
        match self {
            Self::LdPreloadHijack => 0,
            Self::PathInjection => 1,
            Self::HijackedCommand => 2,
            Self::SshKeyBackdoor => 3,
            Self::PamBackdoor => 4,
            Self::Webshell => 5,
            Self::BindListener => 6,
            Self::BackdoorProcess => 7,
            Self::UidZeroAccount => 8,
            Self::EmptyPassword => 9,
            Self::MaliciousSudoers => 10,
            Self::CronPersistence => 11,
            Self::StashDir => 12,
            Self::WebSensitiveFile => 13,
            Self::CommandRecorder => 14,
            Self::SuspiciousAccount => 15,
            Self::HistoryCredentialLeak => 16,
            // Session-resident hooks keep re-creating the recorder log file, so
            // they must be dealt with before the on-disk recorder fix can stick.
            Self::SessionEnvHook => 17,
            Self::PreloadResidue => 18,
            // Hardening kinds never surface in an incident scan; ranks exist so
            // the ordering stays total.
            Self::HardeningAuthPermissions => 19,
            Self::HardeningAuditWatch => 20,
            Self::HardeningIntegritySnapshot => 21,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResponseSeverity {
    Critical,
    High,
    Medium,
    Low,
}

impl ResponseSeverity {
    const fn rank(self) -> u8 {
        match self {
            Self::Critical => 0,
            Self::High => 1,
            Self::Medium => 2,
            Self::Low => 3,
        }
    }
}

/// How an account-type fix treats the account: lock the password in place
/// (the default, reversible) or remove the account entirely. Only meaningful
/// for [`ResponseIssueKind::EmptyPassword`]; every other kind plans in the
/// default mode only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FixMode {
    #[default]
    Lock,
    Remove,
}

/// `stat -c '%a|%u|%g|%s|%Y'` captured at scan time; the fix script refuses to
/// run when the live value differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatFingerprint {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub mtime: i64,
}

impl StatFingerprint {
    fn remote_form(&self) -> String {
        format!(
            "{:o}|{}|{}|{}|{}",
            self.mode, self.uid, self.gid, self.size, self.mtime
        )
    }

    fn parse(text: &str) -> Option<Self> {
        let mut fields = text.split('|');
        let mode = u32::from_str_radix(fields.next()?, 8).ok()?;
        let uid = fields.next()?.parse().ok()?;
        let gid = fields.next()?.parse().ok()?;
        let size = fields.next()?.parse().ok()?;
        let mtime = fields.next()?.parse().ok()?;
        if fields.next().is_some() {
            return None;
        }
        Some(Self {
            mode,
            uid,
            gid,
            size,
            mtime,
        })
    }
}

/// A file captured at scan time with its integrity fingerprint; used for
/// secondary objects (preload libraries, fake commands, hook logs, forced
/// commands) that a fix deletes with a TOCTOU re-check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackedPath {
    pub path: String,
    pub sha256: String,
    pub stat: StatFingerprint,
}

/// One auth-critical file whose observed `mode|owner|group` (as printed by
/// `stat -c '%a|%U|%G'`) deviates from the hardening target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionEntry {
    pub path: String,
    pub current: String,
    pub target: String,
}

/// One process of a hooked session cluster: its PID plus the binary the
/// kill re-check compares `/proc/<pid>/exe` against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEnvProcess {
    pub pid: u32,
    pub exe: String,
}

impl PermissionEntry {
    fn parse_triple(text: &str) -> Option<(String, String, String)> {
        let mut fields = text.split('|');
        let mode = fields.next()?;
        let owner = fields.next()?;
        let group = fields.next()?;
        if fields.next().is_some() {
            return None;
        }
        if mode.is_empty() || owner.is_empty() || group.is_empty() {
            return None;
        }
        Some((mode.to_owned(), owner.to_owned(), group.to_owned()))
    }
}

/// Validated identity of the object a fix will touch. Never serialized: the
/// page only ever sees the display fields of [`ResponseIssue`], and fix
/// planning re-derives executable semantics from this core-owned value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssueObject {
    Path {
        path: String,
        sha256: String,
        stat: StatFingerprint,
    },
    Account {
        username: String,
        uid: u32,
        home: String,
    },
    SudoersRule {
        file: String,
        line: u32,
        line_sha256: String,
    },
    CronEntry {
        file: String,
        line: u32,
        line_sha256: String,
    },
    Process {
        pids: Vec<u32>,
        exe_path: String,
        /// `Some(port)` when the process holds a suspicious LISTEN socket
        /// (`bind-listener`): verification then also requires the port closed.
        listen_port: Option<u16>,
    },
    /// `/etc/ld.so.preload` plus the shared libraries it references.
    LdPreload {
        file: String,
        sha256: String,
        stat: StatFingerprint,
        libs: Vec<TrackedPath>,
    },
    /// One PATH-injection line in a shell startup file, plus the fake wrapper
    /// commands found inside the directories it injects.
    StartupLine {
        file: String,
        line: u32,
        line_sha256: String,
        injected_dirs: Vec<String>,
        linked_fakes: Vec<TrackedPath>,
    },
    /// One `command="..."` forced-command entry in an authorized_keys file.
    AuthKeyEntry {
        file: String,
        line: u32,
        line_sha256: String,
        command_path: Option<TrackedPath>,
    },
    /// One non-comment `pam_permit.so` line in `/etc/pam.d/*`.
    PamLine {
        file: String,
        line: u32,
        line_sha256: String,
    },
    /// A hidden stash directory (e.g. `/var/tmp/.sysd`) referenced by
    /// persistence entries or backdoor processes.
    StashDir { path: String },
    /// One PROMPT_COMMAND recorder hook line, plus the log file it writes to.
    RecorderHook {
        file: String,
        line: u32,
        line_sha256: String,
        log: Option<TrackedPath>,
    },
    /// One history line carrying a cleartext credential.
    HistoryLine {
        file: String,
        line: u32,
        line_sha256: String,
    },
    /// One live login-session tree whose in-memory environment still carries
    /// a hook from the (possibly already deleted) startup files: a
    /// PROMPT_COMMAND recorder, an injected PATH entry or a resident
    /// LD_PRELOAD. The environment propagates to every child — the shell may
    /// even have `exec`ed away — so the cluster holds every process sharing
    /// the same hooked environment. Deleting the startup file does not clean
    /// these copies; the sessions themselves must end.
    SessionEnv {
        processes: Vec<SessionEnvProcess>,
        /// Closed signature codes: `prompt-recorder`, `injected-path`,
        /// `resident-preload`.
        signatures: Vec<String>,
    },
    /// A deleted suspicious shared library still mapped by running
    /// processes (`/proc/<pid>/maps` marks it `(deleted)`); the in-memory
    /// hook survives until each process restarts. Reported for guidance:
    /// killing system services blindly can take the business down, so no
    /// automatic fix is offered.
    ResidentLib {
        lib_path: String,
        pids: Vec<u32>,
        exes: Vec<String>,
    },
    /// Hardening: auth-critical files whose mode/owner deviates from the
    /// closed baseline; entries carry the observed and target permission
    /// text so the fix can re-check and restore both ways.
    HardeningPermissions { entries: Vec<PermissionEntry> },
    /// Hardening: auditd watch points to add (paths only, key and
    /// permissions are fixed by the engine).
    HardeningAuditWatch { points: Vec<String> },
    /// Hardening: create (or rebuild) the integrity manifest of
    /// auth-critical files under `/var/case/hardening/`.
    HardeningSnapshot {},
}

impl IssueObject {
    /// Closed validation run before any plan is built. Rejects path traversal,
    /// paths outside the response whitelist, malformed digests, invalid
    /// account names, and objects that no longer match the issue kind (for
    /// example a non-zero UID under `uid-zero-account`).
    pub fn validate(&self, kind: ResponseIssueKind) -> CoreResult<()> {
        match (kind, self) {
            (ResponseIssueKind::HijackedCommand, Self::Path { path, sha256, stat }) => {
                let allowed_dir =
                    path.starts_with("/usr/local/bin/") || hidden_dir_ancestor(path).is_some();
                if !is_allowed_response_path(path) || !allowed_dir {
                    return Err(CoreError::validation(
                        "response issue path",
                        format!("path {path:?} is outside the response whitelist"),
                    ));
                }
                validate_file_fingerprint(sha256, stat)?;
                let name = path.rsplit('/').next().unwrap_or_default();
                if !is_valid_command_name(name) {
                    return Err(CoreError::validation(
                        "response issue command name",
                        format!("invalid command name {name:?}"),
                    ));
                }
                Ok(())
            }
            (
                ResponseIssueKind::WebSensitiveFile | ResponseIssueKind::Webshell,
                Self::Path { path, sha256, stat },
            ) => {
                if !path.starts_with("/var/www/") || !is_allowed_response_path(path) {
                    return Err(CoreError::validation(
                        "response issue web file",
                        format!("path {path:?} is outside /var/www/"),
                    ));
                }
                validate_file_fingerprint(sha256, stat)
            }
            (
                kind @ (ResponseIssueKind::UidZeroAccount
                | ResponseIssueKind::EmptyPassword
                | ResponseIssueKind::SuspiciousAccount),
                Self::Account {
                    username,
                    uid,
                    home,
                },
            ) => {
                if !is_valid_username(username) {
                    return Err(CoreError::validation(
                        "response issue account",
                        format!("invalid username {username:?}"),
                    ));
                }
                if kind == ResponseIssueKind::UidZeroAccount && *uid != 0 {
                    return Err(CoreError::validation(
                        "response issue account",
                        format!("uid-zero-account issue carries non-zero uid {uid}"),
                    ));
                }
                if kind == ResponseIssueKind::SuspiciousAccount && *uid < 1000 {
                    return Err(CoreError::validation(
                        "response issue account",
                        format!("suspicious-account issue carries system uid {uid}"),
                    ));
                }
                if !home.is_empty()
                    && (!home.starts_with('/')
                        || home.split('/').any(|component| component == ".."))
                {
                    return Err(CoreError::validation(
                        "response issue account",
                        format!("invalid home directory {home:?}"),
                    ));
                }
                Ok(())
            }
            (
                ResponseIssueKind::MaliciousSudoers,
                Self::SudoersRule {
                    file,
                    line,
                    line_sha256,
                },
            ) => {
                if *file != "/etc/sudoers" && !file.starts_with("/etc/sudoers.d/") {
                    return Err(CoreError::validation(
                        "response issue sudoers file",
                        format!("file {file:?} is outside /etc/sudoers*"),
                    ));
                }
                validate_line_reference(*line, line_sha256)
            }
            (
                ResponseIssueKind::CronPersistence,
                Self::CronEntry {
                    file,
                    line,
                    line_sha256,
                },
            ) => {
                let allowed = *file == "/etc/crontab"
                    || file.starts_with("/etc/cron.d/")
                    || file.starts_with("/var/spool/cron/");
                if !allowed || file.split('/').any(|component| component == "..") {
                    return Err(CoreError::validation(
                        "response issue cron file",
                        format!("file {file:?} is outside the cron whitelist"),
                    ));
                }
                validate_line_reference(*line, line_sha256)
            }
            (
                kind @ (ResponseIssueKind::BackdoorProcess | ResponseIssueKind::BindListener),
                Self::Process {
                    pids,
                    exe_path,
                    listen_port,
                },
            ) => {
                if pids.is_empty() || pids.len() > 64 {
                    return Err(CoreError::validation(
                        "response issue process",
                        "must carry between 1 and 64 pids",
                    ));
                }
                if !pids.iter().all(|pid| is_valid_pid(&pid.to_string())) {
                    return Err(CoreError::validation(
                        "response issue process",
                        "pid out of range",
                    ));
                }
                if !is_allowed_response_path(exe_path) {
                    return Err(CoreError::validation(
                        "response issue process body",
                        format!("path {exe_path:?} is outside the response whitelist"),
                    ));
                }
                if kind == ResponseIssueKind::BindListener && listen_port.is_none() {
                    return Err(CoreError::validation(
                        "response issue listener",
                        "bind-listener issue must carry the listen port",
                    ));
                }
                Ok(())
            }
            (
                ResponseIssueKind::LdPreloadHijack,
                Self::LdPreload {
                    file,
                    sha256,
                    stat,
                    libs,
                },
            ) => {
                if file != "/etc/ld.so.preload" {
                    return Err(CoreError::validation(
                        "response issue preload file",
                        format!("file {file:?} is not /etc/ld.so.preload"),
                    ));
                }
                validate_file_fingerprint(sha256, stat)?;
                if libs.len() > MAX_LINKED_PATHS {
                    return Err(CoreError::validation(
                        "response issue preload libraries",
                        "too many referenced libraries",
                    ));
                }
                for lib in libs {
                    validate_tracked_path(lib)?;
                }
                Ok(())
            }
            (
                ResponseIssueKind::PathInjection,
                Self::StartupLine {
                    file,
                    line,
                    line_sha256,
                    injected_dirs,
                    linked_fakes,
                },
            ) => {
                validate_startup_file(file)?;
                validate_line_reference(*line, line_sha256)?;
                if injected_dirs.is_empty()
                    || injected_dirs.len() > MAX_LINKED_PATHS
                    || linked_fakes.len() > MAX_LINKED_PATHS
                {
                    return Err(CoreError::validation(
                        "response issue path injection",
                        "injected dir / linked fake count out of range",
                    ));
                }
                for dir in injected_dirs {
                    if !is_allowed_response_path(dir) {
                        return Err(CoreError::validation(
                            "response issue injected dir",
                            format!("dir {dir:?} is outside the response whitelist"),
                        ));
                    }
                }
                for fake in linked_fakes {
                    validate_tracked_path(fake)?;
                }
                Ok(())
            }
            (
                ResponseIssueKind::SshKeyBackdoor,
                Self::AuthKeyEntry {
                    file,
                    line,
                    line_sha256,
                    command_path,
                },
            ) => {
                if !is_authorized_keys_path(file) {
                    return Err(CoreError::validation(
                        "response issue authorized_keys",
                        format!("file {file:?} is not an authorized_keys path"),
                    ));
                }
                validate_line_reference(*line, line_sha256)?;
                if let Some(command) = command_path {
                    validate_tracked_path(command)?;
                }
                Ok(())
            }
            (
                ResponseIssueKind::PamBackdoor,
                Self::PamLine {
                    file,
                    line,
                    line_sha256,
                },
            ) => {
                if !file.starts_with("/etc/pam.d/")
                    || !is_allowed_response_path(file)
                    || !is_valid_command_name(file.rsplit('/').next().unwrap_or_default())
                {
                    return Err(CoreError::validation(
                        "response issue pam file",
                        format!("file {file:?} is outside /etc/pam.d/"),
                    ));
                }
                validate_line_reference(*line, line_sha256)
            }
            (ResponseIssueKind::StashDir, Self::StashDir { path }) => {
                if hidden_dir_ancestor(path).as_deref() != Some(path.as_str())
                    || !is_allowed_response_path(path)
                {
                    return Err(CoreError::validation(
                        "response issue stash dir",
                        format!("dir {path:?} is not an allowed hidden stash directory"),
                    ));
                }
                Ok(())
            }
            (
                ResponseIssueKind::CommandRecorder,
                Self::RecorderHook {
                    file,
                    line,
                    line_sha256,
                    log,
                },
            ) => {
                validate_startup_file(file)?;
                validate_line_reference(*line, line_sha256)?;
                if let Some(log) = log {
                    validate_tracked_path(log)?;
                }
                Ok(())
            }
            (
                ResponseIssueKind::HistoryCredentialLeak,
                Self::HistoryLine {
                    file,
                    line,
                    line_sha256,
                },
            ) => {
                if !is_history_file_path(file) {
                    return Err(CoreError::validation(
                        "response issue history file",
                        format!("file {file:?} is not an allowed .bash_history path"),
                    ));
                }
                validate_line_reference(*line, line_sha256)
            }
            (
                ResponseIssueKind::SessionEnvHook,
                Self::SessionEnv {
                    processes,
                    signatures,
                },
            ) => {
                if processes.is_empty() || processes.len() > 64 {
                    return Err(CoreError::validation(
                        "response issue session processes",
                        "process list must contain 1 to 64 entries",
                    ));
                }
                let mut seen = BTreeSet::new();
                for process in processes {
                    if process.pid == 0 {
                        return Err(CoreError::validation(
                            "response issue session pid",
                            "pid must be a positive integer",
                        ));
                    }
                    if !process.exe.starts_with('/') || process.exe.len() > 256 {
                        return Err(CoreError::validation(
                            "response issue session exe",
                            format!("exe {:?} is not a bounded absolute path", process.exe),
                        ));
                    }
                    if !seen.insert(process.pid) {
                        return Err(CoreError::validation(
                            "response issue session pid",
                            "pid list contains duplicates",
                        ));
                    }
                }
                if signatures.is_empty() || signatures.len() > 3 {
                    return Err(CoreError::validation(
                        "response issue session signatures",
                        "signature list must contain 1 to 3 codes",
                    ));
                }
                if signatures
                    .iter()
                    .any(|code| !SESSION_SIGNATURE_CODES.contains(&code.as_str()))
                {
                    return Err(CoreError::validation(
                        "response issue session signatures",
                        "signature code outside the closed set",
                    ));
                }
                Ok(())
            }
            (
                ResponseIssueKind::PreloadResidue,
                Self::ResidentLib {
                    lib_path,
                    pids,
                    exes,
                },
            ) => {
                if !is_suspicious_lib_path(lib_path) {
                    return Err(CoreError::validation(
                        "response issue resident lib",
                        format!("lib {lib_path:?} is outside the suspicious library prefixes"),
                    ));
                }
                validate_pid_list(pids)?;
                if exes.is_empty() || exes.len() > 64 {
                    return Err(CoreError::validation(
                        "response issue resident lib exes",
                        "exe list must contain 1 to 64 entries",
                    ));
                }
                if exes
                    .iter()
                    .any(|exe| !exe.starts_with('/') || exe.len() > 256)
                {
                    return Err(CoreError::validation(
                        "response issue resident lib exes",
                        "exe entries must be bounded absolute paths",
                    ));
                }
                Ok(())
            }
            (
                ResponseIssueKind::HardeningAuthPermissions,
                Self::HardeningPermissions { entries },
            ) => {
                if entries.is_empty() || entries.len() > 32 {
                    return Err(CoreError::validation(
                        "response hardening permissions",
                        "entry list must contain 1 to 32 files",
                    ));
                }
                for entry in entries {
                    if !is_hardening_permission_path(&entry.path) {
                        return Err(CoreError::validation(
                            "response hardening permissions",
                            format!("path {:?} is outside the hardening target set", entry.path),
                        ));
                    }
                    if PermissionEntry::parse_triple(&entry.current).is_none()
                        || PermissionEntry::parse_triple(&entry.target).is_none()
                    {
                        return Err(CoreError::validation(
                            "response hardening permissions",
                            "permission triples must look like mode|owner|group",
                        ));
                    }
                }
                Ok(())
            }
            (ResponseIssueKind::HardeningAuditWatch, Self::HardeningAuditWatch { points }) => {
                if points.is_empty() || points.len() > AUDIT_WATCH_POINTS.len() {
                    return Err(CoreError::validation(
                        "response hardening audit watch",
                        "watch point list is empty or oversized",
                    ));
                }
                if points
                    .iter()
                    .any(|point| !AUDIT_WATCH_POINTS.contains(&point.as_str()))
                {
                    return Err(CoreError::validation(
                        "response hardening audit watch",
                        "watch point outside the closed point set",
                    ));
                }
                if points.len()
                    != points
                        .iter()
                        .collect::<std::collections::BTreeSet<_>>()
                        .len()
                {
                    return Err(CoreError::validation(
                        "response hardening audit watch",
                        "watch point list contains duplicates",
                    ));
                }
                Ok(())
            }
            (ResponseIssueKind::HardeningIntegritySnapshot, Self::HardeningSnapshot {}) => Ok(()),
            (kind, object) => Err(CoreError::validation(
                "response issue object",
                format!(
                    "object variant does not match issue kind {}: {object:?}",
                    kind.slug()
                ),
            )),
        }
    }
}

fn validate_line_reference(line: u32, line_sha256: &str) -> CoreResult<()> {
    if line == 0 || line > 1_000_000 {
        return Err(CoreError::validation(
            "response issue line",
            "line number out of range",
        ));
    }
    if !is_sha256_hex(line_sha256) {
        return Err(CoreError::validation(
            "response issue line digest",
            "line sha256 must be 64 lowercase hex characters",
        ));
    }
    Ok(())
}

/// One detected incident. `object` stays inside core; it is the only source of
/// executable identity for [`ResponseEngineService::plan_fix`].
#[derive(Debug, Clone, Serialize)]
pub struct ResponseIssue {
    pub kind: ResponseIssueKind,
    pub severity: ResponseSeverity,
    pub summary: String,
    pub evidence: Vec<String>,
    pub fixable: bool,
    pub fix_summary: Option<String>,
    #[serde(skip_serializing)]
    object: IssueObject,
}

impl ResponseIssue {
    pub fn object(&self) -> &IssueObject {
        &self.object
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ResponseScan {
    pub issues: Vec<ResponseIssue>,
    /// True when a remote section hit its line cap; the displayed issue list
    /// is then known to be incomplete.
    pub truncated: bool,
    /// Why parts of the target could not be inspected (missing privilege,
    /// unreadable files). Never presented as "no risk".
    pub gaps: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FixStep {
    label: String,
    script: String,
}

/// An immutable, target-bound fix plan. Created by
/// [`ResponseEngineService::plan_fix`] after a live fingerprint re-check.
#[derive(Debug, Clone)]
pub struct ResponseFixPlan {
    pub operation: OperationPlan,
    pub issue_kind: ResponseIssueKind,
    /// Remote evidence archive directory (`/var/case/bak/<UTC>-<kind>`) the
    /// fix populates before deleting anything.
    pub archive_dir: String,
    /// `Some(70s)` for backdoor processes: the caller waits this long before
    /// `verify_fix` so a cron respawn would show up.
    pub cross_period_verify_delay: Option<Duration>,
    issue: ResponseIssue,
    // Fully privilege-wrapped command text. For password sudo the wrapping is
    // `sudo -S` and carries no secret; the password rides stdin at run time.
    privilege: Privilege,
    steps: Vec<FixStep>,
    verify_script: String,
    restore_script: Option<String>,
}

impl ResponseFixPlan {
    pub fn issue(&self) -> &ResponseIssue {
        &self.issue
    }

    pub fn step_labels(&self) -> Vec<&str> {
        self.steps.iter().map(|step| step.label.as_str()).collect()
    }
}

/// Handle between `execute_fix` and `verify_fix`: holds the journaled
/// operation state machine so verification cannot run against a different
/// plan. Not serializable; the backend keeps it in memory next to its opaque
/// issue handle.
#[derive(Debug)]
pub struct ResponseFixExecution {
    pub operation_id: String,
    pub summary: String,
    pub archive_dir: String,
    pub cross_period_verify_delay: Option<Duration>,
    operation: PlannedOperation,
    plan: ResponseFixPlan,
}

#[derive(Debug)]
pub struct ResponseFixVerification {
    pub operation_id: String,
    pub verification: VerificationResult,
}

/// The privilege the session can reach. Password sudo keeps the password
/// inside [`SecretValue`] for the plan's whole lifetime; it never enters
/// command text, logs, journals or DTOs — only the stdin of the sensitive
/// channel that runs the wrapped command.
#[derive(Debug, Clone)]
enum Privilege {
    Root,
    SudoNoPassword,
    SudoWithPassword(Arc<SecretValue>),
}

#[derive(Debug, Clone)]
pub struct ResponseEngineService {
    ssh: SshService,
    target: Arc<TargetContext>,
}

impl ResponseEngineService {
    pub fn new(ssh: SshService, target: Arc<TargetContext>) -> Self {
        Self { ssh, target }
    }

    /// Run all seven detectors over the bound session. Detector failures become
    /// `gaps` entries, never silently empty results; a transport-level failure
    /// of the scan itself is an error.
    pub async fn scan(&self, session: &BoundSshSession) -> CoreResult<ResponseScan> {
        self.scan_with(session, None, None).await
    }

    /// [`Self::scan`] with an optional closed kind selection (None = every
    /// detector) and an optional progress callback receiving the stable stage
    /// codes below. The callback fires on real phase boundaries only; the
    /// caller maps the codes to labels and percent.
    pub async fn scan_with(
        &self,
        session: &BoundSshSession,
        kinds: Option<&[ResponseIssueKind]>,
        progress: Option<&ScanProgress>,
    ) -> CoreResult<ResponseScan> {
        let report = |code: &str| {
            if let Some(progress) = progress {
                progress(code);
            }
        };
        self.target.validate(session.target())?;
        report(SCAN_STAGE_PRIVILEGE);
        let privilege = self.probe_privilege(session).await?;
        let session_user = self.probe_session_username(session).await?;
        report(SCAN_STAGE_COLLECT);
        let output = match &privilege {
            Some(privilege) => {
                self.run_privileged(
                    session,
                    privilege,
                    &scan_script(),
                    "response scan",
                    SCAN_TIMEOUT,
                )
                .await?
            }
            None => {
                self.run_command(
                    session,
                    format!("/bin/sh -c {}", shq(&scan_script())),
                    "response scan",
                    SCAN_TIMEOUT,
                )
                .await?
            }
        };
        if output.len() > MAX_SCAN_OUTPUT_BYTES {
            return Err(CoreError::validation(
                "response scan output",
                format!("exceeds the {MAX_SCAN_OUTPUT_BYTES}-byte limit"),
            ));
        }
        let raw = split_sections(&output)?;
        let mut truncated = false;
        let mut gaps = Vec::new();
        if privilege.is_none() {
            gaps.push(
                "当前会话不是 root 且没有免密 sudo：/etc/shadow、cron 目录与其他用户的进程可能无法读取，扫描不完整且所有修复不可用"
                    .to_owned(),
            );
        }
        if session_user.is_none() {
            gaps.push(
                "无法确定会话登录用户名：可疑登录账户检测未排除当前登录用户，可能把会话账户本身列为可疑"
                    .to_owned(),
            );
        }
        let mut issues = Vec::new();
        let hijack_rows = parse_hijacked(raw.hijack, &mut truncated);
        for row in &hijack_rows {
            issues.push(hijacked_issue(row, privilege.is_some()));
        }
        let uid0 = parse_uid0_accounts(raw.uid0, &mut truncated);
        let empty_names = parse_empty_password_accounts(raw.shadow, &mut gaps);
        let flagged: Vec<String> = uid0
            .iter()
            .map(|account| account.username.clone())
            .chain(empty_names.iter().cloned())
            .collect();
        for account in &uid0 {
            issues.push(uid_zero_issue(account.clone(), privilege.is_some()));
        }
        // Non-system accounts with a real login shell that are neither the
        // session's own login nor already flagged by the uid-zero /
        // empty-password detectors: classic planted backdoor accounts.
        let passwd_accounts = parse_passwd_accounts(raw.passwd, &mut truncated, &mut gaps);
        for account in passwd_accounts {
            if !is_suspicious_login_account(&account, session_user.as_deref(), &flagged) {
                continue;
            }
            issues.push(suspicious_account_issue(account, privilege.is_some()));
        }
        let sudoers_rows = parse_config_lines(raw.sudoers, &mut truncated, &mut gaps);
        let cron_rows = parse_config_lines(raw.cron, &mut truncated, &mut gaps);
        for row in &sudoers_rows {
            if let Some(severity) = classify_sudoers_line(&row.text, &flagged) {
                issues.push(sudoers_issue(row, severity, privilege.is_some()));
            }
        }
        for row in &cron_rows {
            if is_suspicious_cron_line(&row.text) {
                issues.push(cron_issue(row, privilege.is_some()));
            }
        }
        let process_rows = parse_process_rows(raw.proc_rows, &mut truncated);

        // --- deep-compromise sections (v2) ----------------------------------
        if let Some(preload) = parse_preload_section(raw.preload, &mut truncated) {
            issues.push(ld_preload_issue(&preload, privilege.is_some()));
        }
        let path_rows = parse_config_lines(raw.pathinj, &mut truncated, &mut gaps);
        for row in &path_rows {
            if let Some(dirs) = classify_path_injection_line(&row.text) {
                issues.push(path_injection_issue(
                    row,
                    &dirs,
                    &hijack_rows,
                    privilege.is_some(),
                ));
            }
        }
        let authkey_rows = parse_config_lines(raw.authkeys, &mut truncated, &mut gaps);
        let mut authkey_hits: Vec<(&ConfigLine, Option<String>)> = Vec::new();
        for row in &authkey_rows {
            if let Some(command_path) = classify_authkey_line(&row.text) {
                authkey_hits.push((row, command_path));
            }
        }
        let pam_rows = parse_config_lines(raw.pam, &mut truncated, &mut gaps);
        for row in &pam_rows {
            if is_pam_permit_line(&row.text) {
                issues.push(pam_backdoor_issue(row, privilege.is_some()));
            }
        }
        let listen_rows = parse_listen_rows(raw.listen, &mut truncated);
        for listener in &listen_rows {
            if let Some(issue) = bind_listener_issue(listener, &process_rows, privilege.is_some()) {
                issues.push(issue);
            }
        }
        let web_rows = parse_web_rows(raw.web, &mut truncated);
        for row in &web_rows {
            if let Some(issue) = web_file_issue(row, privilege.is_some()) {
                issues.push(issue);
            }
        }
        let hook_rows = parse_config_lines(raw.hook, &mut truncated, &mut gaps);
        let mut recorder_hits: Vec<(&ConfigLine, Option<String>)> = Vec::new();
        for row in &hook_rows {
            if let Some(log_path) = classify_recorder_hook_line(&row.text) {
                recorder_hits.push((row, log_path));
            }
        }
        let history_rows = parse_config_lines(raw.hist, &mut truncated, &mut gaps);
        for row in &history_rows {
            if history_line_leaks_credential(&row.text) {
                issues.push(history_issue(row, privilege.is_some()));
            }
        }
        // Live sessions still carrying hooks in memory: deleting the startup
        // file does not stop an already logged-in tree (shell, exec'd
        // children, …) from re-creating the recorder log, so these sessions
        // must end before the on-disk fix can stick. Processes sharing the
        // same hooked environment form one cluster = one login session.
        for cluster in cluster_session_env(parse_session_env_rows(raw.environ, &mut truncated)) {
            issues.push(session_env_issue(&cluster, privilege.is_some()));
        }
        if privilege.is_none() {
            gaps.push(
                "未提权：其他用户会话的 /proc 环境与内存映射不可读，会话驻留钩子与恶意库驻留进程检测仅覆盖当前用户"
                    .to_owned(),
            );
        }
        for cluster in cluster_resident_libs(parse_resident_lib_rows(raw.maps, &mut truncated)) {
            issues.push(resident_lib_issue(&cluster));
        }
        // Hidden stash directories are derived from evidence that names them:
        // suspicious cron lines and suspicious process command lines. A hidden
        // directory nothing references is not reported on its own.
        let mut stash_refs: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for row in &cron_rows {
            if !is_suspicious_cron_line(&row.text) {
                continue;
            }
            for token in row.text.split_whitespace() {
                if let Some(dir) = hidden_dir_ancestor(token) {
                    stash_refs
                        .entry(dir)
                        .or_default()
                        .push(format!("{}:{}", row.file, row.line));
                }
            }
        }
        for row in &process_rows {
            if row.cmdline.contains(SELF_MARKER) {
                continue;
            }
            for token in row
                .cmdline
                .split_whitespace()
                .chain(std::iter::once(row.exe.trim_end_matches(" (deleted)")))
            {
                if let Some(dir) = hidden_dir_ancestor(token) {
                    stash_refs
                        .entry(dir)
                        .or_default()
                        .push(format!("进程 PID {} 引用", row.pid));
                }
            }
        }
        for (dir, refs) in &stash_refs {
            issues.push(stash_dir_issue(dir, refs, privilege.is_some()));
        }

        for cluster in cluster_backdoor_processes(process_rows) {
            issues.push(backdoor_issue(cluster, privilege.is_some()));
        }

        // Secondary bodies (recorder log files, forced-command scripts) need
        // scan-time fingerprints so their fixes can re-check before deleting.
        // One bounded follow-up probe covers all of them.
        let mut tracked_paths: Vec<String> = Vec::new();
        for (_, command_path) in &authkey_hits {
            if let Some(path) = command_path {
                tracked_paths.push(path.clone());
            }
        }
        for (_, log_path) in recorder_hits.iter() {
            if let Some(path) = log_path {
                tracked_paths.push(path.clone());
            }
        }
        tracked_paths.retain(|path| is_allowed_response_path(path));
        tracked_paths.sort();
        tracked_paths.dedup();
        tracked_paths.truncate(MAX_LINKED_PATHS);
        let mut fingerprints: BTreeMap<String, (String, StatFingerprint)> = BTreeMap::new();
        if !tracked_paths.is_empty() {
            report(SCAN_STAGE_LINKED);
        }
        if privilege.is_some() && !tracked_paths.is_empty() {
            let fp_script = tracked_fingerprint_script(&tracked_paths);
            let fp_output = match &privilege {
                Some(privilege) => {
                    self.run_privileged(
                        session,
                        privilege,
                        &fp_script,
                        "response tracked fingerprint probe",
                        SCAN_TIMEOUT,
                    )
                    .await?
                }
                None => unreachable!("privilege checked above"),
            };
            fingerprints = parse_tracked_fingerprints(&fp_output);
        }
        for (row, command_path) in &authkey_hits {
            let fingerprint = command_path
                .as_ref()
                .and_then(|path| fingerprints.get(path).cloned());
            issues.push(authkey_issue(
                row,
                command_path,
                fingerprint,
                privilege.is_some(),
            ));
        }
        for (row, log_path) in &recorder_hits {
            issues.push(recorder_issue(
                row,
                log_path.as_deref(),
                log_path
                    .as_deref()
                    .and_then(|path| fingerprints.get(path).cloned()),
                privilege.is_some(),
            ));
        }

        // The shadow line only names the account; uid/home come from a bounded
        // follow-up lookup so the fix object is complete.
        let mut empty_accounts: BTreeMap<String, (u32, String)> = BTreeMap::new();
        let lookup_names: Vec<String> = empty_names
            .iter()
            .take(MAX_EMPTY_PASSWORD_ACCOUNTS)
            .filter(|name| is_valid_username(name))
            .cloned()
            .collect();
        if !lookup_names.is_empty() {
            report(SCAN_STAGE_ACCOUNTS);
            let lookup_script = account_lookup_script(&lookup_names);
            let lookup = match &privilege {
                Some(privilege) => {
                    self.run_privileged(
                        session,
                        privilege,
                        &lookup_script,
                        "response account lookup",
                        SCAN_TIMEOUT,
                    )
                    .await?
                }
                None => {
                    self.run_command(
                        session,
                        lookup_script,
                        "response account lookup",
                        SCAN_TIMEOUT,
                    )
                    .await?
                }
            };
            for (name, uid, home) in parse_account_lookup(&lookup) {
                empty_accounts.insert(name, (uid, home));
            }
        }
        for name in empty_names {
            issues.push(empty_password_issue(
                &name,
                empty_accounts.get(&name).cloned(),
                privilege.is_some(),
            ));
        }
        // A closed kind selection narrows the report to the categories the
        // operator asked for; detectors still ran in full.
        if let Some(kinds) = kinds {
            issues.retain(|issue| kinds.contains(&issue.kind));
        }
        // "先修眼睛": severity first, then the fixed kind order, so the
        // ld.so.preload / PATH-injection / hijacked-command findings that make
        // every other observation untrustworthy always lead the list.
        issues.sort_by_key(|issue| (issue.severity.rank(), issue.kind.sort_rank()));
        self.target.validate(session.target())?;
        Ok(ResponseScan {
            issues,
            truncated,
            gaps,
        })
    }

    /// Build an immutable fix plan for one scanned issue. Re-validates the
    /// object, re-reads its live fingerprint, and refuses to plan when the
    /// object changed since the scan (TOCTOU guard). `mode` selects how an
    /// empty-password account is fixed; every other kind accepts only the
    /// default.
    pub async fn plan_fix(
        &self,
        session: &BoundSshSession,
        issue: &ResponseIssue,
        mode: FixMode,
    ) -> CoreResult<ResponseFixPlan> {
        self.target.validate(session.target())?;
        issue.object.validate(issue.kind)?;
        if mode != FixMode::Lock && issue.kind != ResponseIssueKind::EmptyPassword {
            return Err(CoreError::validation(
                "response fix mode",
                format!("{} 类问题不支持该修复方式", issue.kind.label()),
            ));
        }
        let privilege = self.probe_privilege(session).await?.ok_or_else(|| {
            CoreError::validation(
                "response fix privilege",
                "需要 root 或 sudo 权限（免密或可用连接口令）才能执行修复",
            )
        })?;
        let archive_dir = format!(
            "{ARCHIVE_ROOT}/{}-{}",
            Utc::now().format("%Y%m%dT%H%M%SZ"),
            issue.kind.slug()
        );
        let mut step_labels = Vec::new();
        let mut step_scripts = Vec::new();
        let summary: String;
        let restore_description: Option<String>;
        let mut restore_script = None;
        let mut cross_period_verify_delay = None;
        // Kinds whose verification needs plan-time state (e.g. the business
        // page was 200 before a web fix) build their verify script here
        // instead of in `verify_script_for`.
        let mut verify_override: Option<String> = None;

        match &issue.object {
            IssueObject::Path { path, sha256, stat }
                if issue.kind == ResponseIssueKind::HijackedCommand =>
            {
                let observed = self
                    .probe_path_fingerprint(session, &privilege, path)
                    .await?;
                ensure_path_fingerprint(path, sha256, *stat, &observed)?;
                summary = format!("归档后删除被劫持的命令 {path}，并复核 PATH 解析回到系统位置");
                step_labels.push(format!("归档并删除 {path}"));
                step_scripts.push(hijacked_command_fix_script(
                    path,
                    sha256,
                    *stat,
                    &archive_dir,
                ));
                restore_description = Some(format!("从远端归档 {archive_dir} 恢复 {path}"));
                restore_script = Some(file_restore_script(&archive_dir, path));
            }
            IssueObject::Path { path, sha256, stat }
                if matches!(
                    issue.kind,
                    ResponseIssueKind::WebSensitiveFile | ResponseIssueKind::Webshell
                ) =>
            {
                let observed = self
                    .probe_path_fingerprint(session, &privilege, path)
                    .await?;
                ensure_path_fingerprint(path, sha256, *stat, &observed)?;
                // The business page must still answer 200 after the fix; the
                // pre-fix observation is frozen into the verify script so a
                // fix can never silently kill the site.
                let business_ok = self.probe_business_ok(session, &privilege).await?;
                // A webshell alone in a hidden upload directory takes the whole
                // directory with it; in a shared directory only the file goes.
                let mut delete_dir: Option<String> = None;
                if issue.kind == ResponseIssueKind::Webshell
                    && let Some((parent, _)) = path.rsplit_once('/')
                {
                    let hidden = parent
                        .rsplit('/')
                        .next()
                        .is_some_and(|name| name.len() >= 2 && name.starts_with('.'));
                    if hidden && is_allowed_response_path(parent) {
                        match self
                            .probe_dir_regular_files(session, &privilege, parent)
                            .await?
                        {
                            Some(files) if files.iter().all(|file| file == path) => {
                                delete_dir = Some(parent.to_owned());
                            }
                            _ => {}
                        }
                    }
                }
                summary = match &delete_dir {
                    Some(dir) => format!(
                        "归档后删除纯恶意隐藏目录 {dir}（含 WebShell {path}），复验业务首页保持 200"
                    ),
                    None => {
                        format!("归档后删除 {path}，复验文件不存在且业务首页保持 200")
                    }
                };
                step_labels.push(match &delete_dir {
                    Some(dir) => format!("归档并删除目录 {dir}"),
                    None => format!("归档并删除 {path}"),
                });
                step_scripts.push(web_file_fix_script(
                    path,
                    sha256,
                    *stat,
                    delete_dir.as_deref(),
                    &archive_dir,
                ));
                restore_description = Some(match &delete_dir {
                    Some(dir) => format!("从远端归档 {archive_dir} 恢复目录 {dir}"),
                    None => format!("从远端归档 {archive_dir} 恢复 {path}"),
                });
                restore_script = Some(match &delete_dir {
                    Some(dir) => dir_restore_script(&archive_dir, dir),
                    None => file_restore_script(&archive_dir, path),
                });
                verify_override = Some(web_verify_script(path, delete_dir.as_deref(), business_ok));
            }
            IssueObject::Account {
                username,
                uid,
                home,
            } if matches!(
                issue.kind,
                ResponseIssueKind::UidZeroAccount | ResponseIssueKind::SuspiciousAccount
            ) =>
            {
                let observed = self
                    .probe_passwd_account(session, &privilege, username)
                    .await?;
                if observed != Some((*uid, home.clone())) {
                    return Err(CoreError::validation(
                        "response fix recheck",
                        format!("账户 {username} 的 uid/家目录在扫描后发生变化，已拒绝修复"),
                    ));
                }
                let remove_home = home_is_user_owned_location(home);
                let account_label = if issue.kind == ResponseIssueKind::UidZeroAccount {
                    "影子账户"
                } else {
                    "可疑登录账户"
                };
                summary = if remove_home {
                    format!("归档账户数据后删除{account_label} {username} 及其家目录 {home}")
                } else {
                    format!(
                        "归档账户数据后删除{account_label} {username}；家目录 {home} 属于系统位置，仅删除账户不删目录"
                    )
                };
                step_labels.push(format!("删除账户 {username}"));
                step_scripts.push(account_removal_fix_script(
                    issue.kind,
                    username,
                    remove_home,
                    home,
                    &archive_dir,
                )?);
                restore_description = None;
            }
            IssueObject::Account { username, home, .. } => {
                let still_empty = self
                    .probe_shadow_empty(session, &privilege, username)
                    .await?;
                if !still_empty {
                    return Err(CoreError::validation(
                        "response fix recheck",
                        format!("账户 {username} 的口令字段在扫描后已非空，已拒绝修复"),
                    ));
                }
                match mode {
                    FixMode::Lock => {
                        summary = format!(
                            "归档 /etc/shadow 后锁定账户 {username} 的口令（passwd -l，不删除账户）"
                        );
                        step_labels.push(format!("锁定账户 {username} 的口令"));
                        step_scripts.push(empty_password_fix_script(username, &archive_dir));
                        restore_description =
                            Some(format!("从远端归档 {archive_dir} 恢复 /etc/shadow"));
                        restore_script = Some(file_restore_script(&archive_dir, "/etc/shadow"));
                    }
                    FixMode::Remove => {
                        let remove_home = home_is_user_owned_location(home);
                        summary = if remove_home {
                            format!(
                                "归档账户数据后删除空口令账户 {username} 及其家目录 {home}（从 /etc/passwd 与 /etc/shadow 移除）"
                            )
                        } else {
                            format!(
                                "归档账户数据后删除空口令账户 {username}（从 /etc/passwd 与 /etc/shadow 移除；家目录 {home} 保留）"
                            )
                        };
                        step_labels.push(format!("删除账户 {username}"));
                        step_scripts.push(account_removal_fix_script(
                            issue.kind,
                            username,
                            remove_home,
                            home,
                            &archive_dir,
                        )?);
                        restore_description = None;
                    }
                }
            }
            IssueObject::SudoersRule {
                file,
                line,
                line_sha256,
            } => {
                self.ensure_line_unchanged(session, &privilege, file, *line, line_sha256)
                    .await?;
                let effective = self
                    .count_effective_lines(session, &privilege, file)
                    .await?;
                let delete_file = file.starts_with("/etc/sudoers.d/") && effective == 1;
                summary = if delete_file {
                    format!("归档后删除恶意 sudoers 文件 {file}，visudo -c 校验失败时自动回滚")
                } else {
                    format!(
                        "归档后删除 {file} 第 {line} 行的恶意授权，visudo -c 校验失败时自动回滚"
                    )
                };
                step_labels.push(summary.clone());
                step_scripts.push(sudoers_fix_script(
                    file,
                    *line,
                    line_sha256,
                    delete_file,
                    &archive_dir,
                ));
                restore_description = Some(format!("从远端归档 {archive_dir} 恢复 {file}"));
                restore_script = Some(file_restore_script(&archive_dir, file));
            }
            IssueObject::CronEntry {
                file,
                line,
                line_sha256,
            } => {
                self.ensure_line_unchanged(session, &privilege, file, *line, line_sha256)
                    .await?;
                let effective = self
                    .count_effective_lines(session, &privilege, file)
                    .await?;
                let delete_file = file.starts_with("/etc/cron.d/") && effective == 1;
                summary = if delete_file {
                    format!("归档后删除恶意 cron 文件 {file}")
                } else {
                    format!("归档后按行号与行摘要双复核删除 {file} 第 {line} 行")
                };
                step_labels.push(summary.clone());
                step_scripts.push(cron_fix_script(
                    file,
                    *line,
                    line_sha256,
                    delete_file,
                    &archive_dir,
                ));
                restore_description = Some(format!("从远端归档 {archive_dir} 恢复 {file}"));
                restore_script = Some(file_restore_script(&archive_dir, file));
            }
            IssueObject::Process {
                pids,
                exe_path,
                listen_port,
            } => {
                let body_present = self
                    .ensure_process_unchanged(session, &privilege, pids, exe_path)
                    .await?;
                // Locked order: cut any cron keep-alive channel that references
                // the body first, then remove the body, then kill the pids.
                // A body already removed by a sibling fix (e.g. the stash-dir
                // sweep) skips the archive/delete step — the processes still
                // run from the deleted file and killing them is the point.
                let cascaded = self
                    .find_cron_channels(session, &privilege, exe_path)
                    .await?
                    .into_iter()
                    .take(MAX_CASCADE_CRON_STEPS)
                    .collect::<Vec<_>>();
                let listener_note = match listen_port {
                    Some(port) => format!("（监听端口 {port}，复验要求端口关闭）"),
                    None => String::new(),
                };
                match (body_present, cascaded.is_empty()) {
                    (true, true) => {
                        summary = format!(
                            "归档后删除后门本体 {exe_path}，按 /proc 复核后终止 {} 个进程{listener_note}",
                            pids.len()
                        );
                    }
                    (true, false) => {
                        summary = format!(
                            "先级联清除 {} 条引用 {exe_path} 的 cron 保活项，再删除本体并终止 {} 个进程{listener_note}",
                            cascaded.len(),
                            pids.len()
                        );
                    }
                    (false, _) => {
                        summary = format!(
                            "本体 {exe_path} 已被其他修复删除：仅按 /proc 复核后终止仍在运行的 {} 个进程{listener_note}",
                            pids.len()
                        );
                    }
                }
                for entry in &cascaded {
                    entry.validate()?;
                    step_labels.push(format!(
                        "清除 cron 保活项 {} 第 {} 行",
                        entry.file, entry.line
                    ));
                    step_scripts.push(cron_fix_script(
                        &entry.file,
                        entry.line,
                        &entry.line_sha256,
                        entry.delete_file,
                        &archive_dir,
                    ));
                }
                if body_present {
                    step_labels.push(format!("归档并删除后门本体 {exe_path}"));
                    step_scripts.push(backdoor_body_fix_script(exe_path, &archive_dir));
                }
                step_labels.push(format!("按 /proc 复核后终止 {} 个后门进程", pids.len()));
                step_scripts.push(backdoor_kill_script(pids, exe_path));
                cross_period_verify_delay = Some(CROSS_PERIOD_VERIFY_DELAY);
                if body_present {
                    restore_description = Some(format!(
                        "从远端归档 {archive_dir} 恢复 {exe_path}（进程不会自动重启）"
                    ));
                    restore_script = Some(file_restore_script(&archive_dir, exe_path));
                } else {
                    restore_description =
                        Some("被终止的进程不会自动重启；本体文件已由其他修复删除".to_owned());
                }
            }
            IssueObject::LdPreload {
                file,
                sha256,
                stat,
                libs,
            } => {
                let observed = self
                    .probe_path_fingerprint(session, &privilege, file)
                    .await?;
                ensure_path_fingerprint(file, sha256, *stat, &observed)?;
                for lib in libs {
                    // A library that vanished since the scan needs no fix; one
                    // that changed aborts the whole plan.
                    if let Some(observed) = self
                        .probe_path_fingerprint_opt(session, &privilege, &lib.path)
                        .await?
                    {
                        ensure_path_fingerprint(&lib.path, &lib.sha256, lib.stat, &observed)?;
                    }
                }
                summary = format!(
                    "归档后删除 {file} 及其引用的 {} 个动态库，解除 readdir 级输出劫持",
                    libs.len()
                );
                step_labels.push(format!("归档并删除 {file} 与 {} 个注入库", libs.len()));
                step_scripts.push(ld_preload_fix_script(
                    file,
                    sha256,
                    *stat,
                    libs,
                    &archive_dir,
                ));
                restore_description =
                    Some(format!("从远端归档 {archive_dir} 恢复 {file} 与注入库"));
                restore_script = Some(ld_preload_restore_script(&archive_dir, file, libs));
            }
            IssueObject::StartupLine {
                file,
                line,
                line_sha256,
                linked_fakes,
                ..
            } => {
                self.ensure_line_unchanged(session, &privilege, file, *line, line_sha256)
                    .await?;
                let effective = self
                    .count_effective_lines(session, &privilege, file)
                    .await?;
                let delete_file = file.starts_with("/etc/profile.d/") && effective == 1;
                summary = if delete_file {
                    format!(
                        "归档后删除整文件可疑的 PATH 注入文件 {file}，并连带删除注入目录中的伪命令"
                    )
                } else {
                    format!(
                        "归档后删除 {file} 第 {line} 行的 PATH 注入，并连带删除注入目录中的伪命令"
                    )
                };
                step_labels.push(if delete_file {
                    format!("归档并删除 {file}")
                } else {
                    format!("归档后按行号与行摘要双复核删除 {file} 第 {line} 行")
                });
                step_scripts.push(cron_fix_script(
                    file,
                    *line,
                    line_sha256,
                    delete_file,
                    &archive_dir,
                ));
                if !linked_fakes.is_empty() {
                    step_labels.push(format!("连带删除 {} 个伪命令", linked_fakes.len()));
                    step_scripts.push(fake_cleanup_fix_script(linked_fakes, &archive_dir));
                }
                restore_description = Some(format!("从远端归档 {archive_dir} 恢复 {file}"));
                restore_script = Some(file_restore_script(&archive_dir, file));
                verify_override = Some(startup_line_verify_script(
                    file,
                    line_sha256,
                    delete_file,
                    linked_fakes,
                ));
            }
            IssueObject::AuthKeyEntry {
                file,
                line,
                line_sha256,
                command_path,
            } => {
                self.ensure_line_unchanged(session, &privilege, file, *line, line_sha256)
                    .await?;
                let effective = self
                    .count_effective_lines(session, &privilege, file)
                    .await?;
                let delete_file = effective == 1;
                summary = if delete_file {
                    format!("归档后删除整文件均为后门的 {file}")
                } else {
                    format!("归档后删除 {file} 第 {line} 行的 command= 强制命令条目")
                };
                step_labels.push(if delete_file {
                    format!("归档并删除 {file}")
                } else {
                    format!("归档后按行号与行摘要双复核删除 {file} 第 {line} 行")
                });
                step_scripts.push(cron_fix_script(
                    file,
                    *line,
                    line_sha256,
                    delete_file,
                    &archive_dir,
                ));
                if let Some(command) = command_path {
                    step_labels.push(format!("删除强制命令脚本本体 {}", command.path));
                    step_scripts.push(tracked_delete_fix_script(command, &archive_dir));
                }
                restore_description = Some(format!("从远端归档 {archive_dir} 恢复 {file}"));
                restore_script = Some(file_restore_script(&archive_dir, file));
                verify_override = Some(authkey_verify_script(
                    file,
                    line_sha256,
                    delete_file,
                    command_path.as_ref(),
                ));
            }
            IssueObject::PamLine {
                file,
                line,
                line_sha256,
            } => {
                self.ensure_line_unchanged(session, &privilege, file, *line, line_sha256)
                    .await?;
                summary = format!("归档后删除 {file} 第 {line} 行的 pam_permit 万能密码");
                step_labels.push(summary.clone());
                step_scripts.push(cron_fix_script(
                    file,
                    *line,
                    line_sha256,
                    false,
                    &archive_dir,
                ));
                restore_description = Some(format!("从远端归档 {archive_dir} 恢复 {file}"));
                restore_script = Some(file_restore_script(&archive_dir, file));
                verify_override = Some(pam_verify_script(file));
            }
            IssueObject::StashDir { path } => {
                if !self.probe_dir_present(session, &privilege, path).await? {
                    return Err(CoreError::validation(
                        "response fix recheck",
                        format!("藏匿目录 {path} 在扫描后已不存在，已拒绝修复"),
                    ));
                }
                summary = format!("归档后删除后门藏匿目录 {path} 及其全部内容");
                step_labels.push(format!("归档并删除目录 {path}"));
                step_scripts.push(stash_dir_fix_script(path, &archive_dir));
                restore_description = Some(format!("从远端归档 {archive_dir} 恢复目录 {path}"));
                restore_script = Some(dir_restore_script(&archive_dir, path));
            }
            IssueObject::RecorderHook {
                file,
                line,
                line_sha256,
                log,
            } => {
                self.ensure_line_unchanged(session, &privilege, file, *line, line_sha256)
                    .await?;
                let effective = self
                    .count_effective_lines(session, &privilege, file)
                    .await?;
                let delete_file = file.starts_with("/etc/profile.d/") && effective == 1;
                summary = format!(
                    "归档后删除 {file} 中的命令录音钩子{}；注意：若删除后录音文件再次出现，说明仍有旧登录会话的钩子留在内存中，需退出全部 SSH 会话后重验",
                    log.as_ref()
                        .map(|log| format!("，并删除录音文件 {}", log.path))
                        .unwrap_or_default()
                );
                step_labels.push(if delete_file {
                    format!("归档并删除钩子文件 {file}")
                } else {
                    format!("归档后按行号与行摘要双复核删除 {file} 第 {line} 行钩子")
                });
                step_scripts.push(cron_fix_script(
                    file,
                    *line,
                    line_sha256,
                    delete_file,
                    &archive_dir,
                ));
                if let Some(log) = log {
                    step_labels.push(format!("删除录音文件 {}", log.path));
                    step_scripts.push(tracked_delete_fix_script(log, &archive_dir));
                }
                restore_description = Some(format!("从远端归档 {archive_dir} 恢复 {file}"));
                restore_script = Some(file_restore_script(&archive_dir, file));
                verify_override = Some(recorder_verify_script(
                    file,
                    line_sha256,
                    delete_file,
                    log.as_ref().map(|log| log.path.as_str()),
                ));
            }
            IssueObject::HistoryLine {
                file,
                line,
                line_sha256,
            } => {
                self.ensure_line_unchanged(session, &privilege, file, *line, line_sha256)
                    .await?;
                summary =
                    format!("归档 {file} 后删除第 {line} 行的明文密码记录（保留文件其余内容）");
                step_labels.push(summary.clone());
                step_scripts.push(cron_fix_script(
                    file,
                    *line,
                    line_sha256,
                    false,
                    &archive_dir,
                ));
                restore_description = Some(format!("从远端归档 {archive_dir} 恢复 {file}"));
                restore_script = Some(file_restore_script(&archive_dir, file));
            }
            IssueObject::SessionEnv {
                processes,
                signatures,
            } => {
                // Every PID must still exist, resolve to the same binary and
                // still carry the same hook signatures; a recycled or ended
                // PID refuses the plan instead of killing an innocent process.
                self.ensure_session_env_unchanged(session, &privilege, processes, signatures)
                    .await?;
                summary = format!(
                    "按 /proc 逐个复核进程身份后终止 {} 个会话进程（{}）：钩子驻留在该会话树的内存环境里，这是唯一可靠的清除方式",
                    processes.len(),
                    processes
                        .iter()
                        .map(|process| format!("PID {}", process.pid))
                        .collect::<Vec<_>>()
                        .join("、")
                );
                step_labels.push(format!(
                    "复核并终止 {} 个会话进程（TERM→KILL）",
                    processes.len()
                ));
                step_scripts.push(session_env_kill_script(processes));
                // Terminated login sessions cannot be restored; the operator
                // reconnects when needed.
                restore_description = None;
                verify_override = Some(session_env_verify_script(processes, signatures));
            }
            IssueObject::HardeningPermissions { entries } => {
                self.ensure_permissions_unchanged(session, &privilege, entries)
                    .await?;
                summary = format!(
                    "收紧 {} 个认证关键文件（shadow、sudoers、authorized_keys 等）的权限与属主到基线值",
                    entries.len()
                );
                step_labels.push("把原始权限记录到归档目录".to_owned());
                step_scripts.push(permissions_record_script(&archive_dir, entries));
                step_labels.push(format!("chmod/chown 收紧 {} 个文件", entries.len()));
                step_scripts.push(permissions_fix_script(entries));
                restore_description = Some(format!(
                    "按远端归档 {archive_dir}/original-permissions.txt 中记录的原值逐项恢复"
                ));
                restore_script = Some(permissions_restore_script(&archive_dir));
                verify_override = Some(permissions_verify_script(entries));
            }
            IssueObject::HardeningAuditWatch { points } => {
                self.ensure_audit_watch_absent(session, &privilege, points)
                    .await?;
                summary = format!(
                    "为 {} 个入侵篡改热点部署 auditd 实时监控（watch 键 {AUDIT_WATCH_KEY}，账号/计划任务/启动脚本被改动即留审计记录）",
                    points.len()
                );
                step_labels.push(format!("auditctl 添加 {} 条 watch 规则", points.len()));
                step_scripts.push(audit_watch_fix_script(points));
                restore_description = Some(format!(
                    "按相同点位逐条 auditctl -W 撤销（键 {AUDIT_WATCH_KEY}）"
                ));
                restore_script = Some(audit_watch_restore_script(points));
                verify_override = Some(audit_watch_verify_script(points));
            }
            IssueObject::HardeningSnapshot {} => {
                summary = format!(
                    "对认证与后门高发位置的文件建立 sha256 完整性清单（{HARDENING_MANIFEST}），下次加固检查时自动比对漂移"
                );
                step_labels.push("生成关键文件完整性清单（上限 256 项）".to_owned());
                step_scripts.push(snapshot_fix_script());
                restore_description = Some("撤销时删除该清单文件".to_owned());
                restore_script = Some(snapshot_restore_script());
                verify_override = Some(snapshot_verify_script());
            }
            _ => {
                return Err(CoreError::validation(
                    "response issue object",
                    format!("对象类型与问题类别 {} 不匹配", issue.kind.slug()),
                ));
            }
        }

        let mut operation =
            OperationPlan::new(session.target().clone(), summary, true, restore_description)?;
        operation
            .metadata
            .insert("source".to_owned(), "response-engine".to_owned());
        operation
            .metadata
            .insert("issue-kind".to_owned(), issue.kind.slug().to_owned());
        let steps: Vec<FixStep> = step_labels
            .into_iter()
            .zip(step_scripts)
            .map(|(label, script)| FixStep {
                label,
                script: privileged_command(&privilege, &script),
            })
            .collect();
        operation
            .metadata
            .insert("steps-sha256".to_owned(), steps_digest(&steps));
        let raw_verify = match verify_override {
            Some(script) => script,
            None => verify_script_for(issue.kind, &issue.object, mode)?,
        };
        let verify_script = privileged_command(&privilege, &raw_verify);
        Ok(ResponseFixPlan {
            operation,
            issue_kind: issue.kind,
            archive_dir,
            cross_period_verify_delay,
            issue: issue.clone(),
            privilege: privilege.clone(),
            steps,
            verify_script,
            restore_script: restore_script.map(|script| privileged_command(&privilege, &script)),
        })
    }

    /// Confirm and run the synchronous part of a plan, then journal it.
    /// Verification is deliberately separate: for backdoor processes the
    /// caller waits `cross_period_verify_delay` before calling `verify_fix`.
    pub async fn execute_fix(
        &self,
        session: &BoundSshSession,
        plan: ResponseFixPlan,
        confirmation: DangerousConfirmation,
        journal: &PortableOperationJournal,
    ) -> CoreResult<ResponseFixExecution> {
        self.target.validate(session.target())?;
        if plan.operation.target != *session.target() {
            return Err(CoreError::validation(
                "response fix target",
                "plan is not bound to this SSH target epoch",
            ));
        }
        let mut operation = PlannedOperation::plan(plan.operation.clone());
        operation.confirm(confirmation)?;
        let executor = ResponseFixExecutor {
            service: self,
            session,
            plan: &plan,
        };
        if let Err(error) = operation.execute(&self.target, &executor).await {
            if operation.state() == crate::operations::OperationState::StaleAfterExecution {
                operation.journal(journal)?;
            }
            return Err(error);
        }
        operation.journal(journal)?;
        Ok(ResponseFixExecution {
            operation_id: plan.operation.id.clone(),
            summary: plan.operation.summary.clone(),
            archive_dir: plan.archive_dir.clone(),
            cross_period_verify_delay: plan.cross_period_verify_delay,
            operation,
            plan,
        })
    }

    /// Re-check the target after a fix and journal the outcome. Callers run
    /// this after `cross_period_verify_delay` (immediately for other kinds).
    pub async fn verify_fix(
        &self,
        session: &BoundSshSession,
        mut execution: ResponseFixExecution,
        journal: &PortableOperationJournal,
    ) -> CoreResult<ResponseFixVerification> {
        self.target.validate(session.target())?;
        let executor = ResponseFixExecutor {
            service: self,
            session,
            plan: &execution.plan,
        };
        let verification = execution
            .operation
            .verify(&self.target, &executor, journal)
            .await?;
        Ok(ResponseFixVerification {
            operation_id: execution.plan.operation.id.clone(),
            verification,
        })
    }

    async fn run_command(
        &self,
        session: &BoundSshSession,
        command: String,
        subject: &'static str,
        timeout: Duration,
    ) -> CoreResult<String> {
        let output = self.ssh.execute_bound(session, command, timeout).await?;
        successful_output(subject, output)
    }

    async fn probe_privilege(&self, session: &BoundSshSession) -> CoreResult<Option<Privilege>> {
        let output = self
            .run_command(
                session,
                "id -u".to_owned(),
                "probe remote user identity",
                SCAN_TIMEOUT,
            )
            .await?;
        match output.trim() {
            "0" => return Ok(Some(Privilege::Root)),
            value if value.bytes().all(|byte| byte.is_ascii_digit()) => {}
            _ => {
                return Err(CoreError::validation(
                    "remote user identity",
                    "id -u returned an invalid value",
                ));
            }
        }
        let answer = self
            .run_command(
                session,
                "sudo -n true >/dev/null 2>&1 && echo yes || echo no".to_owned(),
                "probe passwordless sudo",
                SCAN_TIMEOUT,
            )
            .await?;
        if answer.trim() == "yes" {
            return Ok(Some(Privilege::SudoNoPassword));
        }
        // Password sudo: the stored connection password rides the sensitive
        // channel's stdin. A missing or rejected password degrades the scan
        // instead of failing it.
        let Some(password) = self.ssh.bound_session_password(session)? else {
            return Ok(None);
        };
        let privilege = Privilege::SudoWithPassword(Arc::new(password));
        let checked = self
            .run_privileged(
                session,
                &privilege,
                "/usr/bin/id -u",
                "probe password sudo",
                SCAN_TIMEOUT,
            )
            .await;
        match checked {
            Ok(output) if output.trim() == "0" => Ok(Some(privilege)),
            _ => Ok(None),
        }
    }

    /// The login name the session authenticated with, so the suspicious-account
    /// detector can exclude the operator's own account. `id -un` runs
    /// unprivileged; an unparsable answer degrades to `None` plus a gaps entry.
    async fn probe_session_username(
        &self,
        session: &BoundSshSession,
    ) -> CoreResult<Option<String>> {
        let output = self
            .run_command(
                session,
                "id -un".to_owned(),
                "probe session username",
                SCAN_TIMEOUT,
            )
            .await?;
        let name = output.trim();
        Ok(is_valid_username(name).then(|| name.to_owned()))
    }

    /// Run a raw script under the session's privilege. For password sudo the
    /// command text is the `sudo -S` wrapper (no secret in it) and the
    /// password is piped through the sensitive channel's stdin.
    async fn run_privileged(
        &self,
        session: &BoundSshSession,
        privilege: &Privilege,
        script: &str,
        subject: &'static str,
        timeout: Duration,
    ) -> CoreResult<String> {
        self.run_wrapped(
            session,
            privilege,
            privileged_command(privilege, script),
            subject,
            timeout,
        )
        .await
    }

    /// Run command text that is already privilege-wrapped.
    async fn run_wrapped(
        &self,
        session: &BoundSshSession,
        privilege: &Privilege,
        command: String,
        subject: &'static str,
        timeout: Duration,
    ) -> CoreResult<String> {
        if let Privilege::SudoWithPassword(password) = privilege {
            let limits =
                SshSensitiveCommandLimits::new(MAX_SCAN_OUTPUT_BYTES, MAX_SENSITIVE_STDERR_BYTES)?;
            let mut stdin = password.expose().as_bytes().to_vec();
            stdin.push(b'\n');
            let output = self
                .ssh
                .execute_bound_sensitive(
                    session,
                    Zeroizing::new(command),
                    Zeroizing::new(stdin),
                    timeout,
                    limits,
                )
                .await?;
            return sensitive_output(subject, output);
        }
        self.run_command(session, command, subject, timeout).await
    }

    /// Recheck probes read root-only files (`/etc/shadow`, sudoers), so they
    /// run under the same privilege wrapper as the fix itself.
    async fn run_probe(
        &self,
        session: &BoundSshSession,
        privilege: &Privilege,
        script: &str,
        subject: &'static str,
    ) -> CoreResult<String> {
        self.run_privileged(session, privilege, script, subject, SCAN_TIMEOUT)
            .await
    }

    async fn probe_path_fingerprint(
        &self,
        session: &BoundSshSession,
        privilege: &Privilege,
        path: &str,
    ) -> CoreResult<(String, StatFingerprint)> {
        let script = format!(
            "set -eu; [ -f {path} ] && [ ! -L {path} ]; sum=$(/usr/bin/sha256sum -- {path} | /usr/bin/awk '{{print $1}}'); fp=$(/usr/bin/stat -c '%a|%u|%g|%s|%Y' -- {path}); /usr/bin/printf '%s\\t%s\\n' \"$sum\" \"$fp\"",
            path = shq(path),
        );
        let output = self
            .run_probe(session, privilege, &script, "response fingerprint probe")
            .await?;
        let line = output.lines().next().unwrap_or_default();
        let (sha256, stat) = line.split_once('\t').ok_or_else(|| {
            CoreError::validation("response fingerprint probe", "unexpected probe output")
        })?;
        let stat = StatFingerprint::parse(stat).ok_or_else(|| {
            CoreError::validation("response fingerprint probe", "unexpected stat fingerprint")
        })?;
        Ok((sha256.to_owned(), stat))
    }

    /// Same fingerprint probe, but a path that vanished since the scan is not
    /// an error: it simply needs no fix. A *changed* path is still caught by
    /// the caller's `ensure_path_fingerprint`.
    async fn probe_path_fingerprint_opt(
        &self,
        session: &BoundSshSession,
        privilege: &Privilege,
        path: &str,
    ) -> CoreResult<Option<(String, StatFingerprint)>> {
        let script = format!(
            "if [ -f {path} ] && [ ! -L {path} ]; then\n  sum=$(/usr/bin/sha256sum -- {path} | /usr/bin/awk '{{print $1}}')\n  fp=$(/usr/bin/stat -c '%a|%u|%g|%s|%Y' -- {path})\n  /usr/bin/printf '%s\\t%s\\n' \"$sum\" \"$fp\"\nfi\n",
            path = shq(path),
        );
        let output = self
            .run_probe(session, privilege, &script, "response fingerprint probe")
            .await?;
        let Some(line) = output.lines().next() else {
            return Ok(None);
        };
        if line.is_empty() {
            return Ok(None);
        }
        let (sha256, stat) = line.split_once('\t').ok_or_else(|| {
            CoreError::validation("response fingerprint probe", "unexpected probe output")
        })?;
        let stat = StatFingerprint::parse(stat).ok_or_else(|| {
            CoreError::validation("response fingerprint probe", "unexpected stat fingerprint")
        })?;
        Ok(Some((sha256.to_owned(), stat)))
    }

    /// Snapshot of the business front page before a web fix: `Some(true)` when
    /// `http://127.0.0.1/` answered 200 (the verify script then demands it
    /// still does), `Some(false)` when it answered anything else, `None` when
    /// the target has no python3 and the check must be skipped.
    async fn probe_business_ok(
        &self,
        session: &BoundSshSession,
        privilege: &Privilege,
    ) -> CoreResult<Option<bool>> {
        let script = "if [ -x /usr/bin/python3 ]; then\n  /usr/bin/python3 -c 'import urllib.request;print(\"BUSINESS_OK\" if urllib.request.urlopen(\"http://127.0.0.1/\",timeout=5).status==200 else \"BUSINESS_FAIL\")' 2>/dev/null || /usr/bin/printf 'BUSINESS_FAIL\\n'\nelse\n  /usr/bin/printf 'BUSINESS_UNKNOWN\\n'\nfi\n";
        let output = self
            .run_probe(session, privilege, script, "response business probe")
            .await?;
        Ok(match output.lines().next() {
            Some("BUSINESS_OK") => Some(true),
            Some("BUSINESS_FAIL") => Some(false),
            _ => None,
        })
    }

    /// Regular files directly inside `dir`, enumerated through the getdents64
    /// walker so an LD_PRELOAD `readdir` hook cannot hide entries. `None` when
    /// the target lacks python3 (callers then fall back to file-only fixes).
    async fn probe_dir_regular_files(
        &self,
        session: &BoundSshSession,
        privilege: &Privilege,
        dir: &str,
    ) -> CoreResult<Option<Vec<String>>> {
        let script = format!(
            "if [ -x /usr/bin/python3 ]; then\n{pywalk}\n  hawk_walk {dir} 0\nelse\n  /usr/bin/printf 'NOPY\\n'\nfi\n",
            pywalk = PYWALK_FUNCTION,
            dir = shq(dir),
        );
        let output = self
            .run_probe(session, privilege, &script, "response dir listing probe")
            .await?;
        if output.lines().next() == Some("NOPY") {
            return Ok(None);
        }
        let mut files = Vec::new();
        for line in output.lines() {
            if let Some(path) = line.strip_prefix("F\t") {
                if files.len() >= 256 {
                    break;
                }
                files.push(path.to_owned());
            }
        }
        Ok(Some(files))
    }

    async fn probe_dir_present(
        &self,
        session: &BoundSshSession,
        privilege: &Privilege,
        dir: &str,
    ) -> CoreResult<bool> {
        let script = format!(
            "if [ -d {dir} ]; then /usr/bin/printf 'PRESENT\\n'; else /usr/bin/printf 'ABSENT\\n'; fi\n",
            dir = shq(dir),
        );
        let output = self
            .run_probe(session, privilege, &script, "response dir probe")
            .await?;
        Ok(output.lines().next() == Some("PRESENT"))
    }

    async fn probe_passwd_account(
        &self,
        session: &BoundSshSession,
        privilege: &Privilege,
        username: &str,
    ) -> CoreResult<Option<(u32, String)>> {
        let script = format!(
            "/usr/bin/awk -F: -v u={user} '$1==u {{printf \"%s\\t%s\\n\",$3,$6}}' /etc/passwd",
            user = shq(username),
        );
        let output = self
            .run_probe(session, privilege, &script, "response account recheck")
            .await?;
        let Some(line) = output.lines().next() else {
            return Ok(None);
        };
        let Some((uid, home)) = line.split_once('\t') else {
            return Ok(None);
        };
        Ok(uid.parse::<u32>().ok().map(|uid| (uid, home.to_owned())))
    }

    async fn probe_shadow_empty(
        &self,
        session: &BoundSshSession,
        privilege: &Privilege,
        username: &str,
    ) -> CoreResult<bool> {
        let script = format!(
            "/usr/bin/awk -F: -v u={user} '$1==u {{print ($2==\"\" ? \"empty\" : \"set\")}}' /etc/shadow",
            user = shq(username),
        );
        let output = self
            .run_probe(session, privilege, &script, "response shadow recheck")
            .await?;
        Ok(output.lines().next() == Some("empty"))
    }

    async fn ensure_line_unchanged(
        &self,
        session: &BoundSshSession,
        privilege: &Privilege,
        file: &str,
        line: u32,
        line_sha256: &str,
    ) -> CoreResult<()> {
        let script = format!(
            "set -eu; [ -f {file} ] && [ ! -L {file} ]; /usr/bin/sed -n '{line}p' -- {file} | /usr/bin/sha256sum | /usr/bin/awk '{{print $1}}'",
            file = shq(file),
            line = line,
        );
        let output = self
            .run_probe(session, privilege, &script, "response line recheck")
            .await?;
        ensure_line_digest(line_sha256, output.lines().next().unwrap_or_default(), file)
    }

    async fn count_effective_lines(
        &self,
        session: &BoundSshSession,
        privilege: &Privilege,
        file: &str,
    ) -> CoreResult<u32> {
        let script = format!(
            "/usr/bin/grep -cv '^[[:space:]]*\\(#\\|$\\)' -- {file} 2>/dev/null || printf '0\\n'",
            file = shq(file),
        );
        let output = self
            .run_probe(session, privilege, &script, "response line count")
            .await?;
        output
            .lines()
            .next()
            .and_then(|line| line.trim().parse::<u32>().ok())
            .ok_or_else(|| CoreError::validation("response line count", "unexpected count output"))
    }

    /// Returns whether the body file still exists. A body removed by a
    /// sibling fix (e.g. the stash-dir sweep) must NOT abort the plan — the
    /// processes keep running from the deleted file and killing them is
    /// exactly what is still missing; only changed PIDs refuse the plan.
    async fn ensure_process_unchanged(
        &self,
        session: &BoundSshSession,
        privilege: &Privilege,
        pids: &[u32],
        exe_path: &str,
    ) -> CoreResult<bool> {
        let pid_list = pids
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(" ");
        let script = format!(
            "# {SELF_MARKER}\n[ -f {exe} ] || {{ printf 'BODY_GONE\\n'; exit 0; }}\nfor pid in {pids}; do\n  if [ -d \"/proc/$pid\" ]; then\n    cmd=$(/usr/bin/tr '\\0\\n' '  ' < \"/proc/$pid/cmdline\" 2>/dev/null || true)\n    case \"$cmd\" in\n      *{SELF_MARKER}*) ;;\n      *{exe}*) ;;\n      *) printf 'PID_CHANGED\\n'; exit 0 ;;\n    esac\n  fi\ndone\nprintf 'RECHECK_OK\\n'",
            exe = shq(exe_path),
            pids = pid_list,
        );
        let output = self
            .run_probe(session, privilege, &script, "response process recheck")
            .await?;
        match output.lines().next() {
            Some("RECHECK_OK") => Ok(true),
            Some("BODY_GONE") => Ok(false),
            _ => Err(CoreError::validation(
                "response process recheck",
                "进程命令行在扫描后发生变化，已拒绝修复",
            )),
        }
    }

    /// Re-run the cron detector and keep only suspicious entries whose line
    /// references the backdoor body; those keep-alive channels must be cut
    /// before the process fix runs.
    async fn find_cron_channels(
        &self,
        session: &BoundSshSession,
        privilege: &Privilege,
        exe_path: &str,
    ) -> CoreResult<Vec<CascadedCron>> {
        let output = self
            .run_probe(
                session,
                privilege,
                &cron_scan_script(),
                "response cron cascade scan",
            )
            .await?;
        let section = section_between(&output, MARKER_CRON, MARKER_DONE)?;
        let mut truncated = false;
        let mut gaps = Vec::new();
        let rows = parse_config_lines(section, &mut truncated, &mut gaps);
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for row in &rows {
            if is_effective_config_line(&row.text) {
                *counts.entry(row.file.as_str()).or_default() += 1;
            }
        }
        Ok(rows
            .iter()
            .filter(|row| is_suspicious_cron_line(&row.text) && row.text.contains(exe_path))
            .map(|row| CascadedCron {
                file: row.file.clone(),
                line: row.line,
                line_sha256: line_sha256(&row.text),
                delete_file: row.file.starts_with("/etc/cron.d/")
                    && counts.get(row.file.as_str()).copied().unwrap_or(0) == 1,
            })
            .collect())
    }

    /// The hooked session tree must still be exactly the one the scan saw:
    /// same PIDs, same binaries and the same hook signatures still present in
    /// their environments. A PID that ended or was recycled refuses the plan.
    async fn ensure_session_env_unchanged(
        &self,
        session: &BoundSshSession,
        privilege: &Privilege,
        processes: &[SessionEnvProcess],
        signatures: &[String],
    ) -> CoreResult<()> {
        let mut checks = String::new();
        for process in processes {
            checks.push_str(&format!(
                "if [ -d \"/proc/{pid}\" ]; then\n  live=$(/usr/bin/readlink \"/proc/{pid}/exe\" 2>/dev/null || /usr/bin/printf '%s' '-')\n  if [ \"$live\" != {exe} ] && [ \"$live\" != \"{exe} (deleted)\" ]; then /usr/bin/printf '%s\\n' 'PID_CHANGED'; exit 0; fi\n  env_out=$(TR \"/proc/{pid}/environ\")\n  sig_ok=1\n{sig_checks}  if [ \"$sig_ok\" = 1 ]; then found=$((found+1)); fi\nfi\n",
                pid = process.pid,
                exe = shq(&process.exe),
                sig_checks = session_signature_checks(signatures).replace("ok=0", "sig_ok=0"),
            ));
        }
        let script = format!(
            "# {SELF_MARKER}\nTR() {{ /usr/bin/tr '\\0' '\\n' < \"$1\" 2>/dev/null || true; }}\nfound=0\n{checks}if [ \"$found\" = {expected} ]; then /usr/bin/printf '%s\\n' 'RECHECK_OK'; else /usr/bin/printf '%s\\n' 'SIG_GONE'; fi",
            checks = checks,
            expected = processes.len(),
        );
        let output = self
            .run_probe(session, privilege, &script, "response session recheck")
            .await?;
        match output.lines().next() {
            Some("RECHECK_OK") => Ok(()),
            Some("PID_CHANGED") => Err(CoreError::validation(
                "response session recheck",
                "某个会话 PID 现在指向另一个程序（PID 被复用），已拒绝修复；请重新扫描",
            )),
            Some("SIG_GONE") => Err(CoreError::validation(
                "response session recheck",
                "会话的环境钩子在扫描后已消失或进程已结束，无需修复；请重新扫描",
            )),
            _ => Err(CoreError::validation(
                "response session recheck",
                "无法确认会话进程身份，已拒绝修复",
            )),
        }
    }

    /// Every permission entry must still show exactly the `current` triple
    /// captured at scan time; anything that changed in between re-plans.
    async fn ensure_permissions_unchanged(
        &self,
        session: &BoundSshSession,
        privilege: &Privilege,
        entries: &[PermissionEntry],
    ) -> CoreResult<()> {
        let mut script = String::from("# {SELF_MARKER}\nok=1\n");
        for entry in entries {
            script.push_str(&format!(
                "if [ -e {path} ]; then cur=$(/usr/bin/stat -c '%a|%U|%G' -- {path} 2>/dev/null || true); [ \"$cur\" = {current} ] || ok=0; fi\n",
                path = shq(&entry.path),
                current = shq(&entry.current),
            ));
        }
        script.push_str("if [ \"$ok\" = 1 ]; then /usr/bin/printf '%s\\n' 'RECHECK_OK'; else /usr/bin/printf '%s\\n' 'PERM_CHANGED'; fi");
        let script = script.replace("{SELF_MARKER}", SELF_MARKER);
        let output = self
            .run_probe(session, privilege, &script, "hardening permission recheck")
            .await?;
        match output.lines().next() {
            Some("RECHECK_OK") => Ok(()),
            _ => Err(CoreError::validation(
                "hardening permission recheck",
                "文件权限在扫描后发生变化，请重新检查加固项",
            )),
        }
    }

    /// auditctl must still exist and none of the watch points may already be
    /// watched when the plan is built.
    async fn ensure_audit_watch_absent(
        &self,
        session: &BoundSshSession,
        privilege: &Privilege,
        points: &[String],
    ) -> CoreResult<()> {
        let mut point_tests = String::new();
        for point in points {
            point_tests.push_str(&format!(
                "if printf '%s\\n' \"$rules\" | /usr/bin/grep -Fq -- {point} && printf '%s\\n' \"$rules\" | /usr/bin/grep -Fq {key}; then /usr/bin/printf '%s\\n' 'ALREADY_PRESENT'; exit 0; fi\n",
                point = shq(point),
                key = shq(AUDIT_WATCH_KEY),
            ));
        }
        let script = format!(
            "# {SELF_MARKER}\n{AUDITCTL_RESOLVE}\nrules=$(\"$AUDITCTL\" -l 2>/dev/null || true)\n{point_tests}/usr/bin/printf '%s\\n' 'RECHECK_OK'",
            point_tests = point_tests,
            AUDITCTL_RESOLVE = AUDITCTL_RESOLVE,
        );
        let output = self
            .run_probe(session, privilege, &script, "hardening audit recheck")
            .await?;
        match output.lines().next() {
            Some("RECHECK_OK") => Ok(()),
            Some("NO_AUDITCTL") => Err(CoreError::validation(
                "hardening audit recheck",
                "目标上 auditctl 不可用，无法部署监控规则",
            )),
            Some("ALREADY_PRESENT") => Err(CoreError::validation(
                "hardening audit recheck",
                "部分监控规则在扫描后已存在，请重新检查加固项",
            )),
            _ => Err(CoreError::validation(
                "hardening audit recheck",
                "无法确认 auditd 状态，已拒绝执行",
            )),
        }
    }

    /// Post-incident hardening sweep: three closed items (auth file
    /// permissions, auditd tamper watches, integrity manifest), each with a
    /// live status. Only `Pending` items are plannable through
    /// [`ResponseEngineService::plan_hardening`].
    pub async fn hardening_scan(&self, session: &BoundSshSession) -> CoreResult<HardeningScan> {
        self.target.validate(session.target())?;
        let privilege = self.probe_privilege(session).await?;
        let script = hardening_scan_script();
        let output = match &privilege {
            Some(privilege) => {
                self.run_privileged(
                    session,
                    privilege,
                    &script,
                    "response hardening scan",
                    SCAN_TIMEOUT,
                )
                .await?
            }
            None => {
                self.run_command(
                    session,
                    format!("/bin/sh -c {}", shq(&script)),
                    "response hardening scan",
                    SCAN_TIMEOUT,
                )
                .await?
            }
        };
        if output.len() > MAX_SCAN_OUTPUT_BYTES {
            return Err(CoreError::validation(
                "response hardening scan output",
                format!("exceeds the {MAX_SCAN_OUTPUT_BYTES}-byte limit"),
            ));
        }
        let mut gaps = Vec::new();
        if privilege.is_none() {
            gaps.push(
                "未提权：auditd 规则与完整性清单可能读不到，加固检查不完整且所有加固动作不可用"
                    .to_owned(),
            );
        }
        let perm_section = hardening_section(&output, "LOVELYHAWK_HARDENING_PERM_V1")?;
        let audit_section = hardening_section(&output, "LOVELYHAWK_HARDENING_AUDIT_V1")?;
        let snap_section = hardening_section(&output, "LOVELYHAWK_HARDENING_SNAP_V1")?;
        let privileged = privilege.is_some();
        let mut items = vec![
            hardening_permissions_item(perm_section, privileged),
            hardening_audit_item(audit_section, privileged),
            hardening_snapshot_item(snap_section, privileged),
        ];
        items.retain(|item| item.kind.is_hardening());
        Ok(HardeningScan { items, gaps })
    }

    /// Plan one hardening item. Thin guard over [`Self::plan_fix`]: only the
    /// hardening kinds pass, so incident issue handles can never route here.
    pub async fn plan_hardening(
        &self,
        session: &BoundSshSession,
        issue: &ResponseIssue,
    ) -> CoreResult<ResponseFixPlan> {
        if !issue.kind.is_hardening() {
            return Err(CoreError::validation(
                "hardening plan",
                format!("{} 不是加固项", issue.kind.label()),
            ));
        }
        self.plan_fix(session, issue, FixMode::Lock).await
    }
}

/// Outcome states of one hardening item on the target right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HardeningStatus {
    /// The target deviates from the hardening baseline and a plan exists.
    Pending,
    /// The baseline is already met; the note explains what was observed.
    Compliant(String),
    /// The item does not apply on this target; the note says why.
    NotApplicable(String),
}

/// One hardening finding. `issue` is `Some` exactly when the status is
/// [`HardeningStatus::Pending`] and carries the validated object the plan
/// will re-check.
#[derive(Debug, Clone)]
pub struct HardeningItem {
    pub kind: ResponseIssueKind,
    pub status: HardeningStatus,
    pub summary: String,
    pub evidence: Vec<String>,
    pub fixable: bool,
    pub fix_summary: Option<String>,
    pub issue: Option<ResponseIssue>,
}

#[derive(Debug, Clone)]
pub struct HardeningScan {
    pub items: Vec<HardeningItem>,
    pub gaps: Vec<String>,
}

fn hardening_section<'a>(output: &'a str, marker: &str) -> CoreResult<&'a str> {
    let start = marker_line_start(output, marker).ok_or_else(|| {
        CoreError::validation("hardening scan output", format!("missing marker {marker}"))
    })?;
    let content_start = start + marker.len() + 1;
    let rest = &output[content_start..];
    // Sections end where the next hardening marker begins a new line
    // (including the trailing DONE marker).
    let end = rest
        .find("\nLOVELYHAWK_HARDENING_")
        .map(|offset| offset + 1)
        .unwrap_or(rest.len());
    Ok(&rest[..end])
}

/// The shell-side signature checks shared by the session re-check probe:
/// every signature the scan saw must still be observable in the live
/// environment of the same PID.
fn session_signature_checks(signatures: &[String]) -> String {
    let mut checks = String::new();
    if signatures.iter().any(|code| code == "prompt-recorder") {
        checks.push_str("prompt=$(printf '%s\\n' \"$env_out\" | /usr/bin/grep -m1 '^PROMPT_COMMAND=' || true)\ncase \"$prompt\" in *'>>'*) ;; *) ok=0 ;; esac\n");
    }
    if signatures.iter().any(|code| code == "resident-preload") {
        checks.push_str("ldpre=$(printf '%s\\n' \"$env_out\" | /usr/bin/grep -m1 '^LD_PRELOAD=' || true)\ncase \"$ldpre\" in *'(deleted)'*|*'/var/tmp/'*|*'/tmp/'*|*'/dev/shm/'*|*'/opt/'*) ;; '') ;; *) ok=0 ;; esac\n");
    }
    if signatures.iter().any(|code| code == "injected-path") {
        checks.push_str("pathval=$(printf '%s\\n' \"$env_out\" | /usr/bin/grep -m1 '^PATH=' || true)\ncase \"$pathval\" in */.[!.]*|*/var/tmp/*|*/tmp/*|*/dev/shm/*) ;; *) ok=0 ;; esac\n");
    }
    if checks.is_empty() {
        checks.push_str("ok=0\n");
    }
    checks
}

fn hardening_scan_script() -> String {
    format!(
        r#"# LOVELYRES_RESPONSE
printf 'LOVELYHAWK_HARDENING_PERM_V1\n'
for f in /etc/shadow /etc/gshadow /etc/sudoers /root/.ssh /root/.ssh/authorized_keys /var/spool/cron/crontabs /home/*/.ssh /home/*/.ssh/authorized_keys /etc/ssh/ssh_host_*_key; do
  [ -e "$f" ] || continue
  /usr/bin/stat -c 'PERM|%n|%a|%U|%G' -- "$f" 2>/dev/null || true
done
printf 'LOVELYHAWK_HARDENING_AUDIT_V1\n'
AUDITCTL=$(command -v auditctl 2>/dev/null || true)
[ -n "$AUDITCTL" ] || {{ [ -x /sbin/auditctl ] && AUDITCTL=/sbin/auditctl; }}
[ -n "$AUDITCTL" ] || {{ [ -x /usr/sbin/auditctl ] && AUDITCTL=/usr/sbin/auditctl; }}
if [ -n "$AUDITCTL" ]; then
  printf 'AUDITCTL\t%s\n' "$AUDITCTL"
  "$AUDITCTL" -l 2>/dev/null | /usr/bin/grep -F '{AUDIT_WATCH_KEY}' || true
else
  printf 'NOAUDITCTL\n'
fi
printf 'LOVELYHAWK_HARDENING_SNAP_V1\n'
if [ -f {manifest} ]; then
  printf 'SNAP\tpresent\t%s\n' "$(/usr/bin/wc -l < {manifest} 2>/dev/null | /usr/bin/tr -d ' ')"
  n=0
  while IFS= read -r line; do
    n=$((n+1)); [ $n -gt {recheck} ] && break
    sum=$(printf '%s' "$line" | /usr/bin/awk '{{print $1}}')
    p=${{line#* }}
    [ -n "$p" ] || continue
    if [ ! -e "$p" ]; then printf 'DRIFT\tmissing\t%s\n' "$p"; continue; fi
    cur=$(/usr/bin/sha256sum -- "$p" 2>/dev/null | /usr/bin/awk '{{print $1}}')
    [ "$cur" = "$sum" ] || printf 'DRIFT\tchanged\t%s\n' "$p"
  done < {manifest}
else
  printf 'SNAP\tabsent\t0\n'
fi
printf 'LOVELYHAWK_HARDENING_DONE_V1\n'
"#,
        AUDIT_WATCH_KEY = AUDIT_WATCH_KEY,
        manifest = HARDENING_MANIFEST,
        recheck = MAX_SNAPSHOT_RECHECK,
    )
}

/// Target permission triple for one observed path: fixed targets use the
/// baseline table; per-user `.ssh` paths and host keys keep their current
/// owner/group and only enforce the mode.
fn hardening_permission_target(path: &str, current: &str) -> Option<String> {
    if let Some((_, target)) = HARDENING_PERMISSION_TARGETS
        .iter()
        .find(|(target, _)| *target == path)
    {
        return Some((*target).to_owned());
    }
    let (mode, owner, group) = PermissionEntry::parse_triple(current)?;
    let enforce_mode = |target_mode: &str| {
        if mode != target_mode {
            Some(format!("{target_mode}|{owner}|{group}"))
        } else {
            None
        }
    };
    if path.starts_with("/home/") && path.ends_with("/.ssh") {
        return enforce_mode("700");
    }
    if path.starts_with("/home/") && path.ends_with("/.ssh/authorized_keys") {
        return enforce_mode("600");
    }
    if path.starts_with("/etc/ssh/ssh_host_") && path.ends_with("_key") {
        return enforce_mode("600");
    }
    None
}

fn hardening_permissions_item(section: &str, privileged: bool) -> HardeningItem {
    let mut deviations: Vec<PermissionEntry> = Vec::new();
    let mut seen = 0usize;
    for line in section.lines() {
        // `stat -c 'PERM|%n|%a|%U|%G'`: pipe-separated because coreutils does
        // not promise escape handling in -c formats across versions.
        let Some(rest) = line.strip_prefix("PERM|") else {
            continue;
        };
        let mut fields = rest.splitn(3, '|');
        let (Some(path), Some(mode), Some(triple_tail)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let triple = format!("{mode}|{triple_tail}");
        seen += 1;
        if !is_hardening_permission_path(path) {
            continue;
        }
        let Some(target) = hardening_permission_target(path, &triple) else {
            continue;
        };
        if triple != target {
            deviations.push(PermissionEntry {
                path: path.to_owned(),
                current: triple.to_owned(),
                target,
            });
        }
    }
    let deviations = deviations.into_iter().take(32).collect::<Vec<_>>();
    if deviations.is_empty() {
        return HardeningItem {
            kind: ResponseIssueKind::HardeningAuthPermissions,
            status: HardeningStatus::Compliant(format!(
                "已检查 {seen} 个认证关键文件，权限与属主均在基线内"
            )),
            summary: "认证关键文件（shadow、sudoers、authorized_keys 等）权限符合基线".to_owned(),
            evidence: Vec::new(),
            fixable: false,
            fix_summary: None,
            issue: None,
        };
    }
    let mut evidence = Vec::new();
    for entry in &deviations {
        evidence.push(format!(
            "{}：当前 {}，应收紧为 {}",
            entry.path, entry.current, entry.target
        ));
    }
    let issue = ResponseIssue {
        kind: ResponseIssueKind::HardeningAuthPermissions,
        severity: ResponseSeverity::Medium,
        summary: format!("{} 个认证关键文件的权限或属主偏离基线", deviations.len()),
        evidence: evidence.clone(),
        fixable: privileged,
        fix_summary: Some("记录原始权限到归档目录后按基线逐项 chmod/chown 收紧".to_owned()),
        object: IssueObject::HardeningPermissions {
            entries: deviations.clone(),
        },
    };
    HardeningItem {
        kind: ResponseIssueKind::HardeningAuthPermissions,
        status: HardeningStatus::Pending,
        summary: format!("{} 个认证关键文件的权限或属主偏离基线", deviations.len()),
        evidence,
        fixable: privileged,
        fix_summary: Some("记录原始权限到归档目录后按基线逐项 chmod/chown 收紧".to_owned()),
        issue: Some(issue),
    }
}

fn hardening_audit_item(section: &str, privileged: bool) -> HardeningItem {
    if section
        .lines()
        .any(|line| line.trim_end_matches('\r') == "NOAUDITCTL")
    {
        return HardeningItem {
            kind: ResponseIssueKind::HardeningAuditWatch,
            status: HardeningStatus::NotApplicable(
                "目标上没有 auditctl/auditd（容器或未安装审计组件），无法部署防复发监控；如有条件请在宿主机或安装 auditd 后重试"
                    .to_owned(),
            ),
            summary: "防复发监控（auditd 篡改热点告警）在目标上不可用".to_owned(),
            evidence: Vec::new(),
            fixable: false,
            fix_summary: None,
            issue: None,
        };
    }
    let watched: Vec<&str> = section
        .lines()
        .filter(|line| line.contains(AUDIT_WATCH_KEY))
        .collect();
    let missing: Vec<String> = AUDIT_WATCH_POINTS
        .iter()
        .filter(|point: &&&str| {
            let point: &str = point;
            !watched
                .iter()
                .any(|rule| rule.contains(point) && rule.contains(AUDIT_WATCH_KEY))
        })
        .map(|point| (*point).to_owned())
        .collect();
    if missing.is_empty() {
        return HardeningItem {
            kind: ResponseIssueKind::HardeningAuditWatch,
            status: HardeningStatus::Compliant(format!(
                "{} 个篡改热点已全部在监控中（watch 键 {AUDIT_WATCH_KEY}）",
                AUDIT_WATCH_POINTS.len()
            )),
            summary: "入侵篡改热点已全部处于 auditd 监控中".to_owned(),
            evidence: Vec::new(),
            fixable: false,
            fix_summary: None,
            issue: None,
        };
    }
    let evidence: Vec<String> = missing
        .iter()
        .map(|point| format!("未监控的篡改热点：{point}"))
        .collect();
    let summary = format!(
        "还有 {} 个入侵篡改热点（账号、计划任务、启动脚本、藏匿目录等）没有 auditd 监控",
        missing.len()
    );
    let issue = ResponseIssue {
        kind: ResponseIssueKind::HardeningAuditWatch,
        severity: ResponseSeverity::Low,
        summary: summary.clone(),
        evidence: evidence.clone(),
        fixable: privileged,
        fix_summary: Some(format!(
            "auditctl 为每个热点添加 watch（键 {AUDIT_WATCH_KEY}）；规则为运行时生效，重启后需要重新部署"
        )),
        object: IssueObject::HardeningAuditWatch {
            points: missing.clone(),
        },
    };
    HardeningItem {
        kind: ResponseIssueKind::HardeningAuditWatch,
        status: HardeningStatus::Pending,
        summary,
        evidence,
        fixable: privileged,
        fix_summary: Some(format!(
            "auditctl 为每个热点添加 watch（键 {AUDIT_WATCH_KEY}）；规则为运行时生效，重启后需要重新部署"
        )),
        issue: Some(issue),
    }
}

fn hardening_snapshot_item(section: &str, privileged: bool) -> HardeningItem {
    let mut present = false;
    let mut total = 0usize;
    let mut drift: Vec<String> = Vec::new();
    for line in section.lines() {
        let line = line.trim_end_matches('\r');
        if let Some(rest) = line.strip_prefix("SNAP\t") {
            let mut fields = rest.splitn(3, '\t');
            present = fields.next() == Some("present");
            if let Some(count) = fields.next() {
                total = count.parse().unwrap_or(0);
            }
        } else if let Some(rest) = line.strip_prefix("DRIFT\t") {
            let mut fields = rest.splitn(3, '\t');
            if let (Some(kind), Some(path)) = (fields.next(), fields.next()) {
                drift.push(format!(
                    "{}：{path}",
                    if kind == "missing" {
                        "已消失"
                    } else {
                        "内容已变化"
                    }
                ));
            }
        }
    }
    let drift = drift.into_iter().take(8).collect::<Vec<_>>();
    if !present {
        let summary = "尚未建立关键文件完整性清单，入侵复发时无法快速发现被篡改的文件".to_owned();
        let issue = ResponseIssue {
            kind: ResponseIssueKind::HardeningIntegritySnapshot,
            severity: ResponseSeverity::Low,
            summary: summary.clone(),
            evidence: Vec::new(),
            fixable: privileged,
            fix_summary: Some(
                "对认证与后门高发位置的文件计算 sha256 清单（上限 256 项）并存放在目标机，加固检查时自动比对漂移"
                    .to_owned(),
            ),
            object: IssueObject::HardeningSnapshot {},
        };
        return HardeningItem {
            kind: ResponseIssueKind::HardeningIntegritySnapshot,
            status: HardeningStatus::Pending,
            summary,
            evidence: Vec::new(),
            fixable: privileged,
            fix_summary: Some(
                "对认证与后门高发位置的文件计算 sha256 清单（上限 256 项）并存放在目标机，加固检查时自动比对漂移"
                    .to_owned(),
            ),
            issue: Some(issue),
        };
    }
    if drift.is_empty() {
        return HardeningItem {
            kind: ResponseIssueKind::HardeningIntegritySnapshot,
            status: HardeningStatus::Compliant(format!(
                "已建清单（{total} 项），抽查最近 {} 项无漂移",
                MAX_SNAPSHOT_RECHECK
            )),
            summary: "关键文件完整性清单已建立且未见漂移".to_owned(),
            evidence: Vec::new(),
            fixable: false,
            fix_summary: None,
            issue: None,
        };
    }
    let summary = format!(
        "完整性清单之后有 {} 处关键文件变化（可能是你刚完成的处置），确认无误后可重建清单收编当前状态",
        drift.len()
    );
    let issue = ResponseIssue {
        kind: ResponseIssueKind::HardeningIntegritySnapshot,
        severity: ResponseSeverity::Low,
        summary: summary.clone(),
        evidence: drift.clone(),
        fixable: privileged,
        fix_summary: Some("重新生成完整性清单，把当前状态固化为新基线".to_owned()),
        object: IssueObject::HardeningSnapshot {},
    };
    HardeningItem {
        kind: ResponseIssueKind::HardeningIntegritySnapshot,
        status: HardeningStatus::Pending,
        summary,
        evidence: drift,
        fixable: privileged,
        fix_summary: Some("重新生成完整性清单，把当前状态固化为新基线".to_owned()),
        issue: Some(issue),
    }
}

#[derive(Debug)]
struct CascadedCron {
    file: String,
    line: u32,
    line_sha256: String,
    delete_file: bool,
}

impl CascadedCron {
    fn validate(&self) -> CoreResult<()> {
        IssueObject::CronEntry {
            file: self.file.clone(),
            line: self.line,
            line_sha256: self.line_sha256.clone(),
        }
        .validate(ResponseIssueKind::CronPersistence)
    }
}

#[derive(Debug)]
struct ResponseFixExecutor<'a> {
    service: &'a ResponseEngineService,
    session: &'a BoundSshSession,
    plan: &'a ResponseFixPlan,
}

impl ResponseFixExecutor<'_> {
    fn ensure_plan(&self, definition: &OperationPlan) -> CoreResult<()> {
        if definition.id != self.plan.operation.id
            || definition.target != self.plan.operation.target
            || definition.metadata.get("steps-sha256") != Some(&steps_digest(&self.plan.steps))
        {
            return Err(CoreError::validation(
                "response fix plan",
                "executor is bound to a different immutable plan",
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl OperationExecutor for ResponseFixExecutor<'_> {
    async fn execute(&self, definition: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        self.ensure_plan(definition)?;
        for step in &self.plan.steps {
            let output = self
                .service
                .run_wrapped(
                    self.session,
                    &self.plan.privilege,
                    step.script.clone(),
                    "response fix step",
                    FIX_TIMEOUT,
                )
                .await
                .map_err(|error| {
                    CoreError::ssh(
                        "response fix step",
                        format!("步骤「{}」失败：{error}", step.label),
                    )
                })?;
            if output.contains(FIX_ROLLBACK_MARKER) {
                return Err(CoreError::ssh(
                    "response fix step",
                    format!(
                        "步骤「{}」写入后校验失败，已从归档 {}/ 自动恢复",
                        step.label, self.plan.archive_dir
                    ),
                ));
            }
            if !output.contains(FIX_OK_MARKER) {
                return Err(CoreError::ssh(
                    "response fix step",
                    format!("步骤「{}」缺少完成标记，按失败处理", step.label),
                ));
            }
        }
        Ok(ExecutionReceipt {
            summary: format!(
                "已执行 {} 个修复步骤；删除前证据已归档至远端 {}",
                self.plan.steps.len(),
                self.plan.archive_dir
            ),
            restore_token: Some(self.plan.archive_dir.clone()),
        })
    }

    async fn verify(
        &self,
        definition: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        self.ensure_plan(definition)?;
        let output = self
            .service
            .run_wrapped(
                self.session,
                &self.plan.privilege,
                self.plan.verify_script.clone(),
                "response fix verify",
                FIX_TIMEOUT,
            )
            .await?;
        if output.contains(VERIFY_OK_MARKER) {
            Ok(VerificationResult {
                passed: true,
                detail: "复验通过：对象已清除且目标状态符合预期".to_owned(),
            })
        } else if output.contains(VERIFY_FAIL_MARKER) {
            Ok(VerificationResult {
                passed: false,
                detail: "复验未通过：对象仍然存在或目标状态发生变化".to_owned(),
            })
        } else {
            Err(CoreError::ssh(
                "response fix verify",
                "verification script returned no verdict marker",
            ))
        }
    }

    async fn restore(
        &self,
        definition: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<()> {
        self.ensure_plan(definition)?;
        let Some(script) = &self.plan.restore_script else {
            return Err(CoreError::Unsupported {
                feature: "自动恢复账户类修复（归档保留在远端，供人工恢复）",
            });
        };
        let output = self
            .service
            .run_wrapped(
                self.session,
                &self.plan.privilege,
                script.clone(),
                "response fix restore",
                FIX_TIMEOUT,
            )
            .await?;
        if output.contains(RESTORE_OK_MARKER) {
            Ok(())
        } else {
            Err(CoreError::ssh(
                "response fix restore",
                "restore script returned no completion marker",
            ))
        }
    }
}

fn successful_output(subject: &'static str, output: SshCommandOutput) -> CoreResult<String> {
    if output.timed_out {
        return Err(CoreError::ssh(subject, "remote command timed out"));
    }
    if output.exit_code != Some(0) {
        return Err(CoreError::ssh(
            subject,
            format!(
                "remote command exited with {:?}: {}",
                output.exit_code,
                output.output.chars().take(1_024).collect::<String>()
            ),
        ));
    }
    Ok(output.output)
}

/// The sensitive channel separates the streams; on failure only stderr (which
/// may carry sudo's refusal but never the password) is quoted, bounded.
fn sensitive_output(
    subject: &'static str,
    output: SshSensitiveCommandOutput,
) -> CoreResult<String> {
    if output.exit_code != Some(0) {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CoreError::ssh(
            subject,
            format!(
                "remote command exited with {:?}: {}",
                output.exit_code,
                stderr.chars().take(1_024).collect::<String>()
            ),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Wrap a raw script for the session's privilege. Root and passwordless sudo
/// keep the audit-module shape; password sudo wraps with `sudo -S` so the
/// password never appears in command text — it travels over stdin instead.
fn privileged_command(privilege: &Privilege, script: &str) -> String {
    match privilege {
        Privilege::Root => privileged_script(true, script),
        Privilege::SudoNoPassword => privileged_script(false, script),
        Privilege::SudoWithPassword(_) => sudo_stdin_command(script),
    }
}

fn sudo_stdin_command(script: &str) -> String {
    format!("sudo -S -p '' -- /bin/sh -c {}", shq(script))
}

fn steps_digest(steps: &[FixStep]) -> String {
    let mut digest = Sha256::new();
    for step in steps {
        digest.update((step.script.len() as u64).to_be_bytes());
        digest.update(step.script.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

fn is_allowed_response_path(path: &str) -> bool {
    if !path.starts_with('/') || path.len() > 512 || path.contains('\0') {
        return false;
    }
    if path.split('/').any(|component| component == "..") {
        return false;
    }
    if ALLOWED_PATH_EXACT.contains(&path) {
        return true;
    }
    if ALLOWED_PATH_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix) && path.len() > prefix.len())
    {
        return true;
    }
    if hidden_dir_ancestor(path).is_some() {
        return true;
    }
    is_authorized_keys_path(path) || is_history_file_path(path)
}

/// The nearest ancestor directory whose name is hidden (starts with `.` and
/// has at least one more character) sitting directly below a world-writable
/// or attacker-favoured prefix — e.g. `/var/tmp/.sysd/watcher` yields
/// `/var/tmp/.sysd`. System pseudo-dirs are denylisted.
fn hidden_dir_ancestor(path: &str) -> Option<String> {
    for prefix in HIDDEN_DIR_PREFIXES {
        let Some(rest) = path.strip_prefix(prefix) else {
            continue;
        };
        let first = rest.split('/').next()?;
        if first.len() >= 2 && first.starts_with('.') && !first.contains(' ') {
            let dir = format!("{prefix}{first}");
            if !STASH_DIR_DENYLIST.contains(&dir.as_str()) {
                return Some(dir);
            }
        }
    }
    None
}

fn is_authorized_keys_path(path: &str) -> bool {
    if path == "/root/.ssh/authorized_keys" {
        return true;
    }
    let Some(rest) = path.strip_prefix("/home/") else {
        return false;
    };
    let mut parts = rest.split('/');
    matches!(parts.next(), Some(user) if is_valid_username(user))
        && parts.next() == Some(".ssh")
        && parts.next() == Some("authorized_keys")
        && parts.next().is_none()
}

fn is_history_file_path(path: &str) -> bool {
    if path == "/root/.bash_history" {
        return true;
    }
    let Some(rest) = path.strip_prefix("/home/") else {
        return false;
    };
    let mut parts = rest.split('/');
    matches!(parts.next(), Some(user) if is_valid_username(user))
        && parts.next() == Some(".bash_history")
        && parts.next().is_none()
}

/// A mapped `.so` under one of the attacker-favoured prefixes. The name must
/// contain `.so` so random deleted data files under /tmp never qualify.
fn is_suspicious_lib_path(path: &str) -> bool {
    if path.len() > 512 || path.contains('\0') || path.split('/').any(|c| c == "..") {
        return false;
    }
    if !path.contains(".so") {
        return false;
    }
    RESIDENT_LIB_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix) && path.len() > prefix.len())
}

fn validate_pid_list(pids: &[u32]) -> CoreResult<()> {
    if pids.is_empty() || pids.len() > 64 {
        return Err(CoreError::validation(
            "response issue pid list",
            "pid list must contain 1 to 64 entries",
        ));
    }
    if pids.contains(&0) {
        return Err(CoreError::validation(
            "response issue pid list",
            "pid 0 is never a userspace process",
        ));
    }
    Ok(())
}

/// Paths the permission hardening may touch: the fixed targets plus the
/// per-user `.ssh` shapes and host key files.
fn is_hardening_permission_path(path: &str) -> bool {
    if HARDENING_PERMISSION_TARGETS
        .iter()
        .any(|(target, _)| *target == path)
    {
        return true;
    }
    if let Some(rest) = path.strip_prefix("/home/") {
        let mut parts = rest.split('/');
        let user_ok = matches!(parts.next(), Some(user) if is_valid_username(user));
        let second = parts.next();
        let third = parts.next();
        let fourth = parts.next();
        return user_ok
            && fourth.is_none()
            && ((second == Some(".ssh") && third.is_none())
                || (second == Some(".ssh") && third == Some("authorized_keys")));
    }
    if let Some(rest) = path.strip_prefix("/etc/ssh/ssh_host_") {
        return rest.ends_with("_key") && !rest.contains('/') && rest.len() > 4;
    }
    false
}

fn validate_file_fingerprint(sha256: &str, stat: &StatFingerprint) -> CoreResult<()> {
    if !is_sha256_hex(sha256) {
        return Err(CoreError::validation(
            "response issue digest",
            "sha256 must be 64 lowercase hex characters",
        ));
    }
    if stat.mode > 0o7777 {
        return Err(CoreError::validation(
            "response issue stat fingerprint",
            "mode is out of range",
        ));
    }
    Ok(())
}

fn validate_tracked_path(tracked: &TrackedPath) -> CoreResult<()> {
    if !is_allowed_response_path(&tracked.path) {
        return Err(CoreError::validation(
            "response issue tracked path",
            format!("path {:?} is outside the response whitelist", tracked.path),
        ));
    }
    validate_file_fingerprint(&tracked.sha256, &tracked.stat)
}

fn validate_startup_file(file: &str) -> CoreResult<()> {
    let allowed = STARTUP_FILES_EXACT.contains(&file)
        || (file.starts_with("/etc/profile.d/")
            && is_valid_command_name(file.rsplit('/').next().unwrap_or_default()));
    if !allowed || !is_allowed_response_path(file) {
        return Err(CoreError::validation(
            "response issue startup file",
            format!("file {file:?} is outside the shell startup whitelist"),
        ));
    }
    Ok(())
}

fn is_valid_command_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// sha256 of the exact line bytes plus the trailing newline, matching what
/// `sed -n 'Np' FILE | sha256sum` reports for that line remotely.
fn line_sha256(line: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(line.as_bytes());
    digest.update(b"\n");
    format!("{:x}", digest.finalize())
}

fn ensure_path_fingerprint(
    path: &str,
    expected_sha256: &str,
    expected_stat: StatFingerprint,
    observed: &(String, StatFingerprint),
) -> CoreResult<()> {
    if observed.0 != expected_sha256 || observed.1 != expected_stat {
        return Err(CoreError::validation(
            "response fix recheck",
            format!("{path} 的内容或属性指纹在扫描后发生变化，已拒绝修复"),
        ));
    }
    Ok(())
}

fn ensure_line_digest(expected: &str, observed: &str, file: &str) -> CoreResult<()> {
    if observed != expected {
        return Err(CoreError::validation(
            "response fix recheck",
            format!("{file} 目标行内容在扫描后发生变化，已拒绝修复"),
        ));
    }
    Ok(())
}

fn home_is_user_owned_location(home: &str) -> bool {
    home.len() > "/home/".len() && home.starts_with("/home/")
}

// ---------------------------------------------------------------------------
// scan command templates (static, absolute tool paths, direct /proc reads)
// ---------------------------------------------------------------------------

fn scan_script() -> String {
    SCAN_SCRIPT_TEMPLATE
        .replace("__MAX_CONFIG_LINES__", &MAX_CONFIG_LINES.to_string())
        .replace("__MAX_PROCESS_ROWS__", &MAX_PROCESS_ROWS.to_string())
        .replace("__MAX_PASSWD_LINES__", &MAX_PASSWD_LINES.to_string())
        .replace("__MAX_LISTEN_ROWS__", &MAX_LISTEN_ROWS.to_string())
        .replace("__MAX_ENV_SESSIONS__", &MAX_ENV_SESSIONS.to_string())
        .replace("__MAX_RESIDUE_ROWS__", &MAX_RESIDUE_ROWS.to_string())
        .replace("__PYWALK__", PYWALK_FUNCTION)
}

/// Shell function embedded into scan and plan scripts: enumerate a directory
/// tree with a raw `getdents64` syscall via python3 ctypes, so an LD_PRELOAD
/// `readdir` hook (ghost-range v2's libsyslog.so) cannot hide entries from
/// us. Callers without python3 fall back to `find` and record a scan gap.
const PYWALK_FUNCTION: &str = r#"hawk_walk() {
  /usr/bin/python3 - "$1" "$2" <<'LOVELYRES_PYWALK_EOF'
import ctypes, os, stat as statmod, sys

root = sys.argv[1]
maxdepth = int(sys.argv[2])
libc = ctypes.CDLL(None, use_errno=True)
seen = [0]

def scandir(d):
    try:
        fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return
    try:
        buf = ctypes.create_string_buffer(65536)
        while True:
            n = libc.syscall(217, fd, buf, 65536)
            if n <= 0:
                return
            off = 0
            while off < n:
                reclen = int.from_bytes(buf[off + 16:off + 18], "little")
                name = bytes(buf[off + 19:off + reclen]).split(b"\x00", 1)[0]
                off += reclen
                if name not in (b".", b".."):
                    yield name
    finally:
        os.close(fd)

def walk(d, depth):
    if seen[0] > 20000:
        return
    for name in scandir(d) or ():
        path = d.rstrip("/") + "/" + name.decode("utf-8", "replace")
        try:
            st = os.lstat(path)
        except OSError:
            continue
        seen[0] += 1
        if statmod.S_ISDIR(st.st_mode):
            sys.stdout.write("D\t" + path + "\n")
            if depth < maxdepth:
                walk(path, depth + 1)
        elif statmod.S_ISREG(st.st_mode):
            sys.stdout.write("F\t" + path + "\n")

try:
    walk(root, 0)
except Exception:
    pass
LOVELYRES_PYWALK_EOF
}
"#;

const SCAN_SCRIPT_TEMPLATE: &str = r#"# LOVELYRES_RESPONSE_SCAN_V1
__PYWALK__
printf 'LOVELYRES_RESPONSE_HIJACK_V1\n'
hijack_dirs="/usr/local/bin"
for f in /etc/profile /etc/bash.bashrc /etc/environment /root/.bashrc /root/.bash_profile /etc/profile.d/*.sh; do
  [ -f "$f" ] && [ -r "$f" ] || continue
  for tok in $(/usr/bin/grep -h 'PATH' -- "$f" 2>/dev/null | /usr/bin/grep -oE '/[A-Za-z0-9_][A-Za-z0-9_/+.@-]*' | /usr/bin/sort -u); do
    case "$tok" in
      /usr/bin|/usr/local/bin|/usr/sbin|/usr/local/sbin|/bin|/sbin|/usr/games|/usr/local/games|/snap/bin) ;;
      */.*|/tmp/*|/var/tmp/*|/dev/shm/*|/opt/*) hijack_dirs="$hijack_dirs $tok" ;;
    esac
  done
done
if [ -x /usr/bin/python3 ]; then
  hidden_dirs=$(for base in /opt /tmp /var/tmp /dev/shm; do
    [ -d "$base" ] && hawk_walk "$base" 1
  done 2>/dev/null | /usr/bin/awk -F'\t' '$1=="D" {print $2}')
else
  /usr/bin/printf 'GAP\t目标缺少 python3，隐藏目录枚举依赖可能被劫持的 readdir，伪命令可能漏报\n'
  hidden_dirs=$(for base in /opt /tmp /var/tmp /dev/shm; do
    for d in "$base"/.[!.]*; do [ -d "$d" ] && printf '%s\n' "$d"; done
  done 2>/dev/null)
fi
for d in $hidden_dirs; do
  case "${d##*/}" in .?*) hijack_dirs="$hijack_dirs $d" ;; esac
done
hijack_dirs=$(printf '%s\n' $hijack_dirs | /usr/bin/sort -u | /usr/bin/head -n 64)
for dir in $hijack_dirs; do
  [ -d "$dir" ] || continue
  for path in "$dir"/*; do
    [ -f "$path" ] && [ ! -L "$path" ] && [ -r "$path" ] || continue
    name=${path##*/}
    /usr/bin/grep -q 'grep -E' -- "$path" 2>/dev/null || continue
    sig_call=$(/usr/bin/grep -m1 -E "/(usr/bin|bin)/$name([ \"']|$)" -- "$path" 2>/dev/null)
    [ -n "$sig_call" ] || continue
    sig_grep=$(/usr/bin/grep -m1 'grep -E' -- "$path" 2>/dev/null)
    sum=$(/usr/bin/sha256sum -- "$path" 2>/dev/null | /usr/bin/awk '{print $1}')
    fp=$(/usr/bin/stat -c '%a|%u|%g|%s|%Y' -- "$path" 2>/dev/null)
    resolved=$(command -v "$name" 2>/dev/null || /usr/bin/printf '%s' 'unknown')
    /usr/bin/printf 'HIT\t%s\t%s\t%s\t%s\t%s\t%s\n' "$path" "$sum" "$fp" "$resolved" "$sig_grep" "$sig_call"
  done
done
printf 'LOVELYRES_RESPONSE_UID0_V1\n'
/usr/bin/awk -F: '$3==0 && $1!="root" {printf "%s\t%s\t%s\n",$1,$3,$6}' /etc/passwd 2>/dev/null
printf 'LOVELYRES_RESPONSE_SHADOW_V1\n'
if [ -f /etc/shadow ] && [ ! -L /etc/shadow ] && [ -r /etc/shadow ]; then
  /usr/bin/awk -F: '$2=="" {print $1}' /etc/shadow 2>/dev/null
else
  /usr/bin/printf 'GAP\t/etc/shadow 不可读，无法检查空口令账户\n'
fi
printf 'LOVELYRES_RESPONSE_PASSWD_V1\n'
if [ -f /etc/passwd ] && [ ! -L /etc/passwd ] && [ -r /etc/passwd ]; then
  /usr/bin/awk -F: '{printf "%s\t%s\t%s\t%s\t%s\n",$1,$3,$4,$6,$7}' /etc/passwd 2>/dev/null
else
  /usr/bin/printf 'GAP\t/etc/passwd 不可读，无法检查可疑登录账户\n'
fi | /usr/bin/awk -v max=__MAX_PASSWD_LINES__ 'NR<=max {print} NR==max+1 {print "TRUNCATED"}'
printf 'LOVELYRES_RESPONSE_SUDOERS_V1\n'
for file in /etc/sudoers /etc/sudoers.d/*; do
  if [ -f "$file" ] && [ ! -L "$file" ]; then
    if [ -r "$file" ]; then
      /usr/bin/awk '{printf "%s\t%d\t%s\n", FILENAME, FNR, $0}' "$file"
    else
      /usr/bin/printf 'GAP\tsudoers 文件 %s 不可读\n' "$file"
    fi
  fi
done | /usr/bin/awk -v max=__MAX_CONFIG_LINES__ 'NR<=max {print} NR==max+1 {print "TRUNCATED"}'
printf 'LOVELYRES_RESPONSE_CRON_V1\n'
for file in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* /var/spool/cron/*; do
  if [ -f "$file" ] && [ ! -L "$file" ]; then
    if [ -r "$file" ]; then
      /usr/bin/awk '{printf "%s\t%d\t%s\n", FILENAME, FNR, $0}' "$file"
    else
      /usr/bin/printf 'GAP\tcron 文件 %s 不可读\n' "$file"
    fi
  fi
done | /usr/bin/awk -v max=__MAX_CONFIG_LINES__ 'NR<=max {print} NR==max+1 {print "TRUNCATED"}'
printf 'LOVELYRES_RESPONSE_PROC_V1\n'
for proc_dir in /proc/[0-9]*; do
  pid=${proc_dir#/proc/}
  cmdline=$(/usr/bin/tr '\0\n' '  ' < "$proc_dir/cmdline" 2>/dev/null || true)
  [ -n "$cmdline" ] || continue
  exe=$(/usr/bin/readlink "$proc_dir/exe" 2>/dev/null || /usr/bin/printf '%s' '-')
  /usr/bin/printf '%s\t%s\t%s\n' "$pid" "$exe" "$cmdline"
done | /usr/bin/awk -v max=__MAX_PROCESS_ROWS__ 'NR<=max {print} NR==max+1 {print "TRUNCATED"}'
printf 'LOVELYRES_RESPONSE_PRELOAD_V1\n'
if [ -e /etc/ld.so.preload ]; then
  if [ -f /etc/ld.so.preload ] && [ ! -L /etc/ld.so.preload ] && [ -r /etc/ld.so.preload ]; then
    sum=$(/usr/bin/sha256sum -- /etc/ld.so.preload | /usr/bin/awk '{print $1}')
    fp=$(/usr/bin/stat -c '%a|%u|%g|%s|%Y' -- /etc/ld.so.preload)
    /usr/bin/printf 'PRELOAD\t%s\t%s\n' "$sum" "$fp"
    while IFS= read -r rawlib; do
      lib=$(/usr/bin/printf '%s' "$rawlib" | /usr/bin/sed 's/^[ \t]*//; s/[ \t]*$//')
      case "$lib" in ''|'#'*) continue ;; esac
      case "$lib" in /*) ;; *) continue ;; esac
      if [ -f "$lib" ] && [ ! -L "$lib" ]; then
        lsum=$(/usr/bin/sha256sum -- "$lib" 2>/dev/null | /usr/bin/awk '{print $1}')
        lfp=$(/usr/bin/stat -c '%a|%u|%g|%s|%Y' -- "$lib" 2>/dev/null)
        /usr/bin/printf 'LIB\t%s\t%s\t%s\n' "$lib" "$lsum" "$lfp"
      else
        /usr/bin/printf 'LIB\t%s\tMISSING\t-\n' "$lib"
      fi
    done < /etc/ld.so.preload
  else
    /usr/bin/printf 'GAP\t/etc/ld.so.preload 存在但不可安全读取（符号链接或权限不足）\n'
  fi
fi
printf 'LOVELYRES_RESPONSE_PATHINJ_V1\n'
for file in /etc/profile /etc/bash.bashrc /etc/environment /root/.bashrc /root/.bash_profile /etc/profile.d/*.sh; do
  if [ -f "$file" ] && [ ! -L "$file" ]; then
    if [ -r "$file" ]; then
      /usr/bin/awk '/PATH/ {printf "%s\t%d\t%s\n", FILENAME, FNR, $0}' "$file"
    else
      /usr/bin/printf 'GAP\tshell 启动文件 %s 不可读，PATH 注入未检查\n' "$file"
    fi
  fi
done | /usr/bin/awk -v max=__MAX_CONFIG_LINES__ 'NR<=max {print} NR==max+1 {print "TRUNCATED"}'
printf 'LOVELYRES_RESPONSE_AUTHKEYS_V1\n'
[ -r /root ] || /usr/bin/printf 'GAP\t/root 不可读，root 的 authorized_keys 未检查\n'
for file in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
  if [ -f "$file" ] && [ ! -L "$file" ]; then
    if [ -r "$file" ]; then
      /usr/bin/awk '{printf "%s\t%d\t%s\n", FILENAME, FNR, $0}' "$file"
    else
      /usr/bin/printf 'GAP\tauthorized_keys 文件 %s 不可读\n' "$file"
    fi
  fi
done | /usr/bin/awk -v max=__MAX_CONFIG_LINES__ 'NR<=max {print} NR==max+1 {print "TRUNCATED"}'
printf 'LOVELYRES_RESPONSE_PAM_V1\n'
for file in /etc/pam.d/*; do
  if [ -f "$file" ] && [ ! -L "$file" ]; then
    if [ -r "$file" ]; then
      /usr/bin/awk '{printf "%s\t%d\t%s\n", FILENAME, FNR, $0}' "$file"
    else
      /usr/bin/printf 'GAP\tPAM 配置 %s 不可读\n' "$file"
    fi
  fi
done | /usr/bin/awk -v max=__MAX_CONFIG_LINES__ 'NR<=max {print} NR==max+1 {print "TRUNCATED"}'
printf 'LOVELYRES_RESPONSE_LISTEN_V1\n'
listens=$(/usr/bin/awk '$4=="0A" {printf "%s %s\n", $2, $10}' /proc/net/tcp /proc/net/tcp6 2>/dev/null | /usr/bin/sort -u | /usr/bin/head -n __MAX_LISTEN_ROWS__)
if [ -n "$listens" ]; then
  printf '%s\n' "$listens" | while read -r local inode; do
    pid='-'; exe='-'; cmd='-'
    for proc_dir in /proc/[0-9]*; do
      found=0
      for fd in "$proc_dir"/fd/*; do
        link=$(/usr/bin/readlink "$fd" 2>/dev/null) || continue
        case "$link" in
          "socket:[$inode]") pid=${proc_dir#/proc/}; found=1; break ;;
        esac
      done
      if [ "$found" = 1 ]; then
        exe=$(/usr/bin/readlink "$proc_dir/exe" 2>/dev/null || /usr/bin/printf '%s' '-')
        cmd=$(/usr/bin/tr '\0\n' '  ' < "$proc_dir/cmdline" 2>/dev/null | /usr/bin/cut -c1-300)
        break
      fi
    done
    /usr/bin/printf 'LIS\t%s\t%s\t%s\t%s\t%s\n' "$local" "$inode" "$pid" "$exe" "$cmd"
  done
fi
printf 'LOVELYRES_RESPONSE_WEB_V1\n'
web_roots=$(
  for conf in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf /etc/apache2/sites-enabled/*; do
    [ -f "$conf" ] && [ -r "$conf" ] || continue
    /usr/bin/awk '/^[ \t]*(root|DocumentRoot)[ \t]+\// {print $2}' "$conf" 2>/dev/null
  done
  [ -d /var/www/html ] && printf '%s\n' /var/www/html
)
web_roots=$(printf '%s\n' $web_roots | /usr/bin/tr -d ';' | /usr/bin/sort -u)
if [ -z "$web_roots" ]; then
  /usr/bin/printf 'GAP\t未发现 Web 根目录（nginx/apache 配置与 /var/www/html 均不存在），Web 层未检查\n'
fi
if [ -x /usr/bin/python3 ]; then
  for root in $web_roots; do
    case "$root" in /*) ;; *) continue ;; esac
    [ -d "$root" ] && hawk_walk "$root" 6
  done 2>/dev/null
else
  /usr/bin/printf 'GAP\t目标缺少 python3，Web 目录枚举走 find，LD_PRELOAD 类 readdir 钩子可能隐藏条目\n'
  for root in $web_roots; do
    case "$root" in /*) ;; *) continue ;; esac
    [ -d "$root" ] && /usr/bin/find "$root" -maxdepth 6 -type f 2>/dev/null | /usr/bin/sed 's|^|F\t|'
  done
fi | while IFS='	' read -r kind path; do
  [ "$kind" = "F" ] || continue
  base=${path##*/}
  lower=$(/usr/bin/printf '%s' "$base" | /usr/bin/tr 'A-Z' 'a-z')
  case "$lower" in
    .env|*.zip|*.tar|*.tgz|*.tbz2|*.txz|*.gz|*.bz2|*.xz|*.7z|*.rar|*.sql|*.bak|*.dump|*backup*|*dump*)
      sum=$(/usr/bin/sha256sum -- "$path" 2>/dev/null | /usr/bin/awk '{print $1}')
      fp=$(/usr/bin/stat -c '%a|%u|%g|%s|%Y' -- "$path" 2>/dev/null)
      /usr/bin/printf 'WEBCAND\t%s\t%s\t%s\n' "$path" "$sum" "$fp" ;;
  esac
  case "$lower" in
    *.php|*.php5|*.phtml|*.jsp|*.jspx|*.asp|*.aspx)
      sig=$(/usr/bin/grep -m1 -E 'eval|assert|Runtime\.exec|ProcessBuilder|base64_decode|shell_exec|passthru|popen|system\(|\$_(POST|REQUEST|GET|COOKIE)' -- "$path" 2>/dev/null | /usr/bin/cut -c1-300)
      if [ -n "$sig" ]; then
        sum=$(/usr/bin/sha256sum -- "$path" 2>/dev/null | /usr/bin/awk '{print $1}')
        fp=$(/usr/bin/stat -c '%a|%u|%g|%s|%Y' -- "$path" 2>/dev/null)
        /usr/bin/printf 'SH3LLCAND\t%s\t%s\t%s\t%s\n' "$path" "$sum" "$fp" "$sig"
      fi ;;
  esac
done | /usr/bin/awk -v max=__MAX_CONFIG_LINES__ 'NR<=max {print} NR==max+1 {print "TRUNCATED"}'
printf 'LOVELYRES_RESPONSE_HOOK_V1\n'
for file in /etc/profile /etc/bash.bashrc /etc/environment /root/.bashrc /root/.bash_profile /etc/profile.d/*.sh; do
  if [ -f "$file" ] && [ ! -L "$file" ] && [ -r "$file" ]; then
    /usr/bin/awk '/PROMPT_COMMAND/ {printf "%s\t%d\t%s\n", FILENAME, FNR, $0}' "$file"
  fi
done | /usr/bin/awk -v max=__MAX_CONFIG_LINES__ 'NR<=max {print} NR==max+1 {print "TRUNCATED"}'
printf 'LOVELYRES_RESPONSE_HISTORY_V1\n'
[ -r /root ] || /usr/bin/printf 'GAP\t/root 不可读，root 的 .bash_history 未检查\n'
for file in /root/.bash_history /home/*/.bash_history; do
  if [ -f "$file" ] && [ ! -L "$file" ]; then
    if [ -r "$file" ]; then
      /usr/bin/awk -v max=__MAX_CONFIG_LINES__ 'NR<=max {printf "%s\t%d\t%s\n", FILENAME, FNR, $0}' "$file"
    else
      /usr/bin/printf 'GAP\t历史文件 %s 不可读，明文密码未检查\n' "$file"
    fi
  fi
done | /usr/bin/awk -v max=__MAX_CONFIG_LINES__ 'NR<=max {print} NR==max+1 {print "TRUNCATED"}'
printf 'LOVELYRES_RESPONSE_ENVIRON_V1\n'
for proc_dir in /proc/[0-9]*; do
  cmd=$(/usr/bin/tr '\0\n' '  ' < "$proc_dir/cmdline" 2>/dev/null || true)
  case "$cmd" in
    *LOVELYRES_RESPONSE*) continue ;;
  esac
  interesting=$(/usr/bin/tr '\0' '\n' < "$proc_dir/environ" 2>/dev/null | /usr/bin/grep -m3 -E '^(PROMPT_COMMAND|LD_PRELOAD|PATH)=' || true)
  [ -n "$interesting" ] || continue
  prompt=$(printf '%s\n' "$interesting" | /usr/bin/grep -m1 '^PROMPT_COMMAND=' | /usr/bin/cut -c1-300 || true)
  ldpre=$(printf '%s\n' "$interesting" | /usr/bin/grep -m1 '^LD_PRELOAD=' | /usr/bin/cut -c1-300 || true)
  pathval=$(printf '%s\n' "$interesting" | /usr/bin/grep -m1 '^PATH=' | /usr/bin/cut -c1-300 || true)
  emit=0
  [ -n "$prompt" ] && emit=1
  [ -n "$ldpre" ] && emit=1
  case "$pathval" in
    */.[!.]*|*/var/tmp/*|*/tmp/*|*/dev/shm/*) emit=1 ;;
  esac
  [ "$emit" = 1 ] || continue
  pid=${proc_dir#/proc/}
  exe=$(/usr/bin/readlink "$proc_dir/exe" 2>/dev/null || /usr/bin/printf '%s' '-')
  /usr/bin/printf 'ENVROW\t%s\t%s\t%s\t%s\t%s\n' "$pid" "$exe" "$prompt" "$ldpre" "$pathval"
done | /usr/bin/awk -v max=__MAX_ENV_SESSIONS__ 'NR<=max {print} NR==max+1 {print "TRUNCATED"}'
printf 'LOVELYRES_RESPONSE_MAPS_V1\n'
for proc_dir in /proc/[0-9]*; do
  cmd=$(/usr/bin/tr '\0\n' '  ' < "$proc_dir/cmdline" 2>/dev/null || true)
  case "$cmd" in
    *LOVELYRES_RESPONSE*) continue ;;
  esac
  hits=$(/usr/bin/grep -E ' /(usr/local/lib|usr/local/libexec|opt|var/tmp|tmp|dev/shm)/' -- "$proc_dir/maps" 2>/dev/null || true)
  [ -n "$hits" ] || continue
  pid=${proc_dir#/proc/}
  exe=$(/usr/bin/readlink "$proc_dir/exe" 2>/dev/null || /usr/bin/printf '%s' '-')
  printf '%s\n' "$hits" | /usr/bin/awk -v pid="$pid" -v exe="$exe" '{path=$6; for (i = 7; i <= NF; i++) path = path " " $i; print pid "\t" exe "\t" path}'
done | while IFS="$(printf '\t')" read -r pid exe path; do
  base=${path% (deleted)}
  case "$base" in
    *.so|*.so.*) ;;
    *) continue ;;
  esac
  if [ "$base" != "$path" ] || [ ! -e "$base" ]; then
    /usr/bin/printf 'MAPHIT\t%s\t%s\t%s\n' "$pid" "$exe" "$path"
  fi
done | /usr/bin/sort -u | /usr/bin/awk -v max=__MAX_RESIDUE_ROWS__ 'NR<=max {print} NR==max+1 {print "TRUNCATED"}'
printf 'LOVELYRES_RESPONSE_DONE_V1\n'
"#;

fn cron_scan_script() -> String {
    format!(
        "# {SELF_MARKER}\nprintf '{MARKER_CRON}\\n'\nfor file in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* /var/spool/cron/*; do\n  if [ -f \"$file\" ] && [ ! -L \"$file\" ] && [ -r \"$file\" ]; then\n    /usr/bin/awk '{{printf \"%s\\t%d\\t%s\\n\", FILENAME, FNR, $0}}' \"$file\"\n  fi\ndone | /usr/bin/awk -v max={MAX_CONFIG_LINES} 'NR<=max {{print}} NR==max+1 {{print \"TRUNCATED\"}}'\nprintf '{MARKER_DONE}\\n'"
    )
}

fn account_lookup_script(names: &[String]) -> String {
    let mut script = String::new();
    for name in names {
        script.push_str(&format!(
            "/usr/bin/awk -F: -v u={name} '$1==u {{printf \"%s\\t%s\\t%s\\n\",$1,$3,$6}}' /etc/passwd 2>/dev/null\n",
            name = shq(name),
        ));
    }
    script
}

// ---------------------------------------------------------------------------
// scan output parsing and closed classification
// ---------------------------------------------------------------------------

struct RawSections<'a> {
    hijack: &'a str,
    uid0: &'a str,
    shadow: &'a str,
    passwd: &'a str,
    sudoers: &'a str,
    cron: &'a str,
    proc_rows: &'a str,
    preload: &'a str,
    pathinj: &'a str,
    authkeys: &'a str,
    pam: &'a str,
    listen: &'a str,
    web: &'a str,
    hook: &'a str,
    hist: &'a str,
    environ: &'a str,
    maps: &'a str,
}

/// Byte offset of the first line that *is* the marker. Section markers must
/// anchor to whole lines: the PROC section legitimately contains our own scan
/// shell's cmdline — the entire script as one long line (newlines turned to
/// spaces by `tr`), with every marker string embedded as a substring.
/// Substring matching would cut sections at those embedded copies.
fn marker_line_start(text: &str, marker: &str) -> Option<usize> {
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        if line.trim_end_matches(['\n', '\r']) == marker {
            return Some(offset);
        }
        offset += line.len();
    }
    None
}

fn section_between<'a>(text: &'a str, start: &str, end: &str) -> CoreResult<&'a str> {
    let start_at = marker_line_start(text, start).ok_or_else(|| {
        CoreError::validation("response scan output", format!("missing marker {start}"))
    })?;
    let content_start = start_at + start.len() + 1;
    let stop = marker_line_start(text, end).ok_or_else(|| {
        CoreError::validation("response scan output", format!("missing marker {end}"))
    })?;
    if stop < content_start {
        return Err(CoreError::validation(
            "response scan output",
            format!("marker {end} precedes {start}"),
        ));
    }
    Ok(&text[content_start..stop])
}

fn split_sections(text: &str) -> CoreResult<RawSections<'_>> {
    Ok(RawSections {
        hijack: section_between(text, MARKER_HIJACK, MARKER_UID0)?,
        uid0: section_between(text, MARKER_UID0, MARKER_SHADOW)?,
        shadow: section_between(text, MARKER_SHADOW, MARKER_PASSWD)?,
        passwd: section_between(text, MARKER_PASSWD, MARKER_SUDOERS)?,
        sudoers: section_between(text, MARKER_SUDOERS, MARKER_CRON)?,
        cron: section_between(text, MARKER_CRON, MARKER_PROC)?,
        proc_rows: section_between(text, MARKER_PROC, MARKER_PRELOAD)?,
        preload: section_between(text, MARKER_PRELOAD, MARKER_PATHINJ)?,
        pathinj: section_between(text, MARKER_PATHINJ, MARKER_AUTHKEYS)?,
        authkeys: section_between(text, MARKER_AUTHKEYS, MARKER_PAM)?,
        pam: section_between(text, MARKER_PAM, MARKER_LISTEN)?,
        listen: section_between(text, MARKER_LISTEN, MARKER_WEB)?,
        web: section_between(text, MARKER_WEB, MARKER_HOOK)?,
        hook: section_between(text, MARKER_HOOK, MARKER_HIST)?,
        hist: section_between(text, MARKER_HIST, MARKER_ENVIRON)?,
        environ: section_between(text, MARKER_ENVIRON, MARKER_MAPS)?,
        maps: section_between(text, MARKER_MAPS, MARKER_DONE)?,
    })
}

#[derive(Debug, Clone)]
struct HijackRow {
    path: String,
    sha256: String,
    stat: StatFingerprint,
    resolved: String,
}

/// The wrapper signature is closed here, not in the remote script: the shell
/// side only nominates candidates, a row becomes a finding only when the file
/// both filters with `grep -E` and calls its real counterpart by absolute
/// path (the swallow-and-forward shape of a hijacked command).
fn parse_hijacked(section: &str, truncated: &mut bool) -> Vec<HijackRow> {
    let mut rows = Vec::new();
    for line in section.lines() {
        let line = line.trim_end_matches('\r');
        if line == "TRUNCATED" {
            *truncated = true;
            continue;
        }
        let Some(rest) = line.strip_prefix("HIT\t") else {
            continue;
        };
        let mut fields = rest.splitn(6, '\t');
        let (Some(path), Some(sha256), Some(stat), Some(resolved), Some(sig_grep), Some(sig_call)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        if !is_allowed_response_path(path) || !is_sha256_hex(sha256) {
            continue;
        }
        let name = path.rsplit('/').next().unwrap_or_default();
        if !is_valid_command_name(name) {
            continue;
        }
        if !sig_grep.contains("grep -E") {
            continue;
        }
        let calls_real = sig_call.contains(&format!("/usr/bin/{name}"))
            || sig_call.contains(&format!("/bin/{name}"));
        if !calls_real {
            continue;
        }
        let Some(stat) = StatFingerprint::parse(stat) else {
            continue;
        };
        rows.push(HijackRow {
            path: path.to_owned(),
            sha256: sha256.to_owned(),
            stat,
            resolved: clip_evidence(resolved),
        });
    }
    rows
}

#[derive(Debug, Clone)]
struct DetectedAccount {
    username: String,
    uid: u32,
    home: String,
}

fn parse_uid0_accounts(section: &str, truncated: &mut bool) -> Vec<DetectedAccount> {
    let mut accounts = Vec::new();
    for line in section.lines() {
        let line = line.trim_end_matches('\r');
        if line == "TRUNCATED" {
            *truncated = true;
            continue;
        }
        let mut fields = line.splitn(3, '\t');
        let (Some(username), Some(uid), Some(home)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if !is_valid_username(username) {
            continue;
        }
        let Ok(uid) = uid.parse::<u32>() else {
            continue;
        };
        if uid != 0 {
            continue;
        }
        accounts.push(DetectedAccount {
            username: username.to_owned(),
            uid,
            home: clip_evidence(home),
        });
    }
    accounts
}

/// One row of the passwd scan section: username, uid, gid, home, shell.
#[derive(Debug, Clone)]
struct PasswdAccount {
    username: String,
    uid: u32,
    gid: u32,
    home: String,
    shell: String,
}

fn parse_passwd_accounts(
    section: &str,
    truncated: &mut bool,
    gaps: &mut Vec<String>,
) -> Vec<PasswdAccount> {
    let mut accounts = Vec::new();
    for line in section.lines() {
        let line = line.trim_end_matches('\r');
        if line == "TRUNCATED" {
            *truncated = true;
            continue;
        }
        if let Some(gap) = line.strip_prefix("GAP\t") {
            gaps.push(gap.to_owned());
            continue;
        }
        let mut fields = line.splitn(5, '\t');
        let (Some(username), Some(uid), Some(gid), Some(home), Some(shell)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        if !is_valid_username(username) {
            continue;
        }
        let (Ok(uid), Ok(gid)) = (uid.parse::<u32>(), gid.parse::<u32>()) else {
            continue;
        };
        accounts.push(PasswdAccount {
            username: username.to_owned(),
            uid,
            gid,
            home: clip_evidence(home),
            shell: clip_evidence(shell),
        });
    }
    accounts
}

/// A passwd row is a suspicious login account only when every condition holds:
/// non-system uid (uid 0 non-root rows belong to the uid-zero detector), a
/// real interactive shell from the closed set, not the account this session
/// logged in with, and not already flagged by the uid-zero or empty-password
/// detectors (an empty-password account is reported once, under that kind).
fn is_suspicious_login_account(
    account: &PasswdAccount,
    session_user: Option<&str>,
    flagged: &[String],
) -> bool {
    account.uid >= 1000
        && INTERACTIVE_SHELLS.contains(&account.shell.as_str())
        && session_user != Some(account.username.as_str())
        && !flagged.iter().any(|name| name == &account.username)
}

fn parse_empty_password_accounts(section: &str, gaps: &mut Vec<String>) -> Vec<String> {
    let mut names = Vec::new();
    for line in section.lines() {
        let line = line.trim_end_matches('\r');
        if let Some(gap) = line.strip_prefix("GAP\t") {
            gaps.push(gap.to_owned());
            continue;
        }
        if is_valid_username(line) {
            names.push(line.to_owned());
        }
    }
    names
}

fn parse_account_lookup(output: &str) -> Vec<(String, u32, String)> {
    output
        .lines()
        .filter_map(|line| {
            let mut fields = line.trim_end_matches('\r').splitn(3, '\t');
            let (name, uid, home) = (fields.next()?, fields.next()?, fields.next()?);
            if !is_valid_username(name) {
                return None;
            }
            Some((
                name.to_owned(),
                uid.parse::<u32>().ok()?,
                clip_evidence(home),
            ))
        })
        .collect()
}

#[derive(Debug)]
struct ConfigLine {
    file: String,
    line: u32,
    text: String,
}

fn parse_config_lines(
    section: &str,
    truncated: &mut bool,
    gaps: &mut Vec<String>,
) -> Vec<ConfigLine> {
    let mut rows = Vec::new();
    for raw in section.lines() {
        let raw = raw.trim_end_matches('\r');
        if raw == "TRUNCATED" {
            *truncated = true;
            continue;
        }
        if let Some(gap) = raw.strip_prefix("GAP\t") {
            gaps.push(gap.to_owned());
            continue;
        }
        let mut fields = raw.splitn(3, '\t');
        let (Some(file), Some(line), Some(text)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if !file.starts_with('/') || file.split('/').any(|component| component == "..") {
            continue;
        }
        let Ok(line) = line.parse::<u32>() else {
            continue;
        };
        if line == 0 {
            continue;
        }
        rows.push(ConfigLine {
            file: file.to_owned(),
            line,
            text: clip_evidence(text),
        });
    }
    rows
}

#[derive(Debug)]
struct ProcessRow {
    pid: u32,
    exe: String,
    cmdline: String,
}

fn parse_process_rows(section: &str, truncated: &mut bool) -> Vec<ProcessRow> {
    let mut rows = Vec::new();
    for raw in section.lines() {
        let raw = raw.trim_end_matches('\r');
        if raw == "TRUNCATED" {
            *truncated = true;
            continue;
        }
        let mut fields = raw.splitn(3, '\t');
        let (Some(pid), Some(exe), Some(cmdline)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if !is_valid_pid(pid) {
            continue;
        }
        let Ok(pid) = pid.parse::<u32>() else {
            continue;
        };
        rows.push(ProcessRow {
            pid,
            exe: clip_evidence(exe),
            cmdline: clip_evidence(cmdline),
        });
    }
    rows
}

#[derive(Debug)]
struct ProcessCluster {
    body_path: Option<String>,
    pids: Vec<u32>,
    sample: String,
}

fn cluster_backdoor_processes(rows: Vec<ProcessRow>) -> Vec<ProcessCluster> {
    let mut clusters: BTreeMap<String, ProcessCluster> = BTreeMap::new();
    for row in rows {
        // Our own scan/verify shells carry the marker in their command line;
        // without this exclusion the scanner would report itself.
        if row.cmdline.contains(SELF_MARKER) {
            continue;
        }
        let exe = row.exe.trim_end_matches(" (deleted)").to_owned();
        let body_token = row
            .cmdline
            .split_whitespace()
            .find(|token| {
                SUSPICIOUS_EXEC_PREFIXES
                    .iter()
                    .any(|prefix| token.starts_with(prefix))
            })
            .map(str::to_owned);
        let exe_suspicious = SUSPICIOUS_EXEC_PREFIXES
            .iter()
            .any(|prefix| exe.starts_with(prefix));
        if body_token.is_none() && !exe_suspicious {
            continue;
        }
        let body_path = body_token.filter(|token| is_allowed_response_path(token));
        let key = body_path.clone().unwrap_or_else(|| {
            if exe_suspicious {
                exe.clone()
            } else {
                format!(
                    "cmdline:{}",
                    row.cmdline.chars().take(64).collect::<String>()
                )
            }
        });
        let cluster = clusters.entry(key).or_insert_with(|| ProcessCluster {
            body_path: body_path.clone(),
            pids: Vec::new(),
            sample: row.cmdline.clone(),
        });
        cluster.pids.push(row.pid);
    }
    clusters.into_values().collect()
}

fn is_effective_config_line(text: &str) -> bool {
    let trimmed = text.trim_start();
    !trimmed.is_empty() && !trimmed.starts_with('#')
}

fn line_mentions_account(line: &str, account: &str) -> bool {
    line.split(|character: char| {
        character.is_whitespace() || matches!(character, ',' | ':' | '(' | ')' | '=' | '!')
    })
    .any(|token| token == account)
}

fn classify_sudoers_line(text: &str, flagged_accounts: &[String]) -> Option<ResponseSeverity> {
    let trimmed = text.trim_start();
    if !is_effective_config_line(trimmed) || trimmed.starts_with("Defaults") {
        return None;
    }
    if flagged_accounts
        .iter()
        .any(|account| line_mentions_account(trimmed, account))
    {
        return Some(ResponseSeverity::High);
    }
    if trimmed.contains("NOPASSWD") {
        return Some(ResponseSeverity::Medium);
    }
    None
}

fn is_suspicious_cron_line(text: &str) -> bool {
    let trimmed = text.trim_start();
    if !is_effective_config_line(trimmed) {
        return false;
    }
    // Environment assignments such as SHELL=/bin/sh or PATH=... are not jobs.
    let head = trimmed.split_whitespace().next().unwrap_or_default();
    if !head.starts_with('@')
        && head.contains('=')
        && head.split('=').next().is_some_and(|name| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte == b'_')
        })
    {
        return false;
    }
    CRON_SUSPICIOUS_TOKENS
        .iter()
        .any(|token| trimmed.contains(token))
}

fn clip_evidence(text: &str) -> String {
    text.chars().take(MAX_EVIDENCE_CHARS).collect()
}

/// Evidence strings cross into the page, whose contract refuses control
/// bytes; digests keep the raw clipped text, display keeps a sanitized copy.
fn clip_display(text: &str) -> String {
    clip_evidence(text)
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

// --- ld.so.preload hijack ---------------------------------------------------

#[derive(Debug)]
struct PreloadHit {
    sha256: String,
    stat: StatFingerprint,
    libs: Vec<TrackedPath>,
    /// Referenced libraries that are missing on disk or outside the fix
    /// whitelist; they are evidence, not fix targets.
    unresolved: Vec<String>,
}

fn parse_preload_section(section: &str, truncated: &mut bool) -> Option<PreloadHit> {
    let mut preload: Option<(String, StatFingerprint)> = None;
    let mut libs = Vec::new();
    let mut unresolved = Vec::new();
    for line in section.lines() {
        let line = line.trim_end_matches('\r');
        if line == "TRUNCATED" {
            *truncated = true;
            continue;
        }
        if let Some(rest) = line.strip_prefix("PRELOAD\t") {
            let mut fields = rest.splitn(2, '\t');
            let (Some(sha256), Some(stat)) = (fields.next(), fields.next()) else {
                continue;
            };
            if !is_sha256_hex(sha256) {
                continue;
            }
            let Some(stat) = StatFingerprint::parse(stat) else {
                continue;
            };
            preload = Some((sha256.to_owned(), stat));
        } else if let Some(rest) = line.strip_prefix("LIB\t") {
            let mut fields = rest.splitn(3, '\t');
            let (Some(path), Some(sha256), Some(stat)) =
                (fields.next(), fields.next(), fields.next())
            else {
                continue;
            };
            if !path.starts_with('/') || path.split('/').any(|component| component == "..") {
                continue;
            }
            let tracked = StatFingerprint::parse(stat)
                .filter(|_| sha256 != "MISSING" && is_sha256_hex(sha256))
                .map(|stat| TrackedPath {
                    path: path.to_owned(),
                    sha256: sha256.to_owned(),
                    stat,
                });
            match tracked {
                Some(tracked)
                    if libs.len() < MAX_LINKED_PATHS && is_allowed_response_path(&tracked.path) =>
                {
                    libs.push(tracked);
                }
                _ => unresolved.push(clip_display(path)),
            }
        }
    }
    // An existing, readable preload file with at least one library line is the
    // finding; an empty file is not.
    let (sha256, stat) = preload?;
    if libs.is_empty() && unresolved.is_empty() {
        return None;
    }
    Some(PreloadHit {
        sha256,
        stat,
        libs,
        unresolved,
    })
}

// --- PATH injection ----------------------------------------------------------

/// A startup-file line is a PATH injection when it assigns PATH and references
/// a directory that is hidden or lives under a world-writable prefix; the
/// closed standard set is never flagged. Returns the injected directories.
fn classify_path_injection_line(text: &str) -> Option<Vec<String>> {
    let trimmed = text.trim_start();
    if !is_effective_config_line(trimmed) || !trimmed.contains("PATH=") {
        return None;
    }
    let mut dirs = Vec::new();
    for token in trimmed.split(|character: char| {
        character.is_whitespace() || matches!(character, '"' | '\'' | ':' | '=' | ';')
    }) {
        if !token.starts_with('/') || token.len() < 2 || STANDARD_PATH_DIRS.contains(&token) {
            continue;
        }
        let hidden = token
            .split('/')
            .any(|component| component.len() >= 2 && component.starts_with('.'));
        let world_writable = token.starts_with("/tmp/")
            || token.starts_with("/var/tmp/")
            || token.starts_with("/dev/shm/");
        if hidden || world_writable {
            dirs.push(token.trim_end_matches('/').to_owned());
        }
    }
    dirs.sort();
    dirs.dedup();
    dirs.truncate(MAX_LINKED_PATHS);
    (!dirs.is_empty()).then_some(dirs)
}

// --- authorized_keys forced commands ----------------------------------------

/// Some(forced command path, when extractable) for an effective entry whose
/// options carry `command=`.
fn classify_authkey_line(text: &str) -> Option<Option<String>> {
    let trimmed = text.trim_start();
    if !is_effective_config_line(trimmed) {
        return None;
    }
    // Options live before the key-type token; a `command=` after it would be
    // key material, not an option.
    let key_start = [
        "ssh-rsa",
        "ssh-ed25519",
        "ecdsa-sha2-",
        "sk-ssh-",
        "sk-ecdsa-",
        "ssh-dss",
    ]
    .iter()
    .filter_map(|marker| trimmed.find(marker))
    .min();
    let options = match key_start {
        Some(start) => &trimmed[..start],
        None => trimmed,
    };
    if !options.contains("command=") {
        return None;
    }
    let after = &options[options.find("command=")? + "command=".len()..];
    let command = after
        .trim_start()
        .strip_prefix('"')
        .and_then(|rest| rest.split('"').next())
        .and_then(|inner| inner.split_whitespace().next())
        .filter(|token| token.starts_with('/'))
        .map(str::to_owned);
    Some(command)
}

// --- PAM ---------------------------------------------------------------------

fn is_pam_permit_line(text: &str) -> bool {
    let trimmed = text.trim_start();
    if !is_effective_config_line(trimmed) || !trimmed.contains("pam_permit") {
        return false;
    }
    // Only the universal-password shape counts: an `auth` rule whose control
    // field is `sufficient`. Stock distro files legitimately terminate every
    // stack with a `required pam_permit.so` (or `[default=…]` control) rule —
    // removing those breaks the whole PAM stack, so they must not match.
    let mut fields = trimmed.split_whitespace();
    matches!(
        (fields.next(), fields.next(), fields.next()),
        (Some("auth"), Some("sufficient"), Some("pam_permit.so"))
    )
}

// --- bind listeners ----------------------------------------------------------

#[derive(Debug)]
struct ListenRow {
    address: String,
    port: u16,
    loopback: bool,
    pid: Option<u32>,
    exe: String,
    cmdline: String,
}

fn parse_listen_rows(section: &str, truncated: &mut bool) -> Vec<ListenRow> {
    let mut rows = Vec::new();
    for line in section.lines() {
        let line = line.trim_end_matches('\r');
        if line == "TRUNCATED" {
            *truncated = true;
            continue;
        }
        let Some(rest) = line.strip_prefix("LIS\t") else {
            continue;
        };
        let mut fields = rest.splitn(5, '\t');
        let (Some(local), Some(_inode), Some(pid), Some(exe), Some(cmdline)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        let Some((addr_hex, port_hex)) = local.split_once(':') else {
            continue;
        };
        let Ok(port) = u16::from_str_radix(port_hex, 16) else {
            continue;
        };
        if port == 0 {
            continue;
        }
        // /proc/net/tcp prints v4 addresses as little-endian hex.
        let loopback = match addr_hex.len() {
            8 => u32::from_str_radix(addr_hex, 16)
                .map(|value| value & 0xff == 0x7f)
                .unwrap_or(false),
            32 => addr_hex == "00000000000000000000000001000000",
            _ => false,
        };
        let address = if addr_hex.len() == 8 {
            u32::from_str_radix(addr_hex, 16)
                .map(|value| {
                    format!(
                        "{}.{}.{}.{}",
                        value & 0xff,
                        (value >> 8) & 0xff,
                        (value >> 16) & 0xff,
                        (value >> 24) & 0xff
                    )
                })
                .unwrap_or_else(|_| addr_hex.to_owned())
        } else {
            addr_hex.to_owned()
        };
        rows.push(ListenRow {
            address,
            port,
            loopback,
            pid: pid.parse::<u32>().ok(),
            exe: clip_evidence(exe),
            cmdline: clip_evidence(cmdline),
        });
    }
    rows
}

// --- web files ----------------------------------------------------------------

#[derive(Debug)]
struct WebRow {
    path: String,
    sha256: String,
    stat: StatFingerprint,
    /// The matched signature line for SH3LLCAND rows.
    sig: Option<String>,
}

const WEB_SCRIPT_EXTS: &[&str] = &[".php", ".php5", ".phtml", ".jsp", ".jspx", ".asp", ".aspx"];
const WEB_BACKUP_EXTS: &[&str] = &[
    ".zip", ".tar", ".tgz", ".tbz2", ".txz", ".gz", ".bz2", ".xz", ".7z", ".rar", ".sql", ".bak",
    ".dump", ".sqlite", ".db",
];
const WEBSHELL_SIGNATURES: &[&str] = &[
    "eval($_POST",
    "eval($_REQUEST",
    "eval($_GET",
    "eval($_COOKIE",
    "eval(base64_decode",
    "assert($_",
    "assert(base64_decode",
    "Runtime.exec",
    "ProcessBuilder",
    "shell_exec($",
    "passthru($",
    "popen($",
    "system($",
];

fn parse_web_rows(section: &str, truncated: &mut bool) -> Vec<WebRow> {
    let mut rows = Vec::new();
    for line in section.lines() {
        let line = line.trim_end_matches('\r');
        if line == "TRUNCATED" {
            *truncated = true;
            continue;
        }
        let (rest, is_shell) = match line.strip_prefix("WEBCAND\t") {
            Some(rest) => (rest, false),
            None => match line.strip_prefix("SH3LLCAND\t") {
                Some(rest) => (rest, true),
                None => continue,
            },
        };
        let mut fields = rest.splitn(4, '\t');
        let (Some(path), Some(sha256), Some(stat)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let sig = if is_shell {
            fields.next().map(clip_display)
        } else {
            None
        };
        if !path.starts_with('/') || path.split('/').any(|component| component == "..") {
            continue;
        }
        if !is_sha256_hex(sha256) {
            continue;
        }
        let Some(stat) = StatFingerprint::parse(stat) else {
            continue;
        };
        rows.push(WebRow {
            path: path.to_owned(),
            sha256: sha256.to_owned(),
            stat,
            sig,
        });
        if rows.len() >= MAX_WEB_ROWS {
            *truncated = true;
            break;
        }
    }
    rows
}

fn is_web_sensitive_name(base: &str) -> bool {
    let lower = base.to_lowercase();
    if lower == ".env" || lower.starts_with(".env.") {
        return true;
    }
    let ext_ok = WEB_BACKUP_EXTS.iter().any(|ext| lower.ends_with(ext));
    ext_ok && (lower.contains("backup") || lower.contains("dump") || lower.contains("bak"))
}

fn is_webshell_candidate(path: &str, sig: &str) -> bool {
    let lower = path.to_lowercase();
    WEB_SCRIPT_EXTS.iter().any(|ext| lower.ends_with(ext))
        && WEBSHELL_SIGNATURES
            .iter()
            .any(|needle| sig.contains(needle))
}

// --- command recorder hooks ----------------------------------------------------

/// Some(log path under the whitelist, when parseable) for an effective
/// startup line whose PROMPT_COMMAND appends to a file.
fn classify_recorder_hook_line(text: &str) -> Option<Option<String>> {
    let trimmed = text.trim_start();
    if !is_effective_config_line(trimmed) {
        return None;
    }
    if !(trimmed.contains("PROMPT_COMMAND") && trimmed.contains(">>")) {
        return None;
    }
    let after = trimmed.split(">>").nth(1)?.trim_start();
    let log = after
        .split(|character: char| {
            character.is_whitespace() || matches!(character, '"' | '\'' | ';' | '&')
        })
        .find(|token| token.starts_with('/'))
        .map(str::to_owned);
    Some(log)
}

// --- history credential leaks ---------------------------------------------------

/// Closed cleartext-credential shapes in shell history: mysql-style attached
/// passwords (`-p'secret'`, `-psecret` in a mysql-ish line), `chpasswd` pipes
/// and `password=`/`passwd=` assignments with a value.
fn history_line_leaks_credential(text: &str) -> bool {
    if text.trim_start().starts_with('#') {
        return false;
    }
    let lower = text.to_lowercase();
    if lower.contains("chpasswd") {
        return true;
    }
    for key in ["password=", "passwd="] {
        if let Some(pos) = lower.find(key) {
            let value = lower[pos + key.len()..].trim_start_matches(['\'', '"']);
            if !value.is_empty() && !value.starts_with(['\'', '"', ' ', '=']) {
                return true;
            }
        }
    }
    if text.contains("-p'") || text.contains("-p\"") {
        return true;
    }
    let mysqlish = lower.contains("mysql");
    if mysqlish {
        for token in text.split_whitespace() {
            if token.starts_with("-p") && token.len() > 2 {
                return true;
            }
        }
    }
    false
}

/// Which credential shape matched, for evidence that never quotes the secret.
fn history_leak_feature(text: &str) -> &'static str {
    let lower = text.to_lowercase();
    if lower.contains("chpasswd") {
        "chpasswd 明文口令"
    } else if lower.contains("password=") || lower.contains("passwd=") {
        "password= 明文赋值"
    } else {
        "mysql -p 内联口令"
    }
}

// --- tracked secondary bodies ---------------------------------------------------

fn tracked_fingerprint_script(paths: &[String]) -> String {
    let mut script = String::new();
    for path in paths {
        script.push_str(&format!(
            "if [ -f {path} ] && [ ! -L {path} ]; then\n  sum=$(/usr/bin/sha256sum -- {path} | /usr/bin/awk '{{print $1}}')\n  fp=$(/usr/bin/stat -c '%a|%u|%g|%s|%Y' -- {path})\n  /usr/bin/printf 'FP\\t%s\\t%s\\t%s\\n' {printed} \"$sum\" \"$fp\"\nfi\n",
            path = shq(path),
            printed = shq(path),
        ));
    }
    script
}

fn parse_tracked_fingerprints(output: &str) -> BTreeMap<String, (String, StatFingerprint)> {
    let mut map = BTreeMap::new();
    for line in output.lines() {
        let Some(rest) = line.strip_prefix("FP\t") else {
            continue;
        };
        let mut fields = rest.splitn(3, '\t');
        let (Some(path), Some(sha256), Some(stat)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if !is_sha256_hex(sha256) {
            continue;
        }
        let Some(stat) = StatFingerprint::parse(stat) else {
            continue;
        };
        map.insert(path.to_owned(), (sha256.to_owned(), stat));
    }
    map
}

// ---------------------------------------------------------------------------
// issue construction
// ---------------------------------------------------------------------------

fn hijacked_issue(row: &HijackRow, privileged: bool) -> ResponseIssue {
    let name = row.path.rsplit('/').next().unwrap_or_default();
    ResponseIssue {
        kind: ResponseIssueKind::HijackedCommand,
        severity: ResponseSeverity::Critical,
        summary: format!("命令 {name} 被劫持：{} 吞改真实命令输出", row.path),
        evidence: vec![
            format!("文件：{}（内容含 grep -E 吞行逻辑并回调真身）", row.path),
            format!("sha256：{}", row.sha256),
            format!("stat：{}", row.stat.remote_form()),
            format!("当前 PATH 解析：{name} → {}", row.resolved),
        ],
        fixable: privileged,
        fix_summary: Some(
            "归档到 /var/case/bak 后删除伪造命令，并复核 PATH 解析回到系统位置".to_owned(),
        ),
        object: IssueObject::Path {
            path: row.path.clone(),
            sha256: row.sha256.clone(),
            stat: row.stat,
        },
    }
}

fn uid_zero_issue(account: DetectedAccount, privileged: bool) -> ResponseIssue {
    ResponseIssue {
        kind: ResponseIssueKind::UidZeroAccount,
        severity: ResponseSeverity::High,
        summary: format!("存在 UID 为 0 的影子账户 {}", account.username),
        evidence: vec![format!(
            "/etc/passwd：{}:x:0:0（家目录 {}）",
            account.username, account.home
        )],
        fixable: privileged,
        fix_summary: Some("userdel 删除该账户；家目录属于系统位置时仅删账户不删目录".to_owned()),
        object: IssueObject::Account {
            username: account.username,
            uid: account.uid,
            home: account.home,
        },
    }
}

fn suspicious_account_issue(account: PasswdAccount, privileged: bool) -> ResponseIssue {
    ResponseIssue {
        kind: ResponseIssueKind::SuspiciousAccount,
        severity: ResponseSeverity::Medium,
        summary: format!(
            "账户 {}（uid {}）是非系统登录账户，可能是入侵者预留",
            account.username, account.uid
        ),
        evidence: vec![format!(
            "/etc/passwd：{}:x:{}:{}（家目录 {}，shell {}）",
            account.username, account.uid, account.gid, account.home, account.shell
        )],
        fixable: privileged,
        fix_summary: Some("userdel 删除该账户；家目录属于系统位置时仅删账户不删目录".to_owned()),
        object: IssueObject::Account {
            username: account.username,
            uid: account.uid,
            home: account.home,
        },
    }
}

fn empty_password_issue(
    name: &str,
    account: Option<(u32, String)>,
    privileged: bool,
) -> ResponseIssue {
    let (uid, home, resolvable) = match account {
        Some((uid, home)) => (uid, home, true),
        None => (u32::MAX, String::new(), false),
    };
    let mut evidence = vec![format!("/etc/shadow：{name} 的口令字段为空")];
    if !resolvable {
        evidence.push("该账户在 /etc/passwd 中没有条目，无法自动锁定".to_owned());
    }
    ResponseIssue {
        kind: ResponseIssueKind::EmptyPassword,
        severity: ResponseSeverity::High,
        summary: format!("账户 {name} 的口令字段为空，可免密登录"),
        evidence,
        fixable: privileged && resolvable,
        fix_summary: Some("归档 /etc/shadow 后 passwd -l 锁定口令（不删除账户）".to_owned()),
        object: IssueObject::Account {
            username: name.to_owned(),
            uid,
            home,
        },
    }
}

fn sudoers_issue(row: &ConfigLine, severity: ResponseSeverity, privileged: bool) -> ResponseIssue {
    ResponseIssue {
        kind: ResponseIssueKind::MaliciousSudoers,
        severity,
        summary: format!("sudoers 存在可疑授权（{} 第 {} 行）", row.file, row.line),
        evidence: vec![
            format!("{}:{}: {}", row.file, row.line, row.text),
            format!("行 sha256：{}", line_sha256(&row.text)),
        ],
        fixable: privileged,
        fix_summary: Some(
            "归档后删除恶意行/文件，visudo -c 校验失败自动从归档回滚并复检".to_owned(),
        ),
        object: IssueObject::SudoersRule {
            file: row.file.clone(),
            line: row.line,
            line_sha256: line_sha256(&row.text),
        },
    }
}

fn cron_issue(row: &ConfigLine, privileged: bool) -> ResponseIssue {
    ResponseIssue {
        kind: ResponseIssueKind::CronPersistence,
        severity: ResponseSeverity::High,
        summary: format!("cron 存在可疑持久化任务（{} 第 {} 行）", row.file, row.line),
        evidence: vec![
            format!("{}:{}: {}", row.file, row.line, row.text),
            format!("行 sha256：{}", line_sha256(&row.text)),
        ],
        fixable: privileged,
        fix_summary: Some("归档后按行号与行 sha256 双复核删除该 cron 项".to_owned()),
        object: IssueObject::CronEntry {
            file: row.file.clone(),
            line: row.line,
            line_sha256: line_sha256(&row.text),
        },
    }
}

fn backdoor_issue(cluster: ProcessCluster, privileged: bool) -> ResponseIssue {
    let fixable = privileged && cluster.body_path.is_some();
    let (body, mut evidence) = match &cluster.body_path {
        Some(path) => (path.clone(), vec![format!("后门本体：{path}")]),
        None => (
            String::new(),
            vec!["可疑进程不在可自动修复的路径白名单内，需人工处置".to_owned()],
        ),
    };
    evidence.push(format!("PID：{:?}", cluster.pids));
    evidence.push(format!("命令行样例：{}", cluster.sample));
    ResponseIssue {
        kind: ResponseIssueKind::BackdoorProcess,
        severity: ResponseSeverity::High,
        summary: if body.is_empty() {
            format!("发现可疑后门进程（PID {:?}）", cluster.pids)
        } else {
            format!("发现后门进程 {body}（{} 个实例运行中）", cluster.pids.len())
        },
        evidence,
        fixable,
        fix_summary: fixable.then(|| {
            "先断关联 cron 保活，再删除本体并按 /proc 复核后终止进程；70 秒后跨周期复验".to_owned()
        }),
        object: IssueObject::Process {
            pids: cluster.pids,
            exe_path: body,
            listen_port: None,
        },
    }
}

fn ld_preload_issue(hit: &PreloadHit, privileged: bool) -> ResponseIssue {
    let mut evidence = vec![
        "/etc/ld.so.preload 非空：每个新进程都会被强制注入下列动态库（readdir 等 libc 函数可能被钩子替换，ls/find/ps 都会撒谎）".to_owned(),
        format!("preload 文件 sha256：{}", hit.sha256),
    ];
    for lib in &hit.libs {
        evidence.push(format!(
            "引用库：{}（存在，属主 uid={}，sha256={}）",
            lib.path, lib.stat.uid, lib.sha256
        ));
    }
    for path in &hit.unresolved {
        evidence.push(format!(
            "引用库：{path}（不存在或不在修复白名单内，需人工确认）"
        ));
    }
    let deletable = hit.libs.len();
    ResponseIssue {
        kind: ResponseIssueKind::LdPreloadHijack,
        severity: ResponseSeverity::Critical,
        summary: format!(
            "/etc/ld.so.preload 注入了 {} 个动态库，系统命令输出不可信",
            deletable + hit.unresolved.len()
        ),
        evidence,
        fixable: privileged,
        fix_summary: Some("归档后删除 /etc/ld.so.preload 及其引用的在白名单内的动态库".to_owned()),
        object: IssueObject::LdPreload {
            file: "/etc/ld.so.preload".to_owned(),
            sha256: hit.sha256.clone(),
            stat: hit.stat,
            libs: hit.libs.clone(),
        },
    }
}

fn path_injection_issue(
    row: &ConfigLine,
    dirs: &[String],
    hijack_rows: &[HijackRow],
    privileged: bool,
) -> ResponseIssue {
    let linked_fakes: Vec<TrackedPath> = hijack_rows
        .iter()
        .filter(|fake| {
            dirs.iter()
                .any(|dir| fake.path.starts_with(&format!("{dir}/")))
        })
        .map(|fake| TrackedPath {
            path: fake.path.clone(),
            sha256: fake.sha256.clone(),
            stat: fake.stat,
        })
        .collect();
    let mut evidence = vec![
        format!("{}:{}: {}", row.file, row.line, clip_display(&row.text)),
        format!("注入目录：{}", dirs.join(", ")),
        "只删伪命令不删注入行，下次登录伪命令会重新生效".to_owned(),
    ];
    if !linked_fakes.is_empty() {
        evidence.push(format!(
            "注入目录中的伪命令：{}",
            linked_fakes
                .iter()
                .map(|fake| fake.path.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    ResponseIssue {
        kind: ResponseIssueKind::PathInjection,
        severity: ResponseSeverity::Critical,
        summary: format!(
            "{} 第 {} 行把可疑目录注入 PATH（{}）",
            row.file,
            row.line,
            dirs.join(", ")
        ),
        evidence,
        fixable: privileged,
        fix_summary: Some(
            "归档后删除注入行（profile.d 中整文件可疑时删除整文件），并连带删除注入目录里的伪命令"
                .to_owned(),
        ),
        object: IssueObject::StartupLine {
            file: row.file.clone(),
            line: row.line,
            line_sha256: line_sha256(&row.text),
            injected_dirs: dirs.to_vec(),
            linked_fakes,
        },
    }
}

fn authkey_issue(
    row: &ConfigLine,
    command_path: &Option<String>,
    fingerprint: Option<(String, StatFingerprint)>,
    privileged: bool,
) -> ResponseIssue {
    let mut evidence = vec![format!(
        "{}:{}: {}",
        row.file,
        row.line,
        clip_display(&row.text)
    )];
    let command = match (command_path, fingerprint) {
        (Some(path), Some((sha256, stat))) => {
            evidence.push(format!("强制命令脚本：{path}（存在，sha256={sha256}）"));
            Some(TrackedPath {
                path: path.clone(),
                sha256,
                stat,
            })
        }
        (Some(path), None) => {
            evidence.push(format!("强制命令脚本：{path}（当前不存在或未取到指纹）"));
            None
        }
        (None, _) => {
            evidence.push("未能从条目中解析出强制命令的绝对路径".to_owned());
            None
        }
    };
    ResponseIssue {
        kind: ResponseIssueKind::SshKeyBackdoor,
        severity: ResponseSeverity::Critical,
        summary: format!(
            "{} 第 {} 行是 command= 强制命令后门（持钥者连接即执行攻击者脚本）",
            row.file, row.line
        ),
        evidence,
        fixable: privileged,
        fix_summary: Some(
            "归档后删除该 authorized_keys 条目（整文件均恶意时删整文件），并删除 command= 指向的脚本本体"
                .to_owned(),
        ),
        object: IssueObject::AuthKeyEntry {
            file: row.file.clone(),
            line: row.line,
            line_sha256: line_sha256(&row.text),
            command_path: command,
        },
    }
}

fn pam_backdoor_issue(row: &ConfigLine, privileged: bool) -> ResponseIssue {
    ResponseIssue {
        kind: ResponseIssueKind::PamBackdoor,
        severity: ResponseSeverity::Critical,
        summary: format!(
            "{} 第 {} 行含 pam_permit 万能密码（任意口令均可通过认证）",
            row.file, row.line
        ),
        evidence: vec![
            format!("{}:{}: {}", row.file, row.line, clip_display(&row.text)),
            format!("行 sha256：{}", line_sha256(&row.text)),
        ],
        fixable: privileged,
        fix_summary: Some("归档后按行号与行 sha256 双复核删除该 PAM 行".to_owned()),
        object: IssueObject::PamLine {
            file: row.file.clone(),
            line: row.line,
            line_sha256: line_sha256(&row.text),
        },
    }
}

fn bind_listener_issue(
    row: &ListenRow,
    process_rows: &[ProcessRow],
    privileged: bool,
) -> Option<ResponseIssue> {
    if row.cmdline.contains(SELF_MARKER) {
        return None;
    }
    let exe_suspicious = SUSPICIOUS_EXEC_PREFIXES
        .iter()
        .any(|prefix| row.exe.starts_with(prefix));
    let body_token = row
        .cmdline
        .split_whitespace()
        .find(|token| {
            SUSPICIOUS_EXEC_PREFIXES
                .iter()
                .any(|prefix| token.starts_with(prefix))
        })
        .map(str::to_owned);
    let suspicious_process = exe_suspicious || body_token.is_some();
    let unusual_loopback = row.loopback && !BENIGN_LOOPBACK_PORTS.contains(&row.port);
    if !suspicious_process && !unusual_loopback {
        return None;
    }
    let body = body_token
        .filter(|token| is_allowed_response_path(token))
        .or_else(|| {
            exe_suspicious
                .then(|| row.exe.clone())
                .filter(|exe| is_allowed_response_path(exe))
        });
    let fixable = privileged && row.pid.is_some() && body.is_some();
    let mut evidence = vec![
        format!(
            "监听：{}:{}（/proc/net/tcp(6) 直读，LISTEN 状态）",
            row.address, row.port
        ),
        format!(
            "进程：PID {}，exe={}，cmdline={}",
            row.pid
                .map(|pid| pid.to_string())
                .unwrap_or_else(|| "-".into()),
            row.exe,
            clip_display(&row.cmdline)
        ),
    ];
    // The same body may run as SEVERAL processes (a boot race can start the
    // bind script twice: one holds the socket, the others spin on
    // bind-retry). Killing only the socket holder lets a spinner grab the
    // port a moment later, so every live process of this body joins the fix.
    let mut pids: Vec<u32> = row.pid.into_iter().collect();
    if let Some(body) = body.as_deref() {
        for process in process_rows {
            if process.cmdline.contains(SELF_MARKER) || pids.contains(&process.pid) {
                continue;
            }
            if process
                .cmdline
                .split_whitespace()
                .any(|token| token == body)
                || process.exe == body
            {
                pids.push(process.pid);
            }
        }
        pids.sort_unstable();
        pids.truncate(64);
    }
    if pids.len() > 1 {
        evidence.push(format!(
            "同一本体的全部进程一并处置：{:?}（含未持 socket 的实例，防止端口被立即抢回）",
            pids
        ));
    }
    if !fixable {
        evidence.push("监听进程不在可自动修复的路径白名单内或属主不可定位，需人工处置".to_owned());
    }
    Some(ResponseIssue {
        kind: ResponseIssueKind::BindListener,
        severity: ResponseSeverity::High,
        summary: format!(
            "发现可疑监听 {}:{}（{}）",
            row.address,
            row.port,
            body.as_deref().unwrap_or("属主进程可疑")
        ),
        evidence,
        fixable,
        fix_summary: fixable.then(|| {
            "按后门进程处置链联动：先断关联 cron 保活，再删除监听脚本本体并按 /proc 复核后终止进程；70 秒后跨周期复验端口关闭"
                .to_owned()
        }),
        object: IssueObject::Process {
            pids,
            exe_path: body.unwrap_or_else(|| row.exe.clone()),
            listen_port: Some(row.port),
        },
    })
}

fn web_file_issue(row: &WebRow, privileged: bool) -> Option<ResponseIssue> {
    let base = row.path.rsplit('/').next().unwrap_or_default();
    let fixable = privileged && row.path.starts_with("/var/www/");
    match &row.sig {
        Some(sig) => {
            if !is_webshell_candidate(&row.path, sig) {
                return None;
            }
            Some(ResponseIssue {
                kind: ResponseIssueKind::Webshell,
                severity: ResponseSeverity::Critical,
                summary: format!("Web 根下发现 WebShell：{}", row.path),
                evidence: vec![
                    format!("文件：{}", row.path),
                    format!("命中特征行：{sig}"),
                    format!("sha256：{}", row.sha256),
                ],
                fixable,
                fix_summary: fixable.then(|| {
                    "归档后删除 WebShell 文件（所在隐藏目录若纯恶意则整目录删除）；复验文件不存在且业务首页仍为 200"
                        .to_owned()
                }),
                object: IssueObject::Path {
                    path: row.path.clone(),
                    sha256: row.sha256.clone(),
                    stat: row.stat,
                },
            })
        }
        None => {
            if !is_web_sensitive_name(base) {
                return None;
            }
            Some(ResponseIssue {
                kind: ResponseIssueKind::WebSensitiveFile,
                severity: ResponseSeverity::High,
                summary: format!("Web 根下存在敏感文件：{}（可直接下载泄露）", row.path),
                evidence: vec![
                    format!("文件：{}", row.path),
                    format!("sha256：{}", row.sha256),
                    format!("stat：{}", row.stat.remote_form()),
                ],
                fixable,
                fix_summary: fixable
                    .then(|| "归档后删除该文件；复验文件不存在且业务首页仍为 200".to_owned()),
                object: IssueObject::Path {
                    path: row.path.clone(),
                    sha256: row.sha256.clone(),
                    stat: row.stat,
                },
            })
        }
    }
}

fn recorder_issue(
    row: &ConfigLine,
    log_path: Option<&str>,
    fingerprint: Option<(String, StatFingerprint)>,
    privileged: bool,
) -> ResponseIssue {
    let mut evidence = vec![format!(
        "{}:{}: {}",
        row.file,
        row.line,
        clip_display(&row.text)
    )];
    let log = match (log_path, fingerprint) {
        (Some(path), Some((sha256, stat))) => {
            evidence.push(format!("录音文件：{path}（存在，sha256={sha256}）"));
            Some(TrackedPath {
                path: path.to_owned(),
                sha256,
                stat,
            })
        }
        (Some(path), None) => {
            evidence.push(format!(
                "录音文件：{path}（当前不存在，删除钩子后不会再生成）"
            ));
            None
        }
        (None, _) => None,
    };
    ResponseIssue {
        kind: ResponseIssueKind::CommandRecorder,
        severity: ResponseSeverity::High,
        summary: format!(
            "{} 第 {} 行是 PROMPT_COMMAND 命令录音钩子，交互命令被持续记录",
            row.file, row.line
        ),
        evidence,
        fixable: privileged,
        fix_summary: Some(
            "归档后删除钩子文件/行与录音文件；若删除后录音文件再次出现，说明仍有旧登录会话的钩子留在内存中，需退出全部 SSH 会话后重验"
                .to_owned(),
        ),
        object: IssueObject::RecorderHook {
            file: row.file.clone(),
            line: row.line,
            line_sha256: line_sha256(&row.text),
            log,
        },
    }
}

fn history_issue(row: &ConfigLine, privileged: bool) -> ResponseIssue {
    ResponseIssue {
        kind: ResponseIssueKind::HistoryCredentialLeak,
        severity: ResponseSeverity::Medium,
        summary: format!(
            "{} 第 {} 行含明文密码（{}）",
            row.file,
            row.line,
            history_leak_feature(&row.text)
        ),
        // The leaked secret itself never crosses into the page: only the
        // location, the matched feature and the line digest are evidence.
        evidence: vec![
            format!("{}:{}", row.file, row.line),
            format!("命中特征：{}", history_leak_feature(&row.text)),
            format!("行 sha256：{}", line_sha256(&row.text)),
        ],
        fixable: privileged,
        fix_summary: Some(
            "归档整个历史文件后按行号与行 sha256 双复核删除该行（不清空整个文件）".to_owned(),
        ),
        object: IssueObject::HistoryLine {
            file: row.file.clone(),
            line: row.line,
            line_sha256: line_sha256(&row.text),
        },
    }
}

// ---------------------------------------------------------------------------
// session-resident environment hooks and resident-library residue
// ---------------------------------------------------------------------------

struct SessionEnvRow {
    pid: u32,
    exe: String,
    prompt: String,
    ldpreload: String,
    path: String,
}

fn bounded_env_value(text: &str) -> String {
    text.chars()
        .filter(|ch| !ch.is_control())
        .take(300)
        .collect()
}

fn parse_session_env_rows(section: &str, truncated: &mut bool) -> Vec<SessionEnvRow> {
    let mut rows = Vec::new();
    for line in section.lines() {
        let line = line.trim_end_matches('\r');
        if line == "TRUNCATED" {
            *truncated = true;
            continue;
        }
        let Some(rest) = line.strip_prefix("ENVROW\t") else {
            continue;
        };
        let mut fields = rest.splitn(5, '\t');
        let (Some(pid), Some(exe), Some(prompt), Some(ldpreload), Some(path)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        let Ok(pid) = pid.parse::<u32>() else {
            continue;
        };
        if pid == 0 || !exe.starts_with('/') || exe.len() > 256 {
            continue;
        }
        rows.push(SessionEnvRow {
            pid,
            exe: exe.to_owned(),
            prompt: bounded_env_value(prompt),
            ldpreload: bounded_env_value(ldpreload),
            path: bounded_env_value(path),
        });
    }
    rows
}

/// `LD_PRELOAD` in a live session is only suspicious for values pointing at
/// deleted or attacker-favoured locations; a distro packaging variable is
/// not a finding.
fn env_preload_suspicious(value: &str) -> bool {
    let value = value.strip_prefix("LD_PRELOAD=").unwrap_or(value);
    value.split(':').any(|path| {
        path.contains("(deleted)")
            || path.starts_with("/var/tmp/")
            || path.starts_with("/tmp/")
            || path.starts_with("/dev/shm/")
            || path.starts_with("/opt/")
    })
}

fn env_path_injected(value: &str) -> bool {
    let value = value.strip_prefix("PATH=").unwrap_or(value);
    value.split(':').any(|dir| {
        let name = dir.rsplit('/').next().unwrap_or(dir);
        (name.len() >= 2 && name.starts_with('.'))
            || dir == "/var/tmp"
            || dir.starts_with("/var/tmp/")
            || dir == "/tmp"
            || dir.starts_with("/tmp/")
            || dir == "/dev/shm"
            || dir.starts_with("/dev/shm/")
    })
}

fn session_signatures(row: &SessionEnvRow) -> Vec<String> {
    let mut signatures = Vec::new();
    if row.prompt.contains(">>") {
        signatures.push("prompt-recorder".to_owned());
    }
    if env_preload_suspicious(&row.ldpreload) {
        signatures.push("resident-preload".to_owned());
    }
    if env_path_injected(&row.path) {
        signatures.push("injected-path".to_owned());
    }
    signatures
}

/// The mirror of [`session_signature_checks`] for verification: sets `ok=0`
/// when a signature IS still present, so any live process carrying the hook
/// fails the sweep.
fn session_signature_violations(signatures: &[String]) -> String {
    let mut checks = String::new();
    if signatures.iter().any(|code| code == "prompt-recorder") {
        checks.push_str("prompt=$(printf '%s\\n' \"$env_out\" | /usr/bin/grep -m1 '^PROMPT_COMMAND=' || true)\ncase \"$prompt\" in *'>>'*) ok=0 ;; esac\n");
    }
    if signatures.iter().any(|code| code == "resident-preload") {
        checks.push_str("ldpre=$(printf '%s\\n' \"$env_out\" | /usr/bin/grep -m1 '^LD_PRELOAD=' || true)\ncase \"$ldpre\" in *'(deleted)'*|*'/var/tmp/'*|*'/tmp/'*|*'/dev/shm/'*|*'/opt/'*) ok=0 ;; esac\n");
    }
    if signatures.iter().any(|code| code == "injected-path") {
        checks.push_str("pathval=$(printf '%s\\n' \"$env_out\" | /usr/bin/grep -m1 '^PATH=' || true)\ncase \"$pathval\" in */.[!.]*|*/var/tmp/*|*/tmp/*|*/dev/shm/*) ok=0 ;; esac\n");
    }
    checks
}

fn session_signature_label(code: &str) -> &'static str {
    match code {
        "prompt-recorder" => "PROMPT_COMMAND 录音钩子",
        "injected-path" => "被注入的 PATH 目录",
        _ => "驻留的 LD_PRELOAD",
    }
}

/// Processes sharing the same hooked environment form one cluster — one
/// login session tree (the shell may have exec'd away; children inherit the
/// environment verbatim). Distinct hook payloads stay distinct clusters.
struct SessionEnvCluster {
    processes: Vec<SessionEnvProcess>,
    signatures: Vec<String>,
    prompt: String,
    ldpreload: String,
    path: String,
}

fn cluster_session_env(rows: Vec<SessionEnvRow>) -> Vec<SessionEnvCluster> {
    let mut by_env: BTreeMap<(String, String, String), Vec<SessionEnvProcess>> = BTreeMap::new();
    let mut signature_of: BTreeMap<(String, String, String), Vec<String>> = BTreeMap::new();
    for row in rows {
        let signatures = session_signatures(&row);
        if signatures.is_empty() {
            continue;
        }
        let key = (row.prompt.clone(), row.ldpreload.clone(), row.path.clone());
        by_env
            .entry(key.clone())
            .or_default()
            .push(SessionEnvProcess {
                pid: row.pid,
                exe: row.exe,
            });
        signature_of.entry(key).or_insert(signatures);
    }
    by_env
        .into_iter()
        .map(|((prompt, ldpreload, path), mut processes)| {
            processes.sort_by_key(|process| process.pid);
            SessionEnvCluster {
                processes,
                signatures: signature_of
                    .remove(&(prompt.clone(), ldpreload.clone(), path.clone()))
                    .unwrap_or_default(),
                prompt,
                ldpreload,
                path,
            }
        })
        .collect()
}

fn session_env_issue(cluster: &SessionEnvCluster, privileged: bool) -> ResponseIssue {
    let signatures = &cluster.signatures;
    let mut evidence = vec![format!(
        "会话进程：{}",
        cluster
            .processes
            .iter()
            .map(|process| format!("PID {}（{}）", process.pid, process.exe))
            .collect::<Vec<_>>()
            .join("、")
    )];
    if signatures.iter().any(|code| code == "prompt-recorder") {
        evidence.push(format!("环境变量：{}", clip_display(&cluster.prompt)));
    }
    if signatures.iter().any(|code| code == "resident-preload") {
        evidence.push(format!("环境变量：{}", clip_display(&cluster.ldpreload)));
    }
    if signatures.iter().any(|code| code == "injected-path") {
        evidence.push(format!("环境变量：{}", clip_display(&cluster.path)));
    }
    evidence.push(
        "钩子在登录时写进了该会话的内存环境：删除启动文件不影响它，录音文件会被不断重建，只有终结该会话才能清除"
            .to_owned(),
    );
    let labels = signatures
        .iter()
        .map(|code| session_signature_label(code))
        .collect::<Vec<_>>()
        .join("、");
    ResponseIssue {
        kind: ResponseIssueKind::SessionEnvHook,
        severity: ResponseSeverity::Critical,
        summary: format!(
            "一个登录会话（{} 个进程）的内存环境仍驻留{}，删除启动文件清不掉它",
            cluster.processes.len(),
            labels
        ),
        evidence,
        fixable: privileged,
        fix_summary: privileged.then(|| {
            "按 /proc 逐个复核进程身份后终止该会话全部进程（TERM→KILL）；该终端里未保存的工作会丢失，复验钩子环境消失"
                .to_owned()
        }),
        object: IssueObject::SessionEnv {
            processes: cluster.processes.clone(),
            signatures: signatures.clone(),
        },
    }
}

struct ResidentLibRow {
    pid: u32,
    exe: String,
    lib: String,
}

struct ResidentLibCluster {
    lib_path: String,
    pids: Vec<u32>,
    exes: Vec<String>,
}

fn parse_resident_lib_rows(section: &str, truncated: &mut bool) -> Vec<ResidentLibRow> {
    let mut rows = Vec::new();
    for line in section.lines() {
        let line = line.trim_end_matches('\r');
        if line == "TRUNCATED" {
            *truncated = true;
            continue;
        }
        let Some(rest) = line.strip_prefix("MAPHIT\t") else {
            continue;
        };
        let mut fields = rest.splitn(3, '\t');
        let (Some(pid), Some(exe), Some(lib)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let Ok(pid) = pid.parse::<u32>() else {
            continue;
        };
        let base = lib.strip_suffix(" (deleted)").unwrap_or(lib);
        if pid == 0
            || !exe.starts_with('/')
            || exe.len() > 256
            || !is_suspicious_lib_path(base)
            || lib.len() > 512
        {
            continue;
        }
        rows.push(ResidentLibRow {
            pid,
            exe: exe.to_owned(),
            lib: base.to_owned(),
        });
    }
    rows
}

fn cluster_resident_libs(rows: Vec<ResidentLibRow>) -> Vec<ResidentLibCluster> {
    let mut by_lib: BTreeMap<String, (BTreeSet<u32>, BTreeSet<String>)> = BTreeMap::new();
    for row in rows {
        let entry = by_lib.entry(row.lib).or_default();
        entry.0.insert(row.pid);
        entry.1.insert(row.exe);
    }
    by_lib
        .into_iter()
        .map(|(lib_path, (pids, exes))| ResidentLibCluster {
            lib_path,
            pids: pids.into_iter().collect(),
            exes: exes.into_iter().collect(),
        })
        .collect()
}

/// Guidance-only: killing nginx/sshd/… just to clear a deleted mapping can
/// take the business down, so the engine reports and explains instead of
/// offering a blind kill.
fn resident_lib_issue(cluster: &ResidentLibCluster) -> ResponseIssue {
    ResponseIssue {
        kind: ResponseIssueKind::PreloadResidue,
        severity: ResponseSeverity::High,
        summary: format!(
            "已删除的 {} 仍被 {} 个运行中进程加载（内存里的钩子副本要等进程重启才消失）",
            cluster.lib_path,
            cluster.pids.len()
        ),
        evidence: vec![
            format!("PID：{:?}", cluster.pids),
            format!("进程本体：{}", cluster.exes.join(", ")),
            "新启动的进程不再加载该库；只有常驻旧进程仍带着钩子副本".to_owned(),
            "处置建议：按业务窗口重启对应服务或整机；重启前确认持久化链已全部清除，否则库文件会被重新植入"
                .to_owned(),
        ],
        fixable: false,
        fix_summary: None,
        object: IssueObject::ResidentLib {
            lib_path: cluster.lib_path.clone(),
            pids: cluster.pids.clone(),
            exes: cluster.exes.clone(),
        },
    }
}

fn stash_dir_issue(dir: &str, refs: &[String], privileged: bool) -> ResponseIssue {
    let mut unique: Vec<&String> = refs.iter().collect();
    unique.sort();
    unique.dedup();
    unique.truncate(8);
    let fixable = privileged
        && hidden_dir_ancestor(dir).as_deref() == Some(dir)
        && is_allowed_response_path(dir);
    ResponseIssue {
        kind: ResponseIssueKind::StashDir,
        severity: ResponseSeverity::High,
        summary: format!("发现后门藏匿目录 {dir}（被持久化项或后门进程引用）"),
        evidence: vec![format!(
            "引用来源：{}",
            unique
                .iter()
                .map(|r| r.as_str())
                .collect::<Vec<_>>()
                .join("；")
        )],
        fixable,
        fix_summary: fixable.then(|| {
            "归档整个目录后删除（应先完成后门进程与监听处置，避免看守进程重建）".to_owned()
        }),
        object: IssueObject::StashDir {
            path: dir.to_owned(),
        },
    }
}

// ---------------------------------------------------------------------------
// fix command builders (every interpolated value is validated + shq'd)
// ---------------------------------------------------------------------------

fn archive_prelude(archive_dir: &str, paths: &[&str]) -> String {
    let mut script = format!(
        "/usr/bin/install -d -m 700 -- {dir}\n",
        dir = shq(archive_dir)
    );
    for path in paths {
        script.push_str(&format!(
            "if [ -e {path} ]; then /usr/bin/cp -rp --parents -- {path} {dir}; fi\n",
            path = shq(path),
            dir = shq(archive_dir),
        ));
    }
    script.push_str(&format!(
        "/usr/bin/find {dir} -type f ! -name MANIFEST.sha256 -print0 | /usr/bin/sort -z | /usr/bin/xargs -0 -r /usr/bin/sha256sum > {dir}/MANIFEST.sha256\n",
        dir = shq(archive_dir),
    ));
    script
}

fn hijacked_command_fix_script(
    path: &str,
    sha256: &str,
    stat: StatFingerprint,
    archive_dir: &str,
) -> String {
    format!(
        "set -eu\n[ -f {path} ] && [ ! -L {path} ]\n[ \"$(/usr/bin/stat -c '%a|%u|%g|%s|%Y' -- {path})\" = {fp} ]\n[ \"$(/usr/bin/sha256sum -- {path} | /usr/bin/awk '{{print $1}}')\" = {sha} ]\n{archive}/usr/bin/rm -f -- {path}\n[ ! -e {path} ]\n/usr/bin/printf '%s\\n' '{FIX_OK_MARKER}'\n",
        path = shq(path),
        fp = shq(&stat.remote_form()),
        sha = shq(sha256),
        archive = archive_prelude(archive_dir, &[path]),
    )
}

/// Account removal shared by the uid-zero, empty-password-remove and
/// suspicious-account fixes. The precondition re-proves the account still
/// matches the issue kind before `userdel` runs; `-r` is added only for a home
/// under `/home/`. The four account databases (passwd/shadow/group/gshadow)
/// are archived before anything is deleted.
fn account_removal_fix_script(
    kind: ResponseIssueKind,
    username: &str,
    remove_home: bool,
    home: &str,
    archive_dir: &str,
) -> CoreResult<String> {
    let mut archived = vec!["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"];
    if remove_home {
        archived.push(home);
    }
    let flag = if remove_home { " -r" } else { "" };
    let precondition = match kind {
        ResponseIssueKind::UidZeroAccount => format!(
            "/usr/bin/awk -F: -v u={user} '$1==u && $3==0 {{found=1}} END {{exit !found}}' /etc/passwd",
            user = shq(username),
        ),
        ResponseIssueKind::EmptyPassword => format!(
            "/usr/bin/awk -F: -v u={user} '$1==u {{found=1}} END {{exit !found}}' /etc/passwd\n/usr/bin/awk -F: -v u={user} '$1==u && $2==\"\" {{found=1}} END {{exit !found}}' /etc/shadow",
            user = shq(username),
        ),
        ResponseIssueKind::SuspiciousAccount => format!(
            "/usr/bin/awk -F: -v u={user} '$1==u && $3>=1000 {{found=1}} END {{exit !found}}' /etc/passwd",
            user = shq(username),
        ),
        _ => {
            return Err(CoreError::validation(
                "response account removal",
                format!("{} 类问题不支持删除账户", kind.label()),
            ));
        }
    };
    Ok(format!(
        "set -eu\n{precondition}\n{archive}/usr/sbin/userdel -f{flag} -- {user}\nif /usr/bin/awk -F: -v u={user} '$1==u {{found=1}} END {{exit !found}}' /etc/passwd; then\n  /usr/bin/printf '%s\\n' 'account still present'\n  exit 1\nfi\n/usr/bin/printf '%s\\n' '{FIX_OK_MARKER}'\n",
        precondition = precondition,
        user = shq(username),
        archive = archive_prelude(archive_dir, &archived),
        flag = flag,
    ))
}

fn empty_password_fix_script(username: &str, archive_dir: &str) -> String {
    format!(
        "set -eu\n/usr/bin/awk -F: -v u={user} '$1==u && $2==\"\" {{found=1}} END {{exit !found}}' /etc/shadow\n{archive}/usr/bin/passwd -l {user}\n/usr/bin/awk -F: -v u={user} '$1==u && $2 ~ /^!/ {{ok=1}} $1==u && $2==\"\" {{bad=1}} END {{exit !(ok && !bad)}}' /etc/shadow\n/usr/bin/printf '%s\\n' '{FIX_OK_MARKER}'\n",
        user = shq(username),
        archive = archive_prelude(archive_dir, &["/etc/shadow"]),
    )
}

fn sudoers_fix_script(
    file: &str,
    line: u32,
    line_sha256: &str,
    delete_file: bool,
    archive_dir: &str,
) -> String {
    let removal = if delete_file {
        format!("/usr/bin/rm -f -- {file}", file = shq(file))
    } else {
        format!(
            "/usr/bin/sed -i '{line}d' -- {file}",
            line = line,
            file = shq(file)
        )
    };
    format!(
        "set -eu\n[ -f {file} ] && [ ! -L {file} ]\n[ \"$(/usr/bin/sed -n '{line}p' -- {file} | /usr/bin/sha256sum | /usr/bin/awk '{{print $1}}')\" = {sha} ]\n{archive}{removal}\nif /usr/sbin/visudo -c >/dev/null 2>&1; then\n  /usr/bin/printf '%s\\n' '{FIX_OK_MARKER}'\nelse\n  /usr/bin/cp -rp -- {adir}{file} {file}\n  /usr/sbin/visudo -c >/dev/null 2>&1 || true\n  /usr/bin/printf '%s\\n' '{FIX_ROLLBACK_MARKER}'\n  exit 3\nfi\n",
        file = shq(file),
        line = line,
        sha = shq(line_sha256),
        archive = archive_prelude(archive_dir, &[file]),
        removal = removal,
        adir = shq(archive_dir),
    )
}

fn cron_fix_script(
    file: &str,
    line: u32,
    line_sha256: &str,
    delete_file: bool,
    archive_dir: &str,
) -> String {
    let removal = if delete_file {
        format!("/usr/bin/rm -f -- {file}", file = shq(file))
    } else {
        format!(
            "/usr/bin/sed -i '{line}d' -- {file}",
            line = line,
            file = shq(file)
        )
    };
    format!(
        "set -eu\n[ -f {file} ] && [ ! -L {file} ]\n[ \"$(/usr/bin/sed -n '{line}p' -- {file} | /usr/bin/sha256sum | /usr/bin/awk '{{print $1}}')\" = {sha} ]\n{archive}{removal}\n/usr/bin/printf '%s\\n' '{FIX_OK_MARKER}'\n",
        file = shq(file),
        line = line,
        sha = shq(line_sha256),
        archive = archive_prelude(archive_dir, &[file]),
        removal = removal,
    )
}

fn backdoor_body_fix_script(exe_path: &str, archive_dir: &str) -> String {
    format!(
        "set -eu\n[ -f {exe} ]\n{archive}/usr/bin/rm -f -- {exe}\n[ ! -e {exe} ]\n/usr/bin/printf '%s\\n' '{FIX_OK_MARKER}'\n",
        exe = shq(exe_path),
        archive = archive_prelude(archive_dir, &[exe_path]),
    )
}

fn backdoor_kill_script(pids: &[u32], exe_path: &str) -> String {
    let pid_list = pids
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let pass = |signal: &str| {
        format!(
            "for pid in {pids}; do\n  if [ -d \"/proc/$pid\" ]; then\n    cmd=$(/usr/bin/tr '\\0\\n' '  ' < \"/proc/$pid/cmdline\" 2>/dev/null || true)\n    case \"$cmd\" in\n      *{SELF_MARKER}*) ;;\n      *{exe}*) kill -{signal} \"$pid\" 2>/dev/null || true ;;\n    esac\n  fi\ndone",
            pids = pid_list,
            exe = shq(exe_path),
            signal = signal,
        )
    };
    format!(
        "# {SELF_MARKER}\n{term}\nsleep 2\n{kill}\n/usr/bin/printf '%s\\n' '{FIX_OK_MARKER}'\n",
        term = pass("TERM"),
        kill = pass("KILL"),
    )
}

/// Terminate every process of one hooked session tree after re-checking
/// that each PID still resolves to the same binary. Nothing is deleted on
/// disk.
fn session_env_kill_script(processes: &[SessionEnvProcess]) -> String {
    let pass = |signal: &str| {
        let mut body = String::new();
        for process in processes {
            body.push_str(&format!(
                "if [ -d \"/proc/{pid}\" ]; then\n  live=$(/usr/bin/readlink \"/proc/{pid}/exe\" 2>/dev/null || /usr/bin/printf '%s' '-')\n  cmd=$(/usr/bin/tr '\\0\\n' '  ' < \"/proc/{pid}/cmdline\" 2>/dev/null || true)\n  case \"$cmd\" in\n    *{SELF_MARKER}*) ;;\n    *)\n      if [ \"$live\" = {exe} ] || [ \"$live\" = \"{exe} (deleted)\" ]; then\n        kill -{signal} \"{pid}\" 2>/dev/null || true\n      fi\n      ;;\n  esac\nfi\n",
                pid = process.pid,
                exe = shq(&process.exe),
                signal = signal,
            ));
        }
        body
    };
    format!(
        "# {SELF_MARKER}\n{term}\nsleep 2\n{kill}\n/usr/bin/printf '%s\\n' '{FIX_OK_MARKER}'\n",
        term = pass("TERM"),
        kill = pass("KILL"),
    )
}

/// Passed when none of the session PIDs survives, or no process on the host
/// still carries any of the flagged signatures in its environment.
fn session_env_verify_script(processes: &[SessionEnvProcess], signatures: &[String]) -> String {
    let mut checks = String::new();
    for process in processes {
        checks.push_str(&format!(
            "if [ -d \"/proc/{pid}\" ]; then\n  live=$(/usr/bin/readlink \"/proc/{pid}/exe\" 2>/dev/null || /usr/bin/printf '%s' '-')\n  if [ \"$live\" = {exe} ] || [ \"$live\" = \"{exe} (deleted)\" ]; then ok=0; fi\nfi\n",
            pid = process.pid,
            exe = shq(&process.exe),
        ));
    }
    // Belt and braces: the signatures must be gone from every live process,
    // so a respawned session carrying the same hook cannot pass unnoticed.
    // `session_signature_checks` sets ok=0 exactly when the environment still
    // shows one of the flagged signatures.
    checks.push_str(&format!(
        "for proc_dir in /proc/[0-9]*; do\n  env_out=$(/usr/bin/tr '\\0' '\\n' < \"$proc_dir/environ\" 2>/dev/null || true)\n{sig_checks}done\n",
        sig_checks = session_signature_violations(signatures),
    ));
    format!(
        "# {SELF_MARKER}\nok=1\n{checks}if [ \"$ok\" = 1 ]; then /usr/bin/printf '%s\\n' '{VERIFY_OK_MARKER}'; else /usr/bin/printf '%s\\n' '{VERIFY_FAIL_MARKER}'; fi",
    )
    .replace("{SELF_MARKER}", SELF_MARKER)
}

/// Record the observed `mode|owner|group` of every entry before changing it.
/// Pipe-separated because coreutils does not promise escape handling in `-c`
/// formats across versions, and the closed target paths never contain pipes.
fn permissions_record_script(archive_dir: &str, entries: &[PermissionEntry]) -> String {
    let mut script = format!(
        "/usr/bin/install -d -m 700 {dir}\n: > {dir}/original-permissions.txt\n",
        dir = shq(archive_dir),
    );
    for entry in entries {
        script.push_str(&format!(
            "if [ -e {path} ]; then /usr/bin/stat -c '%a|%U|%G|%n' -- {path} >> {dir}/original-permissions.txt 2>/dev/null || true; fi\n",
            path = shq(&entry.path),
            dir = shq(archive_dir),
        ));
    }
    script.push_str(&format!("/usr/bin/printf '%s\\n' '{}'\n", FIX_OK_MARKER));
    script
}

fn permissions_fix_script(entries: &[PermissionEntry]) -> String {
    let mut script = format!("# {marker}\n", marker = SELF_MARKER);
    for entry in entries {
        let Some((mode, owner, group)) = PermissionEntry::parse_triple(&entry.target) else {
            continue;
        };
        script.push_str(&format!(
            "if [ -e {path} ]; then /bin/chmod {mode} -- {path} 2>/dev/null || true; /bin/chown {owner}:{group} -- {path} 2>/dev/null || true; fi\n",
            path = shq(&entry.path),
            mode = mode,
            owner = owner,
            group = group,
        ));
    }
    script.push_str(&format!("/usr/bin/printf '%s\\n' '{}'", FIX_OK_MARKER));
    script
}

fn permissions_restore_script(archive_dir: &str) -> String {
    format!(
        "set -eu\n[ -f {dir}/original-permissions.txt ]\nwhile IFS='|' read -r mode owner group path; do\n  case \"$path\" in /etc/*|/root/*|/home/*|/var/spool/*) ;; *) continue ;; esac\n  [ -e \"$path\" ] || continue\n  /bin/chmod \"$mode\" -- \"$path\" 2>/dev/null || true\n  /bin/chown \"$owner:$group\" -- \"$path\" 2>/dev/null || true\ndone < {dir}/original-permissions.txt\n/usr/bin/printf '%s\\n' '{ok}'",
        dir = shq(archive_dir),
        ok = RESTORE_OK_MARKER,
    )
}

fn permissions_verify_script(entries: &[PermissionEntry]) -> String {
    let mut script = format!("# {marker}\nok=1\n", marker = SELF_MARKER);
    for entry in entries {
        script.push_str(&format!(
            "if [ -e {path} ]; then cur=$(/usr/bin/stat -c '%a|%U|%G' -- {path} 2>/dev/null || true); if [ \"$cur\" != {target} ]; then ok=0; fi; fi\n",
            path = shq(&entry.path),
            target = shq(&entry.target),
        ));
    }
    script.push_str(&verify_footer());
    script
}

/// Resolve auditctl on the target at run time; the plan only carries the
/// closed watch points.
const AUDITCTL_RESOLVE: &str = "AUDITCTL=$(command -v auditctl 2>/dev/null || true)\n[ -n \"$AUDITCTL\" ] || { [ -x /sbin/auditctl ] && AUDITCTL=/sbin/auditctl; }\n[ -n \"$AUDITCTL\" ] || { [ -x /usr/sbin/auditctl ] && AUDITCTL=/usr/sbin/auditctl; }\n[ -n \"$AUDITCTL\" ] || { /usr/bin/printf '%s\\n' 'NO_AUDITCTL'; exit 0; }";

fn audit_watch_fix_script(points: &[String]) -> String {
    let mut script = format!(
        "# {marker}\n{resolver}\n",
        marker = SELF_MARKER,
        resolver = AUDITCTL_RESOLVE
    );
    for point in points {
        script.push_str(&format!(
            "\"$AUDITCTL\" -w {point} -p wa -k {key} >/dev/null 2>&1 || true\n",
            point = shq(point),
            key = AUDIT_WATCH_KEY,
        ));
    }
    script.push_str(&format!("/usr/bin/printf '%s\\n' '{}'", FIX_OK_MARKER));
    script
}

fn audit_watch_restore_script(points: &[String]) -> String {
    let mut script = format!("set -eu\n{resolver}\n", resolver = AUDITCTL_RESOLVE);
    for point in points {
        script.push_str(&format!(
            "\"$AUDITCTL\" -W {point} -p wa -k {key} >/dev/null 2>&1 || true\n",
            point = shq(point),
            key = AUDIT_WATCH_KEY,
        ));
    }
    script.push_str(&format!("/usr/bin/printf '%s\\n' '{}'", RESTORE_OK_MARKER));
    script
}

fn audit_watch_verify_script(points: &[String]) -> String {
    let mut script = format!(
        "# {marker}\n{resolver}\nok=1\nrules=$(\"$AUDITCTL\" -l 2>/dev/null || true)\n",
        marker = SELF_MARKER,
        resolver = AUDITCTL_RESOLVE,
    );
    for point in points {
        script.push_str(&format!(
            "if ! printf '%s\\n' \"$rules\" | /usr/bin/grep -Fq -- {point}; then ok=0; fi\nif ! printf '%s\\n' \"$rules\" | /usr/bin/grep -Fq -- {key}; then ok=0; fi\n",
            point = shq(point),
            key = shq(AUDIT_WATCH_KEY),
        ));
    }
    script.push_str(&verify_footer());
    script
}

/// Hash the closed hardening file set into the manifest. Bounded to
/// [`MAX_SNAPSHOT_FILES`] entries so a crowded /etc cannot blow up the run.
/// The glob list stays on one `for` line: dash rejects a newline right after
/// `in`, and the fix script runs under `/bin/sh`.
fn snapshot_fix_script() -> String {
    let globs = HARDENING_SNAPSHOT_GLOBS.join(" ");
    format!(
        "# {marker}\n/usr/bin/install -d -m 700 {dir}\nlist=$(for g in {globs}; do for f in $g; do [ -f \"$f\" ] && [ ! -L \"$f\" ] && printf '%s\\n' \"$f\"; done; done | /usr/bin/sort -u | /usr/bin/head -n {max})\n[ -n \"$list\" ]\n: > {manifest}.tmp\nwhile IFS= read -r f; do\n  sum=$(/usr/bin/sha256sum -- \"$f\" 2>/dev/null | /usr/bin/awk '{{print $1}}')\n  [ -n \"$sum\" ] && /usr/bin/printf '%s %s\\n' \"$sum\" \"$f\" >> {manifest}.tmp\ndone <<EOF2\n$list\nEOF2\n[ -s {manifest}.tmp ]\n/bin/mv -f -- {manifest}.tmp {manifest}\n/bin/chmod 600 -- {manifest}\n/usr/bin/printf '%s\\n' '{ok}'",
        marker = SELF_MARKER,
        dir = shq(HARDENING_MANIFEST_DIR),
        manifest = shq(HARDENING_MANIFEST),
        max = MAX_SNAPSHOT_FILES,
        globs = globs,
        ok = FIX_OK_MARKER,
    )
}

fn snapshot_restore_script() -> String {
    format!(
        "set -eu\n[ -f {manifest} ]\n/bin/rm -f -- {manifest}\n/usr/bin/printf '%s\\n' '{ok}'",
        manifest = shq(HARDENING_MANIFEST),
        ok = RESTORE_OK_MARKER,
    )
}

/// The manifest must exist, be non-empty and (spot-checked) still match the
/// files it froze.
fn snapshot_verify_script() -> String {
    format!(
        "# {marker}\nok=1\n[ -s {manifest} ] || ok=0\nn=0\nwhile IFS= read -r line; do\n  n=$((n+1)); [ $n -gt 8 ] && break\n  sum=$(printf '%s' \"$line\" | /usr/bin/awk '{{print $1}}')\n  p=${{line#* }}\n  [ -n \"$p\" ] || continue\n  if [ ! -e \"$p\" ]; then continue; fi\n  cur=$(/usr/bin/sha256sum -- \"$p\" 2>/dev/null | /usr/bin/awk '{{print $1}}')\n  [ \"$cur\" = \"$sum\" ] || ok=0\ndone < {manifest}\nif [ \"$ok\" = 1 ]; then /usr/bin/printf '%s\\n' '{ok_marker}'; else /usr/bin/printf '%s\\n' '{fail_marker}'; fi",
        marker = SELF_MARKER,
        manifest = shq(HARDENING_MANIFEST),
        ok_marker = VERIFY_OK_MARKER,
        fail_marker = VERIFY_FAIL_MARKER,
    )
}

fn file_restore_script(archive_dir: &str, path: &str) -> String {
    format!(
        "set -eu\n[ -f {backup} ] && [ ! -L {backup} ]\n/usr/bin/cp -rp -- {backup} {path}\n/usr/bin/printf '%s\\n' '{RESTORE_OK_MARKER}'\n",
        backup = shq(&format!("{archive_dir}{path}")),
        path = shq(path),
    )
}

/// Restore a whole directory archived with `cp -rp --parents`.
fn dir_restore_script(archive_dir: &str, path: &str) -> String {
    format!(
        "set -eu\n[ -d {backup} ]\n[ ! -e {path} ]\n/usr/bin/cp -rp -- {backup} {path}\n/usr/bin/printf '%s\\n' '{RESTORE_OK_MARKER}'\n",
        backup = shq(&format!("{archive_dir}{path}")),
        path = shq(path),
    )
}

/// Re-check (stat + sha256) and delete one tracked secondary body, tolerating
/// a path that already vanished (a sibling fix may have removed it) but
/// refusing a path whose fingerprint changed since the scan.
fn tracked_delete_fix_script(tracked: &TrackedPath, archive_dir: &str) -> String {
    format!(
        "set -eu\n{archive}if [ -e {path} ]; then\n  [ -f {path} ] && [ ! -L {path} ]\n  [ \"$(/usr/bin/stat -c '%a|%u|%g|%s|%Y' -- {path})\" = {fp} ]\n  [ \"$(/usr/bin/sha256sum -- {path} | /usr/bin/awk '{{print $1}}')\" = {sha} ]\n  /usr/bin/rm -f -- {path}\nfi\n[ ! -e {path} ]\n/usr/bin/printf '%s\\n' '{FIX_OK_MARKER}'\n",
        archive = archive_prelude(archive_dir, &[tracked.path.as_str()]),
        path = shq(&tracked.path),
        fp = shq(&tracked.stat.remote_form()),
        sha = shq(&tracked.sha256),
    )
}

/// `/etc/ld.so.preload` plus every library it references; deleting the preload
/// file first instantly unhooks `readdir` for newly spawned processes.
fn ld_preload_fix_script(
    file: &str,
    sha256: &str,
    stat: StatFingerprint,
    libs: &[TrackedPath],
    archive_dir: &str,
) -> String {
    let mut paths: Vec<&str> = vec![file];
    paths.extend(libs.iter().map(|lib| lib.path.as_str()));
    let mut script = format!(
        "set -eu\n[ -f {file} ] && [ ! -L {file} ]\n[ \"$(/usr/bin/stat -c '%a|%u|%g|%s|%Y' -- {file})\" = {fp} ]\n[ \"$(/usr/bin/sha256sum -- {file} | /usr/bin/awk '{{print $1}}')\" = {sha} ]\n{archive}/usr/bin/rm -f -- {file}\n[ ! -e {file} ]\n",
        file = shq(file),
        fp = shq(&stat.remote_form()),
        sha = shq(sha256),
        archive = archive_prelude(archive_dir, &paths),
    );
    for lib in libs {
        script.push_str(&format!(
            "if [ -e {path} ]; then\n  [ -f {path} ] && [ ! -L {path} ]\n  [ \"$(/usr/bin/stat -c '%a|%u|%g|%s|%Y' -- {path})\" = {fp} ]\n  [ \"$(/usr/bin/sha256sum -- {path} | /usr/bin/awk '{{print $1}}')\" = {sha} ]\n  /usr/bin/rm -f -- {path}\nfi\n",
            path = shq(&lib.path),
            fp = shq(&lib.stat.remote_form()),
            sha = shq(&lib.sha256),
        ));
    }
    script.push_str(&format!("/usr/bin/printf '%s\\n' '{FIX_OK_MARKER}'\n"));
    script
}

fn ld_preload_restore_script(archive_dir: &str, file: &str, libs: &[TrackedPath]) -> String {
    let mut script = String::from("set -eu\n");
    for lib in libs {
        script.push_str(&format!(
            "if [ -f {backup} ]; then /usr/bin/cp -rp -- {backup} {path}; fi\n",
            backup = shq(&format!("{archive_dir}{}", lib.path)),
            path = shq(&lib.path),
        ));
    }
    script.push_str(&format!(
        "[ -f {backup} ] && [ ! -L {backup} ]\n/usr/bin/cp -rp -- {backup} {path}\n/usr/bin/printf '%s\\n' '{RESTORE_OK_MARKER}'\n",
        backup = shq(&format!("{archive_dir}{file}")),
        path = shq(file),
    ));
    script
}

/// Fake wrapper commands living inside PATH-injected directories. Each is
/// re-checked before deletion; one already removed by the hijacked-command
/// fix is skipped, one that changed aborts the step.
fn fake_cleanup_fix_script(fakes: &[TrackedPath], archive_dir: &str) -> String {
    let paths: Vec<&str> = fakes.iter().map(|fake| fake.path.as_str()).collect();
    let mut script = format!(
        "set -eu\n{archive}",
        archive = archive_prelude(archive_dir, &paths),
    );
    for fake in fakes {
        script.push_str(&format!(
            "if [ -e {path} ]; then\n  [ -f {path} ] && [ ! -L {path} ]\n  [ \"$(/usr/bin/stat -c '%a|%u|%g|%s|%Y' -- {path})\" = {fp} ]\n  [ \"$(/usr/bin/sha256sum -- {path} | /usr/bin/awk '{{print $1}}')\" = {sha} ]\n  /usr/bin/rm -f -- {path}\nfi\n",
            path = shq(&fake.path),
            fp = shq(&fake.stat.remote_form()),
            sha = shq(&fake.sha256),
        ));
    }
    script.push_str(&format!("/usr/bin/printf '%s\\n' '{FIX_OK_MARKER}'\n"));
    script
}

/// Hidden stash directory: archived whole, then removed recursively. The path
/// passed closed validation (hidden dir under a world-writable prefix, never
/// a denylisted system dir).
fn stash_dir_fix_script(path: &str, archive_dir: &str) -> String {
    format!(
        "set -eu\n[ -d {path} ] && [ ! -L {path} ]\n{archive}/usr/bin/rm -rf -- {path}\n[ ! -e {path} ]\n/usr/bin/printf '%s\\n' '{FIX_OK_MARKER}'\n",
        path = shq(path),
        archive = archive_prelude(archive_dir, &[path]),
    )
}

/// Web file fix: delete the file, or the whole hidden directory when the plan
/// proved it contained nothing else.
fn web_file_fix_script(
    path: &str,
    sha256: &str,
    stat: StatFingerprint,
    delete_dir: Option<&str>,
    archive_dir: &str,
) -> String {
    let archived: Vec<&str> = match delete_dir {
        Some(dir) => vec![dir],
        None => vec![path],
    };
    let removal = match delete_dir {
        Some(dir) => format!("/usr/bin/rm -rf -- {dir}", dir = shq(dir)),
        None => format!("/usr/bin/rm -f -- {path}", path = shq(path)),
    };
    format!(
        "set -eu\n[ -f {path} ] && [ ! -L {path} ]\n[ \"$(/usr/bin/stat -c '%a|%u|%g|%s|%Y' -- {path})\" = {fp} ]\n[ \"$(/usr/bin/sha256sum -- {path} | /usr/bin/awk '{{print $1}}')\" = {sha} ]\n{archive}{removal}\n[ ! -e {path} ]\n/usr/bin/printf '%s\\n' '{FIX_OK_MARKER}'\n",
        path = shq(path),
        fp = shq(&stat.remote_form()),
        sha = shq(sha256),
        archive = archive_prelude(archive_dir, &archived),
        removal = removal,
    )
}

/// Shell snippet (expects an `ok=1` variable in scope) that fails verification
/// when any line of `file` still hashes to `line_sha256`. Whole-file digest
/// search, so a second identical-looking line elsewhere cannot mask a miss.
fn line_absent_check(file: &str, line_sha256: &str) -> String {
    format!(
        "if [ -e {file} ]; then\n  while IFS= read -r hawk_line || [ -n \"$hawk_line\" ]; do\n    if [ \"$(/usr/bin/printf '%s\\n' \"$hawk_line\" | /usr/bin/sha256sum | /usr/bin/awk '{{print $1}}')\" = {sha} ]; then ok=0; fi\n  done < {file}\nfi\n",
        file = shq(file),
        sha = shq(line_sha256),
    )
}

fn verify_footer() -> String {
    format!(
        "if [ \"$ok\" = 1 ]; then /usr/bin/printf '%s\\n' '{VERIFY_OK_MARKER}'; else /usr/bin/printf '%s\\n' '{VERIFY_FAIL_MARKER}'; fi\n"
    )
}

fn startup_line_verify_script(
    file: &str,
    line_sha256: &str,
    delete_file: bool,
    linked_fakes: &[TrackedPath],
) -> String {
    let mut script = String::from("ok=1\n");
    if delete_file {
        script.push_str(&format!(
            "if [ -e {file} ]; then ok=0; fi\n",
            file = shq(file)
        ));
    } else {
        script.push_str(&line_absent_check(file, line_sha256));
    }
    for fake in linked_fakes {
        script.push_str(&format!(
            "if [ -e {path} ]; then ok=0; fi\n",
            path = shq(&fake.path)
        ));
    }
    script.push_str(&verify_footer());
    script
}

fn recorder_verify_script(
    file: &str,
    line_sha256: &str,
    delete_file: bool,
    log_path: Option<&str>,
) -> String {
    let mut script = String::from("ok=1\n");
    if delete_file {
        script.push_str(&format!(
            "if [ -e {file} ]; then ok=0; fi\n",
            file = shq(file)
        ));
    } else {
        script.push_str(&line_absent_check(file, line_sha256));
    }
    if let Some(log) = log_path {
        script.push_str(&format!("if [ -e {log} ]; then ok=0; fi\n", log = shq(log)));
    }
    script.push_str(&verify_footer());
    script
}

fn authkey_verify_script(
    file: &str,
    line_sha256: &str,
    delete_file: bool,
    command_path: Option<&TrackedPath>,
) -> String {
    let mut script = String::from("ok=1\n");
    if delete_file {
        script.push_str(&format!(
            "if [ -e {file} ]; then ok=0; fi\n",
            file = shq(file)
        ));
    } else {
        script.push_str(&line_absent_check(file, line_sha256));
    }
    if let Some(command) = command_path {
        script.push_str(&format!(
            "if [ -e {path} ]; then ok=0; fi\n",
            path = shq(&command.path)
        ));
    }
    script.push_str(&verify_footer());
    script
}

/// PAM verification is pattern-based, not line-based: after the fix the file
/// must carry no effective `pam_permit.so` line at all, so a second stacked
/// backdoor line in the same file still fails verification honestly.
fn pam_verify_script(file: &str) -> String {
    format!(
        "ok=1\nif [ -e {file} ]; then\n  if /usr/bin/grep -v '^[[:space:]]*#' -- {file} 2>/dev/null | /usr/bin/grep -q 'pam_permit'; then ok=0; fi\nfi\n{footer}",
        file = shq(file),
        footer = verify_footer(),
    )
}

/// Web verification: the file (and the hidden directory when taken) must be
/// gone; when the business front page answered 200 at plan time it still
/// must, so a fix can never silently kill the site.
fn web_verify_script(path: &str, delete_dir: Option<&str>, business_ok: Option<bool>) -> String {
    let mut script = format!("ok=1\nif [ -e {path} ]; then ok=0; fi\n", path = shq(path));
    if let Some(dir) = delete_dir {
        script.push_str(&format!("if [ -e {dir} ]; then ok=0; fi\n", dir = shq(dir)));
    }
    if business_ok == Some(true) {
        script.push_str(
            "if [ -x /usr/bin/python3 ]; then\n  /usr/bin/python3 -c 'import urllib.request;print(\"BUSINESS_OK\" if urllib.request.urlopen(\"http://127.0.0.1/\",timeout=5).status==200 else \"BUSINESS_FAIL\")' 2>/dev/null | /usr/bin/grep -q '^BUSINESS_OK$' || ok=0\nfi\n",
        );
    }
    script.push_str(&verify_footer());
    script
}

fn verify_script_for(
    kind: ResponseIssueKind,
    object: &IssueObject,
    mode: FixMode,
) -> CoreResult<String> {
    let script = match (kind, object) {
        (ResponseIssueKind::HijackedCommand, IssueObject::Path { path, .. }) => {
            let name = path.rsplit('/').next().unwrap_or_default();
            if !is_valid_command_name(name) {
                return Err(CoreError::validation(
                    "response verify",
                    "invalid command name in path object",
                ));
            }
            format!(
                "ok=1\nif [ -e {path} ]; then ok=0; fi\nresolved=$(command -v {name} 2>/dev/null || true)\ncase \"$resolved\" in\n  /usr/bin/{name}|/bin/{name}) ;;\n  *) ok=0 ;;\nesac\nif [ \"$ok\" = 1 ]; then /usr/bin/printf '%s\\n' '{VERIFY_OK_MARKER}'; else /usr/bin/printf '%s\\n' '{VERIFY_FAIL_MARKER}'; fi\n",
                path = shq(path),
                name = shq(name),
            )
        }
        (ResponseIssueKind::UidZeroAccount, IssueObject::Account { username, .. }) => format!(
            "if /usr/bin/awk -F: -v u={user} '$1==u && $3==0 {{found=1}} END {{exit !found}}' /etc/passwd; then /usr/bin/printf '%s\\n' '{VERIFY_FAIL_MARKER}'; else /usr/bin/printf '%s\\n' '{VERIFY_OK_MARKER}'; fi\n",
            user = shq(username),
        ),
        (ResponseIssueKind::EmptyPassword, IssueObject::Account { username, .. }) => match mode {
            FixMode::Lock => format!(
                "if /usr/bin/awk -F: -v u={user} '$1==u && $2==\"\" {{found=1}} END {{exit !found}}' /etc/shadow; then /usr/bin/printf '%s\\n' '{VERIFY_FAIL_MARKER}'; else /usr/bin/printf '%s\\n' '{VERIFY_OK_MARKER}'; fi\n",
                user = shq(username),
            ),
            // Removal is verified against both account databases: the account
            // must be gone from /etc/passwd and carry no shadow entry at all.
            FixMode::Remove => format!(
                "ok=1\nif /usr/bin/awk -F: -v u={user} '$1==u {{found=1}} END {{exit !found}}' /etc/passwd; then ok=0; fi\nif /usr/bin/awk -F: -v u={user} '$1==u {{found=1}} END {{exit !found}}' /etc/shadow; then ok=0; fi\nif [ \"$ok\" = 1 ]; then /usr/bin/printf '%s\\n' '{VERIFY_OK_MARKER}'; else /usr/bin/printf '%s\\n' '{VERIFY_FAIL_MARKER}'; fi\n",
                user = shq(username),
            ),
        },
        // A removed suspicious account must be gone from both account
        // databases, same bar as empty-password removal.
        (ResponseIssueKind::SuspiciousAccount, IssueObject::Account { username, .. }) => format!(
            "ok=1\nif /usr/bin/awk -F: -v u={user} '$1==u {{found=1}} END {{exit !found}}' /etc/passwd; then ok=0; fi\nif /usr/bin/awk -F: -v u={user} '$1==u {{found=1}} END {{exit !found}}' /etc/shadow; then ok=0; fi\nif [ \"$ok\" = 1 ]; then /usr/bin/printf '%s\\n' '{VERIFY_OK_MARKER}'; else /usr/bin/printf '%s\\n' '{VERIFY_FAIL_MARKER}'; fi\n",
            user = shq(username),
        ),
        (
            ResponseIssueKind::MaliciousSudoers,
            IssueObject::SudoersRule {
                file,
                line,
                line_sha256,
            },
        ) => format!(
            "ok=1\nif [ -e {file} ]; then\n  if [ \"$(/usr/bin/sed -n '{line}p' -- {file} 2>/dev/null | /usr/bin/sha256sum | /usr/bin/awk '{{print $1}}')\" = {sha} ]; then ok=0; fi\nfi\n/usr/sbin/visudo -c >/dev/null 2>&1 || ok=0\nif [ \"$ok\" = 1 ]; then /usr/bin/printf '%s\\n' '{VERIFY_OK_MARKER}'; else /usr/bin/printf '%s\\n' '{VERIFY_FAIL_MARKER}'; fi\n",
            file = shq(file),
            line = line,
            sha = shq(line_sha256),
        ),
        (
            ResponseIssueKind::CronPersistence,
            IssueObject::CronEntry {
                file,
                line,
                line_sha256,
            },
        ) => format!(
            "ok=1\nif [ -e {file} ]; then\n  if [ \"$(/usr/bin/sed -n '{line}p' -- {file} 2>/dev/null | /usr/bin/sha256sum | /usr/bin/awk '{{print $1}}')\" = {sha} ]; then ok=0; fi\nfi\nif [ \"$ok\" = 1 ]; then /usr/bin/printf '%s\\n' '{VERIFY_OK_MARKER}'; else /usr/bin/printf '%s\\n' '{VERIFY_FAIL_MARKER}'; fi\n",
            file = shq(file),
            line = line,
            sha = shq(line_sha256),
        ),
        (ResponseIssueKind::BackdoorProcess, IssueObject::Process { exe_path, .. }) => format!(
            "# {SELF_MARKER}\nok=1\nif [ -e {exe} ]; then ok=0; fi\nfor proc_dir in /proc/[0-9]*; do\n  cmd=$(/usr/bin/tr '\\0\\n' '  ' < \"$proc_dir/cmdline\" 2>/dev/null || true)\n  case \"$cmd\" in\n    *{SELF_MARKER}*) ;;\n    *{exe}*) ok=0 ;;\n  esac\ndone\nif [ \"$ok\" = 1 ]; then /usr/bin/printf '%s\\n' '{VERIFY_OK_MARKER}'; else /usr/bin/printf '%s\\n' '{VERIFY_FAIL_MARKER}'; fi\n",
            exe = shq(exe_path),
        ),
        (ResponseIssueKind::LdPreloadHijack, IssueObject::LdPreload { file, libs, .. }) => {
            let mut script = format!(
                "ok=1\nif [ -e {file} ]; then\n  n=$(/usr/bin/grep -cv '^[[:space:]]*\\(#\\|$\\)' -- {file} 2>/dev/null || true)\n  if [ \"${{n:-0}}\" != \"0\" ]; then ok=0; fi\nfi\n",
                file = shq(file),
            );
            for lib in libs {
                script.push_str(&format!(
                    "if [ -e {path} ]; then ok=0; fi\n",
                    path = shq(&lib.path)
                ));
            }
            script.push_str(&verify_footer());
            script
        }
        (
            ResponseIssueKind::BindListener,
            IssueObject::Process {
                exe_path,
                listen_port,
                ..
            },
        ) => {
            let Some(port) = listen_port else {
                return Err(CoreError::validation(
                    "response verify",
                    "bind-listener issue must carry the listen port",
                ));
            };
            let port_hex = format!("{port:04X}");
            format!(
                "# {SELF_MARKER}\nok=1\nif [ -e {exe} ]; then ok=0; fi\nfor proc_dir in /proc/[0-9]*; do\n  cmd=$(/usr/bin/tr '\\0\\n' '  ' < \"$proc_dir/cmdline\" 2>/dev/null || true)\n  case \"$cmd\" in\n    *{SELF_MARKER}*) ;;\n    *{exe}*) ok=0 ;;\n  esac\ndone\nif /usr/bin/awk '$4==\"0A\" {{print $2}}' /proc/net/tcp /proc/net/tcp6 2>/dev/null | /usr/bin/grep -qi ':{port_hex}$'; then ok=0; fi\nif [ \"$ok\" = 1 ]; then /usr/bin/printf '%s\\n' '{VERIFY_OK_MARKER}'; else /usr/bin/printf '%s\\n' '{VERIFY_FAIL_MARKER}'; fi\n",
                exe = shq(exe_path),
                port_hex = port_hex,
            )
        }
        (ResponseIssueKind::StashDir, IssueObject::StashDir { path }) => format!(
            "ok=1\nif [ -e {path} ]; then ok=0; fi\n{footer}",
            path = shq(path),
            footer = verify_footer(),
        ),
        (
            ResponseIssueKind::HistoryCredentialLeak,
            IssueObject::HistoryLine {
                file, line_sha256, ..
            },
        ) => format!(
            "ok=1\n{check}{footer}",
            check = line_absent_check(file, line_sha256),
            footer = verify_footer(),
        ),
        _ => {
            return Err(CoreError::validation(
                "response verify",
                "issue object does not match its kind",
            ));
        }
    };
    Ok(script)
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::*;
    use crate::{
        BackendServices, PortableStore,
        ssh::{SshConnectionStatus, TestSessionHarness},
        target::TargetIdentity,
    };

    const FAKE_PS_SHA: &str = "0b9e4f6b8b05a2f6f6c2c7a2b1f0b8d6a7c9e1d2f3a4b5c6d7e8f9a0b1c2d3e4";
    const GHOST_MAINT_LINE: &str = "* * * * * root pgrep -f kmod-health >/dev/null 2>&1 || (nohup /usr/local/libexec/kmod-health >/dev/null 2>&1 &)";
    const REBOOT_LINE: &str = "@reboot /usr/local/libexec/kmod-health >/dev/null 2>&1";
    const SUDOERS_LINE: &str = "xbackup ALL=(ALL) NOPASSWD: ALL";

    fn sample_stat() -> StatFingerprint {
        StatFingerprint {
            mode: 0o755,
            uid: 0,
            gid: 0,
            size: 45,
            mtime: 1_761_696_000,
        }
    }

    fn sample_scan_output() -> String {
        format!(
            "{MARKER_HIJACK}\nHIT\t/usr/local/bin/ps\t{FAKE_PS_SHA}\t755|0|0|45|1761696000\t/usr/local/bin/ps\tgrep -E -v LOVELYRES\t/usr/bin/ps \"$@\"\nHIT\t/usr/local/bin/ls\t{FAKE_PS_SHA}\t755|0|0|43|1761696000\t/usr/local/bin/ls\tgrep -E -v LOVELYRES\t/bin/ls \"$@\"\n{MARKER_UID0}\nxbackup\t0\t/var/backups\n{MARKER_SHADOW}\nwatcher\n{MARKER_PASSWD}\nroot\t0\t0\t/root\t/bin/bash\noperator\t1000\t1000\t/home/operator\t/bin/bash\nwatcher\t1001\t1001\t/home/watcher\t/bin/sh\nsvc-backup\t1002\t1002\t/home/svc-backup\t/bin/bash\ndaemon\t1\t1\t/usr/sbin\t/usr/sbin/nologin\n{MARKER_SUDOERS}\n/etc/sudoers\t21\troot\tALL=(ALL:ALL) ALL\n/etc/sudoers.d/backup-jobs\t1\t{SUDOERS_LINE}\n{MARKER_CRON}\n/etc/crontab\t10\t17 *\t* * *	root    cd / && run-parts --report /etc/cron.hourly\n/etc/cron.d/ghost-maint\t1\t{GHOST_MAINT_LINE}\n/var/spool/cron/crontabs/root\t1\t{REBOOT_LINE}\n{MARKER_PROC}\n1\t/sbin/init\t/sbin/init\n901\t/usr/bin/bash\t/bin/bash /usr/local/libexec/kmod-health\n902\t/usr/bin/sh\t/bin/sh -c # LOVELYRES_RESPONSE_SCAN_V1 /usr/local/libexec/kmod-health\n{MARKER_PRELOAD}\n{MARKER_PATHINJ}\n{MARKER_AUTHKEYS}\n{MARKER_PAM}\n{MARKER_LISTEN}\n{MARKER_WEB}\n{MARKER_HOOK}\n{MARKER_HIST}\n{MARKER_ENVIRON}\n{MARKER_MAPS}\n{MARKER_DONE}\n"
        )
    }

    #[test]
    fn hijacked_rows_from_the_range_parse_into_path_issues() {
        let mut truncated = false;
        let rows = parse_hijacked(
            "HIT\t/usr/local/bin/ps\t0b9e4f6b8b05a2f6f6c2c7a2b1f0b8d6a7c9e1d2f3a4b5c6d7e8f9a0b1c2d3e4\t755|0|0|45|1761696000\t/usr/local/bin/ps\tgrep -E -v LOVELYRES\t/usr/bin/ps \"$@\"\n",
            &mut truncated,
        );
        assert_eq!(rows.len(), 1);
        assert!(!truncated);
        let issue = hijacked_issue(rows.first().unwrap(), true);
        assert_eq!(issue.kind, ResponseIssueKind::HijackedCommand);
        assert!(issue.fixable);
        match issue.object() {
            IssueObject::Path { path, sha256, stat } => {
                assert_eq!(path, "/usr/local/bin/ps");
                assert_eq!(sha256, FAKE_PS_SHA);
                assert_eq!(stat.mode, 0o755);
            }
            other => panic!("unexpected object {other:?}"),
        }
        issue.object().validate(issue.kind).unwrap();
    }

    #[test]
    fn uid_zero_row_from_the_range_parses_into_an_account_issue() {
        let mut truncated = false;
        let accounts = parse_uid0_accounts("xbackup\t0\t/var/backups\n", &mut truncated);
        assert_eq!(accounts.len(), 1);
        let issue = uid_zero_issue(accounts.into_iter().next().unwrap(), true);
        assert_eq!(issue.kind, ResponseIssueKind::UidZeroAccount);
        assert!(issue.summary.contains("xbackup"));
        issue.object().validate(issue.kind).unwrap();
    }

    #[test]
    fn empty_password_row_from_the_range_parses_and_gaps_surface() {
        let mut gaps = Vec::new();
        let names = parse_empty_password_accounts("watcher\n", &mut gaps);
        assert_eq!(names, ["watcher"]);
        assert!(gaps.is_empty());

        let mut gaps = Vec::new();
        let names = parse_empty_password_accounts(
            "GAP\t/etc/shadow 不可读，无法检查空口令账户\n",
            &mut gaps,
        );
        assert!(names.is_empty());
        assert_eq!(gaps.len(), 1);

        let lookup = parse_account_lookup("watcher\t1001\t/home/watcher\n");
        assert_eq!(
            lookup,
            [("watcher".to_owned(), 1001, "/home/watcher".to_owned())]
        );
    }

    fn passwd_account(username: &str, uid: u32, shell: &str) -> PasswdAccount {
        PasswdAccount {
            username: username.to_owned(),
            uid,
            gid: uid,
            home: format!("/home/{username}"),
            shell: shell.to_owned(),
        }
    }

    #[test]
    fn suspicious_account_selection_hits_locked_backdoors_and_skips_known_accounts() {
        let accounts = vec![
            // Locked-state watcher (`watcher:!:...` in shadow): the
            // empty-password detector stays silent, this detector must hit.
            passwd_account("watcher", 1001, "/bin/sh"),
            // The session's own login is never suspicious.
            passwd_account("ctfops", 1000, "/bin/bash"),
            // System shells are not login accounts.
            passwd_account("svc", 1003, "/usr/sbin/nologin"),
            passwd_account("sync-job", 1004, "/bin/sync"),
            // uid below 1000 is a system account by convention.
            passwd_account("legacy", 999, "/bin/bash"),
            // Already reported as empty-password this scan: deduped.
            passwd_account("emptyone", 1005, "/bin/bash"),
            // The full interactive-shell set is accepted.
            passwd_account("z", 1006, "/bin/zsh"),
            passwd_account("d", 1007, "/bin/dash"),
            passwd_account("a", 1008, "/bin/ash"),
        ];
        let flagged = vec!["emptyone".to_owned(), "xbackup".to_owned()];
        let hits: Vec<&str> = accounts
            .iter()
            .filter(|account| is_suspicious_login_account(account, Some("ctfops"), &flagged))
            .map(|account| account.username.as_str())
            .collect();
        assert_eq!(hits, ["watcher", "z", "d", "a"]);
        // Without a known session user the session account itself is reported;
        // scan() surfaces a gaps entry alongside in that case.
        let hits: Vec<&str> = accounts
            .iter()
            .filter(|account| is_suspicious_login_account(account, None, &flagged))
            .map(|account| account.username.as_str())
            .collect();
        assert_eq!(hits, ["watcher", "ctfops", "z", "d", "a"]);
    }

    #[test]
    fn suspicious_account_issue_carries_the_passwd_line_and_validates() {
        let issue = suspicious_account_issue(passwd_account("watcher", 1001, "/bin/sh"), true);
        assert_eq!(issue.kind, ResponseIssueKind::SuspiciousAccount);
        assert_eq!(issue.severity, ResponseSeverity::Medium);
        assert!(issue.summary.contains("可能是入侵者预留"));
        assert!(
            issue.evidence[0].contains("watcher:x:1001:1001"),
            "{:?}",
            issue.evidence
        );
        assert!(issue.evidence[0].contains("/bin/sh"));
        assert!(issue.fixable);
        issue.object().validate(issue.kind).unwrap();
        // System uids are rejected at planning time even if a row slipped in.
        let system = IssueObject::Account {
            username: "watcher".to_owned(),
            uid: 0,
            home: "/home/watcher".to_owned(),
        };
        assert!(matches!(
            system.validate(ResponseIssueKind::SuspiciousAccount),
            Err(CoreError::Validation { .. })
        ));
    }

    #[test]
    fn suspicious_account_removal_template_archives_four_databases_and_deletes() {
        let script = account_removal_fix_script(
            ResponseIssueKind::SuspiciousAccount,
            "watcher",
            true,
            "/home/watcher",
            "/var/case/bak/ts-suspicious-account",
        )
        .unwrap();
        // The precondition re-proves a non-system uid before userdel runs.
        assert!(script.contains("$1==u && $3>=1000 {found=1}"));
        assert!(script.contains("/usr/sbin/userdel -f -r -- 'watcher'"));
        for archived in [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/group",
            "/etc/gshadow",
            "/home/watcher",
        ] {
            assert!(script.contains(&format!("-- '{archived}'")), "{archived}");
        }

        // A system home is never recursively deleted, same rule as uid-zero.
        let system_home = account_removal_fix_script(
            ResponseIssueKind::SuspiciousAccount,
            "watcher",
            false,
            "/var/backups",
            "/var/case/bak/ts-suspicious-account",
        )
        .unwrap();
        assert!(system_home.contains("/usr/sbin/userdel -f -- 'watcher'"));
        assert!(!system_home.contains("userdel -f -r"));

        // Removal verifies against both account databases.
        let object = IssueObject::Account {
            username: "watcher".to_owned(),
            uid: 1001,
            home: "/home/watcher".to_owned(),
        };
        let verify =
            verify_script_for(ResponseIssueKind::SuspiciousAccount, &object, FixMode::Lock)
                .unwrap();
        assert!(verify.contains("/etc/passwd"));
        assert!(verify.contains("/etc/shadow"));
        assert!(verify.contains(VERIFY_OK_MARKER));
    }

    #[test]
    fn sudoers_classification_flags_the_range_line_and_spares_defaults() {
        let flagged = vec!["xbackup".to_owned(), "watcher".to_owned()];
        assert_eq!(
            classify_sudoers_line(SUDOERS_LINE, &flagged),
            Some(ResponseSeverity::High)
        );
        assert_eq!(
            classify_sudoers_line(
                "deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl reload nginx",
                &[]
            ),
            Some(ResponseSeverity::Medium)
        );
        for benign in [
            "root\tALL=(ALL:ALL) ALL",
            "%sudo   ALL=(ALL:ALL) ALL",
            "Defaults\tenv_reset",
            "# a comment",
            "",
        ] {
            assert_eq!(classify_sudoers_line(benign, &flagged), None, "{benign:?}");
        }
        // Mention of the account as a token only, not as a substring.
        assert_eq!(
            classify_sudoers_line("xbackup2 ALL=(ALL) ALL", &flagged),
            None
        );
    }

    #[test]
    fn cron_classification_flags_range_persistence_and_spares_stock_crontab() {
        assert!(is_suspicious_cron_line(GHOST_MAINT_LINE));
        assert!(is_suspicious_cron_line(REBOOT_LINE));
        for benign in [
            "SHELL=/bin/sh",
            "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin",
            "17 *\t* * *	root    cd / && run-parts --report /etc/cron.hourly",
            "25 6\t* * *	root\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )",
            "# m h dom mon dow user command",
        ] {
            assert!(!is_suspicious_cron_line(benign), "{benign:?}");
        }
    }

    #[test]
    fn process_classification_groups_the_range_backdoor_and_excludes_our_scan() {
        let mut truncated = false;
        let rows = parse_process_rows(
            "1\t/sbin/init\t/sbin/init\n901\t/usr/bin/bash\t/bin/bash /usr/local/libexec/kmod-health\n902\t/usr/bin/sh\t/bin/sh -c # LOVELYRES_RESPONSE_SCAN_V1 /usr/local/libexec/kmod-health\n",
            &mut truncated,
        );
        let clusters = cluster_backdoor_processes(rows);
        assert_eq!(clusters.len(), 1);
        let cluster = clusters.into_iter().next().unwrap();
        assert_eq!(
            cluster.body_path.as_deref(),
            Some("/usr/local/libexec/kmod-health")
        );
        assert_eq!(cluster.pids, [901]);
        let issue = backdoor_issue(cluster, true);
        assert!(issue.fixable);
        assert_eq!(
            issue
                .object()
                .validate(ResponseIssueKind::BackdoorProcess)
                .unwrap(),
            ()
        );
    }

    #[test]
    fn process_outside_the_path_whitelist_is_reported_but_not_fixable() {
        // A non-hidden path directly under /tmp still clusters as a backdoor
        // but stays outside the fix whitelist (only hidden stash dirs and the
        // classic libexec location are writable by a fix).
        let mut truncated = false;
        let rows = parse_process_rows("77\t/usr/bin/bash\tbash /tmp/miner\n", &mut truncated);
        let clusters = cluster_backdoor_processes(rows);
        assert_eq!(clusters.len(), 1);
        let issue = backdoor_issue(clusters.into_iter().next().unwrap(), true);
        assert!(!issue.fixable);
        assert!(issue.fix_summary.is_none());
        assert!(matches!(
            issue.object().validate(ResponseIssueKind::BackdoorProcess),
            Err(CoreError::Validation { .. })
        ));
    }

    #[test]
    fn line_digest_matches_what_sed_piped_to_sha256sum_reports() {
        // Independent vector: printf 'hello\n' | sha256sum
        assert_eq!(
            line_sha256("hello"),
            "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
        );
    }

    #[test]
    fn object_validation_rejects_traversal_foreign_paths_and_shape_mismatch() {
        let stat = sample_stat();
        for path in [
            "../../etc/passwd",
            "/usr/local/bin/../../etc/passwd",
            "/etc/hostname",
            "/usr/local/bin/",
            "usr/local/bin/ps",
        ] {
            let object = IssueObject::Path {
                path: path.to_owned(),
                sha256: FAKE_PS_SHA.to_owned(),
                stat,
            };
            assert!(
                matches!(
                    object.validate(ResponseIssueKind::HijackedCommand),
                    Err(CoreError::Validation { .. })
                ),
                "should reject {path:?}"
            );
        }

        for username in ["bad;user", "a b", "1root", "-h", ""] {
            let object = IssueObject::Account {
                username: username.to_owned(),
                uid: 0,
                home: "/var/backups".to_owned(),
            };
            assert!(
                matches!(
                    object.validate(ResponseIssueKind::UidZeroAccount),
                    Err(CoreError::Validation { .. })
                ),
                "should reject {username:?}"
            );
        }

        let non_zero = IssueObject::Account {
            username: "watcher".to_owned(),
            uid: 1001,
            home: "/home/watcher".to_owned(),
        };
        assert!(matches!(
            non_zero.validate(ResponseIssueKind::UidZeroAccount),
            Err(CoreError::Validation { .. })
        ));
        // ...while the same account shape is valid for an empty-password fix.
        non_zero.validate(ResponseIssueKind::EmptyPassword).unwrap();

        let bad_digest = IssueObject::CronEntry {
            file: "/etc/cron.d/ghost-maint".to_owned(),
            line: 1,
            line_sha256: "not-hex".to_owned(),
        };
        assert!(matches!(
            bad_digest.validate(ResponseIssueKind::CronPersistence),
            Err(CoreError::Validation { .. })
        ));

        let wrong_variant = IssueObject::CronEntry {
            file: "/etc/cron.d/ghost-maint".to_owned(),
            line: 1,
            line_sha256: line_sha256(GHOST_MAINT_LINE),
        };
        assert!(matches!(
            wrong_variant.validate(ResponseIssueKind::HijackedCommand),
            Err(CoreError::Validation { .. })
        ));
    }

    #[test]
    fn stale_fingerprints_and_line_digests_are_rejected_before_planning() {
        let stat = sample_stat();
        let shifted = StatFingerprint { size: 46, ..stat };
        assert!(matches!(
            ensure_path_fingerprint(
                "/usr/local/bin/ps",
                FAKE_PS_SHA,
                stat,
                &(FAKE_PS_SHA.to_owned(), shifted),
            ),
            Err(CoreError::Validation { .. })
        ));
        assert!(matches!(
            ensure_path_fingerprint(
                "/usr/local/bin/ps",
                FAKE_PS_SHA,
                stat,
                &("f".repeat(64), stat),
            ),
            Err(CoreError::Validation { .. })
        ));
        ensure_path_fingerprint(
            "/usr/local/bin/ps",
            FAKE_PS_SHA,
            stat,
            &(FAKE_PS_SHA.to_owned(), stat),
        )
        .unwrap();
        assert!(matches!(
            ensure_line_digest(
                &line_sha256(GHOST_MAINT_LINE),
                &line_sha256("other"),
                "/etc/cron.d/ghost-maint"
            ),
            Err(CoreError::Validation { .. })
        ));
    }

    #[test]
    fn sudoers_file_delete_template_archives_removes_and_rolls_back_on_visudo_failure() {
        let sha = line_sha256(SUDOERS_LINE);
        let script = sudoers_fix_script(
            "/etc/sudoers.d/backup-jobs",
            1,
            &sha,
            true,
            "/var/case/bak/20261029T000000Z-malicious-sudoers",
        );
        let expected = format!(
            "set -eu\n[ -f '/etc/sudoers.d/backup-jobs' ] && [ ! -L '/etc/sudoers.d/backup-jobs' ]\n[ \"$(/usr/bin/sed -n '1p' -- '/etc/sudoers.d/backup-jobs' | /usr/bin/sha256sum | /usr/bin/awk '{{print $1}}')\" = '{sha}' ]\n/usr/bin/install -d -m 700 -- '/var/case/bak/20261029T000000Z-malicious-sudoers'\nif [ -e '/etc/sudoers.d/backup-jobs' ]; then /usr/bin/cp -rp --parents -- '/etc/sudoers.d/backup-jobs' '/var/case/bak/20261029T000000Z-malicious-sudoers'; fi\n/usr/bin/find '/var/case/bak/20261029T000000Z-malicious-sudoers' -type f ! -name MANIFEST.sha256 -print0 | /usr/bin/sort -z | /usr/bin/xargs -0 -r /usr/bin/sha256sum > '/var/case/bak/20261029T000000Z-malicious-sudoers'/MANIFEST.sha256\n/usr/bin/rm -f -- '/etc/sudoers.d/backup-jobs'\nif /usr/sbin/visudo -c >/dev/null 2>&1; then\n  /usr/bin/printf '%s\\n' 'RESPONSE_FIX_OK'\nelse\n  /usr/bin/cp -rp -- '/var/case/bak/20261029T000000Z-malicious-sudoers''/etc/sudoers.d/backup-jobs' '/etc/sudoers.d/backup-jobs'\n  /usr/sbin/visudo -c >/dev/null 2>&1 || true\n  /usr/bin/printf '%s\\n' 'RESPONSE_FIX_ROLLBACK'\n  exit 3\nfi\n"
        );
        assert_eq!(script, expected);
    }

    #[test]
    fn sudoers_line_delete_template_uses_line_number_and_digest_double_check() {
        let sha = line_sha256(SUDOERS_LINE);
        let script = sudoers_fix_script(
            "/etc/sudoers",
            42,
            &sha,
            false,
            "/var/case/bak/ts-malicious-sudoers",
        );
        assert!(script.contains("/usr/bin/sed -i '42d' -- '/etc/sudoers'"));
        assert!(script.contains("/usr/bin/sed -n '42p' -- '/etc/sudoers' | /usr/bin/sha256sum"));
        assert!(script.contains("visudo -c"));
        assert!(script.contains("RESPONSE_FIX_ROLLBACK"));
        assert!(script.contains(&format!("= '{sha}'")));
    }

    #[test]
    fn cron_fix_and_kill_templates_double_check_and_exclude_our_own_shell() {
        let sha = line_sha256(REBOOT_LINE);
        let cron = cron_fix_script(
            "/var/spool/cron/crontabs/root",
            1,
            &sha,
            false,
            "/var/case/bak/ts-cron-persistence",
        );
        assert!(cron.contains("/usr/bin/sed -i '1d' -- '/var/spool/cron/crontabs/root'"));
        assert!(cron.contains(&format!("= '{sha}'")));

        let kill = backdoor_kill_script(&[901, 902], "/usr/local/libexec/kmod-health");
        assert!(kill.contains("for pid in 901 902;"));
        assert!(kill.contains("*LOVELYRES_RESPONSE*) ;;"));
        assert!(kill.contains("kill -TERM \"$pid\""));
        assert!(kill.contains("kill -KILL \"$pid\""));
        // TERM pass precedes the KILL pass.
        assert!(kill.find("kill -TERM").unwrap() < kill.find("kill -KILL").unwrap());
    }

    #[test]
    fn uid_zero_fix_drops_r_for_system_homes_and_keeps_it_under_home() {
        let system = account_removal_fix_script(
            ResponseIssueKind::UidZeroAccount,
            "xbackup",
            false,
            "/var/backups",
            "/var/case/bak/ts-uid-zero-account",
        )
        .unwrap();
        assert!(system.contains("/usr/sbin/userdel -f -- 'xbackup'"));
        assert!(!system.contains("userdel -f -r"));
        let user_home = account_removal_fix_script(
            ResponseIssueKind::UidZeroAccount,
            "evil",
            true,
            "/home/evil",
            "/var/case/bak/ts-uid-zero-account",
        )
        .unwrap();
        assert!(user_home.contains("/usr/sbin/userdel -f -r -- 'evil'"));
        assert!(user_home.contains("'/home/evil'"));
        assert!(!home_is_user_owned_location("/var/backups"));
        assert!(!home_is_user_owned_location("/home"));
        assert!(home_is_user_owned_location("/home/evil"));
    }

    #[test]
    fn section_splitting_rejects_truncated_output() {
        assert!(split_sections(&sample_scan_output()).is_ok());
        let missing_done = sample_scan_output().replace(MARKER_DONE, "GONE");
        assert!(matches!(
            split_sections(&missing_done),
            Err(CoreError::Validation { .. })
        ));
    }

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("lovelyres-response-{}", uuid::Uuid::new_v4()));
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

    #[tokio::test]
    async fn scan_over_the_bound_session_finds_all_seven_range_issue_kinds() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        harness.set_execute_outputs([
            "0\n".to_owned(),
            "operator\n".to_owned(),
            sample_scan_output(),
            "watcher\t1001\t/home/watcher\n".to_owned(),
        ]);
        let scan = services.response_engine().scan(&session).await.unwrap();
        assert!(!scan.truncated);
        assert!(scan.gaps.is_empty(), "{:?}", scan.gaps);
        let kinds: Vec<ResponseIssueKind> = scan.issues.iter().map(|issue| issue.kind).collect();
        for kind in [
            ResponseIssueKind::HijackedCommand,
            ResponseIssueKind::UidZeroAccount,
            ResponseIssueKind::EmptyPassword,
            ResponseIssueKind::SuspiciousAccount,
            ResponseIssueKind::MaliciousSudoers,
            ResponseIssueKind::CronPersistence,
            ResponseIssueKind::BackdoorProcess,
        ] {
            assert!(kinds.contains(&kind), "missing {kind:?} in {kinds:?}");
        }
        // Two hijacked commands, two cron entries, one of everything else, and
        // the scan's own shell is never reported as a backdoor. Of the passwd
        // rows only svc-backup is suspicious: root/daemon are system accounts,
        // operator is the session's own login and watcher is already reported
        // as an empty-password account.
        assert_eq!(scan.issues.len(), 9);
        let suspicious: Vec<&ResponseIssue> = scan
            .issues
            .iter()
            .filter(|issue| issue.kind == ResponseIssueKind::SuspiciousAccount)
            .collect();
        assert_eq!(suspicious.len(), 1);
        assert!(suspicious[0].summary.contains("svc-backup"));
        assert_eq!(suspicious[0].severity, ResponseSeverity::Medium);
        assert!(scan.issues.iter().all(|issue| issue.fixable));
        let serialized = serde_json::to_string(&scan).unwrap();
        assert!(!serialized.contains("\"object\""));
    }

    #[tokio::test]
    async fn plan_fix_refuses_a_path_whose_fingerprint_changed_since_the_scan() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        harness.set_execute_outputs([
            "0\n".to_owned(),
            format!("{}\t755|0|0|99|1761696001\n", "f".repeat(64)),
        ]);
        let issue = ResponseIssue {
            kind: ResponseIssueKind::HijackedCommand,
            severity: ResponseSeverity::High,
            summary: "test".to_owned(),
            evidence: Vec::new(),
            fixable: true,
            fix_summary: None,
            object: IssueObject::Path {
                path: "/usr/local/bin/ps".to_owned(),
                sha256: FAKE_PS_SHA.to_owned(),
                stat: sample_stat(),
            },
        };
        let result = services
            .response_engine()
            .plan_fix(&session, &issue, FixMode::Lock)
            .await;
        assert!(matches!(result, Err(CoreError::Validation { .. })));
    }

    #[tokio::test]
    async fn hijacked_command_plan_execute_and_verify_complete_the_operation_lifecycle() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        harness.set_execute_outputs([
            "0\n".to_owned(),
            format!("{FAKE_PS_SHA}\t755|0|0|45|1761696000\n"),
            "RESPONSE_FIX_OK\n".to_owned(),
            "RESPONSE_VERIFY_OK\n".to_owned(),
        ]);
        let issue = ResponseIssue {
            kind: ResponseIssueKind::HijackedCommand,
            severity: ResponseSeverity::High,
            summary: "test".to_owned(),
            evidence: Vec::new(),
            fixable: true,
            fix_summary: None,
            object: IssueObject::Path {
                path: "/usr/local/bin/ps".to_owned(),
                sha256: FAKE_PS_SHA.to_owned(),
                stat: sample_stat(),
            },
        };
        let engine = services.response_engine();
        let plan = engine
            .plan_fix(&session, &issue, FixMode::Lock)
            .await
            .unwrap();
        assert!(plan.operation.dangerous);
        assert!(plan.cross_period_verify_delay.is_none());
        assert!(plan.archive_dir.contains("hijacked-command"));
        let confirmation = DangerousConfirmation::approve(&plan.operation);
        let journal = services.operation_journal();
        let execution = engine
            .execute_fix(&session, plan, confirmation, journal)
            .await
            .unwrap();
        assert!(execution.summary.contains("删除被劫持的命令"));
        assert!(execution.archive_dir.starts_with("/var/case/bak/"));
        let verification = engine
            .verify_fix(&session, execution, journal)
            .await
            .unwrap();
        assert!(verification.verification.passed);
        assert_eq!(journal.entries().unwrap().len(), 2);

        let commands = harness.execute_commands();
        let fix_command = commands
            .iter()
            .find(|command| !command.contains("userdel") && command.contains("rm -f"))
            .expect("a fix step ran");
        assert!(fix_command.contains("/usr/local/bin/ps"));
        assert!(fix_command.contains(FAKE_PS_SHA));
        assert!(fix_command.contains("MANIFEST.sha256"));
    }

    /// Regression: a body already removed by a sibling fix (the stash-dir
    /// sweep runs before the process fix in a hand-driven order) must not
    /// dead-end the plan — the processes keep running from the deleted file,
    /// so the fix degrades to kill-only instead of refusing.
    #[tokio::test]
    async fn backdoor_plan_degrades_to_kill_only_when_the_body_is_already_gone() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        let cron_section = format!("{MARKER_CRON}\n{MARKER_DONE}\n");
        harness.set_execute_outputs(["0\n".to_owned(), "BODY_GONE\n".to_owned(), cron_section]);
        let issue = ResponseIssue {
            kind: ResponseIssueKind::BackdoorProcess,
            severity: ResponseSeverity::High,
            summary: "test".to_owned(),
            evidence: Vec::new(),
            fixable: true,
            fix_summary: None,
            object: IssueObject::Process {
                pids: vec![38, 45, 60],
                exe_path: "/var/tmp/.sysd/watcher".to_owned(),
                listen_port: None,
            },
        };
        let plan = services
            .response_engine()
            .plan_fix(&session, &issue, FixMode::Lock)
            .await
            .unwrap();
        assert!(plan.operation.summary.contains("已被其他修复删除"));
        let labels = plan.step_labels().join(" | ");
        assert!(labels.contains("终止 3 个后门进程"), "{labels}");
        assert!(
            !labels.contains("归档并删除后门本体"),
            "nothing is left to archive: {labels}"
        );
        assert_eq!(
            plan.cross_period_verify_delay,
            Some(CROSS_PERIOD_VERIFY_DELAY)
        );
    }

    #[tokio::test]
    async fn backdoor_plan_cascades_cron_removal_before_body_and_kill() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        let cron_section = format!(
            "{MARKER_CRON}\n/etc/cron.d/ghost-maint\t1\t{GHOST_MAINT_LINE}\n/var/spool/cron/crontabs/root\t1\t{REBOOT_LINE}\n{MARKER_DONE}\n"
        );
        harness.set_execute_outputs(["0\n".to_owned(), "RECHECK_OK\n".to_owned(), cron_section]);
        let issue = ResponseIssue {
            kind: ResponseIssueKind::BackdoorProcess,
            severity: ResponseSeverity::High,
            summary: "test".to_owned(),
            evidence: Vec::new(),
            fixable: true,
            fix_summary: None,
            object: IssueObject::Process {
                pids: vec![901],
                exe_path: "/usr/local/libexec/kmod-health".to_owned(),
                listen_port: None,
            },
        };
        let plan = services
            .response_engine()
            .plan_fix(&session, &issue, FixMode::Lock)
            .await
            .unwrap();
        assert_eq!(
            plan.cross_period_verify_delay,
            Some(CROSS_PERIOD_VERIFY_DELAY)
        );
        let labels = plan.step_labels();
        assert_eq!(labels.len(), 4);
        assert!(labels[0].contains("cron"));
        assert!(labels[1].contains("cron"));
        assert!(labels[2].contains("本体"));
        assert!(labels[3].contains("终止"));
        // The ghost-maint file has exactly one effective line, so the file
        // itself is removed; the root crontab keeps its other lines and is
        // edited in place by line number. Step scripts are privilege-wrapped,
        // so match on the parts that survive quoting.
        let scripts: Vec<&str> = plan.steps.iter().map(|step| step.script.as_str()).collect();
        assert!(scripts[0].contains("rm -f") && scripts[0].contains("cron.d/ghost-maint"));
        assert!(scripts[1].contains("sed -i") && scripts[1].contains("crontabs/root"));
        assert!(scripts[2].contains("rm -f") && scripts[2].contains("libexec/kmod-health"));
        assert!(scripts[3].contains("kill -TERM"));
    }

    #[test]
    fn fix_mode_defaults_to_lock_and_uses_kebab_case_on_the_wire() {
        assert_eq!(FixMode::default(), FixMode::Lock);
        assert_eq!(serde_json::to_string(&FixMode::Lock).unwrap(), "\"lock\"");
        assert_eq!(
            serde_json::from_str::<FixMode>("\"remove\"").unwrap(),
            FixMode::Remove
        );
        assert!(serde_json::from_str::<FixMode>("\"delete\"").is_err());
    }

    #[test]
    fn empty_password_remove_template_deletes_the_account_and_verifies_absence() {
        let script = account_removal_fix_script(
            ResponseIssueKind::EmptyPassword,
            "watcher",
            true,
            "/home/watcher",
            "/var/case/bak/ts-empty-password",
        )
        .unwrap();
        // The precondition proves the account still exists and is still
        // empty-password before anything is deleted.
        assert!(script.contains("$1==u {found=1}"));
        assert!(script.contains("$2==\"\" {found=1}"));
        assert!(script.contains("/usr/sbin/userdel -f -r -- 'watcher'"));
        for archived in ["/etc/passwd", "/etc/shadow", "/home/watcher"] {
            assert!(script.contains(&format!("-- '{archived}'")), "{archived}");
        }

        // A system home is never recursively deleted, same rule as uid-zero.
        let system_home = account_removal_fix_script(
            ResponseIssueKind::EmptyPassword,
            "watcher",
            false,
            "/var/backups",
            "/var/case/bak/ts-empty-password",
        )
        .unwrap();
        assert!(system_home.contains("/usr/sbin/userdel -f -- 'watcher'"));
        assert!(!system_home.contains("userdel -f -r"));

        // Removal verifies against both account databases.
        let object = IssueObject::Account {
            username: "watcher".to_owned(),
            uid: 1001,
            home: "/home/watcher".to_owned(),
        };
        let verify =
            verify_script_for(ResponseIssueKind::EmptyPassword, &object, FixMode::Remove).unwrap();
        assert!(verify.contains("/etc/passwd"));
        assert!(verify.contains("/etc/shadow"));
        assert!(verify.contains(VERIFY_OK_MARKER));
        let lock_verify =
            verify_script_for(ResponseIssueKind::EmptyPassword, &object, FixMode::Lock).unwrap();
        assert!(lock_verify.contains("$2==\"\""));
        assert!(!lock_verify.contains("/etc/passwd"));

        // Removal is closed to account issues.
        assert!(matches!(
            account_removal_fix_script(
                ResponseIssueKind::HijackedCommand,
                "watcher",
                false,
                "/home/watcher",
                "/var/case/bak/ts",
            ),
            Err(CoreError::Validation { .. })
        ));
    }

    #[tokio::test]
    async fn remove_mode_is_rejected_for_non_account_issues_and_plans_delete_accounts() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        let path_issue = ResponseIssue {
            kind: ResponseIssueKind::HijackedCommand,
            severity: ResponseSeverity::High,
            summary: "test".to_owned(),
            evidence: Vec::new(),
            fixable: true,
            fix_summary: None,
            object: IssueObject::Path {
                path: "/usr/local/bin/ps".to_owned(),
                sha256: FAKE_PS_SHA.to_owned(),
                stat: sample_stat(),
            },
        };
        // The mode check runs before any remote probe.
        assert!(matches!(
            services
                .response_engine()
                .plan_fix(&session, &path_issue, FixMode::Remove)
                .await,
            Err(CoreError::Validation { .. })
        ));

        // A remove-mode plan for an empty-password account deletes the account
        // and offers no automatic restore.
        harness.set_execute_outputs(["0\n".to_owned(), "empty\n".to_owned()]);
        let account_issue = ResponseIssue {
            kind: ResponseIssueKind::EmptyPassword,
            severity: ResponseSeverity::High,
            summary: "test".to_owned(),
            evidence: Vec::new(),
            fixable: true,
            fix_summary: None,
            object: IssueObject::Account {
                username: "watcher".to_owned(),
                uid: 1001,
                home: "/home/watcher".to_owned(),
            },
        };
        let plan = services
            .response_engine()
            .plan_fix(&session, &account_issue, FixMode::Remove)
            .await
            .unwrap();
        assert!(plan.operation.summary.contains("删除空口令账户 watcher"));
        assert!(plan.operation.restore_description.is_none());
        // Step scripts are privilege-wrapped, so match fragments that survive quoting.
        assert!(plan.steps[0].script.contains("userdel -f -r"));
        assert!(plan.steps[0].script.contains("watcher"));
        assert!(plan.verify_script.contains("/etc/passwd"));
    }

    #[tokio::test]
    async fn locked_backdoor_account_scans_as_suspicious_instead_of_empty_password() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        // The shadow section is empty because watcher's field is `!` (locked,
        // non-empty); the account body is only visible in the passwd section.
        let scan_output = format!(
            "{MARKER_HIJACK}\n{MARKER_UID0}\n{MARKER_SHADOW}\n{MARKER_PASSWD}\nctfops\t1000\t1000\t/home/ctfops\t/bin/bash\nwatcher\t1001\t1001\t/home/watcher\t/bin/sh\n{MARKER_SUDOERS}\n{MARKER_CRON}\n{MARKER_PROC}\n{MARKER_PRELOAD}\n{MARKER_PATHINJ}\n{MARKER_AUTHKEYS}\n{MARKER_PAM}\n{MARKER_LISTEN}\n{MARKER_WEB}\n{MARKER_HOOK}\n{MARKER_HIST}\n{MARKER_ENVIRON}\n{MARKER_MAPS}\n{MARKER_DONE}\n"
        );
        harness.set_execute_outputs(["0\n".to_owned(), "ctfops\n".to_owned(), scan_output]);
        let scan = services.response_engine().scan(&session).await.unwrap();
        assert!(scan.gaps.is_empty(), "{:?}", scan.gaps);
        assert_eq!(scan.issues.len(), 1, "{:?}", scan.issues);
        let issue = &scan.issues[0];
        assert_eq!(issue.kind, ResponseIssueKind::SuspiciousAccount);
        assert_eq!(issue.severity, ResponseSeverity::Medium);
        assert!(issue.summary.contains("watcher"));
        assert!(issue.fixable);
        issue.object().validate(issue.kind).unwrap();
    }

    #[tokio::test]
    async fn suspicious_account_plan_rechecks_passwd_and_removes_the_account() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        let issue = ResponseIssue {
            kind: ResponseIssueKind::SuspiciousAccount,
            severity: ResponseSeverity::Medium,
            summary: "test".to_owned(),
            evidence: Vec::new(),
            fixable: true,
            fix_summary: None,
            object: IssueObject::Account {
                username: "watcher".to_owned(),
                uid: 1001,
                home: "/home/watcher".to_owned(),
            },
        };
        // Remove mode stays exclusive to empty-password issues; the check runs
        // before any remote probe.
        assert!(matches!(
            services
                .response_engine()
                .plan_fix(&session, &issue, FixMode::Remove)
                .await,
            Err(CoreError::Validation { .. })
        ));

        harness.set_execute_outputs(["0\n".to_owned(), "1001\t/home/watcher\n".to_owned()]);
        let plan = services
            .response_engine()
            .plan_fix(&session, &issue, FixMode::Lock)
            .await
            .unwrap();
        assert!(plan.operation.summary.contains("删除可疑登录账户 watcher"));
        assert!(plan.operation.restore_description.is_none());
        // Step scripts are privilege-wrapped, so match fragments that survive quoting.
        assert!(plan.steps[0].script.contains("userdel -f -r"));
        assert!(plan.steps[0].script.contains("watcher"));
        assert!(plan.verify_script.contains("/etc/passwd"));
        assert!(plan.verify_script.contains("/etc/shadow"));

        // A uid/home change since the scan aborts planning (TOCTOU guard).
        harness.set_execute_outputs(["0\n".to_owned(), "1001\t/root\n".to_owned()]);
        assert!(matches!(
            services
                .response_engine()
                .plan_fix(&session, &issue, FixMode::Lock)
                .await,
            Err(CoreError::Validation { .. })
        ));
    }

    fn store_lab_password(services: &BackendServices, password: &str) {
        use std::collections::BTreeSet;

        use crate::connections::{
            ConnectionConfig, ConnectionSecretChanges, SecretChange, SshAuthMethod,
        };

        services
            .connections()
            .upsert(
                ConnectionConfig {
                    id: "connection-a".to_owned(),
                    name: "lab".to_owned(),
                    host: "host-a.test".to_owned(),
                    port: 22,
                    username: "operator".to_owned(),
                    auth_method: SshAuthMethod::Password,
                    private_key_path: None,
                    certificate_path: None,
                    agent_identity_fingerprint: None,
                    jump_host: None,
                    tags: BTreeSet::new(),
                    notes: None,
                    environment: None,
                    role: None,
                    group: None,
                    host_key_fingerprint: None,
                },
                ConnectionSecretChanges {
                    password: SecretChange::Replace(SecretValue::new(password)),
                    ..ConnectionSecretChanges::default()
                },
            )
            .unwrap();
    }

    #[tokio::test]
    async fn password_sudo_wraps_with_sudo_stdin_and_never_puts_the_password_in_command_text() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        store_lab_password(&services, "s3cret-lab");
        harness.set_execute_outputs([
            "1000\n".to_owned(),
            "no\n".to_owned(),
            "0\n".to_owned(),
            "operator\n".to_owned(),
            sample_scan_output(),
            "watcher\t1001\t/home/watcher\n".to_owned(),
        ]);
        let scan = services.response_engine().scan(&session).await.unwrap();
        assert!(scan.gaps.is_empty(), "{:?}", scan.gaps);
        assert!(scan.issues.iter().all(|issue| issue.fixable));

        let commands = harness.execute_commands();
        let wrapped: Vec<&String> = commands
            .iter()
            .filter(|command| command.contains("sudo -S -p ''"))
            .collect();
        // The sudo probe, the scan itself and the account lookup all run
        // through the password-sudo wrapper.
        assert_eq!(wrapped.len(), 3, "{commands:?}");
        for command in &wrapped {
            assert!(command.contains("-- /bin/sh -c"), "{command}");
            assert!(!command.contains("s3cret-lab"), "{command}");
        }
        let stdins = harness.sensitive_stdins();
        assert_eq!(stdins.len(), 3);
        assert!(stdins.iter().all(|stdin| stdin == b"s3cret-lab\n"));
    }

    #[tokio::test]
    async fn missing_or_rejected_sudo_password_degrades_the_scan_without_failing_it() {
        // No stored connection at all: nothing to feed sudo -S.
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        harness.set_execute_outputs([
            "1000\n".to_owned(),
            "no\n".to_owned(),
            "operator\n".to_owned(),
            sample_scan_output(),
            "watcher\t1001\t/home/watcher\n".to_owned(),
        ]);
        let scan = services.response_engine().scan(&session).await.unwrap();
        assert!(!scan.gaps.is_empty());
        assert!(scan.issues.iter().all(|issue| !issue.fixable));

        // A stored password that sudo rejects degrades the same way.
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        store_lab_password(&services, "wrong-password");
        harness.set_execute_outputs([
            "1000\n".to_owned(),
            "no\n".to_owned(),
            "<exit 1>sudo: sorry, try again.\n".to_owned(),
            "operator\n".to_owned(),
            sample_scan_output(),
            "watcher\t1001\t/home/watcher\n".to_owned(),
        ]);
        let scan = services.response_engine().scan(&session).await.unwrap();
        assert!(!scan.gaps.is_empty());
        assert!(scan.issues.iter().all(|issue| !issue.fixable));
        // The rejected attempt still never put the password on a command line.
        assert!(
            harness
                .execute_commands()
                .iter()
                .all(|command| !command.contains("wrong-password"))
        );
    }

    #[test]
    fn debug_output_of_password_privilege_is_redacted() {
        let privilege = Privilege::SudoWithPassword(Arc::new(SecretValue::new("s3cret-lab")));
        let debug = format!("{privilege:?}");
        assert!(!debug.contains("s3cret-lab"));
    }

    // --- v2 deep-compromise detectors -----------------------------------------

    const LIBSYSLOG_SHA: &str = "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809";

    fn tracked(path: &str) -> TrackedPath {
        TrackedPath {
            path: path.to_owned(),
            sha256: FAKE_PS_SHA.to_owned(),
            stat: sample_stat(),
        }
    }

    fn config_line(file: &str, line: u32, text: &str) -> ConfigLine {
        ConfigLine {
            file: file.to_owned(),
            line,
            text: text.to_owned(),
        }
    }

    #[test]
    fn preload_section_parses_present_missing_and_foreign_libs() {
        let mut truncated = false;
        let section = format!(
            "PRELOAD\t{FAKE_PS_SHA}\t644|0|0|28|1761696000\nLIB\t/usr/local/lib/libsyslog.so\t{LIBSYSLOG_SHA}\t755|0|0|24576|1761696000\nLIB\t/usr/local/lib/gone.so\tMISSING\t-\nLIB\t/etc/foreign.so\t{LIBSYSLOG_SHA}\t755|0|0|100|1761696000\n"
        );
        let hit = parse_preload_section(&section, &mut truncated).expect("a preload hit");
        assert!(!truncated);
        assert_eq!(hit.libs.len(), 1);
        assert_eq!(hit.libs[0].path, "/usr/local/lib/libsyslog.so");
        assert_eq!(hit.unresolved.len(), 2);
        let issue = ld_preload_issue(&hit, true);
        assert_eq!(issue.kind, ResponseIssueKind::LdPreloadHijack);
        assert_eq!(issue.severity, ResponseSeverity::Critical);
        assert!(issue.fixable);
        issue.object().validate(issue.kind).unwrap();
        // No preload file, or a preload file with no library lines: no issue.
        assert!(parse_preload_section("", &mut truncated).is_none());
        let empty = format!("PRELOAD\t{FAKE_PS_SHA}\t644|0|0|0|1761696000\n");
        assert!(parse_preload_section(&empty, &mut truncated).is_none());
    }

    #[test]
    fn path_injection_classification_hits_hidden_dirs_and_spares_standard_paths() {
        let hit =
            classify_path_injection_line("export PATH=/opt/.sbin:/usr/local/bin:/usr/bin:$PATH")
                .expect("hidden dir injection");
        assert_eq!(hit, vec!["/opt/.sbin".to_owned()]);
        let tmp = classify_path_injection_line("PATH=/tmp/.bin:$PATH").expect("tmp hidden dir");
        assert_eq!(tmp, vec!["/tmp/.bin".to_owned()]);
        for benign in [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "export PATH=\"$HOME/bin:$PATH\"",
            "# export PATH=/opt/.sbin:$PATH",
            "JAVA_HOME=/opt/java",
        ] {
            assert!(classify_path_injection_line(benign).is_none(), "{benign:?}");
        }
    }

    #[test]
    fn path_injection_issue_links_the_fake_commands_inside_injected_dirs() {
        let mut truncated = false;
        let hijack_rows = parse_hijacked(
            "HIT\t/opt/.sbin/ps\t0b9e4f6b8b05a2f6f6c2c7a2b1f0b8d6a7c9e1d2f3a4b5c6d7e8f9a0b1c2d3e4\t755|0|0|45|1761696000\t/opt/.sbin/ps\tgrep -E -v LOVELYRES\t/usr/bin/ps \"$@\"\nHIT\t/usr/local/bin/ls\t0b9e4f6b8b05a2f6f6c2c7a2b1f0b8d6a7c9e1d2f3a4b5c6d7e8f9a0b1c2d3e4\t755|0|0|43|1761696000\t/usr/local/bin/ls\tgrep -E -v LOVELYRES\t/bin/ls \"$@\"\n",
            &mut truncated,
        );
        let row = config_line(
            "/etc/profile.d/ghost-path.sh",
            1,
            "export PATH=/opt/.sbin:/usr/local/bin:/usr/bin:/bin",
        );
        let dirs = classify_path_injection_line(&row.text).unwrap();
        let issue = path_injection_issue(&row, &dirs, &hijack_rows, true);
        assert_eq!(issue.kind, ResponseIssueKind::PathInjection);
        assert_eq!(issue.severity, ResponseSeverity::Critical);
        match issue.object() {
            IssueObject::StartupLine {
                injected_dirs,
                linked_fakes,
                ..
            } => {
                assert_eq!(injected_dirs, &["/opt/.sbin".to_owned()]);
                // Only the fake inside the injected dir is linked; the
                // /usr/local/bin fake belongs to its own hijack issue.
                assert_eq!(linked_fakes.len(), 1);
                assert_eq!(linked_fakes[0].path, "/opt/.sbin/ps");
            }
            other => panic!("unexpected object {other:?}"),
        }
        issue.object().validate(issue.kind).unwrap();
    }

    #[test]
    fn authkey_forced_command_parses_only_the_options_prefix() {
        let line =
            "command=\"/var/tmp/.sysd/.backup.sh\",no-pty ssh-ed25519 AAAAC3NzaCfake comment";
        assert_eq!(
            classify_authkey_line(line),
            Some(Some("/var/tmp/.sysd/.backup.sh".to_owned()))
        );
        // command= after the key-type token is key material, not an option.
        let plain = "ssh-ed25519 AAAAC3NzaCfake command=/var/tmp/.sysd/.backup.sh";
        assert_eq!(classify_authkey_line(plain), None);
        // A forced command without an absolute path still reports the entry.
        let relative = "command=\"run.sh\" ssh-ed25519 AAAAC3NzaCfake";
        assert_eq!(classify_authkey_line(relative), Some(None));
        assert_eq!(
            classify_authkey_line("# command=\"/x\" ssh-ed25519 AAAA"),
            None
        );
    }

    #[test]
    fn pam_permit_classification_flags_effective_lines_only() {
        assert!(is_pam_permit_line("auth sufficient pam_permit.so"));
        assert!(is_pam_permit_line("auth\t sufficient\t pam_permit.so"));
        assert!(!is_pam_permit_line("# auth sufficient pam_permit.so"));
        assert!(!is_pam_permit_line("auth required pam_unix.so"));
        // Stock distro stack terminators are legitimate; deleting them breaks
        // the whole PAM stack (regression: a common-* sweep once killed sudo).
        assert!(!is_pam_permit_line("auth required pam_permit.so"));
        assert!(!is_pam_permit_line("session [default=1] pam_permit.so"));
        assert!(!is_pam_permit_line("account required pam_permit.so"));
    }

    #[test]
    fn listen_rows_decode_proc_net_tcp_and_classify_suspicion() {
        let mut truncated = false;
        let rows = parse_listen_rows(
            "LIS\t0100007F:1E61\t424242\t903\t/var/tmp/.sysd/netmon\t/var/tmp/.sysd/netmon -l 7777\nLIS\t00000000:0016\t111\t100\t/usr/sbin/sshd\t/usr/sbin/sshd -D\nLIS\t0100007F:0CEA\t112\t101\t/usr/sbin/mysqld\t/usr/sbin/mysqld\n",
            &mut truncated,
        );
        assert_eq!(rows.len(), 3);
        assert!(rows[0].loopback);
        assert_eq!(rows[0].port, 7777);
        assert_eq!(rows[0].address, "127.0.0.1");
        let no_extra_processes: Vec<ProcessRow> = Vec::new();
        let listener =
            bind_listener_issue(&rows[0], &no_extra_processes, true).expect("suspicious listener");
        assert_eq!(listener.kind, ResponseIssueKind::BindListener);
        assert!(listener.fixable);
        match listener.object() {
            IssueObject::Process {
                pids,
                exe_path,
                listen_port,
            } => {
                assert_eq!(pids, &[903]);
                assert_eq!(exe_path, "/var/tmp/.sysd/netmon");
                assert_eq!(*listen_port, Some(7777));
            }
            other => panic!("unexpected object {other:?}"),
        }
        listener.object().validate(listener.kind).unwrap();
        // sshd on 22 and mysql on loopback 3306 are plausible services.
        assert!(bind_listener_issue(&rows[1], &no_extra_processes, true).is_none());
        assert!(bind_listener_issue(&rows[2], &no_extra_processes, true).is_none());
        // A business site bound to 127.0.0.1:80/443 (ghost-range v2 ships
        // nginx exactly that way) is a service, not a bind backdoor.
        let mut more = parse_listen_rows(
            "LIS\t0100007F:0050\t7\t200\t/usr/sbin/nginx\tnginx: master process\nLIS\t0100007F:01BB\t8\t201\t/usr/sbin/nginx\tnginx: master process\n",
            &mut truncated,
        );
        more.reverse();
        for row in &more {
            assert!(bind_listener_issue(row, &no_extra_processes, true).is_none());
        }
    }

    #[test]
    fn bind_listener_issue_pulls_in_every_process_of_the_same_body() {
        let mut truncated = false;
        let rows = parse_listen_rows(
            "LIS\t0100007F:1E61\t424242\t903\t/usr/bin/python3.10\tpython3 /var/tmp/.sysd/netmon.py\n",
            &mut truncated,
        );
        // Boot races leave a second copy spinning on bind-retry; killing only
        // the socket holder would let it take the port right back.
        let process_rows =
            "902\t/usr/bin/python3.10\tpython3 /var/tmp/.sysd/netmon.py\n".to_owned();
        let processes = parse_process_rows(&process_rows, &mut truncated);
        let listener = bind_listener_issue(&rows[0], &processes, true).expect("listener");
        match listener.object() {
            IssueObject::Process { pids, .. } => assert_eq!(pids, &[902, 903]),
            other => panic!("unexpected object {other:?}"),
        }
        assert!(listener.evidence.iter().any(|line| line.contains("902")));
    }

    #[test]
    fn web_name_and_webshell_classification() {
        for hit in [
            ".env",
            ".env.production",
            "site_backup.zip",
            "db_dump.sql",
            "wwwbak.tar.gz",
        ] {
            assert!(is_web_sensitive_name(hit), "{hit}");
        }
        for benign in ["index.html", "schema.txt", "app.js", "backup"] {
            assert!(!is_web_sensitive_name(benign), "{benign}");
        }
        assert!(is_webshell_candidate(
            "/var/www/html/.backups/sh3ll.php",
            "<?php eval($_POST['c']);"
        ));
        assert!(!is_webshell_candidate(
            "/var/www/html/readme.txt",
            "eval($_POST"
        ));
        assert!(!is_webshell_candidate(
            "/var/www/html/index.php",
            "echo hello;"
        ));
    }

    #[test]
    fn history_classification_hits_cleartext_passwords_and_spares_lookalikes() {
        for hit in [
            "mysql -uroot -p'Str0ng!pass' -e 'show databases'",
            "mysql -h 127.0.0.1 -u root -pSecret123",
            "echo 'user:Str0ng!pass' | chpasswd",
            "password=Hunter2 ssh admin@example",
        ] {
            assert!(history_line_leaks_credential(hit), "{hit:?}");
        }
        for benign in [
            "nmap -p- 10.0.0.0/24",
            "ssh -p22 admin@example",
            "passwd",
            "grep password= /etc/app.conf",
            "# mysql -uroot -p'root'",
        ] {
            assert!(!history_line_leaks_credential(benign), "{benign:?}");
        }
    }

    #[test]
    fn recorder_hook_parses_the_append_target() {
        let line = "PROMPT_COMMAND='history -a >> /var/tmp/.sysd/.cmds'";
        assert_eq!(
            classify_recorder_hook_line(line),
            Some(Some("/var/tmp/.sysd/.cmds".to_owned()))
        );
        // An append without an absolute target reports the hook but no log.
        assert_eq!(
            classify_recorder_hook_line("PROMPT_COMMAND='history -a >> log.txt'"),
            Some(None)
        );
        // No append: not a recorder. A comment: not effective.
        assert_eq!(
            classify_recorder_hook_line("PROMPT_COMMAND='history -a'"),
            None
        );
        assert_eq!(
            classify_recorder_hook_line("# PROMPT_COMMAND='history -a >> /var/tmp/.sysd/.cmds'"),
            None
        );
    }

    #[test]
    fn hidden_stash_dirs_are_whitelisted_and_system_dirs_stay_closed() {
        assert_eq!(
            hidden_dir_ancestor("/var/tmp/.sysd/kmod"),
            Some("/var/tmp/.sysd".to_owned())
        );
        assert_eq!(
            hidden_dir_ancestor("/opt/.sbin/ps"),
            Some("/opt/.sbin".to_owned())
        );
        assert!(is_allowed_response_path("/var/tmp/.sysd/kmod"));
        assert!(is_allowed_response_path("/dev/shm/.x/run.sh"));
        for closed in [
            "/tmp/.X11-unix/X0",
            "/tmp/miner",
            "/var/tmp/plain",
            "/etc/.x/tool",
        ] {
            assert!(!is_allowed_response_path(closed), "{closed}");
        }
    }

    #[test]
    fn issue_sorting_puts_the_eyes_first() {
        let mut items = [
            (
                ResponseIssueKind::HistoryCredentialLeak,
                ResponseSeverity::Medium,
            ),
            (ResponseIssueKind::BackdoorProcess, ResponseSeverity::High),
            (
                ResponseIssueKind::HijackedCommand,
                ResponseSeverity::Critical,
            ),
            (
                ResponseIssueKind::LdPreloadHijack,
                ResponseSeverity::Critical,
            ),
            (ResponseIssueKind::Webshell, ResponseSeverity::Critical),
            (ResponseIssueKind::PathInjection, ResponseSeverity::Critical),
        ];
        items.sort_by_key(|(kind, severity)| (severity.rank(), kind.sort_rank()));
        let ordered: Vec<ResponseIssueKind> = items.iter().map(|(kind, _)| *kind).collect();
        assert_eq!(
            ordered,
            [
                ResponseIssueKind::LdPreloadHijack,
                ResponseIssueKind::PathInjection,
                ResponseIssueKind::HijackedCommand,
                ResponseIssueKind::Webshell,
                ResponseIssueKind::BackdoorProcess,
                ResponseIssueKind::HistoryCredentialLeak,
            ]
        );
    }

    #[test]
    fn ld_preload_fix_template_rechecks_preload_and_each_library() {
        let libs = vec![tracked("/usr/local/lib/libsyslog.so")];
        let script = ld_preload_fix_script(
            "/etc/ld.so.preload",
            FAKE_PS_SHA,
            sample_stat(),
            &libs,
            "/var/case/bak/ts-ld-preload-hijack",
        );
        assert!(script.contains("'/etc/ld.so.preload'"));
        assert!(script.contains(FAKE_PS_SHA));
        assert!(script.contains("755|0|0|45|1761696000"));
        assert!(script.contains("'/usr/local/lib/libsyslog.so'"));
        assert!(script.contains("MANIFEST.sha256"));
        assert!(script.contains(FIX_OK_MARKER));
        let restore = ld_preload_restore_script(
            "/var/case/bak/ts-ld-preload-hijack",
            "/etc/ld.so.preload",
            &libs,
        );
        assert!(restore.contains(RESTORE_OK_MARKER));
        assert!(restore.contains("libsyslog.so"));
        let object = IssueObject::LdPreload {
            file: "/etc/ld.so.preload".to_owned(),
            sha256: FAKE_PS_SHA.to_owned(),
            stat: sample_stat(),
            libs,
        };
        let verify =
            verify_script_for(ResponseIssueKind::LdPreloadHijack, &object, FixMode::Lock).unwrap();
        assert!(verify.contains("grep -cv"));
        assert!(verify.contains("libsyslog.so"));
        assert!(verify.contains(VERIFY_OK_MARKER));
    }

    #[test]
    fn stash_and_bind_listener_templates() {
        let object = IssueObject::StashDir {
            path: "/var/tmp/.sysd".to_owned(),
        };
        object.validate(ResponseIssueKind::StashDir).unwrap();
        let verify =
            verify_script_for(ResponseIssueKind::StashDir, &object, FixMode::Lock).unwrap();
        assert!(verify.contains("'/var/tmp/.sysd'"));
        assert!(verify.contains(VERIFY_OK_MARKER));
        let fix = stash_dir_fix_script("/var/tmp/.sysd", "/var/case/bak/ts-stash-dir");
        assert!(fix.contains("rm -rf"));
        assert!(fix.contains("MANIFEST.sha256"));

        let listener = IssueObject::Process {
            pids: vec![903],
            exe_path: "/var/tmp/.sysd/netmon".to_owned(),
            listen_port: Some(7777),
        };
        let verify =
            verify_script_for(ResponseIssueKind::BindListener, &listener, FixMode::Lock).unwrap();
        assert!(verify.contains(":1E61"));
        assert!(verify.contains("/proc/net/tcp"));
        // A listener object without its port cannot build a verify script.
        let no_port = IssueObject::Process {
            pids: vec![903],
            exe_path: "/var/tmp/.sysd/netmon".to_owned(),
            listen_port: None,
        };
        assert!(
            verify_script_for(ResponseIssueKind::BindListener, &no_port, FixMode::Lock).is_err()
        );
    }

    #[test]
    fn line_based_verify_templates_search_the_whole_file() {
        let object = IssueObject::HistoryLine {
            file: "/root/.bash_history".to_owned(),
            line: 42,
            line_sha256: line_sha256("mysql -p'x'"),
        };
        object
            .validate(ResponseIssueKind::HistoryCredentialLeak)
            .unwrap();
        let verify = verify_script_for(
            ResponseIssueKind::HistoryCredentialLeak,
            &object,
            FixMode::Lock,
        )
        .unwrap();
        assert!(verify.contains("while IFS= read -r hawk_line"));
        assert!(verify.contains("'/root/.bash_history'"));

        let startup = startup_line_verify_script(
            "/etc/profile",
            &line_sha256("export PATH=/opt/.sbin:$PATH"),
            false,
            &[tracked("/opt/.sbin/ps")],
        );
        assert!(startup.contains("while IFS= read -r hawk_line"));
        assert!(startup.contains("'/opt/.sbin/ps'"));
        let delete_file = startup_line_verify_script("/etc/profile.d/x.sh", "deadbeef", true, &[]);
        assert!(delete_file.contains("if [ -e '/etc/profile.d/x.sh' ]; then ok=0; fi"));
    }

    #[test]
    fn web_verify_freezes_the_business_observation() {
        let with_business = web_verify_script("/var/www/html/.env", None, Some(true));
        assert!(with_business.contains("urllib.request"));
        assert!(with_business.contains("'/var/www/html/.env'"));
        let without = web_verify_script("/var/www/html/.env", None, Some(false));
        assert!(!without.contains("urllib"));
        let dir_case = web_verify_script(
            "/var/www/html/.backups/sh3ll.php",
            Some("/var/www/html/.backups"),
            None,
        );
        assert!(dir_case.contains("'/var/www/html/.backups'"));
        assert!(!dir_case.contains("urllib"));
    }

    /// The ghost-range-v2 shape: 23 issues across 16 kinds (no suspicious
    /// account: watcher is empty-password and ctfops is the session login).
    fn sample_v2_scan_output() -> String {
        format!(
            "{MARKER_HIJACK}\n\
             HIT\t/opt/.sbin/ps\t{FAKE_PS_SHA}\t755|0|0|45|1761696000\t/opt/.sbin/ps\tgrep -E -v LOVELYRES\t/usr/bin/ps \"$@\"\n\
             HIT\t/opt/.sbin/ls\t{FAKE_PS_SHA}\t755|0|0|43|1761696000\t/opt/.sbin/ls\tgrep -E -v LOVELYRES\t/bin/ls \"$@\"\n\
             HIT\t/opt/.sbin/netstat\t{FAKE_PS_SHA}\t755|0|0|44|1761696000\t/opt/.sbin/netstat\tgrep -E -v LOVELYRES\t/bin/netstat \"$@\"\n\
             {MARKER_UID0}\nxbackup\t0\t/var/backups\n\
             {MARKER_SHADOW}\nwatcher\n\
             {MARKER_PASSWD}\n\
             root\t0\t0\t/root\t/bin/bash\n\
             ctfops\t1000\t1000\t/home/ctfops\t/bin/bash\n\
             watcher\t1001\t1001\t/home/watcher\t/bin/sh\n\
             xbackup\t0\t0\t/var/backups\t/bin/bash\n\
             daemon\t1\t1\t/usr/sbin\t/usr/sbin/nologin\n\
             {MARKER_SUDOERS}\n/etc/sudoers.d/ghost\t1\txbackup ALL=(ALL) NOPASSWD: ALL\n\
             {MARKER_CRON}\n\
             /etc/cron.d/ghost-maint\t1\t* * * * * root pgrep -f kmod-health >/dev/null 2>&1 || (nohup /var/tmp/.sysd/kmod-health >/dev/null 2>&1 &)\n\
             /var/spool/cron/crontabs/root\t1\t@reboot /var/tmp/.sysd/kmod-health >/dev/null 2>&1\n\
             /var/spool/cron/crontabs/root\t2\t* * * * * /var/tmp/.sysd/watcher.sh >/dev/null 2>&1\n\
             {MARKER_PROC}\n\
             1\t/sbin/init\t/sbin/init\n\
             901\t/var/tmp/.sysd/kmod-health\t/var/tmp/.sysd/kmod-health\n\
             902\t/var/tmp/.sysd/watcher\t/var/tmp/.sysd/watcher\n\
             903\t/var/tmp/.sysd/netmon\t/var/tmp/.sysd/netmon -l 7777\n\
             {MARKER_PRELOAD}\n\
             PRELOAD\t{FAKE_PS_SHA}\t644|0|0|28|1761696000\n\
             LIB\t/usr/local/lib/libsyslog.so\t{LIBSYSLOG_SHA}\t755|0|0|24576|1761696000\n\
             {MARKER_PATHINJ}\n\
             /etc/profile.d/ghost-path.sh\t1\texport PATH=/opt/.sbin:/usr/local/bin:/usr/bin:/bin\n\
             {MARKER_AUTHKEYS}\n\
             /root/.ssh/authorized_keys\t1\tcommand=\"/var/tmp/.sysd/.backup.sh\",no-pty ssh-ed25519 AAAAC3NzaCfake\n\
             {MARKER_PAM}\n\
             /etc/pam.d/common-auth\t15\tauth sufficient pam_permit.so\n\
             {MARKER_LISTEN}\n\
             LIS\t0100007F:1E61\t424242\t903\t/var/tmp/.sysd/netmon\t/var/tmp/.sysd/netmon -l 7777\n\
             {MARKER_WEB}\n\
             WEBCAND\t/var/www/html/.env\t{FAKE_PS_SHA}\t644|33|33|51|1761696000\n\
             WEBCAND\t/var/www/html/site_backup.zip\t{FAKE_PS_SHA}\t644|33|33|1024|1761696000\n\
             SH3LLCAND\t/var/www/html/.backups/sh3ll.php\t{FAKE_PS_SHA}\t644|33|33|64|1761696000\t<?php eval($_POST['c']); ?>\n\
             {MARKER_HOOK}\n\
             /etc/profile.d/sysstat.sh\t2\tPROMPT_COMMAND='history -a >> /var/tmp/.sysd/.cmds'\n\
             {MARKER_HIST}\n\
             /root/.bash_history\t42\tmysql -uroot -p'Str0ng!pass' -e 'show databases'\n\
             {MARKER_ENVIRON}\n\
             ENVROW\t905\t/usr/bin/bash\tPROMPT_COMMAND=history -a; echo x >> /var/tmp/.sysd/.cmds\t\tPATH=/opt/.sbin:/usr/bin:/bin\n\
             {MARKER_MAPS}\n\
             MAPHIT\t906\t/usr/sbin/nginx\t/usr/local/lib/libsyslog.so (deleted)\n\
             {MARKER_DONE}\n"
        )
    }

    #[tokio::test]
    async fn v2_deep_compromise_scan_finds_sixteen_kinds_with_the_eyes_first() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        harness.set_execute_outputs([
            "0\n".to_owned(),
            "ctfops\n".to_owned(),
            sample_v2_scan_output(),
            format!(
                "FP\t/var/tmp/.sysd/.backup.sh\t{FAKE_PS_SHA}\t755|0|0|128|1761696000\nFP\t/var/tmp/.sysd/.cmds\t{FAKE_PS_SHA}\t600|0|0|512|1761696000\n"
            ),
            "watcher\t1001\t/home/watcher\n".to_owned(),
        ]);
        let scan = services.response_engine().scan(&session).await.unwrap();
        assert!(scan.gaps.is_empty(), "{:?}", scan.gaps);
        assert_eq!(scan.issues.len(), 25, "{:?}", scan.issues);
        let mut kinds: Vec<ResponseIssueKind> =
            scan.issues.iter().map(|issue| issue.kind).collect();
        let mut unique = kinds.clone();
        unique.sort_by_key(|kind| kind.slug());
        unique.dedup();
        assert_eq!(unique.len(), 18, "{unique:?}");
        assert!(!unique.contains(&ResponseIssueKind::SuspiciousAccount));
        // 先修眼睛: ld.so.preload, PATH injection, then the hijacked commands.
        assert_eq!(kinds[0], ResponseIssueKind::LdPreloadHijack);
        assert_eq!(kinds[1], ResponseIssueKind::PathInjection);
        assert_eq!(kinds[2], ResponseIssueKind::HijackedCommand);
        kinds.clear();
        // preload-residue is guidance-only by design (a blind kill could take
        // the business down); every other finding carries an executable fix.
        assert!(
            scan.issues
                .iter()
                .all(|issue| issue.fixable || issue.kind == ResponseIssueKind::PreloadResidue)
        );
        assert!(
            scan.issues
                .iter()
                .any(|issue| issue.kind == ResponseIssueKind::PreloadResidue && !issue.fixable)
        );
        for issue in &scan.issues {
            issue.object().validate(issue.kind).unwrap();
        }
    }

    /// Regression: the PROC section always contains our own scan shell, whose
    /// cmdline is the entire scan script on one line — every section marker
    /// embedded as a substring. Marker anchoring must keep the sections after
    /// PROC intact instead of cutting them at those embedded copies.
    #[tokio::test]
    async fn self_scan_cmdline_inside_proc_section_does_not_break_section_splitting() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        let embedded = scan_script().replace('\n', " ");
        let self_row = format!("222\t/usr/bin/dash\t/bin/sh -c {embedded}\n");
        let poisoned = sample_v2_scan_output().replace(
            &format!("{MARKER_PROC}\n"),
            &format!("{MARKER_PROC}\n{self_row}"),
        );
        harness.set_execute_outputs([
            "0\n".to_owned(),
            "ctfops\n".to_owned(),
            poisoned,
            format!(
                "FP\t/var/tmp/.sysd/.backup.sh\t{FAKE_PS_SHA}\t755|0|0|128|1761696000\nFP\t/var/tmp/.sysd/.cmds\t{FAKE_PS_SHA}\t600|0|0|512|1761696000\n"
            ),
            "watcher\t1001\t/home/watcher\n".to_owned(),
        ]);
        let scan = services.response_engine().scan(&session).await.unwrap();
        assert_eq!(scan.issues.len(), 25, "{:?}", scan.issues);
        assert_eq!(scan.issues[0].kind, ResponseIssueKind::LdPreloadHijack);
        // The self row is excluded from process clustering, not turned into
        // a phantom backdoor finding.
        let backdoors = scan
            .issues
            .iter()
            .filter(|issue| issue.kind == ResponseIssueKind::BackdoorProcess)
            .count();
        assert_eq!(backdoors, 3);
    }

    // --- session-resident environment hooks -------------------------------

    #[test]
    fn session_env_rows_classify_into_the_three_closed_signatures() {
        let mut truncated = false;
        let rows = parse_session_env_rows(
            "ENVROW\t101\t/usr/bin/bash\tPROMPT_COMMAND=history 1 >> /var/tmp/.sysd/.cmds\t\tPATH=/opt/.sbin:/usr/bin:/bin\n\
             ENVROW\t102\t/usr/bin/bash\t\tLD_PRELOAD=/var/tmp/.evil.so\tPATH=/usr/local/bin:/usr/bin:/bin\n\
             ENVROW\t103\t/usr/bin/sleep\tPROMPT_COMMAND=history 1 >> /var/tmp/.sysd/.cmds\t\tPATH=/opt/.sbin:/usr/bin:/bin\n\
             ENVROW\t104\t/usr/bin/bash\t\t\tPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n",
            &mut truncated,
        );
        assert_eq!(rows.len(), 4);
        assert!(!truncated);
        assert_eq!(
            session_signatures(&rows[0]),
            vec!["prompt-recorder".to_owned(), "injected-path".to_owned()]
        );
        assert_eq!(
            session_signatures(&rows[1]),
            vec!["resident-preload".to_owned()]
        );
        // A stock PATH and no PROMPT_COMMAND is a clean session, not a finding.
        assert!(session_signatures(&rows[3]).is_empty());
        // The shell exec'd away (row 2 is the sleep binary) — the environment
        // lives on in the child, so the tree must still cluster with row 0.
        let clusters = cluster_session_env(rows);
        assert_eq!(clusters.len(), 2);
        let hooked = clusters
            .iter()
            .find(|cluster| cluster.processes.len() == 2)
            .expect("shell and exec'd child share one environment");
        assert_eq!(
            hooked
                .processes
                .iter()
                .map(|process| process.pid)
                .collect::<Vec<_>>(),
            vec![101, 103]
        );
        let issue = session_env_issue(hooked, true);
        assert_eq!(issue.kind, ResponseIssueKind::SessionEnvHook);
        assert!(issue.summary.contains("2 个进程"));
        assert!(issue.fixable);
        issue.object().validate(issue.kind).unwrap();
        let unprivileged = session_env_issue(hooked, false);
        assert!(!unprivileged.fixable);
    }

    #[test]
    fn session_env_rows_reject_malformed_lines() {
        let mut truncated = false;
        let rows = parse_session_env_rows(
            "ENVROW\t0\t/usr/bin/bash\t\t\t\n\
             ENVROW\tabc\t/usr/bin/bash\t\t\t\n\
             ENVROW\t104\trelative/exe\t\t\t\n\
             ENVROW\t105\t/usr/bin/bash\tPROMPT_COMMAND=x >> log\t\t\n\
             TRUNCATED\n",
            &mut truncated,
        );
        assert!(truncated);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].pid, 105);
    }

    #[test]
    fn session_env_objects_validate_processes_and_signature_set() {
        let processes = vec![
            SessionEnvProcess {
                pid: 42,
                exe: "/usr/bin/bash".to_owned(),
            },
            SessionEnvProcess {
                pid: 43,
                exe: "/usr/bin/sleep".to_owned(),
            },
        ];
        IssueObject::SessionEnv {
            processes: processes.clone(),
            signatures: vec!["prompt-recorder".to_owned()],
        }
        .validate(ResponseIssueKind::SessionEnvHook)
        .unwrap();
        assert!(
            IssueObject::SessionEnv {
                processes: vec![SessionEnvProcess {
                    pid: 0,
                    exe: "/usr/bin/bash".to_owned(),
                }],
                signatures: vec!["prompt-recorder".to_owned()],
            }
            .validate(ResponseIssueKind::SessionEnvHook)
            .is_err()
        );
        assert!(
            IssueObject::SessionEnv {
                processes: vec![SessionEnvProcess {
                    pid: 42,
                    exe: "bash".to_owned(),
                }],
                signatures: vec!["prompt-recorder".to_owned()],
            }
            .validate(ResponseIssueKind::SessionEnvHook)
            .is_err()
        );
        assert!(
            IssueObject::SessionEnv {
                processes: vec![
                    SessionEnvProcess {
                        pid: 42,
                        exe: "/usr/bin/bash".to_owned(),
                    },
                    SessionEnvProcess {
                        pid: 42,
                        exe: "/usr/bin/bash".to_owned(),
                    },
                ],
                signatures: vec!["prompt-recorder".to_owned()],
            }
            .validate(ResponseIssueKind::SessionEnvHook)
            .is_err()
        );
        assert!(
            IssueObject::SessionEnv {
                processes,
                signatures: vec!["not-a-code".to_owned()],
            }
            .validate(ResponseIssueKind::SessionEnvHook)
            .is_err()
        );
    }

    #[test]
    fn session_env_scripts_carry_recheck_and_verdict_markers() {
        let processes = vec![
            SessionEnvProcess {
                pid: 105,
                exe: "/usr/bin/bash".to_owned(),
            },
            SessionEnvProcess {
                pid: 106,
                exe: "/usr/bin/sleep".to_owned(),
            },
        ];
        let kill = session_env_kill_script(&processes);
        assert!(kill.contains("kill -TERM"));
        assert!(kill.contains("kill -KILL"));
        assert!(kill.contains("/proc/105"));
        assert!(kill.contains("/proc/106"));
        assert!(kill.contains(FIX_OK_MARKER));
        let verify = session_env_verify_script(
            &processes,
            &["prompt-recorder".to_owned(), "injected-path".to_owned()],
        );
        assert!(verify.contains(VERIFY_OK_MARKER));
        assert!(verify.contains(VERIFY_FAIL_MARKER));
        assert!(verify.contains("PROMPT_COMMAND"));
        // The global sweep must cover every process, not just the cluster.
        assert!(verify.contains("for proc_dir in /proc/[0-9]*"));
    }

    // --- resident-library residue ------------------------------------------

    #[test]
    fn resident_lib_rows_cluster_by_library_and_stay_guidance_only() {
        let mut truncated = false;
        let rows = parse_resident_lib_rows(
            "MAPHIT\t201\t/usr/sbin/nginx\t/usr/local/lib/libsyslog.so (deleted)\n\
             MAPHIT\t202\t/usr/bin/python3.10\t/usr/local/lib/libsyslog.so (deleted)\n\
             MAPHIT\t203\t/usr/sbin/nginx\t/usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)\n\
             MAPHIT\t204\t/usr/sbin/nginx\t/usr/local/lib/python3.10/site.py\n",
            &mut truncated,
        );
        assert!(!truncated);
        // /usr/lib upgrades are out of scope and non-.so mappings never match.
        assert_eq!(rows.len(), 2);
        let clusters = cluster_resident_libs(rows);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].lib_path, "/usr/local/lib/libsyslog.so");
        assert_eq!(clusters[0].pids, vec![201, 202]);
        let issue = resident_lib_issue(&clusters[0]);
        assert_eq!(issue.kind, ResponseIssueKind::PreloadResidue);
        assert!(!issue.fixable);
        issue.object().validate(issue.kind).unwrap();
        // A resident-lib object outside the suspicious prefixes never validates.
        assert!(
            IssueObject::ResidentLib {
                lib_path: "/usr/lib/x86_64-linux-gnu/libcrypto.so.3".to_owned(),
                pids: vec![1],
                exes: vec!["/usr/sbin/sshd".to_owned()],
            }
            .validate(ResponseIssueKind::PreloadResidue)
            .is_err()
        );
    }

    // --- hardening ----------------------------------------------------------

    #[test]
    fn hardening_permission_item_flags_only_deviations() {
        let section = "PERM|/etc/shadow|644|root|shadow\n\
                       PERM|/etc/gshadow|640|root|shadow\n\
                       PERM|/home/ops/.ssh|755|ops|ops\n\
                       PERM|/etc/random/file|777|root|root\n";
        let item = hardening_permissions_item(section, true);
        assert_eq!(item.kind, ResponseIssueKind::HardeningAuthPermissions);
        assert_eq!(item.status, HardeningStatus::Pending);
        let issue = item.issue.expect("pending item carries its issue");
        match issue.object() {
            IssueObject::HardeningPermissions { entries } => {
                // shadow mode deviates and the .ssh dir mode deviates; the
                // path outside the target set is ignored entirely.
                assert_eq!(entries.len(), 2);
                assert!(entries.iter().any(|entry| entry.path == "/etc/shadow"
                    && entry.current == "644|root|shadow"
                    && entry.target == "640|root|shadow"));
                assert!(entries.iter().any(
                    |entry| entry.path == "/home/ops/.ssh" && entry.target.starts_with("700|")
                ));
            }
            other => panic!("unexpected object {other:?}"),
        }
        issue.object().validate(issue.kind).unwrap();
        let compliant = hardening_permissions_item("PERM|/etc/shadow|640|root|shadow\n", true);
        assert!(matches!(compliant.status, HardeningStatus::Compliant(_)));
        assert!(compliant.issue.is_none());
    }

    #[test]
    fn hardening_permission_objects_reject_paths_outside_the_target_set() {
        let entry = PermissionEntry {
            path: "/etc/passwd".to_owned(),
            current: "644|root|root".to_owned(),
            target: "600|root|root".to_owned(),
        };
        assert!(
            IssueObject::HardeningPermissions {
                entries: vec![entry]
            }
            .validate(ResponseIssueKind::HardeningAuthPermissions)
            .is_err()
        );
        let good = PermissionEntry {
            path: "/etc/shadow".to_owned(),
            current: "644|root|shadow".to_owned(),
            target: "640|root|shadow".to_owned(),
        };
        IssueObject::HardeningPermissions {
            entries: vec![good],
        }
        .validate(ResponseIssueKind::HardeningAuthPermissions)
        .unwrap();
    }

    #[test]
    fn hardening_audit_item_covers_unavailable_missing_and_compliant() {
        let unavailable = hardening_audit_item("NOAUDITCTL\n", true);
        assert!(matches!(
            unavailable.status,
            HardeningStatus::NotApplicable(_)
        ));
        let missing = hardening_audit_item("AUDITCTL\t/usr/sbin/auditctl\n", true);
        let issue = missing.issue.expect("missing points are plannable");
        match issue.object() {
            IssueObject::HardeningAuditWatch { points } => {
                assert_eq!(points.len(), AUDIT_WATCH_POINTS.len());
            }
            other => panic!("unexpected object {other:?}"),
        }
        issue.object().validate(issue.kind).unwrap();
        // A duplicate point list never validates.
        assert!(
            IssueObject::HardeningAuditWatch {
                points: vec!["/etc/passwd".to_owned(), "/etc/passwd".to_owned()]
            }
            .validate(ResponseIssueKind::HardeningAuditWatch)
            .is_err()
        );
        assert!(
            IssueObject::HardeningAuditWatch {
                points: vec!["/etc/not-a-point".to_owned()]
            }
            .validate(ResponseIssueKind::HardeningAuditWatch)
            .is_err()
        );
        let watched: Vec<&str> = AUDIT_WATCH_POINTS.to_vec();
        let rules = watched
            .iter()
            .map(|point| format!("-w {point} -p wa -k {AUDIT_WATCH_KEY}"))
            .collect::<Vec<_>>()
            .join("\n");
        let compliant =
            hardening_audit_item(&format!("AUDITCTL\t/usr/sbin/auditctl\n{rules}\n"), true);
        assert!(matches!(compliant.status, HardeningStatus::Compliant(_)));
    }

    #[test]
    fn hardening_snapshot_item_moves_from_absent_to_clean_to_drift() {
        let absent = hardening_snapshot_item("SNAP\tabsent\t0\n", true);
        assert_eq!(absent.status, HardeningStatus::Pending);
        assert!(absent.issue.is_some());
        let clean = hardening_snapshot_item("SNAP\tpresent\t12\n", true);
        assert!(matches!(clean.status, HardeningStatus::Compliant(_)));
        let drifted = hardening_snapshot_item(
            "SNAP\tpresent\t12\nDRIFT\tchanged\t/etc/passwd\nDRIFT\tmissing\t/etc/cron.d/ghost-maint\n",
            true,
        );
        assert_eq!(drifted.status, HardeningStatus::Pending);
        assert_eq!(drifted.evidence.len(), 2);
        assert!(drifted.evidence[0].contains("/etc/passwd"));
    }

    #[test]
    fn hardening_sections_split_between_their_markers() {
        let output = "LOVELYHAWK_HARDENING_PERM_V1\nPERM|/etc/shadow|640|root|shadow\nLOVELYHAWK_HARDENING_AUDIT_V1\nAUDITCTL\t/usr/sbin/auditctl\nLOVELYHAWK_HARDENING_SNAP_V1\nSNAP\tabsent\t0\nLOVELYHAWK_HARDENING_DONE_V1\n";
        let perm = hardening_section(output, "LOVELYHAWK_HARDENING_PERM_V1").unwrap();
        assert!(perm.contains("PERM|/etc/shadow"));
        assert!(!perm.contains("AUDITCTL"));
        let snap = hardening_section(output, "LOVELYHAWK_HARDENING_SNAP_V1").unwrap();
        assert!(snap.contains("SNAP\tabsent\t0"));
        assert!(hardening_section(output, "LOVELYHAWK_HARDENING_MISSING").is_err());
    }

    #[test]
    fn hardening_scripts_print_the_step_and_verdict_markers() {
        let entries = vec![PermissionEntry {
            path: "/etc/shadow".to_owned(),
            current: "644|root|shadow".to_owned(),
            target: "640|root|shadow".to_owned(),
        }];
        assert!(permissions_record_script("/var/case/bak/x", &entries).contains(FIX_OK_MARKER));
        let fix = permissions_fix_script(&entries);
        assert!(fix.contains("chmod 640"));
        assert!(fix.contains("chown root:shadow"));
        assert!(fix.contains(FIX_OK_MARKER));
        assert!(permissions_verify_script(&entries).contains(VERIFY_OK_MARKER));
        let points = vec!["/etc/passwd".to_owned()];
        let watch_fix = audit_watch_fix_script(&points);
        assert!(watch_fix.contains("-w") && watch_fix.contains("/etc/passwd"));
        let watch_undo = audit_watch_restore_script(&points);
        assert!(watch_undo.contains("-W") && watch_undo.contains("/etc/passwd"));
        assert!(audit_watch_verify_script(&points).contains(VERIFY_OK_MARKER));
        assert!(snapshot_fix_script().contains(HARDENING_MANIFEST));
        assert!(snapshot_verify_script().contains(VERIFY_OK_MARKER));
        assert!(snapshot_restore_script().contains(RESTORE_OK_MARKER));
    }

    #[tokio::test]
    async fn hardening_scan_builds_three_items_from_one_probe() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        harness.set_execute_outputs([
            "0\n".to_owned(), // id -u → root
            "LOVELYHAWK_HARDENING_PERM_V1\nPERM|/etc/shadow|644|root|shadow\nLOVELYHAWK_HARDENING_AUDIT_V1\nNOAUDITCTL\nLOVELYHAWK_HARDENING_SNAP_V1\nSNAP\tabsent\t0\nLOVELYHAWK_HARDENING_DONE_V1\n".to_owned(),
        ]);
        let scan = services
            .response_engine()
            .hardening_scan(&session)
            .await
            .unwrap();
        assert_eq!(scan.items.len(), 3);
        assert!(scan.gaps.is_empty());
        let perm = scan
            .items
            .iter()
            .find(|item| item.kind == ResponseIssueKind::HardeningAuthPermissions)
            .unwrap();
        assert_eq!(perm.status, HardeningStatus::Pending);
        assert!(perm.fixable);
        let audit = scan
            .items
            .iter()
            .find(|item| item.kind == ResponseIssueKind::HardeningAuditWatch)
            .unwrap();
        assert!(matches!(audit.status, HardeningStatus::NotApplicable(_)));
        let snap = scan
            .items
            .iter()
            .find(|item| item.kind == ResponseIssueKind::HardeningIntegritySnapshot)
            .unwrap();
        assert_eq!(snap.status, HardeningStatus::Pending);
    }

    #[tokio::test]
    async fn plan_hardening_rejects_incident_kinds() {
        let root = TestRoot::new();
        let (services, session, _harness) = bound_services(&root).await;
        let incident = ResponseIssue {
            kind: ResponseIssueKind::PamBackdoor,
            severity: ResponseSeverity::Critical,
            summary: "x".to_owned(),
            evidence: vec![],
            fixable: true,
            fix_summary: None,
            object: IssueObject::PamLine {
                file: "/etc/pam.d/sshd".to_owned(),
                line: 4,
                line_sha256: "0".repeat(64),
            },
        };
        let error = services
            .response_engine()
            .plan_hardening(&session, &incident)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("加固"));
    }
}
