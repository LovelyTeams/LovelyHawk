//! Read-only remote file analysis with one validated path boundary.

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use futures::{StreamExt, stream};
use serde::{Deserialize, Serialize};

use crate::shell_escape::shq;
use crate::ssh::{BoundSshSession, SshCommandOutput, SshService};
use crate::target::TargetContext;
use crate::{CoreError, CoreResult};

const MAX_ANALYSIS_OUTPUT_BYTES: usize = 65_536;
const MAX_CONCURRENT_CHECKS: usize = 4;
const REMOTE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FileAnalysisCheck {
    Hashes,
    Signature,
    Metadata,
    FileSize,
    Permissions,
    Timestamps,
    MimeType,
    Strings,
    HexDump,
    LineCount,
    ArchiveList,
    RelatedProcesses,
    HardLinks,
    ProcessMaps,
    SuspiciousPath,
    HiddenFile,
    SuidSgid,
    WebshellIndicators,
    BackdoorIndicators,
    CryptoMinerIndicators,
    ReverseShellIndicators,
    ElfHeader,
    DynamicDependencies,
    ExtendedAttributes,
    FileCapabilities,
    SelinuxContext,
    SymlinkTarget,
    PackageOwner,
    ConfigReferences,
}

impl FileAnalysisCheck {
    pub const ALL: [Self; 29] = [
        Self::Hashes,
        Self::Signature,
        Self::Metadata,
        Self::FileSize,
        Self::Permissions,
        Self::Timestamps,
        Self::MimeType,
        Self::Strings,
        Self::HexDump,
        Self::LineCount,
        Self::ArchiveList,
        Self::RelatedProcesses,
        Self::HardLinks,
        Self::ProcessMaps,
        Self::ExtendedAttributes,
        Self::FileCapabilities,
        Self::SelinuxContext,
        Self::ElfHeader,
        Self::DynamicDependencies,
        Self::SymlinkTarget,
        Self::PackageOwner,
        Self::ConfigReferences,
        Self::SuspiciousPath,
        Self::HiddenFile,
        Self::SuidSgid,
        Self::WebshellIndicators,
        Self::BackdoorIndicators,
        Self::CryptoMinerIndicators,
        Self::ReverseShellIndicators,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Hashes => "MD5 / SHA-1 / SHA-256",
            Self::Signature => "文件签名",
            Self::Metadata => "元数据 / Inode",
            Self::FileSize => "文件大小",
            Self::Permissions => "权限 / ACL",
            Self::Timestamps => "时间戳",
            Self::MimeType => "MIME 类型",
            Self::Strings => "可打印字符串",
            Self::HexDump => "十六进制",
            Self::LineCount => "行数统计",
            Self::ArchiveList => "归档清单",
            Self::RelatedProcesses => "关联进程",
            Self::HardLinks => "硬链接",
            Self::ProcessMaps => "进程映射",
            Self::SuspiciousPath => "可疑路径",
            Self::HiddenFile => "隐藏文件",
            Self::SuidSgid => "SUID / SGID",
            Self::WebshellIndicators => "WebShell 特征",
            Self::BackdoorIndicators => "后门特征",
            Self::CryptoMinerIndicators => "挖矿特征",
            Self::ReverseShellIndicators => "反弹 Shell 特征",
            Self::ElfHeader => "ELF 结构",
            Self::DynamicDependencies => "动态依赖",
            Self::ExtendedAttributes => "扩展属性",
            Self::FileCapabilities => "文件能力",
            Self::SelinuxContext => "SELinux 标签",
            Self::SymlinkTarget => "符号链接",
            Self::PackageOwner => "所属软件包",
            Self::ConfigReferences => "配置引用",
        }
    }

    pub const fn group_label(self) -> &'static str {
        match self {
            Self::Hashes
            | Self::Signature
            | Self::Metadata
            | Self::FileSize
            | Self::Permissions
            | Self::Timestamps
            | Self::MimeType => "基础信息",
            Self::Strings
            | Self::HexDump
            | Self::LineCount
            | Self::ArchiveList
            | Self::ElfHeader
            | Self::DynamicDependencies => "内容与结构",
            Self::RelatedProcesses
            | Self::HardLinks
            | Self::ProcessMaps
            | Self::ExtendedAttributes
            | Self::FileCapabilities
            | Self::SelinuxContext
            | Self::SymlinkTarget
            | Self::PackageOwner
            | Self::ConfigReferences => "系统关联",
            Self::SuspiciousPath
            | Self::HiddenFile
            | Self::SuidSgid
            | Self::WebshellIndicators
            | Self::BackdoorIndicators
            | Self::CryptoMinerIndicators
            | Self::ReverseShellIndicators => "安全检测",
        }
    }

    pub const fn recommended(self) -> bool {
        matches!(
            self,
            Self::Hashes
                | Self::Signature
                | Self::Metadata
                | Self::Permissions
                | Self::Timestamps
                | Self::MimeType
                | Self::SuspiciousPath
                | Self::HiddenFile
                | Self::SuidSgid
                | Self::WebshellIndicators
                | Self::BackdoorIndicators
                | Self::CryptoMinerIndicators
                | Self::ReverseShellIndicators
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileAnalysisRequest {
    pub remote_path: String,
    pub checks: BTreeSet<FileAnalysisCheck>,
    pub strings_limit: usize,
    pub hex_bytes: usize,
}

impl FileAnalysisRequest {
    pub fn recommended(remote_path: impl Into<String>) -> Self {
        Self {
            remote_path: remote_path.into(),
            checks: FileAnalysisCheck::ALL
                .into_iter()
                .filter(|check| check.recommended())
                .collect(),
            strings_limit: 100,
            hex_bytes: 512,
        }
    }

    pub fn validate(&self) -> CoreResult<()> {
        validate_remote_file_path(&self.remote_path)?;
        if self.checks.is_empty() || self.checks.len() > FileAnalysisCheck::ALL.len() {
            return Err(CoreError::validation(
                "file analysis checks",
                "must contain 1..=29 closed checks",
            ));
        }
        if !(1..=10_000).contains(&self.strings_limit) {
            return Err(CoreError::validation("strings limit", "must be 1..=10000"));
        }
        if !(1..=65_536).contains(&self.hex_bytes) {
            return Err(CoreError::validation(
                "hex dump size",
                "must be 1..=65536 bytes",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileAnalysisFinding {
    pub check: FileAnalysisCheck,
    pub output: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileAnalysisResult {
    pub remote_path: String,
    pub findings: Vec<FileAnalysisFinding>,
}

#[derive(Debug, Clone)]
pub struct FileAnalysisService {
    ssh: SshService,
    target: Arc<TargetContext>,
}

impl FileAnalysisService {
    pub fn new(ssh: SshService, target: Arc<TargetContext>) -> Self {
        Self { ssh, target }
    }

    pub async fn analyze(
        &self,
        session: &BoundSshSession,
        request: &FileAnalysisRequest,
    ) -> CoreResult<FileAnalysisResult> {
        request.validate()?;
        self.target.validate(session.target())?;
        let operations = request
            .checks
            .iter()
            .copied()
            .enumerate()
            .map(|(index, check)| {
                let service = self.clone();
                let session = session.clone();
                let request = request.clone();
                async move {
                    let result = service.analyze_check(&session, &request, check).await;
                    (index, result)
                }
            });
        let mut outcomes = stream::iter(operations)
            .buffer_unordered(MAX_CONCURRENT_CHECKS)
            .collect::<Vec<_>>()
            .await;
        self.target.validate(session.target())?;
        outcomes.sort_by_key(|(index, _)| *index);
        let findings = outcomes
            .into_iter()
            .map(|(_, result)| result)
            .collect::<CoreResult<Vec<_>>>()?;
        Ok(FileAnalysisResult {
            remote_path: request.remote_path.clone(),
            findings,
        })
    }

    async fn analyze_check(
        &self,
        session: &BoundSshSession,
        request: &FileAnalysisRequest,
        check: FileAnalysisCheck,
    ) -> CoreResult<FileAnalysisFinding> {
        self.target.validate(session.target())?;
        let command = build_analysis_command(request, check)?;
        let output = self
            .ssh
            .execute_bound(session, command, REMOTE_TIMEOUT)
            .await?;
        self.target.validate(session.target())?;
        parse_analysis_output(check, output)
    }
}

fn build_analysis_command(
    request: &FileAnalysisRequest,
    check: FileAnalysisCheck,
) -> CoreResult<String> {
    validate_remote_file_path(&request.remote_path)?;
    let path = shq(&request.remote_path);
    Ok(match check {
        FileAnalysisCheck::Hashes => format!(
            "md5sum -- {path} 2>/dev/null | awk '{{print \"md5=\" tolower($1)}}' && sha1sum -- {path} 2>/dev/null | awk '{{print \"sha1=\" tolower($1)}}' && sha256sum -- {path} 2>/dev/null | awk '{{print \"sha256=\" tolower($1)}}'"
        ),
        FileAnalysisCheck::Signature => format!(
            "file --brief -- {path} 2>/dev/null; head -c 16 -- {path} 2>/dev/null | od -An -tx1"
        ),
        FileAnalysisCheck::Metadata => format!(
            "stat -c 'mode=%A|uid=%u|gid=%g|size=%s|inode=%i|links=%h|device=%d' -- {path} 2>/dev/null"
        ),
        FileAnalysisCheck::FileSize => format!(
            "stat -c 'bytes=%s|blocks=%b|block_size=%B' -- {path} 2>/dev/null; du -h -- {path} 2>/dev/null | head -n 1"
        ),
        FileAnalysisCheck::Permissions => format!(
            "stat -c '%A|%a|%U|%G' -- {path} 2>/dev/null; getfacl -cp -- {path} 2>/dev/null || true"
        ),
        FileAnalysisCheck::Timestamps => {
            format!("stat -c 'atime=%x|mtime=%y|ctime=%z|birth=%w' -- {path} 2>/dev/null")
        }
        FileAnalysisCheck::MimeType => format!("file --brief --mime-type -- {path} 2>/dev/null"),
        FileAnalysisCheck::Strings => format!(
            "strings -a -- {path} 2>/dev/null | head -n {}",
            request.strings_limit
        ),
        FileAnalysisCheck::HexDump => format!(
            "head -c {} -- {path} 2>/dev/null | od -Ax -tx1z -v",
            request.hex_bytes
        ),
        FileAnalysisCheck::LineCount => {
            format!("wc -l -- {path} 2>/dev/null | awk '{{print $1}}'")
        }
        FileAnalysisCheck::ArchiveList => format!(
            "(tar -tf {path} 2>/dev/null || unzip -Z1 {path} 2>/dev/null || true) | head -n 1000"
        ),
        FileAnalysisCheck::RelatedProcesses => {
            format!("lsof -- {path} 2>/dev/null | head -n 200 || true")
        }
        FileAnalysisCheck::HardLinks => {
            format!("find / -xdev -samefile {path} -print 2>/dev/null | head -n 200 || true")
        }
        FileAnalysisCheck::ProcessMaps => {
            format!("grep -F -l -- {path} /proc/[0-9]*/maps 2>/dev/null | head -n 200 || true")
        }
        FileAnalysisCheck::SuspiciousPath => format!(
            "case {path} in /tmp/*|/var/tmp/*|/dev/shm/*|/run/user/*) echo suspicious-path;; *) echo normal-path;; esac"
        ),
        FileAnalysisCheck::HiddenFile => format!(
            "name=$(basename -- {path}); case \"$name\" in .*) echo hidden-file;; *) echo visible-file;; esac"
        ),
        FileAnalysisCheck::SuidSgid => format!(
            "stat -c 'mode=%A|octal=%a' -- {path} 2>/dev/null; if find {path} -maxdepth 0 -perm /6000 -print -quit 2>/dev/null | grep -q .; then echo privileged-bits=yes; else echo privileged-bits=no; fi"
        ),
        FileAnalysisCheck::WebshellIndicators => format!(
            "grep -Eina -m 100 -- '(eval[[:space:]]*\\(|base64_decode|assert[[:space:]]*\\(|system[[:space:]]*\\(|shell_exec|passthru|Runtime\\.getRuntime|ProcessBuilder)' {path} 2>/dev/null || true"
        ),
        FileAnalysisCheck::BackdoorIndicators => format!(
            "grep -Eina -m 100 -- '(authorized_keys|LD_PRELOAD|/etc/cron|useradd|chmod[[:space:]]+\\+s|nohup|setsid)' {path} 2>/dev/null || true"
        ),
        FileAnalysisCheck::CryptoMinerIndicators => format!(
            "grep -Eina -m 100 -- '(stratum\\+tcp|xmrig|cryptonight|monero|nanopool|minergate)' {path} 2>/dev/null || true"
        ),
        FileAnalysisCheck::ReverseShellIndicators => format!(
            "grep -Eina -m 100 -- '(/dev/tcp|/dev/udp|bash[[:space:]]+-i|nc[[:space:]].*-e|ncat[[:space:]].*--exec|socket\\(|connect\\()' {path} 2>/dev/null || true"
        ),
        FileAnalysisCheck::ElfHeader => {
            format!("readelf -h -l -S -- {path} 2>/dev/null | head -n 500 || true")
        }
        FileAnalysisCheck::DynamicDependencies => {
            format!("readelf -d -- {path} 2>/dev/null | head -n 300 || true")
        }
        FileAnalysisCheck::ExtendedAttributes => {
            format!("getfattr -d -m- -- {path} 2>/dev/null || true")
        }
        FileAnalysisCheck::FileCapabilities => {
            format!("getcap -- {path} 2>/dev/null || true")
        }
        FileAnalysisCheck::SelinuxContext => {
            format!("ls -Zd -- {path} 2>/dev/null || true")
        }
        FileAnalysisCheck::SymlinkTarget => format!(
            "if [ -L {path} ]; then readlink -- {path}; readlink -f -- {path}; else echo not-a-symlink; fi"
        ),
        FileAnalysisCheck::PackageOwner => format!(
            "(dpkg -S -- {path} 2>/dev/null || rpm -qf -- {path} 2>/dev/null || apk info -W -- {path} 2>/dev/null || pacman -Qo -- {path} 2>/dev/null) | head -n 20"
        ),
        FileAnalysisCheck::ConfigReferences => {
            format!("grep -RFl -m 100 -- {path} /etc 2>/dev/null | head -n 100 || true")
        }
    })
}

fn validate_remote_file_path(path: &str) -> CoreResult<()> {
    if !path.starts_with('/')
        || path.len() > 4_096
        || path.contains(['\0', '\n', '\r'])
        || path.split('/').any(|component| component == "..")
    {
        return Err(CoreError::validation(
            "remote file path",
            "must be an absolute traversal-free path of at most 4096 bytes",
        ));
    }
    Ok(())
}

fn parse_analysis_output(
    check: FileAnalysisCheck,
    output: SshCommandOutput,
) -> CoreResult<FileAnalysisFinding> {
    if output.timed_out || output.exit_code.is_some_and(|code| code != 0) {
        return Err(CoreError::validation(
            "file analysis command",
            format!(
                "remote check {} failed (exit={:?}, timed_out={})",
                check.label(),
                output.exit_code,
                output.timed_out
            ),
        ));
    }
    let (output, truncated) = truncate_utf8(output.output, MAX_ANALYSIS_OUTPUT_BYTES);
    if check == FileAnalysisCheck::Hashes {
        validate_hash_output(&output)?;
    }
    Ok(FileAnalysisFinding {
        check,
        output,
        truncated,
    })
}

fn validate_hash_output(output: &str) -> CoreResult<()> {
    let expected = [("md5", 32), ("sha1", 40), ("sha256", 64)];
    let lines = output.lines().collect::<Vec<_>>();
    let valid = lines.len() == expected.len()
        && lines.iter().zip(expected).all(|(line, (name, length))| {
            line.strip_prefix(name)
                .and_then(|value| value.strip_prefix('='))
                .is_some_and(|value| {
                    value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
        });
    if !valid {
        return Err(CoreError::validation(
            "file hashes",
            "remote command did not return exact MD5, SHA-1 and SHA-256 digests",
        ));
    }
    Ok(())
}

fn truncate_utf8(value: String, maximum_bytes: usize) -> (String, bool) {
    if value.len() <= maximum_bytes {
        return (value, false);
    }
    const SUFFIX: &str = "\n…[truncated]";
    let mut end = maximum_bytes.saturating_sub(SUFFIX.len());
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    (format!("{}{}", &value[..end], SUFFIX), true)
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, sync::Arc};

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
            let path =
                std::env::temp_dir().join(format!("lovelyres-file-analysis-{}", Uuid::new_v4()));
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

    fn request(path: &str, check: FileAnalysisCheck) -> FileAnalysisRequest {
        FileAnalysisRequest {
            remote_path: path.to_owned(),
            checks: BTreeSet::from([check]),
            strings_limit: 100,
            hex_bytes: 256,
        }
    }

    #[test]
    fn catalog_covers_every_legacy_analysis_family_without_raw_actions() {
        assert_eq!(FileAnalysisCheck::ALL.len(), 29);
        let labels = FileAnalysisCheck::ALL
            .into_iter()
            .map(FileAnalysisCheck::label)
            .collect::<BTreeSet<_>>();
        assert_eq!(labels.len(), FileAnalysisCheck::ALL.len());
        assert!(FileAnalysisCheck::ALL.contains(&FileAnalysisCheck::Hashes));
        assert!(FileAnalysisCheck::ALL.contains(&FileAnalysisCheck::ArchiveList));
        assert!(FileAnalysisCheck::ALL.contains(&FileAnalysisCheck::HardLinks));
        assert!(FileAnalysisCheck::ALL.contains(&FileAnalysisCheck::SelinuxContext));
        assert!(FileAnalysisCheck::ALL.contains(&FileAnalysisCheck::ConfigReferences));
        assert!(FileAnalysisCheck::ALL.contains(&FileAnalysisCheck::ReverseShellIndicators));
        assert_eq!(
            FileAnalysisRequest::recommended("/tmp/evidence")
                .checks
                .len(),
            13
        );
    }

    #[test]
    fn every_path_reaches_posix_quote_boundary() {
        let request = request(
            "/tmp/a'; touch /tmp/pwned; echo '",
            FileAnalysisCheck::Metadata,
        );
        let command = build_analysis_command(&request, FileAnalysisCheck::Metadata).unwrap();
        assert!(command.contains("'/tmp/a'\\''; touch /tmp/pwned; echo '\\'''"));
        assert!(!command.contains("stat -c '/tmp/a';"));
    }

    #[test]
    fn rejects_relative_traversal_and_line_injection_paths() {
        for path in ["etc/passwd", "/tmp/../etc/shadow", "/tmp/x\nwhoami"] {
            assert!(
                request(path, FileAnalysisCheck::Metadata)
                    .validate()
                    .is_err()
            );
        }
    }

    #[test]
    fn hashes_are_exact_and_hostile_utf8_output_is_bounded() {
        let hashes = parse_analysis_output(
            FileAnalysisCheck::Hashes,
            SshCommandOutput {
                command: "closed".to_owned(),
                output: format!(
                    "md5={}\nsha1={}\nsha256={}\n",
                    "ab".repeat(16),
                    "cd".repeat(20),
                    "ef".repeat(32)
                ),
                exit_code: Some(0),
                duration_ms: 1,
                timed_out: false,
            },
        )
        .unwrap();
        assert!(!hashes.truncated);

        let malformed = parse_analysis_output(
            FileAnalysisCheck::Hashes,
            SshCommandOutput {
                command: "closed".to_owned(),
                output: "sha256=not-a-digest".to_owned(),
                exit_code: Some(0),
                duration_ms: 1,
                timed_out: false,
            },
        );
        assert!(malformed.is_err());

        let bounded = parse_analysis_output(
            FileAnalysisCheck::Strings,
            SshCommandOutput {
                command: "closed".to_owned(),
                output: "界".repeat(MAX_ANALYSIS_OUTPUT_BYTES),
                exit_code: Some(0),
                duration_ms: 1,
                timed_out: false,
            },
        )
        .unwrap();
        assert!(bounded.truncated);
        assert!(bounded.output.len() <= MAX_ANALYSIS_OUTPUT_BYTES);
        assert!(bounded.output.is_char_boundary(bounded.output.len()));
    }

    #[test]
    fn binary_dependency_check_never_invokes_ldd_on_attacker_controlled_files() {
        let request = request("/tmp/untrusted", FileAnalysisCheck::DynamicDependencies);
        let command =
            build_analysis_command(&request, FileAnalysisCheck::DynamicDependencies).unwrap();
        assert!(command.contains("readelf -d"));
        assert!(!command.contains("ldd"));
    }

    #[tokio::test]
    async fn analysis_is_bound_to_the_active_target() {
        let root = TestRoot::new();
        let (services, session, harness) = bound_services(&root).await;
        harness.set_execute_output(format!(
            "md5={}\nsha1={}\nsha256={}\n",
            "ab".repeat(16),
            "cd".repeat(20),
            "ef".repeat(32)
        ));
        let request = FileAnalysisRequest {
            remote_path: "/tmp/evidence".to_owned(),
            checks: BTreeSet::from([FileAnalysisCheck::Hashes]),
            strings_limit: 100,
            hex_bytes: 256,
        };
        let result = services
            .file_analysis()
            .analyze(&session, &request)
            .await
            .unwrap();
        assert_eq!(result.remote_path, "/tmp/evidence");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].check, FileAnalysisCheck::Hashes);

        services
            .activate_target(TargetIdentity::new("connection-b").unwrap())
            .unwrap();
        assert!(
            services
                .file_analysis()
                .analyze(&session, &request)
                .await
                .is_err()
        );
    }
}
