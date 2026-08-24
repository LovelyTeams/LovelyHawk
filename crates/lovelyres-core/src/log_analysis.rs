//! Target-bound log collection, threat summarization, and safely quoted queries.

use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use chrono::NaiveDate;
use futures::{StreamExt, stream};
use parking_lot::Mutex;
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::domain::bounded_text;
use crate::operations::{
    DangerousConfirmation, ExecutionReceipt, OperationExecutor, OperationJournal, OperationPlan,
    OperationState, PlannedOperation, VerificationResult,
};
use crate::shell_escape::shq;
use crate::ssh::{BoundSshSession, SshCommandOutput, SshService};
use crate::store::StoreFile;
use crate::target::{TargetContext, TargetGuard, TargetIdentity};
use crate::{CoreError, CoreResult, PortableStore};

const MAX_PAGE_SIZE: usize = 10_000;
const MAX_LOG_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_LOG_LINE_CHARS: usize = 16 * 1024;
const MAX_LOG_FILES: usize = 100;
const MAX_MULTI_LOG_SOURCES: usize = 10;
const MAX_IOC_INDICATORS: usize = 64;
const MAX_IOC_RESULTS: usize = 256;
const REMOTE_TIMEOUT: Duration = Duration::from_secs(60);
const LOG_RULES_SCHEMA_ID: &str = "lovelyres-log-rules/v1";
const LOCAL_LOG_RULE_TARGET: &str = "portable-workspace:log-rules";
const MAX_LOG_RULES: usize = 128;
const MAX_LOG_RULE_NAME_BYTES: usize = 128;
const MAX_LOG_RULE_PATTERN_BYTES: usize = 1_024;

pub const COMMON_LOG_FILES: &[(&str, &str)] = &[
    ("/var/log/auth.log", "认证日志"),
    ("/var/log/secure", "安全日志"),
    ("/var/log/syslog", "系统日志"),
    ("/var/log/messages", "系统消息"),
    ("/var/log/kern.log", "内核日志"),
    ("/var/log/cron", "计划任务日志"),
    ("/var/log/maillog", "邮件日志"),
    ("/var/log/boot.log", "启动日志"),
    ("/var/log/dmesg", "设备消息"),
    ("/var/log/audit/audit.log", "审计日志"),
];

pub const HIGHLIGHT_KEYWORDS: &[&str] = &[
    "Failed password",
    "authentication failure",
    "Invalid user",
    "Accepted",
    "sudo",
    "COMMAND=",
    "denied",
    "unauthorized",
    "segfault",
    "oom-killer",
    "reverse mapping",
];

const SUSPICIOUS_KEYWORDS: &[&str] = &[
    "reverse shell",
    "nc -e",
    "ncat",
    "/dev/tcp",
    "/dev/udp",
    "wget http",
    "curl http",
    "chmod 777",
    "chmod +s",
    "LD_PRELOAD",
    "crontab -e",
    "useradd",
    "iptables -F",
    "history -c",
    "unset HISTFILE",
    ".ssh/authorized_keys",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub service: String,
    pub message: String,
    pub raw: String,
    pub highlighted: bool,
    pub source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IpCount {
    pub ip: String,
    pub count: usize,
    pub last_seen: String,
    pub action_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserCount {
    pub username: String,
    pub count: usize,
    pub success_count: usize,
    pub fail_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ThreatSummary {
    pub brute_force_count: usize,
    pub successful_login_count: usize,
    pub privilege_escalation_count: usize,
    pub suspicious_activity_count: usize,
    pub top_source_ips: Vec<IpCount>,
    pub top_target_users: Vec<UserCount>,
    pub hourly_distribution: Vec<usize>,
    pub threat_level: ThreatLevel,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ThreatLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

/// A validated calendar day used by both file-log and journal queries.
///
/// The string form is always the fixed ISO `YYYY-MM-DD` representation. Keeping this typed in
/// Core prevents UI-controlled free-form date expressions from reaching `grep` or journalctl.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct LogCalendarDay(NaiveDate);

impl LogCalendarDay {
    pub fn parse(value: &str) -> CoreResult<Self> {
        if value.len() != 10
            || value.as_bytes().get(4) != Some(&b'-')
            || value.as_bytes().get(7) != Some(&b'-')
        {
            return Err(CoreError::validation(
                "log calendar day",
                "must use the exact YYYY-MM-DD format",
            ));
        }
        NaiveDate::parse_from_str(value, "%Y-%m-%d")
            .map(Self)
            .map_err(|_| CoreError::validation("log calendar day", "is not a valid date"))
    }

    pub fn as_iso_string(&self) -> String {
        self.0.format("%Y-%m-%d").to_string()
    }

    fn file_filter(self) -> String {
        self.0.format("%Y-%m-%d").to_string()
    }

    fn journal_since(self) -> String {
        self.0.format("%Y-%m-%d 00:00:00").to_string()
    }

    fn journal_until(self) -> String {
        self.0.format("%Y-%m-%d 23:59:59").to_string()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogRuleSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogMatchRule {
    pub id: String,
    pub name: String,
    pub pattern: String,
    pub severity: LogRuleSeverity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateLogMatchRule {
    pub name: String,
    pub pattern: String,
    pub severity: LogRuleSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct LogRulesDocument {
    schema: String,
    rules: Vec<LogMatchRule>,
}

impl Default for LogRulesDocument {
    fn default() -> Self {
        Self {
            schema: LOG_RULES_SCHEMA_ID.to_owned(),
            rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRuleRemovalPlan {
    rule: LogMatchRule,
    rules_sha256: String,
    operation: OperationPlan,
}

impl LogRuleRemovalPlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn rule(&self) -> &LogMatchRule {
        &self.rule
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRuleRemovalOutcome {
    pub removed_rule_id: String,
    pub verification: VerificationResult,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogQuery {
    pub log_path: String,
    pub page: usize,
    pub page_size: usize,
    pub filter: Option<String>,
    pub date_filter: Option<LogCalendarDay>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JournalQuery {
    pub page: usize,
    pub page_size: usize,
    pub unit: Option<String>,
    pub filter: Option<String>,
    pub date_filter: Option<LogCalendarDay>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MultiLogQuery {
    pub log_paths: Vec<String>,
    pub line_limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IocSearchQuery {
    pub indicators: Vec<String>,
    pub log_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogFileInfo {
    pub path: String,
    pub name: String,
    pub size: u64,
    pub modified: String,
    pub readable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogAnalysisResult {
    pub entries: Vec<LogEntry>,
    pub total_count: usize,
    pub highlighted_count: usize,
    pub threat_summary: Option<ThreatSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MultiLogResult {
    pub entries: Vec<LogEntry>,
    pub total_count: usize,
    pub sources: Vec<String>,
    pub threat_summary: ThreatSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IocMatch {
    pub indicator: String,
    pub log_file: String,
    pub count: usize,
    pub sample_lines: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IocSearchResult {
    pub results: Vec<IocMatch>,
    pub total_matches: usize,
}

#[derive(Debug, Clone)]
pub struct LogAnalysisService {
    ssh: SshService,
    target: Arc<TargetContext>,
    store: PortableStore,
    rule_lock: Arc<Mutex<()>>,
    local_rule_target: Arc<TargetContext>,
    local_rule_guard: TargetGuard,
}

impl LogAnalysisService {
    pub fn new(ssh: SshService, target: Arc<TargetContext>, store: PortableStore) -> Self {
        let local_rule_target = Arc::new(TargetContext::new());
        let local_rule_guard = local_rule_target
            .activate(
                TargetIdentity::new(LOCAL_LOG_RULE_TARGET)
                    .expect("the built-in local log-rule target is valid"),
            )
            .expect("a new local log-rule target can be activated");
        Self {
            ssh,
            target,
            store,
            rule_lock: Arc::new(Mutex::new(())),
            local_rule_target,
            local_rule_guard,
        }
    }

    pub fn list_rules(&self) -> CoreResult<Vec<LogMatchRule>> {
        let _guard = self.rule_lock.lock();
        Ok(self.load_rules_locked()?.rules)
    }

    pub fn add_rule(&self, input: CreateLogMatchRule) -> CoreResult<LogMatchRule> {
        validate_rule_fields(&input.name, &input.pattern)?;
        let _guard = self.rule_lock.lock();
        let mut document = self.load_rules_locked()?;
        if document.rules.len() >= MAX_LOG_RULES {
            return Err(CoreError::validation(
                "log match rules",
                format!("may contain at most {MAX_LOG_RULES} rules"),
            ));
        }
        if document
            .rules
            .iter()
            .any(|rule| rule.name.eq_ignore_ascii_case(input.name.trim()))
        {
            return Err(CoreError::validation(
                "log rule name",
                "must be unique ignoring ASCII case",
            ));
        }
        let rule = LogMatchRule {
            id: format!("log-rule-{}", Uuid::new_v4()),
            name: input.name.trim().to_owned(),
            pattern: input.pattern,
            severity: input.severity,
        };
        document.rules.push(rule.clone());
        self.store.write(StoreFile::LogRules, &document)?;
        Ok(rule)
    }

    pub fn match_rules(
        &self,
        rules: &[LogMatchRule],
        entries: &[LogEntry],
    ) -> CoreResult<Vec<Option<LogMatchRule>>> {
        if rules.len() > MAX_LOG_RULES || entries.len() > MAX_PAGE_SIZE {
            return Err(CoreError::validation(
                "log rule matching",
                "rules or entries exceed the bounded page limits",
            ));
        }
        let compiled = rules
            .iter()
            .map(|rule| {
                validate_rule_id(&rule.id)?;
                let regex = validate_rule_fields(&rule.name, &rule.pattern)?;
                Ok::<_, CoreError>((rule, regex))
            })
            .collect::<CoreResult<Vec<_>>>()?;
        Ok(entries
            .iter()
            .map(|entry| {
                compiled
                    .iter()
                    .find(|(_, regex)| regex.is_match(&entry.raw))
                    .map(|(rule, _)| (*rule).clone())
            })
            .collect())
    }

    pub fn plan_remove_rule(&self, rule_id: &str) -> CoreResult<LogRuleRemovalPlan> {
        validate_rule_id(rule_id)?;
        let _guard = self.rule_lock.lock();
        let document = self.load_rules_locked()?;
        let rule = document
            .rules
            .iter()
            .find(|rule| rule.id == rule_id)
            .cloned()
            .ok_or_else(|| CoreError::NotFound {
                entity: "log match rule",
                id: rule_id.to_owned(),
            })?;
        let rules_sha256 = log_rules_sha256(&document.rules);
        let mut operation = OperationPlan::new(
            self.local_rule_guard.clone(),
            format!("永久删除日志匹配规则「{}」；此操作不可恢复。", rule.name),
            true,
            None,
        )?;
        operation
            .metadata
            .insert("rule-id".to_owned(), rule.id.clone());
        operation
            .metadata
            .insert("rule-set-sha256".to_owned(), rules_sha256.clone());
        Ok(LogRuleRemovalPlan {
            rule,
            rules_sha256,
            operation,
        })
    }

    pub async fn execute_remove_rule(
        &self,
        plan: LogRuleRemovalPlan,
        confirmation: DangerousConfirmation,
        journal: &dyn OperationJournal,
    ) -> CoreResult<LogRuleRemovalOutcome> {
        let removed_rule_id = plan.rule.id.clone();
        let executor = LogRuleRemovalExecutor {
            service: self.clone(),
            plan: plan.clone(),
        };
        let mut operation = PlannedOperation::plan(plan.operation);
        operation.confirm(confirmation)?;
        if let Err(error) = operation
            .execute(self.local_rule_target.as_ref(), &executor)
            .await
        {
            if operation.state() == OperationState::StaleAfterExecution {
                operation.journal(journal)?;
            }
            return Err(error);
        }
        operation.journal(journal)?;
        let verification = operation
            .verify(self.local_rule_target.as_ref(), &executor, journal)
            .await?;
        if !verification.passed {
            return Err(CoreError::validation(
                "log rule removal verification",
                verification.detail,
            ));
        }
        Ok(LogRuleRemovalOutcome {
            removed_rule_id,
            verification,
        })
    }

    fn load_rules_locked(&self) -> CoreResult<LogRulesDocument> {
        let document = self
            .store
            .read_or_default::<LogRulesDocument>(StoreFile::LogRules)?;
        validate_rules_document(&document)?;
        Ok(document)
    }

    pub async fn read_file(
        &self,
        session: &BoundSshSession,
        query: &LogQuery,
        include_threat_summary: bool,
    ) -> CoreResult<LogAnalysisResult> {
        validate_log_query(query)?;
        let command = generate_log_read_command(query)?;
        let output = self
            .read_command(session, command, "read remote log")
            .await?;
        Ok(analysis_result(
            &output,
            query.page_size.clamp(1, MAX_PAGE_SIZE),
            None,
            include_threat_summary,
        ))
    }

    pub async fn read_journal(
        &self,
        session: &BoundSshSession,
        query: &JournalQuery,
        include_threat_summary: bool,
    ) -> CoreResult<LogAnalysisResult> {
        validate_journal_query(query)?;
        let command = generate_journalctl_command(
            query.page,
            query.page_size,
            query.unit.as_deref(),
            query.filter.as_deref(),
            query.date_filter,
        )?;
        let output = self
            .read_command(session, command, "read journal logs")
            .await?;
        Ok(analysis_result(
            &output,
            query.page_size.clamp(1, MAX_PAGE_SIZE),
            Some("journalctl"),
            include_threat_summary,
        ))
    }

    pub async fn list_files(&self, session: &BoundSshSession) -> CoreResult<Vec<LogFileInfo>> {
        let output = self
            .read_command(
                session,
                generate_list_log_files_command(),
                "list remote log files",
            )
            .await?;
        Ok(parse_log_files(&output))
    }

    pub async fn analyze_multi(
        &self,
        session: &BoundSshSession,
        query: &MultiLogQuery,
    ) -> CoreResult<MultiLogResult> {
        validate_multi_log_query(query)?;
        self.target.validate(session.target())?;
        let operations = query
            .log_paths
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, path)| {
                let service = self.clone();
                let session = session.clone();
                let line_limit = query.line_limit;
                async move {
                    let request = LogQuery {
                        log_path: path.clone(),
                        page: 1,
                        page_size: line_limit,
                        filter: None,
                        date_filter: None,
                    };
                    let result = service.read_file(&session, &request, false).await;
                    (index, path, result)
                }
            });
        let mut results = stream::iter(operations)
            .buffer_unordered(4)
            .collect::<Vec<_>>()
            .await;
        self.target.validate(session.target())?;
        results.sort_by_key(|(index, _, _)| *index);
        let sources = query.log_paths.clone();
        let mut entries = Vec::new();
        for (_, path, result) in results {
            let Ok(result) = result else {
                continue;
            };
            entries.extend(result.entries.into_iter().map(|mut entry| {
                entry.source = Some(path.clone());
                entry
            }));
        }
        entries.sort_by(|left, right| left.timestamp.cmp(&right.timestamp));
        entries.truncate(MAX_PAGE_SIZE);
        let threat_summary = analyze_threats(&entries);
        Ok(MultiLogResult {
            total_count: entries.len(),
            entries,
            sources,
            threat_summary,
        })
    }

    pub async fn search_iocs(
        &self,
        session: &BoundSshSession,
        query: &IocSearchQuery,
    ) -> CoreResult<IocSearchResult> {
        validate_ioc_query(query)?;
        self.target.validate(session.target())?;
        let operations = query
            .indicators
            .iter()
            .flat_map(|indicator| {
                query
                    .log_paths
                    .iter()
                    .map(move |path| (indicator.clone(), path.clone()))
            })
            .collect::<Vec<_>>();
        let tasks = operations.into_iter().map(|(indicator, path)| {
            let service = self.clone();
            let session = session.clone();
            async move {
                let command = generate_ioc_search_command(&indicator, &path)?;
                let output = service
                    .read_command(&session, command, "search log IOC")
                    .await?;
                Ok::<_, CoreError>(parse_ioc_match(indicator, path, &output))
            }
        });
        let outcomes = stream::iter(tasks)
            .buffer_unordered(4)
            .collect::<Vec<_>>()
            .await;
        self.target.validate(session.target())?;
        let mut results = outcomes
            .into_iter()
            .filter_map(Result::ok)
            .flatten()
            .collect::<Vec<_>>();
        results.sort_by(|left, right| {
            right
                .count
                .cmp(&left.count)
                .then_with(|| left.indicator.cmp(&right.indicator))
                .then_with(|| left.log_file.cmp(&right.log_file))
        });
        results.truncate(MAX_IOC_RESULTS);
        let total_matches = results
            .iter()
            .fold(0usize, |total, item| total.saturating_add(item.count));
        Ok(IocSearchResult {
            results,
            total_matches,
        })
    }

    async fn read_command(
        &self,
        session: &BoundSshSession,
        command: String,
        subject: &'static str,
    ) -> CoreResult<String> {
        self.target.validate(session.target())?;
        let output = self
            .ssh
            .execute_bound(session, command, REMOTE_TIMEOUT)
            .await?;
        self.target.validate(session.target())?;
        validate_command_output(subject, output)
    }
}

fn validate_command_output(subject: &'static str, output: SshCommandOutput) -> CoreResult<String> {
    if output.timed_out || output.exit_code.is_some_and(|code| code != 0) {
        return Err(CoreError::Validation {
            subject,
            message: format!(
                "remote command failed (exit={:?}, timed_out={})",
                output.exit_code, output.timed_out
            ),
        });
    }
    if output.output.len() > MAX_LOG_OUTPUT_BYTES {
        return Err(CoreError::Validation {
            subject,
            message: format!("remote output exceeds {MAX_LOG_OUTPUT_BYTES} bytes"),
        });
    }
    Ok(output.output)
}

fn analysis_result(
    output: &str,
    maximum_entries: usize,
    source: Option<&str>,
    include_threat_summary: bool,
) -> LogAnalysisResult {
    let entries = output
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.is_empty()
                && line != "Log file not found"
                && line != "No matching entries"
                && line != "journalctl not available"
        })
        .take(maximum_entries)
        .map(|line| {
            let bounded = truncate_chars(line, MAX_LOG_LINE_CHARS);
            let mut entry = parse_log_line(&bounded, HIGHLIGHT_KEYWORDS);
            entry.source = source.map(str::to_owned);
            entry
        })
        .collect::<Vec<_>>();
    let highlighted_count = entries.iter().filter(|entry| entry.highlighted).count();
    let threat_summary = include_threat_summary.then(|| analyze_threats(&entries));
    LogAnalysisResult {
        total_count: entries.len(),
        entries,
        highlighted_count,
        threat_summary,
    }
}

fn parse_log_files(output: &str) -> Vec<LogFileInfo> {
    let mut files = output
        .lines()
        .filter_map(|line| {
            let mut fields = line.splitn(3, '|');
            let size = fields.next()?.parse::<u64>().ok()?;
            let path = fields.next()?.trim();
            let modified = fields.next()?.trim();
            validate_remote_log_path(path).ok()?;
            let name = path.rsplit('/').next().unwrap_or(path);
            Some(LogFileInfo {
                path: path.to_owned(),
                name: truncate_chars(name, 256),
                size,
                modified: truncate_chars(modified, 64),
                readable: true,
            })
        })
        .take(MAX_LOG_FILES)
        .collect::<Vec<_>>();
    for (path, name) in COMMON_LOG_FILES {
        if !files.iter().any(|file| file.path == *path) {
            files.push(LogFileInfo {
                path: (*path).to_owned(),
                name: (*name).to_owned(),
                size: 0,
                modified: String::new(),
                readable: false,
            });
        }
    }
    files.sort_by(|left, right| {
        right
            .readable
            .cmp(&left.readable)
            .then_with(|| left.path.cmp(&right.path))
    });
    files.truncate(MAX_LOG_FILES);
    files
}

fn parse_ioc_match(indicator: String, path: String, output: &str) -> Option<IocMatch> {
    let mut lines = output.lines();
    let count = lines
        .next()
        .and_then(|line| line.trim().parse::<usize>().ok())?
        .min(1_000_000);
    if count == 0 {
        return None;
    }
    let sample_lines = lines
        .filter(|line| !line.trim().is_empty())
        .take(3)
        .map(|line| truncate_chars(line, 4_096))
        .collect();
    Some(IocMatch {
        indicator,
        log_file: path,
        count,
        sample_lines,
    })
}

#[derive(Debug)]
struct LogRuleRemovalExecutor {
    service: LogAnalysisService,
    plan: LogRuleRemovalPlan,
}

#[async_trait]
impl OperationExecutor for LogRuleRemovalExecutor {
    async fn execute(&self, definition: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        if definition != &self.plan.operation {
            return Err(CoreError::validation(
                "log rule removal",
                "executor received a different immutable plan",
            ));
        }
        let _guard = self.service.rule_lock.lock();
        let mut document = self.service.load_rules_locked()?;
        if log_rules_sha256(&document.rules) != self.plan.rules_sha256 {
            return Err(CoreError::validation(
                "log rule removal",
                "the rule set changed after confirmation",
            ));
        }
        let before = document.rules.len();
        document.rules.retain(|rule| rule.id != self.plan.rule.id);
        if document.rules.len() == before {
            return Err(CoreError::NotFound {
                entity: "log match rule",
                id: self.plan.rule.id.clone(),
            });
        }
        self.service.store.write(StoreFile::LogRules, &document)?;
        Ok(ExecutionReceipt {
            summary: format!("permanently removed log match rule {}", self.plan.rule.id),
            restore_token: None,
        })
    }

    async fn verify(
        &self,
        definition: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        if definition != &self.plan.operation {
            return Err(CoreError::validation(
                "log rule removal",
                "verification received a different immutable plan",
            ));
        }
        let absent = !self
            .service
            .list_rules()?
            .iter()
            .any(|rule| rule.id == self.plan.rule.id);
        Ok(VerificationResult {
            passed: absent,
            detail: if absent {
                "verified that the reviewed log match rule is absent".to_owned()
            } else {
                "the reviewed log match rule still exists".to_owned()
            },
        })
    }

    async fn restore(&self, _: &OperationPlan, _: &ExecutionReceipt) -> CoreResult<()> {
        Err(CoreError::Unsupported {
            feature: "restoring a removed log match rule",
        })
    }
}

fn validate_rule_fields(name: &str, pattern: &str) -> CoreResult<Regex> {
    let name = name.trim();
    if name.is_empty() || name.len() > MAX_LOG_RULE_NAME_BYTES || name.chars().any(char::is_control)
    {
        return Err(CoreError::validation(
            "log rule name",
            format!("must be non-empty, control-free, and at most {MAX_LOG_RULE_NAME_BYTES} bytes"),
        ));
    }
    if pattern.is_empty()
        || pattern.len() > MAX_LOG_RULE_PATTERN_BYTES
        || pattern.chars().any(char::is_control)
    {
        return Err(CoreError::validation(
            "log rule pattern",
            format!(
                "must be non-empty, control-free, and at most {MAX_LOG_RULE_PATTERN_BYTES} bytes"
            ),
        ));
    }
    RegexBuilder::new(pattern)
        .case_insensitive(true)
        .size_limit(256 * 1024)
        .dfa_size_limit(512 * 1024)
        .build()
        .map_err(|error| CoreError::validation("log rule pattern", error.to_string()))
}

fn validate_rule_id(id: &str) -> CoreResult<()> {
    let suffix = id.strip_prefix("log-rule-").ok_or_else(|| {
        CoreError::validation("log rule ID", "must use the service-generated namespace")
    })?;
    Uuid::parse_str(suffix)
        .map(|_| ())
        .map_err(|_| CoreError::validation("log rule ID", "contains an invalid UUID"))
}

fn validate_rules_document(document: &LogRulesDocument) -> CoreResult<()> {
    if document.schema != LOG_RULES_SCHEMA_ID {
        return Err(CoreError::validation(
            "log rules document",
            "contains an unsupported inner schema",
        ));
    }
    if document.rules.len() > MAX_LOG_RULES {
        return Err(CoreError::validation(
            "log match rules",
            format!("contains more than {MAX_LOG_RULES} rules"),
        ));
    }
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    for rule in &document.rules {
        validate_rule_id(&rule.id)?;
        validate_rule_fields(&rule.name, &rule.pattern)?;
        if !ids.insert(rule.id.as_str()) || !names.insert(rule.name.to_ascii_lowercase()) {
            return Err(CoreError::validation(
                "log match rules",
                "contain duplicate IDs or names",
            ));
        }
    }
    Ok(())
}

fn log_rules_sha256(rules: &[LogMatchRule]) -> String {
    let mut digest = Sha256::new();
    for rule in rules {
        for value in [&rule.id, &rule.name, &rule.pattern] {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value.as_bytes());
        }
        digest.update([rule.severity as u8]);
    }
    format!("{:x}", digest.finalize())
}

fn validate_log_query(query: &LogQuery) -> CoreResult<()> {
    validate_remote_log_path(&query.log_path)?;
    validate_pagination(query.page, query.page_size)?;
    if let Some(filter) = query
        .filter
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        bounded_text("log filter", filter.trim(), 1_024)?;
    }
    Ok(())
}

fn validate_journal_query(query: &JournalQuery) -> CoreResult<()> {
    validate_pagination(query.page, query.page_size)?;
    for (subject, value, maximum) in [
        ("journal unit", query.unit.as_deref(), 256),
        ("journal filter", query.filter.as_deref(), 1_024),
    ] {
        if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
            bounded_text(subject, value.trim(), maximum)?;
        }
    }
    Ok(())
}

fn validate_multi_log_query(query: &MultiLogQuery) -> CoreResult<()> {
    if query.log_paths.is_empty() || query.log_paths.len() > MAX_MULTI_LOG_SOURCES {
        return Err(CoreError::validation(
            "multi-log sources",
            format!("must contain 1..={MAX_MULTI_LOG_SOURCES} paths"),
        ));
    }
    if !(1..=MAX_PAGE_SIZE).contains(&query.line_limit) {
        return Err(CoreError::validation(
            "multi-log line limit",
            format!("must be 1..={MAX_PAGE_SIZE}"),
        ));
    }
    validate_unique_paths(&query.log_paths)
}

fn validate_ioc_query(query: &IocSearchQuery) -> CoreResult<()> {
    if query.indicators.is_empty() || query.indicators.len() > MAX_IOC_INDICATORS {
        return Err(CoreError::validation(
            "IOC indicators",
            format!("must contain 1..={MAX_IOC_INDICATORS} values"),
        ));
    }
    if query.log_paths.is_empty() || query.log_paths.len() > MAX_MULTI_LOG_SOURCES {
        return Err(CoreError::validation(
            "IOC log sources",
            format!("must contain 1..={MAX_MULTI_LOG_SOURCES} paths"),
        ));
    }
    if query
        .indicators
        .len()
        .checked_mul(query.log_paths.len())
        .is_none_or(|count| count > MAX_IOC_RESULTS)
    {
        return Err(CoreError::validation(
            "IOC search matrix",
            format!("must contain at most {MAX_IOC_RESULTS} indicator/source pairs"),
        ));
    }
    let mut indicators = BTreeSet::new();
    for indicator in &query.indicators {
        let indicator = indicator.trim();
        bounded_text("IOC indicator", indicator, 512)?;
        if !indicators.insert(indicator) {
            return Err(CoreError::validation(
                "IOC indicators",
                "must not contain duplicate values",
            ));
        }
    }
    validate_unique_paths(&query.log_paths)
}

fn validate_unique_paths(paths: &[String]) -> CoreResult<()> {
    let mut unique = BTreeSet::new();
    for path in paths {
        validate_remote_log_path(path)?;
        if !unique.insert(path.as_str()) {
            return Err(CoreError::validation(
                "log paths",
                "must not contain duplicate values",
            ));
        }
    }
    Ok(())
}

fn validate_pagination(page: usize, page_size: usize) -> CoreResult<()> {
    if page == 0 || page > 100_000 || !(1..=MAX_PAGE_SIZE).contains(&page_size) {
        return Err(CoreError::validation(
            "log pagination",
            format!("page must be 1..=100000 and page size 1..={MAX_PAGE_SIZE}"),
        ));
    }
    Ok(())
}

fn truncate_chars(value: &str, maximum: usize) -> String {
    let mut chars = value.chars();
    let mut truncated = chars.by_ref().take(maximum).collect::<String>();
    if chars.next().is_some() {
        truncated.push('…');
    }
    truncated
}

pub fn parse_log_line(line: &str, keywords: &[&str]) -> LogEntry {
    let highlighted = keywords.iter().any(|keyword| line.contains(keyword));
    if line.contains("type=") && line.contains("msg=audit(") {
        return parse_audit_line(line, highlighted);
    }
    let fields: Vec<_> = line.split_whitespace().collect();
    let timestamp = if fields.len() >= 3 {
        format!("{} {} {}", fields[0], fields[1], fields[2])
    } else {
        String::new()
    };
    let service = fields
        .get(4)
        .map(|value| value.trim_end_matches(':').to_owned())
        .unwrap_or_else(|| "unknown".to_owned());
    let message = line
        .find(':')
        .map(|position| line[position + 1..].trim().to_owned())
        .unwrap_or_else(|| line.to_owned());
    LogEntry {
        timestamp,
        level: detect_level(line).to_owned(),
        service,
        message,
        raw: line.to_owned(),
        highlighted,
        source: None,
    }
}

fn parse_audit_line(line: &str, highlighted: bool) -> LogEntry {
    let audit_type = extract_field(line, "type=");
    let success = extract_field(line, "success=");
    let executable = extract_field(line, "exe=").replace('"', "");
    let command = extract_field(line, "comm=").replace('"', "");
    let level = if matches!(audit_type.as_str(), "EXECVE" | "SYSCALL") {
        if success == "no" { "ERROR" } else { "WARN" }
    } else if audit_type.contains("USER_AUTH") || audit_type.contains("USER_LOGIN") {
        if success == "no" { "ERROR" } else { "INFO" }
    } else {
        "INFO"
    };
    let tail = line.split("):").nth(1).unwrap_or(line).trim();
    let message = if executable.is_empty() {
        tail.to_owned()
    } else {
        format!("{tail} exe={executable} comm={command}")
    };
    LogEntry {
        timestamp: extract_audit_timestamp(line),
        level: level.to_owned(),
        service: format!("audit({audit_type})"),
        message,
        raw: line.to_owned(),
        highlighted,
        source: None,
    }
}

fn extract_field(line: &str, prefix: &str) -> String {
    let Some(start) = line.find(prefix) else {
        return String::new();
    };
    let rest = &line[start + prefix.len()..];
    if let Some(quoted) = rest.strip_prefix('"') {
        quoted.split('"').next().unwrap_or_default().to_owned()
    } else {
        rest.split_whitespace()
            .next()
            .unwrap_or_default()
            .to_owned()
    }
}

fn extract_audit_timestamp(line: &str) -> String {
    let Some(rest) = line
        .find("audit(")
        .map(|position| &line[position + "audit(".len()..])
    else {
        return String::new();
    };
    rest.split(':')
        .next()
        .and_then(|value| value.parse::<f64>().ok())
        .and_then(|epoch| chrono::DateTime::from_timestamp(epoch as i64, 0))
        .map(|timestamp| timestamp.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_default()
}

fn detect_level(line: &str) -> &'static str {
    let lower = line.to_ascii_lowercase();
    if [
        "fail",
        "error",
        "denied",
        "invalid user",
        "authentication failure",
    ]
    .iter()
    .any(|value| lower.contains(value))
    {
        "ERROR"
    } else if lower.contains("warn") {
        "WARN"
    } else if lower.contains("debug") {
        "DEBUG"
    } else {
        "INFO"
    }
}

pub fn analyze_threats(entries: &[LogEntry]) -> ThreatSummary {
    let mut brute_force = 0;
    let mut successful_login = 0;
    let mut privilege_escalation = 0;
    let mut suspicious_activity = 0;
    let mut ips: HashMap<String, (usize, String, String)> = HashMap::new();
    let mut users: HashMap<String, (usize, usize)> = HashMap::new();
    let mut hourly_distribution = vec![0; 24];

    for entry in entries {
        let lower = entry.raw.to_ascii_lowercase();
        if lower.contains("failed password") || lower.contains("authentication failure") {
            brute_force += 1;
            if let Some(ip) = extract_ip(&entry.raw) {
                let value = ips.entry(ip).or_insert((0, String::new(), String::new()));
                value.0 += 1;
                value.1.clone_from(&entry.timestamp);
                value.2 = "failed_login".to_owned();
            }
            if let Some(user) = extract_target_user(&entry.raw) {
                users.entry(user).or_insert((0, 0)).1 += 1;
            }
        }
        if lower.contains("accepted password") || lower.contains("accepted publickey") {
            successful_login += 1;
            if let Some(ip) = extract_ip(&entry.raw) {
                let value = ips.entry(ip).or_insert((0, String::new(), String::new()));
                value.0 += 1;
                value.1.clone_from(&entry.timestamp);
                value.2 = "accepted_login".to_owned();
            }
            if let Some(user) = extract_target_user(&entry.raw) {
                users.entry(user).or_insert((0, 0)).0 += 1;
            }
        }
        if lower.contains("sudo") || lower.contains("su:") || lower.contains("command=") {
            privilege_escalation += 1;
        }
        if SUSPICIOUS_KEYWORDS
            .iter()
            .any(|keyword| lower.contains(&keyword.to_ascii_lowercase()))
        {
            suspicious_activity += 1;
        }
        if let Some(hour) = extract_hour(&entry.timestamp)
            && hour < 24
        {
            hourly_distribution[hour] += 1;
        }
    }

    let mut top_source_ips: Vec<_> = ips
        .into_iter()
        .map(|(ip, (count, last_seen, action_type))| IpCount {
            ip,
            count,
            last_seen,
            action_type,
        })
        .collect();
    top_source_ips.sort_by(|left, right| right.count.cmp(&left.count));
    top_source_ips.truncate(20);
    let mut top_target_users: Vec<_> = users
        .into_iter()
        .map(|(username, (success_count, fail_count))| UserCount {
            username,
            count: success_count + fail_count,
            success_count,
            fail_count,
        })
        .collect();
    top_target_users.sort_by(|left, right| right.count.cmp(&left.count));
    top_target_users.truncate(20);

    let threat_level = if brute_force > 100 || suspicious_activity > 10 {
        ThreatLevel::Critical
    } else if brute_force > 50 || suspicious_activity > 5 {
        ThreatLevel::High
    } else if brute_force > 10 || suspicious_activity > 0 {
        ThreatLevel::Medium
    } else if brute_force > 0 {
        ThreatLevel::Low
    } else {
        ThreatLevel::None
    };
    ThreatSummary {
        brute_force_count: brute_force,
        successful_login_count: successful_login,
        privilege_escalation_count: privilege_escalation,
        suspicious_activity_count: suspicious_activity,
        top_source_ips,
        top_target_users,
        hourly_distribution,
        threat_level,
    }
}

fn extract_ip(line: &str) -> Option<String> {
    for pattern in ["from ", "rhost=", "SRC=", "src=", "addr="] {
        if let Some(position) = line.find(pattern) {
            let token = line[position + pattern.len()..]
                .split(|character: char| !character.is_ascii_digit() && character != '.')
                .next()?;
            if token.parse::<std::net::Ipv4Addr>().is_ok() {
                return Some(token.to_owned());
            }
        }
    }
    line.split_whitespace().find_map(|word| {
        let value =
            word.trim_matches(|character: char| !character.is_ascii_digit() && character != '.');
        value
            .parse::<std::net::Ipv4Addr>()
            .ok()
            .filter(|address| !address.is_loopback() && !address.is_unspecified())
            .map(|address| address.to_string())
    })
}

fn extract_target_user(line: &str) -> Option<String> {
    for (start, end) in [
        ("for invalid user ", " from"),
        ("Invalid user ", " from"),
        ("for ", " from"),
        ("user=", " "),
    ] {
        if let Some(position) = line.find(start) {
            let rest = &line[position + start.len()..];
            let value = rest.split(end).next().unwrap_or_default().trim();
            if !value.is_empty()
                && value.len() < 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            {
                return Some(value.to_owned());
            }
        }
    }
    None
}

fn extract_hour(timestamp: &str) -> Option<usize> {
    timestamp
        .split_whitespace()
        .find(|part| part.contains(':'))
        .and_then(|part| part.split(':').next())
        .and_then(|hour| hour.parse().ok())
}

pub fn generate_log_read_command(query: &LogQuery) -> CoreResult<String> {
    validate_remote_log_path(&query.log_path)?;
    let page = query.page.max(1);
    let page_size = query.page_size.clamp(1, MAX_PAGE_SIZE);
    let total_lines = page.saturating_mul(page_size);
    let mut filters = String::new();
    if let Some(filter) = query
        .filter
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        bounded_text("log filter", filter, 1_024)?;
        filters.push_str(&format!(" | grep -i -- {}", shq(filter)));
    }
    if let Some(date) = query.date_filter {
        filters.push_str(&format!(" | grep -- {}", shq(&date.file_filter())));
    }
    let path = shq(&query.log_path);
    if filters.is_empty() {
        if page == 1 {
            Ok(format!("tail -n {page_size} -- {path} 2>/dev/null"))
        } else {
            Ok(format!(
                "tail -n {total_lines} -- {path} 2>/dev/null | head -n {page_size}"
            ))
        }
    } else if page == 1 {
        Ok(format!(
            "cat -- {path} 2>/dev/null{filters} | tail -n {page_size}"
        ))
    } else {
        Ok(format!(
            "cat -- {path} 2>/dev/null{filters} | tail -n {total_lines} | head -n {page_size}"
        ))
    }
}

pub fn generate_journalctl_command(
    page: usize,
    page_size: usize,
    unit: Option<&str>,
    filter: Option<&str>,
    date_filter: Option<LogCalendarDay>,
) -> CoreResult<String> {
    let mut command = "journalctl --no-pager".to_owned();
    for (flag, value, maximum) in [("-u", unit, 256)] {
        if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
            bounded_text("journal filter", value, maximum)?;
            command.push_str(&format!(" {flag} {}", shq(value)));
        }
    }
    if let Some(date) = date_filter {
        command.push_str(&format!(
            " --since {} --until {}",
            shq(&date.journal_since()),
            shq(&date.journal_until())
        ));
    }
    let page = page.max(1);
    let page_size = page_size.clamp(1, MAX_PAGE_SIZE);
    let total_lines = page.saturating_mul(page_size);
    if page == 1 {
        command.push_str(&format!(" -n {page_size}"));
    } else {
        command.push_str(&format!(" -n {total_lines} | head -n {page_size}"));
    }
    if let Some(filter) = filter.map(str::trim).filter(|value| !value.is_empty()) {
        bounded_text("journal text filter", filter, 1_024)?;
        command.push_str(&format!(" | grep -i -- {}", shq(filter)));
    }
    Ok(command)
}

pub fn generate_list_log_files_command() -> String {
    r#"find /var/log -maxdepth 2 -type f \( -name "*.log" -o -name "messages" -o -name "secure" -o -name "syslog" -o -name "auth.log" \) -readable -exec stat -c "%s|%n|%Y" {} \; 2>/dev/null | head -100"#.to_owned()
}

pub fn generate_ioc_search_command(indicator: &str, log_path: &str) -> CoreResult<String> {
    bounded_text("IOC indicator", indicator, 512)?;
    validate_remote_log_path(log_path)?;
    Ok(format!(
        "grep -F -c -- {indicator} {path} 2>/dev/null || echo '0'; grep -F -m 3 -- {indicator} {path} 2>/dev/null || true",
        indicator = shq(indicator),
        path = shq(log_path),
    ))
}

fn validate_remote_log_path(path: &str) -> CoreResult<()> {
    if !path.starts_with("/var/log/")
        || path.len() > 4_096
        || path.contains(['\0', '\n', '\r'])
        || path.split('/').any(|component| component == "..")
    {
        return Err(CoreError::validation(
            "remote log path",
            "must stay below /var/log and be traversal-free with at most 4096 bytes",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BackendServices, PortableStore};

    struct TestRoot(std::path::PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("lovelyres-log-rules-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn services(&self) -> BackendServices {
            BackendServices::new(PortableStore::prepare(self.0.clone()).unwrap()).unwrap()
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn command_arguments_are_quoted_and_pagination_is_bounded() {
        let command = generate_log_read_command(&LogQuery {
            log_path: "/var/log/a; touch /tmp/pwned".to_owned(),
            page: usize::MAX,
            page_size: usize::MAX,
            filter: Some("x'; touch /tmp/filter; echo '".to_owned()),
            date_filter: None,
        })
        .unwrap();
        assert!(command.contains("'/var/log/a; touch /tmp/pwned'"));
        assert!(command.contains("'x'\\''; touch /tmp/filter; echo '\\'''"));
        assert!(command.contains("head -n 10000"));
        assert!(!command.contains("grep -i 'x';"));
    }

    #[test]
    fn journal_limit_precedes_filter_pipeline() {
        let command = generate_journalctl_command(1, 100, None, Some("failed"), None).unwrap();
        assert!(command.contains(" -n 100 | grep -i -- 'failed'"));
    }

    #[test]
    fn calendar_day_is_strict_and_generates_closed_file_and_journal_bounds() {
        let leap_day = LogCalendarDay::parse("2024-02-29").unwrap();
        assert_eq!(leap_day.as_iso_string(), "2024-02-29");
        for invalid in [
            "2023-02-29",
            "2024-2-29",
            "2024/02/29",
            "2024-13-01",
            "2024-02-29; id",
            "2024-02-29\n--since yesterday",
        ] {
            assert!(
                LogCalendarDay::parse(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }

        let file = generate_log_read_command(&LogQuery {
            log_path: "/var/log/messages".to_owned(),
            page: 1,
            page_size: 100,
            filter: None,
            date_filter: Some(leap_day),
        })
        .unwrap();
        assert!(file.contains("grep -- '2024-02-29'"));

        let journal =
            generate_journalctl_command(1, 100, Some("sshd"), None, Some(leap_day)).unwrap();
        assert!(journal.contains("--since '2024-02-29 00:00:00'"));
        assert!(journal.contains("--until '2024-02-29 23:59:59'"));
    }

    #[tokio::test]
    async fn portable_log_rules_validate_match_and_remove_through_exact_workflow() {
        let root = TestRoot::new();
        let services = root.services();
        let logs = services.log_analysis();
        for invalid in ["(", "\n", &"x".repeat(MAX_LOG_RULE_PATTERN_BYTES + 1)] {
            assert!(
                logs.add_rule(CreateLogMatchRule {
                    name: "invalid".to_owned(),
                    pattern: invalid.to_owned(),
                    severity: LogRuleSeverity::High,
                })
                .is_err()
            );
        }
        let rule = logs
            .add_rule(CreateLogMatchRule {
                name: "Encoded payload".to_owned(),
                pattern: "eval\\(|base64_decode".to_owned(),
                severity: LogRuleSeverity::Critical,
            })
            .unwrap();
        assert!(
            logs.add_rule(CreateLogMatchRule {
                name: "encoded PAYLOAD".to_owned(),
                pattern: "ignored".to_owned(),
                severity: LogRuleSeverity::Low,
            })
            .is_err()
        );
        let entries = vec![
            LogEntry {
                timestamp: String::new(),
                level: "INFO".to_owned(),
                service: "web".to_owned(),
                message: "attacker text".to_owned(),
                raw: "<script>BASE64_DECODE($x)</script>".to_owned(),
                highlighted: false,
                source: None,
            },
            LogEntry {
                timestamp: String::new(),
                level: "INFO".to_owned(),
                service: "web".to_owned(),
                message: "ordinary".to_owned(),
                raw: "ordinary".to_owned(),
                highlighted: false,
                source: None,
            },
        ];
        let rules = logs.list_rules().unwrap();
        let matches = logs.match_rules(&rules, &entries).unwrap();
        assert_eq!(matches[0].as_ref().map(|rule| &rule.id), Some(&rule.id));
        assert_eq!(matches[0].as_ref().unwrap().name, "Encoded payload");
        assert!(matches[1].is_none());

        let rejected = logs.plan_remove_rule(&rule.id).unwrap();
        let error = logs
            .execute_remove_rule(
                rejected.clone(),
                DangerousConfirmation::reject(rejected.definition()),
                services.operation_journal(),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, CoreError::OperationCancelled { .. }));
        assert_eq!(logs.list_rules().unwrap().len(), 1);
        assert!(services.operation_journal().entries().unwrap().is_empty());

        let approved = logs.plan_remove_rule(&rule.id).unwrap();
        let outcome = logs
            .execute_remove_rule(
                approved.clone(),
                DangerousConfirmation::approve(approved.definition()),
                services.operation_journal(),
            )
            .await
            .unwrap();
        assert_eq!(outcome.removed_rule_id, rule.id);
        assert!(outcome.verification.passed);
        assert!(logs.list_rules().unwrap().is_empty());
        assert_eq!(services.operation_journal().entries().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn concurrent_rule_change_rejects_reviewed_removal_before_side_effect() {
        let root = TestRoot::new();
        let services = root.services();
        let logs = services.log_analysis();
        let first = logs
            .add_rule(CreateLogMatchRule {
                name: "first".to_owned(),
                pattern: "first".to_owned(),
                severity: LogRuleSeverity::Medium,
            })
            .unwrap();
        let plan = logs.plan_remove_rule(&first.id).unwrap();
        logs.add_rule(CreateLogMatchRule {
            name: "second".to_owned(),
            pattern: "second".to_owned(),
            severity: LogRuleSeverity::Low,
        })
        .unwrap();

        let error = logs
            .execute_remove_rule(
                plan.clone(),
                DangerousConfirmation::approve(plan.definition()),
                services.operation_journal(),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("changed after confirmation"));
        assert_eq!(logs.list_rules().unwrap().len(), 2);
        assert!(services.operation_journal().entries().unwrap().is_empty());
    }

    #[test]
    fn parses_audit_and_summarizes_login_threats() {
        let lines = [
            "Aug 11 03:01:02 host sshd[1]: Failed password for root from 10.0.0.8 port 22",
            "Aug 11 03:02:02 host sshd[1]: Accepted publickey for admin from 10.0.0.9 port 22",
            "type=SYSCALL msg=audit(1709234567.123:456): success=no exe=\"/bin/sh\" comm=\"sh\"",
        ];
        let entries: Vec<_> = lines
            .iter()
            .map(|line| parse_log_line(line, HIGHLIGHT_KEYWORDS))
            .collect();
        assert_eq!(entries[2].service, "audit(SYSCALL)");
        let summary = analyze_threats(&entries);
        assert_eq!(summary.brute_force_count, 1);
        assert_eq!(summary.successful_login_count, 1);
        assert_eq!(summary.top_source_ips.len(), 2);
        assert_eq!(summary.hourly_distribution[3], 2);
    }

    #[test]
    fn rejects_path_traversal_and_line_injection() {
        let query = LogQuery {
            log_path: "/var/log/../shadow".to_owned(),
            page: 1,
            page_size: 10,
            filter: None,
            date_filter: None,
        };
        assert!(generate_log_read_command(&query).is_err());
        assert!(generate_ioc_search_command("evil\nnext", "/var/log/auth.log").is_err());
        assert!(generate_ioc_search_command("root", "/etc/shadow").is_err());
    }

    #[test]
    fn log_inventory_ignores_remote_paths_outside_var_log_and_bounds_metadata() {
        let output = format!(
            "128|/var/log/auth.log|1700000000\n64|/etc/shadow|1700000001\n32|/var/log/{}|1700000002",
            "界".repeat(400)
        );
        let files = parse_log_files(&output);
        assert!(
            files.iter().any(|file| {
                file.path == "/var/log/auth.log" && file.readable && file.size == 128
            })
        );
        assert!(!files.iter().any(|file| file.path == "/etc/shadow"));
        assert!(files.iter().all(|file| file.name.chars().count() <= 257));
        assert!(files.len() <= MAX_LOG_FILES);
    }

    #[test]
    fn ioc_matrix_is_bounded_deduplicated_and_parsed_as_inert_text() {
        let query = IocSearchQuery {
            indicators: vec!["192.0.2.10".to_owned(), "192.0.2.10".to_owned()],
            log_paths: vec!["/var/log/auth.log".to_owned()],
        };
        assert!(validate_ioc_query(&query).is_err());

        let parsed = parse_ioc_match(
            "<script>alert(1)</script>".to_owned(),
            "/var/log/auth.log".to_owned(),
            "2\n<script>alert(1)</script> first\nsecond",
        )
        .unwrap();
        assert_eq!(parsed.count, 2);
        assert_eq!(parsed.sample_lines[0], "<script>alert(1)</script> first");

        let oversized = IocSearchQuery {
            indicators: (0..MAX_IOC_INDICATORS)
                .map(|index| format!("indicator-{index}"))
                .collect(),
            log_paths: (0..MAX_MULTI_LOG_SOURCES)
                .map(|index| format!("/var/log/source-{index}.log"))
                .collect(),
        };
        assert!(validate_ioc_query(&oversized).is_err());
    }

    #[test]
    fn remote_log_lines_are_utf8_safely_bounded_before_entering_the_model() {
        let output = format!(
            "Aug 11 host service: {}",
            "界".repeat(MAX_LOG_LINE_CHARS + 10)
        );
        let result = analysis_result(&output, 10, Some("test"), true);
        assert_eq!(result.entries.len(), 1);
        assert!(result.entries[0].raw.chars().count() <= MAX_LOG_LINE_CHARS + 1);
        assert_eq!(result.entries[0].source.as_deref(), Some("test"));
        assert!(result.threat_summary.is_some());
    }
}
