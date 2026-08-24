//! Offline disposal reports built from typed audit, case, and detection data.
//!
//! Reports deliberately exclude raw execution commands and credentials. The
//! portable operation journal contributes immutable summaries, verification
//! phases, source categories, and recovery descriptions only.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::Path;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::detection::{DetectionFinding, DetectionScanReport, DetectionSeverity};
use crate::investigation::{
    CaseStatus, EvidenceHashScope, EvidenceKind, IncidentCase, IocType, TimelineEventType,
};
use crate::operations::{JournalPhase, OperationJournalEntry, PortableOperationJournal};
use crate::target::{TargetContext, TargetGuard};
use crate::{CoreError, CoreResult};

pub const DISPOSAL_REPORT_SCHEMA_ID: &str = "lovelyres-disposal-report/v1";
const MAX_REPORT_OPERATIONS: usize = 2_000;
const MAX_TARGET_LABEL_CHARS: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReportFormat {
    Markdown,
    Html,
}

impl ReportFormat {
    pub const fn extension(self) -> &'static str {
        match self {
            Self::Markdown => "md",
            Self::Html => "html",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Markdown => "Markdown",
            Self::Html => "HTML",
        }
    }

    fn content(self, report: &DisposalReport) -> &str {
        match self {
            Self::Markdown => &report.markdown,
            Self::Html => &report.html,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReportOperationStatus {
    Succeeded,
    Failed,
    Restored,
    Uncertain,
}

impl ReportOperationStatus {
    const fn label(self) -> &'static str {
        match self {
            Self::Succeeded => "成功",
            Self::Failed => "失败",
            Self::Restored => "已恢复",
            Self::Uncertain => "状态待核验",
        }
    }

    const fn css_class(self) -> &'static str {
        match self {
            Self::Succeeded => "ok",
            Self::Failed => "fail",
            Self::Restored => "restored",
            Self::Uncertain => "uncertain",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportOperation {
    pub operation_id: String,
    pub target_generation: u64,
    pub source: String,
    pub summary: String,
    pub dangerous: bool,
    pub restore_description: Option<String>,
    pub status: ReportOperationStatus,
    pub verification_detail: String,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisposalReportSnapshot {
    pub target: TargetGuard,
    pub target_label: String,
    pub generated_at: DateTime<Utc>,
    pub operations: Vec<ReportOperation>,
    pub incident: Option<IncidentCase>,
    pub detection: Option<DetectionScanReport>,
}

impl DisposalReportSnapshot {
    pub fn new(
        target: TargetGuard,
        target_label: impl Into<String>,
        generated_at: DateTime<Utc>,
        operations: Vec<ReportOperation>,
        incident: Option<IncidentCase>,
        detection: Option<DetectionScanReport>,
    ) -> CoreResult<Self> {
        let target_label = validated_target_label(target_label.into())?;
        if operations
            .iter()
            .any(|operation| operation.operation_id.trim().is_empty())
        {
            return Err(CoreError::validation(
                "disposal report operation",
                "operation ids must not be empty",
            ));
        }
        if let Some(incident) = &incident
            && incident.target != target.identity
        {
            return Err(CoreError::validation(
                "disposal report incident",
                "incident belongs to a different target",
            ));
        }
        if let Some(detection) = &detection
            && detection.target != target
        {
            return Err(CoreError::validation(
                "disposal report detection",
                "detection report belongs to a different target epoch",
            ));
        }
        Ok(Self {
            target,
            target_label,
            generated_at,
            operations,
            incident,
            detection,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisposalReportSummary {
    pub total: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub restored: usize,
    pub uncertain: usize,
    pub recoverable: usize,
    pub by_source: BTreeMap<String, usize>,
}

impl DisposalReportSummary {
    fn from_operations(operations: &[ReportOperation]) -> Self {
        let mut summary = Self {
            total: operations.len(),
            ..Self::default()
        };
        for operation in operations {
            match operation.status {
                ReportOperationStatus::Succeeded => summary.succeeded += 1,
                ReportOperationStatus::Failed => summary.failed += 1,
                ReportOperationStatus::Restored => summary.restored += 1,
                ReportOperationStatus::Uncertain => summary.uncertain += 1,
            }
            if operation.restore_description.is_some()
                && operation.status != ReportOperationStatus::Restored
            {
                summary.recoverable += 1;
            }
            *summary
                .by_source
                .entry(operation.source.clone())
                .or_default() += 1;
        }
        summary
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisposalReport {
    pub schema: String,
    pub snapshot_sha256: String,
    pub snapshot: DisposalReportSnapshot,
    pub summary: DisposalReportSummary,
    pub markdown: String,
    pub html: String,
}

impl DisposalReport {
    pub fn render(mut snapshot: DisposalReportSnapshot) -> CoreResult<Self> {
        snapshot.operations.sort_by(|left, right| {
            left.occurred_at
                .cmp(&right.occurred_at)
                .then_with(|| left.operation_id.cmp(&right.operation_id))
        });
        let bytes = serde_json::to_vec(&snapshot).map_err(|source| CoreError::Encode {
            subject: "disposal report snapshot",
            source,
        })?;
        let snapshot_sha256 = format!("{:x}", Sha256::digest(bytes));
        let summary = DisposalReportSummary::from_operations(&snapshot.operations);
        let markdown = render_markdown(&snapshot, &summary, &snapshot_sha256);
        let html = render_html(&snapshot, &summary, &snapshot_sha256);
        Ok(Self {
            schema: DISPOSAL_REPORT_SCHEMA_ID.to_owned(),
            snapshot_sha256,
            snapshot,
            summary,
            markdown,
            html,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ReportService {
    target: Arc<TargetContext>,
    journal: PortableOperationJournal,
}

impl ReportService {
    pub fn new(target: Arc<TargetContext>, journal: PortableOperationJournal) -> Self {
        Self { target, journal }
    }

    pub fn generate(
        &self,
        target: &TargetGuard,
        target_label: impl Into<String>,
        detection: Option<DetectionScanReport>,
    ) -> CoreResult<DisposalReport> {
        self.target.validate(target)?;
        if detection
            .as_ref()
            .is_some_and(|report| report.target != *target)
        {
            return Err(CoreError::validation(
                "disposal report detection",
                "detection report belongs to a different target epoch",
            ));
        }
        let entries = self
            .journal
            .entries()?
            .into_iter()
            .filter(|entry| entry.target.identity == target.identity)
            .collect::<Vec<_>>();
        let operations = collapse_journal(entries);
        self.target.validate(target)?;
        DisposalReport::render(DisposalReportSnapshot::new(
            target.clone(),
            target_label,
            Utc::now(),
            operations,
            None,
            detection,
        )?)
    }

    pub fn write_new_export(
        &self,
        report: &DisposalReport,
        format: ReportFormat,
        destination: &Path,
    ) -> CoreResult<()> {
        if !destination.is_absolute() {
            return Err(CoreError::validation(
                "disposal report destination",
                "destination must be an absolute path selected by the user",
            ));
        }
        let extension = destination
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        if !extension.eq_ignore_ascii_case(format.extension()) {
            return Err(CoreError::validation(
                "disposal report destination",
                format!(
                    "{} export requires a .{} file",
                    format.label(),
                    format.extension()
                ),
            ));
        }
        let parent = destination.parent().ok_or_else(|| {
            CoreError::validation("disposal report destination", "destination has no parent")
        })?;
        if !parent.is_dir() {
            return Err(CoreError::validation(
                "disposal report destination",
                "destination parent directory does not exist",
            ));
        }
        let content = format.content(report).as_bytes();
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(destination)
            .map_err(|source| CoreError::io("create disposal report", destination, source))?;
        let write_result = (|| {
            file.write_all(content)
                .map_err(|source| CoreError::io("write disposal report", destination, source))?;
            file.flush()
                .map_err(|source| CoreError::io("flush disposal report", destination, source))?;
            file.sync_all()
                .map_err(|source| CoreError::io("sync disposal report", destination, source))
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(destination);
        }
        write_result
    }
}

fn collapse_journal(mut entries: Vec<OperationJournalEntry>) -> Vec<ReportOperation> {
    entries.sort_by(|left, right| {
        left.occurred_at
            .cmp(&right.occurred_at)
            .then_with(|| left.entry_id.cmp(&right.entry_id))
    });
    let mut operations = BTreeMap::<String, ReportOperation>::new();
    for entry in entries {
        let status = phase_status(entry.phase);
        let operation = operations
            .entry(entry.operation_id.clone())
            .or_insert_with(|| ReportOperation {
                operation_id: entry.operation_id.clone(),
                target_generation: entry.target.generation,
                source: normalized_source(&entry.source),
                summary: entry.summary.clone(),
                dangerous: entry.dangerous,
                restore_description: entry.restore_description.clone(),
                status,
                verification_detail: entry.detail.clone(),
                occurred_at: entry.occurred_at,
            });
        operation.target_generation = entry.target.generation;
        operation.source = normalized_source(&entry.source);
        operation.summary = entry.summary;
        operation.dangerous = entry.dangerous;
        if entry.restore_description.is_some() {
            operation.restore_description = entry.restore_description;
        }
        operation.status = merge_status(operation.status, status);
        operation.verification_detail = entry.detail;
    }
    let mut operations = operations.into_values().collect::<Vec<_>>();
    operations.sort_by(|left, right| {
        left.occurred_at
            .cmp(&right.occurred_at)
            .then_with(|| left.operation_id.cmp(&right.operation_id))
    });
    if operations.len() > MAX_REPORT_OPERATIONS {
        operations.drain(..operations.len() - MAX_REPORT_OPERATIONS);
    }
    operations
}

const fn phase_status(phase: JournalPhase) -> ReportOperationStatus {
    match phase {
        JournalPhase::Executed | JournalPhase::VerificationPassed => {
            ReportOperationStatus::Succeeded
        }
        JournalPhase::VerificationFailed => ReportOperationStatus::Failed,
        JournalPhase::Restored => ReportOperationStatus::Restored,
        JournalPhase::StaleAfterExecution => ReportOperationStatus::Uncertain,
    }
}

const fn merge_status(
    current: ReportOperationStatus,
    incoming: ReportOperationStatus,
) -> ReportOperationStatus {
    if matches!(incoming, ReportOperationStatus::Restored) {
        ReportOperationStatus::Restored
    } else if matches!(incoming, ReportOperationStatus::Failed) {
        ReportOperationStatus::Failed
    } else if matches!(incoming, ReportOperationStatus::Uncertain)
        && !matches!(current, ReportOperationStatus::Failed)
    {
        ReportOperationStatus::Uncertain
    } else {
        current
    }
}

fn normalized_source(source: &str) -> String {
    let value = source.trim();
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        "operation".to_owned()
    } else {
        value.to_owned()
    }
}

fn validated_target_label(value: String) -> CoreResult<String> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > MAX_TARGET_LABEL_CHARS {
        return Err(CoreError::validation(
            "disposal report target label",
            format!("must contain 1..={MAX_TARGET_LABEL_CHARS} characters"),
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(CoreError::validation(
            "disposal report target label",
            "must not contain control characters",
        ));
    }
    Ok(value.to_owned())
}

fn render_markdown(
    snapshot: &DisposalReportSnapshot,
    summary: &DisposalReportSummary,
    snapshot_sha256: &str,
) -> String {
    let mut lines = vec![
        "# LovelyRes 处置交付报告".to_owned(),
        String::new(),
        format!("- 目标：{}", md_inline(&snapshot.target_label)),
        format!(
            "- 目标身份：{} · 代际 {}",
            md_inline(snapshot.target.identity.as_str()),
            snapshot.target.generation
        ),
        format!("- 生成时间：{}", format_timestamp(snapshot.generated_at)),
        format!("- 快照 SHA-256：`{snapshot_sha256}`"),
        format!(
            "- 处置：共 {}，成功 {}，失败 {}，已恢复 {}，待核验 {}",
            summary.total, summary.succeeded, summary.failed, summary.restored, summary.uncertain
        ),
        format!("- 仍有恢复说明：{}", summary.recoverable),
        String::new(),
    ];
    if !summary.by_source.is_empty() {
        lines.push("来源分布：".to_owned());
        lines.push(String::new());
        for (source, count) in &summary.by_source {
            lines.push(format!("- {}：{count}", source_label(source)));
        }
        lines.push(String::new());
    }

    let mut chapter = 1;
    if let Some(detection) = &snapshot.detection {
        lines.push(format!("## {}、检测结果", chapter_label(chapter)));
        chapter += 1;
        lines.push(String::new());
        lines.push(format!(
            "检测时间：{}　可信评分：**{}**　状态：{:?}",
            format_timestamp(detection.started_at),
            detection.overall_score,
            detection.status
        ));
        lines.push(String::new());
        let findings = sorted_findings(detection);
        if findings.is_empty() {
            lines.push("本次检测未发现问题。".to_owned());
        } else {
            lines.push("| 级别 | 问题 | 说明 | 建议 |".to_owned());
            lines.push("| --- | --- | --- | --- |".to_owned());
            for finding in findings {
                lines.push(format!(
                    "| {} | {} | {} | {} |",
                    severity_label(finding.severity),
                    md_cell(&finding.title),
                    md_cell(&finding.description),
                    md_cell(finding.recommendation.as_deref().unwrap_or("-"))
                ));
            }
        }
        lines.push(String::new());
    }

    if let Some(incident) = &snapshot.incident {
        lines.push(format!("## {}、案件与证据链", chapter_label(chapter)));
        chapter += 1;
        lines.push(String::new());
        lines.push(format!("- 案件编号：{}", md_inline(&incident.id)));
        lines.push(format!("- 案件名称：{}", md_inline(&incident.title)));
        lines.push(format!("- 状态：{}", case_status_label(incident.status)));
        lines.push(String::new());
        lines.push("### IOC".to_owned());
        lines.push(String::new());
        if incident.iocs.is_empty() {
            lines.push("暂无 IOC。".to_owned());
        } else {
            lines.push("| 类型 | 值 | 来源 | 加入时间 |".to_owned());
            lines.push("| --- | --- | --- | --- |".to_owned());
            for ioc in &incident.iocs {
                lines.push(format!(
                    "| {} | {} | {} | {} |",
                    ioc_type_label(ioc.ioc_type),
                    md_cell(&ioc.value),
                    md_cell(&ioc.source),
                    format_timestamp_millis(ioc.added_at)
                ));
            }
        }
        lines.push(String::new());
        lines.push("### 证据清单".to_owned());
        lines.push(String::new());
        if incident.evidence.is_empty() {
            lines.push("暂无证据。".to_owned());
        } else {
            lines.push("| 类型 | 证据 | 来源 | SHA-256 | 哈希范围 |".to_owned());
            lines.push("| --- | --- | --- | --- | --- |".to_owned());
            for evidence in &incident.evidence {
                lines.push(format!(
                    "| {} | {} | {} | `{}` | {} |",
                    evidence_kind_label(evidence.kind),
                    md_cell(&evidence.label),
                    md_cell(&evidence.source),
                    evidence.sha256,
                    hash_scope_label(evidence.hash_scope)
                ));
            }
        }
        lines.push(String::new());
        lines.push("### 调查时间线".to_owned());
        lines.push(String::new());
        let mut timeline = incident.timeline.iter().collect::<Vec<_>>();
        timeline.sort_by_key(|event| event.timestamp);
        for event in timeline {
            lines.push(format!(
                "- {} · {} · {} · 会话 {}",
                format_timestamp_millis(event.timestamp),
                md_inline(&event.title),
                timeline_type_label(event.event_type),
                event.target.as_str()
            ));
        }
        lines.push(String::new());
    }

    lines.push(format!("## {}、处置记录", chapter_label(chapter)));
    lines.push(String::new());
    if snapshot.operations.is_empty() {
        lines.push("本次未产生任何已审计变更记录。".to_owned());
    } else {
        for (index, operation) in snapshot.operations.iter().enumerate() {
            lines.push(format!(
                "### {}. {}",
                index + 1,
                md_inline(&operation.summary)
            ));
            lines.push(String::new());
            lines.push(format!(
                "- 时间：{}",
                format_timestamp(operation.occurred_at)
            ));
            lines.push(format!(
                "- 来源：{}　状态：{}　目标代际：{}",
                source_label(&operation.source),
                operation.status.label(),
                operation.target_generation
            ));
            lines.push(format!(
                "- 独立验证：{}",
                md_inline(&operation.verification_detail)
            ));
            if let Some(description) = &operation.restore_description {
                lines.push(format!("- 恢复说明：{}", md_inline(description)));
            } else {
                lines.push("- 恢复说明：未登记，按不可恢复处理。".to_owned());
            }
            lines.push(String::new());
        }
    }
    lines.join("\n")
}

fn render_html(
    snapshot: &DisposalReportSnapshot,
    summary: &DisposalReportSummary,
    snapshot_sha256: &str,
) -> String {
    let source_chips = summary
        .by_source
        .iter()
        .map(|(source, count)| {
            format!(
                "<span class=\"chip\">{} {count}</span>",
                html_escape(source_label(source))
            )
        })
        .collect::<String>();
    let detection_html = snapshot.detection.as_ref().map_or_else(String::new, |detection| {
        let findings = sorted_findings(detection);
        let body = if findings.is_empty() {
            "<p class=\"empty\">本次检测未发现问题。</p>".to_owned()
        } else {
            let rows = findings
                .into_iter()
                .map(|finding| {
                    format!(
                        "<tr><td><span class=\"severity {}\">{}</span></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                        severity_class(finding.severity),
                        severity_label(finding.severity),
                        html_escape(&finding.title),
                        html_escape(&finding.description),
                        html_escape(finding.recommendation.as_deref().unwrap_or("-"))
                    )
                })
                .collect::<String>();
            format!("<table><thead><tr><th>级别</th><th>问题</th><th>说明</th><th>建议</th></tr></thead><tbody>{rows}</tbody></table>")
        };
        format!(
            "<section class=\"card\"><h2>检测结果</h2><p class=\"meta\">{} · 可信评分 <strong>{}</strong></p>{body}</section>",
            html_escape(&format_timestamp(detection.started_at)),
            detection.overall_score
        )
    });
    let incident_html = snapshot
        .incident
        .as_ref()
        .map_or_else(String::new, render_incident_html);
    let operation_html = if snapshot.operations.is_empty() {
        "<section class=\"card\"><h2>处置记录</h2><p class=\"empty\">本次未产生任何已审计变更记录。</p></section>".to_owned()
    } else {
        snapshot
            .operations
            .iter()
            .enumerate()
            .map(|(index, operation)| {
                let restore = operation.restore_description.as_ref().map_or_else(
                    || "<p class=\"warn\">未登记恢复说明，按不可恢复处理。</p>".to_owned(),
                    |description| format!("<p><span class=\"label\">恢复说明</span>{}</p>", html_escape(description)),
                );
                format!(
                    "<article class=\"operation {}\"><h3><span class=\"index\">{}</span>{}</h3><p class=\"meta\">{} · {} · {} · 目标代际 {}</p><p><span class=\"label\">验证结果</span>{}</p>{restore}</article>",
                    operation.status.css_class(),
                    index + 1,
                    html_escape(&operation.summary),
                    html_escape(&format_timestamp(operation.occurred_at)),
                    html_escape(source_label(&operation.source)),
                    operation.status.label(),
                    operation.target_generation,
                    html_escape(&operation.verification_detail)
                )
            })
            .collect::<String>()
    };
    format!(
        "<!DOCTYPE html>\n<html lang=\"zh-CN\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\"><title>LovelyRes 处置交付报告</title><style>{REPORT_CSS}</style></head><body><main><header><h1>LovelyRes 处置交付报告</h1><p>{} · {}</p><div class=\"stats\"><span>处置 {}</span><span>成功 {}</span><span>失败 {}</span><span>已恢复 {}</span><span>待核验 {}</span><span>可恢复 {}</span></div></header><section class=\"card\"><h2>证据快照</h2><p class=\"mono\">SHA-256 {}</p><div>{}</div></section>{}{}<section class=\"section-title\"><h2>处置记录</h2><p>按首次执行时间正序；不导出原始命令或凭据。</p></section>{}</main></body></html>",
        html_escape(&snapshot.target_label),
        html_escape(&format_timestamp(snapshot.generated_at)),
        summary.total,
        summary.succeeded,
        summary.failed,
        summary.restored,
        summary.uncertain,
        summary.recoverable,
        snapshot_sha256,
        source_chips,
        detection_html,
        incident_html,
        operation_html
    )
}

fn render_incident_html(incident: &IncidentCase) -> String {
    let iocs = if incident.iocs.is_empty() {
        "<p class=\"empty\">暂无 IOC。</p>".to_owned()
    } else {
        let rows = incident
            .iocs
            .iter()
            .map(|ioc| {
                format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    ioc_type_label(ioc.ioc_type),
                    html_escape(&ioc.value),
                    html_escape(&ioc.source),
                    html_escape(&format_timestamp_millis(ioc.added_at))
                )
            })
            .collect::<String>();
        format!(
            "<table><thead><tr><th>类型</th><th>值</th><th>来源</th><th>时间</th></tr></thead><tbody>{rows}</tbody></table>"
        )
    };
    let evidence = if incident.evidence.is_empty() {
        "<p class=\"empty\">暂无证据。</p>".to_owned()
    } else {
        let rows = incident
            .evidence
            .iter()
            .map(|evidence| {
                format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td class=\"mono\">{}<br><small>{}</small></td></tr>",
                    evidence_kind_label(evidence.kind),
                    html_escape(&evidence.label),
                    html_escape(&evidence.source),
                    evidence.sha256,
                    hash_scope_label(evidence.hash_scope)
                )
            })
            .collect::<String>();
        format!(
            "<table><thead><tr><th>类型</th><th>证据</th><th>来源</th><th>SHA-256 / 范围</th></tr></thead><tbody>{rows}</tbody></table>"
        )
    };
    let mut timeline = incident.timeline.iter().collect::<Vec<_>>();
    timeline.sort_by_key(|event| event.timestamp);
    let timeline = timeline
        .into_iter()
        .map(|event| {
            format!(
                "<li><strong>{}</strong><span>{} · {} · 会话 {}</span></li>",
                html_escape(&event.title),
                html_escape(&format_timestamp_millis(event.timestamp)),
                timeline_type_label(event.event_type),
                html_escape(event.target.as_str())
            )
        })
        .collect::<String>();
    format!(
        "<section class=\"card\"><h2>案件与证据链</h2><p class=\"meta\">{} · {} · {}</p><h3>IOC（{}）</h3>{}<h3>证据清单（{}）</h3>{}<h3>调查时间线（{}）</h3><ol class=\"timeline\">{}</ol><p class=\"warn\">stored-preview 只校验案件内保存的预览；external-artifact 才代表原始外部证据。</p></section>",
        html_escape(&incident.title),
        html_escape(&incident.id),
        case_status_label(incident.status),
        incident.iocs.len(),
        iocs,
        incident.evidence.len(),
        evidence,
        incident.timeline.len(),
        timeline
    )
}

fn sorted_findings(report: &DetectionScanReport) -> Vec<&DetectionFinding> {
    let mut findings = report
        .modules
        .iter()
        .flat_map(|module| module.findings.iter())
        .collect::<Vec<_>>();
    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| left.title.cmp(&right.title))
    });
    findings
}

pub fn format_timestamp(value: DateTime<Utc>) -> String {
    value.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

fn format_timestamp_millis(value: i64) -> String {
    DateTime::<Utc>::from_timestamp_millis(value)
        .map(format_timestamp)
        .unwrap_or_else(|| "时间无效".to_owned())
}

fn md_inline(value: &str) -> String {
    md_cell(value)
}

fn md_cell(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('|', "\\|")
        .replace(['\r', '\n'], " ")
        .trim()
        .to_owned()
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

const fn chapter_label(value: usize) -> &'static str {
    match value {
        1 => "一",
        2 => "二",
        3 => "三",
        4 => "四",
        _ => "后续",
    }
}

fn source_label(source: &str) -> &str {
    match source {
        "baseline" | "baseline-restore" => "基线修复",
        "firewall" => "边界隔离",
        "java-jar-update" | "java-jar-restore" => "Java 热更新",
        "batch" => "多机批量",
        "database" => "数据库",
        "integrity" => "文件完整性",
        "snapshot" => "取证快照",
        "docker" => "Docker",
        "sftp" => "SFTP",
        "investigation" => "调查工作区",
        "settings" => "设置",
        "connection" => "连接管理",
        _ => "其他操作",
    }
}

const fn severity_label(severity: DetectionSeverity) -> &'static str {
    match severity {
        DetectionSeverity::Critical => "严重",
        DetectionSeverity::High => "高危",
        DetectionSeverity::Medium => "中危",
        DetectionSeverity::Low => "低危",
        DetectionSeverity::Info => "提示",
    }
}

const fn severity_class(severity: DetectionSeverity) -> &'static str {
    match severity {
        DetectionSeverity::Critical => "critical",
        DetectionSeverity::High => "high",
        DetectionSeverity::Medium => "medium",
        DetectionSeverity::Low => "low",
        DetectionSeverity::Info => "info",
    }
}

const fn case_status_label(status: CaseStatus) -> &'static str {
    match status {
        CaseStatus::Open => "调查中",
        CaseStatus::Closed => "已关闭",
    }
}

const fn ioc_type_label(ioc_type: IocType) -> &'static str {
    match ioc_type {
        IocType::Ip => "IP",
        IocType::Domain => "域名",
        IocType::Hash => "哈希",
        IocType::Path => "路径",
        IocType::Process => "进程",
        IocType::User => "用户",
        IocType::Other => "其他",
    }
}

const fn evidence_kind_label(kind: EvidenceKind) -> &'static str {
    match kind {
        EvidenceKind::Finding => "发现",
        EvidenceKind::Path => "路径",
        EvidenceKind::CommandOutput => "命令输出",
        EvidenceKind::Snapshot => "快照",
        EvidenceKind::Pcap => "PCAP",
        EvidenceKind::Log => "日志",
        EvidenceKind::Note => "笔记",
        EvidenceKind::Other => "其他",
    }
}

const fn hash_scope_label(scope: EvidenceHashScope) -> &'static str {
    match scope {
        EvidenceHashScope::StoredPreview => "stored-preview",
        EvidenceHashScope::ExternalArtifact => "external-artifact",
    }
}

const fn timeline_type_label(event_type: TimelineEventType) -> &'static str {
    match event_type {
        TimelineEventType::CaseCreated => "创建案件",
        TimelineEventType::Finding => "发现",
        TimelineEventType::Evidence => "证据",
        TimelineEventType::Ioc => "IOC",
        TimelineEventType::Action => "处置",
        TimelineEventType::Verification => "验证",
        TimelineEventType::Note => "笔记",
    }
}

const REPORT_CSS: &str = r#"
*{box-sizing:border-box}body{margin:0;background:#f5f7fb;color:#172033;font:14px/1.65 system-ui,-apple-system,"Segoe UI",sans-serif}main{max-width:980px;margin:auto;padding:28px}header{background:#0b1b36;color:#fff;border-radius:16px;padding:28px;margin-bottom:18px}h1{font-size:26px;margin:0 0 4px}h2{font-size:18px}h3{font-size:15px}.stats{display:flex;flex-wrap:wrap;gap:8px;margin-top:18px}.stats span,.chip{border-radius:999px;padding:4px 10px;background:#e8eef7;color:#26364f}.stats span{background:#17325d;color:#eaf2ff}.card,.operation,.section-title{background:#fff;border:1px solid #e1e7f0;border-radius:12px;padding:18px;margin:0 0 14px}.operation{border-left-width:4px}.operation.ok{border-left-color:#16a36a}.operation.fail{border-left-color:#dc4c4c}.operation.restored{border-left-color:#64748b}.operation.uncertain{border-left-color:#d18b16}.operation h3{display:flex;gap:8px;align-items:center}.index{display:inline-grid;place-items:center;background:#e9f0ff;color:#215fd1;border-radius:50%;width:24px;height:24px}.meta,.label,small{color:#68758a}.label{display:block;font-size:12px}.mono{font-family:ui-monospace,"Cascadia Mono",monospace;word-break:break-all}.warn{background:#fff7df;color:#855b08;border-radius:8px;padding:8px 10px}.empty{color:#68758a}table{width:100%;border-collapse:collapse;margin:8px 0 16px;font-size:13px}th,td{border:1px solid #e1e7f0;padding:8px;text-align:left;vertical-align:top}th{background:#f2f5f9}.severity{font-weight:600}.severity.critical,.severity.high{color:#b42318}.severity.medium{color:#9a6700}.severity.low{color:#16794f}.severity.info{color:#215fd1}.timeline li{padding:3px}.timeline span{display:block;color:#68758a;font-size:12px}@media print{body{background:#fff}main{max-width:none;padding:0}.card,.operation,.section-title{break-inside:avoid}header{background:#0b1b36!important;print-color-adjust:exact}}
"#;

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;

    use super::*;
    use crate::detection::{
        DetectionKind, DetectionModuleReport, DetectionOutcome, DetectionScanProfile,
        DetectionScanStatus, DetectionSummary,
    };
    use crate::investigation::{CaseIoc, CaseTimelineEvent, EvidenceArtifact};
    use crate::target::TargetIdentity;

    fn guard(value: &str, generation: u64) -> TargetGuard {
        TargetGuard {
            identity: TargetIdentity::new(value).unwrap(),
            generation,
        }
    }

    fn at(second: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 20, 12, 30, second).unwrap()
    }

    fn operation(
        id: &str,
        source: &str,
        status: ReportOperationStatus,
        second: u32,
    ) -> ReportOperation {
        ReportOperation {
            operation_id: id.to_owned(),
            target_generation: 7,
            source: source.to_owned(),
            summary: format!("操作 {id}"),
            dangerous: true,
            restore_description: Some("恢复原配置".to_owned()),
            status,
            verification_detail: "read-back passed".to_owned(),
            occurred_at: at(second),
        }
    }

    fn detection(target: &TargetGuard) -> DetectionScanReport {
        DetectionScanReport {
            id: "scan-1".to_owned(),
            target: target.clone(),
            profile: DetectionScanProfile::Selected,
            started_at: at(10),
            duration_ms: 12,
            status: DetectionScanStatus::Completed,
            overall_score: 72,
            modules: vec![DetectionModuleReport {
                kind: DetectionKind::ProcessAnalysis,
                outcome: DetectionOutcome::Failed,
                score: 72,
                findings: vec![DetectionFinding {
                    title: "a | b".to_owned(),
                    description: "第一行\n第二行 </td><script>alert(1)</script>".to_owned(),
                    severity: DetectionSeverity::High,
                    recommendation: Some("检查 <img src=x onerror=1>".to_owned()),
                    remediation: None,
                }],
                raw_text: String::new(),
                raw_text_truncated: false,
                duration_ms: 12,
            }],
            summary: DetectionSummary {
                high: 1,
                failed_modules: 1,
                ..DetectionSummary::default()
            },
            dropped_progress_events: 0,
        }
    }

    fn incident(target: &TargetGuard) -> IncidentCase {
        IncidentCase {
            id: "case-1".to_owned(),
            title: "WebShell <img src=x onerror=1>".to_owned(),
            status: CaseStatus::Open,
            target: target.identity.clone(),
            created_at: at(1).timestamp_millis(),
            updated_at: at(4).timestamp_millis(),
            iocs: vec![CaseIoc {
                id: "ioc-1".to_owned(),
                ioc_type: IocType::Path,
                value: "</td><script>alert(1)</script>".to_owned(),
                source: "quick-detection:webshell".to_owned(),
                added_at: at(2).timestamp_millis(),
                target: target.identity.clone(),
            }],
            evidence: vec![EvidenceArtifact {
                id: "evidence-1".to_owned(),
                kind: EvidenceKind::Finding,
                label: "可疑文件".to_owned(),
                source: "quick-detection:webshell".to_owned(),
                locator: None,
                preview: "hostile preview".to_owned(),
                sha256: "a".repeat(64),
                hash_scope: EvidenceHashScope::StoredPreview,
                collected_at: at(3).timestamp_millis(),
                target: target.identity.clone(),
            }],
            timeline: vec![CaseTimelineEvent {
                id: "event-1".to_owned(),
                event_type: TimelineEventType::Finding,
                title: "收集证据".to_owned(),
                detail: None,
                source: "quick-detection:webshell".to_owned(),
                timestamp: at(4).timestamp_millis(),
                target: target.identity.clone(),
                evidence_id: Some("evidence-1".to_owned()),
                ioc_id: None,
                operation_id: None,
            }],
        }
    }

    fn snapshot(
        operations: Vec<ReportOperation>,
        with_detection: bool,
        with_incident: bool,
    ) -> DisposalReportSnapshot {
        let target = guard("connection-a", 7);
        DisposalReportSnapshot::new(
            target.clone(),
            "10.0.0.1 · root@10.0.0.1:22",
            at(45),
            operations,
            with_incident.then(|| incident(&target)),
            with_detection.then(|| detection(&target)),
        )
        .unwrap()
    }

    #[test]
    fn summary_distinguishes_status_recovery_and_source_counts() {
        let mut restored = operation("restored", "baseline", ReportOperationStatus::Restored, 3);
        restored.restore_description = Some("restored".to_owned());
        let mut irreversible = operation("failed", "firewall", ReportOperationStatus::Failed, 2);
        irreversible.restore_description = None;
        let report = DisposalReport::render(snapshot(
            vec![
                operation("ok", "baseline", ReportOperationStatus::Succeeded, 1),
                irreversible,
                restored,
                operation("stale", "batch", ReportOperationStatus::Uncertain, 4),
            ],
            false,
            false,
        ))
        .unwrap();
        assert_eq!(report.summary.total, 4);
        assert_eq!(report.summary.succeeded, 1);
        assert_eq!(report.summary.failed, 1);
        assert_eq!(report.summary.restored, 1);
        assert_eq!(report.summary.uncertain, 1);
        assert_eq!(report.summary.recoverable, 2);
        assert_eq!(report.summary.by_source["baseline"], 2);
        assert_eq!(report.summary.by_source["firewall"], 1);
    }

    #[test]
    fn markdown_has_target_stats_chronology_and_explicit_irreversible_status() {
        let mut later = operation("later", "baseline", ReportOperationStatus::Succeeded, 30);
        later.summary = "后做的".to_owned();
        let mut earlier = operation("earlier", "firewall", ReportOperationStatus::Succeeded, 20);
        earlier.summary = "先做的".to_owned();
        earlier.restore_description = None;
        let report = DisposalReport::render(snapshot(vec![later, earlier], false, false)).unwrap();
        assert!(report.markdown.contains("10.0.0.1"));
        assert!(report.markdown.contains("处置：共 2"));
        assert!(report.markdown.contains("按不可恢复处理"));
        assert!(report.markdown.find("先做的") < report.markdown.find("后做的"));
        assert!(!report.markdown.contains("执行命令"));
    }

    #[test]
    fn markdown_detection_cells_cannot_break_tables_and_chapters_renumber() {
        let with_detection = DisposalReport::render(snapshot(Vec::new(), true, false)).unwrap();
        let row = with_detection
            .markdown
            .lines()
            .find(|line| line.contains("a \\| b"))
            .unwrap();
        assert!(row.contains("第一行 第二行"));
        assert!(with_detection.markdown.contains("## 一、检测结果"));
        assert!(with_detection.markdown.contains("## 二、处置记录"));

        let without_detection = DisposalReport::render(snapshot(Vec::new(), false, false)).unwrap();
        assert!(!without_detection.markdown.contains("检测结果"));
        assert!(without_detection.markdown.contains("## 一、处置记录"));
    }

    #[test]
    fn case_ioc_hash_scope_and_exact_target_timeline_are_in_both_formats() {
        let report = DisposalReport::render(snapshot(Vec::new(), false, true)).unwrap();
        for content in [&report.markdown, &report.html] {
            assert!(content.contains(&"a".repeat(64)));
            assert!(content.contains("stored-preview"));
            assert!(content.contains("connection-a"));
            assert!(content.contains("可疑文件"));
        }
    }

    #[test]
    fn html_is_self_contained_printable_and_escapes_all_hostile_text() {
        let mut hostile = operation("hostile", "operation", ReportOperationStatus::Failed, 1);
        hostile.summary = "<img src=x onerror=alert(1)>".to_owned();
        hostile.verification_detail = "</p><script>alert(2)</script>".to_owned();
        let report = DisposalReport::render(snapshot(vec![hostile], true, true)).unwrap();
        assert!(report.html.starts_with("<!DOCTYPE html>"));
        assert!(report.html.contains("@media print"));
        assert!(!report.html.contains("<img src=x"));
        assert!(!report.html.contains("<script>alert"));
        assert!(report.html.contains("&lt;img src=x"));
        assert!(!report.html.contains("<link"));
        assert!(!report.html.contains("<script"));
        assert!(!report.html.contains("@import"));
        assert!(!report.html.contains("url(http"));
    }

    #[test]
    fn html_distinguishes_operation_states_and_empty_report_is_explicit() {
        let report = DisposalReport::render(snapshot(
            vec![
                operation("ok", "operation", ReportOperationStatus::Succeeded, 1),
                operation("fail", "operation", ReportOperationStatus::Failed, 2),
                operation("restore", "operation", ReportOperationStatus::Restored, 3),
                operation("stale", "operation", ReportOperationStatus::Uncertain, 4),
            ],
            false,
            false,
        ))
        .unwrap();
        for class in [
            "operation ok",
            "operation fail",
            "operation restored",
            "operation uncertain",
        ] {
            assert!(report.html.contains(class));
        }
        let empty = DisposalReport::render(snapshot(Vec::new(), false, false)).unwrap();
        assert!(empty.html.contains("本次未产生任何已审计变更记录"));
    }

    #[test]
    fn timestamps_are_zero_padded_to_seconds_in_utc() {
        let timestamp = Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap();
        assert_eq!(format_timestamp(timestamp), "2026-01-02 03:04:05 UTC");
    }

    #[test]
    fn target_mismatch_is_rejected_before_report_rendering() {
        let target = guard("target-a", 1);
        let other = guard("target-b", 1);
        let result = DisposalReportSnapshot::new(
            target,
            "target-a",
            at(1),
            Vec::new(),
            None,
            Some(detection(&other)),
        );
        assert!(matches!(result, Err(CoreError::Validation { .. })));
    }

    #[test]
    fn journal_phases_collapse_to_one_audited_operation() {
        let target = guard("target-a", 1);
        let entry = |entry_id: &str, phase: JournalPhase, second: u32| OperationJournalEntry {
            entry_id: entry_id.to_owned(),
            operation_id: "operation-1".to_owned(),
            target: target.clone(),
            summary: "封禁来源地址".to_owned(),
            dangerous: true,
            source: "firewall".to_owned(),
            restore_description: Some("删除隔离规则".to_owned()),
            phase,
            detail: format!("detail-{entry_id}"),
            occurred_at: at(second),
        };
        let operations = collapse_journal(vec![
            entry("execute", JournalPhase::Executed, 1),
            entry("verify", JournalPhase::VerificationPassed, 2),
            entry("restore", JournalPhase::Restored, 3),
        ]);
        assert_eq!(operations.len(), 1);
        assert_eq!(operations[0].status, ReportOperationStatus::Restored);
        assert_eq!(operations[0].source, "firewall");
        assert_eq!(operations[0].verification_detail, "detail-restore");
    }

    #[test]
    fn export_is_create_new_absolute_and_extension_bound() {
        let root = std::env::temp_dir().join(format!("lovelyres-report-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let target_context = Arc::new(TargetContext::new());
        let store = crate::PortableStore::prepare(root.clone()).unwrap();
        let service = ReportService::new(target_context, PortableOperationJournal::new(store));
        let report = DisposalReport::render(snapshot(Vec::new(), false, false)).unwrap();
        let markdown = root.join("report.md");
        service
            .write_new_export(&report, ReportFormat::Markdown, &markdown)
            .unwrap();
        assert_eq!(fs::read_to_string(&markdown).unwrap(), report.markdown);
        assert!(
            service
                .write_new_export(&report, ReportFormat::Markdown, &markdown)
                .is_err()
        );
        assert_eq!(fs::read_to_string(&markdown).unwrap(), report.markdown);
        assert!(
            service
                .write_new_export(&report, ReportFormat::Html, &root.join("wrong.md"))
                .is_err()
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn report_service_does_not_attach_incident_data() {
        let root = std::env::temp_dir().join(format!("lovelyres-report-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let target_context = Arc::new(TargetContext::new());
        let target = target_context
            .activate(TargetIdentity::new("report-target").unwrap())
            .unwrap();
        let store = crate::PortableStore::prepare(root.clone()).unwrap();
        let service = ReportService::new(target_context, PortableOperationJournal::new(store));

        let report = service.generate(&target, "report-target", None).unwrap();
        assert!(report.snapshot.incident.is_none());

        let _ = fs::remove_dir_all(root);
    }
}
