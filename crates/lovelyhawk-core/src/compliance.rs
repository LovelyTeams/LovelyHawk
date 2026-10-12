//! Closed compliance catalog derived from typed quick-detection receipts.
//!
//! Compliance never executes a command. It only maps an already target-bound
//! [`DetectionScanReport`] onto the fixed CIS and MLPS 2.0 rule catalogs.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};

use crate::{
    detection::{
        DetectionKind, DetectionModuleReport, DetectionOutcome, DetectionScanReport,
        DetectionSeverity,
    },
    target::TargetGuard,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ComplianceStandard {
    Cis,
    Mlps2,
}

impl ComplianceStandard {
    pub const ALL: [Self; 2] = [Self::Cis, Self::Mlps2];

    pub const fn id(self) -> &'static str {
        match self {
            Self::Cis => "cis",
            Self::Mlps2 => "mlps2",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Cis => "CIS Benchmark",
            Self::Mlps2 => "等保 2.0",
        }
    }
}

impl fmt::Display for ComplianceStandard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.id())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum ComplianceCheckId {
    PasswordPolicy,
    SudoAudit,
    PamConfig,
    AccountLockout,
    SelinuxStatus,
    KernelParams,
    UnnecessaryServices,
    AuditConfig,
    SshAudit,
    FirewallCheck,
    BackdoorScan,
    FilePermission,
    LogAnalysis,
    WebshellScan,
    RootkitScan,
    PersistenceScan,
    LogTamper,
}

impl ComplianceCheckId {
    pub const ALL: [Self; 17] = [
        Self::PasswordPolicy,
        Self::SudoAudit,
        Self::PamConfig,
        Self::AccountLockout,
        Self::SelinuxStatus,
        Self::KernelParams,
        Self::UnnecessaryServices,
        Self::AuditConfig,
        Self::SshAudit,
        Self::FirewallCheck,
        Self::BackdoorScan,
        Self::FilePermission,
        Self::LogAnalysis,
        Self::WebshellScan,
        Self::RootkitScan,
        Self::PersistenceScan,
        Self::LogTamper,
    ];

    pub const fn id(self) -> &'static str {
        match self {
            Self::PasswordPolicy => "password-policy",
            Self::SudoAudit => "sudo-audit",
            Self::PamConfig => "pam-config",
            Self::AccountLockout => "account-lockout",
            Self::SelinuxStatus => "selinux-status",
            Self::KernelParams => "kernel-params",
            Self::UnnecessaryServices => "unnecessary-services",
            Self::AuditConfig => "audit-config",
            Self::SshAudit => "ssh-audit",
            Self::FirewallCheck => "firewall-check",
            Self::BackdoorScan => "backdoor-scan",
            Self::FilePermission => "file-permission",
            Self::LogAnalysis => "log-analysis",
            Self::WebshellScan => "webshell-scan",
            Self::RootkitScan => "rootkit-scan",
            Self::PersistenceScan => "persistence-scan",
            Self::LogTamper => "log-tamper",
        }
    }

    pub const fn from_detection_kind(kind: DetectionKind) -> Option<Self> {
        match kind {
            DetectionKind::BackdoorScan => Some(Self::BackdoorScan),
            DetectionKind::FilePermission => Some(Self::FilePermission),
            DetectionKind::SshAudit => Some(Self::SshAudit),
            DetectionKind::FirewallCheck => Some(Self::FirewallCheck),
            DetectionKind::LogAnalysis => Some(Self::LogAnalysis),
            DetectionKind::WebshellScan => Some(Self::WebshellScan),
            DetectionKind::PortScan
            | DetectionKind::UserAudit
            | DetectionKind::ProcessAnalysis
            | DetectionKind::CpuTest
            | DetectionKind::MemoryTest
            | DetectionKind::DiskTest
            | DetectionKind::NetworkTest => None,
        }
    }
}

impl fmt::Display for ComplianceCheckId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.id())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComplianceRule {
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub standard: ComplianceStandard,
    pub clause: &'static str,
    pub severity: DetectionSeverity,
    pub check: ComplianceCheckId,
    pub category: &'static str,
}

pub const MLPS2_RULES: [ComplianceRule; 13] = [
    ComplianceRule {
        id: "mlps2-1",
        title: "身份鉴别 — 密码复杂度",
        description: "应对登录用户进行唯一身份标识和鉴别",
        standard: ComplianceStandard::Mlps2,
        clause: "8.1.4.1 a)",
        severity: DetectionSeverity::High,
        check: ComplianceCheckId::PamConfig,
        category: "身份鉴别",
    },
    ComplianceRule {
        id: "mlps2-2",
        title: "身份鉴别 — 登录失败锁定",
        description: "应限制连续登录失败次数并提供失败处理",
        standard: ComplianceStandard::Mlps2,
        clause: "8.1.4.1 b)",
        severity: DetectionSeverity::High,
        check: ComplianceCheckId::AccountLockout,
        category: "身份鉴别",
    },
    ComplianceRule {
        id: "mlps2-3",
        title: "身份鉴别 — 密码策略",
        description: "口令应具备复杂度要求并定期更换",
        standard: ComplianceStandard::Mlps2,
        clause: "8.1.4.1 c)",
        severity: DetectionSeverity::Medium,
        check: ComplianceCheckId::PasswordPolicy,
        category: "身份鉴别",
    },
    ComplianceRule {
        id: "mlps2-4",
        title: "访问控制 — sudo 配置",
        description: "应按管理角色分配权限并实现权限分离",
        standard: ComplianceStandard::Mlps2,
        clause: "8.1.4.2 a)",
        severity: DetectionSeverity::High,
        check: ComplianceCheckId::SudoAudit,
        category: "访问控制",
    },
    ComplianceRule {
        id: "mlps2-5",
        title: "安全审计 — 审计配置",
        description: "应启用安全审计并记录重要用户行为和安全事件",
        standard: ComplianceStandard::Mlps2,
        clause: "8.1.4.3 a)",
        severity: DetectionSeverity::High,
        check: ComplianceCheckId::AuditConfig,
        category: "安全审计",
    },
    ComplianceRule {
        id: "mlps2-6",
        title: "入侵防范 — SSH 配置",
        description: "应关闭不需要的服务并审查高风险远程登录配置",
        standard: ComplianceStandard::Mlps2,
        clause: "8.1.4.4 a)",
        severity: DetectionSeverity::Medium,
        check: ComplianceCheckId::SshAudit,
        category: "入侵防范",
    },
    ComplianceRule {
        id: "mlps2-7",
        title: "入侵防范 — 防火墙",
        description: "应通过网络地址范围和接入方式限制通信",
        standard: ComplianceStandard::Mlps2,
        clause: "8.1.4.4 b)",
        severity: DetectionSeverity::Medium,
        check: ComplianceCheckId::FirewallCheck,
        category: "入侵防范",
    },
    ComplianceRule {
        id: "mlps2-8",
        title: "恶意代码防范 — 后门检测",
        description: "应配置恶意代码检测与对应防护措施",
        standard: ComplianceStandard::Mlps2,
        clause: "8.1.4.5 a)",
        severity: DetectionSeverity::Critical,
        check: ComplianceCheckId::BackdoorScan,
        category: "恶意代码防范",
    },
    ComplianceRule {
        id: "mlps2-9",
        title: "访问控制 — 文件权限",
        description: "应根据安全策略限制关键文件操作权限",
        standard: ComplianceStandard::Mlps2,
        clause: "8.1.4.2 c)",
        severity: DetectionSeverity::Medium,
        check: ComplianceCheckId::FilePermission,
        category: "访问控制",
    },
    ComplianceRule {
        id: "mlps2-10",
        title: "安全审计 — 日志分析",
        description: "审计记录应包含时间、用户和事件类型等字段",
        standard: ComplianceStandard::Mlps2,
        clause: "8.1.4.3 b)",
        severity: DetectionSeverity::Medium,
        check: ComplianceCheckId::LogAnalysis,
        category: "安全审计",
    },
    ComplianceRule {
        id: "mlps2-11",
        title: "恶意代码防范 — WebShell 检测",
        description: "应检测 Web 应用目录中的恶意脚本文件",
        standard: ComplianceStandard::Mlps2,
        clause: "8.1.4.5 b)",
        severity: DetectionSeverity::Critical,
        check: ComplianceCheckId::WebshellScan,
        category: "恶意代码防范",
    },
    ComplianceRule {
        id: "mlps2-12",
        title: "入侵防范 — Rootkit 检测",
        description: "应检测隐藏进程、内核后门等 Rootkit 行为",
        standard: ComplianceStandard::Mlps2,
        clause: "8.1.4.4 c)",
        severity: DetectionSeverity::Critical,
        check: ComplianceCheckId::RootkitScan,
        category: "入侵防范",
    },
    ComplianceRule {
        id: "mlps2-13",
        title: "安全审计 — 日志完整性",
        description: "审计记录不应被未授权删除或修改",
        standard: ComplianceStandard::Mlps2,
        clause: "8.1.4.3 c)",
        severity: DetectionSeverity::High,
        check: ComplianceCheckId::LogTamper,
        category: "安全审计",
    },
];

pub const CIS_RULES: [ComplianceRule; 10] = [
    ComplianceRule {
        id: "cis-1.1",
        title: "Ensure SELinux or AppArmor is installed",
        description: "Mandatory Access Control must be configured",
        standard: ComplianceStandard::Cis,
        clause: "CIS 1.6.1",
        severity: DetectionSeverity::Medium,
        check: ComplianceCheckId::SelinuxStatus,
        category: "Mandatory Access Control",
    },
    ComplianceRule {
        id: "cis-5.2.1",
        title: "Ensure SSH Protocol is configured properly",
        description: "SSH root login and password authentication must be reviewed",
        standard: ComplianceStandard::Cis,
        clause: "CIS 5.2",
        severity: DetectionSeverity::High,
        check: ComplianceCheckId::SshAudit,
        category: "SSH Server Configuration",
    },
    ComplianceRule {
        id: "cis-5.3.1",
        title: "Ensure password creation requirements are configured",
        description: "Password quality must meet complexity requirements",
        standard: ComplianceStandard::Cis,
        clause: "CIS 5.3.1",
        severity: DetectionSeverity::High,
        check: ComplianceCheckId::PamConfig,
        category: "PAM Configuration",
    },
    ComplianceRule {
        id: "cis-5.4.1",
        title: "Ensure password expiration is configured",
        description: "Password aging policies should be set",
        standard: ComplianceStandard::Cis,
        clause: "CIS 5.4.1",
        severity: DetectionSeverity::Medium,
        check: ComplianceCheckId::PasswordPolicy,
        category: "User Accounts",
    },
    ComplianceRule {
        id: "cis-3.5",
        title: "Ensure firewall is active",
        description: "A host-based firewall must be enabled and configured",
        standard: ComplianceStandard::Cis,
        clause: "CIS 3.5",
        severity: DetectionSeverity::High,
        check: ComplianceCheckId::FirewallCheck,
        category: "Network Configuration",
    },
    ComplianceRule {
        id: "cis-4.1",
        title: "Ensure auditing is enabled",
        description: "The audit system must be operational",
        standard: ComplianceStandard::Cis,
        clause: "CIS 4.1.1",
        severity: DetectionSeverity::High,
        check: ComplianceCheckId::AuditConfig,
        category: "Logging and Auditing",
    },
    ComplianceRule {
        id: "cis-2.1",
        title: "Ensure unnecessary services are disabled",
        description: "Only required services should be running",
        standard: ComplianceStandard::Cis,
        clause: "CIS 2.1",
        severity: DetectionSeverity::Medium,
        check: ComplianceCheckId::UnnecessaryServices,
        category: "Services",
    },
    ComplianceRule {
        id: "cis-1.4",
        title: "Ensure sysctl kernel parameters are configured",
        description: "Network-related kernel parameters must be hardened",
        standard: ComplianceStandard::Cis,
        clause: "CIS 3.1-3.3",
        severity: DetectionSeverity::Medium,
        check: ComplianceCheckId::KernelParams,
        category: "Kernel Parameters",
    },
    ComplianceRule {
        id: "cis-6.1",
        title: "Ensure no persistence mechanisms are planted",
        description: "Check unauthorized cron, shell profile and systemd persistence",
        standard: ComplianceStandard::Cis,
        clause: "CIS 6.1",
        severity: DetectionSeverity::High,
        check: ComplianceCheckId::PersistenceScan,
        category: "Persistence Detection",
    },
    ComplianceRule {
        id: "cis-4.2",
        title: "Ensure log file integrity",
        description: "Log files should not be truncated, deleted or tampered with",
        standard: ComplianceStandard::Cis,
        clause: "CIS 4.2",
        severity: DetectionSeverity::High,
        check: ComplianceCheckId::LogTamper,
        category: "Logging and Auditing",
    },
];

pub fn compliance_rules(standard: ComplianceStandard) -> &'static [ComplianceRule] {
    match standard {
        ComplianceStandard::Cis => &CIS_RULES,
        ComplianceStandard::Mlps2 => &MLPS2_RULES,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplianceRuleStatus {
    Passed,
    Failed,
    Pending,
    NotApplicable,
    Error,
}

impl ComplianceRuleStatus {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Passed => "通过",
            Self::Failed => "未通过",
            Self::Pending => "待检测",
            Self::NotApplicable => "不适用",
            Self::Error => "检测错误",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComplianceRuleResult {
    pub rule: ComplianceRule,
    pub status: ComplianceRuleStatus,
    pub details: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComplianceSummary {
    pub standard: ComplianceStandard,
    pub target: Option<TargetGuard>,
    pub scan_id: Option<String>,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub pending: usize,
    pub not_applicable: usize,
    pub errors: usize,
    pub percent: usize,
    pub results: Vec<ComplianceRuleResult>,
}

impl ComplianceSummary {
    pub fn to_markdown(&self) -> String {
        let mut output = format!(
            "# LovelyHawk 合规检查\n\n- 标准：{}\n- 目标：{}\n- 扫描：{}\n- 通过率：{}%（通过 {} / 总计 {}，失败 {}，待检测 {}，不适用 {}，错误 {}）\n\n| 条款 | 项目 | 检测项 | 结果 |\n|---|---|---|---|\n",
            self.standard.label(),
            self.target
                .as_ref()
                .map(|target| format!(
                    "{} @ generation {}",
                    target.identity.as_str(),
                    target.generation
                ))
                .unwrap_or_else(|| "尚无当前目标报告".to_owned()),
            self.scan_id.as_deref().unwrap_or("尚未运行"),
            self.percent,
            self.passed,
            self.total,
            self.failed,
            self.pending,
            self.not_applicable,
            self.errors,
        );
        for result in &self.results {
            output.push_str(&format!(
                "| {} | {} | `{}` | {} |\n",
                escape_markdown_cell(result.rule.clause),
                escape_markdown_cell(result.rule.title),
                result.rule.check.id(),
                result.status.label(),
            ));
        }
        output
    }
}

pub fn generate_compliance_summary(
    standard: ComplianceStandard,
    report: Option<&DetectionScanReport>,
) -> ComplianceSummary {
    let mapped = report
        .map(|report| {
            report
                .modules
                .iter()
                .filter_map(|module| {
                    ComplianceCheckId::from_detection_kind(module.kind).map(|check| (check, module))
                })
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();

    let results = compliance_rules(standard)
        .iter()
        .copied()
        .map(|rule| {
            let (status, details) = mapped.get(&rule.check).map_or_else(
                || {
                    (
                        ComplianceRuleStatus::Pending,
                        "当前扫描未包含该 typed 检测项".to_owned(),
                    )
                },
                |module| compliance_status(module),
            );
            ComplianceRuleResult {
                rule,
                status,
                details,
            }
        })
        .collect::<Vec<_>>();

    let mut summary = ComplianceSummary {
        standard,
        target: report.map(|report| report.target.clone()),
        scan_id: report.map(|report| report.id.clone()),
        total: results.len(),
        passed: 0,
        failed: 0,
        pending: 0,
        not_applicable: 0,
        errors: 0,
        percent: 0,
        results,
    };
    for result in &summary.results {
        match result.status {
            ComplianceRuleStatus::Passed => summary.passed += 1,
            ComplianceRuleStatus::Failed => summary.failed += 1,
            ComplianceRuleStatus::Pending => summary.pending += 1,
            ComplianceRuleStatus::NotApplicable => summary.not_applicable += 1,
            ComplianceRuleStatus::Error => summary.errors += 1,
        }
    }
    if summary.total > 0 {
        summary.percent = (summary.passed * 100 + summary.total / 2) / summary.total;
    }
    summary
}

fn compliance_status(module: &DetectionModuleReport) -> (ComplianceRuleStatus, String) {
    match module.outcome {
        DetectionOutcome::Passed => (
            ComplianceRuleStatus::Passed,
            format!("{} 分，未发现风险", module.score),
        ),
        DetectionOutcome::Failed => (
            ComplianceRuleStatus::Failed,
            format!(
                "{} 分，{} 个类型化发现",
                module.score,
                module.findings.len()
            ),
        ),
        DetectionOutcome::NotApplicable => (
            ComplianceRuleStatus::NotApplicable,
            "目标环境不适用".to_owned(),
        ),
        DetectionOutcome::Error | DetectionOutcome::Cancelled => {
            (ComplianceRuleStatus::Error, "检测错误或已取消".to_owned())
        }
    }
}

fn escape_markdown_cell(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace(['\r', '\n'], " ")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::Utc;

    use super::*;
    use crate::{
        detection::{DetectionScanProfile, DetectionScanStatus, DetectionSummary},
        target::{TargetContext, TargetIdentity},
    };

    fn module(kind: DetectionKind, outcome: DetectionOutcome) -> DetectionModuleReport {
        DetectionModuleReport {
            kind,
            outcome,
            score: if outcome == DetectionOutcome::Passed {
                100
            } else {
                40
            },
            findings: Vec::new(),
            raw_text: String::new(),
            raw_text_truncated: false,
            duration_ms: 1,
        }
    }

    fn report(modules: Vec<DetectionModuleReport>) -> DetectionScanReport {
        let target = TargetContext::new();
        DetectionScanReport {
            id: "scan-compliance".to_owned(),
            target: target
                .activate(TargetIdentity::new("compliance-host").unwrap())
                .unwrap(),
            profile: DetectionScanProfile::Selected,
            started_at: Utc::now(),
            duration_ms: 2,
            status: DetectionScanStatus::Completed,
            overall_score: 70,
            modules,
            summary: DetectionSummary::default(),
            dropped_progress_events: 0,
        }
    }

    #[test]
    fn every_rule_maps_to_a_closed_hyphenated_detection_id() {
        let supported = ComplianceCheckId::ALL.into_iter().collect::<BTreeSet<_>>();
        let mut rule_ids = BTreeSet::new();
        for rule in CIS_RULES.iter().chain(MLPS2_RULES.iter()) {
            assert!(supported.contains(&rule.check), "{}", rule.id);
            assert!(!rule.check.id().contains('_'), "{}", rule.id);
            assert!(rule_ids.insert(rule.id), "duplicate rule {}", rule.id);
            assert_eq!(
                rule.standard,
                if rule.id.starts_with("cis-") {
                    ComplianceStandard::Cis
                } else {
                    ComplianceStandard::Mlps2
                }
            );
        }
        assert_eq!(rule_ids.len(), CIS_RULES.len() + MLPS2_RULES.len());
    }

    #[test]
    fn summary_counts_only_directly_mapped_scan_results() {
        let report = report(vec![
            module(DetectionKind::SshAudit, DetectionOutcome::Passed),
            module(DetectionKind::FirewallCheck, DetectionOutcome::Failed),
            module(DetectionKind::PortScan, DetectionOutcome::Passed),
        ]);
        let summary = generate_compliance_summary(ComplianceStandard::Cis, Some(&report));
        assert_eq!(summary.total, CIS_RULES.len());
        assert_eq!(summary.passed, 1);
        assert_eq!(summary.failed, 1);
        assert_eq!(summary.pending, CIS_RULES.len() - 2);
        assert_eq!(summary.percent, 10);
        assert_eq!(summary.target.as_ref(), Some(&report.target));
    }

    #[test]
    fn not_applicable_and_errors_do_not_become_false_passes() {
        let report = report(vec![
            module(DetectionKind::WebshellScan, DetectionOutcome::NotApplicable),
            module(DetectionKind::SshAudit, DetectionOutcome::Error),
        ]);
        let summary = generate_compliance_summary(ComplianceStandard::Mlps2, Some(&report));
        assert_eq!(summary.not_applicable, 1);
        assert_eq!(summary.errors, 1);
        assert_eq!(summary.passed, 0);
        assert_eq!(summary.failed, 0);
    }

    #[test]
    fn markdown_export_is_target_bound_and_contains_no_remote_raw_text() {
        let mut report = report(vec![module(
            DetectionKind::SshAudit,
            DetectionOutcome::Failed,
        )]);
        report.modules[0].raw_text = "<script>|remote-secret".to_owned();
        let markdown =
            generate_compliance_summary(ComplianceStandard::Cis, Some(&report)).to_markdown();
        assert!(markdown.contains("compliance-host @ generation 1"));
        assert!(markdown.contains("`ssh-audit`"));
        assert!(!markdown.contains("remote-secret"));
        assert!(!markdown.contains("<script>"));
    }
}
