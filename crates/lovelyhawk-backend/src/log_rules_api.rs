//! The operator's own log match rules: named patterns kept in the portable
//! data directory and applied to the lines a log page has already read.
//!
//! Local only. Nothing here reaches a target: matching takes the page's
//! lines and runs them through core, with the same regex engine that
//! validated each pattern when it was saved, so a rule matches exactly what
//! its pattern says and nothing the page's own engine would read differently.
//! Removing a rule is permanent and goes through a plan the operator confirms.

use std::{collections::HashMap, time::Instant};

use lovelyhawk_core::{
    BackendServices, CoreError,
    log_analysis::{
        CreateLogMatchRule, LogEntry, LogMatchRule, LogRuleRemovalPlan, LogRuleSeverity,
    },
    operations::DangerousConfirmation,
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// One request to `log.rules`, told apart by its action.
#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum LogRulesRequest {
    List,
    Add {
        name: String,
        pattern: String,
        severity: LogRuleSeverity,
    },
    Match {
        lines: Vec<String>,
    },
    PlanRemove {
        id: String,
    },
    ConfirmRemove {
        handle: String,
    },
    CancelRemove {
        handle: String,
    },
}

/// Core keeps at most this many rules (MAX_LOG_RULES in core's log_analysis.rs).
const MAX_RULES: usize = 128;
const MAX_PENDING_REMOVALS: usize = 16;
const REMOVAL_PLAN_TTL_SECONDS: u64 = 300;
/// One page of a log, which is what a page asks to have matched.
pub(crate) const MAX_MATCH_LINES: usize = 500;
pub(crate) const MAX_MATCH_LINE_BYTES: usize = 16 * 1024;

#[derive(Debug, Default)]
pub(crate) struct LogRulesApi {
    pending: Mutex<HashMap<String, PendingRemoval>>,
}

#[derive(Debug)]
struct PendingRemoval {
    created_at: Instant,
    plan: LogRuleRemovalPlan,
}

#[derive(Debug)]
pub(crate) enum LogRulesApiError {
    Core(CoreError),
    InvalidName,
    InvalidPattern,
    DuplicateName,
    Capacity,
    InvalidLines,
    NotFound,
    InvalidPlan,
    PlanCapacity,
}

impl From<CoreError> for LogRulesApiError {
    fn from(error: CoreError) -> Self {
        match &error {
            CoreError::NotFound { .. } => Self::NotFound,
            CoreError::Validation { subject, message } => match *subject {
                "log rule name" if message.contains("unique") => Self::DuplicateName,
                "log rule name" => Self::InvalidName,
                "log rule pattern" => Self::InvalidPattern,
                "log match rules" => Self::Capacity,
                "log rule ID" => Self::NotFound,
                _ => Self::Core(error),
            },
            _ => Self::Core(error),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LogRuleDto {
    id: String,
    name: String,
    pattern: String,
    severity: LogRuleSeverity,
}

impl From<LogMatchRule> for LogRuleDto {
    fn from(rule: LogMatchRule) -> Self {
        Self {
            id: rule.id,
            name: rule.name,
            pattern: rule.pattern,
            severity: rule.severity,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LogRuleList {
    rules: Vec<LogRuleDto>,
    maximum: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LogRuleHit {
    id: String,
    name: String,
    severity: LogRuleSeverity,
}

/// One answer per line asked about, in order: the first rule that matched it, or null.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LogRuleMatches {
    matches: Vec<Option<LogRuleHit>>,
    rule_count: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LogRuleRemovalProposal {
    handle: String,
    summary: String,
    expires_in_seconds: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LogRuleRemovalResult {
    rule_id: String,
    verified: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LogRuleRemovalCancellation {
    cancelled: bool,
}

impl LogRulesApi {
    pub(crate) async fn dispatch(
        &self,
        services: &BackendServices,
        request: LogRulesRequest,
    ) -> Result<Value, LogRulesApiError> {
        let value = match request {
            LogRulesRequest::List => to_value(self.list(services)?),
            LogRulesRequest::Add {
                name,
                pattern,
                severity,
            } => to_value(self.add(services, name, pattern, severity)?),
            LogRulesRequest::Match { lines } => to_value(self.match_lines(services, lines)?),
            LogRulesRequest::PlanRemove { id } => to_value(self.plan_remove(services, &id)?),
            LogRulesRequest::ConfirmRemove { handle } => {
                to_value(self.confirm_remove(services, &handle).await?)
            }
            LogRulesRequest::CancelRemove { handle } => to_value(self.cancel_remove(&handle)?),
        };
        Ok(value)
    }

    pub(crate) fn list(&self, services: &BackendServices) -> Result<LogRuleList, LogRulesApiError> {
        let rules = services.log_analysis().list_rules()?;
        Ok(LogRuleList {
            rules: rules.into_iter().map(LogRuleDto::from).collect(),
            maximum: MAX_RULES,
        })
    }

    pub(crate) fn add(
        &self,
        services: &BackendServices,
        name: String,
        pattern: String,
        severity: LogRuleSeverity,
    ) -> Result<LogRuleDto, LogRulesApiError> {
        let rule = services.log_analysis().add_rule(CreateLogMatchRule {
            name,
            pattern,
            severity,
        })?;
        Ok(rule.into())
    }

    /// Which saved rule, if any, each of these lines matches.
    pub(crate) fn match_lines(
        &self,
        services: &BackendServices,
        lines: Vec<String>,
    ) -> Result<LogRuleMatches, LogRulesApiError> {
        if lines.len() > MAX_MATCH_LINES
            || lines.iter().any(|line| line.len() > MAX_MATCH_LINE_BYTES)
        {
            return Err(LogRulesApiError::InvalidLines);
        }
        let rules = services.log_analysis().list_rules()?;
        let rule_count = rules.len();
        if rules.is_empty() {
            return Ok(LogRuleMatches {
                matches: lines.iter().map(|_| None).collect(),
                rule_count,
            });
        }
        let entries = lines
            .into_iter()
            .map(|raw| LogEntry {
                timestamp: String::new(),
                level: String::new(),
                service: String::new(),
                message: String::new(),
                raw,
                highlighted: false,
                source: None,
            })
            .collect::<Vec<_>>();
        let matches = services
            .log_analysis()
            .match_rules(&rules, &entries)?
            .into_iter()
            .map(|rule| {
                rule.map(|rule| LogRuleHit {
                    id: rule.id,
                    name: rule.name,
                    severity: rule.severity,
                })
            })
            .collect();
        Ok(LogRuleMatches {
            matches,
            rule_count,
        })
    }

    pub(crate) fn plan_remove(
        &self,
        services: &BackendServices,
        id: &str,
    ) -> Result<LogRuleRemovalProposal, LogRulesApiError> {
        let plan = services.log_analysis().plan_remove_rule(id)?;
        let summary = plan.definition().summary.clone();
        let handle = Uuid::new_v4().to_string();
        let mut pending = self.pending.lock();
        Self::prune_expired(&mut pending);
        if pending.len() >= MAX_PENDING_REMOVALS {
            return Err(LogRulesApiError::PlanCapacity);
        }
        pending.insert(
            handle.clone(),
            PendingRemoval {
                created_at: Instant::now(),
                plan,
            },
        );
        Ok(LogRuleRemovalProposal {
            handle,
            summary,
            expires_in_seconds: REMOVAL_PLAN_TTL_SECONDS,
        })
    }

    pub(crate) async fn confirm_remove(
        &self,
        services: &BackendServices,
        handle: &str,
    ) -> Result<LogRuleRemovalResult, LogRulesApiError> {
        let pending = {
            let mut plans = self.pending.lock();
            Self::prune_expired(&mut plans);
            plans.remove(handle).ok_or(LogRulesApiError::InvalidPlan)?
        };
        let confirmation = DangerousConfirmation::approve(pending.plan.definition());
        let outcome = services
            .log_analysis()
            .execute_remove_rule(pending.plan, confirmation, services.operation_journal())
            .await?;
        Ok(LogRuleRemovalResult {
            rule_id: outcome.removed_rule_id,
            verified: outcome.verification.passed,
        })
    }

    pub(crate) fn cancel_remove(
        &self,
        handle: &str,
    ) -> Result<LogRuleRemovalCancellation, LogRulesApiError> {
        let mut plans = self.pending.lock();
        Self::prune_expired(&mut plans);
        plans.remove(handle).ok_or(LogRulesApiError::InvalidPlan)?;
        Ok(LogRuleRemovalCancellation { cancelled: true })
    }

    fn prune_expired(plans: &mut HashMap<String, PendingRemoval>) {
        plans
            .retain(|_, pending| pending.created_at.elapsed().as_secs() < REMOVAL_PLAN_TTL_SECONDS);
    }
}

fn to_value<T: Serialize>(value: T) -> Value {
    // These DTOs always serialize; a null would be refused by the page anyway.
    serde_json::to_value(value).unwrap_or(Value::Null)
}
