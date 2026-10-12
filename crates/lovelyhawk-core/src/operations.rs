//! Enforced lifecycle for destructive and reversible operations.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::store::StoreFile;
use crate::target::{TargetContext, TargetGuard};
use crate::{CoreError, CoreResult, PortableStore};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationPlan {
    pub id: String,
    pub target: TargetGuard,
    pub summary: String,
    pub dangerous: bool,
    pub restore_description: Option<String>,
    pub metadata: BTreeMap<String, String>,
    pub created_at: DateTime<Utc>,
}

impl OperationPlan {
    pub fn new(
        target: TargetGuard,
        summary: impl Into<String>,
        dangerous: bool,
        restore_description: Option<String>,
    ) -> CoreResult<Self> {
        let summary = summary.into();
        if summary.trim().is_empty() || summary.len() > 2_048 {
            return Err(CoreError::validation(
                "operation summary",
                "must be non-empty and at most 2048 bytes",
            ));
        }
        if restore_description
            .as_ref()
            .is_some_and(|description| description.trim().is_empty())
        {
            return Err(CoreError::validation(
                "restore description",
                "must be non-empty when present",
            ));
        }
        Ok(Self {
            id: Uuid::new_v4().to_string(),
            target,
            summary,
            dangerous,
            restore_description,
            metadata: BTreeMap::new(),
            created_at: Utc::now(),
        })
    }
}

/// UI confirmation bound to one operation id; it cannot confirm another plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DangerousConfirmation {
    operation_id: String,
    approved: bool,
}

impl DangerousConfirmation {
    pub fn approve(plan: &OperationPlan) -> Self {
        Self {
            operation_id: plan.id.clone(),
            approved: true,
        }
    }

    pub fn reject(plan: &OperationPlan) -> Self {
        Self {
            operation_id: plan.id.clone(),
            approved: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationState {
    Planned,
    Confirmed,
    Executed,
    StaleAfterExecution,
    Journaled,
    Verified,
    VerificationFailed,
    Restored,
    Cancelled,
}

impl OperationState {
    const fn name(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Confirmed => "confirmed",
            Self::Executed => "executed",
            Self::StaleAfterExecution => "stale-after-execution",
            Self::Journaled => "journaled",
            Self::Verified => "verified",
            Self::VerificationFailed => "verification-failed",
            Self::Restored => "restored",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ExecutionReceipt {
    /// Human-readable result safe to persist in the operation journal.
    pub summary: String,
    /// Opaque executor data retained only in memory and never journaled.
    pub restore_token: Option<String>,
}

impl std::fmt::Debug for ExecutionReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecutionReceipt")
            .field("summary", &self.summary)
            .field(
                "restore_token",
                &self.restore_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationResult {
    pub passed: bool,
    pub detail: String,
}

#[async_trait]
pub trait OperationExecutor: Send + Sync + std::fmt::Debug {
    async fn execute(&self, plan: &OperationPlan) -> CoreResult<ExecutionReceipt>;
    async fn verify(
        &self,
        plan: &OperationPlan,
        receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult>;
    async fn restore(&self, plan: &OperationPlan, receipt: &ExecutionReceipt) -> CoreResult<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum JournalPhase {
    Executed,
    StaleAfterExecution,
    VerificationPassed,
    VerificationFailed,
    Restored,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationJournalEntry {
    pub entry_id: String,
    pub operation_id: String,
    pub target: TargetGuard,
    pub summary: String,
    pub dangerous: bool,
    #[serde(default = "default_operation_source")]
    pub source: String,
    #[serde(default)]
    pub restore_description: Option<String>,
    pub phase: JournalPhase,
    pub detail: String,
    pub occurred_at: DateTime<Utc>,
}

fn default_operation_source() -> String {
    "operation".to_owned()
}

pub trait OperationJournal: Send + Sync + std::fmt::Debug {
    fn append(&self, entry: OperationJournalEntry) -> CoreResult<()>;
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct StoredJournal {
    entries: Vec<OperationJournalEntry>,
}

pub const OPERATION_JOURNAL_EXPORT_SCHEMA: &str = "lovelyres-operation-journal-export/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationJournalExport {
    pub schema: String,
    pub exported_at: DateTime<Utc>,
    pub target: TargetGuard,
    pub entries: Vec<OperationJournalEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationJournalClearPlan {
    operation: OperationPlan,
    entry_ids: Vec<String>,
    entry_set_sha256: String,
}

impl OperationJournalClearPlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn entry_count(&self) -> usize {
        self.entry_ids.len()
    }

    pub fn entry_set_sha256(&self) -> &str {
        &self.entry_set_sha256
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationJournalClearOutcome {
    pub removed_entries: usize,
    pub entry_set_sha256: String,
    pub verification: VerificationResult,
}

#[derive(Debug, Clone)]
pub struct PortableOperationJournal {
    store: PortableStore,
    lock: Arc<Mutex<()>>,
}

impl PortableOperationJournal {
    pub fn new(store: PortableStore) -> Self {
        Self {
            store,
            lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn entries(&self) -> CoreResult<Vec<OperationJournalEntry>> {
        let _guard = self.lock.lock();
        Ok(self
            .store
            .read_or_default::<StoredJournal>(StoreFile::OperationJournal)?
            .entries)
    }

    pub fn entries_for_target(
        &self,
        target: &TargetGuard,
    ) -> CoreResult<Vec<OperationJournalEntry>> {
        Ok(self
            .entries()?
            .into_iter()
            .filter(|entry| entry.target == *target)
            .collect())
    }

    pub fn export_for_target(&self, target: &TargetGuard) -> CoreResult<OperationJournalExport> {
        Ok(OperationJournalExport {
            schema: OPERATION_JOURNAL_EXPORT_SCHEMA.to_owned(),
            exported_at: Utc::now(),
            target: target.clone(),
            entries: self.entries_for_target(target)?,
        })
    }

    pub fn plan_clear_for_target(
        &self,
        target: &TargetGuard,
    ) -> CoreResult<OperationJournalClearPlan> {
        let mut entry_ids = self
            .entries_for_target(target)?
            .into_iter()
            .map(|entry| entry.entry_id)
            .collect::<Vec<_>>();
        entry_ids.sort();
        if entry_ids.is_empty() {
            return Err(CoreError::validation(
                "operation journal clear",
                "there are no entries for the exact target epoch",
            ));
        }
        let entry_set_sha256 = entry_id_set_sha256(&entry_ids);
        let mut operation = OperationPlan::new(
            target.clone(),
            format!(
                "永久清除当前目标会话的 {} 条操作日志；集合摘要 {}。",
                entry_ids.len(),
                entry_set_sha256
            ),
            true,
            None,
        )?;
        operation
            .metadata
            .insert("source".to_owned(), "operation-journal".to_owned());
        operation.metadata.insert(
            "planned-entry-count".to_owned(),
            entry_ids.len().to_string(),
        );
        operation.metadata.insert(
            "planned-entry-set-sha256".to_owned(),
            entry_set_sha256.clone(),
        );
        Ok(OperationJournalClearPlan {
            operation,
            entry_ids,
            entry_set_sha256,
        })
    }

    pub async fn execute_clear_for_target(
        &self,
        target_context: &TargetContext,
        plan: OperationJournalClearPlan,
        confirmation: DangerousConfirmation,
    ) -> CoreResult<OperationJournalClearOutcome> {
        let executor = JournalClearExecutor {
            journal: self.clone(),
            plan: plan.clone(),
        };
        let mut operation = PlannedOperation::plan(plan.operation.clone());
        operation.confirm(confirmation)?;
        if let Err(error) = operation.execute(target_context, &executor).await {
            if operation.state() == OperationState::StaleAfterExecution {
                operation.journal(self)?;
            }
            return Err(error);
        }
        operation.journal(self)?;
        let verification = operation.verify(target_context, &executor, self).await?;
        Ok(OperationJournalClearOutcome {
            removed_entries: plan.entry_ids.len(),
            entry_set_sha256: plan.entry_set_sha256,
            verification,
        })
    }

    fn clear_snapshot(&self, plan: &OperationJournalClearPlan) -> CoreResult<()> {
        let _guard = self.lock.lock();
        let mut journal = self
            .store
            .read_or_default::<StoredJournal>(StoreFile::OperationJournal)?;
        let planned = plan.entry_ids.iter().cloned().collect::<BTreeSet<_>>();
        let mut present = journal
            .entries
            .iter()
            .filter(|entry| entry.target == plan.operation.target)
            .filter(|entry| planned.contains(&entry.entry_id))
            .map(|entry| entry.entry_id.clone())
            .collect::<Vec<_>>();
        present.sort();
        if present != plan.entry_ids || entry_id_set_sha256(&present) != plan.entry_set_sha256 {
            return Err(CoreError::validation(
                "operation journal clear plan",
                "the reviewed entry set changed before execution",
            ));
        }
        journal.entries.retain(|entry| {
            entry.target != plan.operation.target || !planned.contains(&entry.entry_id)
        });
        self.store.write(StoreFile::OperationJournal, &journal)
    }

    fn snapshot_is_absent(&self, plan: &OperationJournalClearPlan) -> CoreResult<bool> {
        let planned = plan
            .entry_ids
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        Ok(!self
            .entries_for_target(&plan.operation.target)?
            .iter()
            .any(|entry| planned.contains(entry.entry_id.as_str())))
    }
}

#[derive(Debug)]
struct JournalClearExecutor {
    journal: PortableOperationJournal,
    plan: OperationJournalClearPlan,
}

#[async_trait]
impl OperationExecutor for JournalClearExecutor {
    async fn execute(&self, definition: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        if definition != &self.plan.operation {
            return Err(CoreError::validation(
                "operation journal clear",
                "executor received a different immutable plan",
            ));
        }
        self.journal.clear_snapshot(&self.plan)?;
        Ok(ExecutionReceipt {
            summary: format!(
                "cleared {} reviewed journal entries",
                self.plan.entry_ids.len()
            ),
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
                "operation journal clear",
                "verification received a different immutable plan",
            ));
        }
        let passed = self.journal.snapshot_is_absent(&self.plan)?;
        Ok(VerificationResult {
            passed,
            detail: if passed {
                format!(
                    "reviewed journal entry set {} is absent",
                    self.plan.entry_set_sha256
                )
            } else {
                "one or more reviewed journal entries remain".to_owned()
            },
        })
    }

    async fn restore(&self, _: &OperationPlan, _: &ExecutionReceipt) -> CoreResult<()> {
        Err(CoreError::Unsupported {
            feature: "restoring permanently cleared operation journal entries",
        })
    }
}

fn entry_id_set_sha256(entry_ids: &[String]) -> String {
    let mut digest = Sha256::new();
    for entry_id in entry_ids {
        digest.update((entry_id.len() as u64).to_be_bytes());
        digest.update(entry_id.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

impl OperationJournal for PortableOperationJournal {
    fn append(&self, entry: OperationJournalEntry) -> CoreResult<()> {
        let _guard = self.lock.lock();
        let mut journal = self
            .store
            .read_or_default::<StoredJournal>(StoreFile::OperationJournal)?;
        journal.entries.push(entry);
        self.store.write(StoreFile::OperationJournal, &journal)
    }
}

/// Stateful operation handle. Side effects are only reachable through methods
/// that enforce the plan/confirm/execute/journal/verify-or-restore order.
#[derive(Debug)]
pub struct PlannedOperation {
    plan: OperationPlan,
    state: OperationState,
    receipt: Option<ExecutionReceipt>,
    stale_after_execute: bool,
}

impl PlannedOperation {
    pub fn plan(plan: OperationPlan) -> Self {
        Self {
            plan,
            state: OperationState::Planned,
            receipt: None,
            stale_after_execute: false,
        }
    }

    pub fn definition(&self) -> &OperationPlan {
        &self.plan
    }

    pub fn state(&self) -> OperationState {
        self.state
    }

    pub fn confirm(&mut self, confirmation: DangerousConfirmation) -> CoreResult<()> {
        self.require_state(OperationState::Planned, "confirm")?;
        if !self.plan.dangerous {
            return Err(CoreError::InvalidOperationState {
                state: self.state.name(),
                action: "confirm a non-dangerous operation",
            });
        }
        if confirmation.operation_id != self.plan.id {
            return Err(CoreError::validation(
                "dangerous confirmation",
                "confirmation belongs to a different operation",
            ));
        }
        if confirmation.approved {
            self.state = OperationState::Confirmed;
            Ok(())
        } else {
            self.state = OperationState::Cancelled;
            Err(CoreError::OperationCancelled {
                operation_id: self.plan.id.clone(),
            })
        }
    }

    pub async fn execute(
        &mut self,
        target: &TargetContext,
        executor: &dyn OperationExecutor,
    ) -> CoreResult<()> {
        if self.plan.dangerous && self.state != OperationState::Confirmed {
            return Err(CoreError::ConfirmationRequired {
                operation_id: self.plan.id.clone(),
            });
        }
        let expected = if self.plan.dangerous {
            OperationState::Confirmed
        } else {
            OperationState::Planned
        };
        self.require_state(expected, "execute")?;

        target.validate(&self.plan.target)?;
        let receipt = executor.execute(&self.plan).await?;
        self.receipt = Some(receipt);
        self.state = OperationState::Executed;
        if let Err(error) = target.validate(&self.plan.target) {
            self.stale_after_execute = true;
            self.state = OperationState::StaleAfterExecution;
            return Err(error);
        }
        Ok(())
    }

    pub fn journal(&mut self, journal: &dyn OperationJournal) -> CoreResult<()> {
        if !matches!(
            self.state,
            OperationState::Executed | OperationState::StaleAfterExecution
        ) {
            return Err(CoreError::InvalidOperationState {
                state: self.state.name(),
                action: "journal execution",
            });
        }
        let receipt = self.receipt()?;
        let phase = if self.stale_after_execute {
            JournalPhase::StaleAfterExecution
        } else {
            JournalPhase::Executed
        };
        journal.append(self.entry(phase, receipt.summary.clone()))?;
        self.state = OperationState::Journaled;
        Ok(())
    }

    pub async fn verify(
        &mut self,
        target: &TargetContext,
        executor: &dyn OperationExecutor,
        journal: &dyn OperationJournal,
    ) -> CoreResult<VerificationResult> {
        self.require_state(OperationState::Journaled, "verify")?;
        if self.stale_after_execute {
            return Err(CoreError::InvalidOperationState {
                state: "journaled-stale-execution",
                action: "verify against a replacement target session",
            });
        }
        target.validate(&self.plan.target)?;
        let receipt = self.receipt()?.clone();
        let verification = match executor.verify(&self.plan, &receipt).await {
            Ok(verification) => verification,
            Err(error) => {
                journal.append(self.entry(JournalPhase::VerificationFailed, error.to_string()))?;
                self.state = OperationState::VerificationFailed;
                return Err(error);
            }
        };
        target.validate(&self.plan.target)?;
        let (phase, state) = if verification.passed {
            (JournalPhase::VerificationPassed, OperationState::Verified)
        } else {
            (
                JournalPhase::VerificationFailed,
                OperationState::VerificationFailed,
            )
        };
        journal.append(self.entry(phase, verification.detail.clone()))?;
        self.state = state;
        Ok(verification)
    }

    pub async fn restore(
        &mut self,
        target: &TargetContext,
        executor: &dyn OperationExecutor,
        journal: &dyn OperationJournal,
    ) -> CoreResult<()> {
        if !matches!(
            self.state,
            OperationState::Executed
                | OperationState::StaleAfterExecution
                | OperationState::Journaled
                | OperationState::Verified
                | OperationState::VerificationFailed
        ) {
            return Err(CoreError::InvalidOperationState {
                state: self.state.name(),
                action: "restore",
            });
        }
        let restore_description = self
            .plan
            .restore_description
            .clone()
            .ok_or_else(|| CoreError::validation("restore", "operation is not reversible"))?;
        target.validate(&self.plan.target)?;
        let receipt = self.receipt()?.clone();
        executor.restore(&self.plan, &receipt).await?;
        target.validate(&self.plan.target)?;
        // The remote restore is already complete at this point. Reflect that
        // truth even when the following durable journal append itself fails.
        self.state = OperationState::Restored;
        journal.append(self.entry(JournalPhase::Restored, restore_description))?;
        Ok(())
    }

    fn receipt(&self) -> CoreResult<&ExecutionReceipt> {
        self.receipt
            .as_ref()
            .ok_or(CoreError::InvalidOperationState {
                state: self.state.name(),
                action: "access execution receipt",
            })
    }

    /// The receipt an executor needs to check its work again later.
    pub(crate) fn execution_receipt(&self) -> CoreResult<&ExecutionReceipt> {
        self.receipt()
    }

    fn require_state(&self, expected: OperationState, action: &'static str) -> CoreResult<()> {
        if self.state == expected {
            Ok(())
        } else {
            Err(CoreError::InvalidOperationState {
                state: self.state.name(),
                action,
            })
        }
    }

    fn entry(&self, phase: JournalPhase, detail: String) -> OperationJournalEntry {
        OperationJournalEntry {
            entry_id: Uuid::new_v4().to_string(),
            operation_id: self.plan.id.clone(),
            target: self.plan.target.clone(),
            summary: self.plan.summary.clone(),
            dangerous: self.plan.dangerous,
            source: operation_source(&self.plan),
            restore_description: self.plan.restore_description.clone(),
            phase,
            detail,
            occurred_at: Utc::now(),
        }
    }
}

fn operation_source(plan: &OperationPlan) -> String {
    if let Some(source) = plan.metadata.get("source")
        && !source.is_empty()
        && source.len() <= 64
        && source
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return source.clone();
    }
    for (key, source) in [
        ("task-id", "batch"),
        ("database-engine", "database"),
        ("baseline_id", "integrity"),
        ("snapshot-id", "snapshot"),
        ("container-id", "docker"),
        ("connection-id", "connection"),
        ("provider-id", "settings"),
        ("note-id", "investigation"),
        ("case-id", "investigation"),
        ("history-id", "investigation"),
    ] {
        if plan.metadata.contains_key(key) {
            return source.to_owned();
        }
    }
    if plan.metadata.contains_key("action") {
        return "sftp".to_owned();
    }
    default_operation_source()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::target::TargetIdentity;

    #[derive(Debug)]
    struct FakeExecutor {
        execute_count: AtomicUsize,
        verification_passes: bool,
        switch_during_execute: Option<Arc<TargetContext>>,
    }

    #[async_trait]
    impl OperationExecutor for FakeExecutor {
        async fn execute(&self, _plan: &OperationPlan) -> CoreResult<ExecutionReceipt> {
            self.execute_count.fetch_add(1, Ordering::SeqCst);
            if let Some(context) = &self.switch_during_execute {
                context.activate(TargetIdentity::new("replacement").unwrap())?;
            }
            Ok(ExecutionReceipt {
                summary: "command completed".to_owned(),
                restore_token: Some("opaque-token".to_owned()),
            })
        }

        async fn verify(
            &self,
            _plan: &OperationPlan,
            _receipt: &ExecutionReceipt,
        ) -> CoreResult<VerificationResult> {
            Ok(VerificationResult {
                passed: self.verification_passes,
                detail: "verification result".to_owned(),
            })
        }

        async fn restore(
            &self,
            _plan: &OperationPlan,
            _receipt: &ExecutionReceipt,
        ) -> CoreResult<()> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("lovelyres-ops-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn setup() -> (TestRoot, Arc<TargetContext>, PortableOperationJournal) {
        let root = TestRoot::new();
        let store = PortableStore::prepare(root.0.clone()).unwrap();
        (
            root,
            Arc::new(TargetContext::new()),
            PortableOperationJournal::new(store),
        )
    }

    #[tokio::test]
    async fn dangerous_operation_cannot_execute_without_matching_confirmation() {
        let (_root, target, journal) = setup();
        let guard = target
            .activate(TargetIdentity::new("host-a").unwrap())
            .unwrap();
        let plan = OperationPlan::new(guard, "remove firewall rule", true, None).unwrap();
        let mut operation = PlannedOperation::plan(plan.clone());
        let executor = FakeExecutor {
            execute_count: AtomicUsize::new(0),
            verification_passes: true,
            switch_during_execute: None,
        };

        assert!(matches!(
            operation.execute(&target, &executor).await,
            Err(CoreError::ConfirmationRequired { .. })
        ));
        assert_eq!(executor.execute_count.load(Ordering::SeqCst), 0);

        let other_plan =
            OperationPlan::new(target.current_guard().unwrap(), "other", true, None).unwrap();
        assert!(
            operation
                .confirm(DangerousConfirmation::approve(&other_plan))
                .is_err()
        );
        operation
            .confirm(DangerousConfirmation::approve(&plan))
            .unwrap();
        operation.execute(&target, &executor).await.unwrap();
        operation.journal(&journal).unwrap();
        assert_eq!(operation.state(), OperationState::Journaled);
    }

    // The frozen migration ledger owns this historical test identifier. The
    // separate recovery test below covers the additional pre-journal path.
    #[tokio::test]
    async fn failed_verification_can_restore_only_after_journaling() {
        let (_root, target, journal) = setup();
        let guard = target
            .activate(TargetIdentity::new("host-a").unwrap())
            .unwrap();
        let plan = OperationPlan::new(
            guard,
            "change service configuration",
            true,
            Some("restore previous configuration".to_owned()),
        )
        .unwrap();
        let mut operation = PlannedOperation::plan(plan.clone());
        let executor = FakeExecutor {
            execute_count: AtomicUsize::new(0),
            verification_passes: false,
            switch_during_execute: None,
        };
        operation
            .confirm(DangerousConfirmation::approve(&plan))
            .unwrap();
        operation.execute(&target, &executor).await.unwrap();
        operation.journal(&journal).unwrap();
        assert!(
            !operation
                .verify(&target, &executor, &journal)
                .await
                .unwrap()
                .passed
        );
        operation
            .restore(&target, &executor, &journal)
            .await
            .unwrap();
        assert_eq!(operation.state(), OperationState::Restored);
        assert_eq!(journal.entries().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn reversible_execution_can_restore_when_the_first_journal_append_was_unavailable() {
        let (_root, target, journal) = setup();
        let guard = target
            .activate(TargetIdentity::new("host-a").unwrap())
            .unwrap();
        let plan = OperationPlan::new(
            guard,
            "change service configuration",
            true,
            Some("restore previous configuration".to_owned()),
        )
        .unwrap();
        let mut operation = PlannedOperation::plan(plan.clone());
        let executor = FakeExecutor {
            execute_count: AtomicUsize::new(0),
            verification_passes: true,
            switch_during_execute: None,
        };
        operation
            .confirm(DangerousConfirmation::approve(&plan))
            .unwrap();
        operation.execute(&target, &executor).await.unwrap();
        assert_eq!(operation.state(), OperationState::Executed);
        operation
            .restore(&target, &executor, &journal)
            .await
            .unwrap();
        assert_eq!(operation.state(), OperationState::Restored);
        assert_eq!(journal.entries().unwrap().len(), 1);
        assert_eq!(journal.entries().unwrap()[0].phase, JournalPhase::Restored);
    }

    #[tokio::test]
    async fn target_is_checked_before_and_after_side_effect() {
        let (_root, target, journal) = setup();
        let guard = target
            .activate(TargetIdentity::new("host-a").unwrap())
            .unwrap();
        let plan = OperationPlan::new(guard, "collect state", false, None).unwrap();
        let mut operation = PlannedOperation::plan(plan);
        let executor = FakeExecutor {
            execute_count: AtomicUsize::new(0),
            verification_passes: true,
            switch_during_execute: Some(target.clone()),
        };
        assert!(matches!(
            operation.execute(&target, &executor).await,
            Err(CoreError::TargetChanged { .. })
        ));
        assert_eq!(operation.state(), OperationState::StaleAfterExecution);
        operation.journal(&journal).unwrap();
        assert_eq!(
            journal.entries().unwrap()[0].phase,
            JournalPhase::StaleAfterExecution
        );
        assert!(
            operation
                .verify(&target, &executor, &journal)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn journal_filters_exports_and_planned_clear_bind_the_full_target_guard() {
        let (_root, target, journal) = setup();
        let current = target
            .activate(TargetIdentity::new("host-a").unwrap())
            .unwrap();
        let other_epoch = TargetGuard {
            identity: current.identity.clone(),
            generation: current.generation + 1,
        };
        let make_entry =
            |entry_id: &str, guard: TargetGuard, summary: &str| OperationJournalEntry {
                entry_id: entry_id.to_owned(),
                operation_id: format!("operation-{entry_id}"),
                target: guard,
                summary: summary.to_owned(),
                dangerous: false,
                source: "test".to_owned(),
                restore_description: None,
                phase: JournalPhase::Executed,
                detail: "ok".to_owned(),
                occurred_at: Utc::now(),
            };
        journal
            .append(make_entry("mine-a", current.clone(), "mine-a"))
            .unwrap();
        journal
            .append(make_entry("mine-b", current.clone(), "mine-b"))
            .unwrap();
        journal
            .append(make_entry(
                "other-epoch",
                other_epoch.clone(),
                "other-epoch",
            ))
            .unwrap();

        let export = journal.export_for_target(&current).unwrap();
        assert_eq!(export.schema, OPERATION_JOURNAL_EXPORT_SCHEMA);
        assert_eq!(export.target, current);
        assert_eq!(
            export
                .entries
                .iter()
                .map(|entry| entry.entry_id.as_str())
                .collect::<Vec<_>>(),
            ["mine-a", "mine-b"]
        );
        let json = serde_json::to_string(&export).unwrap();
        assert!(json.contains("mine-a"));
        assert!(!json.contains("other-epoch"));

        let plan = journal.plan_clear_for_target(&current).unwrap();
        assert_eq!(plan.entry_count(), 2);
        assert_eq!(plan.entry_set_sha256().len(), 64);
        journal
            .append(make_entry(
                "concurrent",
                current.clone(),
                "preserve concurrent append",
            ))
            .unwrap();
        let unrelated = OperationPlan::new(current.clone(), "other", true, None).unwrap();
        assert!(
            journal
                .execute_clear_for_target(
                    target.as_ref(),
                    plan.clone(),
                    DangerousConfirmation::approve(&unrelated),
                )
                .await
                .is_err()
        );
        assert_eq!(journal.entries_for_target(&current).unwrap().len(), 3);

        let outcome = journal
            .execute_clear_for_target(
                target.as_ref(),
                plan.clone(),
                DangerousConfirmation::approve(plan.definition()),
            )
            .await
            .unwrap();
        assert_eq!(outcome.removed_entries, 2);
        assert_eq!(outcome.entry_set_sha256, plan.entry_set_sha256());
        assert!(outcome.verification.passed);

        let remaining = journal.entries_for_target(&current).unwrap();
        assert!(remaining.iter().any(|entry| entry.entry_id == "concurrent"));
        assert!(!remaining.iter().any(|entry| entry.entry_id == "mine-a"));
        assert!(!remaining.iter().any(|entry| entry.entry_id == "mine-b"));
        assert_eq!(journal.entries_for_target(&other_epoch).unwrap().len(), 1);
        assert_eq!(
            remaining
                .iter()
                .filter(|entry| entry.source == "operation-journal")
                .map(|entry| entry.phase)
                .collect::<Vec<_>>(),
            [JournalPhase::Executed, JournalPhase::VerificationPassed]
        );
    }

    #[test]
    fn legacy_journal_entries_default_new_safe_report_fields() {
        let guard = TargetGuard {
            identity: TargetIdentity::new("host-a").unwrap(),
            generation: 1,
        };
        let entry = OperationJournalEntry {
            entry_id: "entry-a".to_owned(),
            operation_id: "operation-a".to_owned(),
            target: guard,
            summary: "legacy summary".to_owned(),
            dangerous: false,
            source: "operation".to_owned(),
            restore_description: None,
            phase: JournalPhase::Executed,
            detail: "legacy detail".to_owned(),
            occurred_at: Utc::now(),
        };
        let mut value = serde_json::to_value(entry).unwrap();
        let object = value.as_object_mut().unwrap();
        object.remove("source");
        object.remove("restore_description");

        let decoded: OperationJournalEntry = serde_json::from_value(value).unwrap();
        assert_eq!(decoded.source, "operation");
        assert_eq!(decoded.restore_description, None);
    }

    #[test]
    fn journal_source_is_bounded_and_cannot_preserve_hostile_metadata() {
        let guard = TargetGuard {
            identity: TargetIdentity::new("host-a").unwrap(),
            generation: 1,
        };
        let mut plan = OperationPlan::new(
            guard,
            "safe summary",
            false,
            Some("restore safely".to_owned()),
        )
        .unwrap();
        plan.metadata
            .insert("source".to_owned(), "<script>bad</script>".to_owned());
        plan.metadata
            .insert("snapshot-id".to_owned(), "snapshot-a".to_owned());
        let operation = PlannedOperation::plan(plan);
        let entry = operation.entry(JournalPhase::Executed, "done".to_owned());

        assert_eq!(entry.source, "snapshot");
        assert_eq!(entry.restore_description.as_deref(), Some("restore safely"));
    }
}
