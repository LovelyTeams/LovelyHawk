//! Reviewed case disposition is a local record, never a claim that the host
//! has passed remediation or health verification.
use super::*;

pub const MAX_CASE_CONCLUSION_CHARS: usize = 1024;
pub const MAX_CASE_FOLLOWUP_CHARS: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaseStatusAction {
    Close,
    Reopen,
}
impl CaseStatusAction {
    fn expected(self) -> CaseStatus {
        match self {
            Self::Close => CaseStatus::Open,
            Self::Reopen => CaseStatus::Closed,
        }
    }
    fn resulting(self) -> CaseStatus {
        match self {
            Self::Close => CaseStatus::Closed,
            Self::Reopen => CaseStatus::Open,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseStatusPlan {
    operation: OperationPlan,
    expected: CaseLibraryRecord,
    action: CaseStatusAction,
    conclusion: String,
    followup: String,
    event_id: String,
    was_current: bool,
}
impl CaseStatusPlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }
    pub fn target(&self) -> &TargetIdentity {
        &self.expected.target
    }
    pub fn case_id(&self) -> &str {
        &self.expected.case_id
    }
    pub fn action(&self) -> CaseStatusAction {
        self.action
    }
    pub fn review_text(&self) -> String {
        format!(
            "{}\n\n{}：{}\n\n{}：{}",
            self.operation.summary,
            if self.action == CaseStatusAction::Close {
                "调查结论（人工记录）"
            } else {
                "重新调查的原因"
            },
            self.conclusion,
            if self.action == CaseStatusAction::Close {
                "尚待处理事项"
            } else {
                "后续调查计划"
            },
            self.followup
        )
    }
}

impl IncidentCaseRepository {
    pub fn plan_case_status(
        &self,
        target: &TargetIdentity,
        case_id: &str,
        expected_revision: &str,
        action: CaseStatusAction,
        conclusion: String,
        followup: String,
    ) -> CoreResult<CaseStatusPlan> {
        validate_target(target)?;
        validate_lookup_id(case_id)?;
        required_text_preserving_ref("case conclusion", &conclusion, MAX_CASE_CONCLUSION_CHARS)?;
        required_text_preserving_ref("case followup", &followup, MAX_CASE_FOLLOWUP_CHARS)?;
        let _transaction = self.context.transaction.lock();
        let document = load_cases(&self.context.store)?;
        let incident = document
            .cases
            .iter()
            .find(|case| case.id == case_id && case.target == *target)
            .ok_or_else(|| not_found("working incident case for target", case_id))?;
        let expected = case_archive::working_record(incident)?;
        if expected.case_sha256 != expected_revision || incident.status != action.expected() {
            return Err(validation(
                "case status stale",
                "review the current case before changing status",
            ));
        }
        self.context.case_activity.lock().ensure_idle(case_id)?;
        ensure_timeline_capacity(incident)?;
        let event_id = generated_id(self.context.ids.as_ref(), "event")?;
        ensure_unique_id(
            incident.timeline.iter().map(|event| event.id.as_str()),
            &event_id,
        )?;
        let was_current = document
            .active_case_by_target
            .get(target.as_str())
            .is_some_and(|id| id == case_id);
        let impact = match action {
            CaseStatusAction::Close if was_current => {
                "保存结案记录后停止向此案新增内容，并清除当前采集归属；之后开始的采集可另建案件。结案是调查记录，不证明主机已修复或恢复安全。"
            }
            CaseStatusAction::Close => {
                "保存结案记录后停止向此案新增内容，保留原证据和其他案件的采集归属。结案是调查记录，不证明主机已修复或恢复安全。"
            }
            CaseStatusAction::Reopen => {
                "保留原有结案记录，新增重新调查记录后允许继续记录；不自动设为当前采集案件。原归档版本不改变。"
            }
        };
        let mut operation = OperationPlan::new(
            self.context.local_guard.clone(),
            format!(
                "{}“{}”：保留 {} 条证据、{} 条线索、{} 条时间线。{}",
                if action == CaseStatusAction::Close {
                    "结案"
                } else {
                    "重新调查案件"
                },
                incident.title,
                incident.evidence.len(),
                incident.iocs.len(),
                incident.timeline.len(),
                impact
            ),
            true,
            None,
        )?;
        operation.metadata.insert("case-id".into(), case_id.into());
        operation
            .metadata
            .insert("case-revision".into(), expected_revision.into());
        // The operation journal gets a commitment, not a second plaintext copy
        // of potentially sensitive investigation conclusions.
        let content = serde_json::to_vec(&(action, &conclusion, &followup)).map_err(|e| {
            CoreError::Encode {
                subject: "case status content",
                source: e,
            }
        })?;
        operation.metadata.insert(
            "case-disposition-sha256".into(),
            format!("{:x}", Sha256::digest(content)),
        );
        let plan = CaseStatusPlan {
            operation,
            expected,
            action,
            conclusion,
            followup,
            event_id,
            was_current,
        };
        // The standard confirmation dialog has an 8 KiB limit. Reserve room for
        // its expiry/interaction explanation instead of truncating the review.
        if plan.review_text().len() > 7 * 1024 {
            return Err(validation(
                "case status review",
                "shorten the conclusion or follow-up so the complete review fits",
            ));
        }
        Ok(plan)
    }

    pub async fn execute_case_status(
        &self,
        plan: CaseStatusPlan,
        confirmation: DangerousConfirmation,
        journal: &dyn OperationJournal,
    ) -> CoreResult<InvestigationOperationOutcome> {
        let operation_id = plan.operation.id.clone();
        let executor = CaseStatusExecutor {
            repository: self.clone(),
            plan: plan.clone(),
            expected_after: Mutex::new(None),
        };
        let verification = run_local_destructive_operation(
            self.context.as_ref(),
            plan.operation,
            confirmation,
            &executor,
            journal,
        )
        .await?;
        Ok(InvestigationOperationOutcome {
            operation_id,
            affected_records: 1,
            verification,
        })
    }

    fn apply_case_status(&self, plan: &CaseStatusPlan) -> CoreResult<String> {
        let _transaction = self.context.transaction.lock();
        self.context
            .case_activity
            .lock()
            .ensure_idle(plan.case_id())?;
        let mut document = load_cases(&self.context.store)?;
        let incident = document
            .cases
            .iter_mut()
            .find(|case| case.id == plan.expected.case_id && case.target == plan.expected.target)
            .ok_or_else(|| not_found("working incident case for target", plan.case_id()))?;
        if case_archive::working_record(incident)? != plan.expected
            || incident.status != plan.action.expected()
        {
            return Err(validation(
                "case status stale",
                "the reviewed case has changed",
            ));
        }
        let current = document
            .active_case_by_target
            .get(plan.target().as_str())
            .is_some_and(|id| id == plan.case_id());
        if current != plan.was_current {
            return Err(validation(
                "case status stale",
                "the current collection case has changed",
            ));
        }
        ensure_timeline_capacity(incident)?;
        ensure_unique_id(
            incident.timeline.iter().map(|event| event.id.as_str()),
            &plan.event_id,
        )?;
        let now = valid_now(self.context.clock.as_ref())?;
        incident.status = plan.action.resulting();
        incident.updated_at = now;
        incident.timeline.insert(
            0,
            CaseTimelineEvent {
                id: plan.event_id.clone(),
                event_type: TimelineEventType::Action,
                title: if plan.action == CaseStatusAction::Close {
                    "结案记录"
                } else {
                    "重新调查"
                }
                .into(),
                detail: Some(format!(
                    "{}：{}\n\n{}：{}\n\n本记录为人工调查判断，不代表主机已通过修复或安全复核。",
                    if plan.action == CaseStatusAction::Close {
                        "调查结论"
                    } else {
                        "重新调查原因"
                    },
                    plan.conclusion,
                    if plan.action == CaseStatusAction::Close {
                        "尚待处理事项"
                    } else {
                        "后续调查计划"
                    },
                    plan.followup
                )),
                source: "case-disposition".into(),
                timestamp: now,
                target: plan.target().clone(),
                evidence_id: None,
                ioc_id: None,
                operation_id: Some(plan.operation.id.clone()),
            },
        );
        let revision = case_archive::case_revision(incident)?;
        if plan.action == CaseStatusAction::Close && current {
            document
                .active_case_by_target
                .remove(plan.target().as_str());
        }
        write_cases(&self.context.store, &document)?;
        Ok(revision)
    }

    /// Compatibility for existing core callers; the UI always supplies an
    /// explicit conclusion and follow-up via `plan_case_status`.
    pub fn plan_close(&self, target: &TargetIdentity, case_id: &str) -> CoreResult<CaseStatusPlan> {
        let case = self
            .case_for_target(target, case_id)?
            .ok_or_else(|| not_found("incident case for target", case_id))?;
        self.plan_case_status(
            target,
            case_id,
            &case_archive::case_revision(&case)?,
            CaseStatusAction::Close,
            "未提供调查结论（兼容调用）".into(),
            "未提供后续事项，需人工核对。".into(),
        )
    }
    pub async fn execute_close(
        &self,
        plan: CaseStatusPlan,
        confirmation: DangerousConfirmation,
        journal: &dyn OperationJournal,
    ) -> CoreResult<InvestigationOperationOutcome> {
        if plan.action != CaseStatusAction::Close {
            return Err(validation("case close plan", "not a close operation"));
        }
        self.execute_case_status(plan, confirmation, journal).await
    }
    #[cfg(test)]
    pub(super) fn close_case(
        &self,
        target: &TargetIdentity,
        case_id: &str,
    ) -> CoreResult<IncidentCase> {
        let plan = self.plan_close(target, case_id)?;
        self.apply_case_status(&plan)?;
        self.case_for_target(target, case_id)?
            .ok_or_else(|| not_found("incident case for target", case_id))
    }
    #[cfg(test)]
    pub(super) fn close_open_for_operation(
        &self,
        target: &TargetIdentity,
        case_id: &str,
    ) -> CoreResult<IncidentCase> {
        self.close_case(target, case_id)
    }
}

#[derive(Debug)]
struct CaseStatusExecutor {
    repository: IncidentCaseRepository,
    plan: CaseStatusPlan,
    expected_after: Mutex<Option<String>>,
}
#[async_trait]
impl OperationExecutor for CaseStatusExecutor {
    async fn execute(&self, _plan: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        let revision = self.repository.apply_case_status(&self.plan)?;
        *self.expected_after.lock() = Some(revision);
        Ok(ExecutionReceipt {
            summary: "recorded one local case disposition".into(),
            restore_token: None,
        })
    }
    async fn verify(
        &self,
        _plan: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        let _transaction = self.repository.context.transaction.lock();
        let document = load_cases(&self.repository.context.store)?;
        let case = document.cases.iter().find(|case| {
            case.id == self.plan.expected.case_id && case.target == self.plan.expected.target
        });
        let passed = match case {
            Some(case) => {
                Some(case_archive::case_revision(case)?) == *self.expected_after.lock()
                    && document
                        .active_case_by_target
                        .get(self.plan.target().as_str())
                        .is_none_or(|id| id != self.plan.case_id())
            }
            None => false,
        };
        Ok(VerificationResult {
            passed,
            detail: if passed {
                "已回读核对案件状态、完整记录与调查结论；此结果不代表远端主机安全。"
            } else {
                "案件在写入后发生变化，未能核对完整状态；请刷新检查。"
            }
            .into(),
        })
    }
    async fn restore(&self, _plan: &OperationPlan, _receipt: &ExecutionReceipt) -> CoreResult<()> {
        Err(CoreError::Unsupported {
            feature: "automatic case disposition rollback; use a newly reviewed status plan",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operations::PortableOperationJournal;
    struct Root(std::path::PathBuf);
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn fixture() -> (
        Root,
        PortableStore,
        InvestigationRepositories,
        TargetIdentity,
        IncidentCase,
    ) {
        let root =
            Root(std::env::temp_dir().join(format!("lovelyres-case-status-{}", Uuid::new_v4())));
        std::fs::create_dir_all(&root.0).unwrap();
        let store = PortableStore::prepare(root.0.clone()).unwrap();
        let repos = InvestigationRepositories::new(store.clone());
        let target = TargetIdentity::new("lab-status-target").unwrap();
        let case = repos
            .cases()
            .create(&target, Some("调查 A".into()))
            .unwrap();
        (root, store, repos, target, case)
    }
    fn plan(
        repos: &InvestigationRepositories,
        case: &IncidentCase,
        action: CaseStatusAction,
    ) -> CaseStatusPlan {
        repos
            .cases()
            .plan_case_status(
                &case.target,
                &case.id,
                &case_archive::case_revision(case).unwrap(),
                action,
                "已核对证据 <script>literal</script>".into(),
                "仍需复核业务日志；不能证明主机安全。".into(),
            )
            .unwrap()
    }
    async fn execute(
        repos: &InvestigationRepositories,
        store: &PortableStore,
        plan: CaseStatusPlan,
    ) -> CoreResult<InvestigationOperationOutcome> {
        let confirmation = DangerousConfirmation::approve(plan.definition());
        repos
            .cases()
            .execute_case_status(
                plan,
                confirmation,
                &PortableOperationJournal::new(store.clone()),
            )
            .await
    }
    fn evidence() -> AddEvidence {
        AddEvidence {
            kind: EvidenceKind::Note,
            label: "new evidence".into(),
            source: "test".into(),
            preview: "unaltered".into(),
            locator: None,
            external_sha256: None,
        }
    }
    #[tokio::test]
    async fn close_and_reopen_preserve_evidence_conclusions_and_selection_without_claiming_safety()
    {
        let (_root, store, repos, target, case) = fixture();
        repos
            .cases()
            .add_evidence_to_case(&target, &case.id, evidence())
            .unwrap();
        let before = repos
            .cases()
            .case_for_target(&target, &case.id)
            .unwrap()
            .unwrap();
        let closing = plan(&repos, &before, CaseStatusAction::Close);
        let operation_id = closing.definition().id.clone();
        let retry = closing.clone();
        assert!(closing.review_text().contains("仍需复核业务日志"));
        assert!(
            execute(&repos, &store, closing)
                .await
                .unwrap()
                .verification
                .passed
        );
        let closed = repos
            .cases()
            .case_for_target(&target, &case.id)
            .unwrap()
            .unwrap();
        assert_eq!(closed.status, CaseStatus::Closed);
        assert_eq!(closed.evidence, before.evidence);
        assert_eq!(closed.iocs, before.iocs);
        assert_eq!(closed.timeline.len(), before.timeline.len() + 1);
        assert_eq!(
            closed.timeline[0].operation_id.as_ref(),
            Some(&operation_id)
        );
        assert!(
            closed.timeline[0]
                .detail
                .as_ref()
                .unwrap()
                .contains("<script>literal</script>")
        );
        assert!(repos.cases().active(&target).unwrap().is_none());
        assert!(execute(&repos, &store, retry).await.is_err());
        assert!(
            repos
                .cases()
                .add_evidence_to_case(&target, &case.id, evidence())
                .is_err()
        );
        let journal = std::fs::read_to_string(store.path_for(StoreFile::OperationJournal)).unwrap();
        assert!(!journal.contains("literal"));
        assert!(!journal.contains("仍需复核"));
        let current = repos
            .cases()
            .create(&target, Some("调查 B".into()))
            .unwrap();
        assert!(
            execute(
                &repos,
                &store,
                plan(&repos, &closed, CaseStatusAction::Reopen)
            )
            .await
            .unwrap()
            .verification
            .passed
        );
        let reopened = repos
            .cases()
            .case_for_target(&target, &case.id)
            .unwrap()
            .unwrap();
        assert_eq!(reopened.status, CaseStatus::Open);
        assert_eq!(&reopened.timeline[1..], closed.timeline.as_slice());
        assert_eq!(reopened.evidence, closed.evidence);
        assert_eq!(
            repos.cases().active(&target).unwrap().unwrap().id,
            current.id
        );
        repos
            .cases()
            .add_evidence_to_case(
                &target,
                &case.id,
                AddEvidence {
                    label: "after reopen".into(),
                    ..evidence()
                },
            )
            .unwrap();
        assert_eq!(
            PortableOperationJournal::new(store)
                .entries()
                .unwrap()
                .len(),
            4
        );
    }
    #[tokio::test]
    async fn changed_content_selection_or_collection_blocks_the_reviewed_close() {
        let (_root, store, repos, target, case) = fixture();
        let closing = plan(&repos, &case, CaseStatusAction::Close);
        let separate = InvestigationRepositories::new(store.clone());
        let reserved = separate
            .cases()
            .reserve_collection(&target, &case.id)
            .unwrap();
        let before = std::fs::read(store.path_for(StoreFile::Cases)).unwrap();
        assert!(execute(&repos, &store, closing).await.is_err());
        assert_eq!(
            std::fs::read(store.path_for(StoreFile::Cases)).unwrap(),
            before
        );
        drop(reserved);
        let closing = plan(&repos, &case, CaseStatusAction::Close);
        repos
            .cases()
            .add_evidence_to_case(&target, &case.id, evidence())
            .unwrap();
        assert!(execute(&repos, &store, closing).await.is_err());
        let changed = repos
            .cases()
            .case_for_target(&target, &case.id)
            .unwrap()
            .unwrap();
        let closing = plan(&repos, &changed, CaseStatusAction::Close);
        repos
            .cases()
            .create(&target, Some("new current".into()))
            .unwrap();
        assert!(execute(&repos, &store, closing).await.is_err());
        assert_eq!(
            repos
                .cases()
                .case_for_target(&target, &case.id)
                .unwrap()
                .unwrap()
                .status,
            CaseStatus::Open
        );
        assert!(
            PortableOperationJournal::new(store)
                .entries()
                .unwrap()
                .is_empty()
        );
    }
    #[tokio::test]
    async fn full_timeline_and_invalid_conclusions_preserve_the_complete_original_document() {
        let (_root, store, repos, target, case) = fixture();
        let revision = case_archive::case_revision(&case).unwrap();
        for (reason, followup) in [
            ("".into(), "none".into()),
            ("reason".into(), " ".into()),
            ("😀".repeat(1025), "none".into()),
            ("reason".into(), "😀".repeat(513)),
        ] {
            assert!(
                repos
                    .cases()
                    .plan_case_status(
                        &target,
                        &case.id,
                        &revision,
                        CaseStatusAction::Close,
                        reason,
                        followup
                    )
                    .is_err()
            );
        }
        assert!(
            repos
                .cases()
                .plan_case_status(
                    &TargetIdentity::new("other").unwrap(),
                    &case.id,
                    &revision,
                    CaseStatusAction::Close,
                    "reason".into(),
                    "none".into()
                )
                .is_err()
        );
        let mut document = load_cases(&store).unwrap();
        let event = case.timeline[0].clone();
        document.cases[0].timeline = (0..MAX_TIMELINE)
            .map(|i| CaseTimelineEvent {
                id: format!("history-{i}"),
                ..event.clone()
            })
            .collect();
        write_cases(&store, &document).unwrap();
        let before = std::fs::read(store.path_for(StoreFile::Cases)).unwrap();
        let result = repos.cases().plan_case_status(
            &target,
            &case.id,
            &case_archive::case_revision(&document.cases[0]).unwrap(),
            CaseStatusAction::Close,
            "reason".into(),
            "none".into(),
        );
        assert!(matches!(
            result,
            Err(CoreError::Validation {
                subject: "case timeline capacity",
                ..
            })
        ));
        assert_eq!(
            std::fs::read(store.path_for(StoreFile::Cases)).unwrap(),
            before
        );
    }
    #[tokio::test]
    async fn wrong_confirmation_cannot_close_and_archived_closed_history_survives_restore() {
        let (_root, store, repos, target, case) = fixture();
        let closing = plan(&repos, &case, CaseStatusAction::Close);
        let other = plan(&repos, &case, CaseStatusAction::Close);
        assert!(
            repos
                .cases()
                .execute_case_status(
                    closing,
                    DangerousConfirmation::approve(other.definition()),
                    &PortableOperationJournal::new(store.clone())
                )
                .await
                .is_err()
        );
        assert!(
            execute(&repos, &store, other)
                .await
                .unwrap()
                .verification
                .passed
        );
        let closed = repos
            .cases()
            .case_for_target(&target, &case.id)
            .unwrap()
            .unwrap();
        let record = repos.cases().library().unwrap().remove(0);
        let archiving = repos
            .cases()
            .plan_archive(&record.key, &record.case_sha256, true)
            .unwrap();
        let confirmation = DangerousConfirmation::approve(archiving.definition());
        repos
            .cases()
            .execute_archive_plan(
                archiving,
                confirmation,
                &PortableOperationJournal::new(store.clone()),
            )
            .await
            .unwrap();
        assert!(
            repos
                .cases()
                .plan_case_status(
                    &target,
                    &case.id,
                    &record.case_sha256,
                    CaseStatusAction::Reopen,
                    "reason".into(),
                    "plan".into()
                )
                .is_err()
        );
        let record = repos.cases().library().unwrap().remove(0);
        let restoring = repos
            .cases()
            .plan_archive(&record.key, &record.case_sha256, false)
            .unwrap();
        let confirmation = DangerousConfirmation::approve(restoring.definition());
        repos
            .cases()
            .execute_archive_plan(
                restoring,
                confirmation,
                &PortableOperationJournal::new(store),
            )
            .await
            .unwrap();
        assert_eq!(
            repos
                .cases()
                .case_for_target(&target, &case.id)
                .unwrap()
                .unwrap(),
            closed
        );
        assert!(repos.cases().active(&target).unwrap().is_none());
    }
}
