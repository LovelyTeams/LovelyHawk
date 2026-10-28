//! Offline access is limited to locally indexed cases. Renderer inputs never
//! carry target authority, archive filenames, evidence contents or destinations.
use crate::case_workspace_api::{self, CaseSection, CaseSummary, CaseWorkspaceResult};
use lovelyhawk_core::{
    BackendServices, CoreError,
    investigation::{
        CaseArchivePlan, CaseLibraryLocation, CaseLibraryRecord, CaseLibrarySnapshot,
        CaseStatusAction, CaseStatusPlan, MAX_CASE_CONCLUSION_CHARS, MAX_CASE_EXPORT_BYTES,
        MAX_CASE_FOLLOWUP_CHARS,
    },
    operations::DangerousConfirmation,
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use uuid::Uuid;

const TTL: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Transfer {
    Archive,
    Restore,
    Close,
    Reopen,
}

#[derive(Deserialize)]
#[serde(
    tag = "action",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum CaseLibraryRequest {
    List {},
    View {
        item_handle: String,
    },
    Items {
        snapshot_handle: String,
        section: CaseSection,
        query: String,
        offset: usize,
    },
    Plan {
        snapshot_handle: String,
        operation: Transfer,
    },
    StatusPlan {
        snapshot_handle: String,
        operation: CaseStatusAction,
        conclusion: String,
        followup: String,
    },
    Confirm {
        plan_handle: String,
    },
    Cancel {
        plan_handle: String,
    },
    Export {
        snapshot_handle: String,
        selected_destination: String,
    },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LibraryItem {
    item_handle: String,
    incident: CaseSummary,
    target_id: String,
    connection_name: Option<String>,
    location: CaseLibraryLocation,
    archived_at: Option<i64>,
}

#[derive(Debug, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub(crate) enum CaseLibraryResult {
    List {
        items: Vec<LibraryItem>,
        working_count: usize,
        archive_count: usize,
    },
    View {
        snapshot_handle: String,
        item: LibraryItem,
    },
    Plan {
        snapshot_handle: String,
        plan_handle: String,
        operation: Transfer,
        summary: String,
        expires_in_seconds: u64,
    },
    Changed {
        plan_handle: String,
        operation: Transfer,
        case_id: String,
        verified: bool,
        message: &'static str,
    },
    Cancelled {
        plan_handle: String,
    },
    Exported {
        snapshot_handle: String,
        filename: String,
        bytes: u64,
        sha256: String,
    },
}

struct Pending {
    plan: PendingPlan,
    expires: Instant,
}
enum PendingPlan {
    Archive(CaseArchivePlan),
    Status(CaseStatusPlan),
}
impl PendingPlan {
    fn operation(&self) -> Transfer {
        match self {
            Self::Archive(plan) => {
                if plan.is_archiving() {
                    Transfer::Archive
                } else {
                    Transfer::Restore
                }
            }
            Self::Status(plan) => {
                if plan.action() == CaseStatusAction::Close {
                    Transfer::Close
                } else {
                    Transfer::Reopen
                }
            }
        }
    }
    fn case_id(&self) -> &str {
        match self {
            Self::Archive(plan) => &plan.record().case_id,
            Self::Status(plan) => plan.case_id(),
        }
    }
}
struct Snapshot {
    value: Arc<CaseLibrarySnapshot>,
    handle: String,
    expires: Instant,
}
#[derive(Default)]
struct State {
    items: HashMap<String, CaseLibraryRecord>,
    items_expires: Option<Instant>,
    snapshot: Option<Snapshot>,
    plans: HashMap<String, Pending>,
}
impl State {
    fn prune(&mut self) {
        let now = Instant::now();
        if self.items_expires.is_some_and(|expiry| expiry <= now) {
            self.items.clear();
            self.items_expires = None;
        }
        if self
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.expires <= now)
        {
            self.snapshot = None;
        }
        self.plans.retain(|_, pending| pending.expires > now);
    }
}
pub(crate) struct CaseLibraryApi {
    services: BackendServices,
    state: Mutex<State>,
}
impl std::fmt::Debug for CaseLibraryApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaseLibraryApi").finish_non_exhaustive()
    }
}
#[derive(Debug)]
pub(crate) enum CaseLibraryError {
    Invalid,
    Stale,
    Busy,
    Capacity,
    Conflict,
    TimelineCapacity,
    Conclusion,
    Unavailable,
}
impl From<CoreError> for CaseLibraryError {
    fn from(error: CoreError) -> Self {
        match error {
            CoreError::Validation {
                subject: "case archive stale" | "case status stale",
                ..
            } => Self::Stale,
            CoreError::Validation {
                subject: "case activity",
                ..
            } => Self::Busy,
            CoreError::Validation {
                subject:
                    "case archive capacity" | "case capacity" | "store write size" | "case archive size",
                ..
            } => Self::Capacity,
            CoreError::Validation {
                subject: "case archive conflict",
                ..
            } => Self::Conflict,
            CoreError::Validation {
                subject: "case timeline capacity",
                ..
            } => Self::TimelineCapacity,
            CoreError::Validation {
                subject: "case conclusion" | "case followup" | "case status review",
                ..
            } => Self::Conclusion,
            _ => Self::Unavailable,
        }
    }
}
impl CaseLibraryApi {
    pub(crate) fn new(services: BackendServices) -> Self {
        Self {
            services,
            state: Mutex::new(State::default()),
        }
    }
    fn snapshot(&self, handle: &str) -> Result<Arc<CaseLibrarySnapshot>, CaseLibraryError> {
        let mut state = self.state.lock();
        state.prune();
        state
            .snapshot
            .as_ref()
            .filter(|snapshot| snapshot.handle == handle)
            .map(|snapshot| Arc::clone(&snapshot.value))
            .ok_or(CaseLibraryError::Stale)
    }
    fn save_plan(
        &self,
        snapshot_handle: String,
        plan: PendingPlan,
        summary: String,
    ) -> Result<CaseLibraryResult, CaseLibraryError> {
        let operation = plan.operation();
        let plan_handle = Uuid::new_v4().to_string();
        let mut state = self.state.lock();
        state.prune();
        if state
            .snapshot
            .as_ref()
            .is_none_or(|current| current.handle != snapshot_handle)
        {
            return Err(CaseLibraryError::Stale);
        }
        state.plans.clear();
        state.plans.insert(
            plan_handle.clone(),
            Pending {
                plan,
                expires: Instant::now() + TTL,
            },
        );
        Ok(CaseLibraryResult::Plan {
            snapshot_handle,
            plan_handle,
            operation,
            summary,
            expires_in_seconds: TTL.as_secs(),
        })
    }
    pub(crate) async fn dispatch(
        &self,
        request: CaseLibraryRequest,
    ) -> Result<serde_json::Value, CaseLibraryError> {
        request.validate()?;
        let cases = self.services.investigation().cases();
        let result = match request {
            CaseLibraryRequest::List {} => {
                let records = cases.library()?;
                // Current connection labels are only navigation aids. Original
                // provenance remains in each evidence record and its manifest.
                let names: HashMap<_, _> = self
                    .services
                    .connections()
                    .list()
                    .unwrap_or_else(|_| {
                        tracing::warn!("Case library could not read current connection labels");
                        Vec::new()
                    })
                    .into_iter()
                    .map(|connection| (connection.config.id, connection.config.name))
                    .collect();
                let working_count = records
                    .iter()
                    .filter(|record| record.location == CaseLibraryLocation::Working)
                    .count();
                let archive_count = records.len() - working_count;
                let mut state = self.state.lock();
                state.prune();
                state.items.clear();
                let mut items = Vec::with_capacity(records.len());
                for record in records {
                    let handle = Uuid::new_v4().to_string();
                    items.push(item(
                        &record,
                        handle.clone(),
                        names.get(record.target.as_str()).cloned(),
                    ));
                    state.items.insert(handle, record);
                }
                state.items_expires = Some(Instant::now() + TTL);
                CaseLibraryResult::List {
                    items,
                    working_count,
                    archive_count,
                }
            }
            CaseLibraryRequest::View { item_handle } => {
                let mut state = self.state.lock();
                state.prune();
                let record = state
                    .items
                    .get(&item_handle)
                    .ok_or(CaseLibraryError::Stale)?;
                let value = cases.library_open(&record.key)?;
                // A click on a stale inventory cannot silently open a different revision.
                if &value.record != record {
                    return Err(CaseLibraryError::Stale);
                }
                if serde_json::to_vec(&value.export)
                    .map_err(|_| CaseLibraryError::Unavailable)?
                    .len()
                    > MAX_CASE_EXPORT_BYTES
                {
                    return Err(CaseLibraryError::Capacity);
                }
                let handle = Uuid::new_v4().to_string();
                let result = CaseLibraryResult::View {
                    snapshot_handle: handle.clone(),
                    item: item(
                        &value.record,
                        item_handle,
                        self.services
                            .connections()
                            .get(value.record.target.as_str())
                            .inspect_err(|_| {
                                tracing::warn!(
                                    "Case library could not read the current connection label"
                                );
                            })
                            .ok()
                            .flatten()
                            .map(|connection| connection.config.name),
                    ),
                };
                state.snapshot = Some(Snapshot {
                    value: Arc::new(value),
                    handle,
                    expires: Instant::now() + TTL,
                });
                state.plans.clear();
                result
            }
            CaseLibraryRequest::Items {
                snapshot_handle,
                section,
                query,
                offset,
            } => {
                let snapshot = self.snapshot(&snapshot_handle)?;
                let result: CaseWorkspaceResult = case_workspace_api::page(
                    &snapshot.export.incident_case,
                    snapshot_handle,
                    section,
                    query,
                    offset,
                );
                return serde_json::to_value(result).map_err(|_| CaseLibraryError::Unavailable);
            }
            CaseLibraryRequest::Plan {
                snapshot_handle,
                operation,
            } => {
                let snapshot = self.snapshot(&snapshot_handle)?;
                let plan = cases.plan_archive(
                    &snapshot.record.key,
                    &snapshot.record.case_sha256,
                    operation == Transfer::Archive,
                )?;
                let summary = plan.definition().summary.clone();
                self.save_plan(snapshot_handle, PendingPlan::Archive(plan), summary)?
            }
            CaseLibraryRequest::StatusPlan {
                snapshot_handle,
                operation,
                conclusion,
                followup,
            } => {
                let snapshot = self.snapshot(&snapshot_handle)?;
                if snapshot.record.location != CaseLibraryLocation::Working {
                    return Err(CaseLibraryError::Invalid);
                }
                let plan = cases.plan_case_status(
                    &snapshot.record.target,
                    &snapshot.record.case_id,
                    &snapshot.record.case_sha256,
                    operation,
                    conclusion,
                    followup,
                )?;
                let summary = plan.review_text();
                self.save_plan(snapshot_handle, PendingPlan::Status(plan), summary)?
            }
            CaseLibraryRequest::Confirm { plan_handle } => {
                let pending = {
                    let mut state = self.state.lock();
                    state.prune();
                    state
                        .plans
                        .remove(&plan_handle)
                        .ok_or(CaseLibraryError::Stale)?
                };
                let operation = pending.plan.operation();
                let case_id = pending.plan.case_id().to_owned();
                let outcome = match pending.plan {
                    PendingPlan::Archive(plan) => {
                        let confirmation = DangerousConfirmation::approve(plan.definition());
                        cases
                            .execute_archive_plan(
                                plan,
                                confirmation,
                                self.services.operation_journal(),
                            )
                            .await?
                    }
                    PendingPlan::Status(plan) => {
                        let confirmation = DangerousConfirmation::approve(plan.definition());
                        cases
                            .execute_case_status(
                                plan,
                                confirmation,
                                self.services.operation_journal(),
                            )
                            .await?
                    }
                };
                let verified = outcome.verification.passed;
                let mut state = self.state.lock();
                state.items.clear();
                state.snapshot = None;
                state.plans.clear();
                CaseLibraryResult::Changed {
                    plan_handle,
                    operation,
                    case_id,
                    verified,
                    message: if !verified {
                        "操作后的核对未通过，请刷新案件库确认实际状态；不要重复执行旧计划。"
                    } else if operation == Transfer::Archive {
                        "案件已完整归档并通过核对，活动列表已释放一个名额。原始留证文件仍在原位置。"
                    } else {
                        match operation {
                            Transfer::Archive => "案件已归档并通过核对。",
                            Transfer::Restore => {
                                "案件已恢复并通过核对。保留原归档版本，当前采集归属未改变。"
                            }
                            Transfer::Close => {
                                "结案记录与案件状态已保存并通过核对。原证据保留；结案不代表主机已恢复安全。"
                            }
                            Transfer::Reopen => {
                                "案件已重新打开调查，原结案记录完整保留。当前采集归属未改变。"
                            }
                        }
                    },
                }
            }
            CaseLibraryRequest::Cancel { plan_handle } => {
                let mut state = self.state.lock();
                state.prune();
                state.plans.remove(&plan_handle);
                CaseLibraryResult::Cancelled { plan_handle }
            }
            CaseLibraryRequest::Export {
                snapshot_handle,
                selected_destination,
            } => {
                let snapshot = self.snapshot(&snapshot_handle)?;
                let (filename, bytes, sha256) =
                    cases.export_library_snapshot(&snapshot, Path::new(&selected_destination))?;
                CaseLibraryResult::Exported {
                    snapshot_handle,
                    filename,
                    bytes,
                    sha256,
                }
            }
        };
        serde_json::to_value(result).map_err(|_| CaseLibraryError::Unavailable)
    }
}

fn item(
    record: &CaseLibraryRecord,
    item_handle: String,
    connection_name: Option<String>,
) -> LibraryItem {
    LibraryItem {
        item_handle,
        incident: CaseSummary::from(record),
        target_id: record.target.as_str().to_owned(),
        connection_name,
        location: record.location,
        archived_at: record.archived_at,
    }
}
impl CaseLibraryRequest {
    fn validate(&self) -> Result<(), CaseLibraryError> {
        let valid = match self {
            Self::List {} => true,
            Self::View { item_handle } => handle(item_handle),
            Self::Items {
                snapshot_handle,
                query,
                offset,
                ..
            } => handle(snapshot_handle) && query.chars().count() <= 256 && *offset <= 1000,
            Self::Plan {
                snapshot_handle,
                operation,
            } => {
                handle(snapshot_handle)
                    && matches!(operation, Transfer::Archive | Transfer::Restore)
            }
            Self::StatusPlan {
                snapshot_handle,
                conclusion,
                followup,
                ..
            } => {
                handle(snapshot_handle)
                    && !conclusion.trim().is_empty()
                    && conclusion.chars().count() <= MAX_CASE_CONCLUSION_CHARS
                    && !followup.trim().is_empty()
                    && followup.chars().count() <= MAX_CASE_FOLLOWUP_CHARS
            }
            Self::Confirm { plan_handle } | Self::Cancel { plan_handle } => handle(plan_handle),
            Self::Export {
                snapshot_handle,
                selected_destination,
            } => {
                handle(snapshot_handle)
                    && selected_destination.len() <= 32_768
                    && !selected_destination.contains('\0')
                    && Path::new(selected_destination).is_absolute()
            }
        };
        if valid {
            Ok(())
        } else {
            Err(CaseLibraryError::Invalid)
        }
    }
}
fn handle(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lovelyhawk_core::{
        PortableStore,
        investigation::{AddEvidence, EvidenceKind},
        target::TargetIdentity,
    };
    use serde_json::{Value, json};
    struct Root(std::path::PathBuf);
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn fixture() -> (Root, BackendServices, CaseLibraryApi, TargetIdentity) {
        let root =
            Root(std::env::temp_dir().join(format!("lovelyres-case-library-{}", Uuid::new_v4())));
        std::fs::create_dir_all(&root.0).unwrap();
        let services = BackendServices::with_runtime(
            PortableStore::prepare(root.0.clone()).unwrap(),
            tokio::runtime::Handle::current(),
        )
        .unwrap();
        let api = CaseLibraryApi::new(services.clone());
        (
            root,
            services,
            api,
            TargetIdentity::new("saved-host-identity").unwrap(),
        )
    }
    async fn call(api: &CaseLibraryApi, request: Value) -> Value {
        api.dispatch(serde_json::from_value(request).unwrap())
            .await
            .unwrap()
    }
    fn evidence(label: &str) -> AddEvidence {
        AddEvidence {
            kind: EvidenceKind::Note,
            label: label.into(),
            source: "lab-original".into(),
            preview: "<script>literal</script>".into(),
            locator: Some("original-source-marker".into()),
            external_sha256: None,
        }
    }
    async fn view(api: &CaseLibraryApi, location: &str) -> Value {
        let list = call(api, json!({"action":"list"})).await;
        let item = list["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["location"] == location)
            .unwrap();
        call(
            api,
            json!({"action":"view", "itemHandle":item["itemHandle"]}),
        )
        .await
    }
    #[tokio::test]
    async fn offline_snapshot_pages_export_archive_restore_and_journal_roundtrip() {
        let (root, services, api, target) = fixture();
        let cases = services.investigation().cases();
        let first = cases
            .create(&target, Some("保全 <img src=x>".into()))
            .unwrap();
        for i in 0..31 {
            cases
                .add_evidence_to_case(&target, &first.id, evidence(&format!("record-{i}")))
                .unwrap();
        }
        let opened = view(&api, "working").await;
        let snapshot = &opened["snapshotHandle"];
        let page = call(&api, json!({"action":"items", "snapshotHandle":snapshot,"section":"evidence","query":"","offset":25})).await;
        assert_eq!(page["total"], 31);
        assert_eq!(page["items"].as_array().unwrap().len(), 6);
        assert_eq!(page["items"][0]["text"], "<script>literal</script>");
        cases
            .add_evidence_to_case(&target, &first.id, evidence("later"))
            .unwrap();
        let export_path = root.0.join("full-case.json");
        let exported = call(
            &api,
            json!({"action":"export","snapshotHandle":snapshot,"selectedDestination":export_path}),
        )
        .await;
        assert_eq!(exported["filename"], "full-case.json");
        assert!(!exported.to_string().contains(root.0.to_str().unwrap()));
        let raw: Value = serde_json::from_slice(&std::fs::read(&export_path).unwrap()).unwrap();
        assert_eq!(
            raw["incident_case"]["evidence"].as_array().unwrap().len(),
            31
        );
        assert!(matches!(
            api.dispatch(
                serde_json::from_value(
                    json!({"action":"plan","snapshotHandle":snapshot,"operation":"archive"})
                )
                .unwrap()
            )
            .await,
            Err(CaseLibraryError::Stale)
        ));
        let opened = view(&api, "working").await;
        let plan = call(&api,json!({"action":"plan","snapshotHandle":opened["snapshotHandle"],"operation":"archive"})).await;
        assert!(plan["summary"].as_str().unwrap().contains("32 条证据"));
        let archived = call(
            &api,
            json!({"action":"confirm","planHandle":plan["planHandle"]}),
        )
        .await;
        assert_eq!(archived["verified"], true);
        assert!(
            api.dispatch(
                serde_json::from_value(json!({"action":"confirm","planHandle":plan["planHandle"]}))
                    .unwrap()
            )
            .await
            .is_err()
        );
        assert!(cases.active(&target).unwrap().is_none());
        let other = cases
            .create(&target, Some("正在调查的另案".into()))
            .unwrap();
        let reopened = CaseLibraryApi::new(services.clone());
        let archived = view(&reopened, "archived").await;
        assert_eq!(archived["item"]["incident"]["evidenceCount"], 32);
        let plan = call(&reopened,json!({"action":"plan","snapshotHandle":archived["snapshotHandle"],"operation":"restore"})).await;
        let restored = call(
            &reopened,
            json!({"action":"confirm","planHandle":plan["planHandle"]}),
        )
        .await;
        assert_eq!(restored["verified"], true);
        assert_eq!(cases.active(&target).unwrap().unwrap().id, other.id);
        let list = call(&reopened, json!({"action":"list"})).await;
        assert_eq!(list["workingCount"], 2);
        assert_eq!(list["archiveCount"], 1);
        assert_eq!(services.operation_journal().entries().unwrap().len(), 4);
    }
    #[tokio::test]
    async fn exact_requests_expiration_and_replaced_views_revoke_authority() {
        let (_root, services, api, target) = fixture();
        services
            .investigation()
            .cases()
            .create(&target, Some("a".into()))
            .unwrap();
        for bad in [
            json!({"action":"list","target":"injected"}),
            json!({"action":"archive","path":"file"}),
            json!({"action":"view","itemHandle":"x","caseId":"x"}),
            json!({"action":"export","snapshotHandle":"s"}),
            json!({"action":"confirm","planHandle":"p","confirmed":true}),
        ] {
            assert!(serde_json::from_value::<CaseLibraryRequest>(bad).is_err());
        }
        let first = view(&api, "working").await;
        let plan = call(
            &api,
            json!({"action":"plan","snapshotHandle":first["snapshotHandle"],"operation":"archive"}),
        )
        .await;
        let _second = view(&api, "working").await;
        for request in [
            json!({"action":"items","snapshotHandle":first["snapshotHandle"],"section":"evidence","offset":0,"query":""}),
            json!({"action":"confirm","planHandle":plan["planHandle"]}),
        ] {
            assert!(matches!(
                api.dispatch(serde_json::from_value(request).unwrap()).await,
                Err(CaseLibraryError::Stale)
            ));
        }
        let opened = view(&api, "working").await;
        let plan = call(&api,json!({"action":"plan","snapshotHandle":opened["snapshotHandle"],"operation":"archive"})).await;
        api.state
            .lock()
            .plans
            .values_mut()
            .for_each(|plan| plan.expires = Instant::now() - Duration::from_secs(1));
        assert!(matches!(
            api.dispatch(
                serde_json::from_value(json!({"action":"confirm","planHandle":plan["planHandle"]}))
                    .unwrap()
            )
            .await,
            Err(CaseLibraryError::Stale)
        ));
        assert!(services.operation_journal().entries().unwrap().is_empty());
        assert_eq!(api.state.lock().plans.len(), 0);
        assert!(api.state.lock().snapshot.is_some());
    }
    #[tokio::test]
    async fn cancellation_and_live_collection_keep_all_working_records() {
        let (_root, services, api, target) = fixture();
        let cases = services.investigation().cases();
        let case = cases.create(&target, Some("capture".into())).unwrap();
        let opened = view(&api, "working").await;
        let plan = call(&api,json!({"action":"plan","snapshotHandle":opened["snapshotHandle"],"operation":"archive"})).await;
        call(
            &api,
            json!({"action":"cancel","planHandle":plan["planHandle"]}),
        )
        .await;
        assert!(
            api.dispatch(
                serde_json::from_value(json!({"action":"confirm","planHandle":plan["planHandle"]}))
                    .unwrap()
            )
            .await
            .is_err()
        );
        let _reservation = cases.reserve_collection(&target, &case.id).unwrap();
        assert!(matches!(api.dispatch(serde_json::from_value(json!({"action":"plan","snapshotHandle":opened["snapshotHandle"],"operation":"archive"})).unwrap()).await,Err(CaseLibraryError::Busy)));
        assert_eq!(cases.library().unwrap().len(), 1);
        assert_eq!(cases.active(&target).unwrap().unwrap().id, case.id);
    }
    #[tokio::test]
    async fn status_plans_require_complete_current_records_and_preserve_the_reviewed_conclusion() {
        let (_root, services, api, target) = fixture();
        let cases = services.investigation().cases();
        let case = cases.create(&target, Some("closure".into())).unwrap();
        let opened = view(&api, "working").await;
        for invalid in [
            json!({"action":"plan","snapshotHandle":opened["snapshotHandle"],"operation":"close"}),
            json!({"action":"status-plan","snapshotHandle":opened["snapshotHandle"],"operation":"close","conclusion":"","followup":"无"}),
        ] {
            assert!(matches!(
                api.dispatch(serde_json::from_value(invalid).unwrap()).await,
                Err(CaseLibraryError::Invalid)
            ));
        }
        let review = call(&api,json!({"action":"status-plan","snapshotHandle":opened["snapshotHandle"],"operation":"close","conclusion":"结论 <script>literal</script>","followup":"仍需复核日志"})).await;
        assert!(review["summary"].as_str().unwrap().contains("仍需复核日志"));
        let reservation = cases.reserve_collection(&target, &case.id).unwrap();
        assert!(matches!(
            api.dispatch(
                serde_json::from_value(
                    json!({"action":"confirm","planHandle":review["planHandle"]})
                )
                .unwrap()
            )
            .await,
            Err(CaseLibraryError::Busy)
        ));
        drop(reservation);
        assert_eq!(
            cases
                .export(&target, &case.id)
                .unwrap()
                .incident_case
                .status,
            lovelyhawk_core::investigation::CaseStatus::Open
        );
        assert!(
            api.dispatch(
                serde_json::from_value(
                    json!({"action":"confirm","planHandle":review["planHandle"]})
                )
                .unwrap()
            )
            .await
            .is_err()
        );
        let review = call(&api,json!({"action":"status-plan","snapshotHandle":opened["snapshotHandle"],"operation":"close","conclusion":"结论 <script>literal</script>","followup":"仍需复核日志"})).await;
        let changed = call(
            &api,
            json!({"action":"confirm","planHandle":review["planHandle"]}),
        )
        .await;
        assert_eq!(changed["operation"], "close");
        assert_eq!(changed["verified"], true);
        let opened = view(&api, "working").await;
        let timeline = call(&api,json!({"action":"items","snapshotHandle":opened["snapshotHandle"],"section":"timeline","offset":0,"query":"仍需复核日志"})).await;
        assert_eq!(timeline["total"], 1);
        assert!(
            timeline["items"][0]["text"]
                .as_str()
                .unwrap()
                .contains("<script>literal</script>")
        );
        let review = call(&api,json!({"action":"status-plan","snapshotHandle":opened["snapshotHandle"],"operation":"reopen","conclusion":"发现新证据","followup":"继续排查"})).await;
        let reopened = call(
            &api,
            json!({"action":"confirm","planHandle":review["planHandle"]}),
        )
        .await;
        assert_eq!(reopened["operation"], "reopen");
        assert_eq!(reopened["verified"], true);
        assert!(cases.active(&target).unwrap().is_none());
    }
    #[tokio::test]
    async fn archived_snapshots_cannot_authorize_a_status_change_even_when_an_identical_working_copy_exists()
     {
        let (_root, services, api, target) = fixture();
        let cases = services.investigation().cases();
        let case = cases
            .create(&target, Some("archive status".into()))
            .unwrap();
        let opened = view(&api, "working").await;
        let plan = call(&api,json!({"action":"plan","snapshotHandle":opened["snapshotHandle"],"operation":"archive"})).await;
        call(
            &api,
            json!({"action":"confirm","planHandle":plan["planHandle"]}),
        )
        .await;
        let archived = view(&api, "archived").await;
        let plan = call(&api,json!({"action":"plan","snapshotHandle":archived["snapshotHandle"],"operation":"restore"})).await;
        call(
            &api,
            json!({"action":"confirm","planHandle":plan["planHandle"]}),
        )
        .await;
        let archived = view(&api, "archived").await;
        assert!(matches!(api.dispatch(serde_json::from_value(json!({"action":"status-plan","snapshotHandle":archived["snapshotHandle"],"operation":"close","conclusion":"reason","followup":"todo"})).unwrap()).await,Err(CaseLibraryError::Invalid)));
        assert_eq!(
            cases
                .export(&target, &case.id)
                .unwrap()
                .incident_case
                .status,
            lovelyhawk_core::investigation::CaseStatus::Open
        );
    }
}
