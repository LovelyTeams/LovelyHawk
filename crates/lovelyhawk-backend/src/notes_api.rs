use std::{
    collections::HashMap,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use lovelyhawk_core::{
    BackendServices, CoreError,
    investigation::{
        CreateNote, InvestigationOperationOutcome, NOTES_SCHEMA_ID, Note, NoteDeletePlan,
        UpdateNote, note_revision,
    },
    operations::DangerousConfirmation,
};
use parking_lot::Mutex;
use serde::Serialize;
use uuid::Uuid;

const MAX_PAGE_SIZE: usize = 100;
const MAX_PAGE_OFFSET: usize = 100_000;
const MAX_PENDING_DELETES: usize = 64;
const DELETE_PLAN_TTL_SECONDS: u64 = 300;
const MAX_CLIPBOARD_EXPORT_BYTES: usize = 120 * 1024;
const CONTENT_PREVIEW_CHARS: usize = 240;

#[derive(Debug, Default)]
pub(crate) struct NotesApi {
    pending_deletes: Mutex<HashMap<String, PendingNoteDelete>>,
}

#[derive(Debug)]
struct PendingNoteDelete {
    created_at: Instant,
    plan: NoteDeletePlan,
}

#[derive(Debug)]
pub(crate) enum NotesApiError {
    Core(CoreError),
    InvalidPage,
    InvalidDeletePlan,
    DeletePlanCapacity,
    ExportTooLarge,
}

impl From<CoreError> for NotesApiError {
    fn from(error: CoreError) -> Self {
        Self::Core(error)
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NoteListPage {
    total: usize,
    offset: usize,
    has_more: bool,
    items: Vec<NoteSummary>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct NoteSummary {
    id: String,
    title: String,
    content_preview: String,
    content_truncated: bool,
    tags: Vec<String>,
    created_at: i64,
    updated_at: i64,
    pinned: bool,
    revision: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NoteResult {
    id: String,
    title: String,
    content: String,
    tags: Vec<String>,
    created_at: i64,
    updated_at: i64,
    pinned: bool,
    revision: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NoteDeleteProposal {
    handle: String,
    summary: String,
    expires_in_seconds: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NoteDeleteResult {
    note_id: String,
    affected_records: usize,
    verified: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NoteDeleteCancellation {
    cancelled: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NotesTextExport {
    note_count: usize,
    text: String,
}

impl NotesApi {
    pub(crate) fn list(
        &self,
        services: &BackendServices,
        query: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> Result<NoteListPage, NotesApiError> {
        if limit == 0 || limit > MAX_PAGE_SIZE || offset > MAX_PAGE_OFFSET {
            return Err(NotesApiError::InvalidPage);
        }
        let notes = match query.map(str::trim).filter(|query| !query.is_empty()) {
            Some(query) => services.investigation().notes().search(query)?,
            None => services.investigation().notes().list()?,
        };
        let total = notes.len();
        let items = notes
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(NoteSummary::from)
            .collect::<Vec<_>>();
        Ok(NoteListPage {
            total,
            offset,
            has_more: offset.saturating_add(items.len()) < total,
            items,
        })
    }

    pub(crate) fn get(
        &self,
        services: &BackendServices,
        id: &str,
    ) -> Result<NoteResult, NotesApiError> {
        let note =
            services
                .investigation()
                .notes()
                .get(id)?
                .ok_or_else(|| CoreError::NotFound {
                    entity: "note",
                    id: id.to_owned(),
                })?;
        Ok(note.into())
    }

    #[cfg(test)]
    pub(crate) fn create(
        &self,
        services: &BackendServices,
        title: Option<String>,
        content: String,
        tags: Vec<String>,
    ) -> Result<NoteResult, NotesApiError> {
        Ok(services
            .investigation()
            .notes()
            .create(CreateNote {
                title,
                content,
                tags,
            })?
            .into())
    }

    pub(crate) fn create_idempotent(
        &self,
        services: &BackendServices,
        mutation_id: &str,
        title: Option<String>,
        content: String,
        tags: Vec<String>,
    ) -> Result<NoteResult, NotesApiError> {
        Ok(services
            .investigation()
            .notes()
            .create_idempotent(
                CreateNote {
                    title,
                    content,
                    tags,
                },
                mutation_id,
            )?
            .into())
    }

    pub(crate) fn update(
        &self,
        services: &BackendServices,
        id: &str,
        title: Option<String>,
        content: Option<String>,
        tags: Option<Vec<String>>,
        expected_revision: &str,
    ) -> Result<NoteResult, NotesApiError> {
        Ok(services
            .investigation()
            .notes()
            .update_if_revision(
                id,
                expected_revision,
                UpdateNote {
                    title,
                    content,
                    tags,
                },
            )?
            .into())
    }

    pub(crate) fn set_pinned(
        &self,
        services: &BackendServices,
        id: &str,
        pinned: bool,
        expected_revision: &str,
    ) -> Result<NoteResult, NotesApiError> {
        Ok(services
            .investigation()
            .notes()
            .set_pinned_if_revision(id, expected_revision, pinned)?
            .into())
    }

    pub(crate) fn add_tag(
        &self,
        services: &BackendServices,
        id: &str,
        tag: String,
        expected_revision: &str,
    ) -> Result<NoteResult, NotesApiError> {
        Ok(services
            .investigation()
            .notes()
            .add_tag_if_revision(id, expected_revision, tag)?
            .into())
    }

    pub(crate) fn remove_tag(
        &self,
        services: &BackendServices,
        id: &str,
        tag: &str,
        expected_revision: &str,
    ) -> Result<NoteResult, NotesApiError> {
        Ok(services
            .investigation()
            .notes()
            .remove_tag_if_revision(id, expected_revision, tag)?
            .into())
    }

    pub(crate) fn plan_delete(
        &self,
        services: &BackendServices,
        id: &str,
        expected_revision: &str,
    ) -> Result<NoteDeleteProposal, NotesApiError> {
        let plan = services
            .investigation()
            .notes()
            .plan_delete_if_revision(id, expected_revision)?;
        let summary = plan.definition().summary.clone();
        let handle = Uuid::new_v4().to_string();
        let mut pending = self.pending_deletes.lock();
        Self::prune_expired(&mut pending);
        if pending.len() >= MAX_PENDING_DELETES {
            return Err(NotesApiError::DeletePlanCapacity);
        }
        pending.insert(
            handle.clone(),
            PendingNoteDelete {
                created_at: Instant::now(),
                plan,
            },
        );
        Ok(NoteDeleteProposal {
            handle,
            summary,
            expires_in_seconds: DELETE_PLAN_TTL_SECONDS,
        })
    }

    pub(crate) async fn confirm_delete(
        &self,
        services: &BackendServices,
        handle: &str,
    ) -> Result<NoteDeleteResult, NotesApiError> {
        let pending = {
            let mut plans = self.pending_deletes.lock();
            Self::prune_expired(&mut plans);
            plans
                .remove(handle)
                .ok_or(NotesApiError::InvalidDeletePlan)?
        };
        let note_id = pending.plan.note_id().to_owned();
        let confirmation = DangerousConfirmation::approve(pending.plan.definition());
        let outcome = services
            .investigation()
            .notes()
            .execute_delete(pending.plan, confirmation, services.operation_journal())
            .await?;
        Ok(NoteDeleteResult::from_outcome(note_id, outcome))
    }

    pub(crate) fn cancel_delete(
        &self,
        handle: &str,
    ) -> Result<NoteDeleteCancellation, NotesApiError> {
        let mut plans = self.pending_deletes.lock();
        Self::prune_expired(&mut plans);
        plans
            .remove(handle)
            .ok_or(NotesApiError::InvalidDeletePlan)?;
        Ok(NoteDeleteCancellation { cancelled: true })
    }

    pub(crate) fn export(
        &self,
        services: &BackendServices,
        id: Option<&str>,
    ) -> Result<NotesTextExport, NotesApiError> {
        let notes = match id {
            Some(id) => vec![services.investigation().notes().get(id)?.ok_or_else(|| {
                CoreError::NotFound {
                    entity: "note",
                    id: id.to_owned(),
                }
            })?],
            None => services.investigation().notes().list()?,
        };
        NotesTextExport::from_notes(notes, current_unix_millis())
    }

    fn prune_expired(plans: &mut HashMap<String, PendingNoteDelete>) {
        plans.retain(|_, pending| pending.created_at.elapsed().as_secs() < DELETE_PLAN_TTL_SECONDS);
    }
}

impl From<Note> for NoteSummary {
    fn from(note: Note) -> Self {
        let revision = note_revision(&note).expect("validated note must have a revision");
        let content_preview = note
            .content
            .chars()
            .take(CONTENT_PREVIEW_CHARS)
            .collect::<String>();
        let content_truncated = note.content.chars().count() > CONTENT_PREVIEW_CHARS;
        Self {
            id: note.id,
            title: note.title,
            content_preview,
            content_truncated,
            tags: note.tags,
            created_at: note.created_at,
            updated_at: note.updated_at,
            pinned: note.pinned,
            revision,
        }
    }
}

impl From<Note> for NoteResult {
    fn from(note: Note) -> Self {
        let revision = note_revision(&note).expect("validated note must have a revision");
        Self {
            id: note.id,
            title: note.title,
            content: note.content,
            tags: note.tags,
            created_at: note.created_at,
            updated_at: note.updated_at,
            pinned: note.pinned,
            revision,
        }
    }
}

impl NoteDeleteResult {
    fn from_outcome(note_id: String, outcome: InvestigationOperationOutcome) -> Self {
        Self {
            note_id,
            affected_records: outcome.affected_records,
            verified: outcome.verification.passed,
        }
    }
}

impl NotesTextExport {
    fn from_notes(notes: Vec<Note>, exported_at_millis: i64) -> Result<Self, NotesApiError> {
        let note_count = notes.len();
        let mut text = BoundedTextBuilder::new();
        text.push_line("LovelyHawk Notes Export")?;
        text.push_str("Schema: ")?;
        text.push_line(NOTES_SCHEMA_ID)?;
        text.push_str("Exported-At-Unix-Ms: ")?;
        text.push_line(&exported_at_millis.to_string())?;
        text.push_str("Count: ")?;
        text.push_line(&note_count.to_string())?;
        for note in notes {
            text.push_str("\n")?;
            text.push_line("----------------------------------------")?;
            text.push_str("Title: ")?;
            text.push_line(&note.title)?;
            text.push_str("Pinned: ")?;
            text.push_line(if note.pinned { "true" } else { "false" })?;
            text.push_str("Created-At-Unix-Ms: ")?;
            text.push_line(&note.created_at.to_string())?;
            text.push_str("Updated-At-Unix-Ms: ")?;
            text.push_line(&note.updated_at.to_string())?;
            text.push_str("Tags: ")?;
            if note.tags.is_empty() {
                text.push_line("(none)")?;
            } else {
                for (index, tag) in note.tags.iter().enumerate() {
                    if index > 0 {
                        text.push_str(", ")?;
                    }
                    text.push_str(tag)?;
                }
                text.push_str("\n")?;
            }
            text.push_line("Content:")?;
            text.push_str(&note.content)?;
            text.push_str("\n")?;
        }
        Ok(Self {
            note_count,
            text: text.finish(),
        })
    }
}

#[derive(Debug)]
struct BoundedTextBuilder {
    text: String,
}

impl BoundedTextBuilder {
    fn new() -> Self {
        Self {
            text: String::with_capacity(MAX_CLIPBOARD_EXPORT_BYTES.min(8 * 1024)),
        }
    }

    fn push_str(&mut self, value: &str) -> Result<(), NotesApiError> {
        let remaining = MAX_CLIPBOARD_EXPORT_BYTES - self.text.len();
        if value.len() > remaining {
            return Err(NotesApiError::ExportTooLarge);
        }
        self.text.push_str(value);
        Ok(())
    }

    fn push_line(&mut self, value: &str) -> Result<(), NotesApiError> {
        self.push_str(value)?;
        self.push_str("\n")
    }

    fn finish(self) -> String {
        self.text
    }
}

fn current_unix_millis() -> i64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    i64::try_from(millis).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, time::Duration};

    use lovelyhawk_core::PortableStore;

    use super::*;

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("lovelyres-notes-api-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn services(root: &TestRoot) -> BackendServices {
        let store = PortableStore::prepare(root.0.clone()).unwrap();
        BackendServices::with_runtime(store, tokio::runtime::Handle::current()).unwrap()
    }

    #[tokio::test]
    async fn crud_search_export_and_verified_delete_stay_typed() {
        let root = TestRoot::new();
        let services = services(&root);
        let api = NotesApi::default();
        let note = api
            .create(
                &services,
                Some("Rootkit 调查".to_owned()),
                "检查 /proc".to_owned(),
                vec!["取证".to_owned()],
            )
            .unwrap();
        let page = api.list(&services, Some("#取证"), 0, 25).unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].id, note.id);

        let export = api.export(&services, Some(&note.id)).unwrap();
        assert_eq!(export.note_count, 1);
        assert!(export.text.contains("Rootkit 调查"));

        let proposal = api
            .plan_delete(&services, &note.id, &note.revision)
            .unwrap();
        let result = api
            .confirm_delete(&services, &proposal.handle)
            .await
            .unwrap();
        assert!(result.verified);
        assert!(
            api.confirm_delete(&services, &proposal.handle)
                .await
                .is_err()
        );
        assert_eq!(services.operation_journal().entries().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn hostile_markup_is_data_and_unknown_delete_handles_do_nothing() {
        let root = TestRoot::new();
        let services = services(&root);
        let api = NotesApi::default();
        let attack = "<img src=x onerror=steal()>";
        let note = api
            .create(
                &services,
                Some(attack.to_owned()),
                attack.to_owned(),
                Vec::new(),
            )
            .unwrap();
        let loaded = api.get(&services, &note.id).unwrap();
        assert_eq!(loaded.title, attack);
        assert_eq!(loaded.content, attack);
        assert!(api.confirm_delete(&services, "unknown").await.is_err());
        assert!(api.get(&services, &note.id).is_ok());
        assert!(services.operation_journal().entries().unwrap().is_empty());
    }

    #[tokio::test]
    async fn update_pin_and_tag_mutations_return_the_persisted_note() {
        let root = TestRoot::new();
        let services = services(&root);
        let api = NotesApi::default();
        let note = api
            .create(
                &services,
                Some("Initial".to_owned()),
                "draft".to_owned(),
                vec!["triage".to_owned()],
            )
            .unwrap();

        let updated = api
            .update(
                &services,
                &note.id,
                Some("Verified".to_owned()),
                Some("evidence".to_owned()),
                Some(vec!["reviewed".to_owned()]),
                &note.revision,
            )
            .unwrap();
        assert_eq!(updated.title, "Verified");
        assert_eq!(updated.content, "evidence");
        assert_eq!(updated.tags, vec!["reviewed"]);

        let pinned = api
            .set_pinned(&services, &note.id, true, &updated.revision)
            .unwrap();
        assert!(pinned.pinned);
        let tagged = api
            .add_tag(&services, &note.id, "artifact".to_owned(), &pinned.revision)
            .unwrap();
        assert_eq!(tagged.tags, vec!["reviewed", "artifact"]);
        let untagged = api
            .remove_tag(&services, &note.id, "reviewed", &tagged.revision)
            .unwrap();
        assert_eq!(untagged.tags, vec!["artifact"]);

        let persisted = api.get(&services, &note.id).unwrap();
        assert_eq!(persisted.title, "Verified");
        assert_eq!(persisted.content, "evidence");
        assert_eq!(persisted.tags, vec!["artifact"]);
        assert!(persisted.pinned);
    }

    #[tokio::test]
    async fn delete_plan_handles_remain_bound_when_confirmed_out_of_order() {
        let root = TestRoot::new();
        let services = services(&root);
        let api = NotesApi::default();
        let first = api
            .create(
                &services,
                Some("First".to_owned()),
                String::new(),
                Vec::new(),
            )
            .unwrap();
        let second = api
            .create(
                &services,
                Some("Second".to_owned()),
                String::new(),
                Vec::new(),
            )
            .unwrap();
        let first_plan = api
            .plan_delete(&services, &first.id, &first.revision)
            .unwrap();
        let second_plan = api
            .plan_delete(&services, &second.id, &second.revision)
            .unwrap();

        let second_result = api
            .confirm_delete(&services, &second_plan.handle)
            .await
            .unwrap();
        assert_eq!(second_result.note_id, second.id);
        assert!(api.get(&services, &second.id).is_err());
        assert_eq!(api.get(&services, &first.id).unwrap().id, first.id);

        let first_result = api
            .confirm_delete(&services, &first_plan.handle)
            .await
            .unwrap();
        assert_eq!(first_result.note_id, first.id);
        assert!(api.get(&services, &first.id).is_err());
    }

    #[tokio::test]
    async fn cancelling_a_delete_plan_consumes_it_without_mutating_or_auditing() {
        let root = TestRoot::new();
        let services = services(&root);
        let api = NotesApi::default();
        let note = api
            .create(
                &services,
                Some("Keep".to_owned()),
                "still present".to_owned(),
                Vec::new(),
            )
            .unwrap();
        let proposal = api
            .plan_delete(&services, &note.id, &note.revision)
            .unwrap();

        let cancellation = api.cancel_delete(&proposal.handle).unwrap();
        assert!(cancellation.cancelled);
        assert!(matches!(
            api.confirm_delete(&services, &proposal.handle).await,
            Err(NotesApiError::InvalidDeletePlan)
        ));
        assert!(matches!(
            api.cancel_delete(&proposal.handle),
            Err(NotesApiError::InvalidDeletePlan)
        ));
        assert!(matches!(
            api.cancel_delete("unknown"),
            Err(NotesApiError::InvalidDeletePlan)
        ));
        assert_eq!(
            api.get(&services, &note.id).unwrap().content,
            "still present"
        );
        assert!(services.operation_journal().entries().unwrap().is_empty());
    }

    #[tokio::test]
    async fn expired_delete_plan_handles_fail_closed() {
        let root = TestRoot::new();
        let services = services(&root);
        let api = NotesApi::default();
        let note = api
            .create(&services, None, String::new(), Vec::new())
            .unwrap();
        let proposal = api
            .plan_delete(&services, &note.id, &note.revision)
            .unwrap();
        api.pending_deletes
            .lock()
            .get_mut(&proposal.handle)
            .unwrap()
            .created_at = Instant::now()
            .checked_sub(Duration::from_secs(DELETE_PLAN_TTL_SECONDS))
            .unwrap();

        assert!(matches!(
            api.cancel_delete(&proposal.handle),
            Err(NotesApiError::InvalidDeletePlan)
        ));
        assert!(matches!(
            api.confirm_delete(&services, &proposal.handle).await,
            Err(NotesApiError::InvalidDeletePlan)
        ));
        assert_eq!(api.get(&services, &note.id).unwrap().id, note.id);
        assert!(services.operation_journal().entries().unwrap().is_empty());
    }

    #[tokio::test]
    async fn oversized_notes_document_is_rejected_before_export_deserialization() {
        use std::fs::File;

        let root = TestRoot::new();
        let services = services(&root);
        let notes_path = root.0.join("data").join("notes.json");
        let file = File::create(notes_path).unwrap();
        file.set_len((lovelyhawk_core::investigation::MAX_NOTES_DOCUMENT_BYTES + 1) as u64)
            .unwrap();

        let error = NotesApi::default().export(&services, None).unwrap_err();
        assert!(matches!(
            error,
            NotesApiError::Core(CoreError::Validation { .. })
        ));
    }

    #[tokio::test]
    async fn single_and_all_exports_stop_at_the_clipboard_limit() {
        let root = TestRoot::new();
        let services = services(&root);
        let api = NotesApi::default();
        let note = api
            .create(
                &services,
                Some("Large".to_owned()),
                "x".repeat(MAX_CLIPBOARD_EXPORT_BYTES),
                Vec::new(),
            )
            .unwrap();

        assert!(matches!(
            api.export(&services, Some(&note.id)),
            Err(NotesApiError::ExportTooLarge)
        ));
        assert!(matches!(
            api.export(&services, None),
            Err(NotesApiError::ExportTooLarge)
        ));
    }

    #[test]
    fn bounded_export_builder_rejects_a_fragment_before_appending_it() {
        let mut builder = BoundedTextBuilder::new();
        builder.push_str("prefix").unwrap();
        let original_len = builder.text.len();
        let oversized_fragment = "x".repeat(MAX_CLIPBOARD_EXPORT_BYTES);

        assert!(matches!(
            builder.push_str(&oversized_fragment),
            Err(NotesApiError::ExportTooLarge)
        ));
        assert_eq!(builder.text.len(), original_len);
        assert_eq!(builder.text, "prefix");
    }
}
