//! Typed, bounded repositories for portable investigation data.
//!
//! These repositories intentionally expose models rather than JSON or paths. All
//! mutations are serialized per portable data root so read-modify-write updates
//! cannot overwrite each other, including AI and command history sharing one file.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock, Weak};

use async_trait::async_trait;
use chrono::Utc;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::operations::{
    DangerousConfirmation, ExecutionReceipt, OperationExecutor, OperationJournal, OperationPlan,
    OperationState, PlannedOperation, VerificationResult,
};
use crate::store::StoreFile;
use crate::target::{TargetContext, TargetGuard, TargetIdentity};
use crate::{CoreError, CoreResult, PortableStore};

pub const NOTES_SCHEMA_ID: &str = "lovelyres-notes/v1";
pub const INCIDENT_CASE_SCHEMA_ID: &str = "lovelyres-incident-case/v1";
pub const HISTORY_SCHEMA_ID: &str = "lovelyres-history/v1";

const LOCAL_INVESTIGATION_TARGET: &str = "portable-workspace:investigation";

pub const MAX_NOTES: usize = 1_000;
pub const MAX_NOTE_TITLE_CHARS: usize = 256;
pub const MAX_NOTE_CONTENT_CHARS: usize = 1_048_576;
pub const MAX_NOTE_TAGS: usize = 32;
pub const MAX_NOTE_TAG_CHARS: usize = 64;
/// Aggregate encoded notes budget. This is checked before the store allocates
/// its JSON input buffer, so a corrupt multi-gigabyte file fails closed.
pub const MAX_NOTES_DOCUMENT_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_CASES: usize = 30;
pub const MAX_IOCS: usize = 500;
pub const MAX_EVIDENCE: usize = 500;
pub const MAX_TIMELINE: usize = 1_000;
pub const MAX_EVIDENCE_PREVIEW_CHARS: usize = 4_096;
pub const MAX_AI_HISTORY: usize = 500;
pub const MAX_COMMAND_HISTORY: usize = 100;
pub const MAX_COMMAND_OUTPUT_CHARS: usize = 64 * 1_024;

const DOCUMENT_VERSION: u32 = 1;
const MAX_ID_CHARS: usize = 128;
const MAX_SEARCH_CHARS: usize = 256;
const MAX_SOURCE_CHARS: usize = 160;
const MAX_IOC_VALUE_CHARS: usize = 2_048;
const MAX_EVIDENCE_LABEL_CHARS: usize = 256;
const MAX_LOCATOR_CHARS: usize = 2_048;
const MAX_TIMELINE_TITLE_CHARS: usize = 240;
const MAX_TIMELINE_DETAIL_CHARS: usize = 4_096;
const MAX_AI_PROVIDER_CHARS: usize = 128;
const MAX_AI_MODEL_CHARS: usize = 256;
const MAX_AI_PROMPT_CHARS: usize = 131_072;
const MAX_AI_RESULT_CHARS: usize = 1_048_576;
const MAX_COMMAND_CHARS: usize = 65_536;
const MAX_COMMAND_TITLE_CHARS: usize = 256;

/// Time source used by repositories. Tests can inject a deterministic clock.
pub trait Clock: Send + Sync + std::fmt::Debug {
    fn now_millis(&self) -> i64;
}

/// ID source used by repositories. Implementations must return a fresh ID.
pub trait IdGenerator: Send + Sync + std::fmt::Debug {
    fn next_id(&self, prefix: &'static str) -> String;
}

#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_millis(&self) -> i64 {
        Utc::now().timestamp_millis()
    }
}

#[derive(Debug, Default)]
pub struct UuidIdGenerator;

impl IdGenerator for UuidIdGenerator {
    fn next_id(&self, prefix: &'static str) -> String {
        format!("{prefix}-{}", Uuid::new_v4())
    }
}

/// A cohesive set of repositories backed by one portable store.
#[derive(Debug, Clone)]
pub struct InvestigationRepositories {
    notes: NoteRepository,
    cases: IncidentCaseRepository,
    ai_history: AiHistoryRepository,
    command_history: CommandHistoryRepository,
}

impl InvestigationRepositories {
    pub fn new(store: PortableStore) -> Self {
        Self::with_sources(store, Arc::new(SystemClock), Arc::new(UuidIdGenerator))
    }

    pub fn with_sources(
        store: PortableStore,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
    ) -> Self {
        let local_target = Arc::new(TargetContext::new());
        let local_guard = local_target
            .activate(
                TargetIdentity::new(LOCAL_INVESTIGATION_TARGET)
                    .expect("the built-in local investigation target is valid"),
            )
            .expect("a new local investigation target can be activated");
        let context = Arc::new(RepositoryContext {
            transaction: transaction_lock_for(&store),
            store,
            clock,
            ids,
            local_target,
            local_guard,
        });
        Self {
            notes: NoteRepository {
                context: Arc::clone(&context),
            },
            cases: IncidentCaseRepository {
                context: Arc::clone(&context),
            },
            ai_history: AiHistoryRepository {
                context: Arc::clone(&context),
            },
            command_history: CommandHistoryRepository { context },
        }
    }

    pub fn notes(&self) -> &NoteRepository {
        &self.notes
    }

    pub fn cases(&self) -> &IncidentCaseRepository {
        &self.cases
    }

    pub fn ai_history(&self) -> &AiHistoryRepository {
        &self.ai_history
    }

    pub fn command_history(&self) -> &CommandHistoryRepository {
        &self.command_history
    }
}

#[derive(Debug)]
struct RepositoryContext {
    store: PortableStore,
    transaction: Arc<Mutex<()>>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
    local_target: Arc<TargetContext>,
    local_guard: TargetGuard,
}

fn transaction_lock_for(store: &PortableStore) -> Arc<Mutex<()>> {
    static LOCKS: OnceLock<Mutex<BTreeMap<PathBuf, Weak<Mutex<()>>>>> = OnceLock::new();
    let root_identity =
        std::fs::canonicalize(store.root()).unwrap_or_else(|_| store.root().to_path_buf());
    let locks = LOCKS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut locks = locks.lock();
    locks.retain(|_, lock| lock.strong_count() > 0);
    if let Some(lock) = locks.get(&root_identity).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(Mutex::new(()));
    locks.insert(root_identity, Arc::downgrade(&lock));
    lock
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvestigationOperationOutcome {
    pub operation_id: String,
    pub affected_records: usize,
    pub verification: VerificationResult,
}

async fn run_local_destructive_operation(
    context: &RepositoryContext,
    plan: OperationPlan,
    confirmation: DangerousConfirmation,
    executor: &dyn OperationExecutor,
    journal: &dyn OperationJournal,
) -> CoreResult<VerificationResult> {
    let mut operation = PlannedOperation::plan(plan);
    operation.confirm(confirmation)?;
    if let Err(error) = operation
        .execute(context.local_target.as_ref(), executor)
        .await
    {
        if operation.state() == OperationState::StaleAfterExecution {
            operation.journal(journal)?;
        }
        return Err(error);
    }
    operation.journal(journal)?;
    let verification = operation
        .verify(context.local_target.as_ref(), executor, journal)
        .await?;
    if !verification.passed {
        return Err(CoreError::Validation {
            subject: "investigation operation verification",
            message: verification.detail,
        });
    }
    Ok(verification)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    pub id: String,
    pub title: String,
    pub content: String,
    pub tags: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub pinned: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CreateNote {
    pub title: Option<String>,
    pub content: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdateNote {
    pub title: Option<String>,
    pub content: Option<String>,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotesExport {
    pub schema: String,
    pub exported_at_millis: i64,
    pub notes: Vec<Note>,
}

#[derive(Debug, Serialize, Deserialize)]
struct NotesDocument {
    version: u32,
    notes: Vec<Note>,
    #[serde(default)]
    create_replays: Vec<NoteCreateReplay>,
}

#[derive(Debug, Serialize, Deserialize)]
struct NoteCreateReplay {
    mutation_id: String,
    request_digest: String,
    note_id: String,
}

impl Default for NotesDocument {
    fn default() -> Self {
        Self {
            version: DOCUMENT_VERSION,
            notes: Vec::new(),
            create_replays: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NoteRepository {
    context: Arc<RepositoryContext>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteDeletePlan {
    note_id: String,
    expected_revision: String,
    operation: OperationPlan,
}

impl NoteDeletePlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn note_id(&self) -> &str {
        &self.note_id
    }

    pub fn expected_revision(&self) -> &str {
        &self.expected_revision
    }
}

#[derive(Debug)]
struct NoteDeleteExecutor {
    repository: NoteRepository,
    note_id: String,
    expected_revision: String,
}

#[async_trait]
impl OperationExecutor for NoteDeleteExecutor {
    async fn execute(&self, _plan: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        if !self
            .repository
            .delete_if_revision(&self.note_id, &self.expected_revision)?
        {
            return Err(not_found("note", &self.note_id));
        }
        Ok(ExecutionReceipt {
            summary: "permanently deleted one portable note".to_owned(),
            restore_token: None,
        })
    }

    async fn verify(
        &self,
        _plan: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        let absent = self.repository.get(&self.note_id)?.is_none();
        Ok(VerificationResult {
            passed: absent,
            detail: if absent {
                "verified that the portable note no longer exists".to_owned()
            } else {
                "the portable note still exists after deletion".to_owned()
            },
        })
    }

    async fn restore(&self, _plan: &OperationPlan, _receipt: &ExecutionReceipt) -> CoreResult<()> {
        Err(CoreError::Unsupported {
            feature: "restoring a permanently deleted note",
        })
    }
}

impl NoteRepository {
    pub fn plan_delete(&self, id: &str) -> CoreResult<NoteDeletePlan> {
        let note = self.get(id)?.ok_or_else(|| not_found("note", id))?;
        let expected_revision = note_revision(&note)?;
        self.build_delete_plan(note, expected_revision)
    }

    pub fn plan_delete_if_revision(
        &self,
        id: &str,
        expected_revision: &str,
    ) -> CoreResult<NoteDeletePlan> {
        let note = self.get(id)?.ok_or_else(|| not_found("note", id))?;
        ensure_note_revision(&note, expected_revision)?;
        self.build_delete_plan(note, expected_revision.to_owned())
    }

    fn build_delete_plan(
        &self,
        note: Note,
        expected_revision: String,
    ) -> CoreResult<NoteDeletePlan> {
        let mut operation = OperationPlan::new(
            self.context.local_guard.clone(),
            format!("永久删除笔记“{}”；此操作不可恢复。", note.title),
            true,
            None,
        )?;
        operation
            .metadata
            .insert("note-id".to_owned(), note.id.clone());
        Ok(NoteDeletePlan {
            note_id: note.id,
            expected_revision,
            operation,
        })
    }

    pub async fn execute_delete(
        &self,
        plan: NoteDeletePlan,
        confirmation: DangerousConfirmation,
        journal: &dyn OperationJournal,
    ) -> CoreResult<InvestigationOperationOutcome> {
        let operation_id = plan.operation.id.clone();
        let executor = NoteDeleteExecutor {
            repository: self.clone(),
            note_id: plan.note_id,
            expected_revision: plan.expected_revision,
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

    pub fn create(&self, input: CreateNote) -> CoreResult<Note> {
        self.create_inner(input, None)
    }

    pub fn create_idempotent(&self, input: CreateNote, mutation_id: &str) -> CoreResult<Note> {
        validate_mutation_id(mutation_id)?;
        self.create_inner(input, Some(mutation_id))
    }

    fn create_inner(&self, input: CreateNote, mutation_id: Option<&str>) -> CoreResult<Note> {
        let title = match input.title {
            Some(title) if !title.trim().is_empty() => {
                required_trimmed("note title", title, MAX_NOTE_TITLE_CHARS)?
            }
            _ => "笔记".to_owned(),
        };
        let content = bounded_text("note content", input.content, MAX_NOTE_CONTENT_CHARS)?;
        let tags = normalize_tags(input.tags)?;
        let request_digest = create_note_digest(&title, &content, &tags)?;
        let now = valid_now(self.context.clock.as_ref())?;
        let _guard = self.context.transaction.lock();
        let mut document = load_notes(&self.context.store)?;
        if let Some(mutation_id) = mutation_id
            && let Some(replay) = document
                .create_replays
                .iter()
                .find(|replay| replay.mutation_id == mutation_id)
        {
            if replay.request_digest != request_digest {
                return Err(validation(
                    "note mutation id",
                    "the mutation id was already used for a different note creation",
                ));
            }
            return document
                .notes
                .iter()
                .find(|note| note.id == replay.note_id)
                .cloned()
                .ok_or_else(|| {
                    validation("notes data", "a create replay references a missing note")
                });
        }
        let id = generated_id(self.context.ids.as_ref(), "note")?;
        ensure_unique_id(document.notes.iter().map(|note| note.id.as_str()), &id)?;
        let note = Note {
            id,
            title,
            content,
            tags,
            created_at: now,
            updated_at: now,
            pinned: false,
        };
        document.notes.insert(0, note.clone());
        if document.notes.len() > MAX_NOTES {
            document.notes.truncate(MAX_NOTES);
        }
        document.create_replays.retain(|replay| {
            document
                .notes
                .iter()
                .any(|stored| stored.id == replay.note_id)
        });
        if let Some(mutation_id) = mutation_id {
            document.create_replays.insert(
                0,
                NoteCreateReplay {
                    mutation_id: mutation_id.to_owned(),
                    request_digest,
                    note_id: note.id.clone(),
                },
            );
            document.create_replays.truncate(256);
        }
        self.context.store.write(StoreFile::Notes, &document)?;
        Ok(note)
    }

    pub fn get(&self, id: &str) -> CoreResult<Option<Note>> {
        validate_lookup_id(id)?;
        let _guard = self.context.transaction.lock();
        Ok(load_notes(&self.context.store)?
            .notes
            .into_iter()
            .find(|note| note.id == id))
    }

    pub fn list(&self) -> CoreResult<Vec<Note>> {
        let _guard = self.context.transaction.lock();
        let mut notes = load_notes(&self.context.store)?.notes;
        sort_notes(&mut notes);
        Ok(notes)
    }

    pub fn update(&self, id: &str, update: UpdateNote) -> CoreResult<Note> {
        self.update_inner(id, None, update)
    }

    pub fn update_if_revision(
        &self,
        id: &str,
        expected_revision: &str,
        update: UpdateNote,
    ) -> CoreResult<Note> {
        self.update_inner(id, Some(expected_revision), update)
    }

    fn update_inner(
        &self,
        id: &str,
        expected_revision: Option<&str>,
        update: UpdateNote,
    ) -> CoreResult<Note> {
        validate_lookup_id(id)?;
        let title = update
            .title
            .map(|title| required_trimmed("note title", title, MAX_NOTE_TITLE_CHARS))
            .transpose()?;
        let content = update
            .content
            .map(|content| bounded_text("note content", content, MAX_NOTE_CONTENT_CHARS))
            .transpose()?;
        let tags = update.tags.map(normalize_tags).transpose()?;
        let now = valid_now(self.context.clock.as_ref())?;
        let _guard = self.context.transaction.lock();
        let mut document = load_notes(&self.context.store)?;
        let note = document
            .notes
            .iter_mut()
            .find(|note| note.id == id)
            .ok_or_else(|| not_found("note", id))?;
        if let Some(expected_revision) = expected_revision {
            ensure_note_revision(note, expected_revision)?;
        }
        if let Some(title) = title {
            note.title = title;
        }
        if let Some(content) = content {
            note.content = content;
        }
        if let Some(tags) = tags {
            note.tags = tags;
        }
        note.updated_at = now;
        let result = note.clone();
        self.context.store.write(StoreFile::Notes, &document)?;
        Ok(result)
    }

    fn delete_if_revision(&self, id: &str, expected_revision: &str) -> CoreResult<bool> {
        validate_lookup_id(id)?;
        let _guard = self.context.transaction.lock();
        let mut document = load_notes(&self.context.store)?;
        let note = match document.notes.iter().find(|note| note.id == id) {
            Some(note) => note,
            None => return Ok(false),
        };
        ensure_note_revision(note, expected_revision)?;
        let previous_len = document.notes.len();
        document.notes.retain(|note| note.id != id);
        if previous_len == document.notes.len() {
            return Ok(false);
        }
        document
            .create_replays
            .retain(|replay| replay.note_id != id);
        self.context.store.write(StoreFile::Notes, &document)?;
        Ok(true)
    }

    pub fn set_pinned(&self, id: &str, pinned: bool) -> CoreResult<Note> {
        self.set_pinned_inner(id, None, pinned)
    }

    pub fn set_pinned_if_revision(
        &self,
        id: &str,
        expected_revision: &str,
        pinned: bool,
    ) -> CoreResult<Note> {
        self.set_pinned_inner(id, Some(expected_revision), pinned)
    }

    fn set_pinned_inner(
        &self,
        id: &str,
        expected_revision: Option<&str>,
        pinned: bool,
    ) -> CoreResult<Note> {
        validate_lookup_id(id)?;
        let now = valid_now(self.context.clock.as_ref())?;
        let _guard = self.context.transaction.lock();
        let mut document = load_notes(&self.context.store)?;
        let note = document
            .notes
            .iter_mut()
            .find(|note| note.id == id)
            .ok_or_else(|| not_found("note", id))?;
        if let Some(expected_revision) = expected_revision {
            ensure_note_revision(note, expected_revision)?;
        }
        note.pinned = pinned;
        note.updated_at = now;
        let result = note.clone();
        self.context.store.write(StoreFile::Notes, &document)?;
        Ok(result)
    }

    pub fn add_tag(&self, id: &str, tag: String) -> CoreResult<Note> {
        self.add_tag_inner(id, None, tag)
    }

    pub fn add_tag_if_revision(
        &self,
        id: &str,
        expected_revision: &str,
        tag: String,
    ) -> CoreResult<Note> {
        self.add_tag_inner(id, Some(expected_revision), tag)
    }

    fn add_tag_inner(
        &self,
        id: &str,
        expected_revision: Option<&str>,
        tag: String,
    ) -> CoreResult<Note> {
        validate_lookup_id(id)?;
        let tag = required_trimmed("note tag", tag, MAX_NOTE_TAG_CHARS)?;
        let now = valid_now(self.context.clock.as_ref())?;
        let _guard = self.context.transaction.lock();
        let mut document = load_notes(&self.context.store)?;
        let note = document
            .notes
            .iter_mut()
            .find(|note| note.id == id)
            .ok_or_else(|| not_found("note", id))?;
        if let Some(expected_revision) = expected_revision {
            ensure_note_revision(note, expected_revision)?;
        }
        if !note.tags.iter().any(|stored| stored == &tag) {
            if note.tags.len() >= MAX_NOTE_TAGS {
                return Err(validation("note tags", "too many tags"));
            }
            note.tags.push(tag);
            note.updated_at = now;
            let result = note.clone();
            self.context.store.write(StoreFile::Notes, &document)?;
            return Ok(result);
        }
        Ok(note.clone())
    }

    pub fn remove_tag(&self, id: &str, tag: &str) -> CoreResult<Note> {
        self.remove_tag_inner(id, None, tag)
    }

    pub fn remove_tag_if_revision(
        &self,
        id: &str,
        expected_revision: &str,
        tag: &str,
    ) -> CoreResult<Note> {
        self.remove_tag_inner(id, Some(expected_revision), tag)
    }

    fn remove_tag_inner(
        &self,
        id: &str,
        expected_revision: Option<&str>,
        tag: &str,
    ) -> CoreResult<Note> {
        validate_lookup_id(id)?;
        let now = valid_now(self.context.clock.as_ref())?;
        let _guard = self.context.transaction.lock();
        let mut document = load_notes(&self.context.store)?;
        let note = document
            .notes
            .iter_mut()
            .find(|note| note.id == id)
            .ok_or_else(|| not_found("note", id))?;
        if let Some(expected_revision) = expected_revision {
            ensure_note_revision(note, expected_revision)?;
        }
        let previous_len = note.tags.len();
        note.tags.retain(|stored| stored != tag);
        if note.tags.len() != previous_len {
            note.updated_at = now;
            let result = note.clone();
            self.context.store.write(StoreFile::Notes, &document)?;
            return Ok(result);
        }
        Ok(note.clone())
    }

    pub fn search(&self, query: &str) -> CoreResult<Vec<Note>> {
        ensure_len("note search", query, MAX_SEARCH_CHARS)?;
        let query = query.trim().to_lowercase();
        let _guard = self.context.transaction.lock();
        let mut notes = load_notes(&self.context.store)?.notes;
        if !query.is_empty() {
            if let Some(tag) = query.strip_prefix('#') {
                notes.retain(|note| {
                    note.tags
                        .iter()
                        .any(|stored| stored.to_lowercase().contains(tag))
                });
            } else {
                notes.retain(|note| {
                    note.title.to_lowercase().contains(&query)
                        || note.content.to_lowercase().contains(&query)
                        || note
                            .tags
                            .iter()
                            .any(|tag| tag.to_lowercase().contains(&query))
                });
            }
        }
        sort_notes(&mut notes);
        Ok(notes)
    }

    pub fn export_all(&self) -> CoreResult<NotesExport> {
        Ok(NotesExport {
            schema: NOTES_SCHEMA_ID.to_owned(),
            exported_at_millis: valid_now(self.context.clock.as_ref())?,
            notes: self.list()?,
        })
    }

    pub fn export_one(&self, id: &str) -> CoreResult<NotesExport> {
        let note = self.get(id)?.ok_or_else(|| not_found("note", id))?;
        Ok(NotesExport {
            schema: NOTES_SCHEMA_ID.to_owned(),
            exported_at_millis: valid_now(self.context.clock.as_ref())?,
            notes: vec![note],
        })
    }
}

fn sort_notes(notes: &mut [Note]) {
    notes.sort_by(|left, right| {
        right
            .pinned
            .cmp(&left.pinned)
            .then_with(|| right.updated_at.cmp(&left.updated_at))
            .then_with(|| left.id.cmp(&right.id))
    });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IocType {
    Ip,
    Domain,
    Hash,
    Path,
    Process,
    User,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    Finding,
    Path,
    CommandOutput,
    Snapshot,
    Pcap,
    Log,
    Note,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TimelineEventType {
    CaseCreated,
    Finding,
    Evidence,
    Ioc,
    Action,
    Verification,
    Note,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaseStatus {
    Open,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceHashScope {
    StoredPreview,
    ExternalArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseIoc {
    pub id: String,
    pub ioc_type: IocType,
    pub value: String,
    pub source: String,
    pub added_at: i64,
    pub target: TargetIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceArtifact {
    pub id: String,
    pub kind: EvidenceKind,
    pub label: String,
    pub source: String,
    pub locator: Option<String>,
    pub preview: String,
    pub sha256: String,
    pub hash_scope: EvidenceHashScope,
    pub collected_at: i64,
    pub target: TargetIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseTimelineEvent {
    pub id: String,
    pub event_type: TimelineEventType,
    pub title: String,
    pub detail: Option<String>,
    pub source: String,
    pub timestamp: i64,
    pub target: TargetIdentity,
    pub evidence_id: Option<String>,
    pub ioc_id: Option<String>,
    pub operation_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentCase {
    pub id: String,
    pub title: String,
    pub status: CaseStatus,
    pub target: TargetIdentity,
    pub created_at: i64,
    pub updated_at: i64,
    pub iocs: Vec<CaseIoc>,
    pub evidence: Vec<EvidenceArtifact>,
    pub timeline: Vec<CaseTimelineEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddEvidence {
    pub kind: EvidenceKind,
    pub label: String,
    pub source: String,
    pub preview: String,
    pub locator: Option<String>,
    pub external_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddTimelineEvent {
    pub event_type: TimelineEventType,
    pub title: String,
    pub detail: Option<String>,
    pub source: String,
    pub operation_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceHashManifest {
    pub id: String,
    pub sha256: String,
    pub hash_scope: EvidenceHashScope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseExportManifest {
    pub case_id: String,
    pub target: TargetIdentity,
    pub evidence_count: usize,
    pub ioc_count: usize,
    pub evidence_hashes: Vec<EvidenceHashManifest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentCaseExport {
    pub schema: String,
    pub exported_at_millis: i64,
    pub manifest: CaseExportManifest,
    pub incident_case: IncidentCase,
}

#[derive(Debug, Serialize, Deserialize)]
struct CasesDocument {
    version: u32,
    cases: Vec<IncidentCase>,
    active_case_by_target: BTreeMap<String, String>,
}

impl Default for CasesDocument {
    fn default() -> Self {
        Self {
            version: DOCUMENT_VERSION,
            cases: Vec::new(),
            active_case_by_target: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct IncidentCaseRepository {
    context: Arc<RepositoryContext>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentCaseClosePlan {
    target: TargetIdentity,
    case_id: String,
    operation: OperationPlan,
}

impl IncidentCaseClosePlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn target(&self) -> &TargetIdentity {
        &self.target
    }

    pub fn case_id(&self) -> &str {
        &self.case_id
    }
}

#[derive(Debug)]
struct IncidentCaseCloseExecutor {
    repository: IncidentCaseRepository,
    target: TargetIdentity,
    case_id: String,
}

#[async_trait]
impl OperationExecutor for IncidentCaseCloseExecutor {
    async fn execute(&self, _plan: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        self.repository
            .close_open_for_operation(&self.target, &self.case_id)?;
        Ok(ExecutionReceipt {
            summary: "closed one portable incident case".to_owned(),
            restore_token: None,
        })
    }

    async fn verify(
        &self,
        _plan: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        let closed = self
            .repository
            .case_for_target(&self.target, &self.case_id)?
            .is_some_and(|incident| incident.status == CaseStatus::Closed);
        Ok(VerificationResult {
            passed: closed,
            detail: if closed {
                "verified that the portable incident case is closed".to_owned()
            } else {
                "the portable incident case is not closed".to_owned()
            },
        })
    }

    async fn restore(&self, _plan: &OperationPlan, _receipt: &ExecutionReceipt) -> CoreResult<()> {
        Err(CoreError::Unsupported {
            feature: "reopening a closed incident case",
        })
    }
}

impl IncidentCaseRepository {
    pub fn plan_close(
        &self,
        target: &TargetIdentity,
        case_id: &str,
    ) -> CoreResult<IncidentCaseClosePlan> {
        validate_target(target)?;
        validate_lookup_id(case_id)?;
        let incident = self
            .case_for_target(target, case_id)?
            .filter(|incident| incident.status == CaseStatus::Open)
            .ok_or_else(|| not_found("open incident case for target", case_id))?;
        let mut operation = OperationPlan::new(
            self.context.local_guard.clone(),
            format!(
                "关闭案件“{}”；关闭后不可在当前版本中重新打开。",
                incident.title
            ),
            true,
            None,
        )?;
        operation
            .metadata
            .insert("case-id".to_owned(), incident.id.clone());
        operation
            .metadata
            .insert("case-target".to_owned(), target.as_str().to_owned());
        Ok(IncidentCaseClosePlan {
            target: target.clone(),
            case_id: incident.id,
            operation,
        })
    }

    pub async fn execute_close(
        &self,
        plan: IncidentCaseClosePlan,
        confirmation: DangerousConfirmation,
        journal: &dyn OperationJournal,
    ) -> CoreResult<InvestigationOperationOutcome> {
        let operation_id = plan.operation.id.clone();
        let executor = IncidentCaseCloseExecutor {
            repository: self.clone(),
            target: plan.target,
            case_id: plan.case_id,
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

    pub fn ensure_active(
        &self,
        target: &TargetIdentity,
        title: Option<String>,
    ) -> CoreResult<IncidentCase> {
        validate_target(target)?;
        let target_key = target.as_str().to_owned();
        let _guard = self.context.transaction.lock();
        let mut document = load_cases(&self.context.store)?;
        if let Some(case_id) = document.active_case_by_target.get(&target_key)
            && let Some(incident) = document.cases.iter().find(|incident| {
                incident.id == *case_id
                    && incident.target == *target
                    && incident.status == CaseStatus::Open
            })
        {
            return Ok(incident.clone());
        }
        let incident = self.new_case(target, title)?;
        ensure_unique_id(
            document.cases.iter().map(|case| case.id.as_str()),
            &incident.id,
        )?;
        insert_case(&mut document, incident.clone());
        self.context.store.write(StoreFile::Cases, &document)?;
        Ok(incident)
    }

    pub fn create(
        &self,
        target: &TargetIdentity,
        title: Option<String>,
    ) -> CoreResult<IncidentCase> {
        validate_target(target)?;
        let _guard = self.context.transaction.lock();
        let mut document = load_cases(&self.context.store)?;
        let incident = self.new_case(target, title)?;
        ensure_unique_id(
            document.cases.iter().map(|case| case.id.as_str()),
            &incident.id,
        )?;
        insert_case(&mut document, incident.clone());
        self.context.store.write(StoreFile::Cases, &document)?;
        Ok(incident)
    }

    pub fn active(&self, target: &TargetIdentity) -> CoreResult<Option<IncidentCase>> {
        validate_target(target)?;
        let _guard = self.context.transaction.lock();
        let document = load_cases(&self.context.store)?;
        let Some(id) = document.active_case_by_target.get(target.as_str()) else {
            return Ok(None);
        };
        Ok(document.cases.into_iter().find(|incident| {
            incident.id == *id && incident.target == *target && incident.status == CaseStatus::Open
        }))
    }

    pub fn list_for_target(&self, target: &TargetIdentity) -> CoreResult<Vec<IncidentCase>> {
        validate_target(target)?;
        let _guard = self.context.transaction.lock();
        Ok(load_cases(&self.context.store)?
            .cases
            .into_iter()
            .filter(|incident| incident.target == *target)
            .collect())
    }

    pub fn select(&self, target: &TargetIdentity, case_id: &str) -> CoreResult<IncidentCase> {
        validate_target(target)?;
        validate_lookup_id(case_id)?;
        let now = valid_now(self.context.clock.as_ref())?;
        let _guard = self.context.transaction.lock();
        let mut document = load_cases(&self.context.store)?;
        let incident = document
            .cases
            .iter_mut()
            .find(|incident| {
                incident.id == case_id
                    && incident.target == *target
                    && incident.status == CaseStatus::Open
            })
            .ok_or_else(|| not_found("open incident case for target", case_id))?;
        incident.updated_at = now;
        let result = incident.clone();
        document
            .active_case_by_target
            .insert(target.as_str().to_owned(), case_id.to_owned());
        self.context.store.write(StoreFile::Cases, &document)?;
        Ok(result)
    }

    fn close_open_for_operation(
        &self,
        target: &TargetIdentity,
        case_id: &str,
    ) -> CoreResult<IncidentCase> {
        self.close_case(target, case_id)
    }

    fn close_case(&self, target: &TargetIdentity, case_id: &str) -> CoreResult<IncidentCase> {
        validate_target(target)?;
        validate_lookup_id(case_id)?;
        let now = valid_now(self.context.clock.as_ref())?;
        let event_id = generated_id(self.context.ids.as_ref(), "event")?;
        let _guard = self.context.transaction.lock();
        let mut document = load_cases(&self.context.store)?;
        let incident = document
            .cases
            .iter_mut()
            .find(|incident| incident.id == case_id && incident.target == *target)
            .ok_or_else(|| not_found("incident case for target", case_id))?;
        if incident.status != CaseStatus::Open {
            return Err(not_found("open incident case for target", case_id));
        }
        ensure_unique_id(
            incident.timeline.iter().map(|event| event.id.as_str()),
            &event_id,
        )?;
        incident.status = CaseStatus::Closed;
        incident.updated_at = now;
        incident.timeline.insert(
            0,
            CaseTimelineEvent {
                id: event_id,
                event_type: TimelineEventType::Action,
                title: "关闭案件".to_owned(),
                detail: None,
                source: "case-workspace".to_owned(),
                timestamp: now,
                target: target.clone(),
                evidence_id: None,
                ioc_id: None,
                operation_id: None,
            },
        );
        incident.timeline.truncate(MAX_TIMELINE);
        let result = incident.clone();
        if document
            .active_case_by_target
            .get(target.as_str())
            .is_some_and(|active| active == case_id)
        {
            document.active_case_by_target.remove(target.as_str());
        }
        self.context.store.write(StoreFile::Cases, &document)?;
        Ok(result)
    }

    pub fn add_ioc(
        &self,
        target: &TargetIdentity,
        ioc_type: IocType,
        value: String,
        source: String,
    ) -> CoreResult<CaseIoc> {
        let case_id = self.active_case_id(target)?;
        self.add_ioc_to_case(target, &case_id, ioc_type, value, source)
    }

    pub fn add_ioc_to_case(
        &self,
        target: &TargetIdentity,
        case_id: &str,
        ioc_type: IocType,
        value: String,
        source: String,
    ) -> CoreResult<CaseIoc> {
        validate_target(target)?;
        validate_lookup_id(case_id)?;
        let value = required_trimmed("IOC value", value, MAX_IOC_VALUE_CHARS)?;
        let source = source_or_default(source)?;
        let now = valid_now(self.context.clock.as_ref())?;
        let _guard = self.context.transaction.lock();
        let mut document = load_cases(&self.context.store)?;
        let incident = open_case_mut(&mut document, target, case_id)?;
        let comparable = comparable_ioc(ioc_type, &value);
        if let Some(existing) = incident.iocs.iter().find(|ioc| {
            ioc.ioc_type == ioc_type && comparable_ioc(ioc_type, &ioc.value) == comparable
        }) {
            return Ok(existing.clone());
        }
        let ioc_id = generated_id(self.context.ids.as_ref(), "ioc")?;
        let event_id = generated_id(self.context.ids.as_ref(), "event")?;
        ensure_unique_id(incident.iocs.iter().map(|ioc| ioc.id.as_str()), &ioc_id)?;
        ensure_unique_id(
            incident.timeline.iter().map(|event| event.id.as_str()),
            &event_id,
        )?;
        let ioc = CaseIoc {
            id: ioc_id,
            ioc_type,
            value: value.clone(),
            source: source.clone(),
            added_at: now,
            target: target.clone(),
        };
        incident.iocs.insert(0, ioc.clone());
        incident.iocs.truncate(MAX_IOCS);
        incident.timeline.insert(
            0,
            CaseTimelineEvent {
                id: event_id,
                event_type: TimelineEventType::Ioc,
                title: truncate_chars(&format!("加入 IOC：{value}"), MAX_TIMELINE_TITLE_CHARS),
                detail: None,
                source,
                timestamp: now,
                target: target.clone(),
                evidence_id: None,
                ioc_id: Some(ioc.id.clone()),
                operation_id: None,
            },
        );
        incident.timeline.truncate(MAX_TIMELINE);
        incident.updated_at = now;
        self.context.store.write(StoreFile::Cases, &document)?;
        Ok(ioc)
    }

    pub fn add_evidence(
        &self,
        target: &TargetIdentity,
        input: AddEvidence,
    ) -> CoreResult<EvidenceArtifact> {
        let case_id = self.active_case_id(target)?;
        self.add_evidence_to_case(target, &case_id, input)
    }

    pub fn add_evidence_to_case(
        &self,
        target: &TargetIdentity,
        case_id: &str,
        input: AddEvidence,
    ) -> CoreResult<EvidenceArtifact> {
        validate_target(target)?;
        validate_lookup_id(case_id)?;
        let label = required_trimmed("evidence label", input.label, MAX_EVIDENCE_LABEL_CHARS)?;
        let source = source_or_default(input.source)?;
        let preview = bounded_text(
            "evidence preview",
            input.preview,
            MAX_EVIDENCE_PREVIEW_CHARS,
        )?;
        let locator = input
            .locator
            .map(|value| optional_trimmed("evidence locator", value, MAX_LOCATOR_CHARS))
            .transpose()?
            .flatten();
        let (sha256, hash_scope) = match input.external_sha256 {
            Some(value) => (
                normalize_sha256(&value)?,
                EvidenceHashScope::ExternalArtifact,
            ),
            None => (
                preview_digest(input.kind, &label, &source, locator.as_deref(), &preview)?,
                EvidenceHashScope::StoredPreview,
            ),
        };
        let now = valid_now(self.context.clock.as_ref())?;
        let _guard = self.context.transaction.lock();
        let mut document = load_cases(&self.context.store)?;
        let incident = open_case_mut(&mut document, target, case_id)?;
        if let Some(existing) = incident.evidence.iter().find(|evidence| {
            evidence.kind == input.kind
                && evidence.sha256 == sha256
                && evidence.hash_scope == hash_scope
        }) {
            return Ok(existing.clone());
        }
        let evidence_id = generated_id(self.context.ids.as_ref(), "evidence")?;
        let event_id = generated_id(self.context.ids.as_ref(), "event")?;
        ensure_unique_id(
            incident
                .evidence
                .iter()
                .map(|evidence| evidence.id.as_str()),
            &evidence_id,
        )?;
        ensure_unique_id(
            incident.timeline.iter().map(|event| event.id.as_str()),
            &event_id,
        )?;
        let evidence = EvidenceArtifact {
            id: evidence_id,
            kind: input.kind,
            label: label.clone(),
            source: source.clone(),
            locator: locator.clone(),
            preview,
            sha256,
            hash_scope,
            collected_at: now,
            target: target.clone(),
        };
        incident.evidence.insert(0, evidence.clone());
        incident.evidence.truncate(MAX_EVIDENCE);
        let event_type = match input.kind {
            EvidenceKind::Finding => TimelineEventType::Finding,
            EvidenceKind::Note => TimelineEventType::Note,
            _ => TimelineEventType::Evidence,
        };
        incident.timeline.insert(
            0,
            CaseTimelineEvent {
                id: event_id,
                event_type,
                title: truncate_chars(&format!("收集证据：{label}"), MAX_TIMELINE_TITLE_CHARS),
                detail: locator,
                source,
                timestamp: now,
                target: target.clone(),
                evidence_id: Some(evidence.id.clone()),
                ioc_id: None,
                operation_id: None,
            },
        );
        incident.timeline.truncate(MAX_TIMELINE);
        incident.updated_at = now;
        self.context.store.write(StoreFile::Cases, &document)?;
        Ok(evidence)
    }

    pub fn add_timeline_event(
        &self,
        target: &TargetIdentity,
        input: AddTimelineEvent,
    ) -> CoreResult<CaseTimelineEvent> {
        let case_id = self.active_case_id(target)?;
        self.add_timeline_event_to_case(target, &case_id, input)
    }

    pub fn add_timeline_event_to_case(
        &self,
        target: &TargetIdentity,
        case_id: &str,
        input: AddTimelineEvent,
    ) -> CoreResult<CaseTimelineEvent> {
        validate_target(target)?;
        validate_lookup_id(case_id)?;
        let title = required_trimmed("timeline title", input.title, MAX_TIMELINE_TITLE_CHARS)?;
        let source = source_or_default(input.source)?;
        let detail = input
            .detail
            .map(|value| optional_trimmed("timeline detail", value, MAX_TIMELINE_DETAIL_CHARS))
            .transpose()?
            .flatten();
        let operation_id = input
            .operation_id
            .map(|value| required_trimmed("operation id", value, MAX_ID_CHARS))
            .transpose()?;
        let now = valid_now(self.context.clock.as_ref())?;
        let event_id = generated_id(self.context.ids.as_ref(), "event")?;
        let _guard = self.context.transaction.lock();
        let mut document = load_cases(&self.context.store)?;
        let incident = open_case_mut(&mut document, target, case_id)?;
        if let Some(operation_id) = operation_id.as_deref()
            && let Some(existing) = incident
                .timeline
                .iter()
                .find(|event| event.operation_id.as_deref() == Some(operation_id))
        {
            return Ok(existing.clone());
        }
        ensure_unique_id(
            incident.timeline.iter().map(|event| event.id.as_str()),
            &event_id,
        )?;
        let event = CaseTimelineEvent {
            id: event_id,
            event_type: input.event_type,
            title,
            detail,
            source,
            timestamp: now,
            target: target.clone(),
            evidence_id: None,
            ioc_id: None,
            operation_id,
        };
        incident.timeline.insert(0, event.clone());
        incident.timeline.truncate(MAX_TIMELINE);
        incident.updated_at = now;
        self.context.store.write(StoreFile::Cases, &document)?;
        Ok(event)
    }

    pub fn export(&self, target: &TargetIdentity, case_id: &str) -> CoreResult<IncidentCaseExport> {
        validate_target(target)?;
        validate_lookup_id(case_id)?;
        let _guard = self.context.transaction.lock();
        let incident_case = load_cases(&self.context.store)?
            .cases
            .into_iter()
            .find(|incident| incident.id == case_id && incident.target == *target)
            .ok_or_else(|| not_found("incident case for target", case_id))?;
        let manifest = CaseExportManifest {
            case_id: incident_case.id.clone(),
            target: target.clone(),
            evidence_count: incident_case.evidence.len(),
            ioc_count: incident_case.iocs.len(),
            evidence_hashes: incident_case
                .evidence
                .iter()
                .map(|evidence| EvidenceHashManifest {
                    id: evidence.id.clone(),
                    sha256: evidence.sha256.clone(),
                    hash_scope: evidence.hash_scope,
                })
                .collect(),
        };
        Ok(IncidentCaseExport {
            schema: INCIDENT_CASE_SCHEMA_ID.to_owned(),
            exported_at_millis: valid_now(self.context.clock.as_ref())?,
            manifest,
            incident_case,
        })
    }

    fn new_case(&self, target: &TargetIdentity, title: Option<String>) -> CoreResult<IncidentCase> {
        let title = match title {
            Some(title) if !title.trim().is_empty() => required_trimmed("case title", title, 160)?,
            _ => truncate_chars(&format!("应急案件 · {}", target.as_str()), 160),
        };
        let now = valid_now(self.context.clock.as_ref())?;
        Ok(IncidentCase {
            id: generated_id(self.context.ids.as_ref(), "case")?,
            title,
            status: CaseStatus::Open,
            target: target.clone(),
            created_at: now,
            updated_at: now,
            iocs: Vec::new(),
            evidence: Vec::new(),
            timeline: vec![CaseTimelineEvent {
                id: generated_id(self.context.ids.as_ref(), "event")?,
                event_type: TimelineEventType::CaseCreated,
                title: "创建案件".to_owned(),
                detail: None,
                source: "case-workspace".to_owned(),
                timestamp: now,
                target: target.clone(),
                evidence_id: None,
                ioc_id: None,
                operation_id: None,
            }],
        })
    }

    fn active_case_id(&self, target: &TargetIdentity) -> CoreResult<String> {
        validate_target(target)?;
        let _guard = self.context.transaction.lock();
        let document = load_cases(&self.context.store)?;
        let case_id = document
            .active_case_by_target
            .get(target.as_str())
            .ok_or_else(|| not_found("active incident case", target.as_str()))?;
        let _ = open_case(&document, target, case_id)?;
        Ok(case_id.clone())
    }

    fn case_for_target(
        &self,
        target: &TargetIdentity,
        case_id: &str,
    ) -> CoreResult<Option<IncidentCase>> {
        validate_target(target)?;
        validate_lookup_id(case_id)?;
        let _guard = self.context.transaction.lock();
        Ok(load_cases(&self.context.store)?
            .cases
            .into_iter()
            .find(|incident| incident.id == case_id && incident.target == *target))
    }
}

fn insert_case(document: &mut CasesDocument, incident: IncidentCase) {
    let target_key = incident.target.as_str().to_owned();
    let case_id = incident.id.clone();
    document.cases.insert(0, incident);
    document.cases.truncate(MAX_CASES);
    document.active_case_by_target.insert(target_key, case_id);
    let retained: BTreeSet<&str> = document
        .cases
        .iter()
        .filter(|incident| incident.status == CaseStatus::Open)
        .map(|incident| incident.id.as_str())
        .collect();
    document
        .active_case_by_target
        .retain(|_, id| retained.contains(id.as_str()));
}

fn open_case<'a>(
    document: &'a CasesDocument,
    target: &TargetIdentity,
    case_id: &str,
) -> CoreResult<&'a IncidentCase> {
    document
        .cases
        .iter()
        .find(|incident| {
            incident.id == case_id
                && incident.target == *target
                && incident.status == CaseStatus::Open
        })
        .ok_or_else(|| not_found("open incident case for target", case_id))
}

fn open_case_mut<'a>(
    document: &'a mut CasesDocument,
    target: &TargetIdentity,
    case_id: &str,
) -> CoreResult<&'a mut IncidentCase> {
    document
        .cases
        .iter_mut()
        .find(|incident| {
            incident.id == case_id
                && incident.target == *target
                && incident.status == CaseStatus::Open
        })
        .ok_or_else(|| not_found("open incident case for target", case_id))
}

pub fn infer_ioc_type(value: &str) -> IocType {
    let value = value.trim();
    if matches!(value.len(), 32 | 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return IocType::Hash;
    }
    if value.parse::<std::net::IpAddr>().is_ok() {
        return IocType::Ip;
    }
    if value.starts_with('/') || value.starts_with("./") || value.starts_with("../") {
        return IocType::Path;
    }
    if is_domain(value) {
        return IocType::Domain;
    }
    IocType::Other
}

pub fn normalize_ioc_values<'a>(
    values: impl IntoIterator<Item = &'a str>,
) -> CoreResult<Vec<String>> {
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    for value in values {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        ensure_len("IOC value", value, MAX_IOC_VALUE_CHARS)?;
        let value = value.to_owned();
        let key = comparable_ioc(infer_ioc_type(&value), &value);
        if seen.insert(key) {
            result.push(value);
        }
    }
    Ok(result)
}

fn comparable_ioc(ioc_type: IocType, value: &str) -> String {
    if ioc_type == IocType::Path {
        format!("path:{value}")
    } else {
        value.to_lowercase()
    }
}

fn is_domain(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 || !value.contains('.') {
        return false;
    }
    let labels: Vec<_> = value.split('.').collect();
    let Some(top_level) = labels.last() else {
        return false;
    };
    if !(2..=63).contains(&top_level.len())
        || !top_level.bytes().all(|byte| byte.is_ascii_alphabetic())
    {
        return false;
    }
    labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiHistoryRecord {
    pub id: String,
    pub timestamp: i64,
    pub provider: String,
    pub model: String,
    pub prompt: String,
    pub result: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddAiHistory {
    pub provider: String,
    pub model: String,
    pub prompt: String,
    pub result: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiHistoryExport {
    pub schema: String,
    pub exported_at_millis: i64,
    pub records: Vec<AiHistoryRecord>,
}

#[derive(Debug, Clone)]
pub struct AiHistoryRepository {
    context: Arc<RepositoryContext>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiHistoryRemovePlan {
    record_id: String,
    operation: OperationPlan,
}

impl AiHistoryRemovePlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn record_id(&self) -> &str {
        &self.record_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiHistoryClearPlan {
    record_ids: Vec<String>,
    record_set_sha256: String,
    operation: OperationPlan,
}

impl AiHistoryClearPlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    /// Exact records authorized by this plan, sorted for deterministic review.
    pub fn record_ids(&self) -> &[String] {
        &self.record_ids
    }

    pub fn record_set_sha256(&self) -> &str {
        &self.record_set_sha256
    }
}

#[derive(Debug)]
struct AiHistoryRemoveExecutor {
    repository: AiHistoryRepository,
    record_id: String,
}

#[async_trait]
impl OperationExecutor for AiHistoryRemoveExecutor {
    async fn execute(&self, _plan: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        if !self.repository.remove(&self.record_id)? {
            return Err(not_found("AI history record", &self.record_id));
        }
        Ok(ExecutionReceipt {
            summary: "permanently removed one AI history record".to_owned(),
            restore_token: None,
        })
    }

    async fn verify(
        &self,
        _plan: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        let absent = !self
            .repository
            .list()?
            .iter()
            .any(|record| record.id == self.record_id);
        Ok(VerificationResult {
            passed: absent,
            detail: if absent {
                "verified that the AI history record no longer exists".to_owned()
            } else {
                "the AI history record still exists after removal".to_owned()
            },
        })
    }

    async fn restore(&self, _plan: &OperationPlan, _receipt: &ExecutionReceipt) -> CoreResult<()> {
        Err(CoreError::Unsupported {
            feature: "restoring removed AI history",
        })
    }
}

#[derive(Debug)]
struct AiHistoryClearExecutor {
    repository: AiHistoryRepository,
    record_ids: BTreeSet<String>,
    record_set_sha256: String,
    removed: Arc<Mutex<usize>>,
}

#[async_trait]
impl OperationExecutor for AiHistoryClearExecutor {
    async fn execute(&self, _plan: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        // Delete only the IDs shown by the confirmation plan. Records added while
        // the dialog is open are outside that authorization and remain intact.
        let removed = self.repository.remove_planned(&self.record_ids)?;
        *self.removed.lock() = removed;
        Ok(ExecutionReceipt {
            summary: format!(
                "permanently removed {removed} planned AI history records (set {})",
                self.record_set_sha256
            ),
            restore_token: None,
        })
    }

    async fn verify(
        &self,
        _plan: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        let remaining = self
            .repository
            .list()?
            .into_iter()
            .filter(|record| self.record_ids.contains(&record.id))
            .count();
        let all_planned_absent = remaining == 0;
        Ok(VerificationResult {
            passed: all_planned_absent,
            detail: if all_planned_absent {
                format!(
                    "verified that planned AI history set {} is absent; concurrent additions are preserved",
                    self.record_set_sha256
                )
            } else {
                format!(
                    "{remaining} records from planned AI history set {} remain",
                    self.record_set_sha256
                )
            },
        })
    }

    async fn restore(&self, _plan: &OperationPlan, _receipt: &ExecutionReceipt) -> CoreResult<()> {
        Err(CoreError::Unsupported {
            feature: "restoring cleared AI history",
        })
    }
}

impl AiHistoryRepository {
    pub fn plan_remove(&self, id: &str) -> CoreResult<AiHistoryRemovePlan> {
        validate_lookup_id(id)?;
        let exists = self.list()?.iter().any(|record| record.id == id);
        if !exists {
            return Err(not_found("AI history record", id));
        }
        let mut operation = OperationPlan::new(
            self.context.local_guard.clone(),
            "永久删除一条 AI 历史；此操作不可恢复。",
            true,
            None,
        )?;
        operation
            .metadata
            .insert("history-id".to_owned(), id.to_owned());
        Ok(AiHistoryRemovePlan {
            record_id: id.to_owned(),
            operation,
        })
    }

    pub async fn execute_remove(
        &self,
        plan: AiHistoryRemovePlan,
        confirmation: DangerousConfirmation,
        journal: &dyn OperationJournal,
    ) -> CoreResult<InvestigationOperationOutcome> {
        let operation_id = plan.operation.id.clone();
        let executor = AiHistoryRemoveExecutor {
            repository: self.clone(),
            record_id: plan.record_id,
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

    pub fn plan_clear(&self) -> CoreResult<AiHistoryClearPlan> {
        let mut record_ids = self
            .list()?
            .into_iter()
            .map(|record| record.id)
            .collect::<Vec<_>>();
        record_ids.sort_unstable();
        let count = record_ids.len();
        let record_set_sha256 = history_id_set_sha256(&record_ids);
        let mut operation = OperationPlan::new(
            self.context.local_guard.clone(),
            format!(
                "永久清空计划中的 {count} 条 AI 历史（集合摘要 {record_set_sha256}）；此操作不可恢复。确认后新增的记录会保留。"
            ),
            true,
            None,
        )?;
        operation
            .metadata
            .insert("planned-history-count".to_owned(), count.to_string());
        operation.metadata.insert(
            "planned-history-id-set-sha256".to_owned(),
            record_set_sha256.clone(),
        );
        Ok(AiHistoryClearPlan {
            record_ids,
            record_set_sha256,
            operation,
        })
    }

    pub async fn execute_clear(
        &self,
        plan: AiHistoryClearPlan,
        confirmation: DangerousConfirmation,
        journal: &dyn OperationJournal,
    ) -> CoreResult<InvestigationOperationOutcome> {
        let operation_id = plan.operation.id.clone();
        let removed = Arc::new(Mutex::new(0));
        let executor = AiHistoryClearExecutor {
            repository: self.clone(),
            record_ids: plan.record_ids.into_iter().collect(),
            record_set_sha256: plan.record_set_sha256,
            removed: Arc::clone(&removed),
        };
        let verification = run_local_destructive_operation(
            self.context.as_ref(),
            plan.operation,
            confirmation,
            &executor,
            journal,
        )
        .await?;
        let affected_records = *removed.lock();
        Ok(InvestigationOperationOutcome {
            operation_id,
            affected_records,
            verification,
        })
    }

    pub fn add(&self, input: AddAiHistory) -> CoreResult<AiHistoryRecord> {
        let provider = required_trimmed("AI provider", input.provider, MAX_AI_PROVIDER_CHARS)?;
        let model = required_trimmed("AI model", input.model, MAX_AI_MODEL_CHARS)?;
        let prompt = required_text_preserving("AI prompt", input.prompt, MAX_AI_PROMPT_CHARS)?;
        let result = bounded_text("AI result", input.result, MAX_AI_RESULT_CHARS)?;
        let source = source_or_default(input.source)?;
        let record = AiHistoryRecord {
            id: generated_id(self.context.ids.as_ref(), "ai")?,
            timestamp: valid_now(self.context.clock.as_ref())?,
            provider,
            model,
            prompt,
            result,
            source,
        };
        let _guard = self.context.transaction.lock();
        let mut history = load_history(&self.context.store)?;
        ensure_unique_id(history.ai.iter().map(|item| item.id.as_str()), &record.id)?;
        history.ai.insert(0, record.clone());
        history.ai.truncate(MAX_AI_HISTORY);
        self.context.store.write(StoreFile::History, &history)?;
        Ok(record)
    }

    pub fn list(&self) -> CoreResult<Vec<AiHistoryRecord>> {
        let _guard = self.context.transaction.lock();
        Ok(load_history(&self.context.store)?.ai)
    }

    pub fn search(&self, query: &str) -> CoreResult<Vec<AiHistoryRecord>> {
        ensure_len("AI history search", query, MAX_SEARCH_CHARS)?;
        let query = query.trim().to_lowercase();
        let _guard = self.context.transaction.lock();
        Ok(load_history(&self.context.store)?
            .ai
            .into_iter()
            .filter(|record| {
                query.is_empty()
                    || record.provider.to_lowercase().contains(&query)
                    || record.model.to_lowercase().contains(&query)
                    || record.prompt.to_lowercase().contains(&query)
                    || record.result.to_lowercase().contains(&query)
                    || record.source.to_lowercase().contains(&query)
            })
            .collect())
    }

    fn remove(&self, id: &str) -> CoreResult<bool> {
        validate_lookup_id(id)?;
        let _guard = self.context.transaction.lock();
        let mut history = load_history(&self.context.store)?;
        let previous_len = history.ai.len();
        history.ai.retain(|record| record.id != id);
        if previous_len == history.ai.len() {
            return Ok(false);
        }
        self.context.store.write(StoreFile::History, &history)?;
        Ok(true)
    }

    fn remove_planned(&self, planned_ids: &BTreeSet<String>) -> CoreResult<usize> {
        let _guard = self.context.transaction.lock();
        let mut history = load_history(&self.context.store)?;
        let previous_len = history.ai.len();
        history
            .ai
            .retain(|record| !planned_ids.contains(&record.id));
        let removed = previous_len - history.ai.len();
        if removed == 0 {
            return Ok(0);
        }
        self.context.store.write(StoreFile::History, &history)?;
        Ok(removed)
    }

    pub fn export(&self) -> CoreResult<AiHistoryExport> {
        Ok(AiHistoryExport {
            schema: HISTORY_SCHEMA_ID.to_owned(),
            exported_at_millis: valid_now(self.context.clock.as_ref())?,
            records: self.list()?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CommandRisk {
    ReadOnly,
    Mutating,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandHistoryRecord {
    pub id: String,
    pub command: String,
    pub command_sha256: String,
    pub title: String,
    pub output: String,
    pub timestamp: i64,
    pub exit_code: Option<i32>,
    pub target: TargetIdentity,
    pub risk: CommandRisk,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddCommandHistory {
    pub command: String,
    pub title: String,
    pub output: String,
    pub exit_code: Option<i32>,
    pub target: TargetIdentity,
    pub source: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReplayBlockReason {
    NotFound,
    TargetMismatch,
    DigestMismatch,
    RiskChanged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandReplayIntent {
    pub history_id: String,
    pub target: TargetIdentity,
    pub command: String,
    pub title: String,
    pub risk: CommandRisk,
    pub requires_dangerous_confirmation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum CommandReplayPlan {
    Blocked { reason: ReplayBlockReason },
    Intent { intent: CommandReplayIntent },
}

#[derive(Debug, Serialize, Deserialize)]
struct HistoryDocument {
    version: u32,
    ai: Vec<AiHistoryRecord>,
    commands: Vec<CommandHistoryRecord>,
}

impl Default for HistoryDocument {
    fn default() -> Self {
        Self {
            version: DOCUMENT_VERSION,
            ai: Vec::new(),
            commands: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CommandHistoryRepository {
    context: Arc<RepositoryContext>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandHistoryRemovePlan {
    target: TargetIdentity,
    record_id: String,
    snapshot_sha256: String,
    operation: OperationPlan,
}

impl CommandHistoryRemovePlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn record_id(&self) -> &str {
        &self.record_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandHistoryClearPlan {
    target: TargetIdentity,
    record_snapshots: Vec<(String, String)>,
    record_set_sha256: String,
    operation: OperationPlan,
}

impl CommandHistoryClearPlan {
    pub fn definition(&self) -> &OperationPlan {
        &self.operation
    }

    pub fn record_set_sha256(&self) -> &str {
        &self.record_set_sha256
    }

    pub fn record_count(&self) -> usize {
        self.record_snapshots.len()
    }
}

#[derive(Debug)]
struct CommandHistoryRemoveExecutor {
    repository: CommandHistoryRepository,
    target: TargetIdentity,
    record_id: String,
    snapshot_sha256: String,
}

#[async_trait]
impl OperationExecutor for CommandHistoryRemoveExecutor {
    async fn execute(&self, _plan: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        self.repository.remove_if_unchanged(
            &self.target,
            &self.record_id,
            &self.snapshot_sha256,
        )?;
        Ok(ExecutionReceipt {
            summary: "permanently removed one target-bound command history record".to_owned(),
            restore_token: None,
        })
    }

    async fn verify(
        &self,
        _plan: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        let absent = !self
            .repository
            .list_for_target(&self.target)?
            .iter()
            .any(|record| record.id == self.record_id);
        Ok(VerificationResult {
            passed: absent,
            detail: if absent {
                "verified that the planned command history record is absent".to_owned()
            } else {
                "the planned command history record remains after deletion".to_owned()
            },
        })
    }

    async fn restore(&self, _plan: &OperationPlan, _receipt: &ExecutionReceipt) -> CoreResult<()> {
        Err(CoreError::Unsupported {
            feature: "restoring removed command history",
        })
    }
}

#[derive(Debug)]
struct CommandHistoryClearExecutor {
    repository: CommandHistoryRepository,
    target: TargetIdentity,
    record_snapshots: BTreeMap<String, String>,
    record_set_sha256: String,
    removed: Arc<Mutex<usize>>,
}

#[async_trait]
impl OperationExecutor for CommandHistoryClearExecutor {
    async fn execute(&self, _plan: &OperationPlan) -> CoreResult<ExecutionReceipt> {
        let removed = self
            .repository
            .remove_planned_if_unchanged(&self.target, &self.record_snapshots)?;
        *self.removed.lock() = removed;
        Ok(ExecutionReceipt {
            summary: format!(
                "permanently removed {removed} planned command history records (set {})",
                self.record_set_sha256
            ),
            restore_token: None,
        })
    }

    async fn verify(
        &self,
        _plan: &OperationPlan,
        _receipt: &ExecutionReceipt,
    ) -> CoreResult<VerificationResult> {
        let remaining = self
            .repository
            .list_for_target(&self.target)?
            .into_iter()
            .filter(|record| self.record_snapshots.contains_key(&record.id))
            .count();
        Ok(VerificationResult {
            passed: remaining == 0,
            detail: if remaining == 0 {
                format!(
                    "verified that planned command history set {} is absent; concurrent additions are preserved",
                    self.record_set_sha256
                )
            } else {
                format!(
                    "{remaining} records from planned command history set {} remain",
                    self.record_set_sha256
                )
            },
        })
    }

    async fn restore(&self, _plan: &OperationPlan, _receipt: &ExecutionReceipt) -> CoreResult<()> {
        Err(CoreError::Unsupported {
            feature: "restoring cleared command history",
        })
    }
}

impl CommandHistoryRepository {
    pub fn plan_remove(
        &self,
        target: &TargetIdentity,
        id: &str,
    ) -> CoreResult<CommandHistoryRemovePlan> {
        validate_target(target)?;
        validate_lookup_id(id)?;
        let record = self
            .list_for_target(target)?
            .into_iter()
            .find(|record| record.id == id)
            .ok_or_else(|| not_found("command history record for target", id))?;
        let snapshot_sha256 = command_history_snapshot_sha256(&record)?;
        let mut operation = OperationPlan::new(
            self.context.local_guard.clone(),
            format!(
                "永久删除目标 {} 的命令历史“{}”；此操作不可恢复。",
                target.as_str(),
                record.title
            ),
            true,
            None,
        )?;
        operation
            .metadata
            .insert("history-id".to_owned(), record.id.clone());
        operation
            .metadata
            .insert("history-target".to_owned(), target.as_str().to_owned());
        operation.metadata.insert(
            "history-snapshot-sha256".to_owned(),
            snapshot_sha256.clone(),
        );
        Ok(CommandHistoryRemovePlan {
            target: target.clone(),
            record_id: record.id,
            snapshot_sha256,
            operation,
        })
    }

    pub async fn execute_remove(
        &self,
        plan: CommandHistoryRemovePlan,
        confirmation: DangerousConfirmation,
        journal: &dyn OperationJournal,
    ) -> CoreResult<InvestigationOperationOutcome> {
        let operation_id = plan.operation.id.clone();
        let executor = CommandHistoryRemoveExecutor {
            repository: self.clone(),
            target: plan.target,
            record_id: plan.record_id,
            snapshot_sha256: plan.snapshot_sha256,
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

    pub fn plan_clear_for_target(
        &self,
        target: &TargetIdentity,
    ) -> CoreResult<CommandHistoryClearPlan> {
        validate_target(target)?;
        let mut record_snapshots = self
            .list_for_target(target)?
            .into_iter()
            .map(|record| {
                let digest = command_history_snapshot_sha256(&record)?;
                Ok((record.id, digest))
            })
            .collect::<CoreResult<Vec<_>>>()?;
        record_snapshots.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        let record_set_sha256 = command_history_record_set_sha256(&record_snapshots);
        let count = record_snapshots.len();
        let mut operation = OperationPlan::new(
            self.context.local_guard.clone(),
            format!(
                "永久清空目标 {} 的计划内 {count} 条命令历史（集合摘要 {record_set_sha256}）；此操作不可恢复。确认后新增的记录会保留。",
                target.as_str()
            ),
            true,
            None,
        )?;
        operation
            .metadata
            .insert("history-target".to_owned(), target.as_str().to_owned());
        operation
            .metadata
            .insert("planned-history-count".to_owned(), count.to_string());
        operation.metadata.insert(
            "planned-history-record-set-sha256".to_owned(),
            record_set_sha256.clone(),
        );
        Ok(CommandHistoryClearPlan {
            target: target.clone(),
            record_snapshots,
            record_set_sha256,
            operation,
        })
    }

    pub async fn execute_clear_for_target(
        &self,
        plan: CommandHistoryClearPlan,
        confirmation: DangerousConfirmation,
        journal: &dyn OperationJournal,
    ) -> CoreResult<InvestigationOperationOutcome> {
        let operation_id = plan.operation.id.clone();
        let removed = Arc::new(Mutex::new(0));
        let executor = CommandHistoryClearExecutor {
            repository: self.clone(),
            target: plan.target,
            record_snapshots: plan.record_snapshots.into_iter().collect(),
            record_set_sha256: plan.record_set_sha256,
            removed: Arc::clone(&removed),
        };
        let verification = run_local_destructive_operation(
            self.context.as_ref(),
            plan.operation,
            confirmation,
            &executor,
            journal,
        )
        .await?;
        let affected_records = *removed.lock();
        Ok(InvestigationOperationOutcome {
            operation_id,
            affected_records,
            verification,
        })
    }

    pub fn add(&self, input: AddCommandHistory) -> CoreResult<CommandHistoryRecord> {
        validate_target(&input.target)?;
        let command = required_trimmed("command", input.command, MAX_COMMAND_CHARS)?;
        let title = required_trimmed(
            "command history title",
            input.title,
            MAX_COMMAND_TITLE_CHARS,
        )?;
        let output = truncate_chars(&input.output, MAX_COMMAND_OUTPUT_CHARS);
        let source = source_or_default(input.source)?;
        let record = CommandHistoryRecord {
            id: generated_id(self.context.ids.as_ref(), "command")?,
            command_sha256: sha256_hex(command.as_bytes()),
            risk: classify_command_risk(&command),
            command,
            title,
            output,
            timestamp: valid_now(self.context.clock.as_ref())?,
            exit_code: input.exit_code,
            target: input.target,
            source,
        };
        let _guard = self.context.transaction.lock();
        let mut history = load_history(&self.context.store)?;
        ensure_unique_id(
            history.commands.iter().map(|item| item.id.as_str()),
            &record.id,
        )?;
        history.commands.insert(0, record.clone());
        history.commands.truncate(MAX_COMMAND_HISTORY);
        self.context.store.write(StoreFile::History, &history)?;
        Ok(record)
    }

    pub fn list_for_target(
        &self,
        target: &TargetIdentity,
    ) -> CoreResult<Vec<CommandHistoryRecord>> {
        validate_target(target)?;
        let _guard = self.context.transaction.lock();
        Ok(load_history(&self.context.store)?
            .commands
            .into_iter()
            .filter(|record| record.target == *target)
            .collect())
    }

    pub fn search(
        &self,
        target: &TargetIdentity,
        query: &str,
    ) -> CoreResult<Vec<CommandHistoryRecord>> {
        validate_target(target)?;
        ensure_len("command history search", query, MAX_SEARCH_CHARS)?;
        let query = query.trim().to_lowercase();
        Ok(self
            .list_for_target(target)?
            .into_iter()
            .filter(|record| {
                query.is_empty()
                    || record.command.to_lowercase().contains(&query)
                    || record.title.to_lowercase().contains(&query)
                    || record.output.to_lowercase().contains(&query)
                    || record.source.to_lowercase().contains(&query)
            })
            .collect())
    }

    fn remove_if_unchanged(
        &self,
        target: &TargetIdentity,
        id: &str,
        expected_snapshot_sha256: &str,
    ) -> CoreResult<()> {
        validate_target(target)?;
        validate_lookup_id(id)?;
        let _guard = self.context.transaction.lock();
        let mut history = load_history(&self.context.store)?;
        let index = history
            .commands
            .iter()
            .position(|record| record.id == id && record.target == *target)
            .ok_or_else(|| not_found("command history record for target", id))?;
        if command_history_snapshot_sha256(&history.commands[index])? != expected_snapshot_sha256 {
            return Err(validation(
                "command history removal plan",
                "the record changed after confirmation was requested; create a new plan",
            ));
        }
        history.commands.remove(index);
        self.context.store.write(StoreFile::History, &history)?;
        Ok(())
    }

    fn remove_planned_if_unchanged(
        &self,
        target: &TargetIdentity,
        planned: &BTreeMap<String, String>,
    ) -> CoreResult<usize> {
        validate_target(target)?;
        let _guard = self.context.transaction.lock();
        let mut history = load_history(&self.context.store)?;
        for (id, expected_snapshot_sha256) in planned {
            let record = history
                .commands
                .iter()
                .find(|record| record.id == id.as_str() && record.target == *target)
                .ok_or_else(|| not_found("planned command history record for target", id))?;
            if command_history_snapshot_sha256(record)? != *expected_snapshot_sha256 {
                return Err(validation(
                    "command history clear plan",
                    "a planned record changed after confirmation was requested; create a new plan",
                ));
            }
        }
        let previous_len = history.commands.len();
        history
            .commands
            .retain(|record| record.target != *target || !planned.contains_key(record.id.as_str()));
        let removed = previous_len.saturating_sub(history.commands.len());
        if removed > 0 {
            self.context.store.write(StoreFile::History, &history)?;
        }
        Ok(removed)
    }

    /// Produce a replay plan only. This repository never executes a command.
    pub fn plan_replay(
        &self,
        active_target: &TargetIdentity,
        id: &str,
    ) -> CoreResult<CommandReplayPlan> {
        validate_target(active_target)?;
        validate_lookup_id(id)?;
        let _guard = self.context.transaction.lock();
        let history = load_history(&self.context.store)?;
        let Some(record) = history.commands.into_iter().find(|record| record.id == id) else {
            return Ok(CommandReplayPlan::Blocked {
                reason: ReplayBlockReason::NotFound,
            });
        };
        if record.target != *active_target {
            return Ok(CommandReplayPlan::Blocked {
                reason: ReplayBlockReason::TargetMismatch,
            });
        }
        if sha256_hex(record.command.as_bytes()) != record.command_sha256 {
            return Ok(CommandReplayPlan::Blocked {
                reason: ReplayBlockReason::DigestMismatch,
            });
        }
        let risk = classify_command_risk(&record.command);
        if risk != record.risk {
            return Ok(CommandReplayPlan::Blocked {
                reason: ReplayBlockReason::RiskChanged,
            });
        }
        Ok(CommandReplayPlan::Intent {
            intent: CommandReplayIntent {
                history_id: record.id,
                target: record.target,
                command: record.command,
                title: record.title,
                risk,
                requires_dangerous_confirmation: risk == CommandRisk::Mutating,
            },
        })
    }
}

/// Conservative risk classification. Shell composition or an unknown command is mutating.
pub fn classify_command_risk(command: &str) -> CommandRisk {
    let command = command.trim();
    if command.is_empty()
        || command.contains([';', '|', '&', '>', '<', '\n', '\r', '`'])
        || command.contains("$(")
    {
        return CommandRisk::Mutating;
    }
    let executable = command.split_ascii_whitespace().next().unwrap_or_default();
    if executable.contains('/') {
        return CommandRisk::Mutating;
    }
    if matches!(
        executable,
        "id" | "whoami"
            | "uname"
            | "uptime"
            | "pwd"
            | "ls"
            | "stat"
            | "cat"
            | "head"
            | "tail"
            | "ps"
            | "netstat"
            | "lsof"
            | "df"
            | "du"
            | "free"
    ) {
        CommandRisk::ReadOnly
    } else {
        CommandRisk::Mutating
    }
}

fn load_notes(store: &PortableStore) -> CoreResult<NotesDocument> {
    let document: NotesDocument =
        store.read_or_default_bounded(StoreFile::Notes, MAX_NOTES_DOCUMENT_BYTES)?;
    validate_notes(&document)?;
    Ok(document)
}

pub fn note_revision(note: &Note) -> CoreResult<String> {
    let bytes = serde_json::to_vec(note).map_err(|source| CoreError::Encode {
        subject: "note revision",
        source,
    })?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn ensure_note_revision(note: &Note, expected_revision: &str) -> CoreResult<()> {
    if expected_revision.len() != 64
        || !expected_revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || note_revision(note)? != expected_revision
    {
        return Err(validation(
            "note revision",
            "the note changed after it was read; reload before mutating it",
        ));
    }
    Ok(())
}

fn validate_mutation_id(value: &str) -> CoreResult<()> {
    if !(16..=64).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(validation("note mutation id", "invalid idempotency key"));
    }
    Ok(())
}

fn create_note_digest(title: &str, content: &str, tags: &[String]) -> CoreResult<String> {
    let bytes =
        serde_json::to_vec(&(title, content, tags)).map_err(|source| CoreError::Encode {
            subject: "note creation digest",
            source,
        })?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn load_cases(store: &PortableStore) -> CoreResult<CasesDocument> {
    let document: CasesDocument = store.read_or_default(StoreFile::Cases)?;
    validate_cases(&document)?;
    Ok(document)
}

fn load_history(store: &PortableStore) -> CoreResult<HistoryDocument> {
    let document: HistoryDocument = store.read_or_default(StoreFile::History)?;
    validate_history(&document)?;
    Ok(document)
}

fn validate_version(document: &'static str, version: u32) -> CoreResult<()> {
    if version != DOCUMENT_VERSION {
        return Err(CoreError::UnsupportedSchema {
            document,
            expected: DOCUMENT_VERSION,
            actual: version,
        });
    }
    Ok(())
}

fn validate_notes(document: &NotesDocument) -> CoreResult<()> {
    validate_version("notes data", document.version)?;
    if document.notes.len() > MAX_NOTES {
        return Err(validation("notes data", "too many notes"));
    }
    let mut ids = BTreeSet::new();
    for note in &document.notes {
        validate_stored_id("note id", &note.id, &mut ids)?;
        required_trimmed_ref("note title", &note.title, MAX_NOTE_TITLE_CHARS)?;
        ensure_len("note content", &note.content, MAX_NOTE_CONTENT_CHARS)?;
        validate_tags(&note.tags)?;
        validate_timestamp(note.created_at)?;
        validate_timestamp(note.updated_at)?;
    }
    if document.create_replays.len() > 256 {
        return Err(validation("notes data", "too many note creation replays"));
    }
    let note_ids = document
        .notes
        .iter()
        .map(|note| note.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut mutation_ids = BTreeSet::new();
    for replay in &document.create_replays {
        validate_mutation_id(&replay.mutation_id)?;
        if !mutation_ids.insert(replay.mutation_id.as_str())
            || replay.request_digest.len() != 64
            || !replay
                .request_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !note_ids.contains(replay.note_id.as_str())
        {
            return Err(validation("notes data", "invalid note creation replay"));
        }
    }
    Ok(())
}

fn validate_cases(document: &CasesDocument) -> CoreResult<()> {
    validate_version("case data", document.version)?;
    if document.cases.len() > MAX_CASES {
        return Err(validation("case data", "too many cases"));
    }
    let mut case_ids = BTreeSet::new();
    for incident in &document.cases {
        validate_stored_id("case id", &incident.id, &mut case_ids)?;
        validate_target(&incident.target)?;
        required_trimmed_ref("case title", &incident.title, 160)?;
        validate_timestamp(incident.created_at)?;
        validate_timestamp(incident.updated_at)?;
        if incident.iocs.len() > MAX_IOCS
            || incident.evidence.len() > MAX_EVIDENCE
            || incident.timeline.len() > MAX_TIMELINE
        {
            return Err(validation("case data", "case child limit exceeded"));
        }
        let mut ioc_ids = BTreeSet::new();
        for ioc in &incident.iocs {
            validate_stored_id("IOC id", &ioc.id, &mut ioc_ids)?;
            if ioc.target != incident.target {
                return Err(validation("case IOC", "target does not match case"));
            }
            required_trimmed_ref("IOC value", &ioc.value, MAX_IOC_VALUE_CHARS)?;
            required_trimmed_ref("IOC source", &ioc.source, MAX_SOURCE_CHARS)?;
            validate_timestamp(ioc.added_at)?;
        }
        let mut evidence_ids = BTreeSet::new();
        for evidence in &incident.evidence {
            validate_stored_id("evidence id", &evidence.id, &mut evidence_ids)?;
            if evidence.target != incident.target {
                return Err(validation("case evidence", "target does not match case"));
            }
            required_trimmed_ref("evidence label", &evidence.label, MAX_EVIDENCE_LABEL_CHARS)?;
            required_trimmed_ref("evidence source", &evidence.source, MAX_SOURCE_CHARS)?;
            ensure_len(
                "evidence preview",
                &evidence.preview,
                MAX_EVIDENCE_PREVIEW_CHARS,
            )?;
            if let Some(locator) = &evidence.locator {
                required_trimmed_ref("evidence locator", locator, MAX_LOCATOR_CHARS)?;
            }
            normalize_sha256(&evidence.sha256)?;
            validate_timestamp(evidence.collected_at)?;
        }
        let mut event_ids = BTreeSet::new();
        for event in &incident.timeline {
            validate_stored_id("timeline event id", &event.id, &mut event_ids)?;
            if event.target != incident.target {
                return Err(validation("case timeline", "target does not match case"));
            }
            required_trimmed_ref("timeline title", &event.title, MAX_TIMELINE_TITLE_CHARS)?;
            required_trimmed_ref("timeline source", &event.source, MAX_SOURCE_CHARS)?;
            if let Some(detail) = &event.detail {
                required_trimmed_ref("timeline detail", detail, MAX_TIMELINE_DETAIL_CHARS)?;
            }
            validate_timestamp(event.timestamp)?;
        }
    }
    for (target, case_id) in &document.active_case_by_target {
        let target = TargetIdentity::new(target.clone())?;
        if !document.cases.iter().any(|incident| {
            incident.id == *case_id
                && incident.target == target
                && incident.status == CaseStatus::Open
        }) {
            return Err(validation(
                "case selection",
                "active case does not belong to the selected target",
            ));
        }
    }
    Ok(())
}

fn validate_history(document: &HistoryDocument) -> CoreResult<()> {
    validate_version("history data", document.version)?;
    if document.ai.len() > MAX_AI_HISTORY || document.commands.len() > MAX_COMMAND_HISTORY {
        return Err(validation("history data", "history limit exceeded"));
    }
    let mut ids = BTreeSet::new();
    for record in &document.ai {
        validate_stored_id("AI history id", &record.id, &mut ids)?;
        validate_timestamp(record.timestamp)?;
        required_trimmed_ref("AI provider", &record.provider, MAX_AI_PROVIDER_CHARS)?;
        required_trimmed_ref("AI model", &record.model, MAX_AI_MODEL_CHARS)?;
        required_text_preserving_ref("AI prompt", &record.prompt, MAX_AI_PROMPT_CHARS)?;
        ensure_len("AI result", &record.result, MAX_AI_RESULT_CHARS)?;
        required_trimmed_ref("AI history source", &record.source, MAX_SOURCE_CHARS)?;
    }
    ids.clear();
    for record in &document.commands {
        validate_stored_id("command history id", &record.id, &mut ids)?;
        validate_timestamp(record.timestamp)?;
        validate_target(&record.target)?;
        required_trimmed_ref("command", &record.command, MAX_COMMAND_CHARS)?;
        required_trimmed_ref(
            "command history title",
            &record.title,
            MAX_COMMAND_TITLE_CHARS,
        )?;
        ensure_len("command output", &record.output, MAX_COMMAND_OUTPUT_CHARS)?;
        required_trimmed_ref("command source", &record.source, MAX_SOURCE_CHARS)?;
        normalize_sha256(&record.command_sha256)?;
    }
    Ok(())
}

#[derive(Serialize)]
struct PreviewDigest<'a> {
    kind: EvidenceKind,
    label: &'a str,
    source: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    locator: Option<&'a str>,
    preview: &'a str,
}

fn preview_digest(
    kind: EvidenceKind,
    label: &str,
    source: &str,
    locator: Option<&str>,
    preview: &str,
) -> CoreResult<String> {
    let bytes = serde_json::to_vec(&PreviewDigest {
        kind,
        label,
        source,
        locator,
        preview,
    })
    .map_err(|source| CoreError::Encode {
        subject: "evidence preview digest",
        source,
    })?;
    Ok(sha256_hex(&bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn history_id_set_sha256(sorted_ids: &[String]) -> String {
    let mut digest = Sha256::new();
    for id in sorted_ids {
        digest.update((id.len() as u64).to_be_bytes());
        digest.update(id.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

fn command_history_snapshot_sha256(record: &CommandHistoryRecord) -> CoreResult<String> {
    let bytes = serde_json::to_vec(record).map_err(|source| CoreError::Encode {
        subject: "command history snapshot",
        source,
    })?;
    Ok(sha256_hex(&bytes))
}

fn command_history_record_set_sha256(sorted_records: &[(String, String)]) -> String {
    let mut digest = Sha256::new();
    for (id, snapshot_sha256) in sorted_records {
        digest.update((id.len() as u64).to_be_bytes());
        digest.update(id.as_bytes());
        digest.update((snapshot_sha256.len() as u64).to_be_bytes());
        digest.update(snapshot_sha256.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

fn normalize_sha256(value: &str) -> CoreResult<String> {
    let normalized = value.trim().to_ascii_lowercase();
    let normalized = normalized.strip_prefix("sha256:").unwrap_or(&normalized);
    if normalized.len() != 64 || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(validation(
            "external evidence SHA-256",
            "must be 64 hexadecimal characters",
        ));
    }
    Ok(normalized.to_owned())
}

fn generated_id(ids: &dyn IdGenerator, prefix: &'static str) -> CoreResult<String> {
    let id = ids.next_id(prefix);
    validate_lookup_id(&id)?;
    Ok(id)
}

fn validate_lookup_id(id: &str) -> CoreResult<()> {
    if id.trim().is_empty() || id.chars().count() > MAX_ID_CHARS || id.chars().any(char::is_control)
    {
        return Err(validation(
            "record id",
            "must be non-empty, bounded, and contain no control characters",
        ));
    }
    Ok(())
}

fn validate_stored_id<'a>(
    subject: &'static str,
    id: &'a str,
    ids: &mut BTreeSet<&'a str>,
) -> CoreResult<()> {
    validate_lookup_id(id)?;
    if !ids.insert(id) {
        return Err(validation(subject, "duplicate id"));
    }
    Ok(())
}

fn ensure_unique_id<'a>(ids: impl IntoIterator<Item = &'a str>, id: &str) -> CoreResult<()> {
    if ids.into_iter().any(|stored| stored == id) {
        return Err(validation(
            "generated id",
            "generator returned a duplicate id",
        ));
    }
    Ok(())
}

fn validate_target(target: &TargetIdentity) -> CoreResult<()> {
    TargetIdentity::new(target.as_str().to_owned()).map(|_| ())
}

fn valid_now(clock: &dyn Clock) -> CoreResult<i64> {
    let now = clock.now_millis();
    validate_timestamp(now)?;
    Ok(now)
}

fn validate_timestamp(timestamp: i64) -> CoreResult<()> {
    if timestamp < 0 {
        return Err(validation("timestamp", "must not be negative"));
    }
    Ok(())
}

fn source_or_default(source: String) -> CoreResult<String> {
    if source.trim().is_empty() {
        return Ok("manual".to_owned());
    }
    required_trimmed("source", source, MAX_SOURCE_CHARS)
}

fn normalize_tags(tags: Vec<String>) -> CoreResult<Vec<String>> {
    if tags.len() > MAX_NOTE_TAGS {
        return Err(validation("note tags", "too many tags"));
    }
    let mut normalized = Vec::new();
    let mut seen = BTreeSet::new();
    for tag in tags {
        let tag = required_trimmed("note tag", tag, MAX_NOTE_TAG_CHARS)?;
        if seen.insert(tag.clone()) {
            normalized.push(tag);
        }
    }
    Ok(normalized)
}

fn validate_tags(tags: &[String]) -> CoreResult<()> {
    if tags.len() > MAX_NOTE_TAGS {
        return Err(validation("note tags", "too many tags"));
    }
    let mut seen = BTreeSet::new();
    for tag in tags {
        required_trimmed_ref("note tag", tag, MAX_NOTE_TAG_CHARS)?;
        if !seen.insert(tag) {
            return Err(validation("note tags", "duplicate tag"));
        }
    }
    Ok(())
}

fn required_trimmed(subject: &'static str, value: String, max_chars: usize) -> CoreResult<String> {
    let value = value.trim();
    required_trimmed_ref(subject, value, max_chars)?;
    Ok(value.to_owned())
}

fn required_trimmed_ref(subject: &'static str, value: &str, max_chars: usize) -> CoreResult<()> {
    if value.trim().is_empty() {
        return Err(validation(subject, "must not be empty"));
    }
    ensure_len(subject, value, max_chars)
}

fn required_text_preserving(
    subject: &'static str,
    value: String,
    max_chars: usize,
) -> CoreResult<String> {
    required_text_preserving_ref(subject, &value, max_chars)?;
    Ok(value)
}

fn required_text_preserving_ref(
    subject: &'static str,
    value: &str,
    max_chars: usize,
) -> CoreResult<()> {
    if value.trim().is_empty() {
        return Err(validation(subject, "must not be empty"));
    }
    ensure_len(subject, value, max_chars)
}

fn optional_trimmed(
    subject: &'static str,
    value: String,
    max_chars: usize,
) -> CoreResult<Option<String>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    ensure_len(subject, value, max_chars)?;
    Ok(Some(value.to_owned()))
}

fn bounded_text(subject: &'static str, value: String, max_chars: usize) -> CoreResult<String> {
    ensure_len(subject, &value, max_chars)?;
    Ok(value)
}

fn ensure_len(subject: &'static str, value: &str, max_chars: usize) -> CoreResult<()> {
    if value.chars().count() > max_chars {
        return Err(validation(
            subject,
            format!("must be at most {max_chars} characters"),
        ));
    }
    Ok(())
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

fn validation(subject: &'static str, message: impl Into<String>) -> CoreError {
    CoreError::validation(subject, message)
}

fn not_found(entity: &'static str, id: &str) -> CoreError {
    CoreError::NotFound {
        entity,
        id: id.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
    use std::thread;

    use super::*;

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("lovelyres-investigation-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Debug)]
    struct TestClock(AtomicI64);

    impl Clock for TestClock {
        fn now_millis(&self) -> i64 {
            self.0.fetch_add(1, Ordering::SeqCst)
        }
    }

    #[derive(Debug, Default)]
    struct SequenceIds(AtomicU64);

    impl IdGenerator for SequenceIds {
        fn next_id(&self, prefix: &'static str) -> String {
            format!("{prefix}-{}", self.0.fetch_add(1, Ordering::SeqCst))
        }
    }

    fn fixture() -> (TestRoot, PortableStore, InvestigationRepositories) {
        let root = TestRoot::new();
        let store = PortableStore::prepare(root.0.clone()).unwrap();
        let repositories = InvestigationRepositories::with_sources(
            store.clone(),
            Arc::new(TestClock(AtomicI64::new(1_700_000_000_000))),
            Arc::new(SequenceIds::default()),
        );
        (root, store, repositories)
    }

    fn target(value: &str) -> TargetIdentity {
        TargetIdentity::new(value).unwrap()
    }

    fn add_command(target: &TargetIdentity, command: &str) -> AddCommandHistory {
        AddCommandHistory {
            command: command.to_owned(),
            title: "test command".to_owned(),
            output: "ok".to_owned(),
            exit_code: Some(0),
            target: target.clone(),
            source: "test".to_owned(),
        }
    }

    // Legacy stable behaviors: notes CRUD, pin/tag search, and export.
    #[test]
    fn notes_preserve_attacker_text_and_export_typed_models() {
        let (_root, _store, repositories) = fixture();
        let note = repositories
            .notes()
            .create(CreateNote {
                title: Some("<img src=x onerror=alert(1)>".to_owned()),
                content: "<script>not executable data</script>".to_owned(),
                tags: vec!["IR".to_owned()],
            })
            .unwrap();
        repositories.notes().set_pinned(&note.id, true).unwrap();
        repositories
            .notes()
            .add_tag(&note.id, "攻击样本".to_owned())
            .unwrap();

        let found = repositories.notes().search("#攻击").unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].content, "<script>not executable data</script>");
        let exported = repositories.notes().export_one(&note.id).unwrap();
        assert_eq!(exported.schema, NOTES_SCHEMA_ID);
        assert_eq!(exported.notes[0].title, "<img src=x onerror=alert(1)>");
    }

    #[test]
    fn note_limits_reject_oversized_text_without_rewriting() {
        let (_root, store, repositories) = fixture();
        let note = repositories.notes().create(CreateNote::default()).unwrap();
        let before = fs::read(store.path_for(StoreFile::Notes)).unwrap();
        let error = repositories
            .notes()
            .update(
                &note.id,
                UpdateNote {
                    content: Some("x".repeat(MAX_NOTE_CONTENT_CHARS + 1)),
                    ..UpdateNote::default()
                },
            )
            .unwrap_err();
        assert!(matches!(error, CoreError::Validation { .. }));
        assert_eq!(fs::read(store.path_for(StoreFile::Notes)).unwrap(), before);
    }

    #[derive(Debug, Default)]
    struct FailingJournal(AtomicU64);

    impl OperationJournal for FailingJournal {
        fn append(&self, _entry: crate::operations::OperationJournalEntry) -> CoreResult<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(CoreError::Validation {
                subject: "operation journal persistence",
                message: "injected write failure".to_owned(),
            })
        }
    }

    #[derive(Debug)]
    struct VerificationFailureExecutor;

    #[async_trait]
    impl OperationExecutor for VerificationFailureExecutor {
        async fn execute(&self, _plan: &OperationPlan) -> CoreResult<ExecutionReceipt> {
            Ok(ExecutionReceipt {
                summary: "test side effect completed".to_owned(),
                restore_token: None,
            })
        }

        async fn verify(
            &self,
            _plan: &OperationPlan,
            _receipt: &ExecutionReceipt,
        ) -> CoreResult<VerificationResult> {
            Ok(VerificationResult {
                passed: false,
                detail: "injected verification failure".to_owned(),
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
    struct StaleAfterSideEffectExecutor {
        target: Arc<TargetContext>,
    }

    #[async_trait]
    impl OperationExecutor for StaleAfterSideEffectExecutor {
        async fn execute(&self, _plan: &OperationPlan) -> CoreResult<ExecutionReceipt> {
            self.target
                .activate(TargetIdentity::new("replacement-local-context").unwrap())?;
            Ok(ExecutionReceipt {
                summary: "test side effect completed".to_owned(),
                restore_token: None,
            })
        }

        async fn verify(
            &self,
            _plan: &OperationPlan,
            _receipt: &ExecutionReceipt,
        ) -> CoreResult<VerificationResult> {
            unreachable!("a stale execution must not be verified")
        }

        async fn restore(
            &self,
            _plan: &OperationPlan,
            _receipt: &ExecutionReceipt,
        ) -> CoreResult<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn note_delete_requires_exact_confirmation_then_journals_and_verifies() {
        let (_root, store, repositories) = fixture();
        let notes = repositories.notes();
        let first = notes
            .create(CreateNote {
                title: Some("first".to_owned()),
                ..CreateNote::default()
            })
            .unwrap();
        let second = notes
            .create(CreateNote {
                title: Some("second".to_owned()),
                ..CreateNote::default()
            })
            .unwrap();
        let journal = crate::operations::PortableOperationJournal::new(store);

        let rejected = notes.plan_delete(&first.id).unwrap();
        let error = notes
            .execute_delete(
                rejected.clone(),
                DangerousConfirmation::reject(rejected.definition()),
                &journal,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, CoreError::OperationCancelled { .. }));
        assert!(notes.get(&first.id).unwrap().is_some());
        assert!(journal.entries().unwrap().is_empty());

        let first_plan = notes.plan_delete(&first.id).unwrap();
        let other_plan = notes.plan_delete(&second.id).unwrap();
        let error = notes
            .execute_delete(
                first_plan,
                DangerousConfirmation::approve(other_plan.definition()),
                &journal,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, CoreError::Validation { .. }));
        assert!(notes.get(&first.id).unwrap().is_some());
        assert!(notes.get(&second.id).unwrap().is_some());
        assert!(journal.entries().unwrap().is_empty());

        let plan = notes.plan_delete(&first.id).unwrap();
        let confirmation = DangerousConfirmation::approve(plan.definition());
        let outcome = notes
            .execute_delete(plan, confirmation, &journal)
            .await
            .unwrap();
        assert_eq!(outcome.affected_records, 1);
        assert!(outcome.verification.passed);
        assert!(notes.get(&first.id).unwrap().is_none());
        assert!(notes.get(&second.id).unwrap().is_some());
        let entries = journal.entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].phase, crate::operations::JournalPhase::Executed);
        assert_eq!(
            entries[1].phase,
            crate::operations::JournalPhase::VerificationPassed
        );
    }

    #[tokio::test]
    async fn note_delete_surfaces_journal_persistence_failure_after_the_side_effect() {
        let (_root, _store, repositories) = fixture();
        let note = repositories.notes().create(CreateNote::default()).unwrap();
        let plan = repositories.notes().plan_delete(&note.id).unwrap();
        let confirmation = DangerousConfirmation::approve(plan.definition());
        let journal = FailingJournal::default();
        let error = repositories
            .notes()
            .execute_delete(plan, confirmation, &journal)
            .await
            .unwrap_err();
        assert!(matches!(error, CoreError::Validation { .. }));
        assert_eq!(journal.0.load(Ordering::SeqCst), 1);
        assert!(repositories.notes().get(&note.id).unwrap().is_none());
    }

    #[tokio::test]
    async fn local_workflow_journals_verification_failure() {
        let (_root, store, repositories) = fixture();
        let plan = OperationPlan::new(
            repositories.notes().context.local_guard.clone(),
            "test verification failure",
            true,
            None,
        )
        .unwrap();
        let confirmation = DangerousConfirmation::approve(&plan);
        let journal = crate::operations::PortableOperationJournal::new(store);
        let error = run_local_destructive_operation(
            repositories.notes().context.as_ref(),
            plan,
            confirmation,
            &VerificationFailureExecutor,
            &journal,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, CoreError::Validation { .. }));
        let entries = journal.entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[1].phase,
            crate::operations::JournalPhase::VerificationFailed
        );
    }

    #[tokio::test]
    async fn local_workflow_journals_a_side_effect_before_returning_stale() {
        let (_root, store, repositories) = fixture();
        let context = repositories.notes().context.clone();
        let plan = OperationPlan::new(
            context.local_guard.clone(),
            "test stale local operation",
            true,
            None,
        )
        .unwrap();
        let confirmation = DangerousConfirmation::approve(&plan);
        let journal = crate::operations::PortableOperationJournal::new(store);
        let error = run_local_destructive_operation(
            context.as_ref(),
            plan,
            confirmation,
            &StaleAfterSideEffectExecutor {
                target: context.local_target.clone(),
            },
            &journal,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, CoreError::TargetChanged { .. }));
        let entries = journal.entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].phase,
            crate::operations::JournalPhase::StaleAfterExecution
        );
    }

    // Legacy stable behaviors: per-target cases, IOC normalization, evidence digest.
    #[tokio::test]
    async fn cases_are_target_isolated_and_close_select_are_scoped() {
        let (_root, store, repositories) = fixture();
        let first = target("target-one");
        let second = target("target-two");
        let first_case = repositories.cases().ensure_active(&first, None).unwrap();
        repositories
            .cases()
            .add_ioc(
                &first,
                IocType::Domain,
                "EVIL.EXAMPLE".to_owned(),
                "test".to_owned(),
            )
            .unwrap();
        let second_case = repositories.cases().ensure_active(&second, None).unwrap();
        assert_ne!(first_case.id, second_case.id);
        assert!(
            repositories
                .cases()
                .select(&second, &first_case.id)
                .is_err()
        );
        assert!(
            repositories
                .cases()
                .plan_close(&second, &first_case.id)
                .is_err()
        );
        assert_eq!(
            repositories.cases().list_for_target(&first).unwrap().len(),
            1
        );
        let plan = repositories
            .cases()
            .plan_close(&first, &first_case.id)
            .unwrap();
        let confirmation = DangerousConfirmation::approve(plan.definition());
        repositories
            .cases()
            .execute_close(
                plan,
                confirmation,
                &crate::operations::PortableOperationJournal::new(store),
            )
            .await
            .unwrap();
        assert_eq!(
            repositories.cases().list_for_target(&first).unwrap()[0].status,
            CaseStatus::Closed
        );
        assert!(repositories.cases().active(&first).unwrap().is_none());
    }

    #[test]
    fn explicit_case_id_mutations_never_follow_a_racing_active_case() {
        let (_root, _store, repositories) = fixture();
        let selected_target = target("target-one");
        let other_target = target("target-two");
        let first = repositories
            .cases()
            .create(&selected_target, Some("case-a".to_owned()))
            .unwrap();
        let second = repositories
            .cases()
            .create(&selected_target, Some("case-b".to_owned()))
            .unwrap();
        let repository = repositories.cases().clone();
        let switcher = repository.clone();
        let switch_target = selected_target.clone();
        let switch_case = second.id.clone();
        let thread = thread::spawn(move || {
            for _ in 0..32 {
                switcher.select(&switch_target, &switch_case).unwrap();
            }
        });
        for index in 0..32 {
            repository
                .add_ioc_to_case(
                    &selected_target,
                    &first.id,
                    IocType::Domain,
                    format!("ioc-{index}.example"),
                    "race-test".to_owned(),
                )
                .unwrap();
        }
        thread.join().unwrap();

        let cases = repository.list_for_target(&selected_target).unwrap();
        let first_after = cases.iter().find(|case| case.id == first.id).unwrap();
        let second_after = cases.iter().find(|case| case.id == second.id).unwrap();
        assert_eq!(first_after.iocs.len(), 32);
        assert!(second_after.iocs.is_empty());
        assert!(
            repository
                .add_ioc_to_case(
                    &other_target,
                    &first.id,
                    IocType::Domain,
                    "wrong-target.example".to_owned(),
                    "race-test".to_owned(),
                )
                .is_err()
        );
    }

    #[test]
    fn explicit_case_id_evidence_and_timeline_reject_closed_or_cross_target_cases() {
        let (_root, _store, repositories) = fixture();
        let selected_target = target("target-one");
        let other = target("target-two");
        let incident = repositories.cases().create(&selected_target, None).unwrap();
        let evidence = AddEvidence {
            kind: EvidenceKind::Finding,
            label: "finding".to_owned(),
            source: "test".to_owned(),
            preview: "preview".to_owned(),
            locator: None,
            external_sha256: None,
        };
        assert!(
            repositories
                .cases()
                .add_evidence_to_case(&other, &incident.id, evidence.clone())
                .is_err()
        );
        repositories
            .cases()
            .add_evidence_to_case(&selected_target, &incident.id, evidence)
            .unwrap();
        let timeline = AddTimelineEvent {
            event_type: TimelineEventType::Action,
            title: "action".to_owned(),
            detail: None,
            source: "test".to_owned(),
            operation_id: None,
        };
        assert!(
            repositories
                .cases()
                .add_timeline_event_to_case(&other, &incident.id, timeline.clone())
                .is_err()
        );
        repositories
            .cases()
            .close_open_for_operation(&selected_target, &incident.id)
            .unwrap();
        assert!(
            repositories
                .cases()
                .add_evidence_to_case(
                    &selected_target,
                    &incident.id,
                    AddEvidence {
                        kind: EvidenceKind::Finding,
                        label: "late".to_owned(),
                        source: "test".to_owned(),
                        preview: String::new(),
                        locator: None,
                        external_sha256: None,
                    },
                )
                .is_err()
        );
        assert!(
            repositories
                .cases()
                .add_timeline_event_to_case(&selected_target, &incident.id, timeline)
                .is_err()
        );
    }

    #[test]
    fn iocs_match_legacy_classification_and_path_case_rules() {
        assert_eq!(infer_ioc_type("192.0.2.10"), IocType::Ip);
        assert_eq!(infer_ioc_type("999.2.3.4"), IocType::Other);
        assert_eq!(infer_ioc_type("evil.example.com"), IocType::Domain);
        assert_eq!(infer_ioc_type(&"a".repeat(64)), IocType::Hash);
        assert_eq!(infer_ioc_type("/tmp/.x"), IocType::Path);
        assert_eq!(
            normalize_ioc_values([
                " EVIL.EXAMPLE.COM ",
                "evil.example.com",
                "/Tmp/X",
                "/tmp/x",
                "",
            ])
            .unwrap(),
            vec!["EVIL.EXAMPLE.COM", "/Tmp/X", "/tmp/x"]
        );
    }

    #[test]
    fn evidence_preview_hashes_deduplicate_and_external_hashes_validate() {
        let (_root, _store, repositories) = fixture();
        let target = target("target-one");
        repositories.cases().ensure_active(&target, None).unwrap();
        let input = AddEvidence {
            kind: EvidenceKind::Finding,
            label: "可疑进程".to_owned(),
            source: "quick-detection:process".to_owned(),
            preview: "pid=42 cmd=/tmp/x".to_owned(),
            locator: None,
            external_sha256: None,
        };
        let first = repositories
            .cases()
            .add_evidence(&target, input.clone())
            .unwrap();
        let duplicate = repositories.cases().add_evidence(&target, input).unwrap();
        assert_eq!(first.id, duplicate.id);
        assert_eq!(first.sha256.len(), 64);
        assert_eq!(first.hash_scope, EvidenceHashScope::StoredPreview);

        let invalid = repositories.cases().add_evidence(
            &target,
            AddEvidence {
                kind: EvidenceKind::Pcap,
                label: "capture.pcap".to_owned(),
                source: "packet-capture".to_owned(),
                preview: String::new(),
                locator: None,
                external_sha256: Some("not-a-hash".to_owned()),
            },
        );
        assert!(matches!(invalid, Err(CoreError::Validation { .. })));
        let exported = repositories.cases().export(&target, &first.id);
        assert!(matches!(exported, Err(CoreError::NotFound { .. })));
        let case_id = repositories.cases().active(&target).unwrap().unwrap().id;
        let exported = repositories.cases().export(&target, &case_id).unwrap();
        assert_eq!(exported.schema, INCIDENT_CASE_SCHEMA_ID);
        assert_eq!(exported.manifest.evidence_hashes[0].sha256, first.sha256);
    }

    #[test]
    fn ai_html_remains_plain_data_and_history_sections_do_not_overwrite_each_other() {
        let (_root, _store, repositories) = fixture();
        let target = target("target-one");
        repositories
            .ai_history()
            .add(AddAiHistory {
                provider: "local".to_owned(),
                model: "model".to_owned(),
                prompt: "what?".to_owned(),
                result: "<img src=x onerror=steal()>".to_owned(),
                source: "manual".to_owned(),
            })
            .unwrap();
        repositories
            .command_history()
            .add(add_command(&target, "id"))
            .unwrap();
        assert_eq!(repositories.ai_history().list().unwrap().len(), 1);
        assert_eq!(
            repositories.ai_history().list().unwrap()[0].result,
            "<img src=x onerror=steal()>"
        );
        assert_eq!(
            repositories
                .command_history()
                .list_for_target(&target)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn ai_history_keeps_the_newest_bounded_records() {
        let (_root, store, repositories) = fixture();
        let history = HistoryDocument {
            ai: (0..MAX_AI_HISTORY)
                .map(|index| AiHistoryRecord {
                    id: format!("existing-{index}"),
                    timestamp: index as i64,
                    provider: "local".to_owned(),
                    model: "model".to_owned(),
                    prompt: format!("prompt-{index}"),
                    result: "result".to_owned(),
                    source: "test".to_owned(),
                })
                .collect(),
            ..HistoryDocument::default()
        };
        store.write(StoreFile::History, &history).unwrap();
        let added = repositories
            .ai_history()
            .add(AddAiHistory {
                provider: "local".to_owned(),
                model: "model".to_owned(),
                prompt: "newest".to_owned(),
                result: "result".to_owned(),
                source: "test".to_owned(),
            })
            .unwrap();
        let records = repositories.ai_history().list().unwrap();
        assert_eq!(records.len(), MAX_AI_HISTORY);
        assert_eq!(records[0].id, added.id);
        assert!(!records.iter().any(|record| record.id == "existing-499"));
    }

    #[tokio::test]
    async fn ai_history_remove_and_clear_use_exact_plans_without_journaling_sensitive_text() {
        let (_root, store, repositories) = fixture();
        let history = repositories.ai_history();
        let first = history
            .add(AddAiHistory {
                provider: "local".to_owned(),
                model: "model".to_owned(),
                prompt: "SECRET-PROMPT".to_owned(),
                result: "SECRET-RESULT".to_owned(),
                source: "test".to_owned(),
            })
            .unwrap();
        history
            .add(AddAiHistory {
                provider: "local".to_owned(),
                model: "model".to_owned(),
                prompt: "another".to_owned(),
                result: "answer".to_owned(),
                source: "test".to_owned(),
            })
            .unwrap();
        let journal = crate::operations::PortableOperationJournal::new(store);

        let remove = history.plan_remove(&first.id).unwrap();
        let confirmation = DangerousConfirmation::approve(remove.definition());
        history
            .execute_remove(remove, confirmation, &journal)
            .await
            .unwrap();
        assert!(
            !history
                .list()
                .unwrap()
                .iter()
                .any(|item| item.id == first.id)
        );

        let clear = history.plan_clear().unwrap();
        let confirmation = DangerousConfirmation::approve(clear.definition());
        let outcome = history
            .execute_clear(clear, confirmation, &journal)
            .await
            .unwrap();
        assert_eq!(outcome.affected_records, 1);
        assert!(history.list().unwrap().is_empty());
        let journal_text = serde_json::to_string(&journal.entries().unwrap()).unwrap();
        assert!(!journal_text.contains("SECRET-PROMPT"));
        assert!(!journal_text.contains("SECRET-RESULT"));
        assert!(journal_text.contains("permanently removed 1 planned AI history records"));
    }

    #[tokio::test]
    async fn ai_history_clear_preserves_records_added_after_the_confirmed_plan() {
        let (_root, store, repositories) = fixture();
        let history = repositories.ai_history();
        let first = history
            .add(AddAiHistory {
                provider: "local".to_owned(),
                model: "model".to_owned(),
                prompt: "planned-one".to_owned(),
                result: "answer".to_owned(),
                source: "test".to_owned(),
            })
            .unwrap();
        let second = history
            .add(AddAiHistory {
                provider: "local".to_owned(),
                model: "model".to_owned(),
                prompt: "planned-two".to_owned(),
                result: "answer".to_owned(),
                source: "test".to_owned(),
            })
            .unwrap();
        let clear = history.plan_clear().unwrap();
        let expected_ids = BTreeSet::from([first.id.clone(), second.id.clone()]);
        assert_eq!(
            clear.record_ids().iter().cloned().collect::<BTreeSet<_>>(),
            expected_ids
        );
        let set_sha256 = clear.record_set_sha256().to_owned();
        assert_eq!(clear.definition().metadata["planned-history-count"], "2");
        assert_eq!(
            clear.definition().metadata["planned-history-id-set-sha256"],
            set_sha256
        );
        assert!(clear.definition().summary.contains(&set_sha256));
        let confirmation = DangerousConfirmation::approve(clear.definition());

        // Model a second producer adding history while the destructive dialog is
        // open. The two barrier phases make this interleaving deterministic.
        let barrier = Arc::new(Barrier::new(2));
        let worker_barrier = Arc::clone(&barrier);
        let worker_history = history.clone();
        let worker = thread::spawn(move || {
            worker_barrier.wait();
            let added = worker_history
                .add(AddAiHistory {
                    provider: "local".to_owned(),
                    model: "model".to_owned(),
                    prompt: "concurrent-addition".to_owned(),
                    result: "must survive".to_owned(),
                    source: "test".to_owned(),
                })
                .unwrap();
            worker_barrier.wait();
            added
        });
        barrier.wait();
        barrier.wait();
        let concurrent = worker.join().unwrap();

        let journal = crate::operations::PortableOperationJournal::new(store);
        let outcome = history
            .execute_clear(clear, confirmation, &journal)
            .await
            .unwrap();
        assert_eq!(outcome.affected_records, 2);
        assert!(outcome.verification.passed);
        assert!(outcome.verification.detail.contains(&set_sha256));
        assert_eq!(history.list().unwrap(), vec![concurrent]);
        let entries = journal.entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert!(
            entries
                .iter()
                .all(|entry| entry.summary.contains(&set_sha256))
        );
        assert!(
            entries
                .iter()
                .all(|entry| entry.detail.contains(&set_sha256))
        );
    }

    #[tokio::test]
    async fn ai_history_clear_wrong_plan_confirmation_has_zero_side_effects() {
        let (_root, store, repositories) = fixture();
        let history = repositories.ai_history();
        let record = history
            .add(AddAiHistory {
                provider: "local".to_owned(),
                model: "model".to_owned(),
                prompt: "must remain".to_owned(),
                result: "answer".to_owned(),
                source: "test".to_owned(),
            })
            .unwrap();
        let clear = history.plan_clear().unwrap();
        let other_plan = history.plan_clear().unwrap();
        let wrong_confirmation = DangerousConfirmation::approve(other_plan.definition());
        let before = fs::read(store.path_for(StoreFile::History)).unwrap();
        let journal = crate::operations::PortableOperationJournal::new(store.clone());

        let error = history
            .execute_clear(clear, wrong_confirmation, &journal)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            CoreError::Validation {
                subject: "dangerous confirmation",
                ..
            }
        ));
        assert_eq!(
            fs::read(store.path_for(StoreFile::History)).unwrap(),
            before
        );
        assert_eq!(history.list().unwrap(), vec![record]);
        assert!(journal.entries().unwrap().is_empty());
    }

    // Legacy command-history stable IDs: target-bound, digest-checked replay assessment.
    #[test]
    fn command_replay_returns_only_target_bound_intents() {
        let (_root, store, repositories) = fixture();
        let active_target = target("target-one");
        let other = target("target-two");
        assert_eq!(classify_command_risk("/tmp/id"), CommandRisk::Mutating);
        let read_only = repositories
            .command_history()
            .add(add_command(&active_target, " id "))
            .unwrap();
        assert!(matches!(
            repositories
                .command_history()
                .plan_replay(&other, &read_only.id)
                .unwrap(),
            CommandReplayPlan::Blocked {
                reason: ReplayBlockReason::TargetMismatch
            }
        ));
        assert!(matches!(
            repositories
                .command_history()
                .plan_replay(&active_target, &read_only.id)
                .unwrap(),
            CommandReplayPlan::Intent {
                intent: CommandReplayIntent {
                    requires_dangerous_confirmation: false,
                    ..
                }
            }
        ));

        let mut history: HistoryDocument = store.read(StoreFile::History).unwrap().unwrap();
        history.commands[0].command = "id; rm -f /tmp/x".to_owned();
        store.write(StoreFile::History, &history).unwrap();
        assert!(matches!(
            repositories
                .command_history()
                .plan_replay(&active_target, &read_only.id)
                .unwrap(),
            CommandReplayPlan::Blocked {
                reason: ReplayBlockReason::DigestMismatch
            }
        ));

        let mutating = repositories
            .command_history()
            .add(add_command(&active_target, "rm -f /tmp/example"))
            .unwrap();
        assert!(matches!(
            repositories
                .command_history()
                .plan_replay(&active_target, &mutating.id)
                .unwrap(),
            CommandReplayPlan::Intent {
                intent: CommandReplayIntent {
                    requires_dangerous_confirmation: true,
                    ..
                }
            }
        ));
    }

    #[tokio::test]
    async fn command_history_wrong_confirmation_has_zero_side_effects() {
        let (_root, store, repositories) = fixture();
        let target = target("target-one");
        let record = repositories
            .command_history()
            .add(add_command(&target, "id"))
            .unwrap();
        let plan = repositories
            .command_history()
            .plan_remove(&target, &record.id)
            .unwrap();
        let unrelated = repositories
            .command_history()
            .plan_remove(&target, &record.id)
            .unwrap();
        let confirmation = DangerousConfirmation::approve(unrelated.definition());
        let journal = crate::operations::PortableOperationJournal::new(store.clone());
        let before = fs::read(store.path_for(StoreFile::History)).unwrap();

        let error = repositories
            .command_history()
            .execute_remove(plan, confirmation, &journal)
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            CoreError::Validation {
                subject: "dangerous confirmation",
                ..
            }
        ));
        assert_eq!(
            fs::read(store.path_for(StoreFile::History)).unwrap(),
            before
        );
        assert_eq!(
            repositories
                .command_history()
                .list_for_target(&target)
                .unwrap(),
            vec![record]
        );
        assert!(journal.entries().unwrap().is_empty());
    }

    #[tokio::test]
    async fn command_history_clear_deletes_only_the_reviewed_snapshot_set() {
        let (_root, store, repositories) = fixture();
        let active_target = target("target-one");
        let other_target = target("target-two");
        let first = repositories
            .command_history()
            .add(add_command(&active_target, "id"))
            .unwrap();
        let second = repositories
            .command_history()
            .add(add_command(&active_target, "uname -a"))
            .unwrap();
        let other = repositories
            .command_history()
            .add(add_command(&other_target, "whoami"))
            .unwrap();
        let plan = repositories
            .command_history()
            .plan_clear_for_target(&active_target)
            .unwrap();
        assert_eq!(plan.record_count(), 2);
        assert_eq!(plan.record_set_sha256().len(), 64);
        let confirmation = DangerousConfirmation::approve(plan.definition());

        let concurrent = repositories
            .command_history()
            .add(add_command(&active_target, "pwd"))
            .unwrap();
        let journal = crate::operations::PortableOperationJournal::new(store);
        let outcome = repositories
            .command_history()
            .execute_clear_for_target(plan, confirmation, &journal)
            .await
            .unwrap();

        assert_eq!(outcome.affected_records, 2);
        assert!(outcome.verification.passed);
        assert_eq!(
            repositories
                .command_history()
                .list_for_target(&active_target)
                .unwrap(),
            vec![concurrent]
        );
        assert_eq!(
            repositories
                .command_history()
                .list_for_target(&other_target)
                .unwrap(),
            vec![other]
        );
        assert!(!journal.entries().unwrap().is_empty());
        assert_ne!(first.id, second.id);
    }

    #[test]
    fn concurrent_history_updates_do_not_get_lost() {
        let (root, _store, repositories) = fixture();
        let lexical_alias_component = root.0.join("lexical-alias");
        fs::create_dir_all(&lexical_alias_component).unwrap();
        let alias_store = PortableStore::prepare(lexical_alias_component.join("..")).unwrap();
        let independently_constructed = InvestigationRepositories::with_sources(
            alias_store,
            Arc::new(TestClock(AtomicI64::new(1_800_000_000_000))),
            Arc::new(SequenceIds(AtomicU64::new(10_000))),
        );
        let mut workers = Vec::new();
        for worker in 0..8 {
            let repositories = if worker % 2 == 0 {
                repositories.clone()
            } else {
                independently_constructed.clone()
            };
            workers.push(thread::spawn(move || {
                if worker % 2 == 0 {
                    repositories
                        .ai_history()
                        .add(AddAiHistory {
                            provider: "local".to_owned(),
                            model: "model".to_owned(),
                            prompt: format!("prompt-{worker}"),
                            result: "result".to_owned(),
                            source: "test".to_owned(),
                        })
                        .unwrap();
                } else {
                    repositories
                        .command_history()
                        .add(add_command(&target("target-one"), "id"))
                        .unwrap();
                }
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(repositories.ai_history().list().unwrap().len(), 4);
        assert_eq!(
            repositories
                .command_history()
                .list_for_target(&target("target-one"))
                .unwrap()
                .len(),
            4
        );
    }

    #[test]
    fn unsupported_schema_is_not_rewritten_by_a_mutation() {
        let (_root, store, repositories) = fixture();
        let path = store.path_for(StoreFile::Notes);
        fs::write(
            &path,
            br#"{"schema_version":99,"data":{"version":1,"notes":[]}}"#,
        )
        .unwrap();
        let before = fs::read(&path).unwrap();
        let error = repositories
            .notes()
            .create(CreateNote::default())
            .unwrap_err();
        assert!(matches!(
            error,
            CoreError::UnsupportedSchema { actual: 99, .. }
        ));
        assert_eq!(fs::read(path).unwrap(), before);
    }

    #[test]
    fn unsupported_history_aggregate_version_is_not_rewritten() {
        let (_root, store, repositories) = fixture();
        let history = HistoryDocument {
            version: 2,
            ai: Vec::new(),
            commands: Vec::new(),
        };
        store.write(StoreFile::History, &history).unwrap();
        let path = store.path_for(StoreFile::History);
        let before = fs::read(&path).unwrap();
        let error = repositories
            .ai_history()
            .add(AddAiHistory {
                provider: "local".to_owned(),
                model: "model".to_owned(),
                prompt: "prompt".to_owned(),
                result: "result".to_owned(),
                source: "test".to_owned(),
            })
            .unwrap_err();
        assert!(matches!(
            error,
            CoreError::UnsupportedSchema {
                document: "history data",
                actual: 2,
                ..
            }
        ));
        assert_eq!(fs::read(path).unwrap(), before);
    }

    #[test]
    fn persistence_failure_keeps_the_previous_atomic_document() {
        let (_root, store, repositories) = fixture();
        repositories.notes().create(CreateNote::default()).unwrap();
        let before = fs::read(store.path_for(StoreFile::Notes)).unwrap();
        fs::remove_dir_all(store.backups_dir()).unwrap();
        fs::write(store.backups_dir(), b"not a directory").unwrap();
        let error = repositories
            .notes()
            .create(CreateNote::default())
            .unwrap_err();
        assert!(matches!(error, CoreError::Io { .. }));
        assert_eq!(fs::read(store.path_for(StoreFile::Notes)).unwrap(), before);
        assert!(
            fs::read_dir(store.root())
                .unwrap()
                .filter_map(Result::ok)
                .all(|entry| { !entry.file_name().to_string_lossy().contains(".tmp-") })
        );
    }
}
