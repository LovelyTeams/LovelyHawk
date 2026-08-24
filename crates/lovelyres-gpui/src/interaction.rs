use std::{collections::VecDeque, sync::OnceLock, time::Instant};

use lovelyres_core::operations::OperationPlan;

use crate::{pages::PageId, theme::ThemeId};

const MAX_DIALOG_TITLE_BYTES: usize = 256;
const MAX_DIALOG_MESSAGE_BYTES: usize = 8 * 1024;
const MAX_PROMPT_VALUE_BYTES: usize = 4 * 1024;
const MAX_OPERATION_ID_BYTES: usize = 256;
const MAX_NOTIFICATION_KEY_BYTES: usize = 128;
const MAX_NOTIFICATION_MESSAGE_BYTES: usize = 4 * 1024;
const MAX_NOTIFICATIONS: usize = 64;
const DEFAULT_TOAST_TIMEOUT_MS: u64 = 3_000;
const ERROR_TOAST_TIMEOUT_MS: u64 = 5_000;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum FocusTarget {
    #[default]
    Workspace,
    SettingsPanel,
    Dialog,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DialogId(u64);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlertDialog {
    pub id: DialogId,
    pub title: String,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromptDialog {
    pub id: DialogId,
    pub title: String,
    pub message: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DangerousConfirmDialog {
    pub id: DialogId,
    pub operation_id: String,
    pub summary: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DialogState {
    Alert(AlertDialog),
    Prompt(PromptDialog),
    DangerousConfirm(DangerousConfirmDialog),
}

impl DialogState {
    pub const fn id(&self) -> DialogId {
        match self {
            Self::Alert(dialog) => dialog.id,
            Self::Prompt(dialog) => dialog.id,
            Self::DangerousConfirm(dialog) => dialog.id,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DialogAction {
    DismissAlert {
        dialog_id: DialogId,
    },
    SubmitPrompt {
        dialog_id: DialogId,
    },
    Cancel {
        dialog_id: DialogId,
    },
    ConfirmDangerous {
        dialog_id: DialogId,
        operation_id: String,
    },
}

impl DialogAction {
    const fn dialog_id(&self) -> DialogId {
        match self {
            Self::DismissAlert { dialog_id }
            | Self::SubmitPrompt { dialog_id }
            | Self::Cancel { dialog_id }
            | Self::ConfirmDangerous { dialog_id, .. } => *dialog_id,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DialogOutcome {
    AlertDismissed {
        dialog_id: DialogId,
    },
    PromptSubmitted {
        dialog_id: DialogId,
        value: String,
    },
    Cancelled {
        dialog_id: DialogId,
    },
    DangerousApproved {
        dialog_id: DialogId,
        operation_id: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DialogError {
    NoActiveDialog,
    DialogIdMismatch,
    ActionTypeMismatch,
    OperationIdMismatch,
    OperationIsNotDangerous,
    OperationIdTooLong,
    OperationSummaryTooLong,
}

#[derive(Debug, Default)]
pub struct DialogHost {
    next_id: u64,
    active: Option<DialogState>,
    outcomes: VecDeque<DialogOutcome>,
}

impl DialogHost {
    pub fn active(&self) -> Option<&DialogState> {
        self.active.as_ref()
    }

    pub fn show_alert(&mut self, title: impl Into<String>, message: impl Into<String>) -> DialogId {
        let id = self.next_id();
        self.active = Some(DialogState::Alert(AlertDialog {
            id,
            title: bounded_text(title.into(), MAX_DIALOG_TITLE_BYTES),
            message: bounded_text(message.into(), MAX_DIALOG_MESSAGE_BYTES),
        }));
        id
    }

    pub fn show_prompt(
        &mut self,
        title: impl Into<String>,
        message: impl Into<String>,
        initial_value: impl Into<String>,
    ) -> DialogId {
        let id = self.next_id();
        self.active = Some(DialogState::Prompt(PromptDialog {
            id,
            title: bounded_text(title.into(), MAX_DIALOG_TITLE_BYTES),
            message: bounded_text(message.into(), MAX_DIALOG_MESSAGE_BYTES),
            value: bounded_text(initial_value.into(), MAX_PROMPT_VALUE_BYTES),
        }));
        id
    }

    pub fn show_dangerous(&mut self, plan: &OperationPlan) -> Result<DialogId, DialogError> {
        if !plan.dangerous {
            return Err(DialogError::OperationIsNotDangerous);
        }
        if plan.id.len() > MAX_OPERATION_ID_BYTES {
            return Err(DialogError::OperationIdTooLong);
        }
        if plan.summary.len() > MAX_DIALOG_MESSAGE_BYTES {
            return Err(DialogError::OperationSummaryTooLong);
        }
        let id = self.next_id();
        self.active = Some(DialogState::DangerousConfirm(DangerousConfirmDialog {
            id,
            operation_id: plan.id.clone(),
            summary: plan.summary.clone(),
        }));
        Ok(id)
    }

    pub fn update_prompt(&mut self, value: impl Into<String>) -> Result<(), DialogError> {
        let Some(DialogState::Prompt(prompt)) = self.active.as_mut() else {
            return Err(if self.active.is_some() {
                DialogError::ActionTypeMismatch
            } else {
                DialogError::NoActiveDialog
            });
        };
        prompt.value = bounded_text(value.into(), MAX_PROMPT_VALUE_BYTES);
        Ok(())
    }

    pub fn dispatch(&mut self, action: DialogAction) -> Result<DialogOutcome, DialogError> {
        let Some(active) = self.active.as_ref() else {
            return Err(DialogError::NoActiveDialog);
        };
        if active.id() != action.dialog_id() {
            return Err(DialogError::DialogIdMismatch);
        }

        let outcome = match (active, action) {
            (DialogState::Alert(dialog), DialogAction::DismissAlert { .. }) => {
                DialogOutcome::AlertDismissed {
                    dialog_id: dialog.id,
                }
            }
            (DialogState::Prompt(dialog), DialogAction::SubmitPrompt { .. }) => {
                DialogOutcome::PromptSubmitted {
                    dialog_id: dialog.id,
                    value: dialog.value.clone(),
                }
            }
            (dialog, DialogAction::Cancel { .. }) => DialogOutcome::Cancelled {
                dialog_id: dialog.id(),
            },
            (
                DialogState::DangerousConfirm(dialog),
                DialogAction::ConfirmDangerous { operation_id, .. },
            ) => {
                if dialog.operation_id != operation_id {
                    return Err(DialogError::OperationIdMismatch);
                }
                DialogOutcome::DangerousApproved {
                    dialog_id: dialog.id,
                    operation_id,
                }
            }
            _ => return Err(DialogError::ActionTypeMismatch),
        };

        self.active = None;
        self.outcomes.push_back(outcome.clone());
        Ok(outcome)
    }

    pub fn take_outcome(&mut self) -> Option<DialogOutcome> {
        self.outcomes.pop_front()
    }

    fn next_id(&mut self) -> DialogId {
        self.next_id = self.next_id.wrapping_add(1).max(1);
        DialogId(self.next_id)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotificationSeverity {
    Info,
    Success,
    Warning,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NotificationId(u64);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Notification {
    pub id: NotificationId,
    pub key: String,
    pub severity: NotificationSeverity,
    pub message: String,
    pub expires_at_ms: Option<u64>,
}

#[derive(Debug, Default)]
pub struct NotificationCenter {
    next_id: u64,
    queue: VecDeque<Notification>,
}

impl NotificationCenter {
    pub fn notifications(&self) -> impl DoubleEndedIterator<Item = &Notification> {
        self.queue.iter()
    }

    pub fn push_persistent(
        &mut self,
        key: impl Into<String>,
        severity: NotificationSeverity,
        message: impl Into<String>,
    ) -> NotificationId {
        self.push(key.into(), severity, message.into(), None)
    }

    pub fn push_timed(
        &mut self,
        key: impl Into<String>,
        severity: NotificationSeverity,
        message: impl Into<String>,
        now_ms: u64,
        timeout_ms: u64,
    ) -> NotificationId {
        self.push(
            key.into(),
            severity,
            message.into(),
            Some(now_ms.saturating_add(timeout_ms)),
        )
    }

    pub fn push_toast(
        &mut self,
        key: impl Into<String>,
        severity: NotificationSeverity,
        message: impl Into<String>,
    ) -> NotificationId {
        self.push_timed(
            key,
            severity,
            message,
            notification_clock_ms(),
            toast_timeout_ms(severity),
        )
    }

    pub fn dismiss(&mut self, id: NotificationId) -> bool {
        let initial_len = self.queue.len();
        self.queue.retain(|notification| notification.id != id);
        self.queue.len() != initial_len
    }

    pub fn expire(&mut self, now_ms: u64) -> bool {
        let initial_len = self.queue.len();
        self.queue.retain(|notification| {
            notification
                .expires_at_ms
                .is_none_or(|expires_at_ms| expires_at_ms > now_ms)
        });
        self.queue.len() != initial_len
    }

    fn push(
        &mut self,
        key: String,
        severity: NotificationSeverity,
        message: String,
        expires_at_ms: Option<u64>,
    ) -> NotificationId {
        let key = bounded_key(key);
        let message = bounded_text(message, MAX_NOTIFICATION_MESSAGE_BYTES);
        if let Some(existing) = self
            .queue
            .iter_mut()
            .find(|notification| notification.key == key)
        {
            existing.severity = severity;
            existing.message = message;
            existing.expires_at_ms = expires_at_ms;
            return existing.id;
        }

        self.next_id = self.next_id.wrapping_add(1).max(1);
        let id = NotificationId(self.next_id);
        if self.queue.len() == MAX_NOTIFICATIONS {
            if let Some(index) = self
                .queue
                .iter()
                .position(|notification| notification.expires_at_ms.is_some())
            {
                self.queue.remove(index);
            } else {
                self.queue.pop_front();
            }
        }
        self.queue.push_back(Notification {
            id,
            key,
            severity,
            message,
            expires_at_ms,
        });
        id
    }
}

pub fn notification_clock_ms() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START
        .get_or_init(Instant::now)
        .elapsed()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

const fn toast_timeout_ms(severity: NotificationSeverity) -> u64 {
    match severity {
        NotificationSeverity::Error => ERROR_TOAST_TIMEOUT_MS,
        NotificationSeverity::Info
        | NotificationSeverity::Success
        | NotificationSeverity::Warning => DEFAULT_TOAST_TIMEOUT_MS,
    }
}

fn bounded_key(value: String) -> String {
    let sanitized = value
        .chars()
        .map(|character| {
            if character.is_control() {
                '�'
            } else {
                character
            }
        })
        .collect();
    bounded_text(sanitized, MAX_NOTIFICATION_KEY_BYTES)
}

fn bounded_text(mut value: String, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value;
    }
    let mut boundary = max_bytes;
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value.truncate(boundary);
    value
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CompetitionTarget {
    Page(PageId),
    Sftp,
}

pub const COMPETITION_SHORTCUTS: [(CompetitionTarget, &str); 8] = [
    (CompetitionTarget::Page(PageId::SecurityReference), "Ctrl+1"),
    (CompetitionTarget::Page(PageId::SystemInfo), "Ctrl+2"),
    (CompetitionTarget::Sftp, "Ctrl+3"),
    (CompetitionTarget::Page(PageId::Docker), "Ctrl+4"),
    (CompetitionTarget::Page(PageId::EmergencyCommands), "Ctrl+5"),
    (CompetitionTarget::Page(PageId::PacketCapture), "Ctrl+6"),
    (CompetitionTarget::Page(PageId::QuickDetection), "Ctrl+7"),
    (CompetitionTarget::Page(PageId::LogAnalysis), "Ctrl+8"),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SettingsDraft {
    pub theme: ThemeId,
    pub compact_mode: bool,
}

#[derive(Debug, Default)]
pub struct SettingsOverlayModel {
    draft: Option<SettingsDraft>,
}

impl SettingsOverlayModel {
    pub const fn draft(&self) -> Option<SettingsDraft> {
        self.draft
    }

    pub const fn is_open(&self) -> bool {
        self.draft.is_some()
    }

    pub fn open(&mut self, theme: ThemeId, compact_mode: bool) {
        self.draft = Some(SettingsDraft {
            theme,
            compact_mode,
        });
    }

    pub fn select_theme(&mut self, theme: ThemeId) {
        if let Some(draft) = self.draft.as_mut() {
            draft.theme = theme;
        }
    }

    pub fn toggle_compact_mode(&mut self) {
        if let Some(draft) = self.draft.as_mut() {
            draft.compact_mode = !draft.compact_mode;
        }
    }

    pub fn mark_saved(&mut self) {
        self.draft = None;
    }

    pub fn cancel(&mut self) {
        self.draft = None;
    }
}

#[derive(Debug, Default)]
pub struct UiInteractions {
    pub dialogs: DialogHost,
    pub notifications: NotificationCenter,
    pub settings: SettingsOverlayModel,
    focus: FocusTarget,
}

impl UiInteractions {
    pub const fn focus_target(&self) -> FocusTarget {
        self.focus
    }

    pub fn open_settings(&mut self, theme: ThemeId, compact_mode: bool) -> bool {
        if self.dialogs.active().is_some() {
            return false;
        }
        self.settings.open(theme, compact_mode);
        self.focus = FocusTarget::SettingsPanel;
        true
    }

    pub fn focus_dialog(&mut self) {
        self.focus = FocusTarget::Dialog;
    }

    pub fn close_top_overlay(&mut self) -> bool {
        if let Some(dialog) = self.dialogs.active() {
            let dialog_id = dialog.id();
            if self
                .dialogs
                .dispatch(DialogAction::Cancel { dialog_id })
                .is_ok()
            {
                self.focus = FocusTarget::Workspace;
                return true;
            }
        }
        if self.settings.is_open() {
            self.settings.cancel();
            self.focus = FocusTarget::Workspace;
            return true;
        }
        false
    }

    pub fn mark_overlay_closed(&mut self) {
        self.focus = FocusTarget::Workspace;
    }
}

#[cfg(test)]
mod tests {
    use gpui::TestAppContext;
    use lovelyres_core::{
        operations::OperationPlan,
        target::{TargetGuard, TargetIdentity},
    };

    use super::*;

    fn dangerous_plan() -> OperationPlan {
        OperationPlan::new(
            TargetGuard {
                identity: TargetIdentity::new("server-a").unwrap(),
                generation: 4,
            },
            "remove the compromised firewall rule",
            true,
            Some("restore the previous firewall rule".to_owned()),
        )
        .unwrap()
    }

    #[test]
    fn palette_is_derived_from_exactly_eighteen_page_descriptors() {
        assert_eq!(PageId::ALL.len(), 20);
        assert_eq!(
            PageId::ALL
                .iter()
                .map(|page| page.descriptor().title)
                .collect::<std::collections::HashSet<_>>()
                .len(),
            PageId::ALL.len()
        );
    }

    #[test]
    fn palette_competition_shortcuts_are_unique_contiguous_and_include_sftp() {
        assert_eq!(
            COMPETITION_SHORTCUTS
                .iter()
                .map(|(_, shortcut)| *shortcut)
                .collect::<Vec<_>>(),
            vec![
                "Ctrl+1", "Ctrl+2", "Ctrl+3", "Ctrl+4", "Ctrl+5", "Ctrl+6", "Ctrl+7", "Ctrl+8",
            ]
        );
        assert_eq!(COMPETITION_SHORTCUTS[2].0, CompetitionTarget::Sftp);
        assert_eq!(
            COMPETITION_SHORTCUTS
                .iter()
                .map(|(target, _)| target)
                .collect::<std::collections::HashSet<_>>()
                .len(),
            COMPETITION_SHORTCUTS.len()
        );
    }

    #[test]
    fn palette_command_workbench_result_is_navigation_only() {
        assert_eq!(
            COMPETITION_SHORTCUTS[4],
            (CompetitionTarget::Page(PageId::EmergencyCommands), "Ctrl+5")
        );
    }

    #[test]
    fn notification_keys_are_deduplicated_and_can_be_closed_manually() {
        let mut center = NotificationCenter::default();
        let first = center.push_persistent("ssh-status", NotificationSeverity::Info, "connecting");
        let duplicate =
            center.push_persistent("ssh-status", NotificationSeverity::Success, "connected");
        assert_eq!(first, duplicate);
        assert_eq!(center.notifications().count(), 1);
        assert_eq!(center.notifications().next().unwrap().message, "connected");
        assert!(center.dismiss(first));
        assert_eq!(center.notifications().count(), 0);
    }

    #[test]
    fn timed_notifications_expire_against_a_pure_model_clock() {
        let mut center = NotificationCenter::default();
        center.push_timed("one", NotificationSeverity::Info, "one", 100, 50);
        center.push_timed("two", NotificationSeverity::Info, "two", 100, 100);
        center.expire(150);
        assert_eq!(center.notifications().count(), 1);
        assert_eq!(center.notifications().next().unwrap().key, "two");
    }

    #[test]
    fn replacing_a_timed_notification_reuses_its_id_and_extends_its_deadline() {
        let mut center = NotificationCenter::default();
        let original = center.push_timed(
            "ssh-status",
            NotificationSeverity::Info,
            "connecting",
            100,
            50,
        );
        let replacement = center.push_timed(
            "ssh-status",
            NotificationSeverity::Success,
            "connected",
            140,
            100,
        );

        assert_eq!(replacement, original);
        assert!(!center.expire(150));
        let notification = center.notifications().next().unwrap();
        assert_eq!(notification.message, "connected");
        assert_eq!(notification.expires_at_ms, Some(240));
        assert!(center.expire(240));
        assert_eq!(center.notifications().count(), 0);
    }

    #[test]
    fn toast_lifetime_matches_legacy_three_and_five_second_contract() {
        let mut center = NotificationCenter::default();
        let before = notification_clock_ms();
        center.push_toast("info", NotificationSeverity::Info, "info");
        center.push_toast("error", NotificationSeverity::Error, "error");
        let after = notification_clock_ms();

        let info_expiry = center
            .notifications()
            .find(|notification| notification.key == "info")
            .and_then(|notification| notification.expires_at_ms)
            .unwrap();
        let error_expiry = center
            .notifications()
            .find(|notification| notification.key == "error")
            .and_then(|notification| notification.expires_at_ms)
            .unwrap();
        assert!(
            (before + DEFAULT_TOAST_TIMEOUT_MS..=after + DEFAULT_TOAST_TIMEOUT_MS)
                .contains(&info_expiry)
        );
        assert!(
            (before + ERROR_TOAST_TIMEOUT_MS..=after + ERROR_TOAST_TIMEOUT_MS)
                .contains(&error_expiry)
        );
    }

    #[test]
    fn notification_flood_is_bounded_and_evicts_old_timed_items_first() {
        let mut center = NotificationCenter::default();
        center.push_timed(
            "old-timed",
            NotificationSeverity::Info,
            "temporary",
            0,
            10_000,
        );
        for index in 0..(MAX_NOTIFICATIONS - 1) {
            center.push_persistent(
                format!("persistent-{index}"),
                NotificationSeverity::Warning,
                "retained",
            );
        }
        center.push_persistent("new", NotificationSeverity::Success, "new");

        assert_eq!(center.notifications().count(), MAX_NOTIFICATIONS);
        assert!(
            center
                .notifications()
                .all(|notification| notification.key != "old-timed")
        );
    }

    #[test]
    fn hostile_notification_and_dialog_text_is_utf8_safely_bounded() {
        let hostile = "中".repeat(10_000);
        let mut center = NotificationCenter::default();
        let id = center.push_persistent(
            format!("key\n{}", "x".repeat(1_000)),
            NotificationSeverity::Error,
            hostile.clone(),
        );
        let replacement = center.push_persistent(
            format!("key�{}", "x".repeat(1_000)),
            NotificationSeverity::Info,
            hostile.clone(),
        );
        assert_eq!(id, replacement);
        let notification = center.notifications().next().unwrap();
        assert!(notification.key.len() <= MAX_NOTIFICATION_KEY_BYTES);
        assert!(notification.message.len() <= MAX_NOTIFICATION_MESSAGE_BYTES);
        assert!(
            notification
                .message
                .is_char_boundary(notification.message.len())
        );

        let mut dialogs = DialogHost::default();
        dialogs.show_prompt(hostile.clone(), hostile.clone(), hostile.clone());
        let DialogState::Prompt(prompt) = dialogs.active().unwrap() else {
            panic!("expected prompt");
        };
        assert!(prompt.title.len() <= MAX_DIALOG_TITLE_BYTES);
        assert!(prompt.message.len() <= MAX_DIALOG_MESSAGE_BYTES);
        assert!(prompt.value.len() <= MAX_PROMPT_VALUE_BYTES);
    }

    #[test]
    fn dangerous_confirmation_is_bound_to_the_plan_id_and_summary() {
        let plan = dangerous_plan();
        let mut host = DialogHost::default();
        let dialog_id = host.show_dangerous(&plan).unwrap();
        let DialogState::DangerousConfirm(dialog) = host.active().unwrap() else {
            panic!("expected dangerous confirmation");
        };
        assert_eq!(dialog.operation_id, plan.id);
        assert_eq!(dialog.summary, plan.summary);

        assert_eq!(
            host.dispatch(DialogAction::SubmitPrompt { dialog_id }),
            Err(DialogError::ActionTypeMismatch)
        );
        assert_eq!(
            host.dispatch(DialogAction::ConfirmDangerous {
                dialog_id,
                operation_id: "different-plan".to_owned(),
            }),
            Err(DialogError::OperationIdMismatch)
        );
        assert!(host.active().is_some());
        assert_eq!(
            host.dispatch(DialogAction::ConfirmDangerous {
                dialog_id,
                operation_id: plan.id.clone(),
            })
            .unwrap(),
            DialogOutcome::DangerousApproved {
                dialog_id,
                operation_id: plan.id,
            }
        );
    }

    #[gpui::test]
    fn overlay_shortcuts_have_explicit_focus_and_close_paths(_cx: &mut TestAppContext) {
        let mut interactions = UiInteractions::default();
        assert!(interactions.open_settings(ThemeId::Sakura, false));
        assert_eq!(interactions.focus_target(), FocusTarget::SettingsPanel);
        interactions.settings.toggle_compact_mode();
        assert_eq!(
            interactions.settings.draft(),
            Some(SettingsDraft {
                theme: ThemeId::Sakura,
                compact_mode: true,
            })
        );
        assert!(interactions.close_top_overlay());
        assert_eq!(interactions.focus_target(), FocusTarget::Workspace);
    }

    #[test]
    fn closing_a_dangerous_dialog_records_cancellation_not_approval() {
        let plan = dangerous_plan();
        let mut interactions = UiInteractions::default();
        let dialog_id = interactions.dialogs.show_dangerous(&plan).unwrap();
        interactions.focus_dialog();
        assert!(interactions.close_top_overlay());
        assert_eq!(
            interactions.dialogs.take_outcome(),
            Some(DialogOutcome::Cancelled { dialog_id })
        );
    }

    #[test]
    fn settings_remain_open_beneath_a_dangerous_confirmation() {
        let plan = dangerous_plan();
        let mut interactions = UiInteractions::default();
        assert!(interactions.open_settings(ThemeId::Dark, false));
        let dialog_id = interactions.dialogs.show_dangerous(&plan).unwrap();
        interactions.focus_dialog();

        assert!(interactions.settings.is_open());
        assert!(interactions.close_top_overlay());
        assert_eq!(
            interactions.dialogs.take_outcome(),
            Some(DialogOutcome::Cancelled { dialog_id })
        );
        assert!(interactions.settings.is_open());
        assert!(interactions.close_top_overlay());
        assert!(!interactions.settings.is_open());
    }
}
