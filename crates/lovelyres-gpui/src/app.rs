use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::Duration,
};

use anyhow::Result;
#[cfg(not(target_os = "windows"))]
use gpui::WindowControlArea;
use gpui::{
    AnyElement, AnyView, App, Application, ClipboardItem, Context, Entity, FocusHandle, KeyBinding,
    MouseButton, Render, RenderImage, SharedString, Subscription, Timer, Window, actions, div, img,
    prelude::*, px,
};
use gpui_component::{
    Icon, IconName, Root, Selectable, Sizable, Theme, ThemeMode,
    button::ButtonVariants,
    input::{Input, InputEvent, InputState},
    scroll::ScrollableElement,
};
use lovelyres_core::{BackendServices, PortableStore, settings::AppSettings, ssh::BoundSshSession};
#[cfg(target_os = "windows")]
use raw_window_handle::{HasWindowHandle, RawWindowHandle};
#[cfg(target_os = "windows")]
use windows::Win32::{
    Foundation::{HWND, LPARAM, WPARAM},
    UI::{
        Input::KeyboardAndMouse::ReleaseCapture,
        WindowsAndMessaging::{
            HTCAPTION, PostMessageW, SC_MOVE, SHOW_WINDOW_CMD, SW_MAXIMIZE, SW_RESTORE,
            ShowWindowAsync, WM_SYSCOMMAND,
        },
    },
};

use crate::{
    ai_history::AiHistoryPage,
    assets::{Assets, embedded_brand_logo, embedded_fonts},
    baseline::BaselinePage,
    batch_servers::BatchServersPage,
    check_audit::CheckAuditPage,
    command_history::{CommandHistoryEvent, CommandHistoryOverlay},
    command_workbench::CommandWorkbenchPage,
    config_generator::ConfigGeneratorPage,
    connection_ui::{ConnectionManager, ConnectionManagerEvent},
    container_terminal::{ContainerTerminalLaunch, ContainerTerminalWindow},
    database::DatabasePage,
    diagnostics::{self, FeasibilityRequest},
    disposal_report::{DisposalReportEvent, DisposalReportOverlay},
    docker::{DockerPage, OpenContainerTerminal},
    firewall::FirewallPage,
    integrity::{IntegrityPage, OpenIntegrityInSftp},
    interaction::{
        COMPETITION_SHORTCUTS, CompetitionTarget, DialogAction, DialogOutcome, DialogState,
        Notification, NotificationId, NotificationSeverity, UiInteractions, notification_clock_ms,
    },
    java::JavaHotUpdatePage,
    kubernetes::KubernetesPage,
    log_analysis::LogAnalysisPage,
    logging::{self, LogGuard},
    middleware::MiddlewarePage,
    notes::NotesPage,
    packet_capture::PacketCapturePage,
    pages::{CapabilityRequirement, PageGroup, PageHost, PageId, PageModel, PendingPageModel},
    portable::write_requested_smoke_marker,
    quick_detection::QuickDetectionPage,
    runtime::TokioBridge,
    security_reference::SecurityReferencePage,
    settings_panel::{SettingsPanel, SettingsPanelEvent},
    sftp::{OpenDirectoryTerminalIntent, SftpNavigator},
    snapshot::SnapshotPage,
    system_info::SystemInfoPage,
    theme::{ThemeId, apply_component_theme},
    windows::{
        NativeWindowKind, NativeWindowRegistry, SecondaryWindow, WindowLifecycle,
        main_window_options, secondary_window_options,
    },
};

#[derive(Clone, Debug)]
pub struct ActiveSshTarget {
    pub connection_id: Arc<str>,
    pub session: BoundSshSession,
    pub label: SharedString,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkspaceRoute {
    ConnectionLanding,
    Page(PageId),
}

const fn workspace_route(target_ready: bool, page: PageId) -> WorkspaceRoute {
    if target_ready
        || matches!(
            page.descriptor().capability,
            CapabilityRequirement::LocalWorkspace | CapabilityRequirement::OptionalAi
        )
    {
        WorkspaceRoute::Page(page)
    } else {
        WorkspaceRoute::ConnectionLanding
    }
}

actions!(
    lovelyres,
    [
        ToggleSidebar,
        CycleTheme,
        OpenCommandHistory,
        OpenDisposalReport,
        OpenApplicationLog,
        OpenSettings,
        CloseOverlay,
        OpenSshTerminal,
        OpenSftpWindow,
        CompetitionShortcut1,
        CompetitionShortcut2,
        CompetitionShortcut3,
        CompetitionShortcut4,
        CompetitionShortcut5,
        CompetitionShortcut6,
        CompetitionShortcut7,
        CompetitionShortcut8
    ]
);

pub struct SharedAppState {
    pub pages: PageHost,
    pub theme: ThemeId,
    pub sidebar_collapsed: bool,
    pub interactions: UiInteractions,
    pub target_label: SharedString,
    pub active_ssh: Option<ActiveSshTarget>,
    pub windows: NativeWindowRegistry,
    directory_terminal_requests: VecDeque<OpenDirectoryTerminalIntent>,
}

impl Default for SharedAppState {
    fn default() -> Self {
        Self {
            pages: PageHost::new(PageId::SystemInfo),
            theme: ThemeId::Dark,
            sidebar_collapsed: false,
            interactions: UiInteractions::default(),
            target_label: "未连接目标".into(),
            active_ssh: None,
            windows: NativeWindowRegistry::default(),
            directory_terminal_requests: VecDeque::new(),
        }
    }
}

impl SharedAppState {
    fn from_settings(settings: &AppSettings) -> Self {
        Self {
            theme: settings.theme.into(),
            sidebar_collapsed: settings.ui.compact_mode,
            ..Self::default()
        }
    }

    pub(crate) fn queue_directory_terminal(&mut self, intent: OpenDirectoryTerminalIntent) -> bool {
        const MAX_PENDING_DIRECTORY_TERMINALS: usize = 8;
        if self.directory_terminal_requests.len() >= MAX_PENDING_DIRECTORY_TERMINALS {
            return false;
        }
        self.directory_terminal_requests.push_back(intent);
        true
    }

    pub(crate) fn has_directory_terminal_for(
        &self,
        target: &lovelyres_core::target::TargetGuard,
    ) -> bool {
        self.directory_terminal_requests
            .iter()
            .any(|request| &request.target == target)
    }

    pub(crate) fn take_directory_terminals_for(
        &mut self,
        target: &lovelyres_core::target::TargetGuard,
    ) -> Vec<OpenDirectoryTerminalIntent> {
        std::mem::take(&mut self.directory_terminal_requests)
            .into_iter()
            .filter(|request| &request.target == target)
            .collect()
    }
}

pub struct AppShell {
    shared: Entity<SharedAppState>,
    _services: Arc<BackendServices>,
    _tokio: Arc<TokioBridge>,
    logging: Arc<LogGuard>,
    brand_logo: Arc<RenderImage>,
    connections: Entity<ConnectionManager>,
    security_reference: Entity<SecurityReferencePage>,
    notes: Entity<NotesPage>,
    ai_history: Entity<AiHistoryPage>,
    settings: Entity<SettingsPanel>,
    system_info: Entity<SystemInfoPage>,
    docker: Entity<DockerPage>,
    kubernetes: Entity<KubernetesPage>,
    quick_detection: Entity<QuickDetectionPage>,
    command_workbench: Entity<CommandWorkbenchPage>,
    log_analysis: Entity<LogAnalysisPage>,
    packet_capture: Entity<PacketCapturePage>,
    integrity: Entity<IntegrityPage>,
    check_audit: Entity<CheckAuditPage>,
    database: Entity<DatabasePage>,
    middleware: Entity<MiddlewarePage>,
    config_generator: Entity<ConfigGeneratorPage>,
    firewall: Entity<FirewallPage>,
    snapshot: Entity<SnapshotPage>,
    baseline: Entity<BaselinePage>,
    java: Entity<JavaHotUpdatePage>,
    batch_servers: Entity<BatchServersPage>,
    sftp_navigator: Entity<SftpNavigator>,
    command_history: Entity<CommandHistoryOverlay>,
    disposal_report: Entity<DisposalReportOverlay>,
    command_history_open: bool,
    disposal_report_open: bool,
    application_log_open: bool,
    scheduled_notification_expirations: HashMap<NotificationId, u64>,
    prompt_input: Entity<InputState>,
    workspace_focus: FocusHandle,
    _interaction_subscriptions: Vec<Subscription>,
    _release_subscription: Subscription,
}

impl AppShell {
    fn new(
        shared: Entity<SharedAppState>,
        services: Arc<BackendServices>,
        tokio: Arc<TokioBridge>,
        logging: Arc<LogGuard>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let brand_logo = embedded_brand_logo()
            .to_image_data(cx.svg_renderer())
            .expect("the checked-in LovelyRes brand PNG must decode");
        cx.observe(&shared, |shell, _, cx| {
            shell.schedule_notification_expirations(cx);
            shell.ensure_directory_terminal_window(cx);
            cx.notify();
        })
        .detach();
        let connections = cx.new(|cx| {
            ConnectionManager::new(services.clone(), tokio.clone(), shared.clone(), window, cx)
        });
        let security_reference =
            cx.new(|cx| SecurityReferencePage::new(services.clone(), shared.clone(), window, cx));
        let notes = cx
            .new(|cx| NotesPage::new(services.clone(), tokio.clone(), shared.clone(), window, cx));
        let ai_history = cx.new(|cx| {
            AiHistoryPage::new(services.clone(), tokio.clone(), shared.clone(), window, cx)
        });
        let settings = cx.new(|cx| {
            SettingsPanel::new(services.clone(), tokio.clone(), shared.clone(), window, cx)
        });
        let system_info = cx.new(|cx| {
            SystemInfoPage::new(services.clone(), tokio.clone(), shared.clone(), window, cx)
        });
        let docker = cx
            .new(|cx| DockerPage::new(services.clone(), tokio.clone(), shared.clone(), window, cx));
        let kubernetes = cx.new(|cx| {
            KubernetesPage::new(services.clone(), tokio.clone(), shared.clone(), window, cx)
        });
        let quick_detection = cx.new(|cx| {
            QuickDetectionPage::new(services.clone(), tokio.clone(), shared.clone(), window, cx)
        });
        let command_workbench = cx.new(|cx| {
            CommandWorkbenchPage::new(services.clone(), tokio.clone(), shared.clone(), window, cx)
        });
        let log_analysis = cx.new(|cx| {
            LogAnalysisPage::new(services.clone(), tokio.clone(), shared.clone(), window, cx)
        });
        let packet_capture = cx.new(|cx| {
            PacketCapturePage::new(services.clone(), tokio.clone(), shared.clone(), window, cx)
        });
        let integrity = cx.new(|cx| {
            IntegrityPage::new(services.clone(), tokio.clone(), shared.clone(), window, cx)
        });
        let check_audit = cx.new(|cx| {
            CheckAuditPage::new(services.clone(), tokio.clone(), shared.clone(), window, cx)
        });
        let database = cx.new(|cx| {
            DatabasePage::new(services.clone(), tokio.clone(), shared.clone(), window, cx)
        });
        let middleware = cx.new(|cx| {
            MiddlewarePage::new(services.clone(), tokio.clone(), shared.clone(), window, cx)
        });
        let config_generator = cx.new(|cx| {
            ConfigGeneratorPage::new(services.clone(), tokio.clone(), shared.clone(), window, cx)
        });
        let firewall = cx.new(|cx| {
            FirewallPage::new(services.clone(), tokio.clone(), shared.clone(), window, cx)
        });
        let snapshot = cx.new(|cx| {
            SnapshotPage::new(services.clone(), tokio.clone(), shared.clone(), window, cx)
        });
        let baseline = cx.new(|cx| {
            BaselinePage::new(services.clone(), tokio.clone(), shared.clone(), window, cx)
        });
        let java = cx.new(|cx| {
            JavaHotUpdatePage::new(services.clone(), tokio.clone(), shared.clone(), window, cx)
        });
        let batch_servers = cx.new(|cx| {
            BatchServersPage::new(services.clone(), tokio.clone(), shared.clone(), window, cx)
        });
        let sftp_navigator = cx.new(|_| SftpNavigator::default());
        let command_history = cx.new(|cx| {
            CommandHistoryOverlay::new(services.clone(), tokio.clone(), shared.clone(), window, cx)
        });
        let disposal_report = cx.new(|cx| {
            DisposalReportOverlay::new(services.clone(), tokio.clone(), shared.clone(), cx)
        });
        if shared.read(cx).active_ssh.is_some() {
            system_info.update(cx, |page, cx| page.activate(window, cx));
        }
        let prompt_input = cx.new(|cx| InputState::new(window, cx).placeholder("请输入内容…"));
        let interaction_subscriptions = vec![
            cx.subscribe_in(
                &connections,
                window,
                |shell, _, event: &ConnectionManagerEvent, window, cx| match event {
                    ConnectionManagerEvent::TargetReady => {
                        shell.activate_page(PageId::SystemInfo, window, cx);
                    }
                },
            ),
            cx.subscribe_in(
                &prompt_input,
                window,
                |shell, input, event: &InputEvent, window, cx| {
                    shell.on_prompt_input(input, event, window, cx);
                },
            ),
            cx.subscribe_in(
                &settings,
                window,
                |shell, _, event: &SettingsPanelEvent, window, cx| {
                    shell.on_settings_panel_event(event, window, cx);
                },
            ),
            cx.subscribe_in(
                &command_history,
                window,
                |shell, _, event: &CommandHistoryEvent, window, cx| match event {
                    CommandHistoryEvent::CloseRequested => {
                        shell.dismiss_command_history(window, cx);
                    }
                },
            ),
            cx.subscribe_in(
                &disposal_report,
                window,
                |shell, _, event: &DisposalReportEvent, window, cx| match event {
                    DisposalReportEvent::CloseRequested => {
                        shell.dismiss_disposal_report(window, cx);
                    }
                },
            ),
            cx.subscribe_in(
                &docker,
                window,
                |shell, _, event: &OpenContainerTerminal, _, cx| {
                    shell.open_container_terminal(event.launch().clone(), cx);
                },
            ),
            cx.subscribe_in(
                &integrity,
                window,
                |shell, _, event: &OpenIntegrityInSftp, window, cx| {
                    shell.sftp_navigator.update(cx, |navigator, cx| {
                        navigator.bind_target(
                            event.target().clone(),
                            event.directory().clone(),
                            cx,
                        );
                    });
                    shell.open_sftp(&OpenSftpWindow, window, cx);
                },
            ),
        ];
        let workspace_focus = cx.focus_handle();
        let closing_shared = shared.clone();
        window.on_window_should_close(cx, move |_, cx| {
            closing_shared.update(cx, |state, cx| {
                state.windows.begin_close(&NativeWindowKind::Main);
                cx.notify();
            });
            true
        });
        let release_subscription = cx.on_release(|shell: &mut Self, cx| {
            shell
                .packet_capture
                .update(cx, |page, cx| page.deactivate(cx));
            shell.integrity.update(cx, |page, cx| page.deactivate(cx));
            shell.check_audit.update(cx, |page, cx| page.deactivate(cx));
            shell.database.update(cx, |page, cx| page.deactivate(cx));
            shell.middleware.update(cx, |page, cx| page.deactivate(cx));
            shell
                .config_generator
                .update(cx, |page, cx| page.deactivate(cx));
            shell.firewall.update(cx, |page, cx| page.deactivate(cx));
            shell.snapshot.update(cx, |page, cx| page.deactivate(cx));
            shell.baseline.update(cx, |page, cx| page.deactivate(cx));
            shell.java.update(cx, |page, cx| page.deactivate(cx));
            shell
                .batch_servers
                .update(cx, |page, cx| page.deactivate(cx));
            shell
                .command_workbench
                .update(cx, |page, cx| page.deactivate(cx));
            shell
                .command_history
                .update(cx, |history, cx| history.deactivate(cx));
            shell
                .disposal_report
                .update(cx, |report, cx| report.deactivate(cx));
            shell.shared.update(cx, |state, cx| {
                state.windows.mark_closed(&NativeWindowKind::Main);
                cx.notify();
            });
        });
        Self {
            shared,
            _services: services,
            _tokio: tokio,
            logging,
            brand_logo,
            connections,
            security_reference,
            notes,
            ai_history,
            settings,
            system_info,
            docker,
            kubernetes,
            quick_detection,
            command_workbench,
            log_analysis,
            packet_capture,
            integrity,
            check_audit,
            database,
            middleware,
            config_generator,
            firewall,
            snapshot,
            baseline,
            java,
            batch_servers,
            sftp_navigator,
            command_history,
            disposal_report,
            command_history_open: false,
            disposal_report_open: false,
            application_log_open: false,
            scheduled_notification_expirations: HashMap::new(),
            prompt_input,
            workspace_focus,
            _interaction_subscriptions: interaction_subscriptions,
            _release_subscription: release_subscription,
        }
    }

    fn activate_page(&mut self, page: PageId, window: &mut Window, cx: &mut Context<Self>) {
        let target_ready = self.shared.read(cx).active_ssh.is_some();
        if workspace_route(target_ready, page) == WorkspaceRoute::ConnectionLanding {
            self.workspace_focus.focus(window);
            return;
        }
        self.dismiss_command_history(window, cx);
        self.dismiss_disposal_report(window, cx);
        self.dismiss_application_log(window, cx);
        self.dismiss_settings(window, cx);
        let previous = self.shared.read(cx).pages.active();
        self.shared.update(cx, |state, cx| {
            state.pages.activate(page);
            state.interactions.settings.cancel();
            state.interactions.mark_overlay_closed();
            cx.notify();
        });
        if previous == PageId::SecurityReference && page != PageId::SecurityReference {
            self.security_reference
                .update(cx, |page, cx| page.deactivate(cx));
        }
        if previous == PageId::Notes && page != PageId::Notes {
            self.notes.update(cx, |page, cx| page.deactivate(cx));
            self.drain_dialog_outcomes(window, cx);
        }
        if previous == PageId::AiHistory && page != PageId::AiHistory {
            self.ai_history.update(cx, |page, cx| page.deactivate(cx));
            self.drain_dialog_outcomes(window, cx);
        }
        if previous == PageId::SystemInfo && page != PageId::SystemInfo {
            self.system_info.update(cx, |page, cx| page.deactivate(cx));
        }
        if previous == PageId::Docker && page != PageId::Docker {
            self.docker.update(cx, |page, cx| page.deactivate(cx));
        }
        if previous == PageId::Kubernetes && page != PageId::Kubernetes {
            self.kubernetes.update(cx, |page, cx| page.deactivate(cx));
        }
        if previous == PageId::QuickDetection && page != PageId::QuickDetection {
            self.quick_detection
                .update(cx, |page, cx| page.deactivate(cx));
        }
        if previous == PageId::LogAnalysis && page != PageId::LogAnalysis {
            self.log_analysis.update(cx, |page, cx| page.deactivate(cx));
        }
        if previous == PageId::PacketCapture && page != PageId::PacketCapture {
            self.packet_capture
                .update(cx, |page, cx| page.deactivate(cx));
        }
        if previous == PageId::Integrity && page != PageId::Integrity {
            self.integrity.update(cx, |page, cx| page.deactivate(cx));
        }
        if previous == PageId::CheckAudit && page != PageId::CheckAudit {
            self.check_audit.update(cx, |page, cx| page.deactivate(cx));
        }
        if previous == PageId::Database && page != PageId::Database {
            self.database.update(cx, |page, cx| page.deactivate(cx));
        }
        if previous == PageId::Middleware && page != PageId::Middleware {
            self.middleware.update(cx, |page, cx| page.deactivate(cx));
        }
        if previous == PageId::ConfigGenerator && page != PageId::ConfigGenerator {
            self.config_generator
                .update(cx, |page, cx| page.deactivate(cx));
        }
        if previous == PageId::Firewall && page != PageId::Firewall {
            self.firewall.update(cx, |page, cx| page.deactivate(cx));
        }
        if previous == PageId::Snapshot && page != PageId::Snapshot {
            self.snapshot.update(cx, |page, cx| page.deactivate(cx));
        }
        if previous == PageId::BaselineQuickEdit && page != PageId::BaselineQuickEdit {
            self.baseline.update(cx, |page, cx| page.deactivate(cx));
        }
        if previous == PageId::JavaHotUpdate && page != PageId::JavaHotUpdate {
            self.java.update(cx, |page, cx| page.deactivate(cx));
        }
        if previous == PageId::BatchServers && page != PageId::BatchServers {
            self.batch_servers
                .update(cx, |page, cx| page.deactivate(cx));
        }
        if previous == PageId::EmergencyCommands && page != PageId::EmergencyCommands {
            self.command_workbench
                .update(cx, |page, cx| page.deactivate(cx));
        }
        if page == PageId::SecurityReference {
            self.security_reference
                .update(cx, |page, cx| page.activate(window, cx));
        } else if page == PageId::Notes {
            self.notes.update(cx, |page, cx| page.activate(window, cx));
        } else if page == PageId::AiHistory {
            self.ai_history
                .update(cx, |page, cx| page.activate(window, cx));
        } else if page == PageId::SystemInfo {
            self.system_info
                .update(cx, |page, cx| page.activate(window, cx));
        } else if page == PageId::Docker {
            self.docker.update(cx, |page, cx| page.activate(window, cx));
        } else if page == PageId::Kubernetes {
            self.kubernetes
                .update(cx, |page, cx| page.activate(window, cx));
        } else if page == PageId::QuickDetection {
            self.quick_detection
                .update(cx, |page, cx| page.activate(window, cx));
        } else if page == PageId::LogAnalysis {
            self.log_analysis
                .update(cx, |page, cx| page.activate(window, cx));
        } else if page == PageId::PacketCapture {
            self.packet_capture
                .update(cx, |page, cx| page.activate(window, cx));
        } else if page == PageId::Integrity {
            self.integrity
                .update(cx, |page, cx| page.activate(window, cx));
        } else if page == PageId::CheckAudit {
            self.check_audit
                .update(cx, |page, cx| page.activate(window, cx));
        } else if page == PageId::Database {
            self.database
                .update(cx, |page, cx| page.activate(window, cx));
        } else if page == PageId::Middleware {
            self.middleware
                .update(cx, |page, cx| page.activate(window, cx));
        } else if page == PageId::ConfigGenerator {
            self.config_generator
                .update(cx, |page, cx| page.activate(window, cx));
        } else if page == PageId::Firewall {
            self.firewall
                .update(cx, |page, cx| page.activate(window, cx));
        } else if page == PageId::Snapshot {
            self.snapshot
                .update(cx, |page, cx| page.activate(window, cx));
        } else if page == PageId::BaselineQuickEdit {
            self.baseline
                .update(cx, |page, cx| page.activate(window, cx));
        } else if page == PageId::JavaHotUpdate {
            self.java.update(cx, |page, cx| page.activate(window, cx));
        } else if page == PageId::BatchServers {
            self.batch_servers
                .update(cx, |page, cx| page.activate(window, cx));
        } else if page == PageId::EmergencyCommands {
            self.command_workbench
                .update(cx, |page, cx| page.activate(window, cx));
        } else {
            self.workspace_focus.focus(window);
        }
    }

    fn toggle_sidebar(&mut self, _: &ToggleSidebar, _: &mut Window, cx: &mut Context<Self>) {
        self.shared.update(cx, |state, cx| {
            state.sidebar_collapsed = !state.sidebar_collapsed;
            cx.notify();
        });
    }

    fn cycle_theme(&mut self, _: &CycleTheme, window: &mut Window, cx: &mut Context<Self>) {
        let theme = self.shared.read(cx).theme.next();
        self.apply_theme(theme, window, cx);
    }

    fn apply_theme(&mut self, theme: ThemeId, window: &mut Window, cx: &mut Context<Self>) {
        self.shared.update(cx, |state, cx| {
            state.theme = theme;
            cx.notify();
        });
        let component_mode = if theme == ThemeId::Light {
            ThemeMode::Light
        } else {
            ThemeMode::Dark
        };
        Theme::change(component_mode, Some(window), cx);
        apply_component_theme(theme, cx);
        match self._services.settings().update(|settings| {
            settings.theme = theme.into();
            Ok(())
        }) {
            Ok(_) => {}
            Err(error) => tracing::error!(%error, "failed to persist theme setting"),
        }
    }

    fn open_settings(&mut self, _: &OpenSettings, window: &mut Window, cx: &mut Context<Self>) {
        self.dismiss_command_history(window, cx);
        self.dismiss_disposal_report(window, cx);
        self.dismiss_application_log(window, cx);
        let opened = self.shared.update(cx, |state, cx| {
            let theme = state.theme;
            let compact_mode = state.sidebar_collapsed;
            let opened = state.interactions.open_settings(theme, compact_mode);
            cx.notify();
            opened
        });
        if opened {
            self.settings
                .update(cx, |settings, cx| settings.activate(window, cx));
        }
    }

    fn close_overlay(&mut self, _: &CloseOverlay, window: &mut Window, cx: &mut Context<Self>) {
        let dialog_was_open = self.shared.read(cx).interactions.dialogs.active().is_some();
        let settings_was_open = self.shared.read(cx).interactions.settings.is_open();
        let closed = self.shared.update(cx, |state, cx| {
            let closed = state.interactions.close_top_overlay();
            cx.notify();
            closed
        });
        if closed {
            self.drain_dialog_outcomes(window, cx);
            if settings_was_open && !dialog_was_open {
                self.settings
                    .update(cx, |settings, cx| settings.deactivate(cx));
            }
            self.workspace_focus.focus(window);
        } else if !self.dismiss_disposal_report(window, cx)
            && !self.dismiss_application_log(window, cx)
            && !self.dismiss_command_history(window, cx)
        {
        }
    }

    fn open_command_history(
        &mut self,
        _: &OpenCommandHistory,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.shared.read(cx).interactions.dialogs.active().is_some() {
            return;
        }
        self.dismiss_settings(window, cx);
        self.dismiss_disposal_report(window, cx);
        self.dismiss_application_log(window, cx);
        self.shared.update(cx, |state, cx| {
            state.interactions.mark_overlay_closed();
            cx.notify();
        });
        if !self.command_history_open {
            self.command_history_open = true;
            self.command_history
                .update(cx, |history, cx| history.activate(window, cx));
            cx.notify();
        }
    }

    fn dismiss_command_history(&mut self, window: &mut Window, cx: &mut Context<Self>) -> bool {
        if !self.command_history_open {
            return false;
        }
        self.command_history_open = false;
        self.command_history
            .update(cx, |history, cx| history.deactivate(cx));
        self.drain_dialog_outcomes(window, cx);
        self.workspace_focus.focus(window);
        cx.notify();
        true
    }

    fn open_disposal_report(
        &mut self,
        _: &OpenDisposalReport,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.shared.read(cx).interactions.dialogs.active().is_some() {
            return;
        }
        let Some(target) = self
            .shared
            .read(cx)
            .active_ssh
            .as_ref()
            .map(|active| active.session.target().clone())
        else {
            return;
        };
        let detection = self.quick_detection.read(cx).current_report_for(&target);
        self.dismiss_command_history(window, cx);
        self.dismiss_settings(window, cx);
        self.dismiss_application_log(window, cx);
        self.shared.update(cx, |state, cx| {
            state.interactions.mark_overlay_closed();
            cx.notify();
        });
        if !self.disposal_report_open {
            self.disposal_report_open = true;
            self.disposal_report
                .update(cx, |report, cx| report.activate(detection, cx));
            cx.notify();
        }
    }

    fn dismiss_disposal_report(&mut self, window: &mut Window, cx: &mut Context<Self>) -> bool {
        if !self.disposal_report_open {
            return false;
        }
        self.disposal_report_open = false;
        self.disposal_report
            .update(cx, |report, cx| report.deactivate(cx));
        self.workspace_focus.focus(window);
        cx.notify();
        true
    }

    fn open_application_log(
        &mut self,
        _: &OpenApplicationLog,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.shared.read(cx).interactions.dialogs.active().is_some() {
            return;
        }
        self.dismiss_command_history(window, cx);
        self.dismiss_disposal_report(window, cx);
        self.dismiss_settings(window, cx);
        self.shared.update(cx, |state, cx| {
            state.interactions.mark_overlay_closed();
            cx.notify();
        });
        if !self.application_log_open {
            self.application_log_open = true;
            cx.notify();
        }
    }

    fn dismiss_application_log(&mut self, window: &mut Window, cx: &mut Context<Self>) -> bool {
        if !self.application_log_open {
            return false;
        }
        self.application_log_open = false;
        self.workspace_focus.focus(window);
        cx.notify();
        true
    }

    fn copy_application_log(&mut self, cx: &mut Context<Self>) {
        cx.write_to_clipboard(ClipboardItem::new_string(self.logging.export_as_text()));
        self.shared.update(cx, |state, cx| {
            state.interactions.notifications.push_toast(
                "application-log-copied",
                NotificationSeverity::Success,
                "诊断日志已复制",
            );
            cx.notify();
        });
    }

    fn clear_application_log(&mut self, cx: &mut Context<Self>) {
        self.logging.clear();
        cx.notify();
    }

    fn dismiss_settings(&mut self, window: &mut Window, cx: &mut Context<Self>) -> bool {
        if !self.shared.read(cx).interactions.settings.is_open() {
            return false;
        }
        self.shared.update(cx, |state, cx| {
            state.interactions.settings.cancel();
            state.interactions.mark_overlay_closed();
            cx.notify();
        });
        self.settings
            .update(cx, |settings, cx| settings.deactivate(cx));
        self.drain_dialog_outcomes(window, cx);
        self.workspace_focus.focus(window);
        true
    }

    fn on_settings_panel_event(
        &mut self,
        event: &SettingsPanelEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        match event {
            SettingsPanelEvent::CloseRequested => {
                self.dismiss_settings(window, cx);
            }
            SettingsPanelEvent::Saved { settings } => {
                self.logging.set_level(settings.log_level);
                let theme: ThemeId = settings.theme.into();
                self.shared.update(cx, |state, cx| {
                    state.theme = theme;
                    state.sidebar_collapsed = settings.ui.compact_mode;
                    state.interactions.notifications.push_toast(
                        "settings-saved",
                        NotificationSeverity::Success,
                        "设置已保存",
                    );
                    cx.notify();
                });
                let component_mode = if theme == ThemeId::Light {
                    ThemeMode::Light
                } else {
                    ThemeMode::Dark
                };
                Theme::change(component_mode, Some(window), cx);
                apply_component_theme(theme, cx);
                self.dismiss_settings(window, cx);
            }
        }
    }

    fn open_ssh(&mut self, _: &OpenSshTerminal, _: &mut Window, cx: &mut Context<Self>) {
        open_secondary(
            NativeWindowKind::SshTerminal,
            self.shared.clone(),
            self._services.clone(),
            self._tokio.clone(),
            self.sftp_navigator.clone(),
            cx,
        );
    }

    fn ensure_directory_terminal_window(&mut self, cx: &mut Context<Self>) {
        let should_open = {
            let state = self.shared.read(cx);
            state.active_ssh.as_ref().is_some_and(|active| {
                state.has_directory_terminal_for(active.session.target())
                    && state.windows.lifecycle(&NativeWindowKind::SshTerminal)
                        == Some(WindowLifecycle::Closed)
            })
        };
        if should_open {
            open_secondary(
                NativeWindowKind::SshTerminal,
                self.shared.clone(),
                self._services.clone(),
                self._tokio.clone(),
                self.sftp_navigator.clone(),
                cx,
            );
        }
    }

    fn open_sftp(&mut self, _: &OpenSftpWindow, _: &mut Window, cx: &mut Context<Self>) {
        open_secondary(
            NativeWindowKind::Sftp,
            self.shared.clone(),
            self._services.clone(),
            self._tokio.clone(),
            self.sftp_navigator.clone(),
            cx,
        );
    }

    fn activate_competition_target(
        &mut self,
        target: CompetitionTarget,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        match target {
            CompetitionTarget::Page(page) => self.activate_page(page, window, cx),
            CompetitionTarget::Sftp => {
                self.workspace_focus.focus(window);
                self.open_sftp(&OpenSftpWindow, window, cx);
            }
        }
    }

    fn competition_shortcut_1(
        &mut self,
        _: &CompetitionShortcut1,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.activate_competition_target(COMPETITION_SHORTCUTS[0].0, window, cx);
    }

    fn competition_shortcut_2(
        &mut self,
        _: &CompetitionShortcut2,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.activate_competition_target(COMPETITION_SHORTCUTS[1].0, window, cx);
    }

    fn competition_shortcut_3(
        &mut self,
        _: &CompetitionShortcut3,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.activate_competition_target(COMPETITION_SHORTCUTS[2].0, window, cx);
    }

    fn competition_shortcut_4(
        &mut self,
        _: &CompetitionShortcut4,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.activate_competition_target(COMPETITION_SHORTCUTS[3].0, window, cx);
    }

    fn competition_shortcut_5(
        &mut self,
        _: &CompetitionShortcut5,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.activate_competition_target(COMPETITION_SHORTCUTS[4].0, window, cx);
    }

    fn competition_shortcut_6(
        &mut self,
        _: &CompetitionShortcut6,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.activate_competition_target(COMPETITION_SHORTCUTS[5].0, window, cx);
    }

    fn competition_shortcut_7(
        &mut self,
        _: &CompetitionShortcut7,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.activate_competition_target(COMPETITION_SHORTCUTS[6].0, window, cx);
    }

    fn competition_shortcut_8(
        &mut self,
        _: &CompetitionShortcut8,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.activate_competition_target(COMPETITION_SHORTCUTS[7].0, window, cx);
    }

    fn open_container_terminal(&mut self, launch: ContainerTerminalLaunch, cx: &mut Context<Self>) {
        open_container_terminal(
            launch,
            self.shared.clone(),
            self._services.clone(),
            self._tokio.clone(),
            cx,
        );
    }

    fn on_prompt_input(
        &mut self,
        input: &Entity<InputState>,
        event: &InputEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        match event {
            InputEvent::Change => {
                let value = input.read(cx).value().to_string();
                self.shared.update(cx, |state, cx| {
                    let _ = state.interactions.dialogs.update_prompt(value);
                    cx.notify();
                });
            }
            InputEvent::PressEnter { .. } => {
                let action =
                    self.shared
                        .read(cx)
                        .interactions
                        .dialogs
                        .active()
                        .and_then(|dialog| match dialog {
                            DialogState::Prompt(prompt) => Some(DialogAction::SubmitPrompt {
                                dialog_id: prompt.id,
                            }),
                            DialogState::Alert(_) | DialogState::DangerousConfirm(_) => None,
                        });
                if let Some(action) = action {
                    self.dispatch_dialog(action, window, cx);
                }
            }
            InputEvent::Focus | InputEvent::Blur => {}
        }
    }

    fn dispatch_dialog(
        &mut self,
        action: DialogAction,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let result = self.shared.update(cx, |state, cx| {
            let result = state.interactions.dialogs.dispatch(action);
            if result.is_ok() {
                state.interactions.mark_overlay_closed();
            }
            cx.notify();
            result
        });
        if result.is_ok() {
            self.drain_dialog_outcomes(window, cx);
            self.workspace_focus.focus(window);
        } else if let Err(error) = result {
            tracing::error!(?error, "dialog action rejected by typed dialog host");
        }
    }

    fn drain_dialog_outcomes(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        loop {
            let outcome = self
                .shared
                .update(cx, |state, _| state.interactions.dialogs.take_outcome());
            let Some(outcome) = outcome else {
                break;
            };
            self.route_dialog_outcome(&outcome, window, cx);
        }
    }

    fn route_dialog_outcome(
        &mut self,
        outcome: &DialogOutcome,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.notes.update(cx, |notes, cx| {
            let _ = notes.handle_dialog_outcome(outcome, window, cx);
        });
        self.ai_history.update(cx, |page, cx| {
            let _ = page.handle_dialog_outcome(outcome, window, cx);
        });
        self.settings.update(cx, |settings, cx| {
            let _ = settings.handle_dialog_outcome(outcome, cx);
        });
        self.command_history.update(cx, |history, cx| {
            let _ = history.handle_dialog_outcome(outcome, window, cx);
        });
        self.log_analysis.update(cx, |page, cx| {
            let _ = page.handle_dialog_outcome(outcome, cx);
        });
    }

    fn schedule_notification_expirations(&mut self, cx: &mut Context<Self>) {
        let timed = self
            .shared
            .read(cx)
            .interactions
            .notifications
            .notifications()
            .filter_map(|notification| {
                notification
                    .expires_at_ms
                    .map(|expires_at_ms| (notification.id, expires_at_ms))
            })
            .collect::<Vec<_>>();
        self.scheduled_notification_expirations
            .retain(|id, _| timed.iter().any(|(active_id, _)| active_id == id));

        for (id, expires_at_ms) in timed {
            if self.scheduled_notification_expirations.get(&id) == Some(&expires_at_ms) {
                continue;
            }
            self.scheduled_notification_expirations
                .insert(id, expires_at_ms);
            let wait =
                Duration::from_millis(expires_at_ms.saturating_sub(notification_clock_ms()).max(1));
            cx.spawn(async move |shell, cx| {
                Timer::after(wait).await;
                let _ = cx.update(|cx| {
                    let Some(shell) = shell.upgrade() else {
                        return;
                    };
                    shell.update(cx, |shell, cx| {
                        if shell.scheduled_notification_expirations.get(&id) != Some(&expires_at_ms)
                        {
                            return;
                        }
                        shell.scheduled_notification_expirations.remove(&id);
                        shell.shared.update(cx, |state, cx| {
                            if state.interactions.notifications.dismiss(id) {
                                cx.notify();
                            }
                        });
                    });
                });
            })
            .detach();
        }
    }

    fn dismiss_notification(&mut self, id: NotificationId, cx: &mut Context<Self>) {
        self.shared.update(cx, |state, cx| {
            state.interactions.notifications.dismiss(id);
            cx.notify();
        });
    }
}

impl Render for AppShell {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let (
            tokens,
            current_page,
            target_ready,
            page_model,
            collapsed,
            settings_open,
            active_dialog,
            notifications,
            target_label,
            theme_label,
            command_history_open,
            disposal_report_open,
            application_log_open,
        ) = {
            let state = self.shared.read(cx);
            (
                state.theme.tokens(),
                state.pages.active(),
                state.active_ssh.is_some(),
                state.pages.model(),
                state.sidebar_collapsed,
                state.interactions.settings.is_open(),
                state.interactions.dialogs.active().cloned(),
                state
                    .interactions
                    .notifications
                    .notifications()
                    .cloned()
                    .collect::<Vec<_>>(),
                state.target_label.clone(),
                state.theme.label(),
                self.command_history_open,
                self.disposal_report_open,
                self.application_log_open,
            )
        };
        let current = current_page.descriptor();
        let route = workspace_route(target_ready, current_page);
        let workspace_manages_scroll = route == WorkspaceRoute::Page(current_page)
            && matches!(
                current_page,
                PageId::SystemInfo
                    | PageId::Docker
                    | PageId::Kubernetes
                    | PageId::QuickDetection
                    | PageId::LogAnalysis
                    | PageId::PacketCapture
                    | PageId::Integrity
                    | PageId::CheckAudit
                    | PageId::Database
                    | PageId::Middleware
                    | PageId::ConfigGenerator
                    | PageId::Firewall
                    | PageId::Snapshot
                    | PageId::BaselineQuickEdit
                    | PageId::JavaHotUpdate
                    | PageId::BatchServers
                    | PageId::EmergencyCommands
                    | PageId::Notes
                    | PageId::AiHistory
            );
        let workspace: AnyElement = if route == WorkspaceRoute::ConnectionLanding {
            connection_landing(self.connections.clone()).into_any_element()
        } else if current_page == PageId::SystemInfo {
            self.system_info.clone().into_any_element()
        } else if current_page == PageId::Docker {
            div().child(self.docker.clone()).into_any_element()
        } else if current_page == PageId::Kubernetes {
            div().child(self.kubernetes.clone()).into_any_element()
        } else if current_page == PageId::QuickDetection {
            constrained_workspace_page(self.quick_detection.clone())
        } else if current_page == PageId::LogAnalysis {
            div().child(self.log_analysis.clone()).into_any_element()
        } else if current_page == PageId::PacketCapture {
            div().child(self.packet_capture.clone()).into_any_element()
        } else if current_page == PageId::Integrity {
            div().child(self.integrity.clone()).into_any_element()
        } else if current_page == PageId::CheckAudit {
            div().child(self.check_audit.clone()).into_any_element()
        } else if current_page == PageId::Database {
            div().child(self.database.clone()).into_any_element()
        } else if current_page == PageId::Middleware {
            div().child(self.middleware.clone()).into_any_element()
        } else if current_page == PageId::ConfigGenerator {
            constrained_workspace_page(self.config_generator.clone())
        } else if current_page == PageId::Firewall {
            div().child(self.firewall.clone()).into_any_element()
        } else if current_page == PageId::Snapshot {
            div().child(self.snapshot.clone()).into_any_element()
        } else if current_page == PageId::BaselineQuickEdit {
            div().child(self.baseline.clone()).into_any_element()
        } else if current_page == PageId::JavaHotUpdate {
            div().child(self.java.clone()).into_any_element()
        } else if current_page == PageId::BatchServers {
            div().child(self.batch_servers.clone()).into_any_element()
        } else if current_page == PageId::EmergencyCommands {
            constrained_workspace_page(self.command_workbench.clone())
        } else {
            match page_model {
                PageModel::Pending(pending_page) => pending_page_content(
                    pending_page,
                    current.title,
                    self.connections.clone(),
                    tokens,
                )
                .into_any_element(),
                PageModel::Implemented(implemented) => match implemented.id {
                    PageId::SecurityReference => div()
                        .child(self.security_reference.clone())
                        .into_any_element(),
                    PageId::Notes => div().child(self.notes.clone()).into_any_element(),
                    PageId::AiHistory => div().child(self.ai_history.clone()).into_any_element(),
                    _ => unreachable!("only fully wired pages may be marked implemented"),
                },
            }
        };
        let workspace_content = if workspace_manages_scroll {
            scroll_managed_workspace(workspace)
        } else {
            div()
                .flex_1()
                .min_h_0()
                .overflow_y_scrollbar()
                .p_4()
                .child(workspace)
                .into_any_element()
        };

        div()
            .id("lovelyres-root")
            .key_context("LovelyRes")
            .track_focus(&self.workspace_focus)
            .on_action(cx.listener(Self::toggle_sidebar))
            .on_action(cx.listener(Self::cycle_theme))
            .on_action(cx.listener(Self::open_command_history))
            .on_action(cx.listener(Self::open_disposal_report))
            .on_action(cx.listener(Self::open_application_log))
            .on_action(cx.listener(Self::open_settings))
            .on_action(cx.listener(Self::close_overlay))
            .on_action(cx.listener(Self::open_ssh))
            .on_action(cx.listener(Self::open_sftp))
            .on_action(cx.listener(Self::competition_shortcut_1))
            .on_action(cx.listener(Self::competition_shortcut_2))
            .on_action(cx.listener(Self::competition_shortcut_3))
            .on_action(cx.listener(Self::competition_shortcut_4))
            .on_action(cx.listener(Self::competition_shortcut_5))
            .on_action(cx.listener(Self::competition_shortcut_6))
            .on_action(cx.listener(Self::competition_shortcut_7))
            .on_action(cx.listener(Self::competition_shortcut_8))
            .relative()
            .size_full()
            .flex()
            .flex_col()
            .overflow_hidden()
            .bg(tokens.background)
            .text_color(tokens.text)
            .font_family("Inter")
            .child(
                div()
                    .h(px(36.0))
                    .flex_none()
                    .flex()
                    .items_center()
                    .px_3()
                    .bg(tokens.surface)
                    .border_b_1()
                    .border_color(tokens.border)
                    .child(titlebar_drag_region(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(
                                div()
                                    .size(px(24.0))
                                    .flex_none()
                                    .overflow_hidden()
                                    .rounded_md()
                                    .bg(tokens.surface_alt)
                                    .child(img(self.brand_logo.clone()).size_full()),
                            )
                            .child("LovelyRes"),
                    ))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_1()
                            .child(
                                crate::buttons::button("titlebar-ssh")
                                    .label("SSH")
                                    .xsmall()
                                    .ghost()
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.open_ssh(&OpenSshTerminal, window, cx)
                                    })),
                            )
                            .child(
                                crate::buttons::button("titlebar-sftp")
                                    .label("SFTP")
                                    .xsmall()
                                    .ghost()
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.open_sftp(&OpenSftpWindow, window, cx)
                                    })),
                            )
                            .child(
                                crate::buttons::button("titlebar-settings")
                                    .xsmall()
                                    .ghost()
                                    .tooltip("设置")
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.open_settings(&OpenSettings, window, cx)
                                    })),
                            )
                            .child(title_button(
                                "window-minimize",
                                IconName::WindowMinimize,
                                tokens,
                                |window, _| {
                                    window.minimize_window();
                                },
                            ))
                            .child(title_button(
                                "window-maximize",
                                IconName::WindowMaximize,
                                tokens,
                                |window, _| {
                                    toggle_window_zoom(window);
                                },
                            ))
                            .child(title_button(
                                "window-close",
                                IconName::WindowClose,
                                tokens,
                                |window, _| {
                                    window.remove_window();
                                },
                            )),
                    ),
            )
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .child(
                        div()
                            .w(if collapsed { px(56.0) } else { px(220.0) })
                            .flex_none()
                            .flex()
                            .flex_col()
                            .bg(tokens.surface)
                            .border_r_1()
                            .border_color(tokens.border)
                            .child(
                                div()
                                    .h(px(48.0))
                                    .flex_none()
                                    .px_2()
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .child(
                                        crate::buttons::button("sidebar-toggle")
                                            .ghost()
                                            .icon(if collapsed {
                                                IconName::PanelLeftOpen
                                            } else {
                                                IconName::PanelLeftClose
                                            })
                                            .tooltip(if collapsed {
                                                "展开导航"
                                            } else {
                                                "收起导航"
                                            })
                                            .h(px(36.0))
                                            .when(collapsed, |button| button.w(px(36.0)))
                                            .when(!collapsed, |button| {
                                                button.w_full().justify_start().label("收起导航")
                                            })
                                            .on_click(cx.listener(|this, _, window, cx| {
                                                this.toggle_sidebar(&ToggleSidebar, window, cx)
                                            })),
                                    ),
                            )
                            .child(sidebar(self, collapsed, tokens, cx)),
                    )
                    .child(
                        div()
                            .id("workspace-content-host")
                            .flex_1()
                            .min_w_0()
                            .flex()
                            .flex_col()
                            .child(workspace_content),
                    ),
            )
            .child(
                div()
                    .id("application-status-bar")
                    .h(px(28.0))
                    .flex_none()
                    .flex()
                    .items_center()
                    .justify_between()
                    .relative()
                    .px_2()
                    .bg(tokens.surface)
                    .border_t_1()
                    .border_color(tokens.border)
                    .child(
                        div()
                            .id("status-target")
                            .absolute()
                            .inset_0()
                            .flex()
                            .items_center()
                            .justify_center()
                            .child(
                                div()
                                    .max_w(px(480.0))
                                    .truncate()
                                    .text_xs()
                                    .text_color(tokens.muted)
                                    .font_family("Cascadia Mono")
                                    .child(target_label),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_1()
                            .child(status_action_button(
                                "status-theme",
                                format!("主题 · {theme_label}"),
                                cx.listener(|this, _, window, cx| {
                                    this.cycle_theme(&CycleTheme, window, cx)
                                }),
                            ))
                            .child(status_action_button(
                                "status-history",
                                "历史",
                                cx.listener(|this, _, window, cx| {
                                    this.open_command_history(&OpenCommandHistory, window, cx)
                                }),
                            ))
                            .child(status_action_button(
                                "status-report",
                                "报告",
                                cx.listener(|this, _, window, cx| {
                                    this.open_disposal_report(&OpenDisposalReport, window, cx)
                                }),
                            ))
                            .child(status_action_button(
                                "status-diagnostics-report",
                                "诊断",
                                cx.listener(|this, _, window, cx| {
                                    this.open_application_log(&OpenApplicationLog, window, cx)
                                }),
                            )),
                    )
                    .child(
                        div()
                            .px_1()
                            .text_xs()
                            .text_color(tokens.muted)
                            .font_family("Cascadia Mono")
                            .child(format!("v{}", env!("CARGO_PKG_VERSION"))),
                    ),
            )
            .when(settings_open, |root| root.child(self.settings.clone()))
            .when(command_history_open, |root| {
                root.child(self.command_history.clone())
            })
            .when(disposal_report_open, |root| {
                root.child(self.disposal_report.clone())
            })
            .when(application_log_open, |root| {
                root.child(application_log_overlay(self, tokens, cx))
            })
            .when_some(active_dialog, |root, dialog| {
                root.child(dialog_overlay(self, dialog, tokens, cx))
            })
            .when(!notifications.is_empty(), |root| {
                root.child(notification_stack(self, notifications, tokens, cx))
            })
    }
}

pub(crate) fn constrained_workspace_page(page: impl IntoElement) -> AnyElement {
    div().size_full().min_h_0().child(page).into_any_element()
}

pub(crate) fn scroll_managed_workspace(workspace: impl IntoElement) -> AnyElement {
    div()
        .flex_1()
        .min_h_0()
        .overflow_hidden()
        .p_4()
        .child(workspace)
        .into_any_element()
}

fn connection_landing(connections: Entity<ConnectionManager>) -> impl IntoElement {
    div()
        .w_full()
        .flex()
        .justify_center()
        .child(div().w_full().max_w(px(840.0)).child(connections))
}

fn pending_page_content(
    pending_page: PendingPageModel,
    current_title: &'static str,
    connections: Entity<ConnectionManager>,
    tokens: crate::theme::ThemeTokens,
) -> impl IntoElement {
    div()
        .child(
            div()
                .mb_5()
                .child(div().text_2xl().mb_2().child(current_title))
                .child(div().text_color(tokens.muted).child(pending_page.summary)),
        )
        .child(
            div()
                .flex()
                .gap_3()
                .mb_5()
                .child(status_card("目标", "等待连接", tokens.warning, tokens))
                .child(status_card(
                    "页面生命周期",
                    "Pending",
                    tokens.warning,
                    tokens,
                ))
                .child(status_card(
                    "安全模式",
                    "远端动作未接线",
                    tokens.accent,
                    tokens,
                )),
        )
        .child(connections)
        .child(
            div()
                .flex()
                .justify_between()
                .items_center()
                .mb_3()
                .child(div().text_lg().child("工作区"))
                .child(
                    div()
                        .rounded_md()
                        .border_1()
                        .border_color(tokens.warning)
                        .px_3()
                        .py_1()
                        .text_sm()
                        .text_color(tokens.warning)
                        .child(format!(
                            "{} · 待迁移：{}",
                            pending_page.status_label(),
                            pending_page.intended_action
                        )),
                ),
        )
        .child(
            div()
                .flex()
                .flex_wrap()
                .gap_3()
                .children(pending_page.sections.iter().map(|section| {
                    div()
                        .min_w(px(220.0))
                        .flex_1()
                        .h(px(180.0))
                        .rounded_lg()
                        .border_1()
                        .border_color(tokens.border)
                        .bg(tokens.surface)
                        .p_4()
                        .child(div().mb_3().child((*section).to_owned()))
                        .child(div().text_sm().text_color(tokens.muted).child(format!(
                            "Pending · {} · 尚未接线，不会执行任何远端动作",
                            capability_label(pending_page.capability)
                        )))
                })),
        )
}

fn sidebar(
    shell: &mut AppShell,
    collapsed: bool,
    tokens: crate::theme::ThemeTokens,
    cx: &mut Context<AppShell>,
) -> impl IntoElement {
    let active = shell.shared.read(cx).pages.active();
    div()
        .flex_1()
        .min_h_0()
        .overflow_y_scrollbar()
        .px_2()
        .pb_2()
        .children(
            PageGroup::ALL
                .into_iter()
                .enumerate()
                .map(|(group_index, group)| {
                    div()
                        .when(collapsed && group_index > 0, |element| {
                            element.child(
                                div()
                                    .h(px(9.0))
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .child(
                                        div().w(px(24.0)).border_t_1().border_color(tokens.border),
                                    ),
                            )
                        })
                        .when(!collapsed, |element| {
                            element.child(
                                div()
                                    .px_2()
                                    .pt_2()
                                    .pb_1()
                                    .text_xs()
                                    .text_color(tokens.muted)
                                    .child(group.label()),
                            )
                        })
                        .children(
                            PageId::ALL
                                .into_iter()
                                .filter(move |page| page.descriptor().group == group)
                                .map(|page| {
                                    let descriptor = page.descriptor();
                                    let selected = active == page;
                                    div()
                                        .id(SharedString::from(format!("page-{page:?}")))
                                        .relative()
                                        .h(px(38.0))
                                        .w_full()
                                        .flex()
                                        .items_center()
                                        .justify_center()
                                        .when(selected && !collapsed, |element| {
                                            element.child(
                                                div()
                                                    .absolute()
                                                    .left_0()
                                                    .top(px(8.0))
                                                    .bottom(px(8.0))
                                                    .w(px(2.0))
                                                    .rounded_full()
                                                    .bg(tokens.accent),
                                            )
                                        })
                                        .child(
                                            crate::buttons::button(SharedString::from(format!(
                                                "sidebar-page-{page:?}"
                                            )))
                                            .ghost()
                                            .icon(sidebar_icon(page))
                                            .tooltip(descriptor.title)
                                            .selected(selected)
                                            .h(px(34.0))
                                            .when(collapsed, |button| button.w(px(36.0)))
                                            .when(!collapsed, |button| {
                                                button
                                                    .w_full()
                                                    .justify_start()
                                                    .label(descriptor.title)
                                            })
                                            .on_click(cx.listener(move |this, _, window, cx| {
                                                this.activate_page(page, window, cx);
                                            })),
                                        )
                                }),
                        )
                }),
        )
}

const fn sidebar_icon(page: PageId) -> IconName {
    match page {
        PageId::SystemInfo => IconName::LayoutDashboard,
        PageId::Docker => IconName::Frame,
        PageId::Kubernetes => IconName::Globe,
        PageId::QuickDetection => IconName::Search,
        PageId::SecurityReference => IconName::BookOpen,
        PageId::EmergencyCommands => IconName::SquareTerminal,
        PageId::LogAnalysis => IconName::File,
        PageId::PacketCapture => IconName::ChartPie,
        PageId::CheckAudit => IconName::Inspector,
        PageId::Integrity => IconName::CircleCheck,
        PageId::Notes => IconName::File,
        PageId::Firewall => IconName::Asterisk,
        PageId::Snapshot => IconName::Calendar,
        PageId::BaselineQuickEdit => IconName::Settings2,
        PageId::Database => IconName::Inbox,
        PageId::Middleware => IconName::Settings2,
        PageId::JavaHotUpdate => IconName::Redo2,
        PageId::BatchServers => IconName::GalleryVerticalEnd,
        PageId::AiHistory => IconName::Bot,
        PageId::ConfigGenerator => IconName::File,
    }
}

fn title_button(
    id: &'static str,
    icon: IconName,
    tokens: crate::theme::ThemeTokens,
    on_click: impl Fn(&mut Window, &mut App) + 'static,
) -> impl IntoElement {
    div()
        .id(id)
        .size(px(30.0))
        .flex()
        .items_center()
        .justify_center()
        .rounded_sm()
        .cursor_pointer()
        .hover(|element| element.bg(tokens.surface_alt))
        .on_click(move |_, window, cx| on_click(window, cx))
        .child(Icon::new(icon).size_4())
}

#[cfg(target_os = "windows")]
fn titlebar_drag_region(child: impl IntoElement) -> impl IntoElement {
    div()
        .h_full()
        .flex_1()
        .flex()
        .items_center()
        .child(child)
        .on_mouse_down(MouseButton::Left, |_, window, _| {
            begin_native_window_drag(window);
        })
}

#[cfg(not(target_os = "windows"))]
fn titlebar_drag_region(child: impl IntoElement) -> impl IntoElement {
    div()
        .h_full()
        .flex_1()
        .flex()
        .items_center()
        .window_control_area(WindowControlArea::Drag)
        .child(child)
}

#[cfg(target_os = "windows")]
fn windows_zoom_command(is_maximized: bool) -> SHOW_WINDOW_CMD {
    if is_maximized {
        SW_RESTORE
    } else {
        SW_MAXIMIZE
    }
}

#[cfg(target_os = "windows")]
fn raw_win32_hwnd(window: &Window) -> Option<HWND> {
    let Ok(handle) = HasWindowHandle::window_handle(window) else {
        tracing::error!("cannot obtain the raw Win32 window handle");
        return None;
    };
    let RawWindowHandle::Win32(handle) = handle.as_raw() else {
        tracing::error!("GPUI returned a non-Win32 handle on Windows");
        return None;
    };
    Some(HWND(handle.hwnd.get() as *mut std::ffi::c_void))
}

#[cfg(target_os = "windows")]
fn windows_move_command() -> u32 {
    SC_MOVE | HTCAPTION
}

#[cfg(target_os = "windows")]
fn begin_native_window_drag(window: &Window) {
    let Some(hwnd) = raw_win32_hwnd(window) else {
        return;
    };
    if let Err(error) = unsafe { ReleaseCapture() } {
        tracing::error!(%error, "failed to release Win32 capture before window drag");
        return;
    }
    if let Err(error) = unsafe {
        PostMessageW(
            Some(hwnd),
            WM_SYSCOMMAND,
            WPARAM(windows_move_command() as usize),
            LPARAM(0),
        )
    } {
        tracing::error!(%error, "failed to begin the native Win32 window drag");
    }
}

#[cfg(target_os = "windows")]
fn toggle_window_zoom(window: &Window) {
    let Some(hwnd) = raw_win32_hwnd(window) else {
        return;
    };
    let command = windows_zoom_command(window.is_maximized());
    if let Err(error) = unsafe { ShowWindowAsync(hwnd, command) }.ok() {
        tracing::error!(%error, "failed to toggle the native Win32 window zoom state");
    }
}

#[cfg(not(target_os = "windows"))]
fn toggle_window_zoom(window: &Window) {
    window.zoom_window();
}

fn status_action_button(
    id: &'static str,
    label: impl Into<SharedString>,
    on_click: impl Fn(&gpui::ClickEvent, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    crate::buttons::button(id)
        .label(label)
        .xsmall()
        .ghost()
        .on_click(on_click)
}

fn status_card(
    label: &'static str,
    value: &'static str,
    indicator: gpui::Rgba,
    tokens: crate::theme::ThemeTokens,
) -> impl IntoElement {
    div()
        .flex_1()
        .min_w(px(160.0))
        .rounded_lg()
        .border_1()
        .border_color(tokens.border)
        .bg(tokens.surface)
        .p_3()
        .child(div().text_sm().text_color(tokens.muted).mb_2().child(label))
        .child(
            div()
                .flex()
                .items_center()
                .gap_2()
                .child(div().size(px(8.0)).rounded_full().bg(indicator))
                .child(value),
        )
}

fn application_log_overlay(
    shell: &mut AppShell,
    tokens: crate::theme::ThemeTokens,
    cx: &mut Context<AppShell>,
) -> impl IntoElement {
    let entries = shell.logging.entries();
    let entry_count = entries.len();
    let level = shell.logging.level().as_str().to_ascii_uppercase();
    let preview = shell.logging.preview_as_text(100);
    let lines = preview
        .lines()
        .map(|line| SharedString::from(line.to_owned()))
        .collect::<Vec<_>>();

    div()
        .id("application-log-backdrop")
        .absolute()
        .inset_0()
        .flex()
        .items_center()
        .justify_center()
        .bg(gpui::rgba(0x00000099))
        .on_click(cx.listener(|this, _, window, cx| {
            this.dismiss_application_log(window, cx);
        }))
        .child(
            div()
                .id("application-log-panel")
                .on_click(|_, _, cx| cx.stop_propagation())
                .w(px(860.0))
                .h(px(620.0))
                .max_h(px(680.0))
                .flex()
                .flex_col()
                .rounded_lg()
                .border_1()
                .border_color(tokens.border)
                .bg(tokens.surface)
                .shadow_lg()
                .p_5()
                .child(
                    div()
                        .flex()
                        .items_start()
                        .justify_between()
                        .gap_4()
                        .mb_4()
                        .child(
                            div()
                                .child(div().text_xl().child("应用诊断日志"))
                                .child(
                                    div()
                                        .mt_1()
                                        .text_sm()
                                        .text_color(tokens.muted)
                                        .child(format!(
                                            "内存缓冲 {entry_count}/500 · 当前级别 {level} · 显示最近 100 条"
                                        )),
                                ),
                        )
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap_2()
                                .child(
                                    crate::buttons::button("application-log-refresh")
                                        .label("刷新")
                                        .small()
                                        .on_click(cx.listener(|_, _, _, cx| cx.notify())),
                                )
                                .child(
                                    crate::buttons::button("application-log-copy")
                                        .label("复制全部")
                                        .small()
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.copy_application_log(cx)
                                        })),
                                )
                                .child(
                                    crate::buttons::button("application-log-clear")
                                        .label("清空缓冲")
                                        .small()
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.clear_application_log(cx)
                                        })),
                                )
                                .child(
                                    crate::buttons::close_button("application-log-close")
                                        .small()
                                        .on_click(cx.listener(|this, _, window, cx| {
                                            this.dismiss_application_log(window, cx);
                                        })),
                                ),
                        ),
                )
                .child(
                    div()
                        .flex_1()
                        .min_h_0()
                        .overflow_scrollbar()
                        .rounded_md()
                        .border_1()
                        .border_color(tokens.border)
                        .bg(tokens.background)
                        .p_3()
                        .font_family("Cascadia Mono")
                        .text_xs()
                        .when(lines.is_empty(), |content| {
                            content.child(
                                div()
                                    .text_color(tokens.muted)
                                    .child("当前缓冲中没有符合级别的日志。"),
                            )
                        })
                        .children(lines.into_iter().map(|line| {
                            div().min_w(px(780.0)).py_1().child(line)
                        })),
                ),
        )
}

fn capability_label(capability: CapabilityRequirement) -> &'static str {
    match capability {
        CapabilityRequirement::ConnectedTarget => "需要活动 SSH 目标",
        CapabilityRequirement::LocalWorkspace => "本地便携工作区",
        CapabilityRequirement::OptionalAi => "可选 AI Provider",
    }
}

fn dialog_overlay(
    shell: &mut AppShell,
    dialog: DialogState,
    tokens: crate::theme::ThemeTokens,
    cx: &mut Context<AppShell>,
) -> impl IntoElement {
    let content = match dialog {
        DialogState::Alert(alert) => div()
            .child(div().text_2xl().mb_3().child(alert.title))
            .child(
                div()
                    .text_sm()
                    .text_color(tokens.muted)
                    .child(alert.message),
            )
            .child(
                div().mt_5().flex().justify_end().child(
                    crate::buttons::button("dialog-alert-dismiss")
                        .label("知道了")
                        .small()
                        .primary()
                        .on_click(cx.listener(move |this, _, window, cx| {
                            this.dispatch_dialog(
                                DialogAction::DismissAlert {
                                    dialog_id: alert.id,
                                },
                                window,
                                cx,
                            )
                        })),
                ),
            )
            .into_any_element(),
        DialogState::Prompt(prompt) => div()
            .child(div().text_2xl().mb_3().child(prompt.title))
            .child(
                div()
                    .mb_3()
                    .text_sm()
                    .text_color(tokens.muted)
                    .child(prompt.message),
            )
            .child(Input::new(&shell.prompt_input).small())
            .child(
                div()
                    .mt_5()
                    .flex()
                    .justify_end()
                    .gap_2()
                    .child(
                        crate::buttons::button("dialog-prompt-cancel")
                            .label("取消")
                            .small()
                            .on_click(cx.listener(move |this, _, window, cx| {
                                this.dispatch_dialog(
                                    DialogAction::Cancel {
                                        dialog_id: prompt.id,
                                    },
                                    window,
                                    cx,
                                )
                            })),
                    )
                    .child(
                        crate::buttons::button("dialog-prompt-submit")
                            .label("确认")
                            .small()
                            .primary()
                            .on_click(cx.listener(move |this, _, window, cx| {
                                this.dispatch_dialog(
                                    DialogAction::SubmitPrompt {
                                        dialog_id: prompt.id,
                                    },
                                    window,
                                    cx,
                                )
                            })),
                    ),
            )
            .into_any_element(),
        DialogState::DangerousConfirm(dangerous) => {
            let cancel_id = dangerous.id;
            let confirm_id = dangerous.id;
            let operation_id = dangerous.operation_id.clone();
            div()
                .child(
                    div()
                        .text_2xl()
                        .mb_3()
                        .text_color(tokens.danger)
                        .child("危险操作确认"),
                )
                .child(div().mb_3().text_sm().child(dangerous.summary))
                .child(
                    div()
                        .rounded_md()
                        .border_1()
                        .border_color(tokens.danger)
                        .p_3()
                        .font_family("Cascadia Mono")
                        .text_xs()
                        .child(format!("OperationPlan: {}", dangerous.operation_id)),
                )
                .child(
                    div()
                        .mt_5()
                        .flex()
                        .justify_end()
                        .gap_2()
                        .child(
                            crate::buttons::button("dialog-dangerous-cancel")
                                .label("取消")
                                .small()
                                .on_click(cx.listener(move |this, _, window, cx| {
                                    this.dispatch_dialog(
                                        DialogAction::Cancel {
                                            dialog_id: cancel_id,
                                        },
                                        window,
                                        cx,
                                    )
                                })),
                        )
                        .child(
                            crate::buttons::button("dialog-dangerous-confirm")
                                .label("确认执行此计划")
                                .small()
                                .danger()
                                .on_click(cx.listener(move |this, _, window, cx| {
                                    this.dispatch_dialog(
                                        DialogAction::ConfirmDangerous {
                                            dialog_id: confirm_id,
                                            operation_id: operation_id.clone(),
                                        },
                                        window,
                                        cx,
                                    )
                                })),
                        ),
                )
                .into_any_element()
        }
    };

    div()
        .id("dialog-backdrop")
        .absolute()
        .inset_0()
        .flex()
        .items_center()
        .justify_center()
        .bg(gpui::rgba(0x00000099))
        .child(
            div()
                .id("dialog-panel")
                .w(px(560.0))
                .max_h(px(620.0))
                .overflow_y_scrollbar()
                .rounded_lg()
                .border_1()
                .border_color(tokens.border)
                .bg(tokens.surface)
                .shadow_lg()
                .p_5()
                .child(content),
        )
}

fn notification_stack(
    _shell: &mut AppShell,
    notifications: Vec<Notification>,
    tokens: crate::theme::ThemeTokens,
    cx: &mut Context<AppShell>,
) -> impl IntoElement {
    div()
        .id("notification-center")
        .absolute()
        .right(px(18.0))
        .bottom(px(40.0))
        .w(px(420.0))
        .flex()
        .flex_col()
        .gap_2()
        .children(notifications.into_iter().rev().map(|notification| {
            let color = notification_color(notification.severity, tokens);
            div()
                .id(SharedString::from(format!(
                    "notification-{}",
                    notification.key
                )))
                .p_3()
                .rounded_lg()
                .border_1()
                .border_color(color)
                .bg(tokens.surface_alt)
                .shadow_lg()
                .flex()
                .items_start()
                .justify_between()
                .gap_3()
                .child(div().flex_1().child(notification.message))
                .child(
                    crate::buttons::button(SharedString::from(format!(
                        "dismiss-notification-{}",
                        notification.key
                    )))
                    .label("×")
                    .xsmall()
                    .ghost()
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.dismiss_notification(notification.id, cx)
                    })),
                )
        }))
}

fn notification_color(
    severity: NotificationSeverity,
    tokens: crate::theme::ThemeTokens,
) -> gpui::Rgba {
    match severity {
        NotificationSeverity::Info => tokens.accent,
        NotificationSeverity::Success => tokens.success,
        NotificationSeverity::Warning => tokens.warning,
        NotificationSeverity::Error => tokens.danger,
    }
}

/// `gpui-component` keeps dialogs, notifications and focused inputs on a per-window `Root`.
/// Every production window must install it as the first view layer.
fn component_root(view: impl Into<AnyView>, window: &mut Window, cx: &mut App) -> Entity<Root> {
    cx.new(|cx| Root::new(view, window, cx))
}

fn open_secondary(
    kind: NativeWindowKind,
    shared: Entity<SharedAppState>,
    services: Arc<BackendServices>,
    tokio: Arc<TokioBridge>,
    sftp_navigator: Entity<SftpNavigator>,
    cx: &mut Context<AppShell>,
) {
    if kind == NativeWindowKind::Main {
        return;
    }
    let ticket = shared.update(cx, |state, cx| {
        let ticket = state.windows.begin_open(kind.clone());
        if ticket.is_none() {
            state.interactions.notifications.push_toast(
                format!("window-busy-{kind:?}"),
                NotificationSeverity::Warning,
                format!("{} 已打开或正在关闭", kind.title()),
            );
        }
        cx.notify();
        ticket
    });
    let Some(ticket) = ticket else {
        return;
    };
    let options = secondary_window_options(&kind, cx);
    let window_shared = shared.clone();
    if let Err(error) = cx.open_window(options, move |window, cx| {
        let secondary = cx.new(|cx| {
            SecondaryWindow::new(
                ticket,
                window_shared,
                services,
                tokio,
                sftp_navigator,
                window,
                cx,
            )
        });
        component_root(secondary, window, cx)
    }) {
        tracing::error!(%error, "failed to open native secondary window");
        shared.update(cx, |state, cx| {
            state.windows.mark_closed(&kind);
            state.interactions.notifications.push_toast(
                format!("window-open-error-{kind:?}"),
                NotificationSeverity::Error,
                format!("无法打开 {}：{error}", kind.title()),
            );
            cx.notify();
        });
    }
}

fn open_container_terminal(
    launch: ContainerTerminalLaunch,
    shared: Entity<SharedAppState>,
    services: Arc<BackendServices>,
    tokio: Arc<TokioBridge>,
    cx: &mut Context<AppShell>,
) {
    let kind = launch.window_kind();
    let ticket = shared.update(cx, |state, cx| {
        let ticket = state.windows.begin_open(kind.clone());
        if ticket.is_none() {
            state.interactions.notifications.push_toast(
                format!("window-busy-{kind:?}"),
                NotificationSeverity::Warning,
                format!("{} 已打开或正在关闭", kind.title()),
            );
        }
        cx.notify();
        ticket
    });
    let Some(ticket) = ticket else {
        return;
    };
    let options = secondary_window_options(&kind, cx);
    let window_shared = shared.clone();
    if let Err(error) = cx.open_window(options, move |window, cx| {
        let terminal = cx.new(|cx| {
            ContainerTerminalWindow::new(ticket, launch, window_shared, services, tokio, window, cx)
        });
        component_root(terminal, window, cx)
    }) {
        tracing::error!(%error, "failed to open native container terminal window");
        shared.update(cx, |state, cx| {
            state.windows.mark_closed(&kind);
            state.interactions.notifications.push_toast(
                format!("window-open-error-{kind:?}"),
                NotificationSeverity::Error,
                format!("无法打开 {}：{error}", kind.title()),
            );
            cx.notify();
        });
    }
}

struct StartupErrorView {
    message: SharedString,
}

impl Render for StartupErrorView {
    fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
        div()
            .size_full()
            .flex()
            .items_center()
            .justify_center()
            .bg(gpui::rgb(0x120f12))
            .text_color(gpui::rgb(0xffe8eb))
            .font_family("Inter")
            .child(
                div()
                    .w(px(620.0))
                    .rounded_lg()
                    .border_1()
                    .border_color(gpui::rgb(0x7d3340))
                    .bg(gpui::rgb(0x25171b))
                    .p_6()
                    .child(div().text_2xl().mb_3().child("LovelyRes 无法启动"))
                    .child(div().mb_3().child(self.message.clone()))
                    .child(
                        div()
                            .text_sm()
                            .text_color(gpui::rgb(0xd9aab2))
                            .child("便携版只会写入程序旁的 data 目录；请移动到可写位置后重试。"),
                    ),
            )
    }
}

pub fn run() -> Result<()> {
    let feasibility_request = FeasibilityRequest::from_environment()?;
    let tokio = TokioBridge::new()?;
    let backend_runtime = tokio.handle();
    let bootstrap = (|| -> Result<(Arc<BackendServices>, AppSettings, Arc<LogGuard>)> {
        let executable = std::env::current_exe()?;
        let store = PortableStore::from_executable_path(executable)?;
        let services = Arc::new(BackendServices::with_runtime(store, backend_runtime)?);
        let settings = services.settings().load()?;
        let logging = logging::initialize(&services.store().logs_dir(), settings.log_level)?;
        Ok((services, settings, logging))
    })();
    let startup_error = bootstrap.as_ref().err().map(|error| format!("{error:#}"));
    let bootstrap = bootstrap.ok();

    Application::new()
        .with_assets(Assets)
        .run(move |cx: &mut App| {
            gpui_component::init(cx);
            let font_error = cx
                .text_system()
                .add_fonts(embedded_fonts())
                .err()
                .map(|error| format!("failed to load embedded fonts: {error:#}"));
            let initial_theme = bootstrap
                .as_ref()
                .map(|(_, settings, _)| settings.theme)
                .map(ThemeId::from)
                .unwrap_or_default();
            let initial_component_mode = if initial_theme == ThemeId::Light {
                ThemeMode::Light
            } else {
                ThemeMode::Dark
            };
            Theme::change(initial_component_mode, None, cx);
            apply_component_theme(initial_theme, cx);
            cx.bind_keys([
                KeyBinding::new("ctrl-b", ToggleSidebar, Some("LovelyRes")),
                KeyBinding::new("ctrl-shift-t", CycleTheme, Some("LovelyRes")),
                KeyBinding::new("ctrl-shift-h", OpenCommandHistory, Some("LovelyRes")),
                KeyBinding::new("ctrl-shift-l", OpenApplicationLog, Some("LovelyRes")),
                KeyBinding::new("ctrl-,", OpenSettings, Some("LovelyRes")),
                KeyBinding::new("escape", CloseOverlay, Some("LovelyRes")),
                KeyBinding::new("ctrl-shift-s", OpenSshTerminal, Some("LovelyRes")),
                KeyBinding::new("ctrl-shift-f", OpenSftpWindow, Some("LovelyRes")),
                KeyBinding::new("ctrl-1", CompetitionShortcut1, Some("LovelyRes")),
                KeyBinding::new("ctrl-2", CompetitionShortcut2, Some("LovelyRes")),
                KeyBinding::new("ctrl-3", CompetitionShortcut3, Some("LovelyRes")),
                KeyBinding::new("ctrl-4", CompetitionShortcut4, Some("LovelyRes")),
                KeyBinding::new("ctrl-5", CompetitionShortcut5, Some("LovelyRes")),
                KeyBinding::new("ctrl-6", CompetitionShortcut6, Some("LovelyRes")),
                KeyBinding::new("ctrl-7", CompetitionShortcut7, Some("LovelyRes")),
                KeyBinding::new("ctrl-8", CompetitionShortcut8, Some("LovelyRes")),
            ]);

            let options = main_window_options(cx);
            let error_message = startup_error.clone().or(font_error);
            let ready = error_message.is_none();
            let feasibility_request = feasibility_request.clone();
            let feasibility_data_root = bootstrap
                .as_ref()
                .map(|(services, _, _)| services.store().root().to_path_buf());
            let diagnostics_runtime = tokio.clone();
            let bootstrap = bootstrap.clone();
            let open_result = cx.open_window(options, move |window, cx| {
                let root = if let Some(message) = error_message {
                    let view = cx.new(|_| StartupErrorView {
                        message: message.into(),
                    });
                    component_root(view, window, cx)
                } else {
                    let (services, settings, logging) =
                        bootstrap.expect("services exist when the bootstrap error is absent");
                    let shared = cx.new(|_| SharedAppState::from_settings(&settings));
                    let shell = cx.new(|cx| {
                        AppShell::new(shared, services, tokio.clone(), logging, window, cx)
                    });
                    component_root(shell, window, cx)
                };

                if ready {
                    window.on_next_frame(move |_, _| {
                        if let Err(error) = write_requested_smoke_marker() {
                            tracing::error!(%error, "failed to write smoke-ready marker");
                        }
                        if let (Some(request), Some(data_root)) =
                            (feasibility_request, feasibility_data_root)
                        {
                            diagnostics_runtime.spawn(async move {
                                match tokio::task::spawn_blocking(move || {
                                    diagnostics::execute(request, &data_root)
                                })
                                .await
                                {
                                    Ok(Ok(())) => {
                                        tracing::info!("wrote GPUI feasibility diagnostics")
                                    }
                                    Ok(Err(error)) => tracing::error!(
                                        %error,
                                        "GPUI feasibility diagnostics failed"
                                    ),
                                    Err(error) => tracing::error!(
                                        %error,
                                        "GPUI feasibility diagnostics worker panicked"
                                    ),
                                }
                            });
                        }
                    });
                }
                root
            });
            if let Err(error) = open_result {
                tracing::error!(%error, "failed to open the LovelyRes root window");
                cx.quit();
                return;
            }
            cx.activate(true);
        });
    Ok(())
}

#[cfg(test)]
mod tests {
    use gpui::{FocusHandle, Render, TestAppContext, Window, div, prelude::*};

    #[test]
    fn shell_chrome_keeps_native_actions_in_the_requested_regions() {
        let source = include_str!("app.rs");
        let titlebar_start = source
            .find(".child(titlebar_drag_region(")
            .expect("custom title bar starts with a drag region");
        let titlebar_end = source[titlebar_start..]
            .find(".child(\n                div()\n                    .flex_1()")
            .map(|offset| titlebar_start + offset)
            .expect("main workspace follows the custom title bar");
        let titlebar = &source[titlebar_start..titlebar_end];
        for action in ["titlebar-ssh", "titlebar-sftp", "titlebar-settings"] {
            assert!(
                titlebar.contains(action),
                "missing title-bar action {action}"
            );
        }
        assert!(
            !titlebar.contains(".label(\"设置\")"),
            "settings must remain an icon-only gear in the title bar"
        );
        assert!(
            !titlebar.contains("target_label"),
            "the active target belongs in the bottom status bar"
        );

        let status_start = source
            .find(".id(\"application-status-bar\")")
            .expect("application status bar is rendered");
        let status_end = source[status_start..]
            .find(".when(settings_open")
            .map(|offset| status_start + offset)
            .expect("application overlays follow the status bar");
        let status_bar = &source[status_start..status_end];
        for action in [
            "status-theme",
            "status-history",
            "status-report",
            "status-diagnostics-report",
        ] {
            assert!(
                status_bar.contains(action),
                "missing status action {action}"
            );
        }
        assert!(status_bar.contains(".id(\"status-target\")"));
        assert!(status_bar.contains(".absolute()"));
        assert!(status_bar.contains(".inset_0()"));
        assert!(status_bar.contains(".justify_center()"));
        assert!(status_bar.contains(".child(target_label)"));
        assert!(status_bar.contains("env!(\"CARGO_PKG_VERSION\")"));
    }

    #[test]
    fn workspace_starts_with_page_content_without_a_repeated_shell_title() {
        let source = include_str!("app.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source precedes tests");
        let host_start = production
            .find(".id(\"workspace-content-host\")")
            .expect("workspace content host");
        let host_end = production[host_start..]
            .find(".child(workspace_content)")
            .map(|offset| host_start + offset)
            .expect("workspace content is mounted directly");
        let host = &production[host_start..host_end];

        assert!(!host.contains("px(48.0)"));
        assert!(!production.contains("workspace_title"));
        assert!(!production.contains("workspace_icon"));
    }

    #[test]
    fn scroll_managed_pages_keep_definite_constraints_in_the_production_shell() {
        let source = include_str!("app.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source precedes tests");

        for (page, entity) in [
            ("PageId::QuickDetection", "self.quick_detection.clone()"),
            ("PageId::ConfigGenerator", "self.config_generator.clone()"),
            (
                "PageId::EmergencyCommands",
                "self.command_workbench.clone()",
            ),
        ] {
            let branch_start = production.find(page).expect("managed page branch");
            let branch = &production[branch_start..];
            assert!(
                branch.contains(&format!("constrained_workspace_page({entity})")),
                "{page} must use the definite-height production page mount"
            );
        }

        let mount_start = production
            .find("pub(crate) fn constrained_workspace_page")
            .expect("constrained page mount");
        let mount_end = production[mount_start..]
            .find("pub(crate) fn scroll_managed_workspace")
            .map(|offset| mount_start + offset)
            .expect("scroll managed host follows the mount");
        let mount = &production[mount_start..mount_end];
        assert!(mount.contains(".size_full()"));
        assert!(mount.contains(".min_h_0()"));
        assert!(production.contains("scroll_managed_workspace(workspace)"));
    }

    #[test]
    fn global_command_search_is_absent_from_the_native_shell() {
        let source = include_str!("app.rs");
        let removed = [
            ["Open", "Command", "Palette"].concat(),
            ["Command", "Palette", "Model"].concat(),
            ["command", "-", "palette"].concat(),
            ["palette", "_", "input"].concat(),
            ["ctrl", "-", "k"].concat(),
            ["⌘", "K"].concat(),
        ];
        for removed in removed {
            assert!(
                !source.contains(&removed),
                "removed global command search leaked back through {removed}"
            );
        }
    }

    #[test]
    fn supported_mainline_has_no_incident_workspace_or_registration_paths() {
        let supported_sources = [
            ("app", include_str!("app.rs")),
            ("crate", include_str!("lib.rs")),
            ("snapshot", include_str!("snapshot.rs")),
            ("packet capture", include_str!("packet_capture.rs")),
            ("log analysis", include_str!("log_analysis.rs")),
            ("disposal report", include_str!("disposal_report.rs")),
        ];
        for removed in [
            ["Open", "Case", "Workspace"].concat(),
            ["case", "_", "workspace"].concat(),
            ["案", "件", "工作区"].concat(),
            [".", "cases", "()"].concat(),
            ["add", "_evidence", "_to", "_case"].concat(),
            ["add", "_ioc", "_to", "_case"].concat(),
            ["ensure", "_active"].concat(),
            ["案", "件"].concat(),
        ] {
            for (name, source) in supported_sources {
                assert!(
                    !source.contains(&removed),
                    "removed incident behavior leaked into {name} through {removed}"
                );
            }
        }
    }

    #[test]
    fn disconnected_navigation_respects_page_capabilities() {
        let state = super::SharedAppState::default();
        assert!(
            state.active_ssh.is_none(),
            "startup must never auto-connect"
        );

        for page in super::PageId::ALL {
            let expected = match page.descriptor().capability {
                super::CapabilityRequirement::ConnectedTarget => {
                    super::WorkspaceRoute::ConnectionLanding
                }
                super::CapabilityRequirement::LocalWorkspace
                | super::CapabilityRequirement::OptionalAi => super::WorkspaceRoute::Page(page),
            };
            assert_eq!(
                super::workspace_route(state.active_ssh.is_some(), page),
                expected,
                "{page:?} must follow its declared capability"
            );
        }
    }

    #[test]
    fn connected_target_routes_to_the_requested_page() {
        for page in super::PageId::ALL {
            assert_eq!(
                super::workspace_route(true, page),
                super::WorkspaceRoute::Page(page)
            );
        }
    }

    #[test]
    fn directory_terminal_queue_is_bounded_and_drops_other_target_epochs() {
        let target_a = lovelyres_core::target::TargetGuard {
            identity: lovelyres_core::target::TargetIdentity::new("host-a").unwrap(),
            generation: 7,
        };
        let target_b = lovelyres_core::target::TargetGuard {
            identity: lovelyres_core::target::TargetIdentity::new("host-b").unwrap(),
            generation: 8,
        };
        let mut state = super::SharedAppState::default();
        for index in 0..8 {
            assert!(
                state.queue_directory_terminal(super::OpenDirectoryTerminalIntent {
                    target: target_a.clone(),
                    path: lovelyres_core::sftp::RemotePath::new(format!("/tmp/{index}")).unwrap(),
                })
            );
        }
        assert!(
            !state.queue_directory_terminal(super::OpenDirectoryTerminalIntent {
                target: target_a.clone(),
                path: lovelyres_core::sftp::RemotePath::new("/tmp/overflow").unwrap(),
            })
        );
        assert!(state.has_directory_terminal_for(&target_a));
        assert_eq!(state.take_directory_terminals_for(&target_a).len(), 8);
        assert!(!state.has_directory_terminal_for(&target_a));

        assert!(
            state.queue_directory_terminal(super::OpenDirectoryTerminalIntent {
                target: target_b,
                path: lovelyres_core::sftp::RemotePath::new("/var/log").unwrap(),
            })
        );
        assert!(
            state.queue_directory_terminal(super::OpenDirectoryTerminalIntent {
                target: target_a.clone(),
                path: lovelyres_core::sftp::RemotePath::new("/etc").unwrap(),
            })
        );
        let requests = state.take_directory_terminals_for(&target_a);
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path.as_str(), "/etc");
        assert!(state.directory_terminal_requests.is_empty());
    }

    struct FocusProbe {
        workspace: FocusHandle,
        settings: FocusHandle,
    }

    impl Render for FocusProbe {
        fn render(&mut self, _: &mut Window, _: &mut gpui::Context<Self>) -> impl IntoElement {
            div()
                .child(div().id("focus-workspace").track_focus(&self.workspace))
                .child(div().id("focus-settings").track_focus(&self.settings))
        }
    }

    #[gpui::test]
    fn settings_focus_handle_is_restored_to_workspace_on_close(cx: &mut TestAppContext) {
        let window = cx.update(|cx| {
            cx.open_window(Default::default(), |_, cx| {
                cx.new(|cx| FocusProbe {
                    workspace: cx.focus_handle(),
                    settings: cx.focus_handle(),
                })
            })
            .unwrap()
        });

        window
            .update(cx, |probe, window, _| {
                probe.settings.focus(window);
                assert!(probe.settings.is_focused(window));
                assert!(!probe.workspace.is_focused(window));

                probe.workspace.focus(window);
                assert!(probe.workspace.is_focused(window));
                assert!(!probe.settings.is_focused(window));
            })
            .unwrap();
    }

    #[gpui::test]
    fn component_root_is_the_first_layer_of_native_windows(cx: &mut TestAppContext) {
        cx.update(gpui_component::init);
        let window = cx.update(|cx| {
            cx.open_window(Default::default(), |window, cx| {
                let probe = cx.new(|cx| FocusProbe {
                    workspace: cx.focus_handle(),
                    settings: cx.focus_handle(),
                });
                super::component_root(probe, window, cx)
            })
            .unwrap()
        });

        window
            .update(cx, |_, window, _| {
                assert!(
                    window
                        .root::<gpui_component::Root>()
                        .expect("test window is still open")
                        .is_some(),
                    "gpui-component Root must wrap every native window"
                );
            })
            .unwrap();
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_maximize_button_uses_explicit_restore_workaround() {
        assert_eq!(super::windows_zoom_command(false), super::SW_MAXIMIZE);
        assert_eq!(super::windows_zoom_command(true), super::SW_RESTORE);
        assert_eq!(
            super::windows_move_command(),
            super::SC_MOVE | super::HTCAPTION
        );
    }
}
