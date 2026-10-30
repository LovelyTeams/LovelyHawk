//! Composition root for shared native application services.

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::runtime::Handle;

use crate::ai::AiService;
use crate::audit::AuditService;
use crate::baseline::BaselineService;
use crate::command_workbench::CommandWorkbenchService;
use crate::connections::ConnectionRepository;
use crate::crypto::CryptoVault;
use crate::database::DatabaseService;
use crate::detection::DetectionService;
use crate::docker::DockerService;
use crate::file_analysis::FileAnalysisService;
use crate::integrity::IntegrityService;
use crate::investigation::InvestigationRepositories;
use crate::java::JavaService;
use crate::kubernetes::KubernetesService;
use crate::log_analysis::LogAnalysisService;
use crate::middleware::MiddlewareService;
use crate::operations::PortableOperationJournal;
use crate::packet_capture::PacketCaptureService;
use crate::path_guard::PathGuard;
use crate::report::ReportService;
use crate::response_engine::ResponseEngineService;
use crate::settings::SettingsRepository;
use crate::sftp::SftpService;
use crate::ssh::{BoundSshSession, SshService};
use crate::ssh_compat::SshCompatibilityService;
use crate::system_info::SystemInfoService;
use crate::target::{TargetContext, TargetGuard, TargetIdentity};
use crate::windows_incident::WindowsIncidentService;
use crate::{CoreError, CoreResult, PortableStore};

/// Strongly typed service graph owned by the native application.
#[derive(Debug, Clone)]
pub struct BackendServices {
    inner: Arc<BackendServicesInner>,
}

#[derive(Debug)]
struct BackendServicesInner {
    store: PortableStore,
    target: Arc<TargetContext>,
    settings: SettingsRepository,
    connections: ConnectionRepository,
    operation_journal: PortableOperationJournal,
    ssh: SshService,
    sftp: SftpService,
    ssh_compatibility: SshCompatibilityService,
    detection: DetectionService,
    docker: DockerService,
    database: DatabaseService,
    log_analysis: LogAnalysisService,
    packet_capture: PacketCaptureService,
    file_analysis: FileAnalysisService,
    investigation: InvestigationRepositories,
    report: ReportService,
    integrity: IntegrityService,
    kubernetes: KubernetesService,
    middleware: MiddlewareService,
    system_info: SystemInfoService,
    ai: Option<AiService>,
    audit: AuditService,
    commands: CommandWorkbenchService,
    baseline: BaselineService,
    java: JavaService,
    windows_incident: WindowsIncidentService,
    response_engine: ResponseEngineService,
}

impl BackendServices {
    pub fn new(store: PortableStore) -> CoreResult<Self> {
        Self::build(store, None)
    }

    /// Build the production service graph with the process-owned Tokio reactor
    /// required by AI and HTTP work. SSH continues to own its dedicated runtime.
    pub fn with_runtime(store: PortableStore, runtime: Handle) -> CoreResult<Self> {
        Self::build(store, Some(runtime))
    }

    fn build(store: PortableStore, runtime: Option<Handle>) -> CoreResult<Self> {
        store.ensure_ready()?;
        let crypto = Arc::new(CryptoVault::load(&store)?);
        let connections = ConnectionRepository::new(store.clone(), crypto.clone());
        let ssh = SshService::new(store.clone(), connections.clone())?;
        let target = Arc::new(TargetContext::new());
        let operation_journal = PortableOperationJournal::new(store.clone());
        let sftp = SftpService::new(ssh.clone(), target.clone(), operation_journal.clone());
        let system_info = SystemInfoService::new(ssh.clone(), sftp.clone(), target.clone());
        let kubernetes = KubernetesService::new(ssh.clone(), target.clone());
        let middleware = MiddlewareService::new(
            ssh.clone(),
            sftp.clone(),
            target.clone(),
            operation_journal.clone(),
            store.clone(),
        );
        let docker = DockerService::new(ssh.clone(), target.clone());
        let database =
            DatabaseService::new(ssh.clone(), target.clone(), store.clone(), crypto.clone());
        let detection = DetectionService::new(ssh.clone(), target.clone(), store.clone());
        let log_analysis = LogAnalysisService::new(ssh.clone(), target.clone(), store.clone());
        let file_analysis = FileAnalysisService::new(ssh.clone(), target.clone());
        let packet_capture = PacketCaptureService::new(ssh.clone(), target.clone());
        let audit = AuditService::new(ssh.clone(), target.clone(), store.clone());
        let integrity = IntegrityService::new(ssh.clone(), target.clone(), store.clone());
        let investigation = InvestigationRepositories::new(store.clone());
        let report = ReportService::new(target.clone(), operation_journal.clone());
        let baseline = BaselineService::new(
            ssh.clone(),
            target.clone(),
            store.clone(),
            operation_journal.clone(),
        );
        let java = JavaService::new(
            ssh.clone(),
            target.clone(),
            store.clone(),
            operation_journal.clone(),
        );
        let commands = CommandWorkbenchService::new(
            ssh.clone(),
            target.clone(),
            investigation.command_history().clone(),
        );
        let settings = SettingsRepository::new(store.clone(), crypto.clone());
        let ai = runtime.map(|runtime| AiService::new(runtime, settings.clone()));
        let windows_incident = WindowsIncidentService::with_store(store.clone());
        let response_engine = ResponseEngineService::new(ssh.clone(), target.clone());
        Ok(Self {
            inner: Arc::new(BackendServicesInner {
                target,
                settings,
                connections,
                operation_journal,
                ssh,
                sftp,
                ssh_compatibility: SshCompatibilityService,
                detection,
                docker,
                database,
                log_analysis,
                packet_capture,
                file_analysis,
                investigation,
                report,
                integrity,
                kubernetes,
                middleware,
                system_info,
                ai,
                audit,
                commands,
                baseline,
                java,
                windows_incident,
                response_engine,
                store,
            }),
        })
    }

    pub fn windows_incident(&self) -> &WindowsIncidentService {
        &self.inner.windows_incident
    }

    pub fn baseline(&self) -> &BaselineService {
        &self.inner.baseline
    }

    pub fn middleware(&self) -> &MiddlewareService {
        &self.inner.middleware
    }

    pub fn java(&self) -> &JavaService {
        &self.inner.java
    }

    pub fn store(&self) -> &PortableStore {
        &self.inner.store
    }

    pub fn target(&self) -> &Arc<TargetContext> {
        &self.inner.target
    }

    pub fn settings(&self) -> &SettingsRepository {
        &self.inner.settings
    }

    pub fn connections(&self) -> &ConnectionRepository {
        &self.inner.connections
    }

    pub fn operation_journal(&self) -> &PortableOperationJournal {
        &self.inner.operation_journal
    }

    pub fn ssh(&self) -> &SshService {
        &self.inner.ssh
    }

    pub fn sftp(&self) -> &SftpService {
        &self.inner.sftp
    }

    pub fn ssh_compatibility(&self) -> &SshCompatibilityService {
        &self.inner.ssh_compatibility
    }

    pub fn detection(&self) -> &DetectionService {
        &self.inner.detection
    }

    pub fn docker(&self) -> &DockerService {
        &self.inner.docker
    }

    pub fn database(&self) -> &DatabaseService {
        &self.inner.database
    }

    pub fn log_analysis(&self) -> &LogAnalysisService {
        &self.inner.log_analysis
    }

    pub fn packet_capture(&self) -> &PacketCaptureService {
        &self.inner.packet_capture
    }

    pub fn file_analysis(&self) -> &FileAnalysisService {
        &self.inner.file_analysis
    }

    pub fn investigation(&self) -> &InvestigationRepositories {
        &self.inner.investigation
    }

    pub fn report(&self) -> &ReportService {
        &self.inner.report
    }

    pub fn integrity(&self) -> &IntegrityService {
        &self.inner.integrity
    }

    pub fn kubernetes(&self) -> &KubernetesService {
        &self.inner.kubernetes
    }

    pub fn system_info(&self) -> &SystemInfoService {
        &self.inner.system_info
    }

    pub fn ai(&self) -> CoreResult<&AiService> {
        self.inner.ai.as_ref().ok_or(CoreError::Unsupported {
            feature: "AI service without an injected process Tokio runtime",
        })
    }

    pub fn audit(&self) -> &AuditService {
        &self.inner.audit
    }

    pub fn commands(&self) -> &CommandWorkbenchService {
        &self.inner.commands
    }

    pub fn response_engine(&self) -> &ResponseEngineService {
        &self.inner.response_engine
    }

    pub fn activate_target(&self, identity: TargetIdentity) -> CoreResult<TargetGuard> {
        self.inner.target.activate(identity)
    }

    /// Bind an actor-owned SSH session to an already activated target epoch.
    /// The actor lookup is asynchronous, so both sides of it are validated.
    pub async fn bind_active_ssh_session(
        &self,
        guard: &TargetGuard,
        session_id: &str,
    ) -> CoreResult<BoundSshSession> {
        self.inner.target.validate(guard)?;
        let bound = self
            .inner
            .ssh
            .bind_session(guard.clone(), session_id)
            .await?;
        self.inner.target.validate(guard)?;
        Ok(bound)
    }

    pub fn path_guard(
        &self,
        sensitive_roots: impl IntoIterator<Item = PathBuf>,
    ) -> CoreResult<PathGuard> {
        PathGuard::for_store(&self.inner.store, sensitive_roots)
    }

    /// Run target-bound asynchronous work with the required double validation.
    /// The closure is not invoked if the preflight check fails, and its result is
    /// rejected if identity or generation changes before completion.
    pub async fn run_guarded<T, F, Fut>(&self, guard: &TargetGuard, operation: F) -> CoreResult<T>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = CoreResult<T>>,
    {
        self.inner.target.validate(guard)?;
        let result = operation().await;
        self.inner.target.validate(guard)?;
        result
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};

    use uuid::Uuid;

    use super::*;
    use crate::CoreError;

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("lovelyres-services-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn services() -> (TestRoot, BackendServices) {
        let root = TestRoot::new();
        let store = PortableStore::prepare(root.0.clone()).unwrap();
        let services = BackendServices::new(store).unwrap();
        (root, services)
    }

    #[test]
    fn ai_runtime_is_explicitly_injected_into_the_production_graph() {
        let (_root, services_without_runtime) = services();
        assert!(matches!(
            services_without_runtime.ai(),
            Err(CoreError::Unsupported { .. })
        ));

        let root = TestRoot::new();
        let store = PortableStore::prepare(root.0.clone()).unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let services = BackendServices::with_runtime(store, runtime.handle().clone()).unwrap();
        assert!(services.ai().is_ok());
    }

    #[tokio::test]
    async fn guarded_work_checks_before_dispatch() {
        let (_root, services) = services();
        let old = services
            .activate_target(TargetIdentity::new("first").unwrap())
            .unwrap();
        services
            .activate_target(TargetIdentity::new("second").unwrap())
            .unwrap();
        let invoked = AtomicBool::new(false);
        let result = services
            .run_guarded(&old, || async {
                invoked.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await;
        assert!(matches!(result, Err(CoreError::TargetChanged { .. })));
        assert!(!invoked.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn guarded_work_rejects_result_after_target_switch() {
        let (_root, services) = services();
        let guard = services
            .activate_target(TargetIdentity::new("first").unwrap())
            .unwrap();
        let result = services
            .run_guarded(&guard, || async {
                services
                    .activate_target(TargetIdentity::new("second").unwrap())
                    .unwrap();
                Ok("stale result")
            })
            .await;
        assert!(matches!(result, Err(CoreError::TargetChanged { .. })));
    }

    #[tokio::test]
    async fn ssh_binding_rejects_a_stale_guard_before_actor_lookup() {
        let (_root, services) = services();
        let stale = services
            .activate_target(TargetIdentity::new("first").unwrap())
            .unwrap();
        services
            .activate_target(TargetIdentity::new("second").unwrap())
            .unwrap();

        let result = services
            .bind_active_ssh_session(&stale, "session-that-must-not-be-looked-up")
            .await;
        assert!(matches!(result, Err(CoreError::TargetChanged { .. })));
    }
}
