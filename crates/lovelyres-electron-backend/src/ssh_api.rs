//! Fixed, capability-based Electron boundary for SSH attempts and bindings.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use lovelyres_core::connections::ConnectionProbePlan;
use lovelyres_core::crypto::SecretValue;
use lovelyres_core::ssh::{BoundSshSession, SshConnectAuthorization};
use lovelyres_core::target::TargetIdentity;
use lovelyres_core::{BackendServices, CoreError, CoreResult, SshHostRole};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::connections_api::ConnectionWriteInput;

const MAX_ATTEMPTS: usize = 16;
const ATTEMPT_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_HANDLE_BYTES: usize = 128;
const MAX_MFA_RESPONSES: usize = 16;
const MAX_MFA_RESPONSE_BYTES: usize = 4 * 1024;
const MAX_MFA_TOTAL_BYTES: usize = 32 * 1024;

#[derive(Clone)]
pub struct SshApi {
    services: BackendServices,
    registry: Arc<Mutex<Registry>>,
}

impl fmt::Debug for SshApi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (attempts, bindings) = self
            .registry
            .lock()
            .map(|registry| (registry.attempts.len(), registry.bindings.len()))
            .unwrap_or_default();
        formatter
            .debug_struct("SshApi")
            .field("attempt_count", &attempts)
            .field("binding_count", &bindings)
            .finish()
    }
}

impl SshApi {
    pub fn new(services: BackendServices) -> Self {
        Self {
            services,
            registry: Arc::new(Mutex::new(Registry::default())),
        }
    }

    pub fn start_connect(self: &Arc<Self>, connection_id: String) -> CoreResult<AttemptStartedDto> {
        validate_connection_id(&connection_id)?;
        if self.services.connections().get(&connection_id)?.is_none() {
            return Err(CoreError::NotFound {
                entity: "connection",
                id: "[opaque]".to_owned(),
            });
        }
        self.start(AttemptWork::Connect { connection_id })
    }

    pub fn start_probe(
        self: &Arc<Self>,
        input: ConnectionWriteInput,
    ) -> CoreResult<AttemptStartedDto> {
        let existing = self.services.connections().get(&input.connection.id)?;
        let (config, changes) = input.into_core(existing.as_ref())?;
        let plan = self.services.ssh().prepare_probe(config, changes)?;
        self.start(AttemptWork::Probe {
            plan: Box::new(plan),
        })
    }

    fn start(self: &Arc<Self>, work: AttemptWork) -> CoreResult<AttemptStartedDto> {
        let (handle, run_id, work, authorization) = {
            let mut registry = self.lock_registry()?;
            registry.remove_expired(Instant::now());
            registry.insert(work, Instant::now())?
        };
        self.spawn_run(handle.clone(), run_id, work, authorization);
        Ok(AttemptStartedDto {
            attempt_handle: handle,
            stage: AttemptStage::Running,
        })
    }

    pub fn get_attempt(&self, handle: &str) -> CoreResult<AttemptStatusDto> {
        validate_handle("SSH attempt handle", handle)?;
        let mut registry = self.lock_registry()?;
        registry.remove_expired(Instant::now());
        registry.status(handle)
    }

    pub fn confirm_host_key(
        self: &Arc<Self>,
        attempt_handle: &str,
        prompt_handle: &str,
    ) -> CoreResult<AttemptStatusDto> {
        validate_handle("SSH attempt handle", attempt_handle)?;
        validate_handle("SSH prompt handle", prompt_handle)?;
        let resumed = {
            let mut registry = self.lock_registry()?;
            registry.remove_expired(Instant::now());
            registry.confirm_host_key(attempt_handle, prompt_handle)?
        };
        self.spawn_run(
            attempt_handle.to_owned(),
            resumed.run_id,
            resumed.work,
            resumed.authorization,
        );
        self.get_attempt(attempt_handle)
    }

    pub fn respond_mfa(
        self: &Arc<Self>,
        attempt_handle: &str,
        prompt_handle: &str,
        responses: &mut SecretResponses,
    ) -> CoreResult<AttemptStatusDto> {
        validate_handle("SSH attempt handle", attempt_handle)?;
        validate_handle("SSH prompt handle", prompt_handle)?;
        let secrets = responses.take()?;
        let resumed = {
            let mut registry = self.lock_registry()?;
            registry.remove_expired(Instant::now());
            registry.respond_mfa(attempt_handle, prompt_handle, secrets)?
        };
        self.spawn_run(
            attempt_handle.to_owned(),
            resumed.run_id,
            resumed.work,
            resumed.authorization,
        );
        self.get_attempt(attempt_handle)
    }

    pub fn cancel_attempt(&self, handle: &str) -> CoreResult<AttemptCancelledDto> {
        validate_handle("SSH attempt handle", handle)?;
        let mut registry = self.lock_registry()?;
        registry.remove_expired(Instant::now());
        // Core does not expose a connection-attempt cancellation token. Aborting
        // this task after a session is created could skip disconnect cleanup, so
        // cancellation is logical: the detached result is rejected and any late
        // session is explicitly disconnected before it can become a binding.
        registry.cancel(handle)?;
        Ok(AttemptCancelledDto { cancelled: true })
    }

    pub async fn disconnect_binding(&self, handle: &str) -> CoreResult<BindingDisconnectedDto> {
        validate_handle("SSH binding handle", handle)?;
        let binding = self.lock_registry()?.take_binding(handle)?;
        let disconnected = self
            .services
            .ssh()
            .disconnect(binding.session.session_id())
            .await;
        let cleared = self
            .services
            .target()
            .clear_if_current(binding.session.target())?;
        disconnected?;
        Ok(BindingDisconnectedDto {
            disconnected: true,
            target_cleared: cleared,
        })
    }

    pub(crate) fn binding_session_clone(&self, handle: &str) -> CoreResult<BoundSshSession> {
        validate_handle("SSH binding handle", handle)?;
        self.lock_registry()?.binding_session_clone(handle)
    }

    fn spawn_run(
        self: &Arc<Self>,
        handle: String,
        run_id: u64,
        work: AttemptWork,
        authorization: SshConnectAuthorization,
    ) {
        let api = Arc::clone(self);
        let task_handle = handle.clone();
        tokio::spawn(async move {
            api.run(task_handle, run_id, work, authorization).await;
        });
    }

    async fn run(
        &self,
        handle: String,
        run_id: u64,
        work: AttemptWork,
        authorization: SshConnectAuthorization,
    ) {
        match work {
            AttemptWork::Probe { plan } => {
                match self
                    .services
                    .ssh()
                    .probe_authorized(&plan, authorization)
                    .await
                {
                    Ok(success) => {
                        let committed = self
                            .services
                            .connections()
                            .commit_probe(success.verified_plan);
                        match committed {
                            Ok(view) => {
                                let target = TargetSummaryDto {
                                    connection_id: view.config.id,
                                    host: view.config.host,
                                    port: view.config.port,
                                    username: view.config.username,
                                    timestamp: success.result.checked_at.to_rfc3339(),
                                };
                                self.finish_probe(&handle, run_id, target);
                            }
                            Err(error) => self.finish_error(&handle, run_id, error),
                        }
                    }
                    Err(error) => self.finish_error(&handle, run_id, error),
                }
            }
            AttemptWork::Connect { connection_id } => {
                match self
                    .services
                    .ssh()
                    .connect_authorized(&connection_id, authorization)
                    .await
                {
                    Ok(status) => self.finish_connect(&handle, run_id, status).await,
                    Err(error) => self.finish_error(&handle, run_id, error),
                }
            }
        }
    }

    fn finish_probe(&self, handle: &str, run_id: u64, target: TargetSummaryDto) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.finish_probe(handle, run_id, target);
        }
    }

    fn finish_error(&self, handle: &str, run_id: u64, error: CoreError) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.finish_error(handle, run_id, error);
        }
    }

    async fn finish_connect(
        &self,
        handle: &str,
        run_id: u64,
        status: lovelyres_core::ssh::SshConnectionStatus,
    ) {
        let still_current = self
            .registry
            .lock()
            .map(|registry| registry.is_running(handle, run_id))
            .unwrap_or(false);
        if !still_current {
            let _ = self.services.ssh().disconnect(&status.session_id).await;
            return;
        }

        let identity = match TargetIdentity::new(status.connection_id.clone()) {
            Ok(identity) => identity,
            Err(_) => {
                let _ = self.services.ssh().disconnect(&status.session_id).await;
                self.finish_error(
                    handle,
                    run_id,
                    invalid(
                        "SSH target identity",
                        "the connected target identity is invalid",
                    ),
                );
                return;
            }
        };
        let guard = match self.services.activate_target(identity) {
            Ok(guard) => guard,
            Err(error) => {
                let _ = self.services.ssh().disconnect(&status.session_id).await;
                self.finish_error(handle, run_id, error);
                return;
            }
        };
        let bound = match self
            .services
            .bind_active_ssh_session(&guard, &status.session_id)
            .await
        {
            Ok(bound) => bound,
            Err(error) => {
                let _ = self.services.ssh().disconnect(&status.session_id).await;
                let _ = self.services.target().clear_if_current(&guard);
                self.finish_error(handle, run_id, error);
                return;
            }
        };
        let target = TargetSummaryDto {
            connection_id: status.connection_id,
            host: status.host,
            port: status.port,
            username: status.username,
            timestamp: status.connected_at.to_rfc3339(),
        };
        let result = self
            .lock_registry()
            .map(|mut registry| registry.finish_connect(handle, run_id, bound, target));
        match result {
            Ok(Ok(Some(old_binding))) => {
                let _ = self
                    .services
                    .ssh()
                    .disconnect(old_binding.session.session_id())
                    .await;
            }
            Ok(Ok(None)) => {}
            Ok(Err(late_session)) => {
                let _ = self
                    .services
                    .ssh()
                    .disconnect(late_session.session_id())
                    .await;
                let _ = self
                    .services
                    .target()
                    .clear_if_current(late_session.target());
            }
            Err(_) => {
                let _ = self.services.ssh().disconnect(&status.session_id).await;
                let _ = self.services.target().clear_if_current(&guard);
            }
        }
    }

    fn lock_registry(&self) -> CoreResult<MutexGuard<'_, Registry>> {
        self.registry
            .lock()
            .map_err(|_| invalid("SSH attempt registry", "internal registry is unavailable"))
    }
}

#[derive(Clone, Debug)]
enum AttemptWork {
    Connect { connection_id: String },
    Probe { plan: Box<ConnectionProbePlan> },
}

#[derive(Debug)]
struct Attempt {
    expires_at: Instant,
    run_id: u64,
    // Probe work can contain write-only credentials. Retain it only while an
    // attempt may need a host-key/MFA resume and drop it at every terminal
    // state instead of leaving secrets resident for the status TTL.
    work: Option<AttemptWork>,
    authorization: SshConnectAuthorization,
    state: AttemptState,
    cancel_consumed: bool,
}

#[derive(Debug)]
enum AttemptState {
    Running,
    AwaitingHostKey(HostKeyPromptDto),
    AwaitingMfa(MfaPromptDto),
    ProbeSucceeded(TargetSummaryDto),
    Connected {
        binding_handle: String,
        target: TargetSummaryDto,
    },
    Failed(AttemptErrorDto),
    Cancelled,
}

#[derive(Debug)]
struct Binding {
    session: BoundSshSession,
}

#[derive(Default, Debug)]
struct Registry {
    attempts: HashMap<String, Attempt>,
    bindings: HashMap<String, Binding>,
}

#[derive(Debug)]
struct ResumedRun {
    run_id: u64,
    work: AttemptWork,
    authorization: SshConnectAuthorization,
}

impl Registry {
    fn insert(
        &mut self,
        work: AttemptWork,
        now: Instant,
    ) -> CoreResult<(String, u64, AttemptWork, SshConnectAuthorization)> {
        if self.attempts.len() >= MAX_ATTEMPTS {
            return Err(invalid(
                "SSH attempt registry",
                "at most 16 attempts may be retained",
            ));
        }
        let handle = unique_handle(&self.attempts)?;
        let authorization = SshConnectAuthorization::default();
        self.attempts.insert(
            handle.clone(),
            Attempt {
                expires_at: now + ATTEMPT_TTL,
                run_id: 1,
                work: Some(work.clone()),
                authorization: authorization.clone(),
                state: AttemptState::Running,
                cancel_consumed: false,
            },
        );
        Ok((handle, 1, work, authorization))
    }

    fn is_running(&self, handle: &str, run_id: u64) -> bool {
        self.attempts.get(handle).is_some_and(|attempt| {
            attempt.run_id == run_id && matches!(attempt.state, AttemptState::Running)
        })
    }

    fn status(&self, handle: &str) -> CoreResult<AttemptStatusDto> {
        let attempt = self.attempts.get(handle).ok_or_else(attempt_not_found)?;
        Ok(AttemptStatusDto::from_state(&attempt.state))
    }

    fn confirm_host_key(
        &mut self,
        attempt_handle: &str,
        prompt_handle: &str,
    ) -> CoreResult<ResumedRun> {
        let attempt = self
            .attempts
            .get_mut(attempt_handle)
            .ok_or_else(attempt_not_found)?;
        let prompt = match &attempt.state {
            AttemptState::AwaitingHostKey(prompt) if prompt.prompt_handle == prompt_handle => {
                prompt.clone()
            }
            _ => return Err(prompt_not_found()),
        };
        match prompt.role {
            SshHostRole::Target => {
                attempt.authorization.host_keys_mut().target_fingerprint = Some(prompt.fingerprint)
            }
            SshHostRole::JumpHost => {
                attempt.authorization.host_keys_mut().jump_host_fingerprint =
                    Some(prompt.fingerprint)
            }
        }
        Self::resume(attempt)
    }

    fn respond_mfa(
        &mut self,
        attempt_handle: &str,
        prompt_handle: &str,
        responses: Vec<SecretValue>,
    ) -> CoreResult<ResumedRun> {
        let attempt = self
            .attempts
            .get_mut(attempt_handle)
            .ok_or_else(attempt_not_found)?;
        let prompt = match &attempt.state {
            AttemptState::AwaitingMfa(prompt) if prompt.prompt_handle == prompt_handle => prompt,
            _ => return Err(prompt_not_found()),
        };
        if responses.len() != prompt.prompts.len() {
            return Err(invalid(
                "SSH MFA responses",
                "the response count must match the one-time prompt",
            ));
        }
        attempt
            .authorization
            .extend_keyboard_interactive_responses(prompt.role, responses)?;
        Self::resume(attempt)
    }

    fn resume(attempt: &mut Attempt) -> CoreResult<ResumedRun> {
        attempt.run_id = attempt
            .run_id
            .checked_add(1)
            .ok_or_else(|| invalid("SSH attempt run", "run counter exhausted"))?;
        attempt.state = AttemptState::Running;
        Ok(ResumedRun {
            run_id: attempt.run_id,
            work: attempt
                .work
                .as_ref()
                .ok_or_else(|| invalid("SSH attempt work", "terminal work was already released"))?
                .clone(),
            authorization: attempt.authorization.clone(),
        })
    }

    fn finish_error(&mut self, handle: &str, run_id: u64, error: CoreError) {
        let Some(attempt) = self.attempts.get_mut(handle) else {
            return;
        };
        if attempt.run_id != run_id || !matches!(attempt.state, AttemptState::Running) {
            return;
        }
        let state = match error {
            CoreError::SshHostKeyConfirmationRequired {
                role,
                host,
                port,
                username,
                fingerprint,
            } => AttemptState::AwaitingHostKey(HostKeyPromptDto {
                prompt_handle: Uuid::new_v4().to_string(),
                role,
                host,
                port,
                username,
                fingerprint,
            }),
            CoreError::SshKeyboardInteractiveRequired { challenge } => {
                AttemptState::AwaitingMfa(MfaPromptDto {
                    prompt_handle: Uuid::new_v4().to_string(),
                    role: challenge.role,
                    host: challenge.host,
                    port: challenge.port,
                    username: challenge.username,
                    name: challenge.name,
                    instructions: challenge.instructions,
                    prompts: challenge
                        .prompts
                        .into_iter()
                        .map(|prompt| MfaFieldDto {
                            prompt: prompt.prompt,
                            echo: prompt.echo,
                        })
                        .collect(),
                })
            }
            CoreError::SshHostKeyChanged {
                role, host, port, ..
            } => AttemptState::Failed(AttemptErrorDto {
                code: "host-key-changed",
                message: "The recorded SSH host key changed. Automatic repinning is not supported.",
                role: Some(role),
                host: Some(host),
                port: Some(port),
                repin_supported: Some(false),
            }),
            _ => AttemptState::Failed(AttemptErrorDto {
                code: "ssh-attempt-failed",
                message: "LovelyRes could not complete the SSH attempt.",
                role: None,
                host: None,
                port: None,
                repin_supported: None,
            }),
        };
        if matches!(state, AttemptState::Failed(_)) {
            attempt.authorization = SshConnectAuthorization::default();
            attempt.work = None;
        }
        attempt.state = state;
    }

    fn finish_probe(&mut self, handle: &str, run_id: u64, target: TargetSummaryDto) {
        let Some(attempt) = self.attempts.get_mut(handle) else {
            return;
        };
        if attempt.run_id == run_id && matches!(attempt.state, AttemptState::Running) {
            attempt.authorization = SshConnectAuthorization::default();
            attempt.work = None;
            attempt.state = AttemptState::ProbeSucceeded(target);
        }
    }

    fn finish_connect(
        &mut self,
        handle: &str,
        run_id: u64,
        session: BoundSshSession,
        target: TargetSummaryDto,
    ) -> Result<Option<Binding>, BoundSshSession> {
        let Some(attempt) = self.attempts.get_mut(handle) else {
            return Err(session);
        };
        if attempt.run_id != run_id || !matches!(attempt.state, AttemptState::Running) {
            return Err(session);
        }
        let binding_handle = Uuid::new_v4().to_string();
        let old_binding = self.bindings.drain().next().map(|(_, binding)| binding);
        self.bindings
            .insert(binding_handle.clone(), Binding { session });
        attempt.authorization = SshConnectAuthorization::default();
        attempt.work = None;
        attempt.state = AttemptState::Connected {
            binding_handle,
            target,
        };
        Ok(old_binding)
    }

    fn cancel(&mut self, handle: &str) -> CoreResult<()> {
        let attempt = self
            .attempts
            .get_mut(handle)
            .ok_or_else(attempt_not_found)?;
        if attempt.cancel_consumed
            || !matches!(
                attempt.state,
                AttemptState::Running
                    | AttemptState::AwaitingHostKey(_)
                    | AttemptState::AwaitingMfa(_)
            )
        {
            return Err(invalid(
                "SSH attempt cancellation",
                "the attempt is no longer cancellable",
            ));
        }
        attempt.cancel_consumed = true;
        attempt.authorization = SshConnectAuthorization::default();
        attempt.work = None;
        attempt.state = AttemptState::Cancelled;
        Ok(())
    }

    fn take_binding(&mut self, handle: &str) -> CoreResult<Binding> {
        self.bindings
            .remove(handle)
            .ok_or_else(|| CoreError::NotFound {
                entity: "SSH binding",
                id: "[opaque]".to_owned(),
            })
    }

    fn binding_session_clone(&self, handle: &str) -> CoreResult<BoundSshSession> {
        self.bindings
            .get(handle)
            .map(|binding| binding.session.clone())
            .ok_or_else(|| CoreError::NotFound {
                entity: "SSH binding",
                id: "[opaque]".to_owned(),
            })
    }

    fn remove_expired(&mut self, now: Instant) {
        self.attempts.retain(|_, attempt| attempt.expires_at > now);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttemptStage {
    Running,
    AwaitingHostKey,
    AwaitingMfa,
    ProbeSucceeded,
    Connected,
    Failed,
    Cancelled,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttemptStartedDto {
    pub attempt_handle: String,
    pub stage: AttemptStage,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttemptStatusDto {
    pub stage: AttemptStage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_key_prompt: Option<HostKeyPromptDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_prompt: Option<MfaPromptDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding_handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<TargetSummaryDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<AttemptErrorDto>,
}

impl AttemptStatusDto {
    fn from_state(state: &AttemptState) -> Self {
        let mut status = Self {
            stage: AttemptStage::Running,
            host_key_prompt: None,
            mfa_prompt: None,
            binding_handle: None,
            target: None,
            error: None,
        };
        match state {
            AttemptState::Running => {}
            AttemptState::AwaitingHostKey(prompt) => {
                status.stage = AttemptStage::AwaitingHostKey;
                status.host_key_prompt = Some(prompt.clone());
            }
            AttemptState::AwaitingMfa(prompt) => {
                status.stage = AttemptStage::AwaitingMfa;
                status.mfa_prompt = Some(prompt.clone());
            }
            AttemptState::ProbeSucceeded(target) => {
                status.stage = AttemptStage::ProbeSucceeded;
                status.target = Some(target.clone());
            }
            AttemptState::Connected {
                binding_handle,
                target,
            } => {
                status.stage = AttemptStage::Connected;
                status.binding_handle = Some(binding_handle.clone());
                status.target = Some(target.clone());
            }
            AttemptState::Failed(error) => {
                status.stage = AttemptStage::Failed;
                status.error = Some(error.clone());
            }
            AttemptState::Cancelled => status.stage = AttemptStage::Cancelled,
        }
        status
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostKeyPromptDto {
    pub prompt_handle: String,
    pub role: SshHostRole,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub fingerprint: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MfaPromptDto {
    pub prompt_handle: String,
    pub role: SshHostRole,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub name: String,
    pub instructions: String,
    pub prompts: Vec<MfaFieldDto>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MfaFieldDto {
    pub prompt: String,
    pub echo: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetSummaryDto {
    pub connection_id: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub timestamp: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttemptErrorDto {
    pub code: &'static str,
    pub message: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<SshHostRole>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repin_supported: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttemptCancelledDto {
    pub cancelled: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BindingDisconnectedDto {
    pub disconnected: bool,
    pub target_cleared: bool,
}

#[derive(Deserialize)]
#[serde(transparent)]
pub struct SecretResponses {
    responses: Vec<String>,
}

impl SecretResponses {
    fn take(&mut self) -> CoreResult<Vec<SecretValue>> {
        if self.responses.is_empty()
            || self.responses.len() > MAX_MFA_RESPONSES
            || self
                .responses
                .iter()
                .any(|response| response.len() > MAX_MFA_RESPONSE_BYTES)
            || self.responses.iter().map(String::len).sum::<usize>() > MAX_MFA_TOTAL_BYTES
        {
            return Err(invalid(
                "SSH MFA responses",
                "responses exceed the fixed count or byte limits",
            ));
        }
        Ok(std::mem::take(&mut self.responses)
            .into_iter()
            .map(SecretValue::new)
            .collect())
    }
}

impl fmt::Debug for SecretResponses {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretResponses")
            .field("response_count", &self.responses.len())
            .finish()
    }
}

impl Drop for SecretResponses {
    fn drop(&mut self) {
        self.responses.iter_mut().for_each(Zeroize::zeroize);
    }
}

fn unique_handle<T>(existing: &HashMap<String, T>) -> CoreResult<String> {
    for _ in 0..8 {
        let handle = Uuid::new_v4().to_string();
        if !existing.contains_key(&handle) {
            return Ok(handle);
        }
    }
    Err(invalid(
        "SSH opaque handle",
        "could not allocate a unique capability",
    ))
}

fn validate_connection_id(value: &str) -> CoreResult<()> {
    if value.trim().is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(invalid(
            "SSH connection id",
            "must be non-empty, at most 128 bytes, and contain no controls",
        ));
    }
    Ok(())
}

fn validate_handle(subject: &'static str, value: &str) -> CoreResult<()> {
    if value.is_empty()
        || value.len() > MAX_HANDLE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(invalid(subject, "must be a bounded opaque identifier"));
    }
    Ok(())
}

fn attempt_not_found() -> CoreError {
    CoreError::NotFound {
        entity: "SSH attempt",
        id: "[opaque]".to_owned(),
    }
}

fn prompt_not_found() -> CoreError {
    CoreError::NotFound {
        entity: "SSH one-time prompt",
        id: "[opaque]".to_owned(),
    }
}

fn invalid(subject: &'static str, message: impl Into<String>) -> CoreError {
    CoreError::Validation {
        subject,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use lovelyres_core::{SshKeyboardInteractiveChallenge, SshKeyboardInteractivePrompt};
    use serde_json::json;

    use super::*;

    fn running_registry() -> (Registry, String) {
        let mut registry = Registry::default();
        let (handle, _, _, _) = registry
            .insert(
                AttemptWork::Connect {
                    connection_id: "server-1".to_owned(),
                },
                Instant::now(),
            )
            .unwrap();
        (registry, handle)
    }

    #[test]
    fn host_key_prompt_is_one_time_and_does_not_accept_renderer_fingerprints() {
        let (mut registry, handle) = running_registry();
        registry.finish_error(
            &handle,
            1,
            CoreError::SshHostKeyConfirmationRequired {
                role: SshHostRole::Target,
                host: "server.example".to_owned(),
                port: 22,
                username: "root".to_owned(),
                fingerprint: "SHA256:observed".to_owned(),
            },
        );
        let status = registry.status(&handle).unwrap();
        let prompt = status.host_key_prompt.unwrap();
        let resumed = registry
            .confirm_host_key(&handle, &prompt.prompt_handle)
            .unwrap();
        assert_eq!(resumed.run_id, 2);
        assert_eq!(
            resumed
                .authorization
                .host_keys()
                .target_fingerprint
                .as_deref(),
            Some("SHA256:observed")
        );
        assert!(
            registry
                .confirm_host_key(&handle, &prompt.prompt_handle)
                .is_err()
        );
    }

    #[test]
    fn mfa_prompt_is_one_time_bounded_and_debug_redacted() {
        let (mut registry, handle) = running_registry();
        registry.finish_error(
            &handle,
            1,
            CoreError::SshKeyboardInteractiveRequired {
                challenge: Box::new(SshKeyboardInteractiveChallenge {
                    role: SshHostRole::Target,
                    host: "server.example".to_owned(),
                    port: 22,
                    username: "root".to_owned(),
                    name: "Verification".to_owned(),
                    instructions: "Enter the current code".to_owned(),
                    prompts: vec![SshKeyboardInteractivePrompt {
                        prompt: "Code:".to_owned(),
                        echo: false,
                    }],
                    supplied_responses: 0,
                }),
            },
        );
        let prompt = registry
            .status(&handle)
            .unwrap()
            .mfa_prompt
            .unwrap()
            .prompt_handle;
        let mut input: SecretResponses = serde_json::from_value(json!(["do-not-print"])).unwrap();
        assert!(!format!("{input:?}").contains("do-not-print"));
        let resumed = registry
            .respond_mfa(&handle, &prompt, input.take().unwrap())
            .unwrap();
        assert_eq!(
            resumed
                .authorization
                .keyboard_interactive_response_count(SshHostRole::Target),
            1
        );
        registry.finish_error(
            &handle,
            resumed.run_id,
            CoreError::Ssh {
                operation: "authenticate",
                message: "rejected".to_owned(),
            },
        );
        assert_eq!(
            registry.attempts[&handle]
                .authorization
                .keyboard_interactive_response_count(SshHostRole::Target),
            0
        );
        assert!(registry.respond_mfa(&handle, &prompt, Vec::new()).is_err());

        let mut oversized: SecretResponses =
            serde_json::from_value(json!(["x".repeat(MAX_MFA_RESPONSE_BYTES + 1)])).unwrap();
        assert!(oversized.take().is_err());
    }

    #[test]
    fn changed_host_key_hard_rejects_without_exposing_fingerprints() {
        let (mut registry, handle) = running_registry();
        registry.finish_error(
            &handle,
            1,
            CoreError::SshHostKeyChanged {
                role: SshHostRole::JumpHost,
                host: "jump.example".to_owned(),
                port: 22,
                expected: "SHA256:recorded-secret-capability".to_owned(),
                observed: "SHA256:hostile-observed".to_owned(),
            },
        );
        let encoded = serde_json::to_string(&registry.status(&handle).unwrap()).unwrap();
        assert!(encoded.contains("host-key-changed"));
        assert!(encoded.contains("\"repinSupported\":false"));
        assert!(!encoded.contains("recorded-secret-capability"));
        assert!(!encoded.contains("hostile-observed"));
    }

    #[test]
    fn registry_caps_attempts_expires_entries_and_rejects_late_results() {
        let mut registry = Registry::default();
        let now = Instant::now();
        let mut first = None;
        for index in 0..MAX_ATTEMPTS {
            let (handle, _, _, _) = registry
                .insert(
                    AttemptWork::Connect {
                        connection_id: format!("server-{index}"),
                    },
                    now,
                )
                .unwrap();
            first.get_or_insert(handle);
        }
        assert!(
            registry
                .insert(
                    AttemptWork::Connect {
                        connection_id: "overflow".to_owned(),
                    },
                    now,
                )
                .is_err()
        );
        let first = first.unwrap();
        registry.attempts.get_mut(&first).unwrap().expires_at = now;
        registry.remove_expired(now);
        registry.finish_error(
            &first,
            1,
            CoreError::Ssh {
                operation: "test",
                message: "late hostile detail".to_owned(),
            },
        );
        assert!(registry.status(&first).is_err());
    }

    #[test]
    fn cancellation_is_one_time_and_late_completion_cannot_overwrite_it() {
        let (mut registry, handle) = running_registry();
        registry.cancel(&handle).unwrap();
        assert!(registry.attempts[&handle].work.is_none());
        assert!(registry.cancel(&handle).is_err());
        registry.finish_error(
            &handle,
            1,
            CoreError::Ssh {
                operation: "test",
                message: "late".to_owned(),
            },
        );
        assert_eq!(
            registry.status(&handle).unwrap().stage,
            AttemptStage::Cancelled
        );
    }

    #[test]
    fn terminal_failure_releases_resumable_work_immediately() {
        let (mut registry, handle) = running_registry();
        registry.finish_error(
            &handle,
            1,
            CoreError::Ssh {
                operation: "test",
                message: "terminal".to_owned(),
            },
        );
        assert_eq!(
            registry.status(&handle).unwrap().stage,
            AttemptStage::Failed
        );
        assert!(registry.attempts[&handle].work.is_none());
    }

    #[test]
    fn public_status_never_contains_core_session_guard_authorization_or_digest_fields() {
        let (registry, handle) = running_registry();
        let encoded = serde_json::to_string(&registry.status(&handle).unwrap()).unwrap();
        for forbidden in [
            "sessionId",
            "generation",
            "authorization",
            "snapshotDigest",
            "expectedDigest",
            "secret",
        ] {
            assert!(!encoded.contains(forbidden));
        }
    }
}
