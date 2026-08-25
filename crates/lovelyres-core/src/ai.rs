//! Typed AI HTTP services with bounded responses and per-stream cancellation.
//!
//! The native UI selects a configured provider and supplies structured messages.
//! It cannot supply an outbound URL, HTTP headers, or an API key. Secrets are
//! resolved from the portable settings repository only inside the Tokio task that
//! sends the request and are held in a zeroizing value for the shortest practical
//! lifetime.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use futures::StreamExt as _;
use parking_lot::Mutex;
use reqwest::header::{AUTHORIZATION, HeaderName, HeaderValue};
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tokio::runtime::Handle;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::crypto::SecretValue;
use crate::events::{
    AiStreamEvent, AiStreamEventKind, AiStreamEventReceiver, AiStreamEventSender,
    ai_stream_event_channel,
};
use crate::net_guard::{
    ProxySettings, filter_headers, http_client, stream_client, validate_outbound_url,
};
use crate::settings::{AiProviderKind, SettingsRepository};
use crate::{CoreError, CoreResult};

const HARD_MAX_MESSAGES: usize = 256;
const HARD_MAX_MESSAGE_BYTES: usize = 1_048_576;
const HARD_MAX_REQUEST_BYTES: usize = 2_097_152;
const HARD_MAX_RESPONSE_BYTES: usize = 16_777_216;
const HARD_MAX_STREAM_CHUNK_BYTES: usize = 262_144;
const HARD_MAX_STREAM_TOTAL_BYTES: usize = 67_108_864;
const HARD_MAX_EVENT_CAPACITY: usize = 4_096;
const HARD_MAX_MODELS: usize = 4_096;
const HARD_MAX_MODEL_ID_BYTES: usize = 1_024;
const MAX_PROVIDER_ID_BYTES: usize = 128;
const MAX_STREAM_ID_BYTES: usize = 128;
const MAX_OUTPUT_TOKENS: u32 = 1_000_000;
const MAX_REMOTE_ERROR_CHARS: usize = 512;
const MAX_EVENT_ERROR_CHARS: usize = 2_048;

/// Resource limits applied before allocation or event delivery.
///
/// `AiService::with_limits` rejects values above the hard ceilings, so callers
/// cannot accidentally turn a native UI preference into an unbounded request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiLimits {
    pub max_messages: usize,
    pub max_message_bytes: usize,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub max_stream_chunk_bytes: usize,
    pub max_stream_total_bytes: usize,
    pub stream_event_capacity: usize,
    pub max_models: usize,
    pub max_model_id_bytes: usize,
    pub stream_idle_timeout: Duration,
}

impl Default for AiLimits {
    fn default() -> Self {
        Self {
            max_messages: 128,
            max_message_bytes: 262_144,
            max_request_bytes: 1_048_576,
            max_response_bytes: 8_388_608,
            max_stream_chunk_bytes: 65_536,
            max_stream_total_bytes: 33_554_432,
            stream_event_capacity: 128,
            max_models: 1_024,
            max_model_id_bytes: 256,
            stream_idle_timeout: Duration::from_secs(120),
        }
    }
}

impl AiLimits {
    fn validate(&self) -> CoreResult<()> {
        validate_limit("AI message count", self.max_messages, HARD_MAX_MESSAGES)?;
        validate_limit(
            "AI message bytes",
            self.max_message_bytes,
            HARD_MAX_MESSAGE_BYTES,
        )?;
        validate_limit(
            "AI request bytes",
            self.max_request_bytes,
            HARD_MAX_REQUEST_BYTES,
        )?;
        validate_limit(
            "AI response bytes",
            self.max_response_bytes,
            HARD_MAX_RESPONSE_BYTES,
        )?;
        validate_limit(
            "AI stream chunk bytes",
            self.max_stream_chunk_bytes,
            HARD_MAX_STREAM_CHUNK_BYTES,
        )?;
        validate_limit(
            "AI stream total bytes",
            self.max_stream_total_bytes,
            HARD_MAX_STREAM_TOTAL_BYTES,
        )?;
        validate_limit(
            "AI stream event capacity",
            self.stream_event_capacity,
            HARD_MAX_EVENT_CAPACITY,
        )?;
        validate_limit("AI model count", self.max_models, HARD_MAX_MODELS)?;
        validate_limit(
            "AI model ID bytes",
            self.max_model_id_bytes,
            HARD_MAX_MODEL_ID_BYTES,
        )?;
        if self.max_stream_chunk_bytes < 4 {
            return Err(CoreError::validation(
                "AI stream chunk bytes",
                "must be at least four bytes so one UTF-8 scalar always fits",
            ));
        }
        if self.max_stream_chunk_bytes > self.max_stream_total_bytes {
            return Err(CoreError::validation(
                "AI stream limits",
                "chunk limit must not exceed total limit",
            ));
        }
        if self.max_message_bytes > self.max_request_bytes {
            return Err(CoreError::validation(
                "AI request limits",
                "one message must not exceed the complete request limit",
            ));
        }
        if self.stream_idle_timeout.is_zero() || self.stream_idle_timeout > Duration::from_secs(600)
        {
            return Err(CoreError::validation(
                "AI stream idle timeout",
                "must be greater than zero and at most ten minutes",
            ));
        }
        Ok(())
    }
}

fn validate_limit(subject: &'static str, value: usize, hard_maximum: usize) -> CoreResult<()> {
    if value == 0 || value > hard_maximum {
        return Err(CoreError::validation(
            subject,
            format!("must be 1..={hard_maximum}"),
        ));
    }
    Ok(())
}

/// Validated identifier of a provider stored in typed settings.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AiProviderId(String);

impl AiProviderId {
    pub fn new(value: impl Into<String>) -> CoreResult<Self> {
        let value = value.into();
        validate_identifier("AI provider ID", &value, MAX_PROVIDER_ID_BYTES)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AiProviderId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A caller-chosen stream identifier. Each active ID is unique per service.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AiStreamId(String);

impl AiStreamId {
    pub fn new(value: impl Into<String>) -> CoreResult<Self> {
        let value = value.into();
        validate_identifier("AI stream ID", &value, MAX_STREAM_ID_BYTES)?;
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
        {
            return Err(CoreError::validation(
                "AI stream ID",
                "must contain only ASCII letters, digits, '-', '_', '.', or ':'",
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AiStreamId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

fn validate_identifier(subject: &'static str, value: &str, maximum: usize) -> CoreResult<()> {
    if value.trim().is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(CoreError::validation(
            subject,
            format!("must be non-empty, control-free, and at most {maximum} bytes"),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AiMessageRole {
    System,
    User,
    Assistant,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiMessage {
    role: AiMessageRole,
    content: String,
}

impl AiMessage {
    pub fn new(role: AiMessageRole, content: impl Into<String>) -> Self {
        Self {
            role,
            content: content.into(),
        }
    }

    pub fn role(&self) -> AiMessageRole {
        self.role
    }

    pub fn content(&self) -> &str {
        &self.content
    }
}

/// Provider-selected completion input. URL, headers, model, and credentials are
/// deliberately absent; those values come from typed portable settings.
#[derive(Debug, Clone, PartialEq)]
pub struct AiCompletionRequest {
    provider_id: AiProviderId,
    messages: Vec<AiMessage>,
    temperature: Option<f32>,
    max_output_tokens: Option<u32>,
}

impl AiCompletionRequest {
    pub fn new(provider_id: AiProviderId, messages: Vec<AiMessage>) -> Self {
        Self {
            provider_id,
            messages,
            temperature: None,
            max_output_tokens: None,
        }
    }

    pub fn with_temperature(mut self, temperature: f32) -> Self {
        self.temperature = Some(temperature);
        self
    }

    pub fn with_max_output_tokens(mut self, maximum: u32) -> Self {
        self.max_output_tokens = Some(maximum);
        self
    }

    pub fn provider_id(&self) -> &AiProviderId {
        &self.provider_id
    }

    pub fn messages(&self) -> &[AiMessage] {
        &self.messages
    }

    fn validate(&self, limits: &AiLimits) -> CoreResult<()> {
        if self.messages.is_empty() || self.messages.len() > limits.max_messages {
            return Err(CoreError::validation(
                "AI messages",
                format!("must contain 1..={} messages", limits.max_messages),
            ));
        }
        let mut total = 0_usize;
        for message in &self.messages {
            if message.content.is_empty() || message.content.len() > limits.max_message_bytes {
                return Err(CoreError::validation(
                    "AI message",
                    format!(
                        "content must be non-empty and at most {} bytes",
                        limits.max_message_bytes
                    ),
                ));
            }
            total = total.checked_add(message.content.len()).ok_or_else(|| {
                CoreError::validation("AI request", "message byte count overflowed")
            })?;
            if total > limits.max_request_bytes {
                return Err(CoreError::validation(
                    "AI request",
                    format!("message content exceeds {} bytes", limits.max_request_bytes),
                ));
            }
        }
        if let Some(temperature) = self.temperature
            && (!temperature.is_finite() || !(0.0..=2.0).contains(&temperature))
        {
            return Err(CoreError::validation(
                "AI temperature",
                "must be finite and in the range 0..=2",
            ));
        }
        if let Some(maximum) = self.max_output_tokens
            && !(1..=MAX_OUTPUT_TOKENS).contains(&maximum)
        {
            return Err(CoreError::validation(
                "AI maximum output tokens",
                format!("must be 1..={MAX_OUTPUT_TOKENS}"),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AiStreamRequest {
    stream_id: AiStreamId,
    completion: AiCompletionRequest,
}

impl AiStreamRequest {
    pub fn new(stream_id: AiStreamId, completion: AiCompletionRequest) -> Self {
        Self {
            stream_id,
            completion,
        }
    }

    pub fn stream_id(&self) -> &AiStreamId {
        &self.stream_id
    }

    pub fn completion(&self) -> &AiCompletionRequest {
        &self.completion
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AiCompletionResponse {
    pub provider_id: String,
    pub status: u16,
    pub body: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiModelList {
    pub provider_id: String,
    pub models: Vec<String>,
}

/// A Tokio-owned task that can be awaited from a frontend bridge without
/// running the HTTP future on the caller's executor. Dropping it aborts
/// unfinished work.
#[must_use = "dropping an AI task aborts the request"]
#[derive(Debug)]
pub struct AiTask<T> {
    join: Option<JoinHandle<CoreResult<T>>>,
}

impl<T> AiTask<T> {
    fn new(join: JoinHandle<CoreResult<T>>) -> Self {
        Self { join: Some(join) }
    }

    pub async fn wait(mut self) -> CoreResult<T> {
        let join = self
            .join
            .take()
            .expect("AI task join handle is present until wait");
        join.await.map_err(task_join_error)?
    }
}

impl<T> Drop for AiTask<T> {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}

fn task_join_error(error: tokio::task::JoinError) -> CoreError {
    CoreError::validation("AI runtime task", format!("Tokio task failed: {error}"))
}

/// A typed cancellation capability for exactly one stream.
#[derive(Debug, Clone)]
pub struct AiStreamCancellation {
    stream_id: AiStreamId,
    sender: watch::Sender<bool>,
}

impl AiStreamCancellation {
    pub fn stream_id(&self) -> &AiStreamId {
        &self.stream_id
    }

    /// Returns true only for the first cancellation request.
    pub fn cancel(&self) -> bool {
        !self.sender.send_replace(true)
    }

    pub fn is_cancelled(&self) -> bool {
        *self.sender.borrow()
    }
}

/// Per-request event receiver. It checks every event's stream ID and synthesizes
/// a terminal cancellation event even when the bounded data channel is full.
#[derive(Debug)]
pub struct AiEventStream {
    expected: AiStreamId,
    receiver: AiStreamEventReceiver,
    cancellation: watch::Receiver<bool>,
    sequence: Arc<AtomicU64>,
    terminal_delivered: bool,
}

impl AiEventStream {
    fn new(
        expected: AiStreamId,
        receiver: AiStreamEventReceiver,
        cancellation: watch::Receiver<bool>,
        sequence: Arc<AtomicU64>,
    ) -> Self {
        Self {
            expected,
            receiver,
            cancellation,
            sequence,
            terminal_delivered: false,
        }
    }

    pub fn stream_id(&self) -> &AiStreamId {
        &self.expected
    }

    pub fn len(&self) -> usize {
        self.receiver.len()
    }

    pub fn is_empty(&self) -> bool {
        self.receiver.is_empty()
    }

    pub async fn recv(&mut self) -> CoreResult<AiStreamEvent> {
        if self.terminal_delivered {
            return Err(CoreError::ChannelClosed { channel: "AI" });
        }
        if *self.cancellation.borrow() {
            return Ok(self.cancelled_event());
        }

        let event = tokio::select! {
            biased;
            _ = cancellation_requested(&mut self.cancellation) => {
                return Ok(self.cancelled_event());
            }
            event = self.receiver.recv() => event?,
        };
        if event.stream_id != self.expected.as_str() {
            self.terminal_delivered = true;
            return Err(CoreError::validation(
                "AI stream event",
                "event stream ID did not match its typed receiver",
            ));
        }
        if matches!(
            event.kind,
            AiStreamEventKind::Completed
                | AiStreamEventKind::Cancelled
                | AiStreamEventKind::Failed { .. }
        ) {
            self.terminal_delivered = true;
        }
        Ok(event)
    }

    fn cancelled_event(&mut self) -> AiStreamEvent {
        self.terminal_delivered = true;
        AiStreamEvent {
            stream_id: self.expected.to_string(),
            sequence: next_sequence(&self.sequence),
            kind: AiStreamEventKind::Cancelled,
        }
    }
}

/// A running streaming request, its bounded events, and its cancellation handle.
#[must_use = "the stream task must be consumed or explicitly cancelled"]
#[derive(Debug)]
pub struct AiStreamTask {
    events: AiEventStream,
    cancellation: AiStreamCancellation,
    join: Option<JoinHandle<CoreResult<()>>>,
}

impl AiStreamTask {
    pub fn events(&mut self) -> &mut AiEventStream {
        &mut self.events
    }

    pub fn cancellation(&self) -> AiStreamCancellation {
        self.cancellation.clone()
    }

    pub async fn wait(&mut self) -> CoreResult<()> {
        let Some(join) = self.join.take() else {
            return Ok(());
        };
        join.await.map_err(task_join_error)?
    }
}

impl Drop for AiStreamTask {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}

/// Pure-core AI service. The process-level Tokio runtime is injected explicitly.
#[derive(Debug, Clone)]
pub struct AiService {
    runtime: Handle,
    settings: SettingsRepository,
    limits: AiLimits,
    active_streams: Arc<Mutex<HashSet<AiStreamId>>>,
}

impl AiService {
    pub fn new(runtime: Handle, settings: SettingsRepository) -> Self {
        Self {
            runtime,
            settings,
            limits: AiLimits::default(),
            active_streams: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn with_limits(
        runtime: Handle,
        settings: SettingsRepository,
        limits: AiLimits,
    ) -> CoreResult<Self> {
        limits.validate()?;
        Ok(Self {
            runtime,
            settings,
            limits,
            active_streams: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    pub fn submit_completion(
        &self,
        request: AiCompletionRequest,
    ) -> CoreResult<AiTask<AiCompletionResponse>> {
        request.validate(&self.limits)?;
        let settings = self.settings.clone();
        let limits = self.limits.clone();
        Ok(AiTask::new(self.runtime.spawn(async move {
            execute_completion(&settings, request, &limits).await
        })))
    }

    pub fn list_models(&self, provider_id: AiProviderId) -> AiTask<AiModelList> {
        let settings = self.settings.clone();
        let limits = self.limits.clone();
        AiTask::new(
            self.runtime
                .spawn(async move { execute_model_list(&settings, provider_id, &limits).await }),
        )
    }

    pub fn start_stream(&self, request: AiStreamRequest) -> CoreResult<AiStreamTask> {
        request.completion.validate(&self.limits)?;
        let (sender, receiver) = ai_stream_event_channel(self.limits.stream_event_capacity)?;
        {
            let mut active = self.active_streams.lock();
            if !active.insert(request.stream_id.clone()) {
                return Err(CoreError::validation(
                    "AI stream ID",
                    "an active stream already uses this ID",
                ));
            }
        }

        let (cancel_sender, cancel_receiver) = watch::channel(false);
        let sequence = Arc::new(AtomicU64::new(0));
        let cancellation = AiStreamCancellation {
            stream_id: request.stream_id.clone(),
            sender: cancel_sender,
        };
        let events = AiEventStream::new(
            request.stream_id.clone(),
            receiver,
            cancel_receiver.clone(),
            sequence.clone(),
        );

        let settings = self.settings.clone();
        let limits = self.limits.clone();
        let stream_id = request.stream_id.clone();
        // Construct the registration before spawning. If the task is aborted
        // before its first poll, dropping the captured future still removes the
        // ID instead of leaving it permanently reserved.
        let registration = ActiveStreamRegistration {
            stream_id: stream_id.clone(),
            active: self.active_streams.clone(),
        };
        let join = self.runtime.spawn(async move {
            let _registration = registration;
            run_stream(
                &settings,
                request,
                &limits,
                sender,
                cancel_receiver,
                sequence,
            )
            .await
        });

        Ok(AiStreamTask {
            events,
            cancellation,
            join: Some(join),
        })
    }

    pub fn is_stream_active(&self, stream_id: &AiStreamId) -> bool {
        self.active_streams.lock().contains(stream_id)
    }
}

#[derive(Debug)]
struct ActiveStreamRegistration {
    stream_id: AiStreamId,
    active: Arc<Mutex<HashSet<AiStreamId>>>,
}

impl Drop for ActiveStreamRegistration {
    fn drop(&mut self) {
        self.active.lock().remove(&self.stream_id);
    }
}

#[derive(Debug, Clone)]
struct ResolvedProvider {
    id: AiProviderId,
    kind: AiProviderKind,
    endpoint: Url,
    model: String,
    proxy: Option<ProxySettings>,
}

fn resolve_provider(
    settings: &SettingsRepository,
    provider_id: &AiProviderId,
) -> CoreResult<ResolvedProvider> {
    let view = settings.load()?;
    let provider = view
        .ai
        .providers
        .into_iter()
        .find(|provider| provider.id == provider_id.as_str())
        .ok_or_else(|| CoreError::NotFound {
            entity: "AI provider",
            id: provider_id.to_string(),
        })?;
    if !provider.enabled {
        return Err(CoreError::validation(
            "AI provider",
            "the selected provider is disabled",
        ));
    }
    let endpoint = validate_outbound_url(&provider.endpoint)?;
    Ok(ResolvedProvider {
        id: provider_id.clone(),
        kind: provider.kind,
        endpoint,
        model: provider.model,
        proxy: view.ai.proxy,
    })
}

async fn execute_completion(
    settings: &SettingsRepository,
    request: AiCompletionRequest,
    limits: &AiLimits,
) -> CoreResult<AiCompletionResponse> {
    let provider = resolve_provider(settings, &request.provider_id)?;
    let body = build_request_body(&provider, &request, false, limits)?;
    let client = http_client(provider.proxy.as_ref())?;
    let builder = apply_generated_headers(client.post(provider.endpoint.clone()), provider.kind)?;
    let response = send_with_short_lived_secret(settings, &provider, builder.body(body)).await?;
    let status = response.status();
    let bytes = read_bounded_response(response, limits.max_response_bytes).await?;
    if !status.is_success() {
        return Err(remote_status_error(status, &bytes));
    }
    let body = serde_json::from_slice(&bytes).map_err(|error| {
        CoreError::validation(
            "AI response",
            format!("response was not valid JSON: {error}"),
        )
    })?;
    Ok(AiCompletionResponse {
        provider_id: provider.id.to_string(),
        status: status.as_u16(),
        body,
    })
}

async fn execute_model_list(
    settings: &SettingsRepository,
    provider_id: AiProviderId,
    limits: &AiLimits,
) -> CoreResult<AiModelList> {
    let provider = resolve_provider(settings, &provider_id)?;
    let endpoint = models_endpoint_from_url(&provider.endpoint, provider.kind)?;
    let client = http_client(provider.proxy.as_ref())?;
    let builder = apply_generated_headers(client.get(endpoint), provider.kind)?;
    let response = send_with_short_lived_secret(settings, &provider, builder).await?;
    let status = response.status();
    let bytes = read_bounded_response(response, limits.max_response_bytes).await?;
    if !status.is_success() {
        return Err(remote_status_error(status, &bytes));
    }
    let models = parse_model_list_bounded(&bytes, limits.max_models, limits.max_model_id_bytes)?;
    Ok(AiModelList {
        provider_id: provider.id.to_string(),
        models,
    })
}

async fn send_with_short_lived_secret(
    settings: &SettingsRepository,
    provider: &ResolvedProvider,
    builder: reqwest::RequestBuilder,
) -> CoreResult<reqwest::Response> {
    let secret = settings.resolve_ai_api_key(provider.id.as_str())?;
    let builder = apply_auth_header(builder, provider.kind, secret.as_ref())?;
    let result = builder.send().await;
    drop(secret);
    result.map_err(|error| {
        CoreError::validation("AI HTTP request", format!("request failed: {error}"))
    })
}

fn apply_generated_headers(
    mut builder: reqwest::RequestBuilder,
    kind: AiProviderKind,
) -> CoreResult<reqwest::RequestBuilder> {
    let mut requested = HashMap::from([
        ("Content-Type".to_owned(), "application/json".to_owned()),
        ("Accept".to_owned(), "application/json".to_owned()),
    ]);
    if kind == AiProviderKind::Anthropic {
        requested.insert("anthropic-version".to_owned(), "2023-06-01".to_owned());
    }
    let (headers, dropped) = filter_headers(&requested);
    if !dropped.is_empty() {
        return Err(CoreError::validation(
            "AI provider headers",
            format!("generated headers failed the outbound allowlist: {dropped:?}"),
        ));
    }
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    Ok(builder)
}

fn apply_auth_header(
    builder: reqwest::RequestBuilder,
    kind: AiProviderKind,
    secret: Option<&SecretValue>,
) -> CoreResult<reqwest::RequestBuilder> {
    let Some(secret) = secret else {
        return Ok(builder);
    };
    let (name, mut value) = match kind {
        AiProviderKind::Anthropic => (
            HeaderName::from_static("x-api-key"),
            HeaderValue::from_str(secret.expose()).map_err(|_| {
                CoreError::validation(
                    "AI API key",
                    "contains characters invalid in an HTTP header",
                )
            })?,
        ),
        AiProviderKind::OpenAiCompatible | AiProviderKind::Gemini => {
            // Gemini's OpenAI-compatible endpoint accepts bearer authentication,
            // keeping secrets out of the query string.
            let bearer = Zeroizing::new(format!("Bearer {}", secret.expose()));
            (
                AUTHORIZATION,
                HeaderValue::from_str(bearer.as_str()).map_err(|_| {
                    CoreError::validation(
                        "AI API key",
                        "contains characters invalid in an HTTP header",
                    )
                })?,
            )
        }
    };
    value.set_sensitive(true);
    Ok(builder.header(name, value))
}

fn build_request_body(
    provider: &ResolvedProvider,
    request: &AiCompletionRequest,
    stream: bool,
    limits: &AiLimits,
) -> CoreResult<Vec<u8>> {
    let value = match provider.kind {
        AiProviderKind::OpenAiCompatible | AiProviderKind::Gemini => {
            let messages = request
                .messages
                .iter()
                .map(|message| {
                    json!({
                        "role": role_name(message.role),
                        "content": message.content,
                    })
                })
                .collect::<Vec<_>>();
            let mut object = Map::from_iter([
                ("model".to_owned(), Value::String(provider.model.clone())),
                ("messages".to_owned(), Value::Array(messages)),
                ("stream".to_owned(), Value::Bool(stream)),
            ]);
            insert_sampling_options(&mut object, request)?;
            Value::Object(object)
        }
        AiProviderKind::Anthropic => {
            let mut system = Vec::new();
            let mut messages = Vec::new();
            for message in &request.messages {
                if message.role == AiMessageRole::System {
                    system.push(message.content.as_str());
                } else {
                    messages.push(json!({
                        "role": role_name(message.role),
                        "content": message.content,
                    }));
                }
            }
            if messages.is_empty() {
                return Err(CoreError::validation(
                    "Anthropic messages",
                    "at least one user or assistant message is required",
                ));
            }
            let mut object = Map::from_iter([
                ("model".to_owned(), Value::String(provider.model.clone())),
                ("messages".to_owned(), Value::Array(messages)),
                ("stream".to_owned(), Value::Bool(stream)),
                (
                    "max_tokens".to_owned(),
                    Value::from(request.max_output_tokens.unwrap_or(1_024)),
                ),
            ]);
            if !system.is_empty() {
                object.insert("system".to_owned(), Value::String(system.join("\n\n")));
            }
            if let Some(temperature) = request.temperature {
                object.insert("temperature".to_owned(), json_number(temperature)?);
            }
            Value::Object(object)
        }
    };
    let bytes = serde_json::to_vec(&value).map_err(|error| CoreError::Encode {
        subject: "AI request",
        source: error,
    })?;
    if bytes.len() > limits.max_request_bytes {
        return Err(CoreError::validation(
            "AI request",
            format!(
                "serialized request exceeds {} bytes",
                limits.max_request_bytes
            ),
        ));
    }
    Ok(bytes)
}

fn insert_sampling_options(
    object: &mut Map<String, Value>,
    request: &AiCompletionRequest,
) -> CoreResult<()> {
    if let Some(temperature) = request.temperature {
        object.insert("temperature".to_owned(), json_number(temperature)?);
    }
    if let Some(maximum) = request.max_output_tokens {
        object.insert("max_tokens".to_owned(), Value::from(maximum));
    }
    Ok(())
}

fn json_number(value: f32) -> CoreResult<Value> {
    serde_json::Number::from_f64(f64::from(value))
        .map(Value::Number)
        .ok_or_else(|| CoreError::validation("AI number", "must be finite"))
}

fn role_name(role: AiMessageRole) -> &'static str {
    match role {
        AiMessageRole::System => "system",
        AiMessageRole::User => "user",
        AiMessageRole::Assistant => "assistant",
    }
}

async fn read_bounded_response(response: reqwest::Response, maximum: usize) -> CoreResult<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(CoreError::validation(
            "AI response",
            format!("Content-Length exceeds {maximum} bytes"),
        ));
    }
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| {
            CoreError::validation("AI response", format!("response read failed: {error}"))
        })?;
        let new_len = body
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| CoreError::validation("AI response", "byte count overflowed"))?;
        if new_len > maximum {
            return Err(CoreError::validation(
                "AI response",
                format!("response exceeds {maximum} bytes"),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn remote_status_error(status: StatusCode, body: &[u8]) -> CoreError {
    CoreError::validation(
        "AI response",
        format!(
            "provider returned HTTP {}: {}",
            status.as_u16(),
            sanitize_remote_error(body)
        ),
    )
}

fn sanitize_remote_error(body: &[u8]) -> String {
    let mut output = String::new();
    for character in String::from_utf8_lossy(body).chars() {
        if output.chars().count() >= MAX_REMOTE_ERROR_CHARS {
            output.push('…');
            break;
        }
        if character.is_control() {
            output.push(' ');
        } else {
            output.push(character);
        }
    }
    output
}

async fn run_stream(
    settings: &SettingsRepository,
    request: AiStreamRequest,
    limits: &AiLimits,
    sender: AiStreamEventSender,
    mut cancellation: watch::Receiver<bool>,
    sequence: Arc<AtomicU64>,
) -> CoreResult<()> {
    let stream_id = request.stream_id.clone();
    let result = execute_stream(
        settings,
        &request,
        limits,
        &sender,
        &mut cancellation,
        &sequence,
    )
    .await;

    match result {
        Ok(StreamEnd::Completed) => {
            let event = stream_event(&stream_id, &sequence, AiStreamEventKind::Completed);
            match send_event(&sender, &mut cancellation, event).await {
                Ok(()) | Err(EventSendError::Cancelled) => Ok(()),
                Err(EventSendError::Core(error)) => Err(error),
            }
        }
        Ok(StreamEnd::Cancelled) => Ok(()),
        Err(error) => {
            if *cancellation.borrow() {
                return Ok(());
            }
            let message = bounded_event_error(&error.to_string());
            let event = stream_event(&stream_id, &sequence, AiStreamEventKind::Failed { message });
            match send_event(&sender, &mut cancellation, event).await {
                Ok(()) | Err(EventSendError::Core(_)) => Err(error),
                Err(EventSendError::Cancelled) => Ok(()),
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamEnd {
    Completed,
    Cancelled,
}

async fn execute_stream(
    settings: &SettingsRepository,
    request: &AiStreamRequest,
    limits: &AiLimits,
    sender: &AiStreamEventSender,
    cancellation: &mut watch::Receiver<bool>,
    sequence: &Arc<AtomicU64>,
) -> CoreResult<StreamEnd> {
    let provider = resolve_provider(settings, &request.completion.provider_id)?;
    let body = build_request_body(&provider, &request.completion, true, limits)?;
    let client = stream_client(provider.proxy.as_ref())?;
    let builder = apply_generated_headers(client.post(provider.endpoint.clone()), provider.kind)?;
    let secret = settings.resolve_ai_api_key(provider.id.as_str())?;
    let builder = apply_auth_header(builder.body(body), provider.kind, secret.as_ref())?;
    let response = tokio::select! {
        biased;
        _ = cancellation_requested(cancellation) => {
            drop(secret);
            return Ok(StreamEnd::Cancelled);
        }
        response = builder.send() => response.map_err(|error| {
            CoreError::validation("AI HTTP stream", format!("request failed: {error}"))
        })?,
    };
    drop(secret);

    let status = response.status();
    if !status.is_success() {
        let bytes =
            read_bounded_stream_error(response, limits.max_response_bytes, cancellation).await?;
        if *cancellation.borrow() {
            return Ok(StreamEnd::Cancelled);
        }
        return Err(remote_status_error(status, &bytes));
    }
    if response
        .content_length()
        .is_some_and(|length| length > limits.max_stream_total_bytes as u64)
    {
        return Err(CoreError::validation(
            "AI stream",
            format!(
                "Content-Length exceeds {} bytes",
                limits.max_stream_total_bytes
            ),
        ));
    }

    let mut bytes_stream = response.bytes_stream();
    let mut utf8 = Utf8Chunker::new(limits.max_stream_chunk_bytes);
    let mut total = 0_usize;
    loop {
        let chunk = tokio::select! {
            biased;
            _ = cancellation_requested(cancellation) => return Ok(StreamEnd::Cancelled),
            result = tokio::time::timeout(limits.stream_idle_timeout, bytes_stream.next()) => {
                match result {
                    Ok(Some(chunk)) => chunk.map_err(|error| {
                        CoreError::validation("AI stream", format!("response read failed: {error}"))
                    })?,
                    Ok(None) => break,
                    Err(_) => return Err(CoreError::validation(
                        "AI stream",
                        "response was idle longer than the configured timeout",
                    )),
                }
            }
        };
        total = total
            .checked_add(chunk.len())
            .ok_or_else(|| CoreError::validation("AI stream", "byte count overflowed"))?;
        if total > limits.max_stream_total_bytes {
            return Err(CoreError::validation(
                "AI stream",
                format!("response exceeds {} bytes", limits.max_stream_total_bytes),
            ));
        }
        for delta in utf8.push(&chunk) {
            let event = stream_event(
                &request.stream_id,
                sequence,
                AiStreamEventKind::Delta(delta),
            );
            match send_event(sender, cancellation, event).await {
                Ok(()) => {}
                Err(EventSendError::Cancelled) => return Ok(StreamEnd::Cancelled),
                Err(EventSendError::Core(error)) => return Err(error),
            }
        }
    }
    for delta in utf8.finish() {
        let event = stream_event(
            &request.stream_id,
            sequence,
            AiStreamEventKind::Delta(delta),
        );
        match send_event(sender, cancellation, event).await {
            Ok(()) => {}
            Err(EventSendError::Cancelled) => return Ok(StreamEnd::Cancelled),
            Err(EventSendError::Core(error)) => return Err(error),
        }
    }
    Ok(StreamEnd::Completed)
}

async fn read_bounded_stream_error(
    response: reqwest::Response,
    maximum: usize,
    cancellation: &mut watch::Receiver<bool>,
) -> CoreResult<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(CoreError::validation(
            "AI error response",
            format!("Content-Length exceeds {maximum} bytes"),
        ));
    }
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    loop {
        let next = tokio::select! {
            biased;
            _ = cancellation_requested(cancellation) => return Ok(body),
            next = stream.next() => next,
        };
        let Some(chunk) = next else {
            break;
        };
        let chunk = chunk.map_err(|error| {
            CoreError::validation(
                "AI error response",
                format!("response read failed: {error}"),
            )
        })?;
        let new_len = body
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| CoreError::validation("AI error response", "byte count overflowed"))?;
        if new_len > maximum {
            return Err(CoreError::validation(
                "AI error response",
                format!("response exceeds {maximum} bytes"),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[derive(Debug)]
enum EventSendError {
    Cancelled,
    Core(CoreError),
}

async fn send_event(
    sender: &AiStreamEventSender,
    cancellation: &mut watch::Receiver<bool>,
    event: AiStreamEvent,
) -> Result<(), EventSendError> {
    if *cancellation.borrow() {
        return Err(EventSendError::Cancelled);
    }
    tokio::select! {
        biased;
        _ = cancellation_requested(cancellation) => Err(EventSendError::Cancelled),
        result = sender.send(event) => result.map_err(EventSendError::Core),
    }
}

async fn cancellation_requested(receiver: &mut watch::Receiver<bool>) {
    if *receiver.borrow_and_update() {
        return;
    }
    loop {
        if receiver.changed().await.is_err() || *receiver.borrow_and_update() {
            return;
        }
    }
}

fn stream_event(
    stream_id: &AiStreamId,
    sequence: &Arc<AtomicU64>,
    kind: AiStreamEventKind,
) -> AiStreamEvent {
    AiStreamEvent {
        stream_id: stream_id.to_string(),
        sequence: next_sequence(sequence),
        kind,
    }
}

fn next_sequence(sequence: &Arc<AtomicU64>) -> u64 {
    sequence.fetch_add(1, Ordering::Relaxed).saturating_add(1)
}

fn bounded_event_error(message: &str) -> String {
    let mut output = message
        .chars()
        .take(MAX_EVENT_ERROR_CHARS)
        .collect::<String>();
    if message.chars().count() > MAX_EVENT_ERROR_CHARS {
        output.push('…');
    }
    output
}

#[derive(Debug)]
struct Utf8Chunker {
    pending: Vec<u8>,
    maximum: usize,
}

impl Utf8Chunker {
    fn new(maximum: usize) -> Self {
        Self {
            pending: Vec::new(),
            maximum,
        }
    }

    fn push(&mut self, bytes: &[u8]) -> Vec<String> {
        self.pending.extend_from_slice(bytes);
        let mut output = Vec::new();
        loop {
            match std::str::from_utf8(&self.pending) {
                Ok(text) => {
                    output.extend(split_utf8(text, self.maximum));
                    self.pending.clear();
                    break;
                }
                Err(error) => {
                    let valid = error.valid_up_to();
                    if valid > 0 {
                        let text = std::str::from_utf8(&self.pending[..valid])
                            .expect("valid_up_to always marks valid UTF-8");
                        output.extend(split_utf8(text, self.maximum));
                        self.pending.drain(..valid);
                    }
                    if let Some(invalid) = error.error_len() {
                        let drain = invalid.min(self.pending.len());
                        self.pending.drain(..drain);
                        output.push("�".to_owned());
                        continue;
                    }
                    break;
                }
            }
        }
        output
    }

    fn finish(self) -> Vec<String> {
        if self.pending.is_empty() {
            Vec::new()
        } else {
            split_utf8(&String::from_utf8_lossy(&self.pending), self.maximum)
        }
    }
}

fn split_utf8(text: &str, maximum: usize) -> Vec<String> {
    let mut output = Vec::new();
    let mut start = 0;
    while start < text.len() {
        let mut end = (start + maximum).min(text.len());
        while end > start && !text.is_char_boundary(end) {
            end -= 1;
        }
        if end == start {
            end = text[start..]
                .char_indices()
                .nth(1)
                .map_or(text.len(), |(index, _)| start + index);
        }
        output.push(text[start..end].to_owned());
        start = end;
    }
    output
}

/// Derive the configured provider's model-list endpoint without accepting a
/// caller-selected URL.
pub fn models_endpoint(endpoint: &str, kind: AiProviderKind) -> CoreResult<Url> {
    let endpoint = validate_outbound_url(endpoint)?;
    models_endpoint_from_url(&endpoint, kind)
}

fn models_endpoint_from_url(endpoint: &Url, _kind: AiProviderKind) -> CoreResult<Url> {
    let mut models = endpoint.clone();
    let trimmed = models.path().trim_end_matches('/');
    let stem = trimmed
        .strip_suffix("/chat/completions")
        .or_else(|| trimmed.strip_suffix("/messages"))
        .or_else(|| trimmed.strip_suffix("/generateContent"))
        .unwrap_or(trimmed);
    let path = if stem.ends_with("/models") {
        stem.to_owned()
    } else if stem.is_empty() || stem == "/" {
        "/v1/models".to_owned()
    } else if stem.contains("/v1") || stem.contains("/api") || stem.contains("/v1beta") {
        format!("{stem}/models")
    } else {
        format!("{stem}/v1/models")
    };
    models.set_path(&path);
    models.set_query(None);
    models.set_fragment(None);
    validate_outbound_url(models.as_str())
}

/// Parse OpenAI/Anthropic `data` and Ollama-style `models` responses using the
/// production default bounds.
pub fn parse_model_list(body: &str) -> CoreResult<Vec<String>> {
    let limits = AiLimits::default();
    if body.len() > limits.max_response_bytes {
        return Err(CoreError::validation(
            "AI model response",
            format!("response exceeds {} bytes", limits.max_response_bytes),
        ));
    }
    parse_model_list_bounded(
        body.as_bytes(),
        limits.max_models,
        limits.max_model_id_bytes,
    )
}

fn parse_model_list_bounded(
    body: &[u8],
    maximum_models: usize,
    maximum_id_bytes: usize,
) -> CoreResult<Vec<String>> {
    let value: Value = serde_json::from_slice(body).map_err(|error| {
        CoreError::validation(
            "AI model response",
            format!("response was not valid JSON: {error}"),
        )
    })?;
    let array = value
        .get("data")
        .and_then(Value::as_array)
        .or_else(|| value.get("models").and_then(Value::as_array))
        .ok_or_else(|| {
            CoreError::validation("AI model response", "expected a data or models array")
        })?;
    if array.len() > maximum_models {
        return Err(CoreError::validation(
            "AI model response",
            format!("contains more than {maximum_models} entries"),
        ));
    }
    let mut seen = HashSet::new();
    let mut models = Vec::new();
    for item in array {
        let Some(raw) = item
            .get("id")
            .and_then(Value::as_str)
            .or_else(|| item.get("name").and_then(Value::as_str))
        else {
            continue;
        };
        let id = raw.trim();
        if id.is_empty()
            || id.len() > maximum_id_bytes
            || id.chars().any(char::is_control)
            || !seen.insert(id.to_owned())
        {
            continue;
        }
        models.push(id.to_owned());
    }
    if models.is_empty() {
        return Err(CoreError::validation(
            "AI model response",
            "provider returned no valid model IDs",
        ));
    }
    Ok(models)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use uuid::Uuid;

    use super::*;
    use crate::PortableStore;
    use crate::crypto::{CryptoVault, SecretValue};
    use crate::settings::{AiProviderSettings, AppSettings};

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("lovelyres-ai-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn repository(
        root: &TestRoot,
        endpoint: &str,
        kind: AiProviderKind,
        secret: Option<&str>,
    ) -> SettingsRepository {
        let store = PortableStore::prepare(root.0.clone()).unwrap();
        let crypto = Arc::new(CryptoVault::load(&store).unwrap());
        let repository = SettingsRepository::new(store, crypto);
        let mut settings = AppSettings::default();
        settings.ai.providers.push(AiProviderSettings {
            id: "test-provider".to_owned(),
            label: "Test Provider".to_owned(),
            kind,
            endpoint: endpoint.to_owned(),
            model: "test-model".to_owned(),
            enabled: true,
            has_api_key: false,
        });
        settings.ai.default_provider_id = Some("test-provider".to_owned());
        repository.save(settings).unwrap();
        if let Some(secret) = secret {
            repository
                .set_ai_api_key("test-provider", Some(SecretValue::new(secret)))
                .unwrap();
        }
        repository
    }

    fn completion() -> AiCompletionRequest {
        AiCompletionRequest::new(
            AiProviderId::new("test-provider").unwrap(),
            vec![AiMessage::new(AiMessageRole::User, "hello")],
        )
    }

    async fn fixed_server(
        status: u16,
        body: Vec<u8>,
    ) -> (String, oneshot::Receiver<Vec<u8>>, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (request_sender, request_receiver) = oneshot::channel();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let request = read_http_request(&mut socket).await;
            let _ = request_sender.send(request);
            let reason = if (200..300).contains(&status) {
                "OK"
            } else {
                "ERROR"
            };
            let header = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = socket.write_all(header.as_bytes()).await;
            let _ = socket.write_all(&body).await;
            let _ = socket.shutdown().await;
        });
        (
            format!("http://{address}/v1/chat/completions"),
            request_receiver,
            task,
        )
    }

    async fn chunked_server(
        chunks: Vec<Vec<u8>>,
    ) -> (String, oneshot::Receiver<Vec<u8>>, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (request_sender, request_receiver) = oneshot::channel();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let request = read_http_request(&mut socket).await;
            let _ = request_sender.send(request);
            let _ = socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await;
            for chunk in chunks {
                let header = format!("{:X}\r\n", chunk.len());
                if socket.write_all(header.as_bytes()).await.is_err()
                    || socket.write_all(&chunk).await.is_err()
                    || socket.write_all(b"\r\n").await.is_err()
                {
                    return;
                }
            }
            let _ = socket.write_all(b"0\r\n\r\n").await;
            let _ = socket.shutdown().await;
        });
        (
            format!("http://{address}/v1/chat/completions"),
            request_receiver,
            task,
        )
    }

    async fn read_http_request(socket: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 2_048];
        let mut expected = None;
        loop {
            let count = socket.read(&mut buffer).await.unwrap_or(0);
            if count == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..count]);
            if let Some(header_end) = find_bytes(&request, b"\r\n\r\n") {
                let header = String::from_utf8_lossy(&request[..header_end]);
                let content_length = header
                    .lines()
                    .find_map(|line| {
                        line.split_once(':').and_then(|(name, value)| {
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                    })
                    .unwrap_or(0);
                expected = Some(header_end + 4 + content_length);
            }
            if expected.is_some_and(|length| request.len() >= length) {
                break;
            }
        }
        request
    }

    fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    #[test]
    fn request_bodies_match_openai_and_anthropic_contracts() {
        let limits = AiLimits::default();
        let openai = ResolvedProvider {
            id: AiProviderId::new("p").unwrap(),
            kind: AiProviderKind::OpenAiCompatible,
            endpoint: Url::parse("https://api.example.com/v1/chat/completions").unwrap(),
            model: "gpt-test".to_owned(),
            proxy: None,
        };
        let request = AiCompletionRequest::new(
            AiProviderId::new("p").unwrap(),
            vec![
                AiMessage::new(AiMessageRole::System, "rules"),
                AiMessage::new(AiMessageRole::User, "hello"),
            ],
        )
        .with_temperature(0.25)
        .with_max_output_tokens(321);
        let body: Value =
            serde_json::from_slice(&build_request_body(&openai, &request, true, &limits).unwrap())
                .unwrap();
        assert_eq!(body["model"], "gpt-test");
        assert_eq!(body["messages"][0]["role"], "system");
        assert_eq!(body["stream"], true);
        assert_eq!(body["max_tokens"], 321);

        let anthropic = ResolvedProvider {
            kind: AiProviderKind::Anthropic,
            ..openai
        };
        let body: Value = serde_json::from_slice(
            &build_request_body(&anthropic, &request, false, &limits).unwrap(),
        )
        .unwrap();
        assert_eq!(body["system"], "rules");
        assert_eq!(body["messages"][0]["role"], "user");
        assert_eq!(body["max_tokens"], 321);
    }

    #[test]
    fn validates_identifiers_messages_and_hard_limits() {
        assert!(AiProviderId::new("\nprovider").is_err());
        assert!(AiStreamId::new("bad stream").is_err());
        assert!(AiStreamId::new("safe:stream-1").is_ok());
        let limits = AiLimits {
            max_request_bytes: HARD_MAX_REQUEST_BYTES + 1,
            ..AiLimits::default()
        };
        assert!(limits.validate().is_err());

        let limits = AiLimits {
            max_message_bytes: 8,
            max_request_bytes: 16,
            ..AiLimits::default()
        };
        assert!(
            AiCompletionRequest::new(
                AiProviderId::new("p").unwrap(),
                vec![AiMessage::new(AiMessageRole::User, "123456789")],
            )
            .validate(&limits)
            .is_err()
        );
        assert!(
            completion()
                .with_temperature(f32::NAN)
                .validate(&limits)
                .is_err()
        );
    }

    #[test]
    fn model_endpoints_and_parsers_preserve_legacy_goldens() {
        assert_eq!(
            models_endpoint(
                "https://api.openai.com/v1/chat/completions",
                AiProviderKind::OpenAiCompatible
            )
            .unwrap()
            .as_str(),
            "https://api.openai.com/v1/models"
        );
        assert_eq!(
            models_endpoint(
                "https://api.anthropic.com/v1/messages",
                AiProviderKind::Anthropic
            )
            .unwrap()
            .as_str(),
            "https://api.anthropic.com/v1/models"
        );
        assert!(models_endpoint("http://169.254.169.254/x", AiProviderKind::Gemini).is_err());

        let openai = r#"{"data":[{"id":"gpt-4o"},{"id":"gpt-4o-mini"},{"id":"gpt-4o"}]}"#;
        assert_eq!(
            parse_model_list(openai).unwrap(),
            vec!["gpt-4o", "gpt-4o-mini"]
        );
        let ollama = r#"{"models":[{"name":"qwen2.5:7b"},{"name":"llama3.1:8b"}]}"#;
        assert_eq!(
            parse_model_list(ollama).unwrap(),
            vec!["qwen2.5:7b", "llama3.1:8b"]
        );
        assert!(parse_model_list(r#"{"data":[]}"#).is_err());
        assert!(parse_model_list("not-json").is_err());
    }

    #[test]
    fn authentication_and_provider_headers_are_generated_not_caller_supplied() {
        let client = reqwest::Client::new();
        let secret = SecretValue::new("secret-value");

        let openai = apply_generated_headers(
            client.post("https://api.example.com/v1/chat/completions"),
            AiProviderKind::OpenAiCompatible,
        )
        .and_then(|builder| {
            apply_auth_header(builder, AiProviderKind::OpenAiCompatible, Some(&secret))
        })
        .unwrap()
        .build()
        .unwrap();
        assert_eq!(openai.headers()[AUTHORIZATION], "Bearer secret-value");
        assert!(openai.headers()[AUTHORIZATION].is_sensitive());
        assert!(!openai.headers().contains_key("host"));

        let anthropic = apply_generated_headers(
            client.post("https://api.anthropic.com/v1/messages"),
            AiProviderKind::Anthropic,
        )
        .and_then(|builder| apply_auth_header(builder, AiProviderKind::Anthropic, Some(&secret)))
        .unwrap()
        .build()
        .unwrap();
        assert_eq!(anthropic.headers()["x-api-key"], "secret-value");
        assert!(anthropic.headers()["x-api-key"].is_sensitive());
        assert_eq!(anthropic.headers()["anthropic-version"], "2023-06-01");
        assert!(!anthropic.headers().contains_key(AUTHORIZATION));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn completion_uses_configured_endpoint_and_encrypted_key_only() {
        let (endpoint, request_capture, server) =
            fixed_server(200, br#"{"answer":"ok"}"#.to_vec()).await;
        let root = TestRoot::new();
        let repository = repository(
            &root,
            &endpoint,
            AiProviderKind::OpenAiCompatible,
            Some("secret-test-key"),
        );
        let service = AiService::new(Handle::current(), repository);
        let response = service
            .submit_completion(completion())
            .unwrap()
            .wait()
            .await
            .unwrap();
        assert_eq!(response.body["answer"], "ok");

        let request = String::from_utf8(request_capture.await.unwrap()).unwrap();
        assert!(request.contains("authorization: Bearer secret-test-key"));
        assert!(request.contains("\"model\":\"test-model\""));
        assert!(!request.to_ascii_lowercase().contains("x-forwarded-for"));
        server.await.unwrap();

        let settings = fs::read_to_string(root.0.join("data/settings.json")).unwrap();
        assert!(settings.contains("enc:v1:"));
        assert!(!settings.contains("secret-test-key"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn model_listing_uses_derived_endpoint_and_bounded_typed_result() {
        let (endpoint, request_capture, server) = fixed_server(
            200,
            br#"{"data":[{"id":"model-a"},{"id":"model-b"},{"id":"model-a"}]}"#.to_vec(),
        )
        .await;
        let root = TestRoot::new();
        let repository = repository(
            &root,
            &endpoint,
            AiProviderKind::OpenAiCompatible,
            Some("models-key"),
        );
        let models = AiService::new(Handle::current(), repository)
            .list_models(AiProviderId::new("test-provider").unwrap())
            .wait()
            .await
            .unwrap();
        assert_eq!(models.models, vec!["model-a", "model-b"]);
        let request = String::from_utf8(request_capture.await.unwrap()).unwrap();
        assert!(request.starts_with("GET /v1/models HTTP/1.1"));
        assert!(request.contains("authorization: Bearer models-key"));
        server.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn model_listing_rejects_non_success_http_status() {
        let (endpoint, request_capture, server) =
            fixed_server(401, br#"{"error":"unauthorized"}"#.to_vec()).await;
        let root = TestRoot::new();
        let repository = repository(
            &root,
            &endpoint,
            AiProviderKind::OpenAiCompatible,
            Some("bad-key"),
        );
        let error = AiService::new(Handle::current(), repository)
            .list_models(AiProviderId::new("test-provider").unwrap())
            .wait()
            .await
            .unwrap_err();
        assert!(error.to_string().contains("HTTP 401"));
        let request = String::from_utf8(request_capture.await.unwrap()).unwrap();
        assert!(request.starts_with("GET /v1/models HTTP/1.1"));
        server.await.unwrap();
    }

    #[test]
    fn malicious_secret_header_is_rejected_before_network_send() {
        let root = TestRoot::new();
        let repository = repository(
            &root,
            "http://127.0.0.1:9/v1/chat/completions",
            AiProviderKind::OpenAiCompatible,
            None,
        );
        let error = repository
            .set_ai_api_key(
                "test-provider",
                Some(SecretValue::new("key\r\nHost: metadata")),
            )
            .unwrap_err();
        assert!(error.to_string().contains("contain no control characters"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn non_streaming_response_has_a_hard_byte_limit() {
        let (endpoint, _request, server) = fixed_server(200, vec![b'x'; 256]).await;
        let root = TestRoot::new();
        let repository = repository(&root, &endpoint, AiProviderKind::OpenAiCompatible, None);
        let limits = AiLimits {
            max_response_bytes: 64,
            ..AiLimits::default()
        };
        let error = AiService::with_limits(Handle::current(), repository, limits)
            .unwrap()
            .submit_completion(completion())
            .unwrap()
            .wait()
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Content-Length exceeds 64 bytes")
        );
        server.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stream_preserves_split_utf8_and_bounds_each_delta() {
        let text = "你abc🙂".as_bytes();
        let chunks = vec![text[..1].to_vec(), text[1..5].to_vec(), text[5..].to_vec()];
        let (endpoint, _request, server) = chunked_server(chunks).await;
        let root = TestRoot::new();
        let repository = repository(&root, &endpoint, AiProviderKind::OpenAiCompatible, None);
        let limits = AiLimits {
            max_stream_chunk_bytes: 5,
            max_stream_total_bytes: 64,
            ..AiLimits::default()
        };
        let service = AiService::with_limits(Handle::current(), repository, limits).unwrap();
        let mut task = service
            .start_stream(AiStreamRequest::new(
                AiStreamId::new("utf8-stream").unwrap(),
                completion(),
            ))
            .unwrap();
        let mut output = String::new();
        let mut previous = 0;
        loop {
            let event = task.events().recv().await.unwrap();
            assert!(event.sequence > previous);
            previous = event.sequence;
            match event.kind {
                AiStreamEventKind::Delta(delta) => {
                    assert!(delta.len() <= 5);
                    output.push_str(&delta);
                }
                AiStreamEventKind::Completed => break,
                other => panic!("unexpected stream event: {other:?}"),
            }
        }
        task.wait().await.unwrap();
        assert_eq!(output, "你abc🙂");
        server.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellation_remains_responsive_when_event_channel_is_full() {
        let (endpoint, _request, server) = chunked_server(vec![vec![b'x'; 8_192]]).await;
        let root = TestRoot::new();
        let repository = repository(&root, &endpoint, AiProviderKind::OpenAiCompatible, None);
        let limits = AiLimits {
            stream_event_capacity: 1,
            max_stream_chunk_bytes: 4,
            ..AiLimits::default()
        };
        let service = AiService::with_limits(Handle::current(), repository, limits).unwrap();
        let stream_id = AiStreamId::new("backpressure-cancel").unwrap();
        let mut task = service
            .start_stream(AiStreamRequest::new(stream_id.clone(), completion()))
            .unwrap();

        tokio::time::timeout(Duration::from_secs(2), async {
            while task.events().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let cancellation = task.cancellation();
        assert!(cancellation.cancel());
        assert!(!cancellation.cancel());
        tokio::time::timeout(Duration::from_secs(1), task.wait())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            task.events().recv().await.unwrap().kind,
            AiStreamEventKind::Cancelled
        );
        assert!(!service.is_stream_active(&stream_id));
        server.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn duplicate_stream_ids_and_stream_total_overflow_fail_closed() {
        let (endpoint, _request, server) = chunked_server(vec![vec![b'x'; 64]]).await;
        let root = TestRoot::new();
        let repository = repository(&root, &endpoint, AiProviderKind::OpenAiCompatible, None);
        let limits = AiLimits {
            max_stream_chunk_bytes: 4,
            max_stream_total_bytes: 8,
            ..AiLimits::default()
        };
        let service = AiService::with_limits(Handle::current(), repository, limits).unwrap();
        let stream_id = AiStreamId::new("bounded-stream").unwrap();
        let mut task = service
            .start_stream(AiStreamRequest::new(stream_id.clone(), completion()))
            .unwrap();
        assert!(
            service
                .start_stream(AiStreamRequest::new(stream_id, completion()))
                .is_err()
        );
        let event = task.events().recv().await.unwrap();
        assert!(matches!(event.kind, AiStreamEventKind::Failed { .. }));
        assert!(task.wait().await.is_err());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn typed_receiver_rejects_a_cross_stream_event() {
        let (sender, receiver) = ai_stream_event_channel(1).unwrap();
        let (_cancel_sender, cancel_receiver) = watch::channel(false);
        let mut events = AiEventStream::new(
            AiStreamId::new("expected").unwrap(),
            receiver,
            cancel_receiver,
            Arc::new(AtomicU64::new(0)),
        );
        sender
            .send(AiStreamEvent {
                stream_id: "other".to_owned(),
                sequence: 1,
                kind: AiStreamEventKind::Completed,
            })
            .await
            .unwrap();
        assert!(events.recv().await.is_err());
    }

    #[test]
    fn injected_runtime_executes_work_when_caller_is_outside_tokio() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let (endpoint, _capture, server) =
            runtime.block_on(fixed_server(200, br#"{"answer":"runtime"}"#.to_vec()));
        let root = TestRoot::new();
        let repository = repository(&root, &endpoint, AiProviderKind::OpenAiCompatible, None);
        let service = AiService::new(runtime.handle().clone(), repository);

        let task = service.submit_completion(completion()).unwrap();
        let response = runtime.block_on(task.wait()).unwrap();
        assert_eq!(response.body["answer"], "runtime");
        runtime.block_on(server).unwrap();
    }

    #[test]
    fn dropping_a_never_polled_stream_releases_its_typed_id() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let root = TestRoot::new();
        let repository = repository(
            &root,
            "http://127.0.0.1:9/v1/chat/completions",
            AiProviderKind::OpenAiCompatible,
            None,
        );
        let service = AiService::new(runtime.handle().clone(), repository);
        let stream_id = AiStreamId::new("never-polled").unwrap();
        let task = service
            .start_stream(AiStreamRequest::new(stream_id.clone(), completion()))
            .unwrap();
        assert!(service.is_stream_active(&stream_id));
        drop(task);

        runtime.block_on(async { tokio::task::yield_now().await });
        assert!(!service.is_stream_active(&stream_id));
        let replacement = service
            .start_stream(AiStreamRequest::new(stream_id, completion()))
            .unwrap();
        drop(replacement);
        runtime.block_on(async { tokio::task::yield_now().await });
    }
}
