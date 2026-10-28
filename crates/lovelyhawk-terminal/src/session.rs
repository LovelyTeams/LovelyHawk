use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_channel::TryRecvError;

use crate::{
    ModelEvent, TerminalConfig, TerminalEvent, TerminalEventIngress, TerminalEventQueue,
    TerminalModel, TerminalModelError, terminal_event_channel,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(u64);

impl SessionId {
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    Connecting,
    Connected,
    Reconnecting { attempt: u32, delay: Duration },
    Disconnected { reason: String },
    Closed { exit_code: Option<i32> },
}

/// Limits work performed by one UI-frame drain.
///
/// A single output event larger than `max_output_bytes` is processed by itself
/// so that an oversized transport chunk cannot permanently block the queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainBudget {
    pub max_events: usize,
    pub max_output_bytes: usize,
}

impl DrainBudget {
    pub const fn new(max_events: usize, max_output_bytes: usize) -> Self {
        Self {
            max_events,
            max_output_bytes,
        }
    }

    pub const fn unlimited() -> Self {
        Self::new(usize::MAX, usize::MAX)
    }
}

impl Default for DrainBudget {
    fn default() -> Self {
        Self::new(256, 1024 * 1024)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionPoll {
    pub processed_events: usize,
    pub output_bytes: usize,
    pub parser_batches: usize,
    pub remaining_events: usize,
    pub model_events: Vec<ModelEvent>,
    pub queue_closed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TabMetadata {
    pub id: SessionId,
    pub title: String,
    pub created_sequence: u64,
    pub last_active_sequence: Option<u64>,
    pub closed_sequence: Option<u64>,
    pub reopen_count: u32,
}

impl TabMetadata {
    pub fn is_open(&self) -> bool {
        self.closed_sequence.is_none()
    }
}

pub trait ReconnectPolicy: Send + Sync {
    fn next_delay(&self, attempt: u32, reason: &str) -> Option<Duration>;
}

#[derive(Debug, Default)]
pub struct NoReconnectPolicy;

impl ReconnectPolicy for NoReconnectPolicy {
    fn next_delay(&self, _attempt: u32, _reason: &str) -> Option<Duration> {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconnectDecision {
    pub session_id: SessionId,
    pub attempt: u32,
    pub delay: Duration,
}

pub struct TerminalSession {
    id: SessionId,
    metadata: TabMetadata,
    state: SessionState,
    reconnect_attempts: u32,
    model: TerminalModel,
    ingress: TerminalEventIngress,
    events: TerminalEventQueue,
    deferred_event: Option<TerminalEvent>,
}

impl TerminalSession {
    fn new(
        id: SessionId,
        label: String,
        config: TerminalConfig,
        created_sequence: u64,
    ) -> Result<Self, TerminalModelError> {
        let (ingress, events) = terminal_event_channel(config.event_capacity)
            .expect("validated terminal config always has a non-zero capacity");
        Ok(Self {
            id,
            metadata: TabMetadata {
                id,
                title: label,
                created_sequence,
                last_active_sequence: None,
                closed_sequence: None,
                reopen_count: 0,
            },
            state: SessionState::Connecting,
            reconnect_attempts: 0,
            model: TerminalModel::new(config)?,
            ingress,
            events,
            deferred_event: None,
        })
    }

    pub fn id(&self) -> SessionId {
        self.id
    }

    pub fn label(&self) -> &str {
        &self.metadata.title
    }

    pub fn set_label(&mut self, label: impl Into<String>) {
        self.metadata.title = label.into();
    }

    pub fn metadata(&self) -> &TabMetadata {
        &self.metadata
    }

    pub fn state(&self) -> &SessionState {
        &self.state
    }

    pub fn reconnect_attempts(&self) -> u32 {
        self.reconnect_attempts
    }

    pub fn model(&self) -> &TerminalModel {
        &self.model
    }

    pub fn model_mut(&mut self) -> &mut TerminalModel {
        &mut self.model
    }

    pub fn ingress(&self) -> TerminalEventIngress {
        self.ingress.clone()
    }

    pub fn process_pending(&mut self, limit: usize) -> SessionPoll {
        self.process_frame(DrainBudget::new(limit, usize::MAX))
    }

    /// Drains a bounded amount of work without dropping or reordering events.
    /// Contiguous output events are passed to the ANSI parser as one batch.
    pub fn process_frame(&mut self, budget: DrainBudget) -> SessionPoll {
        let mut poll = SessionPoll::default();
        let mut output_batch = Vec::new();

        while poll.processed_events < budget.max_events {
            if poll.processed_events > 0 && poll.output_bytes >= budget.max_output_bytes {
                break;
            }
            let event = match self.deferred_event.take() {
                Some(event) => event,
                None => match self.events.try_recv() {
                    Ok(event) => event,
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Closed) => {
                        poll.queue_closed = true;
                        break;
                    }
                },
            };

            if let TerminalEvent::Output(bytes) = &event {
                let would_exceed_bytes = poll
                    .output_bytes
                    .checked_add(bytes.len())
                    .is_none_or(|bytes| bytes > budget.max_output_bytes);
                if poll.processed_events > 0 && would_exceed_bytes {
                    self.deferred_event = Some(event);
                    break;
                }
            }

            poll.processed_events += 1;
            match event {
                TerminalEvent::Output(bytes) => {
                    poll.output_bytes = poll.output_bytes.saturating_add(bytes.len());
                    output_batch.extend(bytes);
                }
                TerminalEvent::Connected | TerminalEvent::Reconnected => {
                    self.flush_output_batch(&mut output_batch, &mut poll);
                    self.state = SessionState::Connected;
                    self.reconnect_attempts = 0;
                }
                TerminalEvent::Disconnected { reason } => {
                    self.flush_output_batch(&mut output_batch, &mut poll);
                    self.state = SessionState::Disconnected { reason };
                }
                TerminalEvent::Closed { exit_code } => {
                    self.flush_output_batch(&mut output_batch, &mut poll);
                    self.state = SessionState::Closed { exit_code };
                }
            }
        }

        self.flush_output_batch(&mut output_batch, &mut poll);
        poll.remaining_events = self
            .events
            .metrics()
            .queued
            .saturating_add(usize::from(self.deferred_event.is_some()));
        poll
    }

    fn flush_output_batch(&mut self, output_batch: &mut Vec<u8>, poll: &mut SessionPoll) {
        if output_batch.is_empty() {
            return;
        }
        poll.parser_batches += 1;
        poll.model_events
            .extend(self.model.feed_output(output_batch).model_events);
        output_batch.clear();
    }

    pub fn close_event_queue(&self) {
        self.events.close();
    }
}

pub struct SessionRegistry {
    next_id: u64,
    sequence: u64,
    active: Option<SessionId>,
    sessions: BTreeMap<SessionId, TerminalSession>,
    closed_tabs: Vec<SessionId>,
    reconnect_policy: Arc<dyn ReconnectPolicy>,
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self {
            next_id: 1,
            sequence: 0,
            active: None,
            sessions: BTreeMap::new(),
            closed_tabs: Vec::new(),
            reconnect_policy: Arc::new(NoReconnectPolicy),
        }
    }
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_reconnect_policy(policy: impl ReconnectPolicy + 'static) -> Self {
        Self {
            reconnect_policy: Arc::new(policy),
            ..Self::default()
        }
    }

    pub fn set_reconnect_policy(&mut self, policy: impl ReconnectPolicy + 'static) {
        self.reconnect_policy = Arc::new(policy);
    }

    pub fn create(
        &mut self,
        label: impl Into<String>,
        config: TerminalConfig,
    ) -> Result<(SessionId, TerminalEventIngress), TerminalModelError> {
        let id = SessionId(self.next_id);
        self.next_id = self.next_id.saturating_add(1);
        let created_sequence = self.next_sequence();
        let session = TerminalSession::new(id, label.into(), config, created_sequence)?;
        let ingress = session.ingress();
        self.sessions.insert(id, session);
        if self.active.is_none() {
            self.activate(id);
        }
        Ok((id, ingress))
    }

    pub fn get(&self, id: SessionId) -> Option<&TerminalSession> {
        self.sessions.get(&id)
    }

    pub fn get_mut(&mut self, id: SessionId) -> Option<&mut TerminalSession> {
        self.sessions.get_mut(&id)
    }

    pub fn metadata(&self, id: SessionId) -> Option<&TabMetadata> {
        self.get(id).map(TerminalSession::metadata)
    }

    pub fn active(&self) -> Option<SessionId> {
        self.active
    }

    pub fn set_active(&mut self, id: SessionId) -> bool {
        if !self
            .sessions
            .get(&id)
            .is_some_and(|session| session.metadata.is_open())
        {
            return false;
        }
        self.activate(id);
        true
    }

    pub fn ids(&self) -> impl Iterator<Item = SessionId> + '_ {
        self.sessions.keys().copied()
    }

    pub fn open_ids(&self) -> impl Iterator<Item = SessionId> + '_ {
        self.sessions
            .iter()
            .filter(|(_, session)| session.metadata.is_open())
            .map(|(id, _)| *id)
    }

    pub fn closed_ids(&self) -> impl Iterator<Item = SessionId> + '_ {
        self.sessions
            .iter()
            .filter(|(_, session)| !session.metadata.is_open())
            .map(|(id, _)| *id)
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    pub fn close_tab(&mut self, id: SessionId, exit_code: Option<i32>) -> bool {
        if !self
            .sessions
            .get(&id)
            .is_some_and(|session| session.metadata.is_open())
        {
            return false;
        }

        let closed_sequence = self.next_sequence();
        let session = self
            .sessions
            .get_mut(&id)
            .expect("open session was checked above");
        session.metadata.closed_sequence = Some(closed_sequence);
        session.state = SessionState::Closed { exit_code };
        self.closed_tabs.push(id);

        if self.active == Some(id) {
            self.active = self.most_recent_open_session();
        }
        true
    }

    pub fn reopen_last_closed(&mut self) -> Option<SessionId> {
        while let Some(id) = self.closed_tabs.pop() {
            if self
                .sessions
                .get(&id)
                .is_none_or(|session| session.metadata.is_open())
            {
                continue;
            }

            let sequence = self.next_sequence();
            let session = self
                .sessions
                .get_mut(&id)
                .expect("closed session was checked above");
            session.metadata.closed_sequence = None;
            session.metadata.reopen_count = session.metadata.reopen_count.saturating_add(1);
            session.metadata.last_active_sequence = Some(sequence);
            session.state = SessionState::Connecting;
            session.reconnect_attempts = 0;
            self.active = Some(id);
            return Some(id);
        }
        None
    }

    pub fn next_reconnect(&mut self, id: SessionId) -> Option<ReconnectDecision> {
        let session = self.sessions.get(&id)?;
        if !session.metadata.is_open() {
            return None;
        }
        let reason = match &session.state {
            SessionState::Disconnected { reason } => reason.clone(),
            _ => return None,
        };
        let attempt = session.reconnect_attempts.saturating_add(1);
        let delay = self.reconnect_policy.next_delay(attempt, &reason)?;

        let session = self
            .sessions
            .get_mut(&id)
            .expect("session was read immediately above");
        session.reconnect_attempts = attempt;
        session.state = SessionState::Reconnecting { attempt, delay };
        Some(ReconnectDecision {
            session_id: id,
            attempt,
            delay,
        })
    }

    pub fn remove(&mut self, id: SessionId) -> Option<TerminalSession> {
        let removed = self.sessions.remove(&id)?;
        self.closed_tabs.retain(|closed_id| *closed_id != id);
        if self.active == Some(id) {
            self.active = self.most_recent_open_session();
        }
        Some(removed)
    }

    fn next_sequence(&mut self) -> u64 {
        self.sequence = self.sequence.saturating_add(1);
        self.sequence
    }

    fn activate(&mut self, id: SessionId) {
        let sequence = self.next_sequence();
        let session = self
            .sessions
            .get_mut(&id)
            .expect("only registered sessions can be activated");
        session.metadata.last_active_sequence = Some(sequence);
        self.active = Some(id);
    }

    fn most_recent_open_session(&self) -> Option<SessionId> {
        self.sessions
            .iter()
            .filter(|(_, session)| session.metadata.is_open())
            .max_by_key(|(id, session)| (session.metadata.last_active_sequence, **id))
            .map(|(id, _)| *id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TerminalSize;

    fn config() -> TerminalConfig {
        TerminalConfig {
            size: TerminalSize::new(20, 2).unwrap(),
            ..Default::default()
        }
    }

    #[test]
    fn sessions_have_isolated_models_and_event_channels() {
        let mut registry = SessionRegistry::new();
        let (first, first_events) = registry.create("first", config()).unwrap();
        let (second, second_events) = registry.create("second", config()).unwrap();

        first_events.try_publish(TerminalEvent::Connected).unwrap();
        first_events
            .try_publish(TerminalEvent::Output(b"alpha".to_vec()))
            .unwrap();
        second_events
            .try_publish(TerminalEvent::Output(b"beta".to_vec()))
            .unwrap();

        let first_poll = registry.get_mut(first).unwrap().process_pending(10);
        let second_poll = registry.get_mut(second).unwrap().process_pending(10);
        assert_eq!(first_poll.output_bytes, 5);
        assert_eq!(second_poll.output_bytes, 4);
        assert_eq!(
            registry.get(first).unwrap().model().visible_text(),
            "alpha\n"
        );
        assert_eq!(
            registry.get(second).unwrap().model().visible_text(),
            "beta\n"
        );
        assert_eq!(
            registry.get(first).unwrap().state(),
            &SessionState::Connected
        );

        assert_eq!(registry.active(), Some(first));
        assert!(registry.set_active(second));
        registry.remove(second);
        assert_eq!(registry.active(), Some(first));
    }

    #[test]
    fn frame_budget_defers_whole_event_without_reordering_or_loss() {
        let mut registry = SessionRegistry::new();
        let (id, ingress) = registry.create("limited", config()).unwrap();
        ingress
            .try_publish(TerminalEvent::Output(b"abcd".to_vec()))
            .unwrap();
        ingress
            .try_publish(TerminalEvent::Output(b"efgh".to_vec()))
            .unwrap();

        let first = registry
            .get_mut(id)
            .unwrap()
            .process_frame(DrainBudget::new(10, 6));
        assert_eq!(first.processed_events, 1);
        assert_eq!(first.output_bytes, 4);
        assert_eq!(first.remaining_events, 1);

        let second = registry
            .get_mut(id)
            .unwrap()
            .process_frame(DrainBudget::new(10, 6));
        assert_eq!(second.processed_events, 1);
        assert_eq!(second.output_bytes, 4);
        assert_eq!(second.remaining_events, 0);
        assert_eq!(registry.get(id).unwrap().model().total_bytes(), 8);
        assert_eq!(
            registry.get(id).unwrap().model().visible_text(),
            "abcdefgh\n"
        );
    }

    #[test]
    fn one_oversized_output_event_makes_progress_in_its_own_frame() {
        let mut registry = SessionRegistry::new();
        let (id, ingress) = registry.create("oversized", config()).unwrap();
        ingress
            .try_publish(TerminalEvent::Output(vec![b'x'; 32]))
            .unwrap();
        ingress.try_publish(TerminalEvent::Connected).unwrap();

        let poll = registry
            .get_mut(id)
            .unwrap()
            .process_frame(DrainBudget::new(10, 8));
        assert_eq!(poll.processed_events, 1);
        assert_eq!(poll.output_bytes, 32);
        assert_eq!(poll.remaining_events, 1);
    }

    #[test]
    fn contiguous_output_is_batched_around_state_events() {
        let mut registry = SessionRegistry::new();
        let (id, ingress) = registry.create("batched", config()).unwrap();
        for chunk in [b"a".as_slice(), b"b", b"c"] {
            ingress
                .try_publish(TerminalEvent::Output(chunk.to_vec()))
                .unwrap();
        }
        ingress.try_publish(TerminalEvent::Connected).unwrap();
        for chunk in [b"d".as_slice(), b"e"] {
            ingress
                .try_publish(TerminalEvent::Output(chunk.to_vec()))
                .unwrap();
        }

        let poll = registry
            .get_mut(id)
            .unwrap()
            .process_frame(DrainBudget::unlimited());
        assert_eq!(poll.processed_events, 6);
        assert_eq!(poll.output_bytes, 5);
        assert_eq!(poll.parser_batches, 2);
        assert_eq!(registry.get(id).unwrap().model().visible_text(), "abcde\n");
    }

    #[test]
    fn poll_limit_leaves_remaining_events_for_next_frame() {
        let mut registry = SessionRegistry::new();
        let (id, ingress) = registry.create("limited", config()).unwrap();
        ingress
            .try_publish(TerminalEvent::Output(b"a".to_vec()))
            .unwrap();
        ingress
            .try_publish(TerminalEvent::Output(b"b".to_vec()))
            .unwrap();

        let first = registry.get_mut(id).unwrap().process_pending(1);
        assert_eq!(first.processed_events, 1);
        assert_eq!(first.remaining_events, 1);
        let second = registry.get_mut(id).unwrap().process_pending(1);
        assert_eq!(second.processed_events, 1);
        assert_eq!(second.remaining_events, 0);
    }

    #[test]
    fn tabs_track_active_close_and_lifo_reopen_metadata() {
        let mut registry = SessionRegistry::new();
        let (first, _) = registry.create("first", config()).unwrap();
        let (second, _) = registry.create("second", config()).unwrap();
        let (third, _) = registry.create("third", config()).unwrap();

        assert_eq!(registry.active(), Some(first));
        assert!(registry.set_active(second));
        assert!(registry.close_tab(second, Some(0)));
        assert_eq!(registry.active(), Some(first));
        assert!(!registry.set_active(second));
        assert!(registry.close_tab(third, None));
        assert_eq!(
            registry.closed_ids().collect::<Vec<_>>(),
            vec![second, third]
        );

        assert_eq!(registry.reopen_last_closed(), Some(third));
        assert_eq!(registry.active(), Some(third));
        let metadata = registry.metadata(third).unwrap();
        assert!(metadata.is_open());
        assert_eq!(metadata.reopen_count, 1);
        assert_eq!(registry.reopen_last_closed(), Some(second));
        assert_eq!(registry.active(), Some(second));
        assert_eq!(registry.reopen_last_closed(), None);
    }

    struct TwoAttempts;

    impl ReconnectPolicy for TwoAttempts {
        fn next_delay(&self, attempt: u32, reason: &str) -> Option<Duration> {
            assert_eq!(reason, "network lost");
            (attempt <= 2).then(|| Duration::from_millis(u64::from(attempt) * 25))
        }
    }

    #[test]
    fn reconnect_schedule_is_entirely_policy_driven_and_resets_on_success() {
        let mut registry = SessionRegistry::with_reconnect_policy(TwoAttempts);
        let (id, ingress) = registry.create("reconnect", config()).unwrap();

        ingress
            .try_publish(TerminalEvent::Disconnected {
                reason: "network lost".to_owned(),
            })
            .unwrap();
        registry.get_mut(id).unwrap().process_pending(1);
        let first = registry.next_reconnect(id).unwrap();
        assert_eq!(first.attempt, 1);
        assert_eq!(first.delay, Duration::from_millis(25));
        assert_eq!(
            registry.get(id).unwrap().state(),
            &SessionState::Reconnecting {
                attempt: 1,
                delay: Duration::from_millis(25),
            }
        );

        ingress
            .try_publish(TerminalEvent::Disconnected {
                reason: "network lost".to_owned(),
            })
            .unwrap();
        registry.get_mut(id).unwrap().process_pending(1);
        assert_eq!(registry.next_reconnect(id).unwrap().attempt, 2);
        ingress
            .try_publish(TerminalEvent::Disconnected {
                reason: "network lost".to_owned(),
            })
            .unwrap();
        registry.get_mut(id).unwrap().process_pending(1);
        assert_eq!(registry.next_reconnect(id), None);

        ingress.try_publish(TerminalEvent::Reconnected).unwrap();
        registry.get_mut(id).unwrap().process_pending(1);
        assert_eq!(registry.get(id).unwrap().reconnect_attempts(), 0);
    }

    #[test]
    fn sustained_high_throughput_is_batched_and_byte_exact() {
        const EVENT_COUNT: usize = 4096;
        const CHUNK_SIZE: usize = 64;
        let mut high_throughput_config = config();
        high_throughput_config.event_capacity = EVENT_COUNT;
        let mut registry = SessionRegistry::new();
        let (id, ingress) = registry
            .create("throughput", high_throughput_config)
            .unwrap();

        for index in 0..EVENT_COUNT {
            let mut chunk = vec![b'a' + (index % 26) as u8; CHUNK_SIZE - 2];
            chunk.extend_from_slice(b"\r\n");
            ingress.try_publish(TerminalEvent::Output(chunk)).unwrap();
        }

        let mut processed_events = 0;
        let mut processed_bytes = 0;
        let mut parser_batches = 0;
        loop {
            let poll = registry
                .get_mut(id)
                .unwrap()
                .process_frame(DrainBudget::new(127, 16 * 1024));
            processed_events += poll.processed_events;
            processed_bytes += poll.output_bytes;
            parser_batches += poll.parser_batches;
            if poll.remaining_events == 0 {
                break;
            }
            assert!(poll.processed_events > 0);
        }

        assert_eq!(processed_events, EVENT_COUNT);
        assert_eq!(processed_bytes, EVENT_COUNT * CHUNK_SIZE);
        assert_eq!(
            registry.get(id).unwrap().model().total_bytes(),
            (EVENT_COUNT * CHUNK_SIZE) as u64
        );
        assert!(parser_batches < EVENT_COUNT / 20);
        let metrics = ingress.metrics();
        assert_eq!(metrics.accepted_events, EVENT_COUNT as u64);
        assert_eq!(metrics.accepted_bytes, (EVENT_COUNT * CHUNK_SIZE) as u64);
        assert_eq!(metrics.rejected_events, 0);
        assert_eq!(metrics.rejected_bytes, 0);
        assert_eq!(metrics.queued, 0);
    }
}
