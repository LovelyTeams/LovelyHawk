use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use async_channel::{Receiver, Sender, TryRecvError, TrySendError};
use async_trait::async_trait;
use thiserror::Error;

use crate::TerminalSize;

/// PTY-to-terminal messages. Each session owns a distinct bounded channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalEvent {
    Output(Vec<u8>),
    Connected,
    Reconnected,
    Disconnected { reason: String },
    Closed { exit_code: Option<i32> },
}

impl TerminalEvent {
    fn payload_len(&self) -> usize {
        match self {
            Self::Output(bytes) => bytes.len(),
            _ => 0,
        }
    }
}

/// Remote PTY operations; a russh adapter implements this trait in the core crate.
///
/// The GPUI pane polls these futures on its background executor. Implementations
/// backed by Tokio I/O must bridge into the process-level Tokio runtime rather
/// than assuming GPUI's executor owns a Tokio reactor.
#[async_trait]
pub trait TerminalTransport: Send + Sync {
    async fn send_input(&self, bytes: &[u8]) -> Result<(), TerminalTransportError>;
    async fn resize(&self, size: TerminalSize) -> Result<(), TerminalTransportError>;
    async fn close(&self) -> Result<(), TerminalTransportError>;
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TerminalTransportError {
    #[error("terminal transport is closed")]
    Closed,
    #[error("terminal transport is backpressured")]
    Backpressure,
    #[error("terminal transport failed: {0}")]
    Other(String),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BackpressureSnapshot {
    pub accepted_events: u64,
    pub accepted_bytes: u64,
    pub rejected_events: u64,
    pub rejected_bytes: u64,
    pub high_watermark: usize,
    pub queued: usize,
    pub capacity: usize,
}

#[derive(Default)]
struct BackpressureCounters {
    accepted_events: AtomicU64,
    accepted_bytes: AtomicU64,
    rejected_events: AtomicU64,
    rejected_bytes: AtomicU64,
    high_watermark: AtomicUsize,
}

impl BackpressureCounters {
    fn accepted(&self, bytes: usize, queued: usize) {
        self.accepted_events.fetch_add(1, Ordering::Relaxed);
        self.accepted_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
        self.high_watermark.fetch_max(queued, Ordering::Relaxed);
    }

    fn rejected(&self, bytes: usize) {
        self.rejected_events.fetch_add(1, Ordering::Relaxed);
        self.rejected_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    fn snapshot(&self, queued: usize, capacity: usize) -> BackpressureSnapshot {
        BackpressureSnapshot {
            accepted_events: self.accepted_events.load(Ordering::Relaxed),
            accepted_bytes: self.accepted_bytes.load(Ordering::Relaxed),
            rejected_events: self.rejected_events.load(Ordering::Relaxed),
            rejected_bytes: self.rejected_bytes.load(Ordering::Relaxed),
            high_watermark: self.high_watermark.load(Ordering::Relaxed),
            queued,
            capacity,
        }
    }
}

#[derive(Clone)]
pub struct TerminalEventIngress {
    sender: Sender<TerminalEvent>,
    counters: Arc<BackpressureCounters>,
    capacity: usize,
}

pub struct TerminalEventQueue {
    receiver: Receiver<TerminalEvent>,
    counters: Arc<BackpressureCounters>,
    capacity: usize,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PublishError {
    #[error("terminal event queue is full")]
    Full(TerminalEvent),
    #[error("terminal event queue is closed")]
    Closed(TerminalEvent),
}

pub fn terminal_event_channel(
    capacity: usize,
) -> Result<(TerminalEventIngress, TerminalEventQueue), TerminalTransportError> {
    if capacity == 0 {
        return Err(TerminalTransportError::Other(
            "terminal event capacity must be non-zero".to_owned(),
        ));
    }

    let (sender, receiver) = async_channel::bounded(capacity);
    let counters = Arc::new(BackpressureCounters::default());
    Ok((
        TerminalEventIngress {
            sender,
            counters: counters.clone(),
            capacity,
        },
        TerminalEventQueue {
            receiver,
            counters,
            capacity,
        },
    ))
}

impl TerminalEventIngress {
    /// Never drops an event silently: full/closed errors return ownership to the caller.
    pub fn try_publish(&self, event: TerminalEvent) -> Result<(), PublishError> {
        let bytes = event.payload_len();
        match self.sender.try_send(event) {
            Ok(()) => {
                self.counters.accepted(bytes, self.sender.len());
                Ok(())
            }
            Err(TrySendError::Full(event)) => {
                self.counters.rejected(bytes);
                Err(PublishError::Full(event))
            }
            Err(TrySendError::Closed(event)) => {
                self.counters.rejected(bytes);
                Err(PublishError::Closed(event))
            }
        }
    }

    pub async fn publish(&self, event: TerminalEvent) -> Result<(), PublishError> {
        let bytes = event.payload_len();
        self.sender.send(event).await.map_err(|error| {
            self.counters.rejected(bytes);
            PublishError::Closed(error.0)
        })?;
        self.counters.accepted(bytes, self.sender.len());
        Ok(())
    }

    pub fn metrics(&self) -> BackpressureSnapshot {
        self.counters.snapshot(self.sender.len(), self.capacity)
    }

    pub fn close(&self) -> bool {
        self.sender.close()
    }
}

impl TerminalEventQueue {
    pub fn try_recv(&self) -> Result<TerminalEvent, TryRecvError> {
        self.receiver.try_recv()
    }

    pub async fn recv(&self) -> Result<TerminalEvent, async_channel::RecvError> {
        self.receiver.recv().await
    }

    pub fn metrics(&self) -> BackpressureSnapshot {
        self.counters.snapshot(self.receiver.len(), self.capacity)
    }

    pub fn close(&self) -> bool {
        self.receiver.close()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_queue_returns_event_and_records_backpressure() {
        let (ingress, queue) = terminal_event_channel(1).unwrap();
        ingress
            .try_publish(TerminalEvent::Output(vec![1, 2, 3]))
            .unwrap();

        let rejected = TerminalEvent::Output(vec![4, 5]);
        assert_eq!(
            ingress.try_publish(rejected.clone()),
            Err(PublishError::Full(rejected))
        );

        assert_eq!(
            queue.try_recv().unwrap(),
            TerminalEvent::Output(vec![1, 2, 3])
        );
        assert_eq!(
            ingress.metrics(),
            BackpressureSnapshot {
                accepted_events: 1,
                accepted_bytes: 3,
                rejected_events: 1,
                rejected_bytes: 2,
                high_watermark: 1,
                queued: 0,
                capacity: 1,
            }
        );
    }

    #[test]
    fn async_publish_waits_for_capacity_instead_of_losing_output() {
        futures::executor::block_on(async {
            let (ingress, queue) = terminal_event_channel(1).unwrap();
            ingress.publish(TerminalEvent::Connected).await.unwrap();
            assert_eq!(queue.recv().await.unwrap(), TerminalEvent::Connected);
            ingress
                .publish(TerminalEvent::Output(b"next".to_vec()))
                .await
                .unwrap();
            assert_eq!(
                queue.recv().await.unwrap(),
                TerminalEvent::Output(b"next".to_vec())
            );
        });
    }
}
