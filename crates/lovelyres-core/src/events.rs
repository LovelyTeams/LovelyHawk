//! Typed, independently bounded streams for long-running core work.

use async_channel::{Receiver, Sender};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::packet_capture::PacketEntry;
use crate::{CoreError, CoreResult};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalEvent {
    pub session_id: String,
    pub sequence: u64,
    pub kind: TerminalEventKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TerminalEventKind {
    Output(Vec<u8>),
    TitleChanged(String),
    Bell,
    Exited { exit_code: Option<i32> },
    Failed { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiStreamEvent {
    pub stream_id: String,
    pub sequence: u64,
    pub kind: AiStreamEventKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AiStreamEventKind {
    Delta(String),
    Completed,
    Cancelled,
    Failed { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketCaptureEvent {
    pub capture_id: String,
    pub sequence: u64,
    pub observed_at: DateTime<Utc>,
    pub kind: PacketCaptureEventKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacketCaptureEventKind {
    Started { interface: String },
    Data(PacketEntry),
    Info { message: String },
    Progress { packets: u64, bytes: u64 },
    ArtifactReady { path: String, sha256: String },
    Stopped,
    Failed { message: String },
}

/// Terminal control surface implemented by the russh-backed transport.
#[async_trait]
pub trait TerminalTransport: Send + Sync + std::fmt::Debug {
    async fn write_input(&self, bytes: Vec<u8>) -> CoreResult<()>;
    async fn resize(&self, columns: u16, rows: u16) -> CoreResult<()>;
    async fn close(&self) -> CoreResult<()>;
}

#[derive(Debug, Clone)]
pub struct TerminalEventSender(Sender<TerminalEvent>);

#[derive(Debug)]
pub struct TerminalEventReceiver(Receiver<TerminalEvent>);

pub fn terminal_event_channel(
    capacity: usize,
) -> CoreResult<(TerminalEventSender, TerminalEventReceiver)> {
    if capacity == 0 {
        return Err(CoreError::InvalidChannelCapacity);
    }
    let (sender, receiver) = async_channel::bounded(capacity);
    Ok((TerminalEventSender(sender), TerminalEventReceiver(receiver)))
}

impl TerminalEventSender {
    pub async fn send(&self, event: TerminalEvent) -> CoreResult<()> {
        self.0
            .send(event)
            .await
            .map_err(|_| CoreError::ChannelClosed {
                channel: "terminal",
            })
    }

    pub fn close(&self) {
        self.0.close();
    }

    pub(crate) fn try_send(&self, event: TerminalEvent) -> bool {
        self.0.try_send(event).is_ok()
    }
}

impl TerminalEventReceiver {
    pub async fn recv(&self) -> CoreResult<TerminalEvent> {
        self.0.recv().await.map_err(|_| CoreError::ChannelClosed {
            channel: "terminal",
        })
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Drain events during a frontend frame without exposing the channel backend.
    pub fn try_recv(&self) -> CoreResult<Option<TerminalEvent>> {
        match self.0.try_recv() {
            Ok(event) => Ok(Some(event)),
            Err(async_channel::TryRecvError::Empty) => Ok(None),
            Err(async_channel::TryRecvError::Closed) => Err(CoreError::ChannelClosed {
                channel: "terminal",
            }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AiStreamEventSender(Sender<AiStreamEvent>);

#[derive(Debug)]
pub struct AiStreamEventReceiver(Receiver<AiStreamEvent>);

pub fn ai_stream_event_channel(
    capacity: usize,
) -> CoreResult<(AiStreamEventSender, AiStreamEventReceiver)> {
    if capacity == 0 {
        return Err(CoreError::InvalidChannelCapacity);
    }
    let (sender, receiver) = async_channel::bounded(capacity);
    Ok((AiStreamEventSender(sender), AiStreamEventReceiver(receiver)))
}

impl AiStreamEventSender {
    pub async fn send(&self, event: AiStreamEvent) -> CoreResult<()> {
        self.0
            .send(event)
            .await
            .map_err(|_| CoreError::ChannelClosed { channel: "AI" })
    }

    pub fn close(&self) {
        self.0.close();
    }
}

impl AiStreamEventReceiver {
    pub async fn recv(&self) -> CoreResult<AiStreamEvent> {
        self.0
            .recv()
            .await
            .map_err(|_| CoreError::ChannelClosed { channel: "AI" })
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct PacketCaptureEventSender(Sender<PacketCaptureEvent>);

#[derive(Debug)]
pub struct PacketCaptureEventReceiver(Receiver<PacketCaptureEvent>);

pub fn packet_capture_event_channel(
    capacity: usize,
) -> CoreResult<(PacketCaptureEventSender, PacketCaptureEventReceiver)> {
    if capacity == 0 {
        return Err(CoreError::InvalidChannelCapacity);
    }
    let (sender, receiver) = async_channel::bounded(capacity);
    Ok((
        PacketCaptureEventSender(sender),
        PacketCaptureEventReceiver(receiver),
    ))
}

impl PacketCaptureEventSender {
    pub async fn send(&self, event: PacketCaptureEvent) -> CoreResult<()> {
        self.0
            .send(event)
            .await
            .map_err(|_| CoreError::ChannelClosed {
                channel: "packet capture",
            })
    }

    pub fn close(&self) {
        self.0.close();
    }
}

impl PacketCaptureEventReceiver {
    pub async fn recv(&self) -> CoreResult<PacketCaptureEvent> {
        self.0.recv().await.map_err(|_| CoreError::ChannelClosed {
            channel: "packet capture",
        })
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn try_recv(&self) -> CoreResult<Option<PacketCaptureEvent>> {
        match self.0.try_recv() {
            Ok(event) => Ok(Some(event)),
            Err(async_channel::TryRecvError::Empty) => Ok(None),
            Err(async_channel::TryRecvError::Closed) => Err(CoreError::ChannelClosed {
                channel: "packet capture",
            }),
        }
    }
}

/// Defaults remain per-domain so a noisy terminal cannot starve another stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventChannelDefaults {
    pub terminal: usize,
    pub ai_stream: usize,
    pub packet_capture: usize,
}

impl Default for EventChannelDefaults {
    fn default() -> Self {
        Self {
            terminal: 512,
            ai_stream: 128,
            packet_capture: 64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn terminal_channel_preserves_binary_output() {
        let (sender, receiver) = terminal_event_channel(1).unwrap();
        sender
            .send(TerminalEvent {
                session_id: "s1".to_owned(),
                sequence: 1,
                kind: TerminalEventKind::Output(vec![0, 0xff, b'\n']),
            })
            .await
            .unwrap();
        assert_eq!(receiver.len(), 1);
        let event = receiver.recv().await.unwrap();
        assert_eq!(event.kind, TerminalEventKind::Output(vec![0, 0xff, b'\n']));
    }

    #[tokio::test]
    async fn terminal_channel_supports_frame_draining_without_exposing_backend() {
        let (sender, receiver) = terminal_event_channel(2).unwrap();
        assert_eq!(receiver.try_recv().unwrap(), None);
        sender
            .send(TerminalEvent {
                session_id: "frame".to_owned(),
                sequence: 1,
                kind: TerminalEventKind::Bell,
            })
            .await
            .unwrap();
        assert!(matches!(
            receiver.try_recv().unwrap(),
            Some(TerminalEvent {
                kind: TerminalEventKind::Bell,
                ..
            })
        ));
        sender.close();
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn each_channel_closes_independently() {
        let (ai_sender, ai_receiver) = ai_stream_event_channel(2).unwrap();
        ai_sender.close();
        assert!(matches!(
            ai_receiver.recv().await,
            Err(CoreError::ChannelClosed { channel: "AI" })
        ));

        let (packet_sender, packet_receiver) = packet_capture_event_channel(2).unwrap();
        packet_sender.close();
        assert!(packet_receiver.recv().await.is_err());
    }

    #[test]
    fn rejects_zero_capacity() {
        assert!(terminal_event_channel(0).is_err());
        assert!(ai_stream_event_channel(0).is_err());
        assert!(packet_capture_event_channel(0).is_err());
    }
}
