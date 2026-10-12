//! Native terminal primitives for LovelyHawk.
//!
//! ANSI emulation is provided by `alacritty_terminal`; this crate owns the
//! bounded transport boundary, LovelyHawk session model, and inspection
//! helpers consumed by the desktop backend.

pub mod completion;
pub mod config;
pub mod geometry;
pub mod input;
pub mod model;
pub mod protocol;
pub mod search;
pub mod session;
pub mod transport;
pub mod workspace;

pub use completion::{CommandCompletion, RemoteCompletion};
pub use config::{TerminalConfig, TerminalConfigError, TerminalSize};
pub use geometry::{PointerSelection, TerminalGeometry};
pub use input::{ImeLayoutRect, ImeState};
pub use model::{
    CellColor, CellPosition, FeedReport, LinkMatch, LinkSource, ModelEvent, OscClipboardPolicy,
    RenderCell, RenderCursor, RenderSnapshot, SearchMatch, SearchOptions, TerminalCell,
    TerminalCursorShape, TerminalModel, TerminalModelError,
};
pub use protocol::{
    MouseButtonCode, MouseEncoding, MouseEventKind, MouseModifiers, MouseProtocol,
    MouseTrackingMode,
};
pub use search::SearchState;
pub use session::{
    DrainBudget, NoReconnectPolicy, ReconnectDecision, ReconnectPolicy, SessionId, SessionPoll,
    SessionRegistry, SessionState, TabMetadata, TerminalSession,
};
pub use transport::{
    BackpressureSnapshot, PublishError, TerminalEvent, TerminalEventIngress, TerminalEventQueue,
    TerminalTransport, TerminalTransportError, terminal_event_channel,
};
pub use workspace::{
    TabDirection, TerminalAiOverlay, TerminalAiState, TerminalAiToken, TerminalSearchOverlay,
    TerminalTab, TerminalTabId, TerminalTabState, TerminalTabToken, TerminalWorkspace,
};
