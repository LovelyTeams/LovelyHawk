//! Native terminal primitives for LovelyRes.
//!
//! ANSI emulation is provided by `alacritty_terminal`; this crate owns the
//! bounded transport boundary, LovelyRes session model, inspection helpers,
//! and the small GPUI view used while the full renderer is being built.

pub mod completion;
pub mod config;
pub mod geometry;
pub mod input;
pub mod keymap;
pub mod model;
pub mod pane;
pub mod protocol;
pub mod search;
pub mod session;
pub mod transport;
pub mod view;
pub mod workspace;

pub use completion::{CommandCompletion, RemoteCompletion};
pub use config::{TerminalConfig, TerminalConfigError, TerminalSize};
pub use geometry::{PointerSelection, TerminalGeometry};
pub use input::{ImeLayoutRect, ImeState};
pub use keymap::{KeyAction, TerminalKeyEncoder, TerminalShortcut};
pub use model::{
    CellColor, CellPosition, FeedReport, LinkMatch, LinkSource, ModelEvent, OscClipboardPolicy,
    RenderCell, RenderCursor, RenderSnapshot, SearchMatch, SearchOptions, TerminalCell,
    TerminalCursorShape, TerminalModel, TerminalModelError,
};
pub use pane::{
    CloseRequestStatus, InputQueueSnapshot, ResizeQueueStatus, TerminalInputQueueError,
    TerminalPane, TerminalPaneEvent,
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
pub use view::{TerminalPalette, TerminalView};
pub use workspace::{
    TabDirection, TerminalAiOverlay, TerminalAiState, TerminalAiToken, TerminalSearchOverlay,
    TerminalTab, TerminalTabId, TerminalTabState, TerminalTabToken, TerminalWorkspace,
};
