# lovelyres-terminal

Native terminal foundation for LovelyRes GPUI. It has no
WebView, xterm.js, ttyd, Wetty, ShellInABox, or gotty dependency.

Implemented in this phase:

- `alacritty_terminal 0.25.1` ANSI/VTE state, true color, wide and combining cells;
- bounded per-session event channels with explicit backpressure metrics;
- typed PTY input/resize/close transport contract;
- scrollback, selection/copy, search, URL and OSC 8 link inspection;
- stateful case-sensitive/regex search with next/previous wrap-around navigation;
- cell-level URL/OSC 8 hit-testing and a Ctrl-click activation handoff;
- bracketed-paste delimiter protection and observable alternate screen state;
- DEC mouse modes 1000/1002/1003 with legacy and SGR 1006 encoding;
- DEC focus-in/out reports and application-cursor/application-keypad encoding;
- OSC 52 remote clipboard writes denied by default, with an explicit size-bounded
  opt-in policy; remote clipboard reads remain disabled;
- isolated multi-session registry with tab metadata, active/close/reopen state,
  and an injectable reconnect policy;
- frame-budgeted event draining that batches contiguous parser input while
  preserving every event and byte in order;
- GPUI 0.2.2 `TerminalPane` with `Focusable` and the canonical
  `EntityInputHandler` → `ElementInputHandler` bridge;
- UTF-16 IME preedit/selection/range/bounds mapping and UTF-8 commit;
- xterm-compatible control, Alt, cursor, navigation, and F1–F12 key encoding;
- local mouse drag selection, wheel scrollback, clipboard shortcuts, and a
  search-overlay request hook;
- measured font metrics, DPI-aware PTY pixel dimensions, and resize dispatch;
- an input-only bounded FIFO that preserves accepted byte order, returns
  rejected bytes to the caller, retries downstream backpressure, and exposes
  rejection counters plus an in-pane saturation warning;
- a coalescing one-slot resize path and an independent high-priority close
  worker, so resize storms cannot consume input capacity and a saturated input
  queue cannot block shutdown;
- per-cell ANSI foreground/background, bold, dim, italic, underline,
  strikeout, inverse, hidden, selection, and cursor rendering.

`TerminalPane::attach` embeds an existing `Arc<Mutex<TerminalModel>>` and an
`Arc<dyn TerminalTransport>`; `TerminalPane::create` creates the model from a
configuration. Tokio-backed transports must bridge through LovelyRes' process
Tokio runtime because GPUI's background executor is intentionally separate.

This is still not a claim of complete SSH compatibility. The real Windows,
OpenSSH, IME, DPI, RDP, font fallback, reconnect, and sustained-throughput
checks are tracked in `FEASIBILITY_GATES.md`. Protocol conformance fixtures and
deterministic high-throughput tests cover the window-independent layer; real
tmux/vim/russh and GPUI frame-time behavior remain release gates.
