# lovelyhawk-terminal

Headless native terminal foundation for LovelyHawk. It has no
WebView, ttyd, Wetty, ShellInABox, or gotty dependency; the desktop
terminal window (`ui/`) consumes its bounded snapshots and events through the
Tauri host's terminal commands and the in-process `lovelyhawk-backend`.

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
- UTF-16 IME preedit/selection/range/bounds mapping and UTF-8 commit;
- measured geometry helpers, DPI-aware PTY pixel dimensions, and resize dispatch;
- per-cell ANSI foreground/background, bold, dim, italic, underline,
  strikeout, inverse, hidden, selection, and cursor state.

Tokio-backed transports must bridge through LovelyHawk's process Tokio runtime
rather than assuming the hosting frontend's executor owns a Tokio reactor.

This is still not a claim of complete SSH compatibility. The real OpenSSH, IME,
reconnect, and sustained-throughput checks are tracked in
`FEASIBILITY_GATES.md`. Protocol conformance fixtures and deterministic
high-throughput tests cover the window-independent layer; real tmux/vim/russh
behavior remains a release gate.
