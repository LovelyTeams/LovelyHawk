# Native terminal feasibility gates

Unit tests establish deterministic encoding and layout behavior; they do not
replace the hardware and interoperability gate required before a release.

## Implemented and covered without a real window

- ANSI parser state, true color, CJK width, combining marks, alternate screen;
- render snapshot containing every cell attribute, selection, and cursor;
- UTF-16 IME composition/replacement/commit and candidate geometry mapping;
- Ctrl/Alt/Shift, application cursor, navigation, and F1–F12 encoding;
- application keypad and DEC focus-in/out encoding;
- mouse coordinate selection, wheel-to-line conversion, font/DPI resize math;
- DEC 1000/1002/1003 tracking with legacy and SGR 1006 wire encoding;
- URL/OSC 8 hit-testing, stateful case/regex search, and link activation handoff;
- OSC 52 clipboard writes denied by default and size-bounded explicit opt-in;
- per-session bounded queues, explicit backpressure accounting, frame budgets,
  parser batching, and byte-exact 4096-event sustained-output coverage;
- tab metadata, active/close/reopen transitions, and policy-driven reconnect;
- JSON conformance fixtures for alternate screen, bracketed paste,
  wide/combining cells, and resize preservation.

## Blocking real-system gate — not yet certified

- Win10 22H2 and current Win11: Microsoft Pinyin preedit/candidate placement,
  commit, cancellation, and repeated composition at 100/150/200% DPI;
- physical display, RDP, VM, and mixed-DPI monitor transitions;
- copy/paste with CJK, emoji, CRLF, large payloads, and bracket delimiters;
- embedded local Inter and monospace font fallback for CJK/emoji glyphs;
- OpenSSH server matrix through russh, including resize during full-screen
  programs, reconnect, alternate screen, bracketed paste, application keypad,
  focus events, and DEC/SGR mouse operation in tmux/vim;
- sustained end-to-end output and resize storms with no queue loss and bounded
  latency. The parser/queue layer is byte-exact; russh-to-frontend scheduling
  still requires real-system certification;
- OSC 52 opt-in UX and Windows clipboard integration. The default-deny policy
  is implemented, but no release flow should enable writes implicitly;
- visual cursor/selection/underline alignment evidence in the desktop (Tauri)
  terminal window;
- renderer performance for large grids in the desktop (Tauri) terminal window if
  the throughput gate misses its frame-time target.

## Explicitly outside this phase

- screen-reader certification for the hosting terminal window;
- any WebView, xterm.js, ttyd, Wetty, ShellInABox, or gotty fallback.
