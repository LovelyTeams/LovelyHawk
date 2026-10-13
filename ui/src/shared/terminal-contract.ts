export const TERMINAL_LIMITS = Object.freeze({
  maximumTerminals: 16,
  maximumTerminalsPerTarget: 2,
  maximumHandleBytes: 128,
  maximumColumns: 160,
  maximumRows: 60,
  maximumScrollbackLines: 5_000,
  maximumInputBytes: 64 * 1_024,
  maximumQueuedInputBytes: 256 * 1_024,
  maximumPollEvents: 64,
  maximumPollBytes: 256 * 1_024,
  maximumOutputEventBytes: 256 * 1_024,
  maximumTotalOutputBytes: 64 * 1_024 * 1_024,
  maximumTitleBytes: 4 * 1_024,
  maximumCellTextBytes: 256,
  maximumSnapshotBytes: 4 * 1_024 * 1_024,
  maximumSearchQueryBytes: 1_024,
  maximumSearchResults: 256,
  maximumSearchMatchBytes: 4 * 1_024,
  maximumSearchResponseBytes: 128 * 1_024,
  maximumSelectionCopyBytes: 128 * 1_024,
  // Mirrors MAXIMUM_TABS and MAXIMUM_TAB_NAME_BYTES in
  // crates/lovelyhawk-desktop/src/child_windows.rs and child_commands.rs.
  maximumTabs: 4,
  maximumTabNameBytes: 4,
} as const);

/**
 * One shell, as the terminal view and its controller use it. A window's tab
 * is one of these; `terminalTabSession` builds it over the window's API.
 */
export interface TerminalSessionApi {
  open(columns: number, rows: number): Promise<TerminalWindowOpened>;
  poll(maximumEvents: number, maximumBytes: number): Promise<TerminalPoll>;
  input(bytesBase64: string): Promise<TerminalInputAcknowledgement>;
  resize(columns: number, rows: number): Promise<TerminalResized>;
  search(
    query: string,
    caseSensitive: boolean,
    regex: boolean,
    maximumResults: number,
  ): Promise<TerminalSearch>;
  close(): Promise<TerminalClosed>;
}

/**
 * What a terminal-family window may call. Its shells are tabs, named by the
 * number the host gave each when it opened; the page never sees the host's
 * handle behind a tab, nor the target.
 */
export interface TerminalApi {
  /** The window's first shell. Every terminal window opens one, once. */
  open(columns: number, rows: number): Promise<TerminalTabOpened>;
  /** Another shell beside the first. Only the host shell's window has tabs. */
  openTab(columns: number, rows: number): Promise<TerminalTabOpened>;
  poll(tab: string, maximumEvents: number, maximumBytes: number): Promise<TerminalPoll>;
  input(tab: string, bytesBase64: string): Promise<TerminalInputAcknowledgement>;
  resize(tab: string, columns: number, rows: number): Promise<TerminalResized>;
  search(
    tab: string,
    query: string,
    caseSensitive: boolean,
    regex: boolean,
    maximumResults: number,
  ): Promise<TerminalSearch>;
  copySelection(text: string): Promise<void>;
  /** Closes one tab's shell; the window stays. */
  closeTab(tab: string): Promise<TerminalClosed>;
  /** Closes the window and every shell in it. */
  close(): Promise<TerminalClosed>;
  /**
   * The read-only file browser for the same target. Main resolves which target
   * the calling window belongs to, so no target identity reaches this renderer.
   */
  openSftpBrowser(): Promise<unknown>;
  listSftpDirectory(browserHandle: string, directoryHandle: string): Promise<unknown>;
  readSftpText(browserHandle: string, fileHandle: string): Promise<unknown>;
  downloadSftpEntry(browserHandle: string, fileHandle: string): Promise<unknown>;
  planSftpOperation(browserHandle: string, input: unknown): Promise<unknown>;
  confirmSftpOperation(planHandle: string): Promise<unknown>;
  executeSftpOperation(planHandle: string): Promise<unknown>;
  cancelSftpOperation(planHandle: string): Promise<unknown>;
  undoSftpOperation(planHandle: string): Promise<unknown>;
  cancelSftpTransfer(browserHandle: string): Promise<unknown>;
  stageSftpUpload(): Promise<unknown>;
  /** The operator's own machine, addressed by opaque directory handles. */
  openLocalBrowser(): Promise<unknown>;
  listLocalDirectory(directoryHandle: string): Promise<unknown>;
  /**
   * Open one file in a window of its own.
   *
   * `editable` is what separates 预览 from 编辑: the same window either way,
   * but a preview has no way to write. Reading and writing go through the SFTP
   * methods above — this only opens the window.
   */
  openFileEditor(
    browserHandle: string,
    entryHandle: string,
    name: string,
    editable: boolean,
  ): Promise<unknown>;
  /**
   * Open a terminal window that starts in a folder the file pane listed. Only
   * the SSH window's own pane can: the host refuses it from any other window.
   */
  openDirectoryTerminal(browserHandle: string, directoryHandle: string, name: string): Promise<unknown>;
  /**
   * What this window was opened for, asked by the editor itself.
   *
   * It cannot ask for anything else: the answer is the scope main recorded
   * when it created the window.
   */
  fileEditorTarget(): Promise<unknown>;
  /**
   * An editor window telling the host whether it holds text that is not on
   * the server. While it does, closing the window from outside the page
   * (Alt+F4, the taskbar) is held until the page answers `onBeforeClose`.
   */
  setUnsavedChanges(unsaved: boolean): Promise<void>;
  /** Answers the host's close question; `handler` resolves to "may close". */
  onBeforeClose(handler: () => Promise<boolean>): () => void;
}

/** What an editor window is looking at. */
export interface FileEditorTarget {
  browserHandle: string;
  entryHandle: string;
  name: string;
  editable: boolean;
}

export function isFileEditorTarget(value: unknown): value is FileEditorTarget {
  return (
    isRecord(value) &&
    hasExactKeys(value, ["browserHandle", "entryHandle", "name", "editable"]) &&
    typeof value.browserHandle === "string" && value.browserHandle.length > 0 &&
    typeof value.entryHandle === "string" && value.entryHandle.length > 0 &&
    typeof value.name === "string" && value.name.length > 0 && value.name.length <= 255 &&
    typeof value.editable === "boolean"
  );
}

export interface TerminalWindowLaunchResult {
  opened: true;
  reused: boolean;
}

export interface TerminalWindowOpened {
  columns: number;
  rows: number;
}

/** A shell the window opened, with the tab number the host gave it. */
export interface TerminalTabOpened extends TerminalWindowOpened {
  tab: string;
}

export interface TerminalSize {
  columns: number;
  rows: number;
}

export interface TerminalOpened {
  handle: string;
  columns: number;
  rows: number;
}

/**
 * The shells a container terminal can land in.
 *
 * Closed, and chosen by the host rather than by the window: a thin image has
 * no bash, and asking for one that is not there opens a terminal that dies on
 * the first keystroke.
 */
export const CONTAINER_TERMINAL_SHELLS = ["sh", "bash", "ash"] as const;
export type ContainerTerminalShell = (typeof CONTAINER_TERMINAL_SHELLS)[number];

/**
 * A terminal opened inside a container.
 *
 * Same handle and size as any other terminal — everything downstream treats it
 * identically — plus which shell was actually found, so the window can say so
 * instead of leaving the operator to wonder why there is no history.
 */
export interface ContainerTerminalOpened extends TerminalOpened {
  shell: ContainerTerminalShell;
}

export type TerminalPollEvent =
  | { kind: "output"; sequence: number; bytes_base64: string }
  | { kind: "title-changed"; sequence: number; title: string; truncated: boolean }
  | { kind: "bell"; sequence: number }
  | { kind: "exited"; sequence: number; exit_code: number | null }
  | { kind: "failed"; sequence: number; code: "terminal-transport-failed" }
  | { kind: "closed"; sequence: number };

export interface TerminalPoll {
  events: TerminalPollEvent[];
  rawBytes: number;
  hasMore: boolean;
}

export interface TerminalInputAcknowledgement {
  acceptedBytes: number;
}

export interface TerminalResized {
  columns: number;
  rows: number;
}

export interface TerminalClosed {
  closed: true;
}

export type TerminalColor =
  | { kind: "named"; name: string }
  | { kind: "indexed"; index: number }
  | { kind: "rgb"; red: number; green: number; blue: number };

export interface TerminalRenderCell {
  row: number;
  column: number;
  text: string;
  width: number;
  foreground: TerminalColor;
  background: TerminalColor;
  bold: boolean;
  dim: boolean;
  italic: boolean;
  underline: boolean;
  strikeout: boolean;
  inverse: boolean;
  hidden: boolean;
  selected: boolean;
}

export interface TerminalRenderCursor {
  row: number;
  column: number;
  shape: "block" | "underline" | "beam" | "hollow-block";
}

export interface TerminalRenderSnapshot {
  columns: number;
  rows: number;
  cells: TerminalRenderCell[][];
  cursor: TerminalRenderCursor | null;
  displayOffset: number;
  alternateScreen: boolean;
  totalOutputBytes: number;
}

export interface TerminalSearchMatch {
  line: number;
  startColumn: number;
  endColumn: number;
  text: string;
}

export interface TerminalSearch {
  matches: TerminalSearchMatch[];
  limited: boolean;
}

type JsonRecord = Record<string, unknown>;
const encoder = new TextEncoder();
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const OPAQUE_HANDLE_PATTERN = /^[A-Za-z0-9-]+$/u;
const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;
const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const CONTROL_PATTERN = /\p{Cc}/u;
const NAMED_COLOR_PATTERN = /^[A-Za-z]+$/u;

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: JsonRecord, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && actual.every((key) => keys.includes(key));
}

function isSafeInteger(value: unknown, minimum: number, maximum: number): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= minimum &&
    value <= maximum
  );
}

function isUtf8(value: unknown, maximumBytes: number, allowEmpty = true): value is string {
  return (
    typeof value === "string" &&
    (allowEmpty || value.length > 0) &&
    encoder.encode(value).byteLength <= maximumBytes
  );
}

function serializedBytes(value: unknown): number | null {
  try {
    return encoder.encode(JSON.stringify(value)).byteLength;
  } catch {
    return null;
  }
}

export function isTerminalBindingHandle(value: unknown): value is string {
  return (
    isUtf8(value, TERMINAL_LIMITS.maximumHandleBytes, false) &&
    OPAQUE_HANDLE_PATTERN.test(value)
  );
}

export function isTerminalSelectionCopyText(value: unknown): value is string {
  return isUtf8(value, TERMINAL_LIMITS.maximumSelectionCopyBytes, false);
}

export function isTerminalHandle(value: unknown): value is string {
  return (
    isUtf8(value, TERMINAL_LIMITS.maximumHandleBytes, false) &&
    UUID_PATTERN.test(value)
  );
}

export function isTerminalSize(columns: unknown, rows: unknown): boolean {
  return (
    isSafeInteger(columns, 1, TERMINAL_LIMITS.maximumColumns) &&
    isSafeInteger(rows, 1, TERMINAL_LIMITS.maximumRows)
  );
}

export function clampTerminalSize(columns: number, rows: number): TerminalSize {
  const boundedColumns = Number.isFinite(columns) ? Math.floor(columns) : 1;
  const boundedRows = Number.isFinite(rows) ? Math.floor(rows) : 1;
  return {
    columns: Math.min(TERMINAL_LIMITS.maximumColumns, Math.max(1, boundedColumns)),
    rows: Math.min(TERMINAL_LIMITS.maximumRows, Math.max(1, boundedRows)),
  };
}

export function isTerminalPollBounds(maximumEvents: unknown, maximumBytes: unknown): boolean {
  return (
    isSafeInteger(maximumEvents, 1, TERMINAL_LIMITS.maximumPollEvents) &&
    isSafeInteger(maximumBytes, 1, TERMINAL_LIMITS.maximumPollBytes)
  );
}

export function isTerminalSearchRequest(
  query: unknown,
  maximumResults: unknown,
): query is string {
  return (
    isUtf8(query, TERMINAL_LIMITS.maximumSearchQueryBytes, false) &&
    !CONTROL_PATTERN.test(query) &&
    isSafeInteger(maximumResults, 1, TERMINAL_LIMITS.maximumSearchResults)
  );
}

export function terminalBase64DecodedLength(
  value: unknown,
  maximumDecodedBytes: number,
  allowEmpty: boolean,
): number | null {
  if (
    typeof value !== "string" ||
    (!allowEmpty && value.length === 0) ||
    value.length > Math.ceil(maximumDecodedBytes / 3) * 4 ||
    !BASE64_PATTERN.test(value)
  ) return null;
  if (value.length === 0) return 0;

  const padding = value.endsWith("==") ? 2 : value.endsWith("=") ? 1 : 0;
  const significantIndex = value.length - padding - 1;
  const significant = BASE64_ALPHABET.indexOf(value[significantIndex] ?? "");
  if (significant < 0) return null;
  if ((padding === 2 && (significant & 0b1111) !== 0) ||
      (padding === 1 && (significant & 0b11) !== 0)) return null;

  const decoded = (value.length / 4) * 3 - padding;
  return decoded <= maximumDecodedBytes ? decoded : null;
}

export function isTerminalOpened(value: unknown): value is TerminalOpened {
  return (
    isRecord(value) &&
    hasExactKeys(value, ["handle", "columns", "rows"]) &&
    isTerminalHandle(value.handle) &&
    isTerminalSize(value.columns, value.rows)
  );
}

export function isContainerTerminalOpened(
  value: unknown,
): value is ContainerTerminalOpened {
  return (
    isRecord(value) &&
    hasExactKeys(value, ["handle", "columns", "rows", "shell"]) &&
    isTerminalHandle(value.handle) &&
    isTerminalSize(value.columns, value.rows) &&
    typeof value.shell === "string" &&
    (CONTAINER_TERMINAL_SHELLS as readonly string[]).includes(value.shell)
  );
}

export function isTerminalWindowLaunchResult(
  value: unknown,
): value is TerminalWindowLaunchResult {
  return (
    isRecord(value) &&
    hasExactKeys(value, ["opened", "reused"]) &&
    value.opened === true &&
    typeof value.reused === "boolean"
  );
}

export function isTerminalWindowOpened(value: unknown): value is TerminalWindowOpened {
  return (
    isRecord(value) &&
    hasExactKeys(value, ["columns", "rows"]) &&
    isTerminalSize(value.columns, value.rows)
  );
}

/** A tab number as the host gives them out: short, decimal, never zero. */
export function isTerminalTabName(value: unknown): value is string {
  return typeof value === "string" &&
    value.length <= TERMINAL_LIMITS.maximumTabNameBytes &&
    /^[1-9][0-9]*$/u.test(value);
}

export function isTerminalTabOpened(value: unknown): value is TerminalTabOpened {
  return (
    isRecord(value) &&
    hasExactKeys(value, ["tab", "columns", "rows"]) &&
    isTerminalTabName(value.tab) &&
    isTerminalSize(value.columns, value.rows)
  );
}

function terminalPollEventBytes(value: unknown): number | null {
  if (!isRecord(value) || !isSafeInteger(value.sequence, 1, Number.MAX_SAFE_INTEGER)) return null;
  switch (value.kind) {
    case "output": {
      if (!hasExactKeys(value, ["kind", "sequence", "bytes_base64"])) return null;
      return terminalBase64DecodedLength(
        value.bytes_base64,
        TERMINAL_LIMITS.maximumOutputEventBytes,
        true,
      );
    }
    case "title-changed":
      return (
        hasExactKeys(value, ["kind", "sequence", "title", "truncated"]) &&
        isUtf8(value.title, TERMINAL_LIMITS.maximumTitleBytes) &&
        typeof value.truncated === "boolean"
      ) ? encoder.encode(value.title).byteLength : null;
    case "bell":
      return hasExactKeys(value, ["kind", "sequence"]) ? 0 : null;
    case "exited":
      return (
        hasExactKeys(value, ["kind", "sequence", "exit_code"]) &&
        (value.exit_code === null || isSafeInteger(value.exit_code, -2_147_483_648, 2_147_483_647))
      ) ? 0 : null;
    case "failed":
      return (
        hasExactKeys(value, ["kind", "sequence", "code"]) &&
        value.code === "terminal-transport-failed"
      ) ? 0 : null;
    case "closed":
      return hasExactKeys(value, ["kind", "sequence"]) ? 0 : null;
    default:
      return null;
  }
}

export function isTerminalPoll(value: unknown): value is TerminalPoll {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["events", "rawBytes", "hasMore"]) ||
    !Array.isArray(value.events) ||
    value.events.length > TERMINAL_LIMITS.maximumPollEvents ||
    !isSafeInteger(value.rawBytes, 0, TERMINAL_LIMITS.maximumPollBytes) ||
    typeof value.hasMore !== "boolean"
  ) return false;

  let calculatedBytes = 0;
  for (const event of value.events) {
    const eventBytes = terminalPollEventBytes(event);
    if (eventBytes === null) return false;
    calculatedBytes += eventBytes;
    if (calculatedBytes > TERMINAL_LIMITS.maximumPollBytes) return false;
  }
  return calculatedBytes === value.rawBytes;
}

export function isTerminalInputAcknowledgement(
  value: unknown,
): value is TerminalInputAcknowledgement {
  return (
    isRecord(value) &&
    hasExactKeys(value, ["acceptedBytes"]) &&
    isSafeInteger(value.acceptedBytes, 1, TERMINAL_LIMITS.maximumInputBytes)
  );
}

export function isTerminalResized(value: unknown): value is TerminalResized {
  return (
    isRecord(value) &&
    hasExactKeys(value, ["columns", "rows"]) &&
    isTerminalSize(value.columns, value.rows)
  );
}

export function isTerminalClosed(value: unknown): value is TerminalClosed {
  return isRecord(value) && hasExactKeys(value, ["closed"]) && value.closed === true;
}

function isTerminalColor(value: unknown): value is TerminalColor {
  if (!isRecord(value)) return false;
  switch (value.kind) {
    case "named":
      return (
        hasExactKeys(value, ["kind", "name"]) &&
        isUtf8(value.name, 64, false) &&
        NAMED_COLOR_PATTERN.test(value.name)
      );
    case "indexed":
      return hasExactKeys(value, ["kind", "index"]) && isSafeInteger(value.index, 0, 255);
    case "rgb":
      return (
        hasExactKeys(value, ["kind", "red", "green", "blue"]) &&
        isSafeInteger(value.red, 0, 255) &&
        isSafeInteger(value.green, 0, 255) &&
        isSafeInteger(value.blue, 0, 255)
      );
    default:
      return false;
  }
}

function isTerminalRenderCell(
  value: unknown,
  expectedRow: number,
  expectedColumn: number,
): value is TerminalRenderCell {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      "row", "column", "text", "width", "foreground", "background", "bold", "dim",
      "italic", "underline", "strikeout", "inverse", "hidden", "selected",
    ]) &&
    value.row === expectedRow &&
    value.column === expectedColumn &&
    isUtf8(value.text, TERMINAL_LIMITS.maximumCellTextBytes, false) &&
    isSafeInteger(value.width, 0, 2) &&
    isTerminalColor(value.foreground) &&
    isTerminalColor(value.background) &&
    [
      value.bold, value.dim, value.italic, value.underline, value.strikeout,
      value.inverse, value.hidden, value.selected,
    ].every((flag) => typeof flag === "boolean")
  );
}

function isTerminalRenderCursor(
  value: unknown,
  columns: number,
  rows: number,
): value is TerminalRenderCursor {
  return (
    isRecord(value) &&
    hasExactKeys(value, ["row", "column", "shape"]) &&
    isSafeInteger(value.row, 0, rows - 1) &&
    isSafeInteger(value.column, 0, columns - 1) &&
    ["block", "underline", "beam", "hollow-block"].includes(String(value.shape))
  );
}

export function isTerminalRenderSnapshot(value: unknown): value is TerminalRenderSnapshot {
  if (!isRecord(value)) return false;
  const { columns, rows } = value;
  if (
    !hasExactKeys(value, [
      "columns", "rows", "cells", "cursor", "displayOffset", "alternateScreen",
      "totalOutputBytes",
    ]) ||
    !isSafeInteger(columns, 1, TERMINAL_LIMITS.maximumColumns) ||
    !isSafeInteger(rows, 1, TERMINAL_LIMITS.maximumRows) ||
    !Array.isArray(value.cells) ||
    value.cells.length !== rows ||
    !isSafeInteger(value.displayOffset, 0, TERMINAL_LIMITS.maximumScrollbackLines) ||
    typeof value.alternateScreen !== "boolean" ||
    !isSafeInteger(value.totalOutputBytes, 0, TERMINAL_LIMITS.maximumTotalOutputBytes) ||
    (value.cursor !== null && !isTerminalRenderCursor(value.cursor, columns, rows))
  ) return false;

  for (let row = 0; row < value.cells.length; row += 1) {
    const cells = value.cells[row];
    if (!Array.isArray(cells) || cells.length !== columns) return false;
    for (let column = 0; column < cells.length; column += 1) {
      if (!isTerminalRenderCell(cells[column], row, column)) return false;
    }
  }
  const bytes = serializedBytes(value);
  return bytes !== null && bytes <= TERMINAL_LIMITS.maximumSnapshotBytes;
}

export function isTerminalSearch(value: unknown): value is TerminalSearch {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["matches", "limited"]) ||
    !Array.isArray(value.matches) ||
    value.matches.length > TERMINAL_LIMITS.maximumSearchResults ||
    typeof value.limited !== "boolean"
  ) return false;
  for (const match of value.matches) {
    if (
      !isRecord(match) ||
      !hasExactKeys(match, ["line", "startColumn", "endColumn", "text"]) ||
      !isSafeInteger(match.line, -2_147_483_648, 2_147_483_647) ||
      !isSafeInteger(match.startColumn, 0, TERMINAL_LIMITS.maximumColumns) ||
      !isSafeInteger(match.endColumn, match.startColumn, TERMINAL_LIMITS.maximumColumns) ||
      !isUtf8(match.text, TERMINAL_LIMITS.maximumSearchMatchBytes)
    ) return false;
  }
  const bytes = serializedBytes(value);
  return bytes !== null && bytes <= TERMINAL_LIMITS.maximumSearchResponseBytes;
}
