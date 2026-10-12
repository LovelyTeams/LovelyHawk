import { listen } from "@tauri-apps/api/event";

import { isLocalBrowserOpaqueHandle, isLocalDirectorySnapshot } from "../shared/local-browser-contract.js";
import {
  isSftpBrowserOpaqueHandle,
  isSftpDirectorySnapshot,
  isSftpOperationInput,
  isSftpOperationPlan,
  isSftpOperationReceipt,
  isSftpOperationUndoResult,
  isSftpTransferCancelResult,
  isSftpStagedUpload,
  isSftpTextPreview,
} from "../shared/sftp-browser-contract.js";
import {
  isFileEditorTarget,
  isTerminalClosed,
  isTerminalInputAcknowledgement,
  isTerminalPoll,
  isTerminalPollBounds,
  isTerminalResized,
  isTerminalSearch,
  isTerminalSearchRequest,
  isTerminalSelectionCopyText,
  isTerminalSize,
  isTerminalWindowLaunchResult,
  isTerminalWindowOpened,
  terminalBase64DecodedLength,
  TERMINAL_LIMITS,
  type TerminalApi,
} from "../shared/terminal-contract.js";
import { invokeHost } from "./transport.js";

const TERMINAL_TIMEOUT_MS = 15_000;
/** The same event the main window's close question uses. */
const BEFORE_CLOSE_EVENT = "lovelyhawk://before-close";
const SFTP_BROWSER_TIMEOUT_MS = 30_000;
const SFTP_OPERATION_TIMEOUT_MS = 100_000;
/** A dialog stays open as long as the operator needs; the transfer bound follows it. */
const DIALOG_TIMEOUT_MS = 60 * 60 * 1_000;

function refuse(message: string): never {
  throw new Error(message);
}

function requireArity(values: unknown[], count: number, message: string): void {
  if (values.length !== count) refuse(message);
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function checked<T>(
  command: string,
  args: Record<string, unknown>,
  timeoutMs: number,
  accept: (value: unknown) => boolean,
  message: string,
): Promise<T> {
  const value = await invokeHost(command, args, timeoutMs);
  if (!accept(value)) refuse(message);
  return value as T;
}

/**
 * The API a terminal, container-terminal or file-editor window gets.
 *
 * None of these calls names a target: the host resolves the binding, the
 * container and the file from what it recorded when it created this window.
 */
export function createTerminalApi(): TerminalApi {
  const api: TerminalApi = {
    open: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid terminal open request.");
      const [columns, rows] = values;
      if (!isTerminalSize(columns, rows)) refuse("Invalid terminal open request.");
      return checked("terminal_open", { columns, rows }, 60_000,
        (value) => isTerminalWindowOpened(value) && value.columns === columns && value.rows === rows,
        "The terminal open response is invalid.");
    },
    poll: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid terminal poll request.");
      const [maximumEvents, maximumBytes] = values;
      if (!isTerminalPollBounds(maximumEvents, maximumBytes)) refuse("Invalid terminal poll request.");
      return checked("terminal_poll", { maximumEvents, maximumBytes }, TERMINAL_TIMEOUT_MS, isTerminalPoll,
        "The terminal poll response is invalid.");
    },
    input: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid terminal input request.");
      const bytesBase64 = values[0];
      const decoded = terminalBase64DecodedLength(bytesBase64, TERMINAL_LIMITS.maximumInputBytes, false);
      if (decoded === null) refuse("Invalid terminal input request.");
      return checked("terminal_input", { bytesBase64 }, TERMINAL_TIMEOUT_MS,
        (value) => isTerminalInputAcknowledgement(value) && value.acceptedBytes === decoded,
        "The terminal input response is invalid.");
    },
    resize: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid terminal resize request.");
      const [columns, rows] = values;
      if (!isTerminalSize(columns, rows)) refuse("Invalid terminal resize request.");
      return checked("terminal_resize", { columns, rows }, TERMINAL_TIMEOUT_MS,
        (value) => isTerminalResized(value) && value.columns === columns && value.rows === rows,
        "The terminal resize response is invalid.");
    },
    search: async (...values: unknown[]) => {
      requireArity(values, 4, "Invalid terminal search request.");
      const [query, caseSensitive, regex, maximumResults] = values;
      if (!isTerminalSearchRequest(query, maximumResults) || typeof caseSensitive !== "boolean" ||
        typeof regex !== "boolean") {
        refuse("Invalid terminal search request.");
      }
      return checked("terminal_search", { query, caseSensitive, regex, maximumResults }, TERMINAL_TIMEOUT_MS,
        isTerminalSearch, "The terminal search response is invalid.");
    },
    copySelection: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid terminal selection copy request.");
      if (!isTerminalSelectionCopyText(values[0])) refuse("Invalid terminal selection copy request.");
      await invokeHost("terminal_copy_selection", { text: values[0] }, TERMINAL_TIMEOUT_MS);
    },
    close: async (...values: unknown[]) => {
      requireArity(values, 0, "Invalid terminal close request.");
      return checked("terminal_close", {}, TERMINAL_TIMEOUT_MS, isTerminalClosed, "The terminal close response is invalid.");
    },
    openSftpBrowser: async (...values: unknown[]) => {
      requireArity(values, 0, "Invalid SFTP browser request.");
      return checked("sftp_open", {}, SFTP_BROWSER_TIMEOUT_MS, isSftpDirectorySnapshot, "The SFTP directory is invalid.");
    },
    listSftpDirectory: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid SFTP directory request.");
      const [browserHandle, directoryHandle] = values;
      if (!isSftpBrowserOpaqueHandle(browserHandle) || !isSftpBrowserOpaqueHandle(directoryHandle)) {
        refuse("Invalid SFTP directory request.");
      }
      return checked("sftp_list", { browserHandle, directoryHandle }, SFTP_BROWSER_TIMEOUT_MS,
        (value) => isSftpDirectorySnapshot(value) && value.browserHandle === browserHandle &&
          value.directoryHandle === directoryHandle,
        "The SFTP directory is invalid.");
    },
    readSftpText: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid SFTP preview request.");
      const [browserHandle, fileHandle] = values;
      if (!isSftpBrowserOpaqueHandle(browserHandle) || !isSftpBrowserOpaqueHandle(fileHandle)) {
        refuse("Invalid SFTP preview request.");
      }
      return checked("sftp_read_text", { browserHandle, fileHandle }, SFTP_BROWSER_TIMEOUT_MS,
        (value) => isSftpTextPreview(value) && value.browserHandle === browserHandle && value.fileHandle === fileHandle,
        "The SFTP preview is invalid.");
    },
    downloadSftpEntry: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid SFTP download request.");
      const [browserHandle, fileHandle] = values;
      if (!isSftpBrowserOpaqueHandle(browserHandle) || !isSftpBrowserOpaqueHandle(fileHandle)) {
        refuse("Invalid SFTP download request.");
      }
      return checked("sftp_download", { browserHandle, fileHandle }, DIALOG_TIMEOUT_MS,
        (value) => record(value) && Object.keys(value).length === 3 && typeof value.saved === "boolean" &&
          (value.saved
            ? typeof value.fileName === "string" && typeof value.bytes === "string"
            : value.fileName === null && value.bytes === null),
        "The SFTP transfer result is invalid.");
    },
    planSftpOperation: async (...values: unknown[]) => {
      requireArity(values, 2, "Invalid SFTP operation request.");
      const [browserHandle, input] = values;
      if (!isSftpBrowserOpaqueHandle(browserHandle) || !isSftpOperationInput(input)) {
        refuse("Invalid SFTP operation request.");
      }
      return checked("sftp_plan", { browserHandle, input }, SFTP_BROWSER_TIMEOUT_MS,
        (value) => isSftpOperationPlan(value) && value.browserHandle === browserHandle && value.kind === input.kind,
        "The SFTP operation plan is invalid.");
    },
    confirmSftpOperation: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid SFTP confirmation request.");
      const planHandle = values[0];
      if (!isSftpBrowserOpaqueHandle(planHandle)) refuse("Invalid SFTP confirmation request.");
      return checked("sftp_confirm", { planHandle }, SFTP_BROWSER_TIMEOUT_MS,
        (value) => isSftpOperationPlan(value) && value.planHandle === planHandle && value.state === "confirmed",
        "The SFTP operation plan is invalid.");
    },
    executeSftpOperation: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid SFTP execution request.");
      const planHandle = values[0];
      if (!isSftpBrowserOpaqueHandle(planHandle)) refuse("Invalid SFTP execution request.");
      return checked("sftp_execute", { planHandle }, SFTP_OPERATION_TIMEOUT_MS,
        (value) => isSftpOperationReceipt(value) && value.planHandle === planHandle,
        "The SFTP operation receipt is invalid.");
    },
    cancelSftpOperation: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid SFTP cancellation request.");
      if (!isSftpBrowserOpaqueHandle(values[0])) refuse("Invalid SFTP cancellation request.");
      return checked("sftp_cancel", { planHandle: values[0] }, SFTP_BROWSER_TIMEOUT_MS,
        (value) => record(value) && value.cancelled === true, "The SFTP cancellation is invalid.");
    },
    cancelSftpTransfer: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid SFTP transfer cancellation.");
      const browserHandle = values[0];
      if (!isSftpBrowserOpaqueHandle(browserHandle)) refuse("Invalid SFTP transfer cancellation.");
      return checked("sftp_cancel_transfer", { browserHandle }, SFTP_BROWSER_TIMEOUT_MS,
        isSftpTransferCancelResult, "The SFTP transfer cancellation is invalid.");
    },
    undoSftpOperation: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid SFTP undo request.");
      const planHandle = values[0];
      if (!isSftpBrowserOpaqueHandle(planHandle)) refuse("Invalid SFTP undo request.");
      return checked("sftp_undo", { planHandle }, SFTP_OPERATION_TIMEOUT_MS,
        (value) => isSftpOperationUndoResult(value) && value.planHandle === planHandle,
        "The SFTP undo result is invalid.");
    },
    stageSftpUpload: async (...values: unknown[]) => {
      if (values.length > 1) refuse("Invalid SFTP staging request.");
      const localFileHandle = values[0];
      if (localFileHandle !== undefined && !isLocalBrowserOpaqueHandle(localFileHandle)) {
        refuse("Invalid SFTP staging request.");
      }
      return checked("sftp_stage_upload", { localFileHandle: localFileHandle ?? null }, DIALOG_TIMEOUT_MS,
        (value) => record(value) && (value.staged === true
          ? isSftpStagedUpload(value.upload)
          : value.staged === false && value.upload === null),
        "The staged upload is invalid.");
    },
    openLocalBrowser: async (...values: unknown[]) => {
      requireArity(values, 0, "Invalid local browser request.");
      return checked("local_open", {}, TERMINAL_TIMEOUT_MS, isLocalDirectorySnapshot, "Invalid local directory listing.");
    },
    listLocalDirectory: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid local directory request.");
      if (!isLocalBrowserOpaqueHandle(values[0])) refuse("Invalid local directory request.");
      return checked("local_list", { directoryHandle: values[0] }, TERMINAL_TIMEOUT_MS, isLocalDirectorySnapshot,
        "Invalid local directory listing.");
    },
    openFileEditor: async (...values: unknown[]) => {
      requireArity(values, 4, "Invalid file editor launch request.");
      const [browserHandle, entryHandle, name, editable] = values;
      if (!isSftpBrowserOpaqueHandle(browserHandle) || !isSftpBrowserOpaqueHandle(entryHandle) ||
        typeof name !== "string" || name.length === 0 || name.length > 255 || typeof editable !== "boolean") {
        refuse("Invalid file editor launch request.");
      }
      return checked("file_editor_open", { browserHandle, entryHandle, name, editable }, TERMINAL_TIMEOUT_MS,
        isTerminalWindowLaunchResult, "The file editor launch result is invalid.");
    },
    openDirectoryTerminal: async (...values: unknown[]) => {
      requireArity(values, 3, "Invalid directory terminal request.");
      const [browserHandle, directoryHandle, name] = values;
      if (!isSftpBrowserOpaqueHandle(browserHandle) || !isSftpBrowserOpaqueHandle(directoryHandle) ||
        typeof name !== "string" || name.length === 0 || name.length > 255) {
        refuse("Invalid directory terminal request.");
      }
      return checked("directory_terminal_open", { browserHandle, directoryHandle, name }, TERMINAL_TIMEOUT_MS,
        isTerminalWindowLaunchResult, "The directory terminal launch result is invalid.");
    },
    fileEditorTarget: async (...values: unknown[]) => {
      requireArity(values, 0, "Invalid file editor target request.");
      return checked("file_editor_target", {}, TERMINAL_TIMEOUT_MS, isFileEditorTarget, "The file editor target is invalid.");
    },
    setUnsavedChanges: async (...values: unknown[]) => {
      requireArity(values, 1, "Invalid unsaved-changes report.");
      if (typeof values[0] !== "boolean") refuse("Invalid unsaved-changes report.");
      await invokeHost("file_editor_unsaved", { unsaved: values[0] }, TERMINAL_TIMEOUT_MS);
    },
    onBeforeClose: (handler: () => Promise<boolean>) => {
      if (typeof handler !== "function") refuse("Invalid close handler.");
      let disposed = false;
      let unlisten: (() => void) | null = null;
      void listen(BEFORE_CLOSE_EVENT, (event) => {
        // Numbered by the host, so a late answer cannot decide a newer close.
        const request = (event.payload as { request?: unknown } | null)?.request;
        if (typeof request !== "number" || !Number.isSafeInteger(request) || request < 1) return;
        void handler().then(
          (allowed) => invokeHost("child_close_decision", { request, allowed: allowed === true }, TERMINAL_TIMEOUT_MS),
          () => invokeHost("child_close_decision", { request, allowed: false }, TERMINAL_TIMEOUT_MS),
        ).catch(() => undefined);
      }).then((stop) => {
        if (disposed) stop();
        else unlisten = stop;
      }, () => undefined);
      return () => {
        disposed = true;
        unlisten?.();
      };
    },
  } as TerminalApi;
  return Object.freeze(api);
}
