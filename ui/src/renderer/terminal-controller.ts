import { errorText } from "./error-text";
import { isTargetLost } from "./target-lost";
import {
  isTerminalClosed,
  isTerminalInputAcknowledgement,
  isTerminalPoll,
  isTerminalResized,
  isTerminalSearch,
  isTerminalSearchRequest,
  isTerminalSize,
  isTerminalWindowOpened,
  terminalBase64DecodedLength,
  TERMINAL_LIMITS,
  type TerminalApi,
  type TerminalPollEvent,
  type TerminalSearch,
  type TerminalSize,
} from "../shared/terminal-contract";

export const TERMINAL_ERROR_MESSAGES = Object.freeze({
  open: "无法打开当前目标的终端。",
  // A folder window's own sentence for the same thing, so a failure with no
  // more detail can be described in terms of the folder.
  openFolder: "无法在这个文件夹里打开终端。",
  // The target dropped off: switched off, rebooted, network gone, sshd
  // stopped. Said once, the same way whether it happened before the shell
  // opened or in the middle of a session, and with the one thing to do next.
  connectionLost: "与目标主机的连接已断开。目标机可能已关机或重启、网络中断，或 SSH 服务停止了。请在主窗口重新连接，再打开新的终端。",
  openFailed: "没能打开终端。可能是连接出了问题，也可能是目标机拒绝了这次操作；详细原因见应用日志。",
  protocol: "终端响应格式异常，没有采用。",
  input: "终端输入发送失败。",
  inputCapacity: "终端输入队列已达到安全上限。",
  poll: "终端输出读取失败。",
  resize: "终端尺寸同步失败。",
  search: "终端搜索失败。",
  // Two refusals an operator can actually do something about. They used to
  // arrive as "search failed" and "output read failed" — the first told nobody
  // to narrow anything, and the second read like a hiccup worth retrying when
  // in fact this session had produced every byte it is ever allowed to.
  searchTooBroad: "匹配到的内容太多了，缩小关键词或加上大小写/正则条件再搜。",
  outputExhausted: "这个终端会话的输出量已经用满，不会再收新内容了。开一个新的终端继续。",
  // The transport carries no reason, so both likely ones are named — and the
  // likelier, a target that dropped off, comes first.
  remoteFailure: "终端已停止：与目标主机的连接中断了，或目标机结束了这个会话。请在主窗口确认连接后再开一个新的终端。",
  // A terminal started in a folder: the window stays open to say why it could not.
  tooManyTerminals: "这台主机上打开的终端已经太多（最多 4 个）。关掉一个再试。",
  folderGone: "这个文件夹的入口已经过期。回到 SSH 终端窗口的文件管理刷新一下，再从那里打开。",
  folderUnusable: "没能在这个文件夹里打开终端。文件夹可能已被删除或不再是文件夹，也可能是连接出了问题；详细原因见应用日志。",
} as const);

/** Picks the sentence for a refusal the sidecar named, or the caller's own. */
export function terminalFailureMessage(reason: unknown, fallback: string): string {
  const text = reason instanceof Error ? reason.message : "";
  // Before anything else: when the target is gone, every other reading of the
  // failure is a guess about something that is not the problem.
  if (isTargetLost(reason)) return TERMINAL_ERROR_MESSAGES.connectionLost;
  if (text.includes("terminal-search-limit")) return TERMINAL_ERROR_MESSAGES.searchTooBroad;
  if (text.includes("terminal-output-limit")) return TERMINAL_ERROR_MESSAGES.outputExhausted;
  if (text.includes("(terminal-capacity)")) return TERMINAL_ERROR_MESSAGES.tooManyTerminals;
  if (text.includes("(sftp-browser-unavailable)")) return TERMINAL_ERROR_MESSAGES.folderGone;
  // A pod shell that did not open: the backend's own sentence says which of
  // its reasons it was (no exec permission, no shell, pod replaced or gone,
  // container not running), and each wants a different next step.
  if (/\((?:kubernetes-pod-[a-z-]+|kubernetes-forbidden)\)\s*$/u.test(text)) {
    return errorText(reason, fallback);
  }
  if (text.includes("(terminal-operation-failed)")) {
    if (fallback === TERMINAL_ERROR_MESSAGES.openFolder) return TERMINAL_ERROR_MESSAGES.folderUnusable;
    if (fallback === TERMINAL_ERROR_MESSAGES.open) return TERMINAL_ERROR_MESSAGES.openFailed;
  }
  return fallback;
}

export interface TerminalOutputSink {
  write(bytes: Uint8Array): void | Promise<void>;
  titleChanged(title: string): void;
  bell(): void;
  exited(exitCode: number | null): void;
  closed(): void;
}

export interface TerminalControllerOptions {
  isScopeCurrent(): boolean;
  onError(message: string): void;
  wait?: (milliseconds: number) => Promise<void>;
  /** The window's own "could not open" sentence; a folder window names the folder. */
  openFailure?: string;
}

type QueueSender = (bytes: Uint8Array) => Promise<void>;

export class BoundedSerialInputQueue {
  private readonly pending: Uint8Array[] = [];
  private readonly drainWaiters: Array<() => void> = [];
  private bufferedBytes = 0;
  private pumping = false;
  private accepting = true;

  constructor(
    private readonly sender: QueueSender,
    private readonly onFault: () => void,
    private readonly maximumBufferedBytes = TERMINAL_LIMITS.maximumQueuedInputBytes,
  ) {}

  enqueue(bytes: Uint8Array): boolean {
    if (
      !this.accepting ||
      bytes.byteLength === 0 ||
      bytes.byteLength > this.maximumBufferedBytes ||
      this.bufferedBytes + bytes.byteLength > this.maximumBufferedBytes
    ) return false;

    for (let offset = 0; offset < bytes.byteLength; offset += TERMINAL_LIMITS.maximumInputBytes) {
      this.pending.push(bytes.slice(offset, offset + TERMINAL_LIMITS.maximumInputBytes));
    }
    this.bufferedBytes += bytes.byteLength;
    this.startPump();
    return true;
  }

  stop(): void {
    this.accepting = false;
  }

  async flush(): Promise<void> {
    if (!this.pumping && this.pending.length === 0) return;
    await new Promise<void>((resolve) => this.drainWaiters.push(resolve));
  }

  get pendingBytes(): number {
    return this.bufferedBytes;
  }

  private startPump(): void {
    if (this.pumping) return;
    this.pumping = true;
    void this.pump();
  }

  private async pump(): Promise<void> {
    try {
      while (this.pending.length > 0) {
        const bytes = this.pending.shift();
        if (bytes === undefined) break;
        await this.sender(bytes);
        this.bufferedBytes -= bytes.byteLength;
      }
    } catch {
      this.accepting = false;
      this.pending.length = 0;
      this.bufferedBytes = 0;
      this.onFault();
    } finally {
      this.pumping = false;
      if (this.pending.length > 0 && this.accepting) {
        this.startPump();
      } else {
        for (const resolve of this.drainWaiters.splice(0)) resolve();
      }
    }
  }
}

export function terminalTextBytes(value: string): Uint8Array | null {
  if (value.length === 0 || value.length > TERMINAL_LIMITS.maximumQueuedInputBytes) return null;
  const bytes = new TextEncoder().encode(value);
  return bytes.byteLength <= TERMINAL_LIMITS.maximumQueuedInputBytes ? bytes : null;
}

export function encodeTerminalBase64(bytes: Uint8Array): string | null {
  if (bytes.byteLength === 0 || bytes.byteLength > TERMINAL_LIMITS.maximumInputBytes) return null;
  let binary = "";
  for (let offset = 0; offset < bytes.byteLength; offset += 16_384) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 16_384));
  }
  try {
    return btoa(binary);
  } catch {
    return null;
  }
}

export function decodeTerminalBase64(value: string): Uint8Array | null {
  const length = terminalBase64DecodedLength(
    value,
    TERMINAL_LIMITS.maximumOutputEventBytes,
    true,
  );
  if (length === null) return null;
  try {
    const binary = atob(value);
    if (binary.length !== length) return null;
    const bytes = new Uint8Array(length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  } catch {
    return null;
  }
}

const defaultWait = (milliseconds: number) => new Promise<void>((resolve) => {
  window.setTimeout(resolve, milliseconds);
});

export class TerminalController {
  private opened = false;
  private expectedSequence = 1;
  private disposed = false;
  private failed = false;
  private closePromise: Promise<void> | null = null;
  private pollPromise: Promise<void> | null = null;
  private pendingResize: TerminalSize | null = null;
  private resizePromise: Promise<void> | null = null;
  private readonly wait: (milliseconds: number) => Promise<void>;
  private readonly inputQueue: BoundedSerialInputQueue;

  constructor(
    private readonly api: TerminalApi,
    private readonly sink: TerminalOutputSink,
    private readonly options: TerminalControllerOptions,
  ) {
    this.wait = options.wait ?? defaultWait;
    this.inputQueue = new BoundedSerialInputQueue(
      async (bytes) => this.sendInput(bytes),
      () => this.fail(TERMINAL_ERROR_MESSAGES.input),
    );
  }

  async open(columns: number, rows: number): Promise<boolean> {
    if (
      this.disposed ||
      this.opened ||
      !this.scopeIsCurrent() ||
      !isTerminalSize(columns, rows)
    ) {
      this.report(TERMINAL_ERROR_MESSAGES.open);
      return false;
    }

    let result: unknown;
    try {
      result = await this.api.open(columns, rows);
    } catch (reason) {
      if (!this.disposed) {
        this.report(terminalFailureMessage(reason, this.options.openFailure ?? TERMINAL_ERROR_MESSAGES.open));
      }
      return false;
    }
    if (!isTerminalWindowOpened(result) || result.columns !== columns || result.rows !== rows) {
      if (!this.disposed) this.report(TERMINAL_ERROR_MESSAGES.protocol);
      return false;
    }
    if (this.disposed || !this.scopeIsCurrent()) {
      await this.closeDetachedSession();
      return false;
    }

    this.opened = true;
    this.pollPromise = this.pollLoop();
    return true;
  }

  enqueueText(value: string): boolean {
    if (this.disposed || this.failed || !this.opened || !this.scopeIsCurrent()) return false;
    const bytes = terminalTextBytes(value);
    if (bytes === null || !this.inputQueue.enqueue(bytes)) {
      this.fail(TERMINAL_ERROR_MESSAGES.inputCapacity);
      return false;
    }
    return true;
  }

  resize(columns: number, rows: number): void {
    if (
      this.disposed ||
      this.failed ||
      !this.opened ||
      !this.scopeIsCurrent() ||
      !isTerminalSize(columns, rows)
    ) return;
    this.pendingResize = { columns, rows };
    if (this.resizePromise === null) {
      this.resizePromise = this.drainResize().finally(() => {
        this.resizePromise = null;
        if (this.pendingResize !== null && !this.disposed && !this.failed) this.resize(
          this.pendingResize.columns,
          this.pendingResize.rows,
        );
      });
    }
  }

  async search(
    query: string,
    caseSensitive: boolean,
    regex: boolean,
    maximumResults: number = TERMINAL_LIMITS.maximumSearchResults,
  ): Promise<TerminalSearch | null> {
    if (
      !this.opened ||
      this.disposed ||
      this.failed ||
      !this.scopeIsCurrent() ||
      !isTerminalSearchRequest(query, maximumResults)
    ) return null;
    try {
      const result = await this.api.search(
        query,
        caseSensitive,
        regex,
        maximumResults,
      );
      if (!this.isCurrentSession()) return null;
      if (!isTerminalSearch(result)) {
        this.fail(TERMINAL_ERROR_MESSAGES.protocol);
        return null;
      }
      return result;
    } catch (reason: unknown) {
      if (this.isCurrentSession()) {
        this.report(terminalFailureMessage(reason, TERMINAL_ERROR_MESSAGES.search));
      }
      return null;
    }
  }

  async dispose(): Promise<void> {
    if (!this.disposed) {
      this.disposed = true;
      this.inputQueue.stop();
    }
    if (this.opened) await this.closeSession();
  }

  async whenPollingStops(): Promise<void> {
    await this.pollPromise;
  }

  private async sendInput(bytes: Uint8Array): Promise<void> {
    const encoded = encodeTerminalBase64(bytes);
    if (encoded === null || !this.isCurrentSession()) throw new Error();
    const result = await this.api.input(encoded);
    if (
      !this.isCurrentSession() ||
      !isTerminalInputAcknowledgement(result) ||
      result.acceptedBytes !== bytes.byteLength
    ) throw new Error();
  }

  private async pollLoop(): Promise<void> {
    while (this.isCurrentSession()) {
      let result: unknown;
      try {
        result = await this.api.poll(
          TERMINAL_LIMITS.maximumPollEvents,
          TERMINAL_LIMITS.maximumPollBytes,
        );
      } catch (reason: unknown) {
        if (this.isCurrentSession()) {
          this.fail(terminalFailureMessage(reason, TERMINAL_ERROR_MESSAGES.poll));
        }
        return;
      }
      if (!this.isCurrentSession()) {
        if (this.opened) await this.closeSession();
        return;
      }
      if (!isTerminalPoll(result)) {
        this.fail(TERMINAL_ERROR_MESSAGES.protocol);
        return;
      }

      for (const event of result.events) {
        if (!this.isCurrentSession() || event.sequence !== this.expectedSequence) {
          this.fail(TERMINAL_ERROR_MESSAGES.protocol);
          return;
        }
        this.expectedSequence += 1;
        if (!await this.applyEvent(event)) return;
      }
      if (!result.hasMore && result.events.length === 0) await this.wait(25);
    }
  }

  private async applyEvent(event: TerminalPollEvent): Promise<boolean> {
    switch (event.kind) {
      case "output": {
        const bytes = decodeTerminalBase64(event.bytes_base64);
        if (bytes === null) {
          this.fail(TERMINAL_ERROR_MESSAGES.protocol);
          return false;
        }
        try {
          await this.sink.write(bytes);
        } catch {
          this.fail(TERMINAL_ERROR_MESSAGES.protocol);
          return false;
        }
        return this.isCurrentSession();
      }
      case "title-changed":
        this.sink.titleChanged(event.title);
        return this.isCurrentSession();
      case "bell":
        this.sink.bell();
        return this.isCurrentSession();
      case "exited":
        this.sink.exited(event.exit_code);
        await this.stop();
        return false;
      case "failed":
        this.sink.closed();
        this.fail(TERMINAL_ERROR_MESSAGES.remoteFailure);
        return false;
      case "closed":
        this.sink.closed();
        await this.stop();
        return false;
    }
  }

  private async drainResize(): Promise<void> {
    while (this.pendingResize !== null) {
      const size = this.pendingResize;
      this.pendingResize = null;
      if (!this.isCurrentSession()) return;
      try {
        const result = await this.api.resize(size.columns, size.rows);
        if (!this.isCurrentSession()) return;
        if (
          !isTerminalResized(result) ||
          result.columns !== size.columns ||
          result.rows !== size.rows
        ) {
          this.fail(TERMINAL_ERROR_MESSAGES.protocol);
          return;
        }
      } catch {
        if (this.isCurrentSession()) this.fail(TERMINAL_ERROR_MESSAGES.resize);
        return;
      }
    }
  }

  /** True once the session was stopped for good after an error. */
  get stopped(): boolean {
    return this.failed;
  }

  private fail(message: string): void {
    if (this.failed || this.disposed) return;
    this.failed = true;
    this.inputQueue.stop();
    this.report(message);
    if (this.opened) void this.closeSession();
  }

  private report(message: string): void {
    if (!this.disposed) this.options.onError(message);
  }

  private scopeIsCurrent(): boolean {
    return !this.disposed && this.options.isScopeCurrent();
  }

  private isCurrentSession(): boolean {
    return this.opened && !this.failed && this.scopeIsCurrent();
  }

  private async stop(): Promise<void> {
    if (!this.opened) return;
    this.disposed = true;
    this.inputQueue.stop();
    await this.closeSession();
  }

  private closeSession(): Promise<void> {
    if (this.closePromise !== null) return this.closePromise;
    this.opened = false;
    this.closePromise = this.closeDetachedSession();
    return this.closePromise;
  }

  private async closeDetachedSession(): Promise<void> {
    try {
      const result = await this.api.close();
      if (!isTerminalClosed(result) && !this.disposed) this.report(TERMINAL_ERROR_MESSAGES.protocol);
    } catch {
      // Closing is best-effort at this renderer boundary; errors never echo backend text.
    }
  }
}
