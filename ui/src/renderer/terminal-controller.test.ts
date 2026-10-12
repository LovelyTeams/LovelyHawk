import { describe, expect, it, vi } from "vitest";

import type {
  TerminalApi,
  TerminalPoll,
  TerminalWindowOpened,
} from "../shared/terminal-contract";
import { TERMINAL_LIMITS } from "../shared/terminal-contract";
import {
  BoundedSerialInputQueue,
  decodeTerminalBase64,
  encodeTerminalBase64,
  TERMINAL_ERROR_MESSAGES,
  TerminalController,
  terminalFailureMessage,
  terminalTextBytes,
  type TerminalOutputSink,
} from "./terminal-controller";

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function createApi(overrides: Partial<TerminalApi> = {}): TerminalApi {
  return {
    open: vi.fn(async (columns, rows) => ({ columns, rows })),
  openSftpBrowser: vi.fn(async () => ({})),
  listSftpDirectory: vi.fn(async () => ({})),
  readSftpText: vi.fn(async () => ({})),
    downloadSftpEntry: vi.fn(async () => ({})),
    planSftpOperation: vi.fn(async () => ({})),
    confirmSftpOperation: vi.fn(async () => ({})),
    executeSftpOperation: vi.fn(async () => ({})),
    cancelSftpOperation: vi.fn(async () => ({})),
    undoSftpOperation: vi.fn(async () => ({})),
    cancelSftpTransfer: vi.fn(async () => ({ cancelled: 0 })),
    stageSftpUpload: vi.fn(async () => ({})),
  openLocalBrowser: vi.fn(async () => ({})),
  listLocalDirectory: vi.fn(async () => ({})),
  openFileEditor: vi.fn(async () => ({ opened: true, reused: false })),
  openDirectoryTerminal: vi.fn(async () => ({ opened: true, reused: false })),
  fileEditorTarget: vi.fn(async () => ({})),
  setUnsavedChanges: vi.fn(async () => undefined),
  onBeforeClose: vi.fn(() => () => undefined),
    poll: vi.fn(async (): Promise<TerminalPoll> => ({
      events: [{ kind: "closed" as const, sequence: 1 }],
      rawBytes: 0,
      hasMore: false,
    })),
    input: vi.fn(async (encoded) => ({ acceptedBytes: atob(encoded).length })),
    resize: vi.fn(async (columns, rows) => ({ columns, rows })),
    search: vi.fn(async () => ({ matches: [], limited: false })),
    copySelection: vi.fn(async () => undefined),
    close: vi.fn(async () => ({ closed: true as const })),
    ...overrides,
  };
}

function createSink() {
  return {
    write: vi.fn(async (_bytes: Uint8Array) => undefined),
    titleChanged: vi.fn((_title: string) => undefined),
    bell: vi.fn(() => undefined),
    exited: vi.fn((_exitCode: number | null) => undefined),
    closed: vi.fn(() => undefined),
  } satisfies TerminalOutputSink;
}

describe("terminal base64 and bounded input queue", () => {
  it("says what to do about the two refusals an operator can act on", () => {
    // These arrived as "search failed" and "output read failed". The first told
    // nobody to narrow anything; the second read like a hiccup worth retrying,
    // when in fact the session had produced every byte it is ever allowed to.
    const broad = terminalFailureMessage(new Error("terminal-search-limit"), "fallback");
    const spent = terminalFailureMessage(new Error("terminal-output-limit"), "fallback");
    expect(broad).toContain("缩小关键词");
    expect(spent).toContain("开一个新的终端");
    expect(broad).not.toBe(spent);
    // A snapshot that would not fit and a broken stream are the same thing to
    // the operator — open another terminal — so they keep the shared sentence.
    expect(terminalFailureMessage(new Error("terminal-protocol-invalid"), "fallback"))
      .toBe("fallback");
    expect(terminalFailureMessage(undefined, "fallback")).toBe("fallback");
    for (const text of [broad, spent]) expect(text).not.toMatch(/terminal-/u);
  });

  it("says why a pod shell did not open, in the backend's own words", () => {
    const open = TERMINAL_ERROR_MESSAGES.open;
    const forbidden = terminalFailureMessage(new Error(
      "当前账号没有在这个 Pod 里执行命令（pods/exec）的权限，终端和文件浏览都用不了。请换有权限的 kubeconfig 或账号。 (kubernetes-pod-exec-forbidden)",
    ), open);
    expect(forbidden).toContain("pods/exec");
    expect(forbidden).not.toContain("(kubernetes-");
    const refused = terminalFailureMessage(new Error("集群拒绝了当前账号的这次读取（权限不足）。 (kubernetes-forbidden)"), open);
    expect(refused).toContain("权限不足");
    // An English sentence or another code keeps the window's own sentence.
    expect(terminalFailureMessage(new Error("The pod is gone. (kubernetes-pod-not-running)"), open)).toBe(open);
    expect(terminalFailureMessage(new Error("无法连接 (ssh-unreachable)"), open)).toBe(open);
  });

  it("says why a folder terminal did not open, in the window that stays open to say it", () => {
    const open = TERMINAL_ERROR_MESSAGES.open;
    const crowded = terminalFailureMessage(new Error("打开的终端太多，请先关闭一些。 (terminal-capacity)"), open);
    const stale = terminalFailureMessage(new Error("这个目录或文件入口已过期，请刷新。 (sftp-browser-unavailable)"), open);
    const failed = terminalFailureMessage(new Error("终端操作没有完成，详细原因见应用日志。 (terminal-operation-failed)"), open);
    expect(crowded).toContain("最多 4 个");
    expect(stale).toContain("回到 SSH 终端窗口的文件管理刷新");
    // A failure with no more detail does not claim to know which cause it was.
    expect(failed).toContain("可能");
    expect(failed).toContain("应用日志");
    // The same code from anything but an open keeps the caller's sentence.
    expect(terminalFailureMessage(new Error("x (terminal-operation-failed)"), "fallback")).toBe("fallback");
    for (const text of [crowded, stale, failed]) expect(text).not.toMatch(/terminal-|sftp-|\(/u);
  });

  it("round-trips arbitrary bytes without Buffer or text coercion", () => {
    const bytes = new Uint8Array([0, 255, 10, 128]);
    const encoded = encodeTerminalBase64(bytes);
    expect(encoded).toBe("AP8KgA==");
    expect(decodeTerminalBase64(encoded ?? "")).toEqual(bytes);
    expect(decodeTerminalBase64("AB==")).toBeNull();
    expect(terminalTextBytes("A界")).toEqual(new Uint8Array([65, 231, 149, 140]));
  });

  it("serializes every accepted chunk and splits only at the backend hard limit", async () => {
    const firstRelease = deferred<void>();
    const sent: Uint8Array[] = [];
    let inFlight = 0;
    let maximumInFlight = 0;
    const queue = new BoundedSerialInputQueue(async (bytes) => {
      inFlight += 1;
      maximumInFlight = Math.max(maximumInFlight, inFlight);
      sent.push(bytes);
      if (sent.length === 1) await firstRelease.promise;
      inFlight -= 1;
    }, vi.fn());
    const source = new Uint8Array(TERMINAL_LIMITS.maximumInputBytes + 3);
    source[0] = 1;
    source[source.length - 1] = 2;

    expect(queue.enqueue(source)).toBe(true);
    await Promise.resolve();
    expect(sent).toHaveLength(1);
    expect(queue.pendingBytes).toBe(source.byteLength);
    firstRelease.resolve();
    await queue.flush();

    expect(sent.map((bytes) => bytes.byteLength)).toEqual([
      TERMINAL_LIMITS.maximumInputBytes,
      3,
    ]);
    expect(maximumInFlight).toBe(1);
    expect(queue.pendingBytes).toBe(0);
    expect(new Uint8Array([...sent[0]!, ...sent[1]!])).toEqual(source);
  });

  it("fails capacity atomically instead of silently dropping an accepted tail", async () => {
    const release = deferred<void>();
    const fault = vi.fn();
    const queue = new BoundedSerialInputQueue(async () => release.promise, fault, 4);
    expect(queue.enqueue(new Uint8Array([1, 2, 3, 4]))).toBe(true);
    expect(queue.enqueue(new Uint8Array([5]))).toBe(false);
    expect(queue.pendingBytes).toBe(4);
    release.resolve();
    await queue.flush();
    expect(fault).not.toHaveBeenCalled();
  });
});

describe("terminal polling lifecycle", () => {
  it("applies ordered output bytes and closes exactly once", async () => {
    const output = new TextEncoder().encode("</script>\u0000raw");
    const api = createApi({
      poll: vi.fn(async (): Promise<TerminalPoll> => ({
        events: [
          { kind: "output", sequence: 1, bytes_base64: btoa(String.fromCharCode(...output)) },
          { kind: "title-changed", sequence: 2, title: "<img src=x>", truncated: false },
          { kind: "closed", sequence: 3 },
        ],
        rawBytes: output.byteLength + new TextEncoder().encode("<img src=x>").byteLength,
        hasMore: false,
      })),
    });
    const sink = createSink();
    const errors: string[] = [];
    const controller = new TerminalController(api, sink, {
      isScopeCurrent: () => true,
      onError: (message) => errors.push(message),
      wait: async () => undefined,
    });

    expect(await controller.open(80, 24)).toBe(true);
    await controller.whenPollingStops();
    await controller.dispose();

    expect(sink.write).toHaveBeenCalledWith(output);
    expect(sink.titleChanged).toHaveBeenCalledWith("<img src=x>");
    expect(api.close).toHaveBeenCalledTimes(1);
    expect(errors).toEqual([]);
  });

  it("rejects a late scope before applying output and closes the main-owned session", async () => {
    const opening = deferred<TerminalWindowOpened>();
    let current = true;
    const api = createApi({ open: vi.fn(() => opening.promise) });
    const sink = createSink();
    const controller = new TerminalController(api, sink, {
      isScopeCurrent: () => current,
      onError: vi.fn(),
      wait: async () => undefined,
    });

    const result = controller.open(80, 24);
    current = false;
    opening.resolve({ columns: 80, rows: 24 });

    expect(await result).toBe(false);
    expect(api.poll).not.toHaveBeenCalled();
    expect(sink.write).not.toHaveBeenCalled();
    expect(api.close).toHaveBeenCalledWith();
  });

  it("rejects late poll output and closes without exposing it", async () => {
    const polling = deferred<TerminalPoll>();
    let current = true;
    const api = createApi({ poll: vi.fn(() => polling.promise) });
    const sink = createSink();
    const controller = new TerminalController(api, sink, {
      isScopeCurrent: () => current,
      onError: vi.fn(),
      wait: async () => undefined,
    });
    expect(await controller.open(80, 24)).toBe(true);
    current = false;
    polling.resolve({
      events: [{ kind: "output", sequence: 1, bytes_base64: "bGF0ZQ==" }],
      rawBytes: 4,
      hasMore: false,
    });
    await controller.whenPollingStops();

    expect(sink.write).not.toHaveBeenCalled();
    expect(api.close).toHaveBeenCalledWith();
  });

  it("uses fixed errors for hostile failures and protocol sequence gaps", async () => {
    const hostile = "</script><img src=x onerror=steal()>";
    const api = createApi({ poll: vi.fn(async () => { throw new Error(hostile); }) });
    const errors: string[] = [];
    const controller = new TerminalController(api, createSink(), {
      isScopeCurrent: () => true,
      onError: (message) => errors.push(message),
      wait: async () => undefined,
    });
    await controller.open(80, 24);
    await controller.whenPollingStops();
    expect(errors).toEqual([TERMINAL_ERROR_MESSAGES.poll]);
    expect(errors.join("")).not.toContain(hostile);
    expect(api.close).toHaveBeenCalledTimes(1);

    const gapApi = createApi({
      poll: vi.fn(async (): Promise<TerminalPoll> => ({
        events: [{ kind: "bell", sequence: 2 }],
        rawBytes: 0,
        hasMore: false,
      })),
    });
    const gapErrors: string[] = [];
    const gap = new TerminalController(gapApi, createSink(), {
      isScopeCurrent: () => true,
      onError: (message) => gapErrors.push(message),
      wait: async () => undefined,
    });
    await gap.open(80, 24);
    await gap.whenPollingStops();
    expect(gapErrors).toEqual([TERMINAL_ERROR_MESSAGES.protocol]);
  });

  it("matches the handle-free input, resize and search endpoint shapes", async () => {
    const polling = deferred<TerminalPoll>();
    const api = createApi({ poll: vi.fn(() => polling.promise) });
    const controller = new TerminalController(api, createSink(), {
      isScopeCurrent: () => true,
      onError: vi.fn(),
      wait: async () => undefined,
    });
    expect(await controller.open(80, 24)).toBe(true);
    expect(controller.enqueueText("A界")).toBe(true);
    controller.resize(90, 30);
    expect(await controller.search("needle", false, false, 5)).toEqual({
      matches: [],
      limited: false,
    });
    await vi.waitFor(() => {
      expect(api.input).toHaveBeenCalledWith("QeeVjA==");
      expect(api.resize).toHaveBeenCalledWith(90, 30);
    });
    expect(api.search).toHaveBeenCalledWith("needle", false, false, 5);
    await controller.dispose();
    expect(api.close).toHaveBeenCalledTimes(1);
  });

  it("unmount disposal invokes close while a poll is still pending", async () => {
    const polling = deferred<TerminalPoll>();
    const api = createApi({ poll: vi.fn(() => polling.promise) });
    const controller = new TerminalController(api, createSink(), {
      isScopeCurrent: () => true,
      onError: vi.fn(),
      wait: async () => undefined,
    });
    await controller.open(80, 24);
    await controller.dispose();
    expect(api.close).toHaveBeenCalledTimes(1);
    expect(api.close).toHaveBeenCalledWith();
  });
});
