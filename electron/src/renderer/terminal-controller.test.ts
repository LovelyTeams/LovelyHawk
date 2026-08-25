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
  openLocalBrowser: vi.fn(async () => ({})),
  listLocalDirectory: vi.fn(async () => ({})),
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
