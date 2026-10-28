import { invoke } from "@tauri-apps/api/core";

import { operatorErrorMessage } from "./error-messages";

/**
 * How a page reaches the desktop host.
 *
 * Every call is a Tauri command. The host resolves the calling window, applies
 * its own allowlist, and answers with a value or a sentence; a timeout here
 * only stops waiting — the host finishes whatever it started, the same way a
 * separate backend process kept working after a renderer gave up.
 */
export interface BackendTransport {
  call(method: string, params: object, timeoutMs: number): Promise<unknown>;
}

const encoder = new TextEncoder();

export function utf8ByteLength(value: string): number {
  return encoder.encode(value).byteLength;
}

/**
 * The host answers a failure with a sentence; give pages a real Error, in the
 * operator's words when the sentence carries a known backend code.
 */
export function hostError(reason: unknown): Error {
  if (reason instanceof Error) {
    const message = operatorErrorMessage(reason.message);
    return message === reason.message ? reason : new Error(message);
  }
  if (typeof reason === "string" && reason.trim().length > 0) return new Error(operatorErrorMessage(reason));
  return new Error("LovelyHawk 没有返回可读的错误信息。");
}

export function withTimeout<T>(work: Promise<T>, timeoutMs: number, message: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const expired = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(message)), timeoutMs);
  });
  return Promise.race([work, expired]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
  });
}

export type HostInvoker = (command: string, args: Record<string, unknown>) => Promise<unknown>;

let invoker: HostInvoker = (command, args) => invoke(command, args);

/** Tests replace the Tauri bridge; nothing else should. */
export function setHostInvokerForTests(next: HostInvoker): void {
  invoker = next;
}

export async function invokeHost(
  command: string,
  args: Record<string, unknown>,
  timeoutMs: number,
): Promise<unknown> {
  try {
    return await withTimeout(invoker(command, args), timeoutMs, "The backend request timed out.");
  } catch (reason) {
    throw hostError(reason);
  }
}

export const hostBackendTransport: BackendTransport = {
  call: (method, params, timeoutMs) => invokeHost("backend_call", { method, params }, timeoutMs),
};
