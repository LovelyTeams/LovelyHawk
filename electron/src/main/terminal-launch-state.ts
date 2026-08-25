import type { SshAttemptStatus } from "../shared/ssh-contract.js";

export type TerminalBindingTransition =
  | { kind: "unchanged" }
  | { kind: "accepted"; bindingHandle: string; previousBindingHandle: string | null }
  | { kind: "stale" };

export class TerminalBindingLaunchState {
  #pendingAttemptHandle: string | null = null;
  #acceptedAttemptHandle: string | null = null;
  #activeBindingHandle: string | null = null;

  startConnect(attemptHandle: string): void {
    this.#pendingAttemptHandle = attemptHandle;
  }

  cancelAttempt(attemptHandle: string): void {
    if (this.#pendingAttemptHandle === attemptHandle) this.#pendingAttemptHandle = null;
  }

  observe(attemptHandle: string, status: SshAttemptStatus): TerminalBindingTransition {
    if (status.stage === "connected") {
      if (
        attemptHandle === this.#acceptedAttemptHandle &&
        status.bindingHandle === this.#activeBindingHandle
      ) {
        return { kind: "unchanged" };
      }
      if (attemptHandle !== this.#pendingAttemptHandle) return { kind: "stale" };
      const previousBindingHandle = this.#activeBindingHandle;
      this.#pendingAttemptHandle = null;
      this.#acceptedAttemptHandle = attemptHandle;
      this.#activeBindingHandle = status.bindingHandle;
      return { kind: "accepted", bindingHandle: status.bindingHandle, previousBindingHandle };
    }
    if (
      (status.stage === "failed" || status.stage === "cancelled") &&
      attemptHandle === this.#pendingAttemptHandle
    ) {
      this.#pendingAttemptHandle = null;
    }
    return { kind: "unchanged" };
  }

  disconnect(bindingHandle: string): boolean {
    if (bindingHandle !== this.#activeBindingHandle) return false;
    this.#activeBindingHandle = null;
    this.#acceptedAttemptHandle = null;
    return true;
  }

  currentBindingHandle(): string | null {
    return this.#activeBindingHandle;
  }
}
