/**
 * One evidence job that stages a file on the SSH host and collects it — a
 * packet capture, a pod file — for one connection.
 *
 * It owns its job: leaving the page or the connection disposes it, and a job
 * still running is cancelled so nothing goes on that no page shows. Every
 * answer is checked against a revision, so a late one never overwrites what
 * a newer request said.
 */
export interface EvidenceJobResult {
  jobHandle: string;
  /** What the job's own temporary file came to; "pending" while it may remain. */
  temporaryFile: string;
}

export interface EvidenceJobViewState<R> {
  phase: "ready" | "choosing" | "running" | "cancelling" | "interrupted" | "done";
  result: R | null;
  error: string | null;
  /** When the job was handed to the target, for an elapsed-time line. */
  startedAt: number | null;
}

/** How one kind of evidence job talks to the backend, and what it says. */
export interface EvidenceJobPolicy<R extends EvidenceJobResult, B> {
  /** Starts the job; null when the folder dialog was dismissed. */
  begin(binding: string, fields: B): Promise<R | null>;
  poll(binding: string, jobHandle: string): Promise<R | null>;
  cancel(binding: string, jobHandle: string): Promise<R | null>;
  running(result: R): boolean;
  /** Whether an update still describes the job on screen. */
  sameJob(previous: R, next: R): boolean;
  /** Said when an update describes another job, connection or folder. */
  changedMessage: string;
  /** Said when no progress could be read and the error had no words of its own. */
  unreachableMessage: string;
}

const POLL_MS = 1_000;
/** How long, in polls, to wait for the target's file to be reported gone. */
const REFRESH_ATTEMPTS = 30;

export class EvidenceJobController<R extends EvidenceJobResult, B> {
  private state: EvidenceJobViewState<R> = idle();
  private listeners = new Set<() => void>();
  private disposed = false;
  private busy = false;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private deadline = 0;
  private revision = 0;

  constructor(
    private policy: EvidenceJobPolicy<R, B>,
    private binding: string,
    private now: () => number = Date.now,
  ) {}

  getSnapshot = (): EvidenceJobViewState<R> => this.state;
  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => { this.listeners.delete(listener); };
  };

  private set(state: EvidenceJobViewState<R>): void {
    if (this.disposed) return;
    this.state = state;
    this.listeners.forEach((listener) => listener());
  }

  private abandon(result: R): void {
    if (this.policy.running(result)) void this.policy.cancel(this.binding, result.jobHandle).catch(() => undefined);
  }

  private accept(result: R): void {
    const previous = this.state.result;
    if (previous !== null && (result.jobHandle !== previous.jobHandle || !this.policy.sameJob(previous, result))) {
      this.abandon(result);
      throw new Error(this.policy.changedMessage);
    }
    const running = this.policy.running(result);
    this.set({ ...this.state, phase: running ? "running" : "done", result, error: null });
    if (running) this.schedule();
  }

  private schedule(): void {
    if (this.timer !== null) clearTimeout(this.timer);
    if (!this.disposed) this.timer = setTimeout(() => { this.timer = null; void this.poll(); }, POLL_MS);
  }

  /** Starts a job; past `deadlineMs` from now, polling cancels it. */
  protected start = async (fields: B, deadlineMs: number): Promise<void> => {
    if (this.disposed || this.busy || (this.state.phase !== "ready" && this.state.phase !== "done" &&
      this.state.phase !== "interrupted")) return;
    this.busy = true;
    const revision = ++this.revision;
    this.set({ ...idle(), phase: "choosing" });
    try {
      const result = await this.policy.begin(this.binding, fields);
      if (result === null) { if (revision === this.revision) this.set(idle()); return; }
      if (this.disposed || revision !== this.revision) { this.abandon(result); return; }
      this.deadline = this.now() + deadlineMs;
      this.set({ phase: "running", result, error: null, startedAt: this.now() });
      this.schedule();
    } catch (error) {
      if (revision === this.revision) this.set({ ...idle(), phase: "interrupted", error: this.message(error) });
    } finally {
      if (revision === this.revision) this.busy = false;
    }
  };

  poll = async (): Promise<void> => {
    const result = this.state.result;
    if (this.disposed || this.busy || result === null || !this.policy.running(result)) return;
    if (this.now() > this.deadline) { await this.cancel(); return; }
    this.busy = true;
    const revision = ++this.revision;
    try {
      const update = await this.policy.poll(this.binding, result.jobHandle);
      if (!this.disposed && revision === this.revision && update !== null) this.accept(update);
    } catch (error) {
      if (revision === this.revision) this.set({ ...this.state, phase: "interrupted", error: this.message(error) });
    } finally {
      if (revision === this.revision) this.busy = false;
    }
  };

  cancel = async (): Promise<void> => {
    const result = this.state.result;
    if (this.disposed || result === null || !this.policy.running(result) || this.state.phase === "cancelling") return;
    if (this.timer !== null) { clearTimeout(this.timer); this.timer = null; }
    const revision = ++this.revision;
    this.busy = true;
    this.set({ ...this.state, phase: "cancelling", error: null });
    try {
      const update = await this.policy.cancel(this.binding, result.jobHandle);
      if (!this.disposed && revision === this.revision && update !== null) {
        this.accept(update);
        // The job is stopped and its file removed after the answer; keep
        // asking for a little while so the page can say whether it went.
        if (update.temporaryFile === "pending") this.followUp(REFRESH_ATTEMPTS);
      }
    } catch (error) {
      if (revision === this.revision) this.set({ ...this.state, phase: "interrupted", error: this.message(error) });
    } finally {
      if (revision === this.revision) this.busy = false;
    }
  };

  private followUp(attempts: number): void {
    if (this.timer !== null) clearTimeout(this.timer);
    if (this.disposed || attempts <= 0) return;
    this.timer = setTimeout(() => { this.timer = null; void this.refresh(attempts - 1); }, POLL_MS);
  }

  /** Another look at a finished job, for the fate of the target's file. */
  private refresh = async (remaining: number): Promise<void> => {
    const result = this.state.result;
    if (this.disposed || this.busy || result === null) return;
    const revision = ++this.revision;
    this.busy = true;
    try {
      const update = await this.policy.poll(this.binding, result.jobHandle);
      if (!this.disposed && revision === this.revision && update !== null) {
        this.accept(update);
        if (update.temporaryFile === "pending") this.followUp(remaining);
      }
    } catch {
      // The job may have gone with its connection; what is shown stays true.
    } finally {
      if (revision === this.revision) this.busy = false;
    }
  };

  /** Back to the start, keeping nothing of a finished job. */
  reset = (): void => {
    if (this.state.result !== null && this.policy.running(this.state.result)) return;
    if (this.timer !== null) { clearTimeout(this.timer); this.timer = null; }
    this.revision++;
    this.busy = false;
    this.set(idle());
  };

  dispose = (): void => {
    this.disposed = true;
    this.revision++;
    if (this.timer !== null) clearTimeout(this.timer);
    this.listeners.clear();
    if (this.state.result !== null) this.abandon(this.state.result);
  };

  private message(error: unknown): string {
    return error instanceof Error && error.message.trim() !== "" ? error.message : this.policy.unreachableMessage;
  }
}

function idle<R>(): EvidenceJobViewState<R> {
  return { phase: "ready", result: null, error: null, startedAt: null };
}
