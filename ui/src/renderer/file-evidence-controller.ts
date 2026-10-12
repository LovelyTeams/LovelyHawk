import { matchesFileEvidenceResult, type FileEvidenceApi, type FileEvidenceRequest, type FileEvidenceResult } from "../shared/file-evidence-contract";
import type { EmergencyCommandPathOffer } from "../shared/emergency-command-contract";

export interface FileEvidenceState {
  phase: "ready" | "choosing" | "collecting" | "cancelling" | "interrupted" | "done";
  result: FileEvidenceResult | null;
  error: string | null;
}

export class FileEvidenceController {
  private state: FileEvidenceState = { phase: "ready", result: null, error: null };
  private listeners = new Set<() => void>();
  private disposed = false;
  private busy = false;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private deadline = 0;
  private revision = 0;
  constructor(private api: FileEvidenceApi, private binding: string, readonly offer: EmergencyCommandPathOffer) {}
  attach = (): void => {
    if (!this.disposed) return;
    this.disposed = false; this.busy = false; this.revision++;
    this.set({ phase: "ready", result: null, error: null });
  };
  getSnapshot = (): FileEvidenceState => this.state;
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private set(state: FileEvidenceState): void { if (this.disposed) return; this.state = state; this.listeners.forEach((fn) => fn()); }
  private async request(request: FileEvidenceRequest): Promise<FileEvidenceResult | null> {
    const result = await this.api.fileEvidence(request);
    if (!matchesFileEvidenceResult(request, result)) throw new Error("采集结果与本次请求不一致，请重新检查连接。");
    return result;
  }
  private async abandon(result: FileEvidenceResult): Promise<void> {
    if (result.state === "collecting") {
      await this.api.fileEvidence({ action: "cancel", bindingHandle: this.binding, jobHandle: result.jobHandle }).catch(() => undefined);
    }
  }
  private accept(result: FileEvidenceResult): void {
    const previous = this.state.result;
    if (result.pathHandle !== this.offer.pathHandle || result.path !== this.offer.path || (previous !== null &&
      (result.jobHandle !== previous.jobHandle || result.targetLabel !== previous.targetLabel || result.folderName !== previous.folderName || result.caseTitle !== previous.caseTitle))) {
      void this.abandon(result);
      throw new Error("文件或来源已变化，已停止展示这次采集结果。");
    }
    this.set({ phase: result.state === "collecting" ? "collecting" : "done", result, error: null });
    if (result.state === "collecting") this.schedule();
  }
  private schedule(): void {
    if (this.timer !== null) clearTimeout(this.timer);
    if (!this.disposed) this.timer = setTimeout(() => { this.timer = null; void this.poll(); }, 700);
  }
  begin = async (): Promise<void> => {
    if (this.disposed || this.busy || this.state.phase !== "ready") return;
    this.busy = true;
    const revision = ++this.revision;
    this.set({ phase: "choosing", result: null, error: null });
    try {
      const result = await this.request({ action: "begin", bindingHandle: this.binding, pathHandle: this.offer.pathHandle });
      if (result === null) { this.set({ phase: "ready", result: null, error: null }); return; }
      if (this.disposed || revision !== this.revision) { await this.abandon(result); return; }
      this.deadline = Date.now() + 16 * 60_000;
      this.accept(result);
    } catch (error) {
      if (revision === this.revision) this.set({ phase: "interrupted", result: null, error: message(error) });
    } finally { if (revision === this.revision) this.busy = false; }
  };
  poll = async (): Promise<void> => {
    const result = this.state.result;
    if (this.disposed || this.busy || !result || result.state !== "collecting") return;
    if (Date.now() > this.deadline) { await this.cancel(); return; }
    this.busy = true;
    const revision = ++this.revision;
    try {
      const update = await this.request({ action: "poll", bindingHandle: this.binding, jobHandle: result.jobHandle });
      if (!this.disposed && revision === this.revision && update !== null) this.accept(update);
    } catch (error) { if (revision === this.revision) this.set({ ...this.state, phase: "interrupted", error: message(error) }); }
    finally { if (revision === this.revision) this.busy = false; }
  };
  cancel = async (): Promise<void> => {
    const result = this.state.result;
    if (this.disposed || !result || result.state !== "collecting" || this.state.phase === "cancelling") return;
    if (this.timer !== null) { clearTimeout(this.timer); this.timer = null; }
    const revision = ++this.revision;
    this.busy = true;
    this.set({ ...this.state, phase: "cancelling", error: null });
    try {
      const update = await this.request({ action: "cancel", bindingHandle: this.binding, jobHandle: result.jobHandle });
      if (!this.disposed && revision === this.revision && update !== null) this.accept(update);
    } catch (error) { if (revision === this.revision) this.set({ ...this.state, phase: "interrupted", error: message(error) }); }
    finally { if (revision === this.revision) this.busy = false; }
  };
  dispose = (): void => {
    this.disposed = true;
    this.revision++;
    if (this.timer !== null) clearTimeout(this.timer);
    this.listeners.clear();
    if (this.state.result !== null) void this.abandon(this.state.result);
  };
}
function message(error: unknown): string { return error instanceof Error ? error.message : "无法读取采集进度，请检查连接。"; }
