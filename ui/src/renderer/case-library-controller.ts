import { matchesCaseLibraryResult, type CaseLibraryApi, type CaseLibraryRequest, type CaseLibraryResult, type CaseTransfer, type CaseStatusAction } from "../shared/case-library-contract";
import type { CaseSection } from "../shared/case-workspace-contract";

type Result<K extends CaseLibraryResult["kind"]> = Extract<CaseLibraryResult, { kind: K }>;
export type LibraryPlan = Result<"plan"> & { expiresAt: number; caseId: string };
export interface CaseLibraryState {
  list: Result<"list"> | null; view: Result<"view"> | null; page: Result<"items"> | null; plan: LibraryPlan | null;
  section: CaseSection; query: string; offset: number; busy: boolean; error: string | null; notice: string | null;
}
const initial = (): CaseLibraryState => ({ list: null, view: null, page: null, plan: null, section: "evidence", query: "", offset: 0, busy: false, error: null, notice: null });
export class CaseLibraryController {
  private state = initial();
  private listeners = new Set<() => void>();
  private generation = 0;
  constructor(private readonly api: CaseLibraryApi) {}
  getSnapshot = (): CaseLibraryState => this.state;
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => this.listeners.delete(listener); };
  private update(patch: Partial<CaseLibraryState>): void { this.state = { ...this.state, ...patch }; for (const listener of this.listeners) listener(); }
  private async call(request: CaseLibraryRequest): Promise<CaseLibraryResult | null> {
    const result = await this.api.caseLibrary(request);
    if (!matchesCaseLibraryResult(request, result)) throw new Error("案件库结果未通过校验，请刷新核对。");
    return result;
  }
  private cancelHandle(planHandle: string): Promise<unknown> { return this.call({ action: "cancel", planHandle }).catch(() => undefined); }
  dispose(): void {
    this.generation += 1;
    if (this.state.plan !== null) void this.cancelHandle(this.state.plan.planHandle);
    this.state = initial();
  }
  private async run(work: (current: () => boolean) => Promise<void>, allowPlan = false): Promise<void> {
    if (this.state.busy || !allowPlan && this.state.plan !== null) return;
    const generation = this.generation;
    const current = () => this.generation === generation;
    this.update({ busy: true, error: null });
    try { await work(current); }
    catch (reason) { if (current()) this.update({ error: reason instanceof Error ? reason.message : "案件操作未完成，请刷新核对实际状态。" }); }
    finally { if (current()) this.update({ busy: false }); }
  }
  async refresh(preferredCaseId?: string): Promise<void> {
    await this.run(async (current) => {
      this.update({ view: null, page: null });
      const list = await this.call({ action: "list" });
      if (current() && list?.kind === "list") {
        this.update({ list });
        if (preferredCaseId !== undefined) {
          const selected = list.items.find((item) => item.incident.id === preferredCaseId && item.location === "working");
          if (selected !== undefined) await this.readCase(selected.itemHandle, current);
          else this.update({ error: "该案件已不在活动列表中，请在案件库重新查找。" });
        }
      }
    });
  }
  async view(itemHandle: string): Promise<void> {
    await this.run(async (current) => {
      await this.readCase(itemHandle, current);
    });
  }
  private async readCase(itemHandle: string, current: () => boolean): Promise<void> {
      this.update({ view: null, page: null, query: "", section: "evidence", offset: 0, notice: null });
      const view = await this.call({ action: "view", itemHandle });
      if (!current() || view?.kind !== "view") return;
      this.update({ view });
      const page = await this.call({ action: "items", snapshotHandle: view.snapshotHandle, section: "evidence", query: "", offset: 0 });
      if (current() && page?.kind === "items") this.update({ page });
  }
  async items(section: CaseSection, query: string, offset = 0): Promise<void> {
    const view = this.state.view;
    if (view === null) return;
    await this.run(async (current) => {
      this.update({ section, query, offset, page: null });
      const page = await this.call({ action: "items", snapshotHandle: view.snapshotHandle, section, query, offset });
      if (current() && page?.kind === "items") this.update({ page });
    });
  }
  async plan(operation: CaseTransfer): Promise<LibraryPlan | null> {
    const view = this.state.view;
    if (view === null) return null;
    return this.planIntent({ action: "plan", snapshotHandle: view.snapshotHandle, operation }, view.item.incident.id);
  }
  async planStatus(operation: CaseStatusAction, conclusion: string, followup: string): Promise<LibraryPlan | null> {
    const view = this.state.view;
    if (view === null || view.item.location !== "working") return null;
    return this.planIntent({ action: "status-plan", snapshotHandle: view.snapshotHandle, operation, conclusion, followup }, view.item.incident.id);
  }
  private async planIntent(request: Extract<CaseLibraryRequest, { action: "plan" | "status-plan" }>, caseId: string): Promise<LibraryPlan | null> {
    let planned: LibraryPlan | null = null;
    await this.run(async (current) => {
      const started = Date.now();
      const result = await this.call(request);
      if (result?.kind !== "plan") return;
      if (!current()) { await this.cancelHandle(result.planHandle); return; }
      planned = { ...result, caseId, expiresAt: started + result.expiresInSeconds * 1000 };
      this.update({ plan: planned, notice: null });
    });
    return planned;
  }
  async cancel(): Promise<void> {
    if (this.state.busy) return;
    const plan = this.state.plan; this.update({ plan: null });
    if (plan !== null) await this.cancelHandle(plan.planHandle);
  }
  async confirm(plan: LibraryPlan): Promise<boolean> {
    if (this.state.plan !== plan) return false;
    if (Date.now() >= plan.expiresAt) { await this.cancel(); this.update({ error: "确认已过期，请重新查看案件并生成计划。" }); return false; }
    let confirmed = false;
    await this.run(async (current) => {
      // A confirmation is single-use even if the response is lost.
      this.update({ plan: null });
      const result = await this.call({ action: "confirm", planHandle: plan.planHandle });
      if (!current() || result?.kind !== "changed") return;
      if (result.caseId !== plan.caseId || result.operation !== plan.operation) throw new Error("操作结果与所确认的案件不一致，请刷新核对。");
      confirmed = result.verified;
      this.update({ notice: result.message, view: null, page: null });
      const list = await this.call({ action: "list" });
      if (current() && list?.kind === "list") this.update({ list });
    }, true);
    return confirmed;
  }
  async export(): Promise<void> {
    const view = this.state.view;
    if (view === null) return;
    await this.run(async (current) => {
      this.update({ notice: null });
      const result = await this.call({ action: "export", snapshotHandle: view.snapshotHandle });
      if (!current()) return;
      this.update({ notice: result === null ? "已取消导出。" : result.kind === "exported" ? `已导出 ${result.filename}（${result.bytes} 字节），完整性已核对。SHA-256：${result.sha256}` : null });
    });
  }
}
