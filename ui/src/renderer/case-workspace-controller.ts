import { matchesCaseWorkspaceResult, type CaseWorkspaceApi, type CaseWorkspaceRequest, type CaseWorkspaceResult, type CaseSection } from "../shared/case-workspace-contract";

export interface CaseWorkspaceState {
  binding: string | null;
  list: Extract<CaseWorkspaceResult, { kind: "list" }> | null;
  view: Extract<CaseWorkspaceResult, { kind: "view" }> | null;
  page: Extract<CaseWorkspaceResult, { kind: "items" }> | null;
  section: CaseSection; query: string; offset: number;
  busy: boolean; error: string | null; notice: string | null;
}
const initial = (): CaseWorkspaceState => ({ binding: null, list: null, view: null, page: null, section: "evidence", query: "", offset: 0, busy: false, error: null, notice: null });
/** Hide old-target data during the render before the binding effect runs. */
export function caseWorkspaceStateForBinding(state: CaseWorkspaceState, binding: string | null): CaseWorkspaceState {
  return state.binding === binding ? state : { ...initial(), binding, busy: binding !== null };
}
type Mutation = Extract<CaseWorkspaceRequest, { action: "create" | "note" | "ioc" | "attach-note" }> | { action: "select"; bindingHandle: string; caseId: string };

export class CaseWorkspaceController {
  private state = initial();
  private listeners = new Set<() => void>();
  private generation = 0;
  private read = 0;
  private writing = false;
  constructor(private readonly api: CaseWorkspaceApi) {}
  getSnapshot = (): CaseWorkspaceState => this.state;
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => this.listeners.delete(listener); };
  private update(patch: Partial<CaseWorkspaceState>): void { this.state = { ...this.state, ...patch }; for (const listener of this.listeners) listener(); }
  dispose(): void { this.generation += 1; this.read += 1; this.writing = false; }
  setBinding(binding: string | null): void {
    this.dispose(); this.state = initial(); this.update({ binding });
    if (binding !== null) void this.refresh();
  }
  private async call(request: CaseWorkspaceRequest): Promise<CaseWorkspaceResult> {
    const result = await this.api.caseWorkspace(request);
    if (!matchesCaseWorkspaceResult(request, result)) throw new Error("案件结果未通过校验，请刷新核对。");
    return result;
  }
  private current(generation: number, read: number): boolean { return this.generation === generation && this.read === read; }
  private fail(reason: unknown): void { this.update({ error: reason instanceof Error ? reason.message : "案件操作未完成，请刷新核对。" }); }
  private async readCase(bindingHandle: string, caseId: string, generation: number, read: number, section: CaseSection, query: string): Promise<void> {
    const view = await this.call({ action: "view", bindingHandle, caseId });
    if (!this.current(generation, read) || view.kind !== "view") return;
    this.update({ view, page: null, section, query, offset: 0 });
    const page = await this.call({ action: "items", bindingHandle, snapshotHandle: view.snapshotHandle, section, query, offset: 0 });
    if (this.current(generation, read) && page.kind === "items") this.update({ page });
  }
  async refresh(preferredCase?: string): Promise<void> {
    const bindingHandle = this.state.binding;
    if (bindingHandle === null || this.writing) return;
    const generation = this.generation, read = ++this.read;
    const preferred = preferredCase ?? this.state.view?.incident.id;
    const { section, query } = this.state;
    this.update({ busy: true, error: null, page: null });
    try {
      const list = await this.call({ action: "list", bindingHandle });
      if (!this.current(generation, read) || list.kind !== "list") return;
      const caseId = list.cases.find((item) => item.id === preferred)?.id ?? list.activeCaseId ?? list.cases[0]?.id;
      this.update({ list, view: null });
      if (caseId !== undefined && caseId !== null) await this.readCase(bindingHandle, caseId, generation, read, section, query);
    } catch (reason) { if (this.current(generation, read)) this.fail(reason); }
    finally { if (this.current(generation, read)) this.update({ busy: false }); }
  }
  async view(caseId: string): Promise<void> {
    const bindingHandle = this.state.binding;
    if (bindingHandle === null || this.writing) return;
    const generation = this.generation, read = ++this.read;
    this.update({ busy: true, error: null, view: null, page: null, notice: null });
    try { await this.readCase(bindingHandle, caseId, generation, read, "evidence", ""); }
    catch (reason) { if (this.current(generation, read)) this.fail(reason); }
    finally { if (this.current(generation, read)) this.update({ busy: false }); }
  }
  async items(section: CaseSection, query: string, offset = 0): Promise<void> {
    const { binding: bindingHandle, view } = this.state;
    if (bindingHandle === null || view === null || this.writing) return;
    const generation = this.generation, read = ++this.read;
    this.update({ busy: true, error: null, section, query, offset, page: null });
    try {
      const page = await this.call({ action: "items", bindingHandle, snapshotHandle: view.snapshotHandle, section, query, offset });
      if (this.current(generation, read) && page.kind === "items") this.update({ page });
    } catch (reason) { if (this.current(generation, read)) this.fail(reason); }
    finally { if (this.current(generation, read)) this.update({ busy: false }); }
  }
  async mutate(request: Mutation): Promise<boolean> {
    if (this.writing || this.state.busy || this.state.binding !== request.bindingHandle) return false;
    this.writing = true;
    const generation = this.generation, read = ++this.read;
    this.update({ busy: true, error: null, notice: null });
    let caseId: string | undefined;
    try {
      const result = await this.call(request);
      if (!this.current(generation, read) || result.kind !== "changed") return false;
      caseId = result.caseId;
      this.update({ notice: result.message });
    } catch (reason) {
      if (this.current(generation, read)) this.fail(reason);
      return false;
    } finally {
      if (this.current(generation, read)) { this.writing = false; this.update({ busy: false }); }
    }
    await this.refresh(caseId);
    return this.generation === generation;
  }
  async report(): Promise<Extract<CaseWorkspaceResult, { kind: "report" }> | null> {
    const { binding: bindingHandle, view } = this.state;
    if (bindingHandle === null || view === null || this.state.busy || this.writing) return null;
    const generation = this.generation, read = ++this.read;
    this.update({ busy: true, error: null });
    try {
      const result = await this.call({ action: "report", bindingHandle, snapshotHandle: view.snapshotHandle });
      return this.current(generation, read) && result.kind === "report" ? result : null;
    } catch (reason) { if (this.current(generation, read)) this.fail(reason); return null; }
    finally { if (this.current(generation, read)) this.update({ busy: false }); }
  }
}
