import {
  isNginxRepairResponse, matchesNginxRepairResponse, isNginxProbePath, isNginxServerName,
  type NginxRepairApi, type NginxRepairPlan, type NginxRepairReceipt,
  type NginxRepairRequest, type NginxRepairResponse,
} from "../shared/nginx-repair-contract";

type Response<K extends NginxRepairResponse["kind"]> = Extract<NginxRepairResponse, { kind: K }>;
export interface NginxRepairDialog {
  id: number;
  phase: "preparing" | "ready" | "confirming" | "executing" | "done" | "failed";
  plan: NginxRepairPlan | null;
  receipt: NginxRepairReceipt | null;
  error: string | null;
}
export interface NginxRepairState {
  inventory: Response<"inventory"> | null;
  configuration: Response<"configuration"> | null;
  history: Response<"history"> | null;
  selectedInstance: string | null;
  endpoints: Response<"listeners"> | null;
  connectivity: Response<"connectivity"> | null;
  reading: "discover" | "load" | "history" | "listeners" | "probe" | "retain" | "discard" | null;
  error: string | null;
  dialog: NginxRepairDialog | null;
}
const initial = (): NginxRepairState => ({ inventory: null, configuration: null, history: null,
  selectedInstance: null, endpoints: null, connectivity: null, reading: null, error: null, dialog: null });
const errorText = (error: unknown): string => error instanceof Error
  ? error.message.slice(0, 1024) : "操作未完成，请重新读取当前状态后再试。";

function samePlan(before: NginxRepairPlan, after: NginxRepairPlan): boolean {
  return before.planHandle === after.planHandle && before.targetLabel === after.targetLabel && before.candidateHandle === after.candidateHandle &&
    before.title === after.title && before.path === after.path && before.line === after.line &&
    before.diff === after.diff && before.impact === after.impact && before.restoreDescription === after.restoreDescription;
}

/** One mounted page owns its reads and unstarted plans. Execution is consumed
 * once; losing the reply never permits another write. Core owns recovery. */
export class NginxRepairController {
  private state = initial();
  private listeners = new Set<() => void>();
  private alive = true;
  private epoch = 0;
  private dialogSequence = 0;
  private execution: Promise<void> | null = null;
  private observationWork: Promise<void> | null = null;

  constructor(private readonly api: NginxRepairApi, readonly binding: string | null) {}
  getSnapshot = (): NginxRepairState => this.state;
  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => { this.listeners.delete(listener); };
  };
  activate(): void {
    if (!this.alive) { this.alive = true; this.update(initial()); }
  }
  dispose(): void {
    const dialog = this.state.dialog;
    this.alive = false;
    this.epoch += 1;
    if (dialog?.plan && dialog.phase !== "executing" && dialog.phase !== "done") this.cancelPlan(dialog.plan.planHandle);
  }
  private update(patch: Partial<NginxRepairState>): void {
    this.state = { ...this.state, ...patch };
    for (const listener of this.listeners) listener();
  }
  private owns(epoch: number, dialogId?: number): boolean {
    return this.alive && this.epoch === epoch && (dialogId === undefined || this.state.dialog?.id === dialogId);
  }
  private available(): boolean {
    return this.alive && this.binding !== null && this.state.reading === null && this.state.dialog === null && !this.hasUnsavedObservation();
  }
  hasUnsavedObservation(): boolean { return this.state.connectivity?.retention.state === "unsaved"; }
  private async request(request: NginxRepairRequest, timeout = 185_000): Promise<NginxRepairResponse> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    let timedOut = false;
    try {
      const pending = this.api.nginxRepair(request).then((response) => {
        if (timedOut && (request.action === "plan" || request.action === "restore") &&
          isNginxRepairResponse(response) && response.kind === "plan") this.cancelPlan(response.plan.planHandle);
        return response;
      });
      const response = await Promise.race([
        pending,
        new Promise<never>((_, reject) => { timer = setTimeout(() => { timedOut = true; reject(new Error("等待响应超时，请检查连接和修补历史。")); }, timeout); }),
      ]);
      if (!matchesNginxRepairResponse(request, response)) throw new Error("返回的操作信息不匹配，请重新读取当前状态。");
      return response;
    } finally { clearTimeout(timer); }
  }
  private cancelPlan(planHandle: string): void {
    if (this.binding !== null) void this.request({ action: "cancel", bindingHandle: this.binding, planHandle }).catch(() => {});
  }
  async read(action: "discover" | "load" | "history" | "listeners", instanceHandle?: string): Promise<void> {
    if (!this.available() || ((action === "load" || action === "listeners") && !instanceHandle)) return;
    if (action === "listeners" && instanceHandle !== this.state.selectedInstance) return;
    const epoch = this.epoch;
    this.update({ reading: action, error: null,
      ...(action === "discover" ? { inventory: null, configuration: null, selectedInstance: null } : {}),
      ...(action === "load" ? { configuration: null, selectedInstance: instanceHandle! } : {}),
      ...(action !== "history" ? { endpoints: null, connectivity: null } : {}),
    });
    try {
      const response = await this.request(action === "load" || action === "listeners"
        ? { action, bindingHandle: this.binding!, instanceHandle: instanceHandle! }
        : { action, bindingHandle: this.binding! });
      if (!this.owns(epoch)) return;
      if (response.kind === "inventory") this.update({ inventory: response });
      if (response.kind === "configuration") this.update({ configuration: response });
      if (response.kind === "history") this.update({ history: response });
      if (response.kind === "listeners") this.update({ endpoints: response });
    } catch (error) { if (this.owns(epoch)) this.update({ error: errorText(error) }); }
    finally { if (this.owns(epoch)) this.update({ reading: null }); }
  }
  clearConnectivity(): void { if (this.state.reading !== "probe" && !this.hasUnsavedObservation()) this.update({ connectivity: null }); }
  async retainObservation(): Promise<void> {
    const observation = this.state.connectivity;
    if (!this.alive || !this.binding || this.state.reading || this.state.dialog || !observation?.retention.canRetry) return;
    const epoch = this.epoch;
    this.update({ reading: "retain", error: null });
    try {
      const response = await this.request({ action: "retain", bindingHandle: this.binding, observationHandle: observation.observationHandle }, 30_000);
      if (this.owns(epoch) && response.kind === "retention") this.update({ connectivity: { ...observation, retention: response.retention } });
    } catch (error) { if (this.owns(epoch)) this.update({ error: errorText(error) }); }
    finally { if (this.owns(epoch)) this.update({ reading: null }); }
  }
  async discardObservation(): Promise<boolean> {
    const observation = this.state.connectivity;
    if (!this.alive || !this.binding || this.state.reading || this.state.dialog || !observation) return false;
    const epoch = this.epoch;
    this.update({ reading: "discard", error: null });
    try {
      await this.request({ action: "discard-observation", bindingHandle: this.binding, observationHandle: observation.observationHandle }, 30_000);
    } catch (error) { if (this.owns(epoch)) this.update({ error: errorText(error) }); }
    finally { if (this.owns(epoch)) this.update({ reading: null, connectivity: null }); }
    // The user explicitly discarded this local observation. A lost/expired
    // cache reply must not trap navigation or prevent disconnecting the target.
    return this.owns(epoch);
  }
  probe(endpointHandle: string, serverName: string, path: string): Promise<void> {
    if (!this.available() || !isNginxServerName(serverName) || !isNginxProbePath(path) ||
      !this.state.endpoints?.endpoints.some((item) => item.endpointHandle === endpointHandle)) return Promise.resolve();
    const work = this.runProbe(endpointHandle, serverName, path);
    this.observationWork = work;
    void work.finally(() => { if (this.observationWork === work) this.observationWork = null; });
    return work;
  }
  private async runProbe(endpointHandle: string, serverName: string, path: string): Promise<void> {
    const epoch = this.epoch;
    this.update({ reading: "probe", connectivity: null, error: null });
    try {
      const response = await this.request({ action: "probe", bindingHandle: this.binding!, endpointHandle, serverName, path }, 60_000);
      if (this.owns(epoch) && response.kind === "connectivity") this.update({ connectivity: response });
    } catch (error) { if (this.owns(epoch)) this.update({ error: errorText(error) }); }
    finally { if (this.owns(epoch)) this.update({ reading: null }); }
  }
  async prepare(candidateHandle: string): Promise<void> {
    const configuration = this.state.configuration;
    if (!this.available() || !configuration || configuration.unresolvedIncludes > 0 ||
      !configuration.candidates.some((candidate) => candidate.candidateHandle === candidateHandle)) return;
    await this.prepareRequest({ action: "plan", bindingHandle: this.binding!,
      configurationHandle: configuration.configurationHandle, candidateHandle });
  }
  async restore(recordHandle: string): Promise<void> {
    if (!this.available()) return;
    const known = this.state.history?.records.some((record) => record.recordHandle === recordHandle && record.canPrepareRestore);
    if (!known) return;
    await this.prepareRequest({ action: "restore", bindingHandle: this.binding!, recordHandle });
  }
  private async prepareRequest(request: NginxRepairRequest): Promise<void> {
    const epoch = this.epoch;
    const id = ++this.dialogSequence;
    this.update({ dialog: { id, phase: "preparing", plan: null, receipt: null, error: null }, error: null });
    try {
      const response = await this.request(request);
      if (response.kind !== "plan") throw new Error("未取得有效修补计划。");
      if (!this.owns(epoch, id)) { this.cancelPlan(response.plan.planHandle); return; }
      this.update({ dialog: { id, phase: "ready", plan: response.plan, receipt: null, error: null } });
    } catch (error) {
      if (this.owns(epoch, id)) this.update({ dialog: { id, phase: "failed", plan: null, receipt: null, error: errorText(error) } });
    }
  }
  closeDialog(): void {
    const dialog = this.state.dialog;
    if (!dialog || dialog.phase === "executing") return;
    if (dialog.plan && dialog.phase !== "done") this.cancelPlan(dialog.plan.planHandle);
    this.update({ dialog: null });
  }
  confirm(): Promise<void> {
    const dialog = this.state.dialog;
    if (!this.alive || this.binding === null || dialog?.phase !== "ready" || !dialog.plan) return Promise.resolve();
    const epoch = this.epoch;
    // Change state before the first await, including rapid double-clicks.
    this.update({ dialog: { ...dialog, phase: "confirming", error: null } });
    const task = this.executePlan(epoch, dialog.id, dialog.plan);
    this.execution = task;
    void task.finally(() => { if (this.execution === task) this.execution = null; });
    return task;
  }
  private async executePlan(epoch: number, id: number, plan: NginxRepairPlan): Promise<void> {
    let dispatched = false;
    try {
      const confirmed = await this.request({ action: "confirm", bindingHandle: this.binding!, planHandle: plan.planHandle });
      if (!this.owns(epoch, id)) { this.cancelPlan(plan.planHandle); return; }
      if (confirmed.kind !== "plan" || !samePlan(plan, confirmed.plan)) throw new Error("确认内容已变化，请关闭后重新准备计划。");
      this.update({ dialog: { id, phase: "executing", plan, receipt: null, error: null } });
      dispatched = true;
      const started = await this.request({ action: "execute", bindingHandle: this.binding!, planHandle: plan.planHandle }, 30_000);
      if (started.kind !== "execution") throw new Error("未取得执行状态。");
      const deadline = Date.now() + 300_000;
      while (this.owns(epoch, id)) {
        const remaining = deadline - Date.now();
        if (remaining <= 0) throw new Error("执行结果等待超时。");
        const result = await this.request({ action: "execution", bindingHandle: this.binding!, executionHandle: started.executionHandle }, Math.min(remaining, 30_000));
        if (!this.owns(epoch, id)) return;
        if (result.kind !== "execution") throw new Error("未取得执行状态。");
        if (result.receipt) {
          if (result.receipt.planHandle !== plan.planHandle) throw new Error("执行结果与本次计划不匹配。");
          this.update({ configuration: null, history: null, endpoints: null, connectivity: null,
            dialog: { id, phase: "done", plan, receipt: result.receipt, error: null } });
          return;
        }
        await new Promise((resolve) => setTimeout(resolve, 500));
      }
    } catch (error) {
      if (!dispatched) this.cancelPlan(plan.planHandle);
      if (this.owns(epoch, id)) this.update({ configuration: dispatched ? null : this.state.configuration,
        ...(dispatched ? { endpoints: null, connectivity: null } : {}),
        dialog: { id, phase: "failed", plan, receipt: null, error: dispatched
          ? "执行结果尚未核实。操作可能仍在验证或恢复，请关闭后查看修补历史并检查业务；不要重复提交。"
          : errorText(error) } });
    }
  }
  async beforeDeactivate(): Promise<boolean> {
    if (this.state.dialog?.phase === "executing") await this.execution;
    this.closeDialog();
    if (this.observationWork) await this.observationWork;
    return !this.hasUnsavedObservation() && this.state.reading !== "retain" && this.state.reading !== "discard";
  }
}
