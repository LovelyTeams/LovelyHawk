import type { PostgresqlObjectPage, PostgresqlObjectDetail, ObjectSection, ObjectFilter } from "../shared/postgresql-object-contract";
import type { PostgresqlRolePage, RoleAccessMode } from "../shared/postgresql-role-contract";
import type { AccessSection, PostgresqlAccessPage } from "../shared/postgresql-access-contract";
import { isPostgresqlRuntimeRequest, matchesPostgresqlRuntimeResponse, type PostgresqlRuntimeApi, type PostgresqlRuntimeJob, type PostgresqlRuntimeRequest, type PostgresqlRuntimeResponse, type PostgresqlProfileSummary } from "../shared/postgresql-runtime-contract";

type Rows = Extract<PostgresqlRuntimeResponse, { kind: "rows" }>;
export interface PostgresqlState {
  profiles: PostgresqlProfileSummary[]; selected: string | null; job: PostgresqlRuntimeJob | null;
  objectPage: PostgresqlObjectPage | null; objectDetail: PostgresqlObjectDetail | null; rolePage: PostgresqlRolePage | null; accessRows: PostgresqlAccessPage | null; rows: Rows | null; busy: boolean; error: string | null; notice: string | null;
}
export class PostgresqlRuntimeController {
  private state: PostgresqlState = { profiles: [], selected: null, job: null, rows: null, accessRows: null, rolePage: null, objectPage: null, objectDetail: null, busy: false, error: null, notice: null };
  private listeners = new Set<() => void>();
  private timer: ReturnType<typeof setTimeout> | null = null;
  private expiry: ReturnType<typeof setTimeout> | null = null;
  private pending: Promise<unknown> | null = null;
  private disposed = false;
  private cancelling = false;
  constructor(private api: PostgresqlRuntimeApi, readonly binding: string) {}
  getSnapshot = (): PostgresqlState => this.state;
  subscribe = (fn: () => void): (() => void) => { this.listeners.add(fn); return () => { this.listeners.delete(fn); }; };
  private set(next: Partial<PostgresqlState>): void { if (!this.disposed) { this.state = { ...this.state, ...next }; this.listeners.forEach(fn => fn()); } }
  hasUnsaved = (): boolean => this.state.job?.retention?.state === "unsaved";
  select = (id: string): void => { if (!this.state.busy && this.state.job?.state !== "reading" && !this.hasUnsaved()) this.set({ selected: id, job: null, rows: null, accessRows: null, rolePage: null, objectPage: null, objectDetail: null, error: null, notice: null }); };
  private async exchange(request: PostgresqlRuntimeRequest): Promise<PostgresqlRuntimeResponse> {
    if (!isPostgresqlRuntimeRequest(request)) throw new Error("请求内容无效，请检查输入长度、地址、端口和证书。");
    const response = await this.api.postgresqlRuntime(request);
    if (!matchesPostgresqlRuntimeResponse(request, response)) throw new Error("返回的数据库结果无法核实，请刷新后重试。");
    return response;
  }
  request = async (request: PostgresqlRuntimeRequest): Promise<PostgresqlRuntimeResponse | null> => {
    if (this.disposed || this.pending || request.bindingHandle !== this.binding) return null;
    this.set({ busy: true, error: null });
    const expectedObject = request.action === "object-detail" && this.state.objectPage?.section === request.section ? this.state.objectPage.rows.find(r => r.oid === request.oid && r.subId === request.subId) : null;
    const expectedRole = request.action === "object-detail" && request.roleOid !== null ? this.state.rolePage?.source.oid === request.roleOid ? this.state.rolePage.source : this.state.accessRows?.section === "roles" ? this.state.accessRows.rows.find(r => r.oid === request.roleOid) : null : null;
    const pending = this.exchange(request); this.pending = pending;
    try {
      const response = await pending;
      if (this.disposed) {
        if (response.kind === "job" && response.job.state === "reading") await this.abandon(response.job);
        return null;
      }
      if (response.kind === "rejected") throw new Error(response.detail);
      switch (response.kind) {
        case "profiles": if (this.state.job && !response.profiles.some(p => p.profileHandle === this.state.job?.profile.profileHandle)) this.set({ job: null, rows: null, accessRows: null, rolePage: null, objectPage: null, objectDetail: null });
          this.set({ profiles: response.profiles, selected: response.profiles.some(p => p.profileHandle === this.state.selected) ? this.state.selected : response.profiles[0]?.profileHandle ?? null }); break;
        case "saved": this.set({ profiles: [...this.state.profiles.filter(p => request.action !== "save" || p.profileHandle !== request.profileHandle), response.profile], selected: response.profile.profileHandle, job: null, rows: null, accessRows: null, rolePage: null, objectPage: null, objectDetail: null, notice: "连接已加密保存并关联当前 SSH 主机。" }); break;
        case "deleted": this.set({ profiles: this.state.profiles.filter(p => p.profileHandle !== response.profileHandle), selected: null, job: null, rows: null, accessRows: null, rolePage: null, objectPage: null, objectDetail: null, notice: response.detail }); break;
        case "job": {
          const previous = this.state.job;
          if (request.action !== "begin" && (!previous || (Object.keys(previous.profile) as (keyof PostgresqlProfileSummary)[]).some(key => previous.profile[key] !== response.job.profile[key]) || previous.startedAt !== response.job.startedAt || previous.targetLabel !== response.job.targetLabel || previous.state !== "reading" && response.job.state !== previous.state && response.job.state !== "expired")) throw new Error("检查结果已变化，请重新读取。");
          if (previous?.retention && request.action !== "begin" && request.action !== "discard-evidence" &&
            (!response.job.retention || previous.retention.caseId !== null && (previous.retention.caseId !== response.job.retention.caseId || previous.retention.caseTitle !== response.job.retention.caseTitle) ||
              previous.retention.recordText !== null && previous.retention.recordText !== response.job.retention.recordText ||
              previous.retention.state === "saved" && (response.job.retention.state !== "saved" || previous.retention.evidenceId !== response.job.retention.evidenceId || previous.retention.sha256 !== response.job.retention.sha256))) throw new Error("检查摘要或归属案件已变化，未采用返回结果。");
          this.set({ job: response.job, rows: response.job.state === "completed" ? this.state.rows : null, accessRows: response.job.state === "completed" ? this.state.accessRows : null, rolePage: response.job.state === "completed" ? this.state.rolePage : null, objectPage: response.job.state === "completed" ? this.state.objectPage : null, objectDetail: response.job.state === "completed" ? this.state.objectDetail : null });
          if (response.job.state === "reading") this.schedule();
          break;
        }
        case "object-rows": {
          const summary = this.state.job?.result?.access.objects[response.section];
          if (this.state.job?.jobHandle !== response.jobHandle || this.state.job.state !== "completed" || summary?.state !== "available" || response.total !== summary.total) throw new Error("对象授权列表已变化，请重新读取。");
          this.set({ objectPage: response, objectDetail: null }); break;
        }
        case "object-detail": {
          if (this.state.job?.jobHandle !== response.jobHandle || this.state.job.state !== "completed" || !expectedObject || JSON.stringify(expectedObject) !== JSON.stringify(response.object) ||
            response.role !== null && (!expectedRole || (Object.keys(response.role) as (keyof typeof response.role)[]).some(k => response.role![k] !== expectedRole[k]))) throw new Error("对象或角色身份已变化，请重新读取。");
          this.set({ objectDetail: response }); break;
        }
        case "role-access": {
          const access = this.state.job?.result?.access;
          const graph = access?.roleGraph;
          if (this.state.job?.jobHandle !== response.jobHandle || this.state.job.state !== "completed" || graph?.state !== "available" ||
            graph.database.oid !== response.database.oid || graph.database.name !== response.database.name || graph.database.ownerOid !== response.database.ownerOid ||
            access?.roles.state !== "available" || response.total >= access.roles.total) throw new Error("角色权限来源已变化，请重新读取。");
          this.set({ rolePage: response }); break;
        }
        case "access-rows": {
          const access = this.state.job?.result?.access;
          const summary = access?.[response.section];
          if (this.state.job?.jobHandle !== response.jobHandle || this.state.job.state !== "completed" || summary?.state !== "available" || summary.total !== response.total ||
            response.section === "roles" && response.rows.some(r => (r.passwordKind !== "unavailable") !== access!.passwordClassification)) throw new Error("访问诊断结果已变化，请重新读取。");
          this.set({ accessRows: response }); break;
        }
        case "rows": if (this.state.job?.jobHandle !== response.jobHandle || this.state.job.state !== "completed" || this.state.job.result?.parameterCount !== response.total) throw new Error("检查结果已变化，请重新读取。");
          this.set({ rows: response }); break;
        default: break;
      }
      return response;
    } catch (error) {
      // Only the bounded main/core error channel supplies these messages; remote SQL errors are never echoed.
      const message = error instanceof Error && error.message.length <= 2048 ? error.message : "无法完成数据库操作，请刷新连接后重试。";
      const previous = this.state.job;
      this.set({ error: message, ...(request.action === "poll" || request.action === "rows" || request.action === "access-rows" || request.action === "role-access" || request.action === "object-rows" || request.action === "object-detail" ? {
        job: previous?.retention ? previous.state === "reading" ? previous : { ...previous, state: "expired", result: null, detail: "参数结果无法继续核实，原检查摘要仍保留。" } : null, rows: null, accessRows: null, rolePage: null, objectPage: null, objectDetail: null,
      } : {}) });
      return null;
    } finally { if (this.pending === pending) this.pending = null; this.set({ busy: false }); }
  };
  list = (): Promise<PostgresqlRuntimeResponse | null> => this.request({ action: "list", bindingHandle: this.binding });
  begin = async (retainEvidence = false): Promise<void> => {
    if (!this.state.selected) return;
    if (this.pending || this.state.job?.state === "reading" || this.hasUnsaved()) return;
    if (this.expiry !== null) clearTimeout(this.expiry);
    this.expiry = setTimeout(() => { this.set({ job: this.hasUnsaved() && this.state.job ? { ...this.state.job, state: "expired", result: null, detail: "生效参数结果已过期，未保存的检查摘要仍保留。" } : null, rows: null, accessRows: null, rolePage: null, objectPage: null, objectDetail: null, notice: "检查结果已过期，请重新读取。" }); }, 600_000);
    this.set({ job: null, rows: null, accessRows: null, rolePage: null, objectPage: null, objectDetail: null, notice: null });
    await this.request({ action: "begin", bindingHandle: this.binding, profileHandle: this.state.selected, retainEvidence });
    if (this.state.job?.state === "completed") await this.rows("", 0);
  };
  retain = (): Promise<PostgresqlRuntimeResponse | null> => this.state.job?.retention?.canRetry
    ? this.request({ action: "retain", bindingHandle: this.binding, jobHandle: this.state.job.jobHandle }) : Promise.resolve(null);
  discard = (): Promise<PostgresqlRuntimeResponse | null> => this.hasUnsaved() && this.state.job
    ? this.request({ action: "discard-evidence", bindingHandle: this.binding, jobHandle: this.state.job.jobHandle }) : Promise.resolve(null);
  rows = (query: string, offset: number): Promise<PostgresqlRuntimeResponse | null> => this.state.job?.state === "completed"
    ? this.request({ action: "rows", bindingHandle: this.binding, jobHandle: this.state.job.jobHandle, query, offset }) : Promise.resolve(null);
  accessRows = (section: AccessSection, query: string, offset: number): Promise<PostgresqlRuntimeResponse | null> => this.state.job?.state === "completed" && this.state.job.result?.access[section].state === "available"
    ? this.request({ action: "access-rows", bindingHandle: this.binding, jobHandle: this.state.job.jobHandle, section, query, offset }) : Promise.resolve(null);
  roleAccess = (roleOid: number, mode: RoleAccessMode, query: string, offset: number): Promise<PostgresqlRuntimeResponse | null> => this.state.job?.state === "completed" && this.state.job.result?.access.roleGraph.state === "available"
    ? this.request({ action: "role-access", bindingHandle: this.binding, jobHandle: this.state.job.jobHandle, roleOid, mode, query, offset }) : Promise.resolve(null);
  objectRows = (section: ObjectSection, query: string, filter: ObjectFilter, offset: number): Promise<PostgresqlRuntimeResponse | null> => this.state.job?.state === "completed" && this.state.job.result?.access.objects[section].state === "available"
    ? this.request({ action: "object-rows", bindingHandle: this.binding, jobHandle: this.state.job.jobHandle, section, query, filter, offset }) : Promise.resolve(null);
  objectDetail = (section: ObjectSection, oid: number, subId: number, roleOid: number | null): Promise<PostgresqlRuntimeResponse | null> => this.state.job?.state === "completed" && this.state.objectPage?.section === section && this.state.objectPage.rows.some(r => r.oid === oid && r.subId === subId)
    ? this.request({ action: "object-detail", bindingHandle: this.binding, jobHandle: this.state.job.jobHandle, section, oid, subId, roleOid }) : Promise.resolve(null);
  private schedule(): void {
    if (this.timer !== null) clearTimeout(this.timer);
    if (!this.disposed && !this.cancelling) this.timer = setTimeout(() => { this.timer = null; void this.poll(); }, 700);
  }
  private async poll(): Promise<void> {
    if (this.disposed || this.cancelling || this.state.job?.state !== "reading") return;
    if (this.pending) { this.schedule(); return; }
    const response = await this.request({ action: "poll", bindingHandle: this.binding, jobHandle: this.state.job.jobHandle });
    if (response?.kind === "job" && response.job.state === "completed") await this.rows("", 0);
  }
  cancel = async (): Promise<void> => {
    if (this.cancelling) return;
    this.cancelling = true;
    if (this.timer !== null) clearTimeout(this.timer);
    try {
      await this.pending?.catch(() => undefined);
      if (this.state.job?.state === "reading") await this.request({ action: "cancel", bindingHandle: this.binding, jobHandle: this.state.job.jobHandle });
    } finally { this.cancelling = false; }
  };
  settle = async (): Promise<void> => { await this.pending?.catch(() => undefined); };
  prepareToLeave = async (confirm: (reason: "unsaved" | "uncertain") => Promise<boolean>): Promise<boolean> => {
    await this.cancel();
    if (this.disposed) return false;
    if (this.state.job?.state === "reading") return await confirm("uncertain") && !this.disposed;
    if (!this.hasUnsaved()) return true;
    const id = this.state.job!.jobHandle;
    if (!(await confirm("unsaved")) || this.disposed || this.state.job?.jobHandle !== id) return false;
    await this.discard(); return !this.disposed && !this.hasUnsaved();
  };
  private async abandon(job: PostgresqlRuntimeJob): Promise<void> {
    try { await this.exchange({ action: "cancel", bindingHandle: this.binding, jobHandle: job.jobHandle }); } catch { /* Core still enforces its 40 second deadline. */ }
  }
  dispose = (): void => {
    if (this.disposed) return;
    this.disposed = true;
    if (this.expiry !== null) clearTimeout(this.expiry);
    if (this.timer !== null) clearTimeout(this.timer);
    if (this.state.job?.state === "reading") void this.abandon(this.state.job);
    this.listeners.clear();
  };
}
