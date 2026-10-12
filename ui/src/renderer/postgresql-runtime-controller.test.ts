import { objectRow, objectPage, objectDetail, unavailableObjects } from "../shared/postgresql-object-fixture.test-support";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { PostgresqlRuntimeResponse } from "../shared/postgresql-runtime-contract";
import { PostgresqlRuntimeController } from "./postgresql-runtime-controller";
const session = { observedAt: "2026-09-07T08:00:00Z", databaseName: "postgres", databaseOid: 5, sessionUser: "audit", effectiveUser: "audit", backendPid: 42, serverAddress: "127.0.0.1", serverPort: 5432, clientAddress: "127.0.0.1", clientPort: 42000, serverStartedAt: "2026-09-07T00:00:00Z", configurationLoadedAt: "2026-09-07T00:00:00Z", inRecovery: false, clusterIdentifierReadable: false, clusterIdentifier: null, settingsReadable: false,
  paths: ["config_file", "data_directory", "hba_file", "ident_file"].map(name => ({ name, path: null })),
  origins: ["ssl", "logging_collector", "log_connections", "log_disconnections", "password_encryption", "log_statement", "listen_addresses", "ssl_min_protocol_version", "ssl_max_protocol_version", "default_transaction_read_only"].map(name => ({ name, source: "default", sourceFile: null, sourceLine: null, pendingRestart: false })) };
const hostProcess = { state: "unavailable", reason: "unsupported", process: null } as const;
const profile = { profileHandle: "p", name: "test", host: "127.0.0.1", port: 5432, username: "audit", database: "postgres", tlsMode: "verify-full", hasPassword: true, hasCa: false, unassigned: false } as const;
const job = { jobHandle: "j", profile, targetLabel: "root@lab", state: "reading", startedAt: "2026-09-07T08:00:00Z", finishedAt: null, detail: "reading", result: null, retention: null } as const;
afterEach(() => vi.useRealTimers());
describe("PostgreSQL review lifecycle", () => {
  it("does not trap navigation after the target is lost and cancellation cannot be verified", async () => {
    const pending = { state: "pending", caseId: "case", caseTitle: "case", evidenceId: null, sha256: null, canRetry: false, detail: "pending", recordText: null };
    const api = { postgresqlRuntime: vi.fn().mockResolvedValueOnce({ kind: "profiles", profiles: [profile] }).mockResolvedValueOnce({ kind: "job", job: { ...job, retention: pending } })
      .mockResolvedValue({ kind: "rejected", action: "cancel", code: "stale", detail: "target lost" }) };
    const controller = new PostgresqlRuntimeController(api, "b"); await controller.list(); await controller.begin(true);
    const confirm = vi.fn().mockResolvedValueOnce(false).mockResolvedValueOnce(true);
    expect(await controller.prepareToLeave(confirm)).toBe(false); expect(confirm).toHaveBeenLastCalledWith("uncertain");
    expect(controller.getSnapshot().job?.state).toBe("reading");
    expect(await controller.prepareToLeave(confirm)).toBe(true); expect(controller.getSnapshot().job?.retention?.state).toBe("pending");
    controller.dispose();
  });
  it("invalidates stale runtime values while preserving an unsaved immutable summary", async () => {
    const retention = { state: "unsaved", caseId: "case", caseTitle: "case", evidenceId: null, sha256: null, canRetry: true, detail: "unsaved", recordText: "original summary" };
    const completed = { ...job, state: "completed", finishedAt: job.startedAt, result: { version: "16.15", tlsMode: "verify-full", parameterCount: 0, noticeCount: 0, access: { hba: { state: "available", reason: null, total: 0, flagged: 0, findings: [] }, ident: { state: "available", reason: null, total: 0, flagged: 0, findings: [] }, roles: { state: "available", reason: null, total: 0, flagged: 0, findings: [] }, memberships: { state: "unavailable", reason: "permission-denied", total: null, flagged: null, findings: [] }, objects: unavailableObjects(), roleGraph: { state: "unavailable", reason: "memberships-unavailable", database: null, additionalManagementLogins: null }, passwordClassification: false }, observations: [], session, hostProcess }, retention };
    const api = { postgresqlRuntime: vi.fn().mockResolvedValueOnce({ kind: "profiles", profiles: [profile] }).mockResolvedValueOnce({ kind: "job", job: completed })
      .mockResolvedValueOnce({ kind: "rejected", action: "rows", code: "stale", detail: "stale" }) };
    const controller = new PostgresqlRuntimeController(api, "b"); await controller.list(); await controller.begin(true);
    expect(controller.getSnapshot().job?.state).toBe("expired"); expect(controller.getSnapshot().job?.result).toBeNull();
    expect(controller.getSnapshot().job?.retention?.recordText).toBe("original summary");
    const confirm = vi.fn().mockResolvedValue(false); expect(await controller.prepareToLeave(confirm)).toBe(false);
    expect(confirm).toHaveBeenCalledWith("unsaved"); controller.dispose();
  });
  it("keeps failed case material across expiry, rejects retargeted retries, and never recollects", async () => {
    vi.useFakeTimers();
    const pending = { state: "pending", caseId: "original-case", caseTitle: "原案件", evidenceId: null, sha256: null, canRetry: false, detail: "pending", recordText: null };
    const unsaved = { ...pending, state: "unsaved", canRetry: true, detail: "save failed", recordText: "original read failed at its original time" };
    const failed = { ...job, state: "failed", finishedAt: job.startedAt, retention: unsaved };
    const saved = { ...unsaved, state: "saved", canRetry: false, detail: "saved", evidenceId: "e", sha256: "a".repeat(64) };
    const api = { postgresqlRuntime: vi.fn().mockResolvedValueOnce({ kind: "profiles", profiles: [profile] })
      .mockResolvedValueOnce({ kind: "job", job: { ...job, retention: pending } }).mockResolvedValueOnce({ kind: "job", job: failed })
      .mockResolvedValueOnce({ kind: "job", job: { ...failed, state: "expired", retention: { ...saved, caseId: "another-case" } } })
      .mockResolvedValueOnce({ kind: "job", job: { ...failed, state: "expired", retention: saved } }) };
    const controller = new PostgresqlRuntimeController(api, "b"); await controller.list(); await controller.begin(true);
    await vi.advanceTimersByTimeAsync(701); expect(controller.hasUnsaved()).toBe(true);
    await controller.begin(); controller.select("another"); expect(controller.getSnapshot().selected).toBe("p");
    await vi.advanceTimersByTimeAsync(600_000); expect(controller.getSnapshot().job?.state).toBe("expired");
    expect(controller.getSnapshot().job?.retention?.recordText).toBe(unsaved.recordText);
    expect(await controller.retain()).toBeNull(); expect(controller.hasUnsaved()).toBe(true);
    expect(controller.getSnapshot().job?.retention?.caseId).toBe("original-case");
    await controller.retain(); expect(controller.getSnapshot().job?.retention?.state).toBe("saved");
    expect(api.postgresqlRuntime.mock.calls.filter(call => call[0].action === "begin")).toHaveLength(1);
    expect(api.postgresqlRuntime.mock.calls.filter(call => call[0].action === "retain")).toHaveLength(2);
    controller.dispose();
  });
  it("waits for pending work before cancelling and retains a failed cancellation record until explicit discard", async () => {
    const pending = { state: "pending", caseId: "case", caseTitle: "case", evidenceId: null, sha256: null, canRetry: false, detail: "pending", recordText: null };
    const cancelled = { ...job, state: "cancelled", finishedAt: job.startedAt, retention: { ...pending, state: "unsaved", canRetry: true, detail: "unsaved", recordText: "cancelled observation" } };
    let resolve!: (value: unknown) => void;
    const api = { postgresqlRuntime: vi.fn().mockResolvedValueOnce({ kind: "profiles", profiles: [profile] }).mockImplementationOnce(() => new Promise(r => { resolve = r; }))
      .mockResolvedValueOnce({ kind: "job", job: cancelled })
      .mockResolvedValueOnce({ kind: "rejected", action: "discard-evidence", code: "busy", detail: "busy" })
      .mockResolvedValueOnce({ kind: "job", job: { ...cancelled, retention: null } }) };
    const controller = new PostgresqlRuntimeController(api, "b"); await controller.list();
    const begin = controller.begin(true); const cancel = controller.cancel();
    expect(api.postgresqlRuntime).toHaveBeenCalledTimes(2);
    resolve({ kind: "job", job: { ...job, retention: pending } }); await begin; await cancel;
    expect(controller.hasUnsaved()).toBe(true); expect(controller.getSnapshot().job?.state).toBe("cancelled");
    await controller.discard(); expect(controller.hasUnsaved()).toBe(true);
    await controller.discard(); expect(controller.hasUnsaved()).toBe(false); controller.dispose();
  });
  it("shows expected domain failures without retaining result data", async () => {
    const api = { postgresqlRuntime: vi.fn().mockResolvedValue({ kind: "rejected", action: "list", code: "stale", detail: "连接已过期，请刷新。" }) };
    const controller = new PostgresqlRuntimeController(api, "b");
    expect(await controller.list()).toBeNull(); expect(controller.getSnapshot().error).toBe("连接已过期，请刷新。");
    expect(controller.getSnapshot().profiles).toEqual([]); controller.dispose();
  });
  it("cancels a late begin result for the original SSH binding when its page was disposed", async () => {
    let resolve!: (value: PostgresqlRuntimeResponse) => void;
    const api = { postgresqlRuntime: vi.fn().mockResolvedValueOnce({ kind: "profiles", profiles: [profile] }).mockImplementationOnce(() => new Promise<PostgresqlRuntimeResponse>(r => { resolve = r; })).mockResolvedValueOnce({ kind: "job", job: { ...job, state: "cancelled", finishedAt: job.startedAt } }) };
    const controller = new PostgresqlRuntimeController(api, "original"); await controller.list();
    const begin = controller.begin(); controller.dispose(); resolve({ kind: "job", job }); await begin;
    expect(api.postgresqlRuntime).toHaveBeenLastCalledWith({ action: "cancel", bindingHandle: "original", jobHandle: "j" });
    expect(controller.getSnapshot().job).toBeNull();
  });
  it("prevents duplicate reads and clears completed evidence when its configuration disappears", async () => {
    const completed = { ...job, state: "completed", finishedAt: job.startedAt, result: { version: "16.15", tlsMode: "verify-full", parameterCount: 0, noticeCount: 0, access: { hba: { state: "available", reason: null, total: 0, flagged: 0, findings: [] }, ident: { state: "available", reason: null, total: 0, flagged: 0, findings: [] }, roles: { state: "available", reason: null, total: 0, flagged: 0, findings: [] }, memberships: { state: "unavailable", reason: "permission-denied", total: null, flagged: null, findings: [] }, objects: unavailableObjects(), roleGraph: { state: "unavailable", reason: "memberships-unavailable", database: null, additionalManagementLogins: null }, passwordClassification: false }, observations: [], session, hostProcess } };
    const api = { postgresqlRuntime: vi.fn().mockResolvedValueOnce({ kind: "profiles", profiles: [profile] }).mockResolvedValueOnce({ kind: "job", job: completed }).mockResolvedValueOnce({ kind: "rows", jobHandle: "j", query: "", offset: 0, total: 0, matched: 0, rows: [] }).mockResolvedValueOnce({ kind: "profiles", profiles: [] }) };
    const controller = new PostgresqlRuntimeController(api, "b"); await controller.list();
    const first = controller.begin(); await controller.begin(); await first;
    expect(api.postgresqlRuntime.mock.calls.filter(call => call[0].action === "begin")).toHaveLength(1);
    expect(controller.getSnapshot().job?.state).toBe("completed"); await controller.list(); expect(controller.getSnapshot().job).toBeNull(); controller.dispose();
  });
  it("refuses another profile's poll response and does not retain stale values", async () => {
    vi.useFakeTimers();
    const api = { postgresqlRuntime: vi.fn().mockResolvedValueOnce({ kind: "profiles", profiles: [profile] }).mockResolvedValueOnce({ kind: "job", job }).mockResolvedValueOnce({ kind: "job", job: { ...job, profile: { ...profile, profileHandle: "other" } } }) };
    const controller = new PostgresqlRuntimeController(api, "b"); await controller.list(); await controller.begin(); await vi.advanceTimersByTimeAsync(701);
    expect(controller.getSnapshot().job).toBeNull(); expect(controller.getSnapshot().error).toContain("已变化"); controller.dispose();
  });
  it("expires displayed results with a monotonic timer without trusting the server timestamp", async () => {
    vi.useFakeTimers();
    const completed = { ...job, state: "completed", finishedAt: "2026-09-07T07:00:00Z", result: { version: "16.15", tlsMode: "verify-full", parameterCount: 0, noticeCount: 0, access: { hba: { state: "available", reason: null, total: 0, flagged: 0, findings: [] }, ident: { state: "available", reason: null, total: 0, flagged: 0, findings: [] }, roles: { state: "available", reason: null, total: 0, flagged: 0, findings: [] }, memberships: { state: "unavailable", reason: "permission-denied", total: null, flagged: null, findings: [] }, objects: unavailableObjects(), roleGraph: { state: "unavailable", reason: "memberships-unavailable", database: null, additionalManagementLogins: null }, passwordClassification: false }, observations: [], session, hostProcess } };
    const api = { postgresqlRuntime: vi.fn().mockResolvedValueOnce({ kind: "profiles", profiles: [profile] }).mockResolvedValueOnce({ kind: "job", job: completed }).mockResolvedValueOnce({ kind: "rows", jobHandle: "j", query: "", offset: 0, total: 0, matched: 0, rows: [] }) };
    const controller = new PostgresqlRuntimeController(api, "b"); await controller.list(); await controller.begin(); expect(controller.getSnapshot().job).not.toBeNull();
    await vi.advanceTimersByTimeAsync(600_001); expect(controller.getSnapshot().job).toBeNull(); expect(controller.getSnapshot().notice).toContain("已过期"); controller.dispose();
  });
  it("clears access pages when their job expires and refuses late diagnostic responses", async () => {
    vi.useFakeTimers();
    const available = { state: "available", reason: null, total: 0, flagged: 0, findings: [] };
    const completed = { ...job, state: "completed", finishedAt: job.startedAt, result: { version: "16.15", tlsMode: "verify-full", parameterCount: 0, noticeCount: 0, observations: [], session, hostProcess, access: { hba: available, ident: available, roles: available, memberships: { state: "unavailable", reason: "permission-denied", total: null, flagged: null, findings: [] }, objects: unavailableObjects(), roleGraph: { state: "unavailable", reason: "memberships-unavailable", database: null, additionalManagementLogins: null }, passwordClassification: false } } };
    let resolve!: (value: unknown) => void;
    const api = { postgresqlRuntime: vi.fn().mockResolvedValueOnce({ kind: "profiles", profiles: [profile] }).mockResolvedValueOnce({ kind: "job", job: completed })
      .mockResolvedValueOnce({ kind: "rows", jobHandle: "j", query: "", offset: 0, total: 0, matched: 0, rows: [] })
      .mockImplementationOnce(() => new Promise(value => { resolve = value; })) };
    const controller = new PostgresqlRuntimeController(api, "b"); await controller.list(); await controller.begin();
    const pending = controller.accessRows("hba", "", 0);
    await vi.advanceTimersByTimeAsync(600_001);
    resolve({ kind: "access-rows", jobHandle: "j", section: "hba", query: "", offset: 0, total: 0, matched: 0, rows: [] });
    await pending;
    expect(controller.getSnapshot().job).toBeNull(); expect(controller.getSnapshot().accessRows).toBeNull();
    expect(controller.getSnapshot().error).toContain("访问诊断结果已变化"); controller.dispose();
  });
  it("accepts diagnostic pages only with the original section count", async () => {
    const available = { state: "available", reason: null, total: 0, flagged: 0, findings: [] };
    const completed = { ...job, state: "completed", finishedAt: job.startedAt, result: { version: "16.15", tlsMode: "verify-full", parameterCount: 0, noticeCount: 0, observations: [], session, hostProcess, access: { hba: available, ident: available, roles: available, memberships: { state: "unavailable", reason: "permission-denied", total: null, flagged: null, findings: [] }, objects: unavailableObjects(), roleGraph: { state: "unavailable", reason: "memberships-unavailable", database: null, additionalManagementLogins: null }, passwordClassification: false } } };
    const api = { postgresqlRuntime: vi.fn().mockResolvedValueOnce({ kind: "profiles", profiles: [profile] }).mockResolvedValueOnce({ kind: "job", job: completed })
      .mockResolvedValueOnce({ kind: "rows", jobHandle: "j", query: "", offset: 0, total: 0, matched: 0, rows: [] })
      .mockResolvedValueOnce({ kind: "access-rows", jobHandle: "j", section: "hba", query: "", offset: 0, total: 0, matched: 0, rows: [] })
      .mockResolvedValueOnce({ kind: "access-rows", jobHandle: "j", section: "hba", query: "missing", offset: 0, total: 1, matched: 0, rows: [] }) };
    const controller = new PostgresqlRuntimeController(api, "b"); await controller.list(); await controller.begin(); await controller.accessRows("hba", "", 0);
    expect(controller.getSnapshot().accessRows?.section).toBe("hba"); await controller.accessRows("hba", "missing", 0);
    expect(controller.getSnapshot().job).toBeNull(); expect(controller.getSnapshot().accessRows).toBeNull(); controller.dispose();
  });

  it("rejects late role paths after expiry and paths from another database owner", async () => {
    vi.useFakeTimers();
    for (const expire of [false,true]) {
      const available = { state: "available", reason: null, total: 0, flagged: 0, findings: [] };
      const database = { oid: session.databaseOid, name: session.databaseName, ownerOid: 1 };
      const completed = { ...job, state: "completed", finishedAt: job.startedAt, result: { version: "16.15", tlsMode: "verify-full", parameterCount: 0, noticeCount: 0, observations: [], session, hostProcess,
        access: { hba: available, ident: available, roles: { ...available, total: 2 }, memberships: available, objects: unavailableObjects(), roleGraph: { state: "available", reason: null, database, additionalManagementLogins: 0 }, passwordClassification: false } } };
      let resolve!: (value: unknown) => void;
      const api = { postgresqlRuntime: vi.fn().mockResolvedValueOnce({ kind: "profiles", profiles: [profile] }).mockResolvedValueOnce({ kind: "job", job: completed })
        .mockResolvedValueOnce({ kind: "rows", jobHandle: "j", query: "", offset: 0, total: 0, matched: 0, rows: [] }).mockImplementationOnce(() => new Promise(value => { resolve = value; })) };
      const controller = new PostgresqlRuntimeController(api,"b"); await controller.list(); await controller.begin();
      const pending = controller.roleAccess(1,"set","",0);
      if (expire) await vi.advanceTimersByTimeAsync(600_001);
      const source = { oid: 1, name: "login", canLogin: true, superuser: false, createRole: false, createDatabase: false, replication: false, bypassRls: false };
      resolve({ kind: "role-access", jobHandle: "j", roleOid: 1, source, database: { ...database, ownerOid: expire ? 1 : 2 }, mode: "set", query: "", offset: 0, total: 0, matched: 0, rows: [] });
      await pending;
      expect(controller.getSnapshot().rolePage).toBeNull(); expect(controller.getSnapshot().job).toBeNull(); expect(controller.getSnapshot().error).toContain("角色权限来源已变化"); controller.dispose();
    }
  });

  it("correlates object identity and discards late detail results while retaining unsaved case material", async () => {
    vi.useFakeTimers();
    for (const expire of [false,true]) {
      const available = { state: "available", reason: null, total: 0, flagged: 0, findings: [] };
      const objects = unavailableObjects(); objects.relations = { state: "available", reason: null, total: 1, omittedDefaults: 0, publicObjects: 1, delegatedObjects: 0, securityDefiners: 0, unfixedDefiners: 0 };
      const retention = { state: "unsaved", caseId: "case", caseTitle: "Original", evidenceId: null, sha256: null, canRetry: true, detail: "storage failed", recordText: "original immutable summary" };
      const completed = { ...job, state: "completed", finishedAt: job.startedAt, retention, result: { version: "16.15", tlsMode: "verify-full", parameterCount: 0, noticeCount: 0, observations: [], session, hostProcess,
        access: { hba: available, ident: available, roles: available, memberships: available, objects, roleGraph: { state: "unavailable", reason: "memberships-unavailable", database: null, additionalManagementLogins: null }, passwordClassification: false } } };
      let resolve!: (value: unknown) => void;
      const api = { postgresqlRuntime: vi.fn().mockResolvedValueOnce({ kind: "profiles", profiles: [profile] }).mockResolvedValueOnce({ kind: "job", job: completed })
        .mockResolvedValueOnce({ kind: "rows", jobHandle: "j", query: "", offset: 0, total: 0, matched: 0, rows: [] }).mockResolvedValueOnce(objectPage).mockImplementationOnce(() => new Promise(value => { resolve = value; })) };
      const controller = new PostgresqlRuntimeController(api,"b"); await controller.list(); await controller.begin(true); await controller.objectRows("relations","","all",0);
      expect(controller.getSnapshot().objectPage).toEqual(objectPage);
      const pending = controller.objectDetail("relations",18000,0,null);
      if (expire) await vi.advanceTimersByTimeAsync(600_001);
      resolve(expire ? objectDetail : { ...objectDetail, object: { ...objectRow, name: "changed identity" } }); await pending;
      expect(controller.getSnapshot().objectDetail).toBeNull(); expect(controller.getSnapshot().objectPage).toBeNull();
      expect(controller.getSnapshot().job?.retention).toEqual(retention); expect(controller.getSnapshot().job?.state).toBe("expired"); expect(controller.getSnapshot().error).toContain("对象或角色身份已变化"); controller.dispose();
    }
  });

});
