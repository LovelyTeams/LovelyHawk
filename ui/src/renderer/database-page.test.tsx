import { unavailableObjects } from "../shared/postgresql-object-fixture.test-support";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { DatabasePage, PostgresqlObservationPanel, runtimeValue } from "./DatabasePage";
import { isPostgresqlRuntimeResponse, postgresqlPathNames, postgresqlReviewNames, type PostgresqlSessionObservation } from "../shared/postgresql-runtime-contract";
describe("Database page", () => {
  it("has an honest disconnected state and exposes the expert view without inventing results", () => {
    const api = { postgresqlRuntime: vi.fn() };
    const html = renderToStaticMarkup(<DatabasePage api={api} bindingHandle={null} targetLabel="未连接主机" />);
    expect(html).toContain("请先连接 SSH 主机"); expect(html).toContain("专家详情"); expect(html).not.toContain("读取完成"); expect(api.postgresqlRuntime).not.toHaveBeenCalled();
  });
  it("escapes target text and names protected empty values explicitly", () => {
    const html = renderToStaticMarkup(<DatabasePage api={{ postgresqlRuntime: vi.fn() }} bindingHandle={null} targetLabel={'<img src=x onerror="bad">'} />);
    expect(html).toContain("&lt;img"); expect(html).not.toContain("<img");
    expect(runtimeValue({ name: "password", value: null, sensitivity: "redacted", presence: "empty", context: "user", source: null, pendingRestart: false, minimum: null, maximum: null, enumValues: [], metadataTruncated: false })).toBe("空值（已保护）");
  });
  it("shows role-hidden parameters to beginners and refuses inconsistent source gaps", () => {
    const session: PostgresqlSessionObservation = {
      observedAt: "2026-09-08T08:00:00Z", databaseName: "postgres", databaseOid: 5, sessionUser: "audit", effectiveUser: "audit", backendPid: 42,
      serverAddress: "::1", serverPort: 5432, clientAddress: "::1", clientPort: 42000, serverStartedAt: "2026-09-08T00:00:00Z", configurationLoadedAt: "2026-09-08T00:00:00Z",
      inRecovery: false, clusterIdentifierReadable: false, clusterIdentifier: null, settingsReadable: false,
      paths: postgresqlPathNames.map(name => ({ name, path: null })),
      origins: postgresqlReviewNames.map(name => ({ name, source: name.startsWith("ssl_") ? null : "default", sourceFile: null, sourceLine: null, pendingRestart: name.startsWith("ssl_") ? null : false })),
    };
    const html = renderToStaticMarkup(<PostgresqlObservationPanel session={session} expert={false} />);
    expect(html).toContain("2 项重点参数未取得"); expect(html).toContain("ssl_min_protocol_version、ssl_max_protocol_version"); expect(html).toContain("这些项目仍需核实"); expect(html).toContain("[::1]:5432");
    const profile = { profileHandle: "p", name: "audit", host: "::1", port: 5432, username: "audit", database: "postgres", tlsMode: "verify-full", hasPassword: true, hasCa: false, unassigned: false };
    const result = { version: "16.15", tlsMode: "verify-full", parameterCount: 300, noticeCount: 0, access: { hba: { state: "available", reason: null, total: 0, flagged: 0, findings: [] }, ident: { state: "available", reason: null, total: 0, flagged: 0, findings: [] }, roles: { state: "available", reason: null, total: 0, flagged: 0, findings: [] }, memberships: { state: "unavailable", reason: "permission-denied", total: null, flagged: null, findings: [] }, objects: unavailableObjects(), roleGraph: { state: "unavailable", reason: "memberships-unavailable", database: null, additionalManagementLogins: null }, passwordClassification: false }, observations: [], session, hostProcess: { state: "unavailable", reason: "unsupported", process: null } };
    const job = { jobHandle: "j", profile, targetLabel: "lab", state: "completed", startedAt: session.observedAt, finishedAt: session.observedAt, detail: "读取完成", retention: null, result };
    expect(isPostgresqlRuntimeResponse({ kind: "job", job })).toBe(true);
    for (const change of [{ sourceFile: "/unexpected.conf" }, { pendingRestart: false }]) {
      const origins = session.origins.map(item => item.name === "ssl_min_protocol_version" ? { ...item, ...change } : item);
      expect(isPostgresqlRuntimeResponse({ kind: "job", job: { ...job, result: { ...result, session: { ...session, origins } } } })).toBe(false);
    }
  });
});
