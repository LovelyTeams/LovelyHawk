import { unavailableObjects } from "../shared/postgresql-object-fixture.test-support";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { isPostgresqlRuntimeResponse, postgresqlPathNames, postgresqlReviewNames, type PostgresqlHostProcess } from "../shared/postgresql-runtime-contract";
import { PostgresqlHostProcessPanel } from "./PostgresqlHostProcessPanel";

const process: PostgresqlHostProcess = { observedAt: "2026-09-08T08:00:00Z", bootId: "c1bf0d9c-bcbc-44e4-a3f5-52cc0857c4a7", backendPid: 42, backendStartTicks: "2000", postmasterPid: 8, postmasterStartTicks: "1000", socketInode: "121", pidNamespace: "4026531840", networkNamespace: "4026531841", mountNamespace: "4026531842", executablePath: "/usr/bin/postgres", executableDevice: "0", executableInode: "151", executableSha256: "a".repeat(64), dataDirectory: "/srv/pg", reportedDirectoryMatches: true };
const session = { observedAt: process.observedAt, databaseName: "postgres", databaseOid: 5, sessionUser: "audit", effectiveUser: "audit", backendPid: 42, serverAddress: "::1", serverPort: 5432, clientAddress: "::1", clientPort: 42000, serverStartedAt: process.observedAt, configurationLoadedAt: process.observedAt, inRecovery: false, clusterIdentifierReadable: false, clusterIdentifier: null, settingsReadable: true, paths: postgresqlPathNames.map(name => ({ name, path: name === "data_directory" ? "/srv/pg" : null })), origins: postgresqlReviewNames.map(name => ({ name, source: "default", sourceFile: null, sourceLine: null, pendingRestart: false })) };
const profile = { profileHandle: "p", name: "audit", host: "::1", port: 5432, username: "audit", database: "postgres", tlsMode: "verify-full", hasPassword: true, hasCa: false, unassigned: false };
const result = { version: "16.15", tlsMode: "verify-full", parameterCount: 300, noticeCount: 0, access: { hba: { state: "available", reason: null, total: 0, flagged: 0, findings: [] }, ident: { state: "available", reason: null, total: 0, flagged: 0, findings: [] }, roles: { state: "available", reason: null, total: 0, flagged: 0, findings: [] }, memberships: { state: "unavailable", reason: "permission-denied", total: null, flagged: null, findings: [] }, objects: unavailableObjects(), roleGraph: { state: "unavailable", reason: "memberships-unavailable", database: null, additionalManagementLogins: null }, passwordClassification: false }, observations: [], session, hostProcess: { state: "matched", reason: null, process } };
const job = { jobHandle: "j", profile, targetLabel: "lab", state: "completed", startedAt: process.observedAt, finishedAt: process.observedAt, detail: "读取完成", retention: null, result };

describe("PostgreSQL host process correspondence", () => {
  it("ties complete, bounded evidence to this SQL backend and its reported directory", () => {
    expect(isPostgresqlRuntimeResponse({ kind: "job", job })).toBe(true);
    for (const change of [{ backendPid: 43 }, { postmasterPid: 42 }, { postmasterStartTicks: "2001" }, { socketInode: "18446744073709551616" }, { networkNamespace: "01" }, { executablePath: "/x\u0000" }, { dataDirectory: "/other" }, { reportedDirectoryMatches: null }, { command: "untrusted" }]) {
      expect(isPostgresqlRuntimeResponse({ kind: "job", job: { ...job, result: { ...result, hostProcess: { ...result.hostProcess, process: { ...process, ...change } } } } })).toBe(false);
    }
    for (const key of Object.keys(process)) {
      const partial = { ...process } as Record<string, unknown>; delete partial[key];
      expect(isPostgresqlRuntimeResponse({ kind: "job", job: { ...job, result: { ...result, hostProcess: { ...result.hostProcess, process: partial } } } })).toBe(false);
    }
    expect(isPostgresqlRuntimeResponse({ kind: "job", job: { ...job, result: { ...result, session: { ...session, serverAddress: null, serverPort: null } } } })).toBe(false);
  });
  it("keeps unavailable checks distinct from matched processes and only expands expert evidence on request", () => {
    const unavailable = renderToStaticMarkup(<PostgresqlHostProcessPanel inspection={{ state: "unavailable", reason: "permission-denied", process: null }} expert={false} />);
    expect(unavailable).toContain("尚未对应到 SSH 主机实例"); expect(unavailable).toContain("参数仍可独立查看"); expect(unavailable).not.toContain("已对应到 SSH 主机上的连接进程");
    const basic = renderToStaticMarkup(<PostgresqlHostProcessPanel inspection={{ state: "matched", reason: null, process }} expert={false} />);
    expect(basic).toContain("已对应到 SSH 主机上的连接进程"); expect(basic).not.toContain(process.executableSha256);
    const expert = renderToStaticMarkup(<PostgresqlHostProcessPanel inspection={{ state: "matched", reason: null, process: { ...process, executablePath: "/srv/<img src=x>", reportedDirectoryMatches: false } }} expert />);
    expect(expert).toContain("目录不一致"); expect(expert).toContain("&lt;img"); expect(expert).not.toContain("<img"); expect(expert).toContain(process.executableSha256); expect(expert).not.toContain("<details open");
  });
});
