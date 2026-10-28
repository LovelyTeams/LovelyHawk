import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { isPostgresqlRolePage, type PostgresqlRolePage, type RoleAttributes, type RoleGraphSummary } from "../shared/postgresql-role-contract";
import { matchesPostgresqlRuntimeResponse } from "../shared/postgresql-runtime-contract";
import { isPostgresqlAccessPage } from "../shared/postgresql-access-contract";
import { PostgresqlRolePanel } from "./PostgresqlRolePanel";
const source: RoleAttributes = { oid: 1, name: "login", canLogin: true, superuser: false, createRole: false, createDatabase: false, replication: false, bypassRls: false };
const target = { ...source, oid: 2, name: "<img src=x>", canLogin: false, superuser: true };
const database = { oid: 5, name: "postgres", ownerOid: 1 };
const page: PostgresqlRolePage = { kind: "role-access", jobHandle: "j", roleOid: 1, source, database, mode: "inherit", query: "", offset: 0, total: 1, matched: 1,
  rows: [{ target, hops: 1, truncated: false, steps: [{ role: { oid: 1, name: source.name }, via: "source", grantOid: null, operation: null }, { role: { oid: 2, name: target.name }, via: "grant", grantOid: 10, operation: "inherit" }] }] };
const summary: RoleGraphSummary = { state: "available", reason: null, database, additionalManagementLogins: 0 };
describe("PostgreSQL role path boundary and explanation", () => {
  it("rejects incomplete, foreign, unbounded and structurally invalid routes", () => {
    expect(isPostgresqlRolePage(page)).toBe(true);
    for (const change of [{ roleOid: 2 }, { mode: "admin" }, { total: 1024 }, { rows: [] }, { query: "\0" }, { command: "SET ROLE" }]) expect(isPostgresqlRolePage({ ...page, ...change })).toBe(false);
    const row = page.rows[0]!;
    for (const change of [{ hops: 2 }, { truncated: true }, { target: source }, { grantorPassword: "secret" }, { steps: [...row.steps, row.steps[0]] }]) expect(isPostgresqlRolePage({ ...page, rows: [{ ...row, ...change }] })).toBe(false);
    for (const change of [{ grantOid: null }, { via: "database-owner", grantOid: null }, { via: "superuser", grantOid: null }, { operation: "set" }, { role: { oid: 3, name: target.name } }]) expect(isPostgresqlRolePage({ ...page, rows: [{ ...row, steps: [row.steps[0], { ...row.steps[1], ...change }] }] })).toBe(false);
    for (const key of Object.keys(page)) { const partial = { ...page } as Record<string, unknown>; delete partial[key]; expect(isPostgresqlRolePage(partial)).toBe(false); }
    const request = { action: "role-access", bindingHandle: "b", jobHandle: "j", roleOid: 1, mode: "inherit", query: "", offset: 0 } as const;
    expect(matchesPostgresqlRuntimeResponse(request,page)).toBe(true);
    for (const change of [{ jobHandle: "other" }, { query: "other" }, { roleOid: 2 }, { offset: 20 }, { mode: "set" as const }]) expect(matchesPostgresqlRuntimeResponse({ ...request, ...change },page)).toBe(false);
  });
  it("validates each raw membership option and refuses unexpected secret fields", () => {
    const row = { oid: 10, memberOid: 1, roleOid: 2, grantorOid: 3, memberName: "login", roleName: "target", grantorName: null, adminOption: true, inheritOption: false, setOption: true, findings: ["membership-admin"] };
    const memberships = { kind: "access-rows", jobHandle: "j", section: "memberships", query: "", offset: 0, matched: 1, total: 1, rows: [row] };
    expect(isPostgresqlAccessPage(memberships)).toBe(true);
    for (const change of [{ roleOid: 1 }, { adminOption: "true" }, { grantorOid: 0 }, { roleName: "\0" }, { password: "secret" }]) expect(isPostgresqlAccessPage({ ...memberships, rows: [{ ...row, ...change }] })).toBe(false);
    for (const key of Object.keys(row)) { const partial = { ...row } as Record<string, unknown>; delete partial[key]; expect(isPostgresqlAccessPage({ ...memberships, rows: [partial] })).toBe(false); }
  });
  it("keeps novice paths visible, renders names as text and explains management scope", () => {
    const onRead = vi.fn();
    const html = renderToStaticMarkup(<PostgresqlRolePanel summary={summary} source={source} page={page} busy={false} onRead={onRead} />);
    expect(html).toContain("自动继承的普通权限来源"); expect(html).toContain("不随普通权限继承");
    expect(html).toContain("&lt;img"); expect(html).not.toContain("<img"); expect(html).toContain("不会执行 SET ROLE"); expect(onRead).not.toHaveBeenCalled();
    const gap = renderToStaticMarkup(<PostgresqlRolePanel summary={{ state: "unavailable", reason: "memberships-unavailable", database: null, additionalManagementLogins: null }} source={source} page={null} busy={false} />);
    expect(gap).toContain("成员授权未完整取得"); expect(gap).toContain("不表示没有权限关联"); expect(gap).not.toContain("<table");
  });
});
