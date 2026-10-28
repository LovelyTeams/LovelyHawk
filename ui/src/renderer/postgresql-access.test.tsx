import { unavailableObjects } from "../shared/postgresql-object-fixture.test-support";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { isPostgresqlAccessPage, isPostgresqlAccessSummary, type PostgresqlAccessPage, type PostgresqlAccessSummary, type PostgresqlHbaRow } from "../shared/postgresql-access-contract";
import { matchesPostgresqlRuntimeResponse } from "../shared/postgresql-runtime-contract";
import { PostgresqlAccessPanel, PostgresqlAccessTable } from "./PostgresqlAccessPanel";

const row: PostgresqlHbaRow = { ruleNumber: 1, fileName: "/srv/pg/<img src=x>.conf", lineNumber: 8, connectionType: "host", databases: ["all"], users: ["role"], address: "127.0.0.1", netmask: "255.255.255.255", method: "trust", optionNames: [], hasIssue: false, findings: ["trust"] };
const page: PostgresqlAccessPage = { kind: "access-rows", jobHandle: "j", section: "hba", query: "", offset: 0, total: 1, matched: 1, rows: [row] };
const summary: PostgresqlAccessSummary = {
  hba: { state: "available", reason: null, total: 1, flagged: 1, findings: [{ code: "trust", count: 1 }] },
  ident: { state: "available", reason: null, total: 0, flagged: 0, findings: [] },
  roles: { state: "unavailable", reason: "permission-denied", total: null, flagged: null, findings: [] }, memberships: { state: "unavailable", reason: "permission-denied", total: null, flagged: null, findings: [] }, objects: unavailableObjects(), roleGraph: { state: "unavailable", reason: "memberships-unavailable", database: null, additionalManagementLogins: null }, passwordClassification: false,
};
describe("PostgreSQL access diagnostics boundary and scope", () => {
  it("refuses secret fields, incomplete rows, wrong counts and another section's response", () => {
    expect(isPostgresqlAccessPage(page)).toBe(true);
    for (const change of [{ options: ["ldapbindpasswd=canary"] }, { error: "canary" }, { optionNames: ["ldapbindpasswd=canary"] }, { findings: ["md5-verifier"] }, { findings: ["trust", "trust"] }, { users: [] }, { lineNumber: 0 }]) {
      expect(isPostgresqlAccessPage({ ...page, rows: [{ ...row, ...change }] })).toBe(false);
    }
    for (const key of Object.keys(row)) {
      const partial = { ...row } as Record<string, unknown>; delete partial[key];
      expect(isPostgresqlAccessPage({ ...page, rows: [partial] })).toBe(false);
    }
    for (const change of [{ fingerprint: "a".repeat(64) }, { total: 513 }, { matched: 2 }, { rows: [] }, { section: "roles" }]) expect(isPostgresqlAccessPage({ ...page, ...change })).toBe(false);
    expect(matchesPostgresqlRuntimeResponse({ action: "access-rows", bindingHandle: "b", jobHandle: "j", section: "hba", query: "", offset: 0 }, page)).toBe(true);
    for (const change of [{ jobHandle: "other" }, { section: "ident" as const }, { query: "role" }, { offset: 50 }]) {
      expect(matchesPostgresqlRuntimeResponse({ action: "access-rows", bindingHandle: "b", jobHandle: "j", section: "hba", query: "", offset: 0, ...change }, page)).toBe(false);
    }
  });
  it("keeps permission gaps and count summaries exact", () => {
    expect(isPostgresqlAccessSummary(summary)).toBe(true);
    for (const change of [{ total: 0 }, { flagged: 2 }, { findings: [] }, { findings: [{ code: "trust", count: 2 }] }, { fingerprint: "private" }]) {
      expect(isPostgresqlAccessSummary({ ...summary, hba: { ...summary.hba, ...change } })).toBe(false);
    }
    for (const change of [{ total: 0 }, { flagged: 0 }, { reason: "unknown" }, { findings: [{ code: "login-superuser", count: 1 }] }]) {
      expect(isPostgresqlAccessSummary({ ...summary, roles: { ...summary.roles, ...change } })).toBe(false);
    }
    expect(isPostgresqlAccessSummary({ ...summary, passwordClassification: true })).toBe(false);
  });
  it("explains missing access for novices and renders expert data as inert text", () => {
    const onRead = vi.fn();
    const basic = renderToStaticMarkup(<PostgresqlAccessPanel summary={summary} page={null} busy={false} expert={false} onRead={onRead} />);
    expect(basic).toContain("已读取 1 项"); expect(basic).toContain("当前账号没有读取权限"); expect(basic).toContain("尚未证明已加载生效");
    expect(basic).not.toContain("访问诊断详情"); expect(basic).not.toContain("<table"); expect(onRead).not.toHaveBeenCalled();
    const detailed = renderToStaticMarkup(<PostgresqlAccessPanel summary={summary} page={page} busy={false} expert onRead={onRead} />);
    expect(detailed).toContain("丢失部分原始引号"); expect(detailed).toContain("未存储口令仍可能通过其他认证方式登录");
    expect(detailed).toContain("&lt;img"); expect(detailed).not.toContain("<img"); expect(detailed).toContain("trust");
    const empty = renderToStaticMarkup(<PostgresqlAccessTable page={{ ...page, query: "missing", matched: 0, rows: [] }} />);
    expect(empty).toContain("当前搜索没有匹配记录"); expect(empty).toContain("不构成安全结论");
  });
});
