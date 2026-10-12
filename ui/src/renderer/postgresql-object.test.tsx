import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { isPostgresqlObjectDetail, isPostgresqlObjectPage, isPostgresqlObjectsSummary } from "../shared/postgresql-object-contract";
import { matchesPostgresqlRuntimeResponse } from "../shared/postgresql-runtime-contract";
import { objectRow, objectPage, objectDetail, unavailableObjects } from "../shared/postgresql-object-fixture.test-support";
import { PostgresqlObjectPanel } from "./PostgresqlObjectPanel";

describe("PostgreSQL object authorization boundary and presentation", () => {
  it("requires complete bounded metadata and keeps secrets out of every object and ACL layer", () => {
    expect(isPostgresqlObjectPage(objectPage)).toBe(true); expect(isPostgresqlObjectDetail(objectDetail)).toBe(true);
    for (const key of Object.keys(objectRow)) {
      const partial = { ...objectRow } as Record<string,unknown>; delete partial[key];
      expect(isPostgresqlObjectPage({ ...objectPage, rows: [partial] })).toBe(false);
    }
    for (const change of [{ fingerprint: "private" }, { oid: "18000" }, { detail: { ...objectRow.detail, prosrc: "private" } }, { namespaceOid: null }, { publicPrivileges: ["EXECUTE"] }, { grantCount: 129 }, { catalogWriteRestricted: true }]) expect(isPostgresqlObjectPage({ ...objectPage, rows: [{ ...objectRow, ...change }] })).toBe(false);
    for (const change of [{ privileges: [] }, { grantOptions: ["SELECT"] }, { privileges: ["EXECUTE"] }, { options: ["private"] }, { granteeName: "someone" }, { via: "inherit" }]) expect(isPostgresqlObjectDetail({ ...objectDetail, grants: [{ ...objectDetail.grants[0], ...change }] })).toBe(false);
    for (const change of [{ total: 2049 }, { matched: 2 }, { filter: "delegated" }, { rows: [objectRow,objectRow], total: 2, matched: 2 }]) expect(isPostgresqlObjectPage({ ...objectPage, ...change })).toBe(false);
  });
  it("separates absent coverage and future creation rules from existing-object permissions", () => {
    const summary = unavailableObjects(); expect(isPostgresqlObjectsSummary(summary)).toBe(true);
    expect(isPostgresqlObjectsSummary({ ...summary, relations: { ...summary.relations, total: 0 } })).toBe(false);
    expect(isPostgresqlObjectsSummary({ ...summary, defaults: { state: "available", reason: null, total: 1, publicObjects: 0, delegatedObjects: 0, omittedDefaults: 1, securityDefiners: 0, unfixedDefiners: 0 } })).toBe(false);
    const future = { ...objectDetail, section: "defaults", object: { ...objectRow, name: null, namespaceOid: null, namespaceName: null, detail: { kind: "default", objectType: "r" }, aclSource: "future-global" }, grants: [{ ...objectDetail.grants[0], via: "future-default" }] };
    expect(isPostgresqlObjectDetail(future)).toBe(true);
    expect(isPostgresqlObjectDetail({ ...future, roleOid: 10 })).toBe(false);
    expect(isPostgresqlObjectDetail({ ...future, object: { ...future.object, aclSource: "builtin-default" } })).toBe(false);
  });
  it("correlates object, selected role, page, and filter with the exact request", () => {
    const request = { action: "object-detail", bindingHandle: "b", jobHandle: "j", section: "relations", oid: 18000, subId: 0, roleOid: null } as const;
    expect(matchesPostgresqlRuntimeResponse(request,objectDetail)).toBe(true);
    for (const change of [{ oid: 18001 }, { subId: 1 }, { roleOid: 10 }, { section: "columns" as const }, { jobHandle: "other" }]) expect(matchesPostgresqlRuntimeResponse({ ...request, ...change },objectDetail)).toBe(false);
    expect(matchesPostgresqlRuntimeResponse({ action: "object-rows", bindingHandle: "b", jobHandle: "j", section: "relations", query: "", filter: "public", offset: 0 },objectPage)).toBe(false);
  });
  it("shows actionable object controls, explicit analysis limits and escaped remote names", () => {
    const summary = unavailableObjects(); summary.relations = { state: "available", reason: null, total: 1, publicObjects: 1, delegatedObjects: 0, omittedDefaults: 0, securityDefiners: 0, unfixedDefiners: 0 };
    const html = renderToStaticMarkup(<PostgresqlObjectPanel summary={summary} source={null} page={objectPage} detail={objectDetail} busy={false} onRead={() => {}} onDetail={() => {}} />);
    expect(html).toContain("查看授权"); expect(html).toContain("对象类别"); expect(html).toContain("&lt;script&gt;fixture&lt;/script&gt;"); expect(html).not.toContain("<script>");
    for (const scope of ["未分析函数正文", "行级安全标志", "两次采集一致不能当作事务快照", "以后创建对象的默认授权"]) expect(html).toContain(scope);
  });
});
