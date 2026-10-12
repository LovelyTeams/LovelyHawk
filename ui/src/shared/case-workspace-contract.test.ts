import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { BACKEND_PROTOCOL, isBootstrapResult } from "./contract";
import { isCaseWorkspaceRequest, matchesCaseWorkspaceResult, type CaseWorkspaceRequest } from "./case-workspace-contract";

describe("case workspace closed contract", () => {
  it("accepts the real backend page inventory so a new page cannot break startup unnoticed", () => {
    const source = readFileSync(new URL("../../../crates/lovelyhawk-backend/src/lib.rs", import.meta.url), "utf8").replaceAll("\r\n", "\n");
    const registry = source.split("fn page_descriptors() -> Vec<PageDescriptor> {")[1]?.split("\n}\n")[0];
    expect(registry).toBeDefined();
    const ids = [...registry!.matchAll(/id: "([^"]+)"/gu)].map((match) => match[1]!);
    expect(ids).toContain("case-workspace");
    const payload = { productName: "LovelyHawk", appVersion: "test", protocolVersion: BACKEND_PROTOCOL, securityReferenceFavoriteIds: [],
      pages: ids.map((id) => ({ id, title: id, icon: "", summary: "", primaryAction: "", group: "investigation", capability: "connected-target", migrationState: "ready", sections: [] })) };
    expect(isBootstrapResult(payload)).toBe(true);
    expect(isBootstrapResult({ ...payload, pages: payload.pages.filter((page) => page.id !== "case-workspace") })).toBe(false);
  });
  it("rejects injected identity, provenance and paths and bounds Unicode input", () => {
    const note = { action: "note", bindingHandle: "binding", caseId: "case", title: "调查", content: "😀".repeat(4096) };
    expect(isCaseWorkspaceRequest(note)).toBe(true);
    for (const value of [{ ...note, content: "😀".repeat(4097) }, { ...note, content: "\ud800" }, { ...note, bindingHandle: "汉".repeat(60) },
      ...["target", "path", "sha256", "operationId", "command", "source"].map((key) => ({ ...note, [key]: "injected" })),
      { action: "__proto__", bindingHandle: "b" }, { ...note, caseId: "case\u0085" }]) expect(isCaseWorkspaceRequest(value)).toBe(false);
    expect(isCaseWorkspaceRequest({ action: "create", bindingHandle: "b", title: "调查", mutationId: "create-replay-001" })).toBe(true);
    expect(isCaseWorkspaceRequest({ action: "attach-note", bindingHandle: "b", caseId: "c", noteId: "n", revision: "a".repeat(64) })).toBe(true);
  });
  it("requires correct case, page scope and complete counts", () => {
    const incident = { id: "case", title: "<script>literal</script>", status: "open", createdAt: 1, updatedAt: 2, evidenceCount: 0, iocCount: 0, timelineCount: 1 };
    const view: CaseWorkspaceRequest = { action: "view", bindingHandle: "b", caseId: "case" };
    expect(matchesCaseWorkspaceResult(view, { kind: "view", incident, snapshotHandle: "s" })).toBe(true);
    expect(matchesCaseWorkspaceResult({ ...view, caseId: "other" }, { kind: "view", incident, snapshotHandle: "s" })).toBe(false);
    const request: CaseWorkspaceRequest = { action: "items", bindingHandle: "b", snapshotHandle: "s", section: "evidence", query: "x", offset: 0 };
    const page = { kind: "items", snapshotHandle: "s", section: "evidence", query: "x", offset: 0, total: 0, hasMore: false, items: [] };
    expect(matchesCaseWorkspaceResult(request, page)).toBe(true);
    for (const patch of [{ snapshotHandle: "old" }, { section: "iocs" }, { query: "old" }, { total: 1 }, { hasMore: true }, { path: "C:/private" }]) expect(matchesCaseWorkspaceResult(request, { ...page, ...patch })).toBe(false);
    const list = { kind: "list", cases: [incident], activeCaseId: "case", totalCases: 1 };
    expect(matchesCaseWorkspaceResult({ action: "list", bindingHandle: "b" }, list)).toBe(true);
    expect(matchesCaseWorkspaceResult({ action: "list", bindingHandle: "b" }, { ...list, cases: [{ ...incident, status: "closed" }] })).toBe(false);
  });
});
