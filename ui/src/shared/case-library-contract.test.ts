import { describe, expect, it } from "vitest";
import { isCaseLibraryRequest, matchesCaseLibraryResult, type CaseLibraryRequest } from "./case-library-contract";
const incident = { id: "case", title: "literal <script>", status: "open", createdAt: 1, updatedAt: 2, evidenceCount: 31, iocCount: 0, timelineCount: 32 };
const item = { itemHandle: "item", incident, targetId: "saved-target", connectionName: null, location: "working", archivedAt: null };
describe("offline case library contract", () => {
  it("accepts only local finite intents without renderer paths or remote authority", () => {
    const requests: CaseLibraryRequest[] = [{ action: "list" }, { action: "view", itemHandle: "item" }, { action: "items", snapshotHandle: "s", section: "evidence", offset: 0, query: "😀".repeat(256) },
      { action: "plan", snapshotHandle: "s", operation: "archive" }, { action: "confirm", planHandle: "p" }, { action: "cancel", planHandle: "p" }, { action: "export", snapshotHandle: "s" }];
    for (const request of requests) {
      expect(isCaseLibraryRequest(request)).toBe(true);
      for (const field of ["target", "bindingHandle", "key", "path", "selectedDestination", "command", "confirmed"]) expect(isCaseLibraryRequest({ ...request, [field]: "injected" })).toBe(false);
    }
    for (const request of [{ action: "constructor" }, { action: "view", itemHandle: "\ud800" }, { action: "plan", snapshotHandle: "s", operation: "delete" },
      { action: "items", snapshotHandle: "s", section: "evidence", offset: 1001, query: "" }, { action: "view", itemHandle: "汉".repeat(50) }]) expect(isCaseLibraryRequest(request)).toBe(false);
  });
  it("requires both disposition fields and preserves a complete bounded review", () => {
    const request = { action: "status-plan", snapshotHandle: "s", operation: "close", conclusion: "结论 <script>literal</script>", followup: "尚待复核" } as const;
    expect(isCaseLibraryRequest(request)).toBe(true);
    for (const patch of [{ conclusion: "" }, { followup: " " }, { conclusion: "😀".repeat(1025) }, { followup: "😀".repeat(513) }, { operation: "archive" }, { verified: true }, { target: "host" }]) expect(isCaseLibraryRequest({ ...request, ...patch })).toBe(false);
    expect(isCaseLibraryRequest({ action: "plan", operation: "close", snapshotHandle: "s" })).toBe(false);
    const plan = { kind: "plan", snapshotHandle: "s", planHandle: "p", operation: "close", summary: "结论 <script>literal</script>\n尚待复核", expiresInSeconds: 300 };
    expect(matchesCaseLibraryResult(request, plan)).toBe(true);
    expect(matchesCaseLibraryResult(request, { ...plan, operation: "reopen" })).toBe(false);
    expect(matchesCaseLibraryResult(request, { ...plan, summary: "😀".repeat(2000) })).toBe(false);
  });
  it("checks inventory counts, duplicate handles and archive provenance", () => {
    const request = { action: "list" } as const;
    const list = { kind: "list", items: [item], workingCount: 1, archiveCount: 0 };
    expect(matchesCaseLibraryResult(request, list)).toBe(true);
    for (const patch of [{ workingCount: 0 }, { archiveCount: 1 }, { items: [item, item], workingCount: 2 }, { items: [{ ...item, archivedAt: 1 }] }, { items: [{ ...item, path: "D:/private" }] }]) expect(matchesCaseLibraryResult(request, { ...list, ...patch })).toBe(false);
    const full = [...Array.from({ length: 30 }, (_, i) => ({ ...item, itemHandle: `working-${i}` })), ...Array.from({ length: 200 }, (_, i) => ({ ...item, itemHandle: `archive-${i}`, location: "archived", archivedAt: 3 }))];
    expect(matchesCaseLibraryResult(request, { ...list, items: full, workingCount: 30, archiveCount: 200 })).toBe(true);
    expect(matchesCaseLibraryResult({ action: "view", itemHandle: "other" }, { kind: "view", snapshotHandle: "s", item })).toBe(false);
  });
  it("correlates plans, pages and exports and never accepts filesystem authority in results", () => {
    const plan = { action: "plan", snapshotHandle: "s", operation: "archive" } as const;
    const value = { kind: "plan", snapshotHandle: "s", planHandle: "p", operation: "archive", summary: "保留全部证据", expiresInSeconds: 300 };
    expect(matchesCaseLibraryResult(plan, value)).toBe(true);
    for (const patch of [{ operation: "restore" }, { snapshotHandle: "other" }, { expiresInSeconds: 0 }, { expiresInSeconds: 301 }]) expect(matchesCaseLibraryResult(plan, { ...value, ...patch })).toBe(false);
    const request = { action: "export", snapshotHandle: "s" } as const;
    const exported = { kind: "exported", snapshotHandle: "s", filename: "完整案件.json", bytes: 1234, sha256: "a".repeat(64) };
    expect(matchesCaseLibraryResult(request, exported)).toBe(true); expect(matchesCaseLibraryResult(request, null)).toBe(true);
    for (const patch of [{ filename: "D:/private.json" }, { bytes: 32 * 1024 * 1024 + 1 }, { sha256: "unknown" }, { snapshotHandle: "other" }, { path: "private" }]) expect(matchesCaseLibraryResult(request, { ...exported, ...patch })).toBe(false);
    expect(matchesCaseLibraryResult(plan, null)).toBe(false);
  });
});
