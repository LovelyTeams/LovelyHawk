import { describe, expect, it } from "vitest";
import { isFileEvidenceRequest, isFileEvidenceResult, matchesFileEvidenceResult } from "./file-evidence-contract";
export const evidenceResult = {
  jobHandle: "job", pathHandle: "path", path: "/tmp/evidence", targetLabel: "root@host:22", caseTitle: "案件",
  folderName: "LovelyHawk-evidence-12345678-1234-4234-8234-123456789012", state: "completed",
  copiedBytes: 3, verifiedBytes: 3, totalBytes: 3, sha256: "a".repeat(64), detail: "已保存",
};
describe("file evidence boundary", () => {
  it("accepts only exact finite requests, keeping local paths and source claims out", () => {
    const input = { action: "begin", bindingHandle: "binding", pathHandle: "path" };
    expect(isFileEvidenceRequest(input)).toBe(true);
    for (const bad of [{ ...input, selectedDirectory: "C:/private" }, { ...input, path: "/etc/shadow" }, { ...input, source: {} },
      { ...input, bindingHandle: "a\u0085" }, { ...input, pathHandle: "汉".repeat(50) }, { ...input, action: "shell" }, { ...input, action: "poll" }])
      expect(isFileEvidenceRequest(bad)).toBe(false);
  });
  it("requires bounded counts, a complete digest and immutable request correlation", () => {
    expect(isFileEvidenceResult(evidenceResult)).toBe(true);
    for (const bad of [{ ...evidenceResult, copiedBytes: 2 }, { ...evidenceResult, verifiedBytes: 4 }, { ...evidenceResult, sha256: null },
      { ...evidenceResult, state: "failed" }, { ...evidenceResult, localPath: "C:/private" }, { ...evidenceResult, folderName: "../../escape" }])
      expect(isFileEvidenceResult(bad)).toBe(false);
    expect(matchesFileEvidenceResult({ action: "poll", bindingHandle: "binding", jobHandle: "other" }, evidenceResult)).toBe(false);
    expect(matchesFileEvidenceResult({ action: "poll", bindingHandle: "binding", jobHandle: "job" }, null)).toBe(false);
    expect(matchesFileEvidenceResult({ action: "begin", bindingHandle: "binding", pathHandle: "path" }, null)).toBe(true);
  });
});
