import { describe, expect, it } from "vitest";

import {
  isWindowsIncidentRequest,
  matchesWindowsIncidentResponse,
} from "./windows-incident-contract";
const sessionId = "00000000-0000-4000-8000-000000000001";

describe("windows-incident contract", () => {
  it("binds process details to both the selected PID and creation timestamp", () => {
    const request = { action: "inspect-process", pid: 12, startTime: "2026-10-24T10:00:00.0000000Z", sessionId } as const;
    const inspection = { pid: 12, startTime: request.startTime, observedAt: "2026-10-24T10:10:00Z", user: "lab", services: [], modules: [], network: [], warnings: [] };
    expect(isWindowsIncidentRequest(request)).toBe(true);
    expect(isWindowsIncidentRequest({ ...request, pid: 0 })).toBe(false);
    expect(isWindowsIncidentRequest({ ...request, startTime: "yesterday'; calc" })).toBe(false);
    expect(isWindowsIncidentRequest({ ...request, path: "C:\\a" })).toBe(false);
    expect(matchesWindowsIncidentResponse(request, { kind: "process-inspection", inspection })).toBe(true);
    expect(matchesWindowsIncidentResponse(request, { kind: "process-inspection", inspection: { ...inspection, startTime: "2026-10-24T09:00:00Z" } })).toBe(false);
    expect(matchesWindowsIncidentResponse(request, { kind: "process-inspection", inspection: { ...inspection, pid: 13 } })).toBe(false);
  });
  it("accepts valid requests and rejects extra or oversized fields", () => {
    expect(isWindowsIncidentRequest({ action: "status" })).toBe(true);
    expect(isWindowsIncidentRequest({ action: "register-plugin" })).toBe(true);
    expect(isWindowsIncidentRequest({ action: "send-chat", text: "hello", sessionId })).toBe(true);
    expect(isWindowsIncidentRequest({ action: "collect-files", path: "C:\\Users\\Public", sessionId })).toBe(
      true,
    );
    expect(
      isWindowsIncidentRequest({
        action: "collect-registry",
        keyPath: "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        sessionId,
      }),
    ).toBe(true);

    expect(isWindowsIncidentRequest({ action: "status", extra: 1 })).toBe(false);
    expect(isWindowsIncidentRequest({ action: "send-chat", text: "" })).toBe(false);
    expect(isWindowsIncidentRequest({ action: "pull-file", remotePath: "C:\\a\nb" })).toBe(false);
  });

  it("matches responses against the requested action", () => {
    expect(
      matchesWindowsIncidentResponse(
        { action: "status" },
        {
          kind: "status",
          status: { listenerRunning: true },
          filelessScript: "Add-Type ...",
        },
      ),
    ).toBe(false);
    expect(
      matchesWindowsIncidentResponse(
        { action: "collect-overview", sessionId },
        { kind: "overview", snapshot: { hostname: "WIN-IR" } },
      ),
    ).toBe(false);
    expect(
      matchesWindowsIncidentResponse(
        { action: "collect-overview", sessionId },
        { kind: "processes", snapshot: {} },
      ),
    ).toBe(false);
  });

  it("validates preview bytes, base64, metadata and the exact response fields", () => {
    const request = { action: "preview-file", path: "C:\\evidence.txt", sessionId } as const;
    const preview = { fullPath: request.path, sizeBytes: 4, lastWriteTime: "", previewB64: "YWJjZA==", previewBytes: 4, truncated: false };
    expect(matchesWindowsIncidentResponse(request, { kind: "file-preview", preview })).toBe(true);
    for (const invalid of [
      { ...preview, previewB64: "%%%%" },
      { ...preview, previewBytes: 3 },
      { ...preview, previewBytes: -1 },
      { ...preview, sizeBytes: 2 },
      { ...preview, truncated: true },
      { ...preview, previewB64: "YQ==".repeat(5500) },
      { ...preview, fullPath: "C:\\a\0b" },
      { ...preview, extra: true },
    ]) expect(matchesWindowsIncidentResponse(request, { kind: "file-preview", preview: invalid })).toBe(false);
    expect(matchesWindowsIncidentResponse(request, { kind: "file-preview", preview: { ...preview, sizeBytes: 100, truncated: true } })).toBe(true);
    expect(matchesWindowsIncidentResponse(request, { kind: "file-preview", preview: { ...preview, sizeBytes: 0, previewBytes: 0, previewB64: "" } })).toBe(true);
  });

  it("rejects malformed nested records and mismatched directory coverage", () => {
    const request = { action: "collect-files", path: "C:\\", sessionId } as const;
    const entry = { name: "example.txt", fullPath: "C:\\example.txt", entryType: "file", sizeBytes: 10, lastWriteTime: "", sha256: "", hidden: false, system: false, riskLevel: "normal", riskReason: "" };
    const snapshot = { currentPath: "C:\\", totalEntries: 1, truncated: false, entries: [entry] };
    expect(matchesWindowsIncidentResponse(request, { kind: "files", snapshot })).toBe(true);
    expect(matchesWindowsIncidentResponse(request, { kind: "files", snapshot: { ...snapshot, totalEntries: 0 } })).toBe(false);
    expect(matchesWindowsIncidentResponse(request, { kind: "files", snapshot: { ...snapshot, totalEntries: 20 } })).toBe(false);
    expect(matchesWindowsIncidentResponse(request, { kind: "files", snapshot: { ...snapshot, totalEntries: 20, truncated: true } })).toBe(true);
    for (const invalid of [{ ...entry, riskLevel: "critical" }, { ...entry, sizeBytes: NaN }, { ...entry, sha256: "not-a-hash" }, { ...entry, hidden: "false" }]) {
      expect(matchesWindowsIncidentResponse(request, { kind: "files", snapshot: { ...snapshot, entries: [invalid] } })).toBe(false);
    }
  });

  it("rejects empty, oversized, control-character paths and unsupported log categories", () => {
    for (const path of ["", " ", "C:\\a\0b", "C:\\a\rb", "C:\\a\nb", `C:\\${"文".repeat(1024)}`]) {
      expect(isWindowsIncidentRequest({ action: "preview-file", path, sessionId })).toBe(false);
      expect(isWindowsIncidentRequest({ action: "collect-files", path, sessionId })).toBe(false);
      expect(isWindowsIncidentRequest({ action: "collect-registry", keyPath: path, sessionId })).toBe(false);
    }
    for (const category of ["", "all; whoami", "ALL", "System"]) expect(isWindowsIncidentRequest({ action: "collect-logs", category, sessionId })).toBe(false);
    expect(isWindowsIncidentRequest({ action: "collect-logs", category: "powershell", sessionId })).toBe(true);
    expect(isWindowsIncidentRequest({ action: "run-command", command: "whoami" })).toBe(false);
    expect(isWindowsIncidentRequest({ action: "run-command", command: "whoami", sessionId: "changed" })).toBe(false);
    expect(isWindowsIncidentRequest({ action: "remediate-baseline", ruleId: "wdigest", sessionId })).toBe(true);
    expect(isWindowsIncidentRequest({ action: "remediate-baseline", ruleId: "defender-tamper", sessionId })).toBe(false);
    expect(isWindowsIncidentRequest({ action: "kill-process", pid: 900, startTime: "2026-10-24T10:00:00Z", sessionId })).toBe(true);
    expect(isWindowsIncidentRequest({ action: "kill-process", pid: 4, startTime: "2026-10-24T10:00:00Z", sessionId })).toBe(false);
    expect(isWindowsIncidentRequest({ action: "remove-startup", sourceType: "registry", name: "Updater", location: "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", sessionId })).toBe(true);
    expect(isWindowsIncidentRequest({ action: "disable-account", name: "support$", sid: "S-1-5-21-1001", sessionId })).toBe(true);
    expect(isWindowsIncidentRequest({ action: "disable-account", name: "support$", sid: "not-a-sid", sessionId })).toBe(false);
    expect(isWindowsIncidentRequest({ action: "delete-file", path: "C:\\Users\\Public\\dropper.exe", dirPath: "C:\\Users\\Public", sessionId })).toBe(true);
    expect(isWindowsIncidentRequest({ action: "delete-registry-value", keyPath: "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", valueName: "Updater", sessionId })).toBe(true);
    expect(isWindowsIncidentRequest({ action: "delete-registry-value", keyPath: "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", valueName: "", sessionId })).toBe(false);
  });
});
