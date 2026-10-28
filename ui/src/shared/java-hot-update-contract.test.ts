import { describe, expect, it } from "vitest";

import {
  isJavaClassEntry,
  isJavaClassStageResult,
  isJavaHotUpdateRequest,
  isJavaHotUpdateResponse,
  isTypedJarPath,
  matchesJavaHotUpdateResponse,
  type JavaHotUpdateRequest,
} from "./java-hot-update-contract";

const sha = "a".repeat(64);
const scan = {
  kind: "scan",
  snapshotHandle: "snap-1",
  version: "openjdk version \"17.0.20\" 2026-07-21",
  tools: ["java", "jar", "jcmd", "jstack", "jmap", "jstat", "javap"].map((tool) => ({ tool, available: tool !== "jmap" })),
  processes: [{
    pid: 4242,
    user: "tomcat",
    cpuPercent: 1.5,
    memoryPercent: 3.25,
    elapsedSeconds: 600,
    command: "/opt/java/bin/java -cp /opt/app/app.jar com.example.Main </td><script>x()</script>",
    commandTruncated: false,
    openFilesReadable: true,
    openJarsIncomplete: false,
    jarHandles: ["jar-1"],
  }],
  jars: [{ jarHandle: "jar-1", path: "/opt/app/app.jar" }],
  jarsTruncated: false,
  expiresInSeconds: 600,
};
const jar = {
  kind: "jar",
  jarHandle: "jar-1",
  path: "/opt/app/app.jar",
  sizeBytes: 2048,
  sha256: sha,
  classCount: 2,
  classes: ["com/example/Main.class", "com/example/Main$Inner.class"],
  truncated: false,
};
const plan = {
  kind: "plan",
  planHandle: "plan-1",
  operation: "update",
  summary: "替换 /opt/app/app.jar 中的 com/example/Main.class",
  jarPath: "/opt/app/app.jar",
  entry: "com/example/Main.class",
  classSha256: sha,
  restoreDescription: "从受管原始 JAR 备份原子恢复，并校验 SHA-256",
  confirmed: false,
  expiresInSeconds: 600,
};

describe("Java hot update contract", () => {
  it("takes handles and a listed class entry, never a path, a command or a local file", () => {
    const valid: JavaHotUpdateRequest[] = [
      { action: "scan", bindingHandle: "b-1" },
      { action: "inspect", bindingHandle: "b-1", snapshotHandle: "s-1", jarHandle: "j-1" },
      { action: "plan", bindingHandle: "b-1", snapshotHandle: "s-1", jarHandle: "j-1", entry: "com/x/A.class", stagedHandle: "c-1" },
      { action: "plan-restore", bindingHandle: "b-1", recordId: "r-1" },
      { action: "execute", bindingHandle: "b-1", planHandle: "p-1" },
      { action: "discard-staged", bindingHandle: "b-1", stagedHandle: "c-1" },
    ];
    for (const request of valid) expect(isJavaHotUpdateRequest(request), request.action).toBe(true);
    for (const forged of [
      { action: "inspect", bindingHandle: "b-1", snapshotHandle: "s-1", jarHandle: "j-1", path: "/etc/passwd" },
      { action: "scan", bindingHandle: "b-1", command: "id" },
      { action: "plan", bindingHandle: "b-1", snapshotHandle: "s-1", jarHandle: "j-1", entry: "../../etc/passwd", stagedHandle: "c-1" },
      { action: "plan", bindingHandle: "b-1", snapshotHandle: "s-1", jarHandle: "/opt/app.jar", entry: "A.class", stagedHandle: "c-1" },
      { action: "stage", bindingHandle: "b-1", localPath: "C:\\x.class" },
      { action: "execute", bindingHandle: "b 1", planHandle: "p-1" },
      { action: "execute", bindingHandle: "b-1" },
    ]) expect(isJavaHotUpdateRequest(forged), JSON.stringify(forged)).toBe(false);
  });

  it("takes a typed JAR path only as an absolute, plain .jar path, and only for reading", () => {
    const request = { action: "inspect-path", bindingHandle: "b-1", snapshotHandle: "s-1", path: "/srv/tomcat/webapps/shop/WEB-INF/lib/shop.jar" };
    expect(isJavaHotUpdateRequest(request)).toBe(true);
    for (const path of ["lib/a.jar", "/etc/passwd", "/opt/../etc/a.jar", "/opt/./a.jar", "/opt//a.jar", "/opt/.jar", " /opt/a.jar", "/opt/a.jar\n",
      "/opt/a\\b.jar", "/opt/a.jar/", `/${"a".repeat(4_096)}.jar`]) {
      expect(isTypedJarPath(path), JSON.stringify(path)).toBe(false);
      expect(isJavaHotUpdateRequest({ ...request, path }), JSON.stringify(path)).toBe(false);
    }
    expect(isTypedJarPath("/opt/my app/App.JAR")).toBe(true);
    // Never with a handle beside it, never for planning.
    expect(isJavaHotUpdateRequest({ ...request, jarHandle: "j-1" })).toBe(false);
    expect(isJavaHotUpdateRequest({ action: "plan", bindingHandle: "b-1", snapshotHandle: "s-1", path: request.path, entry: "A.class", stagedHandle: "c-1" })).toBe(false);
    // The answer must be the JAR that was asked for.
    expect(matchesJavaHotUpdateResponse(request as JavaHotUpdateRequest, { ...jar, path: request.path })).toBe(true);
    expect(matchesJavaHotUpdateResponse(request as JavaHotUpdateRequest, jar)).toBe(false);
  });

  it("accepts only relative class entries made of plain archive names", () => {
    for (const entry of ["Main.class", "com/example/Main$Inner.class", "a-b/c_d/E.class"]) expect(isJavaClassEntry(entry), entry).toBe(true);
    for (const entry of ["/com/A.class", "com/../A.class", "com//A.class", "com/A.java", "com/A b.class", "", "com/A.class\n"]) {
      expect(isJavaClassEntry(entry), entry).toBe(false);
    }
  });

  it("checks each answer's exact shape and keeps hostile text as text", () => {
    for (const response of [scan, jar, plan]) expect(isJavaHotUpdateResponse(response), response.kind).toBe(true);
    expect(isJavaHotUpdateResponse({ ...scan, processes: [{ ...scan.processes[0], jarHandles: ["not-offered"] }] })).toBe(false);
    expect(isJavaHotUpdateResponse({ ...scan, jars: [{ jarHandle: "jar-1", path: "relative/app.jar" }] })).toBe(false);
    expect(isJavaHotUpdateResponse({ ...scan, tools: scan.tools.slice(1) })).toBe(false);
    expect(isJavaHotUpdateResponse({ ...scan, processes: [{ ...scan.processes[0], command: "line\nbreak" }] })).toBe(false);
    // Open files that could not be read cannot be "incompletely" listed, and a JAR is offered once per process.
    expect(isJavaHotUpdateResponse({ ...scan, processes: [{ ...scan.processes[0], openFilesReadable: false, openJarsIncomplete: true }] })).toBe(false);
    expect(isJavaHotUpdateResponse({ ...scan, processes: [{ ...scan.processes[0], openFilesReadable: false }] })).toBe(true);
    expect(isJavaHotUpdateResponse({ ...scan, processes: [{ ...scan.processes[0], jarHandles: ["jar-1", "jar-1"] }] })).toBe(false);
    expect(isJavaHotUpdateResponse({ ...scan, jarsTruncated: "no" })).toBe(false);
    const { jarsTruncated: _omitted, ...withoutTruncation } = scan;
    expect(isJavaHotUpdateResponse(withoutTruncation)).toBe(false);
    // An application server's library JARs, many of them.
    const many = Array.from({ length: 300 }, (_, index) => ({ jarHandle: `jar-${index}`, path: `/srv/tomcat/webapps/shop/WEB-INF/lib/lib-${index}.jar` }));
    expect(isJavaHotUpdateResponse({ ...scan, jars: many, processes: [{ ...scan.processes[0], jarHandles: many.map((jar) => jar.jarHandle) }] })).toBe(true);
    expect(isJavaHotUpdateResponse({ ...jar, sha256: "ABC" })).toBe(false);
    // A list that says it is complete must hold every class it counts.
    expect(isJavaHotUpdateResponse({ ...jar, classCount: 3 })).toBe(false);
    expect(isJavaHotUpdateResponse({ ...jar, classCount: 3, truncated: true })).toBe(true);
    expect(isJavaHotUpdateResponse({ ...plan, entry: "../x.class" })).toBe(false);
    expect(isJavaHotUpdateResponse({ ...plan, localPath: "C:\\x.class" })).toBe(false);
    const receipt = { kind: "receipt", planHandle: "plan-1", operation: "update", verified: true, recordId: "rec-1",
      jarPath: "/opt/app/app.jar", entry: "com/example/Main.class", jarSha256: sha, detail: "ok" };
    expect(isJavaHotUpdateResponse(receipt)).toBe(true);
    // A verified change always names its record and the JAR's new hash.
    expect(isJavaHotUpdateResponse({ ...receipt, recordId: null })).toBe(false);
    expect(isJavaHotUpdateResponse({ ...receipt, verified: false, recordId: null, jarSha256: null })).toBe(true);
  });

  it("matches each answer to the request that asked for it", () => {
    const binding = "b-1";
    expect(matchesJavaHotUpdateResponse({ action: "scan", bindingHandle: binding }, scan)).toBe(true);
    expect(matchesJavaHotUpdateResponse({ action: "inspect", bindingHandle: binding, snapshotHandle: "snap-1", jarHandle: "jar-1" }, jar)).toBe(true);
    expect(matchesJavaHotUpdateResponse({ action: "inspect", bindingHandle: binding, snapshotHandle: "snap-1", jarHandle: "jar-2" }, jar)).toBe(false);
    const planRequest = { action: "plan", bindingHandle: binding, snapshotHandle: "snap-1", jarHandle: "jar-1", entry: "com/example/Main.class", stagedHandle: "c-1" } as const;
    expect(matchesJavaHotUpdateResponse(planRequest, plan)).toBe(true);
    expect(matchesJavaHotUpdateResponse({ ...planRequest, entry: "com/example/Other.class" }, plan)).toBe(false);
    // A plan that comes back already confirmed was not the one just made.
    expect(matchesJavaHotUpdateResponse(planRequest, { ...plan, confirmed: true })).toBe(false);
    expect(matchesJavaHotUpdateResponse({ action: "confirm", bindingHandle: binding, planHandle: "plan-1" }, { ...plan, confirmed: true })).toBe(true);
    expect(matchesJavaHotUpdateResponse({ action: "confirm", bindingHandle: binding, planHandle: "plan-2" }, { ...plan, confirmed: true })).toBe(false);
    expect(matchesJavaHotUpdateResponse({ action: "plan-restore", bindingHandle: binding, recordId: "r" }, plan)).toBe(false);
  });

  it("lets the host's dialog answer only a name, a size and a hash", () => {
    expect(isJavaClassStageResult({ staged: false, class: null })).toBe(true);
    expect(isJavaClassStageResult({ staged: true, class: { stagedHandle: "c-1", name: "Main.class", sizeBytes: 812, sha256: sha } })).toBe(true);
    for (const forged of [
      { staged: true, class: { stagedHandle: "c-1", name: "Main.class", sizeBytes: 812, sha256: sha, localPath: "C:\\Main.class" } },
      { staged: true, class: { stagedHandle: "c-1", name: "C:\\work\\Main.class", sizeBytes: 812, sha256: sha } },
      { staged: true, class: { stagedHandle: "c-1", name: "Main.jar", sizeBytes: 812, sha256: sha } },
      { staged: true, class: null },
    ]) expect(isJavaClassStageResult(forged), JSON.stringify(forged)).toBe(false);
  });
});
