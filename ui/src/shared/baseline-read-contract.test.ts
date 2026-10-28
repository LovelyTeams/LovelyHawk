import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  isBaselineCatalog,
  isBaselineFile,
  isBaselineHistory,
  isBaselineOpaqueHandle,
  isBaselineScan,
} from "./baseline-read-contract";

const hostile = "</code><script>plain()</script><img src=x onerror=plain()>";
const redacted = "[SENSITIVE BASELINE TEXT REDACTED]";

it("accepts a bounded unverified observation but rejects a forged pass or explanation", () => {
  const value = structuredClone(scan);
  const row = value.statuses[0]!;
  row.observedKind = "unverified";
  row.observed = "无法判断（尚未核实配置）";
  expect(isBaselineScan(value)).toBe(true);
  row.compliant = true;
  expect(isBaselineScan(value)).toBe(false);
  row.compliant = false;
  row.observed = "已核实";
  expect(isBaselineScan(value)).toBe(false);
  row.observed = "无法判断（尚未核实配置）";
  row.textTruncated = true;
  expect(isBaselineScan(value)).toBe(false);
});

const catalog = {
  items: [{
    itemHandle: "baseline-item-1",
    category: "ssh",
    component: "ssh",
    risk: "critical",
    valueKind: { kind: "choice", options: ["yes", "no"] },
    title: "关闭 SSH 密码认证",
    description: "仅在确认密钥认证可用后关闭密码认证。",
    recommendation: "no",
    writable: true,
  }, {
    itemHandle: "baseline-item-2",
    category: "kernel",
    component: "system",
    risk: "high",
    valueKind: { kind: "integer", minimum: 0, maximum: 2 },
    title: "启用完整 ASLR",
    description: "随机化进程地址空间。",
    recommendation: "2",
    writable: true,
  }],
  displayed: 2,
  truncated: false,
};

const scan = {
  scanHandle: "baseline-scan-1",
  capturedAt: "2026-08-24T01:02:03Z",
  expiresInSeconds: 300,
  statuses: [{
    itemHandle: "baseline-item-1",
    observedKind: "value",
    observed: hostile,
    compliant: false,
    redacted: false,
    textTruncated: false,
    fix: {
      file: "/etc/ssh/sshd_config",
      lines: ["PasswordAuthentication no"],
      reload: "systemctl reload sshd",
      manualReason: null,
    },
  }, {
    itemHandle: "baseline-item-2",
    observedKind: "missing",
    observed: "未设置",
    compliant: false,
    redacted: false,
    textTruncated: false,
    fix: {
      file: "/etc/sysctl.d/99-lovelyres-baseline.conf",
      lines: ["kernel.randomize_va_space = 2"],
      reload: "sysctl --system",
      manualReason: null,
    },
  }],
  displayed: 2,
  compliantCount: 0,
  nonCompliantCount: 2,
  redactedFieldCount: 0,
  truncated: false,
};

const history = {
  historyHandle: "baseline-history-1",
  expiresInSeconds: 300,
  entries: [{
    historyItemHandle: "baseline-record-1",
    restorable: true,
    state: "applied",
    summary: `已应用 1 项基线改动：${hostile}`,
    changeCount: 1,
    createdAt: "2026-08-24T01:02:03Z",
    updatedAt: "2026-08-24T01:03:04Z",
    redacted: false,
    textTruncated: false,
  }],
  displayed: 1,
  redactedFieldCount: 0,
  truncated: false,
};

describe("baseline read strict contract", () => {
  it("freezes the future public API at exactly four read-only methods", () => {
    const source = readFileSync(new URL("./baseline-read-contract.ts", import.meta.url), "utf8");
    const body = source.match(/export interface BaselineReadApi \{([\s\S]*?)\n\}/u)?.[1] ?? "";
    const methods = [...body.matchAll(/^\s{2}([A-Za-z][A-Za-z0-9]*)\(/gmu)]
      .map((match) => match[1]);
    expect(methods).toEqual([
      "getBaselineCatalog",
      "scanBaseline",
      "listBaselineHistory",
      "readBaselineFile",
    ]);
    // Reading the file behind a check is still reading. Nothing here changes
    // one, and the caller names the check rather than the file.
    expect(body).toContain("readBaselineFile(bindingHandle: string, itemHandle: string)");
    for (const forbidden of [
      "plan", "confirm", "execute", "restore", "reload", "terminal", "export", "ai",
      "write", "path",
    ]) expect(body.toLowerCase()).not.toContain(forbidden);
  });

  it("accepts only bounded safe catalog metadata and opaque unique handles", () => {
    expect(isBaselineOpaqueHandle("baseline-item-a1")).toBe(true);
    expect(isBaselineOpaqueHandle("../raw-id")).toBe(false);
    expect(isBaselineCatalog(catalog)).toBe(true);
    expect(isBaselineCatalog({ ...catalog, targetGeneration: 1 })).toBe(false);
    expect(isBaselineCatalog({
      ...catalog,
      items: catalog.items.map((item) => ({ ...item, itemHandle: "same" })),
    })).toBe(false);
    expect(isBaselineCatalog({
      ...catalog,
      items: [{ ...catalog.items[0], rawId: "ssh-password-authentication" }],
      displayed: 1,
    })).toBe(false);
    expect(isBaselineCatalog({
      ...catalog,
      items: [{ ...catalog.items[0], description: "token=secret" }],
      displayed: 1,
    })).toBe(true);
  });

  it("takes a setting behind a Match block as a finding and never as compliant", () => {
    const conditional = "写在 Match 条件块里，只对部分连接生效";
    const row = {
      ...scan.statuses[0], observedKind: "conditional", observed: conditional, compliant: false,
    };
    expect(isBaselineScan({ ...scan, statuses: [row, scan.statuses[1]] })).toBe(true);
    // The machine behaves one way for some connections and another way for the
    // rest, so calling it compliant would be a claim about only half of them.
    expect(isBaselineScan({
      ...scan,
      statuses: [{ ...row, compliant: true }, scan.statuses[1]],
      compliantCount: 1,
    })).toBe(false);
    // The wording is fixed on this side too, so a target cannot write its own.
    expect(isBaselineScan({
      ...scan,
      statuses: [{ ...row, observed: "looks conditional to me" }, scan.statuses[1]],
    })).toBe(false);
  });

  it("accepts hostile observed text only as bounded data and rejects leaked target or path fields", () => {
    expect(isBaselineScan(scan)).toBe(true);
    expect(isBaselineScan({ ...scan, sessionId: "secret-session" })).toBe(false);
    expect(isBaselineScan({
      ...scan,
      statuses: [{ ...scan.statuses[0], path: "/etc/ssh/sshd_config" }],
      displayed: 1,
      nonCompliantCount: 1,
    })).toBe(false);
    expect(isBaselineScan({
      ...scan,
      statuses: [{ ...scan.statuses[0], observed: "authorization: Bearer secret" }, scan.statuses[1]],
    })).toBe(true);
    expect(isBaselineScan({
      ...scan,
      statuses: [{
        ...scan.statuses[0], observed: redacted, redacted: true,
      }, scan.statuses[1]],
      redactedFieldCount: 1,
    })).toBe(true);
  });

  it("carries the fix for every row and refuses a path dressed up as one", () => {
    expect(isBaselineScan(scan)).toBe(true);
    // The instruction is what the operator acts on, so every row has to have
    // one — a row without it would be a finding with nothing to do about it.
    expect(isBaselineScan({
      ...scan,
      statuses: [{ ...scan.statuses[0], fix: undefined }, scan.statuses[1]],
    })).toBe(false);
    for (const badFile of [
      "relative/path.conf",
      "/etc/../root/.ssh/authorized_keys",
      "/etc/ssh/sshd_config; rm -rf /",
      "/etc/ssh/sshd_config\nPermitRootLogin yes",
    ]) {
      expect(isBaselineScan({
        ...scan,
        statuses: [{
          ...scan.statuses[0],
          fix: { ...scan.statuses[0]!.fix, file: badFile },
        }, scan.statuses[1]],
      }), badFile).toBe(false);
    }
    // Lines are configuration, not prose, and there are never many of them.
    expect(isBaselineScan({
      ...scan,
      statuses: [{ ...scan.statuses[0], fix: { ...scan.statuses[0]!.fix, lines: [] } }, scan.statuses[1]],
    })).toBe(false);
    expect(isBaselineScan({
      ...scan,
      statuses: [{
        ...scan.statuses[0],
        fix: { ...scan.statuses[0]!.fix, lines: Array.from({ length: 9 }, () => "x") },
      }, scan.statuses[1]],
    })).toBe(false);
  });

  it("accepts safe hostile history summaries while rejecting every raw evidence field", () => {
    expect(isBaselineHistory(history)).toBe(true);
    for (const field of ["recordId", "operationId", "digest", "remoteRoot", "files", "backups"]) {
      expect(isBaselineHistory({
        ...history,
        entries: [{ ...history.entries[0], [field]: "raw-secret" }],
      })).toBe(false);
    }
    expect(isBaselineHistory({
      ...history,
      entries: [{ ...history.entries[0], summary: "password=history-secret" }],
    })).toBe(true);
    expect(isBaselineHistory({
      ...history,
      entries: [{ ...history.entries[0], summary: redacted, redacted: true }],
      redactedFieldCount: 1,
    })).toBe(true);
  });

  it("enforces response counts, aggregate truncation consistency and timestamp ordering", () => {
    expect(isBaselineScan({ ...scan, displayed: 1 })).toBe(false);
    expect(isBaselineScan({ ...scan, compliantCount: 1 })).toBe(false);
    expect(isBaselineScan({
      ...scan,
      statuses: [{ ...scan.statuses[0], textTruncated: true }, scan.statuses[1]],
    })).toBe(false);
    expect(isBaselineHistory({
      ...history,
      entries: [{ ...history.entries[0], updatedAt: "2026-08-23T01:03:04Z" }],
    })).toBe(false);
    expect(isBaselineHistory({
      ...history,
      entries: [{ ...history.entries[0], textTruncated: true }],
    })).toBe(false);
    expect(isBaselineCatalog({ ...catalog, items: [], displayed: 0 })).toBe(true);
  });
});

describe("baseline configuration file", () => {
  const file = {
    itemHandle: "baseline-item-1",
    path: "/etc/ssh/sshd_config",
    key: "PermitRootLogin",
    exists: true,
    text: "#PermitRootLogin prohibit-password\nPermitRootLogin yes\nPort 22",
    lineCount: 3,
    mentions: [
      { line: 0, commented: true, effective: false },
      { line: 1, commented: false, effective: true },
    ],
    truncated: false,
  };

  it("accepts a file with its lines marked", () => {
    expect(isBaselineFile(file)).toBe(true);
    // Nothing in force is a real state: every line may be commented out.
    expect(isBaselineFile({
      ...file,
      mentions: [{ line: 0, commented: true, effective: false }],
    })).toBe(true);
  });

  it("shows the file as the target wrote it", () => {
    const messy = {
      ...file,
      text: `${hostile}\n\tPermitRootLogin yes\nroot:$6$salt$hash:19000:0:99999:7:::`,
      lineCount: 3,
      mentions: [{ line: 1, commented: false, effective: true }],
    };
    expect(isBaselineFile(messy)).toBe(true);
    // Tabs and blank lines survive, because a configuration file is evidence.
    expect(isBaselineFile({ ...file, text: "a\n\n\tb", lineCount: 3, mentions: [] })).toBe(true);
    // Control characters that break the rendering do not.
    expect(isBaselineFile({ ...file, text: "PermitRootLogin\u0007 yes", lineCount: 1, mentions: [] }))
      .toBe(false);
  });

  it("refuses a mark that cannot be drawn or cannot be true", () => {
    // Past the end of the text.
    expect(isBaselineFile({ ...file, mentions: [{ line: 9, commented: false, effective: true }] }))
      .toBe(false);
    // A commented line sets nothing, so it cannot be the line in force.
    expect(isBaselineFile({
      ...file,
      mentions: [{ line: 0, commented: true, effective: true }],
    })).toBe(false);
    // Two lines in force is a contradiction.
    expect(isBaselineFile({
      ...file,
      mentions: [
        { line: 0, commented: false, effective: true },
        { line: 1, commented: false, effective: true },
      ],
    })).toBe(false);
    // Marks have to arrive in file order, so the window can draw them once.
    expect(isBaselineFile({
      ...file,
      mentions: [
        { line: 1, commented: false, effective: true },
        { line: 0, commented: true, effective: false },
      ],
    })).toBe(false);
  });

  it("refuses a line count that does not match the text", () => {
    expect(isBaselineFile({ ...file, lineCount: 2 })).toBe(false);
    expect(isBaselineFile({ ...file, lineCount: 4 })).toBe(false);
  });

  it("keeps an absent file empty rather than letting it look blank", () => {
    expect(isBaselineFile({
      ...file, exists: false, text: "", lineCount: 0, mentions: [],
    })).toBe(true);
    // "Not there" with content would be a contradiction the window would draw.
    expect(isBaselineFile({ ...file, exists: false })).toBe(false);
  });

  it("refuses anything that is not one of the catalogue's own files", () => {
    expect(isBaselineFile({ ...file, path: "etc/ssh/sshd_config" })).toBe(false);
    expect(isBaselineFile({ ...file, path: "" })).toBe(false);
    expect(isBaselineFile({ ...file, key: "" })).toBe(false);
    expect(isBaselineFile({ ...file, itemHandle: "../raw-id" })).toBe(false);
    expect(isBaselineFile({ ...file, extra: true })).toBe(false);
  });
});
