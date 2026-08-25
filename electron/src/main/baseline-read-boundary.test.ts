import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const mainSource = readFileSync(new URL("./index.ts", import.meta.url), "utf8");
const preloadSource = readFileSync(new URL("../preload/index.ts", import.meta.url), "utf8");
const contractSource = readFileSync(new URL("../shared/contract.ts", import.meta.url), "utf8");

function frozenApiBody(): string {
  const match = preloadSource.match(
    /const api: LovelyResApi = Object\.freeze\(\{(?<body>[\s\S]*?)^\}\);/mu,
  );
  expect(match?.groups?.body).toBeDefined();
  return match?.groups?.body ?? "";
}

describe("central Baseline Electron boundary", () => {
  it("keeps all three Baseline methods in the central exact 111 preload", () => {
    const body = frozenApiBody();
    const names = [...body.matchAll(/^  (?<name>[A-Za-z_$][A-Za-z0-9_$]*):/gmu)]
      .map((match) => match.groups?.name);
    expect(names).toHaveLength(111);
    for (const name of ["getBaselineCatalog", "scanBaseline", "listBaselineHistory"]) {
      expect(names.filter((candidate) => candidate === name)).toEqual([name]);
    }
    expect(body).toMatch(
      /getBaselineCatalog: \(\) => ipcRenderer\.invoke\("lovelyres:baseline:catalog:get"\)/u,
    );
    expect(body).toMatch(
      /scanBaseline: \(bindingHandle: string\) =>\s*ipcRenderer\.invoke\("lovelyres:baseline:scan", bindingHandle\)/u,
    );
    expect(body).toMatch(
      /listBaselineHistory: \(bindingHandle: string\) =>\s*ipcRenderer\.invoke\("lovelyres:baseline:history:list", bindingHandle\)/u,
    );
  });

  it("registers catalog arity zero and two exact handle-validated arity-one IPC routes", () => {
    for (const channel of [
      "lovelyres:baseline:catalog:get",
      "lovelyres:baseline:scan",
      "lovelyres:baseline:history:list",
    ]) expect((mainSource.match(new RegExp(channel, "gu")) ?? [])).toHaveLength(1);
    const boundary = mainSource.slice(
      mainSource.indexOf('ipcMain.handle("lovelyres:baseline:catalog:get"'),
      mainSource.indexOf('ipcMain.handle("lovelyres:middleware:discover"'),
    );
    expect((boundary.match(/values\.length !== 0/gu) ?? [])).toHaveLength(1);
    expect((boundary.match(/values\.length !== 1/gu) ?? [])).toHaveLength(2);
    expect((boundary.match(/!isBaselineOpaqueHandle\(values\[0\]\)/gu) ?? []))
      .toHaveLength(2);
    expect(boundary).not.toMatch(/\b(?:path|command|terminal|export|plan|confirm|execute|mutat)/iu);
  });

  it("keeps the aggregate API opaque, typed, read-only and exact", () => {
    const api = contractSource.slice(
      contractSource.indexOf("export interface LovelyResApi"),
      contractSource.indexOf("type JsonRecord"),
    );
    expect(api).toContain("getBaselineCatalog(): Promise<BaselineCatalog>;");
    expect(api).toContain("scanBaseline(bindingHandle: string): Promise<BaselineScan>;");
    expect(api).toContain(
      "listBaselineHistory(bindingHandle: string): Promise<BaselineHistory>;",
    );
    for (const forbidden of [
      "planBaseline", "confirmBaseline", "executeBaseline", "restoreBaseline",
      "reloadBaseline", "exportBaseline", "openBaselineTerminal", "readBaselineFile", "invoke(",
    ]) expect(api).not.toContain(forbidden);
  });
});
