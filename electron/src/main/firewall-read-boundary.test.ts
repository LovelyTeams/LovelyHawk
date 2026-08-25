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

describe("central Firewall Electron boundary", () => {
  it("keeps both Firewall methods in the central exact 118 preload", () => {
    const body = frozenApiBody();
    const names = [...body.matchAll(/^  (?<name>[A-Za-z_$][A-Za-z0-9_$]*):/gmu)]
      .map((match) => match.groups?.name);
    expect(names).toHaveLength(118);
    expect(names.filter((name) => name === "inspectFirewall")).toEqual(["inspectFirewall"]);
    expect(names.filter((name) => name === "listFirewallChangeHistory"))
      .toEqual(["listFirewallChangeHistory"]);
    expect(body).toMatch(
      /inspectFirewall: \(bindingHandle: string\) =>\s*ipcRenderer\.invoke\("lovelyres:firewall:inspect", bindingHandle\)/u,
    );
    expect(body).toMatch(
      /listFirewallChangeHistory: \(bindingHandle: string\) =>\s*ipcRenderer\.invoke\("lovelyres:firewall:change-history:list", bindingHandle\)/u,
    );
  });

  it("registers only exact one-argument handle-validated read IPC", () => {
    expect((mainSource.match(/lovelyres:firewall:inspect/gu) ?? [])).toHaveLength(1);
    expect((mainSource.match(/lovelyres:firewall:change-history:list/gu) ?? [])).toHaveLength(1);
    const boundary = mainSource.slice(
      mainSource.indexOf('ipcMain.handle("lovelyres:firewall:inspect"'),
      mainSource.indexOf('ipcMain.handle("lovelyres:baseline:catalog:get"'),
    );
    expect((boundary.match(/values\.length !== 1/gu) ?? [])).toHaveLength(2);
    expect((boundary.match(/!isFirewallOpaqueHandle\(values\[0\]\)/gu) ?? []))
      .toHaveLength(2);
    expect(boundary).not.toMatch(/\b(?:path|command|terminal|export|plan|confirm|execute|mutat)/iu);
  });

  it("keeps the aggregate API concrete and free of Firewall mutation or generic methods", () => {
    const api = contractSource.slice(
      contractSource.indexOf("export interface LovelyResApi"),
      contractSource.indexOf("type JsonRecord"),
    );
    expect(api).toContain(
      "inspectFirewall(bindingHandle: string): Promise<FirewallInspection>;",
    );
    expect(api).toContain(
      "listFirewallChangeHistory(bindingHandle: string): Promise<FirewallHistory>;",
    );
    for (const forbidden of [
      "planFirewall", "confirmFirewall", "executeFirewall", "mutateFirewall",
      "exportFirewall", "openFirewallTerminal", "readFirewallFile", "invoke(",
    ]) expect(api).not.toContain(forbidden);
  });
});
