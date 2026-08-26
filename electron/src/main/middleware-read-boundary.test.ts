import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const mainSource = readFileSync(new URL("./index.ts", import.meta.url), "utf8");
const preloadSource = readFileSync(new URL("../preload/index.ts", import.meta.url), "utf8");
const contractSource = readFileSync(new URL("../shared/contract.ts", import.meta.url), "utf8");
const backendSource = readFileSync(
  new URL("../../../crates/lovelyres-electron-backend/src/lib.rs", import.meta.url),
  "utf8",
);

function frozenApiBody(): string {
  const match = preloadSource.match(
    /const api: LovelyResApi = Object\.freeze\(\{(?<body>[\s\S]*?)^\}\);/mu,
  );
  expect(match?.groups?.body).toBeDefined();
  return match?.groups?.body ?? "";
}

describe("central Middleware Electron boundary", () => {
  it("keeps exactly three read methods in the frozen exact 117 preload", () => {
    const body = frozenApiBody();
    const names = [...body.matchAll(/^  (?<name>[A-Za-z_$][A-Za-z0-9_$]*):/gmu)]
      .map((match) => match.groups?.name);
    expect(names).toHaveLength(117);
    expect(names.filter((name) => name === "discoverMiddleware")).toEqual(["discoverMiddleware"]);
    expect(names.filter((name) => name === "loadMiddlewareConfiguration"))
      .toEqual(["loadMiddlewareConfiguration"]);
    expect(names.filter((name) => name === "listMiddlewareHistory"))
      .toEqual(["listMiddlewareHistory"]);
  });

  it("registers two opaque arity-one routes and one exact opaque-handle object route", () => {
    for (const channel of [
      "lovelyres:middleware:discover",
      "lovelyres:middleware:configuration:load",
      "lovelyres:middleware:history:list",
    ]) expect((mainSource.match(new RegExp(channel, "gu")) ?? [])).toHaveLength(1);

    const boundary = mainSource.slice(
      mainSource.indexOf('ipcMain.handle("lovelyres:middleware:discover"'),
      mainSource.indexOf('ipcMain.handle("lovelyres:check-audit:catalog:get"'),
    );
    expect((boundary.match(/values\.length !== 1/gu) ?? [])).toHaveLength(3);
    expect((boundary.match(/!isMiddlewareOpaqueHandle\(values\[0\]\)/gu) ?? []))
      .toHaveLength(2);
    expect(boundary).toContain(
      'hasOnlyKeys(value, ["bindingHandle", "discoveryHandle", "instanceHandle"])',
    );
    expect((boundary.match(/!isMiddlewareOpaqueHandle\(value\.[a-zA-Z]+Handle\)/gu) ?? []))
      .toHaveLength(3);
    expect(boundary).not.toMatch(/\b(?:path|command|terminal|export|plan|confirm|execute|mutat)/iu);
  });

  it("keeps the aggregate API typed, target-opaque and read-only", () => {
    const api = contractSource.slice(
      contractSource.indexOf("export interface LovelyResApi"),
      contractSource.indexOf("type JsonRecord"),
    );
    expect(api).toContain(
      "discoverMiddleware(bindingHandle: string): Promise<MiddlewareDiscovery>;",
    );
    expect(api).toMatch(
      /loadMiddlewareConfiguration\(\s*bindingHandle: string,\s*discoveryHandle: string,\s*instanceHandle: string,\s*\): Promise<MiddlewareConfiguration>;/u,
    );
    expect(api).toContain(
      "listMiddlewareHistory(bindingHandle: string): Promise<MiddlewareHistory>;",
    );
    for (const forbidden of [
      "planMiddleware",
      "confirmMiddleware",
      "executeMiddleware",
      "restoreMiddleware",
      "exportMiddleware",
      "openMiddlewareTerminal",
      "readMiddlewareFile",
      "invoke(",
    ]) expect(api).not.toContain(forbidden);
  });

  it("closes Middleware capabilities before the real SSH disconnect", () => {
    const branch = backendSource.split("RpcMethod::SshBindingDisconnect =>")[1]
      ?.split("RpcMethod::TerminalOpen")[0] ?? "";
    const close = branch.indexOf("self.middleware_read.close_binding(&params.binding_handle);");
    const disconnect = branch.indexOf(".disconnect_binding(&params.binding_handle)");
    expect(close).toBeGreaterThanOrEqual(0);
    expect(disconnect).toBeGreaterThan(close);
  });
});
