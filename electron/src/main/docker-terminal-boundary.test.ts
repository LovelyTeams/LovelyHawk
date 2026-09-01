import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const mainSource = readFileSync(new URL("./index.ts", import.meta.url), "utf8");
const preloadSource = readFileSync(new URL("../preload/index.ts", import.meta.url), "utf8");
const terminalPreloadSource = readFileSync(
  new URL("../preload/terminal.ts", import.meta.url),
  "utf8",
);
const backendClientSource = readFileSync(new URL("./backend-client.ts", import.meta.url), "utf8");
const backendSource = readFileSync(
  new URL("../../../crates/lovelyres-electron-backend/src/lib.rs", import.meta.url),
  "utf8",
);
const coreSource = readFileSync(
  new URL("../../../crates/lovelyres-core/src/docker.rs", import.meta.url),
  "utf8",
);

function frozenApiBody(): string {
  const match = preloadSource.match(
    /const api: LovelyResApi = Object\.freeze\(\{(?<body>[\s\S]*?)^\}\);/mu,
  );
  expect(match?.groups?.body).toBeDefined();
  return match?.groups?.body ?? "";
}

describe("container terminal boundary", () => {
  it("adds exactly one launch method to the frozen exact 124 preload", () => {
    const body = frozenApiBody();
    const names = [...body.matchAll(/^  (?<name>[A-Za-z_$][A-Za-z0-9_$]*):/gmu)]
      .map((match) => match.groups?.name);
    expect(names).toHaveLength(124);
    expect(names.filter((candidate) => candidate === "openDockerContainerTerminal"))
      .toEqual(["openDockerContainerTerminal"]);
    // The renderer opens a window. It has no way to run a command in a
    // container, and no way to name a shell.
    for (const forbidden of [
      "execDockerContainer", "runDockerContainerCommand", "openDockerContainerShell",
    ]) expect(body).not.toContain(forbidden);
    expect(body).not.toMatch(/shell:/u);
  });

  it("registers one closed IPC route that carries only opaque handles", () => {
    const channel = "lovelyres:docker:container:terminal:open";
    expect((mainSource.match(new RegExp(channel, "gu")) ?? [])).toHaveLength(1);
    expect((preloadSource.match(new RegExp(channel, "gu")) ?? [])).toHaveLength(1);

    const route = mainSource.slice(
      mainSource.indexOf(`ipcMain.handle("${channel}"`),
      mainSource.indexOf('ipcMain.handle("lovelyres:terminal:open"'),
    );
    expect(route).toContain("validateSender(event)");
    expect(route).toContain(
      'hasOnlyKeys(value, ["snapshotHandle", "containerHandle", "containerName"])',
    );
    expect(route).toContain("isDockerOpaqueHandle(value.snapshotHandle)");
    expect(route).toContain("isDockerOpaqueHandle(value.containerHandle)");
    expect(route).toContain("isDockerContainerName(value.containerName)");
    // The binding is the one already current, never one the caller names.
    expect(route).toContain("terminalBindingState.currentBindingHandle()");
    expect(route).not.toContain("values[0].bindingHandle");
  });

  it("settles which container a window is for when the window is created", () => {
    // The window renderer asks for "a terminal" and gets the kind its window
    // is for. If it could pass a container handle at open time, a window
    // opened against one container could be pointed at another.
    expect(terminalPreloadSource).toContain(
      'open: (columns: number, rows: number) =>',
    );
    expect(terminalPreloadSource).not.toContain("containerHandle");
    expect(terminalPreloadSource).not.toContain("snapshotHandle");

    const open = mainSource.slice(
      mainSource.indexOf('ipcMain.handle("lovelyres:terminal:open"'),
      mainSource.indexOf('ipcMain.handle("lovelyres:terminal:poll"'),
    );
    expect(open).toContain("const container = context.container;");
    expect(open).toContain("backend.openTerminal(context.bindingHandle, columns, rows)");
    expect(open).toContain("backend.openDockerContainerTerminal(");
    expect(open).toContain("container.snapshotHandle");
    expect(open).toContain("container.containerHandle");
  });

  it("gives a container its own window rather than replacing the host shell", () => {
    expect(mainSource).toContain(
      "function terminalWindowKey(bindingHandle: string, containerHandle?: string): string {",
    );
    expect(mainSource).toContain("terminalWindowKey(bindingHandle, container?.containerHandle)");
    // Disconnecting still takes every window on that binding with it,
    // container windows included, because they are all keyed by it.
    expect(mainSource).toContain("closeTerminalWindowsForBinding(bindingHandle)");
  });

  it("validates the backend response as strictly as any other terminal open", () => {
    const method = backendClientSource.slice(
      backendClientSource.indexOf("async openDockerContainerTerminal("),
      backendClientSource.indexOf("async loadEmergencyCommandCatalog("),
    );
    // Through the frozen map, not a string built at the call site.
    expect(method).toContain("DOCKER_TERMINAL_RPC_METHODS.open");
    expect(method).toContain("isTerminalBindingHandle(bindingHandle)");
    expect(method).toContain("[snapshotHandle, containerHandle].every(isDockerOpaqueHandle)");
    expect(method).toContain("isTerminalSize(columns, rows)");
    expect(method).toContain("isContainerTerminalOpened(value)");
    expect(method).toContain("value.columns !== columns");
    expect(method).toContain("value.rows !== rows");
    expect(backendClientSource).toContain('open: "docker.container.terminal.open"');
  });

  it("resolves the container through the read registry and probes the shell", () => {
    const dispatch = backendSource.slice(
      backendSource.indexOf("async fn open_container_terminal("),
      backendSource.indexOf("async fn dispatch("),
    );
    // The handle becomes an identity under the read side's scope rules, so a
    // forged one, or one from a refreshed snapshot, names nothing.
    expect(dispatch).toContain("resolve_container_for_mutation(");
    expect(dispatch).toContain("detect_shell(&session, &container)");
    expect(dispatch).toContain("open_container(");
    // The wire never names a shell program or a container id.
    expect(dispatch).not.toMatch(/params\.shell|params\.container_id/u);

    // Core refuses anything that is not running, and says so plainly when the
    // image has no shell to enter.
    expect(coreSource).toContain('format!("container must be running; current state is {state}")');
    expect(coreSource).toContain("for lr_sh in bash ash sh");
  });
});
