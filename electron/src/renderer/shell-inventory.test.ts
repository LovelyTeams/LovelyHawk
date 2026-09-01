import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

function rendererDir(): string {
  return path.dirname(new URL(import.meta.url).pathname.replace(/^\/([a-z]:)/iu, "$1"));
}

function source(name: string): string {
  return readFileSync(path.join(rendererDir(), name), "utf8");
}

/**
 * Page components that exist but are not reachable from the shell, with the
 * reason. A component may only sit here while its Electron boundary is still
 * unbuilt; wiring it means deleting its line, and building a new page without
 * wiring it means adding one. Neither can happen silently.
 */
const NOT_WIRED: Record<string, string> = {};

/** Page components the SSH window hosts instead of the main shell. */
const IN_TERMINAL_WINDOW = ["SftpBrowserPage"];

/**
 * Page components another page hosts instead of the shell. Checking a
 * configuration and writing one are two views of one job, so they share a
 * page; each half is still a page component of its own.
 */
const HOSTED_BY: Record<string, string> = {
  BaselinePage: "ConfigurationPage",
  ConfigGeneratorPage: "ConfigurationPage",
};

describe("application shell inventory", () => {
  it("mounts every page component, or records why it cannot", () => {
    const app = source("App.tsx");
    const components = readdirSync(rendererDir())
      .filter((name) => name.endsWith("Page.tsx"))
      .map((name) => name.slice(0, -".tsx".length));
    expect(components.length).toBeGreaterThan(11);

    const terminalWindow = source("TerminalWindow.tsx");
    for (const component of components) {
      const host = HOSTED_BY[component];
      const hostSource = host === undefined ? "" : source(`${host}.tsx`);
      const mounted = app.includes(`<${component}`) ||
        terminalWindow.includes(`<${component}`) ||
        hostSource.includes(`<${component}`);
      const excused = component in NOT_WIRED;
      expect(mounted, `${component} must be mounted or listed as not wired`).toBe(!excused);
    }
    for (const component of IN_TERMINAL_WINDOW) {
      expect(terminalWindow, `${component} belongs to the SSH window`).toContain(`<${component}`);
      expect(app, `${component} must not also sit in the main shell`).not.toContain(`<${component}`);
    }

  });

  /** The read-only browser rides with the shell it belongs to. */
  it("gives the SSH window a file browser that never holds target identity", () => {
    const terminalWindow = source("TerminalWindow.tsx");
    expect(terminalWindow).toContain('data-testid="toggle-remote-files"');
    expect(terminalWindow).toContain("window.lovelyresTerminal");
    expect(terminalWindow).not.toContain("bindingHandle");

    const preload = readFileSync(
      path.join(rendererDir(), "..", "preload", "terminal.ts"),
      "utf8",
    );
    for (const channel of [
      "lovelyres:terminal:sftp:open",
      "lovelyres:terminal:sftp:directory:list",
      "lovelyres:terminal:sftp:text:read",
    ]) expect(preload).toContain(channel);
    // Main resolves the binding from the calling window, so none is sent.
    expect(preload).not.toContain("bindingHandle");

    const main = readFileSync(path.join(rendererDir(), "..", "main", "index.ts"), "utf8");
    const boundary = main.slice(main.indexOf('ipcMain.handle("lovelyres:terminal:sftp:open"'));
    // Every handler in this tail resolves its window before doing anything —
    // the three browser routes plus the two that open a file in a window of
    // its own. The number is here to notice a new handler, and a new handler
    // that resolves its window is the correct kind of new handler.
    const handlers = [...boundary.matchAll(/ipcMain\.handle\("(?<channel>[^"]+)"/gu)]
      .map((match) => match.groups?.channel);
    expect(handlers).toEqual([
      "lovelyres:terminal:sftp:open",
      "lovelyres:terminal:sftp:directory:list",
      "lovelyres:terminal:file-editor:open",
      "lovelyres:terminal:file-editor:target",
      "lovelyres:terminal:sftp:text:read",
    ]);
    expect((boundary.match(/terminalContextFor\(event\)/gu) ?? []))
      .toHaveLength(handlers.length);
    expect(boundary).toContain("context.bindingHandle");
  });

  it("offers a way to connect from any page that is waiting for a target", () => {
    const app = source("App.tsx");
    expect(app).toContain('activeTarget === null && activePage?.capability === "connected-target"');
    expect(app).toContain('data-testid="content-connect-target"');
    expect(app).toContain("连接目标");
    expect(source("styles.css")).toContain(".content-connect-action");
  });

  /** The migration marker was build bookkeeping, never news for the operator. */
  it("keeps build bookkeeping out of the sidebar", () => {
    const app = source("App.tsx");
    expect(app).not.toContain('page.migrationState === "ready"');
    expect(app).not.toContain("已迁移");
    expect(source("styles.css")).not.toContain(".nav-item > i");
  });
});
