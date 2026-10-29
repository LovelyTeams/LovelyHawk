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
  NginxRepairPage: "ConfigurationPage",
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
    expect(terminalWindow).toContain("window.lovelyhawkTerminal");
    expect(terminalWindow).not.toContain("bindingHandle");

    const bridge = readFileSync(path.join(rendererDir(), "..", "host", "terminal-api.ts"), "utf8");
    for (const command of ["sftp_open", "sftp_list", "sftp_read_text"]) {
      expect(bridge).toContain(`"${command}"`);
    }
    // The host resolves the binding from the calling window, so none is sent.
    expect(bridge).not.toContain("bindingHandle");

    const commands = readFileSync(
      path.join(rendererDir(), "..", "..", "..", "crates", "lovelyhawk-desktop", "src", "child_commands.rs"),
      "utf8",
    );
    // Every command a terminal-family window may call resolves its window
    // first. The number is here to notice a new command, and a new command
    // that resolves its window is the correct kind of new command.
    const handlers = [...commands.matchAll(/#\[tauri::command\]\npub (?:async )?fn (?<name>[a-z_]+)/gu)]
      .map((match) => match.groups?.name);
    expect(handlers).toHaveLength(29);
    expect(handlers).toContain("system_info_file_open");
    expect(handlers).toContain("terminal_open_tab");
    expect(handlers).toContain("terminal_close_tab");
    expect(handlers).toContain("terminal_ai_assist");
    expect(handlers).toContain("directory_terminal_open");
    const bodies = commands.split("#[tauri::command]").slice(1);
    expect(bodies).toHaveLength(handlers.length);
    for (const body of bodies) {
      if (body.includes("fn system_info_file_open")) {
        expect(body).toContain('window.label() != "main"');
        expect(body).toContain("host.current_binding()");
        continue;
      }
      expect(body).toMatch(/scope\(&window, &host\)\?|sftp_plan_step\(\s*&window,\s*&host,/u);
    }
    expect(commands).toContain("scope.binding_handle");
  });

  it("offers a way to connect from any page that is waiting for a target", () => {
    const app = source("App.tsx");
    expect(app).toContain('activeTarget === null && activePage?.capability === "connected-target"');
    expect(app).toContain("<TargetRequiredBanner");
    // One card, not a banner over the page's own "connect first" box saying
    // the same thing: the page stays mounted behind it, hidden, so its state
    // and any unsaved edit keep their own lifecycle.
    expect(app.indexOf("<TargetRequiredBanner")).toBeLessThan(app.indexOf("<Suspense"));
    expect(app).toContain('<div className="content-page" hidden={waitingForTarget}>');
    expect(app).toContain("summary={activePage.summary}");
    expect(app).toContain("sections={activePage.sections}");
    expect(source("styles.css")).toContain(".content-page:not([hidden]) { display: contents; }");
    const banner = source("TargetRequiredBanner.tsx");
    expect(banner).toContain('data-testid="content-connect-target"');
    expect(banner).toContain("连接目标");
    // Connecting still goes through the connection manager and its prompts.
    expect(banner).not.toMatch(/startSshConnect|window\.lovelyhawk/u);
    const css = source("styles.css");
    expect(css).toContain(".content-connect-action");
    expect(css).not.toMatch(/\.content-connect-action \{[^}]*position: absolute/u);
    // The sidebar keeps the same entry at the top of the navigation.
    expect(source("SidebarTarget.tsx")).toContain('data-testid="sidebar-connect-target"');
  });

  /** The migration marker was build bookkeeping, never news for the operator. */
  it("keeps build bookkeeping out of the sidebar", () => {
    const app = source("App.tsx");
    expect(app).not.toContain('page.migrationState === "ready"');
    expect(app).not.toContain("已迁移");
    expect(source("styles.css")).not.toContain(".nav-item > i");
  });
});
