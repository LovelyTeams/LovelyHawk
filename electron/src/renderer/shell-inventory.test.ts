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
const NOT_WIRED: Record<string, string> = {
  // docs/ELECTRON_UI_LEDGER.json item "sftp" is Pending: the renderer page and
  // crates/lovelyres-core/src/sftp.rs exist, but there is no preload binding,
  // no main handler and no sidecar RPC, so the page has nothing to call.
  SftpBrowserPage: "sftp",
};

describe("application shell inventory", () => {
  it("mounts every page component, or records why it cannot", () => {
    const app = source("App.tsx");
    const components = readdirSync(rendererDir())
      .filter((name) => name.endsWith("Page.tsx"))
      .map((name) => name.slice(0, -".tsx".length));
    expect(components.length).toBeGreaterThan(15);

    for (const component of components) {
      const mounted = app.includes(`<${component}`);
      const excused = component in NOT_WIRED;
      expect(mounted, `${component} must be mounted or listed as not wired`).toBe(!excused);
    }

    const ledger = readFileSync(
      path.join(rendererDir(), "..", "..", "..", "docs", "ELECTRON_UI_LEDGER.json"),
      "utf8",
    ) as string;
    const sections = JSON.parse(ledger) as Record<string, unknown>;
    const entries = Object.values(sections)
      .filter((section): section is { id: string; status: string }[] => Array.isArray(section))
      .flat()
      .filter((entry) => typeof entry === "object" && entry !== null && "id" in entry);
    for (const [component, ledgerId] of Object.entries(NOT_WIRED)) {
      const entry = entries.find((item) => item.id === ledgerId);
      expect(entry, `${component} claims ledger item ${ledgerId}`).toBeDefined();
      // Once the ledger says it shipped, the page has to be reachable.
      expect(entry!.status, `${ledgerId} is no longer pending`).not.toBe("Completed");
    }
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
