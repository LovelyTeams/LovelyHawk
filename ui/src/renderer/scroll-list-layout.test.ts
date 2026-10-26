import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

function rendererDir(): string {
  return path.dirname(new URL(import.meta.url).pathname.replace(/^\/([a-z]:)/iu, "$1"));
}

function stylesheets(): { name: string; css: string }[] {
  return readdirSync(rendererDir())
    .filter((name) => name.endsWith(".css"))
    .map((name) => ({ name, css: readFileSync(path.join(rendererDir(), name), "utf8") }));
}

/** Selector -> the direct-child rule that must opt out of flex shrinking. */
const SCROLL_LISTS: Record<string, string> = {
  ".ai-history-list": ".ai-history-row",
  ".emergency-commands-list": ".emergency-command-group",
  ".notes-list": ".note-row",
  ".connection-list": ".connection-list-row",
  ".sftp-operation-dialog": ".sftp-operation-dialog > *",
  ".emergency-path-dialog": ".emergency-path-dialog > *",
  ".kubernetes-action-dialog": ".kubernetes-action-dialog > *",
  ".docker-action-dialog": ".docker-action-dialog > *",
  ".baseline-card-grid": ".baseline-card-grid > *",
  ".baseline-file-pane": ".baseline-file-pane > *",
  ".log-analysis-list": ".log-analysis-group",
  ".system-info-file-scroll": ".system-info-file",
  ".config-product-list": ".config-product-list button",
  // The generator's preview column scrolls when a short window cannot hold
  // its header, file, notes and buttons; only the file panel grows, and it
  // keeps a minimum so the text never slides under what follows it.
  ".config-preview": ".config-preview > *",
  // Both context menus scroll now, because a menu taller than the window used
  // to be clipped by it instead — and the item that fell off the bottom was
  // 删除. A scrolling flex column squeezes its children, so the items pin
  // their own height. See menu-placement.ts.
  ".sftp-context-menu": ".sftp-context-menu button",
  ".emergency-path-menu": ".emergency-path-menu button",
  // The row menu on the system-information tables: forty items for a process,
  // so it scrolls on a short window, and each item pins its own height.
  ".system-info-row-menu": ".system-info-row-menu button",
  // Each group's actions open in a submenu that scrolls the same way.
  ".system-info-row-submenu": ".system-info-row-menu button",
  // The row action dialog body, which scrolls when an inspection output or a
  // plan summary runs long.
  ".system-info-action-body": ".system-info-action-body > *",
  // The save confirmation, which scrolls if a plan summary runs long.
  ".file-editor-dialog": ".file-editor-dialog > *",
  // The Kubernetes details, which scroll when a describe output runs long.
  ".kubernetes-detail-backdrop > .kubernetes-detail": ".kubernetes-detail-backdrop > .kubernetes-detail > *",
  // The JARs a scan found, the class list of an opened JAR, and the plan
  // dialog of Java hot update.
  ".java-jars": ".java-jars li",
  ".java-classes": ".java-classes li",
  ".java-dialog": ".java-dialog > *",
  // The saved log match rules, listed in their dialog.
  ".log-rules-list": ".log-rules-list li",
  // The AI answer under a terminal, which scrolls rather than squeeze the shell.
  ".ssh-window-ai-panel": ".ai-assist-panel",
  ".wir-places": ".wir-places > *",
  // The event log's quick queries and log locations beside the results.
  ".wir-log-rail": ".wir-log-rail > *",
  ".wir-playbooks-rail": ".wir-playbooks-rail > *",
  ".wir-setup-view": ".wir-setup-view > *",
  // Module chrome stays readable; the process module explicitly grows into the remaining space.
  ".wir-workspace": ".wir-workspace > *",
};

function rule(css: string, selector: string): string {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  const match = new RegExp(`(?:^|\\n)${escaped}\\s*\\{([^}]*)\\}`, "u").exec(css);
  return match?.[1] ?? "";
}

describe("scrolling list layout", () => {
  /**
   * A flex column that scrolls still shrinks its children by default, which
   * squeezed the emergency command cards until their titles overlapped the next
   * row. Every row in such a list has to pin its height.
   */
  it("stops every scrolling flex column from squeezing its rows", () => {
    const all = stylesheets();
    for (const [container, row] of Object.entries(SCROLL_LISTS)) {
      const sheet = all.find(({ css }) => rule(css, container) !== "");
      expect(sheet, `${container} rule is missing`).toBeDefined();
      const containerRule = rule(sheet!.css, container);
      expect(containerRule, container).toMatch(/flex-direction: column/u);
      expect(containerRule, container).toMatch(/overflow: auto/u);

      const rowSheet = all.find(({ css }) => rule(css, row) !== "");
      expect(rowSheet, `${row} rule is missing`).toBeDefined();
      expect(rule(rowSheet!.css, row), row).toMatch(/flex:\s*none|flex-shrink:\s*0/u);
    }
  });

  it("keeps the inventory of scrolling flex columns explicit", () => {
    const found: string[] = [];
    for (const { css } of stylesheets()) {
      for (const match of css.matchAll(/(?:^|\n)([^\n{]+)\{([^}]*)\}/gu)) {
        const body = match[2]!.replace(/\s+/gu, " ");
        if (
          body.includes("display: flex") &&
          body.includes("flex-direction: column") &&
          /overflow(?:-y)?: auto/u.test(body)
        ) {
          found.push(match[1]!.trim());
        }
      }
    }
    // A new scrolling list must be added to SCROLL_LISTS above with a pinned row.
    const known = [...Object.keys(SCROLL_LISTS), ".emergency-command-detail",
      ".log-analysis-detail"];
    expect(found.sort()).toEqual(known.sort());
  });
});
