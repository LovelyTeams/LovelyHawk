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
  ".log-analysis-list": ".log-analysis-group",
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
