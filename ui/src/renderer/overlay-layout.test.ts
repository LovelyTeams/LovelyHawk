import { readFileSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

function rendererFile(name: string): string {
  const dir = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([a-z]:)/iu, "$1"));
  return readFileSync(path.join(dir, name), "utf8");
}

function rule(css: string, selector: string): string {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  return new RegExp(`(?:^|\\n)${escaped}\\s*\\{([^}]*)\\}`, "u").exec(css)?.[1] ?? "";
}

describe("command output lines", () => {
  /**
   * The numbers and the lines are two separate columns. A line that named a
   * path carried a 文件操作 button that the page's general button rule made
   * 36px tall, so from that line on every number sat beside the wrong text.
   */
  it("keeps every number and every line exactly one line tall", () => {
    const css = rendererFile("emergency-commands.css");
    const body = rule(css, ".emergency-command-gutter > span,\n.emergency-command-output pre > span");
    expect(body).toMatch(/height:\s*1lh/u);
    expect(body).toMatch(/flex:\s*none/u);
  });

  it("does not let the path button grow its line", () => {
    const css = rendererFile("file-evidence.css");
    const body = rule(css, ".emergency-commands-page button.emergency-path-open");
    // The page rule it overrides sets a 36px floor and 8px padding.
    expect(body).toMatch(/min-height:\s*0/u);
    expect(body).toMatch(/padding:\s*0 /u);
    expect(rule(rendererFile("emergency-commands.css"), ".emergency-commands-page button")).toMatch(/min-height:\s*36px/u);
  });
});

describe("Docker 更多 list", () => {
  /**
   * The actions column is sticky, and each sticky cell is a stacking layer of
   * its own: a list inside one was painted under the next row, and a click on
   * 删除 landed on that row's 暂停. It is fixed and rendered into the body.
   */
  it("is fixed to the window and portaled out of the row", () => {
    expect(rule(rendererFile("docker-page.css"), ".docker-overflow-menu")).toMatch(/position:\s*fixed/u);
    const page = rendererFile("DockerPage.tsx");
    expect(page).toMatch(/return createPortal\(\s*<div\s+ref=\{ref\}\s+className="docker-overflow-menu"/u);
    expect(page).toContain("document.body,");
  });

  it("keeps its buttons styled outside the page subtree", () => {
    const css = rendererFile("docker-page.css");
    expect(rule(css, ":is(.docker-page, .docker-overflow-menu) .docker-action-button")).toMatch(/display:\s*inline-flex/u);
    expect(rule(css, ":is(.docker-page, .docker-overflow-menu) .docker-action-button.is-danger")).toMatch(/var\(--danger-text\)/u);
    expect(css).not.toMatch(/(?:^|\n)\.docker-page \.docker-action-button/u);
  });
});
