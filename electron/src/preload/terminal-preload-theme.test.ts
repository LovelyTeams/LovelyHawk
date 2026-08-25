import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  DEFAULT_THEME_ID,
  THEMES,
  THEME_ARGUMENT_PREFIX,
} from "../shared/theme-contract";

const source = readFileSync(new URL("./terminal.ts", import.meta.url), "utf8");

describe("terminal preload launch theme", () => {
  it("stays self-contained because the sandbox cannot require sibling modules", () => {
    const imports = [...source.matchAll(/^import\s+(?!type\b)[\s\S]*?from\s+"([^"]+)";/gmu)]
      .map((match) => match[1]!);
    expect(imports).toEqual(["electron"]);
  });

  it("repeats exactly the registered theme ids, prefix, and default", () => {
    const ids = /const THEME_IDS = \[([^\]]*)\];/u.exec(source)?.[1] ?? "";
    expect([...ids.matchAll(/"([a-z-]+)"/gu)].map((match) => match[1]))
      .toEqual(THEMES.map((theme) => theme.id));
    expect(source).toContain(`const THEME_ARGUMENT_PREFIX = "${THEME_ARGUMENT_PREFIX}";`);
    expect(source).toContain(`const DEFAULT_THEME = "${DEFAULT_THEME_ID}";`);
  });

  it("never lets theming block the frozen terminal API", () => {
    expect(source).toMatch(/function applyLaunchTheme\(\): void \{\s*try \{/u);
    expect(source).toMatch(/\} catch \{[\s\S]*?\}\s*\}\s*\n\s*applyLaunchTheme\(\);/u);
    expect(source.indexOf("applyLaunchTheme();"))
      .toBeLessThan(source.indexOf("contextBridge.exposeInMainWorld"));
  });
});
