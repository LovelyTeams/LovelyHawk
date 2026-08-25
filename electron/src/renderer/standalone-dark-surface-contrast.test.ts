import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { THEMES } from "./theme/theme";
import { parseThemeTokenTable, themeToken, contrastRatio } from "./theme/theme-test-utils";

const table = parseThemeTokenTable(
  readFileSync(new URL("./theme/themes.css", import.meta.url), "utf8"),
);

describe("standalone dark-surface foregrounds", () => {
  it("keeps Application Log list text on explicit console tokens", () => {
    const css = readFileSync(new URL("./application-log.css", import.meta.url), "utf8");
    expect(css).toMatch(/\.application-log-list \{[^}]*color: var\(--console-text\);[^}]*background: var\(--console-bg\);/u);
    expect(css).toMatch(/\.application-log-entry strong \{ color: var\(--console-text\); \}/u);
    expect(css).toMatch(/\.application-log-entry dd \{[^}]*color: var\(--console-text\);/u);
  });

  it("gives Integrity dark cards an explicit inherited console foreground", () => {
    const css = readFileSync(new URL("./integrity.css", import.meta.url), "utf8");
    expect(css).toMatch(/\.integrity-page \{[^}]*color: var\(--console-text\);/u);
    expect(css).toMatch(/\.integrity-heading-actions button,[\s\S]*?color: inherit;/u);
  });

  it("keeps console foregrounds readable in every registered theme", () => {
    for (const theme of THEMES) {
      expect(
        contrastRatio(
          themeToken(table, theme.id, "console-text"),
          themeToken(table, theme.id, "console-bg"),
        ),
        `${theme.id}: --console-text on --console-bg`,
      ).toBeGreaterThanOrEqual(7);
      expect(
        contrastRatio(
          themeToken(table, theme.id, "console-muted"),
          themeToken(table, theme.id, "console-surface"),
        ),
        `${theme.id}: --console-muted on --console-surface`,
      ).toBeGreaterThanOrEqual(4.5);
    }
  });
});
