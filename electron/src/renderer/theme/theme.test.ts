import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  DEFAULT_THEME_ID,
  THEMES,
  applyTheme,
  isThemeId,
  nextThemeId,
  resolveThemeId,
  themeDefinition,
} from "./theme";
import { themeFromArguments } from "../../shared/theme-contract";
import {
  contrastRatio,
  luminance,
  parseThemeTokenTable,
  themeToken,
} from "./theme-test-utils";

const table = parseThemeTokenTable(
  readFileSync(new URL("./themes.css", import.meta.url), "utf8"),
);

function rendererCssFiles(): string[] {
  const rendererRoot = path.dirname(
    path.dirname(new URL(import.meta.url).pathname.replace(/^\/([a-z]:)/iu, "$1")),
  );
  return readdirSync(rendererRoot)
    .filter((name) => name.endsWith(".css"))
    .map((name) => path.join(rendererRoot, name));
}

describe("theme registry", () => {
  it("registers exactly the SettingsTheme ids with unique labels", () => {
    const contract = readFileSync(
      new URL("../../shared/settings-contract.ts", import.meta.url),
      "utf8",
    );
    // The registry lives in shared/ so main, preload, and the renderer agree.
    const enumSource = /export type SettingsTheme =([^;]+);/u.exec(contract)?.[1] ?? "";
    const contractIds = [...enumSource.matchAll(/"([a-z-]+)"/gu)].map((m) => m[1]!).sort();
    expect([...THEMES.map((theme) => theme.id)].sort()).toEqual(contractIds);
    expect(new Set(THEMES.map((theme) => theme.label)).size).toBe(THEMES.length);
    expect(THEMES.some((theme) => theme.kind === "light")).toBe(true);
    expect(THEMES.some((theme) => theme.kind === "dark")).toBe(true);
  });

  it("resolves unknown ids to the default and cycles through every theme", () => {
    expect(resolveThemeId("dark")).toBe("dark");
    expect(resolveThemeId("no-such-theme")).toBe(DEFAULT_THEME_ID);
    expect(resolveThemeId(undefined)).toBe(DEFAULT_THEME_ID);
    expect(isThemeId("sakura")).toBe(true);
    expect(isThemeId("")).toBe(false);
    expect(themeDefinition("incident-canvas").kind).toBe("dark");
    const seen = new Set<string>();
    let current = resolveThemeId(undefined);
    for (let step = 0; step < THEMES.length; step += 1) {
      seen.add(current);
      current = nextThemeId(current);
    }
    expect(seen.size).toBe(THEMES.length);
    expect(nextThemeId("not-registered")).toBe(THEMES[0]!.id);
  });

  it("stamps data-theme on the root element", () => {
    const root = { dataset: {} as DOMStringMap };
    expect(applyTheme(root, "dark")).toBe("dark");
    expect(root.dataset["theme"]).toBe("dark");
    expect(applyTheme(root, "bogus")).toBe(DEFAULT_THEME_ID);
    expect(root.dataset["theme"]).toBe(DEFAULT_THEME_ID);
  });

  it("derives the scrim color by compositing the backdrop over the chrome color", () => {
    for (const theme of THEMES) {
      const backdrop = /rgb\((\d+) (\d+) (\d+) \/ (\d+)%\)/u
        .exec(themeToken(table, theme.id, "backdrop"));
      expect(backdrop, `${theme.id} backdrop must be rgb(r g b / a%)`).not.toBeNull();
      const alpha = Number(backdrop![4]) / 100;
      const chrome = themeToken(table, theme.id, "chrome-bg").slice(1);
      const composited = [0, 1, 2].map((channel) => {
        const over = Number(backdrop![channel + 1]);
        const under = Number.parseInt(chrome.slice(channel * 2, channel * 2 + 2), 16);
        return Math.round(alpha * over + (1 - alpha) * under);
      });
      const expected = `#${composited.map((v) => v.toString(16).padStart(2, "0")).join("")}`;
      expect(theme.chromeScrimColor, `${theme.id} chromeScrimColor`).toBe(expected);
      // The symbol color is reused unchanged, so it must survive the dimming.
      expect(
        contrastRatio(theme.chromeSymbolColor, theme.chromeScrimColor),
        `${theme.id}: window controls over the scrim`,
      ).toBeGreaterThanOrEqual(4.5);
    }
  });

  it("keeps the native colors main paints identical to the CSS tokens", () => {
    for (const theme of THEMES) {
      expect(theme.chromeColor, `${theme.id} chromeColor`)
        .toBe(themeToken(table, theme.id, "chrome-bg"));
      expect(theme.chromeSymbolColor, `${theme.id} chromeSymbolColor`)
        .toBe(themeToken(table, theme.id, "chrome-text"));
      expect(theme.windowBackground, `${theme.id} windowBackground`)
        .toBe(themeToken(table, theme.id, "bg"));
      expect(theme.terminalBackground, `${theme.id} terminalBackground`)
        .toBe(themeToken(table, theme.id, "term-panel"));
    }
  });

  it("reads a launched window's theme from its argument switch", () => {
    for (const theme of THEMES) {
      expect(themeFromArguments(["--other", `--lovelyres-theme=${theme.id}`])).toBe(theme.id);
    }
    expect(themeFromArguments([])).toBe(DEFAULT_THEME_ID);
    expect(themeFromArguments(["--lovelyres-theme="])).toBe(DEFAULT_THEME_ID);
    expect(themeFromArguments(["--lovelyres-theme=not-a-theme"])).toBe(DEFAULT_THEME_ID);
  });
});

describe("themes.css token table", () => {
  it("defines a block for every registered theme and no unregistered block", () => {
    const cssIds = [...table.keys()].sort();
    expect(cssIds).toEqual([...THEMES.map((theme) => theme.id)].sort());
  });

  it("gives every theme exactly the same token set as the default theme", () => {
    const baseline = [...table.get(DEFAULT_THEME_ID)!.keys()].sort();
    expect(baseline.length).toBeGreaterThan(60);
    for (const theme of THEMES) {
      expect([...table.get(theme.id)!.keys()].sort(), theme.id).toEqual(baseline);
    }
  });

  it("contains only well-formed colors, gradients, and shadows", () => {
    for (const [themeId, tokens] of table) {
      for (const [name, value] of tokens) {
        const label = `${themeId} --${name}`;
        for (const hex of value.matchAll(/#[0-9a-z]+/giu)) {
          expect(hex[0], label).toMatch(/^#(?:[0-9a-f]{3}|[0-9a-f]{6}|[0-9a-f]{8})$/iu);
        }
        expect(value, label).toMatch(
          /^(?:#[0-9a-f]{3,8}|rgb\([^)]+\)|linear-gradient\([\s\S]+\)|radial-gradient\([\s\S]+\)|(?:0|-?\d[\d.]*(?:px|em|rem|%)?)(?:\s|$)|light|dark)/iu,
        );
      }
    }
  });
});

const CONTRAST_PAIRS: readonly [foreground: string, background: string, minimum: number][] = [
  ["text", "bg", 7],
  ["text", "surface", 7],
  ["text", "surface-alt", 7],
  ["text-secondary", "surface", 4.5],
  ["muted", "surface", 4.5],
  ["muted", "surface-alt", 4.5],
  ["muted", "bg", 4.5],
  ["faint", "surface", 3],
  ["accent-text", "accent-soft", 4.5],
  ["accent-text", "surface", 4.5],
  ["on-accent", "accent", 4.5],
  ["accent", "surface", 3],
  ["danger-text", "danger-soft", 4.5],
  ["danger", "surface", 3],
  ["success-text", "success-soft", 4.5],
  ["success", "surface", 3],
  ["warning-text", "warning-soft", 4.5],
  ["warning", "surface", 3],
  ["info-text", "info-soft", 4.5],
  ["info", "surface", 3],
  ["chrome-text", "chrome-bg", 7],
  ["chrome-muted", "chrome-bg", 4.5],
  ["chrome-accent", "chrome-bg", 4.5],
  ["console-text", "console-bg", 7],
  ["console-text", "console-surface", 7],
  ["console-muted", "console-surface", 4.5],
  ["console-muted", "console-bg", 4.5],
  ["console-accent", "console-surface", 4.5],
  ["console-danger-text", "console-surface", 4.5],
  ["console-success-text", "console-surface", 4.5],
  ["console-warning-text", "console-surface", 4.5],
  ["console-danger-text", "console-danger-surface", 4.5],
  ["console-success-text", "console-success-surface", 4.5],
  ["console-warning-text", "console-warning-surface", 4.5],
  ["console-accent", "console-accent-surface", 4.5],
  ["term-text", "term-bg", 7],
  ["term-muted", "term-bg", 4.5],
  ["term-error", "term-bg", 4.5],
  ["term-accent", "term-bg", 4.5],
];

describe("theme contrast", () => {
  for (const theme of THEMES) {
    it(`keeps ${theme.id} foregrounds readable`, () => {
      for (const [foreground, background, minimum] of CONTRAST_PAIRS) {
        const ratio = contrastRatio(
          themeToken(table, theme.id, foreground),
          themeToken(table, theme.id, background),
        );
        expect(
          ratio,
          `${theme.id}: --${foreground} on --${background}`,
        ).toBeGreaterThanOrEqual(minimum);
      }
    });
  }
});

/** 浅色主题不得出现深色表面，深色主题不得出现浅色表面（用户约定）。 */
const SURFACE_TOKENS = [
  "bg", "surface", "surface-alt", "surface-inset", "surface-hover", "input-bg",
  "chrome-bg", "chrome-bg-deep", "console-bg", "console-surface",
  "term-panel", "term-bg", "term-control-bg",
  "accent-soft", "danger-soft", "success-soft", "warning-soft", "info-soft",
  "console-accent-surface", "console-danger-surface",
  "console-success-surface", "console-warning-surface",
] as const;

describe("theme brightness consistency", () => {
  for (const theme of THEMES) {
    it(`keeps every ${theme.id} surface ${theme.kind}`, () => {
      for (const token of SURFACE_TOKENS) {
        const value = themeToken(table, theme.id, token);
        const brightness = luminance(value);
        if (theme.kind === "light") {
          expect(brightness, `${theme.id}: --${token} (${value}) must stay light`)
            .toBeGreaterThanOrEqual(0.45);
        } else {
          expect(brightness, `${theme.id}: --${token} (${value}) must stay dark`)
            .toBeLessThanOrEqual(0.2);
        }
      }
    });
  }
});

describe("token discipline", () => {
  it("keeps every non-theme renderer stylesheet free of color literals", () => {
    for (const file of rendererCssFiles()) {
      const css = readFileSync(file, "utf8");
      const literals = [
        ...css.matchAll(/#[0-9a-f]{3,8}\b|rgba?\(|hsla?\(/giu),
      ].map((match) => match[0]);
      expect(literals, path.basename(file)).toEqual([]);
    }
  });

  /**
   * A surface token as a foreground (or the reverse) survives one theme by luck
   * and turns invisible in the next, so the roles are enforced here.
   */
  it("never uses a surface token as text or a text token as a surface", () => {
    const surfaceOnly = [
      "bg", "surface", "surface-alt", "surface-inset", "surface-hover", "input-bg",
      "accent-soft", "danger-soft", "success-soft", "warning-soft", "info-soft",
      "chrome-bg", "chrome-bg-deep", "console-bg", "console-surface", "term-bg",
      "term-panel", "term-control-bg", "console-accent-surface",
      "console-danger-surface", "console-success-surface", "console-warning-surface",
    ].join("|");
    const textOnly = [
      "text", "text-secondary", "muted", "faint", "accent-text", "on-accent",
      "danger-text", "success-text", "warning-text", "info-text", "chrome-text",
      "chrome-muted", "chrome-faint", "console-text", "console-muted",
      "console-faint", "console-danger-text", "console-success-text",
      "console-warning-text", "term-text", "term-muted",
    ].join("|");
    const asForeground = new RegExp(`(?<![a-z-])color:\\s*var\\(--(?:${surfaceOnly})\\)`, "giu");
    const asBackground = new RegExp(`background[a-z-]*:[^;]*var\\(--(?:${textOnly})\\)`, "giu");
    for (const file of rendererCssFiles()) {
      const css = readFileSync(file, "utf8");
      expect([...css.matchAll(asForeground)].map((m) => m[0]), path.basename(file)).toEqual([]);
      expect([...css.matchAll(asBackground)].map((m) => m[0]), path.basename(file)).toEqual([]);
    }
  });
});
