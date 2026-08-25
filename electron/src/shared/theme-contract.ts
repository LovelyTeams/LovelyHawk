import type { SettingsTheme } from "./settings-contract.js";

export type ThemeKind = "light" | "dark";

export interface ThemeDefinition {
  /** Stable id, persisted through the settings backend (SettingsTheme). */
  readonly id: SettingsTheme;
  /** Chinese label shown by theme pickers. */
  readonly label: string;
  /** Brightness family. Light themes must not show dark surfaces anywhere. */
  readonly kind: ThemeKind;
  /**
   * Native colors main needs before renderer paint. They mirror the CSS tokens
   * of the same theme (--chrome-bg/--chrome-text/--bg/--term-panel); a theme
   * test fails if the two ever drift apart.
   */
  readonly chromeColor: string;
  /**
   * Chrome color composited under the modal backdrop. The OS draws the window
   * controls above the page, so CSS cannot dim them; main repaints the overlay
   * with this while a modal owns the renderer.
   */
  readonly chromeScrimColor: string;
  readonly chromeSymbolColor: string;
  readonly windowBackground: string;
  readonly terminalBackground: string;
}

/**
 * 主题注册表。新增配色：在 renderer/theme/themes.css 增加同名
 * :root[data-theme="…"] 块、在 settings-contract.ts 的 SettingsTheme 枚举
 * 登记，然后在这里加一行。theme.test.ts 会校验 token 完整性、对比度、
 * 明暗一致性，以及此处的原生颜色与 CSS token 完全一致。
 */
export const THEMES: readonly ThemeDefinition[] = [
  {
    id: "light",
    label: "浅色",
    kind: "light",
    chromeColor: "#ffffff",
    chromeScrimColor: "#a0a3a9",
    chromeSymbolColor: "#111827",
    windowBackground: "#f5f7fa",
    terminalBackground: "#eef1f6",
  },
  {
    id: "dark",
    label: "深色",
    kind: "dark",
    chromeColor: "#111823",
    chromeScrimColor: "#0a0e15",
    chromeSymbolColor: "#e8edf5",
    windowBackground: "#0c1119",
    terminalBackground: "#0a1017",
  },
  {
    id: "sakura",
    label: "樱花",
    kind: "light",
    chromeColor: "#ffffff",
    chromeScrimColor: "#aba3a7",
    chromeSymbolColor: "#2c1a22",
    windowBackground: "#fbf6f8",
    terminalBackground: "#f7eaef",
  },
  {
    id: "incident-canvas",
    label: "事件画布",
    kind: "dark",
    chromeColor: "#080d14",
    chromeScrimColor: "#04080c",
    chromeSymbolColor: "#eef4fb",
    windowBackground: "#05080c",
    terminalBackground: "#04070a",
  },
];

export const DEFAULT_THEME_ID: SettingsTheme = "light";

/** Switch used to hand a new window its theme before first paint. */
export const THEME_ARGUMENT_PREFIX = "--lovelyres-theme=";
/**
 * Display-only label for the SSH window title bar, e.g. `root@10.0.0.9:22`.
 * It is presentation text, never a capability: the window still cannot name a
 * target in any request, because main resolves that from the window itself.
 */
export const TARGET_LABEL_ARGUMENT_PREFIX = "--lovelyres-target-label=";
export const MAX_TARGET_LABEL_BYTES = 128;

/** Keeps a label renderable: single line, bounded, no control characters. */
export function sanitizeTargetLabel(value: string): string {
  const encoder = new TextEncoder();
  const plain = [...value].filter((character) => {
    const code = character.codePointAt(0) ?? 0;
    return code >= 0x20 && code !== 0x7f;
  }).join("");
  let bounded = plain;
  while (encoder.encode(bounded).byteLength > MAX_TARGET_LABEL_BYTES) {
    bounded = [...bounded].slice(0, -1).join("");
  }
  return bounded;
}

export function isThemeId(value: unknown): value is SettingsTheme {
  return THEMES.some((theme) => theme.id === value);
}

/** Unknown or legacy ids fall back to the default theme instead of failing. */
export function resolveThemeId(value: unknown): SettingsTheme {
  return isThemeId(value) ? value : DEFAULT_THEME_ID;
}

export function themeDefinition(id: SettingsTheme): ThemeDefinition {
  return THEMES.find((theme) => theme.id === id) ?? THEMES[0]!;
}

/** The next theme in registry order, for a quick cycle toggle. */
export function nextThemeId(current: unknown): SettingsTheme {
  const index = THEMES.findIndex((theme) => theme.id === current);
  return THEMES[(index + 1) % THEMES.length]!.id;
}

/** Reads the theme a window was launched with; defaults when absent or unknown. */
export function themeFromArguments(argv: readonly string[]): SettingsTheme {
  const argument = argv.find((value) => value.startsWith(THEME_ARGUMENT_PREFIX));
  return resolveThemeId(argument?.slice(THEME_ARGUMENT_PREFIX.length));
}
