/**
 * Builds the xterm.js theme from the --term-* tokens in theme/themes.css so a
 * future theme can restyle the terminal without touching renderer code. The
 * fallbacks mirror the default token values for environments without CSS.
 */
export interface XtermThemeColors {
  background: string;
  foreground: string;
  cursor: string;
  cursorAccent: string;
  selectionBackground: string;
  black: string;
  red: string;
  green: string;
  yellow: string;
  blue: string;
  magenta: string;
  cyan: string;
  white: string;
}

const TERM_TOKEN_FALLBACKS = {
  background: ["--term-bg", "#16121d"],
  foreground: ["--term-text", "#f3edf7"],
  cursor: ["--term-cursor", "#ff8bb3"],
  cursorAccent: ["--term-bg", "#16121d"],
  selectionBackground: ["--term-selection", "rgb(112 76 122 / 60%)"],
  black: ["--term-ansi-black", "#17131d"],
  red: ["--term-ansi-red", "#ff7394"],
  green: ["--term-ansi-green", "#82d8ad"],
  yellow: ["--term-ansi-yellow", "#f0c779"],
  blue: ["--term-ansi-blue", "#8bb9ff"],
  magenta: ["--term-ansi-magenta", "#d99bff"],
  cyan: ["--term-ansi-cyan", "#76d9df"],
  white: ["--term-ansi-white", "#f3edf7"],
} as const satisfies Record<keyof XtermThemeColors, readonly [string, string]>;

const COLOR_VALUE = /^(?:#[0-9a-f]{3,8}|rgba?\([^)]+\))$/iu;

export function terminalXtermTheme(readToken: (name: string) => string): XtermThemeColors {
  const theme = {} as Record<keyof XtermThemeColors, string>;
  for (const key of Object.keys(TERM_TOKEN_FALLBACKS) as (keyof XtermThemeColors)[]) {
    const [token, fallback] = TERM_TOKEN_FALLBACKS[key];
    const value = readToken(token).trim();
    theme[key] = COLOR_VALUE.test(value) ? value : fallback;
  }
  return theme;
}
