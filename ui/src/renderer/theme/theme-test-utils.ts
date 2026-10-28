/**
 * Pure parsing and contrast helpers for theme tests. Deliberately free of any
 * Node API so the renderer source tree stays scannable as browser-only code;
 * test files read themes.css themselves and pass its text in.
 */

/** Parses themes.css text into { themeId: { tokenName: value } } without cascading. */
export function parseThemeTokenTable(css: string): Map<string, Map<string, string>> {
  const stripped = css.replace(/\/\*[\s\S]*?\*\//gu, "");
  const table = new Map<string, Map<string, string>>();
  const blockPattern = /((?::root(?:\[data-theme="[a-z-]+"\])?\s*,?\s*)+)\{([^}]*)\}/gu;
  for (const block of stripped.matchAll(blockPattern)) {
    const selectors = block[1]!;
    const ids = [...selectors.matchAll(/\[data-theme="([a-z-]+)"\]/gu)].map((m) => m[1]!);
    if (ids.length === 0 && selectors.includes(":root")) ids.push("light");
    const tokens = new Map<string, string>();
    for (const declaration of block[2]!.matchAll(/--([a-z0-9-]+)\s*:\s*([^;]+);/gu)) {
      tokens.set(declaration[1]!, declaration[2]!.trim());
    }
    for (const id of new Set(ids)) {
      const existing = table.get(id);
      if (existing === undefined) {
        table.set(id, new Map(tokens));
      } else {
        for (const [name, value] of tokens) existing.set(name, value);
      }
    }
  }
  return table;
}

export function themeToken(
  table: Map<string, Map<string, string>>,
  theme: string,
  token: string,
): string {
  const value = table.get(theme)?.get(token);
  if (value === undefined) throw new Error(`Theme '${theme}' does not define --${token}.`);
  return value;
}

function linearChannel(value: number): number {
  const normalized = value / 255;
  return normalized <= 0.04045
    ? normalized / 12.92
    : ((normalized + 0.055) / 1.055) ** 2.4;
}

export function luminance(hex: string): number {
  const match = /^#([0-9a-f]{6})$/iu.exec(hex.trim());
  if (match === null) throw new Error(`Expected a #rrggbb color, got '${hex}'.`);
  const value = Number.parseInt(match[1]!, 16);
  return 0.2126 * linearChannel((value >> 16) & 0xff) +
    0.7152 * linearChannel((value >> 8) & 0xff) +
    0.0722 * linearChannel(value & 0xff);
}

export function contrastRatio(foreground: string, background: string): number {
  const first = luminance(foreground);
  const second = luminance(background);
  const lighter = Math.max(first, second);
  const darker = Math.min(first, second);
  return (lighter + 0.05) / (darker + 0.05);
}
