import type { SettingsTheme } from "./settings-contract.js";

export type ThemeKind = "light" | "dark";

export interface ThemeDefinition {
  /** Stable id, persisted through the settings backend (SettingsTheme). */
  readonly id: SettingsTheme;
  /** Chinese label shown by theme pickers. */
  readonly label: string;
  /** Short Chinese poetic description shown in theme cards. */
  readonly subtitle: string;
  /** Brightness family. Light themes must not show dark surfaces anywhere. */
  readonly kind: ThemeKind;
  /** Four-swatch display palette (ground -> tint -> mid -> accent). */
  readonly swatches: readonly [string, string, string, string];
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
    label: "月白",
    subtitle: "霜纸靛星",
    kind: "light",
    swatches: ["#f8fafc", "#e2e8f0", "#94a3b8", "#3b82f6"],
    chromeColor: "#ffffff",
    chromeScrimColor: "#a0a3a9",
    chromeSymbolColor: "#111827",
    windowBackground: "#f5f7fa",
    terminalBackground: "#eef1f6",
  },
  {
    id: "dark",
    label: "玄青",
    subtitle: "深夜弦月",
    kind: "dark",
    swatches: ["#0c1222", "#1e3050", "#3b6ea5", "#6db3ff"],
    chromeColor: "#111823",
    chromeScrimColor: "#0a0e15",
    chromeSymbolColor: "#e8edf5",
    windowBackground: "#0c1119",
    terminalBackground: "#0a1017",
  },
  {
    id: "sakura",
    label: "樱花",
    subtitle: "绯雪初绽",
    kind: "light",
    swatches: ["#fbf6f8", "#f0e0e6", "#f5cddb", "#c2255c"],
    chromeColor: "#ffffff",
    chromeScrimColor: "#aba3a7",
    chromeSymbolColor: "#2c1a22",
    windowBackground: "#fbf6f8",
    terminalBackground: "#f7eaef",
  },
  {
    id: "pink",
    label: "桃夭",
    subtitle: "灼灼其华",
    kind: "light",
    swatches: ["#fef7fb", "#f3dce6", "#dba0b4", "#e8849f"],
    chromeColor: "#fef7fb",
    chromeScrimColor: "#c1aeb9",
    chromeSymbolColor: "#4a2039",
    windowBackground: "#fef7fb",
    terminalBackground: "#fbeaf2",
  },
  {
    id: "tingwu",
    label: "庭芜绿",
    subtitle: "阶前芳草",
    kind: "light",
    swatches: ["#f5f6ec", "#d8e0c2", "#a8c47c", "#6fa054"],
    chromeColor: "#f5f6ec",
    chromeScrimColor: "#b2baa9",
    chromeSymbolColor: "#2f4526",
    windowBackground: "#f5f6ec",
    terminalBackground: "#eaeed8",
  },
  {
    id: "dongfang",
    label: "东方既白",
    subtitle: "晨光远山",
    kind: "light",
    swatches: ["#eef4fa", "#cdd9e8", "#a5b0cb", "#3a679e"],
    chromeColor: "#eef4fa",
    chromeScrimColor: "#a9b7c5",
    chromeSymbolColor: "#22405f",
    windowBackground: "#eef4fa",
    terminalBackground: "#e2ebf5",
  },
  {
    id: "chunchen",
    label: "春辰",
    subtitle: "新芽桃夭",
    kind: "light",
    swatches: ["#f0f1ed", "#d7dccd", "#b9d3e3", "#7b9651"],
    chromeColor: "#f0f1ed",
    chromeScrimColor: "#b0b7ab",
    chromeSymbolColor: "#35452a",
    windowBackground: "#f0f1ed",
    terminalBackground: "#e5e7e0",
  },
  {
    id: "ruolan",
    label: "挼蓝",
    subtitle: "宣纸水纹",
    kind: "light",
    swatches: ["#faf4e9", "#e6dac6", "#a9d1e7", "#4b90bf"],
    chromeColor: "#faf4e9",
    chromeScrimColor: "#b0bbbd",
    chromeSymbolColor: "#1f4b68",
    windowBackground: "#faf4e9",
    terminalBackground: "#f3e9d8",
  },
  {
    id: "linye",
    label: "林野脉冲",
    subtitle: "青苔信标",
    kind: "light",
    swatches: ["#e6eec9", "#c2d099", "#7da78c", "#35858e"],
    chromeColor: "#f2f7e4",
    chromeScrimColor: "#aabcb2",
    chromeSymbolColor: "#1e4a50",
    windowBackground: "#f2f7e4",
    terminalBackground: "#e6eec9",
  },
  {
    id: "shanhu",
    label: "珊瑚警报",
    subtitle: "松绿珊瑚",
    kind: "light",
    swatches: ["#faf5e4", "#f8b400", "#ff6363", "#125b50"],
    chromeColor: "#fdfaf0",
    chromeScrimColor: "#acbeb4",
    chromeSymbolColor: "#0f4a41",
    windowBackground: "#fdfaf0",
    terminalBackground: "#faf5e4",
  },
  {
    id: "nihong",
    label: "霓虹频谱",
    subtitle: "紫粉流光",
    kind: "light",
    swatches: ["#cfe3ff", "#fcce9e", "#fd72ad", "#a561ff"],
    chromeColor: "#f8f5ff",
    chromeScrimColor: "#b9add2",
    chromeSymbolColor: "#40217a",
    windowBackground: "#f8f5ff",
    terminalBackground: "#efe8ff",
  },
  {
    id: "spark",
    label: "小小火花",
    subtitle: "晴空星芒",
    kind: "light",
    swatches: ["#d1e1fc", "#f9dbf3", "#8eb6fa", "#5d9dfd"],
    chromeColor: "#f5f8ff",
    chromeScrimColor: "#b0bacd",
    chromeSymbolColor: "#29436d",
    windowBackground: "#f5f8ff",
    terminalBackground: "#eaf1ff",
  },
  {
    id: "incident-canvas",
    label: "事件画布",
    subtitle: "极夜青锋",
    kind: "dark",
    swatches: ["#05080c", "#141d2a", "#194754", "#22b8cf"],
    chromeColor: "#080d14",
    chromeScrimColor: "#04080c",
    chromeSymbolColor: "#eef4fb",
    windowBackground: "#05080c",
    terminalBackground: "#04070a",
  },
  {
    id: "shenhai",
    label: "深海薄荷绿",
    subtitle: "深海微光",
    kind: "dark",
    swatches: ["#0a1e21", "#1c4642", "#4f9b83", "#a8cdba"],
    chromeColor: "#091c1f",
    chromeScrimColor: "#061416",
    chromeSymbolColor: "#e9f4ef",
    windowBackground: "#0a1e21",
    terminalBackground: "#071619",
  },
  {
    id: "wuye",
    label: "午夜蓝紫",
    subtitle: "藏青紫雾",
    kind: "dark",
    swatches: ["#14152e", "#332e5c", "#6c62a4", "#a79edc"],
    chromeColor: "#12132a",
    chromeScrimColor: "#0d0e1e",
    chromeSymbolColor: "#eeecfb",
    windowBackground: "#14152e",
    terminalBackground: "#0e0f22",
  },
  {
    id: "jiaotang",
    label: "咖棕焦糖",
    subtitle: "深烘暖金",
    kind: "dark",
    swatches: ["#191007", "#4a3018", "#8a5b2e", "#d2954f"],
    chromeColor: "#170f06",
    chromeScrimColor: "#110b05",
    chromeSymbolColor: "#f7ede1",
    windowBackground: "#191007",
    terminalBackground: "#120b04",
  },
  {
    id: "molv",
    label: "墨绿玫瑰",
    subtitle: "松墨绯红",
    kind: "dark",
    swatches: ["#0d1f19", "#2c4a3c", "#5d8069", "#cf838a"],
    chromeColor: "#0c1d17",
    chromeScrimColor: "#091511",
    chromeSymbolColor: "#ecf2ec",
    windowBackground: "#0d1f19",
    terminalBackground: "#091712",
  },
];

export const DEFAULT_THEME_ID: SettingsTheme = "light";

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

