import type { SettingsTheme } from "../../shared/settings-contract";
import { resolveThemeId } from "../../shared/theme-contract";

export {
  DEFAULT_THEME_ID,
  THEMES,
  isThemeId,
  nextThemeId,
  resolveThemeId,
  themeDefinition,
  type ThemeDefinition,
  type ThemeKind,
} from "../../shared/theme-contract";

/**
 * Applies a theme by stamping data-theme onto the document root; themes.css
 * owns every color. Returns the applied id (after fallback resolution).
 */
export function applyTheme(root: Pick<HTMLElement, "dataset">, value: unknown): SettingsTheme {
  const id = resolveThemeId(value);
  root.dataset["theme"] = id;
  return id;
}
