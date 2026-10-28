import type { SettingsUi } from "../shared/settings-contract";

/**
 * The interface settings an operator can change, as the shell applies them.
 *
 * They used to be saved and then ignored. The stored width may be anything the
 * settings contract allows; the layout clamps what it draws so a very wide
 * sidebar can never squeeze the page out of the minimum window.
 */
export interface UiPreferences {
  sidebarWidth: number;
  showStatusBar: boolean;
  compactMode: boolean;
  animationsEnabled: boolean;
}

export const DEFAULT_UI_PREFERENCES: UiPreferences = Object.freeze({
  sidebarWidth: 240,
  showStatusBar: true,
  compactMode: false,
  animationsEnabled: true,
});

/** What the layout will actually draw for a stored width. */
export const SIDEBAR_WIDTH_RANGE = Object.freeze({ minimum: 200, maximum: 360 });

export function sidebarWidthFor(stored: number): number {
  if (!Number.isFinite(stored)) return DEFAULT_UI_PREFERENCES.sidebarWidth;
  return Math.min(SIDEBAR_WIDTH_RANGE.maximum, Math.max(SIDEBAR_WIDTH_RANGE.minimum, Math.round(stored)));
}

/** Applies stored settings to the document root and returns what took effect. */
export function applyUiPreferences(root: HTMLElement, stored: SettingsUi): UiPreferences {
  const applied: UiPreferences = {
    sidebarWidth: sidebarWidthFor(stored.sidebarWidth),
    showStatusBar: stored.showStatusBar,
    compactMode: stored.compactMode,
    animationsEnabled: stored.animationsEnabled,
  };
  root.style.setProperty("--sidebar-width", `${applied.sidebarWidth}px`);
  root.dataset["density"] = applied.compactMode ? "compact" : "comfortable";
  root.dataset["motion"] = applied.animationsEnabled ? "full" : "reduced";
  return applied;
}
