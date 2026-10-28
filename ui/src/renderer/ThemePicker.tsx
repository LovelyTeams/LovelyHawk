import { useEffect, useId, useRef, useState } from "react";

import type { SettingsTheme } from "../shared/settings-contract";
import { THEMES, themeDefinition } from "./theme/theme";
import { ThemeArt } from "./ThemeArt";

export interface ThemePickerProps {
  themeId: SettingsTheme;
  /** Applies and saves the chosen palette. */
  onSelect: (themeId: SettingsTheme) => void;
}

const GROUPS = [
  { kind: "light", title: "浅色系", hint: "纸底" },
  { kind: "dark", title: "深色系", hint: "夜色" },
] as const;

/**
 * The status-bar palette chooser: a button showing the current palette and a
 * popover of colour posters, light and dark kept apart so a dark palette is
 * never one stray click away from a light one.
 */
export function ThemePicker({ themeId, onSelect }: ThemePickerProps) {
  const [open, setOpen] = useState(false);
  const wrapperRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const panelId = useId();
  const current = themeDefinition(themeId);

  useEffect(() => {
    if (!open) return undefined;
    panelRef.current?.querySelector<HTMLButtonElement>("button[aria-pressed='true']")?.focus({ preventScroll: true });
    function onPointer(event: PointerEvent) {
      if (!wrapperRef.current?.contains(event.target as Node)) setOpen(false);
    }
    function onKey(event: KeyboardEvent) {
      if (event.key !== "Escape") return;
      event.preventDefault();
      event.stopPropagation();
      setOpen(false);
      triggerRef.current?.focus({ preventScroll: true });
    }
    document.addEventListener("pointerdown", onPointer, true);
    document.addEventListener("keydown", onKey, true);
    return () => {
      document.removeEventListener("pointerdown", onPointer, true);
      document.removeEventListener("keydown", onKey, true);
    };
  }, [open]);

  return (
    <div className="theme-picker" ref={wrapperRef}>
      <button
        ref={triggerRef}
        type="button"
        className="statusbar-button theme-picker-trigger"
        data-testid="open-theme-picker"
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-controls={open ? panelId : undefined}
        title="选择界面配色"
        onClick={() => setOpen((value) => !value)}
      >
        <span className="theme-picker-dots" aria-hidden="true">
          {current.swatches.map((color, index) => <i key={index} style={{ background: color }} />)}
        </span>
        <span>配色：{current.label}</span>
      </button>
      {open ? (
        <div ref={panelRef} id={panelId} className="theme-picker-panel" role="dialog" aria-label="选择界面配色">
          <header className="theme-picker-head">
            <strong>配色参考</strong>
            <small>选中后立即应用并保存</small>
          </header>
          <div className="theme-picker-body">
            {GROUPS.map((group) => (
              <section key={group.kind} className="theme-picker-group" aria-label={group.title}>
                <h3>{group.title}<small>{group.hint}</small></h3>
                <div className="theme-picker-grid">
                  {THEMES.filter((theme) => theme.kind === group.kind).map((theme) => (
                    <button
                      key={theme.id}
                      type="button"
                      className="theme-card"
                      data-testid={`theme-card-${theme.id}`}
                      aria-pressed={theme.id === themeId}
                      title={`${theme.label} · ${theme.subtitle}`}
                      onClick={() => {
                        onSelect(theme.id);
                        setOpen(false);
                        triggerRef.current?.focus({ preventScroll: true });
                      }}
                    >
                      <span className="theme-card-art"><ThemeArt theme={theme} /></span>
                      <span className="theme-card-name">{theme.label}</span>
                      <span className="theme-card-sub">{theme.subtitle}</span>
                      <span className="theme-card-dots" aria-hidden="true">
                        {theme.swatches.map((color, index) => <i key={index} style={{ background: color }} />)}
                      </span>
                    </button>
                  ))}
                </div>
              </section>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}
