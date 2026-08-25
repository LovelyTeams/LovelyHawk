import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { emergencyCommandCategories } from "../shared/emergency-command-contract";
import { emergencyCommandTone } from "./emergency-command-icons";

function source(name: string): string {
  return readFileSync(new URL(`./${name}`, import.meta.url), "utf8");
}

const TONES = ["accent", "info", "success", "warning", "danger", "neutral"];

describe("emergency command page chrome", () => {
  it("gives every category a drawn icon and a tone the stylesheet paints", () => {
    const icons = source("emergency-command-icons.tsx");
    const css = source("emergency-commands.css");
    for (const category of emergencyCommandCategories) {
      expect(icons, `${category} needs an icon`).toMatch(new RegExp(`\\n  ${category}: \\(`, "u"));
      const tone = emergencyCommandTone(category);
      expect(TONES, `${category} tone`).toContain(tone);
      expect(css, `.is-${tone} tile`).toContain(`.emergency-command-icon.is-${tone} {`);
    }
  });

  /** The page sits inside the app shell, which already names the section. */
  it("keeps the page title out of the connected view", () => {
    const page = source("EmergencyCommandsPage.tsx");
    const connected = page.slice(page.indexOf('className="emergency-commands-page">'));
    expect(connected).not.toContain("<h1>");
    expect(page).not.toContain("emergency-commands-header");
    // The read-only boundary still has to be visible somewhere on the page.
    expect(page).toContain('className="emergency-commands-readonly"');
  });

  /**
   * The sidecar result carries no duration, so the elapsed time shown to the
   * operator has to be measured around the call itself.
   */
  it("measures the run duration in the renderer", () => {
    const page = source("EmergencyCommandsPage.tsx");
    expect(page).toContain("runStartedAtRef.current = Date.now();");
    expect(page).toContain("setRunElapsedMs(null);");
    expect(page).toContain("setRunElapsedMs(Date.now() - startedAt);");
    expect(page).toContain("完成耗时");
  });

  it("numbers the output without letting the gutter scroll away", () => {
    const page = source("EmergencyCommandsPage.tsx");
    const css = source("emergency-commands.css");
    expect(page).toContain('<span className="emergency-command-gutter" aria-hidden="true">');
    expect(css.slice(css.indexOf(".emergency-command-gutter {"))).toMatch(/position: sticky;\n {2}left: 0;/u);
  });
});
