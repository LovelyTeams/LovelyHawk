import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const mainSource = readFileSync(new URL("./index.ts", import.meta.url), "utf8");
const shellCss = readFileSync(new URL("../renderer/styles.css", import.meta.url), "utf8");

describe("main window sizing", () => {
  it("opens at 1920x1080, clamped to what the display actually offers", () => {
    // Flat 1920×1080 puts the bottom edge under the taskbar on a 1080p screen,
    // and the bottom edge is where the status bar lives.
    expect(mainSource).toContain("screen.getPrimaryDisplay().workAreaSize");
    expect(mainSource).toMatch(/Math\.min\(1_920,\s*work\.width\)/u);
    expect(mainSource).toMatch(/Math\.min\(1_080,\s*work\.height\)/u);
    expect(mainSource).toContain("width: preferred.width");
    expect(mainSource).toContain("height: preferred.height");
    // A display smaller than the floor still gets the floor, so the layout is
    // never asked to render below the size it is built for.
    expect(mainSource).toMatch(/Math\.max\(MIN_WINDOW_WIDTH,/u);
    expect(mainSource).toMatch(/Math\.max\(MIN_WINDOW_HEIGHT,/u);
  });

  it("keeps the minimum in one place, matching the stylesheet's own floor", () => {
    expect(mainSource).toContain("const MIN_WINDOW_WIDTH = 1_080;");
    expect(mainSource).toContain("const MIN_WINDOW_HEIGHT = 700;");
    // Two numbers that must agree: below these the stylesheet does not reflow,
    // it hides content behind a scrollbar.
    expect(shellCss).toMatch(/body\s*\{[^}]*min-width:\s*1080px/u);
    expect(shellCss).toMatch(/body\s*\{[^}]*min-height:\s*700px/u);
    // No stray literal left behind in a window's options.
    expect(mainSource).not.toContain("minWidth: 1_440");
    expect(mainSource).not.toMatch(/width:\s*1_440/u);
  });
});
