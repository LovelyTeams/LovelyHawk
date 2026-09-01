import { describe, expect, it } from "vitest";

import { MENU_VIEWPORT_MARGIN, menuMaxHeight, placeMenu } from "./menu-placement";

const viewport = { width: 1_000, height: 800 };
const menu = { width: 180, height: 300 };

describe("context menu placement", () => {
  it("opens down and to the right when there is room", () => {
    expect(placeMenu({ x: 120, y: 90 }, menu, viewport)).toEqual({ x: 120, y: 90 });
  });

  it("flips above the cursor rather than running off the bottom", () => {
    // The case that started this: a row in the lower third of the window put
    // 删除 and 属性 below the edge, where they could not be reached at all.
    const placed = placeMenu({ x: 120, y: 700 }, menu, viewport);
    expect(placed.y).toBe(400);
    expect(placed.y + menu.height).toBeLessThanOrEqual(viewport.height - MENU_VIEWPORT_MARGIN);
    // Flipped, not merely slid up: the menu clears the row it belongs to.
    expect(placed.y + menu.height).toBe(700);
  });

  it("flips left rather than running off the right edge", () => {
    const placed = placeMenu({ x: 950, y: 90 }, menu, viewport);
    expect(placed.x).toBe(770);
    expect(placed.x + menu.width).toBeLessThanOrEqual(viewport.width - MENU_VIEWPORT_MARGIN);
  });

  it("flips on both axes at once in the bottom-right corner", () => {
    const placed = placeMenu({ x: 980, y: 780 }, menu, viewport);
    expect(placed).toEqual({ x: 800, y: 480 });
  });

  it("pins to the margin when the menu is taller than the window", () => {
    // Flipping cannot help here, so the menu is pinned and scrolls inside its
    // own box — clipping it against the window would hide items silently.
    const tall = { width: 180, height: 900 };
    expect(placeMenu({ x: 120, y: 700 }, tall, viewport).y).toBe(MENU_VIEWPORT_MARGIN);
    expect(menuMaxHeight(viewport.height)).toBe(784);
    expect(menuMaxHeight(viewport.height)).toBeLessThan(tall.height);
  });

  it("never places a menu above or left of the margin", () => {
    expect(placeMenu({ x: 0, y: 0 }, menu, viewport)).toEqual({
      x: MENU_VIEWPORT_MARGIN,
      y: MENU_VIEWPORT_MARGIN,
    });
    expect(placeMenu({ x: -50, y: -50 }, menu, viewport)).toEqual({
      x: MENU_VIEWPORT_MARGIN,
      y: MENU_VIEWPORT_MARGIN,
    });
  });

  it("keeps a zero-height window from producing a negative ceiling", () => {
    expect(menuMaxHeight(0)).toBe(0);
  });
});
