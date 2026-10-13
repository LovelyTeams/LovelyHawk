import { describe, expect, it } from "vitest";

import {
  DROPDOWN_GAP,
  MENU_VIEWPORT_MARGIN,
  placeDropdown,
  SUBMENU_ALIGN,
  menuMaxHeight,
  menuStep,
  placeMenu,
  placeSubmenu,
  refitMenu,
} from "./menu-placement";

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

  it("moves a menu that grew past the bottom after it opened", () => {
    // The host overview's row menu opens with three local items and receives
    // the target's actions afterwards. Placed for 90px, it then grew to 300px
    // from y=600 and its last groups disappeared under the window edge.
    const cursor = { x: 120, y: 600 };
    const opened = placeMenu(cursor, { width: 180, height: 90 }, viewport);
    expect(opened).toEqual(cursor);
    const refitted = refitMenu(opened, cursor, menu, viewport);
    expect(refitted).toEqual({ x: 120, y: 300 });
    expect(refitted.y + menu.height).toBeLessThanOrEqual(viewport.height - MENU_VIEWPORT_MARGIN);
  });

  it("leaves a grown menu where it is while it still fits", () => {
    const cursor = { x: 120, y: 90 };
    const opened = placeMenu(cursor, { width: 180, height: 90 }, viewport);
    expect(refitMenu(opened, cursor, menu, viewport)).toEqual(opened);
    // Already flipped above the cursor and still inside: no second jump.
    expect(refitMenu({ x: 120, y: 400 }, { x: 120, y: 700 }, menu, viewport)).toEqual({ x: 120, y: 400 });
  });

  it("pins a grown menu taller than the window to the margin", () => {
    const tall = { width: 180, height: 900 };
    expect(refitMenu({ x: 120, y: 600 }, { x: 120, y: 600 }, tall, viewport).y).toBe(MENU_VIEWPORT_MARGIN);
  });

  it("opens a submenu to the right of its item, first lines level", () => {
    const anchor = { left: 100, right: 300, top: 200 };
    expect(placeSubmenu(anchor, { width: 180, height: 150 }, viewport)).toEqual({
      x: 300,
      y: 200 - SUBMENU_ALIGN,
    });
  });

  it("flips a submenu to the left of the menu near the right edge", () => {
    const anchor = { left: 700, right: 900, top: 200 };
    const placed = placeSubmenu(anchor, { width: 180, height: 150 }, viewport);
    // Beside the menu, not on top of it.
    expect(placed.x + 180).toBe(700);
  });

  it("slides a submenu up rather than letting it run off the bottom", () => {
    const anchor = { left: 100, right: 300, top: 720 };
    const placed = placeSubmenu(anchor, { width: 180, height: 200 }, viewport);
    expect(placed.y + 200).toBe(viewport.height - MENU_VIEWPORT_MARGIN);
    expect(placed.x).toBe(300);
  });

  it("pins a submenu that fits on neither side or is taller than the window", () => {
    const narrow = { width: 500, height: 800 };
    const placed = placeSubmenu({ left: 120, right: 400, top: 300 }, { width: 300, height: 900 }, narrow);
    expect(placed).toEqual({ x: narrow.width - MENU_VIEWPORT_MARGIN - 300, y: MENU_VIEWPORT_MARGIN });
  });

  it("drops a dropdown under its button, right edges aligned", () => {
    const button = { left: 600, right: 640, top: 100, bottom: 130 };
    expect(placeDropdown(button, { width: 120, height: 80 }, viewport)).toEqual({
      x: 520,
      y: 130 + DROPDOWN_GAP,
    });
  });

  it("opens a dropdown above its button when the rows below run out", () => {
    // The Docker table's last row: below the button there is no room left, and
    // a menu there was cut off by the table's own scroll box.
    const button = { left: 600, right: 640, top: 740, bottom: 770 };
    const placed = placeDropdown(button, { width: 120, height: 80 }, viewport);
    expect(placed.y + 80).toBe(740 - DROPDOWN_GAP);
  });

  it("keeps a dropdown inside the window at the left edge and when it fits neither way", () => {
    expect(placeDropdown({ left: 2, right: 30, top: 100, bottom: 130 }, { width: 120, height: 80 }, viewport).x)
      .toBe(MENU_VIEWPORT_MARGIN);
    const tall = placeDropdown({ left: 600, right: 640, top: 400, bottom: 430 }, { width: 120, height: 600 }, viewport);
    expect(tall.y).toBe(MENU_VIEWPORT_MARGIN);
  });

  it("moves keyboard focus through a menu and wraps at both ends", () => {
    expect(menuStep(-1, 4, "ArrowDown")).toBe(0);
    expect(menuStep(-1, 4, "ArrowUp")).toBe(3);
    expect(menuStep(0, 4, "ArrowDown")).toBe(1);
    expect(menuStep(3, 4, "ArrowDown")).toBe(0);
    expect(menuStep(0, 4, "ArrowUp")).toBe(3);
    expect(menuStep(2, 4, "Home")).toBe(0);
    expect(menuStep(1, 4, "End")).toBe(3);
    expect(menuStep(0, 0, "ArrowDown")).toBe(-1);
  });

  it("keeps a zero-height window from producing a negative ceiling", () => {
    expect(menuMaxHeight(0)).toBe(0);
  });
});
