/**
 * Where a context menu actually fits.
 *
 * Every menu in this app was positioned at the raw cursor coordinates, which
 * is correct exactly until the cursor is near an edge — right-click a row in
 * the lower third of the window and the menu ran off the bottom, with the
 * dangerous items (删除 sits last but one) the first to disappear.
 *
 * The rules, in order:
 *   - open down and to the right of the cursor, which is what a person expects;
 *   - if that overflows an edge, flip to the other side of the cursor, so the
 *     menu never covers the row it belongs to;
 *   - if flipping still does not fit — a menu taller than the window — clamp to
 *     the margin and let the menu scroll inside itself.
 *
 * Pure, and takes its measurements as arguments, so the rules can be tested
 * without a browser.
 */
export interface MenuPoint {
  x: number;
  y: number;
}

export interface MenuBox {
  width: number;
  height: number;
}

/** Breathing room between the menu and the window edge. */
export const MENU_VIEWPORT_MARGIN = 8;

export function placeMenu(
  cursor: MenuPoint,
  menu: MenuBox,
  viewport: MenuBox,
  margin: number = MENU_VIEWPORT_MARGIN,
): MenuPoint {
  return {
    x: placeAxis(cursor.x, menu.width, viewport.width, margin),
    y: placeAxis(cursor.y, menu.height, viewport.height, margin),
  };
}

function placeAxis(at: number, size: number, available: number, margin: number): number {
  const limit = available - margin;
  // The ordinary case: it fits below/right of the cursor.
  if (at + size <= limit) return Math.max(margin, at);
  // Flip to the other side of the cursor rather than merely sliding up, so the
  // menu does not end up sitting on top of the row that was right-clicked.
  const flipped = at - size;
  if (flipped >= margin) return flipped;
  // Taller (or wider) than the window itself. Pin to the margin; the menu's own
  // max-height turns the remainder into a scroll rather than a clip.
  return margin;
}

/**
 * Where an open menu goes once its content has changed size.
 *
 * A menu whose items arrive after it opened was placed for its first, shorter
 * self; growing downwards from there ran the late items off the bottom of the
 * window. While the menu still fits where it is it stays put, so a pointer
 * already on its way to an item does not chase it; once it would cross an edge,
 * the opening rules decide again from the original cursor.
 */
export function refitMenu(
  current: MenuPoint,
  cursor: MenuPoint,
  menu: MenuBox,
  viewport: MenuBox,
  margin: number = MENU_VIEWPORT_MARGIN,
): MenuPoint {
  const fits = (at: number, size: number, available: number): boolean =>
    at >= margin && at + size <= available - margin;
  return {
    x: fits(current.x, menu.width, viewport.width)
      ? current.x
      : placeAxis(cursor.x, menu.width, viewport.width, margin),
    y: fits(current.y, menu.height, viewport.height)
      ? current.y
      : placeAxis(cursor.y, menu.height, viewport.height, margin),
  };
}

/** The side of the item a submenu opens from, in client coordinates. */
export interface MenuAnchor {
  left: number;
  right: number;
  top: number;
}

/**
 * How far a submenu sits above its item, so their first lines line up: the
 * menu's padding plus its border.
 */
export const SUBMENU_ALIGN = 5;

/**
 * Where a submenu goes beside the item that opened it.
 *
 * To the right, its first item level with the parent; flipped to the left
 * when the right edge is too close, so it never covers the menu it came from;
 * slid up when it would run off the bottom, which keeps it beside the parent
 * rather than flipping above it.
 */
export function placeSubmenu(
  anchor: MenuAnchor,
  menu: MenuBox,
  viewport: MenuBox,
  margin: number = MENU_VIEWPORT_MARGIN,
): MenuPoint {
  let x = anchor.right;
  if (x + menu.width > viewport.width - margin) {
    const flipped = anchor.left - menu.width;
    x = flipped >= margin ? flipped : Math.max(margin, viewport.width - margin - menu.width);
  }
  const y = Math.min(anchor.top - SUBMENU_ALIGN, viewport.height - margin - menu.height);
  return { x, y: Math.max(margin, y) };
}

/** A button's box, in client coordinates. */
export interface MenuRect {
  left: number;
  right: number;
  top: number;
  bottom: number;
}

/** Space between a dropdown and the button that opened it. */
export const DROPDOWN_GAP = 4;

/**
 * Where a dropdown goes under the button that opened it.
 *
 * Right edges aligned, just below the button; above it when the window has no
 * room below, so the button stays visible either way; clamped inside the
 * window margin when it is wider or taller than the space on both sides.
 */
export function placeDropdown(
  button: MenuRect,
  menu: MenuBox,
  viewport: MenuBox,
  margin: number = MENU_VIEWPORT_MARGIN,
): MenuPoint {
  const x = Math.min(Math.max(margin, button.right - menu.width), viewport.width - margin - menu.width);
  const below = button.bottom + DROPDOWN_GAP;
  const above = button.top - DROPDOWN_GAP - menu.height;
  const y = below + menu.height <= viewport.height - margin
    ? below
    : above >= margin ? above : margin;
  return { x: Math.max(margin, x), y };
}

/**
 * The item focus moves to on an arrow, Home or End key, wrapping at the ends
 * the way a native menu does. `current` is -1 when no item has focus yet.
 */
export function menuStep(
  current: number,
  count: number,
  key: "ArrowDown" | "ArrowUp" | "Home" | "End",
): number {
  if (count <= 0) return -1;
  switch (key) {
    case "Home": return 0;
    case "End": return count - 1;
    case "ArrowDown": return current < 0 ? 0 : (current + 1) % count;
    case "ArrowUp": return current < 0 ? count - 1 : (current - 1 + count) % count;
  }
}

/**
 * The largest a menu may be before it scrolls inside itself.
 *
 * Kept here next to the placement rules because the two only work together: a
 * menu clamped to the margin still needs a ceiling, or it is clipped by the
 * window instead of by its own box.
 */
export function menuMaxHeight(viewportHeight: number, margin: number = MENU_VIEWPORT_MARGIN): number {
  return Math.max(0, viewportHeight - margin * 2);
}
