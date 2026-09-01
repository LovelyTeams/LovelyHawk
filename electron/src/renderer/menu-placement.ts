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
 * The largest a menu may be before it scrolls inside itself.
 *
 * Kept here next to the placement rules because the two only work together: a
 * menu clamped to the margin still needs a ceiling, or it is clipped by the
 * window instead of by its own box.
 */
export function menuMaxHeight(viewportHeight: number, margin: number = MENU_VIEWPORT_MARGIN): number {
  return Math.max(0, viewportHeight - margin * 2);
}
