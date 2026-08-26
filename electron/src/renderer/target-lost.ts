/**
 * Telling "the target is gone" apart from "this feature failed".
 *
 * When a host goes away every target-bound page fails at once, and each of
 * them guessing out loud — "绑定可能已变化、断开或权限不足" — reads as a dozen
 * broken features rather than one lost connection. The boundary now says which
 * it is, so the pages can stop guessing.
 */

/**
 * The one sentence a lost target gets. Every page says the same thing, because
 * it is the same thing.
 */
export const TARGET_LOST_MESSAGE = "与目标的连接已断开。请重新连接后再试。";

/**
 * Whether a rejected call failed because the connection to the target is gone.
 *
 * The boundary puts its error code in the message, and every capability whose
 * binding no longer resolves ends in `-binding-unavailable`. Matching the
 * suffix rather than each feature's own code keeps this from needing an entry
 * per page.
 */
export function isTargetLost(reason: unknown): boolean {
  const message = reason instanceof Error ? reason.message : String(reason ?? "");
  return message.includes("binding-unavailable");
}

/**
 * The message to show for a failed target-bound read: the shared sentence when
 * the connection is gone, and the page's own wording otherwise.
 */
export function targetFailureMessage(reason: unknown, otherwise: string): string {
  return isTargetLost(reason) ? TARGET_LOST_MESSAGE : otherwise;
}
