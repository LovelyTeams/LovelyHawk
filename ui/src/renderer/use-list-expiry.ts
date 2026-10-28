import { useEffect, useRef, useState } from "react";

/**
 * A list the backend hands out with "valid for N seconds" — the command
 * catalogue, the command-audit snapshot, a directory in the file manager —
 * goes stale on the backend whether or not the page notices. Running from a
 * stale list is refused, so the page says so on time: it marks the list
 * expired, turns off what would be refused, and points at reloading.
 *
 * The deadline is counted from when the page received the list (or from the
 * last use that renews it), a few seconds early so a click right at the edge
 * is not sent to be refused.
 */
export const LIST_EXPIRY_MARGIN_MS = 3_000;

export interface ListExpiry {
  expired: boolean;
  /** Whole minutes left, at least 1 while not expired; null without a list. */
  minutesLeft: number | null;
}

export function listExpiryAt(receivedAt: number, expiresInSeconds: number): number {
  return receivedAt + Math.max(0, expiresInSeconds * 1_000 - LIST_EXPIRY_MARGIN_MS);
}

export function listExpiryState(deadline: number | null, now: number): ListExpiry {
  if (deadline === null) return { expired: false, minutesLeft: null };
  const left = deadline - now;
  return left <= 0
    ? { expired: true, minutesLeft: 0 }
    : { expired: false, minutesLeft: Math.max(1, Math.ceil(left / 60_000)) };
}

/**
 * Tracks one list's deadline. `identity` is the list as received: a new list
 * starts a new deadline. `renewedAt` moves the deadline when a use renews the
 * list on the backend (running a command does; reading a snapshot does not).
 */
export function useListExpiry(
  identity: object | null,
  expiresInSeconds: number | null,
  renewedAt: number | null = null,
): ListExpiry {
  // When this list arrived, noted in the render that first shows it, so a new
  // list never borrows the old one's (possibly passed) deadline for a frame.
  const received = useRef<{ identity: object | null; at: number }>({ identity: null, at: 0 });
  if (received.current.identity !== identity) received.current = { identity, at: Date.now() };
  const [now, setNow] = useState(() => Date.now());
  const deadline = identity === null || expiresInSeconds === null ? null
    // A renewal counts only when it came after this list did.
    : listExpiryAt(Math.max(received.current.at, renewedAt ?? 0), expiresInSeconds);

  useEffect(() => {
    setNow(Date.now());
  }, [deadline]);

  useEffect(() => {
    if (deadline === null) return;
    const refresh = () => setNow(Date.now());
    // A minute's tick keeps "约 N 分钟" honest; the timeout lands on the edge.
    const tick = window.setInterval(refresh, 30_000);
    const edge = window.setTimeout(refresh, Math.max(0, deadline - Date.now()) + 50);
    // Timers in a hidden or minimised window run late; look again on return.
    window.addEventListener("focus", refresh);
    document.addEventListener("visibilitychange", refresh);
    return () => {
      window.clearInterval(tick);
      window.clearTimeout(edge);
      window.removeEventListener("focus", refresh);
      document.removeEventListener("visibilitychange", refresh);
    };
  }, [deadline]);

  return listExpiryState(deadline, now);
}
