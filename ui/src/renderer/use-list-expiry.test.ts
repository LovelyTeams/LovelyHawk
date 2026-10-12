import { describe, expect, it } from "vitest";

import { LIST_EXPIRY_MARGIN_MS, listExpiryAt, listExpiryState } from "./use-list-expiry";

describe("list expiry", () => {
  it("counts from receipt, a little early, and says minutes left until the edge", () => {
    const received = 1_000_000;
    const deadline = listExpiryAt(received, 300);
    expect(deadline).toBe(received + 300_000 - LIST_EXPIRY_MARGIN_MS);
    expect(listExpiryState(deadline, received)).toEqual({ expired: false, minutesLeft: 5 });
    expect(listExpiryState(deadline, received + 250_000)).toEqual({ expired: false, minutesLeft: 1 });
    expect(listExpiryState(deadline, deadline - 1)).toEqual({ expired: false, minutesLeft: 1 });
    expect(listExpiryState(deadline, deadline)).toEqual({ expired: true, minutesLeft: 0 });
    expect(listExpiryState(deadline, deadline + 60_000).expired).toBe(true);
  });

  it("has nothing to say without a list, and a list valid for no time is already expired", () => {
    expect(listExpiryState(null, 5)).toEqual({ expired: false, minutesLeft: null });
    expect(listExpiryState(listExpiryAt(10, 0), 10).expired).toBe(true);
    expect(listExpiryState(listExpiryAt(10, 2), 10).expired).toBe(true);
  });
});
