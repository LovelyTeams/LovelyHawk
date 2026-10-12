import { describe, expect, it } from "vitest";

import { planExpiryLabel } from "./plan-expiry";

describe("how long a plan is still good for", () => {
  it("says it the way a person would", () => {
    // The two values any plan actually carries today.
    expect(planExpiryLabel(300)).toBe("5 分钟");
    expect(planExpiryLabel(120)).toBe("2 分钟");
    // Under a minute stays in seconds — rounding it to "1 分钟" would promise
    // more time than the plan has.
    expect(planExpiryLabel(45)).toBe("45 秒");
    expect(planExpiryLabel(59)).toBe("59 秒");
    expect(planExpiryLabel(60)).toBe("1 分钟");
    expect(planExpiryLabel(90)).toBe("1 分 30 秒");
    expect(planExpiryLabel(3_600)).toBe("1 小时");
    expect(planExpiryLabel(5_400)).toBe("1 小时 30 分");
  });

  it("never claims time a plan does not have", () => {
    // A plan whose window has closed says so rather than printing "0 秒",
    // which reads like it is still there.
    for (const gone of [0, -1, -300]) expect(planExpiryLabel(gone)).toBe("已失效");
    // A sidecar that answered with something that is not a number must not
    // turn into "NaN 秒" on a confirmation screen.
    for (const wrong of [Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(planExpiryLabel(wrong)).toBe("已失效");
    }
    // Fractional seconds round down, so the label is never optimistic.
    expect(planExpiryLabel(119.9)).toBe("1 分 59 秒");
  });
});
