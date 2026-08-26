import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { TARGET_LOST_MESSAGE, isTargetLost, targetFailureMessage } from "./target-lost";

function rendererDir(): string {
  return path.dirname(new URL(import.meta.url).pathname.replace(/^\/([a-z]:)/iu, "$1"));
}

describe("a target that went away", () => {
  it("is told apart from a feature that failed", () => {
    // Every capability whose binding no longer resolves ends the same way, so
    // one match covers all of them.
    for (const code of [
      "baseline-binding-unavailable",
      "emergency-command-binding-unavailable",
      "system-info-binding-unavailable",
      "sftp-browser-binding-unavailable",
    ]) {
      expect(isTargetLost(new Error(`Something went wrong. (${code})`)), code).toBe(true);
    }
    // A feature that genuinely failed still says so in its own words.
    for (const code of [
      "baseline-operation-failed",
      "emergency-command-timeout",
      "check-audit-catalog-unavailable",
      "invalid-params",
    ]) {
      expect(isTargetLost(new Error(`Something went wrong. (${code})`)), code).toBe(false);
    }
    expect(isTargetLost(undefined)).toBe(false);
    expect(isTargetLost("plain string")).toBe(false);
  });

  it("gets the same sentence wherever it happens", () => {
    const lost = new Error("x (docker-binding-unavailable)");
    expect(targetFailureMessage(lost, "Docker 读取失败。")).toBe(TARGET_LOST_MESSAGE);
    expect(targetFailureMessage(new Error("x (docker-operation-failed)"), "Docker 读取失败。"))
      .toBe("Docker 读取失败。");
    // It says what happened and what to do, and names no internals.
    expect(TARGET_LOST_MESSAGE).toContain("连接已断开");
    expect(TARGET_LOST_MESSAGE).not.toMatch(/binding|handle|session|core|绑定/iu);
  });

  /**
   * Before this, a host that went away made every target-bound page guess out
   * loud in its own words. A page that still guesses has been missed.
   */
  it("has replaced every page's guess about why a read failed", () => {
    const guessing: string[] = [];
    for (const name of readdirSync(rendererDir())) {
      if (!name.endsWith(".tsx") || name.endsWith(".test.tsx")) continue;
      const source = readFileSync(path.join(rendererDir(), name), "utf8");
      for (const line of source.split("\n")) {
        if (!/绑定可能已|目标已变化|能力可能过期|绑定可能已失效/u.test(line)) continue;
        if (line.includes("targetFailureMessage(")) continue;
        guessing.push(`${name}: ${line.trim()}`);
      }
    }
    expect(guessing).toEqual([]);
  });
});
