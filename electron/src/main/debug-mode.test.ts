import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { isDebugModeEnabled, isDevToolsChord } from "./debug-mode";

type ChordInput = Parameters<typeof isDevToolsChord>[0];

function chord(overrides: Partial<ChordInput>): ChordInput {
  return {
    type: "keyDown",
    key: "F12",
    control: false,
    meta: false,
    shift: false,
    alt: false,
    ...overrides,
  };
}

describe("isDebugModeEnabled", () => {
  it("is on for unpackaged development builds", () => {
    expect(isDebugModeEnabled(false, {})).toBe(true);
  });

  it("is off for packaged builds by default", () => {
    expect(isDebugModeEnabled(true, {})).toBe(false);
  });

  it("can be forced for a packaged build with LOVELYRES_DEBUG=1 only", () => {
    expect(isDebugModeEnabled(true, { LOVELYRES_DEBUG: "1" })).toBe(true);
    expect(isDebugModeEnabled(true, { LOVELYRES_DEBUG: "true" })).toBe(false);
    expect(isDebugModeEnabled(true, { LOVELYRES_DEBUG: "0" })).toBe(false);
    expect(isDebugModeEnabled(true, { LOVELYRES_DEBUG: "" })).toBe(false);
  });
});

describe("isDevToolsChord", () => {
  it("accepts F12 and Ctrl/Cmd+Shift+I on key down", () => {
    expect(isDevToolsChord(chord({}))).toBe(true);
    expect(isDevToolsChord(chord({ key: "I", control: true, shift: true }))).toBe(true);
    expect(isDevToolsChord(chord({ key: "i", meta: true, shift: true }))).toBe(true);
  });

  it("rejects key-up events, plain I, and modified F12", () => {
    expect(isDevToolsChord(chord({ type: "keyUp" }))).toBe(false);
    expect(isDevToolsChord(chord({ key: "I" }))).toBe(false);
    expect(isDevToolsChord(chord({ key: "I", control: true }))).toBe(false);
    expect(isDevToolsChord(chord({ key: "I", shift: true }))).toBe(false);
    expect(isDevToolsChord(chord({ control: true }))).toBe(false);
    expect(isDevToolsChord(chord({ alt: true }))).toBe(false);
    expect(isDevToolsChord(chord({ key: "I", control: true, shift: true, alt: true }))).toBe(false);
  });
});

describe("main-process debug wiring", () => {
  const source = readFileSync(new URL("./index.ts", import.meta.url), "utf8");

  it("computes debug mode once from packaging state and the environment", () => {
    expect(source).toContain("isDebugModeEnabled(app.isPackaged, process.env)");
  });

  it("gates devTools in every window's webPreferences on debug mode", () => {
    const preferenceBlocks = source.match(/webPreferences:\s*\{[^}]*\}/gu) ?? [];
    expect(preferenceBlocks.length).toBeGreaterThanOrEqual(2);
    for (const block of preferenceBlocks) {
      expect(block).toContain("devTools: debugMode");
    }
  });

  it("installs the DevTools toggle on the main and terminal windows", () => {
    expect(source.match(/installDevToolsToggle\(/gu)?.length).toBe(2);
  });
});
