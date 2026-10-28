import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

function rendererDir(): string {
  return path.dirname(new URL(import.meta.url).pathname.replace(/^\/([a-z]:)/iu, "$1"));
}

function stylesheets(): Array<{ name: string; css: string }> {
  return readdirSync(rendererDir())
    .filter((file) => file.endsWith(".css"))
    .map((name) => ({ name, css: readFileSync(path.join(rendererDir(), name), "utf8").replace(/\/\*[\s\S]*?\*\//gu, "") }));
}

/**
 * The app's text comes in a handful of sizes. The stylesheets had grown 29 —
 * 11.5, 12, 12.5, 13 and 13.5px side by side for the same kind of text, page
 * titles at 22px and overlay titles at 24, and anything a rule did not size at
 * the browser's own 16px — and it showed: some text too large, some too small,
 * next to each other. Every size is now a step of one scale.
 */
describe("type scale", () => {
  it("is the steps it is documented to be, none below 12px", () => {
    const root = readFileSync(path.join(rendererDir(), "styles.css"), "utf8");
    const steps = Object.fromEntries([...root.matchAll(/--(font-[a-z]+|page-title-size):\s*(\d+)px;/gu)]
      .map((match) => [match[1], Number(match[2])]));
    expect(steps).toEqual({
      "font-caption": 12,
      "font-small": 13,
      "font-body": 14,
      "font-subtitle": 16,
      "font-title": 18,
      "page-title-size": 22,
      "font-display": 28,
      "font-hero": 38,
    });
  });

  it("is the only source of a font size in any stylesheet", () => {
    const offenders = stylesheets().flatMap(({ name, css }) => [
      ...[...css.matchAll(/font-size:\s*([^;}]+)/gu)]
        .map((match) => (match[1] ?? "").trim())
        .filter((value) => !/^var\(--(?:font-(?:caption|small|body|subtitle|title|display|hero)|page-title-size|page-lead-size)\)(?:\s*!important)?$/u.test(value) && value !== "inherit")
        .map((value) => `${name}: font-size: ${value}`),
      ...[...css.matchAll(/\bfont:\s*([^;}]+)/gu)]
        .map((match) => (match[1] ?? "").trim())
        .filter((value) => value !== "inherit" && !/^var\(--(?:font-(?:caption|small|body)|page-lead-size)\)[\s/]/u.test(value))
        .map((value) => `${name}: font: ${value}`),
    ]);
    expect(offenders).toEqual([]);
  });

  it("sizes the text no rule sizes, and every form control from the page", () => {
    const root = readFileSync(path.join(rendererDir(), "styles.css"), "utf8");
    expect(root).toMatch(/body \{[^}]*font-size: var\(--font-small\)/u);
    expect(root).toContain("h1 { font-size: var(--page-title-size); }");
    expect(root).toContain("h2 { font-size: var(--font-title); }");
    expect(root).toContain("h3 { font-size: var(--font-subtitle); }");
    // A select did not inherit and kept the browser's own font beside inputs that did.
    expect(root).toContain("button, input, select, textarea { font: inherit; font-size: var(--font-small); }");
  });

  it("is not bypassed by sizes set from code, except the terminal's own cell size", () => {
    const sources = readdirSync(rendererDir())
      .filter((file) => /\.tsx?$/u.test(file) && !/\.test\.tsx?$/u.test(file))
      .filter((name) => /fontSize\s*:/u.test(readFileSync(path.join(rendererDir(), name), "utf8")));
    // xterm sizes its character cells in pixels from this number; it matches --font-small.
    expect(sources).toEqual(["TerminalSurface.tsx"]);
    expect(readFileSync(path.join(rendererDir(), "TerminalSurface.tsx"), "utf8")).toContain("fontSize: 13,");
  });
});
