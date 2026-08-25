import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const source = readFileSync(new URL("./ConnectionManager.tsx", import.meta.url), "utf8");
const cssSource = readFileSync(new URL("./styles.css", import.meta.url), "utf8");

function functionBody(name: string): string {
  const start = source.indexOf(`async function ${name}(`);
  expect(start, `${name} is missing`).toBeGreaterThan(-1);
  const end = source.indexOf("\n  }", start);
  return source.slice(start, end);
}

describe("connection manager remote-operation guard", () => {
  /**
   * `busy` is React state, so a second click landing before the re-render still
   * passes the disabled check. Creating twice with the same generated id makes
   * the backend reject the duplicate, which surfaced as a save failure.
   */
  it("refuses a second in-flight write, probe, or connect", () => {
    for (const name of ["saveConnection", "startProbe", "startConnect"]) {
      const body = functionBody(name);
      expect(body, `${name} entry guard`).toMatch(/if \([^)]*operationInFlightRef\.current\) return;/u);
      expect(body, `${name} claims the flag`).toContain("operationInFlightRef.current = true;");
      expect(body, `${name} releases the flag`).toContain("operationInFlightRef.current = false;");
    }
  });

  it("claims the flag before awaiting and releases it exactly once per operation", () => {
    expect(source.match(/operationInFlightRef\.current = true;/gu)).toHaveLength(3);
    expect(source.match(/operationInFlightRef\.current = false;/gu)).toHaveLength(3);
    // Releases live in finally blocks so a rejected request cannot wedge the panel.
    for (const name of ["saveConnection", "startProbe", "startConnect"]) {
      expect(functionBody(name), `${name} releases in finally`)
        .toMatch(/\} finally \{\s*operationInFlightRef\.current = false;/u);
    }
  });

  it("still generates a fresh id per created connection", () => {
    expect(source).toMatch(/function emptyConnectionForm\(\): ConnectionForm \{\s*return \{\s*id: crypto\.randomUUID\(\)/u);
  });
});

describe("connection manager action rows", () => {
  it("pins the editor and detail actions to the bottom of the scrolling pane", () => {
    for (const selector of [
      "\\.connection-editor > footer",
      "\\.connection-details-view > footer",
    ]) {
      const rule = new RegExp(`${selector} \\{([^}]*)\\}`, "u").exec(cssSource)?.[1] ?? "";
      expect(rule, selector).toContain("position: sticky");
      expect(rule, selector).toContain("bottom: 0");
      // An opaque background is what keeps scrolled content from showing through.
      expect(rule, selector).toContain("background: var(--surface)");
    }
    // The pane itself must stay the scroll container for sticky to resolve against.
    expect(cssSource).toMatch(/\.connection-detail \{[^}]*overflow: auto;/u);
  });
});
