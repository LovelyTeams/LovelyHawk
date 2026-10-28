import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

function rendererDir(): string {
  return path.dirname(new URL(import.meta.url).pathname.replace(/^\/([a-z]:)/iu, "$1"));
}

/**
 * `--on-accent` is the text colour for the accent and status fills. Used on
 * any other surface it can all but vanish: the packet-capture totals were
 * near-white on the light console surface until a lab screenshot showed it.
 * Every rule that sets it must also set one of those fills.
 */
describe("on-accent text", () => {
  it("is only set together with an accent or status background", () => {
    const offenders: string[] = [];
    for (const name of readdirSync(rendererDir()).filter((file) => file.endsWith(".css"))) {
      const css = readFileSync(path.join(rendererDir(), name), "utf8").replace(/\/\*[\s\S]*?\*\//gu, "");
      for (const match of css.matchAll(/([^{}]+)\{([^{}]*)\}/gu)) {
        const selector = (match[1] ?? "").trim().replace(/\s+/gu, " ");
        const body = match[2] ?? "";
        if (/(?:^|[;\s])color:\s*var\(--on-accent\)/u.test(body) &&
          !/background(?:-color)?:[^;]*var\(--(?:accent|accent-strong|danger|success|warning|info|console-accent)\)/u.test(body)) {
          offenders.push(`${name}: ${selector}`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  it("is never replaced by a named colour, which no theme can follow", () => {
    // The hex and rgb() literals are caught by the theme tests; a plain
    // `color: white` on the integrity page's primary button was not.
    const named = /(?:^|[;{\s])(?:color|background(?:-color)?|border(?:-color)?):\s*(?:white|black)\b/u;
    const offenders = readdirSync(rendererDir())
      .filter((file) => file.endsWith(".css"))
      .flatMap((name) => readFileSync(path.join(rendererDir(), name), "utf8")
        .split("\n")
        .filter((line) => named.test(line))
        .map((line) => `${name}: ${line.trim()}`));
    expect(offenders).toEqual([]);
  });
});
