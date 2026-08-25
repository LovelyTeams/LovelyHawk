import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  isTerminalRendererUrl,
  isTrustedRendererUrl,
  resolveRendererAsset,
} from "./renderer-protocol";

describe("renderer protocol boundary", () => {
  const root = path.resolve("renderer-root");

  it("accepts only the packaged LovelyRes origin", () => {
    expect(isTrustedRendererUrl("lovelyres://app/index.html")).toBe(true);
    expect(isTrustedRendererUrl("https://app/index.html")).toBe(false);
    expect(isTrustedRendererUrl("lovelyres://attacker/index.html")).toBe(false);
    expect(isTrustedRendererUrl("not a url")).toBe(false);
  });

  it("rejects traversal, encoded traversal, nul and backslash paths", () => {
    expect(resolveRendererAsset("lovelyres://app/assets/app.js", root)).toBe(
      path.join(root, "assets", "app.js"),
    );
    expect(resolveRendererAsset("lovelyres://app/../secret", root)).toBeNull();
    expect(resolveRendererAsset("lovelyres://app/%2e%2e/secret", root)).toBeNull();
    expect(resolveRendererAsset("lovelyres://app/a%5cb", root)).toBeNull();
    expect(resolveRendererAsset("lovelyres://app/a%00b", root)).toBeNull();
  });

  it("maps only the exact handle-free terminal entry URL to terminal.html", () => {
    const terminalUrl = "lovelyres://app/?window=terminal";
    expect(isTerminalRendererUrl(terminalUrl)).toBe(true);
    expect(resolveRendererAsset(terminalUrl, root)).toBe(path.join(root, "terminal.html"));
    expect(resolveRendererAsset("lovelyres://app/", root)).toBe(path.join(root, "index.html"));
    expect(isTerminalRendererUrl(`${terminalUrl}&binding=forbidden`)).toBe(false);
    expect(isTerminalRendererUrl(`${terminalUrl}#token`)).toBe(false);
    expect(isTerminalRendererUrl("lovelyres://app/terminal.html")).toBe(false);
    expect(resolveRendererAsset("lovelyres://app/?window=terminal&extra=1", root)).toBeNull();
  });
});
