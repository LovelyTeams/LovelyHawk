import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  isTerminalRendererUrl,
  TERMINAL_FAMILY_WINDOWS,
  terminalRendererWindow,
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

  it("maps only the exact handle-free terminal entry URLs to terminal.html", () => {
    const terminalUrl = "lovelyres://app/?window=terminal";
    expect(isTerminalRendererUrl(terminalUrl)).toBe(true);
    expect(resolveRendererAsset(terminalUrl, root)).toBe(path.join(root, "terminal.html"));
    expect(resolveRendererAsset("lovelyres://app/", root)).toBe(path.join(root, "index.html"));
    expect(isTerminalRendererUrl(`${terminalUrl}&binding=forbidden`)).toBe(false);
    expect(isTerminalRendererUrl(`${terminalUrl}#token`)).toBe(false);
    expect(isTerminalRendererUrl("lovelyres://app/terminal.html")).toBe(false);
    expect(resolveRendererAsset("lovelyres://app/?window=terminal&extra=1", root)).toBeNull();
  });

  it("admits the file editor to the same family and nothing else", () => {
    // The editor shares the terminal preload and therefore the target main
    // resolved for the window, which is what lets it read and write a file
    // through the same bounded SFTP handlers the browser uses.
    const editorUrl = "lovelyres://app/?window=file-editor";
    expect(TERMINAL_FAMILY_WINDOWS).toEqual(["terminal", "file-editor"]);
    expect(terminalRendererWindow(editorUrl)).toBe("file-editor");
    expect(terminalRendererWindow("lovelyres://app/?window=terminal")).toBe("terminal");
    expect(resolveRendererAsset(editorUrl, root)).toBe(path.join(root, "terminal.html"));
    // The set is closed: a window kind nobody registered is not in the family.
    for (const rejected of [
      "lovelyres://app/?window=editor",
      "lovelyres://app/?window=file-editor2",
      "lovelyres://app/?window=",
      "lovelyres://app/?window=file-editor&binding=forbidden",
      "lovelyres://app/?window=file-editor#token",
      "https://app/?window=file-editor",
    ]) {
      expect(terminalRendererWindow(rejected), rejected).toBeNull();
      expect(isTerminalRendererUrl(rejected), rejected).toBe(false);
    }
  });
});
