import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterAll, describe, expect, it } from "vitest";

import { isLocalDirectorySnapshot, LOCAL_BROWSER_LIMITS } from "../shared/local-browser-contract";
import { bounded, LocalBrowser } from "./local-browser";

const root = mkdtempSync(path.join(os.tmpdir(), "lovelyres-local-"));
mkdirSync(path.join(root, "projects"));
mkdirSync(path.join(root, "projects", "nested"));
writeFileSync(path.join(root, "notes.txt"), "hello");
writeFileSync(path.join(root, "projects", "app.py"), "print(1)");

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

describe("local browser", () => {
  it("lists the entry point as a snapshot the contract accepts", async () => {
    const browser = new LocalBrowser(root);
    const snapshot = await browser.open();
    expect(isLocalDirectorySnapshot(snapshot)).toBe(true);
    expect(snapshot.directoryLabel).toBe(root);
    // Directories sort first, then names.
    expect(snapshot.entries.map((entry) => entry.name)).toEqual(["projects", "notes.txt"]);
    expect(snapshot.entries[0]!.kind).toBe("directory");
    expect(snapshot.entries[1]!.sizeBytes).toBe("5");
  });

  /** The renderer holds handles, never paths, so only handles can be opened. */
  it("opens only directories it handed out, and refuses anything else", async () => {
    const browser = new LocalBrowser(root);
    const snapshot = await browser.open();
    const projects = snapshot.entries.find((entry) => entry.name === "projects");
    expect(projects).toBeDefined();

    const nested = await browser.list(projects!.entryHandle);
    expect(nested.directoryLabel).toBe(path.join(root, "projects"));
    expect(nested.entries.map((entry) => entry.name)).toEqual(["nested", "app.py"]);
    expect(nested.parentDirectoryHandle).toBe(snapshot.directoryHandle);

    for (const forged of ["not-a-handle", snapshot.entries[1]!.entryHandle, ""]) {
      await expect(browser.list(forged)).rejects.toThrow();
    }
    // A path is not a capability here, whatever it points at.
    await expect(browser.list(root)).rejects.toThrow();
  });

  it("bounds display text instead of passing control characters through", () => {
    expect(bounded("plain", 64)).toEqual({ text: "plain", truncated: false });
    expect(bounded("tab\tname", 64)).toEqual({ text: "tabname", truncated: true });
    const long = "x".repeat(LOCAL_BROWSER_LIMITS.maximumNameBytes + 40);
    const result = bounded(long, LOCAL_BROWSER_LIMITS.maximumNameBytes);
    expect(result.truncated).toBe(true);
    expect(new TextEncoder().encode(result.text).byteLength)
      .toBeLessThanOrEqual(LOCAL_BROWSER_LIMITS.maximumNameBytes);
  });

  it("refuses a non-directory entry point", async () => {
    const browser = new LocalBrowser(path.join(root, "notes.txt"));
    await expect(browser.open()).rejects.toThrow();
  });
});
