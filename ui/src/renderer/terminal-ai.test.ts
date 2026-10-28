import { describe, expect, it } from "vitest";

import { terminalSelectionContent, terminalSelectionLines } from "./terminal-ai";

const bytes = (text: string) => new TextEncoder().encode(text).byteLength;

describe("terminal selection sent for an AI explanation", () => {
  it("sends the selection as it reads, without xterm's padding", () => {
    const selected = "root@web:~# id   \r\nuid=0(root) gid=0(root)\t\n\n";
    expect(terminalSelectionContent(selected, 1_024)).toEqual({
      text: "root@web:~# id\nuid=0(root) gid=0(root)",
      omitted: 0,
    });
    expect(terminalSelectionLines(selected)).toBe(2);
    expect(terminalSelectionLines("")).toBe(0);
  });

  it("keeps whole lines from the top inside the bound and counts the rest", () => {
    const lines = Array.from({ length: 10 }, (_, index) => `第 ${index} 行 ${"x".repeat(20)}`);
    const maximum = bytes(lines.slice(0, 4).join("\n"));
    const content = terminalSelectionContent(lines.join("\n"), maximum);
    expect(content).toEqual({ text: lines.slice(0, 4).join("\n"), omitted: 6 });
    expect(bytes(content.text)).toBeLessThanOrEqual(maximum);
    // One byte less and the fourth line no longer fits.
    expect(terminalSelectionContent(lines.join("\n"), maximum - 1).omitted).toBe(7);
  });

  it("sends the start of one line longer than the bound, never a broken character", () => {
    const long = "密".repeat(100);
    const content = terminalSelectionContent(`${long}\nnext`, 31);
    expect(content.text).toBe("密".repeat(10));
    expect(bytes(content.text)).toBeLessThanOrEqual(31);
    expect(content.omitted).toBe(1);
  });
});
