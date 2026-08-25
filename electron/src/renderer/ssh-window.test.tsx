import { readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import { CommandAssistant, commandAssistantGroups } from "./CommandAssistant";

function source(name: string): string {
  return readFileSync(new URL(`./${name}`, import.meta.url), "utf8");
}

/** True when a file carries raw control characters instead of escapes. */
function hasControlCharacters(text: string): boolean {
  return [...text].some((character) => {
    const code = character.codePointAt(0) ?? 0;
    if (character === "\n" || character === "\t") return false;
    return code === 0x7f || code < 0x20;
  });
}

describe("SSH window shell", () => {
  it("draws its own title bar and a status bar the window can actually fill", () => {
    const window = source("TerminalWindow.tsx");
    expect(window).toContain('data-testid="ssh-window-titlebar"');
    expect(window).toContain('data-testid="ssh-window-status"');
    // Every status field has a real source: a tick, the live grid, or a fact.
    expect(window).toContain("会话时间 {elapsed}");
    expect(window).toContain("行 × ");
    expect(window).toContain("UTF-8");

    // Main paints the system buttons, so the bar must leave room and drag.
    const css = source("ssh-window.css");
    expect(css).toContain("-webkit-app-region: drag;");
    expect(css).toMatch(/\.ssh-window-titlebar \{[^}]*height: 40px;/u);

    const main = source("../main/index.ts");
    const creation = main.slice(main.indexOf("function createTerminalWindow")).slice(0, 2_000);
    expect(creation).toContain('titleBarStyle: "hidden"');
    expect(creation).toContain("titleBarOverlay");
  });

  /** The label is presentation text, never something the window can act on. */
  it("shows which target the window belongs to without holding a capability", () => {
    const window = source("TerminalWindow.tsx");
    expect(window).toContain('document.documentElement.dataset["targetLabel"]');
    expect(window).not.toContain("bindingHandle");

    const preload = source("../preload/terminal.ts");
    expect(preload).toContain("TARGET_LABEL_ARGUMENT_PREFIX");
    expect(preload).toContain("MAX_TARGET_LABEL_BYTES");
    // A label with control characters would break the bar it is drawn in, and
    // the range has to be written as an escape rather than as the characters.
    expect(preload).toContain('.replace(CONTROL_CHARACTERS, "")');
    expect(hasControlCharacters(preload)).toBe(false);
  });

  it("types assistant snippets through the bounded queue and never presses enter", () => {
    const onInsert = vi.fn();
    const html = renderToStaticMarkup(<CommandAssistant onInsert={onInsert} />);
    expect(html).toContain("命令助手");
    for (const group of commandAssistantGroups) expect(html).toContain(group.label);
    expect(html).toContain("ls -la");

    for (const group of commandAssistantGroups) {
      expect(group.snippets.length).toBeGreaterThan(3);
      for (const snippet of group.snippets) {
        expect(snippet.text.startsWith(snippet.label)).toBe(true);
        expect(hasControlCharacters(snippet.text)).toBe(false);
      }
    }

    // The window hands snippets to the terminal, which enqueues them like typed
    // input rather than invoking the channel directly.
    const window = source("TerminalWindow.tsx");
    expect(window).toContain("setInsert((current) => ({ token: (current?.token ?? 0) + 1, text }))");
    expect(window).not.toContain("lovelyresTerminal.input");
    expect(source("TerminalSurface.tsx")).toContain("controllerRef.current?.enqueueText(insertText);");
  });

  it("keeps write actions visibly unavailable instead of pretending", () => {
    const page = source("SftpBrowserPage.tsx");
    expect(page).toContain("文件管理 (SFTP)");
    for (const label of ["上传", "下载", "删除", "新建文件夹"]) expect(page).toContain(label);
    // They are rendered disabled with the reason, and nothing fakes progress.
    expect((page.match(/disabled title=\{PENDING_WRITE\}/gu) ?? [])).toHaveLength(4);
    expect(page).toContain("写操作尚未接入");
    expect(page).not.toContain("MB/s");
    expect(page).not.toContain("传输速度");
  });
});
