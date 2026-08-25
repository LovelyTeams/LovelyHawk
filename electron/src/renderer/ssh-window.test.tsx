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

  /** The local pane reads the operator's machine through opaque handles. */
  it("browses the local machine without letting the renderer name a path", () => {
    const pane = source("LocalFilePane.tsx");
    expect(pane).toContain("api.openLocalBrowser()");
    expect(pane).toContain("api.listLocalDirectory(request.directoryHandle)");
    // Navigation is by handle; a path never crosses back.
    expect(pane).not.toMatch(/[A-Za-z]:\|path\.join|localPath/u);

    const main = source("../main/local-browser.ts");
    expect(main).toContain("#byHandle");
    expect(main).toContain("The local directory capability is unknown or expired.");
    // Links are described, never followed blindly.
    expect(main).toContain("fs.lstat(full)");
  });

  /** Download is the one transfer that needs no plan; the path is main's. */
  it("downloads through the save dialog and never lets the renderer pick a path", () => {
    const page = source("SftpBrowserPage.tsx");
    expect(page).toContain("api.downloadSftpEntry(browserHandle, fileHandle)");
    expect(page).toContain("isSftpTransferResult(value)");
    // A second click while the dialog is open would open a second dialog.
    expect(page).toContain("if (transferInFlight.current) return;");
    expect(page).toContain("已取消保存。");

    const main = source("../main/index.ts");
    const handler = main.slice(main.indexOf('ipcMain.handle("lovelyres:terminal:sftp:download"'));
    expect(handler.slice(0, 1_800)).toContain("dialog.showSaveDialog(window");
    expect(handler.slice(0, 1_800)).toContain("path.isAbsolute(selection.filePath)");
    expect(handler.slice(0, 1_800)).toContain("context.bindingHandle");
    // The renderer sends two capabilities and nothing else.
    expect(handler.slice(0, 1_800)).toContain('hasOnlyKeys(value, ["browserHandle", "fileHandle"])');

    const preload = source("../preload/terminal.ts");
    expect(preload).toContain("lovelyres:terminal:sftp:download");
    expect(preload).not.toContain("localPath");
  });

  /** Nothing changes a target without a plan the operator read and approved. */
  it("routes every write through plan, confirm and execute", () => {
    const page = source("SftpBrowserPage.tsx");
    expect(page).toContain("文件管理 (SFTP)");
    for (const label of ["上传", "下载", "删除", "新建文件夹", "打包"]) expect(page).toContain(label);
    // The three steps are separate calls, in that order.
    const plan = page.indexOf("api.planSftpOperation(browserHandle, input)");
    const confirm = page.indexOf("api.confirmSftpOperation(plan.planHandle)");
    const execute = page.indexOf("api.executeSftpOperation(plan.planHandle)");
    expect(plan).toBeGreaterThan(-1);
    expect(confirm).toBeGreaterThan(plan);
    expect(execute).toBeGreaterThan(confirm);
    // Dismissing a plan releases it instead of leaving it to expire.
    expect(page).toContain("api.cancelSftpOperation(plan.planHandle)");
    // A second click cannot start a second operation.
    expect(page).toContain("if (operationInFlight.current || plan === null) return;");
    // Nothing fakes a transfer rate.
    expect(page).not.toContain("MB/s");
    expect(page).not.toContain("传输速度");

    const dialog = source("SftpOperationDialog.tsx");
    // The plan is shown before it can be run, with its risk and its rollback.
    expect(dialog).toContain("plan.summary");
    expect(dialog).toContain("plan.restoreDescription ?? \"无备份，执行后不可自动还原\"");
    expect(dialog).toContain("已回滚到操作前的状态。");
  });
});
