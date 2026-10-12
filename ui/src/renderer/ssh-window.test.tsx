import { readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import { CommandAssistant, commandAssistantGroups } from "./CommandAssistant";
import { TerminalWindow, terminalWindowKind, type TerminalWindowKind } from "./TerminalWindow";

function source(name: string): string {
  return readFileSync(new URL(`./${name}`, import.meta.url), "utf8");
}

/** The desktop host, which owns windows, dialogs and local paths. */
function host(name: string): string {
  return readFileSync(new URL(`../../../crates/lovelyhawk-desktop/src/${name}`, import.meta.url), "utf8");
}

/** True when a file carries raw control characters instead of escapes. */
function hasControlCharacters(text: string): boolean {
  return [...text].some((character) => {
    const code = character.codePointAt(0) ?? 0;
    if (character === "\n" || character === "\t") return false;
    return code === 0x7f || code < 0x20;
  });
}

describe("terminal window kinds", () => {
  function render(kind: TerminalWindowKind): string {
    const previous = (globalThis as { window?: unknown }).window;
    (globalThis as { window?: unknown }).window = { lovelyhawkTerminal: {} };
    try {
      return renderToStaticMarkup(<TerminalWindow kind={kind} />);
    } finally {
      (globalThis as { window?: unknown }).window = previous;
    }
  }

  it("reads the kind from the query the host loaded, and anything else is the SSH window", () => {
    expect(terminalWindowKind("container")).toBe("container");
    expect(terminalWindowKind("directory")).toBe("directory");
    expect(terminalWindowKind("pod")).toBe("pod");
    for (const other of ["terminal", null, "", "file-editor", "Directory", "directory&x", "Pod", "pods"]) {
      expect(terminalWindowKind(other)).toBe("terminal");
    }
  });

  it("shows the host's files only in the SSH window", () => {
    const ssh = render("terminal");
    expect(ssh).toContain('data-testid="toggle-remote-files"');
    expect(ssh).toContain('aria-label="文件管理"');
    for (const kind of ["container", "pod", "directory"] as const) {
      const markup = render(kind);
      expect(markup, kind).not.toContain('data-testid="toggle-remote-files"');
      expect(markup, kind).not.toContain('aria-label="文件管理"');
      expect(markup, kind).toContain("主机文件在 SSH 终端窗口的文件管理中");
    }
    expect(render("container")).toContain(">容器<");
    expect(render("directory")).toContain(">SSH · 文件夹<");
  });

  it("does not claim a session before one is live", () => {
    const markup = render("directory");
    expect(markup).toMatch(/data-testid="ssh-window-session"><span class="ssh-window-tab-dot is-off" aria-hidden="true"><\/span>正在连接</u);
    expect(markup).toContain("会话时间 —");
    expect(markup).not.toContain("已连接");
  });

  it("is backed by a host that opens the browser only for the SSH window", () => {
    const commands = host("child_commands.rs");
    const sftpOpen = commands.split("pub async fn sftp_open")[1]!.split("#[tauri::command]")[0]!;
    expect(sftpOpen).toContain("if !matches!(scope.kind, ChildKind::Terminal) {");
    expect(sftpOpen.indexOf("ChildKind::Terminal")).toBeLessThan(sftpOpen.indexOf("sftp-browser.open"));
    const folder = commands.split("pub async fn directory_terminal_open")[1]!.split("#[tauri::command]")[0]!;
    expect(folder).toContain("if !matches!(scope.kind, ChildKind::Terminal)");
    expect(folder).not.toContain("terminal.open");
    const windows = host("child_windows.rs");
    expect(windows).toContain('Self::Container(_) => "container"');
    expect(windows).toContain('Self::Directory(_) => "directory"');
  });
});

describe("SSH window shell", () => {
  it("draws its own title bar and a status bar the window can actually fill", () => {
    const window = source("TerminalWindow.tsx");
    expect(window).toContain('data-testid="ssh-window-titlebar"');
    expect(window).toContain('data-testid="ssh-window-status"');
    // Every status field has a real source: a tick while the session is live,
    // the live grid, the session's own state, or a fact.
    expect(window).toContain('会话时间 {elapsed ?? "—"}');
    expect(window).toContain('useElapsedTime(session === "connected")');
    expect(window).toContain("行 × ");
    expect(window).toContain("UTF-8");
    expect(window).toContain("onSession={setSession}");
    // 已连接 only for a live session; never a fixed claim.
    expect(window).not.toMatch(/aria-hidden="true" \/>已连接/u);

    // No system frame: the bar drags the window and draws its own buttons.
    expect(window).toContain('data-tauri-drag-region="deep"');
    expect(window).toContain("<WindowControls />");
    const css = source("ssh-window.css");
    expect(css).not.toContain("-webkit-app-region");
    expect(css).toMatch(/\.ssh-window-titlebar \{[^}]*height: 40px;/u);

    const windows = host("host.rs");
    expect(windows).toContain(".decorations(false)");
    expect(windows).toContain('WebviewUrl::App(format!("terminal.html?window={page}").into())');
  });

  /** The label is presentation text, never something the window can act on. */
  it("shows which target the window belongs to without holding a capability", () => {
    const window = source("TerminalWindow.tsx");
    expect(window).toContain('document.documentElement.dataset["targetLabel"]');
    expect(window).not.toContain("bindingHandle");

    // The host stamps it before first paint, as an encoded string literal.
    const windows = host("host.rs");
    expect(windows).toContain("r.dataset.targetLabel=l");
    expect(windows).toContain("let label = Value::String(target_label.to_owned()).to_string();");
    expect(windows).toContain("launch_script(native.id, &sanitize_label(&label_text))");
    // A label with control characters would break the bar it is drawn in.
    const binding = host("binding_state.rs");
    expect(binding).toContain("MAX_TARGET_LABEL_BYTES");
    expect(binding).toContain(".filter(|character| !character.is_control())");
    expect(hasControlCharacters(windows)).toBe(false);
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
    expect(window).not.toContain("lovelyhawkTerminal.input");
    expect(source("TerminalSurface.tsx")).toContain("controllerRef.current?.enqueueText(insertText);");
  });

  /** The local pane reads the operator's machine through opaque handles. */
  it("browses the local machine without letting the renderer name a path", () => {
    const pane = source("LocalFilePane.tsx");
    expect(pane).toContain("api.openLocalBrowser()");
    expect(pane).toContain("api.listLocalDirectory(request.directoryHandle)");
    // Navigation is by handle; a path never crosses back.
    expect(pane).not.toMatch(/[A-Za-z]:\|path\.join|localPath/u);

    const browser = host("local_browser.rs");
    expect(browser).toContain("directories: HashMap<String, PathBuf>");
    expect(browser).toContain("本机目录已失效，请重新打开。");
    // Links are described, never followed blindly.
    expect(browser).toContain("fs::symlink_metadata(&full)");
  });

  /**
   * The two panes are one transfer surface: a file chosen on the left goes up
   * to the directory open on the right, and it still goes through a plan.
   */
  it("uploads the local selection without either side naming a path", () => {
    const pane = source("LocalFilePane.tsx");
    expect(pane).toContain("onUpload(selectedFile.entryHandle, selectedFile.name)");
    // Only a file can be sent, and only when one is selected.
    expect(pane).toContain('entry.entryHandle === selectedHandle && entry.kind === "file"');
    expect(pane).toContain("disabled={busy || selectedFile === null}");

    const page = source("SftpBrowserPage.tsx");
    expect(page).toContain("await api.stageSftpUpload(next.localFileHandle)");
    expect(page).toContain("localFileHandle: entryHandle");

    // The host resolves the handle to a path; an unlisted handle resolves to nothing.
    const browser = host("local_browser.rs");
    expect(browser).toContain("pub fn resolve_file(&self, entry_handle: &str) -> Option<PathBuf>");

    const commands = host("child_commands.rs");
    const handler = commands.slice(commands.indexOf("pub async fn sftp_stage_upload"));
    expect(handler.slice(0, 2_000)).toContain(".resolve_file(&handle)");
    expect(handler.slice(0, 2_000)).toContain("所选本机文件已不在列表中");
    // Without a handle the operator still picks the file in the system dialog.
    expect(handler.slice(0, 2_000)).toContain("DialogKind::OpenFile");
    expect(host("local_files.rs")).toContain(".filter(|path| path.is_absolute())");
  });

  /** Download is the one transfer that needs no plan; the path is main's. */
  it("downloads through the save dialog and never lets the renderer pick a path", () => {
    const page = source("SftpBrowserPage.tsx");
    expect(page).toContain("api.downloadSftpEntry(browserHandle, fileHandle)");
    expect(page).toContain("isSftpTransferResult(value)");
    // A second click while the dialog is open would open a second dialog.
    expect(page).toContain("if (transferInFlight.current) return;");
    expect(page).toContain("已取消保存。");

    const commands = host("child_commands.rs");
    const handler = commands.slice(commands.indexOf("pub async fn sftp_download"));
    expect(handler.slice(0, 1_800)).toContain("DialogKind::Save");
    expect(handler.slice(0, 1_800)).toContain("scope.binding_handle");
    expect(handler.slice(0, 1_800)).toMatch(/browser_handle: String,\s+file_handle: String,\s+\) ->/u);

    // The page sends two capabilities and nothing else.
    const bridge = readFileSync(new URL("../host/terminal-api.ts", import.meta.url), "utf8");
    expect(bridge).toContain('checked("sftp_download", { browserHandle, fileHandle }');
    expect(bridge).not.toContain("localPath");
  });

  /**
   * The chmod flow used to ask for a mode with nothing on screen to base it on,
   * so the operator had to remember or guess what the file already was.
   */
  it("shows an entry's own bits before offering to change them", () => {
    const menu = source("SftpContextMenu.tsx");
    expect(menu).toContain('{ action: "properties", label: "属性"');

    const page = source("SftpBrowserPage.tsx");
    // Properties is a read: it opens its own panel and never builds a plan.
    expect(page).toContain('if (action === "properties") {');
    expect(page).toContain("setProperties(entry);");
    // Asking for permissions starts from what the server reported.
    expect(page).toContain(
      'if (action === "chmod" && entry !== null && entry.mode !== null) next.mode = entry.mode;',
    );

    // The bits reach the window in the first place.
    const contract = readFileSync(
      new URL("../shared/sftp-browser-contract.ts", import.meta.url), "utf8",
    );
    for (const field of ["mode: string | null", "ownerId: number | null", "groupId: number | null"]) {
      expect(contract).toContain(field);
    }
    expect(contract).toContain('/^[0-7]{4}$/u.test(value)');
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

  it("asks before the file editor closes over unsaved edits or a save in flight", () => {
    const editor = source("FileEditorWindow.tsx");
    // Both ways out of the window go through the same question.
    expect(editor).toContain('data-testid="file-editor-close" onClick={() => void requestClose()}');
    expect(editor).toContain("<WindowControls onClose={() => void requestClose()} />");
    expect(editor).not.toContain("onClick={() => void window.lovelyhawkWindow.close()}");
    expect(editor).toContain("放弃未保存的修改？");
    expect(editor).toContain("保存还没有完成");
    // An in-app dialog, never a system one, and a second click cannot stack questions.
    expect(editor).toContain("<DialogHost dialog={confirmClose.dialog}");
    expect(editor).toContain("if (closingRef.current) return;");
    expect(editor).not.toMatch(/window\.(confirm|alert|prompt)\(/u);

    const controls = source("WindowControls.tsx");
    expect(controls).toContain("onClose === undefined ? void chrome.close() : onClose()");
  });
});
