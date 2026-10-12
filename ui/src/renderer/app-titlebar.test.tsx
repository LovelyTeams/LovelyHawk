import { existsSync, readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { AppTitleBar } from "./AppTitleBar";

const hostSource = readFileSync(new URL("../../../crates/lovelyhawk-desktop/src/host.rs", import.meta.url), "utf8");
const tauriConfig = JSON.parse(
  readFileSync(new URL("../../../crates/lovelyhawk-desktop/tauri.conf.json", import.meta.url), "utf8"),
) as { identifier: string; productName: string; bundle: { icon: string[] } };
const appSource = readFileSync(new URL("./App.tsx", import.meta.url), "utf8");
const titleBarSource = readFileSync(new URL("./AppTitleBar.tsx", import.meta.url), "utf8");
const cssSource = readFileSync(new URL("./styles.css", import.meta.url), "utf8");

describe("AppTitleBar", () => {
  it("renders the current section as inert plain text", () => {
    const hostile = "</small><script>steal()</script>";
    const markup = renderToStaticMarkup(<AppTitleBar section={hostile} />);

    expect(markup).toContain('data-testid="window-titlebar"');
    expect(markup).toContain("LovelyHawk");
    expect(markup).toContain("&lt;/small&gt;&lt;script&gt;steal()&lt;/script&gt;");
    expect(markup).not.toContain("<script>steal()");
    expect(markup).not.toContain("<button");
  });

  it("hides the titlebar semantics while a modal owns the renderer", () => {
    const markup = renderToStaticMarkup(
      <AppTitleBar section="设置" backgroundHidden />,
    );
    expect(markup).toContain('aria-hidden="true"');
  });

  it("draws its own frame: a drag region and window buttons on a frameless window", () => {
    // The host opens every window without a system frame, at the floor size
    // the stylesheet is laid out for.
    expect(hostSource).toContain(".decorations(false)");
    expect(hostSource).toContain(".min_inner_size(MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT)");
    expect(hostSource).toContain("pub const MIN_WINDOW_WIDTH: f64 = 1_080.0;");
    // The whole bar drags; buttons inside it still click.
    expect(titleBarSource).toContain('data-tauri-drag-region="deep"');
    expect(titleBarSource).toContain("<WindowControls />");
    expect(cssSource).not.toContain("-webkit-app-region");
    expect(cssSource).toContain(".window-controls button.is-close:hover");
    // The window background behind the page follows the theme before paint.
    expect(appSource).toContain(
      "setWindowTheme({ theme: themeId, scrim: overlayOpen || pageModalOpen })",
    );
    expect(appSource.match(/<AppTitleBar\b/gu)).toHaveLength(3);
  });

  it("exposes exactly the five named app actions as icon buttons", () => {
    const markup = renderToStaticMarkup(
      <AppTitleBar
        section="主机全景"
        actions={{
          themeLabel: "浅色",
          themeKind: "light",
          sshTerminalDisabled: true,
          onOpenConnections: () => undefined,
          onOpenSshTerminal: () => undefined,
          onOpenCommandHistory: () => undefined,
          onCycleTheme: () => undefined,
          onOpenSettings: () => undefined,
        }}
      />,
    );

    expect([...markup.matchAll(/data-testid="([a-z-]+)"/gu)].map((match) => match[1]))
      .toEqual([
        "window-titlebar",
        "open-connections",
        "open-ssh-terminal",
        "open-command-history",
        "cycle-theme",
        "open-settings",
      ]);
    // Window buttons need the desktop host, so a static render has none.
    expect(markup).not.toMatch(/最小化|最大化|关闭窗口|<input|<select|<textarea|<a /u);
    expect(markup.match(/<button/gu)).toHaveLength(5);
    expect(markup.match(/<svg/gu)).toHaveLength(5);
    // Every action carries a text label for screen readers even though it is an icon.
    expect(markup.match(/aria-label="/gu)).toHaveLength(6);
    expect(markup).toContain('disabled=""');
    expect(cssSource).toContain(".window-titlebar-actions");
  });

  it("gives every window the shipped application icon", () => {
    expect(tauriConfig.productName).toBe("LovelyHawk");
    // Windows groups taskbar buttons by application id, not by executable.
    expect(tauriConfig.identifier).toBe("com.lovelyhawk.desktop");
    expect(tauriConfig.bundle.icon).toContain("icons/icon.ico");
    for (const icon of tauriConfig.bundle.icon) {
      expect(existsSync(new URL(`../../../crates/lovelyhawk-desktop/${icon}`, import.meta.url)), icon).toBe(true);
    }
  });

  it("shows a moon for dark themes and a sun for light ones", () => {
    const render = (themeKind: "light" | "dark") => renderToStaticMarkup(
      <AppTitleBar
        section="主机全景"
        actions={{
          themeLabel: themeKind === "dark" ? "深色" : "浅色",
          themeKind,
          sshTerminalDisabled: false,
          onOpenConnections: () => undefined,
          onOpenSshTerminal: () => undefined,
          onOpenCommandHistory: () => undefined,
          onCycleTheme: () => undefined,
          onOpenSettings: () => undefined,
        }}
      />,
    );

    expect(render("light")).toContain('cx="8" cy="8" r="3"');
    expect(render("dark")).toContain("M13.2 9.7A5.5 5.5 0 0 1 6.3 2.8");
    expect(render("dark")).not.toContain('cx="8" cy="8" r="3"');
  });
});
