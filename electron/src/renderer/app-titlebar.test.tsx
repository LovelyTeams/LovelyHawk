import { readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { AppTitleBar } from "./AppTitleBar";

const mainSource = readFileSync(new URL("../main/index.ts", import.meta.url), "utf8");
const appSource = readFileSync(new URL("./App.tsx", import.meta.url), "utf8");
const cssSource = readFileSync(new URL("./styles.css", import.meta.url), "utf8");

describe("AppTitleBar", () => {
  it("renders the current section as inert plain text", () => {
    const hostile = "</small><script>steal()</script>";
    const markup = renderToStaticMarkup(<AppTitleBar section={hostile} />);

    expect(markup).toContain('data-testid="window-titlebar"');
    expect(markup).toContain("LovelyRes");
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

  it("uses Electron's native window-controls overlay without widening preload authority", () => {
    const createWindow = mainSource.slice(
      mainSource.indexOf("function createWindow(): void"),
      mainSource.indexOf("function writeRequestedSmokeMarker"),
    );

    expect(createWindow).toContain('titleBarStyle: "hidden"');
    // Overlay colors come from the shared theme registry, so a repalette cannot
    // leave the native window controls out of sync with the CSS tokens.
    expect(createWindow).toContain("color: theme.chromeColor");
    expect(createWindow).toContain("symbolColor: theme.chromeSymbolColor");
    expect(createWindow).toContain("height: TITLE_BAR_HEIGHT");
    expect(mainSource).toContain("const TITLE_BAR_HEIGHT = 40;");
    // The OS paints the window controls above the page, so a modal backdrop
    // cannot dim them; main repaints the overlay with the composited color.
    expect(mainSource).toContain(
      "color: activeScrim ? definition.chromeScrimColor : definition.chromeColor,",
    );
    expect(appSource).toContain(
      "setWindowTheme({ theme: themeId, scrim: overlayOpen || pageModalOpen })",
    );
    expect(createWindow).not.toContain("frame: false");
    expect(appSource.match(/<AppTitleBar\b/gu)).toHaveLength(3);
    expect(cssSource).toContain("-webkit-app-region: drag");
    expect(cssSource).toContain("padding: 0 150px 0 14px");
  });

  it("exposes exactly the four named app actions as icon buttons", () => {
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
    // Window controls stay native; the bar must never draw its own.
    expect(markup).not.toMatch(/最小化|最大化|关闭窗口|<input|<select|<textarea|<a /u);
    expect(markup.match(/<button/gu)).toHaveLength(5);
    expect(markup.match(/<svg/gu)).toHaveLength(5);
    // Every action carries a text label for screen readers even though it is an icon.
    expect(markup.match(/aria-label="/gu)).toHaveLength(6);
    expect(markup).toContain('disabled=""');
    expect(cssSource).toContain(".window-titlebar-actions");
    expect(cssSource).toMatch(/\.window-titlebar-actions \{[^}]*-webkit-app-region: no-drag/u);
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
