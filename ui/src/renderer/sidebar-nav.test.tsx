import { readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { PageDescriptor } from "../shared/contract";
import { SidebarNav } from "./SidebarNav";
import { ThemePicker } from "./ThemePicker";
import { THEMES } from "./theme/theme";

const labels = { target: "目标", triage: "摸底", investigation: "调查", operations: "运维", intelligence: "助手" } as const;
const pages = [
  { id: "system-info", group: "triage", title: "主机全景", summary: "主机概况。", icon: "▣", capability: "connected-target" },
  { id: "notes", group: "investigation", title: "笔记", summary: "</p><script>x()</script>", icon: "▤", capability: "local-workspace" },
] as PageDescriptor[];

describe("SidebarNav", () => {
  it("renders every page inside an open, labelled group with the filter", () => {
    const markup = renderToStaticMarkup(
      <SidebarNav pages={pages} groupLabels={labels} activePageId="notes" targetConnected={false} busy={false} rail={false} onNavigate={() => undefined} />,
    );
    expect(markup.match(/class="nav-item[ "]/gu)).toHaveLength(2);
    expect(markup).toContain('data-testid="sidebar-filter"');
    expect(markup).toContain('aria-expanded="true"');
    // Groups without pages are not drawn.
    expect(markup).not.toContain("nav-group--operations");
    expect(markup).toContain('aria-current="page"');
    expect(markup).toContain("需要连接目标");
    expect(markup).toContain("&lt;/p&gt;&lt;script&gt;");
    expect(markup).not.toContain("<script>x()");
  });

  it("names icon-only items in the rail and drops the filter", () => {
    const markup = renderToStaticMarkup(
      <SidebarNav pages={pages} groupLabels={labels} activePageId="notes" targetConnected busy={false} rail onNavigate={() => undefined} />,
    );
    expect(markup).not.toContain("sidebar-filter");
    expect(markup).not.toContain("nav-group-row");
    expect(markup).toContain('aria-label="主机全景"');
  });

  it("offers the rail only while the status bar carries the target", () => {
    const app = readFileSync(new URL("./App.tsx", import.meta.url), "utf8");
    expect(app).toContain("const rail = railPreferred && uiPreferences.showStatusBar;");
  });
});

describe("ThemePicker", () => {
  it("shows the current palette and keeps its popover closed until asked", () => {
    const markup = renderToStaticMarkup(<ThemePicker themeId="tingwu" onSelect={() => undefined} />);
    expect(markup).toContain("配色：庭芜绿");
    expect(markup).toContain('aria-expanded="false"');
    expect(markup).not.toContain("theme-card");
  });

  it("registers a light and dark family with distinct names and four swatches each", () => {
    expect(THEMES.filter((theme) => theme.kind === "light").length).toBeGreaterThan(5);
    expect(THEMES.filter((theme) => theme.kind === "dark").length).toBeGreaterThan(3);
    for (const theme of THEMES) {
      expect(theme.swatches, theme.id).toHaveLength(4);
      expect(theme.subtitle.length, theme.id).toBeGreaterThan(0);
    }
  });
});
