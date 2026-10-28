import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { WinIrPlaybooks } from "./WinIrPlaybooks";
import { WinIrConsole } from "./WinIrConsole";
import { LOG_CATEGORIES } from "./WinIrEvents";
import { WIN_IR_MODULES } from "./win-ir-model";
import { WINDOWS_COMMAND_PRESETS } from "./win-ir-command-presets";
import { FILE_PLACES, REGISTRY_PLACES } from "./win-ir-presets";
import { findPlaybooks, playbookActionLabel, playbookText, PLAYBOOK_SOURCES, WINDOWS_PLAYBOOKS } from "./win-ir-playbooks";

describe("Windows response playbooks", () => {
  it("resolves every action to an existing finite entry point", () => {
    expect(new Set(WINDOWS_PLAYBOOKS.map((plan) => plan.id)).size).toBe(WINDOWS_PLAYBOOKS.length);
    for (const plan of WINDOWS_PLAYBOOKS) {
      expect(plan.steps).toHaveLength(4);
      expect(plan.gaps.length).toBeGreaterThan(0);
      expect(plan.sources.length).toBeGreaterThan(0);
      for (const key of plan.sources) expect(new URL(PLAYBOOK_SOURCES[key].url).protocol).toBe("https:");
      for (const action of plan.steps.flatMap((step) => step.actions)) {
        switch (action.kind) {
          case "module": expect(WIN_IR_MODULES.some((module) => module.key === action.tab)).toBe(true); break;
          case "files": expect(FILE_PLACES.some((place) => place.label === action.preset)).toBe(true); break;
          case "registry": expect(REGISTRY_PLACES.some((place) => place.label === action.preset)).toBe(true); break;
          case "logs": expect(LOG_CATEGORIES.some((category) => category.value === action.category)).toBe(true); break;
          case "command": expect(WINDOWS_COMMAND_PRESETS.some((preset) => preset.id === action.preset)).toBe(true); break;
        }
        expect(playbookActionLabel(action)).not.toContain("不可用");
      }
    }
  });

  it("finds symptoms, tool names and event identifiers without interpreting search text", () => {
    expect(findPlaybooks("  wMi  ").map((plan) => plan.id)).toContain("persistence");
    expect(findPlaybooks("IIS 后门").map((plan) => plan.id)).toEqual(["webshell"]);
    expect(findPlaybooks("删不掉").map((plan) => plan.id)).toEqual(["drivers"]);
    expect(findPlaybooks("4625").map((plan) => plan.id)).toEqual(["rdp"]);
    expect(findPlaybooks("<script>alert(1)</script>")).toEqual([]);
  });

  it("copies guidance with scope and sources without claiming a collected result", () => {
    for (const plan of WINDOWS_PLAYBOOKS) {
      const text = playbookText(plan);
      expect(text).toContain("不是已采集证据或处置结果");
      expect(text).toContain(plan.scope);
      expect(text).toContain("每通道最多 200 条");
      for (const gap of plan.gaps) expect(text).toContain(gap);
      for (const key of plan.sources) expect(text).toContain(PLAYBOOK_SOURCES[key].url);
      expect(new TextEncoder().encode(text).length).toBeLessThan(128 * 1024);
    }
  });

  it("allows offline reading and command preparation but disables target collection", () => {
    const onAction = vi.fn();
    const html = renderToStaticMarkup(<WinIrPlaybooks connected={false} busy={false} onAction={onAction} onCopy={() => undefined} />);
    expect(html).toContain("当前未连接");
    expect(html).toContain('disabled="">打开主机总览');
    expect(html).toMatch(/<button(?![^>]*disabled)[^>]*>准备查询 · 当前权限与令牌<\/button>/u);
    expect(html).not.toContain('type="checkbox"');
    expect(html).not.toContain("<a ");
    expect(onAction).not.toHaveBeenCalled();
  });

  it("stages the fixed recommendation without overwriting or executing the command draft", () => {
    const onRun = vi.fn();
    const html = renderToStaticMarkup(<WinIrConsole panel="command" status={null} busy={false} sessionKey="session" hostname="<script>host</script>" output={null} savedFiles={new Set()} canSave={false} onCopy={() => undefined} onSend={async () => false} onRun={onRun} onSave={() => undefined} onUnregister={() => undefined} suggestion={{ id: "drivers", request: 1 }} />);
    expect(html).toContain("方案推荐：内核驱动服务");
    expect(html).toContain("保留草稿");
    expect(html).toMatch(/<textarea[^>]*>whoami \/all<\/textarea>/u);
    expect(html).toContain("确认并执行");
    expect(onRun).not.toHaveBeenCalled();
  });
});
