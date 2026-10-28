import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type { CheckAuditCommandStatus } from "../shared/check-audit-read-contract";
import {
  isCheckAuditAction,
  isCheckAuditPlan,
  isCheckAuditReceipt,
  type CheckAuditPlan,
  type CheckAuditReceipt,
} from "../shared/check-audit-write-contract";
import { CheckAuditActions, performCheckAuditAction } from "./CheckAuditActions";

const HANDLE = "00000000-0000-4000-8000-000000000001";
const plan: CheckAuditPlan = {
  planHandle: HANDLE, action: "collect", summary: "给 lhprobe-bin 加上命令采集", commands: ["lhprobe-bin"],
  dangerous: true, restoreDescription: "换回全部原程序", confirmed: false, expiresInSeconds: 300,
};
const receipt: CheckAuditReceipt = {
  planHandle: HANDLE, action: "collect", commands: ["lhprobe-bin"], verified: true, detail: "已核对", restored: false,
};
const command = (state: CheckAuditCommandStatus["state"]): CheckAuditCommandStatus => ({
  commandHandle: HANDLE, name: "lhprobe-bin", state, critical: false,
  displayLocation: "/usr/bin/lhprobe-bin", locationRedacted: false, textTruncated: false,
});
function fakeApi(overrides: Partial<Record<string, () => Promise<unknown>>> = {}) {
  return {
    planCheckAuditAction: vi.fn(overrides.plan ?? (async () => plan)),
    confirmCheckAuditAction: vi.fn(overrides.confirm ?? (async () => ({ ...plan, confirmed: true }))),
    executeCheckAuditAction: vi.fn(overrides.execute ?? (async () => receipt)),
    cancelCheckAuditAction: vi.fn(async () => ({ cancelled: true })),
  };
}
const collect: { kind: "collect"; commandHandles: string[] } = { kind: "collect", commandHandles: [HANDLE] };

describe("command audit actions contract", () => {
  it("names commands only by catalog handles, and nothing for the log", () => {
    expect(isCheckAuditAction(collect)).toBe(true);
    expect(isCheckAuditAction({ kind: "clear-log" })).toBe(true);
    for (const forged of [
      { kind: "collect", commandHandles: [] },
      { kind: "collect", commandHandles: ["/usr/bin/ls"] },
      { kind: "collect", commandHandles: [HANDLE, HANDLE] },
      { kind: "collect", commandHandles: [HANDLE], path: "/usr/bin/ls" },
      { kind: "clear-log", path: "/var/log/lovelyres" },
      { kind: "uninstall", commandHandles: [HANDLE] },
      { kind: "collect", commandHandles: Array.from({ length: 33 }, (_, i) => `h-${i}`) },
    ]) expect(isCheckAuditAction(forged), JSON.stringify(forged)).toBe(false);
  });

  it("accepts a plan and a receipt only in their exact shapes", () => {
    expect(isCheckAuditPlan(plan)).toBe(true);
    expect(isCheckAuditPlan({ ...plan, action: "clear-log", commands: [] })).toBe(true);
    expect(isCheckAuditPlan({ ...plan, commands: [] })).toBe(false);
    expect(isCheckAuditPlan({ ...plan, expiresInSeconds: 3_600 })).toBe(false);
    expect(isCheckAuditPlan({ ...plan, path: "/usr/bin/ls" })).toBe(false);
    expect(isCheckAuditReceipt(receipt)).toBe(true);
    // Verified and put back are not both true of one run.
    expect(isCheckAuditReceipt({ ...receipt, restored: true })).toBe(false);
    expect(isCheckAuditReceipt({ ...receipt, commands: ["../ls"] })).toBe(false);
  });
});

describe("command audit change sequence", () => {
  it("shows the whole plan, and runs it once only after approval", async () => {
    const api = fakeApi();
    const ask = vi.fn(async () => true);
    await expect(performCheckAuditAction(api, "b", "s", collect, ask)).resolves.toEqual(receipt);
    const [title, message, label] = ask.mock.calls[0] as unknown as [string, string, string];
    expect(title).toBe("给这个命令加采集？");
    expect(label).toBe("确认加采集");
    for (const part of ["给 lhprobe-bin 加上命令采集", "涉及的命令：lhprobe-bin", "/var/log/lovelyres/command-audit.log",
      "检查不通过时：换回全部原程序", "5 分钟内有效"]) expect(message).toContain(part);
    expect(api.confirmCheckAuditAction).toHaveBeenCalledTimes(1);
    expect(api.executeCheckAuditAction).toHaveBeenCalledTimes(1);
    expect(api.cancelCheckAuditAction).not.toHaveBeenCalled();
  });

  it("drops the plan when it is declined, and runs nothing", async () => {
    const api = fakeApi();
    await expect(performCheckAuditAction(api, "b", "s", collect, async () => false)).resolves.toBeNull();
    expect(api.confirmCheckAuditAction).not.toHaveBeenCalled();
    expect(api.executeCheckAuditAction).not.toHaveBeenCalled();
    expect(api.cancelCheckAuditAction).toHaveBeenCalledWith("b", HANDLE);
  });

  it("asks nothing about a plan of the wrong shape or for another action", async () => {
    for (const wrong of [{ ...plan, action: "clear-log", commands: [] }, { ...plan, summary: "" }, {}]) {
      const api = fakeApi({ plan: async () => wrong });
      const ask = vi.fn(async () => true);
      await expect(performCheckAuditAction(api, "b", "s", collect, ask)).rejects.toThrow();
      expect(ask).not.toHaveBeenCalled();
      expect(api.executeCheckAuditAction).not.toHaveBeenCalled();
    }
  });

  it("does not run a plan whose confirmation came back wrong, and drops it", async () => {
    const api = fakeApi({ confirm: async () => ({ ...plan, confirmed: false }) });
    await expect(performCheckAuditAction(api, "b", "s", collect, async () => true)).rejects.toThrow();
    expect(api.executeCheckAuditAction).not.toHaveBeenCalled();
    expect(api.cancelCheckAuditAction).toHaveBeenCalledWith("b", HANDLE);
  });

  it("reports a run that failed without cancelling a plan already spent", async () => {
    const api = fakeApi({ execute: async () => { throw new Error("改动没有在时限内结束 (check-audit-action-timeout)"); } });
    await expect(performCheckAuditAction(api, "b", "s", collect, async () => true)).rejects.toThrow("时限");
    expect(api.cancelCheckAuditAction).not.toHaveBeenCalled();
  });
});

describe("command audit actions bar", () => {
  const render = (selected: CheckAuditCommandStatus | null, mode: "commands" | "log" = "commands", expired = false) =>
    renderToStaticMarkup(
      <CheckAuditActions bindingHandle="b" snapshotHandle="s" expired={expired} mode={mode} selected={selected}
        api={fakeApi()} ask={async () => false} onChanged={() => undefined} />,
    );

  it("offers collecting only an original program and taking it off only a collected one", () => {
    const original = render(command("original"));
    expect(original).toMatch(/data-testid="check-audit-collect"(?![^>]*disabled)/u);
    expect(original).toMatch(/data-testid="check-audit-uncollect"[^>]*disabled/u);
    const collected = render(command("instrumented"));
    expect(collected).toMatch(/data-testid="check-audit-collect"[^>]*disabled/u);
    expect(collected).toMatch(/data-testid="check-audit-uncollect"(?![^>]*disabled)/u);
    for (const state of ["missing", "foreign-script", "coreutils-shim", "multi-call"] as const) {
      const html = render(command(state));
      expect(html).toMatch(/data-testid="check-audit-collect"[^>]*disabled/u);
      expect(html).toMatch(/data-testid="check-audit-uncollect"[^>]*disabled/u);
    }
    expect(render(null)).toContain("在下面选一个命令");
  });

  it("offers clearing the log, and nothing once the list has expired", () => {
    expect(render(null, "log")).toMatch(/data-testid="check-audit-clear-log"(?![^>]*disabled)/u);
    expect(render(null, "log", true)).toMatch(/data-testid="check-audit-clear-log"[^>]*disabled/u);
    expect(render(command("original"), "commands", true)).toMatch(/data-testid="check-audit-collect"[^>]*disabled/u);
    expect(render(null, "log")).not.toMatch(/wrapper/iu);
  });
});
