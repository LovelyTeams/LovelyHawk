import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type { BaselineCatalogItem, BaselineHistoryEntry, BaselineStatus } from "../shared/baseline-read-contract";
import {
  isBaselineAction,
  isBaselinePlan,
  isBaselineReceipt,
  type BaselineAction,
  type BaselinePlan,
  type BaselineReceipt,
} from "../shared/baseline-write-contract";
import {
  BaselineChangePanel,
  BaselineRestoreAction,
  baselineChangeBlockedReason,
  performBaselineAction,
} from "./BaselineActions";
import { BaselineHistoryView } from "./BaselinePage";

const ITEM = "baseline-item-1";
const plan: BaselinePlan = {
  planHandle: "plan-1", action: "change", summary: "应用 1 项 Linux 安全基线（写入后立即校验并重载）",
  changes: [{ itemHandle: ITEM, before: "yes", after: "no", file: "/etc/ssh/sshd_config" }],
  files: ["/etc/ssh/sshd_config"], reload: "写入后立即校验并重载", dangerous: true,
  restoreDescription: "从受管备份恢复全部配置文件并读回验证", confirmed: false, expiresInSeconds: 300,
};
const receipt: BaselineReceipt = {
  planHandle: "plan-1", action: "change", files: ["/etc/ssh/sshd_config"], verified: true,
  detail: "已写入并由独立读回核对", restored: false,
};
const change: BaselineAction = { kind: "change", changes: [{ itemHandle: ITEM, value: "no" }], reload: "apply-now" };
const item: BaselineCatalogItem = {
  itemHandle: ITEM, category: "ssh", component: "ssh", risk: "high",
  valueKind: { kind: "choice", options: ["no", "prohibit-password", "yes"] },
  title: "禁止 root 直接登录", description: "PermitRootLogin", recommendation: "no", writable: true,
} as BaselineCatalogItem;
const status = (observedKind: BaselineStatus["observedKind"], observed = "yes"): BaselineStatus => ({
  itemHandle: ITEM, observedKind, observed, compliant: false, redacted: false, textTruncated: false,
  fix: { file: "/etc/ssh/sshd_config", lines: ["PermitRootLogin no"], reload: null, manualReason: null },
});
function fakeApi(overrides: Partial<Record<string, () => Promise<unknown>>> = {}) {
  return {
    planBaselineAction: vi.fn(overrides.plan ?? (async () => plan)),
    confirmBaselineAction: vi.fn(overrides.confirm ?? (async () => ({ ...plan, confirmed: true }))),
    executeBaselineAction: vi.fn(overrides.execute ?? (async () => receipt)),
    cancelBaselineAction: vi.fn(async () => ({ cancelled: true })),
  };
}

describe("baseline actions contract", () => {
  it("names settings by catalogue handle and history entries by snapshot handles only", () => {
    expect(isBaselineAction(change)).toBe(true);
    expect(isBaselineAction({ kind: "restore", historyHandle: "history-1", historyItemHandle: "record-1" })).toBe(true);
    for (const forged of [
      { ...change, changes: [] },
      { ...change, reload: "restart" },
      { ...change, changes: [{ itemHandle: ITEM, value: "no", file: "/etc/shadow" }] },
      { ...change, changes: [{ itemHandle: "/etc/ssh/sshd_config", value: "no" }] },
      { ...change, changes: [{ itemHandle: ITEM, value: "no\nPermitEmptyPasswords yes" }] },
      { ...change, changes: [{ itemHandle: ITEM, value: "no" }, { itemHandle: ITEM, value: "yes" }] },
      { kind: "restore", historyHandle: "history-1", historyItemHandle: "record-1", recordId: "x" },
      { kind: "reload", command: "systemctl restart sshd" },
    ]) expect(isBaselineAction(forged), JSON.stringify(forged)).toBe(false);
  });

  it("accepts a plan and a receipt only in their exact shapes", () => {
    expect(isBaselinePlan(plan)).toBe(true);
    expect(isBaselinePlan({ ...plan, action: "restore", changes: [], reload: null })).toBe(true);
    // A change names what it writes and how it takes effect; a restore does not.
    expect(isBaselinePlan({ ...plan, changes: [] })).toBe(false);
    expect(isBaselinePlan({ ...plan, reload: null })).toBe(false);
    expect(isBaselinePlan({ ...plan, action: "restore", reload: null })).toBe(false);
    expect(isBaselinePlan({ ...plan, files: [] })).toBe(false);
    expect(isBaselinePlan({ ...plan, command: "sed -i" })).toBe(false);
    expect(isBaselineReceipt(receipt)).toBe(true);
    expect(isBaselineReceipt({ ...receipt, restored: true })).toBe(false);
  });
});

describe("baseline change sequence", () => {
  it("shows the whole plan, and runs it once only after approval", async () => {
    const api = fakeApi();
    const ask = vi.fn(async () => true);
    await expect(performBaselineAction(api, "binding", change, ask)).resolves.toEqual(receipt);
    const [title, message, label] = ask.mock.calls[0] as unknown as [string, string, string];
    expect(title).toBe("修改这台机器的基线设置？");
    expect(label).toBe("确认修改");
    for (const part of ["/etc/ssh/sshd_config：yes → no", "涉及的完整文件（改前先备份）", "生效方式：写入后立即校验并重载",
      "检查不通过时：从受管备份恢复全部配置文件并读回验证", "不代表业务已经恢复健康", "5 分钟内有效",
      "已经打开的会话不受影响，但之后的新登录会按新规则执行"]) {
      expect(message).toContain(part);
    }
    expect(api.executeBaselineAction).toHaveBeenCalledTimes(1);
  });

  it("drops a declined plan, and asks nothing about a plan of the wrong shape", async () => {
    const declined = fakeApi();
    await expect(performBaselineAction(declined, "binding", change, async () => false)).resolves.toBeNull();
    expect(declined.executeBaselineAction).not.toHaveBeenCalled();
    expect(declined.cancelBaselineAction).toHaveBeenCalledWith("binding", "plan-1");
    const wrong = fakeApi({ plan: async () => ({ ...plan, action: "restore", changes: [], reload: null }) });
    const ask = vi.fn(async () => true);
    await expect(performBaselineAction(wrong, "binding", change, ask)).rejects.toThrow();
    expect(ask).not.toHaveBeenCalled();
  });

  it("says, for a restore, that later changes are never overwritten", async () => {
    const api = fakeApi({ plan: async () => ({ ...plan, action: "restore", changes: [], reload: null }) });
    const ask = vi.fn(async () => false);
    await performBaselineAction(api, "binding", { kind: "restore", historyHandle: "h", historyItemHandle: "r" }, ask);
    const [title, message, label] = ask.mock.calls[0] as unknown as [string, string, string];
    expect(title).toBe("放回这次基线改动之前的文件？");
    expect(label).toBe("确认放回");
    expect(message).toContain("之后又被改过就不放回");
  });
});

describe("baseline change controls", () => {
  const render = (selected: BaselineCatalogItem, observed: BaselineStatus | null, kept: BaselineReceipt | null = null) =>
    renderToStaticMarkup(
      <BaselineChangePanel item={selected} status={observed} bindingHandle="binding" api={fakeApi()}
        ask={async () => false} receipt={kept} onReceipt={() => undefined} onChanged={() => undefined} />,
    );

  it("keeps attribute and audit changes immediate and still planned", () => {
    for (const recommendation of ["权限符合策略", "规则已保存并载入"]) {
      const html = render({ ...item, component: "system", recommendation,
        valueKind: { kind: "choice", options: [recommendation] } }, status("value", "mode:0666,uid:0,gid:42"));
      expect(html).toContain("不会重启服务");
      expect(html).toContain("查看修改计划");
      expect(html).not.toContain('type="radio"');
      expect(html).not.toContain("稍后由你手动重载");
    }
  });

  // The rescan after a change remounts the panel; a receipt it kept itself was
  // gone before anyone could read it, so the page keeps it and hands it back.
  it("shows the receipt the page kept, and none of its own", () => {
    expect(render(item, status("value"))).not.toContain('data-testid="baseline-action-receipt"');
    const shown = render(item, status("value"), receipt);
    expect(shown).toContain('data-testid="baseline-action-receipt"');
    expect(shown).toContain('data-verified="true"');
    expect(shown).toContain("已完成并核对");
    const failed = render(item, status("value"), { ...receipt, verified: false, restored: true });
    expect(failed).toContain('data-verified="false"');
    expect(failed).toContain("检查没有通过，已用备份放回");
    const history = (kept: BaselineReceipt | null) => renderToStaticMarkup(
      <BaselineHistoryView status="ready" history={null} error={null} connected onRefresh={() => undefined}
        receipt={kept} />,
    );
    expect(history(null)).not.toContain('data-testid="baseline-action-receipt"');
    expect(history({ ...receipt, action: "restore" })).toContain("已完成并核对");
  });

  it("offers a change only for a writable setting whose value was read", () => {
    const html = render(item, status("value"));
    expect(html).toContain('data-testid="baseline-change-plan"');
    expect(html).toContain("no（建议）");
    expect(html).toContain("写入后用程序自己的检查核对配置");
    expect(baselineChangeBlockedReason({ ...item, writable: false }, status("value"))).toContain("只检查");
    expect(baselineChangeBlockedReason(item, null)).toContain("先扫描");
    for (const kind of ["unverified", "unsupported", "conditional"] as const) {
      expect(baselineChangeBlockedReason(item, status(kind))).toContain("还没能核实");
    }
    expect(render({ ...item, writable: false }, status("value"))).not.toContain('data-testid="baseline-change-plan"');
  });

  it("offers putting back only an applied entry, and says why an old one cannot be", () => {
    const entry: BaselineHistoryEntry = {
      historyItemHandle: "record-1", state: "applied", restorable: true, summary: "已应用", changeCount: 1,
      createdAt: "2026-10-12T01:00:00Z", updatedAt: "2026-10-12T01:00:00Z", redacted: false, textTruncated: false,
    };
    const restore = (value: BaselineHistoryEntry) => renderToStaticMarkup(
      <BaselineRestoreAction entry={value} historyHandle="history-1" bindingHandle="binding" api={fakeApi()}
        ask={async () => false} onReceipt={() => undefined} onChanged={() => undefined} />,
    );
    expect(restore(entry)).toContain('data-testid="baseline-restore-plan"');
    expect(restore({ ...entry, restorable: false })).toContain("只能查看，不能自动放回");
    expect(restore({ ...entry, state: "restored", restorable: false })).toBe("");
  });
});
