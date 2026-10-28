import { useEffect, useRef, useState } from "react";

import type { CheckAuditCommandStatus } from "../shared/check-audit-read-contract";
import {
  isCheckAuditPlan,
  isCheckAuditReceipt,
  type CheckAuditAction,
  type CheckAuditReceipt,
  type CheckAuditWriteApi,
} from "../shared/check-audit-write-contract";
import { checkAuditStateLabel } from "./check-audit-read-helpers";
import { errorText } from "./error-text";

/** What each change does on the target, said before it is approved. */
const EFFECTS: Record<CheckAuditAction["kind"], string> = {
  collect: "加采集后，命令所在位置的程序换成一段记录脚本：每次运行先把时间、命令、参数、账号和调用进程写进 /var/log/lovelyres/command-audit.log，再交给原程序执行。原程序改成隐藏的备份名留在同一目录，检查不通过会自动换回。需要 root 或免密码 sudo。",
  uncollect: "移除采集：用加采集时留下的备份换回原程序，并核对它与加采集前的 SHA-256 一致；之后这个命令不再记录。已经写下的日志不受影响。需要 root 或免密码 sudo。",
  "clear-log": "清空日志：现有日志改名留在同一目录作为备份（文件名带 clear- 和编号），再建一个新的空日志；之前的记录不会被删除。需要 root 或免密码 sudo。",
};
const TITLES: Record<CheckAuditAction["kind"], string> = {
  collect: "给这个命令加采集？",
  uncollect: "移除这个命令的采集？",
  "clear-log": "清空命令审计日志？",
};
const CONFIRM_LABELS: Record<CheckAuditAction["kind"], string> = {
  collect: "确认加采集",
  uncollect: "确认移除",
  "clear-log": "确认清空",
};

type Ask = (title: string, message: string, confirmLabel?: string) => Promise<boolean>;

/**
 * One change from plan to read-back: the plan is shown in full and approved
 * explicitly, then confirmed and run once. Declining drops the plan. A plan
 * or an answer of the wrong shape stops before anything runs.
 */
export async function performCheckAuditAction(
  api: CheckAuditWriteApi,
  bindingHandle: string,
  snapshotHandle: string,
  action: CheckAuditAction,
  ask: Ask,
): Promise<CheckAuditReceipt | null> {
  let planHandle: string | null = null;
  try {
    const plan = await api.planCheckAuditAction(bindingHandle, snapshotHandle, action);
    if (!isCheckAuditPlan(plan) || plan.action !== action.kind) throw new Error();
    planHandle = plan.planHandle;
    const message = [
      plan.summary,
      plan.commands.length > 0 ? `涉及的命令：${plan.commands.join("、")}` : null,
      EFFECTS[action.kind],
      plan.restoreDescription === null ? null : `检查不通过时：${plan.restoreDescription}`,
      `这次确认只对这一个计划有效，${Math.ceil(plan.expiresInSeconds / 60)} 分钟内有效。`,
    ].filter((line): line is string => line !== null).join("\n\n");
    if (!(await ask(TITLES[action.kind], message, CONFIRM_LABELS[action.kind]))) {
      void api.cancelCheckAuditAction(bindingHandle, plan.planHandle).catch(() => undefined);
      return null;
    }
    const confirmed = await api.confirmCheckAuditAction(bindingHandle, plan.planHandle);
    if (!isCheckAuditPlan(confirmed) || confirmed.planHandle !== plan.planHandle || !confirmed.confirmed) {
      throw new Error();
    }
    // From here the plan is spent: a failure is reported, not cancelled.
    planHandle = null;
    const result = await api.executeCheckAuditAction(bindingHandle, plan.planHandle);
    if (!isCheckAuditReceipt(result) || result.planHandle !== plan.planHandle) throw new Error();
    return result;
  } catch (error) {
    if (planHandle !== null) void api.cancelCheckAuditAction(bindingHandle, planHandle).catch(() => undefined);
    throw error;
  }
}

export interface CheckAuditActionsProps {
  bindingHandle: string;
  snapshotHandle: string;
  /** The catalog has expired: no change is planned from it. */
  expired: boolean;
  /** Which change this bar offers: commands (collect/uncollect) or the log. */
  mode: "commands" | "log";
  /** The command selected in the list, with its collected state. */
  selected: CheckAuditCommandStatus | null;
  api: CheckAuditWriteApi;
  ask: Ask;
  /** Called after a change ran, so the page reads the state again. */
  onChanged(): void;
}

/**
 * The second phase of command audit: adding collection to a command, taking
 * it off, and clearing the log. Each one is planned by the backend, shown in
 * full for an explicit approval, run once, and read back; the page names
 * commands only by the catalog's handles.
 */
export function CheckAuditActions({ bindingHandle, snapshotHandle, expired, mode, selected, api, ask, onChanged }: CheckAuditActionsProps) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [receipt, setReceipt] = useState<CheckAuditReceipt | null>(null);
  const busyRef = useRef(false);
  const mountedRef = useRef(true);
  useEffect(() => () => { mountedRef.current = false; }, []);
  // A result speaks of the target and list it was made on.
  useEffect(() => { setReceipt(null); setError(null); }, [bindingHandle, snapshotHandle]);

  async function run(action: CheckAuditAction) {
    if (busyRef.current || expired) return;
    busyRef.current = true;
    setBusy(true);
    setError(null);
    setReceipt(null);
    try {
      const result = await performCheckAuditAction(api, bindingHandle, snapshotHandle, action, ask);
      if (result === null) return;
      if (mountedRef.current) setReceipt(result);
      onChanged();
    } catch (reason: unknown) {
      if (mountedRef.current) setError(errorText(reason, "这次改动没有完成，目标上的状态请刷新后再确认。"));
    } finally {
      busyRef.current = false;
      if (mountedRef.current) setBusy(false);
    }
  }

  const blocked = expired ? "命令列表已过期，请先重新读取" : null;
  return (
    <section className="check-audit-actions" aria-label={mode === "commands" ? "命令采集" : "日志维护"}
      data-testid="check-audit-actions">
      {mode === "commands" ? (
        <div className="check-audit-actions-bar">
          <span>
            {selected === null
              ? "在下面选一个命令，可以给它加采集或移除采集。"
              : `所选：${selected.name}（${checkAuditStateLabel(selected.state)}）`}
          </span>
          <button type="button" data-testid="check-audit-collect"
            disabled={busy || blocked !== null || selected?.state !== "original"}
            title={blocked ?? (selected !== null && selected.state !== "original" ? collectBlockedReason(selected) : undefined)}
            onClick={() => { if (selected !== null) void run({ kind: "collect", commandHandles: [selected.commandHandle] }); }}>
            加采集…
          </button>
          <button type="button" data-testid="check-audit-uncollect"
            disabled={busy || blocked !== null || selected?.state !== "instrumented"}
            title={blocked ?? (selected !== null && selected.state !== "instrumented" ? "这个命令没有加采集" : undefined)}
            onClick={() => { if (selected !== null) void run({ kind: "uncollect", commandHandles: [selected.commandHandle] }); }}>
            移除采集…
          </button>
        </div>
      ) : (
        <div className="check-audit-actions-bar">
          <span>清空前的日志会改名保留，不会删除。</span>
          <button type="button" data-testid="check-audit-clear-log" disabled={busy || blocked !== null}
            title={blocked ?? undefined} onClick={() => void run({ kind: "clear-log" })}>
            清空日志…
          </button>
        </div>
      )}
      {busy ? <p className="check-audit-actions-status" role="status">正在处理，完成后会读回核对…</p> : null}
      {error !== null ? <p className="check-audit-inline-error" role="alert">{error}</p> : null}
      {receipt !== null ? (
        <p className={`check-audit-actions-receipt ${receipt.verified ? "is-verified" : "is-failed"}`}
          role={receipt.verified ? "status" : "alert"} data-testid="check-audit-receipt"
          data-verified={receipt.verified ? "true" : "false"}>
          <strong>{receipt.verified ? "已完成并核对" : receipt.restored ? "检查没有通过，已换回原状" : "没有完成"}</strong>
          {receipt.commands.length > 0 ? `（${receipt.commands.join("、")}）` : null}
          <span>{receipt.detail}</span>
        </p>
      ) : null}
    </section>
  );
}

function collectBlockedReason(command: CheckAuditCommandStatus): string {
  switch (command.state) {
    case "instrumented": return "这个命令已经加了采集";
    case "missing": return "目标上没有这个命令";
    case "foreign-script": return "这个命令执行的是脚本，不在这里加采集；请先核对它的来源";
    case "coreutils-shim": return "这个命令是 coreutils 的转接，不在这里加采集";
    case "multi-call": return "这个命令是 BusyBox 这类多合一程序的一部分：加采集会同时换掉它的所有命令（包括 sh），所以不提供";
    case "original": return "";
  }
}
