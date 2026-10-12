import { useEffect, useRef, useState } from "react";

import type { BaselineCatalogItem, BaselineHistoryEntry, BaselineStatus } from "../shared/baseline-read-contract";
import {
  isBaselinePlan,
  isBaselineReceipt,
  type BaselineAction,
  type BaselineReceipt,
  type BaselineReloadChoice,
  type BaselineWriteApi,
} from "../shared/baseline-write-contract";
import { errorText } from "./error-text";

type Ask = (title: string, message: string, confirmLabel?: string) => Promise<boolean>;

const RELOAD_LABELS: Record<BaselineReloadChoice, string> = {
  "apply-now": "写入后用程序自己的检查核对配置，通过再重载，让新值生效",
  defer: "只写入配置文件，稍后由你手动重载（重载前新值不生效）",
};

/**
 * One change from plan to read-back: the plan is shown in full and approved
 * explicitly, then confirmed and run once. Declining drops the plan; a plan or
 * an answer of the wrong shape stops before anything runs.
 */
export async function performBaselineAction(
  api: BaselineWriteApi,
  bindingHandle: string,
  action: BaselineAction,
  ask: Ask,
): Promise<BaselineReceipt | null> {
  let planHandle: string | null = null;
  try {
    const plan = await api.planBaselineAction(bindingHandle, action);
    if (!isBaselinePlan(plan) || plan.action !== action.kind) throw new Error();
    planHandle = plan.planHandle;
    const message = [
      plan.summary,
      plan.changes.length > 0
        ? `要改的设置：\n${plan.changes.map((change) => `· ${change.file}：${change.before} → ${change.after}`).join("\n")}`
        : null,
      `涉及的完整文件（改前先备份）：${plan.files.join("、")}`,
      plan.reload === null ? null : `生效方式：${plan.reload}`,
      plan.restoreDescription === null ? null : `检查不通过时：${plan.restoreDescription}`,
      // Changing how sshd lets people in can lock the operator out of the next
      // login, though never out of the session already open.
      plan.files.some((file) => /(^|\/)sshd_config(\.d\/|$)/u.test(file))
        ? "注意：这会改变 SSH 的登录规则。已经打开的会话不受影响，但之后的新登录会按新规则执行；改之前请确认还有别的登录方式（例如普通账号加 sudo、密钥或控制台）。"
        : null,
      action.kind === "restore"
        ? "放回前会核对这些文件仍与当时改完时完全一致；之后又被改过就不放回，以免覆盖别人的改动。"
        : "这只改配置文件，不代表业务已经恢复健康；改完请用业务自己的方式核对。",
      `这次确认只对这一个计划有效，${Math.ceil(plan.expiresInSeconds / 60)} 分钟内有效。`,
    ].filter((line): line is string => line !== null).join("\n\n");
    const approved = await ask(
      action.kind === "change" ? "修改这台机器的基线设置？" : "放回这次基线改动之前的文件？",
      message,
      action.kind === "change" ? "确认修改" : "确认放回",
    );
    if (!approved) {
      void api.cancelBaselineAction(bindingHandle, plan.planHandle).catch(() => undefined);
      return null;
    }
    const confirmed = await api.confirmBaselineAction(bindingHandle, plan.planHandle);
    if (!isBaselinePlan(confirmed) || confirmed.planHandle !== plan.planHandle || !confirmed.confirmed) {
      throw new Error();
    }
    // From here the plan is spent: a failure is reported, not cancelled.
    planHandle = null;
    const result = await api.executeBaselineAction(bindingHandle, plan.planHandle);
    if (!isBaselineReceipt(result) || result.planHandle !== plan.planHandle) throw new Error();
    return result;
  } catch (error) {
    if (planHandle !== null) void api.cancelBaselineAction(bindingHandle, planHandle).catch(() => undefined);
    throw error;
  }
}

/** Why a setting cannot be changed from here, or null when it can. */
export function baselineChangeBlockedReason(item: BaselineCatalogItem, status: BaselineStatus | null): string | null {
  if (!item.writable) return "这一项只检查并给出修改建议，本工具不自动修改它。";
  if (status === null) return "先扫描，读到这台机器上的实际值后才能修改。";
  if (status.observedKind === "not-installed") return "这台机器上没装这个软件。";
  if (["unverified", "unsupported", "conditional"].includes(status.observedKind)) {
    return "这一项在这台机器上的实际配置还没能核实，不自动修改；请按右侧文件内容手动核对。";
  }
  return null;
}

/**
 * The receipt is handed to the page rather than kept here: a finished action
 * rescans and refreshes history, which can remount this component, and a
 * receipt held in it vanished the moment it appeared.
 */
function useAction(resetKey: string, onReceipt: (receipt: BaselineReceipt | null) => void) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const busyRef = useRef(false);
  const mountedRef = useRef(false);
  useEffect(() => {
    mountedRef.current = true;
    return () => { mountedRef.current = false; };
  }, []);
  useEffect(() => { setError(null); }, [resetKey]);
  async function run(task: () => Promise<BaselineReceipt | null>, onDone: () => void) {
    if (busyRef.current) return;
    busyRef.current = true;
    setBusy(true);
    setError(null);
    onReceipt(null);
    try {
      const result = await task();
      if (result === null) return;
      onReceipt(result);
      onDone();
    } catch (reason: unknown) {
      if (mountedRef.current) setError(errorText(reason, "这次改动没有完成，请刷新扫描结果后核对。"));
    } finally {
      busyRef.current = false;
      if (mountedRef.current) setBusy(false);
    }
  }
  return { busy, error, run };
}

export function BaselineReceiptLine({ receipt }: { receipt: BaselineReceipt }) {
  return (
    <p className={`baseline-action-receipt ${receipt.verified ? "is-verified" : "is-failed"}`}
      role={receipt.verified ? "status" : "alert"} data-testid="baseline-action-receipt"
      data-verified={receipt.verified ? "true" : "false"}>
      <strong>{receipt.verified ? "已完成并核对" : receipt.restored ? "检查没有通过，已用备份放回" : "没有完成"}</strong>
      <span>{receipt.detail}</span>
    </p>
  );
}

/**
 * Changing the selected setting: its value (the recommendation by default),
 * how the program picks it up, then the plan for approval.
 */
export function BaselineChangePanel({ item, status, bindingHandle, api, ask, receipt, onReceipt, onChanged }: {
  item: BaselineCatalogItem;
  status: BaselineStatus | null;
  bindingHandle: string;
  api: BaselineWriteApi;
  ask: Ask;
  /** The last change's receipt for this setting, kept by the page. */
  receipt: BaselineReceipt | null;
  onReceipt(receipt: BaselineReceipt | null): void;
  onChanged(): void;
}) {
  const [value, setValue] = useState(item.recommendation);
  const [reload, setReload] = useState<BaselineReloadChoice>("apply-now");
  const { busy, error, run } = useAction(`${bindingHandle}:${item.itemHandle}`, onReceipt);
  useEffect(() => { setValue(item.recommendation); }, [item.itemHandle, item.recommendation]);
  const blocked = baselineChangeBlockedReason(item, status);
  const valueError = item.valueKind.kind === "integer" && !(/^\d+$/u.test(value) &&
    Number(value) >= item.valueKind.minimum && Number(value) <= item.valueKind.maximum)
    ? `请填 ${item.valueKind.minimum} 到 ${item.valueKind.maximum} 之间的整数。`
    : null;
  return (
    <section className="baseline-change" aria-label={`修改 ${item.title}`} data-testid="baseline-change">
      <header>
        <strong>修改这一项</strong>
        <span>{status === null ? "尚未扫描" : `现在：${status.observed}`}</span>
      </header>
      {blocked !== null ? <p className="baseline-change-blocked" data-testid="baseline-change-blocked">{blocked}</p> : (
        <>
          <div className="baseline-change-fields">
            <label>改为
              {item.valueKind.kind === "choice" ? (
                <select value={value} onChange={(event) => setValue(event.target.value)} data-testid="baseline-change-value">
                  {item.valueKind.options.map((option) => (
                    <option key={option} value={option}>{option}{option === item.recommendation ? "（建议）" : ""}</option>
                  ))}
                </select>
              ) : (
                <input value={value} inputMode="numeric" maxLength={10} data-testid="baseline-change-value"
                  onChange={(event) => setValue(event.target.value.trim())} />
              )}
            </label>
            <fieldset>
              <legend>生效方式</legend>
              {(["apply-now", "defer"] as const).map((choice) => (
                <label key={choice}>
                  <input type="radio" name={`baseline-reload-${item.itemHandle}`} checked={reload === choice}
                    onChange={() => setReload(choice)} />
                  {RELOAD_LABELS[choice]}
                </label>
              ))}
            </fieldset>
          </div>
          {valueError !== null ? <p className="baseline-change-error" role="alert">{valueError}</p> : null}
          <div className="baseline-change-actions">
            <button type="button" data-testid="baseline-change-plan"
              disabled={busy || valueError !== null || value === status?.observed}
              title={value === status?.observed ? "已经是这个值" : undefined}
              onClick={() => void run(() => performBaselineAction(api, bindingHandle, {
                kind: "change", changes: [{ itemHandle: item.itemHandle, value }], reload,
              }, ask), onChanged)}>
              {busy ? "处理中…" : "查看修改计划…"}
            </button>
          </div>
        </>
      )}
      {error !== null ? <p className="baseline-change-error" role="alert">{error}</p> : null}
      {receipt !== null ? <BaselineReceiptLine receipt={receipt} /> : null}
    </section>
  );
}

/**
 * Putting one history entry's files back, or why it cannot be. The receipt
 * goes to the page, which shows it above the list: a restore refreshes the
 * history, and every entry comes back under a new handle.
 */
export function BaselineRestoreAction({ entry, historyHandle, bindingHandle, api, ask, onReceipt, onChanged }: {
  entry: BaselineHistoryEntry;
  historyHandle: string;
  bindingHandle: string;
  api: BaselineWriteApi;
  ask: Ask;
  onReceipt(receipt: BaselineReceipt | null): void;
  onChanged(): void;
}) {
  const { busy, error, run } = useAction(`${bindingHandle}:${historyHandle}:${entry.historyItemHandle}`, onReceipt);
  if (entry.state !== "applied") return null;
  return (
    <div className="baseline-restore" data-testid="baseline-restore">
      {entry.restorable ? (
        <button type="button" data-testid="baseline-restore-plan" disabled={busy}
          onClick={() => void run(() => performBaselineAction(api, bindingHandle, {
            kind: "restore", historyHandle, historyItemHandle: entry.historyItemHandle,
          }, ask), onChanged)}>
          {busy ? "处理中…" : "放回改动前的文件…"}
        </button>
      ) : (
        <span className="baseline-restore-blocked">这条旧记录缺少改动后完整文件的证据，只能查看，不能自动放回。</span>
      )}
      {error !== null ? <p className="baseline-change-error" role="alert">{error}</p> : null}
    </div>
  );
}
