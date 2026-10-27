import { TransientNotice } from "./NotificationCenter";
import { useEffect, useRef, useState, type FormEvent } from "react";

import {
  isLogRuleName,
  isLogRulePattern,
  LOG_RULE_LIMITS,
  LOG_RULE_SEVERITIES,
  type LogRule,
  type LogRuleList,
  type LogRuleRemovalProposal,
  type LogRuleRemovalResult,
  type LogRuleSeverity,
} from "../shared/log-rules-contract";
import { DialogHost } from "./DialogHost";
import { errorText } from "./error-text";
import { logRuleSeverityLabel, type LogRulesApi } from "./log-rule-hits";
import { useModalScrim } from "./modal-scrim";
import { planExpiryLabel } from "./plan-expiry";
import { useConfirmDialog } from "./use-confirm-dialog";
import "./emergency-path.css";

interface Draft {
  name: string;
  pattern: string;
  severity: LogRuleSeverity;
}

const emptyDraft: Draft = { name: "", pattern: "", severity: "medium" };

/**
 * The operator's own match rules. They live in the program's data folder and
 * act on nothing but lines a page has already read: each read line is marked
 * with the first rule that matches it. Removing one is permanent, so it goes
 * through the same plan and confirmation as any other removal.
 */
export function LogRulesDialog({ api, returnFocus, onChanged, onClose }: {
  api: LogRulesApi;
  returnFocus: HTMLElement | null;
  /** The saved rules changed; marks on the page are out of date. */
  onChanged(): void;
  onClose(): void;
}) {
  const [rules, setRules] = useState<LogRule[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [draft, setDraft] = useState<Draft>(emptyDraft);
  const [draftError, setDraftError] = useState<string | null>(null);
  const [notice, setNotice] = useState<{ text: string; failed: boolean } | null>(null);
  const [busy, setBusy] = useState(false);
  const busyRef = useRef(false);
  const root = useRef<HTMLElement>(null);
  const nameRef = useRef<HTMLInputElement>(null);
  const { dialog, ask, resolve } = useConfirmDialog();
  const dialogOpen = useRef(false);
  dialogOpen.current = dialog !== null;
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  useModalScrim();

  async function load(): Promise<void> {
    try {
      const list = await api.logRules({ action: "list" }) as LogRuleList;
      setRules(list.rules);
      setLoadError(null);
    } catch (reason) {
      setLoadError(errorText(reason, "没能读出已保存的规则。"));
    }
  }

  useEffect(() => {
    void load();
    nameRef.current?.focus();
    function keydown(event: KeyboardEvent) {
      // The removal question is a dialog of its own and answers its own keys.
      if (dialogOpen.current) return;
      if (event.key === "Escape") { event.preventDefault(); closeRef.current(); return; }
      if (event.key !== "Tab" || !root.current) return;
      const items = [...root.current.querySelectorAll<HTMLElement>(
        "button:not([disabled]), input:not([disabled]), select:not([disabled])")];
      const index = items.indexOf(document.activeElement as HTMLElement);
      if (index < 0 || (event.shiftKey ? index === 0 : index === items.length - 1)) {
        event.preventDefault(); (event.shiftKey ? items.at(-1) : items[0])?.focus();
      }
    }
    document.addEventListener("keydown", keydown);
    return () => {
      document.removeEventListener("keydown", keydown);
      if (returnFocus?.isConnected) returnFocus.focus({ preventScroll: true });
    };
    // Loaded once per opening; the dialog reloads after each change itself.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function guarded(task: () => Promise<void>): Promise<void> {
    if (busyRef.current) return;
    busyRef.current = true;
    setBusy(true);
    try {
      await task();
    } finally {
      busyRef.current = false;
      setBusy(false);
    }
  }

  function submit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    if (!isLogRuleName(draft.name)) {
      setDraftError("规则名称不能为空、不能含控制字符，最长 128 字节。");
      return;
    }
    if (!isLogRulePattern(draft.pattern)) {
      setDraftError("匹配模式不能为空、不能含控制字符，最长 1024 字节。");
      return;
    }
    setDraftError(null);
    void guarded(async () => {
      try {
        const rule = await api.logRules({ action: "add", ...draft }) as LogRule;
        setDraft(emptyDraft);
        setNotice({ text: `已保存规则「${rule.name}」。`, failed: false });
        onChanged();
        await load();
        nameRef.current?.focus();
      } catch (reason) {
        setDraftError(errorText(reason, "没能保存这条规则。"));
      }
    });
  }

  function remove(rule: LogRule): void {
    void guarded(async () => {
      let plan: LogRuleRemovalProposal;
      try {
        plan = await api.logRules({ action: "plan-remove", id: rule.id }) as LogRuleRemovalProposal;
      } catch (reason) {
        setNotice({ text: errorText(reason, "没能准备删除。"), failed: true });
        await load();
        return;
      }
      const confirmed = await ask(
        "删除匹配规则",
        `${plan.summary}\n\n模式：${rule.pattern}\n计划有效期：${planExpiryLabel(plan.expiresInSeconds)}`,
        "删除",
      );
      try {
        if (!confirmed) {
          await api.logRules({ action: "cancel-remove", handle: plan.handle });
          return;
        }
        const result = await api.logRules({ action: "confirm-remove", handle: plan.handle }) as LogRuleRemovalResult;
        setNotice(result.verified
          ? { text: `已删除规则「${rule.name}」，并核对它已不在。`, failed: false }
          : { text: `删除了规则「${rule.name}」，但没能核对它已不在，请刷新确认。`, failed: true });
        onChanged();
      } catch (reason) {
        setNotice({ text: errorText(reason, "删除没有完成。"), failed: true });
      }
      await load();
    });
  }

  const full = rules !== null && rules.length >= LOG_RULE_LIMITS.maximumRules;
  return (
    <div className="emergency-path-backdrop">
      <section ref={root} className="emergency-path-dialog log-rules-dialog" role="dialog" aria-modal="true"
        aria-labelledby="log-rules-title" data-testid="log-rules-dialog">
        <header>
          <h2 id="log-rules-title">日志匹配规则</h2>
          <p>{rules === null ? "正在读取…" : `已有 ${rules.length} / ${LOG_RULE_LIMITS.maximumRules} 条`}</p>
        </header>
        <p>{"规则只保存在本机的程序数据文件夹里。读到的每一行日志会逐条比对规则，标出第一条命中的；"
          + "匹配不区分大小写，不会改动目标机。"}</p>
        {loadError !== null ? <TransientNotice source="日志规则" message={loadError ?? ""} severity="error" inline><p className="emergency-path-error" role="alert">{loadError}</p></TransientNotice> : null}
        {rules !== null && rules.length === 0 ? <p className="log-rules-empty">还没有规则。在下面添加一条，例如名称“webshell”、模式 <code>eval\(|base64_decode</code>。</p> : null}
        {rules !== null && rules.length > 0 ? (
          <ul className="log-rules-list" aria-label="已保存的规则">
            {rules.map((rule) => (
              <li key={rule.id}>
                <span className={`log-analysis-rule-hit is-${rule.severity}`}>{logRuleSeverityLabel(rule.severity)}</span>
                <strong>{rule.name}</strong>
                <code title={rule.pattern}>{rule.pattern}</code>
                <button type="button" disabled={busy} aria-label={`删除规则「${rule.name}」`}
                  onClick={() => remove(rule)}>删除…</button>
              </li>
            ))}
          </ul>
        ) : null}
        <form className="log-rules-form" onSubmit={submit} aria-label="添加规则">
          <label>名称
            <input ref={nameRef} value={draft.name} maxLength={LOG_RULE_LIMITS.maximumNameBytes}
              placeholder="例如 webshell"
              onChange={(event) => setDraft({ ...draft, name: event.target.value })} />
          </label>
          <label>匹配模式（正则表达式）
            <input value={draft.pattern} maxLength={LOG_RULE_LIMITS.maximumPatternBytes}
              placeholder="例如 eval\(|base64_decode" spellCheck={false}
              onChange={(event) => setDraft({ ...draft, pattern: event.target.value })} />
          </label>
          <label>级别
            <select value={draft.severity}
              onChange={(event) => setDraft({ ...draft, severity: event.target.value as LogRuleSeverity })}>
              {LOG_RULE_SEVERITIES.map((severity) => (
                <option key={severity} value={severity}>{logRuleSeverityLabel(severity)}</option>
              ))}
            </select>
          </label>
          <button type="submit" disabled={busy || full} title={full ? "规则已满 128 条" : undefined}>
            {busy ? "处理中…" : "添加规则"}
          </button>
        </form>
        {draftError !== null ? <TransientNotice source="日志规则" message={draftError ?? ""} severity="error" inline><p className="emergency-path-error" role="alert">{draftError}</p></TransientNotice> : null}
        {notice !== null ? (
          <TransientNotice source="日志规则" message={notice.text ?? ""} severity={(notice.failed ? "alert" : "status") === "alert" ? "error" : "info"} inline><p className={notice.failed ? "emergency-path-error" : "log-rules-notice"} role={notice.failed ? "alert" : "status"}>
            {notice.text}
          </p></TransientNotice>
        ) : null}
        <footer><button type="button" onClick={onClose}>关闭</button></footer>
      </section>
      {dialog !== null ? <DialogHost dialog={dialog} scrollMessage onResolve={resolve} /> : null}
    </div>
  );
}
