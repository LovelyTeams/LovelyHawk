import { useEffect, useRef } from "react";
import type { NginxRepairDialog as DialogState } from "./nginx-repair-controller";
import { useModalScrim } from "./modal-scrim";

export function NginxRepairDialog({ dialog, returnFocus, fallbackFocus, onClose, onConfirm }: {
  dialog: DialogState; returnFocus: HTMLElement | null; fallbackFocus: HTMLElement | null; onClose(): void; onConfirm(): void;
}) {
  useModalScrim();
  const host = useRef<HTMLElement>(null);
  const safe = useRef<HTMLButtonElement>(null);
  const current = useRef({ dialog, onClose });
  current.current = { dialog, onClose };
  useEffect(() => {
    const previous = returnFocus ?? (document.activeElement instanceof HTMLElement ? document.activeElement : null);
    const focusSafe = () => (safe.current?.disabled ? host.current : safe.current)?.focus({ preventScroll: true });
    focusSafe();
    function keydown(event: KeyboardEvent) {
      if (event.key === "Escape" && current.current.dialog.phase !== "executing") {
        event.preventDefault(); current.current.onClose(); return;
      }
      if (event.key !== "Tab" || !host.current) return;
      const nodes = Array.from(host.current.querySelectorAll<HTMLElement>('button:not([disabled]), [tabindex="0"]'));
      const index = nodes.indexOf(document.activeElement as HTMLElement);
      if (index < 0 || (event.shiftKey ? index === 0 : index === nodes.length - 1)) {
        event.preventDefault();
        (event.shiftKey ? nodes.at(-1) ?? host.current : nodes[0] ?? host.current).focus();
      }
    }
    function focusin(event: FocusEvent) {
      if (event.target instanceof Node && host.current && !host.current.contains(event.target)) focusSafe();
    }
    document.addEventListener("keydown", keydown);
    document.addEventListener("focusin", focusin);
    return () => {
      document.removeEventListener("keydown", keydown);
      document.removeEventListener("focusin", focusin);
      const target = previous?.isConnected && !(previous instanceof HTMLButtonElement && previous.disabled) ? previous : fallbackFocus;
      if (target?.isConnected) target.focus({ preventScroll: true });
    };
  }, [dialog.id, returnFocus, fallbackFocus]);
  const { plan, receipt, phase, error } = dialog;
  const executing = phase === "executing";
  const complete = phase === "done" || phase === "failed";
  const title = receipt === null ? plan?.title ?? "准备配置变更"
    : receipt.state === "verified" ? plan?.candidateHandle === null ? "已恢复先前配置" : "修补已通过配置与进程验证"
    : receipt.state === "restored" ? "验证未通过，已还原配置" : "结果尚未核实";
  return (
    <div className="nginx-repair-backdrop">
      <section ref={host} className="nginx-repair-dialog" role="dialog" aria-modal="true"
        aria-labelledby="nginx-repair-dialog-title" aria-describedby="nginx-repair-dialog-note" tabIndex={-1}>
        <h2 id="nginx-repair-dialog-title">{title}</h2>
        <p id="nginx-repair-dialog-note" className="nginx-repair-note">
          {executing ? "正在保留备份、写入并验证；失败时按计划恢复。请等待结果后再切换目标。"
            : complete ? "请继续检查实际业务请求；配置与进程验证不能替代业务健康检查。"
            : "核对文件、差异和影响后确认。本次确认只用于下方计划。"}
        </p>
        {phase === "preparing" ? <p role="status">正在读取配置并准备差异…可以取消等待。</p> : null}
        {plan ? <>
          <p className="nginx-repair-target"><strong>操作目标</strong> {plan.targetLabel}</p>
          <p className="nginx-repair-location">{plan.path}{plan.line === null ? "" : ` · 第 ${plan.line} 行`}</p>
          <pre className="nginx-repair-diff" aria-label="配置差异" tabIndex={0}>{plan.diff}</pre>
          <dl className="nginx-repair-plan-details">
            <div><dt>操作影响</dt><dd>{plan.impact}</dd></div>
            <div><dt>备份与恢复</dt><dd>{plan.restoreDescription}</dd></div>
          </dl>
          {phase === "ready" ? <p className="nginx-repair-note">计划最长保留 {Math.ceil(plan.expiresInSeconds / 60)} 分钟；执行前会再次核对实例和配置。</p> : null}
        </> : null}
        {receipt ? <p className={receipt.state === "verified" ? "nginx-repair-result" : "nginx-repair-warning"} role="status">{receipt.detail}</p> : null}
        {error ? <p className="nginx-repair-error" role="alert">{error}</p> : null}
        <footer>
          <button ref={safe} type="button" disabled={executing} onClick={onClose}>{complete ? "关闭并查看历史" : "取消"}</button>
          {!complete ? <button type="button" className="nginx-repair-confirm" disabled={phase !== "ready"} onClick={onConfirm}>
            {executing ? "执行与验证中…" : phase === "confirming" ? "正在确认…" : "确认并执行"}
          </button> : null}
        </footer>
      </section>
    </div>
  );
}
