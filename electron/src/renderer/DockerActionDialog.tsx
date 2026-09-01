import type { DockerActionPlan, DockerActionReceipt } from "../shared/docker-write-contract";
import { useModalScrim } from "./modal-scrim";

export interface DockerActionDialogProps {
  /** The container's name as the pane is showing it. */
  containerName: string;
  actionLabel: string;
  plan: DockerActionPlan | null;
  receipt: DockerActionReceipt | null;
  busy: boolean;
  error: string | null;
  onConfirm: () => void;
  onClose: () => void;
}

/**
 * Plan, then confirm, then run — the same order the file actions use.
 *
 * The operator reads what will happen, what the container is doing right now,
 * and what putting it back would mean, before anything is touched. Afterwards
 * they see what the target itself reported when it was read back, not whether
 * a command exited zero.
 */
export function DockerActionDialog({
  containerName,
  actionLabel,
  plan,
  receipt,
  busy,
  error,
  onConfirm,
  onClose,
}: DockerActionDialogProps) {
  useModalScrim();
  return (
    <div className="docker-action-backdrop" role="presentation">
      <section
        className="docker-action-dialog"
        role="dialog"
        aria-modal="true"
        aria-label={`${actionLabel}容器`}
        data-testid="docker-action-dialog"
      >
        <header>
          <h2>{actionLabel}容器</h2>
          <p>{containerName}</p>
        </header>

        {receipt === null ? (
          <>
            {plan === null ? (
              <p className="docker-action-note">正在读取这个容器现在的状态…</p>
            ) : (
              <div className={plan.dangerous ? "docker-action-panel is-dangerous" : "docker-action-panel"}>
                <dl>
                  {/* The wording comes from the layer that will carry the
                      change out and verify it, so it is shown as that layer
                      stated it rather than rephrased here. */}
                  <div>
                    <dt>将要执行</dt>
                    <dd>{plan.summary}</dd>
                  </div>
                  <div>
                    <dt>操作前状态</dt>
                    <dd>{plan.beforeState}</dd>
                  </div>
                  <div>
                    <dt>风险</dt>
                    <dd>{plan.dangerous ? "高风险，需要确认" : "常规操作"}</dd>
                  </div>
                  <div>
                    <dt>出错后如何还原</dt>
                    <dd>{plan.restoreDescription ?? "这个动作没有自动还原的办法"}</dd>
                  </div>
                  <div>
                    <dt>计划有效期</dt>
                    <dd>{plan.expiresInSeconds} 秒</dd>
                  </div>
                </dl>
              </div>
            )}
            {error === null ? null : <p className="docker-action-error" role="alert">{error}</p>}
            <footer>
              <button type="button" onClick={onClose} disabled={busy}>取消</button>
              <button
                type="button"
                className="is-dangerous"
                disabled={busy || plan === null}
                data-testid="docker-action-execute"
                onClick={onConfirm}
              >
                {busy ? "执行中…" : "确认并执行"}
              </button>
            </footer>
          </>
        ) : (
          <>
            <div className={receipt.verified ? "docker-action-panel" : "docker-action-panel is-dangerous"}>
              <p className="docker-action-summary">
                {receipt.verified ? "已完成，并在目标机上核对过。" : "没有达到预期状态。"}
              </p>
              <dl>
                <div><dt>目标机反馈</dt><dd>{receipt.detail}</dd></div>
                {receipt.verified ? null : (
                  <div>
                    <dt>是否已还原</dt>
                    <dd>{receipt.restored ? "已还原到操作前的状态" : "没有自动还原，请手动检查"}</dd>
                  </div>
                )}
              </dl>
            </div>
            <footer>
              <button type="button" className="is-primary" onClick={onClose}>关闭</button>
            </footer>
          </>
        )}
      </section>
    </div>
  );
}
