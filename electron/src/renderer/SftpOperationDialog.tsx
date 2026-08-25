import { useEffect, useRef, useState } from "react";

import type {
  SftpArchiveFormat,
  SftpOperationKind,
  SftpOperationPlan,
  SftpOperationReceipt,
} from "../shared/sftp-browser-contract";
import { useModalScrim } from "./modal-scrim";

/** What the operator still has to supply before a plan can be built. */
export interface SftpOperationDraft {
  kind: SftpOperationKind;
  /** Shown so the operator can see what the operation is about to touch. */
  subject: string;
  name?: string;
  mode?: string;
  format?: SftpArchiveFormat;
}

export interface SftpOperationDialogProps {
  draft: SftpOperationDraft;
  plan: SftpOperationPlan | null;
  receipt: SftpOperationReceipt | null;
  busy: boolean;
  error: string | null;
  onPlan: (draft: SftpOperationDraft) => void;
  onConfirm: () => void;
  onClose: () => void;
}

const KIND_LABELS: Record<SftpOperationKind, string> = {
  "create-directory": "新建文件夹",
  rename: "重命名",
  chmod: "设置权限",
  remove: "删除",
  archive: "打包",
  upload: "上传",
};

/**
 * Plan, then confirm, then run. The operator reads what the core intends to do
 * before anything is touched, and sees what the core verified afterwards.
 */
export function SftpOperationDialog({
  draft,
  plan,
  receipt,
  busy,
  error,
  onPlan,
  onConfirm,
  onClose,
}: SftpOperationDialogProps) {
  useModalScrim();
  const [name, setName] = useState(draft.name ?? "");
  const [mode, setMode] = useState(draft.mode ?? "");
  const [format, setFormat] = useState<SftpArchiveFormat>(draft.format ?? "tar-gzip");
  const firstFieldRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    firstFieldRef.current?.focus();
  }, []);

  const needsName = draft.kind === "create-directory" || draft.kind === "rename" ||
    draft.kind === "archive" || draft.kind === "upload";
  const needsMode = draft.kind === "chmod";
  const needsFormat = draft.kind === "archive";
  const ready = (!needsName || name.trim().length > 0) &&
    (!needsMode || /^[0-7]{3,4}$/u.test(mode.trim()));

  return (
    <div className="sftp-operation-backdrop" role="presentation">
      <section
        className="sftp-operation-dialog"
        role="dialog"
        aria-modal="true"
        aria-label={KIND_LABELS[draft.kind]}
        data-testid="sftp-operation-dialog"
      >
        <header>
          <h2>{KIND_LABELS[draft.kind]}</h2>
          <p>{draft.subject}</p>
        </header>

        {receipt === null ? (
          <>
            {plan === null ? (
              <div className="sftp-operation-fields">
                {needsName ? (
                  <label>
                    名称
                    <input
                      ref={firstFieldRef}
                      value={name}
                      maxLength={255}
                      onChange={(event) => setName(event.currentTarget.value)}
                    />
                  </label>
                ) : null}
                {needsMode ? (
                  <label>
                    权限（八进制，如 644）
                    <input
                      ref={firstFieldRef}
                      value={mode}
                      maxLength={4}
                      inputMode="numeric"
                      placeholder="644"
                      onChange={(event) => setMode(event.currentTarget.value)}
                    />
                  </label>
                ) : null}
                {needsFormat ? (
                  <label>
                    格式
                    <select
                      value={format}
                      onChange={(event) => setFormat(event.currentTarget.value as SftpArchiveFormat)}
                    >
                      <option value="tar-gzip">tar.gz</option>
                      <option value="tar-zstd">tar.zst</option>
                      <option value="tar">tar</option>
                    </select>
                  </label>
                ) : null}
                {!needsName && !needsMode && !needsFormat ? (
                  <p className="sftp-operation-note">继续会先生成一份计划，执行前你还能再看一次。</p>
                ) : null}
              </div>
            ) : (
              <div className={plan.dangerous ? "sftp-operation-plan is-dangerous" : "sftp-operation-plan"}>
                <p className="sftp-operation-summary">{plan.summary}</p>
                <dl>
                  <div>
                    <dt>风险</dt>
                    <dd>{plan.dangerous ? "高风险，需要确认" : "常规操作"}</dd>
                  </div>
                  <div>
                    <dt>可回滚</dt>
                    <dd>{plan.restoreDescription ?? "无备份，执行后不可自动还原"}</dd>
                  </div>
                  <div>
                    <dt>计划有效期</dt>
                    <dd>{plan.expiresInSeconds} 秒</dd>
                  </div>
                </dl>
              </div>
            )}
            {error === null ? null : <p className="sftp-operation-error" role="alert">{error}</p>}
            <footer>
              <button type="button" onClick={onClose} disabled={busy}>取消</button>
              {plan === null ? (
                <button
                  type="button"
                  className="is-primary"
                  disabled={busy || !ready}
                  onClick={() => onPlan({ ...draft, name: name.trim(), mode: mode.trim(), format })}
                >
                  {busy ? "生成计划中…" : "生成计划"}
                </button>
              ) : (
                <button
                  type="button"
                  className={plan.dangerous ? "is-dangerous" : "is-primary"}
                  disabled={busy}
                  data-testid="sftp-operation-execute"
                  onClick={onConfirm}
                >
                  {busy ? "执行中…" : plan.dangerous ? "确认并执行" : "执行"}
                </button>
              )}
            </footer>
          </>
        ) : (
          <>
            <div className={receipt.passed ? "sftp-operation-receipt is-passed" : "sftp-operation-receipt"}>
              <strong>{receipt.passed ? "已完成并通过校验" : "未通过校验"}</strong>
              <p>{receipt.detail}</p>
              {receipt.restored ? <p className="sftp-operation-restored">已回滚到操作前的状态。</p> : null}
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
