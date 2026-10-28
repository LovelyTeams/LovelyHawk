import { useEffect, useRef, useState } from "react";

import type {
  SftpArchiveFormat,
  SftpOperationKind,
  SftpOperationPlan,
  SftpOperationReceipt,
  SftpOperationUndoResult,
} from "../shared/sftp-browser-contract";
import { useModalScrim } from "./modal-scrim";
import { planExpiryLabel } from "./plan-expiry";

/** What the operator still has to supply before a plan can be built. */
export interface SftpOperationDraft {
  kind: SftpOperationKind;
  /** Shown so the operator can see what the operation is about to touch. */
  subject: string;
  name?: string;
  mode?: string;
  format?: SftpArchiveFormat;
  /** Set when the file came from the local pane; absent means main will ask. */
  localFileHandle?: string;
}

export interface SftpOperationDialogProps {
  draft: SftpOperationDraft;
  plan: SftpOperationPlan | null;
  receipt: SftpOperationReceipt | null;
  /** What the one undo attempt reported, once it has been made. */
  undo?: SftpOperationUndoResult | null;
  /** The undo was attempted, so it is not offered again whatever came back. */
  undoSpent?: boolean;
  busy: boolean;
  error: string | null;
  onPlan: (draft: SftpOperationDraft) => void;
  onConfirm: () => void;
  onUndo?: () => void;
  /** Offered while an upload is copying: stops it, and it removes what it wrote. */
  onCancelTransfer?: (() => void) | undefined;
  cancellingTransfer?: boolean;
  onClose: () => void;
}

/** What an undo puts back, for the kinds the core offers one for. */
const UNDO_EFFECT: Partial<Record<SftpOperationKind, string>> = {
  "create-directory": "撤销会删除这个新建的文件夹。文件夹里已经放了东西时不会删除。",
  rename: "撤销会把名字改回原来的。",
  chmod: "撤销会把权限改回操作前的样子。",
  remove: "撤销会把它从备份移回原来的位置，连同原来的权限。",
};

const KIND_LABELS: Record<SftpOperationKind, string> = {
  "create-directory": "新建文件夹",
  rename: "重命名",
  chmod: "设置权限",
  remove: "删除",
  archive: "打包",
  upload: "上传",
  "write-text": "保存修改",
};

/**
 * Plan, then confirm, then run. The operator reads what the core intends to do
 * before anything is touched, and sees what the core verified afterwards.
 */
export function SftpOperationDialog({
  draft,
  plan,
  receipt,
  undo = null,
  undoSpent = false,
  busy,
  error,
  onPlan,
  onConfirm,
  onUndo = () => undefined,
  onCancelTransfer,
  cancellingTransfer = false,
  onClose,
}: SftpOperationDialogProps) {
  useModalScrim();
  const [askingUndo, setAskingUndo] = useState(false);
  const [name, setName] = useState(draft.name ?? "");
  const [mode, setMode] = useState(draft.mode ?? "");
  const [format, setFormat] = useState<SftpArchiveFormat>(draft.format ?? "tar-gzip");
  const firstFieldRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    firstFieldRef.current?.focus();
  }, []);

  const isUpload = draft.kind === "upload";
  const needsName = draft.kind === "create-directory" || draft.kind === "rename" ||
    draft.kind === "archive" || isUpload;
  const needsMode = draft.kind === "chmod";
  const needsFormat = draft.kind === "archive";
  // An upload falls back to the local file's own name, which is not known
  // until the file is picked.
  const ready = (!needsName || isUpload || name.trim().length > 0) &&
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
                    {isUpload ? "保存到服务器上的名称（留空则沿用本机文件名）" : "名称"}
                    <input
                      ref={firstFieldRef}
                      value={name}
                      maxLength={255}
                      onChange={(event) => setName(event.currentTarget.value)}
                    />
                  </label>
                ) : null}
                {isUpload && draft.localFileHandle === undefined ? (
                  <p className="sftp-operation-note">生成计划时会先请你选择本机文件，执行前你还能再看一次。</p>
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
                    <dd>{planExpiryLabel(plan.expiresInSeconds)}</dd>
                  </div>
                </dl>
              </div>
            )}
            {error === null ? null : <p className="sftp-operation-error" role="alert">{error}</p>}
            <footer>
              {busy && plan !== null && onCancelTransfer !== undefined ? (
                <button type="button" data-testid="sftp-cancel-upload" disabled={cancellingTransfer}
                  onClick={onCancelTransfer}>
                  {cancellingTransfer ? "正在取消…" : "取消上传"}
                </button>
              ) : (
                <button type="button" onClick={onClose} disabled={busy}>取消</button>
              )}
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
          <SftpOperationOutcome
            receipt={receipt}
            undo={undo}
            undoSpent={undoSpent}
            askingUndo={askingUndo}
            busy={busy}
            error={error}
            onAskUndo={() => setAskingUndo(true)}
            onKeep={() => setAskingUndo(false)}
            onUndo={() => {
              setAskingUndo(false);
              onUndo();
            }}
            onClose={onClose} />
        )}
      </section>
    </div>
  );
}

/**
 * What the core verified, and — for verified work of a kind that can be put
 * back — one chance to undo it. The undo asks first and starts on the safe
 * choice; focus comes back to the footer when the question is answered.
 */
export function SftpOperationOutcome({
  receipt,
  undo,
  undoSpent,
  askingUndo,
  busy,
  error,
  onAskUndo,
  onKeep,
  onUndo,
  onClose,
}: {
  receipt: SftpOperationReceipt;
  undo: SftpOperationUndoResult | null;
  undoSpent: boolean;
  askingUndo: boolean;
  busy: boolean;
  error: string | null;
  onAskUndo: () => void;
  onKeep: () => void;
  onUndo: () => void;
  onClose: () => void;
}) {
  const effect = UNDO_EFFECT[receipt.kind];
  const offerUndo = receipt.passed && receipt.undoable && !undoSpent && effect !== undefined;
  const keepRef = useRef<HTMLButtonElement>(null);
  const askRef = useRef<HTMLButtonElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  const returnFocus = useRef(false);
  useEffect(() => {
    if (offerUndo && askingUndo) {
      returnFocus.current = true;
      keepRef.current?.focus();
      return;
    }
    if (!returnFocus.current || busy) return;
    returnFocus.current = false;
    (askRef.current ?? closeRef.current)?.focus();
  }, [offerUndo, askingUndo, busy]);
  return (
    <>
      <div className={receipt.passed ? "sftp-operation-receipt is-passed"
        : receipt.cancelled ? "sftp-operation-receipt is-cancelled" : "sftp-operation-receipt"}>
        <strong>{receipt.passed ? "已完成并通过校验" : receipt.cancelled ? "已取消上传" : "未通过校验"}</strong>
        <p>{receipt.detail}</p>
        {receipt.restored ? <p className="sftp-operation-restored">已回滚到操作前的状态。</p> : null}
        {offerUndo && !askingUndo ? <p className="sftp-operation-note">完成后 10 分钟内可以撤销一次。</p> : null}
      </div>
      {offerUndo && askingUndo ? (
        <div className="sftp-operation-plan is-dangerous" data-testid="sftp-operation-undo-ask">
          <p className="sftp-operation-summary">{effect}</p>
          <p className="sftp-operation-note">
            撤销前会先核对；如果那次操作之后又被改过，就不会动它。只能撤销一次。
          </p>
        </div>
      ) : null}
      {undo === null ? null : (
        <div className={undo.undone ? "sftp-operation-receipt is-passed" : "sftp-operation-receipt"}
          data-testid="sftp-operation-undo-result">
          <strong>{undo.undone ? "已撤销" : "没有撤销"}</strong>
          <p>{undo.detail}</p>
        </div>
      )}
      {error === null ? null : <p className="sftp-operation-error" role="alert">{error}</p>}
      <footer>
        {offerUndo && askingUndo ? (
          <>
            <button key="keep" ref={keepRef} type="button" onClick={onKeep} disabled={busy}
              data-testid="sftp-operation-undo-keep">
              不撤销
            </button>
            <button key="confirm-undo" type="button" className="is-dangerous" disabled={busy}
              data-testid="sftp-operation-undo-confirm" onClick={onUndo}>
              确认撤销
            </button>
          </>
        ) : (
          <>
            {offerUndo ? (
              <button key="ask-undo" ref={askRef} type="button" disabled={busy}
                data-testid="sftp-operation-undo" onClick={onAskUndo}>
                撤销这次操作
              </button>
            ) : null}
            <button key="close" ref={closeRef} type="button" className="is-primary" onClick={onClose} disabled={busy}>
              {busy ? "撤销中…" : "关闭"}
            </button>
          </>
        )}
      </footer>
    </>
  );
}
