import { useEffect, useRef, useState } from "react";

import type {
  EmergencyPathAction,
  EmergencyPathDetail,
  EmergencyPathPlan,
  EmergencyPathReceipt,
  EmergencyPathUndoResult,
} from "../shared/emergency-command-contract";
import { useModalScrim } from "./modal-scrim";
import { planExpiryLabel } from "./plan-expiry";
import "./emergency-path.css";

export interface EmergencyPathDialogProps {
  /** The file the operator right-clicked, as the target printed it. */
  path: string;
  action: EmergencyPathAction;
  detail: EmergencyPathDetail | null;
  plan: EmergencyPathPlan | null;
  receipt: EmergencyPathReceipt | null;
  undo?: EmergencyPathUndoResult | null;
  undoSpent?: boolean;
  busy: boolean;
  error: string | null;
  onConfirm: () => void;
  onUndo?: () => void;
  onClose: () => void;
}

const ACTION_LABELS: Record<EmergencyPathAction, string> = {
  disarm: "去掉执行权限",
  quarantine: "隔离",
};

const ACTION_INTENT: Record<EmergencyPathAction, string> = {
  disarm: "去掉所有人的执行位，连同 setuid、setgid 一起摘掉。文件本身保留，随时还能打开看。",
  quarantine: "把文件从原位置移进目标机上的备份目录。原路径不再有它，需要时可以取回。",
};

const UNDO_EFFECT: Record<EmergencyPathAction, string> = {
  disarm: "撤销会把权限改回操作前的样子，连同 setuid、setgid。这个文件会重新可以执行。",
  quarantine: "撤销会把文件从备份目录移回原路径。原路径会重新出现这个文件，可以再被运行或加载。",
};

/**
 * Plan, then confirm, then run — the same order the file browser uses. The
 * operator reads what will happen before anything is touched, and sees what
 * the target reported afterwards.
 */
export function EmergencyPathDialog({
  path,
  action,
  detail,
  plan,
  receipt,
  undo = null,
  undoSpent = false,
  busy,
  error,
  onConfirm,
  onUndo = () => undefined,
  onClose,
}: EmergencyPathDialogProps) {
  useModalScrim();
  const [askingUndo, setAskingUndo] = useState(false);
  return (
    <div className="emergency-path-backdrop" role="presentation">
      <section
        className="emergency-path-dialog"
        role="dialog"
        aria-modal="true"
        aria-label={ACTION_LABELS[action]}
        data-testid="emergency-path-dialog"
      >
        <header>
          <h2>{ACTION_LABELS[action]}</h2>
          <p>{path}</p>
        </header>

        {receipt === null ? (
          <>
            {detail === null ? (
              <p className="emergency-path-note">正在读取目标机上这个文件的当前状态…</p>
            ) : (
              <div className="emergency-path-panel">
                <p className="emergency-path-summary">{ACTION_INTENT[action]}</p>
                <dl>
                  <div><dt>类型</dt><dd>{pathKindLabel(detail.kind)}</dd></div>
                  <div><dt>权限</dt><dd>{modeLabel(detail)}</dd></div>
                  <div><dt>大小</dt><dd>{byteLabel(detail.size)}</dd></div>
                  <div><dt>属主</dt><dd>{ownerLabel(detail)}</dd></div>
                  <div><dt>修改时间</dt><dd>{timeLabel(detail.modifiedAt)}</dd></div>
                </dl>
              </div>
            )}
            {plan === null ? null : (
              <div className={plan.dangerous ? "emergency-path-panel is-dangerous" : "emergency-path-panel"}>
                <dl>
                  {/* The wording below comes from the layer that will carry the
                      change out and verify it, so it is shown as that layer
                      stated it rather than rephrased here. */}
                  <div>
                    <dt>将要执行</dt>
                    <dd>{plan.summary}</dd>
                  </div>
                  <div>
                    <dt>风险</dt>
                    <dd>{plan.dangerous ? "高风险，需要确认" : "常规操作"}</dd>
                  </div>
                  <div>
                    <dt>出错后如何还原</dt>
                    <dd>{plan.restoreDescription ?? "无备份，执行后不可自动还原"}</dd>
                  </div>
                  <div>
                    <dt>计划有效期</dt>
                    <dd>{planExpiryLabel(plan.expiresInSeconds)}</dd>
                  </div>
                </dl>
              </div>
            )}
            {error === null ? null : <p className="emergency-path-error" role="alert">{error}</p>}
            <footer>
              <button type="button" onClick={onClose} disabled={busy}>取消</button>
              <button
                type="button"
                className="is-dangerous"
                disabled={busy || plan === null}
                data-testid="emergency-path-execute"
                onClick={onConfirm}
              >
                {busy ? "执行中…" : "确认并执行"}
              </button>
            </footer>
          </>
        ) : (
          <EmergencyPathOutcome
            action={action}
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
 * What the target reported, and — for a verified action that can be put back —
 * one chance to undo it. The undo asks first and starts on the safe choice.
 */
export function EmergencyPathOutcome({
  action,
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
  action: EmergencyPathAction;
  receipt: EmergencyPathReceipt;
  undo: EmergencyPathUndoResult | null;
  undoSpent: boolean;
  askingUndo: boolean;
  busy: boolean;
  error: string | null;
  onAskUndo: () => void;
  onKeep: () => void;
  onUndo: () => void;
  onClose: () => void;
}) {
  const offerUndo = receipt.passed && receipt.undoable && !undoSpent;
  const keepRef = useRef<HTMLButtonElement>(null);
  const askRef = useRef<HTMLButtonElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  const returnFocus = useRef(false);
  // The safe choice holds focus while the question is open, so Enter does not
  // undo by accident. Once it is answered — and any undo has come back —
  // focus returns to the footer instead of falling to the page behind.
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
      <div className={receipt.passed || receipt.untouched ? "emergency-path-panel" : "emergency-path-panel is-dangerous"}>
        <p className="emergency-path-summary">
          {receipt.passed ? "已完成，并在目标机上核对过。" : receipt.untouched ? "没有执行，文件保持原样。" : "没有完成。"}
        </p>
        <dl>
          <div><dt>目标机反馈</dt><dd>{receipt.detail}</dd></div>
          {receipt.passed || receipt.untouched ? null : (
            <div>
              <dt>是否已还原</dt>
              <dd>{receipt.restored ? "已还原到操作前的状态" : "未能自动还原，请手动检查"}</dd>
            </div>
          )}
        </dl>
        {offerUndo && !askingUndo ? (
          <p className="emergency-path-note">完成后 10 分钟内可以撤销一次。</p>
        ) : null}
      </div>
      {offerUndo && askingUndo ? (
        <div className="emergency-path-panel is-dangerous" data-testid="emergency-path-undo-ask">
          <p className="emergency-path-summary">{UNDO_EFFECT[action]}</p>
          <p className="emergency-path-note">
            撤销前会先核对这个文件；如果那次操作之后它又被改过，就不会动它。只能撤销一次。
          </p>
        </div>
      ) : null}
      {undo === null ? null : (
        <div className={undo.undone ? "emergency-path-panel" : "emergency-path-panel is-dangerous"}
          data-testid="emergency-path-undo-result">
          <p className="emergency-path-summary">
            {undo.undone ? "已撤销。" : "没有撤销。"}
          </p>
          <dl><div><dt>目标机反馈</dt><dd>{undo.detail}</dd></div></dl>
        </div>
      )}
      {error === null ? null : <p className="emergency-path-error" role="alert">{error}</p>}
      <footer>
        {offerUndo && askingUndo ? (
          <>
            <button key="keep" ref={keepRef} type="button" onClick={onKeep} disabled={busy}
              data-testid="emergency-path-undo-keep">
              不撤销
            </button>
            <button key="confirm-undo" type="button" className="is-dangerous" disabled={busy}
              data-testid="emergency-path-undo-confirm" onClick={onUndo}>
              确认撤销
            </button>
          </>
        ) : (
          <>
            {offerUndo ? (
              <button key="ask-undo" ref={askRef} type="button" disabled={busy}
                data-testid="emergency-path-undo" onClick={onAskUndo}>
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

/** The read-only view, shown when the operator only asked what the file is. */
export function EmergencyPathProperties({
  path,
  detail,
  error,
  onClose,
}: {
  path: string;
  detail: EmergencyPathDetail | null;
  error: string | null;
  onClose: () => void;
}) {
  useModalScrim();
  return (
    <div className="emergency-path-backdrop" role="presentation">
      <section
        className="emergency-path-dialog"
        role="dialog"
        aria-modal="true"
        aria-label="属性"
        data-testid="emergency-path-properties"
      >
        <header>
          <h2>属性</h2>
          <p>{path}</p>
        </header>
        {error !== null ? (
          <p className="emergency-path-error" role="alert">{error}</p>
        ) : detail === null ? (
          <p className="emergency-path-note">正在读取…</p>
        ) : (
          <div className="emergency-path-panel">
            <dl>
              <div><dt>类型</dt><dd>{pathKindLabel(detail.kind)}</dd></div>
              <div><dt>权限</dt><dd>{modeLabel(detail)}</dd></div>
                  <div><dt>执行权限</dt><dd>{executionLabel(detail)}</dd></div>
              <div><dt>大小</dt><dd>{byteLabel(detail.size)}</dd></div>
              <div><dt>属主</dt><dd>{ownerLabel(detail)}</dd></div>
              <div><dt>修改时间</dt><dd>{timeLabel(detail.modifiedAt)}</dd></div>
            </dl>
          </div>
        )}
        <footer>
          <button type="button" className="is-primary" onClick={onClose}>关闭</button>
        </footer>
      </section>
    </div>
  );
}

export function pathKindLabel(kind: EmergencyPathDetail["kind"]): string {
  if (kind === "file") return "文件";
  if (kind === "directory") return "目录";
  if (kind === "symlink") return "符号链接";
  return "其他";
}

function executionLabel(detail: EmergencyPathDetail): string {
  if (detail.mode === null) return "目标机未报告权限，无法判断。";
  if (detail.kind === "directory") return "目录的执行权限用于进入和访问目录。";
  return detail.executable
    ? "设有执行位；能否运行还取决于账号权限、挂载选项和文件类型。"
    : "未设置执行位；脚本仍可能被解释器读取运行。";
}

/** `4755` reads as `rwsr-xr-x`, the way a listing on the target shows it. */
export function symbolicMode(mode: string): string {
  const digits = mode.split("").map((digit) => Number.parseInt(digit, 8));
  if (digits.length !== 4 || digits.some(Number.isNaN)) return mode;
  const [special, ...triples] = digits as [number, number, number, number];
  const specials = [special & 0b100, special & 0b010, special & 0b001];
  const markers = ["s", "s", "t"];
  return triples
    .map((value, index) => {
      const read = (value & 0b100) === 0 ? "-" : "r";
      const write = (value & 0b010) === 0 ? "-" : "w";
      const execute = (value & 0b001) !== 0;
      const marked = specials[index] !== 0;
      const last = marked
        ? execute ? markers[index] as string : (markers[index] as string).toUpperCase()
        : execute ? "x" : "-";
      return `${read}${write}${last}`;
    })
    .join("");
}

function modeLabel(detail: EmergencyPathDetail): string {
  if (detail.mode === null) return "目标机没有报告权限";
  return `${detail.mode}（${symbolicMode(detail.mode)}）`;
}

function ownerLabel(detail: EmergencyPathDetail): string {
  if (detail.ownerId === null && detail.groupId === null) return "目标机没有报告属主";
  return `用户 ${detail.ownerId ?? "未知"} / 组 ${detail.groupId ?? "未知"}`;
}

function byteLabel(size: string): string {
  const bytes = Number(size);
  if (!Number.isFinite(bytes)) return `${size} 字节`;
  if (bytes < 1024) return `${bytes} 字节`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(1)} ${units[unit]}（${size} 字节）`;
}

function timeLabel(modifiedAt: string | null): string {
  if (modifiedAt === null) return "目标机没有报告时间";
  const at = new Date(modifiedAt);
  return Number.isNaN(at.getTime()) ? modifiedAt : at.toLocaleString();
}
