import { useCallback, useEffect, useRef, useState } from "react";

import {
  matchesResponseEngineResponse,
  type ResponseEngineApi,
  type ResponseEnginePlan,
  type ResponseEngineRequest,
  type ResponseEngineScan,
  type ResponseFixMode,
  type ResponseIssue,
  type ResponseIssueKind,
  type ResponseSeverity,
} from "../shared/response-engine-contract";
import { DialogHost } from "./DialogHost";
import { errorText } from "./error-text";
import { useModalScrim } from "./modal-scrim";
import { planExpiryLabel } from "./plan-expiry";
import { useConfirmDialog } from "./use-confirm-dialog";
import "./response-engine.css";

/** 一行问题项的修复进度；进行中的两行状态都由 poll-fix 驱动。 */
export type ResponseFixRowState =
  | { stage: "executing"; operationHandle: string }
  | { stage: "verify-pending"; operationHandle: string }
  | { stage: "completed"; verifyPassed: boolean; summary: string }
  | { stage: "failed"; summary: string };

export interface ResponseEnginePageProps {
  api: ResponseEngineApi;
  bindingHandle: string | null;
  /** Deterministic standalone/SSR fixture; production leaves these unset. */
  initialScan?: ResponseEngineScan | null;
  initialFixes?: Record<string, ResponseFixRowState>;
}

interface FixDialogState {
  issue: ResponseIssue;
  mode: ResponseFixMode;
  plan: ResponseEnginePlan | null;
  busy: boolean;
  error: string | null;
}

/** 后端复验要等到跨过一个 cron 保活周期，轮询间隔取短于它又不打扰目标的值。 */
const POLL_MS = 2_500;

/** 扫描进行中的阶段轮询间隔。 */
const SCAN_POLL_MS = 1_500;

const KIND_META: Record<ResponseIssueKind, { label: string; icon: string }> = {
  "hijacked-command": { label: "命令劫持", icon: "⌁" },
  "uid-zero-account": { label: "UID 为 0 的影子账户", icon: "◉" },
  "empty-password": { label: "空口令账户", icon: "○" },
  "suspicious-account": { label: "可疑登录账户", icon: "◈" },
  "malicious-sudoers": { label: "恶意 sudoers 授权", icon: "⚠" },
  "cron-persistence": { label: "cron 持久化", icon: "↻" },
  "backdoor-process": { label: "后门进程", icon: "✚" },
  "ld-preload-hijack": { label: "动态链接库劫持", icon: "⧉" },
  "path-injection": { label: "PATH 注入", icon: "⇶" },
  "ssh-key-backdoor": { label: "SSH 密钥后门", icon: "⚿" },
  "pam-backdoor": { label: "PAM 认证后门", icon: "⊘" },
  "bind-listener": { label: "可疑监听", icon: "◎" },
  "stash-dir": { label: "后门藏匿目录", icon: "▣" },
  "web-sensitive-file": { label: "Web 敏感文件泄露", icon: "▤" },
  webshell: { label: "WebShell", icon: "✖" },
  "command-recorder": { label: "命令录音钩子", icon: "♪" },
  "history-credential-leak": { label: "历史命令明文密码", icon: "✎" },
  "session-env-hook": { label: "会话驻留钩子", icon: "◈" },
  "preload-residue": { label: "恶意库驻留进程", icon: "⧗" },
};

/** 扫描项选择面板的顺序：按「先修眼睛」的处置顺序排列。 */
const SCAN_KIND_ORDER: ResponseIssueKind[] = [
  "ld-preload-hijack",
  "path-injection",
  "hijacked-command",
  "ssh-key-backdoor",
  "pam-backdoor",
  "webshell",
  "bind-listener",
  "backdoor-process",
  "uid-zero-account",
  "empty-password",
  "suspicious-account",
  "malicious-sudoers",
  "cron-persistence",
  "stash-dir",
  "web-sensitive-file",
  "command-recorder",
  "session-env-hook",
  "preload-residue",
  "history-credential-leak",
];

const SEVERITY_LABEL: Record<ResponseSeverity, string> = {
  critical: "严重",
  high: "高危",
  medium: "中危",
  low: "低危",
};

function isActive(row: ResponseFixRowState): boolean {
  return row.stage === "executing" || row.stage === "verify-pending";
}

export function ResponseEnginePage({
  api,
  bindingHandle,
  initialScan = null,
  initialFixes = {},
}: ResponseEnginePageProps) {
  const [scanState, setScanState] = useState<{ scope: string | null; scan: ResponseEngineScan | null }>(
    () => ({ scope: bindingHandle, scan: initialScan }),
  );
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [scanStage, setScanStage] = useState<{ label: string; percent: number } | null>(null);
  const [scanHandle, setScanHandle] = useState<string | null>(null);
  const [kindsOpen, setKindsOpen] = useState(false);
  const [selectedKinds, setSelectedKinds] = useState<Set<ResponseIssueKind>>(
    () => new Set(SCAN_KIND_ORDER),
  );
  const [fixState, setFixState] = useState<{
    scope: string | null;
    rows: Record<string, ResponseFixRowState>;
  }>(() => ({ scope: bindingHandle, rows: initialFixes }));
  const [dialog, setDialog] = useState<FixDialogState | null>(null);
  const [pollTick, setPollTick] = useState(0);
  const mountedRef = useRef(true);
  const bindingRef = useRef(bindingHandle);
  bindingRef.current = bindingHandle;
  const dialogRef = useRef(dialog);
  dialogRef.current = dialog;
  const scanHandleRef = useRef<string | null>(null);
  scanHandleRef.current = scanHandle;
  const rescanConfirm = useConfirmDialog();

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  // 切换目标后，旧目标的修复计划不再有效；已开始的修复由后端随连接回收。
  useEffect(() => {
    return () => {
      const open = dialogRef.current;
      if (open?.plan !== null && open !== null && bindingRef.current !== null) {
        void api.responseEngine({
          action: "cancel-fix", bindingHandle: bindingRef.current, planHandle: open.plan.planHandle,
        }).catch(() => {});
      }
      setDialog(null);
    };
  }, [api, bindingHandle]);

  const scan = scanState.scope === bindingHandle ? scanState.scan : null;
  const fixes = fixState.scope === bindingHandle ? fixState.rows : {};
  const anyActive = Object.values(fixes).some(isActive);

  const call = useCallback(async (request: ResponseEngineRequest) => {
    const response = await api.responseEngine(request);
    if (!matchesResponseEngineResponse(request, response)) {
      throw new Error("应急处置返回了无法核实的结果。");
    }
    return response;
  }, [api]);

  const runScan = useCallback(async () => {
    const binding = bindingRef.current;
    if (binding === null || scanning) return;
    if (anyActive) {
      const confirmed = await rescanConfirm.ask(
        "重新扫描？",
        "当前还有修复正在执行或等待复验。重新扫描后，本次扫描结果和这些修复的行内进度将不再显示；后端已经开始的修复不会被取消。",
        "仍然重新扫描",
      );
      if (!confirmed || !mountedRef.current || bindingRef.current !== binding) return;
    }
    setScanning(true);
    setScanError(null);
    setScanStage({ label: "正在启动扫描…", percent: 5 });
    try {
      const allSelected = selectedKinds.size === SCAN_KIND_ORDER.length;
      const request: ResponseEngineRequest = allSelected
        ? { action: "scan", bindingHandle: binding }
        : { action: "scan", bindingHandle: binding, kinds: [...selectedKinds] };
      const started = await call(request);
      if (!mountedRef.current || bindingRef.current !== binding) return;
      if (started.kind !== "scan-started") return;
      setScanHandle(started.scanHandle);
      setScanStage({ label: "正在检查目标权限…", percent: 15 });
    } catch (reason) {
      if (!mountedRef.current || bindingRef.current !== binding) return;
      setScanError(errorText(reason, "扫描没有开始；目标状态或权限可能不允许，请稍后重试。"));
      setScanning(false);
      setScanStage(null);
      setScanHandle(null);
    }
  }, [anyActive, call, rescanConfirm, scanning, selectedKinds]);

  // 扫描进度轮询：后端在目标上分阶段执行（权限→全量采集→补充指纹→账号核对），
  // 这里只显示真实到达的阶段，不编造连续动画。
  useEffect(() => {
    const binding = bindingHandle;
    const handle = scanHandle;
    if (binding === null || handle === null || !scanning) return;
    const timer = window.setTimeout(() => {
      void call({ action: "poll-scan", bindingHandle: binding, scanHandle: handle })
        .then((status) => {
          if (!mountedRef.current || bindingRef.current !== binding) return;
          if (status.kind !== "scan-status") return;
          if (status.stage === "running") {
            setScanStage({ label: status.stageLabel, percent: status.percent });
            setPollTick((tick) => tick + 1);
            return;
          }
          setScanning(false);
          setScanStage(null);
          setScanHandle(null);
          if (status.stage === "completed" && status.scan !== null) {
            // 新扫描会吊销旧的问题项句柄，行内进度也随之作废。
            setScanState({ scope: binding, scan: status.scan });
            setFixState({ scope: binding, rows: {} });
          } else if (status.stage === "failed") {
            setScanError(errorText(status.error, "扫描没有完成；目标状态或权限可能不允许，请稍后重试。"));
          }
        })
        .catch(() => {
          if (!mountedRef.current || bindingRef.current !== binding) return;
          setScanning(false);
          setScanStage(null);
          setScanHandle(null);
          setScanError("无法确认扫描结果：进度读取失败或连接已变化，请重试。");
        });
    }, SCAN_POLL_MS);
    return () => window.clearTimeout(timer);
  }, [api, bindingHandle, call, pollTick, scanHandle, scanning]);

  const toggleKind = useCallback((kind: ResponseIssueKind) => {
    setSelectedKinds((current) => {
      const next = new Set(current);
      if (next.has(kind)) {
        next.delete(kind);
      } else {
        next.add(kind);
      }
      return next.size === 0 ? current : next;
    });
  }, []);

  const beginFix = useCallback(async (issue: ResponseIssue, mode: ResponseFixMode) => {
    const binding = bindingRef.current;
    if (binding === null) return;
    setDialog({ issue, mode, plan: null, busy: true, error: null });
    try {
      const response = await call({ action: "plan-fix", bindingHandle: binding, issueHandle: issue.issueHandle, mode });
      if (response.kind !== "plan") return;
      if (!mountedRef.current || bindingRef.current !== binding) return;
      setDialog((current) =>
        current !== null && current.issue.issueHandle === issue.issueHandle && current.mode === mode
          ? { ...current, plan: response, busy: false }
          : current
      );
    } catch (reason) {
      if (!mountedRef.current || bindingRef.current !== binding) return;
      setDialog((current) =>
        current !== null && current.issue.issueHandle === issue.issueHandle
          ? { ...current, busy: false, error: errorText(reason, "无法生成修复方案，请重新扫描后再试。") }
          : current
      );
    }
  }, [call]);

  const changeMode = useCallback((mode: ResponseFixMode) => {
    const current = dialogRef.current;
    const binding = bindingRef.current;
    if (current === null || current.mode === mode || current.busy || binding === null) return;
    // 换一种修复方式就换一份方案；旧方案在后端作废，避免拿错计划。
    if (current.plan !== null) {
      void api.responseEngine({
        action: "cancel-fix", bindingHandle: binding, planHandle: current.plan.planHandle,
      }).catch(() => {});
    }
    void beginFix(current.issue, mode);
  }, [api, beginFix]);

  const confirmFix = useCallback(async () => {
    const current = dialogRef.current;
    const binding = bindingRef.current;
    if (current === null || current.plan === null || current.busy || binding === null) return;
    const { issue, plan } = current;
    setDialog({ ...current, busy: true, error: null });
    try {
      await call({ action: "confirm-fix", bindingHandle: binding, planHandle: plan.planHandle });
      const execution = await call({ action: "execute-fix", bindingHandle: binding, planHandle: plan.planHandle });
      if (!mountedRef.current || bindingRef.current !== binding || execution.kind !== "execution") return;
      setFixState((state) => ({
        scope: binding,
        rows: {
          ...(state.scope === binding ? state.rows : {}),
          [issue.issueHandle]: { stage: "executing", operationHandle: execution.operationHandle },
        },
      }));
      setDialog(null);
    } catch (reason) {
      if (!mountedRef.current || bindingRef.current !== binding) return;
      setDialog((now) =>
        now !== null && now.issue.issueHandle === issue.issueHandle
          ? { ...now, busy: false, error: errorText(reason, "修复未能开始；目标上可能已有修复在进行，或方案已过期。") }
          : now
      );
    }
  }, [call]);

  const closeDialog = useCallback(() => {
    const current = dialogRef.current;
    const binding = bindingRef.current;
    if (current === null || current.busy) return;
    if (current.plan !== null && binding !== null) {
      void api.responseEngine({
        action: "cancel-fix", bindingHandle: binding, planHandle: current.plan.planHandle,
      }).catch(() => {});
    }
    setDialog(null);
  }, [api]);

  // 行内轮询：每个进行中的修复每 2.5 秒问一次后端，直到完成或失败。
  useEffect(() => {
    const binding = bindingHandle;
    if (binding === null) return;
    const active = Object.entries(fixes).filter((entry): entry is [string, ResponseFixRowState & { operationHandle: string }] => isActive(entry[1]));
    if (active.length === 0) return;
    const timer = window.setTimeout(() => {
      void Promise.all(active.map(async ([issueHandle, row]) => {
        let next: ResponseFixRowState;
        try {
          const status = await call({ action: "poll-fix", bindingHandle: binding, operationHandle: row.operationHandle });
          if (status.kind !== "status") return;
          next = status.stage === "running"
            ? { stage: "executing", operationHandle: row.operationHandle }
            : status.stage === "verify-pending"
              ? { stage: "verify-pending", operationHandle: row.operationHandle }
              : status.stage === "completed"
                ? { stage: "completed", verifyPassed: status.verifyPassed === true, summary: status.summary }
                : { stage: "failed", summary: status.summary };
        } catch {
          next = { stage: "failed", summary: "无法确认修复结果：进度读取失败或连接已变化，请重新扫描核对目标状态。" };
        }
        if (!mountedRef.current || bindingRef.current !== binding) return;
        setFixState((state) => {
          if (state.scope !== binding) return state;
          const existing = state.rows[issueHandle];
          if (existing === undefined || !isActive(existing)) return state;
          return { scope: binding, rows: { ...state.rows, [issueHandle]: next } };
        });
      })).finally(() => {
        if (mountedRef.current && bindingRef.current === binding) setPollTick((tick) => tick + 1);
      });
    }, POLL_MS);
    return () => window.clearTimeout(timer);
  }, [api, bindingHandle, call, fixes, pollTick]);

  if (bindingHandle === null) {
    return (
      <main className="response-engine-page response-engine-connect-state">
        <span aria-hidden="true">✚</span>
        <h1>连接目标后开始应急处置</h1>
        <p>连接目标主机后，可以一键扫描入侵痕迹，并对每个问题逐项确认、归档证据、修复并自动复验。</p>
      </main>
    );
  }

  return (
    <main className="response-engine-page">
      <header className="response-engine-heading">
        <div>
          <p>入侵痕迹处置</p>
          <h1>应急处置</h1>
        </div>
        <div className="response-engine-heading-actions">
          <button
            type="button"
            disabled={scanning || dialog !== null}
            aria-expanded={kindsOpen}
            onClick={() => setKindsOpen((open) => !open)}
            data-testid="response-engine-kinds-toggle"
          >
            扫描项（{selectedKinds.size}/{SCAN_KIND_ORDER.length}）
          </button>
          <button
            type="button"
            className="primary"
            disabled={scanning || dialog !== null || selectedKinds.size === 0}
            onClick={() => void runScan()}
            data-testid="response-engine-scan"
          >
            {scanning ? "正在扫描…" : scan === null ? "开始扫描" : "重新扫描"}
          </button>
        </div>
      </header>

      {kindsOpen && !scanning && (
        <section className="response-engine-kinds" aria-label="扫描项选择" data-testid="response-engine-kinds">
          <div className="response-engine-kinds-actions">
            <button type="button" onClick={() => setSelectedKinds(new Set(SCAN_KIND_ORDER))}>全选</button>
            <button
              type="button"
              onClick={() => setSelectedKinds((current) => (current.size === SCAN_KIND_ORDER.length ? new Set(SCAN_KIND_ORDER.filter((kind) => kind === "ld-preload-hijack")) : current))}
            >
              仅「眼睛」三项
            </button>
            <span className="response-engine-kinds-note">默认全部检查；不勾选的项目本次扫描不报告。</span>
          </div>
          <ul>
            {SCAN_KIND_ORDER.map((kind) => {
              const meta = KIND_META[kind];
              const checked = selectedKinds.has(kind);
              return (
                <li key={kind}>
                  <label>
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => toggleKind(kind)}
                      disabled={dialog !== null}
                    />
                    <span aria-hidden="true">{meta.icon}</span>
                    <span>{meta.label}</span>
                  </label>
                </li>
              );
            })}
          </ul>
        </section>
      )}

      {scanError !== null && (
        <p className="response-engine-notice error" role="alert">{scanError}</p>
      )}

      {scanning && scanStage !== null && (
        <section className="response-engine-progress" aria-label="扫描进度" data-testid="response-engine-progress">
          <p className="response-engine-progress-label" role="status">{scanStage.label}</p>
          <div
            className="response-engine-progress-bar"
            role="progressbar"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={scanStage.percent}
          >
            <div className="response-engine-progress-fill" style={{ width: `${scanStage.percent}%` }} />
          </div>
        </section>
      )}

      {scan !== null && scan.gaps.length > 0 && (
        <section className="response-engine-gaps" aria-label="扫描缺口" data-testid="response-engine-gaps">
          <p>本次扫描存在缺口，结果可能不完整：</p>
          <ul>
            {scan.gaps.map((gap, index) => <li key={index}>{gap}</li>)}
          </ul>
        </section>
      )}

      {scan !== null && scan.truncated && (
        <p className="response-engine-truncated">结果较多，已按安全上限截断，看到的不是全部。</p>
      )}

      {scan === null && !scanning ? (
        <p className="response-engine-state">
          点击“开始扫描”检查目标上的十九类入侵痕迹：动态链接库劫持、PATH 注入、命令劫持、SSH 密钥后门、PAM 认证后门、WebShell、可疑监听、后门进程、影子账户、空口令、恶意 sudoers 授权、cron 持久化、后门藏匿目录、Web 敏感文件泄露、命令录音钩子、可疑登录账户、历史命令明文密码、会话驻留钩子和恶意库驻留进程。扫描只读取状态，不改动目标。
        </p>
      ) : null}
      {scanning && scanStage === null && <p className="response-engine-state" role="status">正在扫描目标，请稍候…</p>}

      {scan !== null && !scanning && (
        <>
          <p className="response-engine-state">
            扫描时间：{formatScanTime(scan.scannedAt)}；共发现 {scan.issues.length} 个问题。
          </p>
          {scan.issues.length === 0 ? (
            <p className="response-engine-state" data-testid="response-engine-clean">
              未发现这十九类入侵痕迹。注意：未发现证据不代表目标一定未被入侵。
            </p>
          ) : (
            <section className="response-engine-issues" aria-label="扫描结果">
              {scan.issues.map((issue) => (
                <IssueRow
                  key={issue.issueHandle}
                  issue={issue}
                  fix={fixes[issue.issueHandle] ?? null}
                  blocked={scanning || dialog !== null || anyActive}
                  onFix={() => void beginFix(issue, "lock")}
                />
              ))}
            </section>
          )}
          <footer className="response-engine-footer">
            <button
              type="button"
              disabled={scanning || dialog !== null}
              onClick={() => void runScan()}
              data-testid="response-engine-rescan"
            >
              重新扫描
            </button>
          </footer>
        </>
      )}

      {dialog !== null && (
        <ResponseFixDialog
          issue={dialog.issue}
          mode={dialog.mode}
          plan={dialog.plan}
          busy={dialog.busy}
          error={dialog.error}
          onModeChange={changeMode}
          onConfirm={() => void confirmFix()}
          onClose={closeDialog}
        />
      )}
      {rescanConfirm.dialog !== null && (
        <DialogHost dialog={rescanConfirm.dialog} onResolve={rescanConfirm.resolve} />
      )}
    </main>
  );
}

function formatScanTime(scannedAt: string): string {
  const at = new Date(scannedAt);
  return Number.isNaN(at.getTime()) ? scannedAt : at.toLocaleString();
}

function IssueRow({ issue, fix, blocked, onFix }: {
  issue: ResponseIssue;
  fix: ResponseFixRowState | null;
  blocked: boolean;
  onFix: () => void;
}) {
  const meta = KIND_META[issue.kind];
  return (
    <article className="response-engine-issue" data-issue-kind={issue.kind}>
      <div className="response-engine-issue-head">
        <span className="response-engine-kind-icon" aria-hidden="true">{meta.icon}</span>
        <span className="response-engine-kind">{meta.label}</span>
        <span className={`response-engine-severity ${issue.severity}`}>{SEVERITY_LABEL[issue.severity]}</span>
        {fix === null ? (
          <button
            type="button"
            className="response-engine-fix"
            disabled={!issue.fixable || blocked}
            title={issue.fixable ? undefined : "该问题当前不支持自动修复（可能缺少权限或修复方式）"}
            onClick={onFix}
          >
            修复
          </button>
        ) : (
          <FixStatus fix={fix} />
        )}
      </div>
      <p className="response-engine-summary">{issue.summary}</p>
      {issue.fixable && issue.fixSummary !== null && (
        <p className="response-engine-fix-summary">修复方式：{issue.fixSummary}</p>
      )}
      {!issue.fixable && (
        <p className="response-engine-no-fix">暂不支持自动修复，请按证据人工处置。</p>
      )}
      {issue.evidence.length > 0 && (
        <details className="response-engine-evidence">
          <summary>证据（{issue.evidence.length} 条）</summary>
          <ul>
            {issue.evidence.map((item, index) => <li key={index}><code>{item}</code></li>)}
          </ul>
        </details>
      )}
    </article>
  );
}

function FixStatus({ fix }: { fix: ResponseFixRowState }) {
  switch (fix.stage) {
    case "executing":
      return (
        <span className="response-engine-status is-running" role="status">
          <span className="response-engine-spinner" aria-hidden="true" />正在执行…
        </span>
      );
    case "verify-pending":
      return (
        <span className="response-engine-status is-pending" role="status">
          <span className="response-engine-spinner" aria-hidden="true" />已执行，等待跨周期复验（约 70 秒）…
        </span>
      );
    case "completed":
      return fix.verifyPassed ? (
        <span className="response-engine-status is-done" role="status" title={fix.summary}>
          已执行并复验通过
        </span>
      ) : (
        <span className="response-engine-status is-failed" role="alert" title={fix.summary}>
          已执行，但复验未通过
        </span>
      );
    case "failed":
      return (
        <span className="response-engine-status is-failed" role="alert" title={fix.summary}>
          执行未成功：{fix.summary}
        </span>
      );
  }
}

/** 修复确认弹层：展示方案内容，空口令类先选修复方式，确认后才执行。 */
function ResponseFixDialog({ issue, mode, plan, busy, error, onModeChange, onConfirm, onClose }: {
  issue: ResponseIssue;
  mode: ResponseFixMode;
  plan: ResponseEnginePlan | null;
  busy: boolean;
  error: string | null;
  onModeChange: (mode: ResponseFixMode) => void;
  onConfirm: () => void;
  onClose: () => void;
}) {
  useModalScrim();
  const meta = KIND_META[issue.kind];
  return (
    <div className="response-fix-backdrop" role="presentation">
      <section
        className="response-fix-dialog"
        role="dialog"
        aria-modal="true"
        aria-label={`修复：${meta.label}`}
        data-testid="response-fix-dialog"
      >
        <header>
          <h2>修复：{meta.label}</h2>
          <p>{issue.summary}</p>
        </header>

        {issue.kind === "empty-password" && (
          <fieldset className="response-fix-panel" disabled={busy}>
            <legend>选择修复方式</legend>
            <label>
              <input
                type="radio"
                name="response-fix-mode"
                checked={mode === "lock"}
                onChange={() => onModeChange("lock")}
              />
              <span>锁定账户（默认）——口令被锁定、无法登录，之后可以解锁恢复</span>
            </label>
            <label>
              <input
                type="radio"
                name="response-fix-mode"
                checked={mode === "remove"}
                onChange={() => onModeChange("remove")}
              />
              <span>删除账户——不可自动恢复；删除前证据已归档到目标机，供人工恢复</span>
            </label>
          </fieldset>
        )}

        {plan === null ? (
          <p className="response-fix-note" role="status">
            {busy ? "正在生成修复方案…" : "修复方案不可用。"}
          </p>
        ) : (
          <div className="response-fix-panel is-dangerous">
            <dl>
              <div>
                <dt>将要执行</dt>
                <dd>{plan.summary}</dd>
              </div>
              <div>
                <dt>步骤</dt>
                <dd>
                  <ol className="response-fix-steps">
                    {plan.steps.map((step, index) => <li key={index}>{step}</li>)}
                  </ol>
                </dd>
              </div>
              <div>
                <dt>影响与归档</dt>
                <dd>{plan.impact}</dd>
              </div>
              <div>
                <dt>出错后如何还原</dt>
                <dd>{plan.rollbackNote ?? "不提供自动恢复；归档保留在目标机，供人工恢复"}</dd>
              </div>
              <div>
                <dt>方案有效期</dt>
                <dd>{planExpiryLabel(plan.expiresInSeconds)}</dd>
              </div>
            </dl>
          </div>
        )}

        {error !== null && <p className="response-fix-error" role="alert">{error}</p>}

        <footer>
          <button type="button" onClick={onClose} disabled={busy}>取消</button>
          <button
            type="button"
            className="is-dangerous"
            disabled={busy || plan === null}
            data-testid="response-fix-execute"
            onClick={onConfirm}
          >
            {busy && plan !== null ? "正在执行…" : "确认并执行"}
          </button>
        </footer>
      </section>
    </div>
  );
}
