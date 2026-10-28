import { useEffect, useRef, useState } from "react";

import type {
  SshAttemptCancellation,
  SshAttemptStarted,
  SshAttemptStatus,
  SshBindingDisconnection,
} from "../shared/ssh-contract";
import { isSshMfaResponses } from "../shared/ssh-contract";
import { nextFocusIndex } from "./connection-helpers";
import "./ssh-attempt.css";
import { errorText } from "./error-text";
import { useModalScrim } from "./modal-scrim";

export interface SshAttemptApi {
  getAttempt(attemptHandle: string): Promise<SshAttemptStatus>;
  confirmHostKey(attemptHandle: string, promptHandle: string): Promise<SshAttemptStatus>;
  respondMfa(
    attemptHandle: string,
    promptHandle: string,
    responses: string[],
  ): Promise<SshAttemptStatus>;
  cancelAttempt(attemptHandle: string): Promise<SshAttemptCancellation>;
  disconnectBinding(bindingHandle: string): Promise<SshBindingDisconnection>;
}

interface SshAttemptDialogProps {
  attempt: SshAttemptStarted;
  mode: "probe" | "connect";
  api: SshAttemptApi;
  onTerminal(status: SshAttemptStatus): void;
  onClose(): void;
}

const POLL_INTERVAL_MS = 250;
const focusableSelector =
  'button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])';

export function SshAttemptDialog({
  attempt,
  mode,
  api,
  onTerminal,
  onClose,
}: SshAttemptDialogProps) {
  useModalScrim();
  const [status, setStatus] = useState<SshAttemptStatus>({ stage: "running" });
  const [responses, setResponses] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const dialogRef = useRef<HTMLDivElement>(null);
  const initialFocusRef = useRef<HTMLElement | null>(null);
  const lifecycleRef = useRef(0);
  const terminalReportedRef = useRef(false);
  const apiRef = useRef(api);
  const onTerminalRef = useRef(onTerminal);

  apiRef.current = api;
  onTerminalRef.current = onTerminal;

  useEffect(() => {
    lifecycleRef.current += 1;
    terminalReportedRef.current = false;
    setStatus({ stage: "running" });
    setResponses([]);
    setError(null);
  }, [attempt.attemptHandle]);

  useEffect(() => {
    const lifecycle = lifecycleRef.current;
    let timer: ReturnType<typeof setTimeout> | undefined;
    async function poll() {
      try {
        const next = await apiRef.current.getAttempt(attempt.attemptHandle);
        if (lifecycleRef.current !== lifecycle) return;
        setStatus(next);
        setError(null);
        if (next.stage === "running") timer = setTimeout(() => void poll(), POLL_INTERVAL_MS);
      } catch (reason: unknown) {
        if (lifecycleRef.current === lifecycle) {
          setError(messageFrom(reason, "SSH 状态读取失败。"));
        }
      }
    }
    if (status.stage === "running") timer = setTimeout(() => void poll(), POLL_INTERVAL_MS);
    return () => {
      lifecycleRef.current += 1;
      if (timer !== undefined) clearTimeout(timer);
    };
  }, [attempt.attemptHandle, status.stage]);

  useEffect(() => {
    if (
      status.stage !== "running" &&
      status.stage !== "awaiting-host-key" &&
      status.stage !== "awaiting-mfa" &&
      !terminalReportedRef.current
    ) {
      terminalReportedRef.current = true;
      onTerminalRef.current(status);
    }
  }, [status]);

  useEffect(() => {
    if (status.stage === "awaiting-mfa") {
      setResponses(status.mfaPrompt.prompts.map(() => ""));
    } else {
      setResponses([]);
    }
    requestAnimationFrame(() => initialFocusRef.current?.focus());
  }, [status.stage, status.stage === "awaiting-mfa" ? status.mfaPrompt.promptHandle : null]);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (dialog === null) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.isComposing) return;
      if (event.key === "Escape") {
        event.preventDefault();
        if (!busy) void cancelOrClose();
        return;
      }
      if (event.key !== "Tab") return;
      const items = [...dialog.querySelectorAll<HTMLElement>(focusableSelector)];
      const next = nextFocusIndex(items.indexOf(document.activeElement as HTMLElement), items.length, event.shiftKey);
      if (next === null) return;
      event.preventDefault();
      items[next]?.focus();
    };
    dialog.addEventListener("keydown", onKeyDown);
    return () => dialog.removeEventListener("keydown", onKeyDown);
  }, [busy, status.stage]);

  async function run(operation: () => Promise<SshAttemptStatus>) {
    if (busy) return;
    setBusy(true);
    try {
      const next = await operation();
      setStatus(next);
      setError(null);
    } catch (reason: unknown) {
      setError(messageFrom(reason, "SSH 操作失败。"));
    } finally {
      setBusy(false);
    }
  }

  async function cancelOrClose() {
    if (isTerminal(status)) {
      onClose();
      return;
    }
    setBusy(true);
    try {
      const result = await apiRef.current.cancelAttempt(attempt.attemptHandle);
      if (!result.cancelled) throw new Error("SSH 取消未被确认。");
      const cancelled: SshAttemptStatus = { stage: "cancelled" };
      setStatus(cancelled);
      setError(null);
    } catch (reason: unknown) {
      setError(messageFrom(reason, "SSH 尝试取消失败；对话框保持打开。"));
    } finally {
      setBusy(false);
    }
  }

  async function submitMfa() {
    if (status.stage !== "awaiting-mfa") return;
    if (!isSshMfaResponses(responses) || responses.length !== status.mfaPrompt.prompts.length) {
      setError("MFA 响应数量或 UTF-8 字节长度超出安全边界。");
      return;
    }
    const promptHandle = status.mfaPrompt.promptHandle;
    await run(() =>
      apiRef.current.respondMfa(attempt.attemptHandle, promptHandle, responses),
    );
    setResponses([]);
  }

  return (
    <div className="ssh-attempt-backdrop">
      <div
        ref={dialogRef}
        className="ssh-attempt-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="ssh-attempt-title"
        aria-busy={busy}
      >
        <header>
          <div>
            <p className="eyebrow">SSH 连接</p>
            <h2 id="ssh-attempt-title">{mode === "probe" ? "测试 SSH 配置" : "连接 SSH 目标"}</h2>
          </div>
          <span className={`ssh-stage ${status.stage}`}>{stageLabel(status.stage)}</span>
        </header>

        {error !== null ? <p className="ssh-attempt-error" role="alert">{error}</p> : null}
        {status.stage === "running" ? (
          <section className="ssh-attempt-running" aria-live="polite">
            <span className="ssh-spinner" aria-hidden="true" />
            <div><strong>正在建立安全连接</strong><p>正在后台完成 SSH 握手…</p></div>
          </section>
        ) : null}
        {status.stage === "awaiting-host-key" ? (
          <section className="ssh-host-key-panel">
            <p className="danger-kicker">首次主机密钥确认</p>
            <h3>{status.hostKeyPrompt.role === "target" ? "目标主机" : "堡垒机"}要求独立核验</h3>
            <p>{status.hostKeyPrompt.username}@{status.hostKeyPrompt.host}:{status.hostKeyPrompt.port}</p>
            <code>{status.hostKeyPrompt.fingerprint}</code>
            <p>请通过可信的独立渠道核对指纹。连接或测试成功后，这个指纹会记在该连接里；以后主机密钥一旦变化，连接会被拒绝。</p>
            {/* Not the initial focus: trusting a key is the operator's decision,
                never what a stray Enter does. Focus starts on 取消尝试. */}
            <button
              type="button"
              data-testid="ssh-host-key-trust"
              disabled={busy}
              onClick={() => void run(() => apiRef.current.confirmHostKey(
                attempt.attemptHandle,
                status.hostKeyPrompt.promptHandle,
              ))}
            >我已独立核验，信任此指纹</button>
          </section>
        ) : null}
        {status.stage === "awaiting-mfa" ? (
          <form className="ssh-mfa-panel" onSubmit={(event) => { event.preventDefault(); void submitMfa(); }}>
            <p className="eyebrow">追加验证</p>
            <h3>{status.mfaPrompt.name || "服务器要求进一步认证"}</h3>
            <p>{status.mfaPrompt.instructions}</p>
            <small>{status.mfaPrompt.username}@{status.mfaPrompt.host}:{status.mfaPrompt.port}</small>
            {status.mfaPrompt.prompts.map((prompt, index) => (
              <label key={`${status.mfaPrompt.promptHandle}-${index}`}>
                <span>{prompt.prompt}</span>
                <input
                  ref={index === 0 ? (node) => { initialFocusRef.current = node; } : undefined}
                  type={prompt.echo ? "text" : "password"}
                  autoComplete="one-time-code"
                  value={responses[index] ?? ""}
                  onChange={(event) => {
                    // Read now: React clears currentTarget once this handler
                    // returns, and the updater below may run later, at render.
                    // Reading it there crashed the whole window on typing.
                    const typed = event.currentTarget.value;
                    setResponses((current) => current.map((value, itemIndex) => itemIndex === index ? typed : value));
                  }}
                />
              </label>
            ))}
            <button type="submit" disabled={busy}>提交一次性响应</button>
          </form>
        ) : null}
        {status.stage === "probe-succeeded" || status.stage === "connected" ? (
          <section className="ssh-success-panel">
            <span aria-hidden="true">✓</span>
            <div>
              <h3>{status.stage === "connected" ? "目标已连接" : "SSH 配置验证通过"}</h3>
              <p>{status.target.username}@{status.target.host}:{status.target.port}</p>
            </div>
          </section>
        ) : null}
        {status.stage === "failed" ? (
          <section className="ssh-failure-panel">
            <h3>{status.error.code === "host-key-changed" ? "主机密钥已变化，连接被拒绝" : "SSH 尝试失败"}</h3>
            <p>{status.error.message}</p>
            {status.error.code === "host-key-changed" ? <p>LovelyHawk 不会自动接受新的主机密钥。请先通过其他可信渠道查明密钥为什么变了。</p> : null}
          </section>
        ) : null}
        {status.stage === "cancelled" ? <p className="ssh-cancelled">SSH 尝试已取消；之后才建立的会话会被自动断开。</p> : null}

        <footer>
          <button ref={status.stage === "running" || status.stage === "awaiting-host-key" ? (node) => { initialFocusRef.current = node; } : undefined}
            type="button" data-testid="ssh-attempt-cancel" disabled={busy} onClick={() => void cancelOrClose()}>
            {isTerminal(status) ? "关闭" : "取消尝试"}
          </button>
        </footer>
      </div>
    </div>
  );
}

function isTerminal(status: SshAttemptStatus): boolean {
  return status.stage === "probe-succeeded" || status.stage === "connected" || status.stage === "failed" || status.stage === "cancelled";
}

function stageLabel(stage: SshAttemptStatus["stage"]): string {
  switch (stage) {
    case "running": return "握手中";
    case "awaiting-host-key": return "等待指纹核验";
    case "awaiting-mfa": return "等待 MFA";
    case "probe-succeeded": return "测试通过";
    case "connected": return "已连接";
    case "failed": return "失败";
    case "cancelled": return "已取消";
  }
}

function messageFrom(reason: unknown, fallback: string): string {
  return errorText(reason, fallback);
}
