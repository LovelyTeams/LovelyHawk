import { useEffect, useRef, useState } from "react";

import {
  AI_ASSIST_LIMITS,
  type AiAssistProgress,
  type AiAssistRequest,
  type AiAssistResponse,
  type AiAssistStarted,
  type AiAssistTask,
  type AiProviderChoice,
  type AiProviderChoices,
} from "../shared/ai-assist-contract";
import { errorText } from "./error-text";
import "./ai-assist-panel.css";

export interface AiAssistApi {
  aiAssist(request: AiAssistRequest): Promise<AiAssistResponse>;
}

/** What would be sent, built only when the operator asks to send it. */
export interface AiAssistContent {
  text: string;
  /** Lines left out to stay inside the bound. */
  omitted: number;
}

type Phase =
  | { kind: "loading" }
  | { kind: "unavailable"; message: string }
  | { kind: "choosing" }
  | { kind: "running"; started: AiAssistStarted }
  | { kind: "finished"; started: AiAssistStarted; progress: AiAssistProgress };

const POLL_MS = 250;
const encoder = new TextEncoder();

function reachText(choice: { reach: "local" | "internet" }): string {
  return choice.reach === "local" ? "本机或局域网" : "互联网";
}

function protocolText(protocol: AiProviderChoice["protocol"]): string {
  return protocol === "anthropic" ? "Claude 协议" : "OpenAI 协议";
}

/**
 * Asking a configured AI provider about a result the page holds.
 *
 * Nothing is sent until the operator has seen what would be sent and where,
 * and chosen to send it; a provider on the internet also needs a tick that
 * the text may leave this computer. The answer arrives as plain text, can be
 * stopped at any time, and is stopped when the panel goes away.
 */
export function AiAssistPanel({ api, task, what, subject = "日志原文", unit = "条", build, onClose }: {
  api: AiAssistApi;
  task: AiAssistTask;
  /** What is being sent, said in a few words ("本页 12 条日志和威胁摘要"). */
  what: string;
  /** The text that would leave the computer, as the consent names it. */
  subject?: string;
  /** What the omitted count counts: log entries, or terminal lines. */
  unit?: string;
  build(maximumBytes: number): AiAssistContent;
  onClose(): void;
}) {
  const [phase, setPhase] = useState<Phase>({ kind: "loading" });
  const [choices, setChoices] = useState<AiProviderChoice[]>([]);
  const [providerId, setProviderId] = useState<string | null>(null);
  const [consent, setConsent] = useState(false);
  const [answer, setAnswer] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [preview] = useState(() => build(AI_ASSIST_LIMITS.maximumContentBytes));
  const running = useRef<string | null>(null);
  const live = useRef(true);
  const busy = useRef(false);

  useEffect(() => {
    live.current = true;
    void (async () => {
      try {
        const choices = await api.aiAssist({ action: "providers" }) as AiProviderChoices;
        if (!live.current) return;
        if (choices.providers.length === 0) {
          setPhase({
            kind: "unavailable",
            message: "还没有可用的 AI 服务商。到“设置 → AI 服务商”里添加一个：离线可以接本机或局域网里的模型服务"
              + "（例如 Ollama，填它的 OpenAI 兼容地址），在线可以接 OpenAI 或 Claude。",
          });
          return;
        }
        setChoices(choices.providers);
        setProviderId(choices.defaultProviderId ?? choices.providers[0]!.id);
        setPhase({ kind: "choosing" });
      } catch (reason) {
        if (live.current) setPhase({ kind: "unavailable", message: errorText(reason, "没能读出 AI 服务商设置。") });
      }
    })();
    return () => {
      live.current = false;
      // Leaving the panel stops a stream nobody is reading any more.
      const handle = running.current;
      if (handle !== null) void api.aiAssist({ action: "cancel", handle }).catch(() => undefined);
    };
  }, [api]);

  const chosen = choices.find((choice) => choice.id === providerId) ?? null;
  const needsConsent = chosen?.reach === "internet";
  const kilobytes = Math.max(1, Math.round(encoder.encode(preview.text).byteLength / 1_024));

  async function send(): Promise<void> {
    if (chosen === null || busy.current || (needsConsent && !consent)) return;
    busy.current = true;
    setError(null);
    setAnswer("");
    try {
      const content = build(AI_ASSIST_LIMITS.maximumContentBytes);
      const started = await api.aiAssist({ action: "start", providerId: chosen.id, task, content: content.text }) as AiAssistStarted;
      if (!live.current) {
        void api.aiAssist({ action: "cancel", handle: started.handle }).catch(() => undefined);
        return;
      }
      running.current = started.handle;
      setPhase({ kind: "running", started });
      let collected = "";
      for (;;) {
        await new Promise((resolve) => window.setTimeout(resolve, POLL_MS));
        if (!live.current) return;
        const progress = await api.aiAssist({ action: "poll", handle: started.handle }) as AiAssistProgress;
        if (!live.current) return;
        if (progress.text !== "") {
          collected += progress.text;
          setAnswer(collected);
        }
        if (progress.state !== "running") {
          running.current = null;
          setPhase({ kind: "finished", started, progress });
          return;
        }
      }
    } catch (reason) {
      running.current = null;
      if (live.current) {
        setError(errorText(reason, "AI 解读没有完成。"));
        setPhase({ kind: "choosing" });
      }
    } finally {
      busy.current = false;
    }
  }

  function stop(): void {
    const handle = running.current;
    if (handle !== null) void api.aiAssist({ action: "cancel", handle }).catch(() => undefined);
  }

  return (
    <section className="ai-assist-panel" aria-label="AI 解读" data-testid="ai-assist-panel">
      <header>
        <h3>AI 解读</h3>
        <button type="button" onClick={onClose} disabled={phase.kind === "running"}>收起</button>
      </header>
      {phase.kind === "loading" ? <p role="status">正在读取 AI 服务商…</p> : null}
      {phase.kind === "unavailable" ? <p className="ai-assist-note" role="status">{phase.message}</p> : null}
      {phase.kind === "choosing" ? (
        <div className="ai-assist-choose">
          <label>发给
            <select value={providerId ?? ""} onChange={(event) => { setProviderId(event.target.value); setConsent(false); }}>
              {choices.map((choice) => (
                <option key={choice.id} value={choice.id}>
                  {choice.label} · {choice.model} · {reachText(choice)}
                </option>
              ))}
            </select>
          </label>
          <p data-testid="ai-assist-summary">
            将发送{what}（约 {kilobytes} KB{preview.omitted > 0 ? `，超出上限的 ${preview.omitted} ${unit}不发` : ""}）到
            「{chosen?.label}」，{chosen === null ? "" : `${protocolText(chosen.protocol)}，${reachText(chosen)}`}。
            回答只作参考，结论要自己核实；完成后会存进 AI 历史。
          </p>
          {needsConsent ? (
            <label className="ai-assist-consent">
              <input type="checkbox" checked={consent} data-testid="ai-assist-consent"
                onChange={(event) => setConsent(event.target.checked)} />
              这个服务商在互联网上。{subject}会离开这台电脑，可能含口令、密钥等敏感信息；我确认可以发送。
            </label>
          ) : (
            <p className="ai-assist-note">这个服务商在本机或局域网里，内容不会离开本地网络。</p>
          )}
          <button type="button" className="ai-assist-send" data-testid="ai-assist-send"
            disabled={chosen === null || (needsConsent && !consent)} onClick={() => void send()}>
            发送并解读
          </button>
        </div>
      ) : null}
      {phase.kind === "running" || phase.kind === "finished" ? (
        <div className="ai-assist-answer">
          <p className="ai-assist-note">
            {phase.started.providerLabel} · {phase.started.model} · {reachText(phase.started)}
          </p>
          <pre data-testid="ai-assist-answer" aria-live="polite">{answer || (phase.kind === "running" ? "等待回答…" : "")}</pre>
          {phase.kind === "running" ? (
            <div className="ai-assist-status">
              <span role="status">正在接收…已收到 {answer.length} 字</span>
              <button type="button" data-testid="ai-assist-stop" onClick={stop}>停止</button>
            </div>
          ) : (
            <p className={phase.progress.state === "failed" ? "ai-assist-error" : "ai-assist-note"}
              role={phase.progress.state === "failed" ? "alert" : "status"} data-testid="ai-assist-outcome">
              {phase.progress.state === "completed"
                ? `解读完成${phase.progress.truncated ? "（回答太长，只保留了前面部分）" : ""}，已存进 AI 历史。`
                : phase.progress.state === "cancelled"
                  ? "已停止，这次的回答没有存进 AI 历史。"
                  : `没有完成：${phase.progress.error ?? "服务商没有给出原因。"}`}
            </p>
          )}
          {phase.kind === "finished" ? (
            <button type="button" onClick={() => { setConsent(false); setPhase({ kind: "choosing" }); }}>再解读一次</button>
          ) : null}
        </div>
      ) : null}
      {error !== null ? <p className="ai-assist-error" role="alert">{error}</p> : null}
    </section>
  );
}
