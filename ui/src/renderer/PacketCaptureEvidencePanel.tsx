import { useEffect, useState } from "react";

import type { PacketCaptureEvidenceResult } from "../shared/packet-capture-evidence-contract";
import type { PacketCaptureEvidenceViewState } from "./packet-capture-evidence-controller";
import { formatPacketCaptureBytes } from "./packet-capture-live-helpers";

interface PacketCaptureEvidencePanelProps {
  view: PacketCaptureEvidenceViewState;
  /** Why the start button cannot be used right now, or null when it can. */
  blockedReason: string | null;
  onBegin(): void;
  onCancel(): void;
  onReset(): void;
}

/**
 * Keeping a capture as a file: what it will do, how far it got, and what was
 * kept — the folder, the case, the digest, and whether the target's temporary
 * file is gone. tcpdump's own words appear only as quoted text.
 */
export function PacketCaptureEvidencePanel({ view, blockedReason, onBegin, onCancel, onReset }: PacketCaptureEvidencePanelProps) {
  const result = view.result;
  const running = view.phase === "running" || view.phase === "cancelling" || view.phase === "choosing";
  return (
    <section className="packet-capture-evidence" aria-labelledby="packet-capture-evidence-title" data-testid="packet-capture-evidence">
      <header>
        <div>
          <p>留证</p>
          <h2 id="packet-capture-evidence-title">保存为抓包文件</h2>
        </div>
        {running ? (
          <button type="button" className="danger" disabled={view.phase !== "running"} onClick={onCancel}
            data-testid="packet-capture-evidence-cancel">
            {view.phase === "cancelling" ? "取消中…" : "取消"}
          </button>
        ) : (
          <button type="button" className="primary" disabled={blockedReason !== null} onClick={onBegin}
            title={blockedReason ?? undefined} data-testid="packet-capture-evidence-begin">
            抓包并保存…
          </button>
        )}
      </header>
      {result === null && view.phase !== "choosing" ? (
        <p className="packet-capture-evidence-lead">
          按上面选的网卡、过滤条件、包数和秒数在目标上抓一段，存成可以用 Wireshark 打开的 capture.pcap，
          放进你选的文件夹并登记到当前案件。需要目标上有 tcpdump，并且是 root 或能免密码 sudo。
          抓包时文件先写在目标的 /tmp，读回本机核对摘要后删除；中途断开连接的话它会留在目标上。离开本页会取消。
        </p>
      ) : null}
      {view.phase === "choosing" ? (
        <p className="packet-capture-evidence-lead" role="status">在弹出的窗口里选择存放证据的文件夹…</p>
      ) : null}
      {blockedReason !== null && !running && result === null ? (
        <p className="packet-capture-evidence-blocked">{blockedReason}</p>
      ) : null}
      {view.error !== null ? (
        <p className="packet-capture-evidence-error" role="alert">{view.error}</p>
      ) : null}
      {result !== null ? <EvidenceProgress result={result} startedAt={view.startedAt} /> : null}
      {view.phase === "done" || (view.phase === "interrupted" && result !== null) ? (
        <div className="packet-capture-evidence-actions">
          <button type="button" onClick={onReset} data-testid="packet-capture-evidence-reset">知道了</button>
        </div>
      ) : null}
    </section>
  );
}

function EvidenceProgress({ result, startedAt }: { result: PacketCaptureEvidenceResult; startedAt: number | null }) {
  const elapsed = useElapsedSeconds(result.state === "capturing" ? startedAt : null);
  const failed = result.state === "failed" || result.state === "cancelled";
  return (
    <div className={`packet-capture-evidence-result ${result.state}`} data-testid="packet-capture-evidence-result"
      data-state={result.state}>
      <p className="packet-capture-evidence-phase" role={failed ? "alert" : "status"}>
        <strong>{stateLabel(result)}</strong>
        {result.state === "capturing" ? (
          <span>已过 {Math.min(elapsed, result.durationSeconds)} / 最长 {result.durationSeconds} 秒
            {result.packetLimit !== null ? `，或抓满 ${result.packetLimit} 个包` : ""}</span>
        ) : null}
        {result.state === "collecting" ? (
          <span>已读回 {formatPacketCaptureBytes(result.copiedBytes)} / {formatPacketCaptureBytes(result.totalBytes)}，
            复核 {formatPacketCaptureBytes(result.verifiedBytes)}</span>
        ) : null}
      </p>
      <p>{result.detail}</p>
      {result.tcpdumpLine !== null ? (
        <figure className="packet-capture-evidence-quote">
          <figcaption>tcpdump 的原话</figcaption>
          <pre data-testid="packet-capture-evidence-tcpdump">{result.tcpdumpLine}</pre>
        </figure>
      ) : null}
      <dl>
        <div><dt>网卡</dt><dd>{result.interface}{result.filtered ? "（带过滤条件）" : ""}</dd></div>
        <div><dt>目标</dt><dd>{result.targetLabel}</dd></div>
        <div><dt>案件</dt><dd>{result.caseTitle}</dd></div>
        <div><dt>本机文件夹</dt><dd><code>{result.folderName}</code></dd></div>
        {result.sha256 !== null ? (
          <div><dt>SHA-256</dt><dd><code data-testid="packet-capture-evidence-sha256">{result.sha256}</code></dd></div>
        ) : null}
        {result.state === "completed" || result.state === "saved-unlinked" ? (
          <div><dt>文件</dt><dd>capture.pcap · {formatPacketCaptureBytes(result.totalBytes)}，说明见同目录 manifest.json</dd></div>
        ) : null}
        <div><dt>目标上的临时文件</dt><dd data-testid="packet-capture-evidence-temporary">{temporaryFileLabel(result)}</dd></div>
      </dl>
    </div>
  );
}

function useElapsedSeconds(startedAt: number | null): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (startedAt === null) return;
    const timer = setInterval(() => setNow(Date.now()), 1_000);
    return () => clearInterval(timer);
  }, [startedAt]);
  return startedAt === null ? 0 : Math.max(0, Math.floor((now - startedAt) / 1_000));
}

export function stateLabel(result: PacketCaptureEvidenceResult): string {
  switch (result.state) {
    case "capturing": return "正在抓包";
    case "collecting": return "正在读回并核对";
    case "completed": return "已保存为证据";
    case "saved-unlinked": return "文件已保存，未登记到案件";
    case "failed": return "没有保存";
    case "cancelled": return "已取消";
  }
}

export function temporaryFileLabel(result: PacketCaptureEvidenceResult): string {
  switch (result.temporaryFile) {
    case "pending": return result.state === "capturing" || result.state === "collecting" ? "抓包期间在 /tmp，读回后删除" : "正在删除…";
    case "removed": return "已删除";
    case "left": return "没能删除，还在目标的 /tmp 里（文件名以 lovelyres-pcap- 开头）";
    case "none": return "没有留下";
  }
}
