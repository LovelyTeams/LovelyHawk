import type { PodFileEvidenceResult } from "../shared/pod-file-evidence-contract";
import { visibleName } from "./ExecFileBrowser";
import { formatPacketCaptureBytes } from "./packet-capture-live-helpers";
import type { PodFileEvidenceViewState } from "./pod-file-evidence-controller";

interface PodFileEvidencePanelProps {
  view: PodFileEvidenceViewState;
  onCancel(): void;
  onReset(): void;
}

/**
 * A pod file being kept as evidence: how far it got and what was kept — the
 * folder, the case, the digest, and whether the copy on the SSH host is gone.
 * Shown inside the pod file dialog, which cancels a running job on close.
 */
export function PodFileEvidencePanel({ view, onCancel, onReset }: PodFileEvidencePanelProps) {
  const result = view.result;
  if (view.phase === "ready") return null;
  const running = view.phase === "running" || view.phase === "cancelling";
  return (
    <section className="pod-evidence" aria-label="Pod 文件留证" data-testid="pod-evidence"
      data-state={result?.state ?? view.phase}>
      <header>
        <strong>{view.phase === "choosing" ? "选择存放证据的文件夹…" : result === null ? "留证没有开始" : stateLabel(result)}</strong>
        {running ? (
          <button type="button" className="danger" disabled={view.phase !== "running"} onClick={onCancel}
            data-testid="pod-evidence-cancel">
            {view.phase === "cancelling" ? "取消中…" : "取消留证"}
          </button>
        ) : view.phase === "done" || view.phase === "interrupted" ? (
          <button type="button" onClick={onReset} data-testid="pod-evidence-reset">知道了</button>
        ) : null}
      </header>
      {view.error !== null ? <p className="pod-evidence-error" role="alert">{view.error}</p> : null}
      {result !== null ? (
        <>
          <p role={result.state === "failed" || result.state === "cancelled" ? "alert" : "status"}>
            {result.state === "collecting"
              ? `已读回 ${formatPacketCaptureBytes(result.copiedBytes)} / ${formatPacketCaptureBytes(result.totalBytes)}，复核 ${formatPacketCaptureBytes(result.verifiedBytes)}。`
              : null}
            {result.detail}
          </p>
          <dl>
            <div><dt>文件</dt><dd>{visibleName(result.path)}</dd></div>
            <div><dt>Pod</dt><dd>{result.pod}{result.container === null ? "（默认容器）" : ` · 容器 ${result.container}`}</dd></div>
            <div><dt>案件</dt><dd>{result.caseTitle}</dd></div>
            <div><dt>本机文件夹</dt><dd><code>{result.folderName}</code></dd></div>
            {result.sha256 !== null ? (
              <div><dt>SHA-256</dt><dd><code data-testid="pod-evidence-sha256">{result.sha256}</code></dd></div>
            ) : null}
            {result.state === "completed" || result.state === "saved-unlinked" ? (
              <div><dt>保存为</dt><dd>pod-file.bin · {formatPacketCaptureBytes(result.totalBytes)}，说明见同目录 manifest.json</dd></div>
            ) : null}
            <div><dt>主机上的临时副本</dt><dd data-testid="pod-evidence-temporary">{temporaryFileLabel(result)}</dd></div>
          </dl>
        </>
      ) : null}
    </section>
  );
}

export function stateLabel(result: PodFileEvidenceResult): string {
  switch (result.state) {
    case "copying": return "正在从 Pod 复制到 SSH 主机";
    case "collecting": return "正在读回本机并核对";
    case "completed": return "已保存为证据";
    case "saved-unlinked": return "文件已保存，未登记到案件";
    case "failed": return "没有保存";
    case "cancelled": return "已取消";
  }
}

export function temporaryFileLabel(result: PodFileEvidenceResult): string {
  switch (result.temporaryFile) {
    case "pending": return result.state === "copying" || result.state === "collecting"
      ? "在 SSH 主机的 /tmp，读回后删除"
      : "正在删除…";
    case "removed": return "已删除";
    case "left": return "没能删除，还在 SSH 主机的 /tmp 里（文件名以 lovelyhawk-podfile- 开头）";
    case "none": return "主机上没有留下";
  }
}
