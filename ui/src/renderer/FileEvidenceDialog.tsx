import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import type { EmergencyCommandPathOffer } from "../shared/emergency-command-contract";
import type { FileEvidenceApi } from "../shared/file-evidence-contract";
import { FileEvidenceController } from "./file-evidence-controller";
import { useModalScrim } from "./modal-scrim";
// The dialog frame is shared with the file-action dialogs; the log page opens
// this one without them, so it brings that frame along itself.
import "./emergency-path.css";
import "./file-evidence.css";

export function FileEvidenceDialog({ api, binding, offer, returnFocus, onClose }: {
  api: FileEvidenceApi; binding: string; offer: EmergencyCommandPathOffer; returnFocus: HTMLElement | null; onClose(): void;
}) {
  const [controller] = useState(() => new FileEvidenceController(api, binding, offer));
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  const root = useRef<HTMLElement>(null), close = useRef<HTMLButtonElement>(null);
  const closeRef = useRef(onClose); closeRef.current = onClose;
  useModalScrim();
  useEffect(() => {
    controller.attach();
    close.current?.focus();
    function keydown(event: KeyboardEvent) {
      if (event.key === "Escape") { event.preventDefault(); closeRef.current(); return; }
      if (event.key !== "Tab" || !root.current) return;
      const items = [...root.current.querySelectorAll<HTMLElement>('button:not([disabled]), [tabindex="0"]')];
      const index = items.indexOf(document.activeElement as HTMLElement);
      if (index < 0 || (event.shiftKey ? index === 0 : index === items.length - 1)) {
        event.preventDefault(); (event.shiftKey ? items.at(-1) : items[0])?.focus();
      }
    }
    function focusin(event: FocusEvent) {
      if (event.target instanceof Node && root.current && !root.current.contains(event.target)) close.current?.focus();
    }
    document.addEventListener("keydown", keydown);
    document.addEventListener("focusin", focusin);
    return () => {
      document.removeEventListener("keydown", keydown); controller.dispose();
      document.removeEventListener("focusin", focusin);
      if (returnFocus?.isConnected) returnFocus.focus({ preventScroll: true });
    };
  }, [controller, returnFocus]);
  const result = state.result, running = result?.state === "collecting";
  const percent = !result || result.totalBytes === 0 ? 0 : Math.floor((result.copiedBytes + result.verifiedBytes) * 50 / result.totalBytes);
  return <div className="emergency-path-backdrop">
    <section ref={root} className="emergency-path-dialog file-evidence-dialog" role="dialog" aria-modal="true" aria-labelledby="file-evidence-title">
      <header><h2 id="file-evidence-title">下载留证</h2><p>{offer.path}</p></header>
      <p>保存文件原始字节、来源主机、采集时间、文件属性和 SHA-256 摘要，并关联到当前主机的案件。</p>
      <p className="emergency-path-note">支持普通文件，单文件最多 512 MiB，采集最长 15 分钟。两次远端读取可能更新访问时间并增加磁盘、网络负载；结果不等同于文件系统快照。</p>
      <p className="emergency-path-note">将在所选目录创建独立文件夹。原始内容可能包含敏感信息，请按证据要求保管；sample.bin 应在隔离环境中分析，不能直接执行。</p>
      {state.phase === "choosing" ? <p role="status">请在系统对话框中选择保存目录…</p> : null}
      {result ? <div className="emergency-path-panel">
        <dl><div><dt>来源主机</dt><dd>{result.targetLabel}</dd></div><div><dt>文件夹</dt><dd>{result.folderName}</dd></div>
          <div><dt>案件</dt><dd>{result.caseTitle}</dd></div>
          {result.sha256 ? <div><dt>SHA-256</dt><dd className="file-evidence-hash">{result.sha256}</dd></div> : null}</dl>
        {running ? <><progress aria-label="文件采集进度" value={percent} max={100} />
          <p>{state.phase === "cancelling" ? "正在取消…" : result.totalBytes > 0 && result.verifiedBytes === result.totalBytes ? "远端复核完成，正在回读本机副本并归档…" : `下载 ${result.copiedBytes.toLocaleString()} / ${result.totalBytes.toLocaleString()} 字节；远端复核 ${result.verifiedBytes.toLocaleString()} 字节`}</p></> : null}
        <p role="status">{result.detail}</p>
      </div> : null}
      {state.error ? <p className="emergency-path-error" role="alert">{state.error}</p> : null}
      <footer><button ref={close} type="button" onClick={onClose}>{running ? "取消采集并关闭" : "关闭"}</button>
        {state.phase === "ready" ? <button type="button" className="is-primary" onClick={() => void controller.begin()}>选择目录并留证</button> : null}
        {running ? <button type="button" disabled={state.phase === "cancelling"} onClick={() => void controller.cancel()}>取消采集</button> : null}
        {state.phase === "interrupted" && running ? <button type="button" onClick={() => void controller.poll()}>重新读取进度</button> : null}
      </footer>
    </section>
  </div>;
}
