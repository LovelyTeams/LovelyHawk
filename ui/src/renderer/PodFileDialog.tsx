import { useEffect, useRef, useState, useSyncExternalStore } from "react";

import { isPodFile, type PodFile, type PodFilesApi } from "../shared/exec-files-contract";
import type { PodFileEvidenceApi } from "../shared/pod-file-evidence-contract";
import { errorText } from "./error-text";
import { ExecFileBrowser, visibleName } from "./ExecFileBrowser";
import { useModalScrim } from "./modal-scrim";
import { PodFileEvidenceController, type PodFileEvidenceViewState } from "./pod-file-evidence-controller";
import { PodFileEvidencePanel } from "./PodFileEvidencePanel";

const IDLE_EVIDENCE: PodFileEvidenceViewState = { phase: "ready", result: null, error: null, startedAt: null };
const idleEvidence = (): PodFileEvidenceViewState => IDLE_EVIDENCE;
const noSubscription = (): (() => void) => () => undefined;

export interface PodFileDialogProps {
  api: PodFilesApi & PodFileEvidenceApi;
  bindingHandle: string;
  snapshotHandle: string;
  rowHandle: string;
  /** Display only, `namespace/name`; the pod is the row handle's. */
  podName: string;
  /** One of the pod's containers; null for its default one. */
  container: string | null;
  onClose: () => void;
}

/**
 * Looking at files inside a pod: browse one of its containers (the chosen
 * one, or its default), read a text file, or keep any regular file as case
 * evidence. Nothing is written into the pod — what is in it comes from its
 * image or a volume, and a change made in place is gone at the next restart
 * while the manifest still says otherwise.
 */
export function PodFileDialog({ api, bindingHandle, snapshotHandle, rowHandle, podName, container, onClose }: PodFileDialogProps) {
  useModalScrim();
  const [file, setFile] = useState<PodFile | null>(null);
  const [view, setView] = useState<"browse" | "file">("browse");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const busyRef = useRef(false);
  const mountedRef = useRef(true);
  const dialogRef = useRef<HTMLElement>(null);
  // One evidence job per dialog; closing the dialog cancels one still running.
  const [evidence, setEvidence] = useState<PodFileEvidenceController | null>(null);
  useEffect(() => {
    const controller = new PodFileEvidenceController(api, bindingHandle);
    setEvidence(controller);
    return () => controller.dispose();
  }, [api, bindingHandle]);
  const evidenceView = useSyncExternalStore(
    evidence?.subscribe ?? noSubscription,
    evidence?.getSnapshot ?? idleEvidence,
    idleEvidence,
  );
  const evidenceBusy = evidenceView.phase === "choosing" || evidenceView.phase === "running" ||
    evidenceView.phase === "cancelling";

  useEffect(() => {
    const returnTo = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    dialogRef.current?.querySelector<HTMLInputElement>('[data-testid="exec-browser-path"]')?.focus();
    return () => {
      mountedRef.current = false;
      returnTo?.focus();
    };
  }, []);

  useEffect(() => {
    function keydown(event: KeyboardEvent) {
      if (event.key !== "Escape") return;
      event.preventDefault();
      onClose();
    }
    document.addEventListener("keydown", keydown);
    return () => document.removeEventListener("keydown", keydown);
  }, [onClose]);

  async function read(path: string) {
    if (busyRef.current) return;
    busyRef.current = true;
    setBusy(true);
    setError(null);
    try {
      const value = await api.readKubernetesPodFile(bindingHandle, snapshotHandle, rowHandle, path, container);
      if (!isPodFile(value) || value.path !== path) throw new Error();
      if (!mountedRef.current) return;
      setFile(value);
      setView("file");
    } catch (reason: unknown) {
      if (mountedRef.current) setError(errorText(reason, "没能读取这个文件。"));
    } finally {
      busyRef.current = false;
      if (mountedRef.current) setBusy(false);
    }
  }

  function keep(path: string) {
    if (evidence === null) return;
    setError(null);
    void evidence.begin({ snapshotHandle, rowHandle, container, path });
  }

  return (
    <div className="exec-file-backdrop" role="presentation">
      <section ref={dialogRef} className="exec-file-dialog" role="dialog" aria-modal="true"
        aria-label={`${podName} 的文件`} data-testid="pod-file-dialog">
        <header>
          <div>
            <h2>Pod 文件</h2>
            <p>{container === null ? podName : `${podName} · 容器 ${container}`}</p>
          </div>
          <button type="button" className="exec-file-close" aria-label="关闭 Pod 文件" onClick={onClose}>✕</button>
        </header>
        <nav className="exec-file-tabs view-tabs view-tabs-underline" aria-label="文件视图">
          <button type="button" aria-pressed={view === "browse"} onClick={() => setView("browse")}>浏览</button>
          <button type="button" aria-pressed={view === "file"} disabled={file === null}
            data-testid="pod-file-view-tab" onClick={() => setView("file")}>
            {file === null ? "查看文件" : `查看 ${visibleName(file.path.slice(file.path.lastIndexOf("/") + 1))}`}
          </button>
        </nav>

        <div hidden={view !== "browse"}>
          <ExecFileBrowser
            list={(path) => api.listKubernetesPodDirectory(bindingHandle, snapshotHandle, rowHandle, path, container)}
            disabled={busy}
            fileActions={[{
              label: busy ? "读取中…" : "查看",
              testId: "pod-browser-read",
              describe: (name) => `查看 ${name} 的内容`,
              run: (path) => void read(path),
            }, {
              label: "留证",
              testId: "pod-browser-evidence",
              describe: (name) => evidenceBusy
                ? "已有一个留证在进行，等它完成或取消后再留证"
                : `把 ${name} 的原始字节保存到本机文件夹并登记到案件`,
              run: (path) => { if (!evidenceBusy) keep(path); },
              disabled: evidenceBusy,
            }]}
          />
        </div>

        {view === "file" && file !== null ? (
          <div className="exec-file-view" data-testid="pod-file-view">
            <dl>
              <div><dt>路径</dt><dd>{visibleName(file.path)}</dd></div>
              <div><dt>大小</dt><dd>{file.bytes} 字节</dd></div>
              <div><dt>SHA-256</dt><dd className="exec-file-digest">{file.sha256}</dd></div>
            </dl>
            <textarea readOnly spellCheck={false} aria-label={`${file.path} 的内容`} value={file.text} />
            <div className="exec-file-view-actions">
              <button type="button" disabled={evidenceBusy} data-testid="pod-file-view-evidence"
                onClick={() => keep(file.path)}>把这个文件留证…</button>
            </div>
          </div>
        ) : null}

        <PodFileEvidencePanel view={evidenceView} onCancel={() => void evidence?.cancel()}
          onReset={() => evidence?.reset()} />
        {error !== null ? <p className="exec-browser-error" role="alert">{error}</p> : null}
        <p className="exec-file-note">
          只读：显示的是{container === null ? " Pod 默认容器" : ` 容器 ${container} `}里的文件，查看前后都核对过长度和 SHA-256；不能在这里改动，要改请回到部署清单。
          “留证”把原始字节经 SSH 主机的 /tmp 复制回本机你选的文件夹，并登记到当前案件{evidenceBusy ? "；关闭对话框会取消正在进行的留证" : ""}。
        </p>
        <footer>
          <button type="button" onClick={onClose}>关闭</button>
        </footer>
      </section>
    </div>
  );
}
