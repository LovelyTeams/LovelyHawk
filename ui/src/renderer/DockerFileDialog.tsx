import { TransientNotice } from "./NotificationCenter";
import { useEffect, useRef, useState } from "react";

import type {
  DockerActionPlan,
  DockerActionReceipt,
  DockerContainerFile,
  DockerFileCopyDirection,
  DockerWriteApi,
} from "../shared/docker-write-contract";
import {
  isDockerActionPlan,
  isDockerActionReceipt,
  isDockerContainerFile,
  isDockerFilePath,
  MAX_DOCKER_FILE_BYTES,
} from "../shared/docker-write-contract";
import type { ContainerFilesApi } from "../shared/exec-files-contract";
import { DialogHost } from "./DialogHost";
import { errorText } from "./error-text";
import { ExecFileBrowser } from "./ExecFileBrowser";
import { useModalScrim } from "./modal-scrim";
import { planExpiryLabel } from "./plan-expiry";
import { useConfirmDialog } from "./use-confirm-dialog";

export type DockerFileApi = Pick<
  DockerWriteApi,
  | "readDockerContainerFile"
  | "planDockerFileWrite"
  | "planDockerFileCopy"
  | "confirmDockerContainerAction"
  | "executeDockerContainerAction"
  | "cancelDockerContainerAction"
> & ContainerFilesApi;

type Mode = "browse" | "edit" | "copy";

const MODE_LABEL: Record<Mode, string> = {
  browse: "浏览",
  edit: "编辑文件",
  copy: "复制文件",
};

export interface DockerFileDialogProps {
  api: DockerFileApi;
  bindingHandle: string;
  snapshotHandle: string;
  containerHandle: string;
  /** Display only; the container is the handle's. */
  containerName: string;
  onClose: () => void;
}

const DIRECTIONS: ReadonlyArray<{ value: DockerFileCopyDirection; label: string; source: string; target: string }> = [
  { value: "container-to-host", label: "容器 → 这台主机", source: "容器里的文件", target: "保存到主机上的路径" },
  { value: "host-to-container", label: "这台主机 → 容器", source: "主机上的文件", target: "放到容器里的路径" },
  { value: "in-container", label: "容器里复制一份", source: "容器里的文件", target: "容器里的新路径" },
];

const encoder = new TextEncoder();

/**
 * Edit or copy one file in a container. Nothing is written until a plan has
 * been shown and confirmed; afterwards the receipt says what the target read
 * back, and a failed check is put back from the backup the plan made.
 *
 * Paths here are inside the container or on the connected machine — never on
 * the operator's own computer.
 */
export function DockerFileDialog({
  api,
  bindingHandle,
  snapshotHandle,
  containerHandle,
  containerName,
  onClose,
}: DockerFileDialogProps) {
  useModalScrim();
  // Browsing first: knowing the path is the hard part, and the typed-path
  // field is still one tab away for whoever already knows it.
  const [mode, setMode] = useState<Mode>("browse");
  const [path, setPath] = useState("");
  const [opened, setOpened] = useState<DockerContainerFile | null>(null);
  const [text, setText] = useState("");
  const [direction, setDirection] = useState<DockerFileCopyDirection>("container-to-host");
  const [source, setSource] = useState("");
  const [target, setTarget] = useState("");
  const [plan, setPlan] = useState<DockerActionPlan | null>(null);
  const [receipt, setReceipt] = useState<DockerActionReceipt | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  // A click landing before `busy` renders would send the same remote call twice.
  const busyRef = useRef(false);
  const planRef = useRef<DockerActionPlan | null>(null);
  const mountedRef = useRef(true);
  const firstFieldRef = useRef<HTMLInputElement>(null);
  const dialogRef = useRef<HTMLElement>(null);
  const discard = useConfirmDialog();
  const dirty = opened !== null && text !== opened.text;
  const textBytes = encoder.encode(text).byteLength;

  useEffect(() => {
    // The dialog opens on 浏览, whose first field is the path bar.
    (firstFieldRef.current ?? dialogRef.current?.querySelector<HTMLInputElement>('[data-testid="exec-browser-path"]'))?.focus();
    return () => {
      mountedRef.current = false;
      // A plan nobody confirmed is dropped rather than left to expire.
      const pending = planRef.current;
      if (pending !== null) void api.cancelDockerContainerAction(bindingHandle, pending.planHandle).catch(() => undefined);
    };
  }, [api, bindingHandle]);

  function showPlan(next: DockerActionPlan | null) {
    planRef.current = next;
    setPlan(next);
  }

  async function run<T>(work: () => Promise<T>, fallback: string): Promise<T | null> {
    if (busyRef.current) return null;
    busyRef.current = true;
    setBusy(true);
    setError(null);
    try {
      return await work();
    } catch (reason: unknown) {
      if (mountedRef.current) setError(errorText(reason, fallback));
      return null;
    } finally {
      busyRef.current = false;
      if (mountedRef.current) setBusy(false);
    }
  }

  async function openFile(next = path.trim()) {
    if (!isDockerFilePath(next)) {
      setError("请输入容器里文件的完整路径，以 / 开头，例如 /etc/nginx/nginx.conf。");
      return;
    }
    const file = await run(async () => {
      const value = await api.readDockerContainerFile(bindingHandle, snapshotHandle, containerHandle, containerName, next);
      if (!isDockerContainerFile(value)) throw new Error();
      return value;
    }, "没能打开这个文件。");
    if (file === null || !mountedRef.current) return;
    setOpened(file);
    setText(file.text);
    setNotice(`已打开 ${file.path}（${file.bytes} 字节）。`);
  }

  async function planSave() {
    if (opened === null || !dirty) return;
    if (textBytes > MAX_DOCKER_FILE_BYTES) {
      setError("内容超过了 2 MiB 的上限，不能保存。");
      return;
    }
    const value = await run(async () => {
      const next = await api.planDockerFileWrite(bindingHandle, opened.fileHandle, text);
      if (!isDockerActionPlan(next)) throw new Error();
      return next;
    }, "没能准备这次保存。");
    if (value !== null && mountedRef.current) {
      setReceipt(null);
      showPlan(value);
    }
  }

  async function planCopy() {
    const from = source.trim();
    const to = target.trim();
    if (!isDockerFilePath(from) || !isDockerFilePath(to)) {
      setError("源和目标都要写成以 / 开头的完整文件路径。");
      return;
    }
    if (from === to && direction === "in-container") {
      setError("源和目标不能是同一个文件。");
      return;
    }
    const value = await run(async () => {
      const next = await api.planDockerFileCopy(bindingHandle, snapshotHandle, containerHandle, containerName, direction, from, to);
      if (!isDockerActionPlan(next)) throw new Error();
      return next;
    }, "没能准备这次复制。");
    if (value !== null && mountedRef.current) {
      setReceipt(null);
      showPlan(value);
    }
  }

  async function confirmAndRun() {
    const pending = planRef.current;
    if (pending === null) return;
    const done = await run(async () => {
      await api.confirmDockerContainerAction(bindingHandle, pending.planHandle);
      const value = await api.executeDockerContainerAction(bindingHandle, pending.planHandle);
      if (!isDockerActionReceipt(value)) throw new Error();
      return value;
    }, "这次操作没有完成，目标上的文件请再确认一次。");
    if (!mountedRef.current) return;
    showPlan(null);
    if (done === null) return;
    setReceipt(done);
    // After a verified save the opened revision is out of date; read the file
    // again so the next edit is checked against what is there now.
    if (done.verified && pending.action === "write-file" && opened !== null) await openFile(opened.path);
  }

  function cancelPlan() {
    const pending = planRef.current;
    showPlan(null);
    if (pending !== null) void api.cancelDockerContainerAction(bindingHandle, pending.planHandle).catch(() => undefined);
  }

  /** A file picked while browsing goes to the editor, as if its path were typed. */
  async function openFromBrowser(next: string) {
    if (busyRef.current) return;
    if (dirty && opened?.path !== next &&
      !(await discard.ask("放弃未保存的修改？", `${opened?.path ?? "当前文件"} 还有没保存到容器里的修改，打开别的文件会丢掉它们。`, "放弃修改并打开"))) return;
    setMode("edit");
    setReceipt(null);
    setPath(next);
    if (opened?.path === next) return;
    await openFile(next);
  }

  /** …or to the copy form, as the source of a copy out to the connected machine. */
  function copyFromBrowser(next: string, name: string) {
    setMode("copy");
    setReceipt(null);
    setError(null);
    setDirection("container-to-host");
    setSource(next);
    setTarget(`/tmp/${name}`);
  }

  async function requestClose() {
    if (busyRef.current) return;
    if (dirty && !(await discard.ask("放弃未保存的修改？", "这个文件有还没保存到容器里的修改，关闭后这些修改会丢失。", "放弃修改并关闭"))) return;
    onClose();
  }

  useEffect(() => {
    function keydown(event: KeyboardEvent) {
      if (event.key !== "Escape" || discard.dialog !== null) return;
      event.preventDefault();
      if (planRef.current !== null) cancelPlan();
      else void requestClose();
    }
    document.addEventListener("keydown", keydown);
    return () => document.removeEventListener("keydown", keydown);
  });

  const choice = DIRECTIONS.find((entry) => entry.value === direction) ?? DIRECTIONS[0]!;
  return (
    <div className="docker-action-backdrop" role="presentation">
      <section
        ref={dialogRef}
        className="docker-action-dialog docker-file-dialog"
        role="dialog"
        aria-modal="true"
        aria-label={`${containerName} 的文件`}
        data-testid="docker-file-dialog"
        inert={discard.dialog !== null ? true : undefined}
      >
        <header>
          <h2>容器文件</h2>
          <p>{containerName}</p>
        </header>
        <nav className="docker-file-tabs view-tabs view-tabs-underline" aria-label="文件操作">
          {(["browse", "edit", "copy"] as const).map((entry) => (
            <button key={entry} type="button" aria-pressed={mode === entry} className={mode === entry ? "is-active" : undefined}
              data-testid={`docker-file-mode-${entry}`}
              disabled={busy || plan !== null} onClick={() => { setMode(entry); setError(null); setReceipt(null); }}>
              {MODE_LABEL[entry]}
            </button>
          ))}
        </nav>

        {/* Kept mounted while hidden, so the directory and filter the operator
            was in are still there after a look at a file. */}
        <div hidden={plan !== null || mode !== "browse"}>
          <ExecFileBrowser
            list={(directory) => api.listDockerContainerDirectory(bindingHandle, snapshotHandle, containerHandle, directory)}
            disabled={busy}
            fileActions={[
              {
                label: "打开",
                testId: "docker-browser-open",
                describe: (name) => `在编辑器里打开 ${name}`,
                run: (next) => void openFromBrowser(next),
              },
              {
                label: "复制出来",
                testId: "docker-browser-copy",
                describe: (name) => `把 ${name} 复制到连接的主机上`,
                run: (next, entry) => copyFromBrowser(next, entry.name),
              },
            ]}
          />
        </div>

        {plan === null && mode === "edit" ? (
          <>
            <form className="docker-file-row" onSubmit={(event) => { event.preventDefault(); void openFile(); }}>
              <label className="docker-file-field">
                <span>容器里的文件</span>
                <input ref={firstFieldRef} value={path} maxLength={4_096} placeholder="/etc/nginx/nginx.conf"
                  onChange={(event) => setPath(event.currentTarget.value)} />
              </label>
              <button type="submit" disabled={busy || path.trim() === ""}>{busy && opened === null ? "打开中…" : "打开"}</button>
            </form>
            {opened !== null ? (
              <>
                <textarea className="docker-file-text" aria-label={`${opened.path} 的内容`} spellCheck={false}
                  value={text} onChange={(event) => setText(event.currentTarget.value)} />
                <p className="docker-action-note">{dirty ? `已修改，未保存（${textBytes} 字节）` : "与容器里的内容一致"}</p>
              </>
            ) : (
              <p className="docker-action-note">只能打开 2 MiB 以内的 UTF-8 文本。保存前会先给出计划，写入后重新读出核对，不一致会用备份恢复。</p>
            )}
          </>
        ) : null}

        {plan === null && mode === "copy" ? (
          <form className="docker-file-copy" onSubmit={(event) => { event.preventDefault(); void planCopy(); }}>
            <label className="docker-file-field">
              <span>方向</span>
              <select value={direction} onChange={(event) => setDirection(event.currentTarget.value as DockerFileCopyDirection)}>
                {DIRECTIONS.map((entry) => <option key={entry.value} value={entry.value}>{entry.label}</option>)}
              </select>
            </label>
            <label className="docker-file-field">
              <span>{choice.source}</span>
              <input value={source} maxLength={4_096} placeholder="/etc/hosts" onChange={(event) => setSource(event.currentTarget.value)} />
            </label>
            <label className="docker-file-field">
              <span>{choice.target}</span>
              <input value={target} maxLength={4_096} placeholder="/tmp/hosts.copy" onChange={(event) => setTarget(event.currentTarget.value)} />
            </label>
            <p className="docker-action-note">“主机”指当前连接的这台机器，不是你自己的电脑。目标已存在时会先留备份，复制后核对两边内容。</p>
          </form>
        ) : null}

        {plan !== null ? (
          <div className={plan.dangerous ? "docker-action-panel is-dangerous" : "docker-action-panel"}>
            <dl>
              <div><dt>将要执行</dt><dd>{plan.summary}</dd></div>
              <div><dt>操作前状态</dt><dd>{plan.beforeState}</dd></div>
              <div><dt>出错后如何还原</dt><dd>{plan.restoreDescription ?? "这个操作没有自动还原的办法"}</dd></div>
              <div><dt>计划有效期</dt><dd>{planExpiryLabel(plan.expiresInSeconds)}</dd></div>
            </dl>
          </div>
        ) : null}

        {receipt !== null ? (
          <div className={receipt.verified ? "docker-action-panel" : "docker-action-panel is-dangerous"} data-testid="docker-file-receipt">
            <p className="docker-action-summary">{receipt.verified ? "已完成，并在目标上核对过。" : "没有达到预期。"}</p>
            <dl>
              <div><dt>目标反馈</dt><dd>{receipt.detail}</dd></div>
              {receipt.verified ? null : (
                <div><dt>是否已还原</dt><dd>{receipt.restored ? "已还原到操作前的状态" : "没有自动还原，请手动检查"}</dd></div>
              )}
            </dl>
          </div>
        ) : null}

        {notice !== null && error === null && receipt === null && plan === null ? <TransientNotice source="容器文件" message={notice ?? ""} severity="info" inline><p className="docker-action-note" role="status">{notice}</p></TransientNotice> : null}
        {error !== null ? <TransientNotice source="容器文件" message={error ?? ""} severity="error" inline><p className="docker-action-error" role="alert">{error}</p></TransientNotice> : null}

        <footer>
          {plan !== null ? (
            <>
              <button type="button" disabled={busy} onClick={cancelPlan}>取消</button>
              <button type="button" className="is-dangerous" disabled={busy} data-testid="docker-file-execute" onClick={() => void confirmAndRun()}>
                {busy ? "执行中…" : mode === "edit" ? "确认并写入" : "确认并复制"}
              </button>
            </>
          ) : (
            <>
              <button type="button" disabled={busy} onClick={() => void requestClose()}>关闭</button>
              {mode === "edit" ? (
                <button type="button" className="is-primary" disabled={busy || !dirty} onClick={() => void planSave()}>保存</button>
              ) : mode === "copy" ? (
                <button type="button" className="is-primary" disabled={busy || source.trim() === "" || target.trim() === ""} onClick={() => void planCopy()}>生成计划</button>
              ) : null}
            </>
          )}
        </footer>
      </section>
      {discard.dialog !== null ? <DialogHost dialog={discard.dialog} onResolve={discard.resolve} /> : null}
    </div>
  );
}
