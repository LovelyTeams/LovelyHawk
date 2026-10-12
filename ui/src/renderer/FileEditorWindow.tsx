import { useEffect, useRef, useState } from "react";

import {
  isSftpOperationPlan,
  isSftpOperationReceipt,
  isSftpTextPreview,
  type SftpOperationPlan,
  type SftpOperationReceipt,
  type SftpTextPreview,
} from "../shared/sftp-browser-contract";
import { isFileEditorTarget, type FileEditorTarget } from "../shared/terminal-contract";
import { DialogHost } from "./DialogHost";
import { useModalScrim } from "./modal-scrim";
import { useConfirmDialog } from "./use-confirm-dialog";
import { WindowControls } from "./WindowControls";
import "./file-editor.css";

type LoadStatus = "loading" | "ready" | "error";

/**
 * One remote file, in a window of its own.
 *
 * It replaces the preview panel that used to sit under the file table, which
 * had a third of the pane and could still only show a dozen wrapped lines. The
 * same window serves 预览 and 编辑; the difference is whether it was opened
 * with permission to write, which main decides and this renderer cannot change.
 *
 * Saving is never one click. The write is planned first, the plan says in
 * words what is about to happen to which file, and only then is it confirmed
 * and run — the same three steps every other change in this app goes through.
 */
export function FileEditorWindow() {
  const api = window.lovelyhawkTerminal;
  const [target, setTarget] = useState<FileEditorTarget | null>(null);
  const [status, setStatus] = useState<LoadStatus>("loading");
  const [error, setError] = useState<string | null>(null);
  const [original, setOriginal] = useState<SftpTextPreview | null>(null);
  const [text, setText] = useState("");
  const [plan, setPlan] = useState<SftpOperationPlan | null>(null);
  const [receipt, setReceipt] = useState<SftpOperationReceipt | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  // A save is a remote write; a second click landing before state moves would
  // be a second write.
  const busyRef = useRef(false);
  const [busy, setBusy] = useState(false);
  const confirmClose = useConfirmDialog();
  const closingRef = useRef(false);
  // The confirmation below is a modal; the window chrome dims while it is up.
  useModalScrim(plan !== null);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const resolved = await api.fileEditorTarget();
        if (!isFileEditorTarget(resolved)) throw new Error();
        if (cancelled) return;
        setTarget(resolved);
        const read = await api.readSftpText(resolved.browserHandle, resolved.entryHandle);
        if (!isSftpTextPreview(read) || read.fileHandle !== resolved.entryHandle) throw new Error();
        if (cancelled) return;
        setOriginal(read);
        setText(read.text);
        setStatus("ready");
      } catch {
        if (cancelled) return;
        setStatus("error");
        setError("读不到这个文件：可能不是 UTF-8 文本、超出了可编辑的大小，或者连接已经断了。");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [api]);

  // Saving is offered only when what is on screen is the file. A truncated
  // read is missing its tail, and a read that was not exact had a line ending
  // or a control character changed on the way here — writing either back would
  // save the reader's change rather than the operator's.
  const truncated = original?.truncated === true;
  const faithful = original?.exact === true;
  const editable = target?.editable === true && faithful;
  const dirty = original !== null && text !== original.text;

  async function planSave() {
    if (busyRef.current || target === null || original === null || !editable) return;
    busyRef.current = true;
    setBusy(true);
    setSaveError(null);
    setReceipt(null);
    try {
      const drafted = await api.planSftpOperation(target.browserHandle, {
        kind: "write-text",
        entryHandles: [target.entryHandle],
        text,
        expectedSha256: original.sha256,
      });
      if (!isSftpOperationPlan(drafted)) throw new Error();
      setPlan(drafted);
    } catch {
      setSaveError("没能准备好这次保存：文件可能已经被别人改过，或者会话已经过期。");
    } finally {
      busyRef.current = false;
      setBusy(false);
    }
  }

  async function runSave() {
    const pending = plan;
    if (busyRef.current || pending === null) return;
    busyRef.current = true;
    setBusy(true);
    try {
      // Approval and execution stay two calls: nothing is written until the
      // sidecar has recorded that the operator pressed this button.
      await api.confirmSftpOperation(pending.planHandle);
      const done = await api.executeSftpOperation(pending.planHandle);
      if (!isSftpOperationReceipt(done)) throw new Error();
      setReceipt(done);
      setPlan(null);
      if (done.passed) {
        // Re-read rather than assume: the file now has a new hash, and the
        // next save has to be checked against that one.
        const read = await api.readSftpText(target!.browserHandle, target!.entryHandle);
        if (isSftpTextPreview(read)) {
          setOriginal(read);
          setText(read.text);
        }
      }
    } catch {
      setSaveError("保存没有完成，服务器上的文件请再确认一次。");
      setPlan(null);
    } finally {
      busyRef.current = false;
      setBusy(false);
    }
  }

  function cancelSave() {
    const pending = plan;
    if (pending !== null) void api.cancelSftpOperation(pending.planHandle).catch(() => {});
    setPlan(null);
  }

  // The host holds a close from outside the page (Alt+F4, the taskbar) while
  // this window has unsaved text, and asks below instead.
  useEffect(() => {
    void api.setUnsavedChanges(dirty).catch(() => undefined);
  }, [api, dirty]);

  // Closing drops whatever was typed here, and a save still on its way would
  // finish with nobody left to read whether it passed review.
  async function confirmLeave(): Promise<boolean> {
    return busyRef.current
      ? confirmClose.ask(
        "保存还没有完成",
        "现在关闭将看不到这次保存是否写入并通过复核，之后需要重新打开文件核对服务器上的内容。",
        "仍然关闭",
      )
      : !dirty || confirmClose.ask(
        "放弃未保存的修改？",
        "这个文件有还没保存到服务器的修改，关闭窗口后这些修改会丢失。",
        "放弃修改并关闭",
      );
  }

  async function requestClose() {
    if (closingRef.current) return;
    closingRef.current = true;
    try {
      if (!(await confirmLeave())) return;
      // Told first, so the close that follows is not held and asked again.
      await api.setUnsavedChanges(false).catch(() => undefined);
      await window.lovelyhawkWindow.close();
    } finally {
      closingRef.current = false;
    }
  }

  const confirmLeaveRef = useRef(confirmLeave);
  confirmLeaveRef.current = confirmLeave;
  useEffect(() => api.onBeforeClose(async () => {
    if (closingRef.current) return false;
    closingRef.current = true;
    try {
      return await confirmLeaveRef.current();
    } finally {
      closingRef.current = false;
    }
  }), [api]);

  return (
    <main className="file-editor">
      <header className="file-editor-bar" data-tauri-drag-region="deep">
        <div className="file-editor-identity">
          <strong>{target?.name ?? "文件"}</strong>
          <span>
            {status === "loading" ? "正在读取…"
              : status === "error" ? "读取失败"
                : !target?.editable ? "只读预览"
                  : !faithful ? "只能查看"
                    : dirty ? "已修改，未保存" : "已是服务器上的内容"}
          </span>
        </div>
        <div className="file-editor-actions">
          {editable && (
            <button
              type="button"
              className="file-editor-save"
              disabled={busy || !dirty}
              onClick={() => void planSave()}
            >
              保存
            </button>
          )}
          <button type="button" data-testid="file-editor-close" onClick={() => void requestClose()}>关闭</button>
        </div>
        <WindowControls onClose={() => void requestClose()} />
      </header>

      {status === "error" && <p className="file-editor-error" role="alert">{error}</p>}
      {saveError !== null && <p className="file-editor-error" role="alert">{saveError}</p>}
      {target?.editable === true && !faithful && (
        <p className="file-editor-notice" role="status">
          {truncated
            ? `这个文件太长，只读出了前 ${original?.displayedLineCount} 行（共 ${original?.observedLineCount} 行）。` +
              "正因为看到的不是全部，这里不允许保存——那会把没读到的部分整段删掉。"
            : "这个文件里有显示不出来的内容（比如 Windows 换行或控制字符），屏幕上看到的和文件里的并不完全一样。" +
              "这里不允许保存——存下去改的会是显示时的那份，不是你改的那份。"}
        </p>
      )}
      {receipt !== null && (
        <p className={receipt.passed ? "file-editor-notice" : "file-editor-error"} role="status">
          {receipt.passed ? "已写回服务器并复核通过。" : "写入没有通过复核。"}
          {receipt.restored ? "原文件已从备份恢复。" : ""}
          {receipt.detail}
        </p>
      )}

      <textarea
        className="file-editor-text"
        aria-label={target?.name ?? "文件内容"}
        spellCheck={false}
        readOnly={!editable}
        value={text}
        onChange={(event) => setText(event.currentTarget.value)}
      />

      <footer className="file-editor-status">
        <span>{text.length} 个字符</span>
        {original !== null && <span>{original.observedLineCount} 行</span>}
      </footer>

      {plan !== null && (
        <div className="file-editor-backdrop" role="presentation">
          <div className="file-editor-dialog" role="dialog" aria-modal="true" aria-label="确认保存">
            <h2>确认保存</h2>
            <p className="file-editor-plan">{plan.summary}</p>
            {plan.restoreDescription !== null && (
              <p className="file-editor-restore">出问题时：{plan.restoreDescription}</p>
            )}
            <div className="file-editor-dialog-actions">
              <button type="button" onClick={cancelSave} disabled={busy}>取消</button>
              <button
                type="button"
                className="file-editor-save"
                onClick={() => void runSave()}
                disabled={busy}
              >
                {busy ? "写入中…" : "确认写入"}
              </button>
            </div>
          </div>
        </div>
      )}
      {confirmClose.dialog !== null && (
        <DialogHost dialog={confirmClose.dialog} onResolve={confirmClose.resolve} />
      )}
    </main>
  );
}
