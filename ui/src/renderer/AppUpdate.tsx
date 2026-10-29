import { useEffect, useRef, useState } from "react";
import type { AppDialog, DialogOutcome } from "./dialog-state";
import { DialogHost } from "./DialogHost";
import { errorText } from "./error-text";

/** Lives in App so hiding the status bar or changing pages cannot lose a download. */
export function useAppUpdate() {
  const [version, setVersion] = useState<string | null>(null);
  const [phase, setPhase] = useState<"idle" | "checking" | "downloading">("idle");
  const [progress, setProgress] = useState("");
  const [dialog, setDialog] = useState<AppDialog | null>(null);
  const pendingHandle = useRef<string | null>(null);
  const activeHandle = useRef<string | null>(null);
  const inFlight = useRef(false);
  const mounted = useRef(false);
  const sequence = useRef(0);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const nextId = () => `dialog-${++sequence.current}`;
  const alert = (title: string, message: string) => {
    if (mounted.current) setDialog({ id: nextId(), kind: "alert", title, message });
  };

  useEffect(() => {
    mounted.current = true;
    void window.lovelyhawk.appUpdate({ action: "info" }).then((result) => {
      if (mounted.current && result.kind === "info") setVersion(result.version);
    }).catch(() => { /* The clickable fallback still offers a retry. */ });
    return () => {
      mounted.current = false;
      if (activeHandle.current) void window.lovelyhawk.appUpdate({ action: "cancel", handle: activeHandle.current }).catch(() => undefined);
    };
  }, []);

  async function check() {
    if (inFlight.current) return;
    inFlight.current = true;
    setPhase("checking");
    try {
      const info = await window.lovelyhawk.appUpdate({ action: "info" });
      if (mounted.current && info.kind === "info") setVersion(info.version);
      const result = await window.lovelyhawk.appUpdate({ action: "check" });
      if (!mounted.current || result.kind !== "check") return;
      if (!result.available) {
        alert("检查更新", `GitHub 最新稳定版为 v${result.version}，当前版本无需更新。`);
      } else if (result.handle === null) {
        alert("发现新版本", `GitHub 已发布 v${result.version}，但尚未提供适用于当前平台且带校验文件的便携包。请稍后重试。`);
      } else {
        pendingHandle.current = result.handle;
        setDialog({
          id: nextId(), kind: "confirm", title: `发现新版本 v${result.version}`, confirmLabel: "下载并校验更新包",
          message: `来源：LovelyTeams/LovelyHawk · GitHub Release\n下载后校验 SHA-256。更新前请结束远端任务、保存编辑并关闭程序；解压新版替换程序文件，保留原 data 文件夹。建议先备份整个旧版目录。\n\n${result.notes.slice(0, 4000)}`,
        });
      }
    } catch (reason) { alert("检查更新失败", errorText(reason, "无法检查更新，请稍后重试。")); }
    finally {
      inFlight.current = false;
      if (mounted.current) setPhase("idle");
    }
  }

  async function download(handle: string) {
    if (inFlight.current) return;
    inFlight.current = true;
    activeHandle.current = handle;
    setPhase("downloading");
    setProgress("选择保存位置…");
    let polling = false;
    const timer = setInterval(() => {
      if (polling) return;
      polling = true;
      void window.lovelyhawk.appUpdate({ action: "progress", handle }).then((result) => {
        if (mounted.current && result.kind === "progress" && result.total > 0)
          setProgress(`${Math.floor(result.received / result.total * 100)}%`);
      }).catch(() => undefined).finally(() => { polling = false; });
    }, 500);
    try {
      const result = await window.lovelyhawk.appUpdate({ action: "download", handle });
      if (result.kind === "download" && result.filename !== null) {
        alert("更新包已保存并通过校验", `${result.filename}\n\n结束远端任务、保存编辑并关闭 LovelyHawk 后，解压新版替换程序文件，保留原 data 文件夹。建议先备份旧版目录，以便恢复。\n当前正在运行的版本尚未替换。`);
      }
    } catch (reason) { alert("更新包未保存", errorText(reason, "下载失败，请重新检查更新后重试。")); }
    finally {
      clearInterval(timer);
      activeHandle.current = null;
      inFlight.current = false;
      if (mounted.current) { setPhase("idle"); setProgress(""); }
    }
  }

  async function cancel() {
    const handle = activeHandle.current;
    if (handle === null) return;
    try {
      await window.lovelyhawk.appUpdate({ action: "cancel", handle });
      if (mounted.current) setProgress("正在取消…");
    } catch (reason) { alert("取消下载", errorText(reason, "请先关闭文件选择窗口，再重试取消。")); }
  }

  function resolve(outcome: DialogOutcome) {
    const handle = pendingHandle.current;
    pendingHandle.current = null;
    setDialog(null);
    requestAnimationFrame(() => buttonRef.current?.focus());
    if (outcome.kind === "confirmed" && handle !== null) void download(handle);
  }

  return {
    button: <button ref={buttonRef} type="button" className="statusbar-button" data-testid="app-version"
      disabled={phase === "checking"} title={phase === "downloading" ? "取消更新包下载" : "检查 GitHub Release 更新"}
      aria-haspopup={phase === "idle" ? "dialog" : undefined}
      onClick={() => void (phase === "downloading" ? cancel() : check())}>
      {phase === "checking" ? "检查更新…" : phase === "downloading" ? `下载更新 ${progress} · 取消` : version ? `v${version}` : "版本与更新"}
    </button>,
    dialog: dialog ? <DialogHost dialog={dialog} scrollMessage onResolve={resolve} /> : null,
  };
}
