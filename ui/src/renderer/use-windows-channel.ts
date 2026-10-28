import { useContext, useEffect, useMemo, useRef, useState } from "react";
import { NotificationContext } from "./NotificationCenter";
import { CHANNEL_COLLECTIONS, type WindowsChannelAction, type WindowsChannelOwnerApi, type WindowsChannelTab, type WindowsChannelView } from "../shared/windows-channel-contract";
import type { useWindowsIncident } from "./use-windows-incident";
import { errorText } from "./error-text";

/** The workspace remains the sole executor. The second window only presents it. */
export function useWindowsChannel(api: WindowsChannelOwnerApi | undefined, data: ReturnType<typeof useWindowsIncident>, suggestion: WindowsChannelView["suggestion"], canSave: boolean) {
  const publish = useContext(NotificationContext);
  const publishRef = useRef(publish); publishRef.current = publish;
  const [owner, setOwner] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const alive = useRef(true);
  const ownerRef = useRef<string | null>(null);
  const opening = useRef<Promise<void> | null>(null);
  const latest = useRef(data); latest.current = data;
  const view = useMemo<WindowsChannelView>(() => ({
    hostname: data.snapshots.overview?.hostname ?? "当前远程会话", connected: data.sessionKey !== null,
    busy: data.busy ?? (data.reconnect?.phase === "verifying" || data.reconnect?.phase === "failed" ? "请先在主窗口核对重新连接的目标" : null), batch: data.batch, history: CHANNEL_COLLECTIONS.map(key => ({ key, time: data.collectedAt[key] ?? null, error: data.collectionErrors[key] ?? null })),
    registered: data.status?.registration.registered ?? false,
    messagesSent: data.status?.messagesSent ?? 0, messagesReceived: data.status?.messagesReceived ?? 0,
    logs: data.status?.recentLogs ?? [], files: data.status?.receivedFiles ?? [],
    savedFiles: (data.status?.receivedFiles ?? []).filter(file => data.savedFiles.has(file.fileId)).map(file => file.fileId),
    canSave, output: data.commandOutput, suggestion,
  }), [data.snapshots.overview, data.sessionKey, data.busy, data.batch, data.collectedAt, data.collectionErrors, data.status, data.savedFiles, data.commandOutput, suggestion, canSave, data.reconnect]);
  const viewRef = useRef(view); viewRef.current = view;
  // Serialize publishes/open so a slow older view never overwrites a newer one.
  const writes = useRef(Promise.resolve());
  function serialize(work: () => Promise<void>) {
    const next = writes.current.then(work); writes.current = next.catch(() => undefined); return next;
  }
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
      void writes.current.then(async () => { if (ownerRef.current) await api?.release(ownerRef.current); }).catch(() => undefined);
    };
  }, [api]);
  const published = useRef<{ metadata: string; output: WindowsChannelView["output"]; session: string | null } | null>(null);
  useEffect(() => {
    const metadata = JSON.stringify({ ...view, output: null });
    const previous = published.current;
    if (previous && previous.metadata === metadata && previous.output === view.output && previous.session === data.sessionKey) return;
    if (api && owner) void serialize(async () => {
      await api.sync(owner, latest.current.sessionKey, viewRef.current);
      published.current = { metadata, output: view.output, session: data.sessionKey };
    })
      .catch(reason => { if (alive.current) latest.current.setError(errorText(reason, "通道窗口同步失败，请重新打开。")); });
  }, [api, owner, view]);

  async function dispatch(action: WindowsChannelAction, session: string | null): Promise<boolean> {
    const current = latest.current;
    if (current.sessionKey !== session) throw new Error("连接已变化，未执行旧窗口提交的操作。");
    switch (action.kind) {
      case "run": if (session) return current.runCommand(action.command, session); return false;
      case "send": return current.sendChat(action.text);
      case "save": return current.saveFile(action.fileId);
      case "collect": return current.collect(action.key);
      case "cancel-batch": current.cancelBatch(); return true;
      case "unregister": return current.localAction("unregister-plugin", "正在移除插件注册…", "当前用户的插件注册已移除。");
    }
  }
  useEffect(() => {
    if (!api || !owner) return;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      try {
        const result = await api!.poll(owner!, true);
        if (stopped) return;
        for (const notice of result.notifications) {
          if (publishRef.current) publishRef.current("通道与传输", notice.message, notice.severity);
          else if (notice.severity === "error") latest.current.setError(notice.message);
          else latest.current.setNotice(notice.message);
        }
        setPending(result.pending);
        if (result.work) {
          let ok = false;
          try { ok = await dispatch(result.work.action, result.work.sessionId); }
          catch (reason) { latest.current.setError(errorText(reason, "通道操作未完成，请重试。")); }
          await api!.finish(owner!, result.work.id, ok);
          if (!stopped) setPending(false);
        }
      } catch (reason) { if (!stopped) latest.current.setError(errorText(reason, "通道窗口已失去连接，请重新打开。")); }
      if (!stopped) timer = setTimeout(() => void poll(), 200);
    }
    void poll();
    return () => { stopped = true; clearTimeout(timer); };
  }, [api, owner]);

  async function open(tab: WindowsChannelTab) {
    if (!api) { data.setError("当前版本无法打开独立通道窗口，请更新桌面程序。"); return; }
    if (opening.current) return opening.current;
    const work = serialize(async () => {
      if (!ownerRef.current) {
        const id = await api.attach(); ownerRef.current = id;
        if (!alive.current) { await api.release(id); ownerRef.current = null; return; }
        setOwner(id);
      }
      await api.sync(ownerRef.current, latest.current.sessionKey, viewRef.current);
      await api.open(ownerRef.current, tab);
    }).catch(reason => { if (alive.current) latest.current.setError(errorText(reason, "通道窗口打开失败。")); });
    opening.current = work;
    await work; opening.current = null;
  }
  async function beforeLeave(ask: (title: string, message: string, action: string) => Promise<boolean>): Promise<boolean> {
    try {
      const current = latest.current;
      const state = api && ownerRef.current ? await api.poll(ownerRef.current, false) : null;
      if (current.busy || state?.pending) { current.setError("Windows 任务尚未结束，请等待返回后再离开。"); return false; }
      const receipts = () => (latest.current.status?.receivedFiles ?? []).filter(file => !latest.current.savedFiles.has(file.fileId)).map(file => file.fileId).join(",");
      const receiptIds = receipts();
      const files = receiptIds ? receiptIds.split(",").length : 0;
      if ((state?.dirty || files) && !(await ask("离开 Windows 工作台？", `${state?.dirty ? "独立通道窗口中有未执行的命令草稿或未发送的消息。离开将关闭该窗口并丢弃草稿。\n" : ""}${files ? `还有 ${files} 个接收文件尚未另存；请先保存需要保留的文件。\n` : ""}已提交的命令不会因关窗撤销。`, "离开工作台"))) return false;
      if (latest.current.busy || receiptIds !== receipts()) throw new Error("确认期间任务或接收文件发生变化，请核对后再离开。");
      if (api && ownerRef.current && state) {
        // Host checks the draft version and pending work atomically before
        // destroying the window; an action arriving during confirmation wins.
        await api.release(ownerRef.current, state.draftRevision);
        ownerRef.current = null; setOwner(null);
      }
      return true;
    } catch (reason) {
      latest.current.setError(errorText(reason, "暂时无法确认通道窗口状态，请保留工作台并重试。")); return false;
    }
  }
  return { open, pending, beforeLeave };
}
