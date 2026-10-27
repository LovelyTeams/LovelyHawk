import { useCallback, useEffect, useRef, useState } from "react";

import type {
  DvcRuntimeStatus, WindowsProcessInspection, WindowsFileAccess, WindowsFilePreview, WindowsIncidentApi, WindowsRemoteIntent, WindowsIncidentResponse,
} from "../shared/windows-incident-contract";
import { errorText } from "./error-text";
import { CORE_COLLECTION, DEFAULT_FILE_PATH, DEFAULT_REGISTRY_PATH, WIN_IR_MODULES, type CollectedAt, type CollectionTab, type WinIrSnapshots } from "./win-ir-model";

export function windowsSessionKey(status: DvcRuntimeStatus | null): string | null {
  return status?.channelConnected ? status.sessionId : null;
}

/** What a reconnected host is compared on; matching names are a strong hint, not proof of the same machine. */
export interface HostIdentity { hostname: string; domain: string; osVersion: string }

export type ReconnectState =
  | { phase: "verifying"; host: string }
  | { phase: "kept"; host: string }
  | { phase: "replaced"; host: string; previous: string }
  | { phase: "failed"; host: string; message: string };

export function hostIdentity(snapshots: Partial<WinIrSnapshots>): HostIdentity | null {
  const overview = snapshots.overview;
  return overview?.hostname ? { hostname: overview.hostname, domain: overview.domainOrWorkgroup, osVersion: overview.osVersion } : null;
}

export function sameHost(a: HostIdentity, b: HostIdentity): boolean {
  return a.hostname.toLowerCase() === b.hostname.toLowerCase() && a.domain.toLowerCase() === b.domain.toLowerCase() && a.osVersion === b.osVersion;
}

function collectionRequest(tab: CollectionTab, argument: string): WindowsRemoteIntent {
  switch (tab) {
    case "overview": return { action: "collect-overview" };
    case "baseline": return { action: "collect-baseline" };
    case "processes": return { action: "collect-processes" };
    case "network": return { action: "collect-network" };
    case "services": case "drivers": case "tasks": return { action:"collect-inventory",kind:tab };
    case "startup": return { action: "collect-startup" };
    case "accounts": return { action: "collect-accounts" };
    case "logs": return { action: "collect-logs", category: argument };
    case "files": return { action: "collect-files", path: argument };
    case "registry": return { action: "collect-registry", keyPath: argument };
  }
}

/** One operation at a time; status polling continues while a collector runs. */
export function useWindowsIncident(api: WindowsIncidentApi) {
  const [status, setStatus] = useState<DvcRuntimeStatus | null>(null);
  const [filelessScript, setFilelessScript] = useState("");
  const [snapshots, setSnapshots] = useState<Partial<WinIrSnapshots>>({});
  const [collectedAt, setCollectedAt] = useState<CollectedAt>({});
  const [collectionErrors, setCollectionErrors] = useState<Partial<Record<CollectionTab, string>>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [epoch, setEpoch] = useState(0);
  const [snapshotKey, setSnapshotKey] = useState("");
  const [batch, setBatch] = useState<{ done: number; total: number; stopping: boolean } | null>(null);
  const [commandOutput, setCommandOutput] = useState<{ command: string; output: string; time: string } | null>(null);
  const [savedFiles, setSavedFiles] = useState<ReadonlySet<string>>(new Set());
  const live = useRef(false);
  const locked = useRef(false);
  const statusRef = useRef<DvcRuntimeStatus | null>(null);
  const lastSession = useRef<string | null>(null);
  const epochRef = useRef(0);
  const stopBatch = useRef(false);
  const statusSequence = useRef(0);
  const paths = useRef({ files: DEFAULT_FILE_PATH, registry: DEFAULT_REGISTRY_PATH, logs: "all" });
  const snapshotsRef = useRef<Partial<WinIrSnapshots>>({});
  snapshotsRef.current = snapshots;
  /** A new channel to a host collected before keeps its results only once the host is shown to be the same one. */
  const [reconnect, setReconnect] = useState<ReconnectState | null>(null);
  const previousHost = useRef<HostIdentity | null>(null);

  const clearResults = useCallback((sessionKey: string) => {
    setSnapshotKey(`${sessionKey}:${epochRef.current}`);
    setSnapshots({});
    setCollectedAt({});
    setCollectionErrors({});
    setCommandOutput(null);
    setNotice(null);
    paths.current = { files: DEFAULT_FILE_PATH, registry: DEFAULT_REGISTRY_PATH, logs: "all" };
  }, []);

  const observe = useCallback((next: DvcRuntimeStatus | null) => {
    const previous = windowsSessionKey(statusRef.current);
    const nextKey = windowsSessionKey(next);
    statusRef.current = next;
    if (!live.current) return;
    if (previous !== nextKey) {
      epochRef.current += 1;
      setEpoch(epochRef.current);
      stopBatch.current = true;
      if (nextKey !== null && nextKey !== lastSession.current) {
        const host = hostIdentity(snapshotsRef.current);
        const hadSession = lastSession.current !== null;
        lastSession.current = nextKey;
        if (hadSession && host) {
          previousHost.current = host;
          setReconnect({ phase: "verifying", host: host.hostname });
        } else {
          previousHost.current = null;
          setReconnect(null);
          clearResults(nextKey);
        }
      }
    }
    setStatus(next);
  }, [clearResults]);

  const refresh = useCallback(async () => {
    const sequence = ++statusSequence.current;
    const response = await api.windowsIncident({ action: "status" });
    if (response.kind !== "status") throw new Error("无法读取连接状态。");
    if (live.current && sequence === statusSequence.current) {
      observe(response.status);
      setFilelessScript(response.filelessScript);
      setStatusError(null);
    }
    return response.status;
  }, [api, observe]);

  useEffect(() => {
    live.current = true;
    let disposed = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    async function poll() {
      try { await refresh(); } catch {
        if (!disposed) {
          observe(null);
          setStatusError("暂时无法核实连接状态，已暂停远程操作；正在重试。");
        }
      }
      if (!disposed) timer = setTimeout(() => void poll(), 2000);
    }
    void poll();
    return () => {
      disposed = true;
      live.current = false;
      statusSequence.current += 1;
      epochRef.current += 1;
      stopBatch.current = true;
      clearTimeout(timer);
    };
  }, [observe, refresh]);

  const start = useCallback((label: string) => {
    if (locked.current || !live.current) return false;
    locked.current = true;
    setBusy(label); setError(null); setNotice(null);
    return true;
  }, []);
  const finish = useCallback(() => {
    locked.current = false;
    if (live.current) { setBusy(null); setBatch(null); }
  }, []);

  const remote = useCallback(async (request: WindowsRemoteIntent, expectedEpoch: number) => {
    const expected = windowsSessionKey(statusRef.current);
    if (!expected || expectedEpoch !== epochRef.current) throw new Error("连接已变化，请确认当前目标后重试。");
    const before = await refresh();
    if (!live.current || expectedEpoch !== epochRef.current || windowsSessionKey(before) !== expected) throw new Error("连接已变化，本次操作未继续。");
    const response = await api.windowsIncident({ ...request, sessionId: expected });
    const after = await refresh();
    if (!live.current || expectedEpoch !== epochRef.current || windowsSessionKey(after) !== expected) throw new Error("采集期间连接发生变化，已忽略返回结果，请重新采集。");
    return response;
  }, [api, refresh]);

  const acceptCollection = useCallback((tab: CollectionTab, response: WindowsIncidentResponse) => {
    if (!("snapshot" in response) || (response.kind !== tab && !(response.kind === "inventory" && response.snapshot.kind === tab))) throw new Error("采集结果类型不符，请重试。");
    setSnapshots((previous) => ({ ...previous, [tab]: response.snapshot }));
    setCollectedAt((previous) => ({ ...previous, [tab]: new Date().toISOString() }));
    setCollectionErrors((previous) => { const next = { ...previous }; delete next[tab]; return next; });
    if (response.kind === "files") paths.current.files = response.snapshot.currentPath;
    if (response.kind === "registry") paths.current.registry = response.snapshot.keyPath;
    if (response.kind === "logs") paths.current.logs = response.snapshot.categoryFilter;
  }, []);

  const collect = useCallback(async (tab: CollectionTab, argument?: string): Promise<boolean> => {
    const label = WIN_IR_MODULES.find((module) => module.key === tab)?.label ?? tab;
    if (!start(`正在采集${label}…`)) return false;
    const generation = epochRef.current;
    try {
      const arg = argument ?? (tab === "files" || tab === "registry" || tab === "logs" ? paths.current[tab] : "");
      const response = await remote(collectionRequest(tab, arg), generation);
      acceptCollection(tab, response);
      return true;
    } catch (reason) {
      if (live.current) {
        const message = errorText(reason, "采集未完成，请核对连接和远程账户权限后重试。");
        setError(message);
        if (generation === epochRef.current) setCollectionErrors((previous) => ({ ...previous, [tab]: message }));
      }
      return false;
    } finally { finish(); }
  }, [acceptCollection, finish, remote, start]);

  /** After a reconnect, results stay only if the new channel reaches the same host. */
  const verifyReconnect = useCallback(async () => {
    const expected = previousHost.current;
    if (!expected || !start(`正在核对重新连接的主机 ${expected.hostname}…`)) return;
    const generation = epochRef.current;
    try {
      const response = await remote({ action: "collect-overview" }, generation);
      if (response.kind !== "overview") throw new Error("采集结果类型不符，请重试。");
      const current = { hostname: response.snapshot.hostname, domain: response.snapshot.domainOrWorkgroup, osVersion: response.snapshot.osVersion };
      if (!sameHost(expected, current)) {
        clearResults(windowsSessionKey(statusRef.current) ?? "");
        setReconnect({ phase: "replaced", host: current.hostname, previous: expected.hostname });
      } else setReconnect({ phase: "kept", host: current.hostname });
      acceptCollection("overview", response);
      previousHost.current = null;
    } catch (reason) {
      if (live.current && generation === epochRef.current) setReconnect({ phase: "failed", host: expected.hostname, message: errorText(reason, "核对未完成，请重试。") });
    } finally { finish(); }
  }, [acceptCollection, clearResults, finish, remote, start]);
  useEffect(() => {
    if (reconnect?.phase === "verifying" && windowsSessionKey(status) !== null && busy === null) void verifyReconnect();
  }, [busy, reconnect, status, verifyReconnect]);
  const retryReconnect = useCallback(() => setReconnect((current) => current?.phase === "failed" ? { phase: "verifying", host: current.host } : current), []);
  const discardPrevious = useCallback(() => {
    previousHost.current = null;
    setReconnect(null);
    clearResults(windowsSessionKey(statusRef.current) ?? "");
  }, [clearResults]);
  const dismissReconnect = useCallback(() => setReconnect((current) => current?.phase === "kept" || current?.phase === "replaced" ? null : current), []);

  const collectAll = useCallback(async () => {
    if (!start("正在准备采集核心模块…")) return;
    const generation = epochRef.current;
    stopBatch.current = false;
    let succeeded = 0;
    let failed = 0;
    setBatch({ done: 0, total: CORE_COLLECTION.length, stopping: false });
    try {
      for (const tab of CORE_COLLECTION) {
        if (stopBatch.current || !live.current || generation !== epochRef.current) break;
        const label = WIN_IR_MODULES.find((module) => module.key === tab)?.label;
        setBusy(`正在采集${label}（${succeeded + failed + 1}/${CORE_COLLECTION.length}）…`);
        try {
          acceptCollection(tab, await remote(collectionRequest(tab, tab === "logs" ? "all" : ""), generation));
          succeeded += 1;
        } catch (reason) {
          if (!live.current || generation !== epochRef.current) break;
          failed += 1;
          const message = errorText(reason, "采集失败，请重试。");
          setCollectionErrors((previous) => ({ ...previous, [tab]: message }));
        }
        if (live.current) setBatch((previous) => previous ? { ...previous, done: succeeded + failed } : null);
      }
      if (live.current && generation === epochRef.current) {
        setNotice(`本轮采集：${succeeded} 项完成，${failed} 项失败，${CORE_COLLECTION.length - succeeded - failed} 项未执行。`);
      } else if (live.current) setError("连接发生变化，本轮采集已停止。");
    } finally { finish(); }
  }, [acceptCollection, finish, remote, start]);

  const localAction = useCallback(async (
    action: "register-plugin" | "unregister-plugin" | "start-listener" | "open-remote-desktop" | "reveal-agent",
    label: string, completed: string,
  ) => {
    if (!start(label)) return;
    try {
      const response = await api.windowsIncident({ action });
      if (live.current && response.kind === "status") {
        observe(response.status); setFilelessScript(response.filelessScript); setNotice(completed);
      }
    } catch (reason) { if (live.current) setError(errorText(reason, "操作未完成，请重试。")); }
    finally { finish(); }
  }, [api, finish, observe, start]);

  const previewFile = useCallback(async (path: string): Promise<WindowsFilePreview> => {
    if (!start("正在读取文件预览…")) throw new Error("另一项操作正在进行，请稍后重试。");
    try {
      const response = await remote({ action: "preview-file", path }, epochRef.current);
      if (response.kind !== "file-preview") throw new Error("无法读取文件预览。");
      return response.preview;
    } finally { finish(); }
  }, [finish, remote, start]);

  const inspectFileAccess = useCallback(async (path: string): Promise<WindowsFileAccess> => {
    if (!start("正在只读查询文件权限、进程与服务 / 驱动路径…")) throw new Error("另一项查询正在进行。");
    try { const response = await remote({ action: "inspect-file-access", path }, epochRef.current); if (response.kind !== "file-access") throw new Error("文件诊断结果无效。"); return response.inspection; }
    finally { finish(); }
  }, [finish, remote, start]);

  const inspectProcess = useCallback(async (pid: number, startTime: string): Promise<WindowsProcessInspection> => {
    if (!start("正在核对进程身份并读取网络、服务与 DLL…")) throw new Error("另一项查询正在进行。");
    try {
      const response = await remote({ action: "inspect-process", pid, startTime }, epochRef.current);
      if (response.kind !== "process-inspection") throw new Error("进程关联结果无效。");
      return response.inspection;
    } finally { finish(); }
  }, [finish, remote, start]);

  const pullFile = useCallback(async (path: string) => {
    if (!start("正在拉取文件并核对完整性…")) return false;
    try {
      const response = await remote({ action: "pull-file", remotePath: path }, epochRef.current);
      if (response.kind === "status") {
        observe(response.status);
        setNotice("文件已接收到缓存，SHA256 校验通过。点击「接收与保存」可另存到本机。");
        return true;
      }
      return false;
    } catch (reason) { if (live.current) setError(errorText(reason, "文件拉取失败，请检查大小和读取权限。")); return false; }
    finally { finish(); }
  }, [finish, observe, remote, start]);

  const saveFile = useCallback(async (fileId: string) => {
    if (!api.saveWindowsFile || !start("正在核对文件并准备另存…")) return;
    try {
      const result = await api.saveWindowsFile(fileId);
      if (live.current) {
        if (result.saved) {
          setSavedFiles((previous) => new Set([...previous, fileId]));
          setNotice(`已另存为 ${result.fileName}，文件 SHA256 已复核。`);
        } else setNotice("已取消另存，文件仍保留在接收缓存中。");
      }
    } catch (reason) {
      if (live.current) setError(errorText(reason, "文件未保存；缓存仍可重试，请选择新的文件名以避免覆盖。"));
    } finally { finish(); }
  }, [api, finish, start]);

  const sendChat = useCallback(async (text: string) => {
    if (!start("正在发送消息…")) return false;
    try {
      const response = await remote({ action: "send-chat", text }, epochRef.current);
      if (response.kind === "status") observe(response.status);
      setNotice("消息已提交至当前会话通道。");
      return true;
    } catch (reason) { if (live.current) setError(errorText(reason, "消息未发送。")); return false; }
    finally { finish(); }
  }, [finish, observe, remote, start]);

  const runCommand = useCallback(async (command: string, expectedSession: string) => {
    if (windowsSessionKey(statusRef.current) !== expectedSession) {
      setError("确认期间会话发生变化，请核对目标后重新确认。"); return;
    }
    if (!start("正在等待远程命令返回…")) return;
    try {
      const response = await remote({ action: "run-command", command }, epochRef.current);
      if (response.kind === "command-output") {
        setCommandOutput({ command, output: response.output, time: new Date().toISOString() });
        observe(response.status);
      }
    } catch (reason) { if (live.current) setError(errorText(reason, "命令未完成，请核对远程状态。")); }
    finally { finish(); }
  }, [finish, observe, remote, start]);

  const dispose = useCallback(async (
    tab: CollectionTab,
    request: WindowsRemoteIntent,
    expectedSession: string,
    busyLabel: string,
    doneNotice: string,
  ): Promise<boolean> => {
    if (windowsSessionKey(statusRef.current) !== expectedSession) {
      setError("确认期间会话发生变化，请核对目标后重新确认。");
      return false;
    }
    if (!start(busyLabel)) return false;
    try {
      const response = await remote(request, epochRef.current);
      acceptCollection(tab, response);
      if (live.current) setNotice(doneNotice);
      return true;
    } catch (reason) {
      if (live.current) setError(errorText(reason, "远程处置未完成，请核对连接和远程账户权限后重试。"));
      return false;
    } finally { finish(); }
  }, [acceptCollection, finish, remote, start]);

  const baselineRequest = useCallback(async (request: WindowsRemoteIntent, expectedSession: string, label?: string) => {
    if (windowsSessionKey(statusRef.current) !== expectedSession) throw new Error("连接已变化，请重新读取并预览计划。");
    if (label && !start(label)) throw new Error("当前任务尚未结束。");
    try {
      const response = await remote(request, epochRef.current);
      if (response.kind === "baseline-change-error") throw new Error(response.message);
      return response;
    } finally { if (label) finish(); }
  }, [finish, remote, start]);

  return {
    status, filelessScript, snapshots, collectedAt, collectionErrors, busy, error, statusError, notice, epoch, snapshotKey, batch, commandOutput, savedFiles, saveFile, baselineRequest,
    sessionKey: windowsSessionKey(status), reconnect, retryReconnect, discardPrevious, dismissReconnect, collect, collectAll, refresh, localAction, previewFile, inspectFileAccess, inspectProcess, pullFile, sendChat, runCommand, dispose,
    cancelBatch: () => { stopBatch.current = true; setBatch((previous) => previous ? { ...previous, stopping: true } : null); },
    setNotice, setError, dismissNotice: () => setNotice(null), dismissError: () => setError(null),
  };
}
