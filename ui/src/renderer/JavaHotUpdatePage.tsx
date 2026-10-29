import { TransientNotice } from "./NotificationCenter";
import { useEffect, useMemo, useRef, useState } from "react";

import {
  isJavaClassStageResult,
  isTypedJarPath,
  matchesJavaHotUpdateResponse,
  type JavaHistory,
  type JavaHotUpdateApi,
  type JavaHotUpdateRequest,
  type JavaHotUpdateResponse,
  type JavaJar,
  type JavaJarOffer,
  type JavaPlan,
  type JavaReceipt,
  type JavaRecord,
  type JavaScan,
  type JavaStagedClass,
} from "../shared/java-hot-update-contract";
import { errorText } from "./error-text";
import { useModalScrim } from "./modal-scrim";
import { planExpiryLabel } from "./plan-expiry";
import "./java-hot-update.css";

const SHOWN_CLASSES = 200;
const SHOWN_JARS = 200;

export interface JavaHotUpdatePageProps {
  bindingHandle: string | null;
  api: JavaHotUpdateApi;
}

type Busy = "scan" | "inspect" | "stage" | "plan" | "history" | null;

interface PlanDialogState {
  plan: JavaPlan;
  receipt: JavaReceipt | null;
  running: boolean;
  error: string | null;
}

/**
 * Replace one class inside a JAR a running JVM uses: scan the JVMs, open one
 * of their JARs, pick the class and the replacement file, read the plan,
 * confirm it, and see what was checked afterwards. Every applied change is
 * kept as a record that can put the original JAR back.
 */
export function JavaHotUpdatePage({ bindingHandle, api }: JavaHotUpdatePageProps) {
  const [scan, setScan] = useState<JavaScan | null>(null);
  const [jar, setJar] = useState<JavaJar | null>(null);
  const [jarFilter, setJarFilter] = useState("");
  // Shows only the JARs of one process; null shows every process's.
  const [jarProcess, setJarProcess] = useState<number | null>(null);
  const [typedPath, setTypedPath] = useState("");
  const [typedError, setTypedError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [entry, setEntry] = useState<string | null>(null);
  const [staged, setStaged] = useState<JavaStagedClass | null>(null);
  const [history, setHistory] = useState<JavaHistory | null>(null);
  const [busy, setBusy] = useState<Busy>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [dialog, setDialog] = useState<PlanDialogState | null>(null);
  // A click while a request is on its way would send a second one.
  const inFlight = useRef(false);
  const bindingRef = useRef(bindingHandle);
  bindingRef.current = bindingHandle;

  useEffect(() => {
    setScan(null);
    setJar(null);
    setJarFilter("");
    setJarProcess(null);
    setTypedPath("");
    setTypedError(null);
    setFilter("");
    setEntry(null);
    setStaged(null);
    setHistory(null);
    setBusy(null);
    setError(null);
    setNotice(null);
    setDialog(null);
    inFlight.current = false;
    // The records are kept on this machine: reading them touches nothing on the target.
    if (bindingHandle !== null) void loadHistory(bindingHandle);
  }, [bindingHandle]);

  /** Sends one request; answers for a target that is no longer current are dropped. */
  async function send<T extends JavaHotUpdateResponse>(request: JavaHotUpdateRequest): Promise<T | null> {
    const binding = request.bindingHandle;
    const response = await api.javaHotUpdate(request);
    if (bindingRef.current !== binding) return null;
    if (!matchesJavaHotUpdateResponse(request, response)) throw new Error("Java 热更新返回了无法核实的结果，请重新扫描。");
    return response as T;
  }

  async function guarded(kind: Exclude<Busy, null>, work: (binding: string) => Promise<void>, failure: string) {
    if (bindingHandle === null || inFlight.current) return;
    const binding = bindingHandle;
    inFlight.current = true;
    setBusy(kind);
    setError(null);
    setNotice(null);
    try {
      await work(binding);
    } catch (reason) {
      if (bindingRef.current === binding) setError(errorText(reason, failure));
    } finally {
      if (bindingRef.current === binding) {
        inFlight.current = false;
        setBusy(null);
      }
    }
  }

  async function loadHistory(binding: string) {
    try {
      const result = await send<JavaHistory>({ action: "history", bindingHandle: binding });
      if (result !== null) setHistory(result);
    } catch {
      if (bindingRef.current === binding) setHistory(null);
    }
  }

  function scanJvms() {
    void guarded("scan", async (binding) => {
      const result = await send<JavaScan>({ action: "scan", bindingHandle: binding });
      if (result === null) return;
      setScan(result);
      setJar(null);
      setEntry(null);
      // The process picked last time may be gone; the text filter is the operator's and stays.
      setJarProcess(null);
    }, "没能扫描 Java 进程。");
  }

  function openJar(jarHandle: string) {
    if (scan === null) return;
    const snapshotHandle = scan.snapshotHandle;
    void guarded("inspect", async (binding) => {
      const result = await send<JavaJar>({ action: "inspect", bindingHandle: binding, snapshotHandle, jarHandle });
      if (result === null) return;
      setJar(result);
      setEntry(null);
      setFilter("");
    }, "没能打开这个 JAR。");
  }

  /**
   * Reads a JAR the scan did not list; the backend checks the path again. A
   * refusal is shown beside the field it came from, with what usually causes it.
   */
  function openTypedJar() {
    if (scan === null || !isTypedJarPath(typedPath)) return;
    const snapshotHandle = scan.snapshotHandle;
    const path = typedPath;
    setTypedError(null);
    void guarded("inspect", async (binding) => {
      try {
        const result = await send<JavaJar>({ action: "inspect-path", bindingHandle: binding, snapshotHandle, path });
        if (result === null) return;
        setJar(result);
        setEntry(null);
        setFilter("");
      } catch (reason) {
        if (bindingRef.current !== binding) return;
        setTypedError(reason instanceof Error && reason.message.endsWith("(java-hot-update-failed)")
          ? "没能打开这个路径。请确认它存在、是普通文件而不是符号链接、当前账号能读取，并且确实是 JAR。"
          : errorText(reason, "没能打开这个路径。"));
      }
    }, "没能打开这个路径。");
  }

  function chooseClass() {
    void guarded("stage", async (binding) => {
      const result = await api.stageJavaClass(binding);
      if (bindingRef.current !== binding) return;
      if (!isJavaClassStageResult(result)) throw new Error("所选类文件的结果无法核实。");
      if (!result.staged) {
        setNotice("没有选择文件。");
        return;
      }
      // A file chosen earlier and not used is let go.
      const previous = staged;
      setStaged(result.class);
      if (previous !== null) {
        void send({ action: "discard-staged", bindingHandle: binding, stagedHandle: previous.stagedHandle }).catch(() => undefined);
      }
    }, "没能读取所选的类文件。");
  }

  function discardStaged() {
    if (bindingHandle === null || staged === null) return;
    const handle = staged.stagedHandle;
    setStaged(null);
    void send({ action: "discard-staged", bindingHandle, stagedHandle: handle }).catch(() => undefined);
  }

  function makePlan() {
    if (scan === null || jar === null || entry === null || staged === null) return;
    const request = {
      snapshotHandle: scan.snapshotHandle,
      jarHandle: jar.jarHandle,
      entry,
      stagedHandle: staged.stagedHandle,
    };
    void guarded("plan", async (binding) => {
      // The staged file now belongs to the plan, whatever happens to it.
      setStaged(null);
      const plan = await send<JavaPlan>({ action: "plan", bindingHandle: binding, ...request });
      if (plan === null) return;
      setDialog({ plan, receipt: null, running: false, error: null });
    }, "没能生成替换计划。");
  }

  function planRestore(record: JavaRecord) {
    void guarded("plan", async (binding) => {
      const plan = await send<JavaPlan>({ action: "plan-restore", bindingHandle: binding, recordId: record.recordId });
      if (plan === null) return;
      setDialog({ plan, receipt: null, running: false, error: null });
    }, "没能生成恢复计划。");
  }

  async function confirmAndRun() {
    if (bindingHandle === null || dialog === null || dialog.running || dialog.receipt !== null || inFlight.current) return;
    const binding = bindingHandle;
    const planHandle = dialog.plan.planHandle;
    inFlight.current = true;
    setDialog({ ...dialog, running: true, error: null });
    try {
      const confirmed = await send<JavaPlan>({ action: "confirm", bindingHandle: binding, planHandle });
      if (confirmed === null) return;
      const receipt = await send<JavaReceipt>({ action: "execute", bindingHandle: binding, planHandle });
      if (receipt === null) return;
      setDialog((current) => current === null ? null : { ...current, receipt, running: false });
      void loadHistory(binding);
    } catch (reason) {
      if (bindingRef.current === binding) {
        setDialog((current) => current === null ? null : {
          ...current,
          running: false,
          error: errorText(reason, "没能执行这个计划；JAR 的当前内容请重新打开核对。"),
        });
      }
    } finally {
      if (bindingRef.current === binding) inFlight.current = false;
    }
  }

  function closeDialog() {
    if (dialog === null || dialog.running) return;
    const { plan, receipt } = dialog;
    setDialog(null);
    if (receipt === null && bindingHandle !== null) {
      // Declined: the plan is dropped so it can never run later.
      void send({ action: "cancel", bindingHandle, planHandle: plan.planHandle }).catch(() => undefined);
      setNotice(plan.operation === "update" ? "已取消，JAR 没有被改动。" : "已取消恢复，JAR 保持现状。");
      return;
    }
    // After a change the JAR is opened again so its hash on screen is the current one.
    if (receipt !== null && jar !== null && scan !== null && receipt.jarPath === jar.path) openJar(jar.jarHandle);
  }

  const shownJars = useMemo(() => {
    if (scan === null) return { rows: [] as (JavaJarOffer & { pids: number[] })[], matched: 0 };
    const users = new Map<string, number[]>();
    for (const process of scan.processes) {
      for (const handle of process.jarHandles) users.set(handle, [...(users.get(handle) ?? []), process.pid]);
    }
    const needle = jarFilter.trim().toLowerCase();
    const matched = scan.jars.filter((offer) =>
      (jarProcess === null || (users.get(offer.jarHandle) ?? []).includes(jarProcess)) &&
      (needle === "" || offer.path.toLowerCase().includes(needle)));
    return {
      rows: matched.slice(0, SHOWN_JARS).map((offer) => ({ ...offer, pids: users.get(offer.jarHandle) ?? [] })),
      matched: matched.length,
    };
  }, [scan, jarFilter, jarProcess]);

  const shownClasses = useMemo(() => {
    if (jar === null) return { rows: [] as string[], matched: 0 };
    const needle = filter.trim().toLowerCase();
    const matched = needle === "" ? jar.classes : jar.classes.filter((name) => name.toLowerCase().includes(needle));
    return { rows: matched.slice(0, SHOWN_CLASSES), matched: matched.length };
  }, [jar, filter]);

  if (bindingHandle === null) {
    return (
      <section className="page java-hot-update-page">
        <header className="page-heading"><div><p className="eyebrow">运维</p><h1>Java 热更新</h1>
          <p>连接目标后，在这里找到正在运行的 Java 进程，替换它所用 JAR 里的单个类文件。</p></div></header>
      </section>
    );
  }

  const jarTool = scan?.tools.find((tool) => tool.tool === "jar")?.available ?? null;
  return (
    <section className="page java-hot-update-page" aria-busy={busy !== null}>
      <header className="page-heading">
        <div>
          <p className="eyebrow">运维</p>
          <h1>Java 热更新</h1>
          <p>替换磁盘 JAR 中的类文件；运行中的 JVM 需重启后生效。</p>
        </div>
        <button type="button" data-testid="java-scan" disabled={busy !== null} onClick={scanJvms}>
          {busy === "scan" ? "扫描中…" : scan === null ? "扫描 Java 进程" : "重新扫描"}
        </button>
      </header>

      {error === null ? null : <TransientNotice source="Java 更新" message={error ?? ""} severity="error"><p className="java-error" role="alert">{error}</p></TransientNotice>}
      {notice === null ? null : <TransientNotice source="Java 更新" message={notice ?? ""} severity="info"><p className="java-notice" role="status">{notice}</p></TransientNotice>}

      {scan === null ? (
        <p className="java-empty">{busy === "scan" ? "正在列出 Java 进程和可用的 JDK 工具…" : "先扫描这台主机上的 Java 进程。扫描只读取进程列表和 Java 版本，不改动任何东西。"}</p>
      ) : (
        <>
          <section className="java-section" aria-label="Java 环境">
            <h2>Java 环境</h2>
            <p>{scan.version ?? "没有读到 Java 版本：找不到可用的 java 命令"}</p>
            <p className="java-count">工具先在登录环境的 PATH 里找；找不到时，用运行中 Java 进程所在的 JDK，但只用 root 或当前账号所有、其他账号不能改写的 JDK。</p>
            <ul className="java-tools">
              {scan.tools.map((tool) => (
                <li key={tool.tool} className={tool.available ? "is-available" : "is-missing"}>
                  {tool.tool}<span>{tool.available ? "可用" : "没有"}</span>
                </li>
              ))}
            </ul>
            {jarTool === false ? (
              <p className="java-warning">没有可用的 jar 工具，所以可以看到进程，但不能列出或改写 JAR。常见原因：只装了 JRE；JDK 不在登录环境的 PATH 里，且此刻没有从它启动的 Java 进程；或者那个 JDK 目录其他账号也能改写，出于安全不使用。</p>
            ) : null}
          </section>

          <section className="java-section" aria-label="运行中的 Java 进程">
            <h2>运行中的 Java 进程 · {scan.processes.length} 个</h2>
            {scan.processes.length === 0 ? <p className="java-empty">没有找到正在运行的 Java 进程。</p> : (
              <div className="java-table-wrap">
                <table className="java-processes">
                  <thead><tr><th>PID</th><th>用户</th><th>CPU / 内存</th><th>已运行</th><th>命令行</th><th>JAR</th></tr></thead>
                  <tbody>
                    {scan.processes.map((process) => (
                      <tr key={process.pid}>
                        <td>{process.pid}</td>
                        <td>{process.user}</td>
                        <td>{process.cpuPercent.toFixed(1)}% / {process.memoryPercent.toFixed(1)}%</td>
                        <td>{elapsedLabel(process.elapsedSeconds)}</td>
                        <td><code>{process.command}</code>{process.commandTruncated ? <small>命令行较长，只显示前 512 字节</small> : null}</td>
                        <td>
                          {process.jarHandles.length === 0 ? <small>{process.openFilesReadable ? "没有找到它用到的 JAR" : "命令行里没有完整的 JAR 路径"}</small> : (
                            <button type="button" className="java-process-jars" aria-pressed={jarProcess === process.pid}
                              aria-label={`只看 PID ${process.pid} 的 ${process.jarHandles.length} 个 JAR`}
                              onClick={() => setJarProcess(jarProcess === process.pid ? null : process.pid)}>
                              {process.jarHandles.length} 个 JAR
                            </button>
                          )}
                          {process.openFilesReadable ? null : <small>读不到它打开的文件（需要 root 或进程所属账号），只列出命令行里写明的 JAR</small>}
                          {process.openJarsIncomplete ? <small>它打开的 JAR 较多，或有的文件名无法安全使用，没有全部列出</small> : null}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <section className="java-section" aria-label="JAR 文件">
              <h2>JAR 文件 · {scan.jars.length} 个</h2>
              <p>来自这些进程的命令行，以及它们正打开着的 JAR（应用服务器的 WEB-INF/lib 等）。打开一个 JAR 只读取它的类列表和哈希。</p>
              {scan.jars.length === 0 ? <p className="java-empty">{scan.processes.length === 0
                ? "没有运行中的 Java 进程，所以没有找到 JAR。知道 JAR 的位置时，可以在下面按路径打开。"
                : "没有找到 JAR：进程的命令行里没有完整路径，它打开的文件也读不到或没有 JAR。"}</p> : (
                <>
                  <div className="java-jar-toolbar">
                    <label className="java-filter">筛选 JAR<input type="search" value={jarFilter} maxLength={256} placeholder="文件名或目录"
                      onChange={(event) => setJarFilter(event.target.value)} /></label>
                    {jarProcess === null ? null : (
                      <button type="button" onClick={() => setJarProcess(null)}>显示所有进程的 JAR</button>
                    )}
                  </div>
                  <p className="java-count">{jarProcess === null ? "" : `只看 PID ${jarProcess}，`}匹配 {shownJars.matched} 个
                    {shownJars.matched > shownJars.rows.length ? `，显示前 ${shownJars.rows.length} 个，请缩小筛选` : ""}</p>
                  <ul className="java-jars" aria-label="选择要打开的 JAR">
                    {shownJars.rows.map((offer) => (
                      <li key={offer.jarHandle}>
                        <code>{offer.path}</code>
                        <small>PID {offer.pids.join("、")}</small>
                        <button type="button" className="java-jar-button" disabled={busy !== null || jarTool === false}
                          aria-pressed={jar?.jarHandle === offer.jarHandle} aria-label={`打开 ${offer.path}`}
                          onClick={() => openJar(offer.jarHandle)} title={offer.path}>
                          {jar?.jarHandle === offer.jarHandle ? "已打开" : "打开"}
                        </button>
                      </li>
                    ))}
                  </ul>
                </>
              )}
              {scan.jarsTruncated ? <p className="java-warning">找到的 JAR 超过 {scan.jars.length} 个，这里只列出其中 {scan.jars.length} 个；其余的可以按路径打开。</p> : null}
              <form className="java-typed-jar" onSubmit={(event) => { event.preventDefault(); openTypedJar(); }}>
                <label className="java-filter">按路径打开<input type="text" value={typedPath} maxLength={4_096} spellCheck={false}
                  placeholder="/opt/app/lib/app.jar" aria-describedby="java-typed-jar-hint"
                  onChange={(event) => { setTypedPath(event.target.value); setTypedError(null); }} /></label>
                <button type="submit" disabled={busy !== null || jarTool === false || !isTypedJarPath(typedPath)}>打开</button>
              </form>
              {typedError === null ? null : <TransientNotice source="Java 更新" message={typedError ?? ""} severity="error" inline><p className="java-error" role="alert" data-testid="java-typed-jar-error">{typedError}</p></TransientNotice>}
              <p className="java-count" id="java-typed-jar-hint">{typedPath !== "" && !isTypedJarPath(typedPath)
                ? "需要以 / 开头、以 .jar 结尾的完整路径，不能含 .. 或首尾空格。"
                : "列表里没有时用：例如 Tomcat 会关闭暂时不用的 WEB-INF/lib JAR。同样只读取，不改动。"}</p>
          </section>

          {jar === null ? (busy === "inspect" ? <p className="java-empty">正在列出 JAR 里的类…</p> : null) : (
            <section className="java-section" aria-label="JAR 里的类">
              <h2>{baseName(jar.path)}</h2>
              <dl className="java-facts">
                <div><dt>位置</dt><dd>{jar.path}</dd></div>
                <div><dt>大小</dt><dd>{jar.sizeBytes.toLocaleString()} 字节</dd></div>
                <div><dt>SHA-256</dt><dd><code data-testid="java-jar-sha256">{jar.sha256}</code></dd></div>
                <div><dt>类文件</dt><dd>{jar.classCount} 个{jar.truncated ? `，这里列出前 ${jar.classes.length} 个` : ""}</dd></div>
              </dl>
              <label className="java-filter">筛选类<input type="search" value={filter} maxLength={256} placeholder="类名或包路径"
                onChange={(event) => setFilter(event.target.value)} /></label>
              <p className="java-count">匹配 {shownClasses.matched} 个{shownClasses.matched > shownClasses.rows.length ? `，显示前 ${shownClasses.rows.length} 个，请缩小筛选` : ""}</p>
              <ul className="java-classes" aria-label="选择要替换的类">
                {shownClasses.rows.map((name) => (
                  <li key={name}>
                    <button type="button" aria-pressed={entry === name} onClick={() => setEntry(name)}>{name}</button>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {jar === null ? null : (
            <section className="java-section" aria-label="替换">
              <h2>替换</h2>
              <dl className="java-facts">
                <div><dt>要替换的类</dt><dd>{entry ?? "先在上面选一个类"}</dd></div>
                <div><dt>替换用的文件</dt><dd>{staged === null ? "还没有选择" : `${staged.name} · ${staged.sizeBytes.toLocaleString()} 字节`}</dd></div>
                {staged === null ? null : <div><dt>文件 SHA-256</dt><dd><code>{staged.sha256}</code></dd></div>}
              </dl>
              <div className="java-actions">
                <button type="button" data-testid="java-choose-class" disabled={busy !== null} onClick={chooseClass}>
                  {busy === "stage" ? "读取中…" : staged === null ? "选择 .class 文件" : "换一个文件"}
                </button>
                {staged === null ? null : <button type="button" disabled={busy !== null} onClick={discardStaged}>不用这个文件</button>}
                <button type="button" className="is-primary" data-testid="java-plan" disabled={busy !== null || entry === null || staged === null}
                  onClick={makePlan}>{busy === "plan" ? "正在读取 JAR 现状…" : "生成替换计划"}</button>
              </div>
            </section>
          )}
        </>
      )}

      <section className="java-section" aria-label="替换记录">
        <h2>替换记录</h2>
        {history === null ? <p className="java-empty">{busy === "history" ? "正在读取记录…" : "还没有读到记录。"}</p> : history.records.length === 0 ? (
          <p className="java-empty">这台主机还没有通过这里替换过类文件。</p>
        ) : (
          <ul className="java-records">
            {history.records.map((record) => (
              <li key={record.recordId} data-record-id={record.recordId}>
                <div>
                  <strong>{record.entry}</strong>
                  <span className={record.state === "applied" ? "java-state is-applied" : "java-state is-restored"}>
                    {record.state === "applied" ? "已替换" : "已恢复原 JAR"}</span>
                </div>
                <p>{record.jarPath}</p>
                <small>替换于 {timeLabel(record.createdAt)}{record.updatedAt !== record.createdAt ? ` · 更新于 ${timeLabel(record.updatedAt)}` : ""}</small>
                {record.state === "applied" ? (
                  <button type="button" disabled={busy !== null || dialog !== null} onClick={() => planRestore(record)}>恢复原 JAR</button>
                ) : null}
              </li>
            ))}
          </ul>
        )}
        {history?.truncated ? <p className="java-count">只显示最近 {history.records.length} 条。</p> : null}
      </section>

      {dialog === null ? null : (
        <JavaPlanDialog state={dialog} onConfirm={() => void confirmAndRun()} onClose={closeDialog} />
      )}
    </section>
  );
}

/**
 * The plan as the core wrote it, then the result of running it. Focus starts
 * on 取消: replacing a class is never what a stray Enter does.
 */
export function JavaPlanDialog({ state, onConfirm, onClose }: {
  state: PlanDialogState;
  onConfirm: () => void;
  onClose: () => void;
}) {
  useModalScrim();
  const cancelRef = useRef<HTMLButtonElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  const { plan, receipt, running, error } = state;
  const update = plan.operation === "update";
  useEffect(() => {
    (receipt === null ? cancelRef.current : closeRef.current)?.focus();
  }, [receipt]);
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !running) {
        event.preventDefault();
        onClose();
      }
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [running, onClose]);
  return (
    <div className="java-dialog-backdrop" role="presentation">
      <section className="java-dialog" role="dialog" aria-modal="true" aria-busy={running}
        aria-label={update ? "替换类文件" : "恢复原 JAR"} data-testid="java-plan-dialog">
        <header>
          <h2>{update ? "替换类文件" : "恢复原 JAR"}</h2>
          <p>{plan.jarPath}</p>
        </header>
        {receipt === null ? (
          <>
            <div className="java-panel is-dangerous">
              <dl>
                <div><dt>将要执行</dt><dd>{plan.summary}</dd></div>
                <div><dt>类</dt><dd>{plan.entry}</dd></div>
                <div><dt>{update ? "新类文件 SHA-256" : "当初替换进去的类 SHA-256"}</dt><dd><code>{plan.classSha256}</code></dd></div>
                <div><dt>出问题时</dt><dd>{plan.restoreDescription ?? "没有自动还原的办法"}</dd></div>
                <div><dt>计划有效期</dt><dd>{planExpiryLabel(plan.expiresInSeconds)}</dd></div>
              </dl>
              <p className="java-note">{update
                ? "执行前会再核对一次 JAR 与这个类的当前哈希，和生成计划时不同就不改动。替换只改磁盘上的 JAR，不会重启进程。"
                : "只在 JAR 仍是当初替换后的样子时才恢复；之后被别人改过就不覆盖。恢复同样不会重启进程。"}</p>
            </div>
            {error === null ? null : <TransientNotice source="Java 更新" message={error ?? ""} severity="error"><p className="java-error" role="alert">{error}</p></TransientNotice>}
            {running ? <p className="java-note" role="status">{update ? "正在备份、替换并核对…" : "正在恢复并核对…"}</p> : null}
            <footer>
              <button ref={cancelRef} type="button" data-testid="java-plan-cancel" disabled={running} onClick={onClose}>取消</button>
              <button type="button" className="is-dangerous" data-testid="java-plan-execute" disabled={running} onClick={onConfirm}>
                {running ? "执行中…" : update ? "确认替换" : "确认恢复"}
              </button>
            </footer>
          </>
        ) : (
          <>
            <div className={receipt.verified ? "java-panel" : "java-panel is-dangerous"} data-testid="java-receipt">
              <p className="java-summary">{receipt.verified
                ? (update ? "已替换，并核对过 JAR 里这个类与所选文件一致。" : "已恢复，JAR 与替换前一致。")
                : (update ? "替换没有完成或没有通过核对。" : "恢复没有完成或没有通过核对。")}</p>
              <dl>
                <div><dt>核对结果</dt><dd>{receipt.detail}</dd></div>
                {receipt.jarSha256 === null ? null : <div><dt>JAR 现在的 SHA-256</dt><dd><code>{receipt.jarSha256}</code></dd></div>}
                {receipt.verified && update ? <div><dt>下一步</dt><dd>运行中的进程不会自动加载新类；需要时请按业务要求重启它，并确认业务功能正常。</dd></div> : null}
              </dl>
            </div>
            <footer>
              <button ref={closeRef} type="button" className="is-primary" onClick={onClose}>关闭</button>
            </footer>
          </>
        )}
      </section>
    </div>
  );
}

/** The file name of a location the backend gave back, for display. */
function baseName(location: string): string {
  return location.slice(location.lastIndexOf("/") + 1) || location;
}

function elapsedLabel(seconds: number): string {
  if (seconds < 60) return `${seconds} 秒`;
  if (seconds < 3_600) return `${Math.floor(seconds / 60)} 分钟`;
  if (seconds < 86_400) return `${Math.floor(seconds / 3_600)} 小时`;
  return `${Math.floor(seconds / 86_400)} 天`;
}

function timeLabel(value: string): string {
  const time = new Date(value);
  return Number.isNaN(time.getTime()) ? value : time.toLocaleString("zh-CN", { hour12: false });
}
