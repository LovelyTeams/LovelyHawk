import { forwardRef, useEffect, useImperativeHandle, useMemo, useRef, useState, useSyncExternalStore, type ReactNode } from "react";
import type { NginxRepairApi } from "../shared/nginx-repair-contract";
import { NginxRepairController } from "./nginx-repair-controller";
import { NginxRepairDialog } from "./NginxRepairDialog";
import { NginxConnectivityPanel } from "./NginxConnectivityPanel";
import { useConfirmDialog } from "./use-confirm-dialog";
import { DialogHost } from "./DialogHost";
import "./nginx-repair-page.css";

export interface NginxRepairPageHandle { beforeDeactivate(): Promise<boolean> }
export interface NginxRepairPageProps { api: NginxRepairApi; bindingHandle: string | null; modeSwitch?: ReactNode;
 onCopyRecord?: ((text: string) => Promise<unknown>) | undefined }
const STATES = { applied: "已应用", restored: "已还原", pending: "待核实", "restore-failed": "恢复待处理" } as const;

export const NginxRepairPage = forwardRef<NginxRepairPageHandle, NginxRepairPageProps>(
function NginxRepairPage({ api, bindingHandle, modeSwitch, onCopyRecord }, ref) {
  const controller = useMemo(() => new NginxRepairController(api, bindingHandle), [api, bindingHandle]);
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  const [query, setQuery] = useState("");
  const returnFocus = useRef<HTMLElement | null>(null);
  const headingFocus = useRef<HTMLHeadingElement | null>(null);
  const discard = useConfirmDialog();
  useEffect(() => { controller.activate(); setQuery(""); return () => controller.dispose(); }, [controller]);
  useEffect(() => () => { discard.resolve({ kind: "cancelled", dialogId: "nginx-retention-unmounted" }); }, [controller, discard.resolve]);
  async function discardObservation(): Promise<boolean> {
    const current = controller.getSnapshot().connectivity;
    if (!current || current.retention.state !== "unsaved") return true;
    if (!(await discard.ask("放弃未保存的连接观察？", "本次结果尚未进入案件。请选择取消后重试保存或复制完整记录；放弃后，再次复核会产生新的观察，不能替代这次记录。", "放弃本次未保存结果"))) return false;
    if (controller.getSnapshot().connectivity?.observationHandle !== current.observationHandle) return false;
    return controller.discardObservation();
  }
  useImperativeHandle(ref, () => ({ beforeDeactivate: async () => {
    if (await controller.beforeDeactivate()) return true;
    if (["retain", "discard"].includes(controller.getSnapshot().reading ?? "")) return false;
    return discardObservation();
  } }));
  const { inventory, configuration, history, reading, dialog } = state;
  const blocked = bindingHandle === null || reading !== null || dialog !== null || state.connectivity?.retention.state === "unsaved" || discard.dialog !== null;
  const candidates = configuration?.candidates.filter((candidate) =>
    `${candidate.title} ${candidate.setting} ${candidate.path} ${candidate.line}`.toLocaleLowerCase().includes(query.trim().toLocaleLowerCase())) ?? [];
  function closeDialog() {
    const complete = dialog?.phase === "done" || dialog?.phase === "failed";
    controller.closeDialog();
    if (complete) void controller.read("history");
  }
  return (
    <section className="nginx-repair-page" aria-label="修补已有配置">
      <div className="nginx-repair-workbench" inert={dialog !== null || discard.dialog !== null}>
        <header className="nginx-repair-toolbar">
          {modeSwitch}
          <button type="button" className="nginx-repair-primary" disabled={blocked} onClick={() => void controller.read("discover")}>识别 Nginx 实例</button>
          <button type="button" disabled={blocked} onClick={() => void controller.read("history")}>查看修补历史</button>
        </header>
        <div className="nginx-repair-intro">
          <div><h2 ref={headingFocus} tabIndex={-1}>Nginx 配置修补</h2><p>先只读识别运行实例，再按文件与行号选择修补。当前支持关闭目录列表、隐藏版本信息，以及从已配置的协议中移除旧版 TLS/SSL。</p></div>
          <details><summary>适用条件与验证范围</summary><p>支持使用默认配置启动的独立 Nginx 进程，包括容器中的前台进程。目标需要 Python 3.9+ 和 Linux 进程身份保护能力；自定义启动参数、共享配置、多命名空间或权限不足时会拒绝修补。不会自动安装工具。TLS 修补保留原有 TLSv1.2/TLSv1.3 组合；仅支持旧版协议的客户端可能无法连接。只有旧版协议或包含未知值的位置需单独规划升级。配置和进程验证通过后，仍应检查各监听地址的默认服务器、站点、接口和真实 TLS 连接。</p></details>
        </div>
        {bindingHandle === null ? <p className="nginx-repair-empty">请先连接目标主机，然后识别 Nginx 实例。</p> : null}
        {reading ? <p role="status" className="nginx-repair-note">{{ discover: "正在识别运行实例…", load: "正在读取主配置与引用文件…", history: "正在读取修补历史…", listeners: "正在读取此实例的监听端口…", probe: "正在逐项复核 TLS 与 HTTP，并保存本次观察…", retain: "正在保存原观察，不重新探测主机…", discard: "正在清除本次临时观察…" }[reading]}</p> : null}
        {state.error ? <p role="alert" className="nginx-repair-error">{state.error}</p> : null}
        {bindingHandle !== null && inventory === null && reading === null ? <p className="nginx-repair-empty">点击“识别 Nginx 实例”开始；读取和准备计划都不会修改目标配置。</p> : null}
        {inventory ? <div className="nginx-repair-instances" role="group" aria-label="选择 Nginx 实例">
          {inventory.instances.length === 0 ? <p className="nginx-repair-empty">未发现符合条件的运行实例。请核对 Nginx 是否运行及当前账号权限。</p> : inventory.instances.map((instance) =>
            <button key={instance.instanceHandle} type="button" disabled={blocked} aria-pressed={state.selectedInstance === instance.instanceHandle}
              onClick={() => void controller.read("load", instance.instanceHandle)}>
              <strong>{instance.title}</strong><span>{instance.version} · 读取配置</span>
            </button>)}
        </div> : null}
        {configuration ? <section className="nginx-repair-candidates" aria-label="可修补位置">
          <header><div><h3>可修补位置 <span>{candidates.length} / {configuration.candidates.length}</span></h3>
            <p>已读取 {configuration.fileCount} 个配置文件。每次修改一处，保留其他配置。</p></div>
            <label className="nginx-repair-search"><span>搜索位置</span><input type="search" value={query} maxLength={256} placeholder="配置项、路径或行号" onChange={(event) => setQuery(event.target.value)} /></label>
          </header>
          {configuration.unresolvedIncludes > 0 ? <p className="nginx-repair-warning" role="alert">有 {configuration.unresolvedIncludes} 处引用尚未解析，当前不能修补。请先检查引用文件、变量和读取权限。</p> : null}
          {configuration.candidates.length === 0 ? <p className="nginx-repair-empty">未找到当前支持修改的显式配置项。这不代表整个实例已通过安全基线。</p>
            : candidates.length === 0 ? <p className="nginx-repair-empty">没有匹配位置，请调整搜索条件。</p>
            : <ul>{candidates.map((candidate) => <li key={candidate.candidateHandle}>
              <div className="nginx-repair-candidate-body"><h4>{candidate.title}</h4><p className="nginx-repair-location">{candidate.path} · 第 {candidate.line} 行</p>
                <code>{candidate.before} → {candidate.after}</code></div>
              <button type="button" disabled={blocked || configuration.unresolvedIncludes > 0}
                aria-label={`准备修补：${candidate.title}，${candidate.path} 第 ${candidate.line} 行`}
                onClick={(event) => { returnFocus.current = event.currentTarget; void controller.prepare(candidate.candidateHandle); }}>准备修补</button>
            </li>)}</ul>}
        </section> : null}
        {state.selectedInstance ? <NginxConnectivityPanel key={state.selectedInstance} controller={controller} state={state} blocked={blocked}
          onCopyRecord={onCopyRecord} onDiscard={() => { void discardObservation(); }} /> : null}
        {history ? <section className="nginx-repair-history" aria-label="修补历史">
          <h3>修补历史 <span>{history.totalRecords}</span></h3>
          <p className="nginx-repair-note">按最近操作排列。恢复前会核对实例和当前文件；后续修改不会被旧备份覆盖。</p>
          {history.truncated ? <p className="nginx-repair-warning">显示最近 64 条，共 {history.totalRecords} 条。</p> : null}
          {history.records.length === 0 ? <p className="nginx-repair-empty">这台主机还没有普通 Nginx 进程的修补记录。</p> : <ul>{history.records.map((record) => <li key={record.recordHandle}>
            <div><strong>{STATES[record.state]}</strong><time dateTime={record.createdAt}>{new Date(record.createdAt).toLocaleString()}</time><p className="nginx-repair-location">{record.path}</p></div>
            <button type="button" disabled={blocked || !record.canPrepareRestore} onClick={(event) => { returnFocus.current = event.currentTarget; void controller.restore(record.recordHandle); }}>准备恢复</button>
          </li>)}</ul>}
        </section> : null}
      </div>
      {dialog ? <NginxRepairDialog dialog={dialog} returnFocus={returnFocus.current} fallbackFocus={headingFocus.current} onClose={closeDialog} onConfirm={() => void controller.confirm()} /> : null}
      {discard.dialog ? <DialogHost dialog={discard.dialog} onResolve={discard.resolve} /> : null}
    </section>
  );
});
