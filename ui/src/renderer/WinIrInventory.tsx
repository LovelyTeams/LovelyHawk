import { useEffect, useMemo, useRef, useState } from "react";
import type { WindowsControlOperation, WindowsInventoryEntry, WindowsInventoryKind, WindowsInventorySnapshot } from "../shared/windows-incident-contract";
import { CONTROL_ACTIONS, CONTROL_LABELS } from "./WinIrControlChange";
import { DataTable, DetailPane, FilterChips, RiskCell, SearchBox, StatStrip, WinIrModal, riskChipOptions, riskSort, type Column } from "./WinIrKit";
import { commandExecutable, matchesQuery, riskCounts, type RiskFilter } from "./win-ir-helpers";

const LABELS = {services:"服务",drivers:"驱动",tasks:"计划任务"};
const STATES: Record<string,string> = { Running:"运行中",Stopped:"已停止",Ready:"就绪",Disabled:"已禁用",Unknown:"未知",StartPending:"正在启动",StopPending:"正在停止" };
const START: Record<string,string> = {Auto:"自动",Manual:"手动",Disabled:"禁用",Boot:"引导",System:"系统"};
export function WinIrInventory({kind,snapshot,busy,connected,focus,onCopy,onRegistry,onProcess,onCommand,onFile,onAction,onHistory,onInspect}: {
  kind:WindowsInventoryKind; snapshot:WindowsInventorySnapshot|null;
  busy:boolean; connected:boolean; focus?:{name:string;location:string;request:number}|null;
  onCopy:(text:string)=>void;onRegistry:(path:string)=>void;onProcess:(pid:number)=>void;onCommand:(id:string)=>void;
  onFile:(path:string)=>void;onAction:(entry:WindowsInventoryEntry,operation:WindowsControlOperation)=>void;onHistory:()=>void;
  onInspect:(entry:WindowsInventoryEntry)=>void;
}) {
  const [query,setQuery]=useState("");
  const [risk,setRisk]=useState<RiskFilter>("all");
  const [state,setState]=useState("all");
  const [selected,setSelected]=useState<string|null>(null);
  const [missing,setMissing]=useState(false);
  const [menuEntry,setMenuEntry]=useState<WindowsInventoryEntry|null>(null);
  const focusHandled=useRef(0);
  const entries=useMemo(()=>(snapshot?.entries??[]).map((entry,index)=>({...entry,key:`${entry.location}\0${entry.name}\0${index}`})),[snapshot]);
  useEffect(()=>{
    if (!focus || !snapshot || focusHandled.current===focus.request) return;
    focusHandled.current=focus.request;
    const entry=entries.find(e=>e.name.toLowerCase()===focus.name.toLowerCase() && (kind!=="tasks" || e.location.toLowerCase()===focus.location.toLowerCase()));
    setQuery("");setRisk("all");setState("all");setSelected(entry?.key??null);setMissing(!entry);
  },[focus,snapshot,entries,kind]);
  const current=entries.find((entry)=>entry.key===selected);
  const states=[...new Set(entries.map((entry)=>entry.state))];
  const rows=entries.filter((entry)=>(risk==="all"||entry.riskLevel===risk)&&(state==="all"||entry.state===state)&&matchesQuery(query,entry.name,entry.displayName,entry.command,entry.account,entry.location,entry.pid,...entry.details));
  const primary=(e:WindowsInventoryEntry):WindowsControlOperation=>kind==="tasks"?(e.state==="Running"?"stop":e.state==="Disabled"?"enable":"run"):(e.state==="Running"?"stop":"start");
  const executable=current?commandExecutable(current.command):null;
  const columns:Column<WindowsInventoryEntry & {key:string}>[]=[
    {key:"name",label:`${LABELS[kind]}名称`,width:"23%",sort:(e)=>e.name,render:(e)=><div className="wir-cell-stack wir-inventory-name"><strong title={e.name}>{e.name}</strong><small title={e.displayName||e.location}>{e.displayName||e.location}</small></div>},
    {key:"state",label:"状态",width:"100px",sort:(e)=>e.state,render:(e)=>STATES[e.state]??e.state},
    {key:"mode",label:kind==="tasks"?"运行账户":"启动方式",width:"120px",sort:(e)=>kind==="tasks"?e.account:e.startMode,render:(e)=>kind==="tasks"?(e.account||"未取得"):(START[e.startMode]??e.startMode)},
    {key:"command",label:kind==="tasks"?"任务操作":"执行路径与参数",mono:true,render:(e)=><span className="wir-clip" title={e.command}>{e.command||"未取得 / 非命令操作"}</span>},
    {key:"risk",label:"线索",width:"80px",sort:riskSort((e)=>e.riskLevel),render:(e)=><RiskCell level={e.riskLevel}/>},
    {key:"action",label:"详情与操作",width:"230px",render:(e)=><div className="wir-inventory-row-actions">
      <button type="button" className="win-ir-btn" aria-label={`查看详情 ${e.name}`} disabled={busy} onClick={event=>{event.stopPropagation();onInspect(e);}}>详情</button>
      <button type="button" className="win-ir-btn" disabled={busy||!connected||!e.objectId} aria-label={`${CONTROL_LABELS[primary(e)]} ${e.name}`} onClick={(event)=>{event.stopPropagation();onAction(e,primary(e));}}>{CONTROL_LABELS[primary(e)]}…</button>
      <button type="button" className="win-ir-btn" aria-label={`${e.name} 的全部操作`} aria-haspopup="dialog" disabled={busy} onClick={event=>{event.stopPropagation();setMenuEntry(e);}}>操作 ▾</button>
    </div>},
  ];
  return <div className="wir-module wir-inventory">
    <StatStrip cards={[{label:`已取得${LABELS[kind]}`,value:snapshot?entries.length:"—"},{label:"运行中",value:snapshot?entries.filter((e)=>e.state==="Running").length:"—"},{label:"需关注",value:snapshot?entries.filter((e)=>e.riskLevel!=="normal").length:"—",tone:"medium"}]}/>
    <div className="wir-toolbar"><SearchBox value={query} onChange={setQuery} placeholder={`搜索${LABELS[kind]}、路径、账户或参数`}/><select aria-label={`${LABELS[kind]}状态`} className="win-ir-input wir-select" value={state} onChange={(event)=>setState(event.target.value)}><option value="all">全部状态</option>{states.map((value)=><option key={value} value={value}>{STATES[value]??value}</option>)}</select><button type="button" className="win-ir-btn" disabled={busy||!connected} onClick={onHistory}>处置与恢复记录</button><button type="button" className="win-ir-btn" onClick={()=>onCommand(kind==="tasks"?"tasks":kind)}>查看只读命令</button></div>
    {missing?<p role="status">本次清单中没有找到要定位的对象，请刷新后再核对。</p>:null}
    <FilterChips label={`${LABELS[kind]}风险`} value={risk} onChange={setRisk} options={riskChipOptions(riskCounts(entries,(entry)=>entry.riskLevel))}/>
    {snapshot?.warnings.map((warning,index)=><p key={index} className="wir-reader-warning" role="alert">{warning}</p>)}
    {snapshot?.truncated?<p className="wir-reader-warning" role="status">清单或字段已截断：已观察至少 {snapshot.totalCount} 条，展示 {entries.length} 条；单次最多 2000 条，不能作为完整清单。</p>:null}
    <div className={`wir-master${current?" is-split":""}`}>
      <DataTable label={`${LABELS[kind]}清单`} rows={rows} columns={columns} selectedKey={selected} rowKey={(entry)=>entry.key} onSelect={(entry)=>setSelected(entry?.key??null)} onActivate={onInspect} keyHint="↑↓ 切换 · Enter 打开详情" rowRisk={(entry)=>entry.riskLevel} defaultSort={{key:"risk",descending:true}} empty={snapshot?"没有符合当前筛选条件的条目；请同时检查采集缺口。":`连接后读取${LABELS[kind]}清单。`}/>
      {current?<DetailPane title={current.name} subtitle={current.displayName||LABELS[kind]} risk={current.riskLevel} reasons={current.riskReason?[current.riskReason]:[]} onClose={()=>setSelected(null)} onCopy={onCopy} fields={[
        {label:"位置",value:current.location,mono:true},{label:"执行路径与参数",value:current.command,mono:true},{label:"运行账户",value:current.account||"未取得"},{label:"状态",value:STATES[current.state]??current.state},{label:"启动方式",value:START[current.startMode]??(current.startMode||"见触发器")},{label:"PID",value:current.pid?String(current.pid):"不适用 / 未运行"},...current.details.map((value,index)=>({label:`详细信息 ${index+1}`,value})),
      ]} actions={<><button type="button" className="win-ir-btn" disabled={busy} onClick={()=>onInspect(current)}>打开完整详情</button>{CONTROL_ACTIONS[kind].map(operation=><button key={operation} type="button" className="win-ir-btn" disabled={busy||!connected||!current.objectId} onClick={()=>onAction(current,operation)}>{CONTROL_LABELS[operation]}…</button>)}{executable?<button type="button" className="win-ir-btn" onClick={()=>onFile(executable)}>查看文件 ↗</button>:null}{kind!=="tasks"&&/^HKLM:\\SYSTEM\\CurrentControlSet\\Services\\[^\\]+$/iu.test(current.location)?<button type="button" className="win-ir-btn" onClick={()=>onRegistry(current.location)}>查看注册表配置 ↗</button>:null}{current.pid>4?<button type="button" className="win-ir-btn" onClick={()=>onProcess(current.pid)}>查看所属进程 ↗</button>:null}</>}>
        {!current.objectId?<p className="wir-reader-warning">条目信息不完整或已截断，无法生成处置计划；请重新采集。</p>:null}
        <p className="wir-footnote">操作会先核对当前对象与影响范围，确认后执行。{kind==="drivers"?"引导、系统启动及关键驱动拒绝在线处置；其他驱动也只有支持停止时才能卸载。加载状态不能代替隐藏驱动检测。":kind==="tasks"?"立即运行仅代表调度器接受请求，需复查任务结果。停止仅处理确认时的运行实例。":"不会连带停止依赖服务。启动方式变更不等于服务已经停止或业务已恢复。"}</p></DetailPane>:null}
    </div>
    {menuEntry?<WinIrModal title={`${LABELS[kind]}操作`} subtitle={kind==="tasks"?menuEntry.location+menuEntry.name:menuEntry.name} onClose={()=>setMenuEntry(null)}>
      <p>选择操作后先读取具体计划，确认前不会修改目标。</p>
      <div className="wir-inventory-action-menu">
        <button type="button" className="win-ir-btn" disabled={busy} onClick={()=>{setMenuEntry(null);onInspect(menuEntry);}}>查看完整详情</button>
        {CONTROL_ACTIONS[kind].map(operation=><button type="button" key={operation} className={`win-ir-btn${operation==="delete"?" is-danger":""}`} disabled={busy||!connected||!menuEntry.objectId} onClick={()=>{setMenuEntry(null);onAction(menuEntry,operation);}}>{CONTROL_LABELS[operation]}…</button>)}
      </div>
      <p className="wir-footnote">删除须先禁用并停止，且没有依赖它的服务。只删除注册定义，执行文件保留；删除没有一键恢复备份。</p>
    </WinIrModal>:null}
  </div>;
}
