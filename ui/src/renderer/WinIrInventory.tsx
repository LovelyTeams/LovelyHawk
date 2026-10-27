import { useMemo, useState } from "react";
import type { WindowsInventoryEntry, WindowsInventoryKind, WindowsInventorySnapshot } from "../shared/windows-incident-contract";
import { DataTable, DetailPane, FilterChips, RiskCell, SearchBox, StatStrip, riskChipOptions, riskSort, type Column } from "./WinIrKit";
import { matchesQuery, riskCounts, type RiskFilter } from "./win-ir-helpers";

const LABELS = {services:"服务",drivers:"驱动",tasks:"计划任务"};
const STATES: Record<string,string> = { Running:"运行中",Stopped:"已停止",Ready:"就绪",Disabled:"已禁用",Unknown:"未知",StartPending:"正在启动",StopPending:"正在停止" };
const START: Record<string,string> = {Auto:"自动",Manual:"手动",Disabled:"禁用",Boot:"引导",System:"系统"};
export function WinIrInventory({kind,snapshot,onCopy,onRegistry,onProcess,onCommand}: {
  kind:WindowsInventoryKind; snapshot:WindowsInventorySnapshot|null;
  onCopy:(text:string)=>void;onRegistry:(path:string)=>void;onProcess:(pid:number)=>void;onCommand:(id:string)=>void;
}) {
  const [query,setQuery]=useState("");
  const [risk,setRisk]=useState<RiskFilter>("all");
  const [state,setState]=useState("all");
  const [selected,setSelected]=useState<string|null>(null);
  const entries=useMemo(()=>(snapshot?.entries??[]).map((entry,index)=>({...entry,key:`${entry.location}\0${entry.name}\0${index}`})),[snapshot]);
  const current=entries.find((entry)=>entry.key===selected);
  const states=[...new Set(entries.map((entry)=>entry.state))];
  const rows=entries.filter((entry)=>(risk==="all"||entry.riskLevel===risk)&&(state==="all"||entry.state===state)&&matchesQuery(query,entry.name,entry.displayName,entry.command,entry.account,entry.location,entry.pid,...entry.details));
  const columns:Column<WindowsInventoryEntry & {key:string}>[]=[
    {key:"name",label:`${LABELS[kind]}名称`,width:"25%",sort:(e)=>e.name,render:(e)=><div className="wir-cell-stack"><strong>{e.name}</strong><small>{e.displayName||e.location}</small></div>},
    {key:"state",label:"状态",width:"100px",sort:(e)=>e.state,render:(e)=>STATES[e.state]??e.state},
    {key:"mode",label:kind==="tasks"?"运行账户":"启动方式",width:"120px",sort:(e)=>kind==="tasks"?e.account:e.startMode,render:(e)=>kind==="tasks"?(e.account||"未取得"):(START[e.startMode]??e.startMode)},
    {key:"command",label:kind==="tasks"?"任务操作":"执行路径与参数",mono:true,render:(e)=><span className="wir-clip" title={e.command}>{e.command||"未取得 / 非命令操作"}</span>},
    {key:"risk",label:"线索",width:"80px",sort:riskSort((e)=>e.riskLevel),render:(e)=><RiskCell level={e.riskLevel}/>},
  ];
  return <div className="wir-module">
    <StatStrip cards={[{label:`已取得${LABELS[kind]}`,value:snapshot?entries.length:"—"},{label:"运行中",value:snapshot?entries.filter((e)=>e.state==="Running").length:"—"},{label:"需关注",value:snapshot?entries.filter((e)=>e.riskLevel!=="normal").length:"—",tone:"medium"}]}/>
    <div className="wir-toolbar"><SearchBox value={query} onChange={setQuery} placeholder={`搜索${LABELS[kind]}、路径、账户或参数`}/><select aria-label={`${LABELS[kind]}状态`} className="win-ir-input wir-select" value={state} onChange={(event)=>setState(event.target.value)}><option value="all">全部状态</option>{states.map((value)=><option key={value} value={value}>{STATES[value]??value}</option>)}</select><button type="button" className="win-ir-btn" onClick={()=>onCommand(kind==="tasks"?"tasks":kind)}>查看只读命令</button></div>
    <FilterChips label={`${LABELS[kind]}风险`} value={risk} onChange={setRisk} options={riskChipOptions(riskCounts(entries,(entry)=>entry.riskLevel))}/>
    {snapshot?.warnings.map((warning,index)=><p key={index} className="wir-reader-warning" role="alert">{warning}</p>)}
    {snapshot?.truncated?<p className="wir-reader-warning" role="status">清单或字段已截断：已观察至少 {snapshot.totalCount} 条，展示 {entries.length} 条；单次最多 2000 条，不能作为完整清单。</p>:null}
    <div className={`wir-master${current?" is-split":""}`}>
      <DataTable label={`${LABELS[kind]}清单`} rows={rows} columns={columns} selectedKey={selected} rowKey={(entry)=>entry.key} onSelect={(entry)=>setSelected(entry?.key??null)} rowRisk={(entry)=>entry.riskLevel} defaultSort={{key:"risk",descending:true}} empty={snapshot?"没有符合当前筛选条件的条目；请同时检查采集缺口。":`连接后读取${LABELS[kind]}清单。`}/>
      {current?<DetailPane title={current.name} subtitle={current.displayName||LABELS[kind]} risk={current.riskLevel} reasons={current.riskReason?[current.riskReason]:[]} onClose={()=>setSelected(null)} onCopy={onCopy} fields={[
        {label:"位置",value:current.location,mono:true},{label:"执行路径与参数",value:current.command,mono:true},{label:"运行账户",value:current.account||"未取得"},{label:"状态",value:STATES[current.state]??current.state},{label:"启动方式",value:START[current.startMode]??(current.startMode||"见触发器")},{label:"PID",value:current.pid?String(current.pid):"不适用 / 未运行"},...current.details.map((value,index)=>({label:`详细信息 ${index+1}`,value})),
      ]} actions={<>{kind!=="tasks"&&/^HKLM:\\SYSTEM\\CurrentControlSet\\Services\\[^\\]+$/iu.test(current.location)?<button type="button" className="win-ir-btn" onClick={()=>onRegistry(current.location)}>查看注册表配置 ↗</button>:null}{current.pid>4?<button type="button" className="win-ir-btn" onClick={()=>onProcess(current.pid)}>查看所属进程 ↗</button>:null}</>}><p className="wir-footnote">{kind==="drivers"?"这里列出驱动服务配置及其报告的状态，不是完整内核模块或隐藏驱动检测。停止驱动可能导致蓝屏，需另行核对业务影响。":kind==="tasks"?"包含系统任务及已禁用任务；触发器为摘要，不能代替完整任务 XML 或任务执行历史。":"服务运行状态来自本次采集，不等于业务健康。共享进程可能承载多个服务。"}</p></DetailPane>:null}
    </div>
  </div>;
}
