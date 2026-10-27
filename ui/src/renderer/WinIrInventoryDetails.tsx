import { useEffect, useRef, useState } from "react";
import type { WindowsControlOperation, WindowsIncidentResponse, WindowsInventoryDetails, WindowsInventoryEntry, WindowsInventoryKind, WindowsRemoteIntent } from "../shared/windows-incident-contract";
import { CONTROL_ACTIONS, CONTROL_LABELS } from "./WinIrControlChange";
import { WinIrModal } from "./WinIrKit";
import { errorText } from "./error-text";

export type InventoryDetailSelection = {kind:WindowsInventoryKind;entry:WindowsInventoryEntry;session:string|null;observedAt:string};
export function WinIrInventoryDetails({selection,currentSession,onRequest,onClose,onCopy,onAction}: {
  selection:InventoryDetailSelection;currentSession:string|null;
  onRequest:(request:WindowsRemoteIntent,session:string,label?:string)=>Promise<WindowsIncidentResponse>;
  onClose:()=>void;onCopy:(text:string)=>void;onAction:(operation:WindowsControlOperation)=>void;
}) {
  const [details,setDetails]=useState<WindowsInventoryDetails|null>(null);
  const [error,setError]=useState<string|null>(null);
  const [working,setWorking]=useState(false);
  const started=useRef(false), live=useRef(true), lock=useRef(false);
  const available=!!selection.session && currentSession===selection.session;
  const entry=selection.entry;
  const fullName=selection.kind==="tasks"?entry.location+entry.name:entry.name;
  const title={tasks:"计划任务详情",services:"服务详情",drivers:"驱动详情"}[selection.kind];
  useEffect(()=>{live.current=true;return()=>{live.current=false;};},[]);
  async function read() {
    if(lock.current||!available||!entry.objectId||!selection.session)return;
    lock.current=true;setWorking(true);setError(null);
    try {
      const response=await onRequest({action:"inspect-inventory",objectId:entry.objectId},selection.session,"正在只读核对所选对象详情…");
      if(response.kind!=="inventory-details"||response.details.kind!==selection.kind||response.details.name!==fullName)throw new Error("返回对象与所选条目不一致，请刷新清单。");
      if(live.current)setDetails(response.details);
    }catch(reason){if(live.current)setError(errorText(reason,"读取详情失败，请核对权限并刷新清单。"));}
    finally{lock.current=false;if(live.current)setWorking(false);}
  }
  useEffect(()=>{if(!started.current){started.current=true;void read();}});
  const fields=details?.fields??[
    {label:"完整名称",value:fullName},{label:"说明",value:entry.displayName},{label:"位置",value:entry.location},{label:"执行路径与参数",value:entry.command},{label:"运行账户",value:entry.account||"未取得"},{label:"采集时状态",value:entry.state},{label:"启动方式",value:entry.startMode||"见触发器"},...entry.details.map((value,index)=>({label:`采集信息 ${index+1}`,value})),
  ];
  const copy=()=>onCopy([title,`对象：${fullName}`,`读取时间：${details?.observedAt??selection.observedAt}`,...fields.map(field=>`${field.label}：${field.value}`),...(details?.warnings??[])].join("\n"));
  return <WinIrModal wide title={title} subtitle={fullName} onClose={onClose} actions={<>
    <button type="button" className="win-ir-btn" onClick={copy}>复制详情</button>
    <button type="button" className="win-ir-btn" disabled={working||!available||!entry.objectId} onClick={()=>void read()}>重新读取详情</button>
    {CONTROL_ACTIONS[selection.kind].map(operation=><button type="button" key={operation} className={`win-ir-btn${operation==="delete"?" is-danger":""}`} disabled={working||!available||!entry.objectId} onClick={()=>onAction(operation)}>{CONTROL_LABELS[operation]}…</button>)}
    <button type="button" className="win-ir-btn" onClick={onClose}>关闭详情</button>
  </>}>
    <p>{details?`目标：${details.target} · 读取于 ${details.observedAt}`:`清单采集于 ${selection.observedAt}；当前显示已采集字段。`}</p>
    {working?<p role="status">正在只读读取详情，最长等待 45 秒；关闭窗口后不会展示迟到结果。</p>:null}
    {!available?<p role="alert">当前未连接原会话，仅保留已取得的详情；重新连接后请刷新清单。</p>:null}
    {!entry.objectId?<p role="alert">条目信息不完整或已截断，请重新采集后读取实时详情。</p>:null}
    {error?<p className="wir-reader-warning" role="alert">{error} 当前保留的是此前采集内容。</p>:null}
    <dl className="wir-inventory-fields" tabIndex={0} aria-label="对象详细信息">{fields.map((field,index)=><div key={`${field.label}:${index}`}><dt>{field.label}</dt><dd>{field.value||"未配置 / 未提供"}</dd></div>)}</dl>
    {details?.warnings.map((warning,index)=><p key={index} className="wir-reader-warning">{warning}</p>)}
    <p className="wir-footnote">操作仍会重新读取并预览；删除须先禁用并停止对象。删除只移除注册定义，文件保留且没有一键恢复备份。</p>
  </WinIrModal>;
}
