import { describe,expect,it } from "vitest";
import { isWindowsIncidentRequest,matchesWindowsIncidentResponse,isWindowsProcessPlan,isWindowsProcessChangeReport,isWindowsInventorySnapshot } from "./windows-incident-contract";
const sessionId="00000000-0000-4000-8000-000000000001";
const root={pid:100,ppid:10,name:"lab.exe",startTime:"2026-10-27T00:00:00.1234560Z"};
const plan={id:sessionId,target:"lab",expiresAt:1800000000,tree:true,items:[root,{...root,pid:101,ppid:100,startTime:"2026-10-27T00:00:00.1234570Z"}]};
describe("process plans and inventories",()=>{
  it("rejects injected scopes and requires exactly a plan id to apply",()=>{
    expect(isWindowsIncidentRequest({action:"plan-process-change",pid:100,startTime:root.startTime,tree:true,sessionId})).toBe(true);
    expect(isWindowsIncidentRequest({action:"apply-process-plan",planId:sessionId,sessionId,pids:[100]})).toBe(false);
    expect(isWindowsIncidentRequest({action:"collect-inventory",kind:"services;whoami",sessionId})).toBe(false);
  });
  it("validates parent identity, including microsecond creation times, and response scope",()=>{
    expect(isWindowsProcessPlan(plan)).toBe(true);
    expect(isWindowsProcessPlan({...plan,items:[root,{...root,pid:101,ppid:999}]})).toBe(false);
    expect(isWindowsProcessPlan({...plan,tree:false})).toBe(false);
    expect(matchesWindowsIncidentResponse({action:"plan-process-change",pid:102,startTime:root.startTime,tree:true,sessionId},{kind:"process-plan",plan})).toBe(false);
    expect(isWindowsProcessChangeReport({id:sessionId,message:"结果",items:[{pid:100,state:"verified"},{pid:100,state:"failed"}]})).toBe(false);
  });
  it("keeps permission gaps and rejects different inventory kinds or unbounded rows",()=>{
    const snapshot={kind:"drivers",observedAt:root.startTime,totalCount:0,truncated:false,warnings:["权限不足"],entries:[]};
    expect(isWindowsInventorySnapshot(snapshot)).toBe(true);
    expect(matchesWindowsIncidentResponse({action:"collect-inventory",kind:"services",sessionId},{kind:"inventory",snapshot})).toBe(false);
    expect(isWindowsInventorySnapshot({...snapshot,extra:"unexpected"})).toBe(false);
  });
});
