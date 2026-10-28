// Real SFTP/RPC and the native desktop app over CDP. Only the OS save dialogs
// are answered, through the debug build's scripted dialog answers; product IPC and reads are real.
import { execFileSync, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { inspectHtmlFile, startDesktop } from "./desktop.mjs";
import { Sidecar, connect } from "./rpc-harness.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const distro = process.env.CASE_LAB ?? "ubuntu";
if (!["ubuntu", "alpine"].includes(distro)) throw new Error("Choose ubuntu or alpine");
const runId = randomUUID(), name = `lr-case-workspace-${runId.slice(0, 8)}`;
const evidence = path.join(repository, "target/lab-case-workspace", runId);
const exportsRoot = path.join(evidence, "exports"); fs.mkdirSync(exportsRoot, { recursive: true });
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lovelyhawk-case-workspace-"));
const checks = [], consoleErrors = [], rendererContexts = [];
let containerId, imageId, version, sidecar, app, session, failure;
const keepalive = spawn("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", "cat"], { windowsHide: true, stdio: ["pipe", "ignore", "ignore"] });
keepalive.once("error", (error) => { failure ??= String(error); });
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function check(label, actual) { checks.push({ label, passed: Boolean(actual) }); console.log(`${actual ? "PASS" : "FAIL"} ${label}`); if (!actual) throw new Error(label); }
function wsl(...args) { return execFileSync("wsl.exe", ["-d", "Ubuntu", "-u", "root", "--", ...args], { encoding: "utf8", windowsHide: true, timeout: 60_000, maxBuffer: 2 * 1024 * 1024 }).trim(); }
const docker = (...args) => wsl("docker", ...args);
function owned() {
  const current = JSON.parse(docker("inspect", containerId))[0];
  if (current.Id !== containerId || current.Image !== imageId || current.Name !== `/${name}` || current.Config.Labels?.["lovelyres-test-run"] !== runId ||
    current.HostConfig.Privileged || current.Mounts.length !== 0 || current.HostConfig.NetworkMode !== "bridge") throw new Error("Fixture identity changed");
  return current;
}
const onHost = (...args) => { owned(); return docker("exec", containerId, ...args); };
async function until(fn, label, timeout = 60_000) { const end = Date.now() + timeout; while (Date.now() < end) { if (await fn()) return; await sleep(150); } throw new Error(`Timed out: ${label}`); }
const click = (selector, text) => session.evaluate(`(() => { const button = [...document.querySelectorAll(${JSON.stringify(selector)})].find(e => e.textContent.includes(${JSON.stringify(text)}) && !e.disabled); if (!button) throw new Error('Control missing'); button.click(); })()`);
const uiWait = (expression, label) => until(() => session.evaluate(expression), label);
async function finish(binding, job) { let current = job; await until(async () => { current = await sidecar.call("emergency.file-evidence", { action: "poll", bindingHandle: binding, jobHandle: job.jobHandle }); return current.state !== "collecting"; }, "file collection", 120_000); return current; }
try {
  imageId = docker("image", "inspect", `lovelyres-lab:${distro}`, "--format", "{{.Id}}");
  const host = wsl("hostname", "-I").split(/\s+/u).find((ip) => /^172\.(1[6-9]|2\d|3[01])\./u.test(ip)); if (!host) throw new Error("Missing private WSL address");
  containerId = docker("run", "-d", "--name", name, "--label", `lovelyres-test-run=${runId}`, "--memory", "384m", "--cpus", "1", "--pids-limit", "128", "-p", `${host}::22`, imageId);
  check("owned fixture has no privileged access or host mounts", Boolean(owned()));
  const port = Number(owned().NetworkSettings.Ports["22/tcp"][0].HostPort);
  version = onHost("sh", "-c", "cat /etc/os-release; uname -m");
  onHost("sh", "-c", "head -c 16777216 /dev/zero > /usr/local/bin/lr-case-evidence; chmod 4700 /usr/local/bin/lr-case-evidence");
  sidecar = new Sidecar(path.join(repository, "target/debug/lovelyhawk-backend.exe"), dataRoot);
  const connected = await connect(sidecar, { host, port, username: "root", password: "LabRoot#2026", id: runId, name });
  const binding = connected.bindingHandle;
  const call = (action, input = {}) => sidecar.call("case.workspace", { action, bindingHandle: binding, ...input });
  const titleA = "案件 A · Web 异常调查", titleB = "案件 B · 数据库排查";
  const requestA = { title: titleA, mutationId: randomUUID() };
  const a = await call("create", requestA), b = await call("create", { title: titleB, mutationId: randomUUID() });
  check("explicit case creation selects the new case", (await call("list")).activeCaseId === b.caseId);
  const replay = await call("create", requestA);
  check("creation replay preserves the original ID and later selection", replay.caseId === a.caseId && (await call("list")).activeCaseId === b.caseId && (await call("list")).cases.length === 2);
  let denied = false; try { await call("create", { ...requestA, title: "changed" }); } catch { denied = true; } check("changed creation retry is refused", denied);
  const original = await call("view", { caseId: a.caseId });
  for (let i=0;i<30;i++) await call("note", { caseId: a.caseId, title: `调查记录 ${i}`, content: `不可执行的测试文本 ${i} <img src=x onerror=window.caseInjected=1>` });
  check("manual evidence uses explicit case even while another is active", (await call("list")).cases.find(c=>c.id===a.caseId).evidenceCount === 30 && (await call("list")).activeCaseId === b.caseId);
  const originalItems = await call("items", { snapshotHandle: original.snapshotHandle, section: "evidence", query: "", offset: 0 });
  check("case view is immutable while newer evidence arrives", originalItems.total === 0);
  const oldReport = await call("report", { snapshotHandle: original.snapshotHandle });
  check("report follows the viewed snapshot rather than current selection", oldReport.report.evidenceCount === 0 && oldReport.report.incidentIncluded);
  const current = await call("view", { caseId: a.caseId });
  denied = false; try { await call("items", { snapshotHandle: original.snapshotHandle, section: "evidence", query: "", offset: 0 }); } catch { denied = true; } check("replaced case snapshot is revoked", denied);
  const first = await call("items", { snapshotHandle: current.snapshotHandle, section: "evidence", query: "", offset: 0 });
  const second = await call("items", { snapshotHandle: current.snapshotHandle, section: "evidence", query: "", offset: 25 });
  check("pagination preserves all evidence without overlap", first.items.length===25 && first.hasMore && second.items.length===5 && !second.hasMore && new Set([...first.items,...second.items].map(i=>i.id)).size===30);
  const found = await call("items", { snapshotHandle: current.snapshotHandle, section: "evidence", query: "测试文本 29", offset: 0 });
  check("search covers full evidence text with literal hostile markup", found.total===1 && found.items[0].text.includes("<img") && found.items[0].hashScope==="stored-preview");
  await call("note", { caseId: a.caseId, title: "调查记录 0", content: "不可执行的测试文本 0 <img src=x onerror=window.caseInjected=1>" });
  check("identical manual record retry does not create duplicate evidence", (await call("list")).cases.find(c=>c.id===a.caseId).evidenceCount===30);
  const note = await sidecar.call("notes.create", { mutationId:randomUUID(), title:"实验室交接笔记",content:"笔记正文 <script>window.caseInjected=2</script>",tags:[] });
  await call("attach-note", { caseId:a.caseId,noteId:note.id,revision:note.revision });
  await sidecar.call("notes.update", { id:note.id,expectedRevision:note.revision,mutationId:randomUUID(),content:"后来修改的笔记" });
  denied=false; try { await call("attach-note",{caseId:a.caseId,noteId:note.id,revision:note.revision}); } catch { denied=true; } check("changed note revision cannot be attached silently", denied);
  const noteView=await call("view",{caseId:a.caseId}); const archived=await call("items",{snapshotHandle:noteView.snapshotHandle,section:"evidence",query:"实验室交接笔记",offset:0});
  check("archived note retains original reviewed content after editing", archived.total===1&&archived.items[0].text===note.content&&archived.items[0].locator.includes(note.revision));
  await call("select",{caseId:a.caseId});
  const catalog=await sidecar.call("emergency-command.catalog.load",{bindingHandle:binding}); const cmd=catalog.commands.find(c=>c.title==="SUID 可执行");
  const output=await sidecar.call("emergency-command.run",{bindingHandle:binding,snapshotHandle:catalog.snapshotHandle,commandHandle:cmd.commandHandle,containerHandle:null});
  const offer=output.paths.find(p=>p.path==="/usr/local/bin/lr-case-evidence"); check("real investigation offers the owned inert sample",Boolean(offer));
  const started=await sidecar.call("emergency.file-evidence",{action:"begin",bindingHandle:binding,pathHandle:offer.pathHandle,selectedDirectory:exportsRoot});
  await call("select",{caseId:b.caseId}); const collected=await finish(binding,started);
  const manifest=JSON.parse(fs.readFileSync(path.join(exportsRoot,collected.folderName,"manifest.json"),"utf8"));
  check("in-flight file evidence keeps the captured case when selection changes",collected.state==="completed"&&collected.caseTitle===titleA&&manifest.case_id===a.caseId&&(await call("list")).activeCaseId===b.caseId);
  const another=await connect(sidecar,{host,port,username:"root",password:"LabRoot#2026",id:`${runId}-other`,name:`${name}-other`});
  denied=false;try{await sidecar.call("case.workspace",{action:"view",bindingHandle:another.bindingHandle,caseId:a.caseId});}catch{denied=true;}check("another connection cannot read a foreign case",denied);
  denied=false;try{await call("note",{caseId:a.caseId,title:"late",content:"must not save"});}catch{denied=true;}check("revoked binding cannot append a late record",denied);
  sidecar.close();sidecar=undefined;await sleep(300);
  if(distro==="ubuntu") {
    const reportFile=path.join(exportsRoot,"case-report.md");
    // The debug host consumes one scripted answer per system dialog. The probe
    // attaches once the real main document has loaded; enabling Runtime/Log
    // replays anything it logged before that, so startup errors still count.
    app=await startDesktop({dataRoot,evidence,dialogAnswers:[reportFile],
      onConsoleError:(entry)=>consoleErrors.push(JSON.stringify({...entry.params,phase:entry.phase,source:entry.source,afterCheck:checks.at(-1)?.label??"startup"})),
      onPageEvent:(method,params,target)=>{if(method==="Runtime.executionContextCreated")rendererContexts.push({url:target.url,context:params.context});}});
    session=app.session;
    await uiWait("document.querySelector('.connection-card')!==null","connection cards");
    await session.evaluate(`[...document.querySelectorAll('.connection-card')].find(e=>e.querySelector('strong').textContent===${JSON.stringify(name)}).querySelector('button').click()`);
    await uiWait("document.querySelector('[data-testid=disconnect-target]:not([disabled])')!==null","connected UI");
    await click(".nav-item","案件工作台");await uiWait("document.querySelectorAll('.case-list-item').length===2 && !document.querySelector('.case-workspace [role=status]')","case list");
    const fill=async(selector,value)=>session.evaluate(`(()=>{const e=document.querySelector(${JSON.stringify(selector)});const proto=e.tagName==='TEXTAREA'?HTMLTextAreaElement.prototype:HTMLInputElement.prototype;Object.getOwnPropertyDescriptor(proto,'value').set.call(e,${JSON.stringify(value)});e.dispatchEvent(new Event('input',{bubbles:true}));})()`);
    await click(".case-heading button","新建案件");await uiWait("document.querySelector('.case-draft input')!==null","create form");
    check("case creation focuses the named input",await session.evaluate("document.activeElement===document.querySelector('.case-draft input')"));
    await fill(".case-draft input","案件 C · 原生界面建案");await click(".case-draft button","创建并设为当前");await uiWait("document.querySelectorAll('.case-list-item').length===3 && !document.querySelector('.case-draft')","native case created");
    await click(".case-list-item",titleA);await uiWait(`document.querySelector('.case-detail h2')?.textContent===${JSON.stringify(titleA)} && document.querySelectorAll('.case-entry').length===25`,"view case A");
    check("browsing case A leaves native case C current",await session.evaluate("[...document.querySelectorAll('.case-list-item')].find(e=>e.textContent.includes('案件 C')).textContent.includes('当前归档案件')"));
    await session.send("Emulation.setDeviceMetricsOverride",{width:1080,height:700,deviceScaleFactor:1,mobile:false});
    check("case workspace fits the minimum window without horizontal overflow",await session.evaluate("document.documentElement.scrollWidth<=innerWidth+1 && document.querySelector('.case-workspace').scrollWidth<=document.querySelector('.case-workspace').clientWidth+1"));
    await session.shot("case-workspace.png");
    await click(".case-detail button","添加调查记录");await fill(".case-draft input","原生调查记录");await fill(".case-draft textarea","已核对实验室进程与日志；保持现场。<img src=x onerror=window.caseInjected=9>");
    await click(".nav-item","安全速查");await uiWait("document.querySelector('[role=dialog]')!==null","unsaved draft prompt");await click("[role=dialog] button","取消");
    check("cancelled navigation retains the investigation draft",await session.evaluate("document.querySelector('.case-draft textarea')?.value.includes('保持现场')"));
    await click(".case-draft button","保存到此案");await uiWait("!document.querySelector('.case-draft') && document.querySelector('.case-notice')?.textContent.includes('已保存')","note saved");
    await click(".case-detail button","添加线索");await fill(".case-draft textarea","203.0.113.45");await click(".case-draft button","保存到此案");await uiWait("!document.querySelector('.case-draft') && document.querySelector('.case-notice')?.textContent.includes('线索')","IOC saved");
    await click(".case-detail button","关联笔记");await uiWait("document.querySelector('.case-note-choices button')!==null","note choices");await click(".case-note-choices button","实验室交接笔记");await uiWait("document.querySelector('.case-note-picker pre')?.textContent.includes('后来修改')","review current note");
    await click(".case-draft button","保存到此案");await uiWait("!document.querySelector('.case-draft') && document.querySelector('.case-notice')?.textContent.includes('所选版本')","note linked");
    await fill(".case-search input","原生调查记录");await uiWait("document.querySelectorAll('.case-entry').length===1 && document.querySelector('.case-entry')?.textContent.includes('原生调查记录')","search native evidence");
    check("hostile evidence remains plain text in the native UI",await session.evaluate("window.caseInjected===undefined && document.querySelector('.case-entry img')===null && document.querySelector('.case-entry pre').textContent.includes('<img')"));
    await session.shot("case-evidence.png");await click(".case-tabs button","时间线");await uiWait("document.querySelector('.case-entry button')!==null","linked timeline");await click(".case-entry button","查看关联证据");await uiWait("document.querySelectorAll('.case-entry').length===1 && document.querySelector('.case-tabs [aria-pressed=true]')?.textContent.includes('证据')","timeline evidence link");
    check("timeline link returns keyboard focus to evidence search",await session.evaluate("document.activeElement===document.querySelector('.case-search input')"));
    check("timeline link resolves the associated evidence",await session.evaluate("document.querySelector('.case-entry')?.textContent.includes('实验室交接笔记')"));
    await click(".case-detail button","生成此案报告");await uiWait("document.querySelector('.disposal-report-evidence')!==null","case report");await click(".disposal-report-body nav button","Markdown");await uiWait("document.querySelector('.disposal-report-preview pre')?.textContent.includes('原生调查记录')","selected case report content");
    check("native report includes viewed A without silently selecting it",await session.evaluate("document.querySelector('.disposal-report-preview pre').textContent.includes('案件 A') && !document.querySelector('.disposal-report-preview pre').textContent.includes('案件 C') && document.querySelector('.disposal-report-notice').textContent.includes('所查看')"));
    await session.shot("case-report.png");await click(".disposal-report-heading button","保存 MD");await until(()=>fs.existsSync(reportFile),"native report export");
    check("native main export contains the selected case and evidence provenance",fs.readFileSync(reportFile,"utf8").includes("原生调查记录")&&fs.readFileSync(reportFile,"utf8").includes("external-artifact")&&fs.readFileSync(reportFile,"utf8").includes(`root@${host}:${port}`));
    await click(".disposal-report-heading button","关闭");
    check("report close returns focus to its case action",await session.evaluate("document.activeElement?.textContent==='生成此案报告'"));
    const loadCases=()=>JSON.parse(fs.readFileSync(path.join(dataRoot,"data/cases.json"),"utf8")).data;
    const statusBefore=loadCases(),activeDuringStatus=statusBefore.active_case_by_target[runId],evidenceBeforeStatus=statusBefore.cases.find(c=>c.id===a.caseId).evidence;
    await click(".case-detail button","结案并记录结论");await uiWait(`document.querySelector('.case-status-draft h2')?.textContent.includes(${JSON.stringify(titleA)})`,"review selected case disposition");
    check("online close action opens the viewed case and focuses its conclusion",await session.evaluate(`document.querySelector('.case-status-draft h2').textContent.includes(${JSON.stringify(titleA)})&&document.activeElement===document.querySelector('.case-status-draft textarea')`));
    const conclusion="已核对实验室证据；尚不能证明主机安全。<img src=x onerror=window.caseInjected=11>\n"+"审阅证据。".repeat(130)+"CONCLUSION_END",followup="待交接人员复核业务日志与恢复情况。\n"+"继续复核业务状态。".repeat(30)+"FOLLOWUP_END";
    await fill(".case-status-draft textarea",conclusion);await fill(".case-status-draft label:nth-child(2) textarea",followup);
    await click(".nav-item","安全速查");await uiWait("document.querySelector('[role=dialog]')?.textContent.includes('未保存的案件结论')","unsaved conclusion prompt");await click("[role=dialog] button","取消");
    check("cancelled navigation preserves both disposition fields",await session.evaluate(`document.querySelector('.case-status-draft textarea').value===${JSON.stringify(conclusion)}&&document.querySelector('.case-status-draft label:nth-child(2) textarea').value===${JSON.stringify(followup)}`));
    await click(".case-status-draft button","核对完整记录");await uiWait("document.querySelector('[role=dialog]')?.textContent.includes('确认结案')","review complete conclusion");
    check("close confirmation includes the entire conclusion and unresolved work as literal text",await session.evaluate(`document.querySelector('[role=dialog]').textContent.includes(${JSON.stringify(conclusion)})&&document.querySelector('[role=dialog]').textContent.includes(${JSON.stringify(followup)})&&document.querySelector('[role=dialog] img')===null&&window.caseInjected===undefined`));
    check("long case review scrolls while its title and actions remain inside the minimum window",await session.evaluate("(() => { const host=document.querySelector('[role=dialog]'),body=host.querySelector('.dialog-host-message'),box=host.getBoundingClientRect(),footer=host.querySelector('footer').getBoundingClientRect(); return body.scrollHeight>body.clientHeight&&box.top>=0&&box.bottom<=innerHeight&&footer.bottom<=innerHeight&&footer.top>=box.top; })()"));
    await session.evaluate("document.querySelector('.dialog-host-message').focus()");
    await session.send("Input.dispatchKeyEvent",{type:"keyDown",key:"Enter",code:"Enter",windowsVirtualKeyCode:13});await session.send("Input.dispatchKeyEvent",{type:"keyUp",key:"Enter",code:"Enter",windowsVirtualKeyCode:13});
    check("Enter while reading the full review does not confirm or lose its keyboard focus",loadCases().cases.find(c=>c.id===a.caseId).status==="open"&&await session.evaluate("document.querySelector('[role=dialog]')!==null&&document.activeElement===document.querySelector('.dialog-host-message')"));
    await session.send("Input.dispatchKeyEvent",{type:"keyDown",key:"End",code:"End",windowsVirtualKeyCode:35});await session.send("Input.dispatchKeyEvent",{type:"keyUp",key:"End",code:"End",windowsVirtualKeyCode:35});
    await uiWait("document.querySelector('.dialog-host-message').scrollHeight-document.querySelector('.dialog-host-message').clientHeight-document.querySelector('.dialog-host-message').scrollTop<2","keyboard scroll to complete review end");
    check("the complete review can be scrolled with the keyboard",await session.evaluate("document.querySelector('.dialog-host-message').scrollHeight-document.querySelector('.dialog-host-message').clientHeight-document.querySelector('.dialog-host-message').scrollTop<2"));
    await session.shot("case-close-review.png");await click("[role=dialog] button","取消");
    check("cancelled close leaves the case open and retains the conclusion",loadCases().cases.find(c=>c.id===a.caseId).status==="open"&&await session.evaluate(`document.querySelector('.case-status-draft textarea').value===${JSON.stringify(conclusion)}`));
    await click(".case-status-draft button","核对完整记录");await uiWait("document.querySelector('[role=dialog]')?.textContent.includes('确认结案')","fresh close plan");await click("[role=dialog] button","确认结案");
    await uiWait("!document.querySelector('.case-status-draft')&&document.querySelector('.case-notice')?.textContent.includes('结案记录')","case closed");
    const closedCase=loadCases().cases.find(c=>c.id===a.caseId);
    check("closing preserves every evidence record and the other active collection case",closedCase.status==="closed"&&JSON.stringify(closedCase.evidence)===JSON.stringify(evidenceBeforeStatus)&&loadCases().active_case_by_target[runId]===activeDuringStatus&&closedCase.timeline[0].detail.includes(followup)&&closedCase.timeline[0].operation_id);
    await click(".cases-mode button","当前主机");await uiWait("document.querySelector('[data-testid=case-workspace]')!==null&&document.querySelectorAll('.case-list-item').length===3","live cases after close");await click(".case-list-item",titleA);
    await uiWait("document.querySelector('.case-detail h2')?.textContent.includes('案件 A')&&!document.querySelector('.case-workspace [role=status]')","closed case view");
    check("closed case disables evidence additions but still allows its report",await session.evaluate("[...document.querySelectorAll('.case-detail button')].find(e=>e.textContent==='添加调查记录').disabled&&![...document.querySelectorAll('.case-detail button')].find(e=>e.textContent==='生成此案报告').disabled"));
    await click(".case-detail button","生成此案报告");await uiWait("document.querySelector('.disposal-report-evidence')!==null","closed case report");await click(".disposal-report-body nav button","Markdown");await uiWait("document.querySelector('.disposal-report-preview pre')?.textContent.includes('FOLLOWUP_END')","closure included in report");
    check("closed case report retains the complete manual conclusion and its limits",await session.evaluate(`(()=>{const text=document.querySelector('.disposal-report-preview pre').textContent.split('\\n').map(line=>line.startsWith('        ')?line.slice(8):line).join('\\n');return text.includes(${JSON.stringify(conclusion)})&&text.includes(${JSON.stringify(followup)})&&text.includes('人工调查判断')&&text.includes(${JSON.stringify(closedCase.timeline[0].operation_id)});})()`));
    await session.shot("case-closed-report.png");
    const closedHtmlFile=path.join(exportsRoot,"closed-case-report.html");
    app.setDialogAnswers([closedHtmlFile]);
    await click(".disposal-report-heading button","保存 HTML");await until(()=>fs.existsSync(closedHtmlFile),"closed case HTML export");
    // Changed in the Tauri port: there is no hidden window to render the export, so it is parsed inertly in the page; layout overflow and the rendered screenshot are no longer observed.
    const standalone=await inspectHtmlFile(session,closedHtmlFile,"(d)=>{const detail=[...d.querySelectorAll('.timeline-detail')].find(e=>e.textContent.includes('CONCLUSION_END'));return {text:detail?.textContent,hostile:d.querySelector('script,img')!==null};}");
    check("exported HTML holds the full literal conclusion and followup without active content",standalone.text?.includes(conclusion)&&standalone.text.includes(followup)&&standalone.text.includes(closedCase.timeline[0].operation_id)&&!standalone.hostile);
    await click(".disposal-report-heading button","关闭");
    await click(".case-detail button","重新调查");await uiWait("document.querySelector('.case-status-draft h2')?.textContent.includes('重新调查')","reopen reason form");
    await fill(".case-status-draft textarea","交接后发现新的日志线索。");await fill(".case-status-draft label:nth-child(2) textarea","继续核对日志与进程来源。");
    await click(".case-status-draft button","核对完整记录");await uiWait("document.querySelector('[role=dialog]')?.textContent.includes('确认重新调查')","reopen review");await click("[role=dialog] button","确认重新调查");
    await uiWait("!document.querySelector('.case-status-draft')&&document.querySelector('.case-notice')?.textContent.includes('重新打开调查')","case reopened");
    const reopenedCase=loadCases().cases.find(c=>c.id===a.caseId);
    check("reopening preserves the full closed history and does not reselect the case",reopenedCase.status==="open"&&JSON.stringify(reopenedCase.timeline.slice(1))===JSON.stringify(closedCase.timeline)&&JSON.stringify(reopenedCase.evidence)===JSON.stringify(closedCase.evidence)&&loadCases().active_case_by_target[runId]===activeDuringStatus);
    await click("[data-testid=disconnect-target]","断开");
    await uiWait("document.querySelector('[data-testid=case-library]')!==null && document.querySelectorAll('.case-list-item').length===3","offline case library");
    check("disconnect keeps the case page available as an offline library",await session.evaluate("document.querySelector('.cases-mode [aria-pressed=true]')?.textContent==='本机案件库'"));
    await click(".case-list-item",titleA);await uiWait(`document.querySelector('.case-detail h2')?.textContent===${JSON.stringify(titleA)} && document.querySelectorAll('.case-entry').length===25`,"offline evidence");
    check("offline evidence remains literal and fits the minimum window",await session.evaluate("window.caseInjected===undefined && document.querySelector('.case-entry img')===null && document.documentElement.scrollWidth<=innerWidth+1 && document.querySelector('.case-workspace').scrollWidth<=document.querySelector('.case-workspace').clientWidth+1"));
    const jsonFile=path.join(exportsRoot,"complete-case.json");
    app.setDialogAnswers([jsonFile]);
    await click(".case-detail button","导出完整案件 JSON");await until(()=>fs.existsSync(jsonFile),"offline JSON export");
    await uiWait("document.querySelector('.case-notice')?.textContent.includes('已导出')","verified offline export");
    const exportedCase=JSON.parse(fs.readFileSync(jsonFile,"utf8"));
    check("native offline JSON contains the complete viewed case and original file provenance",exportedCase.schema==="lovelyres-incident-case/v1"&&exportedCase.incident_case.id===a.caseId&&exportedCase.incident_case.evidence.length>32&&exportedCase.incident_case.evidence.some(e=>e.hash_scope==="external-artifact"&&e.locator.includes("sample.bin")));
    const activeBefore=loadCases().active_case_by_target[runId];
    await click(".case-detail button","归档此案");await uiWait("document.querySelector('[role=dialog]')?.textContent.includes('确认归档')","review archive");
    check("archive confirmation names the exact case and explains evidence preservation",await session.evaluate(`document.querySelector('[role=dialog]').textContent.includes(${JSON.stringify(titleA)}) && document.querySelector('[role=dialog]').textContent.includes('原始留证文件')`));
    await session.shot("case-archive-review.png");await click("[role=dialog] button","取消");
    await uiWait("!document.querySelector('[role=dialog]')","cancel archive");
    check("cancel leaves all working cases and their evidence intact",loadCases().cases.some(c=>c.id===a.caseId&&c.evidence.length===exportedCase.incident_case.evidence.length)&&loadCases().archives.length===0);
    await click(".case-detail button","归档此案");await uiWait("document.querySelector('[role=dialog]')!==null","archive review again");await click("[role=dialog] button","确认归档");
    await uiWait("document.querySelector('.case-notice')?.textContent.includes('已完整归档') && document.querySelector('.case-capacity')?.textContent.includes('活动案件 2 / 30')","verified archive");
    const archivedDocument=loadCases(),archiveIndex=archivedDocument.archives.find(e=>e.record.case_id===a.caseId);
    const archiveFile=path.join(dataRoot,"data/case-archives",`${archiveIndex.archive_id}.json`),archiveBytes=fs.readFileSync(archiveFile);
    check("archiving releases a slot only after the exact complete archive exists",!archivedDocument.cases.some(c=>c.id===a.caseId)&&JSON.stringify(JSON.parse(archiveBytes).incident_case)===JSON.stringify(exportedCase.incident_case)&&archivedDocument.active_case_by_target[runId]===activeBefore);
    check("archiving preserves the original collected file and manifest",fs.existsSync(path.join(exportsRoot,collected.folderName,"sample.bin"))&&fs.existsSync(path.join(exportsRoot,collected.folderName,"manifest.json")));
    await click(".case-list-item",titleA);await uiWait("[...document.querySelectorAll('.case-detail button')].some(e=>e.textContent==='恢复到活动列表'&&!e.disabled)","open archived version");
    await session.shot("case-library-offline.png");await click(".case-detail button","恢复到活动列表");await uiWait("document.querySelector('[role=dialog]')?.textContent.includes('确认恢复')","restore review");await click("[role=dialog] button","确认恢复");
    await uiWait("document.querySelector('.case-notice')?.textContent.includes('已恢复') && document.querySelectorAll('.case-list-item').length===4","restore completed");
    const restored=loadCases();
    check("restoring retains the immutable archive and does not change current collection",JSON.stringify(restored.cases.find(c=>c.id===a.caseId))===JSON.stringify(exportedCase.incident_case)&&fs.readFileSync(archiveFile).equals(archiveBytes)&&restored.active_case_by_target[runId]===activeBefore&&restored.archives.length===1);
    const archivedButton=await session.evaluate(`(()=>{const e=[...document.querySelectorAll('.case-list-item')].find(e=>e.textContent.includes(${JSON.stringify(titleA)})&&e.textContent.includes('已归档'));if(!e)return false;e.click();return true;})()`);check("restored case and archive version remain separately selectable",archivedButton);
    await uiWait("[...document.querySelectorAll('.case-detail button')].some(e=>e.textContent==='恢复到活动列表'&&!e.disabled)","archive version remains readable");await click(".case-detail button","恢复到活动列表");
    await uiWait("document.querySelector('.case-error')?.textContent.includes('已有同编号案件')","restore conflict");
    check("restore refuses to overwrite the already active same-ID case",!await session.evaluate("document.querySelector('[role=dialog]')!==null")&&loadCases().cases.length===3&&fs.readFileSync(archiveFile).equals(archiveBytes));
    await session.shot("case-library-restored.png");
    fs.writeFileSync(path.join(exportsRoot,"archive-version.json"),archiveBytes);
    // Startup errors arrive in consoleErrors with phase "startup" (replayed when the page was attached).
    check("desktop console has no errors",consoleErrors.length===0);
  }
} catch (error) {
  failure = String(error); console.error(failure); process.exitCode = 1;
  if (session) { try { await session.shot("failure.png"); fs.writeFileSync(path.join(evidence, "failure-text.txt"), await session.evaluate("document.body.innerText")); } catch {} }
} finally {
  sidecar?.close();
  if (app) await app.close();
  if (containerId) { try { owned(); docker("rm", "-f", containerId); check("owned container removed", true); } catch (error) { failure ??= String(error); process.exitCode = 1; } }
  try {
    const resolved = fs.realpathSync(dataRoot), temp = fs.realpathSync(os.tmpdir());
    if (path.dirname(resolved) !== temp || !/^lovelyhawk-case-workspace-[A-Za-z0-9]{6}$/u.test(path.basename(resolved))) throw new Error("Unexpected test data directory");
    fs.rmSync(resolved, { recursive: true, maxRetries: 10, retryDelay: 300 }); check("isolated app data removed", true);
  } catch (error) { failure ??= String(error); process.exitCode = 1; }
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify({ runId, date: new Date().toISOString(), distro, imageId, version, checks, consoleErrors, rendererContexts, error: failure ?? null,
    limits: ["native OS report and case JSON save dialogs alone are answered through the debug build's scripted dialog answers", "exported HTML is parsed inertly in the app page; its rendered layout and screenshot are not captured (the Tauri host has no hidden window)", "page console observation starts when CDP attaches to the loaded document; earlier messages are those the page replays", "SFTP double observation is not an atomic filesystem snapshot", "container userland evidence does not establish complete distribution support"] }, null, 2));
  console.log(`Evidence: ${path.join(evidence, "report.json")}`); keepalive.stdin.end();
}
