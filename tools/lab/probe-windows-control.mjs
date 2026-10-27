// Local Windows validation. Creates at most one uniquely named, current-user,
// manually triggered sleeping task. It never elevates or mutates existing tasks/services.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createHash, randomUUID } from "node:crypto";
import { gzipSync } from "node:zlib";
import { spawnSync } from "node:child_process";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const root = path.join(repo, "target", "windows-control", randomUUID());
fs.mkdirSync(root, { recursive: true });
const powershell = path.join(process.env.SystemRoot, "System32/WindowsPowerShell/v1.0/powershell.exe");
const checks = [];
function record(name, state, detail = undefined) { checks.push({ name, state, detail }); console.log(`${state} ${name}`); }
function ps(source) {
  const compressed = gzipSync(Buffer.from(`[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);\n${source}`)).toString("base64");
  const loader = `$m=[IO.MemoryStream]::new([Convert]::FromBase64String('${compressed}'));$z=[IO.Compression.GZipStream]::new($m,[IO.Compression.CompressionMode]::Decompress);$r=[IO.StreamReader]::new($z,[Text.Encoding]::UTF8);try{& ([ScriptBlock]::Create($r.ReadToEnd()))}finally{$r.Dispose();$m.Dispose()}`;
  const encoded = Buffer.from(loader, "utf16le").toString("base64");
  if (encoded.length > 29000) throw new Error("command budget exceeded");
  const result = spawnSync(powershell, ["-NoProfile", "-NonInteractive", "-EncodedCommand", encoded], { encoding: "utf8", windowsHide: true, timeout: 45000, maxBuffer: 4 * 1024 * 1024 });
  if (result.status !== 0 || result.error) throw new Error("PowerShell failed or timed out; no raw target output retained");
  return JSON.parse(result.stdout.trim());
}
const script = fs.readFileSync(path.join(repo, "crates/lovelyhawk-core/src/windows_incident/control.ps1"), "utf8").replaceAll("\r\n","\n");
function control(request) {
  const data = Buffer.from(JSON.stringify(request)).toString("base64");
  const source=process.env.LOVELYHAWK_PROBE_DIAGNOSTICS==="1"?script.replace("}catch{\n  $receipt.state=","}catch{\n  $probeFailure=$_.Exception.GetType().FullName+': line '+$_.InvocationInfo.ScriptLineNumber\n  $receipt.state=").replace("@{error=$receipt.message}","@{error=$receipt.message;diagnostic=$probeFailure}"):script;
  const result=ps(`$request=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${data}'))|ConvertFrom-Json\n${source}`);
  if(result.diagnostic)record("inspection diagnostic", "INFO",result.diagnostic);
  return result;
}
function assert(name, condition) { record(name, condition ? "PASS" : "FAIL"); if (!condition) throw new Error(name); }
const nonce = `LovelyHawk-Control-${randomUUID()}`;
const folder = `\\${nonce}\\`;
const subject = { kind: "tasks", name: "OwnedSleep", location: folder };
let created = false;
let failed = false;
let environment = null;
try {
  environment=ps("$o=Get-CimInstance Win32_OperatingSystem;@{os=$o.Caption;version=$o.Version;architecture=$o.OSArchitecture;powershell=$PSVersionTable.PSVersion.ToString();elevated=([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)}|ConvertTo-Json");
  const catalog = ps(fs.readFileSync(path.join(repo, "crates/lovelyhawk-core/src/windows_incident/startup_catalog.ps1"), "utf8"));
  assert("19 explicit categories with matching counts", catalog.categories.length === 19 && catalog.categories.every(c => c.count === catalog.entries.filter(e => e.category === c.category).length));
  record("catalog observation", "PASS", { total: catalog.entries.length, truncated: catalog.truncated, categories: catalog.categories, warnings: catalog.warnings });
  const protectedPlan = control({ mode: "inspect", subject: { kind: "services", name: "RpcSs", location: "" }, operation: "stop" });
  assert("core service preview refused without effects", !!protectedPlan.error);
  const service = control({ mode: "inspect", subject: { kind: "services", name: "Spooler", location: "" }, operation: "manual" });
  record("read-only service configuration and dependencies", service.observation ? "PASS" : "NOT_RUN", service.observation ? { state: service.observation.state, setting: service.observation.setting } : "Permissions or system protection refused inspection");
  record("service and driver mutations", "NOT_RUN", "No owned service/driver fixture or elevated token; no real service changed");
  const create = ps(`$ErrorActionPreference='Stop';$s=New-Object -ComObject Schedule.Service;$s.Connect();$root=$s.GetFolder('\\');$created=$false;try{$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;$f=$root.CreateFolder('${nonce}');$created=$true;$t=$s.NewTask(0);$t.RegistrationInfo.Author='${nonce}';$t.RegistrationInfo.Description='Owned LovelyHawk inert task verification';$t.Principal.UserId=$sid;$t.Principal.LogonType=3;$t.Principal.RunLevel=0;$t.Settings.Enabled=$true;$t.Settings.Hidden=$true;$t.Settings.ExecutionTimeLimit='PT1M';$t.Settings.AllowDemandStart=$true;$t.Settings.DisallowStartIfOnBatteries=$false;$a=$t.Actions.Create(0);$a.Path=Join-Path $env:SystemRoot 'System32\\WindowsPowerShell\\v1.0\\powershell.exe';$a.Arguments='-NoProfile -NonInteractive -WindowStyle Hidden -Command "Start-Sleep -Seconds 45"';[void]$f.RegisterTaskDefinition('OwnedSleep',$t,2,$sid,$null,3);@{created=$true}|ConvertTo-Json}catch{if($created){$root.DeleteFolder('${nonce}',0)};@{created=$false;reason='Current account cannot create the isolated scheduler fixture'}|ConvertTo-Json}`);
  created = create.created;
  if (!created) record("owned scheduled-task mutations", "NOT_RUN", create.reason);
  else {
    const inspect = (operation) => control({ mode: "inspect", subject, operation });
    const apply = (operation, plan) => control({ mode: "apply", subject, operation, machine: plan.machine, fingerprint: plan.observation.fingerprint });
    const first = inspect("disable");
    assert("owned task preview exposes original enabled state", first.observation?.setting === "1" && first.observation.instances.length===0);
    const disabled = apply("disable", first);
    assert("disable has independent readback", disabled.state === "verified" && disabled.after.setting === "0");
    const stale = apply("disable", first);
    assert("changed configuration rejects stale confirmation", stale.state === "refused");
    const enabled = apply("enable", inspect("enable"));
    assert("restore enabled state preserves full definition", enabled.state === "verified" && enabled.after.setting === "1" && enabled.after.configHash === first.observation.configHash);
    const run = apply("run", inspect("run"));
    assert("manual run reports submission, not business success", run.state === "submitted");
    const taskState=ps(`$s=New-Object -ComObject Schedule.Service;$s.Connect();$f=$s.GetFolder('\\${nonce}');$timer=[Diagnostics.Stopwatch]::StartNew();do{$t=$f.GetTask('OwnedSleep');$count=@($s.GetRunningTasks(1)|Where-Object{[string]::Equals([string]$_.Path,[string]$t.Path,[StringComparison]::OrdinalIgnoreCase)}).Count;if($count -gt 0){break};Start-Sleep -Milliseconds 200}while($timer.Elapsed.TotalSeconds -lt 5);@{instances=$count;state=$t.State;lastResult=$t.LastTaskResult}|ConvertTo-Json`);
    record("owned task after run", "INFO",taskState);
    const stopping = inspect("stop");
    assert("stop preview identifies running instances", stopping.observation?.instances.length > 0);
    const stopped = apply("stop", stopping);
    assert("stop verifies only approved task instances", stopped.state === "verified" && !stopped.after.instances.some(id => stopping.observation.instances.includes(id)));
  }
} catch (error) { failed = true; record("probe completion", "FAIL", String(error.message)); }
finally {
  if (created) {
    try {
      const cleanup = ps(`$ErrorActionPreference='Stop';$s=New-Object -ComObject Schedule.Service;$s.Connect();$f=$s.GetFolder('\\${nonce}');$t=$f.GetTask('OwnedSleep');[xml]$x=$t.Xml;if($x.Task.RegistrationInfo.Author -cne '${nonce}' -or $x.Task.Actions.Exec.Arguments -cne '-NoProfile -NonInteractive -WindowStyle Hidden -Command "Start-Sleep -Seconds 45"'){throw 'Ownership changed'};$t.Stop(0);$f.DeleteTask('OwnedSleep',0);$s.GetFolder('\\').DeleteFolder('${nonce}',0);@{removed=$true}|ConvertTo-Json`);
      assert("only the owned task and empty folder removed", cleanup.removed);
    } catch { failed = true; record("owned task cleanup", "FAIL", { folder, task: subject.name }); }
  }
  const sourceHashes=Object.fromEntries(["control.ps1","startup_catalog.ps1","inventory.ps1","control.rs"].map(name=>[name,createHash("sha256").update(fs.readFileSync(path.join(repo,"crates/lovelyhawk-core/src/windows_incident",name))).digest("hex")]));
  fs.writeFileSync(path.join(root, "results.json"), JSON.stringify({ observedAt: new Date().toISOString(), environment, sourceHashes, scope: "local native scripts; not RDP or core journal integration", checks }, null, 2));
  console.log(root);
}
if (failed) process.exitCode = 1;
