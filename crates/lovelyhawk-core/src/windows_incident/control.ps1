$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
function Hash($s){$h=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$s)))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}}
$subject=$request.subject;$op=[string]$request.operation;$name=[string]$subject.name;$kind=[string]$subject.kind
$target=[Environment]::MachineName
$machine=Hash ((Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid)
$native=$null;$task=$null;$scm=[IntPtr]::Zero;$handle=[IntPtr]::Zero
$started=$false;$receipt=@{state='refused';message='检查未通过，未执行。';after=$null}
function RegistryIdentity($root){
  $parts=New-Object 'Collections.Generic.List[string]';$pending=New-Object 'Collections.Generic.Queue[string]';$pending.Enqueue('');$n=0
  while($pending.Count){
    if(++$n -gt 128){throw 'Service configuration exceeds inspection limit'}
    $relative=$pending.Dequeue();$path=if($relative){$root+'\'+$relative}else{$root};$key=Get-Item -LiteralPath $path
    try{
      $parts.Add($relative);$parts.Add($key.GetAccessControl().GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]13))
      $values=@($key.GetValueNames()|Sort-Object);if($values.Count -gt 256){throw 'Value limit'}
      foreach($v in $values){
        if($relative -eq '' -and $v -ceq 'Start'){continue}
        $value=$key.GetValue($v,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $encoded=if($value -is [byte[]]){[Convert]::ToBase64String($value)}else{ConvertTo-Json -InputObject $value -Compress -Depth 3}
        if($encoded.Length -gt 32768){throw 'Value size limit'}
        $parts.Add((@($v,[string]$key.GetValueKind($v),$encoded)|ConvertTo-Json -Compress))
      }
      foreach($child in ($key.GetSubKeyNames()|Sort-Object)){if($pending.Count -ge 128){throw 'Subkey limit'};$pending.Enqueue($(if($relative){$relative+'\'+$child}else{$child}))}
    }finally{$key.Dispose()}
  }
  return Hash ($parts -join "`n")
}
function Native-Setup {
  Add-Type -AssemblyName System.ServiceProcess
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class LovelyHawkControl {
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern IntPtr OpenSCManager(string m,string d,uint a);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern IntPtr OpenService(IntPtr m,string n,uint a);
 [DllImport("advapi32.dll",SetLastError=true)] public static extern bool CloseServiceHandle(IntPtr h);
 [DllImport("advapi32.dll",SetLastError=true)] public static extern bool QueryServiceStatusEx(IntPtr h,int l,byte[] b,uint s,out uint n);
 [DllImport("advapi32.dll",SetLastError=true)] public static extern bool ControlService(IntPtr h,uint c,byte[] s);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern bool StartService(IntPtr h,uint n,IntPtr a);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern bool ChangeServiceConfig(IntPtr h,uint t,uint s,uint e,string p,string g,IntPtr tag,string dep,string acc,string pwd,string display);
 [DllImport("advapi32.dll",SetLastError=true)] public static extern bool QueryServiceObjectSecurity(IntPtr h,uint info,byte[] b,uint n,out uint needed);
 public static IntPtr Manager(){return OpenSCManager(null,null,1);}
 public static bool ConfigureMode(IntPtr h,uint mode){return ChangeServiceConfig(h,uint.MaxValue,mode,uint.MaxValue,null,null,IntPtr.Zero,null,null,null,null);}
 public static uint[] Status(IntPtr h){byte[] b=new byte[36];uint n;if(!QueryServiceStatusEx(h,0,b,36,out n))throw new Exception("Status failed");uint[] r=new uint[9];for(int i=0;i<9;i++)r[i]=BitConverter.ToUInt32(b,i*4);return r;}
 public static string Security(IntPtr h){uint n;QueryServiceObjectSecurity(h,7,null,0,out n);if(n==0||n>65536)throw new Exception("Security size");byte[] b=new byte[n];if(!QueryServiceObjectSecurity(h,7,b,n,out n))throw new Exception("Security failed");return Convert.ToBase64String(b);}
}
'@
}
function Service-Object {
  $status=[LovelyHawkControl]::Status($handle)
  $path='HKLM:\SYSTEM\CurrentControlSet\Services\'+$name
  $key=Get-Item -LiteralPath $path
  try{$mode=[int]$key.GetValue('Start');$type=[int]$key.GetValue('Type');$critical=[int]$key.GetValue('ErrorControl');$command=[string]$key.GetValue('ImagePath','',[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}finally{$key.Dispose()}
  if(($kind -eq 'drivers') -ne (($type -band 3) -ne 0)){throw 'Object type changed'}
  $config=Hash ((RegistryIdentity $path)+[LovelyHawkControl]::Security($handle))
  $controller=[System.ServiceProcess.ServiceController]::new($name)
  try{
    $dependents=@($controller.DependentServices|Where-Object{$_.Status -ne 'Stopped'}|ForEach-Object{$_.ServiceName}|Sort-Object)
    $dependencyStates=New-Object 'Collections.Generic.List[string]';$queue=New-Object 'Collections.Generic.Queue[object]';$seen=@{}
    foreach($dependency in $controller.ServicesDependedOn){$queue.Enqueue($dependency)}
    while($queue.Count){
      if($queue.Count+$seen.Count -gt 128){throw 'Dependency traversal limit'}
      $dependency=$queue.Dequeue()
      try{if($seen.ContainsKey($dependency.ServiceName)){continue};$seen[$dependency.ServiceName]=$true;if($seen.Count -gt 64){throw 'Dependency limit'};$dependency.Refresh();$dependencyStates.Add($dependency.ServiceName+':'+$dependency.Status);foreach($parent in $dependency.ServicesDependedOn){$queue.Enqueue($parent)}}finally{$dependency.Dispose()}
    }
    $dependencies=@($dependencyStates|Sort-Object)
  }finally{$controller.Dispose()}
  if($dependents.Count -gt 64 -or $dependencies.Count -gt 64){throw 'Dependency limit'}
  $state=[string]@{1='Stopped';2='StartPending';3='StopPending';4='Running';5='ContinuePending';6='PausePending';7='Paused'}[[int]$status[1]]
  return @{configHash=$config;setting=[string]$mode;state=$state;command=$command;critical=$critical;canStop=($status[2] -band 1) -ne 0;pid=[uint32]$status[7];dependents=$dependents;dependencies=$dependencies;instances=@();fingerprint=(Hash ($config+':'+$mode+':'+$state+':'+$status[7]+':'+($dependents -join '|')+':'+($dependencies -join '|')))}
}
function Task-Runs {
  # Include hidden tasks; GetInstances(0) can omit them on supported Windows versions.
  $all=$scheduler.GetRunningTasks(1);if($all.Count -gt 2048){throw 'Running task inspection limit'}
  $matches=@($all|Where-Object{[string]::Equals([string]$_.Path,[string]$task.Path,[StringComparison]::OrdinalIgnoreCase)})
  if($matches.Count -gt 64){throw 'Running instance limit'}
  return $matches
}
function Task-Object {
  $xml=[string]$task.Xml;if($xml.Length -gt 262144){throw 'Task definition limit'}
  $settings=New-Object System.Xml.XmlReaderSettings;$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null;$settings.MaxCharactersInDocument=262144
  $reader=[Xml.XmlReader]::Create([IO.StringReader]::new($xml),$settings);$doc=New-Object Xml.XmlDocument;$doc.XmlResolver=$null
  try{$doc.Load($reader)}finally{$reader.Dispose()}
  $ns=New-Object Xml.XmlNamespaceManager($doc.NameTable);$ns.AddNamespace('t','http://schemas.microsoft.com/windows/2004/02/mit/task')
  $commands=@($doc.SelectNodes('/t:Task/t:Actions/t:Exec',$ns)|ForEach-Object{($_.Command+' '+$_.Arguments).Trim()})
  $enabled=$doc.SelectSingleNode('/t:Task/t:Settings/t:Enabled',$ns)
  if($enabled){[void]$enabled.ParentNode.RemoveChild($enabled)}
  $runs=@(Task-Runs)
  $ids=@($runs|ForEach-Object{[string]$_.InstanceGuid}|Sort-Object)
  $config=Hash ($doc.OuterXml+[string]$task.GetSecurityDescriptor(7))
  $flag=if($task.Enabled){'1'}else{'0'}
  $state=[string]@{0='Unknown';1='Disabled';2='Queued';3='Ready';4='Running'}[[int]$task.State]
  return @{configHash=$config;setting=$flag;state=$state;command=($commands -join ' ; ');critical=0;canStop=$true;pid=0;dependents=@();dependencies=@();instances=@($ids);fingerprint=(Hash ($config+':'+$flag+':'+$state+':'+($ids -join '|')))}
}
function Observe {if($kind -eq 'tasks'){Task-Object}else{Service-Object}}
function Check-Operation($o){
  if($kind -eq 'tasks'){
    if(@('run','stop','enable','disable') -notcontains $op){throw 'Invalid operation'}
    if($op -eq 'run' -and $o.setting -ne '1'){throw 'Task disabled'}
    if($op -eq 'stop' -and $o.instances.Count -eq 0){throw 'No approved running task instance'}
  }else{
    if(@('start','stop','restart','automatic','manual','disable') -notcontains $op){throw 'Invalid operation'}
    if(@('RpcSs','RpcEptMapper','DcomLaunch','TermService','SessionEnv','UmRdpService','Winmgmt','Schedule','EventLog','PlugPlay','Power','LSM','SamSs','BFE','MpsSvc','LanmanWorkstation','LanmanServer') -contains $name){throw 'Core or connection service'}
    if([int]$o.setting -lt 2 -or $o.critical -ge 2){throw 'Boot or critical service'}
    if(@('Stopped','Running') -notcontains $o.state){throw 'Service transitioning'}
    if(@('stop','restart') -contains $op){if($o.state -ne 'Running' -or -not $o.canStop -or $o.dependents.Count){throw 'Cannot stop without affecting dependencies'}}
    if(@('start','restart') -contains $op){if($o.setting -eq '4' -or @($o.dependencies|Where-Object{$_ -notlike '*:Running'}).Count){throw 'Disabled or inactive dependency'}}
    if($op -eq 'start' -and $o.state -ne 'Stopped'){throw 'Already running'}
    if($o.pid -gt 0){
      $processes=@(Get-CimInstance Win32_Process -OperationTimeoutSec 6|Select-Object -First 32769);if($processes.Count -gt 32768){throw 'Process limit'}
      $by=@{};foreach($p in $processes){$by[[uint32]$p.ProcessId]=$p};$ancestorId=[uint32]$PID;$seen=@{}
      while($by.ContainsKey($ancestorId) -and -not $seen.ContainsKey($ancestorId)){if($ancestorId -eq $o.pid){throw 'Collector service'};$seen[$ancestorId]=$true;$ancestorId=[uint32]$by[$ancestorId].ParentProcessId}
    }
  }
}
function Wait-Service($state){$timer=[Diagnostics.Stopwatch]::StartNew();while($timer.Elapsed.TotalSeconds -lt 12){if(([LovelyHawkControl]::Status($handle))[1] -eq $state){return};Start-Sleep -Milliseconds 150};throw 'Service wait timeout'}
try{
  if($kind -eq 'tasks'){
    $scheduler=New-Object -ComObject 'Schedule.Service';$scheduler.Connect();$folderPath=([string]$subject.location).TrimEnd('\');if(-not $folderPath){$folderPath='\'};$folder=$scheduler.GetFolder($folderPath);$task=$folder.GetTask($name)
  }else{
    Native-Setup;$scm=[LovelyHawkControl]::Manager();if($scm -eq [IntPtr]::Zero){throw 'SCM permission'}
    $rights=[uint32]0x2000d
    if($request.mode -eq 'apply'){$rights=$rights -bor $(if(@('automatic','manual','disable') -contains $op){2}elseif($op -eq 'restart'){0x30}elseif($op -eq 'start'){0x10}else{0x20})}
    $handle=[LovelyHawkControl]::OpenService($scm,$name,$rights);if($handle -eq [IntPtr]::Zero){throw 'Service permission'}
  }
  $before=Observe
  if($request.mode -eq 'inspect'){
    Check-Operation $before
    @{target=$target;machine=$machine;observation=$before}|ConvertTo-Json -Depth 8 -Compress
    return
  }
  if($machine -cne $request.machine -or $before.fingerprint -cne $request.fingerprint){throw 'Target or configuration changed'}
  Check-Operation $before
  # Immediate second read after permission/dependency checks; Windows does not offer a configuration CAS.
  if((Observe).fingerprint -cne $before.fingerprint){throw 'Configuration changed during checks'}
  $started=$true
  if($kind -eq 'tasks'){
    switch($op){
      'enable' {$task.Enabled=$true}
      'disable' {$task.Enabled=$false}
      'run' {$run=$task.Run($null);if(-not $run.InstanceGuid){throw 'No run receipt'};$receipt.state='submitted';$receipt.message='调度器已接受本次运行请求；任务可能已迅速退出，请查看任务日志与实际业务结果。'}
      'stop' {foreach($id in $before.instances){$match=@(Task-Runs|Where-Object{$_.InstanceGuid -ceq $id});foreach($r in $match){$r.Stop()}}}
    }
  }else{
    if(@('stop','restart') -contains $op){if(-not [LovelyHawkControl]::ControlService($handle,1,(New-Object byte[] 28))){throw 'Stop refused'};Wait-Service 1}
    if(@('start','restart') -contains $op){if(-not [LovelyHawkControl]::StartService($handle,0,[IntPtr]::Zero)){throw 'Start refused'};Wait-Service 4}
    if(@('automatic','manual','disable') -contains $op){$mode=@{automatic=2;manual=3;disable=4}[$op];if(-not [LovelyHawkControl]::ConfigureMode($handle,$mode)){throw 'Change refused'}}
  }
  $after=Observe;$receipt.after=$after
  if($after.configHash -cne $before.configHash){throw 'Other configuration changed; verify manually'}
  $expected=switch($op){'automatic'{'2'};'manual'{'3'};'disable'{if($kind -eq 'tasks'){'0'}else{'4'}};'enable'{'1'};default{$before.setting}}
  if($after.setting -cne $expected){throw 'Setting readback mismatch'}
  if($kind -ne 'tasks' -and (($op -eq 'stop' -and $after.state -ne 'Stopped') -or (@('start','restart') -contains $op -and $after.state -ne 'Running'))){throw 'Service state readback mismatch'}
  if($kind -eq 'tasks' -and $op -eq 'stop' -and @($after.instances|Where-Object{$before.instances -contains $_}).Count){throw 'Approved task instances still running'}
  if($receipt.state -ne 'submitted'){$receipt.state='verified';$receipt.message='已独立回读并核实本次变更；服务或任务状态不代表业务健康。'}
}catch{
  $receipt.state=if($started){'uncertain'}else{'refused'}
  $receipt.message=if($started){'操作已经开始，但未能完整核实结果。请刷新对象并核对日志，不要重复旧计划；不会自动重启已停止的对象。'}else{'对象、权限、依赖或系统保护条件未通过，未执行。请刷新；核心 / 引导服务、运行中的依赖以及采集连接服务不支持此处直接操作。'}
}finally{
  if($handle -ne [IntPtr]::Zero){[void][LovelyHawkControl]::CloseServiceHandle($handle)}
  if($scm -ne [IntPtr]::Zero){[void][LovelyHawkControl]::CloseServiceHandle($scm)}
}
if($request.mode -eq 'inspect'){@{error=$receipt.message}|ConvertTo-Json -Compress}else{$receipt|ConvertTo-Json -Depth 8 -Compress}
