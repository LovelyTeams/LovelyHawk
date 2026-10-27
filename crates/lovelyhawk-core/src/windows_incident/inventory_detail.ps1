$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$subject=$request.subject;$name=[string]$subject.name;$kind=[string]$subject.kind
$fields=New-Object 'Collections.Generic.List[object]';$warnings=New-Object 'Collections.Generic.List[string]'
function Warn($text){if($warnings.Count -lt 16 -and -not $warnings.Contains($text)){$warnings.Add($text)}}
function Field($label,$value){
  if($fields.Count -ge 96){Warn '详情超过 96 个字段，部分信息未展示。';return}
  $text=if($null -eq $value){'未取得'}else{[string]$value}
  if($text.Length -gt 2000){$text=$text.Substring(0,2000)+'…[截断]';Warn '部分长字段已截断，请结合系统管理工具查看完整配置。'}
  $fields.Add(@{label=$label;value=$text})
}
try{
  if($kind -eq 'tasks'){
    $scheduler=New-Object -ComObject Schedule.Service;$scheduler.Connect();$folder=([string]$subject.location).TrimEnd('\');if(-not $folder){$folder='\'}
    $task=$scheduler.GetFolder($folder).GetTask($name);$fullName=[string]$subject.location+$name
    $xml=[string]$task.Xml;if($xml.Length -gt 262144){throw 'Task definition too large'}
    $settings=New-Object Xml.XmlReaderSettings;$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null;$settings.MaxCharactersInDocument=262144
    $reader=[Xml.XmlReader]::Create([IO.StringReader]::new($xml),$settings);$doc=New-Object Xml.XmlDocument;$doc.XmlResolver=$null
    try{$doc.Load($reader)}finally{$reader.Dispose()}
    $ns=New-Object Xml.XmlNamespaceManager($doc.NameTable);$ns.AddNamespace('t','http://schemas.microsoft.com/windows/2004/02/mit/task')
    Field '完整任务路径' $task.Path
    Field '状态' (@{0='未知';1='已禁用';2='已排队';3='就绪';4='运行中'}[[int]$task.State])
    Field '启用状态' $(if($task.Enabled){'启用'}else{'禁用'})
    foreach($pair in @(@('说明','RegistrationInfo/Description'),@('作者','RegistrationInfo/Author'),@('注册日期','RegistrationInfo/Date'),@('运行账户','Principals/Principal/UserId'),@('运行组','Principals/Principal/GroupId'),@('登录类型','Principals/Principal/LogonType'),@('运行权限','Principals/Principal/RunLevel'))){$node=$doc.SelectSingleNode('/t:Task/t:'+($pair[1] -replace '/','/t:'),$ns);if($node){Field $pair[0] $node.InnerText}}
    foreach($pair in @(@('上次运行时间（目标本地时间）','LastRunTime'),@('下次计划时间（目标本地时间）','NextRunTime'))){try{$date=[DateTime]$task.($pair[1]);Field $pair[0] $(if($date.Year -lt 1901){'调度器未提供有效时间'}else{$date.ToString('yyyy-MM-dd HH:mm:ss')})}catch{Warn '未取得完整的任务运行时间。'}}
    try{Field '上次返回代码（不代表业务成功）' ([string]$task.LastTaskResult);Field '错过运行次数' $task.NumberOfMissedRuns}catch{Warn '未取得任务返回代码或错过运行次数。'}
    foreach($pair in @(@('多实例策略','MultipleInstancesPolicy'),@('执行时限','ExecutionTimeLimit'),@('隐藏任务','Hidden'),@('错过后尽快运行','StartWhenAvailable'),@('需要网络','RunOnlyIfNetworkAvailable'),@('电池模式禁止启动','DisallowStartIfOnBatteries'),@('切换电池时停止','StopIfGoingOnBatteries'),@('允许唤醒','WakeToRun'))){$node=$doc.SelectSingleNode('/t:Task/t:Settings/t:'+$pair[1],$ns);if($node){Field $pair[0] $node.InnerText}}
    $actions=@($doc.SelectNodes('/t:Task/t:Actions/*',$ns));Field '操作数量' $actions.Count
    for($i=0;$i -lt [Math]::Min(32,$actions.Count);$i++){
      $a=$actions[$i];$parts=New-Object 'Collections.Generic.List[string]';$parts.Add('类型：'+$a.LocalName)
      foreach($p in @('Command','Arguments','WorkingDirectory','ClassId')){$n=$a.SelectSingleNode('t:'+$p,$ns);if($n){$parts.Add($p+'：'+$n.InnerText)}}
      if($a.LocalName -ne 'Exec'){Warn '非命令操作只显示类型及类标识；组件私有数据、邮件与附件内容不进入此详情。'}
      Field ('操作 '+($i+1)) ($parts -join "`n")
    }
    $triggers=@($doc.SelectNodes('/t:Task/t:Triggers/*',$ns));Field '触发器数量' $triggers.Count
    for($i=0;$i -lt [Math]::Min(32,$triggers.Count);$i++){
      $t=$triggers[$i];$parts=New-Object 'Collections.Generic.List[string]';$parts.Add('类型：'+$t.LocalName)
      foreach($p in @('StartBoundary','EndBoundary','Enabled','Delay','RandomDelay','UserId','Subscription','Repetition/Interval','Repetition/Duration','Repetition/StopAtDurationEnd','ScheduleByDay/DaysInterval','ScheduleByWeek/WeeksInterval')){$n=$t.SelectSingleNode('t:'+($p -replace '/','/t:'),$ns);if($n){$parts.Add($p+'：'+$n.InnerText)}}
      foreach($p in @('ScheduleByWeek/DaysOfWeek','ScheduleByMonth/DaysOfMonth','ScheduleByMonth/Months','ScheduleByMonthDayOfWeek/DaysOfWeek','ScheduleByMonthDayOfWeek/Weeks','ScheduleByMonthDayOfWeek/Months')){$n=$t.SelectSingleNode('t:'+($p -replace '/','/t:'),$ns);if($n){$parts.Add($p+'：'+(($n.ChildNodes|ForEach-Object{if($_.InnerText){$_.InnerText}else{$_.LocalName}}) -join ', '))}}
      Field ('触发器 '+($i+1)) ($parts -join "`n")
    }
    if($actions.Count -gt 32 -or $triggers.Count -gt 32){Warn '操作与触发器各最多展示 32 项，详情不完整。'}
    Warn '时间由目标调度器按其本地时区报告；下次时间可能包含已禁用触发器，返回代码不能代替业务验证。'
  }else{
    $class=if($kind -eq 'drivers'){'Win32_SystemDriver'}else{'Win32_Service'}
    $all=@(Get-CimInstance -ClassName $class -OperationTimeoutSec 12|Select-Object -First 2001)
    if($all.Count -gt 2000){throw 'Inventory limit'}
    $matched=@($all|Where-Object{[string]::Equals([string]$_.Name,$name,[StringComparison]::OrdinalIgnoreCase)})
    if($matched.Count -ne 1){throw 'Object missing or ambiguous'};$s=$matched[0];$fullName=$name
    foreach($pair in @(@('名称','Name'),@('显示名称','DisplayName'),@('说明','Description'),@('执行路径与参数','PathName'),@('运行账户','StartName'),@('状态','State'),@('启动方式','StartMode'),@('服务类型','ServiceType'),@('错误控制','ErrorControl'),@('接受停止','AcceptStop'),@('退出代码','ExitCode'),@('服务特定退出代码','ServiceSpecificExitCode'))){Field $pair[0] $s.($pair[1])}
    if($kind -eq 'services'){Field 'PID' $s.ProcessId}
    Add-Type -AssemblyName System.ServiceProcess
    $controller=[System.ServiceProcess.ServiceController]::new($name)
    try{foreach($pair in @(@('依赖的服务','ServicesDependedOn'),@('依赖此对象的服务','DependentServices'))){try{$items=@($controller.($pair[1]));try{if($items.Count -gt 64){Warn '服务依赖只展示前 64 项。'};Field $pair[0] (($items|Select-Object -First 64|ForEach-Object{$_.ServiceName+' · '+$_.Status}) -join "`n")}finally{foreach($item in $items){$item.Dispose()}}}catch{Warn '未能读取全部依赖关系，请检查权限。'}}}finally{$controller.Dispose()}
    $key=$null
    try{$key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Services\'+$name);if($null -eq $key){throw 'Registry missing'};Field '注册表位置' ('HKLM:\SYSTEM\CurrentControlSet\Services\'+$name);foreach($pair in @(@('原始执行配置','ImagePath'),@('延迟自动启动','DelayedAutoStart'),@('加载顺序组','Group'),@('启动保护级别','LaunchProtected'))){$v=$key.GetValue($pair[1],$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames);if($null -ne $v){Field $pair[0] $v}}}catch{Warn '服务注册表配置读取不完整。'}finally{if($key){$key.Dispose()}}
    Warn '状态与依赖是本次只读观察；驱动停止状态不代表驱动包已卸载，未发现记录也不能排除隐藏驱动。'
  }
  @{objectId=[string]$request.objectId;target=[Environment]::MachineName;kind=$kind;name=$fullName;observedAt=[DateTime]::UtcNow.ToString('o');fields=$fields.ToArray();warnings=$warnings.ToArray()}|ConvertTo-Json -Depth 5 -Compress
}catch{@{error='无法完整读取对象详情，请核对权限并刷新清单。'}|ConvertTo-Json -Compress}
