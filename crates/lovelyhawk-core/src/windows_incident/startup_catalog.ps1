$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$rows=New-Object 'Collections.Generic.List[object]'
$categories=@('logon','explorer','internet-explorer','services','drivers','codecs','winsock','print','lsa','network','boot-execute','image-hijacks','app-init','known-dlls','winlogon','ime','tasks','gadgets','folder-extensions')
$coverage=@{};foreach($c in $categories){$coverage[$c]=@{category=$c;count=0;status='complete';message='已检查本版本支持的固定位置；不代表覆盖全部持久化机制。'}}
$collectionState=@{truncated=$false;bytes=0};$seenRows=@{}
$clock=[Diagnostics.Stopwatch]::StartNew()
$view=if([Environment]::Is64BitOperatingSystem){[Microsoft.Win32.RegistryView]::Registry64}else{[Microsoft.Win32.RegistryView]::Registry32}
$roots=@{'HKLM:'=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$view);'HKCU:'=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser,$view)}
function Gap($c,$text){$coverage[$c].status='partial';$coverage[$c].message=$text}
function In-Time($c){if($clock.Elapsed.TotalSeconds -gt 30){Gap $c '本次采集达到时间上限，部分位置尚未读取。';return $false};return $true}
function Open-Key($path){$roots[$path.Substring(0,5)].OpenSubKey($path.Substring(6),$false)}
function Clip($v,$n){$s=[string]$v;if($s.Length -gt $n){$collectionState.truncated=$true;return $s.Substring(0,$n)+'…[截断]'};return $s}
function Row($c,$source,$name,$location,$command,$account,$state){
  $identity=@($c,$source,$location,$name)|ConvertTo-Json -Compress
  if($seenRows.ContainsKey($identity)){return}
  if($rows.Count -ge 20000 -or $coverage[$c].count -ge 5000){$collectionState.truncated=$true;Gap $c '达到本次条目上限（每类 5000 / 总共 20000），清单不完整。';return}
  $row=@{category=$c;sourceType=$source;name=(Clip $name 500);location=(Clip $location 2000);command=(Clip $command 2000);runAs=(Clip $account 250);state=(Clip $state 60)}
  $bytes=[Text.Encoding]::UTF8.GetByteCount(($row|ConvertTo-Json -Depth 8 -Compress))+1
  if($collectionState.bytes+$bytes -gt 4460000){$collectionState.truncated=$true;Gap $c '达到本次 4.5 MB 字节预算，清单不完整。';return}
  $collectionState.bytes+=$bytes
  $seenRows[$identity]=$true
  $rows.Add($row)
  $coverage[$c].count++
}
function Reg($c,$path,$names=$null){
  if(-not(In-Time $c)){return}
  $key=$null
  try{
    # Literal registry paths from the fixed catalog; missing locations are distinct from access errors.
    $key=Open-Key $path
    if($null -eq $key){return}
    $all=@($key.GetValueNames())
    if($all.Count -gt 5000){Gap $c '单个注册表位置超过 5000 个值，已截断。';$collectionState.truncated=$true}
    foreach($name in ($all|Select-Object -First 5000)){
      if(-not(In-Time $c)){break}
      if($null -ne $names -and $names -notcontains $name){continue}
      $kind=$key.GetValueKind($name)
      $value=$key.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
      if($value -is [byte[]]){$text='二进制配置 · '+$value.Length+' 字节（请在注册表中核实）'}
      elseif($value -is [string[]]){$text=$value -join ' | '}
      else{$text=[string]$value}
      Row $c 'registry' $name $path $text '' ([string]$kind)
    }
  }catch{Gap $c '部分注册表位置读取失败，请核对权限；空结果不能解释为不存在启动项。'}
  finally{if($null -ne $key){$key.Dispose()}}
}
function Children($c,$path,$names=$null,$suffix='',$scanLimit=5000){
  if(-not(In-Time $c)){return}
  $parent=$null
  try{
    $parent=Open-Key $path;if($null -eq $parent){return}
    $keys=@($parent.GetSubKeyNames())
    if($keys.Count -gt $scanLimit){Gap $c '注册表子项超过本次上限，清单已截断。';$collectionState.truncated=$true}
    foreach($k in ($keys|Select-Object -First $scanLimit)){
      if(-not(In-Time $c)){break}
      $p=$path+'\'+$k+$suffix
      Reg $c $p $names
    }
  }catch{Gap $c '部分注册表子项无法枚举，请核对权限。'}
  finally{if($null -ne $parent){$parent.Dispose()}}
}
function Classes($c,$path){
  # Preserve registrations and resolve referenced COM servers without activating them.
  if(-not(In-Time $c)){return}
  Reg $c $path
  Children $c $path
  $parent=$null
  try{
    $parent=Open-Key $path;if($null -eq $parent){return}
    $keys=@($parent.GetSubKeyNames());if($keys.Count -gt 1000){Gap $c '仅解析前 1000 个 COM 注册的服务器路径。'}
    foreach($childName in ($keys|Select-Object -First 1000)){
      $k=$parent.OpenSubKey($childName);if($null -eq $k){continue}
      try{$id=if($childName -match '^\{[0-9a-fA-F-]{36}\}$'){$childName}else{[string]$k.GetValue('')}}finally{$k.Dispose()}
      if($id -match '^\{[0-9a-fA-F-]{36}\}$'){
        $base=if($path.StartsWith('HKCU:')){'HKCU:\Software\Classes\'}else{'HKLM:\Software\Classes\'}
        if($path -like '*WOW6432Node*'){$base+='WOW6432Node\'}
        Reg $c ($base+'CLSID\'+$id+'\InprocServer32') @('','ThreadingModel')
        Reg $c ($base+'CLSID\'+$id+'\LocalServer32') @('')
        if($c -eq 'ime' -and [Environment]::Is64BitOperatingSystem){Reg $c ($base+'WOW6432Node\CLSID\'+$id+'\InprocServer32') @('')}
      }
    }
  }catch{Gap $c '部分 COM 注册无法解析，保留已读注册信息。'}
  finally{if($null -ne $parent){$parent.Dispose()}}
}
foreach($hive in @('HKLM:','HKCU:')){
  foreach($software in @('Software','Software\WOW6432Node')){
    $ms=$hive+'\'+$software+'\Microsoft\Windows\CurrentVersion'
    foreach($sub in @('Run','RunOnce','RunOnceEx','Policies\Explorer\Run')){Reg 'logon' ($ms+'\'+$sub)}
    Children 'logon' ($hive+'\'+$software+'\Microsoft\Active Setup\Installed Components') @('StubPath')
    foreach($sub in @('ShellIconOverlayIdentifiers','ShellExecuteHooks','SharedTaskScheduler','ShellServiceObjects')){Classes 'explorer' ($ms+'\Explorer\'+$sub)}
    Classes 'folder-extensions' ($ms+'\Explorer\FolderExtensions')
    Reg 'explorer' ($ms+'\ShellServiceObjectDelayLoad')
    Classes 'internet-explorer' ($hive+'\'+$software+'\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects')
    Reg 'internet-explorer' ($hive+'\'+$software+'\Microsoft\Internet Explorer\Toolbar')
    Classes 'internet-explorer' ($hive+'\'+$software+'\Microsoft\Internet Explorer\Extensions')
    Reg 'app-init' ($hive+'\'+$software+'\Microsoft\Windows NT\CurrentVersion\Windows') @('AppInit_DLLs','LoadAppInit_DLLs','RequireSignedAppInit_DLLs')
    Reg 'winlogon' ($hive+'\'+$software+'\Microsoft\Windows NT\CurrentVersion\Winlogon') @('Shell','Userinit','GinaDLL','Taskman','System','AppSetup')
    Children 'winlogon' ($hive+'\'+$software+'\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify')
    Children 'image-hijacks' ($hive+'\'+$software+'\Microsoft\Windows NT\CurrentVersion\Image File Execution Options') @('Debugger','GlobalFlag','VerifierDlls')
    Children 'image-hijacks' ($hive+'\'+$software+'\Microsoft\Windows NT\CurrentVersion\SilentProcessExit') @('MonitorProcess','ReportingMode')
    Reg 'codecs' ($hive+'\'+$software+'\Microsoft\Windows NT\CurrentVersion\Drivers32')
    Children 'gadgets' ($hive+'\'+$software+'\Microsoft\Windows\CurrentVersion\Sidebar')
  }
  foreach($classes in @('Software\Classes','Software\Classes\WOW6432Node')){
    foreach($type in @('*','AllFileSystemObjects','Directory','Drive','Folder')){
      foreach($extension in @('ContextMenuHandlers','PropertySheetHandlers','CopyHookHandlers','DragDropHandlers')){
        Classes 'explorer' ($hive+'\'+$classes+'\'+$type+'\shellex\'+$extension)
      }
    }
    Classes 'internet-explorer' ($hive+'\'+$classes+'\Protocols\Filter')
    Classes 'internet-explorer' ($hive+'\'+$classes+'\Protocols\Handler')
    Classes 'folder-extensions' ($hive+'\'+$classes+'\Folder\shellex\ColumnHandlers')
    Children 'folder-extensions' ($hive+'\'+$classes+'\Folder\shell') @('') '\command'
    foreach($id in @('{083863F1-70DE-11d0-BD40-00A0C911CE86}','{AC757296-3522-4E11-9862-C17BE5A1767E}')){Classes 'codecs' ($hive+'\'+$classes+'\CLSID\'+$id+'\Instance')}
  }
}
$system='HKLM:\SYSTEM\CurrentControlSet'
Reg 'boot-execute' ($system+'\Control\Session Manager') @('BootExecute','SetupExecute','Execute','S0InitialCommand')
Reg 'known-dlls' ($system+'\Control\Session Manager\KnownDLLs')
Reg 'known-dlls' ($system+'\Control\Session Manager\KnownDLLs32')
Reg 'lsa' ($system+'\Control\Lsa') @('Authentication Packages','Security Packages','Notification Packages')
Reg 'lsa' ($system+'\Control\Lsa\OSConfig') @('Security Packages')
Children 'print' ($system+'\Control\Print\Monitors') @('Driver')
foreach($arch in @('Windows x64','Windows NT x86')){Children 'print' ($system+'\Control\Print\Environments\'+$arch+'\Print Processors') @('Driver')}
Reg 'network' ($system+'\Control\NetworkProvider\Order') @('ProviderOrder')
Children 'network' ($system+'\Services') @('ProviderPath','Name','Class') '\NetworkProvider' 2000
foreach($catalog in @('Protocol_Catalog9','NameSpace_Catalog5')){
  foreach($entries in @('Catalog_Entries','Catalog_Entries64')){Children 'winsock' ($system+'\Services\WinSock2\Parameters\'+$catalog+'\'+$entries)}
}
Children 'ime' ($system+'\Control\Keyboard Layouts') @('Ime File','Layout File','Layout Text')
foreach($hive in @('HKLM:','HKCU:')){Classes 'ime' ($hive+'\Software\Microsoft\CTF\TIP')}
$sidebarSettings=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Microsoft\Windows Sidebar\Settings.ini'
try{
  if(Test-Path -LiteralPath $sidebarSettings -PathType Leaf){
    $file=Get-Item -LiteralPath $sidebarSettings -Force
    if(($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $file.Length -gt 65536){Gap 'gadgets' '小工具设置为链接或超过 64 KiB，未读取其内容。'}else{
      Row 'gadgets' 'settings-file' 'Sidebar Settings.ini' $file.DirectoryName $file.FullName '' '历史小工具配置（存在不代表正在运行）'
      $reader=[IO.StreamReader]::new($file.FullName);$buffer=New-Object char[] 65537
      try{$length=$reader.ReadBlock($buffer,0,65537)}finally{$reader.Dispose()}
      if($length -gt 65536){Gap 'gadgets' '读取期间小工具配置超过上限，未解析引用。'}else{
        $index=0;foreach($line in ([string]::new($buffer,0,$length) -split '\r?\n')){if($line -match '^\s*PrivateSetting_GadgetName\s*=\s*(.*)$'){Row 'gadgets' 'settings-file' ('小工具 '+(++$index)) $file.FullName $Matches[1].Trim() '' '配置引用（未加载组件）'}}
      }
    }
  }
}catch{Gap 'gadgets' '小工具设置文件无法读取。'}
foreach($folder in @([Environment]::GetFolderPath('Startup'),[Environment]::GetFolderPath('CommonStartup'))){
  try{
    if(-not $folder -or -not(Test-Path -LiteralPath $folder)){continue}
    $files=@(Get-ChildItem -LiteralPath $folder -File -Force -ErrorAction Stop|Select-Object -First 5001)
    if($files.Count -gt 5000){Gap 'logon' '启动目录超过本次上限。';$collectionState.truncated=$true}
    foreach($f in ($files|Select-Object -First 5000)){Row 'logon' 'startup-folder' $f.Name $folder $f.FullName '' '目录项（未执行或解析快捷方式）'}
  }catch{Gap 'logon' '部分启动目录无法读取。'}
}
foreach($kind in @('services','drivers')){
  if(-not(In-Time $kind)){continue}
  try{
    $class=if($kind -eq 'services'){'Win32_Service'}else{'Win32_SystemDriver'}
    $all=@(Get-CimInstance $class -OperationTimeoutSec 8|Select-Object -First 5001)
    if($all.Count -gt 5000){Gap $kind '服务条目超过启动项视图上限，可在独立页面继续排查。';$collectionState.truncated=$true}
    foreach($s in ($all|Select-Object -First 5000)){Row $kind $(if($kind -eq 'services'){'service'}else{'driver'}) $s.Name ($system+'\Services\'+$s.Name) $s.PathName $s.StartName ($s.State+' / '+$s.StartMode)}
  }catch{$coverage[$kind].status='unavailable';$coverage[$kind].message='CIM 清单读取失败，请核对权限和系统支持。'}
}
try{
  if(-not(In-Time 'tasks')){throw 'Time budget'}
  $all=@(Get-ScheduledTask -ErrorAction Stop|Select-Object -First 5001)
  if($all.Count -gt 5000){Gap 'tasks' '任务超过启动项视图上限，可在计划任务页面继续排查。';$collectionState.truncated=$true}
  foreach($t in ($all|Select-Object -First 5000)){
    $command=(@($t.Actions|Select-Object -First 10|ForEach-Object{([string]$_.Execute+' '+$_.Arguments).Trim()}) -join ' ; ')
    Row 'tasks' 'scheduled-task' $t.TaskName $t.TaskPath $command $t.Principal.UserId ([string]$t.State)
  }
}catch{$coverage.tasks.status='unavailable';$coverage.tasks.message='计划任务读取失败或工具不可用。'}
$warnings=@('范围：计算机与当前采集账户；未加载或其他账户的配置不在本次范围。','分类是已知配置位置；IE、小工具等历史功能即使未安装也可能残留配置。','服务 / 驱动 / 计划任务包含禁用与手动项；配置存在不等于已经执行。')
$result=@{observedAt=[DateTime]::UtcNow.ToString('o');truncated=$collectionState.truncated;warnings=$warnings;categories=@($categories|ForEach-Object{$coverage[$_]});entries=$rows.ToArray()}
$json=$result|ConvertTo-Json -Depth 8 -Compress
if([Text.Encoding]::UTF8.GetByteCount($json) -gt 4500000){throw '启动项响应超过本次字节预算，请缩小范围。'}
foreach($key in $roots.Values){$key.Dispose()}
$json
