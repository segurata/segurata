# The windows connector's read-only probe. Windows PowerShell from System32 runs it with -NoProfile
# -NonInteractive -Command. It calls no cmdlet, so module autoloading stays off and no module is
# ever loaded from PSModulePath: only .NET, WMI and in-box COM objects. Each section is one try
# block, so a section that fails (access denied, a namespace this edition lacks) leaves the others.
# Output: one record per line, a section name then key=value fields, tab-separated, UTF-8.
# The connector passes it as a single argument, so it holds no double quote.
$ErrorActionPreference = 'Stop'
$PSModuleAutoLoadingPreference = 'None'
$tab = [string][char]9
$out = [Text.StringBuilder]::new()

function Clean($v) {
  if ($null -eq $v -or $v -is [DBNull]) { return '' }
  if ($v -is [datetime]) {
    if ($v.Kind -eq [DateTimeKind]::Utc) { return $v.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) }
    return $v.ToString('yyyy-MM-ddTHH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)
  }
  return ([string]$v) -replace '[\t\r\n]', ' '
}

function Rec([string]$sec) {
  $line = $sec
  for ($i = 0; $i + 1 -lt $args.Count; $i += 2) { $line += $tab + $args[$i] + '=' + (Clean $args[$i + 1]) }
  [void]$out.Append($line + [string][char]10)
}

function Fail([string]$sec, $err) {
  $ex = $err.Exception
  while ($null -ne $ex.InnerException) { $ex = $ex.InnerException }
  $code = '0x{0:X8}' -f $ex.HResult
  $denied = $ex -is [UnauthorizedAccessException] -or $ex.HResult -eq -2147024891
  if ($ex -is [Management.ManagementException]) {
    $code = [string]$ex.ErrorCode
    $denied = $ex.ErrorCode -eq [Management.ManagementStatus]::AccessDenied
  }
  Rec 'err' 'sec' $sec 'denied' $denied 'code' $code 'msg' $ex.Message
}

function Wmi([string]$ns, [string]$query) { [Management.ManagementObjectSearcher]::new($ns, $query).Get() }

function Prop($o, [string]$name) { try { return $o[$name] } catch { return $null } }

function Com([string]$progid) { [Activator]::CreateInstance([Type]::GetTypeFromProgID($progid, $true)) }

try {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $admin = [Security.Principal.WindowsPrincipal]::new($id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  Rec 'self' 'sid' $id.User.Value 'elevated' $admin
} catch { Fail 'self' $_ }

try {
  foreach ($o in (Wmi 'root\cimv2' 'SELECT Caption, Version, ProductType FROM Win32_OperatingSystem')) {
    Rec 'os' 'caption' $o['Caption'] 'version' $o['Version'] 'type' $o['ProductType']
  }
} catch { Fail 'os' $_ }

try {
  $shell = Com 'Shell.Application'
  foreach ($d in [IO.DriveInfo]::GetDrives()) {
    if ($d.DriveType -ne [IO.DriveType]::Fixed) { continue }
    $letter = $d.Name.TrimEnd('\')
    $v = $null
    try { $v = $shell.NameSpace($d.Name).Self.ExtendedProperty('System.Volume.BitLockerProtection') } catch { $v = $null }
    Rec 'vol' 'letter' $letter 'system' ($letter -eq $env:SystemDrive) 'shell' $v
  }
} catch { Fail 'vol' $_ }

try {
  foreach ($o in (Wmi 'root\cimv2\Security\MicrosoftVolumeEncryption' 'SELECT DriveLetter, ProtectionStatus FROM Win32_EncryptableVolume')) {
    Rec 'bde' 'letter' $o['DriveLetter'] 'protection' $o['ProtectionStatus']
  }
} catch { Fail 'bde' $_ }

try {
  $fw = Com 'HNetCfg.FwPolicy2'
  Rec 'fwcur' 'types' $fw.CurrentProfileTypes
  foreach ($t in 1, 2, 4) { Rec 'fw' 'profile' $t 'enabled' $fw.FirewallEnabled($t) 'inbound' $fw.DefaultInboundAction($t) }
} catch { Fail 'fw' $_ }

try {
  foreach ($o in (Wmi 'root\Microsoft\Windows\Defender' 'SELECT * FROM MSFT_MpComputerStatus')) {
    Rec 'mp' 'service' (Prop $o 'AMServiceEnabled') 'av' (Prop $o 'AntivirusEnabled') 'rtp' (Prop $o 'RealTimeProtectionEnabled') 'sigage' (Prop $o 'AntivirusSignatureAge') 'tamper' (Prop $o 'IsTamperProtected') 'mode' (Prop $o 'AMRunningMode')
  }
} catch { Fail 'mp' $_ }

try {
  foreach ($o in (Wmi 'root\SecurityCenter2' 'SELECT displayName, productState FROM AntiVirusProduct')) { Rec 'av' 'name' $o['displayName'] 'state' $o['productState'] }
} catch { Fail 'av' $_ }

try {
  foreach ($o in (Wmi 'root\SecurityCenter2' 'SELECT displayName, productState FROM FirewallProduct')) { Rec 'fwp' 'name' $o['displayName'] 'state' $o['productState'] }
} catch { Fail 'fwp' $_ }

try {
  $r = (Com 'Microsoft.Update.AutoUpdate').Results
  Rec 'wu' 'installed' $r.LastInstallationSuccessDate 'searched' $r.LastSearchSuccessDate
} catch { Fail 'wu' $_ }

try { Rec 'reboot' 'required' (Com 'Microsoft.Update.SystemInfo').RebootRequired } catch { Fail 'reboot' $_ }

try {
  $names = @{}
  foreach ($p in [Diagnostics.Process]::GetProcesses()) { $names[$p.Id] = $p.ProcessName }
  foreach ($o in (Wmi 'root\StandardCimv2' 'SELECT LocalAddress, LocalPort, OwningProcess FROM MSFT_NetTCPConnection WHERE State = 2')) {
    $owner = [int]$o['OwningProcess']
    Rec 'tcp' 'addr' $o['LocalAddress'] 'port' $o['LocalPort'] 'pid' $owner 'proc' $names[$owner]
  }
} catch { Fail 'tcp' $_ }

try {
  foreach ($o in (Wmi 'root\cimv2' 'SELECT Name, ProcessId, CommandLine FROM Win32_Process WHERE Name = ''brave.exe'' OR Name = ''chrome.exe'' OR Name = ''msedge.exe''')) {
    $cmd = [string]$o['CommandLine']
    if ($cmd.Contains('--remote-debugging-')) { Rec 'browser' 'name' $o['Name'] 'pid' $o['ProcessId'] 'cmd' $cmd }
  }
} catch { Fail 'browser' $_ }

try {
  foreach ($o in (Wmi 'root\cimv2' 'SELECT Name, SID, Disabled, PasswordRequired FROM Win32_UserAccount WHERE LocalAccount = TRUE')) {
    Rec 'user' 'name' $o['Name'] 'sid' $o['SID'] 'disabled' $o['Disabled'] 'pwreq' $o['PasswordRequired']
  }
} catch { Fail 'user' $_ }

try {
  $group = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544').Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
  $adsi = [ADSI]('WinNT://' + $env:COMPUTERNAME + '/' + $group + ',group')
  foreach ($m in $adsi.Invoke('Members')) {
    $t = $m.GetType()
    $path = $t.InvokeMember('ADsPath', 'GetProperty', $null, $m, $null)
    $class = $t.InvokeMember('Class', 'GetProperty', $null, $m, $null)
    $sid = [Security.Principal.SecurityIdentifier]::new([byte[]]$t.InvokeMember('objectSid', 'GetProperty', $null, $m, $null), 0).Value
    Rec 'admin' 'path' $path 'class' $class 'sid' $sid
  }
} catch { Fail 'admin' $_ }

try {
  foreach ($o in (Wmi 'root\cimv2' 'SELECT Name, Path, Type FROM Win32_Share')) {
    $n = [string]$o['Name']
    Rec 'share' 'name' $n 'path' $o['Path'] 'type' $o['Type']
    if ($n.EndsWith('$') -or [uint32]$o['Type'] -ne 0) { continue }
    try {
      $key = $n.Replace('\', '\\').Replace('''', '\''')
      $setting = [Management.ManagementObject]::new('root\cimv2:Win32_LogicalShareSecuritySetting.Name=''' + $key + '''')
      $r = $setting.InvokeMethod('GetSecurityDescriptor', $null, $null)
      if ([uint32]$r['ReturnValue'] -ne 0) { Rec 'shareacl' 'name' $n 'code' $r['ReturnValue']; continue }
      $dacl = $r['Descriptor']['DACL']
      if ($null -eq $dacl) { Rec 'shareace' 'name' $n 'sid' 'S-1-1-0' 'mask' 2032127 'type' 0; continue }
      foreach ($ace in $dacl) { Rec 'shareace' 'name' $n 'sid' $ace['Trustee']['SIDString'] 'mask' $ace['AccessMask'] 'type' $ace['AceType'] }
    } catch { Fail ('shareacl:' + $n) $_ }
  }
} catch { Fail 'share' $_ }

try {
  foreach ($o in (Wmi 'root\cimv2' 'SELECT Name, InstallState FROM Win32_OptionalFeature WHERE Name = ''SMB1Protocol''')) { Rec 'feature' 'name' $o['Name'] 'state' $o['InstallState'] }
} catch { Fail 'feature' $_ }

$bytes = [Text.UTF8Encoding]::new($false).GetBytes($out.ToString())
$stdout = [Console]::OpenStandardOutput()
$stdout.Write($bytes, 0, $bytes.Length)
$stdout.Flush()
