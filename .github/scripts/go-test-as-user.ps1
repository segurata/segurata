# Runs go test ./... in the job's standard-user process (see the test-windows-standard-user job in
# ci.yml), after checking that its token is a standard user's.
param(
  [Parameter(Mandatory)] [string] $Sid,
  [Parameter(Mandatory)] [string] $GoBin,
  [Parameter(Mandatory)] [string] $RgBin
)
$ErrorActionPreference = 'Stop'

# Start-Process -Credential passes the runner's environment on. Replace it with the block Windows
# builds for this token at logon (system and user variables, the profile's paths), as a user
# signing in gets.
Add-Type -Namespace SegurataCI -Name UserEnv -MemberDefinition @'
[DllImport("userenv.dll", SetLastError = true)]
public static extern bool CreateEnvironmentBlock(out IntPtr block, IntPtr token, bool inherit);
[DllImport("userenv.dll")]
public static extern bool DestroyEnvironmentBlock(IntPtr block);
'@
$block = [IntPtr]::Zero
if (-not [SegurataCI.UserEnv]::CreateEnvironmentBlock([ref]$block, [Security.Principal.WindowsIdentity]::GetCurrent().Token, $false)) {
  throw "CreateEnvironmentBlock: error $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
}
$fresh = @{}
try {
  for ($at = $block; ($entry = [Runtime.InteropServices.Marshal]::PtrToStringUni($at)); $at = [IntPtr]::Add($at, 2 * ($entry.Length + 1))) {
    $eq = $entry.IndexOf('=', 1)
    $fresh[$entry.Substring(0, $eq)] = $entry.Substring($eq + 1)
  }
} finally {
  [void][SegurataCI.UserEnv]::DestroyEnvironmentBlock($block)
}
foreach ($name in [Environment]::GetEnvironmentVariables().Keys) {
  if (-not $fresh.ContainsKey($name)) { [Environment]::SetEnvironmentVariable($name, $null) }
}
foreach ($name in $fresh.Keys) { [Environment]::SetEnvironmentVariable($name, $fresh[$name]) }
$env:PATH = "$GoBin;$RgBin;$env:PATH"
$env:GOTOOLCHAIN = 'local'
# A disposable VM: the native clipboard test clears the clipboard.
$env:SEGURATA_TEST_DISPOSABLE_CLIPBOARD = '1'

whoami /user /groups /priv
$groups = whoami /groups /fo csv | ConvertFrom-Csv
$profileDir = [Environment]::GetFolderPath('UserProfile')
$checks = [ordered]@{
  'runs as the standard user' = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq $Sid
  'not an administrator'      = -not ($groups | Where-Object SID -EQ 'S-1-5-32-544')
  'medium integrity'          = [bool]($groups | Where-Object SID -EQ 'S-1-16-8192')
  'interactive logon'         = [bool]($groups | Where-Object SID -EQ 'S-1-5-4')
  'own profile loaded'        = $env:USERPROFILE -eq $profileDir -and (Test-Path -LiteralPath (Join-Path $profileDir 'NTUSER.DAT'))
  'temp in the profile'       = $env:TEMP.StartsWith($profileDir + '\', 'OrdinalIgnoreCase')
}
$checks.GetEnumerator() | ForEach-Object { '{0}: {1}' -f $_.Key, $_.Value }
if ($checks.Values -contains $false) { Write-Error "this process does not hold a standard user's token" }

go env GOCACHE GOMODCACHE GOTMPDIR
go test ./...
exit $LASTEXITCODE
