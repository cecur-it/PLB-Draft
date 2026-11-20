#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Installs and enrolls the Cecur CS3 Windows log forwarder (Fluent Bit + watchdog task).

.DESCRIPTION
  1. Verifies and unpacks a locally supplied Fluent Bit Windows ZIP (air-gap friendly; SHA-256 checked).
  2. Redeems the one-time enrollment token at /api/fleet/enroll/claim (TLS trust via -CaFile,
     optional SPKI pin via -PinSha256) and receives a per-agent ingest key.
  3. Renders the config into a data directory ACL'd to SYSTEM + Administrators only.
  4. Registers the "CecurForwarder" service (auto-restart) and the "CecurForwarderWatchdog"
     scheduled task (runs Test-CecurForwarder.ps1 -Remediate every minute).

  Re-running without a token keeps existing credentials (idempotent upgrade of config/watchdog).

.EXAMPLE
  $t = Read-Host -AsSecureString 'Enrollment token'
  .\Install-CecurForwarder.ps1 -ConsoleUrl https://cs3.example.internal -AgentId cecur-ag-ab12cd34 `
      -EnrollmentToken $t -CaFile .\internal-ca.pem -FluentBitZip .\fluent-bit-3.1.9-win64.zip `
      -FluentBitSha256 <hex>

.EXAMPLE
  .\Install-CecurForwarder.ps1 -Uninstall
#>
[CmdletBinding(SupportsShouldProcess)]
param(
  [string]$ConsoleUrl,
  [string]$AgentId,
  [securestring]$EnrollmentToken,
  [string]$TokenFile,
  [string]$CaFile,
  [string]$ClientCert,
  [string]$ClientKey,
  [ValidatePattern('^[A-Za-z0-9+/=]{44}$')]
  [string]$PinSha256,
  [string]$FluentBitZip,
  [string]$FluentBitSha256,
  [switch]$NoRevocationCheck,
  [switch]$Uninstall,
  [string]$BackupDir,
  [string]$InstallDir = (Join-Path $env:ProgramFiles 'CecurForwarder'),
  [string]$DataDir = (Join-Path $env:ProgramData 'CecurForwarder')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ServiceName = 'CecurForwarder'
$TaskName = 'CecurForwarderWatchdog'
$SrcDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Write-Log([string]$m) { Write-Host "[cecur-forwarder] $m" }

function Invoke-NativeChecked([string]$FilePath, [string[]]$ArgumentList, [string]$FailureMessage) {
  & $FilePath @ArgumentList | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "$FailureMessage (exit code $LASTEXITCODE)" }
}

function Protect-Directory([string]$Path) {
  # Well-known SIDs keep this locale-independent: S-1-5-18 = SYSTEM, S-1-5-32-544 = Administrators.
  Invoke-NativeChecked 'icacls.exe' @($Path, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F') "icacls failed on $Path"
}

function Backup-ForwarderState([string]$Destination) {
  if (Test-Path -LiteralPath $Destination) { throw "Backup destination already exists; choose a new empty directory: $Destination" }
  New-Item -ItemType Directory -Path $Destination | Out-Null
  Protect-Directory $Destination
  $manifest = @()
  foreach ($source in @(@{ Path = $InstallDir; Name = 'install' }, @{ Path = $DataDir; Name = 'data' })) {
    if (-not (Test-Path -LiteralPath $source.Path)) { continue }
    $sourceRoot = (Resolve-Path -LiteralPath $source.Path).Path.TrimEnd('\')
    $target = Join-Path $Destination $source.Name
    Copy-Item -LiteralPath $sourceRoot -Destination $target -Recurse -Force
    foreach ($file in @(Get-ChildItem -LiteralPath $sourceRoot -Recurse -File)) {
      $relative = $file.FullName.Substring($sourceRoot.Length).TrimStart('\')
      $copy = Join-Path $target $relative
      if (-not (Test-Path -LiteralPath $copy -PathType Leaf)) { throw "Backup verification failed: missing $relative" }
      $sourceHash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
      $copyHash = (Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash
      if ($sourceHash -ne $copyHash) { throw "Backup verification failed: hash mismatch for $relative" }
      $manifest += [pscustomobject]@{ source = $source.Name; path = $relative; sha256 = $sourceHash }
    }
  }
  Set-Content -LiteralPath (Join-Path $Destination 'manifest.json') -Value (ConvertTo-Json -InputObject $manifest) -Encoding ASCII
  Write-Log "verified state backup: $Destination"
}

function ConvertTo-PlainText([securestring]$Secure) {
  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
  try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
  finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

# ---------------------------------------------------------------------------------------- uninstall
if ($Uninstall) {
  if (-not $BackupDir) {
    $BackupDir = Join-Path $env:ProgramData ('CecurForwarder-Backup-' + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))
  }
  if ($PSCmdlet.ShouldProcess($ServiceName, "Back up state to $BackupDir and remove forwarder")) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
      Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    $existingService = Get-Service $ServiceName -ErrorAction SilentlyContinue
    if ($existingService -and $existingService.Status -ne 'Stopped') { Stop-Service $ServiceName -Force }
    Backup-ForwarderState $BackupDir
    if ($existingService) {
      Invoke-NativeChecked 'sc.exe' @('delete', $ServiceName) 'Could not delete the forwarder service'
    }
    foreach ($path in @($InstallDir, $DataDir)) {
      if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force }
    }
    Write-Log "removed; credentials and configuration remain in the verified backup $BackupDir"
  }
  return
}

# ------------------------------------------------------------------------------------------ validate
if (-not $ConsoleUrl) { throw '-ConsoleUrl is required' }
$uri = [Uri]$ConsoleUrl
if ($uri.Scheme -ne 'https') { throw 'Console URL must be https:// (plaintext HTTP is refused)' }
$base = '{0}://{1}:{2}' -f $uri.Scheme, $uri.Host, $uri.Port
$confPath = Join-Path $DataDir 'fluent-bit.conf'
$envPath = Join-Path $DataDir 'agent.json'

$curl = Get-Command curl.exe -ErrorAction SilentlyContinue
if (-not $curl) { throw 'curl.exe (Windows 10 1803+ / Server 2019+) is required for the enrollment claim.' }
if ([bool]$ClientCert -ne [bool]$ClientKey) { throw '-ClientCert and -ClientKey must be given together' }
foreach ($file in @($CaFile, $ClientCert, $ClientKey)) {
  if ($file -and -not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Certificate file not found: $file" }
}
$fbExe = Join-Path $InstallDir 'fluent-bit\bin\fluent-bit.exe'
if (-not (Test-Path $fbExe)) {
  if (-not $FluentBitZip) { throw 'Fluent Bit is not installed; supply -FluentBitZip and -FluentBitSha256.' }
  if ($FluentBitSha256 -notmatch '^[0-9a-fA-F]{64}$') { throw '-FluentBitSha256 must be the publisher-provided 64-character SHA-256 digest.' }
  if (-not (Test-Path -LiteralPath $FluentBitZip -PathType Leaf)) { throw "Fluent Bit ZIP not found: $FluentBitZip" }
  $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $FluentBitZip).Hash
  if ($actual -ne $FluentBitSha256.ToUpperInvariant()) { throw "Fluent Bit ZIP checksum mismatch (got $actual)" }
  Write-Log 'Fluent Bit ZIP SHA-256 verified'
}

# ----------------------------------------------------------------------------------------- directories
foreach ($d in @($InstallDir, $DataDir, (Join-Path $DataDir 'buffer'), (Join-Path $DataDir 'pki'))) {
  New-Item -ItemType Directory -Path $d -Force | Out-Null
}
Protect-Directory $DataDir

$caDest = Join-Path $DataDir 'pki\ca.pem'
if ($CaFile) { Copy-Item -LiteralPath $CaFile -Destination $caDest -Force }
if ($ClientCert) {
  Copy-Item -LiteralPath $ClientCert -Destination (Join-Path $DataDir 'pki\agent.crt') -Force
  Copy-Item -LiteralPath $ClientKey -Destination (Join-Path $DataDir 'pki\agent.key') -Force
}

# ------------------------------------------------------------------------------------------ Fluent Bit
if (-not (Test-Path $fbExe)) {
  $tmp = Join-Path ([IO.Path]::GetTempPath()) ("cecur-fb-" + [guid]::NewGuid())
  try {
    Expand-Archive -LiteralPath $FluentBitZip -DestinationPath $tmp
    $root = Get-ChildItem $tmp -Directory | Select-Object -First 1
    if (-not $root) { throw 'Fluent Bit ZIP did not contain an installation directory.' }
    Move-Item -LiteralPath $root.FullName -Destination (Join-Path $InstallDir 'fluent-bit')
  } finally {
    if (Test-Path -LiteralPath $tmp) { Remove-Item $tmp -Recurse -Force }
  }
  if (-not (Test-Path $fbExe)) { throw 'fluent-bit.exe not found after extraction' }
}

# --------------------------------------------------------------------------------------------- enroll
$token = $null
if ($EnrollmentToken) { $token = ConvertTo-PlainText $EnrollmentToken }
elseif ($TokenFile) { $token = (Get-Content -LiteralPath $TokenFile -Raw).Trim() }
elseif ($env:CS3_ENROLL_TOKEN) { $token = $env:CS3_ENROLL_TOKEN }

if ($token) {
  if (-not $AgentId -or $AgentId -notmatch '^[A-Za-z0-9._-]{1,64}$') { throw '-AgentId is required and must match [A-Za-z0-9._-]{1,64}' }
  if ($token -notmatch '^[A-Za-z0-9._~+/=-]{8,128}$') { throw 'Enrollment token has unexpected characters' }
  Write-Log "claiming enrollment for $AgentId"
  $curlArgs = @('-fsS', '--max-time', '30', '--proto', '=https', '--tlsv1.2', '-X', 'POST',
            '-H', 'Content-Type: application/json', '--data', '@-')
  if (Test-Path $caDest) { $curlArgs += @('--cacert', $caDest) }
  if ($PinSha256) { $curlArgs += @('--pinnedpubkey', "sha256//$PinSha256") }
  if ($NoRevocationCheck) { $curlArgs += '--ssl-no-revoke' }
  # Token travels via stdin, not the command line (visible in process listings / 4688 events).
  $body = '{"agentId":"' + $AgentId + '","token":"' + $token + '"}'
  $resp = $body | & curl.exe @curlArgs "$base/api/fleet/enroll/claim"
  if ($LASTEXITCODE -ne 0) { throw 'Enrollment claim failed (expired/used token, TLS trust or pin mismatch?)' }
  $token = $null; $body = $null
  $claim = ($resp -join '') | ConvertFrom-Json
  if (-not $claim.ingestKey) { throw 'Console response did not include an ingest key' }
  [pscustomobject]@{
    host = $uri.Host; port = $uri.Port; agentId = $claim.agentId; ingestKey = $claim.ingestKey
    hostname = $env:COMPUTERNAME; pin = $PinSha256
  } | ConvertTo-Json | Set-Content -LiteralPath $envPath -Encoding ASCII
}
elseif (-not (Test-Path $envPath)) {
  throw 'No enrollment token (-EnrollmentToken / -TokenFile / CS3_ENROLL_TOKEN) and no existing credentials.'
}
$cfg = Get-Content -LiteralPath $envPath -Raw | ConvertFrom-Json

# ------------------------------------------------------------------------------------------ config
$tpl = Get-Content -LiteralPath (Join-Path $SrcDir 'templates\fluent-bit-windows.conf') -Raw
$caForConf = if (Test-Path $caDest) { $caDest } else { '' }
$map = @{
  '@@DATA_DIR@@' = $DataDir; '@@HOSTNAME@@' = $cfg.hostname; '@@CS3_HOST@@' = $cfg.host
  '@@CS3_PORT@@' = [string]$cfg.port; '@@CA_FILE@@' = $caForConf; '@@INGEST_KEY@@' = $cfg.ingestKey
}
foreach ($k in $map.Keys) { $tpl = $tpl.Replace($k, $map[$k]) }
if (-not $caForConf) { $tpl = ($tpl -split "`r?`n" | Where-Object { $_ -notmatch '^\s*tls\.ca_file\s' }) -join "`r`n" }  # fall back to the Windows trust store
# mTLS is enabled whenever a client certificate/key pair is present in the pki directory.
if ((Test-Path (Join-Path $DataDir 'pki\agent.crt')) -and (Test-Path (Join-Path $DataDir 'pki\agent.key'))) {
  $tpl = $tpl -replace '(?m)^(\s*)# (tls\.(crt|key)_file)', '$1$2'
  Write-Log 'mTLS enabled (client certificate configured)'
}
Set-Content -LiteralPath $confPath -Value $tpl -Encoding ASCII

Copy-Item (Join-Path $SrcDir 'Test-CecurForwarder.ps1') (Join-Path $InstallDir 'Test-CecurForwarder.ps1') -Force

# ----------------------------------------------------------------------------------------- service
$binPath = '"{0}" -c "{1}"' -f $fbExe, $confPath
if (Get-Service $ServiceName -ErrorAction SilentlyContinue) {
  Stop-Service $ServiceName -Force
  Invoke-NativeChecked 'sc.exe' @('config', $ServiceName, 'binPath=', $binPath, 'start=', 'delayed-auto') 'Could not configure the forwarder service'
} else {
  New-Service -Name $ServiceName -BinaryPathName $binPath -DisplayName 'Cecur CS3 Log Forwarder' `
    -Description 'Forwards Windows event logs to the Cecur CS3 console' -StartupType Automatic | Out-Null
  Invoke-NativeChecked 'sc.exe' @('config', $ServiceName, 'start=', 'delayed-auto') 'Could not configure delayed forwarder startup'
}
# Restart after 5s, 30s, 60s; reset the failure counter after a day.
Invoke-NativeChecked 'sc.exe' @('failure', $ServiceName, 'reset=', '86400', 'actions=', 'restart/5000/restart/30000/restart/60000') 'Could not configure forwarder restart recovery'
Start-Service $ServiceName

# ---------------------------------------------------------------------------------------- watchdog
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
  -Argument ('-NoProfile -ExecutionPolicy Bypass -File "{0}" -Remediate' -f (Join-Path $InstallDir 'Test-CecurForwarder.ps1'))
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

Start-Sleep -Seconds 3
if ((Get-Service $ServiceName).Status -ne 'Running') { throw "Service $ServiceName failed to start; see the Application event log." }
Write-Log "installed and running (agent $($cfg.agentId))"
