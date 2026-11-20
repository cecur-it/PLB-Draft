#requires -Version 5.1
<#
.SYNOPSIS
  install.ps1 — Windows OS-specific installer script for the CS3 Platform,
  covering all three deployment profiles (cloud | onprem | airgap).

.DESCRIPTION
  Invoked BY cs3-launcher.mjs after the onboarding wizard has populated
  .env — it is not normally run directly by an operator. Performs the
  Windows-native OS-level provisioning step for the profile already
  selected and validated by the launcher: pinned Ollama install with
  loopback-only binding under a dedicated low-privilege local account,
  approved model pulls (onprem) or offline bundle load (airgap), and
  starting the CS3 ESOC Console container.

.PARAMETER Profile
  Required. One of: cloud, onprem, airgap.

.PARAMETER Bundle
  Required for -Profile airgap. Path to a pre-verified model bundle.

.EXAMPLE
  install.ps1 -Profile onprem
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('cloud', 'onprem', 'airgap')]
  [string]$Profile,

  [Parameter(Mandatory = $false)]
  [string]$Bundle
)

$ErrorActionPreference = 'Stop'

# Pin the exact Ollama release qualified for this CS3 release (2026 release with
# Gemma-4 / Nemotron-3-Nano support). Keep in lockstep with OLLAMA_PINNED_VERSION
# in scripts/install-ollama.sh.
$OllamaPinnedVersion = '0.40.5'
$ServiceAccount = 'cs3-ollama'
$ServiceName = 'cs3-ollama'
$OllamaBindAddr = '127.0.0.1:11434'
$OllamaHome = Join-Path $env:ProgramData 'CS3\ollama'
$ModelsTarget = Join-Path $OllamaHome 'models'
$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

function Write-Log {
  param([string]$Message)
  Write-Host "[install.ps1] $Message"
}

function Write-WarnLog {
  param([string]$Message)
  Write-Warning "[install.ps1] $Message"
}

function Write-FailClosed {
  param([string]$Message)
  Write-Error "[install.ps1][FAIL] $Message"
  exit 1
}

function Invoke-NativeChecked {
  param(
    [Parameter(Mandatory = $true)][string]$FilePath,
    [string[]]$ArgumentList = @(),
    [Parameter(Mandatory = $true)][string]$FailureMessage
  )
  & $FilePath @ArgumentList
  $nativeExitCode = $LASTEXITCODE
  if ($nativeExitCode -ne 0) {
    Write-FailClosed "$FailureMessage (exit code $nativeExitCode)."
  }
}

function Invoke-NativeProbe {
  param(
    [Parameter(Mandatory = $true)][string]$FilePath,
    [string[]]$ArgumentList = @()
  )
  # PowerShell 5.1 can turn redirected native stderr into a terminating error under Stop.
  $previousPreference = $ErrorActionPreference
  try {
    $ErrorActionPreference = 'Continue'
    $output = @(& $FilePath @ArgumentList 2>$null)
    $nativeExitCode = $LASTEXITCODE
    return [pscustomobject]@{ Output = $output; ExitCode = $nativeExitCode }
  } finally {
    $ErrorActionPreference = $previousPreference
  }
}

function Update-ProcessPath {
  $machinePath = [Environment]::GetEnvironmentVariable('PATH', 'Machine')
  $userPath = [Environment]::GetEnvironmentVariable('PATH', 'User')
  $env:PATH = @($machinePath, $userPath) -join ';'
}

function Add-MachinePath {
  param([Parameter(Mandatory = $true)][string]$Directory)
  $machinePath = [Environment]::GetEnvironmentVariable('PATH', 'Machine')
  $parts = @($machinePath -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  if ($parts -notcontains $Directory) {
    [Environment]::SetEnvironmentVariable('PATH', (@($parts) + $Directory) -join ';', 'Machine')
  }
  Update-ProcessPath
}

$envPath = Join-Path $RepoRoot '.env'
if (-not (Test-Path $envPath)) {
  Write-FailClosed ".env not found. Run cs3-launcher.mjs first so the onboarding wizard can populate it."
}

function Import-DotEnv {
  param([string]$Path)
  $map = @{}
  Get-Content -Path $Path | ForEach-Object {
    $line = $_.Trim()
    if ($line -eq '' -or $line.StartsWith('#')) { return }
    $idx = $line.IndexOf('=')
    if ($idx -lt 0) { return }
    $key = $line.Substring(0, $idx).Trim()
    $value = $line.Substring($idx + 1).Trim()
    $map[$key] = $value
  }
  return $map
}

$EnvMap = Import-DotEnv -Path $envPath

function New-RandomPassword {
  $bytes = New-Object byte[] 32
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  $rng.GetBytes($bytes)
  $rng.Dispose()
  # Base64 plus a fixed suffix guarantees upper/lower/digit/symbol complexity classes.
  return ([Convert]::ToBase64String($bytes) + 'aA1!')
}

function Add-UserRight {
  param([string]$Right, [string]$Account)
  $sid = (New-Object System.Security.Principal.NTAccount($Account)).Translate([System.Security.Principal.SecurityIdentifier]).Value
  $tmp = Join-Path $env:TEMP ('cs3-secpol-' + [System.Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $tmp -Force | Out-Null
  try {
    $cfg = Join-Path $tmp 'current.inf'
    $db = Join-Path $tmp 'secedit.sdb'
    Invoke-NativeChecked -FilePath 'secedit.exe' -ArgumentList @('/export', '/cfg', $cfg, '/areas', 'USER_RIGHTS') -FailureMessage 'Could not export Windows user-rights policy' | Out-Null
    if (-not (Test-Path $cfg)) { Write-FailClosed 'secedit.exe did not produce a user-rights policy file.' }
    $found = $false
    $lines = foreach ($line in (Get-Content -Path $cfg)) {
      if ($line -match ('^' + [regex]::Escape($Right) + '\s*=')) {
        $found = $true
        if ($line -notmatch [regex]::Escape("*$sid")) { "$line,*$sid" } else { $line }
      } else {
        $line
      }
    }
    if (-not $found) {
      $lines = foreach ($line in $lines) {
        $line
        if ($line -match '^\[Privilege Rights\]\s*$') { "$Right = *$sid" }
      }
    }
    Set-Content -Path $cfg -Value $lines -Encoding Unicode
    Invoke-NativeChecked -FilePath 'secedit.exe' -ArgumentList @('/configure', '/db', $db, '/cfg', $cfg, '/areas', 'USER_RIGHTS') -FailureMessage 'Could not apply Windows user-rights policy' | Out-Null
  } finally {
    Remove-Item -Path $tmp -Recurse -Force -ErrorAction SilentlyContinue
  }
}

# The password exists only in memory and is never written to disk. Existing service-account
# credentials are left untouched on an idempotent rerun; rotating them before NSSM is updated
# can strand an otherwise working service.
$script:ServicePassword = $null

function Initialize-ServiceAccount {
  $existing = Get-LocalUser -Name $ServiceAccount -ErrorAction SilentlyContinue
  if ($null -eq $existing) {
    $script:ServicePassword = New-RandomPassword
    $secure = ConvertTo-SecureString -String $script:ServicePassword -AsPlainText -Force
    Write-Log "Creating dedicated, low-privilege local account: $ServiceAccount"
    # The account never logs on interactively. It needs a (random, never-stored) password because
    # Windows refuses service logons for blank-password accounts.
    New-LocalUser -Name $ServiceAccount -Password $secure -AccountNeverExpires -PasswordNeverExpires `
      -UserMayNotChangePassword -Description 'CS3 Ollama service account (non-interactive).' | Out-Null
    # Standard Users group only — never add this account to Administrators.
    Add-LocalGroupMember -Group 'Users' -Member $ServiceAccount | Out-Null
  } else {
    Write-Log "Service account $ServiceAccount already exists — preserving its credentials."
  }
  # Least privilege: may log on as a service, may never log on interactively / over the network.
  Add-UserRight -Right 'SeServiceLogonRight' -Account $ServiceAccount
  Add-UserRight -Right 'SeDenyInteractiveLogonRight' -Account $ServiceAccount
  Add-UserRight -Right 'SeDenyNetworkLogonRight' -Account $ServiceAccount
}

function Install-OllamaBinary {
  param([string]$OfflineBinary)

  $installed = Get-Command ollama -ErrorAction SilentlyContinue
  if ($installed) {
    $versionOutput = & ollama --version 2>$null
    if ($versionOutput -match [regex]::Escape($OllamaPinnedVersion)) {
      Write-Log "Ollama $OllamaPinnedVersion already installed — skipping (idempotent)."
      return
    }
  }

  if ($OfflineBinary) {
    if (-not (Test-Path $OfflineBinary)) {
      Write-FailClosed "Offline Ollama binary not found: $OfflineBinary"
    }
    Write-Log "Installing Ollama from offline binary (no network access): $OfflineBinary"
    $destDir = "$env:ProgramFiles\CS3\ollama"
    New-Item -ItemType Directory -Path $destDir -Force | Out-Null
    Copy-Item -Path $OfflineBinary -Destination (Join-Path $destDir 'ollama.exe') -Force
    Add-MachinePath -Directory $destDir
    Assert-OllamaPinnedVersion
    return
  }

  if ($Profile -eq 'airgap') {
    Write-FailClosed "Profile is 'airgap' but no offline binary was provided (-Bundle must contain bin/ollama.exe). Refusing to fetch from the network."
  }

  Write-Log "Installing Ollama $OllamaPinnedVersion via winget (pinned version)..."
  $winget = Get-Command winget -ErrorAction SilentlyContinue
  if (-not $winget) {
    Write-FailClosed "winget was not found. Install Ollama $OllamaPinnedVersion manually from https://ollama.com/download and re-run."
  }
  Invoke-NativeChecked -FilePath 'winget' -ArgumentList @('install', '--id', 'Ollama.Ollama', '--version', $OllamaPinnedVersion, '--silent', '--accept-package-agreements', '--accept-source-agreements') -FailureMessage "winget install of Ollama $OllamaPinnedVersion failed"
  Update-ProcessPath
  Assert-OllamaPinnedVersion
}

function Assert-OllamaPinnedVersion {
  $command = Get-Command ollama -ErrorAction SilentlyContinue
  if (-not $command) {
    $candidate = Join-Path "$env:ProgramFiles\CS3\ollama" 'ollama.exe'
    if (Test-Path $candidate) { $command = Get-Command $candidate }
  }
  if (-not $command) { Write-FailClosed 'ollama.exe was not found after installation.' }
  $versionOutput = & $command.Source --version
  if ($LASTEXITCODE -ne 0 -or $versionOutput -notmatch ('(?i)(^|[^0-9])' + [regex]::Escape($OllamaPinnedVersion) + '([^0-9]|$)')) {
    Write-FailClosed "Installed Ollama does not report the required pinned version $OllamaPinnedVersion."
  }
}

function Set-LoopbackOnlyBinding {
  # Ollama on Windows reads OLLAMA_HOST from the environment; pin it to
  # loopback at the machine scope so the server never binds a routable
  # interface, matching the systemd/launchd hardening on Linux/macOS.
  [Environment]::SetEnvironmentVariable('OLLAMA_HOST', $OllamaBindAddr, 'Machine')
  $env:OLLAMA_HOST = $OllamaBindAddr
  Write-Log "OLLAMA_HOST pinned to $OllamaBindAddr (loopback only)."
}

function Set-OllamaModelsPath {
  # Ollama on Windows reads OLLAMA_MODELS from the environment. Without this the service account would
  # fall back to its own (non-existent) profile and the models pulled/loaded below would never be found.
  New-Item -ItemType Directory -Path $ModelsTarget -Force | Out-Null
  [Environment]::SetEnvironmentVariable('OLLAMA_MODELS', $ModelsTarget, 'Machine')
  $env:OLLAMA_MODELS = $ModelsTarget
  Write-Log "OLLAMA_MODELS set to $ModelsTarget (machine scope)."
}

function Set-OllamaRuntimePolicy {
  $maxLoaded = $EnvMap['OLLAMA_MAX_LOADED_MODELS']
  if ($maxLoaded -ne '3') { Write-FailClosed 'OLLAMA_MAX_LOADED_MODELS must be 3 for the three-model production preload.' }
  [Environment]::SetEnvironmentVariable('OLLAMA_MAX_LOADED_MODELS', $maxLoaded, 'Machine')
  $env:OLLAMA_MAX_LOADED_MODELS = $maxLoaded
}

function Grant-ServiceAccountDataAccess {
  # Only the service account (plus SYSTEM/Administrators) may read or write the model store.
  Invoke-NativeChecked -FilePath 'icacls.exe' -ArgumentList @($OllamaHome, '/inheritance:r', '/grant:r', 'SYSTEM:(OI)(CI)F', 'Administrators:(OI)(CI)F', "${ServiceAccount}:(OI)(CI)M") -FailureMessage 'Could not secure the Ollama model-store ACL' | Out-Null
  $children = Join-Path $OllamaHome '*'
  if (Get-ChildItem -LiteralPath $OllamaHome -Force | Select-Object -First 1) {
    Invoke-NativeChecked -FilePath 'icacls.exe' -ArgumentList @($children, '/reset', '/T') -FailureMessage 'Could not restore inherited ACLs beneath the Ollama model store' | Out-Null
  }
}

function Find-Nssm {
  param([string]$OfflineNssm)
  if ($OfflineNssm -and (Test-Path $OfflineNssm)) {
    $destDir = "$env:ProgramFiles\CS3\ollama"
    New-Item -ItemType Directory -Path $destDir -Force | Out-Null
    Copy-Item -Path $OfflineNssm -Destination (Join-Path $destDir 'nssm.exe') -Force
    return (Join-Path $destDir 'nssm.exe')
  }
  $cmd = Get-Command nssm -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  if ($Profile -ne 'airgap') {
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
      Write-Log 'Installing NSSM (service wrapper for ollama serve) via winget...'
      Invoke-NativeChecked -FilePath 'winget' -ArgumentList @('install', '--id', 'NSSM.NSSM', '--silent', '--accept-package-agreements', '--accept-source-agreements') -FailureMessage 'winget install of NSSM failed' | Out-Null
      Update-ProcessPath
      $cmd = Get-Command nssm -ErrorAction SilentlyContinue
      if ($cmd) { return $cmd.Source }
    }
  }
  return $null
}

function Register-OllamaService {
  param([string]$OfflineNssm)

  $ollamaExe = (Get-Command ollama -ErrorAction SilentlyContinue).Source
  if (-not $ollamaExe) {
    $candidate = Join-Path "$env:ProgramFiles\CS3\ollama" 'ollama.exe'
    if (Test-Path $candidate) { $ollamaExe = $candidate }
  }
  if (-not $ollamaExe) {
    Write-FailClosed 'ollama.exe not found; cannot register the cs3-ollama Windows service.'
  }
  # ollama.exe is not a native Windows service binary (it never answers the Service Control Manager),
  # so it is hosted by NSSM, which runs `ollama serve` under the cs3-ollama account.
  $nssm = Find-Nssm -OfflineNssm $OfflineNssm
  if (-not $nssm) {
    Write-FailClosed "NSSM was not found. Install it (winget install NSSM.NSSM; airgap: include bin\nssm.exe in the bundle) and re-run."
  }

  $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
  if ($existing -and $existing.Status -ne 'Stopped') {
    Write-Log "Stopping service $ServiceName before updating its runtime..."
    try {
      Stop-Service -Name $ServiceName -Force -ErrorAction Stop
      $existing.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    } catch {
      Write-FailClosed "Service $ServiceName did not stop cleanly: $($_.Exception.Message)"
    }
  }

  $sourceOllama = $ollamaExe
  $serviceBinDir = "$env:ProgramFiles\CS3\ollama"
  New-Item -ItemType Directory -Path $serviceBinDir -Force | Out-Null

  $sourceBinDir = Split-Path -Parent $sourceOllama
  $userBinDir = "$env:LOCALAPPDATA\Programs\Ollama"
  if (Test-Path (Join-Path $userBinDir 'ollama.exe')) {
    $sourceBinDir = $userBinDir
  }
  $ollamaExe = Join-Path $serviceBinDir 'ollama.exe'
  if ($sourceBinDir -ne $serviceBinDir) {
    Copy-Item -Path (Join-Path $sourceBinDir '*') -Destination $serviceBinDir -Recurse -Force
  }
  $runtimeServer = @(
    (Join-Path $serviceBinDir 'llama-server.exe')
    (Join-Path $serviceBinDir 'lib\ollama\llama-server.exe')
  ) | Where-Object { Test-Path $_ } | Select-Object -First 1
  if (-not $runtimeServer) {
    Write-FailClosed "Staged Ollama runtime is incomplete: llama-server.exe was not found under $serviceBinDir."
  }

  $nssmItem = Get-Item -Path $nssm
  $nssmSource = $nssm
  if ($nssmItem.Target) { $nssmSource = [string]$nssmItem.Target[0] }
  $serviceNssm = Join-Path $serviceBinDir 'nssm.exe'
  if ($nssmSource -ne $serviceNssm) {
    Copy-Item -Path $nssmSource -Destination $serviceNssm -Force
  }
  $nssm = $serviceNssm
  Add-MachinePath -Directory $serviceBinDir
  Write-Log "Staged the Ollama runtime and service wrapper in $serviceBinDir for least-privilege access."

  # The Ollama desktop app (installed by winget) auto-starts its own server on 11434; stop it so the
  # hardened service owns the port.
  Get-Process -Name 'ollama app', 'ollama' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

  Grant-ServiceAccountDataAccess

  $logDir = Join-Path $OllamaHome 'logs'
  New-Item -ItemType Directory -Path $logDir -Force | Out-Null

  if ($existing) {
    Write-Log "Service $ServiceName already registered — updating its configuration without rotating credentials."
    Invoke-NativeChecked -FilePath $nssm -ArgumentList @('set', $ServiceName, 'Application', $ollamaExe) -FailureMessage 'Could not set the Ollama service binary' | Out-Null
    Invoke-NativeChecked -FilePath $nssm -ArgumentList @('set', $ServiceName, 'AppParameters', 'serve') -FailureMessage 'Could not set the Ollama service arguments' | Out-Null
  } else {
    if (-not $script:ServicePassword) {
      # A pre-existing account without a service has no recoverable password. Reset it only now,
      # immediately before service registration, rather than at the start of installation.
      $script:ServicePassword = New-RandomPassword
      $secure = ConvertTo-SecureString -String $script:ServicePassword -AsPlainText -Force
      Set-LocalUser -Name $ServiceAccount -Password $secure
    }
    Write-Log "Registering Windows service $ServiceName (ollama serve) under account $ServiceAccount..."
    Invoke-NativeChecked -FilePath $nssm -ArgumentList @('install', $ServiceName, $ollamaExe, 'serve') -FailureMessage 'NSSM service installation failed' | Out-Null
  }

  if ($existing) {
    Invoke-NativeChecked -FilePath 'sc.exe' -ArgumentList @('config', $ServiceName, 'binPath=', ('"{0}"' -f $nssm)) -FailureMessage 'Could not update the Ollama service wrapper path' | Out-Null
  }

  $nssmSettings = @(
    @('DisplayName', 'CS3 Ollama (loopback-only)'),
    @('Description', 'CS3 local LLM runtime: ollama serve bound to loopback under the cs3-ollama service account.'),
    @('Start', 'SERVICE_AUTO_START'),
    @('AppDirectory', $OllamaHome),
    @('AppEnvironmentExtra', "OLLAMA_HOST=$OllamaBindAddr", "OLLAMA_MODELS=$ModelsTarget", "OLLAMA_MAX_LOADED_MODELS=$($EnvMap['OLLAMA_MAX_LOADED_MODELS'])", "HOME=$OllamaHome", "USERPROFILE=$OllamaHome"),
    @('AppStdout', (Join-Path $logDir 'cs3-ollama.log')),
    @('AppStderr', (Join-Path $logDir 'cs3-ollama.err.log')),
    @('AppExit', 'Default', 'Restart'),
    @('AppRestartDelay', '5000')
  )
  foreach ($setting in $nssmSettings) {
    Invoke-NativeChecked -FilePath $nssm -ArgumentList (@('set', $ServiceName) + $setting) -FailureMessage "Could not configure NSSM setting $($setting[0])" | Out-Null
  }
  if ($script:ServicePassword) {
    Invoke-NativeChecked -FilePath $nssm -ArgumentList @('set', $ServiceName, 'ObjectName', ".\$ServiceAccount", $script:ServicePassword) -FailureMessage 'Could not configure the Ollama service account' | Out-Null
  }

  try {
    Start-Service -Name $ServiceName -ErrorAction Stop
    $svc = Get-Service -Name $ServiceName -ErrorAction Stop
    $svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
  } catch {
    Write-FailClosed "Service $ServiceName did not reach Running within 30 seconds: $($_.Exception.Message); see $logDir for details."
  }
  $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
  if (-not $svc -or $svc.Status -ne 'Running') {
    Write-FailClosed "Service $ServiceName did not reach the Running state; see $logDir for details."
  }
  Write-Log "Service $ServiceName is running, bound to $OllamaBindAddr under $ServiceAccount."
}

function Get-RequiredModelTags {
  $preload = $EnvMap['OLLAMA_PRELOAD_MODELS']
  if ([string]::IsNullOrWhiteSpace($preload)) {
    $preload = 'nemotron-3-nano:30b,gemma4:26b,gemma4:31b'
  }
  return @($preload -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
}

function Assert-ProductionModelConfiguration {
  $required = @{
    CS3_MODEL_TRIAGE = 'nemotron-3-nano:30b'
    CS3_MODEL_REASONING = 'gemma4:26b'
    CS3_MODEL_REASONING_DEEP = 'gemma4:31b'
    CS3_MODEL_SECURITY = 'nemotron-3-nano:30b'
    CS3_MODEL_ERROW_SECURITY = 'cs3-errow-security'
    INFERENCE_MODEL_TRIAGE = 'nemotron-3-nano:30b'
    INFERENCE_MODEL_FORENSIC = 'gemma4:26b'
    INFERENCE_MODEL_REASONING_DEEP = 'gemma4:31b'
    INFERENCE_MODEL_SECURITY = 'nemotron-3-nano:30b'
    INFERENCE_MODEL_ERROW_SECURITY = 'nemotron-3-nano:30b'
    INFERENCE_MODEL_GUARD = 'gemma4:26b'
    OLLAMA_PRIMARY_MODEL = 'nemotron-3-nano:30b'
    OLLAMA_FALLBACK_MODEL = 'gemma4:26b'
    OLLAMA_SECURITY_MODEL = 'nemotron-3-nano:30b'
    OLLAMA_REASONING_DEEP_MODEL = 'gemma4:31b'
    OLLAMA_ERROW_SECURITY_MODEL = 'nemotron-3-nano:30b'
    OLLAMA_MAX_LOADED_MODELS = '3'
  }
  foreach ($key in $required.Keys) {
    if ($EnvMap[$key] -ne $required[$key]) {
      Write-FailClosed "$key must be '$($required[$key])' for this production release. Re-run onboarding or repair .env; no model substitution is permitted."
    }
  }
  $preload = @(Get-RequiredModelTags)
  if (($preload -join ',') -ne 'nemotron-3-nano:30b,gemma4:26b,gemma4:31b') {
    Write-FailClosed 'OLLAMA_PRELOAD_MODELS must contain exactly nemotron-3-nano:30b,gemma4:26b,gemma4:31b in production order.'
  }
  $budgets = @{ INFERENCE_MAX_TOKENS_TRIAGE = '1024'; INFERENCE_MAX_TOKENS_SECURITY = '2048'; INFERENCE_MAX_TOKENS_ERROW = '4096' }
  foreach ($key in $budgets.Keys) {
    if ($EnvMap[$key] -and $EnvMap[$key] -ne $budgets[$key]) {
      Write-FailClosed "$key must be $($budgets[$key]) for this production release."
    }
  }
}

function Assert-LocalModels {
  $ollama = Get-Command ollama -ErrorAction SilentlyContinue
  if (-not $ollama) { Write-FailClosed 'ollama.exe not found; cannot verify the required model inventory.' }
  $inventory = & $ollama.Source list
  if ($LASTEXITCODE -ne 0) { Write-FailClosed 'ollama list failed; the local model service is not healthy.' }
  foreach ($model in @(Get-RequiredModelTags)) {
    $modelPattern = '(?m)^\s*' + [regex]::Escape($model) + '\s+'
    if (@($inventory -match $modelPattern).Count -eq 0) {
      Write-FailClosed "Required model $model is absent from ollama list."
    }
    Invoke-NativeChecked -FilePath $ollama.Source -ArgumentList @('show', $model) -FailureMessage "ollama show failed for required model $model" | Out-Null
  }
  Write-Log 'Verified all required production models with ollama list/show.'
}

function Assert-InstallerPreflight {
  if ($env:OS -ne 'Windows_NT') { Write-FailClosed 'install.ps1 supports Windows hosts only.' }
  if ($Profile -ne 'cloud') {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
      Write-FailClosed 'On-prem and air-gap installation must run from an elevated Administrator PowerShell.'
    }
    Assert-ProductionModelConfiguration
  }
  if ($Profile -eq 'airgap') {
    if (-not $Bundle -or -not (Test-Path $Bundle -PathType Leaf)) { Write-FailClosed 'airgap profile requires an existing -Bundle file.' }
    if ($EnvMap['CS3_AIRGAP_BUNDLE_SHA256'] -notmatch '^[0-9a-fA-F]{64}$') {
      Write-FailClosed 'CS3_AIRGAP_BUNDLE_SHA256 must be a 64-character SHA-256 hash.'
    }
    if ($EnvMap['CS3_TELEMETRY_ENABLED'] -ne 'false' -or $EnvMap['CS3_UPDATE_CHECK_ENABLED'] -ne 'false') {
      Write-FailClosed 'Telemetry/update checks must be disabled before any air-gap installation changes are made.'
    }
  }
  $port = 0
  if ($EnvMap['CS3_CONSOLE_PORT'] -and (-not [int]::TryParse($EnvMap['CS3_CONSOLE_PORT'], [ref]$port) -or $port -lt 1 -or $port -gt 65535)) {
    Write-FailClosed 'CS3_CONSOLE_PORT must be an integer between 1 and 65535.'
  }
}

function New-PostgreSqlSecret {
  $bytes = New-Object byte[] 32
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
  return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Protect-InstallerSecretFile {
  param([Parameter(Mandatory = $true)][string]$Path)
  Invoke-NativeChecked -FilePath 'icacls.exe' -ArgumentList @($Path, '/inheritance:r', '/grant:r', 'SYSTEM:(F)', 'Administrators:(F)') -FailureMessage "Could not protect secret file $Path" | Out-Null
}

function Write-ProtectedDotEnv {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [string[]]$Lines
  )
  $parent = Split-Path -Parent $Path
  $temp = Join-Path $parent ('.cs3-env-' + [Guid]::NewGuid().ToString('N') + '.tmp')
  try {
    [IO.File]::WriteAllLines($temp, $Lines, (New-Object Text.UTF8Encoding($false)))
    Protect-InstallerSecretFile -Path $temp
    Move-Item $temp $Path -Force
  } finally {
    if (Test-Path $temp) { Remove-Item $temp -Force }
  }
}

function Set-DotEnvValues {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][hashtable]$Values,
    [string[]]$InitialLines = @()
  )
  $lines = @(
    if (Test-Path $Path) { Get-Content -Path $Path } else { $InitialLines }
  )
  foreach ($key in $Values.Keys) {
    $pattern = '^' + [regex]::Escape($key) + '='
    $found = $false
    for ($i = 0; $i -lt $lines.Count; $i++) {
      if ($lines[$i] -match $pattern) {
        $lines[$i] = "$key=$($Values[$key])"
        $found = $true
      }
    }
    if (-not $found) { $lines += "$key=$($Values[$key])" }
  }
  Write-ProtectedDotEnv -Path $Path -Lines $lines
}

function Initialize-SocPersistence {
  param([Parameter(Mandatory = $true)][string]$DockerPath)

  $composeDir = Join-Path $PSScriptRoot 'deployment\docker'
  $composeFile = Join-Path $composeDir 'docker-compose.yml'
  $windowsOverride = Join-Path $composeDir 'docker-compose.windows.yml'
  $composeEnv = Join-Path $composeDir '.env'
  $roleInit = Join-Path $composeDir 'postgres\init\001_roles.sh'
  foreach ($requiredFile in @($composeFile, $windowsOverride, $roleInit)) {
    if (-not (Test-Path $requiredFile -PathType Leaf)) { Write-FailClosed "Required PostgreSQL deployment file is missing: $requiredFile" }
  }

  $composeLines = @(
    if (Test-Path $composeEnv) { Get-Content -Path $composeEnv }
  )
  $malformedComposeEnv = (
    $composeLines.Count -eq 1 -and
    $composeLines[0].StartsWith('# CS3 local PostgreSQL secrets;') -and
    $composeLines[0].Contains('POSTGRES_DB=')
  )
  $composeMap = if ((Test-Path $composeEnv) -and -not $malformedComposeEnv) { Import-DotEnv -Path $composeEnv } else { @{} }
  $database = if ($composeMap['POSTGRES_DB']) { $composeMap['POSTGRES_DB'] } else { 'cs3' }
  $postgresUser = if ($composeMap['POSTGRES_USER']) { $composeMap['POSTGRES_USER'] } else { 'postgres' }
  if ($database -notmatch '^[A-Za-z0-9_]+$' -or $postgresUser -notmatch '^[A-Za-z0-9_]+$') {
    Write-FailClosed 'POSTGRES_DB and POSTGRES_USER must contain only letters, digits, and underscores.'
  }

  $volumeProbe = Invoke-NativeProbe -FilePath $DockerPath -ArgumentList @('volume', 'inspect', 'cs3_pgdata')
  $containerProbe = Invoke-NativeProbe -FilePath $DockerPath -ArgumentList @('inspect', 'cs3-postgres')
  $databaseExists = ($volumeProbe.ExitCode -eq 0 -or $containerProbe.ExitCode -eq 0)
  $secretKeys = @('POSTGRES_PASSWORD', 'CS3_APP_PASSWORD', 'CS3_MIGRATOR_PASSWORD', 'CS3_ARCHIVER_PASSWORD')
  $missing = @($secretKeys | Where-Object { -not $composeMap[$_] })
  if ($missing.Count -gt 0) {
    if ($databaseExists -or $EnvMap['DATABASE_URL']) {
      Write-FailClosed 'PostgreSQL credentials are incomplete for an existing configuration. Restore the original deployment/docker/.env; refusing credential rotation.'
    }
    foreach ($key in $missing) { $composeMap[$key] = New-PostgreSqlSecret }
    Write-Log 'Generated new cryptographic PostgreSQL credentials for the initial database only.'
  }
  if ($malformedComposeEnv) {
    # This is reachable only for a fresh database with no existing DATABASE_URL; discard the partial scalar write.
    Remove-Item $composeEnv -Force
  }
  $composeMap['POSTGRES_DB'] = $database
  $composeMap['POSTGRES_USER'] = $postgresUser

  # Hex secrets are URL-safe and keep the console limited to the cs3_app runtime role.
  $databaseUrl = 'postgres://cs3_app:' + $composeMap['CS3_APP_PASSWORD'] + '@host.docker.internal:5432/' + $database
  if ($EnvMap['DATABASE_URL'] -and $EnvMap['DATABASE_URL'] -ne $databaseUrl) {
    Write-FailClosed 'DATABASE_URL does not match the protected local PostgreSQL runtime credentials; refusing to rotate or replace them.'
  }

  $composeValues = @{
    POSTGRES_DB = $database
    POSTGRES_USER = $postgresUser
    POSTGRES_PASSWORD = $composeMap['POSTGRES_PASSWORD']
    CS3_APP_PASSWORD = $composeMap['CS3_APP_PASSWORD']
    CS3_MIGRATOR_PASSWORD = $composeMap['CS3_MIGRATOR_PASSWORD']
    CS3_ARCHIVER_PASSWORD = $composeMap['CS3_ARCHIVER_PASSWORD']
  }
  Set-DotEnvValues -Path $composeEnv -Values $composeValues -InitialLines @('# CS3 local PostgreSQL secrets; generated once and protected for Administrators/SYSTEM only.')

  if (-not $EnvMap['DATABASE_URL']) {
    $secretDir = Join-Path $env:ProgramData 'CS3\secrets'
    New-Item -ItemType Directory -Path $secretDir -Force | Out-Null
    Invoke-NativeChecked -FilePath 'icacls.exe' -ArgumentList @($secretDir, '/inheritance:r', '/grant:r', 'SYSTEM:(OI)(CI)F', 'Administrators:(OI)(CI)F') -FailureMessage 'Could not protect the CS3 secret-backup directory' | Out-Null
    $envBackup = Join-Path $secretDir ('env-pre-postgres-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.bak')
    Copy-Item $envPath $envBackup
    Protect-InstallerSecretFile -Path $envBackup
    Set-DotEnvValues -Path $envPath -Values @{ DATABASE_URL = $databaseUrl }
    $EnvMap['DATABASE_URL'] = $databaseUrl
    Write-Log 'Added the least-privilege DATABASE_URL without changing existing onboarding credentials.'
  }

  # Windows checkouts can use CRLF, but the Linux postgres entrypoint requires an LF shebang.
  $roleText = [IO.File]::ReadAllText($roleInit)
  $normalizedRoleText = $roleText.Replace("`r`n", "`n").Replace("`r", "`n")
  if ($normalizedRoleText -ne $roleText) {
    [IO.File]::WriteAllText($roleInit, $normalizedRoleText, (New-Object Text.UTF8Encoding($false)))
    Write-Log 'Normalized the PostgreSQL role-init shell script to LF line endings.'
  }

  Invoke-NativeChecked -FilePath $DockerPath -ArgumentList @('compose', 'version') -FailureMessage 'Docker Compose is required for local PostgreSQL persistence' | Out-Null
  $composeArgs = @('compose', '--env-file', $envPath, '--env-file', $composeEnv, '-f', $composeFile, '-f', $windowsOverride, 'up', '-d')
  if ($Profile -eq 'airgap') { $composeArgs += @('--pull', 'never') }
  $composeArgs += 'postgres'
  Invoke-NativeChecked -FilePath $DockerPath -ArgumentList $composeArgs -FailureMessage 'Could not start the local PostgreSQL persistence service'

  $deadline = [DateTime]::UtcNow.AddMinutes(3)
  $postgresState = ''
  do {
    $stateProbe = Invoke-NativeProbe -FilePath $DockerPath -ArgumentList @('inspect', '--format', '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}', 'cs3-postgres')
    $postgresState = [string]($stateProbe.Output | Select-Object -Last 1)
    if ($stateProbe.ExitCode -eq 0 -and $postgresState -eq 'running|healthy') { break }
    if ($postgresState -match '^(exited|dead)\|') { break }
    Start-Sleep -Seconds 2
  } while ([DateTime]::UtcNow -lt $deadline)
  if ($postgresState -ne 'running|healthy') {
    Write-FailClosed "PostgreSQL did not become healthy (last state: $postgresState). Inspect docker logs cs3-postgres; no credentials were rotated."
  }
  Write-Log 'Local PostgreSQL is healthy; durable console persistence is available on loopback.'
}

function Start-SocConsole {
  $image = $EnvMap['CS3_CONSOLE_IMAGE']
  $port = $EnvMap['CS3_CONSOLE_PORT']
  if (-not $port) { $port = '3000' }
  if (-not $image) { Write-FailClosed 'CS3_CONSOLE_IMAGE is required; refusing to skip the console container.' }

  $docker = Get-Command docker -ErrorAction SilentlyContinue
  if (-not $docker) { Write-FailClosed 'Docker is required for the CS3 console but was not found on PATH.' }
  Invoke-NativeChecked -FilePath $docker.Source -ArgumentList @('info', '--format', '{{.ServerVersion}}') -FailureMessage 'Docker Engine is not reachable' | Out-Null
  if ($Profile -ne 'cloud' -and $EnvMap['CS3_PERSISTENCE'] -eq 'postgres') {
    Initialize-SocPersistence -DockerPath $docker.Source
  }

  # Acquire or verify the image before disrupting an existing working container. On-prem installs
  # build the versioned local image from the packaged source; registry substitutions must be digest-pinned.
  $buildLocal = ($Profile -eq 'onprem' -and $image -notmatch '/')
  if ($Profile -eq 'onprem' -and -not $buildLocal -and $image -notmatch '@sha256:[0-9a-fA-F]{64}$') {
    Write-FailClosed 'An on-prem registry console image must include an explicit @sha256:<64-hex> digest.'
  }
  $imageInspection = Invoke-NativeProbe -FilePath $docker.Source -ArgumentList @('image', 'inspect', $image)
  $imagePresent = ($imageInspection.ExitCode -eq 0)
  if (-not $imagePresent -and $Profile -eq 'airgap') {
    Write-FailClosed "Image $image is not present locally. Load it from the verified air-gap bundle before starting the console."
  }
  if ($buildLocal) {
    Write-Log "Building versioned console image $image from packaged source."
    Invoke-NativeChecked -FilePath $docker.Source -ArgumentList @('build', '--pull=false', '--load', '-t', $image, (Join-Path $PSScriptRoot 'demo\demo-100226')) -FailureMessage "Could not build $image from packaged source"
  } elseif (-not $imagePresent -and $Profile -ne 'airgap') {
    Write-Log "Pulling console image $image."
    Invoke-NativeChecked -FilePath $docker.Source -ArgumentList @('pull', $image) -FailureMessage "Could not pull console image $image"
  }

  $containerName = 'cs3-soc-console'
  $backupName = 'cs3-soc-console-install-backup'
  $backupInspection = Invoke-NativeProbe -FilePath $docker.Source -ArgumentList @('inspect', $backupName)
  if ($backupInspection.ExitCode -eq 0) { Write-FailClosed "Stale rollback container $backupName exists. Inspect and remove it only after backing up required state." }
  $containerInspection = Invoke-NativeProbe -FilePath $docker.Source -ArgumentList @('inspect', $containerName)
  $hasExisting = ($containerInspection.ExitCode -eq 0)
  if ($hasExisting) {
    Write-Log 'Preserving the existing console as a rollback container until its replacement starts.'
    Invoke-NativeChecked -FilePath $docker.Source -ArgumentList @('stop', $containerName) -FailureMessage 'Could not stop the existing console' | Out-Null
    Invoke-NativeChecked -FilePath $docker.Source -ArgumentList @('rename', $containerName, $backupName) -FailureMessage 'Could not preserve the existing console for rollback' | Out-Null
  }

  # Docker Desktop runs containers in a VM, so the container's 127.0.0.1 is not the Windows host.
  $dockerArgs = @('run', '-d', '--name', $containerName, '--env-file', "$envPath", '-p', "${port}:3000")
  if ($Profile -ne 'cloud') {
    $dockerArgs += @('--add-host=host.docker.internal:host-gateway', '-e', 'OLLAMA_BASE_URL=http://host.docker.internal:11434/v1')
  }
  Write-Log "Starting CS3 ESOC Console container ($image) on port $port..."
  & $docker.Source @dockerArgs $image
  if ($LASTEXITCODE -ne 0) {
    Invoke-NativeProbe -FilePath $docker.Source -ArgumentList @('rm', '-f', $containerName) | Out-Null
    if ($hasExisting) {
      Invoke-NativeChecked -FilePath $docker.Source -ArgumentList @('rename', $backupName, $containerName) -FailureMessage 'Could not restore the previous console name after a failed replacement' | Out-Null
      Invoke-NativeChecked -FilePath $docker.Source -ArgumentList @('start', $containerName) -FailureMessage 'Could not restart the previous console after a failed replacement' | Out-Null
    }
    Write-FailClosed 'Failed to start the ESOC Console container.'
  }

  $deadline = [DateTime]::UtcNow.AddMinutes(2)
  $state = ''
  $failure = ''
  do {
    $stateInspection = Invoke-NativeProbe -FilePath $docker.Source -ArgumentList @('inspect', '--format', '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}', $containerName)
    $state = $stateInspection.Output | Select-Object -Last 1
    if ($stateInspection.ExitCode -ne 0) { $failure = 'Could not inspect the new console container state.'; break }
    if ($state -eq 'healthy' -or $state -eq 'running') { break }
    if ($state -eq 'unhealthy' -or $state -eq 'exited' -or $state -eq 'dead') { $failure = "Console container entered state $state."; break }
    Start-Sleep -Seconds 2
  } while ([DateTime]::UtcNow -lt $deadline)
  if (-not $failure -and $state -ne 'healthy' -and $state -ne 'running') { $failure = "Console container did not become healthy (last state: $state)." }
  if ($failure) {
    Invoke-NativeProbe -FilePath $docker.Source -ArgumentList @('rm', '-f', $containerName) | Out-Null
    if ($hasExisting) {
      Invoke-NativeChecked -FilePath $docker.Source -ArgumentList @('rename', $backupName, $containerName) -FailureMessage 'Could not restore the previous console name after an unhealthy replacement' | Out-Null
      Invoke-NativeChecked -FilePath $docker.Source -ArgumentList @('start', $containerName) -FailureMessage 'Could not restart the previous console after an unhealthy replacement' | Out-Null
    }
    Write-FailClosed $failure
  }
  if ($hasExisting) {
    Invoke-NativeChecked -FilePath $docker.Source -ArgumentList @('rm', $backupName) -FailureMessage 'New console is healthy, but its stopped rollback container could not be removed' | Out-Null
  }
  Write-Log "Console container is $state."
}

function Install-OnpremOllamaAndModel {
  Initialize-ServiceAccount
  Install-OllamaBinary -OfflineBinary $null
  Set-LoopbackOnlyBinding
  Set-OllamaModelsPath
  Set-OllamaRuntimePolicy
  Register-OllamaService -OfflineNssm $null

  $ollama = Get-Command ollama -ErrorAction SilentlyContinue
  if (-not $ollama) { Write-FailClosed 'ollama.exe not found after installation; cannot provision models.' }
  foreach ($model in @(Get-RequiredModelTags)) {
    if ($model -eq 'cs3-errow-security') { Write-FailClosed 'The Errow gateway route must never be used as an Ollama model tag.' }
    Write-Log "Pulling approved model tag: $model"
    Invoke-NativeChecked -FilePath $ollama.Source -ArgumentList @('pull', $model) -FailureMessage "Failed to pull required model $model"
  }
  Assert-LocalModels
}

function Install-AirgapOllamaAndModel {
  $actualHash = (Get-FileHash -Path $Bundle -Algorithm SHA256).Hash
  if ($actualHash -ine $EnvMap['CS3_AIRGAP_BUNDLE_SHA256']) {
    Write-FailClosed "Air-gap bundle SHA-256 mismatch. Expected $($EnvMap['CS3_AIRGAP_BUNDLE_SHA256']); actual $actualHash. No files were extracted."
  }
  Write-Log "Verified air-gap bundle SHA-256: $actualHash"

  $stagingDir = Join-Path $env:TEMP ("cs3-airgap-" + [System.Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null
  try {
    Write-Log "Extracting verified bundle (no registry pull will be attempted): $Bundle"
    Invoke-NativeChecked -FilePath 'tar.exe' -ArgumentList @('-xf', $Bundle, '-C', $stagingDir) -FailureMessage 'Could not extract the verified air-gap bundle'

    $offlineBinary = $null
    $candidateBinary = Join-Path $stagingDir 'bin\ollama.exe'
    if (Test-Path $candidateBinary) { $offlineBinary = $candidateBinary }

    $offlineNssm = $null
    $candidateNssm = Join-Path $stagingDir 'bin\nssm.exe'
    if (Test-Path $candidateNssm) { $offlineNssm = $candidateNssm }

    Initialize-ServiceAccount
    Install-OllamaBinary -OfflineBinary $offlineBinary
    Set-LoopbackOnlyBinding
    Set-OllamaModelsPath
    Set-OllamaRuntimePolicy

    $imagesSource = Join-Path $stagingDir 'images'
    if (Test-Path $imagesSource) {
      $docker = Get-Command docker -ErrorAction SilentlyContinue
      if (-not $docker) { Write-FailClosed 'The bundle contains images but Docker is unavailable to load them.' }
      Get-ChildItem -Path $imagesSource -Filter '*.tar' | ForEach-Object {
        Write-Log "Loading offline console image: $($_.FullName)"
        Invoke-NativeChecked -FilePath $docker.Source -ArgumentList @('load', '-i', $_.FullName) -FailureMessage "Failed to load offline image $($_.Name)"
      }
    }

    $modelsSource = Join-Path $stagingDir 'models'
    if (-not (Test-Path $modelsSource -PathType Container)) { Write-FailClosed 'The verified bundle does not contain the required models directory.' }
    Write-Log "Loading models directly into the local Ollama store from the bundle (no registry pull): $ModelsTarget"
    New-Item -ItemType Directory -Path $ModelsTarget -Force | Out-Null
    Copy-Item -Path (Join-Path $modelsSource '*') -Destination $ModelsTarget -Recurse -Force

    # Register/start the service after the models are in place so it opens a complete store.
    Register-OllamaService -OfflineNssm $offlineNssm
    Assert-LocalModels
  } finally {
    Remove-Item -Path $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
  }
  Write-Log 'Air-gap bundle, local models, and disabled telemetry/update policy verified.'
}

Assert-InstallerPreflight

switch ($Profile) {
  'cloud' {
    Start-SocConsole
  }
  'onprem' {
    Install-OnpremOllamaAndModel
    Start-SocConsole
  }
  'airgap' {
    Install-AirgapOllamaAndModel
    Start-SocConsole
  }
}

Write-Log "Windows installer finished for profile: $Profile"
