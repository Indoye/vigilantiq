<#
  VigilantIQ — agent « Parc & correctifs » pour Windows 10/11 et Windows Server 2016+ (PowerShell 5.1 ou 7).

  Installation (invite PowerShell en administrateur) :
    powershell -NoProfile -ExecutionPolicy Bypass -File .\vigilantiq-agent.ps1 -Install
  Désinstallation :
    powershell -NoProfile -ExecutionPolicy Bypass -File "C:\ProgramData\VigilantIQ\Patch\agent.ps1" -Uninstall

  L'agent s'installe dans C:\ProgramData\VigilantIQ\Patch (accès réservé à SYSTEM et aux administrateurs) et tourne
  en tâche planifiée sous le compte SYSTEM : il se synchronise chaque minute avec la console. Communication sortante
  uniquement (HTTPS 443), requêtes signées HMAC-SHA256 avec la clé de l'équipement (protégée par DPAPI).
  Il n'exécute que des actions prédéfinies (inventaire, mises à jour Windows Update et winget, désinstallation d'une
  mise à jour, redémarrage), et seulement si la tâche est signée avec la clé de l'équipement.
#>
param([switch]$Install, [switch]$Uninstall, [switch]$Once, [switch]$Status)

$ErrorActionPreference = 'Stop'
$AgentVersion = '1.0.0'
$Server = '__VQ_SERVER__'
$EnrollToken = '__VQ_ENROLL_TOKEN__'
if ($env:VQ_SERVER) { $Server = $env:VQ_SERVER }
if ($env:VQ_ENROLL_TOKEN) { $EnrollToken = $env:VQ_ENROLL_TOKEN }
$BaseDir = if ($env:VQ_STATE_DIR) { $env:VQ_STATE_DIR } elseif ($env:ProgramData) { Join-Path $env:ProgramData 'VigilantIQ\Patch' } else { '/var/lib/vigilantiq-ps' }
$StateFile = Join-Path $BaseDir 'state.json'
$Installed = Join-Path $BaseDir 'agent.ps1'
$LogFile = Join-Path $BaseDir 'agent.log'
$TaskName = 'VigilantIQ Patch Agent'
# Simulation : les installations et redémarrages sont journalisés mais pas exécutés (tests, démonstration).
$DryRun = $env:VQ_DRY_RUN -eq '1'
$RebootMessage = 'VigilantIQ : redémarrage dans 5 minutes pour terminer l''installation des correctifs. Enregistrez votre travail.'
$IsWin = [Environment]::OSVersion.Platform -eq 'Win32NT'

function Write-Log([string]$m) {
  $line = "{0} {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m
  try {
    if ((Test-Path $LogFile) -and (Get-Item $LogFile).Length -gt 2MB) { Move-Item -Force $LogFile "$LogFile.1" }
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
  } catch { }
  Write-Host $line
}

# ---------- État local ----------

function Protect-Text([string]$s) {
  if (-not $IsWin) { return $s }
  Add-Type -AssemblyName System.Security
  $b = [Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($s), $null, 'LocalMachine')
  return 'dpapi:' + [Convert]::ToBase64String($b)
}
function Unprotect-Text([string]$s) {
  if (-not $s.StartsWith('dpapi:')) { return $s }
  Add-Type -AssemblyName System.Security
  $b = [Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($s.Substring(6)), $null, 'LocalMachine')
  return [Text.Encoding]::UTF8.GetString($b)
}
function Get-State {
  if (-not (Test-Path $StateFile)) { return @{} }
  $o = Get-Content -Raw -Path $StateFile | ConvertFrom-Json
  $h = @{}
  foreach ($p in $o.PSObject.Properties) { $h[$p.Name] = $p.Value }
  if ($h.key) { $h.key = Unprotect-Text $h.key }
  return $h
}
function Save-State($h) {
  New-Item -ItemType Directory -Force -Path $BaseDir | Out-Null
  $copy = @{}
  foreach ($k in $h.Keys) { $copy[$k] = $h[$k] }
  if ($copy.key) { $copy.key = Protect-Text $copy.key }
  ($copy | ConvertTo-Json -Compress) | Set-Content -Path $StateFile -Encoding UTF8
}
function Get-ServerUrl($state) {
  $s = $Server
  if ($state -and $state.server) { $s = $state.server }
  $s = $s.TrimEnd('/')
  $u = [Uri]$s
  $local = @('localhost', '127.0.0.1', '::1') -contains $u.Host
  if ($u.Scheme -ne 'https' -and -not ($u.Scheme -eq 'http' -and $local)) { throw "Adresse du serveur invalide : HTTPS obligatoire ($s)" }
  return $s
}

# ---------- HTTP ----------

function Get-Hmac([string]$key, [byte[]]$data) {
  $h = New-Object System.Security.Cryptography.HMACSHA256
  $h.Key = [Text.Encoding]::UTF8.GetBytes($key)
  return (-join ($h.ComputeHash($data) | ForEach-Object { $_.ToString('x2') }))
}
function Invoke-Vq([string]$path, $body, [string]$key, $state) {
  $json = $body | ConvertTo-Json -Depth 8 -Compress
  $bytes = [Text.Encoding]::UTF8.GetBytes($json)
  $headers = @{ 'User-Agent' = "vigilantiq-agent/$AgentVersion (windows)" }
  if ($key) {
    $ts = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString()
    $sig = Get-Hmac $key ([Text.Encoding]::UTF8.GetBytes("$ts.") + $bytes)
    $headers['Authorization'] = "Bearer $key"
    $headers['X-VQ-Timestamp'] = $ts
    $headers['X-VQ-Signature'] = "sha256=$sig"
  }
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  $url = (Get-ServerUrl $state) + $path
  try {
    $r = Invoke-WebRequest -Uri $url -Method Post -Body $bytes -ContentType 'application/json; charset=utf-8' -Headers $headers -UseBasicParsing -TimeoutSec 120
    $text = if ($r.Content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($r.Content) } else { [string]$r.Content }
    return @{ code = [int]$r.StatusCode; body = ($text | ConvertFrom-Json) }
  } catch {
    $resp = $_.Exception.Response
    if ($null -eq $resp) { throw }
    $code = [int]$resp.StatusCode
    $msg = "HTTP $code"
    try { if ($_.ErrorDetails.Message) { $msg = ($_.ErrorDetails.Message | ConvertFrom-Json).error } } catch { }
    return @{ code = $code; body = [pscustomobject]@{ error = $msg } }
  }
}

# ---------- Inventaire ----------

function Get-MachineId {
  $g = ''
  try { $g = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid } catch { }
  if (-not $g) { $g = [Environment]::MachineName }
  $sha = [Security.Cryptography.SHA256]::Create()
  return (-join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("vigilantiq:$g")) | ForEach-Object { $_.ToString('x2') })).Substring(0, 32)
}

function Find-Winget {
  $c = Get-Command winget.exe -ErrorAction SilentlyContinue
  if ($c) { return $c.Source }
  $p = Get-ChildItem -Path "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe" -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
  if ($p) { return $p.FullName }
  return $null
}

function Test-RebootPending {
  if (-not $IsWin) { return $false }
  $keys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
  )
  foreach ($k in $keys) { if (Test-Path $k) { return $true } }
  return $false
}

function Get-Inventory {
  if ($env:VQ_INVENTORY_FILE) { return (Get-Content -Raw $env:VQ_INVENTORY_FILE | ConvertFrom-Json) }
  $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
  $os = Get-CimInstance Win32_OperatingSystem
  $cs = Get-CimInstance Win32_ComputerSystem
  $bios = Get-CimInstance Win32_BIOS
  $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
  $arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
  $ip = $null
  try { $ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } | Select-Object -First 1).IPAddress } catch { }

  $apps = New-Object System.Collections.ArrayList
  $roots = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
  Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } | ForEach-Object {
    $roots += "Registry::HKEY_USERS\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
  }
  foreach ($r in $roots) {
    Get-ItemProperty $r -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and $_.SystemComponent -ne 1 -and -not $_.ParentKeyName } | ForEach-Object {
      [void]$apps.Add(@{ name = [string]$_.DisplayName; version = [string]$_.DisplayVersion; publisher = [string]$_.Publisher })
    }
  }
  $kbs = @(Get-HotFix -ErrorAction SilentlyContinue | ForEach-Object { @{ id = [string]$_.HotFixID; installedOn = if ($_.InstalledOn) { $_.InstalledOn.ToString('yyyy-MM-dd') } else { '' } } })
  $drivers = @(Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue | Where-Object { $_.DriverProviderName -and $_.DriverProviderName -notmatch '^Microsoft' -and $_.DeviceName } |
    Sort-Object DeviceName -Unique | Select-Object -First 400 | ForEach-Object { @{ name = [string]$_.DeviceName; version = [string]$_.DriverVersion; provider = [string]$_.DriverProviderName; date = if ($_.DriverDate) { ([datetime]$_.DriverDate).ToString('yyyy-MM-dd') } else { '' } } })

  return @{
    hostname = $env:COMPUTERNAME
    ip = $ip
    domain = [string]$cs.Domain
    user = [string]$cs.UserName
    rebootPending = (Test-RebootPending)
    appManager = [bool](Find-Winget)
    os = @{ family = 'windows'; name = [string]$os.Caption; build = [int]$cv.CurrentBuildNumber; ubr = [int]$cv.UBR; displayVersion = [string]$cv.DisplayVersion; arch = [string]$arch; productType = [int]$os.ProductType }
    hardware = @{ manufacturer = [string]$cs.Manufacturer; model = [string]$cs.Model; serial = [string]$bios.SerialNumber; biosVendor = [string]$bios.Manufacturer; biosVersion = [string]$bios.SMBIOSBIOSVersion; biosDate = if ($bios.ReleaseDate) { ([datetime]$bios.ReleaseDate).ToString('yyyy-MM-dd') } else { '' }; cpu = [string]$cpu.Name; ramMb = [string][math]::Round($cs.TotalPhysicalMemory / 1MB) }
    kbs = $kbs
    apps = @($apps)
    drivers = $drivers
  }
}

# ---------- Actions ----------

function Invoke-Reboot([string]$mode, [System.Collections.ArrayList]$log) {
  if (-not (Test-RebootPending) -and -not $DryRun) { return $false }
  if ($mode -eq 'redemarrer') {
    if ($DryRun) { [void]$log.Add('[simulation] shutdown.exe /r /t 300'); return $true }
    & shutdown.exe /r /t 300 /c $RebootMessage | Out-Null
    [void]$log.Add('Redémarrage programmé dans 5 minutes')
    return $true
  }
  if ($mode -eq 'prevenir') {
    if (-not $DryRun) { & msg.exe * /TIME:3600 'VigilantIQ : des correctifs ont été installés. Redémarrez votre ordinateur dès que possible.' 2>$null | Out-Null }
    [void]$log.Add('Utilisateurs prévenus : redémarrage nécessaire')
  }
  return $false
}

$SecurityCategory = '0fa1201d-4330-4fa8-8ae9-b877473b6441'
$CriticalCategory = 'e6cf1350-c01b-414d-a61f-263d14d133b4'

function Install-WindowsUpdates([System.Collections.ArrayList]$log) {
  if ($DryRun) { [void]$log.Add('[simulation] Windows Update : recherche et installation des mises à jour de sécurité et critiques'); return @{ ok = $true; kbs = @('KB0000000'); reboot = $true } }
  $session = New-Object -ComObject Microsoft.Update.Session
  $session.ClientApplicationID = 'VigilantIQ'
  $result = $session.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
  $coll = New-Object -ComObject Microsoft.Update.UpdateColl
  foreach ($u in $result.Updates) {
    $cats = @($u.Categories | ForEach-Object { $_.CategoryID })
    if ($cats -contains $SecurityCategory -or $cats -contains $CriticalCategory) {
      if (-not $u.EulaAccepted) { $u.AcceptEula() }
      [void]$coll.Add($u)
    }
  }
  if ($coll.Count -eq 0) { [void]$log.Add('Windows Update : aucune mise à jour de sécurité en attente'); return @{ ok = $true; kbs = @(); reboot = $false } }
  $dl = $session.CreateUpdateDownloader(); $dl.Updates = $coll; [void]$dl.Download()
  $inst = $session.CreateUpdateInstaller(); $inst.Updates = $coll
  $r = $inst.Install()
  $kbs = @(); $ok = $true
  for ($i = 0; $i -lt $coll.Count; $i++) {
    $u = $coll.Item($i); $code = $r.GetUpdateResult($i).ResultCode
    $kb = @($u.KBArticleIDs | ForEach-Object { "KB$_" }) -join ','
    [void]$log.Add(("{0} [{1}] : {2}" -f $u.Title, $kb, @{ 2 = 'installée'; 3 = 'installée avec erreurs'; 4 = 'échec'; 5 = 'annulée' }[[int]$code]))
    if ($code -eq 2 -or $code -eq 3) { $kbs += @($u.KBArticleIDs | ForEach-Object { "KB$_" }) } else { $ok = $false }
  }
  return @{ ok = $ok; kbs = $kbs; reboot = [bool]$r.RebootRequired }
}

function Invoke-Winget([string[]]$wgArgs, [System.Collections.ArrayList]$log) {
  if ($DryRun) { [void]$log.Add("[simulation] winget $($wgArgs -join ' ')"); return 0 }
  $wg = Find-Winget
  if (-not $wg) { [void]$log.Add('winget introuvable sur cette machine'); return 1 }
  $out = & $wg @wgArgs --silent --accept-package-agreements --accept-source-agreements --disable-interactivity 2>&1 | Out-String
  [void]$log.Add($out.Substring([Math]::Max(0, $out.Length - 1500)))
  return $LASTEXITCODE
}

function Job-Install($p) {
  $log = New-Object System.Collections.ArrayList
  $data = @{ kbs = @(); apps = @() }
  $ok = $true
  foreach ($it in @($p.items)) {
    if ($it.kind -eq 'windows') {
      $w = Install-WindowsUpdates $log
      $data.kbs = $w.kbs; if (-not $w.ok) { $ok = $false }
    } elseif ($it.kind -eq 'winget') {
      if ($it.id -notmatch '^[A-Za-z0-9.+_-]+$') { [void]$log.Add("Identifiant winget refusé : $($it.id)"); $ok = $false; continue }
      $code = Invoke-Winget @('upgrade', '--id', $it.id, '--exact') $log
      # -1978335189 : aucune mise à jour applicable (déjà à jour)
      if ($code -eq 0 -or $code -eq -1978335189) { $data.apps += @{ id = $it.id; from = $it.from } } else { [void]$log.Add("$($it.name) : échec (code $code)"); $ok = $false }
    }
  }
  $data.rebootRequired = (Test-RebootPending)
  $data.rebooting = Invoke-Reboot $p.reboot $log
  $status = 'echec'; if ($ok) { $status = 'succes' }
  return @{ status = $status; log = ($log -join "`n"); data = $data }
}

function Job-Rollback($p) {
  $log = New-Object System.Collections.ArrayList
  $ok = $true
  foreach ($kb in @($p.kbs)) {
    if ($kb -notmatch '^KB(\d{6,8})$') { continue }
    if ($DryRun) { [void]$log.Add("[simulation] wusa.exe /uninstall /kb:$($Matches[1])"); continue }
    $proc = Start-Process -FilePath 'wusa.exe' -ArgumentList "/uninstall /kb:$($Matches[1]) /quiet /norestart" -Wait -PassThru
    # 3010 : redémarrage nécessaire ; 2359303 : mise à jour absente
    if (@(0, 3010, 2359303) -contains $proc.ExitCode) { [void]$log.Add("$kb désinstallée (code $($proc.ExitCode))") } else { [void]$log.Add("$kb : désinstallation impossible (code $($proc.ExitCode))"); $ok = $false }
  }
  foreach ($a in @($p.apps)) {
    if (-not $a.from -or $a.id -notmatch '^[A-Za-z0-9.+_-]+$' -or [string]$a.from -notmatch '^[A-Za-z0-9.+_-]+$') { continue }
    $code = Invoke-Winget @('install', '--id', $a.id, '--exact', '--version', [string]$a.from, '--force') $log
    if ($code -ne 0) { $ok = $false }
  }
  [void](Invoke-Reboot $p.reboot $log)
  $status = 'echec'; if ($ok) { $status = 'succes' }
  return @{ status = $status; log = ($log -join "`n"); data = @{ rebootRequired = (Test-RebootPending) } }
}

function Job-Reboot($p) {
  $log = New-Object System.Collections.ArrayList
  if (-not $p.force -and -not (Test-RebootPending)) { return @{ status = 'succes'; log = 'Aucun redémarrage nécessaire.'; data = @{ rebooting = $false } } }
  if ($DryRun) { return @{ status = 'succes'; log = '[simulation] shutdown.exe /r /t 300'; data = @{ rebooting = $true } } }
  & shutdown.exe /r /t 300 /c $RebootMessage | Out-Null
  return @{ status = 'succes'; log = 'Redémarrage programmé dans 5 minutes'; data = @{ rebooting = $true } }
}

function Invoke-Job($job, [string]$key) {
  $want = Get-Hmac $key ([Text.Encoding]::UTF8.GetBytes("$($job.id).$($job.action).$($job.payload)"))
  if ($want -ne [string]$job.sig) { return @{ id = $job.id; status = 'echec'; log = 'Signature de la tâche invalide : tâche refusée.' } }
  try {
    $p = $job.payload | ConvertFrom-Json
    switch ($job.action) {
      'scan' { $r = @{ status = 'succes'; log = 'Inventaire envoyé.'; data = @{ inventory = $true } } }
      'install' { $r = Job-Install $p }
      'rollback' { $r = Job-Rollback $p }
      'reboot' { $r = Job-Reboot $p }
      default { $r = @{ status = 'echec'; log = 'Action inconnue : refusée.' } }
    }
  } catch {
    $r = @{ status = 'echec'; log = "Erreur de l'agent : $($_.Exception.Message)" }
  }
  $r.id = $job.id
  if ($r.log -and $r.log.Length -gt 20000) { $r.log = $r.log.Substring($r.log.Length - 20000) }
  return $r
}

# ---------- Synchronisation ----------

function Register-Device($state) {
  if (-not $EnrollToken.StartsWith('vqe_')) { throw "Jeton d'enrôlement absent : téléchargez l'installeur depuis la console VigilantIQ." }
  $inv = Get-Inventory
  $r = Invoke-Vq '/api/v1/agent/enroll' @{ token = $EnrollToken; machineId = (Get-MachineId); hostname = $inv.hostname; os = $inv.os; agentVersion = $AgentVersion } $null $state
  if ($r.code -ne 200 -or -not $r.body.key) { throw "Enrôlement refusé : $($r.body.error)" }
  $state.deviceId = $r.body.deviceId
  $state.key = $r.body.key
  $state.server = Get-ServerUrl $state
  $state.lastInventory = 0
  Save-State $state
  Write-Log "Équipement enrôlé (n° $($state.deviceId))"
  return $state
}

function Sync-Vq($state, $results, [bool]$forceInventory) {
  $body = @{ agentVersion = $AgentVersion; rebootPending = (Test-RebootPending); results = @($results) }
  $hours = 4; if ($state.inventoryHours) { $hours = [double]$state.inventoryHours }
  $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  $last = 0; if ($state.lastInventory) { $last = [double]$state.lastInventory }
  if ($forceInventory -or $state.wantInventory -or ($now - $last) -gt ($hours * 3600)) { $body.inventory = Get-Inventory }
  $r = Invoke-Vq '/api/v1/agent/sync' $body $state.key $state
  if ($r.code -eq 401) { throw [UnauthorizedAccessException]::new([string]$r.body.error) }
  if ($r.code -ne 200) { throw "Synchronisation refusée : $($r.body.error)" }
  if ($body.inventory) { $state.lastInventory = $now }
  $state.wantInventory = [bool]$r.body.wantInventory
  if ($r.body.inventoryHours) { $state.inventoryHours = $r.body.inventoryHours }
  if ($r.body.pollSeconds) { $state.pollSeconds = $r.body.pollSeconds }
  Save-State $state
  return $r.body
}

function Update-Self($state, $upd) {
  $want = Get-Hmac $state.key ([Text.Encoding]::UTF8.GetBytes("script.$($upd.script)"))
  if (-not $upd.script -or $want -ne [string]$upd.sig) { Write-Log 'Mise à jour de l''agent refusée : signature invalide'; return $false }
  $target = $Installed; if (-not (Test-Path $target)) { $target = $PSCommandPath }
  [IO.File]::WriteAllText($target, [string]$upd.script, (New-Object Text.UTF8Encoding($true)))
  Write-Log "Agent mis à jour en version $($upd.version)"
  return $true
}

function Invoke-Cycle($state) {
  $r = Sync-Vq $state @() $false
  if ($r.update) { if (Update-Self $state $r.update) { return $true } }
  $jobs = @($r.jobs)
  while ($jobs.Count -gt 0) {
    $results = @(); $inv = $false
    foreach ($j in $jobs) {
      Write-Log "Tâche $($j.id) : $($j.action)"
      $results += (Invoke-Job $j $state.key)
      if (@('scan', 'install', 'rollback') -contains $j.action) { $inv = $true }
    }
    $r = Sync-Vq $state $results $inv
    $jobs = @($r.jobs)
  }
  return $false
}

function Install-Agent {
  if ($IsWin) {
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $admin) { throw 'Lancez l''installation dans une invite PowerShell en administrateur.' }
  }
  New-Item -ItemType Directory -Force -Path $BaseDir | Out-Null
  if ($IsWin) { & icacls.exe $BaseDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null }
  if ($PSCommandPath -ne $Installed) { Copy-Item -Force -Path $PSCommandPath -Destination $Installed }
  $state = Get-State
  if (-not $state.key) { $state = Register-Device $state }
  if ($IsWin) {
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    & schtasks.exe /Create /F /TN $TaskName /SC MINUTE /MO 15 /RU SYSTEM /RL HIGHEST /TR "`"$ps`" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Installed`"" | Out-Null
    & schtasks.exe /Run /TN $TaskName | Out-Null
  }
  Write-Host "Agent VigilantIQ installé : l'équipement apparaît dans la console (Parc & correctifs)."
}

function Uninstall-Agent {
  if ($IsWin) { & schtasks.exe /Delete /F /TN $TaskName 2>$null | Out-Null }
  foreach ($f in @($StateFile, $Installed)) { if (Test-Path $f) { Remove-Item -Force $f } }
  Write-Host 'Agent désinstallé. Supprimez l''équipement dans la console pour effacer ses données.'
}

# ---------- Point d'entrée ----------

if ($Install) { Install-Agent; exit 0 }
if ($Uninstall) { Uninstall-Agent; exit 0 }
if ($Status) { $s = Get-State; @{ version = $AgentVersion; enrolled = [bool]$s.key; deviceId = $s.deviceId; server = $s.server } | ConvertTo-Json; exit 0 }

$state = Get-State
if (-not $state.key) { $state = Register-Device $state }
if ($Once) { [void](Invoke-Cycle $state); exit 0 }

# Lancé par la tâche planifiée toutes les 15 minutes : synchronisation chaque minute pendant 14 minutes.
# Une seule instance à la fois (comportement par défaut du planificateur) ; une nouvelle version prend effet au cycle suivant.
$deadline = (Get-Date).AddMinutes(14)
$delay = 30
while ((Get-Date) -lt $deadline) {
  try {
    if (Invoke-Cycle $state) { break }
    $delay = 30
    $poll = 60; if ($state.pollSeconds) { $poll = [int]$state.pollSeconds }
    Start-Sleep -Seconds ([Math]::Max(15, $poll))
  } catch [UnauthorizedAccessException] {
    Write-Log "Clé refusée par le serveur ($($_.Exception.Message)) : équipement supprimé ou clé renouvelée. Réinstallez l'agent."
    break
  } catch {
    Write-Log "Synchronisation impossible : $($_.Exception.Message)"
    Start-Sleep -Seconds $delay
    $delay = [Math]::Min($delay * 2, 300)
  }
}
