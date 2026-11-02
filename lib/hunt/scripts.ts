/**
 * Agent collecteur léger : scripts PowerShell (Windows) et shell (Linux, macOS) générés pour un équipement.
 * Ils lisent les connexions établies, le cache DNS (Windows) et les empreintes SHA-256 des exécutables en cours,
 * puis les envoient à VigilantIQ (requête signée HMAC-SHA256). Lecture seule : aucune modification du système.
 */

const psq = (s: string) => s.replace(/'/g, "''");
const shq = (s: string) => s.replace(/'/g, "'\\''");

export function powershellAgent(url: string, key: string): string {
  return `# VigilantIQ — agent collecteur (lecture seule). À exécuter en tant qu'administrateur ou SYSTEM.
# Collecte : connexions TCP établies, cache DNS, empreintes SHA-256 des exécutables en cours.
$ErrorActionPreference = 'SilentlyContinue'
$Key = '${psq(key)}'
$Url = '${psq(url)}'
$Dir = Join-Path $env:ProgramData 'VigilantIQ'
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
$CacheFile = Join-Path $Dir 'hashes.json'
$Cache = @{}
if (Test-Path $CacheFile) { (Get-Content $CacheFile -Raw | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $Cache[$_.Name] = $_.Value } }

$sb = New-Object System.Text.StringBuilder
$os = (Get-CimInstance Win32_OperatingSystem).Caption
$ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notmatch '^(127\\.|169\\.254\\.)' } | Select-Object -First 1).IPAddress
[void]$sb.AppendLine("host\`t$env:COMPUTERNAME\`t$os\`t$ip")

$procs = @{}
Get-Process | ForEach-Object { $procs[$_.Id] = $_ }
Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notmatch '^(127\\.|::1$|0\\.0\\.0\\.0)' } |
  Sort-Object RemoteAddress, RemotePort -Unique | Select-Object -First 3000 | ForEach-Object {
    $name = $procs[[int]$_.OwningProcess].ProcessName
    [void]$sb.AppendLine("conn\`t$($_.RemoteAddress)\`t$($_.RemotePort)\`t$name")
  }

Get-DnsClientCache | Select-Object -ExpandProperty Entry -Unique | Select-Object -First 3000 | ForEach-Object {
  [void]$sb.AppendLine("dns\`t$_")
}

$procs.Values | Where-Object { $_.Path } | Sort-Object Path -Unique | Select-Object -First 400 | ForEach-Object {
  $f = Get-Item -LiteralPath $_.Path
  $id = "$($f.FullName)|$($f.LastWriteTimeUtc.Ticks)|$($f.Length)"
  $h = $Cache[$id]
  if (-not $h) { $h = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash; if ($h) { $Cache[$id] = $h } }
  if ($h) { [void]$sb.AppendLine("proc\`t$($_.ProcessName)\`t$($f.FullName)\`t$h") }
}
$Cache | ConvertTo-Json -Compress | Set-Content -Path $CacheFile -Encoding UTF8

$body = [Text.Encoding]::UTF8.GetBytes($sb.ToString())
$ts = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString()
$hmac = New-Object System.Security.Cryptography.HMACSHA256
$hmac.Key = [Text.Encoding]::UTF8.GetBytes($Key)
$toSign = [Text.Encoding]::UTF8.GetBytes("$ts.") + $body
$sig = 'sha256=' + (-join ($hmac.ComputeHash($toSign) | ForEach-Object { $_.ToString('x2') }))
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-RestMethod -Uri $Url -Method Post -Body $body -ContentType 'text/plain; charset=utf-8' -Headers @{ Authorization = "Bearer $Key"; 'X-VQ-Timestamp' = $ts; 'X-VQ-Signature' = $sig } | Out-Null
`;
}

export function shellAgent(url: string, key: string): string {
  return `#!/bin/sh
# VigilantIQ — agent collecteur (lecture seule) pour Linux et macOS. À exécuter en root.
# Collecte : connexions TCP établies et empreintes SHA-256 des exécutables en cours. Nécessite curl et openssl.
KEY='${shq(key)}'
URL='${shq(url)}'
TMP=$(mktemp) || exit 1
trap 'rm -f "$TMP"' EXIT
OS=$(uname -sr)
{
  printf 'host\\t%s\\t%s\\n' "$(hostname)" "$OS"
  if command -v ss >/dev/null 2>&1; then
    # Colonnes : Recv-Q Send-Q Locale Distante Processus
    ss -tnpH state established 2>/dev/null | awk '{
      peer=$4; n=split(peer, p, ":"); port=p[n]; ip=substr(peer, 1, length(peer)-length(port)-1); gsub(/[\\[\\]]/, "", ip)
      proc=""; if (match($0, /users:\\(\\("[^"]+"/)) proc=substr($0, RSTART+9, RLENGTH-10)
      printf "conn\\t%s\\t%s\\t%s\\n", ip, port, proc }' | sort -u | head -n 3000
  elif command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP -sTCP:ESTABLISHED 2>/dev/null | awk 'NR>1 { split($9, a, "->"); peer=a[2]; n=split(peer, p, ":"); port=p[n]; ip=substr(peer, 1, length(peer)-length(port)-1); gsub(/[\\[\\]]/, "", ip); printf "conn\\t%s\\t%s\\t%s\\n", ip, port, $1 }' | sort -u | head -n 3000
  fi
  if [ -d /proc/1 ]; then
    for e in /proc/[0-9]*/exe; do readlink "$e" 2>/dev/null; done | grep '^/' | sort -u | head -n 400 | while read -r f; do
      h=$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1); [ -n "$h" ] && printf 'proc\\t%s\\t%s\\t%s\\n' "$(basename "$f")" "$f" "$h"
    done
  else
    ps -axo comm= | grep '^/' | sort -u | head -n 400 | while read -r f; do
      h=$(shasum -a 256 "$f" 2>/dev/null | cut -d' ' -f1); [ -n "$h" ] && printf 'proc\\t%s\\t%s\\t%s\\n' "$(basename "$f")" "$f" "$h"
    done
  fi
} > "$TMP"
TS=$(date +%s)
SIG="sha256=$( (printf '%s.' "$TS"; cat "$TMP") | openssl dgst -sha256 -hmac "$KEY" | sed 's/^.* //')"
curl -fsS -m 60 -X POST "$URL" -H "Authorization: Bearer $KEY" -H "X-VQ-Timestamp: $TS" -H "X-VQ-Signature: $SIG" -H "Content-Type: text/plain; charset=utf-8" --data-binary @"$TMP" >/dev/null
`;
}

/** Instructions d'installation (planification toutes les 15 minutes). */
export const INSTALL = {
  windows: [
    "Copiez le script dans C:\\ProgramData\\VigilantIQ\\agent.ps1",
    'Dans une invite administrateur : schtasks /Create /SC MINUTE /MO 15 /TN "VigilantIQ" /RU SYSTEM /TR "powershell -NoProfile -ExecutionPolicy Bypass -File C:\\ProgramData\\VigilantIQ\\agent.ps1"',
    'Premier envoi immédiat : schtasks /Run /TN "VigilantIQ"',
  ],
  unix: [
    "sudo install -m 700 vigilantiq-agent.sh /opt/vigilantiq/agent.sh (créez le dossier /opt/vigilantiq au besoin)",
    "sudo crontab -e, puis ajoutez : */15 * * * * /opt/vigilantiq/agent.sh",
    "Premier envoi immédiat : sudo /opt/vigilantiq/agent.sh",
  ],
};
