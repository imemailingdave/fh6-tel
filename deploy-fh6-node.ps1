<#
.SYNOPSIS
    Turnkey Windows 10 Pro Provisioning & Orchestration Script for Forza Horizon 6 Telemetry.
.DESCRIPTION
    1. Self-elevates to Administrator via UAC while preserving working directory and parameters.
    2. Enforces idempotent Windows Defender Firewall rules (UDP 20439, UDP 20440, TCP 8080).
    3. Queries the GitHub Releases API (TLS 1.2) to download and unblock fh6-tel-serve-windows-x86_64.exe.
    4. Self-scaffolds scripts/udp_fanout_logger.py and updates .gitignore if missing.
    5. Launches fh6-tel-serve and the Python UDP Fan-Out Relay with atomic Ctrl+C teardown.
.EXAMPLE
    .\deploy-fh6-node.ps1 -AndroidIp "192.168.1.85" -AndroidPort 5606
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, HelpMessage = "LAN IPv4 address of your Android device running SIM Dashboard")]
    [string]$AndroidIp = "192.168.1.85",

    [Parameter(Mandatory = $false, HelpMessage = "UDP listen port configured in SIM Dashboard")]
    [int]$AndroidPort = 5606,

    [Parameter(Mandatory = $false, HelpMessage = "Ingress UDP port on this PC targeted by Xbox Series X Data Out")]
    [int]$RelayPort = 20439,

    [Parameter(Mandatory = $false, HelpMessage = "Localhost UDP port owned by fh6-tel-serve")]
    [int]$ServerUdpPort = 20440,

    [Parameter(Mandatory = $false, HelpMessage = "HTTP port for the fh6-tel-serve web dashboard")]
    [int]$WebPort = 8080,

    [Parameter(Mandatory = $false, HelpMessage = "Authentication token for the fh6-tel-serve web dashboard")]
    [string]$AuthToken = "fh6-local-telemetry",

    [Parameter(Mandatory = $false, HelpMessage = "Disable continuous CSV logging of Free Roam & clutch metrics")]
    [switch]$DisableCsv,

    [Parameter(Mandatory = $false, HelpMessage = "Force re-download of fh6-tel-serve binary from GitHub Releases")]
    [switch]$ForceUpdate,

    [Parameter(Mandatory = $false, HelpMessage = "Provision firewall, binaries, and scripts without starting servers")]
    [switch]$SetupOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ==============================================================================
# 1. SELF-ELEVATION TO ADMINISTRATOR (UAC HANDSHAKE)
# ==============================================================================
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[UAC] Elevating privileges to configure Windows Defender Firewall..." -ForegroundColor Yellow
    $argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"")
    foreach ($key in $PSBoundParameters.Keys) {
        $val = $PSBoundParameters[$key]
        if ($val -is [switch]) {
            if ($val.IsPresent) { $argList += "-$key" }
        } else {
            $argList += "-$key"
            $argList += "`"$val`""
        }
    }
    Start-Process -FilePath "powershell.exe" -ArgumentList $argList -Verb RunAs -WorkingDirectory $PSScriptRoot
    exit
}

Set-Location -Path $PSScriptRoot
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "   FH6 TELEMETRY NODE PROVISIONER & UDP FAN-OUT ORCHESTRATOR (WIN10 PRO)  " -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan

# ==============================================================================
# 2. DETECT LOCAL LAN IPv4 ADDRESS & VERIFY NETWORK PROFILE
# ==============================================================================
$lanIp = (
    Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object {
        $_.IPAddress -notlike "127.*" -and
        $_.IPAddress -notlike "169.254.*" -and
        $_.PrefixOrigin -ne "WellKnown" -and
        $_.InterfaceAlias -notmatch "vEthernet|WSL|Loopback|VMware|VirtualBox"
    } |
    Select-Object -First 1
).IPAddress

if (-not $lanIp) {
    $lanIp = "127.0.0.1"
    Write-Warning "Could not auto-detect a physical RFC 1918 LAN IPv4 address. Defaulting display to 127.0.0.1."
}

$netProfiles = Get-NetConnectionProfile
foreach ($prof in $netProfiles) {
    if ($prof.NetworkCategory -eq "Public") {
        Write-Warning "Interface '$($prof.InterfaceAlias)' is set to 'Public'. Switching to 'Private' so LAN UDP telemetry is permitted..."
        Set-NetConnectionProfile -InterfaceIndex $prof.InterfaceIndex -NetworkCategory Private
    }
}

# ==============================================================================
# 3. IDEMPOTENT WINDOWS DEFENDER FIREWALL CONFIGURATION
# ==============================================================================
function Set-IdempotentFirewallRule {
    param(
        [string]$DisplayName,
        [string]$Protocol,
        [uint16]$LocalPort,
        [string]$Description
    )
    $existing = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
    if ($null -eq $existing) {
        New-NetFirewallRule -DisplayName $DisplayName `
            -Description $Description `
            -Direction Inbound `
            -Action Allow `
            -Protocol $Protocol `
            -LocalPort $LocalPort `
            -Profile Private,Domain | Out-Null
        Write-Host "[FIREWALL] Created Inbound $Protocol Rule '$DisplayName' (Port $LocalPort)" -ForegroundColor Green
    } else {
        Set-NetFirewallRule -DisplayName $DisplayName -Enabled True -Action Allow -Profile Private,Domain | Out-Null
        Write-Host "[FIREWALL] Verified Inbound $Protocol Rule '$DisplayName' (Port $LocalPort)" -ForegroundColor DarkGray
    }
}

Set-IdempotentFirewallRule -DisplayName "FH6 Telemetry - UDP Fan-Out Relay Ingress" `
    -Protocol "UDP" -LocalPort $RelayPort `
    -Description "Allows 60Hz Forza Horizon 6 UDP telemetry from Xbox Series X to the Python Fan-Out Relay."

Set-IdempotentFirewallRule -DisplayName "FH6 Telemetry - fh6-tel-serve UDP Socket" `
    -Protocol "UDP" -LocalPort $ServerUdpPort `
    -Description "Allows UDP telemetry packets into the fh6-tel-serve SQLite recording daemon."

Set-IdempotentFirewallRule -DisplayName "FH6 Telemetry - Web Dashboard HTTP" `
    -Protocol "TCP" -LocalPort $WebPort `
    -Description "Allows LAN browsers and mobile devices to view the fh6-tel-serve web dashboard."

# ==============================================================================
# 4. DIRECTORY STRUCTURE & .GITIGNORE HARDENING
# ==============================================================================
$binDir     = Join-Path $PSScriptRoot "bin"
$scriptsDir = Join-Path $PSScriptRoot "scripts"
$logsDir    = Join-Path $PSScriptRoot "logs"

foreach ($dir in @($binDir, $scriptsDir, $logsDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
    }
}

$gitignorePath = Join-Path $PSScriptRoot ".gitignore"
$ignoreEntries = @("bin/", "logs/", "*.csv", "*.bin", "*.db", "*.db-wal", "*.db-shm", "local_config.json")
if (Test-Path $gitignorePath) {
    $currentIgnore = Get-Content $gitignorePath -Raw
    $addedEntries = @()
    foreach ($entry in $ignoreEntries) {
        if ($currentIgnore -notmatch [regex]::Escape($entry)) {
            Add-Content -Path $gitignorePath -Value $entry
            $addedEntries += $entry
        }
    }
    if ($addedEntries.Count -gt 0) {
        Write-Host "[GIT] Appended telemetry exclusions to .gitignore: $($addedEntries -join ', ')" -ForegroundColor Green
    }
}

# ==============================================================================
# 5. DOWNLOAD & UNBLOCK fh6-tel-serve BINARY (TLS 1.2 + STREAM OPTIMIZATION)
# ==============================================================================
$serverExeName = "fh6-tel-serve-windows-x86_64.exe"
$serverExePath = Join-Path $binDir $serverExeName

if ((-not (Test-Path $serverExePath)) -or $ForceUpdate.IsPresent) {
    Write-Host "[GITHUB] Querying TheBanHammer/fh6-tel Releases API for latest $serverExeName..." -ForegroundColor Cyan
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $oldProgress = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
        $releaseApi = "https://api.github.com/repos/TheBanHammer/fh6-tel/releases/latest"
        $headers = @{ "User-Agent" = "FH6-Telemetry-Win10-Deployer" }
        $release = Invoke-RestMethod -Uri $releaseApi -Headers $headers -Method Get

        $asset = $release.assets | Where-Object { $_.name -eq $serverExeName } | Select-Object -First 1
        if ($null -eq $asset) {
            throw "Asset '$serverExeName' was not found in release $($release.tag_name)."
        }

        Write-Host "[DOWNLOAD] Fetching $($asset.name) ($($release.tag_name))..." -ForegroundColor Cyan
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $serverExePath -Headers $headers
        Unblock-File -Path $serverExePath -ErrorAction SilentlyContinue
        Write-Host "[DOWNLOAD] Installed and unblocked $serverExePath" -ForegroundColor Green
    } finally {
        $ProgressPreference = $oldProgress
    }
} else {
    Unblock-File -Path $serverExePath -ErrorAction SilentlyContinue
    Write-Host "[BINARY] Verified existing server binary: $serverExePath" -ForegroundColor DarkGray
}

# ==============================================================================
# 6. ENSURE scripts/udp_fanout_logger.py EXISTS (SELF-SCAFFOLDING)
# ==============================================================================
$relayScriptPath = Join-Path $scriptsDir "udp_fanout_logger.py"
if (-not (Test-Path $relayScriptPath)) {
    Write-Host "[SCAFFOLD] Writing scripts/udp_fanout_logger.py..." -ForegroundColor Cyan
    $pythonCode = @'
#!/usr/bin/env python3
"""
FH6 Telemetry UDP Fan-Out Relay & Mechanical Logger
Receives 60Hz UDP datagrams from Xbox Series X and multiplexes them to:
  1. Local fh6-tel / fh6-tel-serve instance (127.0.0.1:20440)
  2. Android Mobile HUD running SIM Dashboard (<ANDROID_IP>:5606)
  3. Optional local CSV logger (captures Free Roam + Manual-with-Clutch telemetry)
"""
import argparse
import csv
import os
import socket
import struct
import time
from datetime import datetime

def parse_key_metrics(packet: bytes):
    """Unpacks essential Sled + Car Dash metrics accounting for the 12-byte Horizon gap."""
    if len(packet) < 323:
        return None
    is_race_on, ts_ms, max_rpm, idle_rpm, cur_rpm = struct.unpack_from("<iIfff", packet, 0)
    car_ordinal, car_class, car_pi, drivetrain = struct.unpack_from("<iiii", packet, 212)
    pos_x, pos_y, pos_z, speed_ms, power_w, torque_nm = struct.unpack_from("<ffffff", packet, 244)
    accel, brake, clutch, handbrake, gear, steer = struct.unpack_from("<BBBBBb", packet, 315)
    return (
        ts_ms, is_race_on, car_ordinal, car_pi,
        round(cur_rpm, 1), round(max_rpm, 1), round(speed_ms * 2.23694, 2),
        round(power_w / 745.7, 2), round(torque_nm, 2),
        accel, brake, clutch, gear, steer
    )

def run_relay(listen_ip: str, listen_port: int, targets: list, log_csv: bool):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((listen_ip, listen_port))
    print(f"[FH6-RELAY] Bound to UDP {listen_ip}:{listen_port}")
    print(f"[FH6-RELAY] Multiplexing targets: {targets}")

    csv_file = None
    csv_writer = None
    if log_csv:
        os.makedirs("logs", exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_path = os.path.join("logs", f"fh6_session_{stamp}.csv")
        csv_file = open(csv_path, mode="w", newline="", encoding="utf-8")
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow([
            "TimestampMS", "IsRaceOn", "CarOrdinal", "CarPI",
            "CurrentRPM", "MaxRPM", "SpeedMPH", "PowerHP", "TorqueNm",
            "Throttle_255", "Brake_255", "Clutch_255", "Gear", "Steer_127"
        ])
        print(f"[FH6-RELAY] Recording continuous CSV telemetry -> {csv_path}")

    packet_count = 0
    last_report = time.time()

    try:
        while True:
            data, addr = sock.recvfrom(512)
            for target_ip, target_port in targets:
                sock.sendto(data, (target_ip, target_port))

            if csv_writer and len(data) >= 323:
                metrics = parse_key_metrics(data)
                if metrics and metrics[4] > 0.0:
                    csv_writer.writerow(metrics)

            packet_count += 1
            now = time.time()
            if now - last_report >= 5.0:
                hz = packet_count / (now - last_report)
                print(f"[FH6-RELAY] Xbox Ingress ({addr[0]}) | Rate: {hz:.1f} Hz | Payload: {len(data)} B")
                packet_count = 0
                last_report = now
                if csv_file:
                    csv_file.flush()
    except KeyboardInterrupt:
        print("\n[FH6-RELAY] Stopping UDP relay cleanly.")
    finally:
        if csv_file:
            csv_file.close()
        sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FH6 UDP Telemetry Fan-Out Relay")
    parser.add_argument("--listen-ip", default="0.0.0.0")
    parser.add_argument("--listen-port", type=int, default=20439)
    parser.add_argument("--targets", nargs="+", default=["127.0.0.1:20440"])
    parser.add_argument("--csv", action="store_true")
    args = parser.parse_args()

    parsed_targets = []
    for t in args.targets:
        host, port_str = t.split(":")
        parsed_targets.append((host, int(port_str)))

    run_relay(args.listen_ip, args.listen_port, parsed_targets, args.csv)
'@
    Set-Content -Path $relayScriptPath -Value $pythonCode -Encoding UTF8
    Write-Host "[SCAFFOLD] Created $relayScriptPath" -ForegroundColor Green
}

# Verify Python 3 availability on PATH
$pythonCmd = Get-Command "python" -ErrorAction SilentlyContinue
if ($null -eq $pythonCmd) {
    throw "Python 3 was not found on your Windows PATH. Install Python 3 or add it to PATH before running."
}

if ($SetupOnly.IsPresent) {
    Write-Host "`n[COMPLETE] Provisioning finished (-SetupOnly specified). Ready to launch." -ForegroundColor Green
    exit 0
}

# ==============================================================================
# 7. ATOMIC PROCESS ORCHESTRATION (fh6-tel-serve + PYTHON UDP RELAY)
# ==============================================================================
# Ensure no stale fh6-tel or fh6-tel-serve instance is locking UDP 20440 or SQLite DB
$staleProcs = Get-Process -Name "fh6-tel-serve-windows-x86_64", "fh6-tel" -ErrorAction SilentlyContinue
if ($staleProcs) {
    Write-Warning "Stopping existing fh6-tel process(es) to release UDP port $ServerUdpPort and SQLite lock..."
    $staleProcs | Stop-Process -Force
    Start-Sleep -Milliseconds 500
}

$sqliteDbPath = Join-Path $env:LOCALAPPDATA "fh6-tel\sessions.db"

Write-Host ""
Write-Host "--------------------------------------------------------------------------" -ForegroundColor Yellow
Write-Host "                    TACTICAL TELEMETRY DISPATCH MANIFEST                  " -ForegroundColor Yellow
Write-Host "--------------------------------------------------------------------------" -ForegroundColor Yellow
Write-Host " 1. XBOX SERIES X (FH6 Settings -> HUD and Gameplay -> Data Out):"
Write-Host "    - Data Out            : ON"
Write-Host "    - Data Out IP Address : $lanIp" -ForegroundColor Green
Write-Host "    - Data Out IP Port    : $RelayPort" -ForegroundColor Green
Write-Host ""
Write-Host " 2. ANDROID MOBILE HUD (SIM Dashboard / Browser):"
Write-Host "    - SIM Dashboard Target: ${AndroidIp}:${AndroidPort} (Ensure VPN Split-Tunnel/LAN Bypass is ON)" -ForegroundColor Cyan
Write-Host "    - Web HUD URL         : http://${lanIp}:${WebPort} (Auth Token: $AuthToken)" -ForegroundColor Cyan
Write-Host ""
Write-Host " 3. PC ARCHIVAL STORAGE:"
Write-Host "    - SQLite Lap Database : $sqliteDbPath"
Write-Host "    - Continuous CSV Logs : $logsDir"
Write-Host "--------------------------------------------------------------------------" -ForegroundColor Yellow
Write-Host "Press Ctrl+C at any time to shut down both the relay and server cleanly.`n" -ForegroundColor Gray

$serverArgs = @(
    "--ip", "0.0.0.0",
    "--port", "$WebPort",
    "--udp-port", "$ServerUdpPort",
    "--auth-token", "$AuthToken"
)

$serverProcess = $null
try {
    Write-Host "[LAUNCH] Starting fh6-tel-serve headless daemon on UDP :$ServerUdpPort / HTTP :$WebPort..." -ForegroundColor Cyan
    $serverProcess = Start-Process -FilePath $serverExePath `
        -ArgumentList $serverArgs `
        -WorkingDirectory $PSScriptRoot `
        -NoNewWindow `
        -PassThru

    Start-Sleep -Milliseconds 600

    $relayTargets = @("127.0.0.1:$ServerUdpPort")
    if (-not [string]::IsNullOrWhiteSpace($AndroidIp)) {
        $relayTargets += "${AndroidIp}:${AndroidPort}"
    }

    $pyArgs = @(
        "`"$relayScriptPath`"",
        "--listen-ip", "0.0.0.0",
        "--listen-port", "$RelayPort",
        "--targets"
    ) + $relayTargets

    if (-not $DisableCsv.IsPresent) {
        $pyArgs += "--csv"
    }

    Write-Host "[LAUNCH] Starting Python UDP Fan-Out Relay on UDP :$RelayPort..." -ForegroundColor Cyan
    & python $pyArgs
} finally {
    Write-Host "`n[TEARDOWN] Releasing sockets and flushing SQLite write-ahead logs..." -ForegroundColor Yellow
    if ($null -ne $serverProcess -and -not $serverProcess.HasExited) {
        Stop-Process -Id $serverProcess.Id -Force -ErrorAction SilentlyContinue
        Write-Host "[TEARDOWN] Stopped fh6-tel-serve (PID $($serverProcess.Id))." -ForegroundColor Green
    }
    Write-Host "[TEARDOWN] Telemetry node shut down cleanly." -ForegroundColor Green
}