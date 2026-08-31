# ============================================================================
# SIEM-Lite Windows Native PowerShell Event Log Collector
# Run in an elevated PowerShell session to stream Windows Security Events
# ============================================================================

param(
    [string]$SiemUrl = "http://localhost:8000",
    [int]$IntervalSec = 3
)

$AgentId = "AGT-WIN-PS-$($env:COMPUTERNAME)"
$HostIp = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "127*" -and $_.IPAddress -notlike "169.254*" } | Select-Object -First 1).IPAddress

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "🛡️ SIEM-Lite Native Windows PowerShell Security Log Shipper" -ForegroundColor Green
Write-Host "Host: $env:COMPUTERNAME ($HostIp) | Target: $SiemUrl" -ForegroundColor Yellow
Write-Host "================================================================" -ForegroundColor Cyan

# Send Initial Heartbeat
$HeartbeatBody = @{
    agent_id = $AgentId
    name = "PowerShell Security Shipper ($env:COMPUTERNAME)"
    type = "Windows PowerShell Shipper"
    hostname = $env:COMPUTERNAME
    ip_address = $HostIp
    os = (Get-CimInstance Win32_OperatingSystem).Caption
    events_sent = 0
} | ConvertTo-Json

try {
    Invoke-RestMethod -Uri "$SiemUrl/api/agents/heartbeat" -Method Post -Body $HeartbeatBody -ContentType "application/json" -TimeoutSec 3 | Out-Null
    Write-Host "[+] Registered agent successfully with SIEM-Lite" -ForegroundColor Green
} catch {
    Write-Warning "Could not connect to SIEM server at $SiemUrl."
}

$LastCheckTime = (Get-Date).AddMinutes(-1)

while ($true) {
    try {
        $Now = Get-Date
        $Events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            StartTime = $LastCheckTime
            Id = @(4625, 4624, 4720, 1102, 7045)
        } -ErrorAction SilentlyContinue

        $LastCheckTime = $Now

        if ($Events) {
            foreach ($evt in $Events) {
                $Severity = "INFO"
                if ($evt.Id -eq 4625 -or $evt.Id -eq 4720) { $Severity = "WARN" }
                if ($evt.Id -eq 1102 -or $evt.Id -eq 7045) { $Severity = "HIGH" }

                $CleanMessage = ($evt.Message -split "`r`n")[0]
                if ($CleanMessage.Length -gt 150) { $CleanMessage = $CleanMessage.Substring(0, 150) }

                $LogPayload = @{
                    source = "windows-server"
                    ip = $HostIp
                    user = if ($evt.UserId) { $evt.UserId.Value } else { "SYSTEM" }
                    severity = $Severity
                    message = "Windows Event $($evt.Id): $CleanMessage"
                    timestamp = (Get-Date -Date $evt.TimeCreated -Format "yyyy-MM-ddTHH:mm:ssZ")
                } | ConvertTo-Json

                Invoke-RestMethod -Uri "$SiemUrl/api/logs" -Method Post -Body $LogPayload -ContentType "application/json" -TimeoutSec 3 | Out-Null
                Write-Host "[FORWARDED] Event ID $($evt.Id) -> $CleanMessage" -ForegroundColor Cyan
            }
        }
    } catch {
        # Silent continue on polling interval
    }
    Start-Sleep -Seconds $IntervalSec
}
