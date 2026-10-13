$ErrorActionPreference = "Continue"
$ProjectDir = "D:\PROJECTS\SIEM-CORRELATION-ENGINE"
$StackDir = "$ProjectDir\stack"

Write-Host "=========================================================="
Write-Host "  Stopping Standalone Elastic Stack"
Write-Host "=========================================================="

# Stop Kibana
if (Test-Path "$StackDir\kibana.pid") {
    $kpid = (Get-Content "$StackDir\kibana.pid" -ErrorAction SilentlyContinue).Trim()
    if ($kpid) {
        Stop-Process -Id $kpid -Force -ErrorAction SilentlyContinue
        Write-Host "[+] Stopped Kibana process PID $kpid."
    }
    Remove-Item "$StackDir\kibana.pid" -Force -ErrorAction SilentlyContinue
}
Get-Process -Name node -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "*kibana-8.13.0*" } | Stop-Process -Force -ErrorAction SilentlyContinue

# Stop Elasticsearch
if (Test-Path "$StackDir\es.pid") {
    $espid = (Get-Content "$StackDir\es.pid" -ErrorAction SilentlyContinue).Trim()
    if ($espid) {
        Stop-Process -Id $espid -Force -ErrorAction SilentlyContinue
        Write-Host "[+] Stopped Elasticsearch process PID $espid."
    }
    Remove-Item "$StackDir\es.pid" -Force -ErrorAction SilentlyContinue
}
Get-Process -Name java -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "*elasticsearch-8.13.0*" } | Stop-Process -Force -ErrorAction SilentlyContinue

Write-Host "[+] Elastic Stack stopped cleanly."
Write-Host "=========================================================="
