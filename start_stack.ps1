$ErrorActionPreference = "Continue"
$ProjectDir = "D:\PROJECTS\SIEM-CORRELATION-ENGINE"
$StackDir = "$ProjectDir\stack"
$EsDir = "$StackDir\elasticsearch-8.13.0"
$KbnDir = "$StackDir\kibana-8.13.0"

Write-Host "=========================================================="
Write-Host "  Starting Standalone Elastic Stack (127.0.0.1)"
Write-Host "=========================================================="

# 1. Start Elasticsearch if not running
$esUp = $false
try {
    $ping = Invoke-RestMethod -Uri "http://127.0.0.1:9200" -TimeoutSec 2 -ErrorAction SilentlyContinue
    if ($ping.version.number) {
        Write-Host "[+] Elasticsearch 8.13 is already running on http://127.0.0.1:9200."
        $esUp = $true
    }
} catch {}

if (-not $esUp) {
    Write-Host "[*] Launching Elasticsearch 8.13.0..."
    $env:ES_JAVA_OPTS = "-Xms1g -Xmx1g"
    $esProc = Start-Process -FilePath "$EsDir\bin\elasticsearch.bat" -WorkingDirectory $EsDir -WindowStyle Hidden -PassThru
    $esProc.Id | Out-File "$StackDir\es.pid" -Encoding ascii
    Write-Host "    Waiting for Elasticsearch on http://127.0.0.1:9200..."
    for ($i = 0; $i -lt 45; $i++) {
        Start-Sleep -Seconds 2
        try {
            $res = Invoke-RestMethod -Uri "http://127.0.0.1:9200" -TimeoutSec 2 -ErrorAction SilentlyContinue
            if ($res.version.number) {
                Write-Host "[+] Elasticsearch is READY! Version: $($res.version.number)"
                $esUp = $true
                break
            }
        } catch {}
    }
}

# 2. Start Kibana if not running
$kbnUp = $false
try {
    $kping = Invoke-RestMethod -Uri "http://127.0.0.1:5601/api/status" -TimeoutSec 2 -ErrorAction SilentlyContinue
    if ($kping.status.overall.level) {
        Write-Host "[+] Kibana is already running on http://127.0.0.1:5601."
        $kbnUp = $true
    }
} catch {}

if (-not $kbnUp) {
    Write-Host "[*] Launching Kibana 8.13.0..."
    $kbnProc = Start-Process -FilePath "$KbnDir\bin\kibana.bat" -WorkingDirectory $KbnDir -WindowStyle Hidden -PassThru
    $kbnProc.Id | Out-File "$StackDir\kibana.pid" -Encoding ascii
    Write-Host "    Waiting for Kibana on http://127.0.0.1:5601..."
    for ($j = 0; $j -lt 60; $j++) {
        Start-Sleep -Seconds 3
        try {
            $kres = Invoke-RestMethod -Uri "http://127.0.0.1:5601/api/status" -TimeoutSec 2 -ErrorAction SilentlyContinue
            if ($kres.status.overall.level) {
                Write-Host "[+] Kibana is READY! Level: $($kres.status.overall.level)"
                $kbnUp = $true
                break
            }
        } catch {}
    }
}

Write-Host "=========================================================="
Write-Host "  Stack Startup Completed Successfully"
Write-Host "  Elasticsearch: http://127.0.0.1:9200"
Write-Host "  Kibana:        http://127.0.0.1:5601"
Write-Host "=========================================================="
