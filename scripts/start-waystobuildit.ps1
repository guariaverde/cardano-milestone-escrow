$ErrorActionPreference = "Stop"
$Cloudflared = "C:\Program Files (x86)\cloudflared\cloudflared.exe"
$CertPath = "d:\Development\milestone-escrow\cloudflare\cert.pem"
$ConfigPath = "d:\Development\milestone-escrow\cloudflare\config.yml"

Write-Host "=== Starting Milestone Escrow Platform for https://waystobuildit.com ===" -ForegroundColor Cyan

$BackendProc = Start-Process -FilePath "go" -ArgumentList "-C","backend","run","./cmd/server" -PassThru
Write-Host "Go server running locally on http://127.0.0.1:8080 (PID: $($BackendProc.Id))" -ForegroundColor Green

try {
    & $Cloudflared --origincert $CertPath --config $ConfigPath tunnel run waystobuildit
} finally {
    if ($BackendProc -and !$BackendProc.HasExited) {
        Stop-Process -Id $BackendProc.Id -Force
    }
}
