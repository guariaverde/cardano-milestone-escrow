$ErrorActionPreference = "Stop"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " 1. CREDENTIAL & SECRET LEAK SCANNER (Pre-Commit / Pre-Push)" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# 1A. Verify sensitive directories are never tracked or staged in Git
$BlockedPathPatterns = @(
    "^cloudflare/",
    "^data/",
    "^private_docs/",
    "^\.agents/",
    "AGENTS\.md$",
    "LESSON_.*\.md$",
    "GRANT_STRATEGY\.md$",
    "STAKEHOLDER_AND_GRANT_PITCH\.md$",
    "\.pem$",
    "\.skey$",
    "\.vkey$",
    "-creds\.json$",
    "^\.env$"
)

$TrackedAndStaged = git status --porcelain | ForEach-Object { $_.Substring(3).Trim() }
foreach ($file in $TrackedAndStaged) {
    foreach ($pat in $BlockedPathPatterns) {
        if ($file -match $pat) {
            Write-Host "❌ BLOCKED: Sensitive file '$file' matched restricted pattern '$pat'!" -ForegroundColor Red
            exit 1
        }
    }
}

# 1B. Scan source files for leaked private keys, Cloudflare tunnel secrets, or API tokens
$SecretRegexes = @(
    "-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "TunnelSecret",
    "Argo TunnelToken",
    "ed25519_sk1",
    "xprv1"
)

$SourceFiles = Get-ChildItem -Path "backend","frontend","contracts","config","docs","scripts" -Recurse -File -ErrorAction SilentlyContinue
foreach ($f in $SourceFiles) {
    if ($f.FullName -match "security-and-code-review\.ps1$") { continue }
    $content = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
    if (!$content) { continue }
    foreach ($regex in $SecretRegexes) {
        if ($content -match $regex) {
            Write-Host "❌ SECRET DETECTED in $($f.FullName) (matched '$regex')!" -ForegroundColor Red
            exit 1
        }
    }
}
Write-Host "✅ Zero credentials, certificates, or private keys exposed in repository files." -ForegroundColor Green

Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host " 2. AUTOMATED CODE REVIEW & INVARIANT AUDIT" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# 2A. Ensure zero floating-point currency math in Go backend
$GoFiles = Get-ChildItem -Path "backend" -Filter "*.go" -Recurse
foreach ($gf in $GoFiles) {
    $goContent = Get-Content $gf.FullName -Raw
    if ($goContent -match "\bfloat32\b|\bfloat64\b") {
        Write-Host "❌ CODE REVIEW FAILED: Floating-point type (float32/float64) found in $($gf.FullName)! Use integer units only." -ForegroundColor Red
        exit 1
    }
}
Write-Host "✅ Invariant Check: Zero floating-point currency math in Go backend." -ForegroundColor Green

# 2B. Run Go Static Analyzer (go vet)
Write-Host "Running 'go vet ./...' static code analysis..." -ForegroundColor Yellow
go -C backend vet ./...
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ CODE REVIEW FAILED: 'go vet' reported issues!" -ForegroundColor Red
    exit 1
}
Write-Host "✅ Static Analysis ('go vet ./...'): Clean." -ForegroundColor Green

# 2C. Run Full Automated Security & Unit Test Suite
Write-Host "Running full Go unit & security test suite..." -ForegroundColor Yellow
go -C backend test ./...
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ CODE REVIEW FAILED: Automated tests failed!" -ForegroundColor Red
    exit 1
}
Write-Host "✅ All automated unit & security tests passed!" -ForegroundColor Green
Write-Host "`n🎉 Pre-push credential check & code review PASSED." -ForegroundColor Green
