# ──────────────────────────────────────────────────────────────────
# Phish Net — Install Script (Windows PowerShell)
#
# Usage:
#   irm https://raw.githubusercontent.com/rakshand2005/Phish-Tank/main/install.ps1 | iex
# ──────────────────────────────────────────────────────────────────

$Repo = "rakshand2005/phish-tank"   # ← Using your GitHub username/repo
$Image = "ghcr.io/${Repo}:latest"

Write-Host ""
Write-Host "🛡️  Phish Net — Installer" -ForegroundColor Cyan
Write-Host "───────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ""

# Check if Docker is installed
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Docker is not installed." -ForegroundColor Red
    Write-Host "   Install Docker Desktop from: https://docs.docker.com/get-docker/"
    exit 1
}

Write-Host "📦 Pulling scanner image from GitHub Container Registry..." -ForegroundColor Yellow
docker pull $Image

Write-Host ""
Write-Host "🔧 Creating 'phishnet' command..." -ForegroundColor Yellow

# Create PowerShell function
$FunctionDef = @"

# Phish Net
function phishnet {
    docker run --rm -v //var/run/docker.sock:/var/run/docker.sock `$Image `@args
}
"@

# Add to PowerShell profile
if (-not (Test-Path $PROFILE)) {
    New-Item -Path $PROFILE -ItemType File -Force | Out-Null
}

# Remove old function if it exists
$ProfileContent = Get-Content $PROFILE -Raw -ErrorAction SilentlyContinue
if ($ProfileContent) {
    $ProfileContent = $ProfileContent -replace '(?ms)# Phish Net\r?\nfunction phishnet \{[^}]+\}\r?\n', ''
    Set-Content $PROFILE -Value $ProfileContent
}

# Add new function
Add-Content $PROFILE -Value $FunctionDef

Write-Host "   Added to $PROFILE" -ForegroundColor Green
Write-Host ""
Write-Host "✅ Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "   Usage:" -ForegroundColor White
Write-Host "     phishnet scan nginx:1.14"
Write-Host "     phishnet scan nginx:1.14 --output json"
Write-Host "     phishnet scan nginx:1.14 --fail-on CRITICAL"
Write-Host "     phishnet integrity nginx:1.14"
Write-Host "     phishnet fix nginx:1.14"
Write-Host ""
Write-Host "   ⚠️  Restart your terminal or run: . `$PROFILE" -ForegroundColor Yellow
Write-Host ""
