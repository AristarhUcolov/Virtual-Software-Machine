# Build script for Virtual Software Machine.
# Скрипт сборки Virtual Software Machine.
#
#   .\build.ps1            - build both CLI and GUI / собрать CLI и GUI
#   .\build.ps1 -CliOnly   - build only the CLI (no C compiler needed)
param([switch]$CliOnly)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force bin | Out-Null

Write-Host "[1/2] Building CLI -> bin\vsm-cli.exe" -ForegroundColor Cyan
$env:CGO_ENABLED = "0"
go build -o bin\vsm-cli.exe .\cmd\vsm-cli
if ($?) { Write-Host "      OK" -ForegroundColor Green }

if (-not $CliOnly) {
    Write-Host "[2/2] Building GUI -> bin\vsm.exe (requires a C compiler / mingw-w64)" -ForegroundColor Cyan
    $env:CGO_ENABLED = "1"
    go build -ldflags "-H=windowsgui" -o bin\vsm.exe .\cmd\vsm
    if ($?) { Write-Host "      OK" -ForegroundColor Green }
}

Write-Host "Done. Binaries are in .\bin" -ForegroundColor Green
