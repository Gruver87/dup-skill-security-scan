#Requires -Version 5.1
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

function Assert-NativeExit {
  param([Parameter(Mandatory)][string]$Label)
  if ($null -eq $LASTEXITCODE) { return }
  if ($LASTEXITCODE -ne 0) { throw "$Label failed with exit $LASTEXITCODE" }
}

python -m pip install -e ".[dev]" -q
Assert-NativeExit "pip"
python -m ruff check src tests
Assert-NativeExit "ruff"
python -m pytest -q
Assert-NativeExit "pytest"
Write-Host "test_all PASS"
exit 0
