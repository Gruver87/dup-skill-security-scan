#Requires -Version 5.1
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Pack = Join-Path (Split-Path -Parent $Root) "dup-agent-skills"
$Report = Join-Path $Root "reports\dup-agent-skills"

if (-not (Test-Path (Join-Path $Pack "skills"))) {
  Write-Error "dup-agent-skills not found at $Pack"
  exit 2
}

Set-Location $Root
python -m pip install -e . -q
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

python -m skill_security scan $Pack --source "Gruver87/dup-agent-skills" --report-dir $Report
$scanExit = $LASTEXITCODE
python -m skill_security check-install $Pack --source "Gruver87/dup-agent-skills"
$instExit = $LASTEXITCODE
Write-Host "scan_exit=$scanExit check_install_exit=$instExit"
exit $instExit
