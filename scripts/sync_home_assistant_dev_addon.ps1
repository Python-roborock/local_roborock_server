param(
    [string]$HomeAssistantHost = "192.168.20.199",
    [string]$AddonSlug = "roborock_local_server_dev"
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$tempExportRoot = Join-Path $repoRoot "dist\ha_sync_export"
$exportedAddonDir = Join-Path $tempExportRoot $AddonSlug
$haLocalAddonsRoot = "\\$HomeAssistantHost\addons\local"
$haAddonDir = Join-Path $haLocalAddonsRoot $AddonSlug

if (-not (Test-Path $haLocalAddonsRoot)) {
    throw "Home Assistant local add-on path is not reachable: $haLocalAddonsRoot"
}

uv run python "$PSScriptRoot\export_home_assistant_dev_addon.py" --output-dir $tempExportRoot

if (-not (Test-Path $exportedAddonDir)) {
    throw "Export completed but addon directory was not found: $exportedAddonDir"
}

New-Item -ItemType Directory -Path $haAddonDir -Force | Out-Null

robocopy $exportedAddonDir $haAddonDir /MIR /NFL /NDL /NJH /NJS /NP | Out-Null
$robocopyExitCode = $LASTEXITCODE
if ($robocopyExitCode -ge 8) {
    throw "robocopy failed with exit code $robocopyExitCode"
}

Write-Output "Synced $exportedAddonDir -> $haAddonDir"
