#!/usr/bin/env pwsh
# AttackTree wrapper: locates a Python runtime with PyYAML and delegates to the engine.
# Usage: ./attacktree.ps1 <subcommand> [args...]   (see scripts/python/attacktree.py --help)
$ErrorActionPreference = "Stop"

$engine = Join-Path (Split-Path -Parent $PSScriptRoot) "python/attacktree.py"
if (-not (Test-Path $engine)) {
    Write-Error "attacktree: engine not found at $engine"
    exit 2
}

foreach ($py in @("python3", "python", "py")) {
    if (Get-Command $py -ErrorAction SilentlyContinue) {
        & $py -c "import yaml" 2>$null
        if ($LASTEXITCODE -eq 0) {
            & $py $engine @args
            exit $LASTEXITCODE
        }
    }
}

if (Get-Command uv -ErrorAction SilentlyContinue) {
    & uv run --quiet --with pyyaml --with jsonschema python $engine @args
    exit $LASTEXITCODE
}

Write-Error "attacktree: no Python runtime with PyYAML found. Install PyYAML (pip install pyyaml) or uv."
exit 2
