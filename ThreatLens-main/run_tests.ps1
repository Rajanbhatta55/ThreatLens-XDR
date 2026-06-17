param(
    [switch]$Quiet,
    [string[]]$PytestArgs = @()
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$venvPython = Join-Path $repoRoot '.venv\Scripts\python.exe'

if (Test-Path $venvPython) {
    $python = $venvPython
} else {
    $python = 'python'
}

$pytestCommand = @('-m', 'pytest')

if ($Quiet) {
    $pytestCommand += '-q'
}

if ($PytestArgs.Count -gt 0) {
    $pytestCommand += $PytestArgs
}

Write-Host "Running tests with: $python $($pytestCommand -join ' ')"
& $python @pytestCommand
exit $LASTEXITCODE