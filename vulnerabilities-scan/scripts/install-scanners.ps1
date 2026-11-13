<#
.SYNOPSIS
    Bootstrap the scanner installer on Windows.

.DESCRIPTION
    Finds a Python 3 and hands every argument to scripts\install_scanners.py,
    which owns the tool matrix (winget, choco, scoop, go, gem, npm, pipx), the
    plan and the verification. This wrapper exists only because a Windows user
    may not have a `python3` on PATH under that name.

    It installs nothing itself, never elevates, and never pipes a download into
    a shell. Steps that need administrator rights are printed by the engine for
    you to run in an elevated shell.

    Winget is the usual path on Windows 10/11; chocolatey and scoop are used when
    winget is absent. A Microsoft Store Python works but is sandboxed, so the
    engine's  -m pip  steps may fail there; install python.org's build if so.

.PARAMETER Engine
    Override the path to install_scanners.py (default: next to this script).

.EXAMPLE
    .\scripts\install-scanners.ps1
    Print the install plan without touching the machine.

.EXAMPLE
    .\scripts\install-scanners.ps1 --list
    Print the tool-by-OS install matrix as JSON.

.EXAMPLE
    .\scripts\install-scanners.ps1 --check
    Probe what is installed and exit 1 if any tool is missing.

.EXAMPLE
    .\scripts\install-scanners.ps1 --yes
    Install everything the audit can drive, using winget/choco/scoop/go/gem/npm.

.NOTES
    Exit codes: 0 plan printed or everything installed; 1 a tool is still
    missing; 2 Python 3 is missing, or the engine refused the request.

    If Windows blocks the script, run it as:
      powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install-scanners.ps1
#>

# PositionalBinding=$false matters: without it PowerShell would bind a bare
# "--check" to the first declared parameter instead of forwarding it to the
# engine, so every documented invocation would silently do the wrong thing.
[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$Engine = "",
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Rest
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Engine)) {
    $here = Split-Path -Parent $MyInvocation.MyCommand.Path
    $Engine = Join-Path $here "install_scanners.py"
}

if (-not (Test-Path -LiteralPath $Engine)) {
    Write-Error "install_scanners.py not found next to this wrapper ($Engine)"
    exit 2
}

function Find-Python {
    # The py launcher is the canonical Windows entry point and pins a major
    # version; python.exe may be a Store shim that opens the Store instead.
    foreach ($candidate in @("py -3", "python", "python3")) {
        $parts = $candidate.Split(" ")
        $exe = $parts[0]
        $command = Get-Command $exe -ErrorAction SilentlyContinue
        if ($null -eq $command) { continue }
        $probeArgs = @()
        if ($parts.Length -gt 1) { $probeArgs = $parts[1..($parts.Length - 1)] }
        $probeArgs += @("-c", "import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)")
        & $exe @probeArgs *> $null
        if ($LASTEXITCODE -eq 0) { return $candidate }
    }
    return $null
}

$python = Find-Python
if ($null -eq $python) {
    Write-Host "error: no Python 3.8+ found." -ForegroundColor Red
    Write-Host "  Install it with one of:"
    Write-Host "    winget install --id Python.Python.3.12 -e --source winget"
    Write-Host "    choco install python -y"
    Write-Host "    scoop install python"
    Write-Host "  or download from https://www.python.org/downloads/windows/"
    exit 2
}

$parts = $python.Split(" ")
$exe = $parts[0]
$prefix = @()
if ($parts.Length -gt 1) { $prefix = $parts[1..($parts.Length - 1)] }

$arguments = @($prefix) + @($Engine)
if ($null -ne $Rest) { $arguments += $Rest }

& $exe @arguments
exit $LASTEXITCODE
