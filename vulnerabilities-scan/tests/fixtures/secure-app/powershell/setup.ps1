# Bootstrap script, secure mirror image of the vulnerable one.
param([Parameter(Mandatory = $true)][ValidateSet('nightly', 'release')][string]$Channel)

$root = Join-Path $env:LOCALAPPDATA 'agent-bootstrap'
New-Item -ItemType Directory -Force -Path $root | Out-Null

# The script is fetched to a file, checked against a published hash, and run by
# path with an allow-listed channel argument. It is never evaluated as text.
$target = Join-Path $root 'bootstrap.ps1'
Invoke-WebRequest -Uri "https://example.invalid/bootstrap-$Channel.ps1" -OutFile $target -UseBasicParsing
$expected = (Invoke-WebRequest -Uri "https://example.invalid/bootstrap-$Channel.sha256" -UseBasicParsing).Content.Trim()
$actual = (Get-FileHash -Algorithm SHA256 -Path $target).Hash.ToLower()
if ($actual -ne $expected) { throw 'bootstrap hash mismatch' }
& $target -Channel $Channel
