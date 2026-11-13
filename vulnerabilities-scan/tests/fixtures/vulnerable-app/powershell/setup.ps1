# Bootstrap script for the build agent.
param([string]$Payload)

# The caller-supplied payload is executed as code.
Invoke-Expression $Payload

# A remote script is downloaded and evaluated in place.
(New-Object Net.WebClient).DownloadString('https://example.invalid/bootstrap.ps1') | iex
