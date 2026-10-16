<#
  Builds offpatch-agent.msi with the WiX Toolset (v4/v5). Run on Windows:

    dotnet tool install --global wix
    wix extension add -g WixToolset.Util.wixext
    .\build-msi.ps1 -Version 0.1.0 -ConfigDir C:\offpatch-build\config

  ConfigDir: bundle.pub (required), ca.pem (optional), root.pub (optional).
  The agent binary is taken from ..\..\bin\windows\pmagent.exe (make windows),
  stamped with -Version via -ldflags if you build it here with -BuildAgent.
  Sign the resulting MSI with your code-signing certificate (signtool) before
  distribution; endpoints and GPO should only accept signed installers.
#>
param(
  [Parameter(Mandatory = $true)][string]$Version,
  [Parameter(Mandatory = $true)][string]$ConfigDir,
  [switch]$BuildAgent,
  [string]$Out = "offpatch-agent-$Version.msi"
)
$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\..\.."
$src = Join-Path $root "bin\windows"

if ($BuildAgent) {
  Push-Location $root
  $env:GOOS = "windows"; $env:GOARCH = "amd64"
  go build -ldflags "-X offpatch/internal/agent.Version=$Version" -o "$src\pmagent.exe" ./cmd/pmagent
  Pop-Location
}
if (-not (Test-Path "$src\pmagent.exe")) { throw "missing $src\pmagent.exe (run make windows or -BuildAgent)" }
if (-not (Test-Path "$ConfigDir\bundle.pub")) { throw "missing $ConfigDir\bundle.pub" }

$hasCA = [int](Test-Path "$ConfigDir\ca.pem")
$hasRoot = [int](Test-Path "$ConfigDir\root.pub")
$caArg = if ($hasCA) { '-ca &quot;[INSTALLFOLDER]ca.pem&quot;' } else { '' }
$rootArg = if ($hasRoot) { '-root-pubkey &quot;[INSTALLFOLDER]root.pub&quot;' } else { '' }

wix build "$PSScriptRoot\offpatch-agent.wxs" -ext WixToolset.Util.wixext -arch x64 `
  -d "Version=$Version" -d "SourceDir=$src" -d "ConfigDir=$ConfigDir" `
  -d "HasCA=$hasCA" -d "HasRoot=$hasRoot" -d "CAArg=$caArg" -d "RootArg=$rootArg" `
  -o $Out
Write-Host "built $Out"
Get-FileHash $Out -Algorithm SHA256
