# Build the release Windows PE with version metadata before SignPath signing.
# Shared by CI smoke and the release workflow so the same executable shape is tested.
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+$')]
  [string]$Version,
  [string]$Output = 'dist/osidiag.exe'
)

$ErrorActionPreference = 'Stop'
$parts = $Version.Split('.')
$numericVersion = @{
  Major = [int]$parts[0]
  Minor = [int]$parts[1]
  Patch = [int]$parts[2]
  Build = 0
}
$info = @{
  FixedFileInfo = @{ FileVersion = $numericVersion; ProductVersion = $numericVersion }
  StringFileInfo = @{
    CompanyName = 'Ivan Versluis'
    FileDescription = 'OSI network diagnostics for Linux and Windows'
    FileVersion = $Version
    ProductVersion = $Version
    ProductName = 'osidiag'
    InternalName = 'osidiag'
    OriginalFilename = 'osidiag.exe'
    LegalCopyright = 'Copyright 2026 Ivan Versluis'
  }
}
$info | ConvertTo-Json -Depth 10 | Set-Content 'cmd/osidiag/versioninfo.json' -Encoding utf8

# A pin prevents release metadata changes caused by mutable tool versions.
go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@v1.7.0
if ($LASTEXITCODE -ne 0) { throw 'Unable to install pinned goversioninfo' }
$generator = Join-Path (go env GOPATH) 'bin/goversioninfo.exe'
if (-not (Test-Path $generator)) { throw 'goversioninfo executable missing' }

Push-Location 'cmd/osidiag'
try {
  & $generator -64 -o resource.syso
  if ($LASTEXITCODE -ne 0) { throw 'Windows resource generation failed' }
} finally { Pop-Location }

$destination = [System.IO.Path]::GetFullPath($Output)
New-Item -ItemType Directory -Force -Path (Split-Path $destination) | Out-Null
$env:CGO_ENABLED = '0'
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
go build -trimpath -ldflags "-s -w -X main.version=$Version" -o $destination ./cmd/osidiag
if ($LASTEXITCODE -ne 0) { throw 'Windows build failed' }

$resource = (Get-Item $destination).VersionInfo
if ($resource.ProductName -ne 'osidiag' -or
    $resource.ProductVersion -notlike "$Version*" -or
    $resource.FileVersion -notlike "$Version*") {
  throw "Windows version metadata mismatch: $($resource.ProductName), $($resource.ProductVersion), $($resource.FileVersion)"
}
$signature = Get-AuthenticodeSignature -FilePath $destination
if ($signature.Status -ne 'NotSigned') {
  throw "Original build should not be signed before SignPath: $($signature.Status)"
}
Write-Host "Built unsigned osidiag Windows AMD64 $Version with verified version metadata"
