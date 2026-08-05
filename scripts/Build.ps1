[CmdletBinding()]
param([string] $Version = 'dev', [string] $Output = '.\bin')
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $Output | Out-Null
$ldflags = "-s -w -X main.version=$Version"
$env:CGO_ENABLED = '0'
$env:GOOS = 'windows'; $env:GOARCH = 'amd64'
go build -trimpath -ldflags $ldflags -o (Join-Path $Output 'gpo-agent-windows-amd64.exe') .\cmd\agent
go build -trimpath -ldflags $ldflags -o (Join-Path $Output 'gpoctl-windows-amd64.exe') .\cmd\gpoctl
$env:GOOS = 'linux'; $env:GOARCH = 'amd64'
go build -trimpath -ldflags $ldflags -o (Join-Path $Output 'gpo-server-linux-amd64') .\cmd\server
Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED
