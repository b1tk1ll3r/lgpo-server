#requires -Modules GroupPolicy
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $GpoName,
    [Parameter(Mandatory)] [string] $PolicyName,
    [Parameter(Mandatory)] [string] $ServerUrl,
    [Parameter(Mandatory)] [string] $AdminToken,
    [Parameter(Mandatory)] [string] $GpoCtl,
    [string] $Note = '',
    [string] $Domain,
    [string] $DomainController,
    [switch] $InsecureSkipVerify,
    [switch] $ForceVersion
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $GpoCtl -PathType Leaf)) { throw "gpoctl not found: $GpoCtl" }
$work = Join-Path ([IO.Path]::GetTempPath()) ("gpo-publish-" + [guid]::NewGuid().ToString('N'))
$backup = Join-Path $work 'backup'
$zip = Join-Path $work 'gpo-backup.zip'
New-Item -ItemType Directory -Force -Path $backup | Out-Null
try {
    $params = @{ Name = $GpoName; Path = $backup }
    if ($Note) { $params.Comment = $Note }
    if ($Domain) { $params.Domain = $Domain }
    if ($DomainController) { $params.Server = $DomainController }
    Backup-GPO @params | Out-Null

    # CreateFromDirectory includes hidden files such as bkupInfo.xml. The ZIP root
    # contains manifest.xml plus the GUID-named GPO backup directory expected by LGPO.exe.
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::CreateFromDirectory(
        $backup,
        $zip,
        [IO.Compression.CompressionLevel]::Optimal,
        $false
    )

    $args = @('upload', '-server', $ServerUrl, '-token', $AdminToken, '-policy', $PolicyName, '-file', $zip)
    if ($Note) { $args += @('-note', $Note) }
    if ($InsecureSkipVerify) { $args += '-insecure-skip-verify' }
    if ($ForceVersion) { $args += '-force' }
    & $GpoCtl @args
    if ($LASTEXITCODE -ne 0) { throw "gpoctl exited with code $LASTEXITCODE" }
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
