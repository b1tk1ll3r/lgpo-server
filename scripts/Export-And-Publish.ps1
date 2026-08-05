#requires -Modules GroupPolicy
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $GpoName,
    [string] $PolicyName = '',
    [Parameter(Mandatory)] [string] $ServerUrl,
    [Parameter(Mandatory)] [string] $AdminToken,
    [Parameter(Mandatory)] [string] $GpoCtl,
    [string] $Note = '',
    [string] $Domain,
    [string] $DomainController,
    [switch] $InsecureSkipVerify,
    [switch] $ForceVersion,
    [switch] $StrictPolicyName
)

$ErrorActionPreference = 'Stop'
$policyNamePattern = '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'

function ConvertTo-RepositoryPolicyName {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Value)

    $valueToConvert = $Value.Trim()
    if ([string]::IsNullOrWhiteSpace($valueToConvert)) {
        throw 'PolicyName must not be empty.'
    }

    # Remove diacritics where possible and replace every sequence of characters
    # that is unsafe for a repository identifier with a single hyphen.
    $decomposed = $valueToConvert.Normalize([Text.NormalizationForm]::FormD)
    $builder = [Text.StringBuilder]::new()
    $separatorPending = $false

    foreach ($character in $decomposed.ToCharArray()) {
        $category = [Globalization.CharUnicodeInfo]::GetUnicodeCategory($character)
        if ($category -eq [Globalization.UnicodeCategory]::NonSpacingMark) {
            continue
        }

        $text = [string] $character
        if ($text -match '^[A-Za-z0-9._-]$') {
            [void] $builder.Append($character)
            $separatorPending = $false
        }
        elseif (-not $separatorPending -and $builder.Length -gt 0) {
            [void] $builder.Append('-')
            $separatorPending = $true
        }
    }

    $converted = $builder.ToString()
    $converted = $converted -replace '-{2,}', '-'
    $converted = $converted.Trim([char[]]'.-_')

    if ([string]::IsNullOrWhiteSpace($converted)) {
        throw "PolicyName '$Value' cannot be converted to a valid repository name."
    }
    if ($converted[0] -notmatch '[A-Za-z0-9]') {
        $converted = 'gpo-' + $converted
    }
    if ($converted.Length -gt 64) {
        $converted = $converted.Substring(0, 64).TrimEnd([char[]]'.-_')
    }
    if ($converted -notmatch $policyNamePattern) {
        throw "PolicyName '$Value' cannot be converted to a name matching $policyNamePattern."
    }
    return $converted
}

if (-not (Test-Path -LiteralPath $GpoCtl -PathType Leaf)) {
    throw "gpoctl not found: $GpoCtl"
}

$requestedPolicyName = if ([string]::IsNullOrWhiteSpace($PolicyName)) { $GpoName } else { $PolicyName.Trim() }
if ($requestedPolicyName -match $policyNamePattern) {
    $resolvedPolicyName = $requestedPolicyName
}
elseif ($StrictPolicyName) {
    throw "PolicyName '$requestedPolicyName' is invalid. It must match $policyNamePattern (maximum 64 characters; no spaces or umlauts)."
}
else {
    $resolvedPolicyName = ConvertTo-RepositoryPolicyName -Value $requestedPolicyName
    Write-Warning "PolicyName '$requestedPolicyName' was normalized to '$resolvedPolicyName'."
}

Write-Host "Publishing AD GPO '$GpoName' as repository policy '$resolvedPolicyName'."

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

    $arguments = @(
        'upload',
        '-server', $ServerUrl,
        '-token', $AdminToken,
        '-policy', $resolvedPolicyName,
        '-file', $zip
    )
    if ($Note) { $arguments += @('-note', $Note) }
    if ($InsecureSkipVerify) { $arguments += '-insecure-skip-verify' }
    if ($ForceVersion) { $arguments += '-force' }

    & $GpoCtl @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "gpoctl exited with code $LASTEXITCODE"
    }
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
