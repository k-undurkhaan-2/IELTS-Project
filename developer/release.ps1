<#
IELTS Practice App - Windows Release Script
Path: developer/release.ps1

Usage:
  powershell -ExecutionPolicy Bypass -File developer/release.ps1
  powershell -ExecutionPolicy Bypass -File developer/release.ps1 1.0.0

Output:
  dist/ielts-practice-{version}.zip

The archive contains runtime files only. Users can extract it and open
index.html directly with the file:// protocol; Node.js is not required after
release packaging.
#>

param(
    [Parameter(Position = 0)]
    [string]$Version
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = (Resolve-Path (Join-Path $ScriptDir '..')).Path
Set-Location $ProjectRoot

function Get-ReleaseVersion {
    param([string]$RequestedVersion)

    if (-not [string]::IsNullOrWhiteSpace($RequestedVersion)) {
        return $RequestedVersion
    }

    if (Get-Command git -ErrorAction SilentlyContinue) {
        & git rev-parse --git-dir *> $null
        if ($LASTEXITCODE -eq 0) {
            $described = & git describe --tags --always --dirty 2>$null
            if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($described)) {
                return $described.Trim()
            }
        }
    }

    return 'snapshot'
}

function Add-ZipDirectoryEntry {
    param(
        [System.IO.Compression.ZipArchive]$Archive,
        [string]$EntryName,
        [System.Collections.Generic.HashSet[string]]$SeenEntries
    )

    $directoryEntry = $EntryName.TrimEnd('/') + '/'
    if ($SeenEntries.Add($directoryEntry)) {
        [void]$Archive.CreateEntry($directoryEntry)
    }
}

function Add-ZipFileEntry {
    param(
        [System.IO.Compression.ZipArchive]$Archive,
        [string]$SourcePath,
        [string]$EntryName,
        [System.Collections.Generic.HashSet[string]]$SeenEntries
    )

    if ($SeenEntries.Add($EntryName)) {
        [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
            $Archive,
            $SourcePath,
            $EntryName,
            [System.IO.Compression.CompressionLevel]::Optimal
        )
    }
}

function Require-ZipEntry {
    param(
        [string[]]$Entries,
        [string]$EntryName
    )

    if ($EntryName -notin $Entries) {
        throw "release zip missing required entry: $EntryName"
    }
}

function Reject-ZipEntryPrefix {
    param(
        [string[]]$Entries,
        [string]$Prefix
    )

    $matches = $Entries | Where-Object { $_.StartsWith($Prefix, [System.StringComparison]::Ordinal) } | Select-Object -First 20
    if ($matches) {
        throw "release zip contains forbidden path prefix: $Prefix`n$($matches -join "`n")"
    }
}

function Reject-ZipEntryPattern {
    param(
        [string[]]$Entries,
        [string]$Pattern
    )

    $matches = $Entries | Where-Object { [regex]::IsMatch($_, $Pattern) } | Select-Object -First 20
    if ($matches) {
        throw "release zip contains forbidden entries matching: $Pattern`n$($matches -join "`n")"
    }
}

function Format-ReleaseSize {
    param([long]$Bytes)

    if ($Bytes -ge 1GB) { return ('{0:N1} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N1} MB' -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ('{0:N1} KB' -f ($Bytes / 1KB)) }
    return "$Bytes B"
}

function Get-ZipEntrySha256 {
    param([System.IO.Compression.ZipArchiveEntry]$Entry)

    $stream = $Entry.Open()
    try {
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        try {
            return ([System.BitConverter]::ToString($sha256.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
        } finally {
            $sha256.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

$Version = Get-ReleaseVersion $Version
$Version = [regex]::Replace($Version, '[^A-Za-z0-9._-]', '-')

$DistDir = Join-Path $ProjectRoot 'dist'
$ZipName = "ielts-practice-$Version.zip"
$ZipPath = Join-Path $DistDir $ZipName
$ReceiptName = "ielts-practice-$Version.release-receipt.json"
$ReceiptPath = Join-Path $DistDir $ReceiptName
$ManifestHelper = Join-Path $ProjectRoot 'developer/standalone-release-manifest.mjs'

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    throw 'node is required to build bundles and enforce the standalone release manifest.'
}

Write-Host '============================================'
Write-Host ' IELTS Practice App - Windows Release Builder'
Write-Host " Version : $Version"
Write-Host " Output  : dist/$ZipName"
Write-Host '============================================'

Write-Host ''
Write-Host '[1/2] Building bundles...'
$BuildScript = Join-Path $ProjectRoot 'scripts/build-bundles.mjs'
if (-not (Test-Path -LiteralPath $BuildScript)) {
    throw 'scripts/build-bundles.mjs not found.'
}

& node $BuildScript
if ($LASTEXITCODE -ne 0) {
    throw "bundle build failed with exit code $LASTEXITCODE"
}
Write-Host '       Bundles generated: js/bundles/'

Write-Host ''
Write-Host '[2/2] Creating distribution zip...'

if (Test-Path -LiteralPath $DistDir) {
    Remove-Item -LiteralPath $DistDir -Recurse -Force
}
[void](New-Item -ItemType Directory -Path $DistDir)

$StagingDir = $null
try {
$stageOutput = @(& node $ManifestHelper stage --project-root $ProjectRoot --receipt $ReceiptPath 2>&1)
if ($LASTEXITCODE -ne 0) {
    throw "standalone release manifest staging failed:`n$($stageOutput -join "`n")"
}
$StagingDir = ($stageOutput -join "`n").Trim()
if ([string]::IsNullOrWhiteSpace($StagingDir) -or -not (Test-Path -LiteralPath $StagingDir -PathType Container)) {
    throw "standalone release manifest helper returned an invalid staging directory: $StagingDir"
}

$Receipt = Get-Content -Raw -LiteralPath $ReceiptPath | ConvertFrom-Json
$archive = $null
try {
    $archive = [System.IO.Compression.ZipFile]::Open($ZipPath, [System.IO.Compression.ZipArchiveMode]::Create)
    $seenEntries = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($directory in @($Receipt.archiveDirectories)) {
        Add-ZipDirectoryEntry $archive $directory $seenEntries
    }
    foreach ($file in @($Receipt.files)) {
        $nativeRelativePath = $file.archivePath -replace '/', [System.IO.Path]::DirectorySeparatorChar
        $sourcePath = Join-Path $StagingDir $nativeRelativePath
        Add-ZipFileEntry $archive $sourcePath $file.archivePath $seenEntries
    }
} finally {
    if ($null -ne $archive) {
        $archive.Dispose()
    }
    $temporaryStageRoot = Split-Path -Parent $StagingDir
    if (Test-Path -LiteralPath $temporaryStageRoot) {
        Remove-Item -LiteralPath $temporaryStageRoot -Recurse -Force
    }
}

$verifyArchive = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
try {
    $zipEntries = @($verifyArchive.Entries | ForEach-Object { $_.FullName })
    $zipFileHashes = @{}
    foreach ($entry in @($verifyArchive.Entries | Where-Object { -not $_.FullName.EndsWith('/') })) {
        $zipFileHashes[$entry.FullName] = Get-ZipEntrySha256 $entry
    }
} finally {
    $verifyArchive.Dispose()
}

$zipListPath = Join-Path ([System.IO.Path]::GetTempPath()) ("ielts-release-zip-list-{0}.txt" -f ([guid]::NewGuid().ToString('N')))
try {
    [System.IO.File]::WriteAllText(
        $zipListPath,
        (($zipEntries -join "`n") + "`n"),
        [System.Text.UTF8Encoding]::new($false)
    )
    $verifyOutput = @(& node $ManifestHelper verify-archive-list --receipt $ReceiptPath --archive-list $zipListPath 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "release archive manifest verification failed:`n$($verifyOutput -join "`n")"
    }
} finally {
    if (Test-Path -LiteralPath $zipListPath) {
        Remove-Item -LiteralPath $zipListPath -Force
    }
}

foreach ($file in @($Receipt.files)) {
    if (-not $zipFileHashes.ContainsKey($file.archivePath)) {
        throw "release zip missing receipt file: $($file.archivePath)"
    }
    if ($zipFileHashes[$file.archivePath] -ne $file.sha256) {
        throw "release zip content hash differs from staged source: $($file.archivePath)"
    }
}

$duplicateEntries = @($zipEntries | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })
if ($duplicateEntries) {
    throw "release zip contains duplicate entries:`n$($duplicateEntries -join "`n")"
}

$unsafeEntries = @($zipEntries | Where-Object {
    $_.Contains('\') -or
    $_.StartsWith('/', [System.StringComparison]::Ordinal) -or
    [regex]::IsMatch($_, '^[A-Za-z]:') -or
    [regex]::IsMatch($_, '(^|/)\.\.(/|$)')
})
if ($unsafeEntries) {
    throw "release zip contains unsafe entry paths:`n$($unsafeEntries -join "`n")"
}

foreach ($requiredFile in @($Receipt.requiredFiles)) {
    Require-ZipEntry $zipEntries $requiredFile
}

Reject-ZipEntryPrefix $zipEntries 'templates/'
Reject-ZipEntryPrefix $zipEntries 'ListeningPractice/'
Reject-ZipEntryPrefix $zipEntries 'assets/generated/listening-exams/'
Reject-ZipEntryPrefix $zipEntries '.git/'
Reject-ZipEntryPrefix $zipEntries 'node_modules/'
Reject-ZipEntryPrefix $zipEntries 'developer/tests/'
Reject-ZipEntryPrefix $zipEntries 'backend/'
Reject-ZipEntryPattern $zipEntries '(^|/)\.env($|\.)'
Reject-ZipEntryPattern $zipEntries '(^|/)[^/]*\.(key|pem|p12|pfx|kdbx|log|tmp|temp|bak)$'
Reject-ZipEntryPattern $zipEntries '(^|/)\.ssh(/|$)'
Reject-ZipEntryPattern $zipEntries '(^|/)~\$[^/]*$'
Reject-ZipEntryPattern $zipEntries '^ListeningPractice/.*\.(MOV|mov|MP4|mp4)$'
Reject-ZipEntryPattern $zipEntries '^assets/scripts/.*\.py$'
Reject-ZipEntryPattern $zipEntries '^js/(app|core|data|runtime|services|utils|components|presentation|views)/'

$zipSize = Format-ReleaseSize (Get-Item -LiteralPath $ZipPath).Length

Write-Host ''
Write-Host '============================================'
Write-Host " Done: dist/$ZipName"
Write-Host " Size : $zipSize"
Write-Host " Receipt: dist/$ReceiptName"
Write-Host ''
Write-Host ' Extract the archive and open index.html directly.'
Write-Host ' No Node.js or build tools are required after packaging.'
Write-Host '============================================'
} catch {
    if (-not [string]::IsNullOrWhiteSpace($StagingDir)) {
        $temporaryStageRoot = Split-Path -Parent $StagingDir
        if (Test-Path -LiteralPath $temporaryStageRoot) {
            Remove-Item -LiteralPath $temporaryStageRoot -Recurse -Force
        }
    }
    if (Test-Path -LiteralPath $ZipPath) {
        Remove-Item -LiteralPath $ZipPath -Force
    }
    throw
}
