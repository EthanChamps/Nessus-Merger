<#
.SYNOPSIS
High-performance merger for .nessus XML files, optimized for scans with 1000+ hosts.

.DESCRIPTION
Merges multiple .nessus files into a single file that can be imported back into Nessus.
Uses the proven XmlDocument DOM approach (ImportNode + AppendChild) with XmlDocument.Load()
for faster file loading. Based on the techniques from Dark Operator and 0xPrime.

Optimizations over basic implementations:
- Uses XmlDocument.Load() instead of Get-Content + [xml] cast (avoids double memory)
- Progress reporting for large merges
- Optional host deduplication by IP/hostname
- Excludes the output file from input if it exists in the same directory

.PARAMETER Path
Directory containing .nessus files. Defaults to the current directory.

.PARAMETER OutputFile
Name of the merged output file. Defaults to "merged_nessus_report.nessus".

.PARAMETER Name
Name for the merged report. Defaults to "Merged Report". Alias: -reportname

.PARAMETER Deduplicate
When specified, skips duplicate hosts (matched by hostname). Keeps the first occurrence.

.EXAMPLE
.\Merge-NessusFiles.ps1

.EXAMPLE
.\Merge-NessusFiles.ps1 -Path "C:\Scans" -OutputFile "combined.nessus" -Name "Q1 Scan"

.EXAMPLE
.\Merge-NessusFiles.ps1 -Deduplicate
#>

[CmdletBinding()]
Param(
    [Alias("filepath")]
    [string]$Path = (Resolve-Path .\).Path,

    [Alias("outputfilename")]
    [string]$OutputFile = "merged_nessus_report.nessus",

    [Alias("reportname")]
    [string]$Name = "Merged Report",

    [switch]$Deduplicate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Resolve output path early so we can exclude it ─────────────────────
$outPath = Join-Path $Path $OutputFile

# ── Collect .nessus files (exclude the output file if it already exists) ─
$nessusFiles = Get-ChildItem -Path $Path -Filter *.nessus |
    Where-Object { $_.FullName -ne (Resolve-Path $outPath -ErrorAction SilentlyContinue) } |
    Sort-Object Name

if ($nessusFiles.Count -eq 0) {
    Write-Host "No .nessus files found in $Path" -ForegroundColor Red
    exit 1
}

Write-Host "Found $($nessusFiles.Count) .nessus file(s) in $Path" -ForegroundColor Cyan

$totalHosts = 0
$skippedHosts = 0
$seenHosts = @{}
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# ── Phase 1: Load the first file as the base merged document ───────────
$primaryFile = $nessusFiles[0]
Write-Host "Primary file: $($primaryFile.Name)" -ForegroundColor Green

# Use XmlDocument.Load() — faster than Get-Content + [xml] cast
$mergedDoc = New-Object System.Xml.XmlDocument
$mergedDoc.Load($primaryFile.FullName)

$mergedReport = $mergedDoc.SelectSingleNode("//Report")

if (-not $mergedReport) {
    Write-Host "ERROR: Primary file does not contain a valid Nessus report structure." -ForegroundColor Red
    exit 1
}

# Count hosts already in the primary file
$primaryHosts = $mergedReport.SelectNodes("ReportHost")
$primaryCount = $primaryHosts.Count
$totalHosts += $primaryCount

# Track primary hosts for deduplication
if ($Deduplicate.IsPresent) {
    foreach ($host in $primaryHosts) {
        $hostName = $host.GetAttribute("name")
        if ($hostName) {
            $seenHosts[$hostName] = $true
        }
    }
}

Write-Host "[1/$($nessusFiles.Count)] Loaded primary: $primaryCount hosts" -ForegroundColor Green

# ── Phase 2: Merge ReportHost nodes from remaining files ───────────────
for ($i = 1; $i -lt $nessusFiles.Count; $i++) {
    $file = $nessusFiles[$i]
    Write-Host "[$($i + 1)/$($nessusFiles.Count)] Processing: $($file.Name)" -ForegroundColor Green

    # Load the file using XmlDocument.Load()
    $reportDoc = New-Object System.Xml.XmlDocument
    $reportDoc.Load($file.FullName)

    # Select all ReportHost nodes
    $reportHosts = $reportDoc.SelectNodes("//ReportHost")

    $addedCount = 0
    $skippedCount = 0

    foreach ($reportHost in $reportHosts) {
        $hostName = $reportHost.GetAttribute("name")

        # Check for duplicates if deduplication is enabled
        if ($Deduplicate.IsPresent -and $hostName -and $seenHosts.ContainsKey($hostName)) {
            $skippedCount++
            continue
        }

        if ($hostName) {
            $seenHosts[$hostName] = $true
        }

        # Import the node into the merged document and append it
        $importedNode = $mergedDoc.ImportNode($reportHost, $true)
        $mergedReport.AppendChild($importedNode) | Out-Null

        $addedCount++

        # Progress every 100 hosts
        if ($addedCount % 100 -eq 0) {
            Write-Host "  ... $addedCount hosts processed" -ForegroundColor DarkGray
        }
    }

    $totalHosts += $addedCount
    $skippedHosts += $skippedCount

    $statusMsg = "  + $addedCount hosts added"
    if ($skippedCount -gt 0) {
        $statusMsg += ", $skippedCount duplicates skipped"
    }
    Write-Host $statusMsg -ForegroundColor Green

    # Release memory from the loaded file
    $reportDoc = $null
}

# ── Phase 3: Set report name and save ──────────────────────────────────
$mergedReport.SetAttribute("name", $Name)

Write-Host "Saving merged report to $outPath ..." -ForegroundColor Cyan
$mergedDoc.Save($outPath)

# Free memory
$mergedDoc = $null

$stopwatch.Stop()

# ── Summary ────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Merge complete" -ForegroundColor Cyan
Write-Host "  Files merged : $($nessusFiles.Count)" -ForegroundColor Cyan
Write-Host "  Total hosts  : $totalHosts" -ForegroundColor Cyan
if ($Deduplicate.IsPresent) {
    Write-Host "  Duplicates   : $skippedHosts skipped" -ForegroundColor Yellow
}
Write-Host "  Output       : $outPath" -ForegroundColor Cyan
Write-Host "  Elapsed      : $($stopwatch.Elapsed.ToString('hh\:mm\:ss\.fff'))" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
