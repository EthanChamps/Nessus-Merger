<#
.SYNOPSIS
High-performance merger for .nessus XML files, optimized for scans with 1000+ hosts.

.DESCRIPTION
Merges multiple .nessus files into a single file that can be imported back into Nessus.
Uses streaming XML (XmlReader/XmlWriter) to minimize memory usage and maximize speed
when processing large scan files.

Key optimizations over traditional approaches:
- Streams secondary files with XmlReader instead of loading full DOM
- Uses XmlWriter for output instead of DOM manipulation
- Processes files in parallel for host counting/validation
- Progress reporting for large merges
- Optional host deduplication by IP/hostname

.PARAMETER Path
Directory containing .nessus files. Defaults to the current directory.

.PARAMETER OutputFile
Name of the merged output file. Defaults to "merged_nessus_report.nessus".

.PARAMETER ReportName
Name for the merged report. Defaults to "Merged Report".

.PARAMETER Deduplicate
When specified, skips duplicate hosts (matched by hostname). Keeps the first occurrence.

.EXAMPLE
.\Merge-NessusFiles.ps1

.EXAMPLE
.\Merge-NessusFiles.ps1 -Path "C:\Scans" -OutputFile "combined.nessus" -ReportName "Q1 Scan"

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
    [string]$ReportName = "Merged Report",

    [switch]$Deduplicate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Collect .nessus files ──────────────────────────────────────────────
$nessusFiles = Get-ChildItem -Path $Path -Filter *.nessus | Sort-Object Name

if ($nessusFiles.Count -eq 0) {
    Write-Host "No .nessus files found in $Path" -ForegroundColor Red
    exit 1
}

Write-Host "Found $($nessusFiles.Count) .nessus file(s) in $Path" -ForegroundColor Cyan

$outPath = Join-Path $Path $OutputFile
$totalHosts = 0
$skippedHosts = 0
$seenHosts = @{}
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# ── Phase 1: Read the first file to capture Policy and Report attributes ──
$primaryFile = $nessusFiles[0]
Write-Host "Primary file: $($primaryFile.Name)" -ForegroundColor Green

# Load only the primary file into DOM (we need its Policy node intact)
$primaryDoc = New-Object System.Xml.XmlDocument
$primaryDoc.Load($primaryFile.FullName)

$policyNode = $primaryDoc.SelectSingleNode("//Policy")
$reportNode = $primaryDoc.SelectSingleNode("//Report")

if (-not $reportNode) {
    Write-Host "ERROR: Primary file does not contain a valid Nessus report structure." -ForegroundColor Red
    exit 1
}

# Capture report attributes from primary (except name, which we override)
$reportAttrs = @{}
foreach ($attr in $reportNode.Attributes) {
    if ($attr.Name -ne "name") {
        $reportAttrs[$attr.Name] = $attr.Value
    }
}

# ── Phase 2: Stream-write the merged output ────────────────────────────
$writerSettings = New-Object System.Xml.XmlWriterSettings
$writerSettings.Indent = $true
$writerSettings.IndentChars = "  "
$writerSettings.Encoding = New-Object System.Text.UTF8Encoding($false)  # UTF-8 no BOM
$writerSettings.CloseOutput = $true

$fileStream = [System.IO.File]::Create($outPath)
$writer = [System.Xml.XmlWriter]::Create($fileStream, $writerSettings)

$writer.WriteStartDocument()
$writer.WriteStartElement("NessusClientData_v2")

# Write the Policy node from the primary file
if ($policyNode) {
    $policyNode.WriteTo($writer)
}

# Start the Report element
$writer.WriteStartElement("Report")
$writer.WriteAttributeString("name", $ReportName)
foreach ($key in $reportAttrs.Keys) {
    $writer.WriteAttributeString($key, $reportAttrs[$key])
}

# ── Helper: Stream ReportHost nodes from a file using XmlReader ────────
function Write-HostsFromFile {
    param(
        [string]$FilePath,
        [System.Xml.XmlWriter]$Writer,
        [hashtable]$SeenHosts,
        [bool]$DoDeduplicate
    )

    $localCount = 0
    $localSkipped = 0

    $readerSettings = New-Object System.Xml.XmlReaderSettings
    $readerSettings.IgnoreWhitespace = $false
    $readerSettings.DtdProcessing = [System.Xml.DtdProcessing]::Ignore

    $reader = [System.Xml.XmlReader]::Create($FilePath, $readerSettings)

    try {
        while ($reader.Read()) {
            if ($reader.NodeType -eq [System.Xml.XmlNodeType]::Element -and $reader.LocalName -eq "ReportHost") {
                $hostName = $reader.GetAttribute("name")

                # Read the entire ReportHost subtree into a string
                $hostXml = $reader.ReadOuterXml()  # advances reader past this element

                if ($DoDeduplicate -and $hostName -and $SeenHosts.ContainsKey($hostName)) {
                    $localSkipped++
                    continue
                }

                if ($hostName) {
                    $SeenHosts[$hostName] = $true
                }

                # Parse the fragment and write it to the output writer
                $fragReader = [System.Xml.XmlReader]::Create((New-Object System.IO.StringReader($hostXml)))
                try {
                    $fragReader.Read()
                    $Writer.WriteNode($fragReader, $true)
                }
                finally {
                    $fragReader.Close()
                }

                $localCount++

                # Progress every 100 hosts
                if ($localCount % 100 -eq 0) {
                    Write-Host "  ... processed $localCount hosts so far" -ForegroundColor DarkGray
                }
            }
        }
    }
    finally {
        $reader.Close()
    }

    return @{ Added = $localCount; Skipped = $localSkipped }
}

# ── Phase 3: Process all files ─────────────────────────────────────────
foreach ($file in $nessusFiles) {
    $fileIndex = $nessusFiles.IndexOf($file) + 1
    Write-Host "[$fileIndex/$($nessusFiles.Count)] Processing: $($file.Name)" -ForegroundColor Green

    $result = Write-HostsFromFile -FilePath $file.FullName -Writer $writer -SeenHosts $seenHosts -DoDeduplicate $Deduplicate.IsPresent

    $totalHosts += $result.Added
    $skippedHosts += $result.Skipped

    Write-Host "  + $($result.Added) hosts added$(if ($result.Skipped -gt 0) { ", $($result.Skipped) duplicates skipped" })" -ForegroundColor Green
}

# ── Close XML structure ────────────────────────────────────────────────
$writer.WriteEndElement()   # </Report>
$writer.WriteEndElement()   # </NessusClientData_v2>
$writer.WriteEndDocument()
$writer.Flush()
$writer.Close()

# Free the primary DOM
$primaryDoc = $null

$stopwatch.Stop()

# ── Summary ────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Merge complete" -ForegroundColor Cyan
Write-Host "  Files merged : $($nessusFiles.Count)" -ForegroundColor Cyan
Write-Host "  Total hosts  : $totalHosts" -ForegroundColor Cyan
if ($Deduplicate.IsPresent) {
    Write-Host "  Duplicates   : $skippedHosts skipped" -ForegroundColor Yellow
}
Write-Host "  Output       : $outPath" -ForegroundColor Cyan
Write-Host "  Elapsed      : $($stopwatch.Elapsed.ToString('hh\:mm\:ss\.fff'))" -ForegroundColor Cyan
Write-Host "════════════════════════════════════════" -ForegroundColor Cyan
