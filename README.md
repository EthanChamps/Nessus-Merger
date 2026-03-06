# Nessus Merger

High-performance `.nessus` file merger optimized for large scans (1000+ hosts). Available as both PowerShell (Windows) and Bash (Kali/Linux) scripts.

## Why This Exists

Standard Nessus merge tools load entire XML documents into memory and use DOM manipulation to combine them. This works fine for small scans, but becomes painfully slow (or crashes) with large enterprise scans containing thousands of hosts and hundreds of megabytes of XML.

### Performance Optimizations

| Technique | Benefit |
|---|---|
| **Streaming XML (XmlReader/iterparse)** | Processes hosts one at a time instead of loading entire files into memory |
| **Direct XmlWriter output** | Writes merged XML without building a complete DOM tree (PowerShell) |
| **lxml C parser** | 5-10x faster XML parsing than pure Python (Bash/Kali version) |
| **Memory-efficient iteration** | Frees parsed elements as they're processed to keep memory flat |
| **Optional deduplication** | Skips duplicate hosts by hostname to avoid bloated reports |

## Usage

### PowerShell (Windows)

```powershell
# Merge all .nessus files in current directory
.\Merge-NessusFiles.ps1

# Specify directory, output file, and report name
.\Merge-NessusFiles.ps1 -Path "C:\Scans" -OutputFile "combined.nessus" -ReportName "Q1 Scan"

# Merge with host deduplication
.\Merge-NessusFiles.ps1 -Deduplicate
```

**Parameters:**

| Parameter | Default | Description |
|---|---|---|
| `-Path` | Current directory | Directory containing `.nessus` files |
| `-OutputFile` | `merged_nessus_report.nessus` | Output filename |
| `-ReportName` | `Merged Report` | Name shown in Nessus for the merged report |
| `-Deduplicate` | Off | Skip duplicate hosts (matched by hostname) |

### Bash / Kali Linux

```bash
# Make executable (first time only)
chmod +x merge-nessus.sh

# Merge all .nessus files in current directory
./merge-nessus.sh

# Specify directory, output file, and report name
./merge-nessus.sh -p /opt/scans -o combined.nessus -n "Q1 Scan"

# Merge with host deduplication
./merge-nessus.sh --deduplicate
```

**Options:**

| Flag | Default | Description |
|---|---|---|
| `-p, --path` | `.` | Directory containing `.nessus` files |
| `-o, --output` | `merged_nessus_report.nessus` | Output filename |
| `-n, --name` | `Merged Report` | Report name |
| `-d, --deduplicate` | Off | Skip duplicate hosts |
| `-h, --help` | — | Show help |

**Requirements:** Python 3 (pre-installed on Kali). For best performance, install `python3-lxml`:

```bash
sudo apt install python3-lxml
```

## How .nessus Files Are Structured

```xml
<NessusClientData_v2>
  <Policy>...</Policy>          <!-- scan configuration -->
  <Report name="...">
    <ReportHost name="192.168.1.1">  <!-- one per scanned host -->
      <HostProperties>...</HostProperties>
      <ReportItem>...</ReportItem>   <!-- one per finding -->
      ...
    </ReportHost>
    ...
  </Report>
</NessusClientData_v2>
```

The merger takes the `Policy` from the first file and combines all `ReportHost` elements from every file into a single `Report`.

## Credits

Inspired by [NessusReportMerger](https://github.com/0xprime/NessusReportMerger) by 0xPrime.
