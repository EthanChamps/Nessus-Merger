#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# merge-nessus.sh — High-performance .nessus file merger for Linux/Kali
#
# Merges multiple .nessus XML scan files into a single file that Nessus
# can re-import. Optimized for scans with 1000+ hosts using streaming
# XML processing via Python 3 + lxml (both pre-installed on Kali).
#
# Usage:
#   ./merge-nessus.sh [OPTIONS]
#
# Options:
#   -p, --path DIR          Directory containing .nessus files (default: .)
#   -o, --output FILE       Output filename (default: merged_nessus_report.nessus)
#   -n, --name NAME         Report name (default: Merged Report)
#   -d, --deduplicate       Skip duplicate hosts (by hostname)
#   -h, --help              Show this help message
#
# Examples:
#   ./merge-nessus.sh
#   ./merge-nessus.sh -p /opt/scans -o combined.nessus -n "Q1 Scan"
#   ./merge-nessus.sh --deduplicate
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Defaults ────────────────────────────────────────────────────────────────
SCAN_DIR="."
OUTPUT_FILE="merged_nessus_report.nessus"
REPORT_NAME="Merged Report"
DEDUPLICATE=0

# ── Parse arguments ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--path)        SCAN_DIR="$2";      shift 2 ;;
        -o|--output)      OUTPUT_FILE="$2";    shift 2 ;;
        -n|--name)        REPORT_NAME="$2";    shift 2 ;;
        -d|--deduplicate) DEDUPLICATE=1;       shift   ;;
        -h|--help)
            sed -n '2,/^# ──/{ /^# ──/d; s/^# \?//p }' "$0"
            exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# ── Check for Python 3 ─────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    echo "[!] python3 is required but not found." >&2
    exit 1
fi

# ── Delegate to inline Python for speed ─────────────────────────────────────
exec python3 - "$SCAN_DIR" "$OUTPUT_FILE" "$REPORT_NAME" "$DEDUPLICATE" <<'PYTHON_SCRIPT'
import sys
import os
import time
import glob

scan_dir     = sys.argv[1]
output_file  = sys.argv[2]
report_name  = sys.argv[3]
deduplicate  = sys.argv[4] == "1"

# ── Locate .nessus files ───────────────────────────────────────────────────
nessus_files = sorted(glob.glob(os.path.join(scan_dir, "*.nessus")))

output_path = os.path.join(scan_dir, output_file)

# Exclude the output file if it already exists in the source directory
nessus_files = [f for f in nessus_files if os.path.abspath(f) != os.path.abspath(output_path)]

if not nessus_files:
    print(f"\033[91mNo .nessus files found in {scan_dir}\033[0m")
    sys.exit(1)

print(f"\033[96mFound {len(nessus_files)} .nessus file(s) in {scan_dir}\033[0m")

# ── Try lxml first (C-backed, ~5-10x faster), fall back to stdlib ──────────
try:
    from lxml import etree
    USING_LXML = True
    print("\033[96mUsing lxml (fast C parser)\033[0m")
except ImportError:
    import xml.etree.ElementTree as etree
    USING_LXML = False
    print("\033[93mUsing stdlib xml.etree (install python3-lxml for 5-10x speedup)\033[0m")

start_time = time.time()
total_hosts = 0
skipped_hosts = 0
seen_hosts = set()

# ── Phase 1: Parse primary file to get Policy and Report structure ─────────
primary_file = nessus_files[0]
print(f"\033[92mPrimary file: {os.path.basename(primary_file)}\033[0m")

if USING_LXML:
    primary_tree = etree.parse(primary_file)
else:
    primary_tree = etree.parse(primary_file)

primary_root = primary_tree.getroot()
policy_node = primary_root.find("Policy")
report_node = primary_root.find("Report")

if report_node is None:
    print("\033[91mERROR: Primary file has no valid Report element.\033[0m")
    sys.exit(1)

# ── Phase 2: Build output by streaming ─────────────────────────────────────
# We'll construct the output tree with the policy from primary,
# then stream-append ReportHost elements from all files.

# Create output root
out_root = etree.Element("NessusClientData_v2")

# Copy Policy
if policy_node is not None:
    out_root.append(policy_node)

# Create Report element with merged name
out_report = etree.SubElement(out_root, "Report")
out_report.set("name", report_name)
# Copy other report attributes
for attr_name, attr_val in report_node.attrib.items():
    if attr_name != "name":
        out_report.set(attr_name, attr_val)

# Free primary tree (we've extracted what we need)
del primary_tree, primary_root, report_node

# ── Phase 3: Stream hosts from each file ──────────────────────────────────
def process_file_lxml(filepath):
    """Use lxml iterparse to stream ReportHost elements without loading full DOM."""
    global total_hosts, skipped_hosts
    local_added = 0
    local_skipped = 0

    context = etree.iterparse(filepath, events=("end",), tag="ReportHost")
    for event, elem in context:
        host_name = elem.get("name", "")

        if deduplicate and host_name in seen_hosts:
            local_skipped += 1
            elem.clear()
            # Also clear preceding siblings to free memory
            while elem.getprevious() is not None:
                del elem.getparent()[0]
            continue

        if host_name:
            seen_hosts.add(host_name)

        # Deep copy and append to output
        out_report.append(elem)

        local_added += 1
        if local_added % 200 == 0:
            print(f"  ... {local_added} hosts processed", flush=True)

        # Clear preceding siblings to free memory during iteration
        while elem.getprevious() is not None:
            parent = elem.getparent()
            if parent is not None and len(parent) > 1:
                del parent[0]

    total_hosts += local_added
    skipped_hosts += local_skipped
    return local_added, local_skipped


def process_file_stdlib(filepath):
    """Use stdlib iterparse — no lxml memory tricks but still streaming."""
    global total_hosts, skipped_hosts
    local_added = 0
    local_skipped = 0

    for event, elem in etree.iterparse(filepath, events=("end",)):
        if elem.tag != "ReportHost":
            continue

        host_name = elem.get("name", "")

        if deduplicate and host_name in seen_hosts:
            local_skipped += 1
            elem.clear()
            continue

        if host_name:
            seen_hosts.add(host_name)

        out_report.append(elem)
        local_added += 1

        if local_added % 200 == 0:
            print(f"  ... {local_added} hosts processed", flush=True)

    total_hosts += local_added
    skipped_hosts += local_skipped
    return local_added, local_skipped


process_file = process_file_lxml if USING_LXML else process_file_stdlib

for idx, fpath in enumerate(nessus_files, 1):
    fname = os.path.basename(fpath)
    fsize_mb = os.path.getsize(fpath) / (1024 * 1024)
    print(f"\033[92m[{idx}/{len(nessus_files)}] Processing: {fname} ({fsize_mb:.1f} MB)\033[0m")

    added, skipped = process_file(fpath)

    msg = f"  + {added} hosts added"
    if skipped > 0:
        msg += f", {skipped} duplicates skipped"
    print(f"\033[92m{msg}\033[0m")

# ── Phase 4: Write output ──────────────────────────────────────────────────
print(f"\033[96mWriting merged report to {output_path} ...\033[0m", flush=True)

out_tree = etree.ElementTree(out_root)

if USING_LXML:
    out_tree.write(output_path, xml_declaration=True, encoding="UTF-8", pretty_print=True)
else:
    out_tree.write(output_path, xml_declaration=True, encoding="UTF-8")

elapsed = time.time() - start_time
output_size_mb = os.path.getsize(output_path) / (1024 * 1024)

# ── Summary ────────────────────────────────────────────────────────────────
print()
print("\033[96m" + "═" * 42 + "\033[0m")
print(f"\033[96m  Merge complete\033[0m")
print(f"\033[96m  Files merged : {len(nessus_files)}\033[0m")
print(f"\033[96m  Total hosts  : {total_hosts}\033[0m")
if deduplicate:
    print(f"\033[93m  Duplicates   : {skipped_hosts} skipped\033[0m")
print(f"\033[96m  Output       : {output_path} ({output_size_mb:.1f} MB)\033[0m")
print(f"\033[96m  Elapsed      : {elapsed:.2f}s\033[0m")
print("\033[96m" + "═" * 42 + "\033[0m")
PYTHON_SCRIPT
