#!/usr/bin/env bash
# tls_scan.sh - Two-phase TLS/SSL scanner using nmap
#
# Phase 1: Discover open TCP ports (nmap top 1000)
# Phase 2: Run ssl-enum-ciphers on open ports to detect protocol versions
# Output:  CSV with only hosts/ports running vulnerable protocols
#          (SSLv2, SSLv3, TLSv1.0, TLSv1.1)
#
# Usage:
#   ./tls_scan.sh -f hosts.txt [-o results.csv] [-T4]
#
# Input file: one hostname or IP per line

set -euo pipefail

# Defaults
OUTPUT="tls_scan_results.csv"
HOSTS_FILE=""
NMAP_TIMING="-T4"
NMAP_EXTRA_ARGS=""

usage() {
    cat <<EOF
Usage: $(basename "$0") -f HOSTS_FILE [OPTIONS]

Options:
  -f FILE    File with hosts to scan (one per line)
  -o FILE    Output CSV file (default: tls_scan_results.csv)
  -T TIMING  Nmap timing template 0-5 (default: 4)
  -a ARGS    Extra nmap arguments (quoted string)
  -h         Show this help

Requires: nmap with ssl-enum-ciphers script (nmap --script ssl-enum-ciphers)

Examples:
  $(basename "$0") -f hosts.txt
  $(basename "$0") -f hosts.txt -o report.csv -T 3
  $(basename "$0") -f hosts.txt -a "--top-ports 100"
EOF
    exit 1
}

while getopts "f:o:T:a:h" opt; do
    case "$opt" in
        f) HOSTS_FILE="$OPTARG" ;;
        o) OUTPUT="$OPTARG" ;;
        T) NMAP_TIMING="-T${OPTARG}" ;;
        a) NMAP_EXTRA_ARGS="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [[ -z "$HOSTS_FILE" ]]; then
    echo "Error: -f HOSTS_FILE is required" >&2
    usage
fi

if [[ ! -f "$HOSTS_FILE" ]]; then
    echo "Error: file not found: $HOSTS_FILE" >&2
    exit 1
fi

if ! command -v nmap &>/dev/null; then
    echo "Error: nmap is required but not found. Install with: apt install nmap" >&2
    exit 1
fi

# Check ssl-enum-ciphers script is available
if ! nmap --script-help ssl-enum-ciphers &>/dev/null; then
    echo "Error: nmap ssl-enum-ciphers script not found." >&2
    echo "Install nmap scripts or check your nmap installation." >&2
    exit 1
fi

TMPDIR_SCAN=$(mktemp -d)
trap 'rm -rf "$TMPDIR_SCAN"' EXIT

TOTAL=$(grep -cve '^\s*$\|^\s*#' "$HOSTS_FILE" || true)
VULNERABLE_PROTOS="SSLv2|SSLv3|TLSv1\.0|TLSv1\.1"

echo "============================================"
echo "  TLS/SSL Version Scanner (nmap-based)"
echo "============================================"
echo "  Hosts file:  $HOSTS_FILE ($TOTAL hosts)"
echo "  Output:      $OUTPUT"
echo "  Timing:      $NMAP_TIMING"
echo ""

# -------------------------------------------------------------------
# Phase 1: Port discovery — find open TCP ports on all hosts
# -------------------------------------------------------------------
echo "[Phase 1] Discovering open TCP ports (top 1000) ..."

PHASE1_XML="${TMPDIR_SCAN}/phase1.xml"

nmap -sS --open -oX "$PHASE1_XML" $NMAP_TIMING \
    $NMAP_EXTRA_ARGS -iL "$HOSTS_FILE" 2>/dev/null || \
nmap -sT --open -oX "$PHASE1_XML" $NMAP_TIMING \
    $NMAP_EXTRA_ARGS -iL "$HOSTS_FILE" 2>/dev/null

# Parse phase 1 results: extract host + open ports
# Build a target list for phase 2
PHASE2_TARGETS="${TMPDIR_SCAN}/phase2_targets.txt"
> "$PHASE2_TARGETS"

# Use xmllint or grep/awk to parse nmap XML
python3 - "$PHASE1_XML" "$PHASE2_TARGETS" <<'PYEOF'
import xml.etree.ElementTree as ET
import sys

xml_file = sys.argv[1]
out_file = sys.argv[2]

tree = ET.parse(xml_file)
root = tree.getroot()

targets = []
for host_el in root.findall('.//host'):
    # Get hostname or IP
    addr = ""
    addr_el = host_el.find('address[@addrtype="ipv4"]')
    if addr_el is None:
        addr_el = host_el.find('address[@addrtype="ipv6"]')
    if addr_el is not None:
        addr = addr_el.get('addr', '')

    hostname = ""
    hn_el = host_el.find('.//hostname')
    if hn_el is not None:
        hostname = hn_el.get('name', '')

    display = hostname if hostname else addr
    if not addr:
        continue

    # Get open ports
    ports = []
    for port_el in host_el.findall('.//port[@protocol="tcp"]'):
        state_el = port_el.find('state')
        if state_el is not None and state_el.get('state') == 'open':
            ports.append(port_el.get('portid'))

    if ports:
        targets.append((addr, display, ports))

with open(out_file, 'w') as f:
    for addr, display, ports in targets:
        port_str = ','.join(ports)
        f.write(f"{addr}\t{display}\t{port_str}\n")

print(f"  Found {sum(len(t[2]) for t in targets)} open ports across {len(targets)} hosts")
PYEOF

if [[ ! -s "$PHASE2_TARGETS" ]]; then
    echo "  No open ports found. Nothing to scan for TLS."
    echo "Hostname,Port,Protocols" > "$OUTPUT"
    echo "Results saved to: $OUTPUT (empty — no open ports found)"
    exit 0
fi

# -------------------------------------------------------------------
# Phase 2: TLS version detection on open ports
# -------------------------------------------------------------------
echo ""
echo "[Phase 2] Checking TLS/SSL versions on open ports ..."

PHASE2_XML="${TMPDIR_SCAN}/phase2.xml"

# Build nmap target arguments from phase 1 results
# Scan each host only on its discovered open ports
COMBINED_RESULTS="${TMPDIR_SCAN}/combined.csv"
> "$COMBINED_RESULTS"

while IFS=$'\t' read -r addr display ports; do
    HOST_XML="${TMPDIR_SCAN}/ssl_${addr}.xml"

    nmap -sV --script ssl-enum-ciphers -p "$ports" "$addr" \
        -oX "$HOST_XML" $NMAP_TIMING 2>/dev/null || true

    # Parse the ssl-enum-ciphers output
    python3 - "$HOST_XML" "$display" "$COMBINED_RESULTS" <<'PYEOF'
import xml.etree.ElementTree as ET
import re
import sys

xml_file = sys.argv[1]
display_host = sys.argv[2]
out_file = sys.argv[3]

VULNERABLE = {'SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1'}

tree = ET.parse(xml_file)
root = tree.getroot()

results = []
for host_el in root.findall('.//host'):
    for port_el in host_el.findall('.//port[@protocol="tcp"]'):
        portid = port_el.get('portid')

        # Look for ssl-enum-ciphers script output
        for script_el in port_el.findall('.//script[@id="ssl-enum-ciphers"]'):
            output = script_el.get('output', '')

            # Extract protocol versions from the output
            # Matches lines like "  TLSv1.0:", "  SSLv3:", etc.
            found_protos = re.findall(
                r'(SSLv[23]|TLSv1\.[0-3])\s*:', output
            )

            # Also check table elements
            for table_el in script_el.findall('.//table'):
                key = table_el.get('key', '')
                if re.match(r'(SSLv[23]|TLSv1\.[0-3])', key):
                    found_protos.append(key)

            # Deduplicate and keep only vulnerable
            vuln = sorted(set(p for p in found_protos if p in VULNERABLE))
            if vuln:
                results.append((display_host, portid, '|'.join(vuln)))

with open(out_file, 'a') as f:
    for host, port, protos in results:
        f.write(f'{host},{port},{protos}\n')
PYEOF

done < "$PHASE2_TARGETS"

# -------------------------------------------------------------------
# Write final CSV
# -------------------------------------------------------------------
{
    echo "Hostname,Port,Protocols"
    if [[ -s "$COMBINED_RESULTS" ]]; then
        sort -t, -k1,1 -k2,2n "$COMBINED_RESULTS"
    fi
} > "$OUTPUT"

# Summary
AFFECTED=$(wc -l < "$COMBINED_RESULTS" 2>/dev/null || echo 0)
AFFECTED=$((AFFECTED))

echo ""
echo "============================================"
echo "  Results saved to: $OUTPUT"
echo "  Affected host:port entries: $AFFECTED"
echo "============================================"
echo ""

if [[ "$AFFECTED" -gt 0 ]]; then
    echo "--- Affected Hosts ---"
    while IFS=, read -r h p protos; do
        echo "  $h:$p  -> $protos"
    done < "$COMBINED_RESULTS"
fi
