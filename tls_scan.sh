#!/usr/bin/env bash
# tls_scan.sh - Scan hosts for SSL/TLS versions and report those using
#               SSLv2, SSLv3, TLS 1.0, or TLS 1.1 (anything below TLS 1.2).
#
# Usage:
#   ./tls_scan.sh -f hosts.txt [-p 443] [-o results.csv] [-t 5] [-j 20]
#
# Input file: one host per line, optionally host:port
# Output: CSV spreadsheet of affected hosts

set -euo pipefail

# Defaults
PORT=443
OUTPUT="tls_scan_results.csv"
TIMEOUT=5
MAX_JOBS=20
HOSTS_FILE=""

usage() {
    cat <<EOF
Usage: $(basename "$0") -f HOSTS_FILE [OPTIONS]

Options:
  -f FILE    File containing hosts to scan (one per line, optional host:port)
  -p PORT    Default port if not specified per-host (default: 443)
  -o FILE    Output CSV file (default: tls_scan_results.csv)
  -t SECS    Connection timeout in seconds (default: 5)
  -j NUM     Max parallel scans (default: 20)
  -h         Show this help
EOF
    exit 1
}

while getopts "f:p:o:t:j:h" opt; do
    case "$opt" in
        f) HOSTS_FILE="$OPTARG" ;;
        p) PORT="$OPTARG" ;;
        o) OUTPUT="$OPTARG" ;;
        t) TIMEOUT="$OPTARG" ;;
        j) MAX_JOBS="$OPTARG" ;;
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

if ! command -v openssl &>/dev/null; then
    echo "Error: openssl is required but not found" >&2
    exit 1
fi

TMPDIR_SCAN=$(mktemp -d)
trap 'rm -rf "$TMPDIR_SCAN"' EXIT

PROTOCOLS=(
    "ssl2:-ssl2:SSLv2"
    "ssl3:-ssl3:SSLv3"
    "tls1:-tls1:TLSv1.0"
    "tls1_1:-tls1_1:TLSv1.1"
    "tls1_2:-tls1_2:TLSv1.2"
    "tls1_3:-tls1_3:TLSv1.3"
)

# Test which protocol flags openssl supports
SUPPORTED_PROTOS=()
for entry in "${PROTOCOLS[@]}"; do
    IFS=: read -r key flag label <<< "$entry"
    if openssl s_client "$flag" 2>&1 | grep -qi "unknown option\|no such option\|invalid command" 2>/dev/null; then
        echo "Note: openssl does not support $flag ($label), skipping" >&2
    else
        SUPPORTED_PROTOS+=("$entry")
    fi
done

test_protocol() {
    local host="$1" port="$2" flag="$3" timeout="$4"
    echo | timeout "$timeout" openssl s_client "$flag" -connect "${host}:${port}" 2>/dev/null
}

scan_host() {
    local input="$1"
    local host port

    # Parse host:port
    if [[ "$input" == *:* ]]; then
        host="${input%%:*}"
        port="${input##*:}"
    else
        host="$input"
        port="$PORT"
    fi

    local enabled=()
    local vulnerable=()

    for entry in "${SUPPORTED_PROTOS[@]}"; do
        IFS=: read -r key flag label <<< "$entry"
        if test_protocol "$host" "$port" "$flag" "$TIMEOUT" | grep -q "BEGIN CERTIFICATE\|Protocol.*:"; then
            enabled+=("$label")
            # Flag anything below TLS 1.2
            case "$key" in
                ssl2|ssl3|tls1|tls1_1) vulnerable+=("$label") ;;
            esac
        fi
    done

    local enabled_str vulnerable_str status
    enabled_str=$(IFS='|'; echo "${enabled[*]:-none}")
    vulnerable_str=$(IFS='|'; echo "${vulnerable[*]:-}")

    if [[ ${#vulnerable[@]} -gt 0 ]]; then
        status="AFFECTED"
    elif [[ ${#enabled[@]} -eq 0 ]]; then
        status="NO_TLS"
    else
        status="OK"
    fi

    local result_file="${TMPDIR_SCAN}/$(echo "${host}_${port}" | tr '/:' '__')"
    echo "${host},${port},${enabled_str},${vulnerable_str},${status}" > "$result_file"
}

# Count total hosts
TOTAL=$(grep -cve '^\s*$\|^\s*#' "$HOSTS_FILE" || true)
echo "Scanning $TOTAL hosts (max $MAX_JOBS parallel) ..."

ACTIVE=0
COUNT=0

while IFS= read -r line; do
    # Skip blank lines and comments
    line=$(echo "$line" | xargs)
    [[ -z "$line" || "$line" == \#* ]] && continue

    scan_host "$line" &
    ((ACTIVE++)) || true
    ((COUNT++)) || true

    # Progress
    if (( COUNT % 10 == 0 )); then
        echo "  Progress: $COUNT / $TOTAL hosts queued"
    fi

    # Throttle
    if (( ACTIVE >= MAX_JOBS )); then
        wait -n 2>/dev/null || wait
        ((ACTIVE--)) || true
    fi
done < "$HOSTS_FILE"

# Wait for remaining jobs
wait
echo "Scan complete. Writing results ..."

# Write CSV
{
    echo "Host,Port,Enabled Protocols,Vulnerable Protocols,Status"
    for f in "$TMPDIR_SCAN"/*; do
        [[ -f "$f" ]] && cat "$f"
    done
} | sort -t, -k5,5 -k1,1 > "$OUTPUT"

# Summary
AFFECTED=$(grep -c ",AFFECTED$" "$OUTPUT" || true)
OK=$(grep -c ",OK$" "$OUTPUT" || true)
NO_TLS=$(grep -c ",NO_TLS$" "$OUTPUT" || true)

echo ""
echo "=== Results saved to: $OUTPUT ==="
echo "  Total scanned:  $TOTAL"
echo "  AFFECTED (SSL or < TLS 1.2):  $AFFECTED"
echo "  OK (TLS 1.2+ only):           $OK"
echo "  No TLS response:              $NO_TLS"
echo ""

if [[ "$AFFECTED" -gt 0 ]]; then
    echo "--- Affected Hosts ---"
    grep ",AFFECTED$" "$OUTPUT" | while IFS=, read -r h p en vn st; do
        echo "  $h:$p  vulnerable: $vn"
    done
fi
