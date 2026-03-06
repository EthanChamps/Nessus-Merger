# Nessus Merger & Security CSV Toolkit

A collection of scripts for merging Nessus scan files, deduplicating CSV reports, resolving IPs to hostnames, and scanning for vulnerable TLS/SSL versions.

## Tools

### `tls_scan.sh` — TLS/SSL Version Scanner
Finds hosts running outdated SSL/TLS (SSLv2, SSLv3, TLSv1.0, TLSv1.1) using nmap.

```bash
# Scan hosts from a file, output to CSV
./tls_scan.sh -f hosts.txt

# Custom output file and timing
./tls_scan.sh -f hosts.txt -o report.csv -T 3
```

**How it works:** Phase 1 discovers open ports (top 1000), Phase 2 runs `ssl-enum-ciphers` only on those ports. Output CSV has columns: `Hostname, Port, Protocols`.

**Requires:** `nmap` with `ssl-enum-ciphers` script, `python3`

---

### `csv_dedup.py` — CSV Deduplication
Compares two CSV files by the `Name` column and removes duplicates from the second file.

```bash
python3 csv_dedup.py
# Prompts for two CSV file paths
```

**Outputs:** `<file2>_cleaned.csv` and a `<file2>_removed_log.csv` with timestamps.

---

### `csv_resolve_hosts.py` — IP-to-Hostname Resolver
Replaces IP addresses in a CSV `Host` column with hostnames via `nslookup`.

```bash
python3 csv_resolve_hosts.py
# Prompts for a CSV file path
```

**Outputs:** `<file>_resolved.csv` with IPs replaced by hostnames where possible.
