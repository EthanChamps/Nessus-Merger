#!/usr/bin/env python3
"""
CSV IP-to-Hostname Resolver

Reads a CSV file, finds IP addresses in the "Host" column,
runs nslookup to resolve them to hostnames, and replaces the IP.
Entries that are already hostnames or that fail to resolve are left unchanged.
"""

import csv
import os
import re
import subprocess
import sys


# Regex to match an IPv4 address
IPV4_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def is_ip_address(value):
    """Check if a string looks like an IPv4 address."""
    return bool(IPV4_PATTERN.match(value.strip()))


def nslookup(ip):
    """Run nslookup and return the hostname, or None if it fails."""
    try:
        result = subprocess.run(
            ["nslookup", ip],
            capture_output=True,
            text=True,
            timeout=5,
        )
        # Parse nslookup output for "name = <hostname>"
        for line in result.stdout.splitlines():
            if "name =" in line.lower():
                # Format: "1.0.168.192.in-addr.arpa\tname = hostname."
                hostname = line.split("=")[-1].strip().rstrip(".")
                return hostname
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def main():
    print("=== CSV IP-to-Hostname Resolver ===\n")

    filepath = input("Enter the path to the CSV file: ").strip()

    if not os.path.isfile(filepath):
        print(f"Error: File not found at '{filepath}'")
        sys.exit(1)

    # Read the CSV
    with open(filepath, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        headers = reader.fieldnames
        rows = list(reader)

    if headers is None or "Host" not in headers:
        print("Error: CSV does not contain a 'Host' column.")
        sys.exit(1)

    resolved_count = 0
    skipped_count = 0
    failed_count = 0

    for row in rows:
        host = row["Host"].strip()

        if not is_ip_address(host):
            skipped_count += 1
            continue

        print(f"  Resolving {host}...", end=" ", flush=True)
        hostname = nslookup(host)

        if hostname:
            row["Host"] = hostname
            resolved_count += 1
            print(f"-> {hostname}")
        else:
            failed_count += 1
            print("-> could not resolve, keeping IP")

    # Write output
    base, ext = os.path.splitext(filepath)
    output_path = f"{base}_resolved{ext}"

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nResults:")
    print(f"  Total rows:              {len(rows)}")
    print(f"  IPs resolved:            {resolved_count}")
    print(f"  IPs failed (kept as-is): {failed_count}")
    print(f"  Already hostnames:       {skipped_count}")
    print(f"\n  Output -> {output_path}")


if __name__ == "__main__":
    main()
