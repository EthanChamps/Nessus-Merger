#!/usr/bin/env python3
"""
CSV Comparison & Deduplication Script

Compares two CSV files by the "Name" column (case-insensitive).
Rows in file 2 whose Name already exists in file 1 are removed.
Outputs a cleaned version of file 2 and a log of deleted rows.
"""

import csv
import os
import sys
from datetime import datetime


def read_csv(filepath):
    """Read a CSV file and return its headers and rows."""
    with open(filepath, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        headers = reader.fieldnames
        rows = list(reader)
    return headers, rows


def main():
    print("=== CSV Comparison & Deduplication ===\n")

    # Prompt for file paths
    file1_path = input("Enter the path to CSV file 1 (reference file): ").strip()
    file2_path = input("Enter the path to CSV file 2 (file to deduplicate): ").strip()

    # Validate files exist
    for path, label in [(file1_path, "File 1"), (file2_path, "File 2")]:
        if not os.path.isfile(path):
            print(f"Error: {label} not found at '{path}'")
            sys.exit(1)

    # Read both files
    headers1, rows1 = read_csv(file1_path)
    headers2, rows2 = read_csv(file2_path)

    # Validate that both files have a "Name" column
    for headers, label in [(headers1, "File 1"), (headers2, "File 2")]:
        if headers is None or "Name" not in headers:
            print(f"Error: {label} does not contain a 'Name' column.")
            sys.exit(1)

    # Build a set of names from file 1 (lowercase for case-insensitive comparison)
    file1_names = {row["Name"].strip().lower() for row in rows1}

    # Split file 2 rows into kept and removed
    kept_rows = []
    removed_rows = []

    for row in rows2:
        name = row["Name"].strip().lower()
        if name in file1_names:
            removed_rows.append(row)
        else:
            kept_rows.append(row)

    # Build output file paths
    base, ext = os.path.splitext(file2_path)
    cleaned_path = f"{base}_cleaned{ext}"
    log_path = f"{base}_removed_log.csv"

    # Write cleaned file 2
    with open(cleaned_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers2)
        writer.writeheader()
        writer.writerows(kept_rows)

    # Write removal log
    log_headers = ["Removed_At"] + headers2
    with open(log_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=log_headers)
        writer.writeheader()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for row in removed_rows:
            log_row = {"Removed_At": timestamp, **row}
            writer.writerow(log_row)

    # Summary
    print(f"\nResults:")
    print(f"  File 1 entries:          {len(rows1)}")
    print(f"  File 2 original entries: {len(rows2)}")
    print(f"  Duplicates removed:      {len(removed_rows)}")
    print(f"  File 2 entries kept:     {len(kept_rows)}")
    print(f"\n  Cleaned file -> {cleaned_path}")
    print(f"  Removal log  -> {log_path}")


if __name__ == "__main__":
    main()
