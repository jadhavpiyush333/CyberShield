#!/usr/bin/env python3
"""Validate canonical CyberShield new-module CSV schemas; does not train models."""
import argparse
import csv
import sys
from pathlib import Path

SCHEMAS = {
    "email": (("text", "label"), {"phishing", "legitimate"}),
    "social_scams": (("text", "label"), {"scam", "legitimate"}),
    "qr": (("url", "label"), {"malicious", "benign"}),
    "document_metadata": (("sample_id", "file_type", "label"), {"malicious", "benign"}),
    "apk_metadata": (("sample_id", "label"), {"malware", "benign"}),
    "upi_scams": (("text", "label"), {"scam", "legitimate"}),
    "call_transcripts": (("text", "label"), {"scam", "legitimate"}),
}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", default="data/raw", help="Directory containing canonical CSV files")
    root = Path(parser.parse_args().data_dir)
    failed = False
    for name, (required, allowed) in SCHEMAS.items():
        path = root / f"{name}.csv"
        if not path.exists():
            print(f"NOT FOUND  {path}")
            continue
        try:
            with path.open("r", encoding="utf-8-sig", newline="") as stream:
                reader = csv.DictReader(stream)
                fields = set(reader.fieldnames or [])
                missing = set(required) - fields
                if missing:
                    print(f"FAIL       {path}: missing columns {sorted(missing)}")
                    failed = True
                    continue
                rows, bad_labels, empty_rows = 0, set(), 0
                for row in reader:
                    rows += 1
                    label = (row.get("label") or "").strip().lower()
                    if label not in allowed:
                        bad_labels.add(label or "<empty>")
                    if any(not (row.get(col) or "").strip() for col in required):
                        empty_rows += 1
                if rows == 0:
                    print(f"EMPTY      {path}: header only; not ready for training")
                elif bad_labels or empty_rows:
                    print(f"CHECK      {path}: rows={rows}, invalid_labels={sorted(bad_labels)}, rows_with_empty_required_fields={empty_rows}")
                    failed = True
                else:
                    print(f"PASS       {path}: rows={rows}, allowed_labels={sorted(allowed)}")
        except (OSError, UnicodeError, csv.Error) as exc:
            print(f"FAIL       {path}: {exc}")
            failed = True
    print("\nSchema checks only: provenance, duplicates, leakage, label quality and license must be reviewed separately.")
    return 1 if failed else 0

if __name__ == "__main__":
    sys.exit(main())
