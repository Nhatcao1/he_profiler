#!/usr/bin/env python3
"""Build a tiny synthetic company phone directory for the BinFHE LUT demo.

This is demo data, not an authoritative registry. The important relationship is:

    lookup_slot -> masked phone record -> company_code

The server can turn the lookup_slot -> company_code relation into a BinFHE LUT.
During encrypted evaluation, the server receives Enc(lookup_slot), not the
phone number or plaintext lookup slot.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class DirectoryEntry:
    lookup_slot: int
    phone_number: str
    company_code: int
    company_name: str
    registry_status: str


DIRECTORY_ENTRIES = [
    DirectoryEntry(0, "+84000000000", 0, "Unknown", "unknown"),
    DirectoryEntry(1, "+84961234567", 1, "Viettel", "verified_company"),
    DirectoryEntry(2, "+84971234567", 1, "Viettel", "verified_company"),
    DirectoryEntry(3, "+84981234567", 1, "Viettel", "verified_company"),
    DirectoryEntry(4, "+84861234567", 1, "Viettel", "verified_company"),
    DirectoryEntry(5, "+84911234567", 2, "VNPT/VinaPhone", "verified_company"),
    DirectoryEntry(6, "+84941234567", 2, "VNPT/VinaPhone", "verified_company"),
    DirectoryEntry(7, "+84881234567", 2, "VNPT/VinaPhone", "verified_company"),
    DirectoryEntry(8, "+84901234567", 3, "MobiFone", "verified_company"),
    DirectoryEntry(9, "+84931234567", 3, "MobiFone", "verified_company"),
    DirectoryEntry(10, "+84891234567", 3, "MobiFone", "verified_company"),
    DirectoryEntry(11, "+84921234567", 4, "Vietnamobile", "registered"),
    DirectoryEntry(12, "+84991234567", 5, "Gmobile", "registered"),
    DirectoryEntry(13, "+84241234567", 6, "Hanoi Landline", "registered"),
    DirectoryEntry(14, "+84281234567", 7, "HCMC Landline", "registered"),
    DirectoryEntry(15, "+84701234567", 8, "Other Registered", "registered"),
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("db/company_directory.sqlite"))
    parser.add_argument("--client-inputs", type=Path, default=None)
    return parser.parse_args()


def normalize_phone(phone_number: str) -> str:
    return "".join(ch for ch in phone_number if ch.isdigit())


def phone_hash(phone_number: str) -> str:
    return hashlib.sha256(normalize_phone(phone_number).encode("utf-8")).hexdigest()


def mask_phone(phone_number: str) -> str:
    digits = normalize_phone(phone_number)
    if len(digits) <= 6:
        return "*" * len(digits)
    return f"{digits[:4]}***{digits[-3:]}"


def create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        DROP TABLE IF EXISTS company_directory;

        CREATE TABLE company_directory (
          lookup_slot INTEGER PRIMARY KEY,
          phone_number_masked TEXT NOT NULL,
          phone_number_sha256 TEXT NOT NULL,
          company_code INTEGER NOT NULL,
          company_name TEXT NOT NULL,
          registry_status TEXT NOT NULL,
          registry_version TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        """
    )


def build_database(args: argparse.Namespace) -> None:
    args.out.parent.mkdir(parents=True, exist_ok=True)
    created_at = datetime.now(timezone.utc).isoformat()

    with sqlite3.connect(args.out) as conn:
        create_schema(conn)
        conn.executemany(
            """
            INSERT INTO company_directory (
              lookup_slot, phone_number_masked, phone_number_sha256,
              company_code, company_name, registry_status,
              registry_version, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    entry.lookup_slot,
                    mask_phone(entry.phone_number),
                    phone_hash(entry.phone_number),
                    entry.company_code,
                    entry.company_name,
                    entry.registry_status,
                    "synthetic-v1",
                    created_at,
                )
                for entry in DIRECTORY_ENTRIES
            ],
        )
        conn.commit()


def write_client_inputs(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["phone_number"])
        for entry in DIRECTORY_ENTRIES[1:]:
            writer.writerow([entry.phone_number])


def main() -> None:
    args = parse_args()
    build_database(args)
    if args.client_inputs is not None:
        write_client_inputs(args.client_inputs)

    print(f"wrote database: {args.out}")
    if args.client_inputs is not None:
        print(f"wrote client inputs: {args.client_inputs}")


if __name__ == "__main__":
    main()
