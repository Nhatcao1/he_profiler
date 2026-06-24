#!/usr/bin/env python3
"""Build a tiny phone-prefix organization database for the BinFHE LUT demo.

This is synthetic demo data. The prefix labels are human-readable examples, not
an authoritative telecom registry.
"""

from __future__ import annotations

import argparse
import csv
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class PrefixRule:
    prefix_code: int
    prefix_label: str
    organization_code: int
    organization_name: str


PREFIX_RULES = [
    PrefixRule(0, "unknown", 0, "Unknown"),
    PrefixRule(1, "096", 1, "Viettel"),
    PrefixRule(2, "097", 1, "Viettel"),
    PrefixRule(3, "098", 1, "Viettel"),
    PrefixRule(4, "086", 1, "Viettel"),
    PrefixRule(5, "091", 2, "VNPT/VinaPhone"),
    PrefixRule(6, "094", 2, "VNPT/VinaPhone"),
    PrefixRule(7, "088", 2, "VNPT/VinaPhone"),
    PrefixRule(8, "090", 3, "MobiFone"),
    PrefixRule(9, "093", 3, "MobiFone"),
    PrefixRule(10, "089", 3, "MobiFone"),
    PrefixRule(11, "092", 4, "Vietnamobile"),
    PrefixRule(12, "099", 5, "Gmobile"),
    PrefixRule(13, "024", 6, "Landline"),
    PrefixRule(14, "028", 6, "Landline"),
    PrefixRule(15, "other_registered", 7, "Other Registered"),
]

PREFIX_TO_CODE = {
    rule.prefix_label: rule.prefix_code
    for rule in PREFIX_RULES
    if rule.prefix_label not in {"unknown", "other_registered"}
}

SAMPLE_PHONES = [
    "+84961234567",
    "+84971234567",
    "+84981234567",
    "+84861234567",
    "+84911234567",
    "+84941234567",
    "+84881234567",
    "+84901234567",
    "+84931234567",
    "+84891234567",
    "+84921234567",
    "+84991234567",
    "+84241234567",
    "+84281234567",
    "+84701234567",
    "+84123456789",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("db/phone_org.sqlite"))
    parser.add_argument("--client-inputs", type=Path, default=None)
    return parser.parse_args()


def normalize_phone(phone_number: str) -> str:
    return "".join(ch for ch in phone_number if ch.isdigit())


def phone_prefix(phone_number: str) -> str:
    digits = normalize_phone(phone_number)
    if digits.startswith("84") and len(digits) >= 4:
        return "0" + digits[2:4]
    if digits.startswith("0") and len(digits) >= 3:
        return digits[:3]
    return "unknown"


def phone_prefix_code(phone_number: str) -> int:
    prefix = phone_prefix(phone_number)
    return PREFIX_TO_CODE.get(prefix, 15 if prefix != "unknown" else 0)


def create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        DROP TABLE IF EXISTS organization_prefixes;

        CREATE TABLE organization_prefixes (
          prefix_code INTEGER PRIMARY KEY,
          prefix_label TEXT NOT NULL,
          organization_code INTEGER NOT NULL,
          organization_name TEXT NOT NULL,
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
            INSERT INTO organization_prefixes (
              prefix_code, prefix_label, organization_code,
              organization_name, registry_version, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    rule.prefix_code,
                    rule.prefix_label,
                    rule.organization_code,
                    rule.organization_name,
                    "synthetic-v1",
                    created_at,
                )
                for rule in PREFIX_RULES
            ],
        )
        conn.commit()


def write_client_inputs(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["phone_number", "phone_prefix_code"])
        for phone_number in SAMPLE_PHONES:
            writer.writerow([phone_number, phone_prefix_code(phone_number)])


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
