#!/usr/bin/env python3
"""Build a tiny server-side risk assessment database for the BinFHE LUT demo."""

from __future__ import annotations

import argparse
import csv
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


HIGH_RISK_CHANNELS = {1, 4, 5, 8}
HIGH_RISK_PRODUCTS = {3, 12, 13, 14, 17}
HIGH_RISK_SEGMENTS = {5, 6, 7}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--transactions", type=Path, required=True)
    parser.add_argument("--customers", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=Path("db/risk_assessments.sqlite"))
    parser.add_argument("--client-inputs", type=Path, default=None)
    parser.add_argument("--limit", type=int, default=1000)
    return parser.parse_args()


def load_customers(path: Path) -> dict[int, dict[str, str]]:
    with path.open(newline="") as f:
        return {int(row["customer_id"]): row for row in csv.DictReader(f)}


def score_row(tx: dict[str, str], customer: dict[str, str]) -> int:
    amount = float(tx["amount"])
    risk_weight = float(customer["risk_weight"])
    channel_id = int(tx["channel_id"])
    product_id = int(tx["product_id"])
    segment_id = int(customer["segment_id"])

    score = 0
    if amount > 8000:
        score += 4
    elif amount > 5000:
        score += 2

    if risk_weight > 1.5:
        score += 4
    elif risk_weight > 1.0:
        score += 2

    if channel_id in HIGH_RISK_CHANNELS:
        score += 3
    if product_id in HIGH_RISK_PRODUCTS:
        score += 2
    if segment_id in HIGH_RISK_SEGMENTS:
        score += 1

    return min(max(score, 0), 15)


def create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        DROP TABLE IF EXISTS risk_assessments;

        CREATE TABLE risk_assessments (
          assessment_id INTEGER PRIMARY KEY,
          customer_id INTEGER NOT NULL,
          transaction_id INTEGER NOT NULL,

          amount REAL NOT NULL,
          channel_id INTEGER NOT NULL,
          product_id INTEGER NOT NULL,
          customer_risk_weight REAL NOT NULL,
          segment_id INTEGER NOT NULL,
          region_id INTEGER NOT NULL,

          base_risk_score INTEGER NOT NULL,
          base_risk_code INTEGER NOT NULL,

          model_version TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        """
    )


def build_database(args: argparse.Namespace) -> list[tuple[int, int]]:
    customers = load_customers(args.customers)
    args.out.parent.mkdir(parents=True, exist_ok=True)

    created_at = datetime.now(timezone.utc).isoformat()
    sample_inputs: list[tuple[int, int]] = []

    with sqlite3.connect(args.out) as conn, args.transactions.open(newline="") as f:
        create_schema(conn)
        reader = csv.DictReader(f)

        for index, tx in enumerate(reader, start=1):
            if args.limit and index > args.limit:
                break

            customer = customers[int(tx["customer_id"])]
            base_code = score_row(tx, customer)
            assessment_id = index

            conn.execute(
                """
                INSERT INTO risk_assessments (
                  assessment_id, customer_id, transaction_id,
                  amount, channel_id, product_id, customer_risk_weight,
                  segment_id, region_id, base_risk_score, base_risk_code,
                  model_version, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    assessment_id,
                    int(tx["customer_id"]),
                    int(tx["row_id"]),
                    float(tx["amount"]),
                    int(tx["channel_id"]),
                    int(tx["product_id"]),
                    float(customer["risk_weight"]),
                    int(customer["segment_id"]),
                    int(customer["region_id"]),
                    base_code,
                    base_code,
                    "rule-v1",
                    created_at,
                ),
            )

            if len(sample_inputs) < 16:
                # Private client/app signal bucket for this transaction.
                # Example meaning: device/session anomaly, retry pressure, or app-side warning.
                sample_inputs.append((assessment_id, (assessment_id * 5 + 3) % 16))

        conn.commit()

    return sample_inputs


def write_client_inputs(path: Path, rows: list[tuple[int, int]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["assessment_id", "client_signal_code"])
        writer.writerows(rows)


def main() -> None:
    args = parse_args()
    if args.limit <= 0:
        raise ValueError("--limit must be positive")

    sample_inputs = build_database(args)
    if args.client_inputs is not None:
        write_client_inputs(args.client_inputs, sample_inputs)

    print(f"wrote database: {args.out}")
    if args.client_inputs is not None:
        print(f"wrote client inputs: {args.client_inputs}")


if __name__ == "__main__":
    main()
