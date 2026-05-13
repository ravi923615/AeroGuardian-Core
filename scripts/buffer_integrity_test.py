#!/usr/bin/env python3
"""Buffer-integrity test runner for ARINC 424 navigation records.

This script is the CLI entry-point for the RTOS Memory Sandbox audit.
It exercises the ``buffer_validator`` module by feeding a mix of
valid-length and intentionally oversized records into the parser,
then prints a JSON audit summary of all security exceptions.

Usage::

    PYTHONPATH=src python3 scripts/buffer_integrity_test.py
    PYTHONPATH=src python3 scripts/buffer_integrity_test.py --verbose
    PYTHONPATH=src python3 scripts/buffer_integrity_test.py --record "CUSTOM_RECORD_DATA..."
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import List, Optional, Sequence

from aeroguardian.buffer_validator import (
    ARINC_424_RECORD_COLUMNS,
    ARINC_429_WORD_BYTES,
    run_buffer_integrity_audit,
)


# ---------------------------------------------------------------------------
# Built-in test vectors
# ---------------------------------------------------------------------------

def _build_test_vectors() -> List[str]:
    """Return a curated set of ARINC 424-style records for testing.

    Includes:
    1. A well-formed 132-character record (should pass).
    2. A record exactly at the boundary (should pass).
    3. A record 1 byte over the limit (should trigger SecurityException).
    4. A massively oversized record (stress test).
    5. A record with embedded null bytes (memory corruption probe).
    6. A record exceeding the 32-bit ARINC 429 word boundary when
       packed into individual 4-byte words.
    """
    # 1. Valid: exactly 132 characters, well-formed ARINC 424 layout
    valid_record = (
        "SUSAP"          # Record type + area code (5 chars)
        "KJFK  "         # Airport ICAO (6 chars)
        "13L  "          # Runway ident (5 chars)
        + "N40414300W073475400"   # Coordinates (19 chars)
        + " " * (ARINC_424_RECORD_COLUMNS - 35)  # Pad to 132
    )

    # 2. Boundary: exactly 132 characters
    boundary_record = "A" * ARINC_424_RECORD_COLUMNS

    # 3. Overflow by 1 byte
    overflow_one = "B" * (ARINC_424_RECORD_COLUMNS + 1)

    # 4. Massively oversized — simulates an injection payload
    overflow_massive = (
        "SUSAPKJFK  13L  "
        + "X" * 512  # deliberate overflow payload
    )

    # 5. Null-byte probe — attempts to trick C-string termination
    null_probe = (
        "SUSAP"
        "KLAX  "
        "25R  "
        + "\x00" * 20
        + "INJECTED_AFTER_NULL"
        + " " * 50
    )

    # 6. Crafted to produce individual ARINC 429 words > 4 bytes when
    #    the raw record is split naively (tests the word-level check).
    word_overflow = "W" * (ARINC_429_WORD_BYTES * 33 + 5)

    return [
        valid_record,
        boundary_record,
        overflow_one,
        overflow_massive,
        null_probe,
        word_overflow,
    ]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "RTOS Memory Sandbox — Buffer-integrity test for ARINC 424 "
            "navigation record parsing.  Feeds valid and intentionally "
            "oversized records into a fixed-width buffer parser and "
            "reports all security exceptions as structured JSON."
        ),
    )
    parser.add_argument(
        "--record",
        action="append",
        dest="records",
        metavar="RAW",
        help=(
            "Supply one or more custom raw records to parse.  May be "
            "repeated.  When omitted the built-in test vectors are used."
        ),
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable DEBUG-level logging for the buffer validator.",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        format="%(levelname)s  %(name)s  %(message)s",
        level=level,
    )

    records = args.records if args.records else _build_test_vectors()
    summary = run_buffer_integrity_audit(records)

    print(json.dumps(summary, indent=2))

    if summary["total_exceptions"] > 0:
        print(
            f"\n⚠  {summary['total_exceptions']} Security Exception(s) "
            f"detected across {summary['unsafe_records']} record(s).",
            file=sys.stderr,
        )
        return 1

    print("\n✓  All records within buffer limits.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
