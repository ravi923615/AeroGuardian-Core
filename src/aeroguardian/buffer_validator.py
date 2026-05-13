"""Memory-bound simulator for ARINC 424 navigation record parsing.

This module enforces ARINC 429 32-bit word constraints on incoming
navigation data, simulating the fixed-width buffer discipline used by
RTOS-hosted Flight Management Systems (FMS).  When a record or data word
exceeds the expected width, a structured ``SecurityException`` event is
logged instead of allowing an unchecked write — the same behaviour a
hardened avionics parser should exhibit.

Reference widths
~~~~~~~~~~~~~~~~
* **ARINC 429 data word**: 32 bits (4 bytes).
* **ARINC 424 fixed-column record**: 132 characters (one record per line
  in the standard supplement file format).
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

logger = logging.getLogger("aeroguardian.buffer_validator")

# ---------------------------------------------------------------------------
# Constants — ARINC 424 / 429 width limits
# ---------------------------------------------------------------------------

ARINC_429_WORD_BITS: int = 32
"""ARINC 429 defines a 32-bit data word."""

ARINC_429_WORD_BYTES: int = ARINC_429_WORD_BITS // 8  # 4
"""Byte-level representation of one ARINC 429 word."""

ARINC_424_RECORD_COLUMNS: int = 132
"""Standard ARINC 424 supplement record width (characters per line)."""


# ---------------------------------------------------------------------------
# Structured result / event types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SecurityException:
    """Emitted when an input violates the fixed-width buffer boundary.

    Mirrors the ``DetectionEvent`` / ``SandboxEvent`` pattern used
    elsewhere in AeroGuardian-Core.
    """

    code: str
    observed_at: str
    field_name: str
    input_length: int
    buffer_limit: int
    overflow_bytes: int
    reason: str
    severity: str = "CRITICAL"
    raw_excerpt: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ParsedNavRecord:
    """Result of successfully parsing an ARINC 424 navigation record."""

    record_type: str
    airport_ident: str
    runway_ident: str
    raw_record: str
    word_count: int
    is_safe: bool = True
    exceptions: List[SecurityException] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result["exceptions"] = [e for e in result["exceptions"]]
        return result


# ---------------------------------------------------------------------------
# Fixed-width buffer
# ---------------------------------------------------------------------------

class FixedWidthBuffer:
    """Simulates an RTOS fixed-width memory buffer.

    Writes that would exceed ``capacity`` are rejected and a
    ``SecurityException`` is recorded rather than silently truncating
    or (worse) overflowing into adjacent memory.
    """

    def __init__(self, capacity: int) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be a positive integer")
        self._capacity = capacity
        self._data = bytearray(capacity)
        self._write_pos = 0
        self._exceptions: List[SecurityException] = []

    # -- properties ---------------------------------------------------------

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def bytes_used(self) -> int:
        return self._write_pos

    @property
    def bytes_remaining(self) -> int:
        return self._capacity - self._write_pos

    @property
    def exceptions(self) -> List[SecurityException]:
        return list(self._exceptions)

    # -- operations ---------------------------------------------------------

    def write(self, payload: bytes, *, field_name: str = "unknown") -> bool:
        """Attempt to write *payload* into the buffer.

        Returns ``True`` when the write succeeds and ``False`` when the
        payload would overflow the buffer.  In the overflow case a
        ``SecurityException`` is appended and the buffer is **not**
        modified — matching defensive RTOS behaviour.
        """
        if len(payload) > self.bytes_remaining:
            exc = SecurityException(
                code="BUFFER_OVERFLOW_BLOCKED",
                observed_at=datetime.now(timezone.utc).isoformat(),
                field_name=field_name,
                input_length=len(payload),
                buffer_limit=self._capacity,
                overflow_bytes=len(payload) - self.bytes_remaining,
                reason=(
                    f"Write of {len(payload)} bytes into field "
                    f"'{field_name}' would exceed the "
                    f"{self._capacity}-byte fixed-width buffer by "
                    f"{len(payload) - self.bytes_remaining} bytes."
                ),
                raw_excerpt=payload[:64].hex(),
            )
            self._exceptions.append(exc)
            logger.warning(
                "SecurityException — %s: %s", exc.code, exc.reason,
            )
            return False

        end = self._write_pos + len(payload)
        self._data[self._write_pos:end] = payload
        self._write_pos = end
        return True

    def read(self) -> bytes:
        """Return the buffer contents written so far."""
        return bytes(self._data[: self._write_pos])

    def reset(self) -> None:
        """Clear the buffer without deallocating (simulates RTOS reuse)."""
        self._data[:] = b"\x00" * self._capacity
        self._write_pos = 0


# ---------------------------------------------------------------------------
# ARINC 429 word validator
# ---------------------------------------------------------------------------

def validate_arinc429_word(
    raw: bytes,
    *,
    field_name: str = "ARINC429_WORD",
) -> Optional[SecurityException]:
    """Return a ``SecurityException`` if *raw* exceeds the 32-bit word
    width, otherwise return ``None``.
    """
    if len(raw) <= ARINC_429_WORD_BYTES:
        return None

    exc = SecurityException(
        code="ARINC429_WORD_OVERFLOW",
        observed_at=datetime.now(timezone.utc).isoformat(),
        field_name=field_name,
        input_length=len(raw),
        buffer_limit=ARINC_429_WORD_BYTES,
        overflow_bytes=len(raw) - ARINC_429_WORD_BYTES,
        reason=(
            f"ARINC 429 word '{field_name}' is {len(raw)} bytes; "
            f"the standard mandates a maximum of "
            f"{ARINC_429_WORD_BYTES} bytes (32 bits).  "
            f"Overflow of {len(raw) - ARINC_429_WORD_BYTES} bytes "
            f"rejected to prevent memory corruption."
        ),
        raw_excerpt=raw[:64].hex(),
    )
    logger.warning("SecurityException — %s: %s", exc.code, exc.reason)
    return exc


# ---------------------------------------------------------------------------
# ARINC 424 record parser
# ---------------------------------------------------------------------------

class Arinc424RecordParser:
    """Parse fixed-column ARINC 424 navigation records into a
    ``ParsedNavRecord``, enforcing buffer-width constraints at every
    stage.

    The parser uses a ``FixedWidthBuffer`` internally so that any
    field whose encoded length exceeds the remaining buffer capacity is
    caught and logged as a ``SecurityException`` rather than crashing.

    Column layout (simplified for simulation purposes)::

        Columns   1 –   4 : Record type   (4 chars)
        Columns   5 –  10 : Airport ICAO   (6 chars)
        Columns  11 –  15 : Runway ident   (5 chars)
        Columns  16 – 132 : Remaining data (117 chars, padded)
    """

    FIELD_SPEC: List[tuple] = [
        # (field_name, start_col, width)
        ("record_type",  0,   4),
        ("airport_ident", 4,  6),
        ("runway_ident", 10,  5),
        ("nav_data",     15, 117),
    ]

    def __init__(self, *, strict: bool = True) -> None:
        self._strict = strict

    def parse(self, raw_record: str) -> ParsedNavRecord:
        """Parse a single ARINC 424 record line.

        If the record exceeds ``ARINC_424_RECORD_COLUMNS`` characters,
        a ``SecurityException`` is raised (in strict mode) or logged.
        Individual 32-bit word payloads within the record are also
        validated against the ARINC 429 word-width limit.
        """
        exceptions: List[SecurityException] = []
        encoded = raw_record.encode("utf-8", errors="replace")

        # -- record-level overflow check --
        if len(encoded) > ARINC_424_RECORD_COLUMNS:
            exc = SecurityException(
                code="ARINC424_RECORD_OVERFLOW",
                observed_at=datetime.now(timezone.utc).isoformat(),
                field_name="raw_record",
                input_length=len(encoded),
                buffer_limit=ARINC_424_RECORD_COLUMNS,
                overflow_bytes=len(encoded) - ARINC_424_RECORD_COLUMNS,
                reason=(
                    f"ARINC 424 record is {len(encoded)} bytes; "
                    f"the fixed-column standard allows a maximum of "
                    f"{ARINC_424_RECORD_COLUMNS}.  Excess of "
                    f"{len(encoded) - ARINC_424_RECORD_COLUMNS} bytes "
                    f"rejected."
                ),
                raw_excerpt=encoded[:64].hex(),
            )
            exceptions.append(exc)
            logger.warning(
                "SecurityException — %s: %s", exc.code, exc.reason,
            )

        # -- field-level extraction via fixed-width buffer --
        buf = FixedWidthBuffer(ARINC_424_RECORD_COLUMNS)
        fields: Dict[str, str] = {}

        for field_name, start, width in self.FIELD_SPEC:
            chunk = encoded[start: start + width]
            ok = buf.write(chunk, field_name=field_name)
            if ok:
                fields[field_name] = chunk.decode(
                    "utf-8", errors="replace"
                ).strip()
            else:
                fields[field_name] = ""
                exceptions.extend(buf.exceptions[-1:])

        # -- simulate ARINC 429 word packing --
        # Split the entire record into 4-byte words and validate each.
        word_count = 0
        for offset in range(0, len(encoded), ARINC_429_WORD_BYTES):
            word = encoded[offset: offset + ARINC_429_WORD_BYTES]
            word_exc = validate_arinc429_word(
                word,
                field_name=f"WORD_{word_count}",
            )
            if word_exc is not None:
                exceptions.append(word_exc)
            word_count += 1

        return ParsedNavRecord(
            record_type=fields.get("record_type", ""),
            airport_ident=fields.get("airport_ident", ""),
            runway_ident=fields.get("runway_ident", ""),
            raw_record=raw_record,
            word_count=word_count,
            is_safe=len(exceptions) == 0,
            exceptions=exceptions,
        )


# ---------------------------------------------------------------------------
# Convenience runner
# ---------------------------------------------------------------------------

def run_buffer_integrity_audit(
    records: Sequence[str],
) -> Dict[str, Any]:
    """Run the full buffer-integrity audit over a list of raw records.

    Returns a JSON-serialisable summary dict.
    """
    parser = Arinc424RecordParser()
    results: List[Dict[str, Any]] = []
    all_exceptions: List[Dict[str, Any]] = []

    for idx, record in enumerate(records):
        parsed = parser.parse(record)
        entry: Dict[str, Any] = {
            "index": idx,
            "record_type": parsed.record_type,
            "airport_ident": parsed.airport_ident,
            "runway_ident": parsed.runway_ident,
            "word_count": parsed.word_count,
            "is_safe": parsed.is_safe,
            "exception_count": len(parsed.exceptions),
        }
        results.append(entry)
        for exc in parsed.exceptions:
            enriched = exc.to_dict()
            enriched["record_index"] = idx
            all_exceptions.append(enriched)

    return {
        "total_records": len(records),
        "safe_records": sum(1 for r in results if r["is_safe"]),
        "unsafe_records": sum(1 for r in results if not r["is_safe"]),
        "total_exceptions": len(all_exceptions),
        "records": results,
        "security_exceptions": all_exceptions,
    }
