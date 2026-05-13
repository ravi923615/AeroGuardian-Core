"""Test suite for the RTOS Memory Sandbox — buffer_validator module.

Each test intentionally feeds data that violates the ARINC 424 fixed-column
width (132 chars) or the ARINC 429 32-bit word size (4 bytes) and asserts
that a structured ``SecurityException`` is emitted rather than an uncontrolled
crash or silent truncation.
"""

from __future__ import annotations

import unittest

from aeroguardian.buffer_validator import (
    ARINC_424_RECORD_COLUMNS,
    ARINC_429_WORD_BYTES,
    Arinc424RecordParser,
    FixedWidthBuffer,
    SecurityException,
    run_buffer_integrity_audit,
    validate_arinc429_word,
)


class FixedWidthBufferTests(unittest.TestCase):
    """Low-level FixedWidthBuffer behaviour."""

    def test_write_within_capacity_succeeds(self) -> None:
        buf = FixedWidthBuffer(8)
        self.assertTrue(buf.write(b"\x01\x02\x03\x04", field_name="label"))
        self.assertEqual(buf.bytes_used, 4)
        self.assertEqual(buf.bytes_remaining, 4)
        self.assertEqual(buf.exceptions, [])

    def test_write_at_exact_capacity_succeeds(self) -> None:
        buf = FixedWidthBuffer(4)
        self.assertTrue(buf.write(b"ABCD", field_name="word"))
        self.assertEqual(buf.bytes_used, 4)
        self.assertEqual(buf.bytes_remaining, 0)

    def test_write_exceeding_capacity_is_rejected(self) -> None:
        buf = FixedWidthBuffer(4)
        self.assertFalse(buf.write(b"ABCDE", field_name="overflow"))
        self.assertEqual(buf.bytes_used, 0, "buffer must not be modified")
        self.assertEqual(len(buf.exceptions), 1)
        exc = buf.exceptions[0]
        self.assertEqual(exc.code, "BUFFER_OVERFLOW_BLOCKED")
        self.assertEqual(exc.input_length, 5)
        self.assertEqual(exc.buffer_limit, 4)
        self.assertEqual(exc.overflow_bytes, 1)

    def test_sequential_writes_fill_buffer(self) -> None:
        buf = FixedWidthBuffer(8)
        self.assertTrue(buf.write(b"AB", field_name="first"))
        self.assertTrue(buf.write(b"CD", field_name="second"))
        self.assertTrue(buf.write(b"EFGH", field_name="third"))
        self.assertEqual(buf.bytes_used, 8)
        self.assertEqual(buf.read(), b"ABCDEFGH")

    def test_overflow_after_partial_fill(self) -> None:
        buf = FixedWidthBuffer(6)
        self.assertTrue(buf.write(b"ABC", field_name="a"))
        self.assertFalse(buf.write(b"DEFGH", field_name="b"))
        self.assertEqual(buf.bytes_used, 3, "only first write persists")
        self.assertEqual(len(buf.exceptions), 1)

    def test_reset_clears_buffer(self) -> None:
        buf = FixedWidthBuffer(4)
        buf.write(b"AAAA", field_name="x")
        buf.reset()
        self.assertEqual(buf.bytes_used, 0)
        self.assertEqual(buf.read(), b"")

    def test_zero_capacity_raises(self) -> None:
        with self.assertRaises(ValueError):
            FixedWidthBuffer(0)

    def test_negative_capacity_raises(self) -> None:
        with self.assertRaises(ValueError):
            FixedWidthBuffer(-1)

    def test_massive_overflow_logs_correct_delta(self) -> None:
        buf = FixedWidthBuffer(4)
        payload = b"X" * 1024
        self.assertFalse(buf.write(payload, field_name="huge"))
        exc = buf.exceptions[0]
        self.assertEqual(exc.overflow_bytes, 1020)
        self.assertIn("1024 bytes", exc.reason)


class Arinc429WordValidationTests(unittest.TestCase):
    """Word-level checks against the 32-bit boundary."""

    def test_valid_4_byte_word_passes(self) -> None:
        self.assertIsNone(validate_arinc429_word(b"\xFF\xAB\xCD\x01"))

    def test_shorter_word_passes(self) -> None:
        self.assertIsNone(validate_arinc429_word(b"\x01\x02"))

    def test_empty_word_passes(self) -> None:
        self.assertIsNone(validate_arinc429_word(b""))

    def test_5_byte_word_triggers_exception(self) -> None:
        exc = validate_arinc429_word(b"\x01\x02\x03\x04\x05")
        self.assertIsNotNone(exc)
        self.assertEqual(exc.code, "ARINC429_WORD_OVERFLOW")
        self.assertEqual(exc.overflow_bytes, 1)

    def test_large_word_overflow(self) -> None:
        word = b"A" * 64
        exc = validate_arinc429_word(word, field_name="BIG_WORD")
        self.assertIsNotNone(exc)
        self.assertEqual(exc.input_length, 64)
        self.assertEqual(exc.overflow_bytes, 60)
        self.assertEqual(exc.field_name, "BIG_WORD")


class Arinc424RecordParserTests(unittest.TestCase):
    """Record-level parsing with overflow detection."""

    def setUp(self) -> None:
        self.parser = Arinc424RecordParser()

    def _make_valid_record(self) -> str:
        """Return a well-formed 132-character ARINC 424 record."""
        return (
            "SUSAP"
            "KJFK  "
            "13L  "
            + " " * (ARINC_424_RECORD_COLUMNS - 16)
        )

    # -- valid records --

    def test_valid_record_parses_cleanly(self) -> None:
        record = self._make_valid_record()
        self.assertEqual(len(record), ARINC_424_RECORD_COLUMNS)
        result = self.parser.parse(record)
        self.assertTrue(result.is_safe)
        self.assertEqual(result.exceptions, [])
        self.assertEqual(result.record_type, "SUSA")
        self.assertEqual(result.airport_ident, "PKJFK")

    def test_exact_boundary_record(self) -> None:
        record = "A" * ARINC_424_RECORD_COLUMNS
        result = self.parser.parse(record)
        self.assertTrue(result.is_safe)

    # -- overflow records --

    def test_one_byte_overflow_triggers_security_exception(self) -> None:
        record = "B" * (ARINC_424_RECORD_COLUMNS + 1)
        result = self.parser.parse(record)
        self.assertFalse(result.is_safe)
        overflow_exc = [
            e for e in result.exceptions
            if e.code == "ARINC424_RECORD_OVERFLOW"
        ]
        self.assertGreaterEqual(len(overflow_exc), 1)
        self.assertEqual(overflow_exc[0].overflow_bytes, 1)

    def test_massive_overflow_does_not_crash(self) -> None:
        """Feed a 1 KB payload — the parser must NOT crash."""
        record = "X" * 1024
        result = self.parser.parse(record)
        self.assertFalse(result.is_safe)
        self.assertGreater(len(result.exceptions), 0)
        # Verify we get a record-level overflow
        codes = {e.code for e in result.exceptions}
        self.assertIn("ARINC424_RECORD_OVERFLOW", codes)

    def test_injection_payload_blocked(self) -> None:
        """Simulates a crafted injection string > 132 chars."""
        payload = "SUSAPKJFK  13L  " + "\x41" * 500
        result = self.parser.parse(payload)
        self.assertFalse(result.is_safe)

    def test_null_byte_probe(self) -> None:
        """Null bytes embedded in the record should not cause a crash."""
        record = (
            "SUSAP"
            "KLAX  "
            "25R  "
            + "\x00" * 20
            + "Z" * (ARINC_424_RECORD_COLUMNS - 36)
        )
        # Should parse without raising; safety depends on total length
        result = self.parser.parse(record)
        self.assertIsNotNone(result)

    def test_word_count_is_correct(self) -> None:
        record = self._make_valid_record()
        result = self.parser.parse(record)
        expected_words = (ARINC_424_RECORD_COLUMNS + ARINC_429_WORD_BYTES - 1) // ARINC_429_WORD_BYTES
        self.assertEqual(result.word_count, expected_words)


class Arinc429OverflowStressTests(unittest.TestCase):
    """Intentionally feed strings longer than the 32-bit word format.

    This is the 'Advanced Twist' from the task specification.
    """

    def setUp(self) -> None:
        self.parser = Arinc424RecordParser()

    def test_oversized_word_in_record_generates_exception(self) -> None:
        """A record whose raw bytes, when chunked into 4-byte words,
        produces at least one word > 4 bytes should still be handled
        gracefully (the word-level validator slices, so individual
        words won't exceed 4 bytes — but the *record* overflow is
        caught).
        """
        oversized = "D" * (ARINC_429_WORD_BYTES * 40)  # 160 bytes
        result = self.parser.parse(oversized)
        self.assertFalse(result.is_safe)
        self.assertGreater(len(result.exceptions), 0)

    def test_raw_word_bytes_exceed_32_bits(self) -> None:
        """Directly test a single word that exceeds 4 bytes."""
        word_5_bytes = b"\xFF\xFE\xFD\xFC\xFB"
        exc = validate_arinc429_word(word_5_bytes)
        self.assertIsNotNone(exc)
        self.assertEqual(exc.code, "ARINC429_WORD_OVERFLOW")
        self.assertEqual(exc.overflow_bytes, 1)
        self.assertEqual(exc.severity, "CRITICAL")

    def test_double_width_word(self) -> None:
        """8-byte word — exactly double the ARINC 429 limit."""
        word_8_bytes = b"\xAA" * 8
        exc = validate_arinc429_word(word_8_bytes, field_name="DOUBLE_WORD")
        self.assertIsNotNone(exc)
        self.assertEqual(exc.overflow_bytes, 4)
        self.assertIn("DOUBLE_WORD", exc.reason)

    def test_hundred_byte_word(self) -> None:
        """100-byte word — extreme overflow."""
        word = b"\xBB" * 100
        exc = validate_arinc429_word(word)
        self.assertIsNotNone(exc)
        self.assertEqual(exc.overflow_bytes, 96)


class AuditRunnerTests(unittest.TestCase):
    """Integration tests for ``run_buffer_integrity_audit``."""

    def test_all_valid_records(self) -> None:
        records = ["A" * ARINC_424_RECORD_COLUMNS] * 3
        summary = run_buffer_integrity_audit(records)
        self.assertEqual(summary["total_records"], 3)
        self.assertEqual(summary["safe_records"], 3)
        self.assertEqual(summary["unsafe_records"], 0)
        self.assertEqual(summary["total_exceptions"], 0)

    def test_mixed_records(self) -> None:
        records = [
            "A" * ARINC_424_RECORD_COLUMNS,           # safe
            "B" * (ARINC_424_RECORD_COLUMNS + 10),     # unsafe
        ]
        summary = run_buffer_integrity_audit(records)
        self.assertEqual(summary["total_records"], 2)
        self.assertEqual(summary["safe_records"], 1)
        self.assertGreaterEqual(summary["unsafe_records"], 1)
        self.assertGreater(summary["total_exceptions"], 0)

    def test_empty_input(self) -> None:
        summary = run_buffer_integrity_audit([])
        self.assertEqual(summary["total_records"], 0)
        self.assertEqual(summary["total_exceptions"], 0)

    def test_exception_has_record_index(self) -> None:
        records = ["Z" * (ARINC_424_RECORD_COLUMNS + 5)]
        summary = run_buffer_integrity_audit(records)
        for exc in summary["security_exceptions"]:
            self.assertIn("record_index", exc)
            self.assertEqual(exc["record_index"], 0)


if __name__ == "__main__":
    unittest.main()
