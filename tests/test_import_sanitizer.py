from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from aeroguardian.import_sanitizer import SandboxSimulator, audit_flight_plan_path


class ImportSanitizerTests(unittest.TestCase):
    def test_safe_flight_plan_path_is_allowed(self) -> None:
        audit = audit_flight_plan_path("arrivals/KJFK_STAR.fpl")

        self.assertTrue(audit.is_safe)
        self.assertEqual(audit.normalized_path, "arrivals/KJFK_STAR.fpl")
        self.assertEqual(audit.reasons, [])

    def test_direct_parent_traversal_is_blocked(self) -> None:
        audit = audit_flight_plan_path("../etc/passwd")

        self.assertFalse(audit.is_safe)
        self.assertIn("path contains forbidden traversal markers", audit.reasons)
        self.assertIn("path escapes the flight_plans sandbox", audit.reasons)

    def test_percent_encoded_traversal_is_blocked(self) -> None:
        audit = audit_flight_plan_path("%2E%2E%2Fconfig/system.cfg")

        self.assertFalse(audit.is_safe)
        self.assertEqual(audit.decoded_path, "../config/system.cfg")
        self.assertIn("path contains forbidden traversal markers", audit.reasons)

    def test_double_encoded_traversal_is_blocked(self) -> None:
        audit = audit_flight_plan_path("%252e%252e%252fsecrets.txt")

        self.assertFalse(audit.is_safe)
        self.assertEqual(audit.decoded_path, "../secrets.txt")

    def test_sandbox_logs_and_blocks_outside_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            simulator = SandboxSimulator(tmpdir)

            event = simulator.write_text(
                "flight_importer.py",
                "../overwritten.cfg",
                "MALICIOUS",
            )

            log_path = Path(tmpdir) / "sandbox_audit.log"
            self.assertEqual(event.status, "blocked")
            self.assertTrue(log_path.exists())
            log_entry = json.loads(log_path.read_text(encoding="utf-8").strip())
            self.assertEqual(log_entry["status"], "blocked")
            self.assertIn("sandbox", log_entry["reason"])
            self.assertFalse((Path(tmpdir) / "flight_plans" / "overwritten.cfg").exists())

    def test_sandbox_allows_write_inside_flight_plans(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            simulator = SandboxSimulator(tmpdir)

            event = simulator.write_text(
                "flight_importer.py",
                "domestic/KSEA_KLAX.fpl",
                "ROUTE DATA",
            )

            destination = Path(tmpdir) / "flight_plans" / "domestic" / "KSEA_KLAX.fpl"
            self.assertEqual(event.status, "allowed")
            self.assertTrue(destination.exists())
            self.assertEqual(destination.read_text(encoding="utf-8"), "ROUTE DATA")


if __name__ == "__main__":
    unittest.main()
