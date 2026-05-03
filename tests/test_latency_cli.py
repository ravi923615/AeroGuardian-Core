from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

import pandas as pd

from aeroguardian.latency_cli import main
from aeroguardian.latency_monitor import LatencyAlert


class LatencyCliTests(unittest.TestCase):
    def test_main_emits_summary_and_alerts(self) -> None:
        frame = pd.DataFrame(
            [
                {
                    "time_at_server": pd.Timestamp("2025-01-01T00:00:00Z"),
                    "time_at_sensor": pd.Timestamp("2025-01-01T00:00:00Z"),
                    "sensor_name": "RX-1",
                },
                {
                    "time_at_server": pd.Timestamp("2025-01-01T00:00:01Z"),
                    "time_at_sensor": pd.Timestamp("2025-01-01T00:00:00.4Z"),
                    "sensor_name": "RX-1",
                },
            ]
        )
        alerts = [
            LatencyAlert(
                code="MITM_DELAY_ATTACK",
                observed_at=pd.Timestamp("2025-01-01T00:00:01Z"),
                reason="timing anomaly",
                metrics={"jitter_ms": 600.0},
            )
        ]

        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch("aeroguardian.latency_cli.LatencyMonitor") as monitor_cls:
            monitor = monitor_cls.return_value
            monitor.fetch_server_sensor_times.return_value = frame
            monitor.analyze_frame.return_value = alerts

            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(
                    [
                        "--start",
                        "2025-01-01T00:00:00Z",
                        "--stop",
                        "2025-01-01T00:05:00Z",
                        "--sensor-name",
                        "RX-1",
                    ]
                )

        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr.getvalue(), "")

        lines = stdout.getvalue().strip().splitlines()
        self.assertEqual(len(lines), 2)
        summary = json.loads(lines[0])
        alert = json.loads(lines[1])
        self.assertEqual(summary["sample_count"], 2)
        self.assertEqual(summary["alert_count"], 1)
        self.assertEqual(summary["sensor_name"], "RX-1")
        self.assertEqual(alert["code"], "MITM_DELAY_ATTACK")

    def test_main_validates_consistency_count(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = main(
                [
                    "--start",
                    "2025-01-01T00:00:00Z",
                    "--stop",
                    "2025-01-01T00:05:00Z",
                    "--consistency-count",
                    "0",
                ]
            )

        self.assertEqual(exit_code, 2)
        self.assertIn("--consistency-count must be at least 1", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
