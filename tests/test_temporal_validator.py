from __future__ import annotations

import unittest

import pandas as pd

from aeroguardian.temporal_validator import TemporalSample, TemporalValidator


class TemporalValidatorTests(unittest.TestCase):
    def test_constant_delta_does_not_alert(self) -> None:
        validator = TemporalValidator()
        base_system = pd.Timestamp("2025-01-01T00:10:00Z")
        samples = [
            TemporalSample(
                observed_at_system=base_system,
                time_at_server=base_system - pd.Timedelta(milliseconds=1_000),
            ),
            TemporalSample(
                observed_at_system=base_system,
                time_at_server=base_system - pd.Timedelta(milliseconds=1_000),
            ),
            TemporalSample(
                observed_at_system=base_system,
                time_at_server=base_system - pd.Timedelta(milliseconds=1_000),
            ),
        ]
        self.assertEqual(validator.analyze_samples(samples), [])

    def test_non_constant_delta_is_flagged(self) -> None:
        validator = TemporalValidator()
        base_system = pd.Timestamp("2025-01-01T00:10:00Z")
        samples = [
            TemporalSample(observed_at_system=base_system, time_at_server=base_system - pd.Timedelta(milliseconds=1_000)),
            TemporalSample(observed_at_system=base_system, time_at_server=base_system - pd.Timedelta(milliseconds=900)),
            TemporalSample(observed_at_system=base_system, time_at_server=base_system - pd.Timedelta(milliseconds=1_150)),
        ]

        alerts = validator.analyze_samples(samples)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].code, "REPLAY_ATTACK")
        self.assertIn("max_delta_drift_ms", alerts[0].metrics)

    def test_sawtooth_pattern_is_flagged(self) -> None:
        validator = TemporalValidator()
        base_system = pd.Timestamp("2025-01-01T00:10:00Z")
        deltas_ms = [1000, 1150, 1320, 1080, 1240, 1420, 1180]
        samples = [
            TemporalSample(
                observed_at_system=base_system,
                time_at_server=base_system - pd.Timedelta(milliseconds=delta_ms),
            )
            for delta_ms in deltas_ms
        ]

        alerts = validator.analyze_samples(samples)

        sawtooth_alerts = [alert for alert in alerts if "sawtooth" in alert.reason.lower()]
        self.assertEqual(len(sawtooth_alerts), 1)


if __name__ == "__main__":
    unittest.main()
