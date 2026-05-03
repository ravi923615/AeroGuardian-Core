from __future__ import annotations

import unittest

import pandas as pd

from aeroguardian.latency_monitor import (
    LatencyAlert,
    LatencyMonitor,
    LatencyMonitorConfig,
    LatencySample,
)


def make_sample(server_ms: int, sensor_ms: int, sensor_name: str = "RX-1") -> LatencySample:
    base = pd.Timestamp("2025-01-01T00:00:00Z")
    return LatencySample(
        time_at_server=base + pd.Timedelta(milliseconds=server_ms),
        time_at_sensor=base + pd.Timedelta(milliseconds=sensor_ms),
        sensor_name=sensor_name,
        message_timestamp=base + pd.Timedelta(milliseconds=sensor_ms),
        raw_message="8D40621D58C382D690C8AC2863A7",
    )


class LatencyMonitorTests(unittest.TestCase):
    def test_delay_ms_is_computed_from_sensor_and_server_times(self) -> None:
        sample = make_sample(server_ms=1_200, sensor_ms=1_000)
        self.assertEqual(sample.delay_ms, 200.0)

    def test_consistent_jitter_triggers_mitm_alert(self) -> None:
        monitor = LatencyMonitor(
            LatencyMonitorConfig(jitter_threshold_ms=200.0, consistency_count=3)
        )
        samples = [
            make_sample(1_000, 1_000),  # 0 ms
            make_sample(1_350, 1_000),  # 350 ms
            make_sample(1_100, 1_000),  # 100 ms
            make_sample(1_500, 1_000),  # 500 ms
            make_sample(1_200, 1_000),  # 200 ms
        ]

        alerts = monitor.analyze_samples(samples)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].code, "MITM_DELAY_ATTACK")
        self.assertEqual(alerts[0].metrics["consecutive_exceedances"], 3)
        self.assertEqual(alerts[0].metrics["threshold_ms"], 200.0)

    def test_inconsistent_spikes_do_not_trigger_alert(self) -> None:
        monitor = LatencyMonitor(
            LatencyMonitorConfig(jitter_threshold_ms=200.0, consistency_count=3)
        )
        samples = [
            make_sample(1_000, 1_000),  # 0 ms
            make_sample(1_250, 1_000),  # 250 ms
            make_sample(1_260, 1_000),  # 260 ms -> 10 ms jitter
            make_sample(1_520, 1_000),  # 520 ms -> 260 ms jitter
            make_sample(1_530, 1_000),  # 530 ms -> 10 ms jitter
        ]

        alerts = monitor.analyze_samples(samples)

        self.assertEqual(alerts, [])

    def test_analyze_frame_sorts_by_time_at_server(self) -> None:
        monitor = LatencyMonitor(
            LatencyMonitorConfig(jitter_threshold_ms=200.0, consistency_count=2)
        )
        base = pd.Timestamp("2025-01-01T00:00:00Z")
        frame = pd.DataFrame(
            [
                {
                    "time_at_server": base + pd.Timedelta(milliseconds=1_550),
                    "time_at_sensor": base + pd.Timedelta(milliseconds=1_000),
                    "sensor_name": "RX-1",
                },
                {
                    "time_at_server": base + pd.Timedelta(milliseconds=1_000),
                    "time_at_sensor": base + pd.Timedelta(milliseconds=1_000),
                    "sensor_name": "RX-1",
                },
                {
                    "time_at_server": base + pd.Timedelta(milliseconds=1_300),
                    "time_at_sensor": base + pd.Timedelta(milliseconds=1_000),
                    "sensor_name": "RX-1",
                },
            ]
        )

        alerts = monitor.analyze_frame(frame)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].metrics["current_delay_ms"], 550.0)

    def test_out_of_order_message_timestamp_triggers_alert(self) -> None:
        monitor = LatencyMonitor()
        base = pd.Timestamp("2025-01-01T00:00:00Z")
        samples = [
            LatencySample(
                time_at_server=base + pd.Timedelta(milliseconds=1_000),
                time_at_sensor=base + pd.Timedelta(milliseconds=1_000),
                sensor_name="RX-1",
                message_timestamp=base + pd.Timedelta(milliseconds=1_000),
            ),
            LatencySample(
                time_at_server=base + pd.Timedelta(milliseconds=1_200),
                time_at_sensor=base + pd.Timedelta(milliseconds=900),
                sensor_name="RX-1",
                message_timestamp=base + pd.Timedelta(milliseconds=900),
            ),
        ]

        alerts = monitor.analyze_samples(samples)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].code, "OUT_OF_ORDER_DATA")
        self.assertEqual(alerts[0].metrics["timestamp_inversion_ms"], 100.0)


if __name__ == "__main__":
    unittest.main()
