import unittest

from aeroguardian.detector import MaximumPerformanceFilter
from aeroguardian.models import AircraftState


def make_state(
    *,
    icao24: str = "abc123",
    callsign: str = "AAL123",
    velocity_knots: float = 430.0,
    vertical_rate_fpm: float = 0.0,
    true_track_deg: float = 90.0,
    category: int = 6,
    on_ground: bool = False,
) -> AircraftState:
    return AircraftState(
        icao24=icao24,
        callsign=callsign,
        origin_country="United States",
        time_position=1,
        last_contact=1,
        longitude=-73.0,
        latitude=40.0,
        baro_altitude_m=10000.0,
        on_ground=on_ground,
        velocity_mps=velocity_knots / 1.9438444924406,
        true_track_deg=true_track_deg,
        vertical_rate_mps=vertical_rate_fpm / 196.85039370079,
        sensors=None,
        geo_altitude_m=10020.0,
        squawk="1200",
        spi=False,
        position_source=0,
        category=category,
    )


class MaximumPerformanceFilterTests(unittest.TestCase):
    def test_flags_extreme_vertical_rate(self) -> None:
        detector = MaximumPerformanceFilter()
        detections = detector.evaluate(
            [make_state(vertical_rate_fpm=6500.0)],
            observed_at=100.0,
        )
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].code, "SPOOF_DETECTION")
        self.assertIn("vertical rate", detections[0].reason.lower())

    def test_flags_speed_spike_without_maneuver_proxy(self) -> None:
        detector = MaximumPerformanceFilter()
        detector.evaluate(
            [make_state(velocity_knots=420.0, vertical_rate_fpm=300.0, true_track_deg=91.0)],
            observed_at=100.0,
        )
        detections = detector.evaluate(
            [make_state(velocity_knots=480.5, vertical_rate_fpm=320.0, true_track_deg=92.0)],
            observed_at=101.9,
        )
        self.assertEqual(len(detections), 1)
        self.assertIn("ground speed", detections[0].reason.lower())

    def test_does_not_flag_speed_spike_when_aircraft_is_maneuvering(self) -> None:
        detector = MaximumPerformanceFilter()
        detector.evaluate(
            [make_state(velocity_knots=420.0, vertical_rate_fpm=300.0, true_track_deg=91.0)],
            observed_at=100.0,
        )
        detections = detector.evaluate(
            [make_state(velocity_knots=480.5, vertical_rate_fpm=1500.0, true_track_deg=110.0)],
            observed_at=101.9,
        )
        self.assertEqual(detections, [])

    def test_does_not_flag_non_commercial_aircraft(self) -> None:
        detector = MaximumPerformanceFilter()
        detections = detector.evaluate(
            [make_state(category=2, vertical_rate_fpm=8000.0)],
            observed_at=100.0,
        )
        self.assertEqual(detections, [])


if __name__ == "__main__":
    unittest.main()
