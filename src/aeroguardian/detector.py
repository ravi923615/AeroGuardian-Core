from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

from .models import AircraftState, DetectionEvent


@dataclass(frozen=True)
class FilterConfig:
    vertical_rate_limit_fpm: float = 6000.0
    speed_delta_limit_knots: float = 50.0
    update_window_seconds: float = 2.0
    pitch_proxy_vertical_rate_delta_fpm: float = 300.0
    pitch_proxy_track_delta_deg: float = 3.0


@dataclass
class _ObservedState:
    state: AircraftState
    observed_at: float


class MaximumPerformanceFilter:
    def __init__(self, config: Optional[FilterConfig] = None) -> None:
        self.config = config or FilterConfig()
        self._previous_by_aircraft: Dict[str, _ObservedState] = {}

    def evaluate(
        self,
        states: Iterable[AircraftState],
        observed_at: float,
    ) -> List[DetectionEvent]:
        detections: List[DetectionEvent] = []

        for state in states:
            previous = self._previous_by_aircraft.get(state.icao24)
            self._previous_by_aircraft[state.icao24] = _ObservedState(
                state=state,
                observed_at=observed_at,
            )

            if not state.is_commercial:
                continue

            vertical_rate = state.vertical_rate_fpm
            if vertical_rate is not None and abs(vertical_rate) > self.config.vertical_rate_limit_fpm:
                detections.append(
                    DetectionEvent(
                        code="SPOOF_DETECTION",
                        icao24=state.icao24,
                        callsign=state.callsign,
                        observed_at=observed_at,
                        reason="Commercial aircraft vertical rate exceeded maximum-performance threshold.",
                        metrics={
                            "vertical_rate_fpm": round(vertical_rate, 2),
                            "threshold_fpm": self.config.vertical_rate_limit_fpm,
                        },
                    )
                )

            if previous is None:
                continue

            speed_delta = _delta(state.velocity_knots, previous.state.velocity_knots)
            if speed_delta is None or speed_delta <= self.config.speed_delta_limit_knots:
                continue

            observed_delta = observed_at - previous.observed_at
            if observed_delta > self.config.update_window_seconds:
                continue

            if not _pitch_proxy_unchanged(
                previous.state,
                state,
                vertical_rate_delta_limit_fpm=self.config.pitch_proxy_vertical_rate_delta_fpm,
                track_delta_limit_deg=self.config.pitch_proxy_track_delta_deg,
            ):
                continue

            detections.append(
                DetectionEvent(
                    code="SPOOF_DETECTION",
                    icao24=state.icao24,
                    callsign=state.callsign,
                    observed_at=observed_at,
                    reason="Commercial aircraft ground speed changed abruptly without a matching maneuver proxy.",
                    metrics={
                        "ground_speed_delta_knots": round(speed_delta, 2),
                        "threshold_knots": self.config.speed_delta_limit_knots,
                        "observed_delta_seconds": round(observed_delta, 3),
                    },
                )
            )

        return detections


def _delta(current: Optional[float], previous: Optional[float]) -> Optional[float]:
    if current is None or previous is None:
        return None
    return abs(current - previous)


def _track_delta_deg(current: Optional[float], previous: Optional[float]) -> Optional[float]:
    if current is None or previous is None:
        return None
    delta = abs(current - previous) % 360.0
    return min(delta, 360.0 - delta)


def _pitch_proxy_unchanged(
    previous: AircraftState,
    current: AircraftState,
    vertical_rate_delta_limit_fpm: float,
    track_delta_limit_deg: float,
) -> bool:
    # OpenSky state vectors do not include pitch, so we approximate "no pitch change"
    # as nearly unchanged vertical-rate and track observations across consecutive samples.
    vertical_rate_delta = _delta(current.vertical_rate_fpm, previous.vertical_rate_fpm)
    track_delta = _track_delta_deg(current.true_track_deg, previous.true_track_deg)

    if vertical_rate_delta is None or track_delta is None:
        return False

    return (
        vertical_rate_delta <= vertical_rate_delta_limit_fpm
        and track_delta <= track_delta_limit_deg
    )
