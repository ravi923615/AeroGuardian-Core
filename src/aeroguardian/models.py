from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

COMMERCIAL_CATEGORIES = {4, 5, 6}


@dataclass(frozen=True)
class AircraftState:
    icao24: str
    callsign: Optional[str]
    origin_country: Optional[str]
    time_position: Optional[int]
    last_contact: Optional[int]
    longitude: Optional[float]
    latitude: Optional[float]
    baro_altitude_m: Optional[float]
    on_ground: Optional[bool]
    velocity_mps: Optional[float]
    true_track_deg: Optional[float]
    vertical_rate_mps: Optional[float]
    sensors: Optional[List[int]]
    geo_altitude_m: Optional[float]
    squawk: Optional[str]
    spi: Optional[bool]
    position_source: Optional[int]
    category: Optional[int] = None

    @classmethod
    def from_api_row(cls, row: List[Any]) -> "AircraftState":
        padded = list(row) + [None] * max(0, 18 - len(row))
        return cls(
            icao24=str(padded[0]).lower(),
            callsign=(padded[1] or "").strip() or None,
            origin_country=padded[2],
            time_position=padded[3],
            last_contact=padded[4],
            longitude=padded[5],
            latitude=padded[6],
            baro_altitude_m=padded[7],
            on_ground=padded[8],
            velocity_mps=padded[9],
            true_track_deg=padded[10],
            vertical_rate_mps=padded[11],
            sensors=padded[12],
            geo_altitude_m=padded[13],
            squawk=padded[14],
            spi=padded[15],
            position_source=padded[16],
            category=padded[17],
        )

    @property
    def velocity_knots(self) -> Optional[float]:
        if self.velocity_mps is None:
            return None
        return self.velocity_mps * 1.9438444924406

    @property
    def vertical_rate_fpm(self) -> Optional[float]:
        if self.vertical_rate_mps is None:
            return None
        return self.vertical_rate_mps * 196.85039370079

    @property
    def is_commercial(self) -> bool:
        return bool(
            self.category in COMMERCIAL_CATEGORIES
            and not self.on_ground
            and self.callsign
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Snapshot:
    time: int
    states: List[AircraftState]
    rate_limit_remaining: Optional[str] = None


@dataclass(frozen=True)
class DetectionEvent:
    code: str
    icao24: str
    callsign: Optional[str]
    observed_at: float
    reason: str
    metrics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

