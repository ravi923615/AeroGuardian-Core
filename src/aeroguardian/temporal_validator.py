from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

import pandas as pd


@dataclass(frozen=True)
class TemporalSample:
    observed_at_system: pd.Timestamp
    time_at_server: pd.Timestamp
    last_contact: Optional[pd.Timestamp] = None
    icao24: Optional[str] = None
    callsign: Optional[str] = None

    @property
    def delta_t_ms(self) -> float:
        return (self.observed_at_system - self.time_at_server).total_seconds() * 1000.0


@dataclass(frozen=True)
class TemporalAlert:
    code: str
    observed_at: pd.Timestamp
    reason: str
    metrics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["observed_at"] = self.observed_at.isoformat()
        return payload


@dataclass(frozen=True)
class TemporalValidatorConfig:
    delta_drift_tolerance_ms: float = 50.0
    sawtooth_rise_threshold_ms: float = 100.0
    sawtooth_drop_threshold_ms: float = 180.0
    min_sawtooth_cycles: int = 2


class TemporalValidator:
    def __init__(self, config: Optional[TemporalValidatorConfig] = None) -> None:
        self.config = config or TemporalValidatorConfig()

    def fetch_last_contact_and_server_time(
        self,
        start: str | float | int | datetime | pd.Timestamp,
        stop: str | float | int | datetime | pd.Timestamp,
        *,
        limit: Optional[int] = None,
        cached: bool = True,
        compress: bool = False,
    ) -> pd.DataFrame:
        Trino, FlarmRaw, select = _load_pyopensky_trino()
        start_ts = pd.to_datetime(start, utc=True)
        stop_ts = pd.to_datetime(stop, utc=True)

        stmt = (
            select(
                FlarmRaw.timeatserver.label("time_at_server"),
                FlarmRaw.timestamp.label("last_contact"),
                FlarmRaw.icao24.label("icao24"),
                FlarmRaw.callsign.label("callsign"),
            )
            .where(
                FlarmRaw.timeatserver >= start_ts,
                FlarmRaw.timeatserver <= stop_ts,
                FlarmRaw.hour >= start_ts.floor("1h"),
                FlarmRaw.hour < stop_ts.ceil("1h"),
            )
            .order_by(FlarmRaw.timeatserver)
        )

        if limit is not None:
            stmt = stmt.limit(limit)

        trino = Trino()
        result = trino.query(stmt, cached=cached, compress=compress)
        if result.shape[0] == 0:
            return result

        result["time_at_server"] = pd.to_datetime(result["time_at_server"], utc=True)
        result["last_contact"] = pd.to_datetime(result["last_contact"], utc=True)
        return result

    def analyze_frame(
        self,
        frame: pd.DataFrame,
        *,
        observed_at_system: Optional[pd.Timestamp] = None,
    ) -> List[TemporalAlert]:
        if frame.empty:
            return []

        if "time_at_server" not in frame.columns:
            raise ValueError("frame is missing required column: time_at_server")

        now = observed_at_system or pd.Timestamp(datetime.now(timezone.utc))
        normalized = frame.sort_values("time_at_server").reset_index(drop=True)
        samples = [
            TemporalSample(
                observed_at_system=now,
                time_at_server=pd.to_datetime(row["time_at_server"], utc=True),
                last_contact=(
                    pd.to_datetime(row["last_contact"], utc=True)
                    if row.get("last_contact") is not None
                    else None
                ),
                icao24=row.get("icao24"),
                callsign=row.get("callsign"),
            )
            for row in normalized.to_dict(orient="records")
        ]
        return self.analyze_samples(samples)

    def analyze_samples(self, samples: Sequence[TemporalSample]) -> List[TemporalAlert]:
        if len(samples) < 3:
            return []

        deltas = [sample.delta_t_ms for sample in samples]
        diffs = [curr - prev for prev, curr in zip(deltas, deltas[1:])]
        alerts: List[TemporalAlert] = []

        max_drift = max(abs(value) for value in diffs)
        if max_drift > self.config.delta_drift_tolerance_ms:
            alerts.append(
                TemporalAlert(
                    code="REPLAY_ATTACK",
                    observed_at=samples[-1].observed_at_system,
                    reason=(
                        "System-clock vs message-server delta is not constant. "
                        "This timing instability can indicate replayed traffic."
                    ),
                    metrics={
                        "max_delta_drift_ms": round(max_drift, 3),
                        "drift_tolerance_ms": self.config.delta_drift_tolerance_ms,
                    },
                )
            )

        if self._has_sawtooth_pattern(diffs):
            alerts.append(
                TemporalAlert(
                    code="REPLAY_ATTACK",
                    observed_at=samples[-1].observed_at_system,
                    reason=(
                        "Delta-t shows a sawtooth rise-and-reset pattern, "
                        "consistent with delayed replay injection windows."
                    ),
                    metrics={
                        "sawtooth_rise_threshold_ms": self.config.sawtooth_rise_threshold_ms,
                        "sawtooth_drop_threshold_ms": self.config.sawtooth_drop_threshold_ms,
                        "min_sawtooth_cycles": self.config.min_sawtooth_cycles,
                    },
                )
            )

        return alerts

    def _has_sawtooth_pattern(self, diffs: Sequence[float]) -> bool:
        cycles = 0
        rise_accumulator = 0.0
        saw_rise = False

        for step in diffs:
            if step > 0:
                rise_accumulator += step
                if rise_accumulator >= self.config.sawtooth_rise_threshold_ms:
                    saw_rise = True
                continue

            if not saw_rise:
                rise_accumulator = max(0.0, rise_accumulator + step)
                continue

            if step <= -self.config.sawtooth_drop_threshold_ms:
                cycles += 1
                rise_accumulator = 0.0
                saw_rise = False
            else:
                rise_accumulator = max(0.0, rise_accumulator + step)

        return cycles >= self.config.min_sawtooth_cycles


def _load_pyopensky_trino() -> tuple[Any, Any, Any]:
    try:
        from sqlalchemy import select
        from pyopensky.schema import FlarmRaw
        from pyopensky.trino import Trino
    except PermissionError as exc:
        raise RuntimeError(
            "pyopensky could not initialize its local configuration directory. "
            "Set XDG_CONFIG_HOME or HOME to a writable location before using the temporal validator."
        ) from exc
    except ImportError as exc:
        raise RuntimeError(
            "pyopensky with Trino support is required for temporal validation. "
            "Install project dependencies before running this module."
        ) from exc

    return Trino, FlarmRaw, select
