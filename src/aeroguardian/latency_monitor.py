from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence

import pandas as pd


@dataclass(frozen=True)
class LatencySample:
    time_at_server: pd.Timestamp
    time_at_sensor: pd.Timestamp
    sensor_name: Optional[str] = None
    message_timestamp: Optional[pd.Timestamp] = None
    raw_message: Optional[str] = None

    @property
    def delay_ms(self) -> float:
        return (self.time_at_server - self.time_at_sensor).total_seconds() * 1000.0


@dataclass(frozen=True)
class LatencyAlert:
    code: str
    observed_at: pd.Timestamp
    reason: str
    metrics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["observed_at"] = self.observed_at.isoformat()
        return payload


@dataclass(frozen=True)
class LatencyMonitorConfig:
    jitter_threshold_ms: float = 200.0
    consistency_count: int = 3


class LatencyMonitor:
    """Detect suspicious timing jitter between sensor and server timestamps.

    The current pyopensky 2.16 public schema exposes exact ``timeatserver`` and
    ``timeatsensor`` columns on ``FlarmRaw``. Historical ADS-B raw tables expose
    ``mintime`` / ``maxtime`` instead, so this module uses the exact
    server-vs-sensor timestamps when available rather than silently treating the
    ADS-B timing bounds as identical semantics.
    """

    def __init__(self, config: Optional[LatencyMonitorConfig] = None) -> None:
        self.config = config or LatencyMonitorConfig()

    def fetch_server_sensor_times(
        self,
        start: str | float | int | datetime | pd.Timestamp,
        stop: str | float | int | datetime | pd.Timestamp,
        *,
        sensor_name: Optional[str] = None,
        cached: bool = True,
        compress: bool = False,
        limit: Optional[int] = None,
    ) -> pd.DataFrame:
        Trino, FlarmRaw, select = _load_pyopensky_trino()

        start_ts = pd.to_datetime(start, utc=True)
        stop_ts = pd.to_datetime(stop, utc=True)

        stmt = (
            select(
                FlarmRaw.timeatserver.label("time_at_server"),
                FlarmRaw.timeatsensor.label("time_at_sensor"),
                FlarmRaw.timestamp.label("message_timestamp"),
                FlarmRaw.sensorname.label("sensor_name"),
                FlarmRaw.rawmessage.label("raw_message"),
            )
            .where(
                FlarmRaw.timeatserver >= start_ts,
                FlarmRaw.timeatserver <= stop_ts,
                FlarmRaw.hour >= start_ts.floor("1h"),
                FlarmRaw.hour < stop_ts.ceil("1h"),
            )
            .order_by(FlarmRaw.timeatserver)
        )

        if sensor_name is not None:
            stmt = stmt.where(FlarmRaw.sensorname == sensor_name)

        if limit is not None:
            stmt = stmt.limit(limit)

        trino = Trino()
        result = trino.query(stmt, cached=cached, compress=compress)
        if result.shape[0] == 0:
            return result

        for column in ("time_at_server", "time_at_sensor", "message_timestamp"):
            result[column] = pd.to_datetime(result[column], utc=True)

        return result

    def analyze_frame(self, frame: pd.DataFrame) -> List[LatencyAlert]:
        if frame.empty:
            return []

        required_columns = {"time_at_server", "time_at_sensor"}
        missing_columns = required_columns - set(frame.columns)
        if missing_columns:
            raise ValueError(
                "frame is missing required columns: "
                + ", ".join(sorted(missing_columns))
            )

        normalized = frame.sort_values("time_at_server").reset_index(drop=True)
        samples = [
            LatencySample(
                time_at_server=pd.to_datetime(row["time_at_server"], utc=True),
                time_at_sensor=pd.to_datetime(row["time_at_sensor"], utc=True),
                sensor_name=row.get("sensor_name"),
                message_timestamp=(
                    pd.to_datetime(row["message_timestamp"], utc=True)
                    if row.get("message_timestamp") is not None
                    else None
                ),
                raw_message=row.get("raw_message"),
            )
            for row in normalized.to_dict(orient="records")
        ]
        return self.analyze_samples(samples)

    def analyze_samples(
        self,
        samples: Sequence[LatencySample],
    ) -> List[LatencyAlert]:
        if len(samples) < 2:
            return []

        alerts: List[LatencyAlert] = []
        alerts.extend(self._detect_out_of_order_samples(samples))
        consecutive_exceedances = 0

        for previous, current in zip(samples, samples[1:]):
            previous_delay = previous.delay_ms
            current_delay = current.delay_ms
            jitter_ms = abs(current_delay - previous_delay)

            if jitter_ms > self.config.jitter_threshold_ms:
                consecutive_exceedances += 1
            else:
                consecutive_exceedances = 0

            if consecutive_exceedances < self.config.consistency_count:
                continue

            alerts.append(
                LatencyAlert(
                    code="MITM_DELAY_ATTACK",
                    observed_at=current.time_at_server,
                    reason=(
                        "Sensor-to-server packet delay jitter exceeded the configured "
                        "threshold consistently, suggesting a potential delay injection path."
                    ),
                    metrics={
                        "sensor_name": current.sensor_name,
                        "current_delay_ms": round(current_delay, 3),
                        "previous_delay_ms": round(previous_delay, 3),
                        "jitter_ms": round(jitter_ms, 3),
                        "threshold_ms": self.config.jitter_threshold_ms,
                        "consecutive_exceedances": consecutive_exceedances,
                    },
                )
            )
            consecutive_exceedances = 0

        return alerts

    def _detect_out_of_order_samples(
        self,
        samples: Sequence[LatencySample],
    ) -> List[LatencyAlert]:
        alerts: List[LatencyAlert] = []

        for index, (previous, current) in enumerate(zip(samples, samples[1:]), start=1):
            previous_msg_ts = previous.message_timestamp or previous.time_at_sensor
            current_msg_ts = current.message_timestamp or current.time_at_sensor

            if current_msg_ts >= previous_msg_ts:
                continue

            inversion_ms = abs((previous_msg_ts - current_msg_ts).total_seconds() * 1000.0)
            alerts.append(
                LatencyAlert(
                    code="OUT_OF_ORDER_DATA",
                    observed_at=current.time_at_server,
                    reason=(
                        "Packet sequence moved backward in sensor/message time, "
                        "indicating late or out-of-order data arrival."
                    ),
                    metrics={
                        "sensor_name": current.sensor_name,
                        "sequence_index": index,
                        "previous_message_timestamp": previous_msg_ts.isoformat(),
                        "current_message_timestamp": current_msg_ts.isoformat(),
                        "timestamp_inversion_ms": round(inversion_ms, 3),
                    },
                )
            )

        return alerts


def _load_pyopensky_trino() -> tuple[Any, Any, Any]:
    try:
        from sqlalchemy import select
        from pyopensky.schema import FlarmRaw
        from pyopensky.trino import Trino
    except PermissionError as exc:
        raise RuntimeError(
            "pyopensky could not initialize its local configuration directory. "
            "Set XDG_CONFIG_HOME or HOME to a writable location before using the latency monitor."
        ) from exc
    except ImportError as exc:
        raise RuntimeError(
            "pyopensky with Trino support is required for latency monitoring. "
            "Install project dependencies before running this module."
        ) from exc

    return Trino, FlarmRaw, select
