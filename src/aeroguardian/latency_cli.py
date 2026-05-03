from __future__ import annotations

import argparse
import json
import sys
from typing import Optional, Sequence

from .latency_monitor import LatencyMonitor, LatencyMonitorConfig


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Query server-vs-sensor timing samples through pyopensky historical data "
            "and flag sustained jitter that may indicate a delay-injection path."
        )
    )
    parser.add_argument(
        "--start",
        required=True,
        help="Start of the query window in a pandas-compatible datetime format.",
    )
    parser.add_argument(
        "--stop",
        required=True,
        help="End of the query window in a pandas-compatible datetime format.",
    )
    parser.add_argument(
        "--sensor-name",
        help="Optional sensor name filter for the historical timing query.",
    )
    parser.add_argument(
        "--jitter-threshold-ms",
        type=float,
        default=200.0,
        help="Alert threshold for delay-jitter magnitude in milliseconds.",
    )
    parser.add_argument(
        "--consistency-count",
        type=int,
        default=3,
        help="Number of consecutive threshold exceedances required before alerting.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Optional row limit for the underlying historical query.",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Bypass pyopensky cached query results.",
    )
    parser.add_argument(
        "--compress-cache",
        action="store_true",
        help="Store pyopensky cache results in compressed parquet format.",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.consistency_count < 1:
        print("error: --consistency-count must be at least 1", file=sys.stderr)
        return 2

    monitor = LatencyMonitor(
        LatencyMonitorConfig(
            jitter_threshold_ms=args.jitter_threshold_ms,
            consistency_count=args.consistency_count,
        )
    )

    try:
        frame = monitor.fetch_server_sensor_times(
            start=args.start,
            stop=args.stop,
            sensor_name=args.sensor_name,
            cached=not args.no_cache,
            compress=args.compress_cache,
            limit=args.limit,
        )
        alerts = monitor.analyze_frame(frame)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    summary = {
        "sample_count": int(frame.shape[0]),
        "alert_count": len(alerts),
        "sensor_name": args.sensor_name,
        "jitter_threshold_ms": args.jitter_threshold_ms,
        "consistency_count": args.consistency_count,
    }
    print(json.dumps(summary, separators=(",", ":")))
    for alert in alerts:
        print(json.dumps(alert.to_dict(), separators=(",", ":")))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
