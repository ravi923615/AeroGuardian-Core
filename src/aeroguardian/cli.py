from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Iterable, Optional, Sequence, Tuple

from .detector import MaximumPerformanceFilter
from .models import AircraftState, DetectionEvent, Snapshot
from .opensky_client import OpenSkyClient, OpenSkyError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Pull live OpenSky state vectors and flag spoof-like performance anomalies.",
    )
    parser.add_argument("--interval", type=float, default=2.0, help="Polling interval in seconds.")
    parser.add_argument("--iterations", type=int, default=0, help="Number of polling cycles. Zero means run forever.")
    parser.add_argument(
        "--icao24",
        action="append",
        default=[],
        help="Filter to one or more ICAO24 addresses. Repeat the flag to add multiple addresses.",
    )
    parser.add_argument(
        "--bbox",
        nargs=4,
        type=float,
        metavar=("LAMIN", "LOMIN", "LAMAX", "LOMAX"),
        help="Restrict the query to a latitude/longitude bounding box.",
    )
    parser.add_argument(
        "--no-extended",
        action="store_true",
        help="Skip the extended category field.",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    client = OpenSkyClient()
    detector = MaximumPerformanceFilter()

    recommended = client.recommended_resolution_seconds()
    if args.interval < recommended:
        print(
            f"warning: requested interval {args.interval}s is faster than the current OpenSky resolution "
            f"of about {recommended}s for this authentication mode.",
            file=sys.stderr,
        )

    iteration = 0
    try:
        while args.iterations == 0 or iteration < args.iterations:
            observed_at = time.time()
            snapshot = client.fetch_states(
                icao24=args.icao24,
                bbox=_coerce_bbox(args.bbox),
                extended=not args.no_extended,
            )
            detections = detector.evaluate(snapshot.states, observed_at=observed_at)
            _print_snapshot(snapshot)
            _print_detections(detections)
            iteration += 1
            if args.iterations and iteration >= args.iterations:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 130
    except OpenSkyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    return 0


def _coerce_bbox(raw_bbox: Optional[Sequence[float]]) -> Optional[Tuple[float, float, float, float]]:
    if not raw_bbox:
        return None
    return tuple(raw_bbox)  # type: ignore[return-value]


def _print_snapshot(snapshot: Snapshot) -> None:
    commercial_count = sum(1 for state in snapshot.states if state.is_commercial)
    message = {
        "snapshot_time": snapshot.time,
        "state_count": len(snapshot.states),
        "commercial_count": commercial_count,
        "rate_limit_remaining": snapshot.rate_limit_remaining,
    }
    print(json.dumps(message, separators=(",", ":")))


def _print_detections(detections: Iterable[DetectionEvent]) -> None:
    for detection in detections:
        print(json.dumps(detection.to_dict(), separators=(",", ":")))


if __name__ == "__main__":
    raise SystemExit(main())

