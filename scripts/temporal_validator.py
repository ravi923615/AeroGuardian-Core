#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import sys

from aeroguardian.temporal_validator import TemporalValidator, TemporalValidatorConfig


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Validate temporal consistency between local system clock and "
            "message server timestamps to identify replay-like timing artifacts."
        )
    )
    parser.add_argument("--start", required=True, help="Start time for the pyopensky query.")
    parser.add_argument("--stop", required=True, help="Stop time for the pyopensky query.")
    parser.add_argument("--limit", type=int, help="Optional query row limit.")
    parser.add_argument(
        "--delta-drift-tolerance-ms",
        type=float,
        default=50.0,
        help="Allowed drift of Δt between adjacent samples before flagging instability.",
    )
    parser.add_argument(
        "--sawtooth-rise-threshold-ms",
        type=float,
        default=100.0,
        help="Minimum cumulative Δt rise used in sawtooth detection.",
    )
    parser.add_argument(
        "--sawtooth-drop-threshold-ms",
        type=float,
        default=180.0,
        help="Minimum Δt drop that completes a sawtooth cycle.",
    )
    parser.add_argument(
        "--min-sawtooth-cycles",
        type=int,
        default=2,
        help="Required sawtooth cycles before flagging replay behavior.",
    )
    parser.add_argument("--no-cache", action="store_true", help="Bypass pyopensky cache.")
    parser.add_argument(
        "--compress-cache",
        action="store_true",
        help="Store pyopensky cache in compressed parquet format.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    validator = TemporalValidator(
        TemporalValidatorConfig(
            delta_drift_tolerance_ms=args.delta_drift_tolerance_ms,
            sawtooth_rise_threshold_ms=args.sawtooth_rise_threshold_ms,
            sawtooth_drop_threshold_ms=args.sawtooth_drop_threshold_ms,
            min_sawtooth_cycles=args.min_sawtooth_cycles,
        )
    )

    try:
        frame = validator.fetch_last_contact_and_server_time(
            start=args.start,
            stop=args.stop,
            limit=args.limit,
            cached=not args.no_cache,
            compress=args.compress_cache,
        )
        alerts = validator.analyze_frame(frame)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    summary = {
        "sample_count": int(frame.shape[0]),
        "alert_count": len(alerts),
        "alert_code": "REPLAY_ATTACK",
        "delta_drift_tolerance_ms": args.delta_drift_tolerance_ms,
        "sawtooth_rise_threshold_ms": args.sawtooth_rise_threshold_ms,
        "sawtooth_drop_threshold_ms": args.sawtooth_drop_threshold_ms,
        "min_sawtooth_cycles": args.min_sawtooth_cycles,
    }
    print(json.dumps(summary, separators=(",", ":")))
    for alert in alerts:
        print(json.dumps(alert.to_dict(), separators=(",", ":")))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
