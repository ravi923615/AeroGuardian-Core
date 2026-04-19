# AeroGuardian-Core

A lightweight Python monitor that pulls live OpenSky Network state vectors and flags suspicious performance anomalies on commercial aircraft.

## What it does

- Polls `https://opensky-network.org/api/states/all` for live state vectors.
- Supports anonymous access and OAuth2 client-credentials authentication.
- Applies a `SPOOF_DETECTION` filter to commercial aircraft when:
  - absolute vertical rate exceeds `6000` feet per minute, or
  - ground speed changes by more than `50` knots across a single observed `2` second update while the aircraft shows no meaningful maneuver proxy.

## Important OpenSky constraints

- OpenSky's official REST docs currently describe `5` second time resolution for authenticated state-vector queries and `10` second resolution for anonymous queries.
- OpenSky state vectors do not expose aircraft pitch directly.

Because pitch is not available, the second rule uses an explicit proxy: the speed spike is only flagged when `true_track` and `vertical_rate` remain nearly unchanged between consecutive observations. That keeps the heuristic aligned with the intent of "without a pitch change" while staying within the published state-vector schema.

## Environment

Anonymous access works without credentials, but authenticated access is recommended for better resolution and higher quotas.

Supported environment variables:

- `OPENSKY_CLIENT_ID`
- `OPENSKY_CLIENT_SECRET`

The script also accepts the documentation-style fallbacks:

- `CLIENT_ID`
- `CLIENT_SECRET`

## Usage

Run the monitor as a module:

```bash
PYTHONPATH=src python3 -m aeroguardian.cli --interval 2 --iterations 5
```

Or use the helper script:

```bash
PYTHONPATH=src python3 scripts/pull_live_state_vectors.py --interval 2 --bbox 33.5 -119.0 35.0 -117.0
```

Example with authenticated access:

```bash
export OPENSKY_CLIENT_ID="your_client_id"
export OPENSKY_CLIENT_SECRET="your_client_secret"
PYTHONPATH=src python3 scripts/pull_live_state_vectors.py --interval 2 --iterations 10
```

## Output

Each polling cycle prints a compact snapshot summary followed by any `SPOOF_DETECTION` findings with the metrics that triggered them.

## References

- [OpenSky API landing page](https://opensky-network.org/data/api)
- [OpenSky REST API docs](https://openskynetwork.github.io/opensky-api/rest.html)
- [OpenSky FAQ authentication guidance](https://opensky-network.org/about/faq)

