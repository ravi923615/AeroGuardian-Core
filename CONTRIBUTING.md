# Contributing to AeroGuardian-Core

Thanks for taking a look at AeroGuardian-Core.

## Where contributions help most

- Detection quality: reduce false positives and improve the anomaly logic.
- Data engineering: add replay datasets, storage, or streaming outputs.
- Developer experience: packaging, tests, linting, and local tooling.
- Documentation: demos, architecture notes, and aviation-domain explanations.

## Local setup

```bash
git clone https://github.com/ravi923615/AeroGuardian-Core.git
cd AeroGuardian-Core
PYTHONPATH=src python3 -m unittest discover -s tests
```

## Development notes

- The OpenSky polling client lives in `src/aeroguardian/opensky_client.py`.
- Detection logic lives in `src/aeroguardian/detector.py`.
- The CLI entry point lives in `src/aeroguardian/cli.py`.
- Tests live in `tests/test_detector.py`.

## Suggested contribution flow

1. Open an issue or describe the idea clearly in a pull request.
2. Keep changes scoped and explain the operational impact.
3. Add or update tests whenever the detection behavior changes.
4. Include sample output when you change user-facing monitoring behavior.

## Good first contributions

- Add a replay mode for saved snapshots.
- Improve commercial-aircraft filtering and categorization.
- Add structured export formats such as NDJSON or CSV.
- Add benchmarking around polling cadence and detection latency.
