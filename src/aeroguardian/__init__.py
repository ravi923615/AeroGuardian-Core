"""AeroGuardian core package."""

from importlib import import_module
from typing import Any, Dict, Tuple


_EXPORTS: Dict[str, Tuple[str, str]] = {
    "AircraftState": (".models", "AircraftState"),
    "Arinc424RecordParser": (".buffer_validator", "Arinc424RecordParser"),
    "DetectionEvent": (".models", "DetectionEvent"),
    "FilterConfig": (".detector", "FilterConfig"),
    "FixedWidthBuffer": (".buffer_validator", "FixedWidthBuffer"),
    "ImportAuditResult": (".import_sanitizer", "ImportAuditResult"),
    "LatencyAlert": (".latency_monitor", "LatencyAlert"),
    "LatencyMonitor": (".latency_monitor", "LatencyMonitor"),
    "LatencyMonitorConfig": (".latency_monitor", "LatencyMonitorConfig"),
    "LatencySample": (".latency_monitor", "LatencySample"),
    "MaximumPerformanceFilter": (".detector", "MaximumPerformanceFilter"),
    "OpenSkyClient": (".opensky_client", "OpenSkyClient"),
    "SandboxEvent": (".import_sanitizer", "SandboxEvent"),
    "SandboxSimulator": (".import_sanitizer", "SandboxSimulator"),
    "SecurityException": (".buffer_validator", "SecurityException"),
    "Snapshot": (".models", "Snapshot"),
    "TemporalAlert": (".temporal_validator", "TemporalAlert"),
    "TemporalSample": (".temporal_validator", "TemporalSample"),
    "TemporalValidator": (".temporal_validator", "TemporalValidator"),
    "TemporalValidatorConfig": (".temporal_validator", "TemporalValidatorConfig"),
    "audit_flight_plan_path": (".import_sanitizer", "audit_flight_plan_path"),
}

__all__ = list(_EXPORTS)


def __getattr__(name: str) -> Any:
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc

    value = getattr(import_module(module_name, __name__), attribute_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
