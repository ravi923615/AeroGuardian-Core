from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import unquote


RAW_FORBIDDEN_MARKERS = (
    "../",
    "..\\",
    "%2e%2e%2f",
    "%2e%2e/",
    "%2e%2e%5c",
    "%252e%252e%252f",
    "%00",
)
DEFAULT_ALLOWED_DIRECTORY = "flight_plans"


@dataclass(frozen=True)
class ImportAuditResult:
    requested_path: str
    decoded_path: str
    normalized_path: str
    is_safe: bool
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SandboxEvent:
    observed_at: str
    script_name: str
    requested_path: str
    resolved_path: str
    allowed_root: str
    status: str
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def audit_flight_plan_path(file_path: str) -> ImportAuditResult:
    requested_path = file_path.strip()
    reasons: List[str] = []

    if not requested_path:
        return ImportAuditResult(
            requested_path=file_path,
            decoded_path="",
            normalized_path="",
            is_safe=False,
            reasons=["path is empty"],
        )

    lowered = requested_path.lower()
    decoded_path = _decode_repeatedly(requested_path)
    normalized_for_checks = decoded_path.replace("\\", "/")

    if any(marker in lowered for marker in RAW_FORBIDDEN_MARKERS):
        reasons.append("path contains forbidden traversal markers")

    if "\x00" in requested_path or "\x00" in decoded_path:
        reasons.append("path contains a null-byte terminator")

    if _looks_like_absolute_path(normalized_for_checks):
        reasons.append("absolute paths are not allowed")

    path_parts = [
        part
        for part in PurePosixPath(normalized_for_checks).parts
        if part not in ("", ".", "/")
    ]
    if any(part == ".." for part in path_parts):
        reasons.append("path escapes the flight_plans sandbox")

    normalized_parts = [part for part in path_parts if part != ".."]
    normalized_path = "/".join(normalized_parts)
    if not normalized_path:
        reasons.append("path must resolve to a file inside the sandbox")

    return ImportAuditResult(
        requested_path=file_path,
        decoded_path=normalized_for_checks,
        normalized_path=normalized_path,
        is_safe=not reasons,
        reasons=_deduplicate(reasons),
    )


class SandboxSimulator:
    def __init__(
        self,
        sandbox_root: str | Path,
        *,
        allowed_directory: str = DEFAULT_ALLOWED_DIRECTORY,
        log_path: str | Path | None = None,
    ) -> None:
        self.sandbox_root = Path(sandbox_root).resolve()
        self.allowed_directory = allowed_directory.strip("/\\") or DEFAULT_ALLOWED_DIRECTORY
        self.allowed_root = (self.sandbox_root / self.allowed_directory).resolve()
        self.allowed_root.mkdir(parents=True, exist_ok=True)
        self.log_path = Path(log_path).resolve() if log_path is not None else self.sandbox_root / "sandbox_audit.log"
        self.events: List[SandboxEvent] = []

    def write_text(
        self,
        script_name: str,
        requested_path: str,
        content: str,
        *,
        encoding: str = "utf-8",
    ) -> SandboxEvent:
        audit = audit_flight_plan_path(requested_path)
        destination = (self.allowed_root / audit.normalized_path).resolve()

        if not audit.is_safe:
            return self._record_event(
                script_name=script_name,
                requested_path=requested_path,
                resolved_path=str(destination),
                status="blocked",
                reason="; ".join(audit.reasons),
            )

        if not destination.is_relative_to(self.allowed_root):
            return self._record_event(
                script_name=script_name,
                requested_path=requested_path,
                resolved_path=str(destination),
                status="blocked",
                reason="write would escape the /flight_plans/ directory",
            )

        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding=encoding)
        return self._record_event(
            script_name=script_name,
            requested_path=requested_path,
            resolved_path=str(destination),
            status="allowed",
            reason="write kept inside the /flight_plans/ directory",
        )

    def export_log(self) -> List[Dict[str, Any]]:
        return [event.to_dict() for event in self.events]

    def _record_event(
        self,
        *,
        script_name: str,
        requested_path: str,
        resolved_path: str,
        status: str,
        reason: str,
    ) -> SandboxEvent:
        event = SandboxEvent(
            observed_at=datetime.now(timezone.utc).isoformat(),
            script_name=script_name,
            requested_path=requested_path,
            resolved_path=resolved_path,
            allowed_root=str(self.allowed_root),
            status=status,
            reason=reason,
        )
        self.events.append(event)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event.to_dict(), separators=(",", ":")) + "\n")
        return event


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Audit imported flight-plan paths for traversal indicators and optionally "
            "simulate a sandboxed write into /flight_plans/."
        )
    )
    parser.add_argument("flight_plan_path", help="Simulated imported flight-plan path.")
    parser.add_argument(
        "--script-name",
        default="flight_plan_importer.py",
        help="Name of the importing script for sandbox audit logging.",
    )
    parser.add_argument(
        "--sandbox-root",
        default=".",
        help="Root directory that contains the simulated /flight_plans/ sandbox.",
    )
    parser.add_argument(
        "--payload",
        default="SIMULATED_FLIGHT_PLAN",
        help="Content written during sandbox simulation.",
    )
    parser.add_argument(
        "--simulate-write",
        action="store_true",
        help="Attempt a sandboxed write after auditing the path.",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    audit = audit_flight_plan_path(args.flight_plan_path)
    print(json.dumps(audit.to_dict(), separators=(",", ":")))

    if not args.simulate_write:
        return 0 if audit.is_safe else 1

    simulator = SandboxSimulator(args.sandbox_root)
    event = simulator.write_text(args.script_name, args.flight_plan_path, args.payload)
    print(json.dumps(event.to_dict(), separators=(",", ":")))
    return 0 if event.status == "allowed" else 1


def _decode_repeatedly(value: str, max_rounds: int = 4) -> str:
    decoded = value
    for _ in range(max_rounds):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    return decoded


def _looks_like_absolute_path(value: str) -> bool:
    return value.startswith("/") or value.startswith("~") or bool(re.match(r"^[A-Za-z]:[/\\]", value))


def _deduplicate(values: Sequence[str]) -> List[str]:
    seen = set()
    ordered: List[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered
