from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class Event:
    timestamp: str
    service: str
    endpoint: str
    status: int
    latency_ms: int
    trace_id: str
    message: str
    scenario_phase: str = "unknown"
    fault_injected: bool = False
    remediation_applied: bool = False
    root_cause_ground_truth: str = "undisclosed"


def deterministic_events() -> list[Event]:
    events: list[Event] = []
    for minute in range(18):
        latency = 90 + (minute % 4) * 11
        status = 200
        message = "checkout request completed"
        phase = "healthy-baseline"
        fault_injected = False
        remediation_applied = False
        if 6 <= minute <= 11:
            phase = "injected-failure"
            fault_injected = True
            message = "payment provider timeout fault active during checkout"
        if 6 <= minute <= 8:
            latency = [920, 1180, 1030][minute - 6]
            status = 500 if minute == 7 else 200
            message = "payment provider timeout during checkout"
        if minute >= 12:
            phase = "recovered"
            remediation_applied = True
            message = "checkout request completed after payment provider timeout remediation"
        events.append(
            Event(
                timestamp=f"2026-10-08T14:{minute:02d}:00Z",
                service="checkout-api",
                endpoint="/checkout",
                status=status,
                latency_ms=latency,
                trace_id=f"trace-{minute:04d}",
                message=message,
                scenario_phase=phase,
                fault_injected=fault_injected,
                remediation_applied=remediation_applied,
                root_cause_ground_truth="payment-provider-timeout" if fault_injected else "none",
            )
        )
    return events


def write_events(path: Path) -> list[Event]:
    path.parent.mkdir(parents=True, exist_ok=True)
    events = deterministic_events()
    with path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(asdict(event), sort_keys=True) + "\n")
    return events


def read_events(path: Path) -> list[Event]:
    with path.open(encoding="utf-8") as handle:
        return [Event(**json.loads(line)) for line in handle if line.strip()]
