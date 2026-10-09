from __future__ import annotations

import json
import statistics
from dataclasses import asdict, dataclass
from pathlib import Path

from .scenario import Event, read_events
from .splunk_client import query_plan_as_dicts


@dataclass(frozen=True)
class Finding:
    id: str
    severity: str
    observation: str
    hypothesis: str
    uncertainty: str
    evidence_event_ids: list[str]
    evidence_query_ids: list[str]


def investigate_local(events_path: Path) -> dict:
    events = read_events(events_path)
    return build_investigation(events, mode="local")


def build_investigation(
    events: list[Event],
    mode: str,
    *,
    splunk_rest_results: list[dict] | None = None,
    splunk_readiness: dict | None = None,
    splunk_ingest: dict | None = None,
    llm_analysis: dict | None = None,
) -> dict:
    event_records = [
        {"id": f"event-{i:03d}", **asdict(event)}
        for i, event in enumerate(events)
    ]
    slow = [item for item in event_records if item["latency_ms"] > 750]
    errors = [item for item in event_records if item["status"] >= 500]
    baseline_events = _phase_events(event_records, "healthy-baseline")
    failure_events = _phase_events(event_records, "injected-failure")
    recovered_events = _phase_events(event_records, "recovered")
    latencies = [item["latency_ms"] for item in event_records]
    baseline = _median_latency(baseline_events)
    recovery = _median_latency(recovered_events)

    findings = [
        Finding(
            id="finding-checkout-provider-timeout",
            severity="high",
            observation=f"{len(slow)} checkout events exceeded 750 ms; {len(errors)} returned HTTP 5xx.",
            hypothesis="The incident is consistent with a downstream payment provider timeout affecting checkout latency and one failed request.",
            uncertainty=_uncertainty_for_mode(mode, splunk_rest_results),
            evidence_event_ids=list(dict.fromkeys(item["id"] for item in slow + errors)),
            evidence_query_ids=[query["id"] for query in query_plan_as_dicts()],
        )
    ]
    lifecycle = build_lifecycle(
        baseline_events=baseline_events,
        failure_events=failure_events,
        recovered_events=recovered_events,
        splunk_rest_results=splunk_rest_results,
    )

    investigation = {
        "schema_version": "splunk-incident-lab.v1",
        "mode": mode,
        "queries": query_plan_as_dicts(),
        "timeline": event_records,
        "findings": [asdict(item) for item in findings],
        "lifecycle": lifecycle,
        "metrics": {
            "event_count": len(event_records),
            "baseline_latency_ms_median": baseline,
            "recovery_latency_ms_median": recovery,
            "max_latency_ms": max(latencies),
            "slow_event_count": len(slow),
            "error_event_count": len(errors),
        },
        "llm_analysis": llm_analysis or {
            "mode": "bounded-template",
            "safety": "No unsupported root cause is asserted; observations, hypotheses, and uncertainty are separate fields.",
            "summary": "Checkout latency spiked during the injected incident window and coincided with payment-provider-timeout messages.",
        },
    }
    if splunk_readiness is not None:
        investigation["splunk_readiness"] = splunk_readiness
    if splunk_ingest is not None:
        investigation["splunk_ingest"] = splunk_ingest
    if splunk_rest_results is not None:
        investigation["splunk_rest_results"] = splunk_rest_results
        investigation["splunk_result_verification"] = verify_splunk_results(splunk_rest_results)
    return investigation


def _uncertainty_for_mode(mode: str, splunk_rest_results: list[dict] | None) -> str:
    if mode == "rest" and splunk_rest_results is not None:
        verification = verify_splunk_results(splunk_rest_results)
        if verification["matches_expected_incident_shape"]:
            return (
                "Telemetry is synthetic, but it was ingested into real Splunk and retrieved through "
                "executed SPL over the Splunk REST API. The payment-provider-timeout cause remains "
                "scenario ground truth, not an independently proven external-provider outage."
            )
        return (
            "Telemetry is synthetic and was queried through Splunk REST, but returned SPL results did "
            "not fully match the expected incident shape."
        )
    return (
        "Local-only analysis uses deterministic synthetic events without executed Splunk REST queries; "
        "use SPLUNK_MODE=rest before claiming Splunk-backed confirmation."
    )


def verify_splunk_results(results: list[dict]) -> dict:
    by_id = {item["query_id"]: item for item in results}
    slow_rows = by_id.get("spl-latency-spike", {}).get("rows", [])
    error_rows = by_id.get("spl-error-rate", {}).get("rows", [])
    phase_rows = by_id.get("spl-lifecycle-phase-health", {}).get("rows", [])
    ground_truth_rows = by_id.get("spl-root-cause-ground-truth", {}).get("rows", [])
    phase_health = _phase_health_from_rows(phase_rows)
    recovery_ok = _phase_is_healthy(phase_health.get("recovered", {}))
    baseline_ok = _phase_is_healthy(phase_health.get("healthy-baseline", {}))
    return {
        "expected_slow_event_count": 3,
        "actual_slow_event_count": len(slow_rows),
        "expected_error_event_count": 1,
        "actual_error_row_count": len(error_rows),
        "expected_ground_truth_event_count": 6,
        "actual_ground_truth_event_count": len(ground_truth_rows),
        "phase_health": phase_health,
        "baseline_healthy": baseline_ok,
        "recovery_healthy": recovery_ok,
        "matches_expected_incident_shape": len(slow_rows) == 3 and len(error_rows) >= 1,
        "matches_expected_lifecycle_shape": (
            len(slow_rows) == 3
            and len(error_rows) >= 1
            and len(ground_truth_rows) == 6
            and baseline_ok
            and recovery_ok
        ),
    }


def build_lifecycle(
    *,
    baseline_events: list[dict],
    failure_events: list[dict],
    recovered_events: list[dict],
    splunk_rest_results: list[dict] | None,
) -> dict:
    failure_slow = [item for item in failure_events if item["latency_ms"] > 750]
    failure_errors = [item for item in failure_events if item["status"] >= 500]
    baseline_errors = [item for item in baseline_events if item["status"] >= 500]
    recovery_slow = [item for item in recovered_events if item["latency_ms"] > 750]
    recovery_errors = [item for item in recovered_events if item["status"] >= 500]
    ground_truth_events = [
        item for item in failure_events
        if item.get("root_cause_ground_truth") == "payment-provider-timeout"
    ]
    root_cause_verified = (
        len(ground_truth_events) == len(failure_events)
        and len(ground_truth_events) >= 3
        and len(failure_slow) == 3
        and len(failure_errors) == 1
    )
    recovery_verified = (
        len(recovered_events) >= 1
        and not recovery_slow
        and not recovery_errors
        and all(item.get("remediation_applied") for item in recovered_events)
    )
    lifecycle = {
        "healthy_baseline": {
            "event_count": len(baseline_events),
            "median_latency_ms": _median_latency(baseline_events),
            "error_count": len(baseline_errors),
            "verified": len(baseline_events) >= 1 and not baseline_errors,
        },
        "controlled_fault_injection": {
            "fault": "payment-provider-timeout",
            "event_count": len(failure_events),
            "slow_event_count": len(failure_slow),
            "error_event_count": len(failure_errors),
            "ground_truth_event_ids": [item["id"] for item in ground_truth_events],
            "observable_symptoms": [
                "checkout latency above 750 ms",
                "HTTP 500 during checkout",
                "payment provider timeout log messages",
            ],
        },
        "root_cause_verification": {
            "verified": root_cause_verified,
            "root_cause": "payment-provider-timeout",
            "evidence_event_ids": [item["id"] for item in ground_truth_events],
            "evidence_query_ids": ["spl-latency-spike", "spl-error-rate", "spl-root-cause-ground-truth"],
            "ground_truth_scope": "controlled synthetic lab fault; not a claim about a real external outage",
        },
        "remediation": {
            "action": "restore payment-provider behavior in the disposable lab by ending the injected timeout phase",
            "applied_in_scenario": True,
            "event_flag": "remediation_applied=true",
        },
        "recovery_verification": {
            "verified": recovery_verified,
            "event_count": len(recovered_events),
            "median_latency_ms": _median_latency(recovered_events),
            "slow_event_count": len(recovery_slow),
            "error_event_count": len(recovery_errors),
            "acceptance": "no recovered checkout event exceeds 750 ms and no recovered checkout event returns 5xx",
        },
    }
    if splunk_rest_results is not None:
        lifecycle["splunk_backed_verification"] = verify_splunk_results(splunk_rest_results)
    return lifecycle


def _phase_events(events: list[dict], phase: str) -> list[dict]:
    return [item for item in events if item.get("scenario_phase") == phase]


def _median_latency(events: list[dict]) -> float | int | None:
    if not events:
        return None
    return statistics.median(item["latency_ms"] for item in events)


def _phase_health_from_rows(rows: list[dict]) -> dict:
    health: dict[str, dict] = {}
    for row in rows:
        phase = row.get("scenario_phase")
        if not phase:
            continue
        health[phase] = {
            "events": _coerce_number(row.get("events")),
            "avg_latency_ms": _coerce_number(row.get("avg_latency_ms")),
            "max_latency_ms": _coerce_number(row.get("max_latency_ms")),
            "errors": _coerce_number(row.get("errors")),
        }
    return health


def _phase_is_healthy(row: dict) -> bool:
    return bool(row) and int(row.get("errors") or 0) == 0 and float(row.get("max_latency_ms") or 0) <= 750


def _coerce_number(value: object) -> int | float | None:
    if value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number.is_integer():
        return int(number)
    return number
