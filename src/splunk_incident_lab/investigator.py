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
    latencies = [item["latency_ms"] for item in event_records]
    baseline = statistics.median([value for value in latencies if value <= 750])

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

    investigation = {
        "schema_version": "splunk-incident-lab.v1",
        "mode": mode,
        "queries": query_plan_as_dicts(),
        "timeline": event_records,
        "findings": [asdict(item) for item in findings],
        "metrics": {
            "event_count": len(event_records),
            "baseline_latency_ms_median": baseline,
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
    return {
        "expected_slow_event_count": 3,
        "actual_slow_event_count": len(slow_rows),
        "expected_error_event_count": 1,
        "actual_error_row_count": len(error_rows),
        "matches_expected_incident_shape": len(slow_rows) == 3 and len(error_rows) >= 1,
    }
