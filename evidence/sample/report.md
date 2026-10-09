# Splunk Incident Investigation Report

Mode: `rest`

## Lifecycle Verification

```json
{
  "controlled_fault_injection": {
    "error_event_count": 1,
    "event_count": 6,
    "fault": "payment-provider-timeout",
    "ground_truth_event_ids": [
      "event-006",
      "event-007",
      "event-008",
      "event-009",
      "event-010",
      "event-011"
    ],
    "observable_symptoms": [
      "checkout latency above 750 ms",
      "HTTP 500 during checkout",
      "payment provider timeout log messages"
    ],
    "slow_event_count": 3
  },
  "healthy_baseline": {
    "error_count": 0,
    "event_count": 6,
    "median_latency_ms": 101.0,
    "verified": true
  },
  "recovery_verification": {
    "acceptance": "no recovered checkout event exceeds 750 ms and no recovered checkout event returns 5xx",
    "error_event_count": 0,
    "event_count": 6,
    "median_latency_ms": 101.0,
    "slow_event_count": 0,
    "verified": true
  },
  "remediation": {
    "action": "restore payment-provider behavior in the disposable lab by ending the injected timeout phase",
    "applied_in_scenario": true,
    "event_flag": "remediation_applied=true"
  },
  "root_cause_verification": {
    "evidence_event_ids": [
      "event-006",
      "event-007",
      "event-008",
      "event-009",
      "event-010",
      "event-011"
    ],
    "evidence_query_ids": [
      "spl-latency-spike",
      "spl-error-rate",
      "spl-root-cause-ground-truth"
    ],
    "ground_truth_scope": "controlled synthetic lab fault; not a claim about a real external outage",
    "root_cause": "payment-provider-timeout",
    "verified": true
  },
  "splunk_backed_verification": {
    "actual_error_row_count": 1,
    "actual_ground_truth_event_count": 6,
    "actual_slow_event_count": 3,
    "baseline_healthy": true,
    "expected_error_event_count": 1,
    "expected_ground_truth_event_count": 6,
    "expected_slow_event_count": 3,
    "matches_expected_incident_shape": true,
    "matches_expected_lifecycle_shape": true,
    "phase_health": {
      "healthy-baseline": {
        "avg_latency_ms": 102.83333333333333,
        "errors": 0,
        "events": 6,
        "max_latency_ms": 123
      },
      "injected-failure": {
        "avg_latency_ms": 577.6666666666666,
        "errors": 1,
        "events": 6,
        "max_latency_ms": 1180
      },
      "recovered": {
        "avg_latency_ms": 102.83333333333333,
        "errors": 0,
        "events": 6,
        "max_latency_ms": 123
      }
    },
    "recovery_healthy": true
  }
}
```

## Metrics

```json
{
  "baseline_latency_ms_median": 101.0,
  "error_event_count": 1,
  "event_count": 18,
  "max_latency_ms": 1180,
  "recovery_latency_ms_median": 101.0,
  "slow_event_count": 3
}
```

## Findings

- **high** `finding-checkout-provider-timeout`: 3 checkout events exceeded 750 ms; 1 returned HTTP 5xx. Hypothesis: The incident is consistent with a downstream payment provider timeout affecting checkout latency and one failed request. Uncertainty: Telemetry is synthetic, but it was ingested into real Splunk and retrieved through executed SPL over the Splunk REST API. The payment-provider-timeout cause remains scenario ground truth, not an independently proven external-provider outage.

## SPL Query Plan

- `spl-latency-spike`: `search index=main source="splunk-incident-lab:checkout" | spath | search service=checkout-api endpoint="/checkout" latency_ms>750 | dedup trace_id | table _time trace_id status latency_ms message`
- `spl-error-rate`: `search index=main source="splunk-incident-lab:checkout" | spath | search service=checkout-api endpoint="/checkout" status>=500 | stats count by status message`
- `spl-lifecycle-phase-health`: `search index=main source="splunk-incident-lab:checkout" | spath | search service=checkout-api endpoint="/checkout" | stats dc(trace_id) as events avg(latency_ms) as avg_latency_ms max(latency_ms) as max_latency_ms dc(eval(if(status>=500, trace_id, null()))) as errors by scenario_phase`
- `spl-root-cause-ground-truth`: `search index=main source="splunk-incident-lab:checkout" | spath | search service=checkout-api endpoint="/checkout" root_cause_ground_truth="payment-provider-timeout" | dedup trace_id | table _time trace_id scenario_phase fault_injected status latency_ms message root_cause_ground_truth`

## Executed SPL Results

- `spl-latency-spike` returned 3 row(s).
- `spl-error-rate` returned 1 row(s).
- `spl-lifecycle-phase-health` returned 3 row(s).
- `spl-root-cause-ground-truth` returned 6 row(s).

```json
{
  "actual_error_row_count": 1,
  "actual_ground_truth_event_count": 6,
  "actual_slow_event_count": 3,
  "baseline_healthy": true,
  "expected_error_event_count": 1,
  "expected_ground_truth_event_count": 6,
  "expected_slow_event_count": 3,
  "matches_expected_incident_shape": true,
  "matches_expected_lifecycle_shape": true,
  "phase_health": {
    "healthy-baseline": {
      "avg_latency_ms": 102.83333333333333,
      "errors": 0,
      "events": 6,
      "max_latency_ms": 123
    },
    "injected-failure": {
      "avg_latency_ms": 577.6666666666666,
      "errors": 1,
      "events": 6,
      "max_latency_ms": 1180
    },
    "recovered": {
      "avg_latency_ms": 102.83333333333333,
      "errors": 0,
      "events": 6,
      "max_latency_ms": 123
    }
  },
  "recovery_healthy": true
}
```

## LLM-Safe Analysis

Mode: `llm-provider`

{"context": "All telemetry was ingested into a real Splunk instance and retrieved via the listed SPL queries over the Splunk REST API. Root-cause verification in the scenario is marked as 'verified'.", "hypotheses": ["The observable incident behavior (latency spikes and one 5xx) is caused by the injected 'payment-provider-timeout' fault active during the injected-failure phase.", "Because the telemetry is synthetic and the fault is a scenario ground truth, this does not assert a real external provider outage in production \u2014 only that the lab injection produced the observed symptoms."], "observations": ["This was a controlled, synthetic fault-injection scenario where a 'payment-provider-timeout' fault was injected during the 'injected-failure' phase.", "Splunk queries (spl-latency-spike, spl-error-rate, spl-lifecycle-phase-health, spl-root-cause-ground-truth) returned results consistent with the injected fault and the expected incident shape.", "During the injected-failure phase there are 6 checkout events; 3 traces exceeded 750 ms latency (trace-0006: 920 ms, trace-0008: 1030 ms, trace-0007: 1180 ms) and 1 of those returned HTTP 500 (trace-0007).", "Baseline and recovered phases each show 6 events with median/avg latency \u2248101 ms and 0 errors; injected-failure phase shows avg latency \u2248577.7 ms, max 1180 ms, and 1 error.", "Remediation for the scenario was applied (remediation_applied=true) and recovery verification shows healthy baseline metrics restored."]}

Safety note: Retrieved evidence was supplied to the model; unsupported claims remain disallowed by prompt contract.
