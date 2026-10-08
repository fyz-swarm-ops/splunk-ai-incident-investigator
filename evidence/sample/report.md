# Splunk Incident Investigation Report

Mode: `rest`

## Metrics

```json
{
  "baseline_latency_ms_median": 101,
  "error_event_count": 1,
  "event_count": 12,
  "max_latency_ms": 1180,
  "slow_event_count": 3
}
```

## Findings

- **high** `finding-checkout-provider-timeout`: 3 checkout events exceeded 750 ms; 1 returned HTTP 5xx. Hypothesis: The incident is consistent with a downstream payment provider timeout affecting checkout latency and one failed request. Uncertainty: Synthetic ground truth indicates provider timeout; live Splunk confirmation still depends on running the Docker lab and ingesting these events.

## SPL Query Plan

- `spl-latency-spike`: `search index=main source="splunk-incident-lab:checkout" | spath | search service=checkout-api endpoint="/checkout" latency_ms>750 | table _time trace_id status latency_ms message`
- `spl-error-rate`: `search index=main source="splunk-incident-lab:checkout" | spath | search service=checkout-api endpoint="/checkout" status>=500 | stats count by status message`

## Executed SPL Results

- `spl-latency-spike` returned 3 row(s).
- `spl-error-rate` returned 1 row(s).

```json
{
  "actual_error_row_count": 1,
  "actual_slow_event_count": 3,
  "expected_error_event_count": 1,
  "expected_slow_event_count": 3,
  "matches_expected_incident_shape": true
}
```

## LLM-Safe Analysis

Mode: `llm-provider`

{"hypothesis": "A downstream payment provider timeout occurred during the incident window and caused elevated checkout latency for three requests and one HTTP 5xx failure.", "observations": ["Splunk query 'spl-latency-spike' returned 3 checkout events with latency_ms 1030, 1180, and 920 (trace_ids: trace-0008, trace-0007, trace-0006). All three events include the message 'payment provider timeout during checkout'.", "Of the three slow events, two have status 200 (trace-0008, trace-0006) and one has status 500 (trace-0007).", "Metrics show baseline median latency 101 ms, max_latency_ms 1180 ms, event_count 12, slow_event_count 3, and error_event_count 1.", "The finding supplied with the evidence states the same hypothesis: 'The incident is consistent with a downstream payment provider timeout affecting checkout latency and one failed request.'", "The evidence source includes a note that the synthetic ground truth indicates a provider timeout and that live Splunk confirmation depends on running the Docker lab and ingesting these events."]}

Safety note: Retrieved evidence was supplied to the model; unsupported claims remain disallowed by prompt contract.
