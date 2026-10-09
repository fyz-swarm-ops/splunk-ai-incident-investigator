from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import subprocess
import sys
from threading import Thread
import time
from urllib import request
import zipfile

from splunk_incident_lab.evidence import EvidenceValidationError, validate_evidence_package, write_reports
from splunk_incident_lab.investigator import build_investigation, investigate_local, verify_splunk_results
from splunk_incident_lab.llm import LlmConfig, analyze_with_llm
from splunk_incident_lab.rollback import (
    DEPLOYMENT_TIME,
    ROLLBACK_CASES,
    SERVICE,
    build_rollback_investigation,
    local_rollback_results,
    query_plan_as_dicts as rollback_query_plan_as_dicts,
    rollback_events,
    write_rollback_events,
)
from splunk_incident_lab.scenario import write_events
from splunk_incident_lab.splunk_client import (
    SplunkAuthenticationError,
    SplunkResponseError,
    SplunkRestClient,
    parse_oneshot_results,
)


def test_investigation_finds_injected_checkout_incident(tmp_path):
    events = tmp_path / "raw" / "events.jsonl"
    write_events(events)

    investigation = investigate_local(events)

    assert investigation["metrics"]["event_count"] == 18
    assert investigation["metrics"]["slow_event_count"] == 3
    assert investigation["metrics"]["error_event_count"] == 1
    assert investigation["lifecycle"]["healthy_baseline"]["verified"] is True
    assert investigation["lifecycle"]["root_cause_verification"]["verified"] is True
    assert investigation["lifecycle"]["recovery_verification"]["verified"] is True
    finding = investigation["findings"][0]
    assert finding["severity"] == "high"
    assert finding["evidence_event_ids"]
    assert "uncertainty" in finding


def test_evidence_package_contains_raw_queries_and_reports(tmp_path):
    events = tmp_path / "raw" / "events.jsonl"
    write_events(events)
    investigation = investigate_local(events)

    outputs = write_reports(tmp_path, investigation)

    assert tmp_path / "manifest.json" in outputs
    assert (tmp_path / "report.html").exists()
    assert (tmp_path / "report.md").exists()
    assert (tmp_path / "investigation.json").exists()
    manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    assert any(item["path"] == "raw/spl-query-plan.json" for item in manifest["files"])
    assert not any(item["path"] == "splunk-incident-evidence.zip" for item in manifest["files"])
    with zipfile.ZipFile(tmp_path / "splunk-incident-evidence.zip") as archive:
        assert "investigation.json" in archive.namelist()
        assert "raw/spl-query-plan.json" in archive.namelist()


def test_evidence_validation_requires_full_lifecycle(tmp_path):
    events = tmp_path / "raw" / "events.jsonl"
    write_events(events)
    investigation = investigate_local(events)
    write_reports(tmp_path, investigation)

    validation = validate_evidence_package(tmp_path)

    assert validation["valid"] is True
    assert validation["lifecycle_verified"] is True


def test_evidence_validation_rejects_hash_drift(tmp_path):
    events = tmp_path / "raw" / "events.jsonl"
    write_events(events)
    investigation = investigate_local(events)
    write_reports(tmp_path, investigation)
    (tmp_path / "report.md").write_text("tampered\n", encoding="utf-8")

    try:
        validate_evidence_package(tmp_path)
    except EvidenceValidationError as exc:
        assert "hash mismatch" in str(exc)
    else:
        raise AssertionError("expected manifest hash drift to fail validation")


def test_rest_mode_uncertainty_distinguishes_real_splunk_from_local(tmp_path):
    events = tmp_path / "raw" / "events.jsonl"
    written = write_events(events)
    splunk_results = [
        {
            "query_id": "spl-latency-spike",
            "rows": [{"trace_id": "trace-0006"}, {"trace_id": "trace-0007"}, {"trace_id": "trace-0008"}],
        },
        {"query_id": "spl-error-rate", "rows": [{"status": "500", "count": "1"}]},
        {
            "query_id": "spl-lifecycle-phase-health",
            "rows": [
                {"scenario_phase": "healthy-baseline", "events": "6", "max_latency_ms": "123", "errors": "0"},
                {"scenario_phase": "injected-failure", "events": "6", "max_latency_ms": "1180", "errors": "1"},
                {"scenario_phase": "recovered", "events": "6", "max_latency_ms": "123", "errors": "0"},
            ],
        },
        {
            "query_id": "spl-root-cause-ground-truth",
            "rows": [{"trace_id": f"trace-{index:04d}"} for index in range(6, 12)],
        },
    ]

    investigation = build_investigation(written, "rest", splunk_rest_results=splunk_results)

    uncertainty = investigation["findings"][0]["uncertainty"]
    assert "ingested into real Splunk" in uncertainty
    assert "Local-only" not in uncertainty


def test_splunk_result_verification_matches_expected_shape():
    results = [
        {
            "query_id": "spl-latency-spike",
            "rows": [{"trace_id": "trace-0006"}, {"trace_id": "trace-0007"}, {"trace_id": "trace-0008"}],
        },
        {"query_id": "spl-error-rate", "rows": [{"status": "500", "count": "1"}]},
        {
            "query_id": "spl-lifecycle-phase-health",
            "rows": [
                {"scenario_phase": "healthy-baseline", "events": "6", "max_latency_ms": "123", "errors": "0"},
                {"scenario_phase": "injected-failure", "events": "6", "max_latency_ms": "1180", "errors": "1"},
                {"scenario_phase": "recovered", "events": "6", "max_latency_ms": "123", "errors": "0"},
            ],
        },
        {
            "query_id": "spl-root-cause-ground-truth",
            "rows": [{"trace_id": f"trace-{index:04d}"} for index in range(6, 12)],
        },
    ]

    verification = verify_splunk_results(results)

    assert verification["matches_expected_incident_shape"] is True
    assert verification["matches_expected_lifecycle_shape"] is True


def test_splunk_search_empty_results_are_valid():
    assert parse_oneshot_results(b'{"results": []}') == []


def test_splunk_search_malformed_response_fails():
    try:
        parse_oneshot_results(b"{not-json")
    except SplunkResponseError as exc:
        assert "malformed" in str(exc)
    else:
        raise AssertionError("expected malformed Splunk response to fail")


def test_splunk_authentication_failure_is_explicit():
    server = _start_server(_SplunkAuthFailureHandler)
    try:
        client = SplunkRestClient(f"http://127.0.0.1:{server.server_port}", "admin", "bad")
        try:
            client.verify_ready()
        except SplunkAuthenticationError as exc:
            assert "authentication failed" in str(exc)
        else:
            raise AssertionError("expected auth failure")
    finally:
        server.shutdown()


def test_splunk_successful_query_round_trip():
    server = _start_server(_SplunkSuccessHandler)
    try:
        client = SplunkRestClient(f"http://127.0.0.1:{server.server_port}", "admin", "ok")
        rows = client.run_search("search index=main")
        assert rows == [{"trace_id": "trace-0006", "latency_ms": "920"}]
    finally:
        server.shutdown()


def test_kubernetes_verification_command_writes_expected_counts(tmp_path):
    server = _start_server(_SplunkK8sHandler)
    output = tmp_path / "raw" / "kubernetes-splunk-results.json"
    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "splunk_incident_lab.cli",
                "verify-k8s",
                "--output",
                str(output),
            ],
            env={
                "SPLUNKD_URL": f"http://127.0.0.1:{server.server_port}",
                "SPLUNK_PASSWORD": "ok",
            },
            check=True,
            capture_output=True,
            text=True,
        )
    finally:
        server.shutdown()

    assert "wrote Kubernetes Splunk verification" in result.stdout
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["matches_expected_kubernetes_shape"] is True
    assert payload["slow_event_count"] == 3
    assert payload["error_event_count"] == 1


def test_llm_analysis_uses_configured_provider():
    server = _start_server(_LlmSuccessHandler)
    try:
        analysis = analyze_with_llm(
            LlmConfig(endpoint=f"http://127.0.0.1:{server.server_port}", api_key="test", model="incident-model"),
            {"metrics": {"slow_event_count": 3}},
        )
    finally:
        server.shutdown()

    assert analysis["mode"] == "llm-provider"
    assert analysis["analysis"]["likely_cause"] == "payment provider timeout"


def test_evidence_ui_serves_queries_findings_timeline_and_evidence(tmp_path):
    events = tmp_path / "raw" / "events.jsonl"
    write_events(events)
    write_reports(tmp_path, investigate_local(events))
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "splunk_incident_lab.cli",
            "serve",
            "--evidence",
            str(tmp_path),
            "--port",
            "0",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert proc.stdout is not None
        line = proc.stdout.readline().strip()
        assert line.startswith("serving evidence UI at ")
        base_url = line.removeprefix("serving evidence UI at ")
        for path, marker in [
            ("/", "Evidence Navigation"),
            ("/api/queries", "spl-latency-spike"),
            ("/api/findings", "finding-checkout-provider-timeout"),
            ("/api/timeline", "trace-0007"),
            ("/api/evidence", "bounded-template"),
        ]:
            with request.urlopen(f"{base_url}{path}", timeout=5) as response:
                assert response.status == 200
                assert marker in response.read().decode("utf-8")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def test_rollback_advisory_ranks_db_pool_exhaustion_without_answer_labels():
    records = [event.__dict__ for event in rollback_events("db-pool-exhaustion")]
    investigation = _rollback_investigation(records)

    workflow = investigation["advisory_workflow"]
    top = workflow["ranked_hypotheses"][0]
    assert top["id"] == "deployment-db-pool-exhaustion"
    assert top["support_level"] == "strong"
    assert "Deployment timing starts the investigation" in workflow["decision_boundary"]
    assert workflow["follow_up_recovery_assessment"]["causality_boundary"].startswith("Recovery after")
    assert not _contains_forbidden_answer_label(investigation)


def test_rollback_advisory_payment_timeout_is_not_deployment_by_timing_only():
    records = [event.__dict__ for event in rollback_events("payment-timeout")]
    investigation = _rollback_investigation(records)

    workflow = investigation["advisory_workflow"]
    top = workflow["ranked_hypotheses"][0]
    assert top["id"] == "coincidental-payment-provider-timeout"
    assert "Do not prioritize rollback yet" in workflow["advisory_recommendation"]
    assert top["supporting_evidence_event_ids"]


def test_rollback_advisory_inconclusive_surfaces_missing_information():
    records = [event.__dict__ for event in rollback_events("inconclusive")]
    investigation = _rollback_investigation(records)

    workflow = investigation["advisory_workflow"]
    top = workflow["ranked_hypotheses"][0]
    assert top["id"] == "deployment-regression-unknown"
    assert "collect missing dependency and database evidence" in workflow["advisory_recommendation"]
    assert "database pool metrics" in workflow["missing_information"]
    assert "payment dependency metrics" in workflow["missing_information"]


def test_rollback_advisory_healthy_negative_control_does_not_recommend_rollback():
    records = [event.__dict__ for event in rollback_events("healthy")]
    investigation = _rollback_investigation(records)

    workflow = investigation["advisory_workflow"]
    assert workflow["baseline_incident_comparison"]["incident"]["degraded_against_baseline"] is False
    assert workflow["follow_up_recovery_assessment"]["recovered"] is False
    assert workflow["follow_up_recovery_assessment"]["intervention_observed"] is False
    assert "no rollback or intervention was observed" in workflow["follow_up_recovery_assessment"]["assessment"]
    assert "Do not roll back" in workflow["advisory_recommendation"]
    assert workflow["ranked_hypotheses"][0]["id"] == "healthy-negative-control"
    assert workflow["ranked_hypotheses"][0]["support_level"] == "strong"
    assert all(item.get("intervention") is None for item in records)
    assert all(
        item["deployment_version"] == "checkout-api@2026.10.09-1"
        for item in records
        if item["signal_type"] == "request" and item["timestamp"] >= DEPLOYMENT_TIME
    )


def test_rollback_demo_generates_all_required_cases(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "splunk_incident_lab.cli",
            "demo-rollback",
            "--output",
            str(tmp_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert "wrote rollback advisory demo" in result.stdout
    summary = json.loads((tmp_path / "rollback-demo-summary.json").read_text(encoding="utf-8"))
    assert {item["case"] for item in summary["cases"]} == set(ROLLBACK_CASES)
    for case in ROLLBACK_CASES:
        assert validate_evidence_package(tmp_path / case)["valid"] is True


def test_rollback_ui_serves_advisory_fields(tmp_path):
    events_path = tmp_path / "raw" / "rollback-events.jsonl"
    write_rollback_events("db-pool-exhaustion", events_path)
    records = [event.__dict__ for event in rollback_events("db-pool-exhaustion")]
    write_reports(tmp_path, _rollback_investigation(records))
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "splunk_incident_lab.cli",
            "serve",
            "--evidence",
            str(tmp_path),
            "--port",
            "0",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert proc.stdout is not None
        line = proc.stdout.readline().strip()
        base_url = line.removeprefix("serving evidence UI at ")
        for path, marker in [
            ("/", "Rollback Advisory Investigator"),
            ("/api/findings", "finding-deployment-db-pool-exhaustion"),
            ("/api/evidence", "ranked_hypotheses"),
            ("/api/timeline", "database connection checkout waited"),
        ]:
            with request.urlopen(f"{base_url}{path}", timeout=5) as response:
                assert response.status == 200
                assert marker in response.read().decode("utf-8")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def test_rollback_query_plan_is_evidence_only():
    serialized = json.dumps(rollback_query_plan_as_dicts(SERVICE, DEPLOYMENT_TIME, 14))
    assert "root_cause_ground_truth" not in serialized
    assert "db_pool" in serialized
    assert "payment_timeout" in serialized


def _start_server(handler: type[BaseHTTPRequestHandler]) -> HTTPServer:
    server = HTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


class _SplunkAuthFailureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(401)
        self.end_headers()

    def log_message(self, format, *args):
        pass


class _SplunkSuccessHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        assert self.path.startswith("/services/search/jobs/oneshot")
        body = b'{"results":[{"trace_id":"trace-0006","latency_ms":"920"}]}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class _SplunkK8sHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        assert self.path.startswith("/services/search/jobs/oneshot")
        rows = [
            {"trace_id": "k8s-trace-0006", "latency_ms": "920", "status": "200"},
            {"trace_id": "k8s-trace-0007", "latency_ms": "1180", "status": "500"},
            {"trace_id": "k8s-trace-0008", "latency_ms": "1030", "status": "200"},
        ]
        body = json.dumps({"results": rows}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class _LlmSuccessHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        assert self.path == "/chat/completions"
        payload = {
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "summary": "Checkout latency and errors match supplied evidence.",
                                "likely_cause": "payment provider timeout",
                                "confidence": "medium",
                                "recommended_actions": ["check provider connectivity"],
                                "caveats": ["synthetic evidence"],
                            }
                        )
                    }
                }
            ]
        }
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def _rollback_investigation(records: list[dict]) -> dict:
    return build_rollback_investigation(
        records,
        service=SERVICE,
        deployment_time=DEPLOYMENT_TIME,
        window_minutes=14,
        mode="local",
        splunk_rest_results=local_rollback_results(records, SERVICE, DEPLOYMENT_TIME, 14),
    )


def _contains_forbidden_answer_label(payload: dict) -> bool:
    serialized = json.dumps(payload)
    return "root_cause_ground_truth" in serialized or "expected_answer" in serialized
