from __future__ import annotations

import argparse
import os
from pathlib import Path

from .evidence import write_reports
from .investigator import build_investigation, investigate_local
from .llm import analyze_with_llm, llm_config_from_env
from .scenario import read_events, write_events
from .splunk_client import SplunkRestClient
from .ui import serve_evidence


def main() -> int:
    parser = argparse.ArgumentParser(prog="splunk-incident-lab")
    sub = parser.add_subparsers(dest="command", required=True)

    seed = sub.add_parser("seed")
    seed.add_argument("--output", type=Path, required=True)

    investigate = sub.add_parser("investigate")
    investigate.add_argument("--mode", choices=["local", "rest"], default="local")
    investigate.add_argument("--events", type=Path, required=True)
    investigate.add_argument("--output", type=Path, required=True)

    verify_k8s = sub.add_parser("verify-k8s")
    verify_k8s.add_argument("--output", type=Path, required=True)

    export = sub.add_parser("export")
    export.add_argument("--evidence", type=Path, required=True)

    serve = sub.add_parser("serve")
    serve.add_argument("--evidence", type=Path, required=True)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)

    args = parser.parse_args()
    if args.command == "seed":
        events = write_events(args.output)
        print(f"wrote {len(events)} events to {args.output}")
        return 0
    if args.command == "investigate":
        args.output.mkdir(parents=True, exist_ok=True)
        if args.mode == "rest":
            client = SplunkRestClient(
                os.environ.get("SPLUNKD_URL", "https://localhost:8089"),
                os.environ.get("SPLUNK_USERNAME", "admin"),
                os.environ["SPLUNK_PASSWORD"],
            )
            readiness = client.verify_ready()
            ingest = client.ingest_events(args.events)
            searches = client.run_searches()
            investigation = build_investigation(
                read_events(args.events),
                mode="rest",
                splunk_readiness=readiness,
                splunk_ingest=ingest,
                splunk_rest_results=searches,
            )
        else:
            investigation = investigate_local(args.events)
        llm_config = llm_config_from_env(os.environ)
        if llm_config is not None:
            investigation["llm_analysis"] = analyze_with_llm(
                llm_config,
                {
                    "metrics": investigation["metrics"],
                    "mode": investigation["mode"],
                    "findings": investigation["findings"],
                    "queries": investigation["queries"],
                    "timeline": investigation["timeline"],
                    "splunk_rest_results": investigation.get("splunk_rest_results", []),
                    "splunk_result_verification": investigation.get("splunk_result_verification"),
                    "evidence_context": _evidence_context(investigation),
                },
            )
        write_reports(args.output, investigation)
        print(f"wrote investigation evidence to {args.output}")
        return 0
    if args.command == "verify-k8s":
        client = SplunkRestClient(
            os.environ.get("SPLUNKD_URL", "https://localhost:8089"),
            os.environ.get("SPLUNK_USERNAME", "admin"),
            os.environ["SPLUNK_PASSWORD"],
        )
        query = (
            'search index=main source="splunk-incident-lab:checkout" '
            '| spath | search trace_id="k8s-trace-*" '
            '| table _time trace_id status latency_ms message'
        )
        rows = client.run_search(query)
        slow = [row for row in rows if int(row.get("latency_ms", 0)) > 750]
        errors = [row for row in rows if int(row.get("status", 0)) >= 500]
        payload = {
            "query": query,
            "row_count": len(rows),
            "slow_event_count": len(slow),
            "error_event_count": len(errors),
            "matches_expected_kubernetes_shape": len(slow) == 3 and len(errors) == 1,
            "rows": rows,
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        import json

        args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote Kubernetes Splunk verification to {args.output}")
        return 0
    if args.command == "export":
        # Reports are written during investigation; export validates/refreshes
        # the package and manifest from the saved investigation payload.
        import json

        investigation = json.loads((args.evidence / "investigation.json").read_text(encoding="utf-8"))
        outputs = write_reports(args.evidence, investigation)
        for output in outputs:
            print(output)
        return 0
    if args.command == "serve":
        serve_evidence(args.evidence, args.host, args.port)
        return 0
    raise AssertionError(args.command)


def _evidence_context(investigation: dict) -> dict:
    if investigation["mode"] == "rest":
        return {
            "telemetry_origin": "synthetic checkout scenario",
            "splunk_path": "events ingested into real Splunk and retrieved through executed SPL over REST",
            "claim_boundary": "validates Splunk integration and evidence retrieval, not a real external provider outage",
        }
    return {
        "telemetry_origin": "synthetic checkout scenario",
        "splunk_path": "local-only file analysis; no Splunk REST query results are present",
        "claim_boundary": "do not claim Splunk-backed confirmation from local mode",
    }


if __name__ == "__main__":
    raise SystemExit(main())
