from __future__ import annotations

import json
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


def serve_evidence(evidence_dir: Path, host: str, port: int) -> None:
    evidence_dir = evidence_dir.resolve()

    class EvidenceHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path in {"/", "/ui"}:
                investigation = _load_investigation(evidence_dir)
                self._send_text(render_ui(investigation), "text/html; charset=utf-8")
                return
            if parsed.path == "/api/investigation":
                self._send_json(_load_investigation(evidence_dir))
                return
            if parsed.path == "/api/queries":
                self._send_json({"queries": _load_investigation(evidence_dir)["queries"]})
                return
            if parsed.path == "/api/findings":
                self._send_json({"findings": _load_investigation(evidence_dir)["findings"]})
                return
            if parsed.path == "/api/timeline":
                self._send_json({"timeline": _load_investigation(evidence_dir)["timeline"]})
                return
            if parsed.path == "/api/evidence":
                investigation = _load_investigation(evidence_dir)
                payload = {
                    "mode": investigation["mode"],
                    "llm_analysis": investigation["llm_analysis"],
                    "splunk_rest_results": investigation.get("splunk_rest_results", []),
                    "splunk_result_verification": investigation.get("splunk_result_verification"),
                }
                if "advisory_workflow" in investigation:
                    payload["advisory_workflow"] = investigation["advisory_workflow"]
                else:
                    payload["lifecycle"] = investigation.get("lifecycle")
                self._send_json(payload)
                return
            self.send_error(404, "not found")

        def log_message(self, format: str, *args: object) -> None:
            pass

        def _send_json(self, payload: dict) -> None:
            body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_text(self, text: str, content_type: str) -> None:
            body = text.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer((host, port), EvidenceHandler)
    print(f"serving evidence UI at http://{host}:{server.server_port}", flush=True)
    server.serve_forever()


def render_ui(investigation: dict) -> str:
    if "advisory_workflow" in investigation:
        return _render_rollback_ui(investigation)
    query_rows = "\n".join(
        "<tr>"
        f"<td><code>{escape(item['id'])}</code></td>"
        f"<td>{escape(item['purpose'])}</td>"
        f"<td><code>{escape(item['query'])}</code></td>"
        "</tr>"
        for item in investigation["queries"]
    )
    findings = "\n".join(
        "<section class=\"finding\">"
        f"<h3>{escape(item['severity'].upper())} {escape(item['id'])}</h3>"
        f"<p>{escape(item['observation'])}</p>"
        f"<p><strong>Hypothesis:</strong> {escape(item['hypothesis'])}</p>"
        f"<p><strong>Uncertainty:</strong> {escape(item['uncertainty'])}</p>"
        f"<p><strong>Evidence events:</strong> {escape(', '.join(item['evidence_event_ids']))}</p>"
        f"<p><strong>Evidence queries:</strong> {escape(', '.join(item['evidence_query_ids']))}</p>"
        "</section>"
        for item in investigation["findings"]
    )
    timeline_rows = "\n".join(
        "<tr>"
        f"<td>{escape(event['timestamp'])}</td>"
        f"<td>{escape(str(event['status']))}</td>"
        f"<td>{escape(str(event['latency_ms']))}</td>"
        f"<td><code>{escape(event['trace_id'])}</code></td>"
        f"<td>{escape(event['message'])}</td>"
        "</tr>"
        for event in investigation["timeline"]
    )
    result_blocks = "\n".join(
        "<details open>"
        f"<summary>{escape(item['query_id'])}: {len(item.get('rows', []))} rows</summary>"
        f"<pre>{escape(json.dumps(item.get('rows', []), indent=2, sort_keys=True))}</pre>"
        "</details>"
        for item in investigation.get("splunk_rest_results", [])
    )
    verification = investigation.get("splunk_result_verification") or {}
    lifecycle = escape(json.dumps(investigation.get("lifecycle", {}), indent=2, sort_keys=True))
    llm_analysis = investigation["llm_analysis"]
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Splunk Incident Investigator</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 0; color: #202124; background: #f7f9fc; }}
main {{ max-width: 1180px; margin: 0 auto; padding: 24px; }}
header {{ border-bottom: 1px solid #d0d7de; background: white; }}
header div {{ max-width: 1180px; margin: 0 auto; padding: 20px 24px; }}
nav a {{ margin-right: 16px; color: #0b57d0; }}
section {{ margin: 24px 0; }}
.finding, details, .panel {{ background: white; border: 1px solid #d0d7de; border-radius: 6px; padding: 14px; }}
table {{ border-collapse: collapse; width: 100%; background: white; }}
td, th {{ border: 1px solid #d0d7de; padding: 8px; text-align: left; vertical-align: top; }}
th {{ background: #eef2f7; }}
code, pre {{ background: #eef2f7; }}
pre {{ overflow: auto; padding: 12px; }}
</style>
</head>
<body>
<header><div>
<h1>Splunk Incident Investigator</h1>
<p>Mode: <code>{escape(investigation['mode'])}</code> | LLM: <code>{escape(llm_analysis['mode'])}</code></p>
<nav>
<a href="#queries">Queries</a>
<a href="#findings">Findings</a>
<a href="#timeline">Timeline</a>
<a href="#evidence">Evidence</a>
<a href="/api/investigation">JSON</a>
</nav>
</div></header>
<main>
<section id="queries">
<h2>Lifecycle Verification</h2>
<pre>{lifecycle}</pre>
<h2>Executed SPL Queries</h2>
<table><tr><th>ID</th><th>Purpose</th><th>SPL</th></tr>{query_rows}</table>
</section>
<section id="findings">
<h2>Findings</h2>
{findings}
</section>
<section id="timeline">
<h2>Timeline</h2>
<table><tr><th>Time</th><th>Status</th><th>Latency ms</th><th>Trace</th><th>Message</th></tr>{timeline_rows}</table>
</section>
<section id="evidence">
<h2>Evidence Navigation</h2>
<div class="panel">
<p><strong>Splunk verification:</strong> {escape(json.dumps(verification, sort_keys=True))}</p>
<p><strong>LLM summary:</strong> {escape(llm_analysis.get('summary', ''))}</p>
<p><strong>LLM safety:</strong> {escape(llm_analysis.get('safety', ''))}</p>
</div>
{result_blocks or '<p>No Splunk REST result rows are present in this evidence package.</p>'}
</section>
</main>
</body>
</html>
"""


def _render_rollback_ui(investigation: dict) -> str:
    workflow = investigation["advisory_workflow"]
    hypothesis_blocks = "\n".join(
        "<section class=\"finding\">"
        f"<h3>{item['rank']}. {escape(item['label'])}</h3>"
        f"<p>Score: <code>{item['score']}</code> ({escape(item['support_level'])})</p>"
        f"<p><strong>Supporting:</strong> {escape(', '.join(item['supporting_evidence_event_ids']) or 'none')}</p>"
        f"<p><strong>Contradicting:</strong> {escape(', '.join(item['contradicting_evidence_event_ids']) or 'none')}</p>"
        f"<p><strong>Missing:</strong> {escape(', '.join(item['missing_information']) or 'none')}</p>"
        "</section>"
        for item in workflow["ranked_hypotheses"]
    )
    query_rows = "\n".join(
        "<tr>"
        f"<td><code>{escape(item['id'])}</code></td>"
        f"<td>{escape(item['purpose'])}</td>"
        f"<td><code>{escape(item['query'])}</code></td>"
        "</tr>"
        for item in investigation["queries"]
    )
    timeline_rows = "\n".join(
        "<tr>"
        f"<td>{escape(event['timestamp'])}</td>"
        f"<td>{escape(event['signal_type'])}</td>"
        f"<td>{escape(str(event['status']))}</td>"
        f"<td>{escape(str(event['latency_ms']))}</td>"
        f"<td><code>{escape(event['trace_id'])}</code></td>"
        f"<td>{escape(event['message'])}</td>"
        "</tr>"
        for event in investigation["timeline"]
    )
    result_blocks = "\n".join(
        "<details open>"
        f"<summary>{escape(item['query_id'])}: {len(item.get('rows', []))} rows</summary>"
        f"<pre>{escape(json.dumps(item.get('rows', []), indent=2, sort_keys=True))}</pre>"
        "</details>"
        for item in investigation.get("splunk_rest_results", [])
    )
    llm = investigation["llm_analysis"]
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rollback Advisory Investigator</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 0; color: #202124; background: #f7f9fc; }}
main {{ max-width: 1180px; margin: 0 auto; padding: 24px; }}
header {{ border-bottom: 1px solid #d0d7de; background: white; }}
header div {{ max-width: 1180px; margin: 0 auto; padding: 20px 24px; }}
nav a {{ margin-right: 16px; color: #0b57d0; }}
section {{ margin: 24px 0; }}
.finding, details, .panel {{ background: white; border: 1px solid #d0d7de; border-radius: 6px; padding: 14px; }}
table {{ border-collapse: collapse; width: 100%; background: white; }}
td, th {{ border: 1px solid #d0d7de; padding: 8px; text-align: left; vertical-align: top; }}
th {{ background: #eef2f7; }}
code, pre {{ background: #eef2f7; }}
pre {{ overflow: auto; padding: 12px; }}
</style>
</head>
<body>
<header><div>
<h1>Rollback Advisory Investigator</h1>
<p>Mode: <code>{escape(investigation['mode'])}</code> | LLM: <code>{escape(llm['mode'])}</code></p>
<nav>
<a href="#brief">Brief</a>
<a href="#queries">Queries</a>
<a href="#findings">Hypotheses</a>
<a href="#timeline">Timeline</a>
<a href="#evidence">Evidence</a>
<a href="/api/investigation">JSON</a>
</nav>
</div></header>
<main>
<section id="brief" class="panel">
<h2>{escape(workflow['question'])}</h2>
<p>{escape(workflow['decision_boundary'])}</p>
<p><strong>Recommendation:</strong> {escape(workflow['advisory_recommendation'])}</p>
<pre>{escape(json.dumps(workflow['baseline_incident_comparison'], indent=2, sort_keys=True))}</pre>
</section>
<section id="queries">
<h2>Executed SPL Queries</h2>
<table><tr><th>ID</th><th>Purpose</th><th>SPL</th></tr>{query_rows}</table>
</section>
<section id="findings">
<h2>Ranked Hypotheses</h2>
{hypothesis_blocks}
</section>
<section class="panel">
<h2>Next Checks</h2>
<ul>{''.join(f'<li>{escape(item)}</li>' for item in workflow['recommended_next_checks'])}</ul>
<h2>Missing Information</h2>
<ul>{''.join(f'<li>{escape(item)}</li>' for item in workflow['missing_information']) or '<li>none</li>'}</ul>
</section>
<section id="timeline">
<h2>Timeline</h2>
<table><tr><th>Time</th><th>Signal</th><th>Status</th><th>Latency ms</th><th>Trace</th><th>Message</th></tr>{timeline_rows}</table>
</section>
<section id="evidence">
<h2>Evidence Navigation</h2>
<p><strong>Recovery:</strong> {escape(workflow['follow_up_recovery_assessment']['assessment'])}</p>
<p><strong>LLM summary:</strong> {escape(llm.get('summary', ''))}</p>
{result_blocks or '<p>No query result rows are present in this evidence package.</p>'}
</section>
</main>
</body>
</html>
"""


def _load_investigation(evidence_dir: Path) -> dict:
    return json.loads((evidence_dir / "investigation.json").read_text(encoding="utf-8"))
