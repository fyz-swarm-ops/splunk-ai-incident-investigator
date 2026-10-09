from __future__ import annotations

import hashlib
import json
import zipfile
from datetime import datetime, timezone
from html import escape
from pathlib import Path


class EvidenceValidationError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_reports(evidence_dir: Path, investigation: dict) -> list[Path]:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = evidence_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    write_json(raw_dir / "spl-query-plan.json", {"queries": investigation["queries"]})
    if "splunk_rest_results" in investigation:
        write_json(raw_dir / "splunk-rest-results.json", {"results": investigation["splunk_rest_results"]})
    write_json(evidence_dir / "investigation.json", investigation)
    markdown = render_markdown(investigation)
    html = render_html(investigation)
    (evidence_dir / "report.md").write_text(markdown, encoding="utf-8")
    (evidence_dir / "report.html").write_text(html, encoding="utf-8")
    manifest = build_manifest(evidence_dir)
    write_json(evidence_dir / "manifest.json", manifest)
    package = evidence_dir / "splunk-incident-evidence.zip"
    with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(evidence_dir.rglob("*")):
            if path.is_file() and path != package:
                archive.write(path, path.relative_to(evidence_dir))
    return [evidence_dir / "investigation.json", evidence_dir / "report.md", evidence_dir / "report.html", evidence_dir / "manifest.json", package]


def build_manifest(evidence_dir: Path) -> dict:
    files = []
    for path in sorted(evidence_dir.rglob("*")):
        if path.is_file() and path.name not in {"manifest.json", "splunk-incident-evidence.zip"}:
            files.append(
                {
                    "path": str(path.relative_to(evidence_dir)),
                    "sha256": sha256_file(path),
                    "size_bytes": path.stat().st_size,
                }
            )
    return {
        "schema_version": "splunk-incident-lab.manifest.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "files": files,
    }


def validate_evidence_package(evidence_dir: Path) -> dict:
    investigation_path = evidence_dir / "investigation.json"
    manifest_path = evidence_dir / "manifest.json"
    if not investigation_path.exists():
        raise EvidenceValidationError(f"missing {investigation_path}")
    if not manifest_path.exists():
        raise EvidenceValidationError(f"missing {manifest_path}")

    investigation = json.loads(investigation_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    _validate_manifest_hashes(evidence_dir, manifest)
    if "advisory_workflow" in investigation:
        return _validate_rollback_advisory(investigation, manifest)
    lifecycle = investigation.get("lifecycle") or {}
    splunk_verification = investigation.get("splunk_result_verification") or {}
    errors: list[str] = []
    if not lifecycle.get("healthy_baseline", {}).get("verified"):
        errors.append("healthy baseline is not verified")
    if not lifecycle.get("root_cause_verification", {}).get("verified"):
        errors.append("root cause is not verified")
    if not lifecycle.get("recovery_verification", {}).get("verified"):
        errors.append("recovery is not verified")
    if investigation.get("mode") == "rest" and not splunk_verification.get("matches_expected_lifecycle_shape"):
        errors.append("executed Splunk results do not match expected lifecycle shape")
    if errors:
        raise EvidenceValidationError("; ".join(errors))
    return {
        "valid": True,
        "mode": investigation.get("mode"),
        "llm_mode": (investigation.get("llm_analysis") or {}).get("mode"),
        "manifest_file_count": len(manifest.get("files", [])),
        "lifecycle_verified": True,
        "splunk_lifecycle_verified": bool(splunk_verification.get("matches_expected_lifecycle_shape")),
    }


def _validate_manifest_hashes(evidence_dir: Path, manifest: dict) -> None:
    for item in manifest.get("files", []):
        relative = item.get("path")
        expected = item.get("sha256")
        if not relative or not expected:
            raise EvidenceValidationError("manifest entry missing path or sha256")
        path = evidence_dir / relative
        if not path.exists():
            raise EvidenceValidationError(f"manifest file missing: {relative}")
        actual = sha256_file(path)
        if actual != expected:
            raise EvidenceValidationError(f"hash mismatch for {relative}")


def render_markdown(investigation: dict) -> str:
    if "advisory_workflow" in investigation:
        return render_rollback_markdown(investigation)
    findings = "\n".join(
        f"- **{item['severity']}** `{item['id']}`: {item['observation']} Hypothesis: {item['hypothesis']} Uncertainty: {item['uncertainty']}"
        for item in investigation["findings"]
    )
    queries = "\n".join(f"- `{item['id']}`: `{item['query']}`" for item in investigation["queries"])
    verification = json.dumps(investigation.get("splunk_result_verification", {}), indent=2, sort_keys=True)
    results = "\n".join(
        f"- `{item['query_id']}` returned {len(item.get('rows', []))} row(s)."
        for item in investigation.get("splunk_rest_results", [])
    ) or "- No Splunk REST result rows are present in this evidence package."
    lifecycle = json.dumps(investigation.get("lifecycle", {}), indent=2, sort_keys=True)
    return f"""# Splunk Incident Investigation Report

Mode: `{investigation['mode']}`

## Lifecycle Verification

```json
{lifecycle}
```

## Metrics

```json
{json.dumps(investigation['metrics'], indent=2, sort_keys=True)}
```

## Findings

{findings}

## SPL Query Plan

{queries}

## Executed SPL Results

{results}

```json
{verification}
```

## LLM-Safe Analysis

Mode: `{investigation['llm_analysis']['mode']}`

{investigation['llm_analysis']['summary']}

Safety note: {investigation['llm_analysis']['safety']}
"""


def render_html(investigation: dict) -> str:
    if "advisory_workflow" in investigation:
        return render_rollback_html(investigation)
    rows = "\n".join(
        f"<tr><td>{event['timestamp']}</td><td>{event['status']}</td><td>{event['latency_ms']}</td><td><code>{event['trace_id']}</code></td><td>{event['message']}</td></tr>"
        for event in investigation["timeline"]
    )
    findings = "\n".join(
        f"<details open><summary>{item['severity']} {item['id']}</summary><p>{item['observation']}</p><p>{item['hypothesis']}</p><p>{item['uncertainty']}</p></details>"
        for item in investigation["findings"]
    )
    queries = "\n".join(
        f"<tr><td><code>{escape(item['id'])}</code></td><td>{escape(item['purpose'])}</td><td><code>{escape(item['query'])}</code></td></tr>"
        for item in investigation["queries"]
    )
    splunk_results = "\n".join(
        f"<details open><summary>{escape(item['query_id'])}: {len(item.get('rows', []))} rows</summary><pre>{escape(json.dumps(item.get('rows', []), indent=2, sort_keys=True))}</pre></details>"
        for item in investigation.get("splunk_rest_results", [])
    ) or "<p>No Splunk REST result rows are present in this evidence package.</p>"
    verification = escape(json.dumps(investigation.get("splunk_result_verification", {}), sort_keys=True))
    lifecycle = escape(json.dumps(investigation.get("lifecycle", {}), indent=2, sort_keys=True))
    llm = investigation["llm_analysis"]
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Splunk Incident Investigation</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #202124; }}
table {{ border-collapse: collapse; width: 100%; }}
td, th {{ border: 1px solid #d0d7de; padding: .45rem; text-align: left; }}
th {{ background: #f6f8fa; }}
details {{ border: 1px solid #d0d7de; border-radius: 6px; padding: .65rem; margin: .75rem 0; }}
code, pre {{ background: #f6f8fa; }}
pre {{ overflow: auto; padding: .75rem; }}
</style>
</head>
<body>
<h1>Splunk Incident Investigation</h1>
<p>Mode: <code>{investigation['mode']}</code></p>
<p>LLM: <code>{escape(llm['mode'])}</code></p>
<h2>Lifecycle Verification</h2>
<pre>{lifecycle}</pre>
<h2>Executed SPL Queries</h2>
<table><tr><th>ID</th><th>Purpose</th><th>SPL</th></tr>{queries}</table>
<h2>Findings</h2>
{findings}
<h2>Timeline</h2>
<table><tr><th>Time</th><th>Status</th><th>Latency ms</th><th>Trace</th><th>Message</th></tr>{rows}</table>
<h2>Evidence Navigation</h2>
<p>Splunk verification: <code>{verification}</code></p>
<p>{escape(llm.get('summary', ''))}</p>
<p>Safety note: {escape(llm.get('safety', ''))}</p>
{splunk_results}
</body>
</html>
"""


def _validate_rollback_advisory(investigation: dict, manifest: dict) -> dict:
    workflow = investigation["advisory_workflow"]
    hypotheses = workflow.get("ranked_hypotheses") or []
    if not hypotheses:
        raise EvidenceValidationError("rollback advisory has no ranked hypotheses")
    if "Deployment timing starts the investigation" not in workflow.get("decision_boundary", ""):
        raise EvidenceValidationError("rollback advisory is missing causality boundary")
    if not workflow.get("recommended_next_checks"):
        raise EvidenceValidationError("rollback advisory is missing recommended next checks")
    verification = investigation.get("splunk_result_verification") or {}
    if "splunk_rest_results" in investigation and not verification.get("all_required_queries_executed"):
        raise EvidenceValidationError("rollback advisory is missing required query results")
    return {
        "valid": True,
        "mode": investigation.get("mode"),
        "llm_mode": (investigation.get("llm_analysis") or {}).get("mode"),
        "manifest_file_count": len(manifest.get("files", [])),
        "rollback_advisory_verified": True,
        "top_hypothesis": hypotheses[0].get("id"),
    }


def render_rollback_markdown(investigation: dict) -> str:
    workflow = investigation["advisory_workflow"]
    hypotheses = "\n".join(
        "\n".join(
            [
                f"### {item['rank']}. {item['label']}",
                f"- Score: `{item['score']}` ({item['support_level']})",
                f"- Supporting evidence: `{', '.join(item['supporting_evidence_event_ids']) or 'none'}`",
                f"- Contradicting evidence: `{', '.join(item['contradicting_evidence_event_ids']) or 'none'}`",
                f"- Missing information: `{', '.join(item['missing_information']) or 'none'}`",
                f"- Evidence queries: `{', '.join(item['evidence_query_ids'])}`",
            ]
        )
        for item in workflow["ranked_hypotheses"]
    )
    queries = "\n".join(f"- `{item['id']}`: `{item['query']}`" for item in investigation["queries"])
    results = "\n".join(
        f"- `{item['query_id']}` returned {len(item.get('rows', []))} row(s)."
        for item in investigation.get("splunk_rest_results", [])
    ) or "- No query result rows are present in this evidence package."
    return f"""# Rollback Advisory Incident Brief

Question: **{workflow['question']}**

Mode: `{investigation['mode']}`

Service: `{workflow['service']}`

Deployment time: `{workflow['deployment_time']}`

Decision boundary: {workflow['decision_boundary']}

## What Changed

```json
{json.dumps(workflow['baseline_incident_comparison'], indent=2, sort_keys=True)}
```

## Recommendation

{workflow['advisory_recommendation']}

## Ranked Hypotheses

{hypotheses}

## Missing Information

{chr(10).join(f"- {item}" for item in workflow['missing_information']) or "- none"}

## Recommended Next Checks

{chr(10).join(f"- {item}" for item in workflow['recommended_next_checks'])}

## Follow-up Recovery Assessment

{workflow['follow_up_recovery_assessment']['assessment']}

{workflow['follow_up_recovery_assessment']['causality_boundary']}

## Executed SPL

{queries}

## Query Results

{results}

## LLM-Safe Analysis

Mode: `{investigation['llm_analysis']['mode']}`

{investigation['llm_analysis']['summary']}

Safety note: {investigation['llm_analysis']['safety']}
"""


def render_rollback_html(investigation: dict) -> str:
    workflow = investigation["advisory_workflow"]
    hypothesis_blocks = "\n".join(
        "<details open>"
        f"<summary>{item['rank']}. {escape(item['label'])} ({item['support_level']}, {item['score']})</summary>"
        f"<p>Supporting evidence: <code>{escape(', '.join(item['supporting_evidence_event_ids']) or 'none')}</code></p>"
        f"<p>Contradicting evidence: <code>{escape(', '.join(item['contradicting_evidence_event_ids']) or 'none')}</code></p>"
        f"<p>Missing information: <code>{escape(', '.join(item['missing_information']) or 'none')}</code></p>"
        f"<p>Evidence queries: <code>{escape(', '.join(item['evidence_query_ids']))}</code></p>"
        "</details>"
        for item in workflow["ranked_hypotheses"]
    )
    query_rows = "\n".join(
        f"<tr><td><code>{escape(item['id'])}</code></td><td>{escape(item['purpose'])}</td><td><code>{escape(item['query'])}</code></td></tr>"
        for item in investigation["queries"]
    )
    timeline_rows = "\n".join(
        f"<tr id=\"{escape(event['id'])}\"><td>{escape(event['timestamp'])}</td><td>{escape(event['signal_type'])}</td><td>{escape(str(event['status']))}</td><td>{escape(str(event['latency_ms']))}</td><td><code>{escape(event['trace_id'])}</code></td><td>{escape(event['message'])}</td></tr>"
        for event in investigation["timeline"]
    )
    result_blocks = "\n".join(
        "<details open>"
        f"<summary>{escape(item['query_id'])}: {len(item.get('rows', []))} rows</summary>"
        f"<pre>{escape(json.dumps(item.get('rows', []), indent=2, sort_keys=True))}</pre>"
        "</details>"
        for item in investigation.get("splunk_rest_results", [])
    ) or "<p>No query result rows are present in this evidence package.</p>"
    llm = investigation["llm_analysis"]
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Rollback Advisory Incident Brief</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #202124; }}
table {{ border-collapse: collapse; width: 100%; }}
td, th {{ border: 1px solid #d0d7de; padding: .45rem; text-align: left; vertical-align: top; }}
th {{ background: #f6f8fa; }}
details, .panel {{ border: 1px solid #d0d7de; border-radius: 6px; padding: .65rem; margin: .75rem 0; }}
code, pre {{ background: #f6f8fa; }}
pre {{ overflow: auto; padding: .75rem; }}
</style>
</head>
<body>
<h1>Rollback Advisory Incident Brief</h1>
<p>Question: <strong>{escape(workflow['question'])}</strong></p>
<p>Mode: <code>{escape(investigation['mode'])}</code> | LLM: <code>{escape(llm['mode'])}</code></p>
<p>{escape(workflow['decision_boundary'])}</p>
<section class="panel">
<h2>Recommendation</h2>
<p>{escape(workflow['advisory_recommendation'])}</p>
</section>
<h2>What Changed</h2>
<pre>{escape(json.dumps(workflow['baseline_incident_comparison'], indent=2, sort_keys=True))}</pre>
<h2>Ranked Hypotheses</h2>
{hypothesis_blocks}
<h2>Missing Information</h2>
<ul>{''.join(f'<li>{escape(item)}</li>' for item in workflow['missing_information']) or '<li>none</li>'}</ul>
<h2>Recommended Next Checks</h2>
<ul>{''.join(f'<li>{escape(item)}</li>' for item in workflow['recommended_next_checks'])}</ul>
<h2>Follow-up Recovery Assessment</h2>
<p>{escape(workflow['follow_up_recovery_assessment']['assessment'])}</p>
<p>{escape(workflow['follow_up_recovery_assessment']['causality_boundary'])}</p>
<h2>Executed SPL</h2>
<table><tr><th>ID</th><th>Purpose</th><th>SPL</th></tr>{query_rows}</table>
<h2>Timeline</h2>
<table><tr><th>Time</th><th>Signal</th><th>Status</th><th>Latency</th><th>Trace</th><th>Message</th></tr>{timeline_rows}</table>
<h2>Evidence Links</h2>
{result_blocks}
</body>
</html>
"""
