from __future__ import annotations

import hashlib
import json
import zipfile
from datetime import datetime, timezone
from html import escape
from pathlib import Path


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


def render_markdown(investigation: dict) -> str:
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
    return f"""# Splunk Incident Investigation Report

Mode: `{investigation['mode']}`

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
