# Splunk AI Incident Investigator

Read-only incident investigation lab for Splunk Enterprise. The project is CLI-first and produces decomposable evidence that can be recomposed into incident timelines, findings, and portable reports.

## Current vertical slice

This first slice provides:

- Pinned Splunk Docker Compose lab wiring using `splunk/splunk:10.0`.
- Explicit license/general-terms gate before starting Splunk.
- Deterministic synthetic checkout telemetry with one injected latency incident.
- Bounded SPL query plan and read-only investigation logic.
- Splunk REST client for readiness/license/auth checks, JSON event ingest, and executed one-shot SPL searches.
- Optional OpenAI-compatible LLM analysis path fed by retrieved evidence; deterministic template mode remains the labeled fallback.
- Evidence export with raw events, executed SPL results, timeline, findings, SHA-256 manifest, JSON, Markdown report, HTML report, and ZIP package.
- Browser evidence UI served from the generated investigation package for queries, findings, timeline, and evidence navigation.
- Kubernetes manifests for the synthetic telemetry generator.
- Unit tests for the investigation engine, evidence package, Splunk REST success/auth/empty/malformed response behavior, and configurable LLM provider calls.
- LinkedIn and Upwork publication drafts in `docs/publication-drafts.md`.

Splunk’s 10.x Docker image path requires both:

- `SPLUNK_START_ARGS=--accept-license`
- `SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com`

Do not run `make lab-up` unless the operator has authority to accept those terms for this local lab. Splunk's current General Terms state that if you do not agree to the terms, or are not authorized to accept them for the customer, you must not download, install, access, or use the offering.

Sources checked on 2026-10-08:

- Splunk Docker repository: https://github.com/splunk/docker-splunk
- Splunk Docker Hub image page: https://hub.docker.com/r/splunk/splunk
- Splunk container deployment docs: https://help.splunk.com/en/splunk-enterprise/get-started/install-and-upgrade/9.3/install-splunk-enterprise-in-virtual-and-containerized-environments/deploy-and-run-splunk-enterprise-inside-a-docker-container
- Splunk General Terms: https://www.splunk.com/en_us/legal/splunk-general-terms.html

## Quick start without Splunk

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
make lab-seed
make lab-investigate
make lab-export
make test
```

Reports are written under `evidence/latest/`.

Downloadable/generated formats:

- `investigation.json`: canonical machine-readable investigation, timeline, findings, LLM analysis, and Splunk verification.
- `report.md`: portable Markdown report.
- `report.html`: portable HTML report with query, timeline, finding, and evidence sections.
- `manifest.json`: SHA-256 manifest for generated evidence files.
- `splunk-incident-evidence.zip`: complete downloadable evidence package.

PDF export is not implemented in this slice. If a PDF is required for a release channel, generate it from `report.html` as an explicit downstream packaging step and record that step in the release acceptance report.

## Splunk lab gate

```bash
export ACCEPT_SPLUNK_TERMS=1
export SPLUNK_PASSWORD='change-this-password'
make lab-up
make lab-seed
make lab-investigate SPLUNK_MODE=rest
make lab-export
make lab-down
```

`SPLUNK_MODE=rest` verifies Splunk readiness, licensing endpoint access, authentication, REST API access, ingests the deterministic event file into Splunk, and executes the bounded SPL plan against `/services/search/jobs/oneshot`. The default mode uses the deterministic local event file so the evidence/reporting path can be developed and tested before license acceptance and full integration.

The compose lab intentionally does not set `SPLUNK_LICENSE_URI=Free`. Splunk's free license disables authenticated remote login, which prevents the REST API checks and executed SPL path this project is designed to verify.

## LLM investigation path

The deterministic template analysis remains the default fallback and is labeled `bounded-template` in `investigation.json`. To exercise an actual model-backed path, configure an OpenAI-compatible chat-completions provider:

```bash
export LLM_API_BASE_URL="https://api.openai.com/v1"
export LLM_API_KEY="..."
export LLM_MODEL="..."
make lab-investigate SPLUNK_MODE=rest
```

When those values are present, retrieved evidence is supplied to the model and `llm_analysis.mode` is written as `llm-provider`. Do not claim LLM-assisted investigation unless this path has been run with a real provider response captured in the exported evidence.

The evidence context distinguishes synthetic telemetry that was ingested into real Splunk and retrieved through executed SPL from local-only deterministic file analysis. Synthetic telemetry validates the integration path and investigation workflow; it does not prove a real third-party provider outage.

## Kubernetes

The manifests in `k8s/` deploy a synthetic telemetry generator. A local `kind` cluster is required for `make lab-deploy`.

The Kubernetes generator emits the same deterministic checkout incident shape as the CLI seed path so local files, Splunk ingest, and cluster telemetry can be compared without random drift.

## Evidence UI

After generating evidence, start the local UI/backend:

```bash
splunk-incident-lab serve --evidence evidence/latest --port 8080
```

Open `http://127.0.0.1:8080/` to inspect the investigation. The UI is backed by these local JSON endpoints:

- `/api/queries`
- `/api/findings`
- `/api/timeline`
- `/api/evidence`
- `/api/investigation`

## Publication drafts

LinkedIn and Upwork drafts are available in `docs/publication-drafts.md`.

## Public-source release acceptance

This project is not publication-ready until it passes the FYZ-1701 public-source release gate from `../docs/FYZ-1701-public-source-release-acceptance.md`: public GitHub clone, recorded commit SHA, README-only rebuild, real Docker/Kubernetes execution where applicable, generated evidence package validation, teardown, reconstruction, and a PASS acceptance report. Do not promote the project on LinkedIn or Upwork until that acceptance report passes for the final public commit.

## Dependencies and license

Runtime dependency:

- `certifi`, used for LLM-provider TLS verification.

Development/test dependency:

- `pytest`, used by `make test`.

External tools used by the full integration path:

- Docker and Docker Compose.
- `kubectl`.
- `kind`.

This repository's original source is MIT licensed. Splunk Enterprise, the `splunk/splunk` container image, Docker, Kubernetes, kind, pytest, certifi, and any configured LLM provider remain governed by their own upstream licenses and terms. Do not commit API keys, Splunk passwords, generated evidence containing private operational data, or proprietary customer telemetry.

## Reproducibility status

- Docker CLI available locally: verified.
- `kubectl` client available locally: verified.
- `kind` CLI available locally: verified.
- Splunk license/general terms acceptance: authorized for the local lab on FYZ-1702 interaction `bfdb99cd-ff4c-45d5-b685-3ecfdf164112`.
