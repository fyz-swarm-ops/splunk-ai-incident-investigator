# Publication Drafts

## LinkedIn

I built a Day 1 vertical slice for a Splunk AI Incident Investigator: a local incident lab that injects deterministic checkout latency telemetry into real Splunk, runs bounded read-only SPL through the Splunk REST API, uses a configurable LLM-provider investigation path over retrieved evidence, and exports a complete evidence package with raw events, findings, reports, and hashes.

The interesting part is the constraint: the AI layer is not allowed to invent a root cause. It separates observations, hypotheses, uncertainty, and evidence references so a human reviewer can inspect exactly what supports the incident narrative.

Current status: the live Splunk REST path, Kubernetes telemetry generator, LLM-provider investigation path, teardown, and clean reproduction have been verified in the development workspace. Public promotion remains gated on a fresh-clone public GitHub acceptance test from the published repository.

## Upwork

Subject: Splunk incident investigation lab with evidence-grade AI reporting

Hi,

I can build a reproducible Splunk incident investigation workflow that turns telemetry into a structured, reviewable incident report. The first slice includes:

- Docker Compose lab using the official Splunk image.
- Deterministic synthetic incident injection.
- Bounded read-only SPL query plan.
- Evidence export with raw events, executed query results, findings, reports, SHA-256 manifest, and ZIP package.
- Browser evidence UI for queries, findings, timeline, and evidence navigation.
- Kubernetes telemetry generator manifests for local cluster reproduction.
- Clear teardown and reproduction instructions.

For environments using the official Splunk Docker image, I require an authorized operator to accept Splunk license/general terms before running live Splunk. Synthetic telemetry validates the reproducible investigation path, but it is labeled as synthetic and does not claim a real third-party provider outage.
