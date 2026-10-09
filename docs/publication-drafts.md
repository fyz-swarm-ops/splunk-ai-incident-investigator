# Publication Drafts

## LinkedIn

I built a Day 1 vertical slice for a Splunk AI Incident Investigator around a practical operator question: should we roll back this deployment?

The lab compares checkout health before and after a deployment, ranks competing explanations, links each recommendation to executed SPL and event evidence, and tells the engineer what to check next. The demo includes database connection-pool exhaustion, a coincidental payment-provider timeout, an inconclusive degradation, and a healthy negative control.

The interesting part is the constraint: deployment timing is a hypothesis, not the answer. The AI layer is not allowed to invent a root cause. It separates observations, hypotheses, uncertainty, missing information, and evidence references so a human reviewer can inspect exactly what supports the incident narrative.

Current status: the live Splunk REST path, Kubernetes telemetry generator, LLM-provider investigation path, teardown, and clean reproduction have been verified in the development workspace. Public promotion remains gated on a fresh-clone public GitHub acceptance test from the published repository.

## Upwork

Subject: Splunk rollback-decision investigation lab with evidence-grade AI reporting

Hi,

I can build a reproducible Splunk incident investigation workflow that turns telemetry into a structured, reviewable operator brief. The first slice answers: "Should we roll back this deployment?"

- Docker Compose lab using the official Splunk image.
- Deterministic synthetic incident injection.
- Bounded read-only SPL query plan.
- Baseline versus post-deployment health comparison.
- Ranked competing hypotheses for deployment regression, database pool exhaustion, payment-provider timeout, and insufficient evidence.
- Missing-information and next-check recommendations before rollback.
- Evidence export with raw events, executed query results, findings, reports, SHA-256 manifest, and ZIP package.
- Browser evidence UI for queries, findings, timeline, and evidence navigation.
- Kubernetes telemetry generator manifests for local cluster reproduction.
- Clear teardown and reproduction instructions.

For environments using the official Splunk Docker image, I require an authorized operator to accept Splunk license/general terms before running live Splunk. Synthetic telemetry validates the reproducible investigation path, but it is labeled as synthetic and does not claim a real third-party provider outage.
