from __future__ import annotations

import json
import statistics
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .splunk_client import SplunkQuery


DEPLOYMENT_TIME = "2026-10-09T15:00:00Z"
SERVICE = "checkout-api"
ROLLBACK_CASES = {
    "db-pool-exhaustion": "Deployment-associated database connection-pool exhaustion.",
    "payment-timeout": "Payment-provider timeout coinciding with the deployment.",
    "inconclusive": "Degradation with insufficient evidence to attribute cause.",
    "healthy": "Healthy negative control.",
}


@dataclass(frozen=True)
class RollbackSignal:
    timestamp: str
    service: str
    signal_type: str
    trace_id: str
    status: int
    latency_ms: int
    message: str
    deployment_version: str
    db_pool_in_use: int | None = None
    db_pool_limit: int | None = None
    payment_timeout_count: int | None = None
    payment_provider: str | None = None
    intervention: str | None = None


def write_rollback_events(case: str, path: Path) -> list[RollbackSignal]:
    path.parent.mkdir(parents=True, exist_ok=True)
    events = rollback_events(case)
    with path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(_compact(asdict(event)), sort_keys=True) + "\n")
    return events


def read_rollback_events(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def rollback_events(case: str) -> list[RollbackSignal]:
    if case not in ROLLBACK_CASES:
        raise ValueError(f"unknown rollback case: {case}")
    start = _parse_time(DEPLOYMENT_TIME)
    events: list[RollbackSignal] = []
    for minute in range(-12, 25, 2):
        timestamp = _format_time(start + timedelta(minutes=minute))
        after_deploy = minute >= 0
        recovered = minute >= 16
        intervention_applied = recovered and case != "healthy"
        status = 200
        latency = 105 + (abs(minute) % 5) * 9
        message = "checkout request completed"
        version = "checkout-api@2026.10.09-0" if not after_deploy or intervention_applied else "checkout-api@2026.10.09-1"
        db_in_use: int | None = 18
        db_limit: int | None = 80
        payment_timeouts: int | None = 0
        provider: str | None = "paynet"
        intervention: str | None = "rollback-completed" if intervention_applied else None

        if case == "db-pool-exhaustion" and 2 <= minute <= 12:
            latency = 860 + (minute % 4) * 95
            status = 500 if minute in {6, 10} else 200
            db_in_use = 80
            db_limit = 80
            message = "database connection checkout waited for pool capacity"
        elif case == "payment-timeout" and 2 <= minute <= 12:
            latency = 790 + (minute % 5) * 120
            status = 504 if minute in {4, 8} else 200
            payment_timeouts = 4 if minute in {4, 8, 12} else 2
            message = "payment provider request timed out before authorization"
        elif case == "inconclusive" and 2 <= minute <= 12:
            latency = 780 + (minute % 3) * 80
            status = 500 if minute == 8 else 200
            db_in_use = None
            db_limit = None
            payment_timeouts = None
            provider = None
            message = "checkout response slowed; dependency metrics unavailable"
        elif case == "healthy" and after_deploy:
            message = "checkout request completed after deployment"

        if recovered:
            status = 200
            latency = 112 + (minute % 4) * 8
            db_in_use = 20 if case != "inconclusive" else None
            payment_timeouts = 0 if case != "inconclusive" else None
            message = (
                "checkout request completed during follow-up recovery window"
                if intervention_applied
                else "checkout request completed during healthy follow-up window"
            )

        events.append(
            RollbackSignal(
                timestamp=timestamp,
                service=SERVICE,
                signal_type="request",
                trace_id=f"rollback-{case}-{minute:+04d}",
                status=status,
                latency_ms=latency,
                message=message,
                deployment_version=version,
                db_pool_in_use=db_in_use,
                db_pool_limit=db_limit,
                payment_timeout_count=payment_timeouts,
                payment_provider=provider,
                intervention=intervention,
            )
        )
    events.append(
        RollbackSignal(
            timestamp=DEPLOYMENT_TIME,
            service=SERVICE,
            signal_type="deployment",
            trace_id=f"deploy-{case}",
            status=200,
            latency_ms=0,
            message="deployment marker observed for checkout-api",
            deployment_version="checkout-api@2026.10.09-1",
        )
    )
    return sorted(events, key=lambda item: item.timestamp)


def rollback_query_plan(service: str, deployment_time: str, window_minutes: int) -> list[SplunkQuery]:
    base = 'search index=main source="splunk-incident-lab:rollback"'
    time_eval = f'| spath | search service="{service}" | eval observed_timestamp=mvindex(timestamp,-1) | eval event_time=strptime(observed_timestamp,"%Y-%m-%dT%H:%M:%SZ") | eval deploy_time=strptime("{deployment_time}","%Y-%m-%dT%H:%M:%SZ")'
    baseline_where = f"| where signal_type=\"request\" AND event_time < deploy_time AND event_time >= deploy_time - {window_minutes * 60}"
    incident_where = f"| where signal_type=\"request\" AND event_time >= deploy_time AND event_time <= deploy_time + {window_minutes * 60} AND isnull(intervention)"
    recovery_where = "| where signal_type=\"request\" AND isnotnull(intervention)"
    return [
        SplunkQuery(
            id="rollback-baseline-health",
            purpose="Summarize pre-deployment checkout latency and errors.",
            query=f"{base} {time_eval} {baseline_where} | stats count as events avg(latency_ms) as avg_latency_ms max(latency_ms) as max_latency_ms count(eval(status>=500)) as errors",
        ),
        SplunkQuery(
            id="rollback-incident-health",
            purpose="Summarize post-deployment checkout latency and errors.",
            query=f"{base} {time_eval} {incident_where} | stats count as events avg(latency_ms) as avg_latency_ms max(latency_ms) as max_latency_ms count(eval(status>=500)) as errors",
        ),
        SplunkQuery(
            id="rollback-db-pool",
            purpose="Check whether database pool saturation coincides with degradation.",
            query=f"{base} {time_eval} {incident_where} | search db_pool_limit=* | eval pool_pct=100*db_pool_in_use/db_pool_limit | stats max(pool_pct) as max_pool_pct max(db_pool_in_use) as max_db_pool_in_use max(db_pool_limit) as db_pool_limit",
        ),
        SplunkQuery(
            id="rollback-payment-provider",
            purpose="Check whether payment-provider timeout signals independently increased.",
            query=f"{base} {time_eval} {incident_where} | search payment_timeout_count=* | stats sum(payment_timeout_count) as payment_timeouts values(payment_provider) as payment_provider",
        ),
        SplunkQuery(
            id="rollback-deployment-marker",
            purpose="Preserve the deployment timestamp as hypothesis context, not proof of cause.",
            query=f'{base} | spath | search service="{service}" signal_type=deployment | table _time deployment_version message trace_id',
        ),
        SplunkQuery(
            id="rollback-recovery-health",
            purpose="Assess follow-up recovery after a manual intervention.",
            query=f"{base} {time_eval} {recovery_where} | stats count as events avg(latency_ms) as avg_latency_ms max(latency_ms) as max_latency_ms count(eval(status>=500)) as errors values(intervention) as intervention",
        ),
    ]


def query_plan_as_dicts(service: str, deployment_time: str, window_minutes: int) -> list[dict]:
    return [asdict(item) for item in rollback_query_plan(service, deployment_time, window_minutes)]


def build_rollback_investigation(
    events: list[dict],
    *,
    service: str,
    deployment_time: str,
    window_minutes: int,
    mode: str,
    splunk_rest_results: list[dict] | None = None,
    llm_analysis: dict | None = None,
) -> dict:
    records = [{"id": f"rollback-event-{index:03d}", **item} for index, item in enumerate(events)]
    baseline, incident, recovery = _windows(records, deployment_time, window_minutes)
    comparison = {
        "baseline": _health_summary(baseline),
        "incident": _health_summary(incident),
        "recovery": _health_summary(recovery),
    }
    hypotheses = _rank_hypotheses(records, incident, comparison)
    degraded = comparison["incident"]["degraded_against_baseline"]
    recommendation = _recommendation(hypotheses, degraded)
    workflow = {
        "question": "Should we roll back this deployment?",
        "service": service,
        "deployment_time": deployment_time,
        "window_minutes": window_minutes,
        "decision_boundary": "Deployment timing starts the investigation but never establishes causation by itself.",
        "baseline_incident_comparison": comparison,
        "ranked_hypotheses": hypotheses,
        "recommended_next_checks": _next_checks(hypotheses, degraded),
        "missing_information": _missing_information(hypotheses, degraded),
        "follow_up_recovery_assessment": _follow_up_recovery(comparison),
        "advisory_recommendation": recommendation,
    }
    investigation = {
        "schema_version": "splunk-incident-lab.rollback.v1",
        "mode": mode,
        "advisory_workflow": workflow,
        "queries": query_plan_as_dicts(service, deployment_time, window_minutes),
        "timeline": records,
        "findings": _findings_from_hypotheses(hypotheses),
        "metrics": {
            "event_count": len(records),
            "incident_error_count": comparison["incident"]["error_count"],
            "incident_max_latency_ms": comparison["incident"]["max_latency_ms"],
            "hypothesis_count": len(hypotheses),
        },
        "llm_analysis": llm_analysis or {
            "mode": "bounded-template",
            "safety": "The advisory workflow ranks hypotheses from telemetry evidence and does not use hidden scenario labels.",
            "summary": recommendation,
        },
    }
    if splunk_rest_results is not None:
        investigation["splunk_rest_results"] = splunk_rest_results
        investigation["splunk_result_verification"] = verify_rollback_splunk_results(splunk_rest_results)
    return investigation


def verify_rollback_splunk_results(results: list[dict]) -> dict:
    by_id = {item.get("query_id"): item for item in results}
    required = [
        "rollback-baseline-health",
        "rollback-incident-health",
        "rollback-db-pool",
        "rollback-payment-provider",
        "rollback-deployment-marker",
        "rollback-recovery-health",
    ]
    present = [query_id for query_id in required if query_id in by_id]
    return {
        "required_query_count": len(required),
        "present_query_count": len(present),
        "all_required_queries_executed": len(present) == len(required),
        "query_ids": present,
    }


def local_rollback_results(events: list[dict], service: str, deployment_time: str, window_minutes: int) -> list[dict]:
    records = [{"id": f"rollback-event-{index:03d}", **item} for index, item in enumerate(events)]
    baseline, incident, recovery = _windows(records, deployment_time, window_minutes)
    db_rows = [
        item for item in incident
        if item.get("db_pool_in_use") is not None and item.get("db_pool_limit")
    ]
    payment_rows = [
        item for item in incident
        if item.get("payment_timeout_count") is not None and item.get("payment_timeout_count", 0) > 0
    ]
    deployment_rows = [item for item in records if item.get("signal_type") == "deployment"]
    query_rows = {
        "rollback-baseline-health": [_health_summary(baseline)],
        "rollback-incident-health": [_health_summary(incident)],
        "rollback-db-pool": [_db_summary(db_rows)],
        "rollback-payment-provider": [_payment_summary(payment_rows)],
        "rollback-deployment-marker": deployment_rows,
        "rollback-recovery-health": [_health_summary(recovery)],
    }
    return [
        {
            "query_id": query.id,
            "purpose": query.purpose,
            "query": query.query,
            "rows": query_rows[query.id],
        }
        for query in rollback_query_plan(service, deployment_time, window_minutes)
    ]


def _windows(records: list[dict], deployment_time: str, window_minutes: int) -> tuple[list[dict], list[dict], list[dict]]:
    deploy = _parse_time(deployment_time)
    start = deploy - timedelta(minutes=window_minutes)
    end = deploy + timedelta(minutes=window_minutes)
    recovery_start = deploy + timedelta(minutes=16)
    requests = [item for item in records if item.get("signal_type") == "request"]
    baseline = [item for item in requests if start <= _parse_time(item["timestamp"]) < deploy]
    incident = [item for item in requests if deploy <= _parse_time(item["timestamp"]) <= end and not item.get("intervention")]
    recovery = [item for item in requests if _parse_time(item["timestamp"]) >= recovery_start or item.get("intervention")]
    return baseline, incident, recovery


def _health_summary(events: list[dict]) -> dict:
    latencies = [int(item["latency_ms"]) for item in events if int(item.get("latency_ms") or 0) > 0]
    errors = [item for item in events if int(item.get("status") or 0) >= 500]
    baseline_like = bool(events) and not errors and (max(latencies) if latencies else 0) <= 750
    return {
        "event_count": len(events),
        "median_latency_ms": statistics.median(latencies) if latencies else None,
        "max_latency_ms": max(latencies) if latencies else None,
        "error_count": len(errors),
        "healthy": baseline_like,
        "degraded_against_baseline": bool(errors) or bool(latencies and max(latencies) > 750),
        "intervention_count": sum(1 for item in events if item.get("intervention")),
        "interventions": sorted({item["intervention"] for item in events if item.get("intervention")}),
        "evidence_event_ids": [item["id"] for item in events if int(item.get("status") or 0) >= 500 or int(item.get("latency_ms") or 0) > 750],
    }


def _rank_hypotheses(records: list[dict], incident: list[dict], comparison: dict) -> list[dict]:
    degraded = comparison["incident"]["degraded_against_baseline"]
    deploy_marker = [item for item in records if item.get("signal_type") == "deployment"]
    db_supported = [
        item for item in incident
        if item.get("db_pool_in_use") is not None
        and item.get("db_pool_limit")
        and float(item["db_pool_in_use"]) / float(item["db_pool_limit"]) >= 0.95
    ]
    db_normal = [
        item for item in incident
        if item.get("db_pool_in_use") is not None
        and item.get("db_pool_limit")
        and float(item["db_pool_in_use"]) / float(item["db_pool_limit"]) < 0.75
    ]
    payment_supported = [item for item in incident if int(item.get("payment_timeout_count") or 0) > 0]
    missing_db = any(item.get("db_pool_in_use") is None for item in incident)
    missing_payment = any(item.get("payment_timeout_count") is None for item in incident)
    healthy_support = [item for item in incident if int(item.get("status") or 0) < 500 and int(item.get("latency_ms") or 0) <= 750]
    hypotheses = [
        _hypothesis(
            "healthy-negative-control",
            "No actionable post-deployment degradation",
            0.9 if not degraded else 0.05,
            healthy_support if not degraded else [],
            db_supported + payment_supported,
            [],
            ["rollback-baseline-health", "rollback-incident-health"],
        ),
        _hypothesis(
            "deployment-db-pool-exhaustion",
            "Deployment-associated database connection-pool exhaustion",
            0.86 if degraded and db_supported else 0.18 if degraded else 0.05,
            db_supported,
            payment_supported if payment_supported else db_normal,
            ["database pool metrics"] if missing_db else [],
            ["rollback-db-pool", "rollback-incident-health", "rollback-deployment-marker"],
        ),
        _hypothesis(
            "coincidental-payment-provider-timeout",
            "Coincidental payment-provider timeout",
            0.82 if degraded and payment_supported and not db_supported else 0.28 if degraded and payment_supported else 0.05,
            payment_supported,
            db_supported or db_normal,
            ["payment-provider timeout metrics"] if missing_payment else [],
            ["rollback-payment-provider", "rollback-incident-health", "rollback-deployment-marker"],
        ),
        _hypothesis(
            "deployment-regression-unknown",
            "Deployment regression with insufficient specific evidence",
            0.52 if degraded and not db_supported and not payment_supported else 0.2 if degraded else 0.04,
            deploy_marker if degraded else [],
            db_supported + payment_supported,
            [
                item
                for item in ["database pool metrics" if missing_db else "", "payment dependency metrics" if missing_payment else ""]
                if item
            ],
            ["rollback-deployment-marker", "rollback-incident-health"],
        ),
    ]
    hypotheses.sort(key=lambda item: item["score"], reverse=True)
    for rank, item in enumerate(hypotheses, start=1):
        item["rank"] = rank
    return hypotheses


def _hypothesis(
    hypothesis_id: str,
    label: str,
    score: float,
    supporting: list[dict],
    contradicting: list[dict],
    missing: list[str],
    query_ids: list[str],
) -> dict:
    return {
        "id": hypothesis_id,
        "label": label,
        "score": round(score, 2),
        "support_level": "strong" if score >= 0.75 else "partial" if score >= 0.45 else "weak",
        "supporting_evidence_event_ids": [item["id"] for item in supporting],
        "contradicting_evidence_event_ids": [item["id"] for item in contradicting],
        "evidence_query_ids": query_ids,
        "missing_information": missing,
    }


def _findings_from_hypotheses(hypotheses: list[dict]) -> list[dict]:
    findings = []
    for item in hypotheses:
        findings.append(
            {
                "id": f"finding-{item['id']}",
                "severity": "high" if item["rank"] == 1 and item["support_level"] == "strong" else "medium",
                "observation": f"{item['label']} support is {item['support_level']} with score {item['score']}.",
                "hypothesis": item["label"],
                "uncertainty": "Review missing information and contradictory evidence before deciding to roll back.",
                "evidence_event_ids": item["supporting_evidence_event_ids"],
                "evidence_query_ids": item["evidence_query_ids"],
            }
        )
    return findings


def _recommendation(hypotheses: list[dict], degraded: bool) -> str:
    if not degraded:
        return "Do not roll back from this evidence alone; the service remains within the healthy control range."
    top = hypotheses[0]
    if top["id"] == "deployment-db-pool-exhaustion" and top["support_level"] == "strong":
        return "Rollback is a reasonable next check, but confirm connection-pool configuration and saturation on the released version first."
    if top["id"] == "coincidental-payment-provider-timeout" and top["support_level"] == "strong":
        return "Do not prioritize rollback yet; investigate the payment provider path because independent timeout evidence is stronger."
    return "Hold rollback as an option, but collect missing dependency and database evidence before attributing cause."


def _next_checks(hypotheses: list[dict], degraded: bool) -> list[str]:
    if not degraded:
        return ["Continue monitoring post-deployment checkout latency and 5xx rate."]
    checks = [
        "Compare connection-pool configuration and saturation between the deployed and prior version.",
        "Check payment-provider status, timeout counts, and provider-specific traces in the same window.",
        "Inspect deploy diff for database client, connection-pool, retry, and timeout changes.",
    ]
    if hypotheses[0]["id"] == "deployment-db-pool-exhaustion":
        checks.insert(0, "Confirm whether rollback or pool-size correction reduces wait time without changing payment-provider behavior.")
    return checks


def _missing_information(hypotheses: list[dict], degraded: bool) -> list[str]:
    missing = []
    for item in hypotheses:
        missing.extend(item["missing_information"])
    if degraded and not missing:
        missing.append("operator confirmation of deploy diff and manual intervention timing")
    return sorted(set(missing))


def _follow_up_recovery(comparison: dict) -> dict:
    recovery = comparison["recovery"]
    intervention_observed = recovery.get("intervention_count", 0) > 0
    recovered = intervention_observed and recovery["event_count"] > 0 and recovery["healthy"]
    if recovered:
        assessment = "Follow-up health returned to baseline range; this supports operational recovery but does not prove the original cause."
    elif recovery["event_count"] > 0 and recovery["healthy"] and not intervention_observed:
        assessment = "Follow-up health stayed within the healthy range, but no rollback or intervention was observed."
    else:
        assessment = "Follow-up health is missing or still degraded; do not close the incident from this evidence."
    return {
        "recovered": recovered,
        "intervention_observed": intervention_observed,
        "evidence_event_ids": recovery["evidence_event_ids"],
        "assessment": assessment,
        "causality_boundary": "Recovery after rollback or intervention is not treated as proof of deployment causation.",
    }


def _db_summary(rows: list[dict]) -> dict:
    if not rows:
        return {"max_pool_pct": None, "evidence_event_ids": []}
    pcts = [100 * float(item["db_pool_in_use"]) / float(item["db_pool_limit"]) for item in rows]
    return {"max_pool_pct": max(pcts), "evidence_event_ids": [item["id"] for item in rows]}


def _payment_summary(rows: list[dict]) -> dict:
    return {
        "payment_timeouts": sum(int(item.get("payment_timeout_count") or 0) for item in rows),
        "payment_provider": sorted({item.get("payment_provider") for item in rows if item.get("payment_provider")}),
        "evidence_event_ids": [item["id"] for item in rows],
    }


def _compact(payload: dict) -> dict:
    return {key: value for key, value in payload.items() if value is not None}


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _format_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
