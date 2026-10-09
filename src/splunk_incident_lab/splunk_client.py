from __future__ import annotations

import base64
import json
import ssl
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib import error, parse, request

from .scenario import Event, read_events


class SplunkClientError(RuntimeError):
    pass


class SplunkAuthenticationError(SplunkClientError):
    pass


class SplunkResponseError(SplunkClientError):
    pass


@dataclass(frozen=True)
class SplunkQuery:
    id: str
    purpose: str
    query: str


SPL_QUERY_PLAN = [
    SplunkQuery(
        id="spl-latency-spike",
        purpose="Find checkout latency spikes above 750 ms.",
        query=(
            'search index=main source="splunk-incident-lab:checkout" '
            '| spath | search service=checkout-api endpoint="/checkout" latency_ms>750 '
            '| dedup trace_id | table _time trace_id status latency_ms message'
        ),
    ),
    SplunkQuery(
        id="spl-error-rate",
        purpose="Find checkout HTTP errors during the incident window.",
        query=(
            'search index=main source="splunk-incident-lab:checkout" '
            '| spath | search service=checkout-api endpoint="/checkout" status>=500 '
            '| stats count by status message'
        ),
    ),
    SplunkQuery(
        id="spl-lifecycle-phase-health",
        purpose="Compare baseline, injected-failure, and recovered checkout health.",
        query=(
            'search index=main source="splunk-incident-lab:checkout" '
            '| spath | search service=checkout-api endpoint="/checkout" '
            '| stats dc(trace_id) as events avg(latency_ms) as avg_latency_ms '
            'max(latency_ms) as max_latency_ms dc(eval(if(status>=500, trace_id, null()))) as errors '
            'by scenario_phase'
        ),
    ),
    SplunkQuery(
        id="spl-root-cause-ground-truth",
        purpose="Verify the controlled fault ground truth is only present during injected failure.",
        query=(
            'search index=main source="splunk-incident-lab:checkout" '
            '| spath | search service=checkout-api endpoint="/checkout" '
            'root_cause_ground_truth="payment-provider-timeout" '
            '| dedup trace_id | table _time trace_id scenario_phase fault_injected status latency_ms message root_cause_ground_truth'
        ),
    ),
]


def query_plan_as_dicts() -> list[dict]:
    return [asdict(item) for item in SPL_QUERY_PLAN]


class SplunkRestClient:
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        *,
        verify_tls: bool = False,
        timeout: int = 30,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.timeout = timeout
        self.context = None if verify_tls else ssl._create_unverified_context()

    def verify_ready(self) -> dict:
        info = self._json_request("GET", "/services/server/info", {"output_mode": "json"})
        license_info = self._json_request("GET", "/services/licenser/licenses", {"output_mode": "json"})
        return {
            "server_info": info,
            "license_info": license_info,
            "auth": "basic",
            "rest_api": self.base_url,
        }

    def ingest_events(self, events_path: Path) -> dict:
        events = read_events(events_path)
        for event in events:
            self.ingest_event(event)
        return {
            "event_count": len(events),
            "source": "splunk-incident-lab:checkout",
            "sourcetype": "_json",
            "index": "main",
        }

    def ingest_event(self, event: Event) -> None:
        params = {
            "index": "main",
            "source": "splunk-incident-lab:checkout",
            "sourcetype": "_json",
            "host": "local-lab",
            "output_mode": "json",
        }
        body = json.dumps(asdict(event), sort_keys=True).encode("utf-8")
        self._json_request("POST", "/services/receivers/simple", params, body)

    def run_searches(self, queries: list[SplunkQuery] | None = None) -> list[dict]:
        results: list[dict] = []
        for query in queries or SPL_QUERY_PLAN:
            response = self.run_search(query.query)
            results.append(
                {
                    "query_id": query.id,
                    "purpose": query.purpose,
                    "query": query.query,
                    "rows": response,
                }
            )
        return results

    def run_search(self, spl: str) -> list[dict]:
        payload = parse.urlencode(
            {
                "search": spl,
                "output_mode": "json",
                "exec_mode": "oneshot",
            }
        ).encode("utf-8")
        raw = self._request("POST", "/services/search/jobs/oneshot", None, payload)
        return parse_oneshot_results(raw)

    def _json_request(
        self,
        method: str,
        path: str,
        params: dict[str, str] | None = None,
        body: bytes | None = None,
    ) -> dict:
        raw = self._request(method, path, params, body)
        if not raw:
            return {}
        try:
            payload = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise SplunkResponseError(f"Splunk returned malformed JSON from {path}") from exc
        if not isinstance(payload, dict):
            raise SplunkResponseError(f"Splunk returned unexpected JSON from {path}")
        return payload

    def _request(
        self,
        method: str,
        path: str,
        params: dict[str, str] | None,
        body: bytes | None,
    ) -> bytes:
        url = f"{self.base_url}{path}"
        if params:
            url = f"{url}?{parse.urlencode(params)}"
        req = request.Request(
            url,
            data=body,
            method=method,
            headers={
                "Authorization": self._auth_header(),
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        try:
            with request.urlopen(req, timeout=self.timeout, context=self.context) as response:
                return response.read()
        except error.HTTPError as exc:
            if exc.code in {401, 403}:
                raise SplunkAuthenticationError(f"Splunk authentication failed with HTTP {exc.code}") from exc
            raise SplunkClientError(f"Splunk REST request failed with HTTP {exc.code}: {path}") from exc
        except error.URLError as exc:
            raise SplunkClientError(f"Splunk REST request failed: {exc.reason}") from exc

    def _auth_header(self) -> str:
        token = base64.b64encode(f"{self.username}:{self.password}".encode("utf-8")).decode("ascii")
        return f"Basic {token}"


def parse_oneshot_results(raw: bytes) -> list[dict]:
    text = raw.decode("utf-8").strip()
    if not text:
        return []
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        rows = []
        for line in text.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SplunkResponseError("Splunk search returned malformed JSON") from exc
            if isinstance(item, dict) and isinstance(item.get("result"), dict):
                rows.append(item["result"])
            elif isinstance(item, dict):
                rows.append(item)
            else:
                raise SplunkResponseError("Splunk search returned unexpected JSON lines")
        return rows
    if isinstance(payload, dict) and isinstance(payload.get("results"), list):
        return payload["results"]
    if isinstance(payload, dict) and isinstance(payload.get("result"), dict):
        return [payload["result"]]
    if isinstance(payload, list):
        return payload
    raise SplunkResponseError("Splunk search returned unexpected JSON")
