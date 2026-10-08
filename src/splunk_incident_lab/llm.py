from __future__ import annotations

import json
import ssl
from dataclasses import dataclass
from urllib import error, request

import certifi


class LlmInvestigationError(RuntimeError):
    pass


@dataclass(frozen=True)
class LlmConfig:
    endpoint: str
    api_key: str
    model: str
    timeout: int = 60


def llm_config_from_env(env: dict[str, str]) -> LlmConfig | None:
    endpoint = env.get("LLM_API_BASE_URL") or env.get("OPENAI_BASE_URL")
    api_key = env.get("LLM_API_KEY") or env.get("OPENAI_API_KEY")
    model = env.get("LLM_MODEL") or env.get("OPENAI_MODEL")
    if not endpoint or not api_key or not model:
        return None
    return LlmConfig(endpoint=endpoint.rstrip("/"), api_key=api_key, model=model)


def analyze_with_llm(config: LlmConfig, evidence: dict) -> dict:
    prompt = {
        "instruction": (
            "Analyze this incident evidence. Return strict JSON with keys "
            "summary, likely_cause, confidence, recommended_actions, and caveats. "
            "Do not invent systems or facts not present in the evidence."
        ),
        "evidence": evidence,
    }
    body = {
        "model": config.model,
        "response_format": {"type": "json_object"},
        "messages": [
            {
                "role": "system",
                "content": "You are a careful incident investigator. Separate observations from hypotheses.",
            },
            {"role": "user", "content": json.dumps(prompt, sort_keys=True)},
        ],
    }
    req = request.Request(
        f"{config.endpoint}/chat/completions",
        data=json.dumps(body).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {config.api_key}",
            "Content-Type": "application/json",
        },
    )
    try:
        context = ssl.create_default_context(cafile=certifi.where())
        with request.urlopen(req, timeout=config.timeout, context=context) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise LlmInvestigationError(f"LLM request failed with HTTP {exc.code}: {detail}") from exc
    except error.URLError as exc:
        raise LlmInvestigationError(f"LLM request failed: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise LlmInvestigationError("LLM provider returned malformed JSON") from exc

    try:
        content = payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise LlmInvestigationError("LLM provider response did not contain message content") from exc

    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as exc:
        raise LlmInvestigationError("LLM analysis content was not strict JSON") from exc

    summary = parsed.get("summary", "")
    if not isinstance(summary, str):
        summary = json.dumps(summary, sort_keys=True)
    return {
        "mode": "llm-provider",
        "provider_endpoint": config.endpoint,
        "model": config.model,
        "safety": "Retrieved evidence was supplied to the model; unsupported claims remain disallowed by prompt contract.",
        "summary": summary,
        "analysis": parsed,
    }
