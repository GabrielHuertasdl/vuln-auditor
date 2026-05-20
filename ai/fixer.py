"""Remediation guidance via Gemini or Claude API.

Resilience features:
  - Per-request timeout (AI_TIMEOUT_SECONDS)
  - Retry with exponential backoff (AI_MAX_RETRIES)
  - Provider fallback: Gemini → Anthropic
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from ai.prompts import MITIGATION_PROMPT, SYSTEM_PROMPT
from core.schemas import Finding

log = logging.getLogger(__name__)

_CONDENSED_FIELDS = ("id", "title", "severity", "confidence", "owasp_category", "cwe_ids", "host", "port", "path")


def _condense(findings: list[Finding]) -> list[dict]:
    return [{k: getattr(f, k, None) for k in _CONDENSED_FIELDS} for f in findings]


async def _call_with_timeout_retry(coro_factory, timeout: float, max_retries: int, label: str) -> Any:
    last_error = None
    for attempt in range(1, max_retries + 1):
        try:
            return await asyncio.wait_for(coro_factory(), timeout=timeout)
        except asyncio.TimeoutError:
            last_error = TimeoutError(f"{label} timed out after {timeout}s (attempt {attempt})")
            log.warning("%s timed out (attempt %d/%d)", label, attempt, max_retries)
        except Exception as e:
            last_error = e
            log.warning("%s failed (attempt %d/%d): %s", label, attempt, max_retries, e)

        if attempt < max_retries:
            await asyncio.sleep(2 ** (attempt - 1))

    raise last_error or RuntimeError(f"{label} failed after {max_retries} attempts")


async def get_mitigations(findings: list[Finding], settings: Any) -> dict[str, dict[str, str]]:
    if not findings:
        return {}

    condensed = _condense(findings)
    payload = {"findings": condensed}
    prompt = MITIGATION_PROMPT.format(findings_json=json.dumps(payload, indent=2, default=str))

    timeout = getattr(settings, "ai_timeout_seconds", 30)
    max_retries = getattr(settings, "ai_max_retries", 2)

    if settings.gemini_api_key:
        try:
            import google.generativeai as genai

            async def _call_gemini():
                genai.configure(api_key=settings.gemini_api_key)
                model = genai.GenerativeModel(settings.gemini_model, system_instruction=SYSTEM_PROMPT)
                response = await model.generate_content_async(prompt)
                text = response.text.replace("```json", "").replace("```", "").strip()
                data = json.loads(text)
                return data.get("mitigations", {})

            return await _call_with_timeout_retry(_call_gemini, timeout, max_retries, "Gemini mitigations")
        except Exception as e:
            log.warning("Gemini mitigation generation failed, falling back to Anthropic: %s", e)

    if settings.anthropic_api_key:
        try:
            import anthropic

            async def _call_anthropic():
                client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
                response = await client.messages.create(
                    model=settings.anthropic_model,
                    max_tokens=4096,
                    system=SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": prompt}],
                )
                text = response.content[0].text
                data = json.loads(text)
                return data.get("mitigations", {})

            return await _call_with_timeout_retry(_call_anthropic, timeout, max_retries, "Anthropic mitigations")
        except Exception as e:
            log.warning("Anthropic mitigation generation failed: %s", e)

    return {}


def apply_ai_results(
    findings: list[Finding], mitigations: dict[str, dict[str, str]], executive_summary: str
) -> list[Finding]:
    """Merge AI-generated mitigations and summary back into finding objects."""
    updated = []
    for f in findings:
        m = mitigations.get(f.id, {})
        updated.append(f.model_copy(update={
            "ai_mitigation": m.get("mitigation"),
            "ai_executive_summary": executive_summary,
        }))
    return updated
