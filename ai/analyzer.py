"""Executive summary generation via Gemini or Claude API.

Resilience features:
  - Per-request timeout (AI_TIMEOUT_SECONDS)
  - Retry with exponential backoff (AI_MAX_RETRIES)
  - Provider fallback: Gemini → Anthropic
  - Clear error messages on partial failure
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from ai.prompts import EXECUTIVE_SUMMARY_PROMPT, SYSTEM_PROMPT
from core.schemas import Finding

log = logging.getLogger(__name__)

_CONDENSED_FIELDS = ("id", "title", "severity", "confidence", "owasp_category", "sources", "host", "port")


def _condense(findings: list[Finding]) -> list[dict]:
    return [{k: getattr(f, k, None) for k in _CONDENSED_FIELDS} for f in findings]


async def _call_with_timeout_retry(coro_factory, timeout: float, max_retries: int, label: str) -> Any:
    """Call an async coroutine factory with timeout + exponential backoff retry."""
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
            await asyncio.sleep(2 ** (attempt - 1))  # 1s, 2s backoff

    raise last_error or RuntimeError(f"{label} failed after {max_retries} attempts")


async def get_executive_summary(findings: list[Finding], settings: Any) -> str:
    if not findings:
        return "No findings were detected during this scan."

    condensed = _condense(findings)
    severity_counts: dict[str, int] = {}
    for f in findings:
        severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

    payload = {"findings": condensed, "severity_counts": severity_counts}
    prompt = EXECUTIVE_SUMMARY_PROMPT.format(findings_json=json.dumps(payload, indent=2, default=str))

    timeout = getattr(settings, "ai_timeout_seconds", 30)
    max_retries = getattr(settings, "ai_max_retries", 2)

    # Try Gemini first
    if settings.gemini_api_key:
        try:
            import google.generativeai as genai

            async def _call_gemini():
                genai.configure(api_key=settings.gemini_api_key)
                model = genai.GenerativeModel(settings.gemini_model, system_instruction=SYSTEM_PROMPT)
                response = await model.generate_content_async(prompt)
                text = response.text.replace("```json", "").replace("```", "").strip()
                data = json.loads(text)
                return data.get("summary", text)

            return await _call_with_timeout_retry(_call_gemini, timeout, max_retries, "Gemini summary")
        except Exception as e:
            log.warning("Gemini summary generation failed, falling back to Anthropic: %s", e)

    # Fallback to Anthropic
    if settings.anthropic_api_key:
        try:
            import anthropic

            async def _call_anthropic():
                client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
                response = await client.messages.create(
                    model=settings.anthropic_model,
                    max_tokens=1024,
                    system=SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": prompt}],
                )
                text = response.content[0].text
                try:
                    data = json.loads(text)
                    return data.get("summary", text)
                except json.JSONDecodeError:
                    return text

            return await _call_with_timeout_retry(_call_anthropic, timeout, max_retries, "Anthropic summary")
        except Exception as e:
            log.warning("Anthropic summary generation failed: %s", e)

    return ""
