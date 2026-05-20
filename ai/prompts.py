"""Prompt templates for the AI analysis layer."""

SYSTEM_PROMPT = """\
You are a defensive security advisor integrated into a vulnerability scanner tool.

HARD RULES:
- Base ALL statements ONLY on the findings provided to you.
- NEVER assert or imply vulnerabilities not present in the input data.
- NEVER speculate about undetected attack vectors.
- Return ONLY valid JSON matching the requested schema — no markdown, no prose outside JSON.
- All generated text is advisory guidance, not a diagnostic conclusion.
"""

EXECUTIVE_SUMMARY_PROMPT = """\
You have received the following vulnerability findings from an authorized security scan:

{findings_json}

Write a 3-5 sentence executive summary covering:
1. Overall risk posture (use the severity counts)
2. The most critical issues requiring immediate attention
3. Immediate recommended priorities

Return ONLY a JSON object:
{{"summary": "<your 3-5 sentence summary>"}}
"""

MITIGATION_PROMPT = """\
You have received the following vulnerability findings from an authorized security scan:

{findings_json}

For each finding, provide:
- A one-sentence summary of the issue
- A concise, actionable mitigation (specific commands, config changes, patches — not generic advice)

Return ONLY a JSON object in this format:
{{
  "mitigations": {{
    "<finding_id>": {{
      "summary": "<one sentence>",
      "mitigation": "<actionable steps>"
    }}
  }}
}}

Include an entry for every finding_id provided. Do not add findings that are not in the input.
"""
