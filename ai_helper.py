"""
ai_helper.py
------------
AI-powered remediation and risk explanation using the Anthropic Claude API.

Replaces the Ollama/llama3 approach from the example with Claude — no local
model installation required, better quality responses, and works in any
environment with internet access.

Features:
  • generate_remediation()   – step-by-step fix plan for a single issue
  • generate_risk_summary()  – plain-English executive summary for a resource
  • generate_batch_report()  – overall scan narrative for a set of issues
  • Streamlit @st.cache_data compatible (call via cached wrapper in app.py)
"""

from __future__ import annotations

import os
import json
import requests
from typing import Optional

# ── Config ────────────────────────────────────────────────────────────────────
ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
MODEL             = "claude-sonnet-4-20250514"
MAX_TOKENS        = 1024

SEVERITY_CONTEXT = {
    'critical': 'This is a CRITICAL severity issue that represents an immediate, serious risk.',
    'high'    : 'This is a HIGH severity issue requiring urgent attention.',
    'medium'  : 'This is a MEDIUM severity issue that should be addressed soon.',
    'low'     : 'This is a LOW severity issue — a hygiene / best-practice improvement.',
}


def _call_claude(prompt: str, system: str = '') -> str:
    """
    Make a single call to the Anthropic Claude API.
    Returns the text response, or a fallback message on failure.
    """
    api_key = os.getenv('ANTHROPIC_API_KEY', '').strip()
    if not api_key:
        return ('⚠️ AI features are disabled because ANTHROPIC_API_KEY is not set. '
                'Set the key to enable AI remediation and summaries.')

    headers = {
        'Content-Type'      : 'application/json',
        'anthropic-version' : '2023-06-01',
        'x-api-key'         : api_key,
    }

    body: dict = {
        'model'     : MODEL,
        'max_tokens': MAX_TOKENS,
        'messages'  : [{'role': 'user', 'content': prompt}],
    }
    if system:
        body['system'] = system

    try:
        resp = requests.post(ANTHROPIC_API_URL, headers=headers, json=body, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        # Extract text from content blocks
        texts = [block.get('text', '') for block in data.get('content', [])
                 if block.get('type') == 'text']
        return '\n'.join(texts).strip()

    except requests.exceptions.Timeout:
        return '⚠️ AI response timed out. Using static remediation guidance above.'
    except requests.exceptions.RequestException as e:
        return f'⚠️ AI unavailable ({e}). Using static remediation guidance above.'
    except (KeyError, ValueError):
        return '⚠️ Unexpected API response format. Using static remediation guidance above.'


# Public functions

def generate_remediation(issue: dict) -> str:
    """
    Generate a concrete, step-by-step remediation plan for a single issue.

    Args:
        issue: A dict with at least: description, severity, rule_id,
               resource_type, region, waste_cost, data_sensitivity

    Returns:
        A 3-5 step remediation plan as a markdown string.
    """
    sev_context   = SEVERITY_CONTEXT.get(issue.get('severity', 'low'), '')
    sensitivity   = issue.get('data_sensitivity') or 'unknown'
    waste         = issue.get('waste_cost', 0)
    cost_note     = f'This issue wastes ${waste:.2f}/month.' if waste > 0 else ''
    pii_note      = ('⚠️ This resource may contain PII or sensitive data — '
                     'data exposure risk is elevated.' 
                     if issue.get('extra', {}).get('contains_pii') else '')

    prompt = f"""You are a senior AWS cloud security and cost-optimization engineer.

A cloud security scan found the following issue:

Resource Type : {issue.get('resource_type', 'unknown')}
Resource ID   : {issue.get('resource_id', 'unknown')}
Region        : {issue.get('region', 'unknown')}
Rule ID       : {issue.get('rule_id', 'unknown')}
Severity      : {issue.get('severity', 'unknown')} — {sev_context}
Data Sensitivity: {sensitivity}
Issue         : {issue.get('description', '')}
{cost_note}
{pii_note}

Provide a clear, actionable remediation plan with exactly 4 steps.
Format as a numbered list. Each step should be concrete and specific to AWS.
Be direct — no preamble, no closing remarks. Start immediately with "1."
"""

    system = ('You are a concise AWS security expert. '
              'Respond only with the numbered remediation steps. No markdown headers.')
    return _call_claude(prompt, system=system)


def generate_risk_summary(resource_id: str, issues: list[dict], total_rwc: float) -> str:
    """
    Generate a plain-English executive summary for all issues on one resource.
    Useful for the "Resource Detail" panel in the dashboard.

    Args:
        resource_id : The resource being summarised.
        issues      : List of issue dicts for this resource.
        total_rwc   : Pre-computed total RWC score.

    Returns:
        2-3 sentence executive summary.
    """
    issue_lines = '\n'.join(
        f'  - [{i.get("severity","?")}] {i.get("rule_id","?")} : {i.get("description","")}'
        for i in issues
    )
    waste = sum(i.get('waste_cost', 0) for i in issues)

    prompt = f"""You are a cloud risk analyst preparing a brief for a non-technical manager.

Resource: {resource_id}
Total RWC Score: {total_rwc} (higher = more urgent)
Monthly Waste: ${waste:.2f}
Issues found:
{issue_lines}

Write a 2-3 sentence plain-English executive summary of the risk this resource poses.
Focus on business impact. Do not use jargon. Do not use bullet points.
Start directly with the summary — no preamble.
"""
    return _call_claude(prompt)


def generate_batch_report(issues: list[dict], top_n: int = 5) -> str:
    """
    Generate an overall narrative summary of the full scan — suitable for
    an executive report or Slack notification.

    Args:
        issues  : Full list of scored issue dicts (sorted by RWC desc).
        top_n   : How many top issues to highlight in the prompt.

    Returns:
        Short narrative paragraph (3-5 sentences).
    """
    from collections import Counter

    sev_counts  = Counter(i.get('severity')   for i in issues)
    type_counts = Counter(i.get('issue_type') for i in issues)
    total_waste = sum(i.get('waste_cost', 0)  for i in issues)

    top_issues = '\n'.join(
        f'  {j+1}. [{i.get("severity","?")}] {i.get("rule_id","?")} on '
        f'{i.get("resource_id","?")} — {i.get("description","")[:80]}'
        for j, i in enumerate(issues[:top_n])
    )

    prompt = f"""You are a cloud security analyst writing a brief executive summary email.

Scan results:
  Total issues  : {len(issues)}
  Critical      : {sev_counts.get("critical", 0)}
  High          : {sev_counts.get("high", 0)}
  Medium        : {sev_counts.get("medium", 0)}
  Low           : {sev_counts.get("low", 0)}
  Misconfigs    : {type_counts.get("misconfiguration", 0)}
  Waste issues  : {type_counts.get("waste", 0)}
  Total waste   : ${total_waste:,.2f}/month

Top {top_n} highest-risk findings:
{top_issues}

Write a 3-5 sentence executive summary. Be direct. Mention the most urgent actions.
Include the waste figure. Do not use headers or bullets. Start directly with the summary.
"""
    return _call_claude(prompt)
