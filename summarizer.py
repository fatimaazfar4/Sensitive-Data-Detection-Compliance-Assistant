"""
summarizer.py
--------------
Two jobs:
  1. Turn structured findings (from detector.py + risk.py) into a natural
     language compliance/security summary.
  2. Answer free-form user questions about the document.

Design choice: the regex engine already gives us ground-truth structured
facts (exact counts, categories, risk level). We do NOT ask the LLM to
re-detect PII — LLMs are unreliable at exact entity extraction and we don't
want hallucinated counts in a compliance report. Instead we feed the LLM the
*already-computed* facts and let it do what LLMs are actually good at:
writing a clear, well-organized narrative, and answering ad-hoc questions
grounded in those facts + relevant (masked) document excerpts.

If no ANTHROPIC_API_KEY is configured, everything still works via a
template-based fallback so the app is fully functional offline / for a demo
without needing to expose an API key.
"""

import os
import re
from typing import List, Dict, Optional

from detector import Finding, summarize_counts

try:
    import anthropic
    _ANTHROPIC_AVAILABLE = True
except ImportError:
    _ANTHROPIC_AVAILABLE = False

MODEL = "claude-sonnet-4-6"


def _get_client() -> Optional["anthropic.Anthropic"]:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key or not _ANTHROPIC_AVAILABLE:
        return None
    return anthropic.Anthropic(api_key=api_key)


def _facts_block(findings: List[Finding], risk_info: Dict, filename: str) -> str:
    counts = summarize_counts(findings)
    counts_str = "\n".join(f"- {cat}: {n}" for cat, n in sorted(counts.items())) or "- None detected"
    return f"""Document: {filename}
Risk level: {risk_info['level']} (score={risk_info['score']})
Risk rationale: {risk_info['rationale']}

Detected sensitive data categories and counts:
{counts_str}

Total findings: {len(findings)}
"""


# ---------------------------------------------------------------------------
# Summary generation
# ---------------------------------------------------------------------------

def generate_summary(findings: List[Finding], risk_info: Dict, filename: str) -> str:
    facts = _facts_block(findings, risk_info, filename)
    client = _get_client()

    if client is None:
        return _template_summary(findings, risk_info, filename)

    prompt = f"""You are a data-privacy and compliance analyst. Based ONLY on the
structured facts below (do not invent any numbers not present here), write a
compliance/security summary with three sections:

1. Compliance Observations
2. Security Risks
3. Suggested Remediation Steps

Keep it concise (under 250 words), use bullet points, and be specific to the
categories of data that were actually found.

FACTS:
{facts}
"""
    try:
        resp = client.messages.create(
            model=MODEL,
            max_tokens=700,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(block.text for block in resp.content if block.type == "text")
    except Exception as e:
        fallback = _template_summary(findings, risk_info, filename)
        return fallback + f"\n\n_(Note: AI summary generation failed, showing rule-based summary. Error: {e})_"


def _template_summary(findings: List[Finding], risk_info: Dict, filename: str) -> str:
    counts = summarize_counts(findings)
    categories = ", ".join(sorted(counts.keys())) if counts else "none"

    lines = ["**Compliance Observations**"]
    if not findings:
        lines.append("- No sensitive data patterns were identified in this document.")
    else:
        lines.append(f"- The document contains {len(findings)} sensitive data instance(s) across categories: {categories}.")
        if risk_info["high_categories"]:
            lines.append(f"- High-severity data types present: {', '.join(risk_info['high_categories'])}.")
        lines.append(f"- Overall document risk classification: **{risk_info['level']}**.")

    lines.append("\n**Security Risks**")
    if not findings:
        lines.append("- No immediate PII/credential exposure risk detected from pattern scanning.")
    else:
        if any(f.category in ("API Key / Secret", "Password", "AWS Access Key", "Private Key Block") for f in findings):
            lines.append("- Exposed credentials/keys were found in plain text — these could allow direct unauthorized system access.")
        if any(f.category in ("Aadhaar Number", "PAN Number") for f in findings):
            lines.append("- Government-issued identity numbers are present, creating identity-theft and regulatory exposure (e.g. under India's DPDP Act).")
        if any(f.category in ("Credit Card Number", "Bank Account Number", "Bank IFSC Code") for f in findings):
            lines.append("- Financial account data is present, creating fraud risk if this document is shared or leaked.")
        if any(f.category == "Email Address" for f in findings) or any(f.category == "Phone Number" for f in findings):
            lines.append("- Personal contact details are present, which fall under general PII/data-protection obligations.")
        lines.append("- Storing/sharing this document without controls increases risk of non-compliance with data protection regulations.")

    lines.append("\n**Suggested Remediation Steps**")
    if not findings:
        lines.append("- No action required; continue periodic re-scanning as document content changes.")
    else:
        lines.append("- Redact or mask sensitive fields before sharing this document externally.")
        lines.append("- Restrict access to this file to authorized personnel only (least-privilege access).")
        lines.append("- Rotate any exposed credentials/API keys immediately.")
        lines.append("- Store the document in an encrypted, access-controlled repository.")
        lines.append("- Maintain an audit log of who accessed or downloaded this document.")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Question answering
# ---------------------------------------------------------------------------

def answer_question(question: str, findings: List[Finding], risk_info: Dict,
                     filename: str, document_text: str) -> str:
    client = _get_client()
    counts = summarize_counts(findings)

    if client is not None:
        facts = _facts_block(findings, risk_info, filename)
        # Give the model a masked/redacted excerpt so raw secrets are never
        # sent to the LLM API — only the structured facts + masked context.
        masked_excerpt = document_text[:3000]
        for f in findings:
            masked_excerpt = masked_excerpt.replace(f.value, f.masked_value)

        prompt = f"""You are a compliance assistant answering questions about a scanned
document. Use ONLY the structured facts and masked excerpt below. Never
reproduce a full sensitive value. Be concise and specific.

FACTS:
{facts}

MASKED DOCUMENT EXCERPT (sensitive values already masked):
\"\"\"{masked_excerpt}\"\"\"

QUESTION: {question}
"""
        try:
            resp = client.messages.create(
                model=MODEL,
                max_tokens=500,
                messages=[{"role": "user", "content": prompt}],
            )
            return "".join(block.text for block in resp.content if block.type == "text")
        except Exception as e:
            return _rule_based_answer(question, findings, risk_info, counts) + \
                f"\n\n_(Note: AI answer failed, showing rule-based answer. Error: {e})_"

    return _rule_based_answer(question, findings, risk_info, counts)


def _rule_based_answer(question: str, findings: List[Finding], risk_info: Dict, counts: Dict[str, int]) -> str:
    q = question.lower()

    # "how many X" questions
    for category in counts:
        cat_words = category.lower().split()
        if any(w in q for w in cat_words) and ("how many" in q or "count" in q or "number of" in q):
            return f"There are **{counts[category]}** instance(s) of **{category}** in this document."

    if "risk" in q and ("compliance" in q or "identif" in q or "level" in q or "classif" in q):
        return f"This document is classified as **{risk_info['level']}**. {risk_info['rationale']}"

    if "summar" in q:
        return "Please see the generated Compliance Summary section above for the full summary."

    if "what sensitive" in q or ("what" in q and "data" in q and "exist" in q) or "list" in q:
        if not counts:
            return "No sensitive data was detected in this document."
        lines = [f"- {cat}: {n}" for cat, n in sorted(counts.items())]
        return "The following sensitive data categories were detected:\n" + "\n".join(lines)

    if not findings:
        return "No sensitive data was detected, so there is nothing further to report for this question. " \
               "Try asking about risk level or request a document summary."

    lines = [f"- {cat}: {n}" for cat, n in sorted(counts.items())]
    return (
        "I can answer questions about detected sensitive data, counts per category, "
        "risk level, and the compliance summary. Here's a quick overview:\n"
        + "\n".join(lines)
        + f"\n\nOverall risk: **{risk_info['level']}**."
    )
