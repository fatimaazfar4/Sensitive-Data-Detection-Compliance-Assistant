"""
redact.py
----------
Produces a redacted copy of the document text, replacing every detected
sensitive value with its masked form (or a solid [REDACTED: category] tag).
"""

from typing import List
from detector import Finding


def redact_text(text: str, findings: List[Finding], mode: str = "mask") -> str:
    """
    mode = "mask"   -> replace with partial mask, e.g. ****1234
    mode = "tag"     -> replace with [REDACTED: Category]
    """
    redacted = text
    # Replace longer values first to avoid partial-overlap issues
    for f in sorted(findings, key=lambda x: len(x.value), reverse=True):
        replacement = f.masked_value if mode == "mask" else f"[REDACTED: {f.category}]"
        redacted = redacted.replace(f.value, replacement)
    return redacted
