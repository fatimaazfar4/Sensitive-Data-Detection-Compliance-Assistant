"""
detector.py
------------
Regex + rule based sensitive-data detection engine.

Design notes (why regex-first instead of only an LLM):
- Deterministic, auditable, and fast — important for a *compliance* tool where
  false negatives are costly and results must be explainable to an auditor.
- Works fully offline / without any paid API key (a hard requirement for a
  tool that will itself be fed confidential documents).
- The LLM layer (summarizer.py) is used *on top* of these structured findings
  to produce natural-language explanations and answer free-form questions —
  not to do the raw entity extraction itself.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class Finding:
    category: str          # e.g. "Email Address"
    value: str              # the raw matched text
    masked_value: str        # redacted/masked version, safe to display
    risk: str                # "High" / "Medium" / "Low"
    line_no: int = -1


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------
# Each entry: category -> (compiled regex, risk level)
PATTERNS: Dict[str, tuple] = {
    "Aadhaar Number": (
        re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"),
        "High",
    ),
    "PAN Number": (
        re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
        "High",
    ),
    "Credit Card Number": (
        re.compile(r"\b(?:\d[ -]?){13,16}\b"),
        "High",
    ),
    "Bank IFSC Code": (
        re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),
        "High",
    ),
    "Bank Account Number": (
        re.compile(r"(?i)\b(?:a/?c\.?|account|acct)\.?\s?(?:no\.?|number)?\s?[:\-]?\s?(\d{9,18})\b"),
        "High",
    ),
    "API Key / Secret": (
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|bearer|aws_secret_access_key)"
            r"\s*[:=]\s*['\"]?[A-Za-z0-9/_\-\.]{10,}['\"]?"
        ),
        "High",
    ),
    "AWS Access Key": (
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "High",
    ),
    "Password": (
        re.compile(r"(?i)\bpassword\s*[:=]\s*['\"]?\S{4,}['\"]?"),
        "High",
    ),
    "Private Key Block": (
        re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|DSA)? ?PRIVATE KEY-----"),
        "High",
    ),
    "Email Address": (
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "Medium",
    ),
    "Phone Number": (
        re.compile(r"(?:(?:\+91[\-\s]?)|(?:0))?\b[6-9]\d{9}\b"),
        "Medium",
    ),
    "Employee ID": (
        re.compile(r"\b(?:EMP|EID|EMPID)[-_]?\d{3,8}\b", re.IGNORECASE),
        "Medium",
    ),
    "Confidential Business Marker": (
        re.compile(
            r"(?i)\b(confidential|internal use only|do not distribute|trade secret|"
            r"proprietary and confidential|strictly confidential|not for circulation)\b"
        ),
        "Low",
    ),
}

# Categories where the value itself must be validated further to reduce
# false positives (Aadhaar / credit-card patterns are just "12/16 digits" and
# will otherwise collide with phone numbers, invoice numbers, etc.)
def _luhn_check(number: str) -> bool:
    digits = [int(d) for d in re.sub(r"[ -]", "", number)]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _mask(category: str, value: str) -> str:
    """Return a human-safe masked representation for display in the UI."""
    clean = re.sub(r"[\s-]", "", value)
    if category in ("Aadhaar Number", "Credit Card Number", "Bank Account Number"):
        if len(clean) <= 4:
            return "*" * len(clean)
        return "*" * (len(clean) - 4) + clean[-4:]
    if category == "Email Address":
        name, _, domain = value.partition("@")
        return (name[0] + "***@" + domain) if name else "***@" + domain
    if category == "Phone Number":
        return "*" * (len(clean) - 2) + clean[-2:]
    if category in ("API Key / Secret", "Password", "AWS Access Key", "Private Key Block"):
        return value[:6] + "..." + "*" * 6
    return value[:2] + "*" * max(len(value) - 2, 0)


def detect(text: str) -> List[Finding]:
    """Run all patterns over `text` and return a de-duplicated list of Findings."""
    findings: List[Finding] = []
    lines = text.splitlines() or [text]

    seen = set()
    for line_no, line in enumerate(lines, start=1):
        for category, (pattern, risk) in PATTERNS.items():
            for match in pattern.finditer(line):
                value = (match.group(1) if match.groups() else match.group(0)).strip()
                if not value:
                    continue

                # Reduce false positives for the two "digits only" categories
                if category == "Aadhaar Number":
                    digits = re.sub(r"[\s-]", "", value)
                    if len(digits) != 12:
                        continue
                    # A 12-digit number on a line that clearly labels itself as a
                    # bank/account number is far more likely to be that, not Aadhaar.
                    if re.search(r"(?i)\b(a/?c|account|acct|bank)\b", line):
                        continue
                if category == "Credit Card Number":
                    digits = re.sub(r"[\s-]", "", value)
                    if len(digits) not in (13, 14, 15, 16) or not _luhn_check(digits):
                        continue

                key = (category, value)
                if key in seen:
                    continue
                seen.add(key)

                findings.append(
                    Finding(
                        category=category,
                        value=value,
                        masked_value=_mask(category, value),
                        risk=risk,
                        line_no=line_no,
                    )
                )
    return findings


def summarize_counts(findings: List[Finding]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.category] = counts.get(f.category, 0) + 1
    return counts
