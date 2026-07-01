"""
risk.py
--------
Aggregates individual Findings into a single document-level risk rating.

Scoring approach (transparent, rule-based — deliberately NOT a black box,
since a compliance tool needs an explainable score):

  High-risk finding    -> 3 points
  Medium-risk finding   -> 2 points
  Low-risk finding      -> 1 point

Thresholds (tunable in one place):
  score == 0                -> Low Risk
  0 < score <= 6             -> Medium Risk
  score > 6                  -> High Risk

  Additionally: ANY High-risk category present (Aadhaar, PAN, card, bank,
  API key/secret, password) automatically floors the document at at least
  Medium Risk, and 2+ distinct high-risk categories forces High Risk,
  regardless of point total. This mirrors how real compliance policies work:
  a single leaked API key or Aadhaar number is a big deal even in an
  otherwise "small" document.
"""

from typing import List, Dict
from detector import Finding

POINTS = {"High": 3, "Medium": 2, "Low": 1}


def classify(findings: List[Finding]) -> Dict:
    if not findings:
        return {
            "level": "Low Risk",
            "score": 0,
            "high_categories": [],
            "rationale": "No sensitive data patterns were detected in the document.",
        }

    score = sum(POINTS[f.risk] for f in findings)
    high_categories = sorted({f.category for f in findings if f.risk == "High"})

    if len(high_categories) >= 2:
        level = "High Risk"
    elif high_categories:
        level = "Medium Risk" if score <= 6 else "High Risk"
    elif score > 6:
        level = "High Risk"
    elif score > 0:
        level = "Medium Risk"
    else:
        level = "Low Risk"

    rationale_bits = []
    if high_categories:
        rationale_bits.append(
            f"{len(high_categories)} high-severity category type(s) detected: {', '.join(high_categories)}."
        )
    rationale_bits.append(f"Weighted sensitivity score: {score}.")

    return {
        "level": level,
        "score": score,
        "high_categories": high_categories,
        "rationale": " ".join(rationale_bits),
    }
