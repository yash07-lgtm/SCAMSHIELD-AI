"""
detector/engine.py
------------------
Scoring and classification engine for ScamShield AI.

Calls run_all_rules(), applies a per-category weight cap, sums the capped
scores, and maps to a verdict.

Verdict thresholds (raised to reduce false positives)
------------------------------------------------------
  0  – 34  →  Likely Legitimate
  35 – 64  →  Suspicious — needs review
  65+      →  Likely Spam/Scam

Per-category cap
----------------
Each rule category contributes its weight AT MOST ONCE to the total score,
regardless of how many pattern matches triggered within that category.
Example: if "Credential / Personal Info Request" fires 3 times with weight 25,
the score only goes up by 25 (not 75).  All 3 matches are still reported as
separate warnings so the user can see exactly what was found.

No messages are stored or transmitted.  All processing is local and stateless.
"""

from .rules import run_all_rules

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_MESSAGE_LENGTH = 20_000  # characters — enforced before analysis

_VERDICT_LEGITIMATE = "Likely Legitimate"
_VERDICT_SUSPICIOUS = "Suspicious — needs review"
_VERDICT_SCAM       = "Likely Spam/Scam"

_VERDICT_META = {
    _VERDICT_LEGITIMATE: {
        "css_class": "ss-verdict-legit",
        "icon":      "bi-shield-check",
        "subtitle":  "No significant warning signs detected",
    },
    _VERDICT_SUSPICIOUS: {
        "css_class": "ss-verdict-spam",
        "icon":      "bi-shield-exclamation",
        "subtitle":  "Some warning signs present — treat with caution",
    },
    _VERDICT_SCAM: {
        "css_class": "ss-verdict-scam",
        "icon":      "bi-shield-x",
        "subtitle":  "Multiple high-risk signals detected",
    },
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _apply_category_cap(raw_warnings: list[dict]) -> tuple[int, list[dict]]:
    """
    Sum weights with a per-category cap: each unique rule name contributes
    its weight at most once to the score, regardless of how many excerpts
    matched.

    Returns (capped_score, raw_warnings_unchanged).
    The raw_warnings list is not modified — all matches are still displayed.
    """
    seen: dict[str, int] = {}
    for w in raw_warnings:
        rule = w["rule"]
        if rule not in seen:
            seen[rule] = w["weight"]
    return min(100, sum(seen.values())), raw_warnings


def _score_to_verdict(score: int) -> str:
    if score >= 65:
        return _VERDICT_SCAM
    if score >= 35:
        return _VERDICT_SUSPICIOUS
    return _VERDICT_LEGITIMATE


def _score_to_confidence(score: int, n_categories: int) -> str:
    """
    Confidence reflects how many *distinct* rule categories fired.
    A single category firing many times is no more confident than one.
    """
    if n_categories == 0:
        return "Low"
    if score >= 65 and n_categories >= 3:
        return "High"
    if score >= 35 or n_categories >= 2:
        return "Medium"
    return "Low"


def _build_explanation(verdict: str, warnings: list[dict]) -> str:
    n = len(warnings)
    # Count distinct categories
    unique_rules = list({w["rule"] for w in warnings})
    disclaimer = (
        " This is an automated assessment based on pattern matching, "
        "not a guarantee. Always verify messages through official channels."
    )
    if verdict == _VERDICT_LEGITIMATE:
        return (
            "No significant warning signs were detected in this message. "
            "It appears to be routine communication." + disclaimer
        )
    joined = (
        unique_rules[0]
        if len(unique_rules) == 1
        else ", ".join(unique_rules[:-1]) + " and " + unique_rules[-1]
    )
    if verdict == _VERDICT_SCAM:
        return (
            f"This message triggered {n} warning signal(s) across "
            f"{len(unique_rules)} category/categories associated with spam or "
            f"scam messages, including: {joined}." + disclaimer
        )
    return (
        f"This message triggered {n} warning signal(s) that merit caution, "
        f"including: {joined}. Evidence is not strong enough to classify as "
        f"spam — review carefully before acting." + disclaimer
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze(text: str) -> dict:
    """
    Analyse *text* and return a result dict suitable for JSON serialisation.

    Parameters
    ----------
    text : str
        The raw message submitted by the user.

    Returns
    -------
    dict with keys:
        verdict        str   — classification label
        score          int   — 0–100 risk score (per-category capped)
        confidence     str   — Low / Medium / High
        signals        int   — number of warning items (all matches)
        css_class      str   — Bootstrap CSS class for the verdict banner
        icon           str   — Bootstrap Icon class
        subtitle       str   — one-line verdict description
        explanation    str   — plain-language summary + disclaimer
        warnings       list  — list of {rule, description, excerpt} dicts
    """
    text = text[:MAX_MESSAGE_LENGTH]

    raw_warnings = run_all_rules(text)
    score, raw_warnings = _apply_category_cap(raw_warnings)

    unique_categories = len({w["rule"] for w in raw_warnings})
    verdict    = _score_to_verdict(score)
    confidence = _score_to_confidence(score, unique_categories)
    explanation = _build_explanation(verdict, raw_warnings)
    meta = _VERDICT_META[verdict]

    warnings_out = [
        {"rule": w["rule"], "description": w["description"], "excerpt": w["excerpt"]}
        for w in raw_warnings
    ]

    return {
        "verdict":     verdict,
        "score":       score,
        "confidence":  confidence,
        "signals":     len(warnings_out),
        "css_class":   meta["css_class"],
        "icon":        meta["icon"],
        "subtitle":    meta["subtitle"],
        "explanation": explanation,
        "warnings":    warnings_out,
    }
