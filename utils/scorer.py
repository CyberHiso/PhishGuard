"""
scorer.py
Converts a list of findings into a weighted risk score (0–100) and
assigns a human-readable risk level label.
"""

# Severity weights — how many points each finding severity contributes.
# Values are tuned so a single HIGH finding alone doesn't max the score,
# but multiple HIGH findings compound quickly toward CRITICAL territory.
SEVERITY_WEIGHTS = {
    "HIGH":   18,
    "MEDIUM": 10,
    "LOW":     4,
}

# Score thresholds that map to risk level labels
RISK_LEVELS = [
    (75, "CRITICAL"),
    (50, "HIGH"),
    (25, "MEDIUM"),
    (0,  "LOW"),
]


def calculate_score(findings: list[dict]) -> int:
    """
    Sum the weighted score for all findings and clamp the result to [0, 100].
    Each finding carries a severity that maps to a point value.
    """
    total = 0
    for finding in findings:
        severity = finding.get("severity", "LOW").upper()
        total += SEVERITY_WEIGHTS.get(severity, 0)

    # Cap at 100 — the score is a risk indicator, not a raw count
    return min(total, 100)


def get_risk_level(score: int) -> str:
    """Return the risk level label for a given score."""
    for threshold, label in RISK_LEVELS:
        if score >= threshold:
            return label
    return "LOW"


def get_verdict(score: int) -> str:
    """Return a plain-English verdict sentence based on the score."""
    if score >= 75:
        return "This email shows strong, multiple indicators of phishing. Do NOT click any links or open attachments."
    elif score >= 50:
        return "This email exhibits several phishing characteristics. Treat with high caution."
    elif score >= 25:
        return "This email has some suspicious elements. Verify the sender independently before acting."
    else:
        return "This email appears relatively low-risk, but always exercise caution with unsolicited messages."
