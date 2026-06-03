"""
classifier.py
Threat classification engine for PhishGuard.

Analyses the full set of findings plus raw email content to assign one or
more MITRE ATT&CK-aligned threat labels to the email.  Each label comes
with a confidence level (HIGH / MEDIUM / LOW) and a short rationale string
so the report can show *why* a classification was chosen.

Threat categories supported
----------------------------
  CREDENTIAL HARVESTING   – T1598 / T1056.003
  BUSINESS EMAIL COMPROMISE (BEC)  – T1534 / T1566.002
  DELIVERY / LOGISTICS SCAM        – generic lure
  ACCOUNT TAKEOVER ATTEMPT         – T1078
  MALWARE DELIVERY                 – T1566.001
  FINANCIAL FRAUD                  – T1657
  GENERIC SPAM / PHISHING          – catch-all
"""

import re


# ---------------------------------------------------------------------------
# Signal definitions
# Each entry is (regex_pattern, weight).  Patterns are matched against the
# lower-cased combined text of: email body + From header + Subject header.
# ---------------------------------------------------------------------------

# --- Credential Harvesting signals ---
CRED_HARVEST_SIGNALS = [
    (r"enter\s+your\s+password",              3),
    (r"confirm\s+your\s+(identity|password)",  3),
    (r"verify\s+your\s+(account|identity)",    3),
    (r"social\s+security\s+number",            3),
    (r"credit\s+card\s+(number|details)",      3),
    (r"banking\s+(credentials|details)",       3),
    (r"(re-?enter|re-?type)\s+your",           2),
    (r"login\s+page",                          2),
    (r"update\s+your\s+(details|information)", 2),
    (r"account\s+verification",                2),
    (r"sign\s+in\s+to\s+verify",               2),
]

# --- BEC (Business Email Compromise) signals ---
BEC_SIGNALS = [
    (r"wire\s+transfer",                       3),
    (r"urgent\s+(payment|invoice|transfer)",   3),
    (r"ceo|cfo|executive|president",           2),
    (r"invoice\s+(attached|enclosed|number)",  3),
    (r"change\s+(payment|bank|account)\s+(details|info)", 3),
    (r"new\s+(bank|account)\s+details",        3),
    (r"(authorize|approve)\s+(this\s+)?payment",2),
    (r"(it\s+)?(helpdesk|support|department)",  2),
    (r"password\s+(reset|expir)",              2),
    (r"vendor\s+(payment|invoice)",            2),
    (r"payroll",                               2),
]

# --- Delivery / Logistics Scam signals ---
DELIVERY_SIGNALS = [
    (r"(your\s+)?(package|parcel|shipment|delivery)",  3),
    (r"(fedex|ups|dhl|usps|royal\s+mail)",             3),
    (r"(failed|missed|pending)\s+delivery",            3),
    (r"(tracking\s+number|track\s+your)",              2),
    (r"customs\s+(fee|charge|duty)",                   3),
    (r"re-?schedule\s+(your\s+)?delivery",             2),
    (r"(out\s+for\s+delivery|delivery\s+attempt)",     2),
    (r"(post\s+office|courier)",                       1),
]

# --- Account Takeover signals ---
ACCOUNT_TAKEOVER_SIGNALS = [
    (r"account\s+(suspended|terminated|locked|blocked|deactivated)", 3),
    (r"unauthorized\s+(access|login|sign-?in)",        3),
    (r"unusual\s+(activity|login|sign-?in)",           3),
    (r"(your\s+)?account\s+has\s+been\s+(compromised|hacked)", 3),
    (r"security\s+alert",                              2),
    (r"(suspicious|unrecognized)\s+(device|location)", 2),
    (r"two-?factor|2fa",                               1),
    (r"reset\s+your\s+password",                       2),
]

# --- Malware Delivery signals ---
MALWARE_SIGNALS = [
    (r"(open|view|download)\s+(the\s+)?(attachment|document|file)", 3),
    (r"enable\s+(macros|editing|content)",             3),
    (r"(invoice|receipt|statement|notice)\s+attached", 3),
    (r"\.exe|\.zip|\.rar|\.js|\.vbs|\.docm|\.xlsm",   3),
    (r"scan\s+(the\s+)?qr\s+code",                     2),
    (r"(click|run|execute)\s+the\s+(file|program)",    2),
]

# --- Financial Fraud / Advance Fee signals ---
FINANCIAL_SIGNALS = [
    (r"(won|winner|selected|chosen)\s+(a\s+)?(prize|lottery|jackpot)", 3),
    (r"(unclaimed|pending)\s+(prize|reward|funds|inheritance)", 3),
    (r"million\s+(dollars?|pounds?|euros?)",           3),
    (r"advance\s+fee",                                 3),
    (r"(tax\s+refund|irs\s+refund|government\s+refund)", 3),
    (r"(transfer|release)\s+(of\s+)?funds",            2),
    (r"bank\s+(transfer|wire)",                        2),
    (r"inheritance",                                   2),
]

# Minimum score to include a classification in the output
CLASSIFICATION_THRESHOLD = 3


# ---------------------------------------------------------------------------
# MITRE ATT&CK reference mapping
# ---------------------------------------------------------------------------

MITRE_MAP = {
    "Credential Harvesting":           "T1598 · Phishing for Information",
    "Business Email Compromise (BEC)": "T1534 · Internal Spearphishing / T1566.002",
    "Delivery / Logistics Scam":       "T1566 · Phishing (Lure)",
    "Account Takeover Attempt":        "T1078 · Valid Accounts",
    "Malware Delivery":                "T1566.001 · Spearphishing Attachment",
    "Financial Fraud":                 "T1657 · Financial Theft",
    "Generic Spam / Phishing":         "T1566 · Phishing",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def classify_threat(findings: list[dict], body_text: str, msg) -> list[dict]:
    """
    Determine one or more threat classifications for this email.

    Parameters
    ----------
    findings  : combined list of all analyzer findings
    body_text : plain-text body (decoded)
    msg       : parsed email.Message (for header access)

    Returns
    -------
    List of classification dicts, sorted by score descending:
        {
          "label":      str,   # human-readable threat type
          "confidence": str,   # HIGH / MEDIUM / LOW
          "rationale":  str,   # one-line explanation
          "mitre":      str,   # MITRE ATT&CK reference
        }
    """
    # Build a single searchable text blob from body + key headers
    subject  = msg.get("Subject", "")
    from_hdr = msg.get("From", "")
    combined = (body_text + " " + subject + " " + from_hdr).lower()

    scores = {
        "Credential Harvesting":           _score_signals(combined, CRED_HARVEST_SIGNALS),
        "Business Email Compromise (BEC)": _score_signals(combined, BEC_SIGNALS),
        "Delivery / Logistics Scam":       _score_signals(combined, DELIVERY_SIGNALS),
        "Account Takeover Attempt":        _score_signals(combined, ACCOUNT_TAKEOVER_SIGNALS),
        "Malware Delivery":                _score_signals(combined, MALWARE_SIGNALS),
        "Financial Fraud":                 _score_signals(combined, FINANCIAL_SIGNALS),
    }

    # Build result list for categories that met the threshold
    results = []
    for label, score in sorted(scores.items(), key=lambda x: x[1], reverse=True):
        if score >= CLASSIFICATION_THRESHOLD:
            results.append({
                "label":      label,
                "confidence": _confidence(score),
                "rationale":  _build_rationale(label, combined),
                "mitre":      MITRE_MAP.get(label, ""),
                "score":      score,   # internal, not shown in report
            })

    # Fall back to Generic Spam if nothing matched but risk score is non-zero
    if not results and findings:
        results.append({
            "label":      "Generic Spam / Phishing",
            "confidence": "LOW",
            "rationale":  "No dominant attack pattern detected; general phishing indicators present.",
            "mitre":      MITRE_MAP["Generic Spam / Phishing"],
            "score":      0,
        })

    return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _score_signals(text: str, signals: list[tuple]) -> int:
    """Sum weights of all signals whose pattern matches anywhere in text."""
    total = 0
    for pattern, weight in signals:
        if re.search(pattern, text):
            total += weight
    return total


def _confidence(score: int) -> str:
    """Map a raw signal score to a confidence label."""
    if score >= 8:
        return "HIGH"
    elif score >= 4:
        return "MEDIUM"
    return "LOW"


def _build_rationale(label: str, text: str) -> str:
    """Return a short human-readable reason string for a classification."""
    rationales = {
        "Credential Harvesting": (
            "Email requests login credentials, personal details, or account verification — "
            "classic credential phishing pattern."
        ),
        "Business Email Compromise (BEC)": (
            "Contains indicators of BEC: IT/helpdesk impersonation, invoice references, "
            "or payment/transfer requests targeting employees."
        ),
        "Delivery / Logistics Scam": (
            "References package delivery, courier services, or shipment tracking — "
            "common lure to harvest personal data or payment info."
        ),
        "Account Takeover Attempt": (
            "Claims of suspicious account activity, unauthorized access, or account suspension "
            "designed to trick the user into surrendering credentials."
        ),
        "Malware Delivery": (
            "Encourages opening an attachment, enabling macros, or downloading a file — "
            "primary vector for malware installation."
        ),
        "Financial Fraud": (
            "Contains lottery winnings, unclaimed inheritance, tax refund, or advance-fee "
            "language to defraud the recipient financially."
        ),
    }
    return rationales.get(label, "Multiple phishing signals detected.")
