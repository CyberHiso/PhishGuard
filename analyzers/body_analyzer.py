"""
body_analyzer.py
Scans the email body text for phishing-related keywords, urgency language,
credential harvesting phrases, and other social engineering patterns.
"""

import re


# --- Urgency and pressure phrases ---
# Attackers create artificial time pressure to prevent careful thinking
URGENCY_PHRASES = [
    r"act\s+(?:now|immediately|urgently|today)",
    r"click\s+(?:now|immediately|here\s+now)",
    r"respond\s+(?:immediately|urgently|within\s+\d+\s+hours?)",
    r"(?:limited|urgent|immediate)\s+action\s+(?:required|needed)",
    r"your\s+account\s+(?:will\s+be|has\s+been)?\s*(?:suspended|terminated|closed|locked|blocked|deactivated)",
    r"(?:must|need\s+to)\s+(?:verify|confirm|update|validate)\s+(?:your|account)",
    r"within\s+\d+\s+(?:hours?|days?)\s+or",
    r"expires?\s+(?:soon|today|in\s+\d+\s+hours?)",
    r"last\s+(?:chance|warning|notice|reminder)",
    r"failure\s+to\s+(?:respond|verify|confirm|act)",
    r"your\s+(?:account|access|service)\s+(?:is|has\s+been)\s+(?:at\s+risk|compromised|flagged|restricted)",
    r"immediately\s+(?:verify|confirm|update|click)",
    r"account\s+(?:suspension|termination)\s+(?:notice|warning)",
]

# --- Credential harvesting phrases ---
# Direct requests for sensitive information are a hallmark of phishing
CREDENTIAL_PHRASES = [
    r"enter\s+your\s+(?:password|pin|credentials|login|username)",
    r"(?:provide|submit|send)\s+your\s+(?:password|credit\s+card|ssn|social\s+security)",
    r"confirm\s+your\s+(?:identity|account|password|details|information)",
    r"verify\s+your\s+(?:account|identity|email|details|information|credentials)",
    r"(?:re-?enter|re-?type)\s+your\s+(?:password|credentials|details)",
    r"banking\s+(?:credentials|details|information|login)",
    r"social\s+security\s+number",
    r"credit\s+card\s+(?:number|details|information)",
    r"(?:your\s+)?(?:full\s+)?(?:name|address|date\s+of\s+birth)\s+(?:and|,)\s+(?:password|pin|ssn)",
]

# --- Suspicious action requests ---
# Pushing the user to do something specific that enables the attack
ACTION_PHRASES = [
    r"click\s+(?:the\s+link|here|below|this\s+link|the\s+button)",
    r"follow\s+(?:the\s+link|this\s+link)",
    r"open\s+(?:the\s+attachment|attached\s+file|the\s+document)",
    r"download\s+(?:and\s+run|and\s+open|the\s+file|the\s+attachment)",
    r"enable\s+(?:macros|editing|content)",
    r"(?:go\s+to|visit|navigate\s+to)\s+(?:this|the|our)\s+(?:website|page|link|site)",
    r"scan\s+(?:the|this)\s+(?:qr\s+code|barcode)",
]

# --- Reward / prize / threat lure phrases ---
# Social engineering lures using fear, greed, or authority
LURE_PHRASES = [
    r"you\s+(?:have\s+)?(?:won|been\s+selected|are\s+a\s+winner)",
    r"(?:congratulations?|congrats)[!,.]",
    r"(?:unclaimed|pending)\s+(?:prize|reward|refund|package|parcel)",
    r"(?:tax\s+refund|irs\s+refund|government\s+refund)",
    r"(?:inheritance|lottery|jackpot)",
    r"million\s+(?:dollars?|pounds?|euros?)\s+(?:waiting|available|unclaimed)",
    r"(?:unusual|suspicious)\s+(?:activity|login|sign-?in)\s+(?:detected|noticed|found)",
    r"(?:unauthorized|unrecognized)\s+(?:access|login|device|transaction)",
    r"your\s+(?:package|parcel|delivery|shipment)\s+(?:is\s+waiting|on\s+hold|failed)",
    r"invoice\s+(?:attached|enclosed|number\s+\d+)",
]

# --- Impersonation indicators in body text ---
IMPERSONATION_PHRASES = [
    r"(?:dear\s+)?(?:valued\s+)?customer[,.]",
    r"dear\s+(?:user|member|account\s+holder|client)[,.]",
    r"(?:your\s+)?(?:paypal|amazon|apple|microsoft|google|netflix|bank)\s+account",
    r"IT\s+(?:department|support|helpdesk|team)",
    r"(?:system|security|account)\s+(?:administrator|team|department)",
]


def _find_phrase_matches(text: str, patterns: list[str]) -> list[str]:
    """Search text for all regex patterns and return list of matched strings."""
    matches = []
    text_lower = text.lower()
    for pattern in patterns:
        for match in re.finditer(pattern, text_lower):
            matched_text = match.group(0)
            # Avoid duplicate entries for the same matched text
            if matched_text not in matches:
                matches.append(matched_text)
    return matches


def _extract_plain_text(msg) -> str:
    """
    Extract plain text from an email.Message object.
    Handles both plain text and HTML multipart emails.
    """
    body_parts = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type in ("text/plain", "text/html"):
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        body_parts.append(payload.decode(charset, errors="replace"))
                except Exception:
                    continue
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                body_parts.append(payload.decode(charset, errors="replace"))
        except Exception:
            body_parts.append(str(msg.get_payload()))

    return "\n".join(body_parts)


def analyze_body(msg) -> list[dict]:
    """
    Scan the email body for phishing-related language patterns.
    Accepts a parsed email.Message object.
    Returns a list of finding dicts: {category, severity, detail}
    """
    findings = []
    body_text = _extract_plain_text(msg)

    if not body_text:
        return findings

    # --- Check 1: Urgency and pressure language ---
    urgency_matches = _find_phrase_matches(body_text, URGENCY_PHRASES)
    for phrase in urgency_matches:
        findings.append({
            "category": "Body",
            "severity": "HIGH",
            "detail": f'Urgency/pressure phrase detected: "{phrase}"',
        })

    # --- Check 2: Credential harvesting requests ---
    cred_matches = _find_phrase_matches(body_text, CREDENTIAL_PHRASES)
    for phrase in cred_matches:
        findings.append({
            "category": "Body",
            "severity": "HIGH",
            "detail": f'Credential request phrase detected: "{phrase}"',
        })

    # --- Check 3: Suspicious action prompts ---
    action_matches = _find_phrase_matches(body_text, ACTION_PHRASES)
    for phrase in action_matches:
        findings.append({
            "category": "Body",
            "severity": "MEDIUM",
            "detail": f'Suspicious action prompt detected: "{phrase}"',
        })

    # --- Check 4: Social engineering lures ---
    lure_matches = _find_phrase_matches(body_text, LURE_PHRASES)
    for phrase in lure_matches:
        findings.append({
            "category": "Body",
            "severity": "MEDIUM",
            "detail": f'Social engineering lure phrase detected: "{phrase}"',
        })

    # --- Check 5: Impersonation language ---
    impersonation_matches = _find_phrase_matches(body_text, IMPERSONATION_PHRASES)
    for phrase in impersonation_matches:
        findings.append({
            "category": "Body",
            "severity": "LOW",
            "detail": f'Impersonation indicator in body: "{phrase}"',
        })

    # --- Check 6: Presence of HTML in a supposedly plain email ---
    # Phishing emails often embed hidden HTML to evade text-based filters
    if "<html" in body_text.lower() or "<body" in body_text.lower():
        if "<script" in body_text.lower():
            findings.append({
                "category": "Body",
                "severity": "HIGH",
                "detail": "JavaScript (<script>) found in email body — highly unusual and dangerous",
            })

    # --- Check 7: Base64-looking inline content blocks (obfuscation attempt) ---
    # Long base64 strings in body text may indicate hidden payload
    b64_pattern = re.compile(r"[A-Za-z0-9+/]{100,}={0,2}")
    if b64_pattern.search(body_text):
        findings.append({
            "category": "Body",
            "severity": "LOW",
            "detail": "Long base64-encoded string detected in body (possible content obfuscation)",
        })

    return findings


def get_body_text(msg) -> str:
    """Public wrapper so phishguard.py can display the raw body if needed."""
    return _extract_plain_text(msg)
