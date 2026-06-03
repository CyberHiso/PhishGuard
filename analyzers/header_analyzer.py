"""
header_analyzer.py
Analyzes email headers for common phishing indicators such as sender spoofing,
From/Reply-To mismatches, suspicious domains, and failed authentication signals.
"""

import re
from email.message import Message


# Domains commonly abused or associated with free/throwaway email services
SUSPICIOUS_SENDING_DOMAINS = [
    "mailinator.com", "guerrillamail.com", "tempmail.com", "yopmail.com",
    "trashmail.com", "sharklasers.com", "dispostable.com", "fakeinbox.com",
    "maildrop.cc", "throwam.com", "spamgourmet.com", "mytemp.email",
]

# Legitimate-looking display name keywords that attackers spoof frequently
IMPERSONATED_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "netflix", "bank",
    "chase", "wells fargo", "citibank", "irs", "fedex", "ups", "dhl",
    "support", "security", "account", "noreply", "no-reply", "helpdesk",
]


def _extract_address(header_value: str) -> str:
    """Pull the raw email address out of a header value like 'Display Name <addr@domain.com>'."""
    if not header_value:
        return ""
    match = re.search(r"<([^>]+)>", header_value)
    if match:
        return match.group(1).strip().lower()
    return header_value.strip().lower()


def _extract_display_name(header_value: str) -> str:
    """Extract only the display portion before the angle-bracket address."""
    if not header_value:
        return ""
    match = re.match(r'^"?([^"<]+)"?\s*<', header_value)
    if match:
        return match.group(1).strip().lower()
    return ""


def _get_domain(email_address: str) -> str:
    """Return the domain part of an email address."""
    if "@" in email_address:
        return email_address.split("@", 1)[1].lower()
    return ""


def analyze_headers(msg: Message) -> list[dict]:
    """
    Run all header checks on a parsed email.Message object.
    Returns a list of finding dicts: {category, severity, detail}
    """
    findings = []

    from_raw = msg.get("From", "")
    reply_to_raw = msg.get("Reply-To", "")
    return_path_raw = msg.get("Return-Path", "")
    received_spf = msg.get("Received-SPF", "")
    dkim_sig = msg.get("DKIM-Signature", "")
    authentication_results = msg.get("Authentication-Results", "")
    x_mailer = msg.get("X-Mailer", "")
    x_originating_ip = msg.get("X-Originating-IP", "")

    from_addr = _extract_address(from_raw)
    from_display = _extract_display_name(from_raw)
    from_domain = _get_domain(from_addr)
    reply_to_addr = _extract_address(reply_to_raw)
    reply_to_domain = _get_domain(reply_to_addr)
    return_path_addr = _extract_address(return_path_raw)
    return_path_domain = _get_domain(return_path_addr)

    # --- Check 1: From / Reply-To mismatch ---
    # Attackers set Reply-To to a different address so replies go to them
    if reply_to_addr and reply_to_addr != from_addr:
        findings.append({
            "category": "Header",
            "severity": "HIGH",
            "detail": f"From/Reply-To mismatch — From: {from_addr} | Reply-To: {reply_to_addr}",
        })

    # --- Check 2: From / Return-Path mismatch ---
    # The envelope sender (Return-Path) differs from the displayed From address
    if return_path_addr and return_path_domain and return_path_domain != from_domain:
        findings.append({
            "category": "Header",
            "severity": "MEDIUM",
            "detail": f"Return-Path domain differs from From domain — From: {from_domain} | Return-Path: {return_path_domain}",
        })

    # --- Check 3: Display name impersonates a trusted brand but domain doesn't match ---
    for brand in IMPERSONATED_BRANDS:
        if brand in from_display and brand not in from_domain:
            findings.append({
                "category": "Header",
                "severity": "HIGH",
                "detail": f'Display name "{from_display}" impersonates "{brand}" but sending domain is "{from_domain}"',
            })
            break  # One finding per email is sufficient for this check

    # --- Check 4: Suspicious or throwaway sending domain ---
    if from_domain in SUSPICIOUS_SENDING_DOMAINS:
        findings.append({
            "category": "Header",
            "severity": "HIGH",
            "detail": f'Sending domain "{from_domain}" is a known disposable/suspicious email provider',
        })

    # --- Check 5: SPF failure signals in headers ---
    spf_combined = (received_spf + " " + authentication_results).lower()
    if "spf=fail" in spf_combined or "spf=softfail" in spf_combined:
        findings.append({
            "category": "Header",
            "severity": "HIGH",
            "detail": "SPF check failed — sending server is not authorized to send for this domain",
        })
    elif "spf=none" in spf_combined:
        findings.append({
            "category": "Header",
            "severity": "MEDIUM",
            "detail": "No SPF record found for sending domain (SPF=none)",
        })

    # --- Check 6: DKIM failure signals ---
    dkim_combined = authentication_results.lower()
    if "dkim=fail" in dkim_combined:
        findings.append({
            "category": "Header",
            "severity": "HIGH",
            "detail": "DKIM signature verification failed — email may have been tampered with",
        })
    elif not dkim_sig and "dkim=pass" not in dkim_combined:
        # No DKIM signature at all is suspicious for a legitimate business email
        findings.append({
            "category": "Header",
            "severity": "LOW",
            "detail": "No DKIM signature present — email authenticity cannot be cryptographically verified",
        })

    # --- Check 7: Suspicious X-Mailer / bulk sending tool indicators ---
    bulk_mailer_patterns = ["phpmailer", "sendblaster", "massmailer", "bulk"]
    if x_mailer:
        for pattern in bulk_mailer_patterns:
            if pattern in x_mailer.lower():
                findings.append({
                    "category": "Header",
                    "severity": "MEDIUM",
                    "detail": f'X-Mailer header suggests bulk/automated sending tool: "{x_mailer}"',
                })
                break

    # --- Check 8: Originating IP exposed (unusual for legit services) ---
    if x_originating_ip:
        findings.append({
            "category": "Header",
            "severity": "LOW",
            "detail": f"X-Originating-IP header present: {x_originating_ip} — may reveal attacker infrastructure",
        })

    return findings
