"""
url_analyzer.py
Extracts all URLs from an email body and analyzes each one for phishing indicators:
IP-based hosts, deceptive display text, suspicious TLDs, excessive subdomains,
URL shorteners, and encoded/obfuscated characters.
"""

import re
from urllib.parse import urlparse, unquote


# TLDs frequently abused in phishing campaigns due to low registration cost
SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".top", ".club",
    ".work", ".click", ".link", ".download", ".stream", ".gdn", ".win",
    ".bid", ".loan", ".review", ".accountant", ".date", ".faith", ".racing",
    ".party", ".trade", ".webcam", ".science", ".country", ".kim", ".ru",
    ".cn", ".su",
}

# Well-known URL shortening services — used to hide the real destination
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bc.vc", "clck.ru", "cutt.ly", "rebrand.ly",
    "shorturl.at", "tiny.cc", "rb.gy", "lnkd.in", "ift.tt",
}

# Legitimate brand domains — used to catch misleading display text tricks
TRUSTED_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "chase", "citibank",
    "wellsfargo", "bankofamerica", "irs", "usps", "fedex", "ups", "dhl",
]

# Regex to match URLs in plain-text and HTML content
URL_PATTERN = re.compile(
    r"https?://[^\s\"'<>\]\)]+",
    re.IGNORECASE,
)

# Regex to capture anchor tags: <a href="URL">display text</a>
ANCHOR_PATTERN = re.compile(
    r'<a\s[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)

# Regex to detect raw IPv4 addresses as the host component of a URL
IP_HOST_PATTERN = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)


def _get_tld(hostname: str) -> str:
    """Return the TLD of a hostname, e.g. 'example.co.uk' -> '.uk'."""
    parts = hostname.lower().split(".")
    if len(parts) >= 2:
        return "." + parts[-1]
    return ""


def _count_subdomains(hostname: str) -> int:
    """Count subdomain levels — e.g. 'a.b.c.example.com' has 3 subdomains."""
    parts = hostname.split(".")
    # Subtract the base domain (2 parts: name + TLD)
    return max(0, len(parts) - 2)


def _strip_html_tags(text: str) -> str:
    """Remove HTML tags from a string to get plain display text."""
    return re.sub(r"<[^>]+>", "", text).strip()


def extract_urls(body: str) -> list[tuple[str, str]]:
    """
    Extract all URLs from email body content.
    Returns list of (url, display_text) tuples.
    For plain URLs, display_text equals the URL itself.
    For anchor tags, display_text is the visible link text.
    """
    results = []
    seen = set()

    # First pass: extract anchor tags with their display text
    for match in ANCHOR_PATTERN.finditer(body):
        url = match.group(1).strip()
        display = _strip_html_tags(match.group(2))
        if url not in seen:
            results.append((url, display))
            seen.add(url)

    # Second pass: catch any remaining plain-text URLs
    for match in URL_PATTERN.finditer(body):
        url = match.group(0).rstrip(".,;:!?)")  # strip trailing punctuation
        if url not in seen:
            results.append((url, url))
            seen.add(url)

    return results


def analyze_urls(body: str) -> list[dict]:
    """
    Analyze all URLs found in the email body for phishing indicators.
    Returns a list of finding dicts: {category, severity, detail}
    """
    findings = []
    url_list = extract_urls(body)

    if not url_list:
        return findings

    for url, display_text in url_list:
        try:
            parsed = urlparse(url)
        except ValueError:
            continue

        hostname = parsed.hostname or ""
        decoded_url = unquote(url).lower()

        # --- Check 1: IP address used instead of domain name ---
        # Legitimate services use domain names; raw IPs are a red flag
        if hostname and IP_HOST_PATTERN.match(hostname):
            findings.append({
                "category": "URL",
                "severity": "HIGH",
                "detail": f"IP-based URL found (no domain name): {url}",
            })

        # --- Check 2: Suspicious TLD ---
        tld = _get_tld(hostname)
        if tld in SUSPICIOUS_TLDS:
            findings.append({
                "category": "URL",
                "severity": "MEDIUM",
                "detail": f'Suspicious TLD "{tld}" in URL: {url}',
            })

        # --- Check 3: URL shortener hiding real destination ---
        if hostname.lower() in URL_SHORTENERS:
            findings.append({
                "category": "URL",
                "severity": "MEDIUM",
                "detail": f"URL shortener detected (real destination hidden): {url}",
            })

        # --- Check 4: Excessive subdomains (subdomain abuse) ---
        # Attackers use subdomain tricks like paypal.secure.evil.com
        subdomain_count = _count_subdomains(hostname)
        if subdomain_count >= 3:
            findings.append({
                "category": "URL",
                "severity": "MEDIUM",
                "detail": f"Excessive subdomains ({subdomain_count} levels) — possible subdomain abuse: {hostname}",
            })

        # --- Check 5: Brand name in subdomain, not in actual domain ---
        # e.g., paypal.evil.com — "paypal" is a subdomain, not the real domain
        hostname_parts = hostname.lower().split(".")
        if len(hostname_parts) >= 3:
            subdomains = ".".join(hostname_parts[:-2])
            base_domain = hostname_parts[-2]
            for brand in TRUSTED_BRANDS:
                if brand in subdomains and brand not in base_domain:
                    findings.append({
                        "category": "URL",
                        "severity": "HIGH",
                        "detail": f'Brand "{brand}" used as subdomain to impersonate: {url}',
                    })
                    break

        # --- Check 6: Misleading display text vs actual URL ---
        # e.g., <a href="evil.com">paypal.com</a>
        display_lower = display_text.lower()
        if display_text != url and ("http" in display_lower or any(b in display_lower for b in TRUSTED_BRANDS)):
            try:
                display_parsed = urlparse(display_text if display_text.startswith("http") else "http://" + display_text)
                display_host = display_parsed.hostname or ""
                if display_host and display_host != hostname:
                    findings.append({
                        "category": "URL",
                        "severity": "HIGH",
                        "detail": f'Misleading link text — displayed: "{display_text}" | actual URL: {url}',
                    })
            except ValueError:
                pass

        # --- Check 7: URL-encoded characters used for obfuscation ---
        if "%" in url and decoded_url != url.lower():
            findings.append({
                "category": "URL",
                "severity": "LOW",
                "detail": f"URL contains encoded characters (possible obfuscation): {url}",
            })

        # --- Check 8: Suspicious keywords in URL path ---
        suspicious_path_keywords = ["login", "signin", "verify", "account", "secure", "update", "confirm", "banking"]
        for keyword in suspicious_path_keywords:
            if keyword in decoded_url and hostname and not any(b in hostname for b in TRUSTED_BRANDS):
                findings.append({
                    "category": "URL",
                    "severity": "LOW",
                    "detail": f'Suspicious keyword "{keyword}" in URL path from unknown domain: {url}',
                })
                break  # One finding per URL for this check

        # --- Check 9: HTTP (non-HTTPS) used for sensitive-looking pages ---
        if parsed.scheme == "http" and any(kw in decoded_url for kw in ["login", "account", "secure", "bank"]):
            findings.append({
                "category": "URL",
                "severity": "MEDIUM",
                "detail": f"Unencrypted HTTP used for sensitive-looking page: {url}",
            })

    return findings
